// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/beacon"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

// TestLogIndexDerivationIndependentOfIndexer imports a chain long enough for
// every table level to fall due, with and without a local log index, and then
// reorgs it across a due height. The index contract is deployed by the
// activation block, so the system calls of all blocks must be derivable from
// the chain alone: an importing node must neither depend on what its own
// index holds nor reject a block because of it.
func TestLogIndexDerivationIndependentOfIndexer(t *testing.T) {
	config := *params.MergedTestChainConfig
	config.AmsterdamTime = new(uint64)
	config.EIP8304Time = new(uint64)
	gspec := &Genesis{Config: &config, Alloc: SystemContractAllocs()}
	gspec.Alloc[benchRootAddr] = types.Account{Balance: benchRootFunds}
	logAddr := crypto.CreateAddress(benchRootAddr, 0)

	makeGen := func(callsPerBlock func(int) int) func(int, *BlockGen) {
		return func(i int, gen *BlockGen) {
			gasPrice := big.NewInt(0)
			if gen.header.BaseFee != nil {
				gasPrice = gen.header.BaseFee
			}
			signer := gen.Signer()
			if gen.header.Number.Uint64() == 1 {
				tx, _ := types.SignNewTx(benchRootKey, signer, &types.LegacyTx{
					Nonce: gen.TxNonce(benchRootAddr), Gas: 3_000_000, Data: eip8304LogCode, GasPrice: gasPrice,
				})
				gen.AddTx(tx)
				return
			}
			for range callsPerBlock(i) {
				tx, _ := types.SignNewTx(benchRootKey, signer, &types.LegacyTx{
					Nonce: gen.TxNonce(benchRootAddr), To: &logAddr, Gas: 200_000, GasPrice: gasPrice,
				})
				gen.AddTx(tx)
			}
		}
	}
	engine := beacon.New(ethash.NewFaker())
	const length = 620 // past the first 256-block publication at block 575
	genDB, chain, receipts := GenerateChainWithGenesis(gspec, engine, length, makeGen(func(i int) int { return i%3 + 1 }))

	// a side chain forking below the due height of the 256-block table
	for i, block := range chain {
		rawdb.WriteBlock(genDB, block)
		rawdb.WriteReceipts(genDB, block.Hash(), block.NumberU64(), receipts[i])
		rawdb.WriteCanonicalHash(genDB, block.Hash(), block.NumberU64())
	}
	const forkAt = 560
	side, _ := GenerateChain(&config, chain[forkAt-1], engine, genDB, 80, makeGen(func(i int) int { return i%2 + 2 }))

	for name, cfg := range map[string]*BlockChainConfig{
		"indexed":  nil,
		"no-index": {LogIndexDisabled: true},
	} {
		bc, err := NewBlockChain(rawdb.NewMemoryDatabase(), gspec, engine, cfg)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if n, err := bc.InsertChain(chain); err != nil {
			t.Fatalf("%s: main chain rejected at block %d: %v", name, chain[n].NumberU64(), err)
		}
		// the heavier side chain forces a reorg over the due height
		if n, err := bc.InsertChain(side); err != nil {
			t.Fatalf("%s: side chain rejected at block %d: %v", name, side[n].NumberU64(), err)
		}
		if head := bc.CurrentBlock(); head.Hash() != side[len(side)-1].Hash() {
			t.Errorf("%s: head %d is not the side chain tip", name, head.Number)
		}
		// the follower brings the index onto the side chain: every table of the
		// head's range belongs to the canonical chain
		if bc.LogIndex() != nil {
			bc.SyncLogIndex()
			ix := bc.LogIndex()
			if ix.HeadHash() != bc.CurrentBlock().Hash() {
				t.Errorf("%s: index head %x, chain head %x", name, ix.HeadHash(), bc.CurrentBlock().Hash())
			}
			headNum := bc.CurrentBlock().Number.Uint64()
			readers := ix.GetRangeReaders(bc.CurrentBlock().Hash(), common.NewRange[uint64](1, headNum), 0)
			if len(readers) == 0 {
				t.Errorf("%s: no tables for the canonical range", name)
			}
			for _, tr := range readers {
				last := tr.Meta.LastBlockNumber
				if want := bc.GetCanonicalHash(last); tr.Meta.LastBlockHash != want {
					t.Errorf("%s: table ending at %d is on hash %x, canonical %x", name, last, tr.Meta.LastBlockHash, want)
				}
			}
		}
		bc.Stop()
	}
}

// TestIndexHistoryPruned pins the behaviour on a node whose old receipts are
// gone: blocks that need only the receipts it still has import normally, and
// the first block on which a table covering a missing block falls due fails
// loudly with the block it misses, then succeeds once the receipts are back.
func TestIndexHistoryPruned(t *testing.T) {
	config := *params.MergedTestChainConfig
	config.AmsterdamTime = new(uint64)
	config.EIP8304Time = new(uint64)
	gspec := &Genesis{Config: &config, Alloc: SystemContractAllocs()}
	gspec.Alloc[benchRootAddr] = types.Account{Balance: benchRootFunds}
	logAddr := crypto.CreateAddress(benchRootAddr, 0)
	engine := beacon.New(ethash.NewFaker())
	_, chain, receipts := GenerateChainWithGenesis(gspec, engine, 700, func(i int, gen *BlockGen) {
		gasPrice := new(big.Int).Add(gen.BaseFee(), big.NewInt(1))
		tx := &types.LegacyTx{Nonce: gen.TxNonce(benchRootAddr), Gas: 200_000, GasPrice: gasPrice}
		if i == 0 {
			tx.Data, tx.Gas = eip8304LogCode, 3_000_000
		} else {
			tx.To = &logAddr
		}
		signed, _ := types.SignNewTx(benchRootKey, gen.Signer(), tx)
		gen.AddTx(signed)
	})
	db := rawdb.NewMemoryDatabase()
	bc, err := NewBlockChain(db, gspec, engine, &BlockChainConfig{LogIndexDisabled: true})
	if err != nil {
		t.Fatal(err)
	}
	defer bc.Stop()
	if n, err := bc.InsertChain(chain[:620]); err != nil {
		t.Fatalf("block %d: %v", chain[n].NumberU64(), err)
	}
	// history pruning below the window, and one receipt set missing inside it
	for n := uint64(1); n < 300; n++ {
		rawdb.DeleteReceipts(db, chain[n-1].Hash(), n)
	}
	rawdb.DeleteReceipts(db, chain[599].Hash(), 600)

	n, err := bc.InsertChain(chain[620:])
	if err == nil {
		t.Fatal("blocks needing a pruned receipt set were imported")
	}
	if got := chain[620+n].NumberU64(); got != 655 {
		t.Errorf("import failed at block %d, want 655 (the first table covering block 600)", got)
	}
	if !strings.Contains(err.Error(), "receipts of block 600") {
		t.Errorf("error does not name the missing receipts: %v", err)
	}
	// with the receipts back the rest imports
	rawdb.WriteReceipts(db, chain[599].Hash(), 600, receipts[599])
	if n, err := bc.InsertChain(chain[620+n:]); err != nil {
		t.Fatalf("block %d after restoring the receipts: %v", chain[620+n].NumberU64(), err)
	}
}
