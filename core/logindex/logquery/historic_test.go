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

package logquery

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/beacon"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/logindex"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

// sliceChain serves generated blocks and their receipts as table history.
type sliceChain struct {
	blocks   []*types.Block
	receipts []types.Receipts
}

func (c sliceChain) GetHeader(hash common.Hash, number uint64) *types.Header {
	if number == 0 || number > uint64(len(c.blocks)) || c.blocks[number-1].Hash() != hash {
		return nil
	}
	return c.blocks[number-1].Header()
}

func (c sliceChain) GetIndexReceipts(hash common.Hash, number uint64) (types.Receipts, error) {
	if c.GetHeader(hash, number) == nil {
		return nil, fmt.Errorf("block %d unknown", number)
	}
	return c.receipts[number-1], nil
}

// TestHistoricContractEndToEnd runs the out-of-protocol mode: EIP-8304 is not
// active on the chain; the roots of the tables of the first 20 blocks are
// exported, a historic contract holding them is deployed by a transaction, and
// a node indexing with the matching hierarchy serves proofs that a verifier
// trusting only the contract's code accepts.
func TestHistoricContractEndToEnd(t *testing.T) {
	config := *params.MergedTestChainConfig
	if config.EIP8304Time != nil {
		t.Fatal("test config has EIP-8304 active")
	}
	emitter := crypto.CreateAddress(rtSender, 1)
	alloc := core.SystemContractAllocs()
	alloc[emitter] = types.Account{Code: diffEmitterCode()}
	alloc[rtSender] = types.Account{Balance: new(big.Int).Lsh(big.NewInt(1), 60)}
	genesis := &core.Genesis{Config: &config, Alloc: alloc}
	engine := beacon.New(ethash.NewFaker())
	signer := types.LatestSigner(&config)

	// the chain before the contract: one call of the emitter per block
	var nonce uint64
	callGen := func(i int, gen *core.BlockGen) {
		tx, _ := types.SignNewTx(rtKey, signer, &types.LegacyTx{
			Nonce: nonce, To: &emitter, Gas: 100_000, GasPrice: new(big.Int).Add(gen.BaseFee(), big.NewInt(1)),
		})
		nonce++
		gen.AddTx(tx)
	}
	const covered = 20
	genDB, pre, preReceipts := core.GenerateChainWithGenesis(genesis, engine, covered, callGen)
	for i, b := range pre {
		rawdb.WriteBlock(genDB, b)
		rawdb.WriteReceipts(genDB, b.Hash(), b.NumberU64(), preReceipts[i])
		rawdb.WriteCanonicalHash(genDB, b.Hash(), b.NumberU64())
	}
	sizes := []uint64{1, 4, 16}
	roots, err := logindex.ExportTableRoots(sliceChain{pre, preReceipts}, pre[covered-1].Header(), sizes)
	if err != nil {
		t.Fatal(err)
	}
	if len(roots) != covered+covered/4-1 { // 20 level-0 tables and the 4-block ones at 4, 8, 12, 16
		t.Fatalf("exported %d roots", len(roots))
	}

	// the contract goes in with a transaction in the block after them
	historic := crypto.CreateAddress(rtSender, nonce)
	post, _ := core.GenerateChain(&config, pre[covered-1], engine, genDB, 8, func(i int, gen *core.BlockGen) {
		if i == 0 {
			tx, _ := types.SignNewTx(rtKey, signer, &types.LegacyTx{
				Nonce: nonce, Gas: 2_000_000, Data: HistoricInitCode(roots), GasPrice: new(big.Int).Add(gen.BaseFee(), big.NewInt(1)),
			})
			nonce++
			gen.AddTx(tx)
			return
		}
		callGen(i, gen)
	})

	bc, err := core.NewBlockChain(rawdb.NewMemoryDatabase(), genesis, engine, &core.BlockChainConfig{
		LogIndexHistoricContract: historic,
		LogIndexHistoricSizes:    sizes,
		LogIndexHistoricLast:     covered,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer bc.Stop()
	if _, err := bc.InsertChain(append(append([]*types.Block{}, pre...), post...)); err != nil {
		t.Fatal(err)
	}
	if code := bc.GetBlockByNumber(covered + 1); code == nil || len(code.Transactions()) != 1 {
		t.Fatal("deployment block missing")
	}
	bc.SyncLogIndex()

	matcher := NewMatcher(bc.LogIndex(), &rtBackend{bc: bc})
	spec := HistoricContract{CodeHash: crypto.Keccak256Hash(HistoricContractCode), TableSizes: sizes, LastBlock: covered}
	matcher.Historic = map[common.Address]HistoricContract{historic: spec}
	rtc := &rtChain{bc: bc, matcher: matcher}

	pattern, err := NewPatternMatcherFromJSON(json.RawMessage(fmt.Sprintf(`{"allOf":[%s,%s]}`, addrLeaf(emitter), topicLeaf(0, topicB))))
	if err != nil {
		t.Fatal(err)
	}
	req := FilterQuery{Pattern: pattern, FirstBlock: 1, LastBlock: covered - 1, Limit: 1000}
	logs, _, proof, err := matcher.GetMatches(context.Background(), &rtView{rtc}, req, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) == 0 {
		t.Fatal("no logs")
	}
	trusted := bc.CurrentBlock()
	opts := DefaultVerifyOptions(bc.Config())
	// the protocol contract is not the one the roots are in: not accepted
	if _, err := proof.Verify(trusted, req, opts); err == nil {
		t.Fatal("proof against an unlisted contract was accepted")
	}
	opts.HistoricContracts = map[common.Address]HistoricContract{historic: spec}
	res, err := proof.Verify(trusted, req, opts)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(res.Logs) != len(logs) {
		t.Fatalf("verified %d logs, served %d", len(res.Logs), len(logs))
	}
	// a contract with other code is rejected
	bad := opts
	bad.HistoricContracts = map[common.Address]HistoricContract{historic: {CodeHash: common.Hash{1}, TableSizes: sizes, LastBlock: covered}}
	if _, err := proof.Verify(trusted, req, bad); err == nil {
		t.Error("proof against a contract with other code was accepted")
	}
	// coverage ending before the proven tables is rejected
	bad.HistoricContracts = map[common.Address]HistoricContract{historic: {CodeHash: spec.CodeHash, TableSizes: sizes, LastBlock: 10}}
	if _, err := proof.Verify(trusted, req, bad); err == nil {
		t.Error("proof past the contract's coverage was accepted")
	}
	// a size the contract is not trusted for is rejected
	bad.HistoricContracts = map[common.Address]HistoricContract{historic: {CodeHash: spec.CodeHash, TableSizes: []uint64{1}, LastBlock: covered}}
	if _, err := proof.Verify(trusted, req, bad); err == nil {
		t.Error("proof with a table size outside the contract's sizes was accepted")
	}
}
