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
	"context"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/beacon"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

// eip8304LogsPerCall is the number of LOG0 events emitted per contract call
// by the log-emitting contract below.
const eip8304LogsPerCall = 200

// eip8304LogCode is a tiny contract that emits eip8304LogsPerCall LOG0 events
// with 32 bytes of (zeroed) data per call, then returns. Used to generate
// log-heavy blocks for the EIP-8304 overhead benchmark.
//
// Runtime disassembly:
//
//	PUSH1 0xc8, PUSH1 0x00    // count, i
//	JUMPDEST                  // loop
//	PUSH1 0x20, PUSH0, LOG0   // log memory[0:32]
//	PUSH1 0x01, ADD, PUSH1 0xc8, DUP2, LT, PUSH1 0x04, JUMPI
//	PUSH0, PUSH0, RETURN
var eip8304LogCode = common.FromHex("60168060095f395ff3" + // init: copy 0x16 bytes of runtime, return
	"60c860005b60205fa060010160c881106004575f5ff3") // runtime: 0xc8 (200) LOG0 events

// benchInsertChainEIP8304 benchmarks block processing with EIP-8304 log index
// writes. With withContract=true the index contract is pre-deployed in the
// genesis alloc, so the table builder and the system call run for every block;
// with withContract=false only the no-code guard path is measured.
//
// Each block is executed via the state processor and its state committed,
// mirroring writeBlockWithState. The index tables of every block are derived
// from the chain's history, like in a real import; the header roots are not
// compared against.
func benchInsertChainEIP8304(b *testing.B, logsPerBlock int, withContract bool) {
	// MergedTestChainConfig activates Shanghai and later forks, which the
	// index contract requires (PUSH0, EIP-3855). Amsterdam is enabled from
	// genesis so the EIP-8304 gate fires; the Prague/Osaka system contracts
	// are deployed so PostExecution's post-execution processing succeeds.
	config := *params.MergedTestChainConfig
	config.AmsterdamTime = new(uint64)
	if withContract {
		config.EIP8304Time = new(uint64)
	}
	gspec := &Genesis{
		Config: &config,
		Alloc:  SystemContractAllocs(),
	}
	gspec.Alloc[benchRootAddr] = types.Account{Balance: benchRootFunds}
	if withContract {
		gspec.Alloc[params.IndexContractAddress] = types.Account{
			Nonce:   1,
			Code:    params.IndexContractCode,
			Balance: common.Big0,
		}
	}
	logAddr := crypto.CreateAddress(benchRootAddr, 0) // deploy tx is the first tx of the chain
	gen := func(i int, gen *BlockGen) {
		gasPrice := big.NewInt(0)
		if gen.header.BaseFee != nil {
			gasPrice = gen.header.BaseFee
		}
		signer := gen.Signer()
		if i == 0 {
			// Deploy the log-emitting contract.
			tx, _ := types.SignNewTx(benchRootKey, signer, &types.LegacyTx{
				Nonce:    gen.TxNonce(benchRootAddr),
				Value:    big.NewInt(0),
				Gas:      3_000_000,
				Data:     eip8304LogCode,
				GasPrice: gasPrice,
			})
			gen.AddTx(tx)
			return
		}
		// Emit the requested number of logs across a few contract calls.
		calls := (logsPerBlock + eip8304LogsPerCall - 1) / eip8304LogsPerCall
		for range calls {
			tx, _ := types.SignNewTx(benchRootKey, signer, &types.LegacyTx{
				Nonce:    gen.TxNonce(benchRootAddr),
				To:       &logAddr,
				Value:    big.NewInt(0),
				Gas:      200_000,
				GasPrice: gasPrice,
			})
			gen.AddTx(tx)
		}
	}
	engine := beacon.New(ethash.NewFaker())
	_, chain, _ := GenerateChainWithGenesis(gspec, engine, b.N, gen)

	db := rawdb.NewMemoryDatabase()
	chainman, _ := NewBlockChain(db, gspec, engine, nil)
	defer chainman.Stop()

	sdb := state.NewMPTDatabase(chainman.triedb, chainman.codedb)
	parentRoot := gspec.ToBlock().Root()

	b.ReportAllocs()
	b.ResetTimer()
	var (
		statedb *state.StateDB
		res     *ProcessResult
		err     error
	)
	for _, block := range chain {
		statedb, err = state.New(parentRoot, sdb)
		if err != nil {
			b.Fatalf("state for block %d: %v", block.NumberU64(), err)
		}
		// Both the serial and the parallel processor build the index tables;
		// use the default path selection.
		cfg := vm.Config{}
		res, err = chainman.processor.Process(context.Background(), block, statedb, nil, nil, cfg, nil)
		if err != nil {
			b.Fatalf("process error (block %d): %v", block.NumberU64(), err)
		}
		root, err := statedb.Commit(chainman.Config().Rules(block.Number(), true, block.Time()), block.NumberU64())
		if err != nil {
			b.Fatalf("state commit error (block %d): %v", block.NumberU64(), err)
		}
		if err := chainman.triedb.Commit(root, false); err != nil {
			b.Fatalf("trie commit error (block %d): %v", block.NumberU64(), err)
		}
		// Persist the block and its receipts like writeBlockWithState does: the
		// index tables of later blocks are derived from them.
		rawdb.WriteBlock(db, block)
		rawdb.WriteReceipts(db, block.Hash(), block.NumberU64(), res.Receipts)
		parentRoot = root
	}
	b.StopTimer()

	// Sanity check: the last block's level-0 table root must have been written
	// to the index contract (slot = table_size*0x400 + first_block%0x400).
	last := chain[b.N-1]
	slot := common.BigToHash(new(big.Int).SetUint64(1*0x400 + last.NumberU64()%0x400))
	if withContract {
		if root := statedb.GetState(params.IndexContractAddress, slot); root == (common.Hash{}) {
			b.Fatalf("index contract slot %x empty: system call did not run", slot)
		}
	} else {
		if code := statedb.GetCode(params.IndexContractAddress); len(code) > 0 {
			b.Fatalf("unexpected code at index contract address")
		}
	}
	// Verify the log-emitting contract actually produced the requested logs,
	// otherwise the benchmark measures nothing. Skip the check when the chain
	// consists only of the deploy block.
	if logsPerBlock > 0 && b.N > 1 {
		total := 0
		for _, r := range res.Receipts {
			total += len(r.Logs)
		}
		expected := (logsPerBlock + eip8304LogsPerCall - 1) / eip8304LogsPerCall * eip8304LogsPerCall
		if total != expected {
			b.Fatalf("block emitted %d logs, want %d", total, expected)
		}
	}
}

// BenchmarkInsertChain_eip8304_active_memdb measures full EIP-8304 block
// processing: table builder + system call + contract storage write per block.
// Log counts are emitted in bins of eip8304LogsPerCall (the contract emits
// 200 logs per call).
func BenchmarkInsertChain_eip8304_active_memdb(b *testing.B) {
	for _, logs := range []int{0, 200, 1000} {
		b.Run(fmt.Sprintf("logs=%d", logs), func(b *testing.B) {
			benchInsertChainEIP8304(b, logs, true)
		})
	}
}

// BenchmarkInsertChain_eip8304_guard_memdb measures the no-code guard path:
// the same code path with no contract deployed (non-dev chains).
func BenchmarkInsertChain_eip8304_guard_memdb(b *testing.B) {
	for _, logs := range []int{0, 200, 1000} {
		b.Run(fmt.Sprintf("logs=%d", logs), func(b *testing.B) {
			benchInsertChainEIP8304(b, logs, false)
		})
	}
}
