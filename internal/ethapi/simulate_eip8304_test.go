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

package ethapi

import (
	"context"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus/beacon"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/logindex"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
)

// TestSimulateIndexTableDerivation pins that simulated blocks commit the same
// higher-level EIP-8304 table roots as real ones: a table that falls due in a
// simulated block is derived from the canonical blocks below it, and the
// contract serves it to a call in a later simulated block.
func TestSimulateIndexTableDerivation(t *testing.T) {
	t.Parallel()

	config := *params.MergedTestChainConfig
	config.EIP8304Time = new(uint64)
	var (
		acc     = newTestAccount()
		emitter = common.HexToAddress("0x0000000000000000000000000000000000000e11")
		genesis = &core.Genesis{
			Config: &config,
			Alloc: types.GenesisAlloc{
				acc.addr: {Balance: big.NewInt(params.Ether)},
				// LOG0 with empty data
				emitter: {Code: common.FromHex("5f5fa000")},
			},
		}
		signer = types.LatestSigner(&config)
	)
	const realBlocks = 7
	backend := newTestBackend(t, realBlocks, genesis, beacon.New(ethash.NewFaker()), func(i int, b *core.BlockGen) {
		tx, _ := types.SignTx(types.NewTx(&types.DynamicFeeTx{
			ChainID:   config.ChainID,
			Nonce:     uint64(i),
			To:        &emitter,
			Gas:       100_000,
			GasFeeCap: new(big.Int).Add(b.BaseFee(), big.NewInt(1)),
			GasTipCap: big.NewInt(1),
		}), signer, acc.key)
		b.AddTx(tx)
	})
	api := NewBlockChainAPI(backend)

	// the 4-block table over blocks 4..7 falls due in block 8, the first
	// simulated block, and is readable from block 9 on
	head := backend.chain.CurrentBlock()
	if head.Number.Uint64() != realBlocks {
		t.Fatalf("head %d, want %d", head.Number, realBlocks)
	}
	want, err := logindex.ExportTableRoots(backend.chain, head, []uint64{4})
	if err != nil || len(want) == 0 || want[0].FirstBlock != 4 {
		t.Fatalf("expected table roots: %v %v", want, err)
	}
	var callData [64]byte
	callData[31], callData[63] = 4, 4 // get(first_block=4, table_size=4)
	data := hexutil.Bytes(callData[:])
	index := params.IndexContractAddress
	tag := rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)
	res, err := api.SimulateV1(context.Background(), simOpts{BlockStateCalls: []simBlock{
		{},
		{},
		{Calls: []TransactionArgs{{To: &index, Data: &data}}},
	}}, &tag)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 3 || len(res[2].Calls) != 1 {
		t.Fatalf("unexpected result shape: %d blocks", len(res))
	}
	call := res[2].Calls[0]
	if call.Error != nil {
		t.Fatalf("get() failed: %v", call.Error.Message)
	}
	if got := common.BytesToHash(call.ReturnValue); got != want[0].Root {
		t.Errorf("simulated get() = %x, want the derived root %x", got, want[0].Root)
	}
}
