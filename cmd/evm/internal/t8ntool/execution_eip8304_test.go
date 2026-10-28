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

package t8ntool

import (
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/logindex"
	"github.com/ethereum/go-ethereum/core/logindex/logquery"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
)

type noTxs struct{}

func (noTxs) Next() bool                      { return false }
func (noTxs) Tx() (*types.Transaction, error) { return nil, nil }

func eip8304Prestate(number uint64, hashes map[math.HexOrDecimal64]common.Hash) *Prestate {
	alloc := core.SystemContractAllocs()
	alloc[params.IndexContractAddress] = types.Account{Nonce: 1, Code: params.IndexContractCode, Balance: common.Big0}
	return &Prestate{
		Pre: alloc,
		Env: stEnv{
			Coinbase:              common.Address{1},
			Random:                big.NewInt(0),
			Difficulty:            big.NewInt(0),
			GasLimit:              30_000_000,
			Number:                number,
			Timestamp:             number * 12,
			ParentTimestamp:       (number - 1) * 12,
			BaseFee:               big.NewInt(1),
			ParentBaseFee:         big.NewInt(1),
			ParentGasUsed:         0,
			ParentGasLimit:        30_000_000,
			ParentBeaconBlockRoot: &common.Hash{},
			BlockHashes:           hashes,
		},
	}
}

// TestT8nIndexTables pins the transition tool's handling of EIP-8304: a block
// on which only the level-0 table is due gets its write, a block on which a
// higher-level table falls due fails instead of getting a wrong state root.
func TestT8nIndexTables(t *testing.T) {
	config := *params.MergedTestChainConfig
	config.EIP8304Time = new(uint64)
	parent := common.Hash{0xaa}

	// block 5: only the level-0 table is due
	pre := eip8304Prestate(5, map[math.HexOrDecimal64]common.Hash{4: parent})
	statedb, _, _, err := pre.Apply(vm.Config{}, &config, noTxs{}, 0)
	if err != nil {
		t.Fatalf("block 5: %v", err)
	}
	slot, ok := logquery.IndexSlot(1, 5)
	if !ok {
		t.Fatal("no slot")
	}
	if got, want := statedb.GetState(params.IndexContractAddress, slot), logindex.BuildLevel0Root(5, parent, nil); got != want {
		t.Errorf("level-0 root in the contract %x, want %x", got, want)
	}

	// block 8: the 4-block table over blocks 4..7 falls due
	pre = eip8304Prestate(8, map[math.HexOrDecimal64]common.Hash{7: parent})
	if _, _, _, err := pre.Apply(vm.Config{}, &config, noTxs{}, 0); err == nil || !strings.Contains(err.Error(), "history") {
		t.Errorf("block 8: error %v, want the missing history error", err)
	}

	// the parent hash is required
	pre = eip8304Prestate(5, nil)
	if _, _, _, err := pre.Apply(vm.Config{}, &config, noTxs{}, 0); err == nil {
		t.Error("block without the parent hash accepted")
	}
}
