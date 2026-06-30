// Copyright 2025 The go-ethereum Authors
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
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// TableWrite describes a table root that should be written to the index contract.
type TableWrite struct {
	FirstBlock uint64
	TableSize  uint64
	Root       common.Hash
}

// BuildLogIndexForBlock builds EIP-8304 log index tables for the given block.
// It returns the list of TableWrites that should be sent to the index contract
// via system calls.
func BuildLogIndexForBlock(blockNumber uint64, receipts types.Receipts, parentHash common.Hash) []TableWrite {
	state := LoadLogIndexState(blockNumber - 1)
	defer SaveLogIndexState(blockNumber, state)

	var tablesToWrite []TableWrite

	// Level 0: single-block table, always built, published immediately
	b0 := types.NewIndexBuilder()
	b0.AddBlockEntries(blockNumber, receipts)
	root0 := b0.Build()
	state.UpdateChainParent(0, root0)
	tablesToWrite = append(tablesToWrite, TableWrite{
		FirstBlock: blockNumber,
		TableSize:  1,
		Root:       root0,
	})

	// Level 1: 4-block tables
	// Schedule at block % 4 == 3 (last block of the 4-block window)
	if blockNumber%4 == 3 && blockNumber >= 3 {
		root := state.GetChainParent(0) // use the level-0 root as placeholder for now
		state.ScheduleTable(1, blockNumber-3, root)
	}
	// Publish at block % 4 == 0 (1-block delay after the window)
	if blockNumber%4 == 0 && blockNumber >= 4 {
		if root, ok := state.GetScheduledTable(1, blockNumber-4); ok {
			state.UpdateChainParent(1, root)
			tablesToWrite = append(tablesToWrite, TableWrite{
				FirstBlock: blockNumber - 4,
				TableSize:  4,
				Root:       root,
			})
		}
	}
	// On non-publish blocks, carry the parent forward
	if parent := state.GetChainParent(1); parent != (common.Hash{}) {
		// parent is already set from a previous publish
	}

	// Levels 2-4: Stub -- carry parent forward (no-op for now)
	for i := 2; i < types.TableLevelCount; i++ {
		_ = state.GetChainParent(uint8(i))
	}

	return tablesToWrite
}
