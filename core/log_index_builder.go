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

// BuildLogIndexForBlock constructs the LogIndex for a block header per EIP-7745b.
//
// Schedule rules (chain i: range = 4^i blocks):
//
//	Chain 0 (1-block):  updated EVERY block
//	Chain 1 (4-block):  scheduled at block%4==0, published at block%4==1
//	Chain 2 (16-block): scheduled at block%16==3, published at block%16==7
//	Chain 3 (64-block): scheduled at block%64==15, published at block%64==31
func BuildLogIndexForBlock(blockNumber uint64, receipts types.Receipts, state *LogIndexState) *types.LogIndex {
	idx := &types.LogIndex{}

	// Chain 0: always instant — build single-block table from current receipts
	b0 := types.NewIndexBuilder(state.GetChainParent(0))
	b0.AddBlockEntries(blockNumber, receipts)
	chain0Root := b0.Build()
	state.UpdateChainParent(0, chain0Root.Table)
	idx.Chain0 = chain0Root

	// Chain 1: 4-block tables, schedule at %4==0, publish at %4==1
	if blockNumber%4 == 0 {
		root := computeMultiBlockTable(blockNumber-3, blockNumber, state.GetChainParent(1))
		state.ScheduleTable(1, blockNumber, root)
	}
	if blockNumber%4 == 1 {
		if root, ok := state.GetScheduledTable(1, blockNumber-1); ok {
			state.UpdateChainParent(1, root)
			idx.Chain1 = types.ChainedTableRoot{Table: root, Parent: state.GetChainParent(1)}
		} else {
			// No scheduled table available (e.g., first block after fork)
			parent := state.GetChainParent(1)
			idx.Chain1 = types.ChainedTableRoot{Table: parent, Parent: parent}
		}
	} else {
		// Copy forward: no change in this chain at this block
		parent := state.GetChainParent(1)
		idx.Chain1 = types.ChainedTableRoot{Table: parent, Parent: parent}
	}

	// Chain 2: 16-block tables, schedule at %16==3, publish at %16==7
	if blockNumber%16 == 3 {
		root := computeMultiBlockTable(blockNumber-15, blockNumber, state.GetChainParent(2))
		state.ScheduleTable(2, blockNumber, root)
	}
	if blockNumber%16 == 7 {
		if root, ok := state.GetScheduledTable(2, blockNumber-4); ok {
			state.UpdateChainParent(2, root)
			idx.Chain2 = types.ChainedTableRoot{Table: root, Parent: state.GetChainParent(2)}
		} else {
			parent := state.GetChainParent(2)
			idx.Chain2 = types.ChainedTableRoot{Table: parent, Parent: parent}
		}
	} else {
		parent := state.GetChainParent(2)
		idx.Chain2 = types.ChainedTableRoot{Table: parent, Parent: parent}
	}

	// Chain 3: 64-block tables, schedule at %64==15, publish at %64==31
	if blockNumber%64 == 15 {
		root := computeMultiBlockTable(blockNumber-63, blockNumber, state.GetChainParent(3))
		state.ScheduleTable(3, blockNumber, root)
	}
	if blockNumber%64 == 31 {
		if root, ok := state.GetScheduledTable(3, blockNumber-16); ok {
			state.UpdateChainParent(3, root)
			idx.Chain3 = types.ChainedTableRoot{Table: root, Parent: state.GetChainParent(3)}
		} else {
			parent := state.GetChainParent(3)
			idx.Chain3 = types.ChainedTableRoot{Table: parent, Parent: parent}
		}
	} else {
		parent := state.GetChainParent(3)
		idx.Chain3 = types.ChainedTableRoot{Table: parent, Parent: parent}
	}

	return idx
}

// computeMultiBlockTable builds a ChainedTable covering a range of blocks.
// For the PoC, this is a placeholder that returns the parent root (the actual
// multi-block merge requires reading receipts from the database).
//
// In production, this would:
//   - Merge four lower-level sorted tables (merge-sort approach), OR
//   - Read all receipts in the range and build the table from scratch.
func computeMultiBlockTable(_startBlock, _endBlock uint64, parent common.Hash) common.Hash {
	// TODO: implement multi-block table construction.
	// For the PoC, the scheduled root is the parent (chain is carried forward).
	// A full implementation would aggregate receipts across the range.
	return parent
}
