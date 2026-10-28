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

package logindex

import (
	"testing"

	"github.com/ethereum/go-ethereum/core/types"
)

// TestLevelRetention pins that a level only keeps the tables the index
// contract can still serve: after 5000 blocks the lowest levels hold their
// ring windows (1025 table sizes plus the publication lag), the higher ones
// everything, and the whole range stays covered.
func TestLevelRetention(t *testing.T) {
	const blocks = 5000
	f := newTestFeed(blocks)
	ix := NewMemoryIndexer()
	defer ix.Stop()
	for i := 1; i <= blocks; i++ {
		ix.AddBlockData(f.headers[i], &types.Body{}, f.receipts[i])
	}
	waitIdle(t, ix)

	complete, partial, _ := ix.storage.tables()
	for level, size := range TableSizes {
		span := ringSlots*size + size + size/4
		windowTables := (span + size - 1) / size
		total := uint64(blocks) / size
		want := min(total, windowTables+1)
		got := complete[level].Count()
		if got+3 < want || got > want+3 {
			t.Errorf("level %d (size %d): %d tables retained, want about %d of %d", level, size, got, want, total)
		}
		if partial[level].Count() != 0 {
			t.Errorf("level %d: %d partial tables left", level, partial[level].Count())
		}
	}
	// the pruned ranges are served by the levels above; the first blocks are
	// the exception: no table covers the genesis block, so blocks 1..15 have
	// no level-2 table and are only held by the levels that have aged out
	coverageGaps(t, ix, 16, blocks+1)

	// the scheduler has settled: nothing left to merge or delete
	ix.lock.Lock()
	defer ix.lock.Unlock()
	complete, partial, _ = ix.storage.tables()
	ops, _ := ix.params.nextTableOperations(complete, partial, ix.makeTargetSet(complete), ix.mergeThreads, ix.mergeThreads)
	if len(ops) != 0 {
		t.Errorf("scheduler still has %d operations after settling: %v", len(ops), ops)
	}
}
