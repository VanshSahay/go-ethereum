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
	"sort"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// TestTableWritesForBlockSchedule feeds 600 blocks through the state-processing
// producer and pins the publication schedule: a level-0 write for every block
// whose root matches the stateless derivation, and a higher-level write for a
// level exactly when its publication deadline falls on the block.
func TestTableWritesForBlockSchedule(t *testing.T) {
	f := newTestFeed(600)
	ix := NewMemoryIndexer()
	defer ix.Stop()

	for i := 1; i <= 600; i++ {
		writes, err := ix.TableWritesForBlock(uint64(i), f.headers[i].ParentHash, f.receipts[i])
		if err != nil {
			t.Fatalf("block %d: %v (hasProcessed=%v num=%d head=%d)", i, err, ix.hasProcessedBlock, ix.processedBlockNumber, ix.headBlock)
		}
		if len(writes) == 0 || writes[0] != (TableWrite{
			FirstBlock: uint64(i),
			TableSize:  1,
			Root:       BuildLevel0Root(uint64(i), f.headers[i].ParentHash, f.receipts[i]),
		}) {
			t.Fatalf("block %d: level-0 write mismatch: %v", i, writes)
		}
		for level := 1; level < len(TableSizes); level++ {
			size := TableSizes[level]
			delay := size + size/4 - 1
			first := uint64(i) - delay
			due := uint64(i) > delay && first%size == 0 && PublicationSchedule(size, first) == uint64(i)
			var write *TableWrite
			for j, w := range writes {
				if w.TableSize == size {
					write = &writes[j]
				}
			}
			if due != (write != nil) {
				t.Fatalf("block %d: level %d due=%v, write=%v", i, level, due, write)
			}
			if write != nil && write.FirstBlock != first {
				t.Errorf("block %d: level %d write first_block %d, want %d", i, level, write.FirstBlock, first)
			}
		}
		ix.AddBlockData(f.headers[i], &types.Body{}, f.receipts[i])
	}
	waitIdle(t, ix)
}

// TestGetRangeReadersDecomposition pins that the range reader decomposition
// covers a queried block range exactly once, without gaps or overlaps.
func TestGetRangeReadersDecomposition(t *testing.T) {
	f := newTestFeed(600)
	ix := NewMemoryIndexer()
	defer ix.Stop()

	for i := 1; i <= 600; i++ {
		ix.AddBlockData(f.headers[i], &types.Body{}, f.receipts[i])
	}
	waitIdle(t, ix)

	for _, r := range []common.Range[uint64]{
		common.NewRange[uint64](1, 100),
		common.NewRange[uint64](50, 300),
		common.NewRange[uint64](1, 600),
		common.NewRange[uint64](513, 88),
	} {
		readers := ix.storage.getRangeReaders(r)
		cover := make([]common.Range[uint64], 0, len(readers))
		for _, tr := range readers {
			cover = append(cover, tr.BlockRange())
		}
		sort.Slice(cover, func(i, j int) bool { return cover[i].First() < cover[j].First() })
		if len(cover) == 0 {
			t.Fatalf("range %v: no readers", r)
		}
		// The cover ranges must be pairwise disjoint and must cover every
		// block of the queried range. Tables straddling the range edges may
		// overhang: the query clamps positions to the requested range.
		for i := 1; i < len(cover); i++ {
			if cover[i].First() < cover[i-1].AfterLast() {
				t.Errorf("range %v: overlap %v and %v", r, cover[i-1], cover[i])
			}
		}
		covered := make(map[uint64]bool)
		for _, c := range cover {
			for b := c.First(); b <= c.Last(); b++ {
				covered[b] = true
			}
		}
		for b := r.First(); b <= r.Last(); b++ {
			if !covered[b] {
				t.Fatalf("range %v: block %d not covered", r, b)
			}
		}
	}
}
