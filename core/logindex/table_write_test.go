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
	"errors"
	"sort"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/lru"
	"github.com/ethereum/go-ethereum/core/types"
)

// feedChain serves a testFeed as the ancestry of a block being built.
type feedChain struct{ f *testFeed }

func (c feedChain) GetHeader(hash common.Hash, number uint64) *types.Header {
	if number >= uint64(len(c.f.headers)) || c.f.headers[number] == nil || c.f.headers[number].Hash() != hash {
		return nil
	}
	return c.f.headers[number]
}

func (c feedChain) GetIndexReceipts(hash common.Hash, number uint64) (types.Receipts, error) {
	if c.GetHeader(hash, number) == nil {
		return nil, errors.New("unknown block")
	}
	return c.f.receipts[number], nil
}

var alwaysActive = func(*types.Header) bool { return true }

// resetDerivedRoots empties the derived root cache: the tests reuse block
// hashes with different history, which real blocks never do.
func resetDerivedRoots() { derivedRoots = lru.NewCache[derivedKey, derivedRoot](256) }

// TestDeriveTableWritesSchedule feeds 600 blocks through the derivation and
// pins the publication schedule: a level-0 write for every block whose root
// matches the stateless derivation, and a higher-level write for a level
// exactly when its publication deadline falls on the block. The derived
// higher-level roots must equal the roots of the indexer's merged tables.
func TestDeriveTableWritesSchedule(t *testing.T) {
	resetDerivedRoots()
	f := newTestFeed(600)
	ix := NewMemoryIndexer()
	defer ix.Stop()
	for i := 1; i <= 600; i++ {
		ix.AddBlockData(f.headers[i], &types.Body{}, f.receipts[i])
	}
	waitIdle(t, ix)

	var compared int
	for i := 1; i <= 600; i++ {
		writes, err := DeriveTableWrites(feedChain{f}, alwaysActive, uint64(i), f.headers[i].ParentHash, f.receipts[i])
		if err != nil {
			t.Fatalf("block %d: %v", i, err)
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
			if write == nil {
				continue
			}
			if write.FirstBlock != first {
				t.Errorf("block %d: level %d write first_block %d, want %d", i, level, write.FirstBlock, first)
			}
			tr, err := ix.storage.getTableReader(tableID{level: level, index: first / size})
			if err != nil {
				continue // not merged by the background scheduler
			}
			if tr.TableRoot != write.Root {
				t.Errorf("block %d: level %d derived root %x, merged table root %x", i, level, write.Root, tr.TableRoot)
			}
			compared++
		}
	}
	if compared < 10 {
		t.Errorf("only %d derived roots were compared with merged tables", compared)
	}
}

// TestDeriveTableWritesPurity pins that the writes depend on nothing but the
// ancestry: other history gives other roots, an inactive first block
// suppresses the table, and a due table without reachable history is an error
// rather than a silently missing write.
func TestDeriveTableWritesPurity(t *testing.T) {
	resetDerivedRoots()
	// block 575 publishes the 256-block table starting at block 256 (and the
	// smaller tables that fall due there)
	const number = 575
	f := newTestFeed(600)
	parent, receipts := f.headers[number].ParentHash, f.receipts[number]
	top := func(w []TableWrite) TableWrite { return w[len(w)-1] }

	base, err := DeriveTableWrites(feedChain{f}, alwaysActive, number, parent, receipts)
	if err != nil {
		t.Fatal(err)
	}
	if got := top(base); got.TableSize != 256 || got.FirstBlock != 256 {
		t.Fatalf("top write %+v, want the 256-block table at 256", got)
	}
	again, _ := DeriveTableWrites(feedChain{f}, alwaysActive, number, parent, receipts)
	if len(again) != len(base) || top(again) != top(base) {
		t.Fatalf("derivation is not deterministic")
	}

	resetDerivedRoots()
	// other receipts inside the covered range change the root
	g := newTestFeed(600)
	g.receipts[300] = testReceipts(9999)
	forked, err := DeriveTableWrites(feedChain{g}, alwaysActive, number, parent, receipts)
	if err != nil {
		t.Fatal(err)
	}
	if top(forked).Root == top(base).Root {
		t.Error("history with other receipts gave the same root")
	}

	resetDerivedRoots()
	// activation after the first block drops the higher-level tables
	late := func(h *types.Header) bool { return h.Number.Uint64() > 256 }
	w, err := DeriveTableWrites(feedChain{f}, late, number, parent, receipts)
	if err != nil {
		t.Fatal(err)
	}
	for _, tw := range w {
		if tw.TableSize == 256 {
			t.Errorf("table published although the fork was inactive at its first block")
		}
	}

	// no ancestry at all: fail closed
	if _, err := DeriveTableWrites(nil, alwaysActive, number, parent, receipts); !errors.Is(err, ErrNoAncestry) {
		t.Errorf("missing ancestry: error %v, want ErrNoAncestry", err)
	}
	resetDerivedRoots()
	// unreachable history (a hole in the receipts): fail closed
	h := newTestFeed(600)
	h.receipts[300] = nil
	if _, err := DeriveTableWrites(missingReceipts{feedChain{h}, 300}, alwaysActive, number, parent, receipts); err == nil {
		t.Error("missing receipts did not fail the derivation")
	}
	// a block that does not follow the parent chain: fail closed
	if _, err := DeriveTableWrites(feedChain{f}, alwaysActive, number, common.Hash{1}, receipts); err == nil {
		t.Error("unknown parent did not fail the derivation")
	}
}

type missingReceipts struct {
	feedChain
	number uint64
}

func (m missingReceipts) GetIndexReceipts(hash common.Hash, number uint64) (types.Receipts, error) {
	if number == m.number {
		return nil, errors.New("receipts pruned")
	}
	return m.feedChain.GetIndexReceipts(hash, number)
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
		readers := ix.storage.getRangeReaders(r, 0)
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

// TestGetRangeReadersPublicationFilter pins that the decomposition restricted
// to tables published by a given block stays contiguous: the unpublished
// higher-level ranges are covered by the published lower-level tables.
func TestGetRangeReadersPublicationFilter(t *testing.T) {
	f := newTestFeed(600)
	ix := NewMemoryIndexer()
	defer ix.Stop()

	for i := 1; i <= 600; i++ {
		ix.AddBlockData(f.headers[i], &types.Body{}, f.receipts[i])
	}
	waitIdle(t, ix)

	r := common.NewRange[uint64](1, 500)
	readers := ix.storage.getRangeReaders(r, 500)
	cover := make([]common.Range[uint64], 0, len(readers))
	for _, tr := range readers {
		br := tr.BlockRange()
		if PublicationSchedule(br.Count(), br.First()) > 500 {
			t.Errorf("table [%d..%d) published after the filter", br.First(), br.AfterLast())
		}
		cover = append(cover, br)
	}
	sort.Slice(cover, func(i, j int) bool { return cover[i].First() < cover[j].First() })
	for i := 1; i < len(cover); i++ {
		if cover[i].First() != cover[i-1].AfterLast() {
			t.Errorf("gap between %v and %v", cover[i-1], cover[i])
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
			t.Fatalf("block %d not covered by published tables", b)
		}
	}
}

// TestBackfillMissingBlocks pins that a hole below the index head is reported
// and repaired without moving the head.
func TestBackfillMissingBlocks(t *testing.T) {
	f := newTestFeed(100)
	ix := NewMemoryIndexer()
	defer ix.Stop()
	for i := 1; i <= 100; i++ {
		if i == 50 {
			continue
		}
		ix.AddBlockData(f.headers[i], &types.Body{}, f.receipts[i])
	}
	waitIdle(t, ix)
	missing := ix.MissingBlocks()
	if missing.Count() != 1 || !missing.Includes(50) {
		t.Fatalf("missing blocks %v, want {50}", missing)
	}
	ix.Backfill(f.headers[50], f.receipts[50])
	waitIdle(t, ix)
	if !ix.MissingBlocks().IsEmpty() {
		t.Fatalf("still missing %v after backfill", ix.MissingBlocks())
	}
	if ix.HeadBlock() != 100 {
		t.Errorf("backfill moved the head to %d", ix.HeadBlock())
	}
	coverageGaps(t, ix, 1, 101)
}
