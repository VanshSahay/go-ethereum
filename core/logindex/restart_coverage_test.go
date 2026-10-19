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

// coverageGaps checks that the complete tables cover [first..afterLast)
// without holes.
func coverageGaps(t *testing.T, ix *Indexer, first, afterLast uint64) {
	t.Helper()
	readers := ix.storage.getRangeReaders(common.NewRange[uint64](first, afterLast-first), 0)
	cover := make([]common.Range[uint64], 0, len(readers))
	for _, tr := range readers {
		cover = append(cover, tr.BlockRange())
	}
	sort.Slice(cover, func(i, j int) bool { return cover[i].First() < cover[j].First() })
	next := first
	for _, c := range cover {
		if c.First() > next {
			t.Errorf("coverage gap [%d..%d)", next, c.First())
		}
		if c.AfterLast() > next {
			next = c.AfterLast()
		}
	}
	if next < afterLast {
		t.Errorf("coverage ends at %d, want %d", next, afterLast)
	}
}

// TestRestartGraceful pins that a stopped and reloaded file indexer keeps the
// full coverage of its persisted tables and keeps indexing where it left off.
func TestRestartGraceful(t *testing.T) {
	path := t.TempDir()
	f := newTestFeed(400)
	canonical := func(n uint64) common.Hash { return f.headers[n].Hash() }

	ix, err := NewIndexer(DefaultParams(), Config{BlockHashAt: canonical}, path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 300; i++ {
		ix.AddBlockData(f.headers[i], &types.Body{}, f.receipts[i])
	}
	waitIdle(t, ix)
	ix.Stop()

	ix2, err := NewIndexer(DefaultParams(), Config{BlockHashAt: canonical}, path)
	if err != nil {
		t.Fatal(err)
	}
	defer ix2.Stop()
	kickIndexer(t, ix2)
	for i := 301; i <= 400; i++ {
		ix2.AddBlockData(f.headers[i], &types.Body{}, f.receipts[i])
	}
	waitIdle(t, ix2)
	coverageGaps(t, ix2, 1, 401)
}

// TestRestartAfterCrash pins that the periodic in-memory table flush bounds
// the loss of an unclean shutdown: everything flushed before the crash stays
// queryable after the reload.
func TestRestartAfterCrash(t *testing.T) {
	path := t.TempDir()
	f := newTestFeed(300)
	canonical := func(n uint64) common.Hash { return f.headers[n].Hash() }

	ix, err := NewIndexer(DefaultParams(), Config{BlockHashAt: canonical}, path)
	if err != nil {
		t.Fatal(err)
	}
	// abandoned without Stop, like a crashed process: only the periodically
	// flushed memory tables survive
	for i := 1; i <= 300; i++ {
		ix.AddBlockData(f.headers[i], &types.Body{}, f.receipts[i])
	}

	ix2, err := NewIndexer(DefaultParams(), Config{BlockHashAt: canonical}, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ix2.Stop()
		ix.Stop()
	}()
	kickIndexer(t, ix2)
	// the flush threshold guarantees at least two full flushes worth of
	// level-0 tables
	coverageGaps(t, ix2, 1, 129)
}
