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
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
)

// bigTestEntries derives a large sorted entry set (several thousand entries,
// enough for the file writer's copy phase to span multiple copy steps).
func bigTestEntries() (common.Hash, []types.IndexEntry) {
	var parent common.Hash
	parent[0] = 0xab
	receipts := make(types.Receipts, 3)
	for i := range receipts {
		logs := make([]*types.Log, 800)
		for j := range logs {
			logs[j] = &types.Log{
				Address: common.HexToAddress("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"),
				Topics:  []common.Hash{{byte(i), byte(j)}},
			}
		}
		receipts[i] = &types.Receipt{Logs: logs}
	}
	return parent, blockEntries(1, parent, receipts)
}

// TestFileTableCrashResume writes a large file table, interrupting the write
// once in the entry-writing phase and once in the final copy phase, and pins
// that both resumes produce a table identical to an uninterrupted oracle.
func TestFileTableCrashResume(t *testing.T) {
	parent, entries := bigTestEntries()
	params := DefaultParams()
	meta := TableMeta{
		LastBlockNumber: 1,
		BlockCount:      1,
		LastBlockHash:   common.Hash{1},
		ParentHash:      parent,
	}
	writeAndVerify := func(interrupt func(tw *tableWriter, added int) (stop bool, addedNow int)) {
		tf, err := newTableFiles(t.TempDir(), 2000000000, 96)
		if err != nil {
			t.Fatal(err)
		}
		defer tf.close()
		name := params.tableName(tableID{level: 0, index: 1})
		tw, err := newFileTableWriter(params, tf, name, false, uint64(len(entries)), false)
		if err != nil {
			t.Fatal(err)
		}
		if err := tw.open(); err != nil {
			t.Fatal(err)
		}
		added := 0
		stop, addedNow := interrupt(tw, 0)
		added = addedNow
		if stop {
			// persist the interrupted state and reopen from it
			if err := tw.close(); err != nil {
				t.Fatal(err)
			}
			tw, err = newFileTableWriter(params, tf, name, true, 0, false)
			if err != nil {
				t.Fatal(err)
			}
			if err := tw.open(); err != nil {
				t.Fatal(err)
			}
		}
		for i := added; i < len(entries); i++ {
			if err := tw.addEntry(entries[i]); err != nil {
				t.Fatal(err)
			}
		}
		// A resumed copy-phase writer already carries its metadata in the
		// persisted state; only a writer still in the entry phase needs it.
		if tw.getPhase() == wpWriteEntries {
			tw.setMeta(meta)
		}
		for {
			done, err := tw.finalize()
			if err != nil {
				t.Fatal(err)
			}
			if done {
				break
			}
		}
		if tw.getPhase() != wpFinalized {
			t.Fatalf("phase = %d, want finalized", tw.getPhase())
		}
		tr, err := newTableReader(params, tf, name)
		if err != nil {
			t.Fatal(err)
		}
		if tr.EntryCount != uint64(len(entries)) {
			t.Fatalf("entry count = %d, want %d", tr.EntryCount, len(entries))
		}
		if want := types.IndexTableRoot(entries); tr.TableRoot != want {
			t.Fatalf("root %x, want %x", tr.TableRoot, want)
		}
		for i, want := range entries {
			got, err := tr.GetEntry(uint64(i))
			if err != nil {
				t.Fatalf("entry %d: %v", i, err)
			}
			if types.CompareEntries(got, want) != 0 {
				t.Fatalf("entry %d mismatch", i)
			}
		}
		// Tree node hashes must match the flat derivation at sampled indices.
		for _, gti := range []uint64{1, 2, 3, 17, 1 << 8, 1 << 11} {
			want, err := types.MerkleNodeHash(entries, gti)
			if err != nil {
				continue // index outside this tree
			}
			got, err := tr.GetHash(gti)
			if err != nil {
				t.Fatalf("hash at %d: %v", gti, err)
			}
			if got != want {
				t.Fatalf("node hash at %d: %x, want %x", gti, got, want)
			}
		}
	}
	// Uninterrupted oracle.
	writeAndVerify(func(tw *tableWriter, added int) (bool, int) { return false, added })
	// Interrupted while writing entries.
	writeAndVerify(func(tw *tableWriter, added int) (bool, int) {
		for i := added; i < len(entries)/2; i++ {
			if err := tw.addEntry(entries[i]); err != nil {
				t.Fatal(err)
			}
		}
		return true, len(entries) / 2
	})
	// Interrupted while copying the final layout (>64KB forces a partial copy
	// step, so the first finalize call returns with more work pending).
	writeAndVerify(func(tw *tableWriter, added int) (bool, int) {
		for i := added; i < len(entries); i++ {
			if err := tw.addEntry(entries[i]); err != nil {
				t.Fatal(err)
			}
		}
		tw.setMeta(meta)
		done, err := tw.finalize()
		if err != nil {
			t.Fatal(err)
		}
		return !done, len(entries)
	})
}

// TestRestartChainOfCustody persists tables, corrupts one table's metadata,
// restarts with a canonical hash source and pins that exactly the corrupted
// table is dropped while everything else validates.
func TestRestartChainOfCustody(t *testing.T) {
	f := newTestFeed(40)
	path := t.TempDir()
	canonical := make(map[uint64]common.Hash)
	for i := 1; i <= 40; i++ {
		canonical[uint64(i)] = f.headers[i].Hash()
	}
	build := func() {
		ix, err := NewIndexer(DefaultParams(), Config{BlockHashAt: func(n uint64) common.Hash { return canonical[n] }}, path)
		if err != nil {
			t.Fatal(err)
		}
		for i := 1; i <= 40; i++ {
			ix.AddBlockData(f.headers[i], &types.Body{}, f.receipts[i])
		}
		waitIdle(t, ix)
		ix.Stop()
	}
	build()

	// Tables below the file storage threshold (entry counts under 4096) are
	// memory-backed and persist in the small tables file. Corrupt the meta of
	// one of them there: decode the small tables blob, flip the stored block
	// hash of level-0 table 20 and write the file back.
	tableName := DefaultParams().tableName(tableID{level: 0, index: 20})
	blob, err := os.ReadFile(filepath.Join(path, memFileName))
	if err != nil {
		t.Fatal(err)
	}
	var memTables []storedMemTable
	if err := rlp.DecodeBytes(blob, &memTables); err != nil {
		t.Fatal(err)
	}
	corrupted := false
	for i, mt := range memTables {
		if mt.Name != tableName {
			continue
		}
		headerLen := int(mt.Data[len(mt.Data)-1])
		var header tableHeader
		if err := rlp.DecodeBytes(mt.Data[len(mt.Data)-1-headerLen:len(mt.Data)-1], &header); err != nil {
			t.Fatal(err)
		}
		header.Meta.LastBlockHash = common.Hash{0xff}
		newHeader, err := rlp.EncodeToBytes(&header)
		if err != nil {
			t.Fatal(err)
		}
		memTables[i].Data = append(mt.Data[:len(mt.Data)-1-headerLen], append(newHeader, byte(len(newHeader)))...)
		corrupted = true
	}
	if !corrupted {
		t.Fatalf("corruption target %s not found in small tables", tableName)
	}
	out, err := rlp.EncodeToBytes(&memTables)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, memFileName), out, 0644); err != nil {
		t.Fatal(err)
	}

	ix, err := NewIndexer(DefaultParams(), Config{BlockHashAt: func(n uint64) common.Hash { return canonical[n] }}, path)
	if err != nil {
		t.Fatal(err)
	}
	defer ix.Stop()
	kickIndexer(t, ix)
	waitIdle(t, ix)
	complete, partial, _ := ix.storage.tables()
	t.Logf("after restart: complete=%v partial=%v", complete, partial)

	if _, err := ix.storage.getTableReader(tableID{level: 0, index: 20}); err == nil {
		t.Error("corrupted table survived startup validation")
	}
	for i := 1; i <= 40; i++ {
		if i == 20 {
			continue
		}
		if _, err := ix.storage.getTableReader(tableID{level: 0, index: uint64(i)}); err != nil {
			t.Errorf("level-0 table %d: %v", i, err)
		}
	}
	for i := uint64(1); i <= 9; i++ {
		if _, err := ix.storage.getTableReader(tableID{level: 1, index: i}); err != nil {
			t.Errorf("level-1 table %d: %v", i, err)
		}
	}
}

// TestReorgWithPendingMerge starts a merge, aborts it mid-way leaving a
// partial writer, and pins that a reorg amputation removes it together with
// its sources.
func TestReorgWithPendingMerge(t *testing.T) {
	f := newTestFeed(40)
	ix := NewMemoryIndexer()
	defer ix.Stop()

	for i := 1; i <= 40; i++ {
		ix.AddBlockData(f.headers[i], &types.Body{}, f.receipts[i])
	}
	waitIdle(t, ix)

	// Start a merge that aborts immediately, leaving a partial writer.
	id := tableID{level: 1, index: 1}
	if _, err := ix.mergeTable(id, func() bool { return true }); err != nil {
		t.Fatal(err)
	}
	_, partial, _ := ix.storage.tables()
	if !partial.includes(id) {
		t.Fatal("aborted merge left no partial writer")
	}

	// Reorg below the merge range: the partial writer must be amputated.
	ix.Revert(f.headers[5])
	waitIdle(t, ix)
	_, partial, _ = ix.storage.tables()
	if partial.includes(id) {
		t.Error("partial writer survived reorg amputation")
	}
	complete, _, _ := ix.storage.tables()
	for _, r := range complete[1] {
		if r.Last() >= 5 {
			t.Errorf("table range %v survives reorg to 5", r)
		}
	}
}

// TestMemTableFlush pins that memory-backed level-0 tables survive a shutdown
// and restart via the small tables file, and validate against the chain.
func TestMemTableFlush(t *testing.T) {
	f := newTestFeed(10)
	path := t.TempDir()
	canonical := make(map[uint64]common.Hash)
	for i := 1; i <= 10; i++ {
		canonical[uint64(i)] = f.headers[i].Hash()
	}
	config := Config{BlockHashAt: func(n uint64) common.Hash { return canonical[n] }}

	ix, err := NewIndexer(DefaultParams(), config, path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 10; i++ {
		ix.AddBlockData(f.headers[i], &types.Body{}, f.receipts[i])
	}
	waitIdle(t, ix)
	ix.Stop()

	ix, err = NewIndexer(DefaultParams(), config, path)
	if err != nil {
		t.Fatal(err)
	}
	defer ix.Stop()
	kickIndexer(t, ix)
	waitIdle(t, ix)
	for i := 1; i <= 10; i++ {
		tr, err := ix.storage.getTableReader(tableID{level: 0, index: uint64(i)})
		if err != nil {
			t.Fatalf("table %d: %v", i, err)
		}
		if tr.Meta.LastBlockHash != canonical[uint64(i)] {
			t.Errorf("table %d: meta hash %x, want %x", i, tr.Meta.LastBlockHash, canonical[uint64(i)])
		}
	}
}
