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
	"encoding/binary"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// testFeed generates a deterministic chain of headers and receipts for tests.
type testFeed struct {
	headers  []*types.Header
	receipts []types.Receipts
}

func newTestFeed(blocks int) *testFeed {
	f := &testFeed{headers: make([]*types.Header, blocks+1), receipts: make([]types.Receipts, blocks+1)}
	parent := common.Hash{}
	for i := 1; i <= blocks; i++ {
		header := &types.Header{
			Number:     big.NewInt(int64(i)),
			ParentHash: parent,
			Time:       uint64(i),
		}
		f.headers[i] = header
		f.receipts[i] = testReceipts(uint64(i))
		parent = header.Hash()
	}
	return f
}

func testReceipts(block uint64) types.Receipts {
	count := int(block%3) + 1
	receipts := make(types.Receipts, count)
	for i := range receipts {
		var txHash common.Hash
		binary.BigEndian.PutUint64(txHash[24:], block*100+uint64(i))
		logs := []*types.Log{
			{
				Address: common.HexToAddress("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"),
				Topics: []common.Hash{
					common.HexToHash("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"),
					{byte(block), byte(i)},
				},
			},
		}
		if block%2 == 0 {
			logs = append(logs, &types.Log{
				Address: common.HexToAddress("0xdac17f958d2ee523a2206206994597c13d831ec7"),
			})
		}
		receipts[i] = &types.Receipt{TxHash: txHash, Logs: logs}
	}
	return receipts
}

// kickIndexer drives the indexer past startup validation and schedules the
// first operations, standing in for the chain feed after a restart.
func kickIndexer(t *testing.T, ix *Indexer) {
	t.Helper()
	ix.lock.Lock()
	defer ix.lock.Unlock()
	for range 100 {
		_, _, initPhase := ix.storage.tables()
		if !initPhase {
			ix.updateTableOperations()
			return
		}
		ix.deliverInitBlock()
	}
	t.Fatal("indexer startup validation did not complete")
}

// waitIdle blocks until the indexer is quiescent: no operation is running or
// scheduled, no partial writers remain, and the scheduler has no more work.
func waitIdle(t *testing.T, ix *Indexer) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		ix.lock.Lock()
		idle := true
		for _, op := range ix.currentOps {
			if op.operation != opNone {
				idle = false
			}
		}
		pending := !idle
		if idle {
			complete, partial, _ := ix.storage.tablesLocked()
			if !partial.isEmpty() {
				pending = true
			} else {
				target := ix.makeTargetSet(complete)
				nextOps, _ := ix.params.nextTableOperations(complete, partial, target, ix.mergeThreads, ix.mergeThreads)
				pending = len(nextOps) > 0
			}
		}
		ix.lock.Unlock()
		if !pending {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("indexer did not become idle")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestNextTableOperationsCascade(t *testing.T) {
	p := DefaultParams()
	complete, partial, target := p.newTableSet(), p.newTableSet(), p.newTableSet()
	for i := uint64(0); i < 10; i++ {
		complete.add(tableID{level: 0, index: i})
		target.add(tableID{level: 0, index: i})
	}
	target.add(tableID{level: 1, index: 0})
	target.add(tableID{level: 1, index: 1})
	target.add(tableID{level: 2, index: 0})

	// Ten complete level-0 tables, targets requiring two level-1 tables and
	// one level-2 table: the newest merge destination is scheduled first.
	ops, required := p.nextTableOperations(complete, partial, target, 4, 4)
	if len(ops) != 2 {
		t.Fatalf("operations = %v, want two merges", ops)
	}
	if ops[0].operation != opMerge || ops[0].id != (tableID{level: 1, index: 1}) {
		t.Errorf("ops[0] = %v, want merge to level 1 index 1", ops[0])
	}
	if ops[1].operation != opMerge || ops[1].id != (tableID{level: 1, index: 0}) {
		t.Errorf("ops[1] = %v, want merge to level 1 index 0", ops[1])
	}
	// Blocks 10..15 are required by the targeted level-2 table [0..16) but
	// not yet indexed: they are the residual demand.
	if want := (common.RangeSet[uint64])([]common.Range[uint64]{common.NewRange[uint64](10, 6)}); !required.Equal(want) {
		t.Errorf("required = %v, want %v", required, want)
	}

	// Shrinking the target range makes the newest level-0 tables deletable,
	// and a delete is scheduled before any merge.
	target2 := p.newTableSet()
	for i := uint64(0); i < 6; i++ {
		target2.add(tableID{level: 0, index: i})
	}
	ops, _ = p.nextTableOperations(complete, partial, target2, 4, 4)
	if ops[0].operation != opDelete || ops[0].id != (tableID{level: 0, index: 9}) {
		t.Errorf("ops[0] = %v, want delete of level 0 index 9", ops[0])
	}
}

func TestMergeTableAgainstSingleWriterOracle(t *testing.T) {
	f := newTestFeed(40)
	ix := NewMemoryIndexer()
	defer ix.Stop()

	for i := 1; i <= 40; i++ {
		ix.AddBlockData(f.headers[i], &types.Body{}, f.receipts[i])
	}
	waitIdle(t, ix)

	// Every completed level-1 and level-2 table must hold exactly the entries
	// and root that a single IndexBuilder over the same block range yields.
	checkAgainstOracle := func(level int, index uint64) {
		id := tableID{level: level, index: index}
		tr, err := ix.storage.getTableReader(id)
		if err != nil {
			t.Fatalf("table %v: %v", id, err)
		}
		r := ix.params.blockRange(id)
		b := types.NewIndexBuilder()
		for bn := r.First(); bn <= r.Last(); bn++ {
			b.AddBlockEntries(f.headers[bn].ParentHash, bn, f.receipts[bn])
		}
		wantRoot := b.Build()
		if tr.TableRoot != wantRoot {
			t.Errorf("table %v: root %x, want %x", id, tr.TableRoot, wantRoot)
		}
		wantEntries := b.Entries()
		if tr.EntryCount != uint64(len(wantEntries)) {
			t.Fatalf("table %v: %d entries, want %d", id, tr.EntryCount, len(wantEntries))
		}
		for i, want := range wantEntries {
			got, err := tr.GetEntry(uint64(i))
			if err != nil {
				t.Fatalf("table %v: entry %d: %v", id, i, err)
			}
			if types.CompareEntries(got, want) != 0 {
				t.Errorf("table %v: entry %d mismatch", id, i)
			}
		}
	}
	// Tables fully covered by the 40-block feed (level index 0 would contain
	// the never-indexed genesis block).
	for index := uint64(1); index <= 9; index++ {
		checkAgainstOracle(1, index)
	}
	checkAgainstOracle(2, 1)
}

func TestMergeMetaChain(t *testing.T) {
	f := newTestFeed(64)
	ix := NewMemoryIndexer()
	defer ix.Stop()

	for i := 1; i <= 64; i++ {
		ix.AddBlockData(f.headers[i], &types.Body{}, f.receipts[i])
	}
	waitIdle(t, ix)

	// A level-2 table covers 16 blocks; its metadata must pin the exact chain
	// segment: ending at the newest covered block's hash and starting right
	// after the oldest covered block. Level-2 index 1 covers blocks 16..31.
	tr, err := ix.storage.getTableReader(tableID{level: 2, index: 1})
	if err != nil {
		t.Fatal(err)
	}
	if tr.Meta.BlockCount != 16 || tr.Meta.LastBlockNumber != 31 {
		t.Errorf("meta = %+v, want blocks [16..31]", tr.Meta)
	}
	if tr.Meta.LastBlockHash != f.headers[31].Hash() {
		t.Errorf("LastBlockHash = %x, want hash of block 31", tr.Meta.LastBlockHash)
	}
	if tr.Meta.ParentHash != f.headers[15].Hash() {
		t.Errorf("ParentHash = %x, want hash of block 15 (parent of block 16)", tr.Meta.ParentHash)
	}
}

func TestSchedulerConvergence(t *testing.T) {
	f := newTestFeed(600)
	ix := NewMemoryIndexer()
	defer ix.Stop()

	for i := 1; i <= 600; i++ {
		ix.AddBlockData(f.headers[i], &types.Body{}, f.receipts[i])
	}
	waitIdle(t, ix)

	// Every fully covered range at every level must have been merged. Level
	// index 0 contains the genesis block and is never built; the last range
	// at each level is incomplete at 600 blocks.
	ix.lock.Lock()
	complete, _, _ := ix.storage.tablesLocked()
	ix.lock.Unlock()
	wantCounts := map[int]uint64{1: 149, 2: 36, 3: 8, 4: 1}
	for level := 1; level <= 4; level++ {
		want := wantCounts[level]
		if got := complete[level].Count(); got != want {
			t.Errorf("level %d: %d complete tables, want %d", level, got, want)
		}
		for index := uint64(1); index <= want; index++ {
			if !complete[level].Includes(index) {
				t.Fatalf("level %d: table %d missing", level, index)
			}
		}
	}
}

func TestReorgAmputation(t *testing.T) {
	f := newTestFeed(40)
	ix := NewMemoryIndexer()
	defer ix.Stop()

	for i := 1; i <= 40; i++ {
		ix.AddBlockData(f.headers[i], &types.Body{}, f.receipts[i])
	}
	waitIdle(t, ix)

	// Reorg to block 33: every table whose range reaches block 34 or beyond
	// is amputated at all levels, and the remaining pyramid must still cover
	// every block up to the new head's parent.
	ix.Revert(f.headers[33])
	waitIdle(t, ix)

	ix.lock.Lock()
	complete, _, _ := ix.storage.tablesLocked()
	ix.lock.Unlock()
	covered := make(map[uint64]bool)
	for level := range TableSizes {
		for _, r := range complete[level] {
			if r.Last() >= 34 {
				t.Errorf("level %d: table range %v survives reorg to 33", level, r)
			}
			for b := r.First(); b <= r.Last(); b++ {
				covered[b] = true
			}
		}
	}
	for b := uint64(1); b <= 32; b++ {
		if !covered[b] {
			t.Fatalf("block %d not covered by any table after reorg", b)
		}
	}
}

func TestEmptyTableWriter(t *testing.T) {
	tw, err := newMemoryTableWriter(DefaultParams(), 0)
	if err != nil {
		t.Fatal(err)
	}
	tw.setMeta(TableMeta{LastBlockNumber: 0, BlockCount: 1})
	done, err := tw.finalize()
	if err != nil || !done {
		t.Fatalf("finalize = %v, %v", done, err)
	}
	if tw.getTableRoot() != ([32]byte{}) {
		t.Errorf("empty table root = %x, want the zero hash", tw.getTableRoot())
	}
}
