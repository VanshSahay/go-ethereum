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
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// errTableNotFound is returned when no complete table or partial writer exists
// under the given id.
var errTableNotFound = errors.New("index table not found")

// tableStorage holds the registry of complete tables and in-progress writers.
// It is shared between the block feed and the merge loop; every method takes
// the internal lock. The memory version keeps everything in RAM; the file
// backed version added later persists the same structures.
type tableStorage struct {
	lock     sync.Mutex
	params   *Params
	readers  map[tableID]*TableReader
	writers  map[tableID]*tableWriter
	complete tableSet
	partial  tableSet
}

func newTableStorage(params *Params) *tableStorage {
	return &tableStorage{
		params:   params,
		readers:  make(map[tableID]*TableReader),
		writers:  make(map[tableID]*tableWriter),
		complete: params.newTableSet(),
		partial:  params.newTableSet(),
	}
}

// tables returns cloned snapshots of the complete and partial sets. The caller
// may mutate the clones freely.
func (ts *tableStorage) tables() (tableSet, tableSet) {
	ts.lock.Lock()
	defer ts.lock.Unlock()

	return ts.tablesLocked()
}

// needs ts.lock
func (ts *tableStorage) tablesLocked() (tableSet, tableSet) {
	complete, partial := ts.params.newTableSet(), ts.params.newTableSet()
	for level := range ts.complete {
		complete[level] = ts.complete[level]
		partial[level] = ts.partial[level]
	}
	return complete, partial
}

// addNewTableWriter creates a writer for a table with the given predetermined
// entry count and registers it as partial.
func (ts *tableStorage) addNewTableWriter(id tableID, entryCount uint64) (*tableWriter, error) {
	ts.lock.Lock()
	defer ts.lock.Unlock()

	return ts.addNewTableWriterLocked(id, entryCount)
}

// needs ts.lock
func (ts *tableStorage) addNewTableWriterLocked(id tableID, entryCount uint64) (*tableWriter, error) {
	if _, ok := ts.readers[id]; ok {
		return nil, errors.New("complete table already exists")
	}
	if _, ok := ts.writers[id]; ok {
		return nil, errors.New("table writer already exists")
	}
	tw, err := newMemoryTableWriter(ts.params, entryCount)
	if err != nil {
		return nil, err
	}
	ts.writers[id] = tw
	ts.partial.add(id)
	return tw, nil
}

// getTableWriter returns an existing partial writer without any locking.
func (ts *tableStorage) getTableWriter(id tableID) (*tableWriter, error) {
	ts.lock.Lock()
	defer ts.lock.Unlock()

	tw, ok := ts.writers[id]
	if !ok {
		return nil, errTableNotFound
	}
	return tw, nil
}

// releaseTableWriter releases a writer after an interrupted merge. The memory
// version keeps the partial writer registered for later resumption.
func (ts *tableStorage) releaseTableWriter(id tableID) error {
	ts.lock.Lock()
	defer ts.lock.Unlock()

	if _, ok := ts.writers[id]; !ok {
		return errTableNotFound
	}
	return nil
}

// getTableReader returns the reader of a complete table.
func (ts *tableStorage) getTableReader(id tableID) (*TableReader, error) {
	ts.lock.Lock()
	defer ts.lock.Unlock()

	tr, ok := ts.readers[id]
	if !ok {
		return nil, errTableNotFound
	}
	return tr, nil
}

// finalizeTableWriter turns a finalized writer into a complete reader.
func (ts *tableStorage) finalizeTableWriter(id tableID) error {
	ts.lock.Lock()
	defer ts.lock.Unlock()

	tw, ok := ts.writers[id]
	if !ok {
		return errTableNotFound
	}
	if tw.getPhase() != wpFinalized {
		return errors.New("table writer is not finalized")
	}
	delete(ts.writers, id)
	ts.partial.remove(id)
	ts.readers[id] = newMemoryTableReader(tw.entries, tw.tableRoot, tw.meta)
	ts.complete.add(id)
	return nil
}

// deleteTable removes a complete table or an in-progress writer.
func (ts *tableStorage) deleteTable(id tableID) error {
	ts.lock.Lock()
	defer ts.lock.Unlock()

	return ts.deleteTableLocked(id)
}

// needs ts.lock
func (ts *tableStorage) deleteTableLocked(id tableID) error {
	if _, ok := ts.readers[id]; ok {
		delete(ts.readers, id)
		ts.complete.remove(id)
		return nil
	}
	if _, ok := ts.writers[id]; ok {
		delete(ts.writers, id)
		ts.partial.remove(id)
		return nil
	}
	return errTableNotFound
}

// deleteTablesFromBlock amputates every table whose block range reaches the
// given block number or beyond, at all levels. This is the reorg cleanup
// primitive: everything indexed from blockNumber on may belong to a
// non-canonical chain segment.
func (ts *tableStorage) deleteTablesFromBlock(blockNumber uint64) {
	ts.lock.Lock()
	defer ts.lock.Unlock()

	ts.deleteTablesFromBlockLocked(blockNumber)
}

// needs ts.lock
func (ts *tableStorage) deleteTablesFromBlockLocked(blockNumber uint64) {
	for i := range ts.params.tableLevels {
		for {
			rs := ts.complete[i].Union(ts.partial[i])
			if rs.IsEmpty() {
				break
			}
			id := tableID{level: i, index: rs.Last()}
			if ts.params.blockRange(id).Last() < blockNumber {
				break
			}
			if err := ts.deleteTableLocked(id); err != nil {
				break
			}
		}
	}
}

// blockEntries derives the EIP-8304 entries of a single block: the parent
// block's block entry (one-block delay, none for genesis), one transaction
// entry per receipt carrying the cumulative log count of the block before the
// transaction, and per-log address and topic entries with tx-relative log
// indices. Entries are returned sorted.
func blockEntries(blockNumber uint64, parentHash common.Hash, receipts types.Receipts) []types.IndexEntry {
	b := types.NewIndexBuilder()
	b.AddBlockEntries(parentHash, blockNumber, receipts)
	entries := b.Entries()
	sort.Slice(entries, func(i, j int) bool {
		return types.CompareEntries(entries[i], entries[j]) < 0
	})
	return entries
}
