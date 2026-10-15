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
	"fmt"
	"math"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
)

const (
	maxOpenWriters   = 8
	writeStateSuffix = ".state"
)

// errTableNotFound is returned when no complete table or partial writer exists
// under the given id.
var errTableNotFound = errors.New("index table not found")

// tableStorage holds the registry of complete tables and in-progress writers.
// It is shared between the block feed and the merge loop; every method takes
// the internal lock. In memory mode (tf == nil) tables live in RAM only.
type tableStorage struct {
	lock                       sync.Mutex
	params                     *Params
	tf                         *tableFiles
	readers                    map[tableID]*TableReader
	writers                    map[tableID]tableWriterImpl
	triggers                   map[tableID]chan struct{}
	lockedWriters              map[tableWriterImpl]chan struct{}
	unlockedOpenWriters        map[tableWriterImpl]uint64
	openWriterCounter          uint64
	complete, partial, preInit tableSet
	initRequest                bool
	initNumber                 uint64
}

func writeTempSuffix(level uint) string {
	return fmt.Sprintf(".temp_%02x", level)
}

func newTableStorage(params *Params) *tableStorage {
	return &tableStorage{
		params:              params,
		readers:             make(map[tableID]*TableReader),
		writers:             make(map[tableID]tableWriterImpl),
		triggers:            make(map[tableID]chan struct{}),
		lockedWriters:       make(map[tableWriterImpl]chan struct{}),
		unlockedOpenWriters: make(map[tableWriterImpl]uint64),
		complete:            params.newTableSet(),
		partial:             params.newTableSet(),
	}
}

// newTableStorageFromFiles loads persisted tables and partial write states
// from the file layer. All loaded tables start out in the preInit set: their
// metadata may belong to a non-canonical chain segment until the startup
// chain-of-custody validation walks their hash chain against a known block.
func newTableStorageFromFiles(params *Params, tf *tableFiles) (*tableStorage, error) {
	ts := newTableStorage(params)
	ts.tf = tf
	ts.preInit = params.newTableSet()
	allFiles := tf.allFiles()
loop:
	for _, name := range allFiles {
		ftype, id, _ := params.parseFileName(name)
		switch ftype {
		case fnUnknown:
			log.Warn("Unexpected index table file", "name", name)
			tf.deleteFile(name)
		case fnTable:
			reader, err := newTableReader(params, tf, params.tableName(id))
			if err != nil {
				log.Error("Invalid index table file", "name", params.tableName(id), "error", err)
				tf.deleteFile(name)
				continue loop
			}
			ts.readers[id] = reader
		case fnWriteState:
			writer, err := newFileTableWriter(params, tf, params.tableName(id), true, 0, id.level == 0)
			if err != nil {
				log.Error("Invalid partial index table file", "name", params.tableName(id), "error", err)
				tf.deleteFile(name)
				continue loop
			}
			ts.writers[id] = writer
		}
	}
	for id := range ts.writers {
		if _, ok := ts.readers[id]; ok {
			log.Warn("Both complete and partial index table found", "name", params.tableName(id))
			delete(ts.writers, id)
			tf.deleteFile(params.tableName(id) + writeStateSuffix)
		}
	}
	for _, name := range allFiles {
		ftype, id, tempLevel := params.parseFileName(name)
		if ftype == fnWriteTemp {
			if w, ok := ts.writers[id]; !ok || tempLevel > w.(*tableWriter).format.subtreeLevels {
				log.Warn("Unexpected index table writer temp file", "name", name)
				tf.deleteFile(name)
			}
		}
	}
	for id := range ts.readers {
		ts.complete.add(id)
		ts.preInit.add(id)
	}
	for id := range ts.writers {
		ts.partial.add(id)
		ts.preInit.add(id)
	}
	if ts.preInit.isEmpty() {
		ts.preInit = nil
	}
	return ts, nil
}

// tables returns cloned snapshots of the complete and partial sets and whether
// startup validation is still pending.
func (ts *tableStorage) tables() (tableSet, tableSet, bool) {
	ts.lock.Lock()
	defer ts.lock.Unlock()

	return ts.tablesLocked()
}

// tablesLocked returns the same snapshots without taking the storage lock; the
// caller must hold it (the indexer methods hold the indexer lock before taking
// the storage lock, tests follow the same order).
func (ts *tableStorage) tablesLocked() (tableSet, tableSet, bool) {
	if ts.complete.count() != uint64(len(ts.readers)) {
		panic("ts.complete.count() != len(ts.readers)")
	}
	if ts.partial.count() != uint64(len(ts.writers)) {
		panic("ts.partial.count() != len(ts.writers)")
	}
	complete := make(tableSet, len(ts.complete))
	for i, rs := range ts.complete {
		complete[i] = slices.Clone(rs)
	}
	partial := make(tableSet, len(ts.partial))
	for i, rs := range ts.partial {
		partial[i] = slices.Clone(rs)
	}
	return complete, partial, ts.preInit != nil
}

func (ts *tableStorage) getTableReader(id tableID) (*TableReader, error) {
	ts.lock.Lock()
	defer ts.lock.Unlock()

	if tr, ok := ts.readers[id]; ok {
		return tr, nil
	}
	return nil, errTableNotFound
}

// getRangeReaders decomposes the given block range into the available complete
// tables, highest level first.
func (ts *tableStorage) getRangeReaders(blockRange common.Range[uint64]) []*TableReader {
	ts.lock.Lock()
	defer ts.lock.Unlock()

	var readers []*TableReader
	rs := common.SingleRangeSet[uint64](blockRange)
	for level := len(ts.params.tableLevels) - 1; level >= 0; level-- {
		avail := ts.complete[level].Intersection(shiftRangeSetLevel(rs, ts.params.tableLevels[0], ts.params.tableLevels[level], true))
		for index := range avail.Iter() {
			id := tableID{level: level, index: index}
			if tr, ok := ts.readers[id]; ok {
				readers = append(readers, tr)
			} else {
				panic("table reader not found for complete table")
			}
		}
		rs = rs.Difference(shiftRangeSetLevel(avail, ts.params.tableLevels[level], ts.params.tableLevels[0], false))
	}
	return readers
}

func (ts *tableStorage) addNewTableWriter(id tableID, entryCount uint64) (tableWriterImpl, error) {
	ts.lock.Lock()
	defer ts.lock.Unlock()

	if ts.writers[id] != nil {
		return nil, errors.New("table already exists")
	}
	var (
		tw  tableWriterImpl
		err error
	)
	if ts.tf == nil {
		tw, err = newMemoryTableWriter(ts.params, entryCount)
	} else {
		tw, err = newFileTableWriter(ts.params, ts.tf, ts.params.tableName(id), false, entryCount, id.level == 0)
	}
	if err != nil {
		return nil, err
	}
	if err := ts.openAndLockTableWriter(tw); err != nil {
		return nil, err
	}
	ts.writers[id] = tw
	ts.partial.add(id)
	return tw, nil
}

// getTableWriter returns the partial writer for the given id, opening and
// locking it. File writers locked by someone else are waited on.
func (ts *tableStorage) getTableWriter(id tableID) (tableWriterImpl, error) {
	ts.lock.Lock()
	defer ts.lock.Unlock()

	for {
		tw, ok := ts.writers[id]
		if !ok {
			return nil, errTableNotFound
		}
		if ch, ok := ts.lockedWriters[tw]; ok {
			ts.lock.Unlock()
			select {
			case <-ch:
			case <-time.After(time.Second * 10):
				ts.lock.Lock()
				return nil, errors.New("wait for table writer lock timed out")
			}
			ts.lock.Lock()
		} else {
			if err := ts.openAndLockTableWriter(tw); err != nil {
				return nil, err
			}
			return tw, nil
		}
	}
}

// releaseTableWriter releases a writer after an interrupted operation, leaving
// it open in memory for a later reopen.
func (ts *tableStorage) releaseTableWriter(id tableID) error {
	ts.lock.Lock()
	defer ts.lock.Unlock()

	tw, ok := ts.writers[id]
	if !ok {
		return errTableNotFound
	}
	ch, ok := ts.lockedWriters[tw]
	if !ok {
		return errors.New("table is not locked")
	}
	delete(ts.lockedWriters, tw)
	ts.openWriterCounter++
	ts.unlockedOpenWriters[tw] = ts.openWriterCounter
	close(ch)
	return nil
}

// openAndLockTableWriter opens the writer's backing storage and marks it
// locked. needs ts.lock.
func (ts *tableStorage) openAndLockTableWriter(tw tableWriterImpl) error {
	if _, ok := ts.lockedWriters[tw]; ok {
		panic("cannot lock already locked writer")
	}
	if _, ok := ts.unlockedOpenWriters[tw]; ok {
		delete(ts.unlockedOpenWriters, tw)
		ts.lockedWriters[tw] = make(chan struct{})
		return nil
	}
	if len(ts.lockedWriters)+len(ts.unlockedOpenWriters) >= maxOpenWriters {
		if len(ts.unlockedOpenWriters) == 0 {
			return errors.New("too many locked table writers")
		}
		var closeTw tableWriterImpl
		minCounter := uint64(math.MaxUint64)
		for tw, counter := range ts.unlockedOpenWriters {
			if counter < minCounter {
				closeTw, minCounter = tw, counter
			}
		}
		if fw, ok := closeTw.(*tableWriter); ok {
			if err := fw.close(); err != nil {
				return err
			}
		}
		delete(ts.unlockedOpenWriters, closeTw)
	}
	if fw, ok := tw.(*tableWriter); ok {
		if err := fw.open(); err != nil {
			return err
		}
	}
	ts.lockedWriters[tw] = make(chan struct{})
	return nil
}

func (ts *tableStorage) finalizeTableWriter(id tableID) error {
	ts.lock.Lock()
	defer ts.lock.Unlock()

	tw, ok := ts.writers[id]
	if !ok {
		return errTableNotFound
	}
	if tw.getPhase() != wpFinalized {
		return errors.New("table writer not finalized yet")
	}
	if ch, ok := ts.lockedWriters[tw]; ok {
		delete(ts.lockedWriters, tw)
		close(ch)
	}
	delete(ts.unlockedOpenWriters, tw)
	delete(ts.writers, id)
	ts.partial.remove(id)
	var tr *TableReader
	if _, ok := tw.(*tableWriter); ok {
		var err error
		if tr, err = newTableReader(ts.params, ts.tf, ts.params.tableName(id)); err != nil {
			return err
		}
	} else {
		mw := tw.(*memoryTableWriter)
		tr = newMemoryTableReader(mw.collectedEntries(), mw.root(), mw.meta)
	}
	ts.readers[id] = tr
	ts.complete.add(id)
	if ch, ok := ts.triggers[id]; ok {
		close(ch)
		delete(ts.triggers, id)
	}
	return nil
}

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
		if ts.tf != nil {
			return ts.tf.deleteFile(ts.params.tableName(id))
		}
		return nil
	}
	if tw, ok := ts.writers[id]; ok {
		if ch, ok := ts.lockedWriters[tw]; ok {
			delete(ts.lockedWriters, tw)
			close(ch)
		}
		delete(ts.unlockedOpenWriters, tw)
		delete(ts.writers, id)
		ts.partial.remove(id)
		return tw.delete()
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

	for i := range ts.params.tableLevels {
		for {
			rs := ts.complete[i].Union(ts.partial[i])
			if rs.IsEmpty() {
				break
			}
			id := tableID{level: i, index: rs.Last()}
			if ts.params.blockRange(id).Last() >= blockNumber {
				if err := ts.deleteTableLocked(id); err != nil {
					break
				}
			} else {
				break
			}
		}
	}
}

// requestInitBlockHash returns the block number whose hash is needed to start
// the chain-of-custody validation of the preInit tables.
func (ts *tableStorage) requestInitBlockHash() (number uint64, request bool) {
	ts.lock.Lock()
	defer ts.lock.Unlock()

	for i, rs := range ts.preInit {
		if !rs.IsEmpty() {
			last := ts.params.blockRange(tableID{level: i, index: rs.Last()}).Last()
			if !request || last > number {
				request, number = true, last
			}
		}
	}
	ts.initRequest, ts.initNumber = request, number
	return
}

// deliverInitBlockHash validates the preInit tables against the given block
// hash: tables whose metadata interlocks with it are accepted and bless their
// parent block, mismatched tables are deleted.
func (ts *tableStorage) deliverInitBlockHash(number uint64, hash common.Hash) bool {
	ts.lock.Lock()
	defer ts.lock.Unlock()

	if ts.preInit == nil {
		return true
	}
	if !ts.initRequest || number != ts.initNumber {
		return false
	}
	ts.initRequest = false
	hashes := make(map[uint64]common.Hash)
	hashes[number] = hash
	for len(hashes) > 0 {
		for number, hash := range hashes {
			for id, tr := range ts.readers {
				if tr.Meta.LastBlockNumber != number || !ts.preInit.includes(id) {
					continue
				}
				if tr.Meta.LastBlockHash == hash {
					if tr.Meta.LastBlockNumber >= tr.Meta.BlockCount {
						hashes[tr.Meta.LastBlockNumber-tr.Meta.BlockCount] = tr.Meta.ParentHash
					}
				} else {
					ts.complete.remove(id)
					delete(ts.readers, id)
					if ts.tf != nil {
						ts.tf.deleteFile(ts.params.tableName(id))
					}
				}
				ts.preInit.remove(id)
			}
			for id, tw := range ts.writers {
				if !ts.preInit.includes(id) {
					continue
				}
				meta := writerMeta(tw)
				if meta.LastBlockNumber != number {
					continue
				}
				if meta.LastBlockHash == hash {
					if meta.LastBlockNumber >= meta.BlockCount {
						hashes[meta.LastBlockNumber-meta.BlockCount] = meta.ParentHash
					}
				} else {
					delete(ts.writers, id)
					ts.partial.remove(id)
					tw.delete()
				}
				ts.preInit.remove(id)
			}
			delete(hashes, number)
		}
	}
	if ts.preInit.isEmpty() {
		ts.preInit = nil
	}
	return ts.preInit == nil
}

// dropPreInit discards all tables that have not been validated yet.
func (ts *tableStorage) dropPreInit() {
	ts.lock.Lock()
	defer ts.lock.Unlock()

	if ts.preInit == nil {
		return
	}
	for level, rs := range ts.preInit {
		for _, r := range rs {
			for index := range r.Iter() {
				ts.deleteTableLocked(tableID{level: level, index: index})
			}
		}
	}
	ts.preInit = nil
}

func (ts *tableStorage) close() {
	ts.lock.Lock()
	defer ts.lock.Unlock()

	for _, ch := range ts.triggers {
		close(ch)
	}
	for tw := range ts.lockedWriters {
		if err := tw.delete(); err != nil {
			log.Error("Failed to delete index table writer", "error", err)
		}
	}
	for tw := range ts.unlockedOpenWriters {
		if err := tw.delete(); err != nil {
			log.Error("Failed to delete index table writer", "error", err)
		}
	}
}

// maxLastBlock returns the newest block number and hash covered by any loaded
// table, for the indexer to resume its head tracking after a restart.
func (ts *tableStorage) maxLastBlock() (uint64, common.Hash, bool) {
	ts.lock.Lock()
	defer ts.lock.Unlock()

	var (
		number uint64
		hash   common.Hash
		found  bool
	)
	for _, tr := range ts.readers {
		if !found || tr.Meta.LastBlockNumber > number {
			number, hash, found = tr.Meta.LastBlockNumber, tr.Meta.LastBlockHash, true
		}
	}
	return number, hash, found
}

func (p *Params) tableName(id tableID) string {
	br := p.blockRange(id)
	return fmt.Sprintf("table_%016x_%016x", br.First(), br.Count())
}

const (
	fnUnknown = iota
	fnTable
	fnWriteState
	fnWriteTemp
)

func (p *Params) parseFileName(name string) (int, tableID, uint) {
	var (
		firstBlock, blockCount uint64
		suffix                 string
		tempLevel              uint
	)
	n, _ := fmt.Sscanf(name, "table_%016x_%016x%s", &firstBlock, &blockCount, &suffix)
	if n != 2 && n != 3 {
		return fnUnknown, tableID{}, 0
	}
	id, ok := p.rangeID(common.NewRange[uint64](firstBlock, blockCount))
	if !ok {
		return fnUnknown, tableID{}, 0
	}
	switch suffix {
	case "":
		return fnTable, id, 0
	case writeStateSuffix:
		return fnWriteState, id, 0
	default:
		if n, _ := fmt.Sscanf(suffix, ".temp_%02x", &tempLevel); n == 1 {
			return fnWriteTemp, id, tempLevel
		}
	}
	return fnUnknown, tableID{}, 0
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
