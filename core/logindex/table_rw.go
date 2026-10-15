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
	"math/bits"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// Table levels and sizes per the EIP-8304 spec: five chained table levels,
// level i covering TableSizes[i] consecutive blocks.
var TableSizes = []uint64{1, 4, 16, 64, 256}

// ErrTableDeleted is returned when accessing a table that has been deleted,
// e.g. by a reorg amputation running concurrently with a merge.
var ErrTableDeleted = errors.New("index table deleted")

// Params configures the table hierarchy.
type Params struct {
	tableLevels                []tableLevel
	fileStorageThresholdHeight uint
}

// DefaultParams returns the EIP-8304 protocol hierarchy: five levels with the
// spec's table sizes.
func DefaultParams() *Params {
	return &Params{
		tableLevels:                makeTableLevels(TableSizes),
		fileStorageThresholdHeight: 12,
	}
}

func makeTableLevels(sizes []uint64) []tableLevel {
	levels := make([]tableLevel, len(sizes))
	for i, size := range sizes {
		levels[i] = tableLevel{blockCount: size}
	}
	return levels
}

// tableFormat describes the shape of the binary tree hashed over a table's
// entries: the tree has leafHeight levels and the leaves sit at positions
// 2^leafHeight + i, zero-padded up to 2^leafHeight. Larger tables are split
// into entry chunks of 2^logEntryChunkSize leaves and subtree chunks of
// subtreeChunkSize branches each; the chunk layout only affects the file
// format, never the resulting root.
const (
	entryChunkSize      = 128
	logEntryChunkSize   = 7
	subtreeChunkSize    = 64
	logSubtreeChunkSize = 6
)

type tableFormat struct {
	entryCount                                    uint64
	firstSubtreeHeight, subtreeLevels, leafHeight uint
	memoryStorage, fileStorage                    uint
}

func (p *Params) newTableFormat(entryCount uint64) (tf tableFormat) {
	tf.entryCount = entryCount
	tf.leafHeight = uint(64 - bits.LeadingZeros64(max(entryCount, 1)-1))
	if tf.leafHeight <= logEntryChunkSize {
		tf.subtreeLevels = 1
	} else {
		tf.subtreeLevels = (tf.leafHeight - logEntryChunkSize + logSubtreeChunkSize - 1) / logSubtreeChunkSize
		tf.firstSubtreeHeight = tf.leafHeight - logEntryChunkSize - (tf.subtreeLevels-1)*logSubtreeChunkSize
	}
	if tf.firstSubtreeHeight < p.fileStorageThresholdHeight {
		if tf.leafHeight < p.fileStorageThresholdHeight {
			tf.memoryStorage = tf.subtreeLevels + 1
		} else {
			tf.memoryStorage = (p.fileStorageThresholdHeight-tf.firstSubtreeHeight)/logSubtreeChunkSize + 1
		}
	}
	tf.fileStorage = tf.subtreeLevels + 1 - tf.memoryStorage
	return
}

func (tf *tableFormat) entryChunkHeight() uint {
	return tf.leafHeight - (tf.firstSubtreeHeight + (tf.subtreeLevels-1)*logSubtreeChunkSize)
}

func (tf *tableFormat) subtreeChunkHeight(level uint) uint {
	switch {
	case level == 0:
		return tf.firstSubtreeHeight
	case level > 0 && level < tf.subtreeLevels:
		return logSubtreeChunkSize
	default:
		panic("invalid table tree level")
	}
}

func (tf *tableFormat) baseHeight(level uint) uint {
	switch {
	case level == 0:
		return 0
	case level == 1:
		return tf.firstSubtreeHeight
	case level > 1 && level <= tf.subtreeLevels:
		return tf.firstSubtreeHeight + logSubtreeChunkSize*(level-1)
	default:
		panic("invalid table tree level")
	}
}

// TableMeta pins a table to a specific chain segment: it indexes the blocks
// [LastBlockNumber+1-BlockCount, LastBlockNumber], ending at LastBlockHash and
// starting right after ParentHash. Merged tables inherit ParentHash from their
// oldest source and LastBlockHash from their newest source, so the metadata of
// all tables interlocks into a chain of custody that reorg cleanup and startup
// validation can walk.
type TableMeta struct {
	LastBlockNumber, BlockCount uint64
	LastBlockHash, ParentHash   common.Hash
}

// tableHeader is the trailer structure of a persisted table file.
type tableHeader struct {
	LevelPointers []uint64
	EntryCount    uint64
	TableRoot     [32]byte
	Meta          TableMeta
}

// Writer phases, shared by the memory and file backed table writers.
const (
	wpNone = iota // new table write, no partial state
	wpWriteEntries
	wpTempCopy
	wpFinalized
)

// TableReader provides read access to a completed table. In memory mode the
// entries are held in RAM and hashes are derived from types.MerkleNodeHash;
// the file backed reader added later serves the same interface from disk.
type TableReader struct {
	entries    []types.IndexEntry
	EntryCount uint64
	TableRoot  [32]byte
	Meta       TableMeta
}

func newMemoryTableReader(entries []types.IndexEntry, root [32]byte, meta TableMeta) *TableReader {
	return &TableReader{
		entries:    entries,
		EntryCount: uint64(len(entries)),
		TableRoot:  root,
		Meta:       meta,
	}
}

// BlockRange returns the range of blocks the table indexes.
func (tr *TableReader) BlockRange() common.Range[uint64] {
	return common.NewRange[uint64](tr.Meta.LastBlockNumber+1-tr.Meta.BlockCount, tr.Meta.BlockCount)
}

// GetEntry returns the entry at the given index.
func (tr *TableReader) GetEntry(index uint64) (types.IndexEntry, error) {
	if index >= tr.EntryCount {
		return nil, errors.New("entry index out of range")
	}
	return tr.entries[index], nil
}

// GetHash returns the hash of the tree node at global tree index gti.
func (tr *TableReader) GetHash(gti uint64) ([32]byte, error) {
	return types.MerkleNodeHash(tr.entries, gti)
}

// findEntry binary searches the sorted entries. Returns the smallest index
// whose entry is >= target and whether it is an exact match.
func (tr *TableReader) findEntry(target types.IndexEntry) (int, bool) {
	min, max := 0, len(tr.entries)
	for min < max {
		mid := (min + max) / 2
		switch types.CompareEntries(tr.entries[mid], target) {
		case -1:
			min = mid + 1
		case 0:
			return mid, true
		case 1:
			max = mid
		}
	}
	return min, false
}

// SeekEntry returns the first entry index >= target and whether it is an exact
// match. Targets beyond the last entry return EntryCount with found == false.
func (tr *TableReader) SeekEntry(target types.IndexEntry) (uint64, bool, error) {
	index, found := tr.findEntry(target)
	return uint64(index), found, nil
}

// tableWriter accumulates the sorted entries of a table with a predetermined
// entry count. In memory mode the entries are held in RAM and finalized into a
// TableReader; the file backed writer added later persists the same stream.
type tableWriter struct {
	entries    []types.IndexEntry
	entryCount uint64 // predetermined total number of entries
	nextEntry  uint64
	format     tableFormat
	meta       TableMeta
	hasMeta    bool
	isDeleted  bool
	phase      uint
	tableRoot  [32]byte
}

func newMemoryTableWriter(p *Params, entryCount uint64) (*tableWriter, error) {
	format := p.newTableFormat(entryCount)
	format.memoryStorage = format.subtreeLevels + 1
	format.fileStorage = 0
	return &tableWriter{
		entryCount: entryCount,
		format:     format,
		phase:      wpWriteEntries,
	}, nil
}

// lastAndNextEntry returns the last entry added so far (nil if none) and the
// total number of entries added so far. The merge resume logic reconstructs
// its per-source positions from these.
func (tw *tableWriter) lastAndNextEntry() (types.IndexEntry, uint64) {
	if len(tw.entries) != 0 {
		return tw.entries[len(tw.entries)-1], tw.nextEntry
	}
	return nil, tw.nextEntry
}

// addEntry appends one entry. Entries must be added in sorted order and the
// total must match the predetermined entry count.
func (tw *tableWriter) addEntry(entry types.IndexEntry) error {
	if tw.isDeleted {
		return ErrTableDeleted
	}
	if tw.phase != wpWriteEntries {
		panic("invalid table write phase")
	}
	if tw.nextEntry >= tw.entryCount {
		panic("too many entries")
	}
	tw.entries = append(tw.entries, entry)
	tw.nextEntry++
	return nil
}

func (tw *tableWriter) setMeta(meta TableMeta) {
	if tw.hasMeta {
		panic("TableMeta already exists")
	}
	tw.meta, tw.hasMeta = meta, true
}

func (tw *tableWriter) getTableRoot() [32]byte {
	if tw.nextEntry != tw.entryCount {
		panic("not enough entries")
	}
	return tw.tableRoot
}

// finalize completes the table: computes the root over the accumulated entries
// and returns done == true. The memory writer always finishes in one step.
func (tw *tableWriter) finalize() (bool, error) {
	if tw.isDeleted {
		return false, ErrTableDeleted
	}
	if tw.phase != wpWriteEntries {
		panic("invalid table write phase")
	}
	if tw.nextEntry != tw.entryCount {
		panic("not enough entries")
	}
	if !tw.hasMeta {
		panic("TableMeta missing")
	}
	if tw.entryCount > 0 {
		tw.tableRoot = types.IndexTableRoot(tw.entries)
	}
	// An empty table has no root: it stays the zero hash.
	tw.phase = wpFinalized
	return true, nil
}

func (tw *tableWriter) getPhase() uint {
	return tw.phase
}
