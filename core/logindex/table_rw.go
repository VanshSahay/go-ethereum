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
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"slices"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/lru"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
)

// Table levels and sizes per the EIP-8304 spec: five chained table levels,
// level i covering TableSizes[i] consecutive blocks.
var TableSizes = []uint64{1, 4, 16, 64, 256}

// MaxTopicCount is the number of log topic entry types per log.
const MaxTopicCount = 4

// ErrTableDeleted is returned when accessing a table that has been deleted,
// e.g. by a reorg amputation running concurrently with a merge.
var ErrTableDeleted = errors.New("index table deleted")

// Params configures the table hierarchy.
type Params struct {
	tableLevels                []tableLevel
	fileStorageThresholdHeight uint

	// out-of-protocol operation: the table roots live in a contract of the
	// given address that is not fed by the protocol's publication schedule
	historic      bool
	indexContract common.Address
	historicLast  uint64   // the last block the contract holds roots for
	historicHeld  []uint64 // sizes the contract holds roots for, nil for all of them
}

// NewHistoricParams returns the parameters of an out-of-protocol hierarchy:
// tables of the given sizes whose roots are stored in the contract at the
// given address for the blocks up to lastBlock, with no publication schedule
// and no ring window. The sizes must start at 1 and each must be a multiple of
// the previous one.
func NewHistoricParams(sizes []uint64, contract common.Address, lastBlock uint64) (*Params, error) {
	if len(sizes) == 0 || sizes[0] != 1 {
		return nil, errors.New("table sizes must start at 1")
	}
	for i := 1; i < len(sizes); i++ {
		if sizes[i] <= sizes[i-1] || sizes[i]%sizes[i-1] != 0 {
			return nil, errors.New("each table size must be a larger multiple of the previous one")
		}
	}
	return &Params{
		tableLevels:                makeTableLevels(sizes),
		fileStorageThresholdHeight: 12,
		historic:                   true,
		indexContract:              contract,
		historicLast:               lastBlock,
	}, nil
}

// WithHeldSizes restricts the table sizes of a historic hierarchy that the
// contract holds roots for: the index still builds every level (the larger
// tables are merged from the smaller ones), but only tables of the held sizes
// are served, so a contract that stores just the top levels (a few hundred
// roots instead of one per block) is enough. The queried range is then served
// by the held tables overlapping it, which may extend past its ends.
func (p *Params) WithHeldSizes(held []uint64) (*Params, error) {
	if !p.historic {
		return nil, errors.New("held sizes only apply to a historic hierarchy")
	}
	for _, size := range held {
		found := false
		for _, level := range p.tableLevels {
			found = found || level.blockCount == size
		}
		if !found {
			return nil, fmt.Errorf("held table size %d is not a size of the hierarchy", size)
		}
	}
	p.historicHeld = held
	return p, nil
}

// holdsLevel reports whether tables of the given level can be served: always
// outside historic mode, and in historic mode when the contract holds their
// roots.
func (p *Params) holdsLevel(level int) bool {
	if !p.historic || p.historicHeld == nil {
		return true
	}
	return slices.Contains(p.historicHeld, p.tableLevels[level].blockCount)
}

// Historic reports whether the hierarchy is out-of-protocol.
func (p *Params) Historic() bool { return p.historic }

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
	entryCacheSize      = 100
	subtreeCacheSize    = 100

	maxCopyLength = 0x10000
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

// getChunkLevel returns the index of the chunk layer a tree node of the given
// height resides in: the entry chunk layer holds the leaves.
func (tf *tableFormat) getChunkLevel(height uint) uint {
	if height <= tf.firstSubtreeHeight {
		return 0
	}
	if height > tf.firstSubtreeHeight+(tf.subtreeLevels-1)*logSubtreeChunkSize {
		return tf.subtreeLevels
	}
	return (height - tf.firstSubtreeHeight + logSubtreeChunkSize - 1) / logSubtreeChunkSize
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

// Entry stream codec: each entry is stored as a 1-byte length prefix followed
// by its raw 38/42/50-byte encoding.
func appendEntryCodec(dst []byte, entry types.IndexEntry) []byte {
	dst = append(dst, byte(len(entry)))
	return append(dst, entry...)
}

func encodeEntryStream(entries []types.IndexEntry) []byte {
	blob := make([]byte, 0, len(entries)*51)
	for _, entry := range entries {
		blob = appendEntryCodec(blob, entry)
	}
	return blob
}

func decodeEntryStream(blob []byte) ([]types.IndexEntry, error) {
	var entries []types.IndexEntry
	for len(blob) > 0 {
		l := int(blob[0])
		if len(blob) < 1+l {
			return nil, errors.New("truncated index entry stream")
		}
		entries = append(entries, types.IndexEntry(blob[1:1+l]))
		blob = blob[1+l:]
	}
	return entries, nil
}

// tableReaderImpl is the internal interface of the memory and file backed
// table reader implementations.
type tableReaderImpl interface {
	getEntry(index uint64) (types.IndexEntry, error)
	getHash(gti uint64) ([32]byte, error)
	seekEntry(target types.IndexEntry) (uint64, bool, error)
}

// TableReader provides read access to a completed table, backed either by RAM
// (memory mode) or by the table file layer.
type TableReader struct {
	impl          tableReaderImpl
	EntryCount    uint64
	TableRoot     [32]byte
	Meta          TableMeta
	IndexContract common.Address // the index contract the table root is published in
}

// BlockRange returns the range of blocks the table indexes.
func (tr *TableReader) BlockRange() common.Range[uint64] {
	return common.NewRange[uint64](tr.Meta.LastBlockNumber+1-tr.Meta.BlockCount, tr.Meta.BlockCount)
}

// GetEntry returns the entry at the given index.
func (tr *TableReader) GetEntry(index uint64) (types.IndexEntry, error) {
	return tr.impl.getEntry(index)
}

// GetHash returns the hash of the tree node at global tree index gti.
func (tr *TableReader) GetHash(gti uint64) ([32]byte, error) {
	return tr.impl.getHash(gti)
}

// SeekEntry returns the first entry index >= target and whether it is an exact
// match. Targets beyond the last entry return EntryCount with found == false.
func (tr *TableReader) SeekEntry(target types.IndexEntry) (uint64, bool, error) {
	return tr.impl.seekEntry(target)
}

// memoryTableReader serves a table held as a sorted in-RAM entry slice.
type memoryTableReader struct {
	entries []types.IndexEntry
}

func newMemoryTableReader(entries []types.IndexEntry, root [32]byte, meta TableMeta) *TableReader {
	return &TableReader{
		impl:          &memoryTableReader{entries: entries},
		EntryCount:    uint64(len(entries)),
		TableRoot:     root,
		Meta:          meta,
		IndexContract: params.IndexContractAddress,
	}
}

func (mr *memoryTableReader) getEntry(index uint64) (types.IndexEntry, error) {
	if index >= uint64(len(mr.entries)) {
		return nil, errors.New("entry index out of range")
	}
	return mr.entries[index], nil
}

func (mr *memoryTableReader) getHash(gti uint64) ([32]byte, error) {
	return types.MerkleNodeHash(mr.entries, gti)
}

func (mr *memoryTableReader) seekEntry(target types.IndexEntry) (uint64, bool, error) {
	min, max := 0, len(mr.entries)
	for min < max {
		mid := (min + max) / 2
		switch types.CompareEntries(mr.entries[mid], target) {
		case -1:
			min = mid + 1
		case 0:
			return uint64(mid), true, nil
		case 1:
			max = mid
		}
	}
	return uint64(min), false, nil
}

// fileEntryChunk holds the entries of one entry chunk together with a memo of
// the chunk-local tree node hashes.
type fileEntryChunk struct {
	entries []types.IndexEntry
	height  uint
	hashes  [][32]byte
	hasHash []bool
}

func (ec *fileEntryChunk) getHash(gti uint64) ([32]byte, error) {
	if ec.hashes == nil {
		ec.hashes = make([][32]byte, 2<<ec.height)
		ec.hasHash = make([]bool, 2<<ec.height)
	}
	if ec.hasHash[gti] {
		return ec.hashes[gti], nil
	}
	gtiHeight := uint(63 - bits.LeadingZeros64(gti))
	if gtiHeight > ec.height {
		return [32]byte{}, errors.New("invalid entry tree index")
	}
	var result [32]byte
	if gti<<(ec.height-gtiHeight) >= uint64(1)<<ec.height+uint64(len(ec.entries)) {
		result = types.MerkleZeroHash(int(ec.height - gtiHeight))
	} else if gti >= uint64(1)<<ec.height {
		result = types.EntryLeafHash(ec.entries[gti-uint64(1)<<ec.height])
	} else {
		left, err := ec.getHash(gti * 2)
		if err != nil {
			return [32]byte{}, err
		}
		right, err := ec.getHash(gti*2 + 1)
		if err != nil {
			return [32]byte{}, err
		}
		hasher := sha256.New()
		hasher.Write(left[:])
		hasher.Write(right[:])
		hasher.Sum(result[:0])
	}
	ec.hashes[gti] = result
	ec.hasHash[gti] = true
	return result, nil
}

// fileSubtreeChunk holds the boundary entries, boundary file positions and
// branch hashes of one subtree chunk.
type fileSubtreeChunk struct {
	boundaryEntries []types.IndexEntry
	boundaryFilePos []uint64
	height, above   uint
	branches        uint
	hashes          [][32]byte
	hasHash         []bool
}

func (sc *fileSubtreeChunk) getHash(gti uint64) ([32]byte, error) {
	if sc.hasHash[gti] {
		return sc.hashes[gti], nil
	}
	gtiHeight := uint(63 - bits.LeadingZeros64(gti))
	if gtiHeight > sc.height {
		return [32]byte{}, errors.New("invalid subtree index")
	}
	var result [32]byte
	if gti<<(sc.height-gtiHeight) >= uint64(1)<<sc.height+uint64(sc.branches) {
		result = types.MerkleZeroHash(int(sc.above + sc.height - gtiHeight))
	} else {
		left, err := sc.getHash(gti * 2)
		if err != nil {
			return [32]byte{}, err
		}
		right, err := sc.getHash(gti*2 + 1)
		if err != nil {
			return [32]byte{}, err
		}
		hasher := sha256.New()
		hasher.Write(left[:])
		hasher.Write(right[:])
		hasher.Sum(result[:0])
	}
	sc.hashes[gti] = result
	sc.hasHash[gti] = true
	return result, nil
}

// subtreesForStorage is the RLP-serializable form of a subtree chunk.
type subtreesForStorage struct {
	BoundaryBlob    []byte
	BoundaryFilePos []uint64
	Hashes          [][32]byte
}

func (sc *fileSubtreeChunk) toStorage() *subtreesForStorage {
	return &subtreesForStorage{
		BoundaryBlob:    encodeEntryStream(sc.boundaryEntries),
		BoundaryFilePos: sc.boundaryFilePos,
		Hashes:          sc.hashes[1<<sc.height : 1<<sc.height+sc.branches],
	}
}

func (ss *subtreesForStorage) toSubtreeChunk(height, above uint) (*fileSubtreeChunk, error) {
	boundaryEntries, err := decodeEntryStream(ss.BoundaryBlob)
	if err != nil {
		return nil, err
	}
	sc := &fileSubtreeChunk{
		boundaryEntries: boundaryEntries,
		boundaryFilePos: ss.BoundaryFilePos,
		height:          height,
		above:           above,
		branches:        uint(len(ss.Hashes)),
		hashes:          make([][32]byte, 2<<height),
		hasHash:         make([]bool, 2<<height),
	}
	for i, hash := range ss.Hashes {
		j := 1<<height + i
		sc.hashes[j] = hash
		sc.hasHash[j] = true
	}
	return sc, nil
}

type subtreePos struct {
	level uint
	index uint64
}

// fileTableReader serves a table from the file layer: entry and subtree chunks
// are read on demand and cached, and tree node hashes are derived chunk-locally.
type fileTableReader struct {
	reader            io.ReaderAt
	entryChunkCache   *lru.Cache[uint64, *fileEntryChunk]
	subtreeChunkCache *lru.Cache[subtreePos, *fileSubtreeChunk]
	format            tableFormat
	levelPointers     []int64
}

func newTableReader(p *Params, tf *tableFiles, name string) (*TableReader, error) {
	ioReader, fileSize, err := tf.getReaderAt(name)
	if err != nil {
		return nil, err
	}
	var headerSizeByte [1]byte
	if _, err := ioReader.ReadAt(headerSizeByte[:], fileSize-1); err != nil {
		return nil, err
	}
	headerEnc := make([]byte, headerSizeByte[0])
	if _, err := ioReader.ReadAt(headerEnc, fileSize-1-int64(headerSizeByte[0])); err != nil {
		return nil, err
	}
	var header tableHeader
	if err := rlp.DecodeBytes(headerEnc, &header); err != nil {
		return nil, err
	}
	fr := &fileTableReader{
		reader:            ioReader,
		entryChunkCache:   lru.NewCache[uint64, *fileEntryChunk](entryCacheSize),
		subtreeChunkCache: lru.NewCache[subtreePos, *fileSubtreeChunk](subtreeCacheSize),
		format:            p.newTableFormat(header.EntryCount),
		levelPointers:     make([]int64, len(header.LevelPointers)),
	}
	for i, p := range header.LevelPointers {
		fr.levelPointers[i] = int64(p)
	}
	return &TableReader{
		impl:          fr,
		EntryCount:    header.EntryCount,
		TableRoot:     header.TableRoot,
		Meta:          header.Meta,
		IndexContract: params.IndexContractAddress,
	}, nil
}

func (fr *fileTableReader) getSubtreeChunk(level uint, index uint64) (*fileSubtreeChunk, error) {
	sp := subtreePos{level, index}
	if sc, ok := fr.subtreeChunkCache.Get(sp); ok {
		return sc, nil
	}
	var start, stop int64
	if level == 0 {
		start, stop = fr.levelPointers[1], fr.levelPointers[0]
	} else {
		sc, err := fr.getSubtreeChunk(level-1, index/subtreeChunkSize)
		if err != nil {
			return nil, err
		}
		i := index % subtreeChunkSize
		start, stop = fr.levelPointers[level+1]+int64(sc.boundaryFilePos[i]), fr.levelPointers[level+1]+int64(sc.boundaryFilePos[i+1])
	}
	enc := make([]byte, stop-start)
	if _, err := fr.reader.ReadAt(enc, start); err != nil {
		return nil, err
	}
	var ss subtreesForStorage
	if err := rlp.DecodeBytes(enc, &ss); err != nil {
		return nil, err
	}
	sc, err := ss.toSubtreeChunk(fr.format.subtreeChunkHeight(level), fr.format.leafHeight-fr.format.baseHeight(level+1))
	if err != nil {
		return nil, err
	}
	fr.subtreeChunkCache.Add(sp, sc)
	return sc, nil
}

func (fr *fileTableReader) getEntryChunk(index uint64) (*fileEntryChunk, error) {
	if ec, ok := fr.entryChunkCache.Get(index); ok {
		return ec, nil
	}
	sc, err := fr.getSubtreeChunk(fr.format.subtreeLevels-1, index/subtreeChunkSize)
	if err != nil {
		return nil, err
	}
	i := index % subtreeChunkSize
	start, stop := sc.boundaryFilePos[i], sc.boundaryFilePos[i+1]
	enc := make([]byte, stop-start)
	if _, err := fr.reader.ReadAt(enc, int64(start)); err != nil {
		return nil, err
	}
	entries, err := decodeEntryStream(enc)
	if err != nil {
		return nil, err
	}
	ec := &fileEntryChunk{
		entries: entries,
		height:  fr.format.entryChunkHeight(),
	}
	fr.entryChunkCache.Add(index, ec)
	return ec, nil
}

func (fr *fileTableReader) getHash(gti uint64) ([32]byte, error) {
	gtiHeight := uint(63 - bits.LeadingZeros64(gti))
	chunkLevel := fr.format.getChunkLevel(gtiHeight)
	chunkBaseHeight := fr.format.baseHeight(chunkLevel)
	chunkIndex := (gti - uint64(1)<<gtiHeight) >> (gtiHeight - chunkBaseHeight)
	m := uint64(1) << (gtiHeight - chunkBaseHeight)
	chunkGti := m + gti&(m-1)
	if chunkLevel == fr.format.subtreeLevels {
		ec, err := fr.getEntryChunk(chunkIndex)
		if err != nil {
			return [32]byte{}, err
		}
		return ec.getHash(chunkGti)
	}
	sc, err := fr.getSubtreeChunk(chunkLevel, chunkIndex)
	if err != nil {
		return [32]byte{}, err
	}
	return sc.getHash(chunkGti)
}

func (fr *fileTableReader) getEntry(index uint64) (types.IndexEntry, error) {
	ec, err := fr.getEntryChunk(index / entryChunkSize)
	if err != nil {
		return nil, err
	}
	return ec.entries[index%entryChunkSize], nil
}

func (fr *fileTableReader) seekEntry(target types.IndexEntry) (uint64, bool, error) {
	var (
		chunkLevel               uint
		chunkIndex, chunkEntries uint64
	)
	chunkEntries = entryChunkSize
	for range fr.format.subtreeLevels {
		chunkEntries *= subtreeChunkSize
	}
	for chunkLevel < fr.format.subtreeLevels {
		sc, err := fr.getSubtreeChunk(chunkLevel, chunkIndex)
		if err != nil {
			return 0, false, err
		}
		subIndex, _ := findInEntries(sc.boundaryEntries, target)
		chunkLevel++
		chunkIndex = chunkIndex*subtreeChunkSize + uint64(subIndex)
		chunkEntries /= subtreeChunkSize
		if chunkIndex*chunkEntries >= fr.format.entryCount {
			return fr.format.entryCount, false, nil
		}
	}
	ec, err := fr.getEntryChunk(chunkIndex)
	if err != nil {
		return 0, false, err
	}
	subIndex, found := findInEntries(ec.entries, target)
	return chunkIndex*entryChunkSize + uint64(subIndex), found, nil
}

// findInEntries binary searches sorted entries. Returns the smallest index
// whose entry is >= target and whether it is an exact match.
func findInEntries(entries []types.IndexEntry, target types.IndexEntry) (int, bool) {
	min, max := 0, len(entries)
	for min < max {
		mid := (min + max) / 2
		switch types.CompareEntries(entries[mid], target) {
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

// tableWriterImpl is the internal interface shared by the memory and file
// backed table writers.
type tableWriterImpl interface {
	entryCount() uint64
	lastAndNextEntry() (types.IndexEntry, uint64)
	addEntry(entry types.IndexEntry) error
	setMeta(meta TableMeta)
	// root returns the table root once every entry has been added. The file
	// writer derives it incrementally while entries stream in; the memory
	// writer computes it on demand.
	root() [32]byte
	finalize() (bool, error)
	getPhase() uint
	delete() error
}

// tableWriter is the file backed writer: entries are streamed into per-level
// temp files (entry chunks into the top level, subtree chunks cascading down),
// then copied into the final layout, the header trailer is appended and the
// result renamed into place. Progress is persisted in a .state file so an
// interrupted write resumes where it left off.
type tableWriter struct {
	tf                      *tableFiles
	name                    string
	entryCountV             uint64
	format                  tableFormat
	meta                    TableMeta
	isOpen, isDeleted       bool
	hasStoredState, hasMeta bool
	phase                   uint
	tableRoot               [32]byte
	// phase == wpWriteEntries
	lastEntryChunk    *fileEntryChunk
	lastSubtreeChunks []*fileSubtreeChunk
	writers           []io.WriteCloser
	writePointers     []int64
	nextEntry         uint64
	// phase == wpTempCopy
	copyLevel                     uint
	copyReader                    io.ReaderAt
	copyReadPointer, copyReadSize int64
	copyWriter                    io.WriteCloser
	copyWritePointer              int64
	levelPointers                 []int64
}

func (tw *tableWriter) entryCount() uint64 { return tw.entryCountV }

func (tw *tableWriter) getPhase() uint { return tw.phase }

func newFileTableWriter(params *Params, tf *tableFiles, name string, storedState bool, entryCount uint64, forceMemory bool) (*tableWriter, error) {
	var state writeState
	if storedState {
		r, l, err := tf.getReaderAt(name + writeStateSuffix)
		if err != nil {
			tf.deleteFile(name + writeStateSuffix)
			return nil, err
		}
		enc := make([]byte, l)
		if _, err := r.ReadAt(enc, 0); err != nil {
			tf.deleteFile(name + writeStateSuffix)
			return nil, err
		}
		if err := rlp.DecodeBytes(enc, &state); err != nil {
			tf.deleteFile(name + writeStateSuffix)
			return nil, err
		}
		entryCount = state.Header.EntryCount
	}
	format := params.newTableFormat(entryCount)
	if forceMemory {
		format.memoryStorage = format.subtreeLevels + 1
	}
	tw := &tableWriter{
		tf:                tf,
		name:              name,
		hasStoredState:    storedState,
		hasMeta:           state.Header.Meta.LastBlockHash != (common.Hash{}),
		meta:              state.Header.Meta,
		lastSubtreeChunks: make([]*fileSubtreeChunk, format.subtreeLevels),
		writers:           make([]io.WriteCloser, format.subtreeLevels+1),
		writePointers:     make([]int64, format.subtreeLevels+1),
		entryCountV:       entryCount,
		format:            format,
	}
	tw.phase = state.Phase
	tw.lastEntryChunk = tw.newEntryChunk()
	tw.nextEntry = state.NextEntry
	tw.tableRoot = state.Header.TableRoot
	switch state.Phase {
	case wpNone:
		for i := range tw.lastSubtreeChunks {
			tw.lastSubtreeChunks[i] = tw.newSubtreeChunk(uint(i))
		}
		tw.phase = wpWriteEntries
	case wpWriteEntries:
		entries, err := decodeEntryStream(state.LastEntryChunkBlob)
		if err != nil {
			tw.delete()
			return nil, err
		}
		tw.lastEntryChunk.entries = entries
		for i := range tw.lastSubtreeChunks {
			sc, err := state.LastSubtreeChunks[i].toSubtreeChunk(tw.format.subtreeChunkHeight(uint(i)), tw.format.leafHeight-tw.format.baseHeight(uint(i+1)))
			if err != nil {
				tw.delete()
				return nil, err
			}
			tw.lastSubtreeChunks[i] = sc
		}
		for i := range tw.format.subtreeLevels + 1 {
			_, l, err := tf.getReaderAt(name + writeTempSuffix(i))
			if err != nil {
				tw.delete()
				return nil, err
			}
			tw.writePointers[i] = l
		}
	case wpTempCopy:
		tw.copyLevel = state.CopyLevel
		tw.copyReadPointer = int64(state.CopyReadPointer)
		tw.levelPointers = make([]int64, len(state.Header.LevelPointers))
		for i, p := range state.Header.LevelPointers {
			tw.levelPointers[i] = int64(p)
		}
		var err error
		tw.copyReader, tw.copyReadSize, err = tf.getReaderAt(name + writeTempSuffix(tw.copyLevel))
		if err != nil {
			tw.delete()
			return nil, err
		}
		_, tw.copyWritePointer, err = tf.getReaderAt(name + writeTempSuffix(tw.format.subtreeLevels))
		if err != nil {
			tw.delete()
			return nil, err
		}
	default:
		tw.delete()
		return nil, errors.New("invalid table write phase")
	}
	return tw, nil
}

func (tw *tableWriter) delete() error {
	var finalErr error
	for _, w := range tw.writers {
		if w != nil {
			if err := w.Close(); err != nil {
				finalErr = err
			}
		}
	}
	if tw.copyWriter != nil {
		if err := tw.copyWriter.Close(); err != nil {
			finalErr = err
		}
	}
	if err := tw.tf.deleteFile(tw.name + writeStateSuffix); err != nil && err != errFileNotFound {
		finalErr = err
	}
	for i := range tw.format.subtreeLevels + 1 {
		if err := tw.tf.deleteFile(tw.name + writeTempSuffix(i)); err != nil && err != errFileNotFound {
			finalErr = err
		}
	}
	if err := tw.tf.deleteFile(tw.name); err != nil && err != errFileNotFound {
		finalErr = err
	}
	tw.isDeleted = true
	return finalErr
}

func (tw *tableWriter) open() error {
	if tw.isDeleted {
		return ErrTableDeleted
	}
	if tw.isOpen {
		panic("table writer is already open")
	}
	if tw.hasStoredState {
		if err := tw.tf.deleteFile(tw.name + writeStateSuffix); err != nil {
			return err
		}
		tw.hasStoredState = false
	}
	var err error
	switch tw.phase {
	case wpWriteEntries:
		for i := range tw.format.subtreeLevels + 1 {
			tw.writers[i], err = tw.tf.getAppendWriter(tw.name+writeTempSuffix(i), i < tw.format.memoryStorage)
			if err != nil {
				return err
			}
		}
	case wpTempCopy:
		tw.copyWriter, err = tw.tf.getAppendWriter(tw.name+writeTempSuffix(tw.format.subtreeLevels), tw.format.subtreeLevels < tw.format.memoryStorage)
		if err != nil {
			return err
		}
	default:
		panic("invalid table write phase")
	}
	tw.isOpen = true
	return nil
}

func (tw *tableWriter) close() error {
	if tw.isDeleted {
		return ErrTableDeleted
	}
	if !tw.isOpen {
		panic("table writer is not open")
	}
	state := writeState{
		Phase:     tw.phase,
		NextEntry: tw.nextEntry,
		Header: tableHeader{
			EntryCount: tw.entryCountV,
			TableRoot:  tw.tableRoot,
			Meta:       tw.meta,
		},
	}
	switch tw.phase {
	case wpWriteEntries:
		for i, w := range tw.writers {
			if err := w.Close(); err != nil {
				return err
			}
			tw.writers[i] = nil // signal for a potential delete() that this writer has been successfully closed
		}
		state.LastEntryChunkBlob = encodeEntryStream(tw.lastEntryChunk.entries)
		state.LastSubtreeChunks = make([]*subtreesForStorage, len(tw.lastSubtreeChunks))
		for i, sc := range tw.lastSubtreeChunks {
			state.LastSubtreeChunks[i] = sc.toStorage()
		}
	case wpTempCopy:
		if err := tw.copyWriter.Close(); err != nil {
			return err
		}
		tw.copyWriter = nil
		state.CopyLevel = tw.copyLevel
		state.CopyReadPointer = uint64(tw.copyReadPointer)
		state.Header.LevelPointers = make([]uint64, len(tw.levelPointers))
		for i, p := range tw.levelPointers {
			state.Header.LevelPointers[i] = uint64(p)
		}
	case wpFinalized:
		tw.isOpen = false
		return nil
	default:
		panic("invalid table write phase")
	}
	sw, err := tw.tf.getAppendWriter(tw.name+writeStateSuffix, true)
	if err != nil {
		return err
	}
	if err := rlp.Encode(sw, &state); err != nil {
		sw.Close()
		return err
	}
	if err := sw.Close(); err != nil {
		return err
	}
	tw.hasStoredState = true
	tw.isOpen = false
	return nil
}

func (tw *tableWriter) newEntryChunk() *fileEntryChunk {
	return &fileEntryChunk{
		height: tw.format.entryChunkHeight(),
	}
}

func (tw *tableWriter) newSubtreeChunk(level uint) *fileSubtreeChunk {
	height := tw.format.subtreeChunkHeight(level)
	return &fileSubtreeChunk{
		height:  height,
		above:   tw.format.leafHeight - tw.format.baseHeight(level+1),
		hashes:  make([][32]byte, 2<<height),
		hasHash: make([]bool, 2<<height),
	}
}

func (tw *tableWriter) lastAndNextEntry() (types.IndexEntry, uint64) {
	if len(tw.lastEntryChunk.entries) != 0 {
		return tw.lastEntryChunk.entries[len(tw.lastEntryChunk.entries)-1], tw.nextEntry
	}
	for i := int(tw.format.subtreeLevels) - 1; i >= 0; i-- {
		if len(tw.lastSubtreeChunks[i].boundaryEntries) > 0 {
			return tw.lastSubtreeChunks[i].boundaryEntries[len(tw.lastSubtreeChunks[i].boundaryEntries)-1], tw.nextEntry
		}
	}
	return nil, tw.nextEntry
}

func (tw *tableWriter) addEntry(entry types.IndexEntry) error {
	if tw.isDeleted {
		return ErrTableDeleted
	}
	if tw.phase != wpWriteEntries {
		panic("invalid table write phase")
	}
	if tw.nextEntry >= tw.entryCountV {
		panic("too many entries")
	}
	tw.lastEntryChunk.entries = append(tw.lastEntryChunk.entries, entry)
	tw.nextEntry++
	if len(tw.lastEntryChunk.entries) == entryChunkSize || tw.nextEntry == tw.entryCountV {
		enc := encodeEntryStream(tw.lastEntryChunk.entries)
		n, err := tw.writers[tw.format.subtreeLevels].Write(enc)
		if err != nil {
			return err
		}
		if n != len(enc) {
			return errors.New("error writing table chunk")
		}
		beforePos := tw.writePointers[tw.format.subtreeLevels]
		tw.writePointers[tw.format.subtreeLevels] += int64(n)
		hash, err := tw.lastEntryChunk.getHash(1)
		if err != nil {
			return err
		}
		if err := tw.addSubtreeEntry(tw.format.subtreeLevels-1, entry, beforePos, tw.writePointers[tw.format.subtreeLevels], hash); err != nil {
			return err
		}
		tw.lastEntryChunk = tw.newEntryChunk()
	}
	return nil
}

func (tw *tableWriter) addSubtreeEntry(level uint, boundaryEntry types.IndexEntry, beforePos, afterPos int64, hash [32]byte) error {
	sc := tw.lastSubtreeChunks[level]
	if sc.branches < subtreeChunkSize-1 {
		sc.boundaryEntries = append(sc.boundaryEntries, boundaryEntry)
	}
	if sc.branches == 0 {
		sc.boundaryFilePos = []uint64{uint64(beforePos)}
	}
	sc.boundaryFilePos = append(sc.boundaryFilePos, uint64(afterPos))
	sc.hashes[1<<sc.height+sc.branches] = hash
	sc.hasHash[1<<sc.height+sc.branches] = true
	sc.branches++
	if sc.branches == subtreeChunkSize || tw.nextEntry == tw.entryCountV {
		ss := sc.toStorage()
		enc, err := rlp.EncodeToBytes(ss)
		if err != nil {
			return err
		}
		n, err := tw.writers[level].Write(enc)
		if err != nil {
			return err
		}
		if n != len(enc) {
			return errors.New("error writing subtree chunk")
		}
		beforePos := tw.writePointers[level]
		tw.writePointers[level] += int64(n)
		if level > 0 {
			hash, err := sc.getHash(1)
			if err != nil {
				return err
			}
			if err := tw.addSubtreeEntry(level-1, boundaryEntry, beforePos, tw.writePointers[level], hash); err != nil {
				return err
			}
		} else {
			subtreeRoot, err := sc.getHash(1)
			if err != nil {
				return err
			}
			var entryCountEnc [32]byte
			binary.LittleEndian.PutUint64(entryCountEnc[0:8], tw.entryCountV)
			hasher := sha256.New()
			hasher.Write(subtreeRoot[:])
			hasher.Write(entryCountEnc[:])
			hasher.Sum(tw.tableRoot[:0])
		}
		tw.lastSubtreeChunks[level] = tw.newSubtreeChunk(level)
	}
	return nil
}

func (tw *tableWriter) setMeta(meta TableMeta) {
	if tw.hasMeta {
		panic("TableMeta already exists")
	}
	tw.meta, tw.hasMeta = meta, true
}

func (tw *tableWriter) root() [32]byte {
	if tw.nextEntry != tw.entryCountV {
		panic("not enough entries")
	}
	return tw.tableRoot
}

func (tw *tableWriter) finalize() (bool, error) {
	if tw.isDeleted {
		return false, ErrTableDeleted
	}
	if tw.phase == wpWriteEntries {
		if tw.nextEntry != tw.entryCountV {
			panic("not enough entries")
		}
		if !tw.hasMeta {
			panic("TableMeta missing")
		}
		for i := range tw.format.subtreeLevels {
			if err := tw.writers[i].Close(); err != nil {
				return false, err
			}
			tw.writers[i] = nil // signal for a potential delete() that this writer has been successfully closed
		}
		tw.copyWriter = tw.writers[tw.format.subtreeLevels]
		tw.copyWritePointer = tw.writePointers[tw.format.subtreeLevels]
		tw.writers = nil
		tw.copyLevel = tw.format.subtreeLevels
		tw.levelPointers = make([]int64, tw.format.subtreeLevels+1)
		tw.phase = wpTempCopy
	}
	if tw.phase != wpTempCopy {
		panic("invalid table write phase")
	}
	for tw.copyReadPointer == tw.copyReadSize {
		tw.levelPointers[tw.copyLevel] = tw.copyWritePointer
		if tw.copyLevel == 0 {
			// last temp level file copied; finalize by adding header
			header := tableHeader{
				LevelPointers: make([]uint64, len(tw.levelPointers)),
				EntryCount:    tw.entryCountV,
				TableRoot:     tw.tableRoot,
				Meta:          tw.meta,
			}
			for i, p := range tw.levelPointers {
				header.LevelPointers[i] = uint64(p)
			}
			headerEnc, err := rlp.EncodeToBytes(&header)
			if err != nil {
				return false, err
			}
			headerEnc = append(headerEnc, byte(len(headerEnc)))
			if _, err := tw.copyWriter.Write(headerEnc); err != nil {
				return false, err
			}
			// close and rename top level temp file and return success
			if err := tw.copyWriter.Close(); err != nil {
				return false, err
			}
			tw.copyWriter = nil
			for i := range tw.format.subtreeLevels {
				if err := tw.tf.deleteFile(tw.name + writeTempSuffix(i)); err != nil {
					return false, err
				}
			}
			if err := tw.tf.renameFile(tw.name+writeTempSuffix(tw.format.subtreeLevels), tw.name); err != nil {
				return false, err
			}
			tw.phase = wpFinalized
			return true, nil
		}
		tw.copyLevel--
		tw.copyReadPointer = 0
		var err error
		if tw.copyReader, tw.copyReadSize, err = tw.tf.getReaderAt(tw.name + writeTempSuffix(tw.copyLevel)); err != nil {
			return false, err
		}
	}
	copyLength := min(tw.copyReadSize-tw.copyReadPointer, maxCopyLength)
	data := make([]byte, copyLength)
	n, err := tw.copyReader.ReadAt(data, tw.copyReadPointer)
	if err != nil {
		return false, err
	}
	if int64(n) != copyLength {
		return false, errors.New("could not read copy data chunk")
	}
	n, err = tw.copyWriter.Write(data)
	if err != nil {
		return false, err
	}
	if int64(n) != copyLength {
		return false, errors.New("could not write copy data chunk")
	}
	tw.copyReadPointer += copyLength
	tw.copyWritePointer += copyLength
	return false, nil
}

// memoryTableWriter accumulates the sorted entries of a table in RAM with a
// predetermined entry count and finalizes into a memory reader.
type memoryTableWriter struct {
	entries     []types.IndexEntry
	entryCountV uint64
	nextEntry   uint64
	meta        TableMeta
	hasMeta     bool
	isDeleted   bool
	phase       uint
	tableRoot   [32]byte
}

func newMemoryTableWriter(p *Params, count uint64) (*memoryTableWriter, error) {
	return &memoryTableWriter{
		entryCountV: count,
		phase:       wpWriteEntries,
	}, nil
}

func (tw *memoryTableWriter) entryCount() uint64 { return tw.entryCountV }

func (tw *memoryTableWriter) getPhase() uint { return tw.phase }

func (tw *memoryTableWriter) lastAndNextEntry() (types.IndexEntry, uint64) {
	if len(tw.entries) != 0 {
		return tw.entries[len(tw.entries)-1], tw.nextEntry
	}
	return nil, tw.nextEntry
}

func (tw *memoryTableWriter) addEntry(entry types.IndexEntry) error {
	if tw.isDeleted {
		return ErrTableDeleted
	}
	if tw.phase != wpWriteEntries {
		panic("invalid table write phase")
	}
	if tw.nextEntry >= tw.entryCountV {
		panic("too many entries")
	}
	tw.entries = append(tw.entries, entry)
	tw.nextEntry++
	return nil
}

func (tw *memoryTableWriter) setMeta(meta TableMeta) {
	if tw.hasMeta {
		panic("TableMeta already exists")
	}
	tw.meta, tw.hasMeta = meta, true
}

func (tw *memoryTableWriter) root() [32]byte {
	if tw.nextEntry != tw.entryCountV {
		panic("not enough entries")
	}
	if tw.entryCountV > 0 {
		return types.IndexTableRoot(tw.entries)
	}
	return [32]byte{}
}

func (tw *memoryTableWriter) finalize() (bool, error) {
	if tw.isDeleted {
		return false, ErrTableDeleted
	}
	if tw.phase != wpWriteEntries {
		panic("invalid table write phase")
	}
	if tw.nextEntry != tw.entryCountV {
		panic("not enough entries")
	}
	if !tw.hasMeta {
		panic("TableMeta missing")
	}
	if tw.entryCountV > 0 {
		tw.tableRoot = types.IndexTableRoot(tw.entries)
	}
	// An empty table has no root: it stays the zero hash.
	tw.phase = wpFinalized
	return true, nil
}

func (tw *memoryTableWriter) delete() error {
	tw.isDeleted = true
	tw.entries = nil
	return nil
}

// collectedEntries returns the entries accumulated by a finalized memory
// writer, for the storage layer to build the reader from.
func (tw *memoryTableWriter) collectedEntries() []types.IndexEntry {
	return tw.entries
}

// writerMeta returns the metadata of a writer regardless of implementation.
func writerMeta(tw tableWriterImpl) TableMeta {
	switch w := tw.(type) {
	case *tableWriter:
		return w.meta
	case *memoryTableWriter:
		return w.meta
	}
	panic("unknown table writer implementation")
}

// writeState is the RLP-serialized crash-resume state of a file writer.
type writeState struct {
	Phase              uint
	NextEntry          uint64
	LastEntryChunkBlob []byte
	LastSubtreeChunks  []*subtreesForStorage
	CopyLevel          uint
	CopyReadPointer    uint64
	Header             tableHeader
}
