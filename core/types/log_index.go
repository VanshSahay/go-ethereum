// Copyright 2025 The go-ethereum Authors
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

package types

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
)

// IndexEntryType discriminates entries in the sorted index table.
type IndexEntryType uint8

const (
	EntryTypeBlock       IndexEntryType = 0 // block hash lookup
	EntryTypeTransaction IndexEntryType = 1 // transaction hash lookup
	EntryTypeLogAddress  IndexEntryType = 2 // log address lookup
	EntryTypeLogTopic0   IndexEntryType = 3 // log topic[0] lookup
	EntryTypeLogTopic1   IndexEntryType = 4 // log topic[1] lookup
	EntryTypeLogTopic2   IndexEntryType = 5 // log topic[2] lookup
	EntryTypeLogTopic3   IndexEntryType = 6 // log topic[3] lookup
)

// IndexEntrySize is the fixed size of each entry in the sorted index table.
const IndexEntrySize = 64

// IndexEntry represents a single 64-byte record in the sorted index table.
//
// Layout (big-endian):
//
//	[0]        entry type (1 byte)
//	[1:33]     index value (32 bytes)
//	[33:41]    block number (8 bytes)
//	[41:45]    transaction index (4 bytes)
//	[45:49]    log index (4 bytes)
//	[49:64]    zero-reserved (15 bytes)
//
// Sorting is lexicographical on the full 64 bytes, giving ordering:
// entry_type, index_value, block_number, tx_index, log_index.
type IndexEntry [IndexEntrySize]byte

// EncodeEntry packs the components into a fixed-size 64-byte index entry.
// Non-applicable position fields should be passed as zero.
func EncodeEntry(entryType IndexEntryType, value common.Hash, blockNumber uint64, txIndex uint32, logIndex uint32) IndexEntry {
	var e IndexEntry
	e[0] = byte(entryType)
	copy(e[1:33], value[:])
	binary.BigEndian.PutUint64(e[33:41], blockNumber)
	binary.BigEndian.PutUint32(e[41:45], txIndex)
	binary.BigEndian.PutUint32(e[45:49], logIndex)
	// bytes 49..63 remain zero
	return e
}

// EntryFields decodes an IndexEntry back to its components.
func (e IndexEntry) EntryFields() (entryType IndexEntryType, value common.Hash, blockNumber uint64, txIndex uint32, logIndex uint32) {
	entryType = IndexEntryType(e[0])
	copy(value[:], e[1:33])
	blockNumber = binary.BigEndian.Uint64(e[33:41])
	txIndex = binary.BigEndian.Uint32(e[41:45])
	logIndex = binary.BigEndian.Uint32(e[45:49])
	return
}

// CompareEntries returns -1, 0, or 1 for lexicographic ordering of two entries.
func CompareEntries(a, b IndexEntry) int {
	return bytes.Compare(a[:], b[:])
}

// ChainedTableRoot is the Merkle root pair for a single ChainedTable.
// Each chain table links its current sorted-entry Merkle root to the
// previous table in the chain, forming a provable history.
type ChainedTableRoot struct {
	Table  common.Hash `json:"table"`  // Merkle root of the sorted index table (SSZ List[Bytes64])
	Parent common.Hash `json:"parent"` // Previous ChainedTable root in this chain (zero for genesis)
}

// LogIndex is the consensus data structure replacing logs_bloom in block headers
// after the EIP-7745b fork. It contains the roots of four ChainedTables, each
// covering a block range of 4^i (i = 0..3) blocks with staggered update schedules.
type LogIndex struct {
	Chain0 ChainedTableRoot `json:"chain0"` // 1-block tables, updated every block
	Chain1 ChainedTableRoot `json:"chain1"` // 4-block tables, published with 1-block delay
	Chain2 ChainedTableRoot `json:"chain2"` // 16-block tables, published with 4-block delay
	Chain3 ChainedTableRoot `json:"chain3"` // 64-block tables, published with 16-block delay
}

// ZeroLogIndex returns a LogIndex with all-zero roots, used at the fork boundary
// and as the initial parent for each chain.
func ZeroLogIndex() LogIndex {
	return LogIndex{}
}

// Equal reports whether two LogIndex values are identical.
func (li LogIndex) Equal(other LogIndex) bool {
	return li.Chain0 == other.Chain0 &&
		li.Chain1 == other.Chain1 &&
		li.Chain2 == other.Chain2 &&
		li.Chain3 == other.Chain3
}

// EncodeRLP implements rlp.Encoder for LogIndex.
// Encodes as: [chain0_table, chain0_parent, chain1_table, chain1_parent, ...]
func (li LogIndex) EncodeRLP(_w io.Writer) error {
	w := rlp.NewEncoderBuffer(_w)
	outer := w.List()
	w.WriteBytes(li.Chain0.Table[:])
	w.WriteBytes(li.Chain0.Parent[:])
	w.WriteBytes(li.Chain1.Table[:])
	w.WriteBytes(li.Chain1.Parent[:])
	w.WriteBytes(li.Chain2.Table[:])
	w.WriteBytes(li.Chain2.Parent[:])
	w.WriteBytes(li.Chain3.Table[:])
	w.WriteBytes(li.Chain3.Parent[:])
	w.ListEnd(outer)
	return w.Flush()
}

// DecodeRLP implements rlp.Decoder for LogIndex.
func (li *LogIndex) DecodeRLP(s *rlp.Stream) error {
	_, err := s.List()
	if err != nil {
		return fmt.Errorf("log_index: expected outer list: %w", err)
	}
	if err := s.ReadBytes((*[common.HashLength]byte)(&li.Chain0.Table)[:], common.HashLength); err != nil {
		return fmt.Errorf("log_index: chain0.table: %w", err)
	}
	if err := s.ReadBytes((*[common.HashLength]byte)(&li.Chain0.Parent)[:], common.HashLength); err != nil {
		return fmt.Errorf("log_index: chain0.parent: %w", err)
	}
	if err := s.ReadBytes((*[common.HashLength]byte)(&li.Chain1.Table)[:], common.HashLength); err != nil {
		return fmt.Errorf("log_index: chain1.table: %w", err)
	}
	if err := s.ReadBytes((*[common.HashLength]byte)(&li.Chain1.Parent)[:], common.HashLength); err != nil {
		return fmt.Errorf("log_index: chain1.parent: %w", err)
	}
	if err := s.ReadBytes((*[common.HashLength]byte)(&li.Chain2.Table)[:], common.HashLength); err != nil {
		return fmt.Errorf("log_index: chain2.table: %w", err)
	}
	if err := s.ReadBytes((*[common.HashLength]byte)(&li.Chain2.Parent)[:], common.HashLength); err != nil {
		return fmt.Errorf("log_index: chain2.parent: %w", err)
	}
	if err := s.ReadBytes((*[common.HashLength]byte)(&li.Chain3.Table)[:], common.HashLength); err != nil {
		return fmt.Errorf("log_index: chain3.table: %w", err)
	}
	if err := s.ReadBytes((*[common.HashLength]byte)(&li.Chain3.Parent)[:], common.HashLength); err != nil {
		return fmt.Errorf("log_index: chain3.parent: %w", err)
	}
	return s.ListEnd()
}
