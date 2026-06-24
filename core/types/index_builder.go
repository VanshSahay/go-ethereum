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
	"crypto/sha256"
	"sort"

	"github.com/ethereum/go-ethereum/common"
	ssz "github.com/ferranbt/fastssz"
)

// maxEntriesLimit is the SSZ list capacity used for ChainedTable merkleization.
// Must be a power of 2 large enough to hold the maximum number of entries in a
// table. Chain 3 covers 64 blocks; worst-case ~266k entries/block × 64 ≈ 17M.
// 2^25 = 33,554,432 provides a safe margin.
const maxEntriesLimit = 1 << 25

// IndexBuilder accumulates IndexEntry values and computes the SSZ Merkle root
// for a ChainedTable.
type IndexBuilder struct {
	entries []IndexEntry
	parent  common.Hash // previous ChainedTable root in the chain
}

// NewIndexBuilder creates a new IndexBuilder with the given parent root.
func NewIndexBuilder(parent common.Hash) *IndexBuilder {
	return &IndexBuilder{
		parent:  parent,
		entries: make([]IndexEntry, 0),
	}
}

// Reset clears accumulated entries while preserving the parent.
func (b *IndexBuilder) Reset() {
	b.entries = b.entries[:0]
}

// AddEntry appends a single 64-byte entry to the builder.
func (b *IndexBuilder) AddEntry(e IndexEntry) {
	b.entries = append(b.entries, e)
}

// AddBlockEntries adds all index entries for a single block's receipts.
// For single-block tables (chain 0), block entries are omitted per spec —
// the block hash is not known during processing of the current block.
func (b *IndexBuilder) AddBlockEntries(blockNumber uint64, receipts Receipts) {
	for txIndex, receipt := range receipts {
		// Transaction entry
		b.AddEntry(EncodeEntry(EntryTypeTransaction, receipt.TxHash, blockNumber, uint32(txIndex), 0))

		for logIndex, log := range receipt.Logs {
			// Log address entry
			addrHash := common.BytesToHash(log.Address.Bytes())
			b.AddEntry(EncodeEntry(EntryTypeLogAddress, addrHash, blockNumber, uint32(txIndex), uint32(logIndex)))

			// Log topic entries (up to 4)
			for topicIdx, topic := range log.Topics {
				entryType := IndexEntryType(int(EntryTypeLogTopic0) + topicIdx)
				b.AddEntry(EncodeEntry(entryType, topic, blockNumber, uint32(txIndex), uint32(logIndex)))
			}
		}
	}
}

// AddBlockEntry adds the block hash entry for the given block.
// This is used for multi-block tables where the block hash is known (past blocks).
func (b *IndexBuilder) AddBlockEntry(blockHash common.Hash, blockNumber uint64) {
	b.AddEntry(EncodeEntry(EntryTypeBlock, blockHash, blockNumber, 0, 0))
}

// Build sorts the accumulated entries and returns a ChainedTableRoot with
// the SSZ Merkle root and the parent link.
func (b *IndexBuilder) Build() ChainedTableRoot {
	// Sort entries lexicographically
	sort.Slice(b.entries, func(i, j int) bool {
		return CompareEntries(b.entries[i], b.entries[j]) < 0
	})

	return ChainedTableRoot{
		Table:  computeSSZMerkleRoot(b.entries),
		Parent: b.parent,
	}
}

// Len returns the number of accumulated entries.
func (b *IndexBuilder) Len() int {
	return len(b.entries)
}

// Entries returns the sorted slice of accumulated entries.
// Call Build() first to ensure they are sorted.
func (b *IndexBuilder) Entries() []IndexEntry {
	return b.entries
}

// computeSSZMerkleRoot computes the SSZ-compatible Merkle root of a sorted
// list of IndexEntry values. Each 64-byte entry is treated as two 32-byte
// SSZ chunks. The tree uses SHA-256 as the hash function per SSZ spec.
func computeSSZMerkleRoot(entries []IndexEntry) common.Hash {
	if len(entries) == 0 {
		// Empty list: return the SSZ zero-hash for a zero-length list.
		// MerkleizeWithMixin with num=0 produces this.
		hh := ssz.NewHasher()
		hh.MerkleizeWithMixin(0, 0, maxEntriesLimit)
		root, _ := hh.HashRoot()
		return common.Hash(root)
	}

	hh := ssz.NewHasher()

	// For each entry, compute the element hash tree root (2 chunks → 1 root)
	// and append to the list hasher.
	for _, entry := range entries {
		// Hash the 64-byte entry as an SSZ basic type: two 32-byte chunks
		eh := ssz.NewHasher()
		eh.PutBytes(entry[:32])  // first chunk
		eh.PutBytes(entry[32:])  // second chunk
		eh.Merkleize(0)          // hash the two chunks together
		elemRoot, _ := eh.HashRoot()
		hh.Append(elemRoot[:])
	}

	// Merkleize the list of element roots.
	hh.MerkleizeWithMixin(0, uint64(len(entries)), maxEntriesLimit)
	root, _ := hh.HashRoot()
	return common.Hash(root)
}

// hashPair returns sha256(left || right). Used for manual Merkle tree operations.
func hashPair(left, right []byte) common.Hash {
	h := sha256.New()
	h.Write(left)
	h.Write(right)
	var out common.Hash
	h.Sum(out[:0])
	return out
}
