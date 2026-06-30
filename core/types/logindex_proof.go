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
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// LogIndexProof is a proof of log inclusion/exclusion against EIP-8304 table roots.
// A light client can verify that specific log entries exist (or don't exist) in a
// block range, given only the trusted table root from the on-chain contract.
type LogIndexProof struct {
	HeadBlockHash   common.Hash  `json:"headBlockHash"`
	HeadBlockNumber uint64       `json:"headBlockNumber"`
	TableRoot       common.Hash  `json:"tableRoot"`     // trusted root from contract
	SortedEntries   []IndexEntry `json:"sortedEntries"` // entries covering the block range
	MatchStart      int          `json:"matchStart"`    // inclusive, -1 if no matches
	MatchEnd        int          `json:"matchEnd"`      // exclusive, -1 if no matches
	MatchingLogs    []*Log       `json:"matchingLogs"`  // the actual matching log objects
}

// GenerateLogProof builds a proof for matching entries in the given block range.
// tableEntries is the merged sorted entries from all blocks in the range.
// matchFn returns true if an entry matches the user's filter.
// matchingLogs are the actual Log objects that matched the filter.
func GenerateLogProof(headBlockHash common.Hash, headBlockNumber uint64, tableRoot common.Hash,
	tableEntries []IndexEntry, matchingLogs []*Log, matchFn func(IndexEntry) bool) *LogIndexProof {

	proof := &LogIndexProof{
		HeadBlockHash:   headBlockHash,
		HeadBlockNumber: headBlockNumber,
		TableRoot:       tableRoot,
		SortedEntries:   tableEntries,
		MatchingLogs:    matchingLogs,
		MatchStart:      -1,
		MatchEnd:        -1,
	}

	// Find the contiguous range of matching entries
	for i, entry := range tableEntries {
		if matchFn(entry) {
			if proof.MatchStart == -1 {
				proof.MatchStart = i
			}
			proof.MatchEnd = i + 1
		}
	}
	return proof
}

// VerifyLogProof verifies a proof against a trusted table root.
// Returns true if the proof is valid (the sorted entries hash to the claimed root).
func VerifyLogProof(proof *LogIndexProof) bool {
	var buf []byte
	for _, entry := range proof.SortedEntries {
		buf = append(buf, entry[:]...)
	}
	computedRoot := crypto.Keccak256Hash(buf)
	return computedRoot == proof.TableRoot
}

// MatchEntryByAddress returns a function that matches address entries.
func MatchEntryByAddress(addr common.Address) func(IndexEntry) bool {
	addrHash := common.BytesToHash(addr.Bytes())
	return func(entry IndexEntry) bool {
		typ, val, _, _, _ := EntryFields(entry)
		return typ == EntryTypeLogAddress && val == addrHash
	}
}

// MatchEntryByTopic returns a function that matches topic entries at a specific topic index.
func MatchEntryByTopic(topicIdx int, topic common.Hash) func(IndexEntry) bool {
	return func(entry IndexEntry) bool {
		typ, val, _, _, _ := EntryFields(entry)
		return typ == EntryType(int(EntryTypeLogTopic0)+topicIdx) && val == topic
	}
}
