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

package logquery

import (
	"slices"
	"sort"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
)

// QueryProof is the self-contained proof of a log query result: the query
// itself, the reference header the result range is anchored to, the state
// proofs of the index contracts holding the table roots, and one multiproof
// per index table covering the proven range.
type QueryProof struct {
	Query              FilterQuery       `json:"query"`
	RefHeader          types.Header      `json:"refHeader"`
	IndexContracts     []common.Address  `json:"indexContracts"`
	ContractProofNodes []hexutil.Bytes   `json:"contractProofNodes"`
	ContractProofCodes []hexutil.Bytes   `json:"contractProofCodes"`
	TableQueryProofs   []tableQueryProof `json:"tableQueryProofs"`
}

// tableQueryProof proves a set of index entries of a single table against the
// table root stored in an index contract, and carries the re-evaluated logs of
// the blocks the proven entries point to.
type tableQueryProof struct {
	FirstBlock    uint64             `json:"firstBlock"`
	TableSize     uint64             `json:"tableSize"`
	EntryCount    uint64             `json:"entryCount"`
	IndexContract uint32             `json:"indexContract"`
	EntryIndices  []uint64           `json:"entryIndices"`
	ProvenEntries []types.IndexEntry `json:"provenEntries"`
	ProofHashes   []common.Hash      `json:"proofHashes"`
	ResultCount   uint64             `json:"resultCount"`
	BlockResults  []blockResults     `json:"blockResults"`
}

// blockResults carries a proven block header, the transaction indexes whose
// receipts contain matching logs and the receipts trie multiproof of those
// receipts.
type blockResults struct {
	Header         types.Header    `json:"header"`
	ProvenReceipts []uint32        `json:"provenReceipts"`
	ReceiptsProof  []hexutil.Bytes `json:"receiptsProof"`
}

// addOrGetIndexContract returns the index of the given contract address in the
// contract list, appending it first if it is not yet listed.
func (p *QueryProof) addOrGetIndexContract(contract common.Address) uint32 {
	for i, c := range p.IndexContracts {
		if c == contract {
			return uint32(i)
		}
	}
	p.IndexContracts = append(p.IndexContracts, contract)
	return uint32(len(p.IndexContracts) - 1)
}

// indexPositionSet is a sorted set of index positions without duplicates.
type indexPositionSet []types.IndexPosition

// ipsUnion returns the union of the sorted sets.
func ipsUnion(sets []indexPositionSet) indexPositionSet {
	var out indexPositionSet
	for _, set := range sets {
		out = append(out, set...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Compare(out[j]) < 0 })
	return slices.CompactFunc(out, func(a, b types.IndexPosition) bool { return a == b })
}

// ipsIntersection returns the intersection of the sorted sets.
func ipsIntersection(sets []indexPositionSet) indexPositionSet {
	if len(sets) == 0 {
		return nil
	}
	out := sets[0]
	for _, set := range sets[1:] {
		var next indexPositionSet
		i, j := 0, 0
		for i < len(out) && j < len(set) {
			switch c := out[i].Compare(set[j]); {
			case c == 0:
				next = append(next, out[i])
				i++
				j++
			case c < 0:
				i++
			default:
				j++
			}
		}
		out = next
	}
	return out
}

// valueBoundary builds the sorted-entries lookup key for the given (type,
// content) pair at position p: the entry's raw encoding with the position
// fields set to p.
func valueBoundary(typ uint32, content []byte, p types.IndexPosition) types.IndexEntry {
	return types.EncodeEntry(types.EntryType(typ), content, p.BlockNumber, p.TxIndex, p.LogIndex)
}

// valueRun implements runSource over the proven entries of the table proof. It
// returns the positions of the entries of the given (type, content) pair within
// [begin, end] and reports whether the proof shows that run to be complete:
//
//   - the proven entries inside the range must sit at consecutive table
//     indices, so no entry of the run can hide between two proven ones;
//   - the run must be bounded on both sides by a proven entry outside the
//     range at the adjacent table index, or by the start or end of the table.
//
// An empty run is shown the same way, by two adjacent proven entries (or a
// table edge) that enclose the range.
func (tqp *tableQueryProof) valueRun(typ uint32, content []byte, begin, end types.IndexPosition) (indexPositionSet, bool) {
	n := len(tqp.ProvenEntries)
	if n == 0 {
		return nil, tqp.EntryCount == 0
	}
	if tqp.EntryIndices[n-1] >= tqp.EntryCount {
		return nil, false
	}
	low := valueBoundary(typ, content, begin)
	high := valueBoundary(typ, content, end)
	// s is the first proven slot at or after the range, e the first one
	// beyond it
	s, _ := findInEntries(tqp.ProvenEntries, low)
	e := s + sort.Search(n-s, func(i int) bool {
		return types.CompareEntries(tqp.ProvenEntries[s+i], high) > 0
	})
	// the window from the left bounding slot to the right bounding slot must
	// be contiguous in the table
	a, b := max(s-1, 0), min(e, n-1)
	for i := a; i < b; i++ {
		if tqp.EntryIndices[i+1] != tqp.EntryIndices[i]+1 {
			return nil, false
		}
	}
	if s == 0 && tqp.EntryIndices[0] != 0 {
		return nil, false
	}
	if e == n && tqp.EntryIndices[n-1] != tqp.EntryCount-1 {
		return nil, false
	}
	run := make(indexPositionSet, 0, e-s)
	for i := s; i < e; i++ {
		pos, err := types.PositionFromEntry(tqp.ProvenEntries[i])
		if err != nil {
			return nil, false
		}
		run = append(run, pos)
	}
	return run, true
}
