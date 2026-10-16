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
	"errors"
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

// indexPositionBoundary is a signed interval boundary of the index position
// space: position p with direction +1 opens an interval, -1 closes it.
type indexPositionBoundary struct {
	p types.IndexPosition
	d int
}

// indexPositionSet represents an ordered set of index positions as a list of
// signed boundaries alternating between interval starts (+1) and ends (-1).
// The boundaries are kept sorted by position, ends before starts on ties.
type indexPositionSet []indexPositionBoundary

// contains tells whether the given position lies inside any interval of the
// set. Intervals are inclusive of both endpoints, and a boundary pair at the
// same position is a single-position interval.
func (ips indexPositionSet) contains(p types.IndexPosition) bool {
	inside := false
	for _, b := range ips {
		if c := b.p.Compare(p); c < 0 {
			inside = b.d > 0
			continue
		}
		// b.p >= p: an opening boundary at p puts p inside; a closing
		// boundary at p leaves p inside (intervals include their ends)
		if b.d > 0 {
			inside = true
		}
		break
	}
	return inside
}

// filter normalizes a boundary list: only positions covered by at least
// threshold input sets are kept. The input lists are concatenated, not sorted.
func ipsMerge(sets []indexPositionSet, threshold int) indexPositionSet {
	var b []indexPositionBoundary
	for _, set := range sets {
		b = append(b, set...)
	}
	sort.SliceStable(b, func(i, j int) bool {
		if c := b[i].p.Compare(b[j].p); c != 0 {
			return c < 0
		}
		return b[i].d > b[j].d
	})
	res := make(indexPositionSet, 0, len(b))
	var (
		sum     int
		lastCmp bool
		start   types.IndexPosition
	)
	for i, bb := range b {
		sum += bb.d
		cmp := sum >= threshold
		if cmp != lastCmp && (i == len(b)-1 || b[i+1].p != bb.p) {
			if cmp {
				start = bb.p
			} else {
				res = append(res,
					indexPositionBoundary{p: start, d: 1},
					indexPositionBoundary{p: bb.p, d: -1})
			}
			lastCmp = cmp
		}
	}
	return res
}

func ipsUnion(sets []indexPositionSet) indexPositionSet {
	if len(sets) == 0 {
		return nil
	}
	return ipsMerge(sets, 1)
}

// filter normalizes the set: only positions covered by at least threshold
// copies in the (concatenated, possibly overlapping) input are kept.
func (ips indexPositionSet) filter(threshold int) indexPositionSet {
	return ipsMerge([]indexPositionSet{ips}, threshold)
}

func ipsIntersection(sets []indexPositionSet) indexPositionSet {
	if len(sets) == 0 {
		return nil
	}
	return ipsMerge(sets, len(sets))
}

// excludeBefore tells whether the entry positions before the given proven
// entry index are proven to not match the entry's (type, content) pair: a gap
// in the proven index list means the prover paid for a multiproof over a
// range that is claimed to contain no matching entries.
func (tqp *tableQueryProof) excludeBefore(i int) bool {
	// positions past the last proven entry are covered by the tail
	// multiproof (iterateProofIndices to MaxUint64), so no gap there
	if i <= 0 || i >= len(tqp.EntryIndices) {
		return false
	}
	return tqp.EntryIndices[i] != tqp.EntryIndices[i-1]+1
}

// valueBoundary builds the sorted-entries boundary lookup key for the given
// (type, content) pair at position p: the entry's raw encoding with the
// position fields set to p.
func valueBoundary(typ uint32, content []byte, p types.IndexPosition) types.IndexEntry {
	return types.EncodeEntry(types.EntryType(typ), content, p.BlockNumber, p.TxIndex, p.LogIndex)
}

// findValueRange binary searches the sorted proven entries for the half-open
// entry index range covered by (type, content) within [begin, end].
func (tqp *tableQueryProof) findValueRange(typ uint32, content []byte, begin, end types.IndexPosition) (int, int) {
	first, _ := findInEntries(tqp.ProvenEntries, valueBoundary(typ, content, begin))
	afterLast, _ := findInEntries(tqp.ProvenEntries, valueBoundary(typ, content, end))
	return first, afterLast
}

// getValueMatches computes the index position set that the proven entries
// imply for the given (type, content) matcher within [begin, end]: runs of
// contiguous proven entries contribute their position intervals, gaps
// contribute proven absence.
func (tqp *tableQueryProof) getValueMatches(typ uint32, content []byte, begin, end types.IndexPosition) indexPositionSet {
	firstInRange, afterLastInRange := tqp.findValueRange(typ, content, begin, end)
	var ips indexPositionSet
	if tqp.excludeBefore(firstInRange) {
		if firstInRange < afterLastInRange {
			ips = append(ips, indexPositionBoundary{p: mustPosition(tqp.ProvenEntries[firstInRange]), d: 1})
		}
	} else {
		ips = append(ips, indexPositionBoundary{p: begin, d: 1})
	}
	for i := firstInRange + 1; i < afterLastInRange; i++ {
		if tqp.excludeBefore(i) {
			ips = append(ips,
				indexPositionBoundary{p: mustPosition(tqp.ProvenEntries[i-1]), d: -1},
				indexPositionBoundary{p: mustPosition(tqp.ProvenEntries[i]), d: 1})
		}
	}
	if tqp.excludeBefore(afterLastInRange) {
		if firstInRange < afterLastInRange {
			ips = append(ips, indexPositionBoundary{p: mustPosition(tqp.ProvenEntries[afterLastInRange-1]), d: -1})
		}
	} else {
		ips = append(ips, indexPositionBoundary{p: end, d: -1})
	}
	return ips
}

// mustPosition decodes the position of an entry, panicking on malformed
// input: proven entries always originate from the indexer's own tables.
func mustPosition(entry types.IndexEntry) types.IndexPosition {
	pos, err := types.PositionFromEntry(entry)
	if err != nil {
		panic("malformed index entry: " + err.Error())
	}
	return pos
}

var errNoSuccessor = errors.New("no valid position after the given one")
