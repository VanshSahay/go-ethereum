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

// indexPositionSet is an exact, sorted set of index positions. The prover
// proves every entry of the searched values in the scanned range, so the set
// reconstructed by the verifier is complete and the exclusion cross-check is
// exact.
type indexPositionSet []types.IndexPosition

// contains tells whether the given position is in the set.
func (ips indexPositionSet) contains(p types.IndexPosition) bool {
	i := sort.Search(len(ips), func(i int) bool { return ips[i].Compare(p) >= 0 })
	return i < len(ips) && ips[i] == p
}

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
	for _, set := range sets {
		if len(set) == 0 {
			return nil
		}
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
// imply for the given (type, content) matcher within [begin, end]: the exact
// positions of every proven value entry. The prover proves all entries of the
// searched values in the scanned range, so within it this set is complete and
// the exclusion cross-check is exact; outside the scanned range no proven
// receipt constrains the set.
func (tqp *tableQueryProof) getValueMatches(typ uint32, content []byte, begin, end types.IndexPosition) indexPositionSet {
	firstInRange, afterLastInRange := tqp.findValueRange(typ, content, begin, end)
	ips := make(indexPositionSet, 0, afterLastInRange-firstInRange)
	for i := firstInRange; i < afterLastInRange; i++ {
		ips = append(ips, mustPosition(tqp.ProvenEntries[i]))
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
