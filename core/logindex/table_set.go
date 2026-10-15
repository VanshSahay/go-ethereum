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
	"github.com/ethereum/go-ethereum/common"
)

// tableSet is the set of existing or required tables at every level of the
// hierarchy, represented as index ranges per level.
type tableSet []common.RangeSet[uint64]

// tableLevel describes one level of the table hierarchy: every table at this
// level covers blockCount consecutive blocks.
type tableLevel struct {
	blockCount uint64
}

// tableID identifies a table by its level and its ordinal at that level. The
// covered block range is derived from the level's block count.
type tableID struct {
	level int
	index uint64
}

func (p *Params) newTableSet() tableSet {
	return make(tableSet, len(p.tableLevels))
}

func (ts tableSet) add(id tableID) {
	ts[id.level] = ts[id.level].Union(common.SingleRangeSet[uint64](common.NewRange[uint64](id.index, 1)))
}

func (ts tableSet) remove(id tableID) {
	ts[id.level] = ts[id.level].Difference(common.SingleRangeSet[uint64](common.NewRange[uint64](id.index, 1)))
}

func (ts tableSet) includes(id tableID) bool {
	return ts[id.level].Includes(id.index)
}

func (ts tableSet) isEmpty() bool {
	for _, rs := range ts {
		if !rs.IsEmpty() {
			return false
		}
	}
	return true
}

func (ts tableSet) count() uint64 {
	var count uint64
	for _, rs := range ts {
		count += rs.Count()
	}
	return count
}

func (p *Params) blockRange(id tableID) common.Range[uint64] {
	return common.NewRange[uint64](p.tableLevels[id.level].blockCount*id.index, p.tableLevels[id.level].blockCount)
}

func (p *Params) rangeID(r common.Range[uint64]) (tableID, bool) {
	for i, tl := range p.tableLevels {
		if tl.blockCount == r.Count() {
			if r.First()%tl.blockCount != 0 {
				return tableID{}, false
			}
			return tableID{level: i, index: r.First() / tl.blockCount}, true
		}
	}
	return tableID{}, false
}

const (
	opNone = iota
	opMerge
	opDelete
)

type tableOperation struct {
	operation int
	id        tableID
}

// compareOps orders table operations: deletes before merges, then newest
// block range first, higher level first on ties. With lowLevelFirst the level
// order is reversed, prioritizing the oldest, smallest tables.
func (p *Params) compareOps(a, b tableOperation, lowLevelFirst bool) int {
	switch {
	case a.operation > b.operation:
		return 1
	case a.operation < b.operation:
		return -1
	}
	if lowLevelFirst {
		switch {
		case a.id.level < b.id.level:
			return 1
		case a.id.level > b.id.level:
			return -1
		}
	}
	aa := p.blockRange(a.id).First()
	bb := p.blockRange(b.id).First()
	switch {
	case aa > bb:
		return 1
	case aa < bb:
		return -1
	}
	if !lowLevelFirst {
		switch {
		case a.id.level < b.id.level:
			return 1
		case a.id.level > b.id.level:
			return -1
		}
	}
	return 0
}

// addToOps inserts newOp into the priority-ordered ops list, dropping it if it
// would land beyond maxThreads. Returns false when the operation was dropped.
func (p *Params) addToOps(ops *[]tableOperation, newOp tableOperation, maxThreads int, lowLevelFirst bool) bool {
	pos := len(*ops)
loop:
	for i, op := range *ops {
		switch p.compareOps(newOp, op, lowLevelFirst) {
		case 0:
			return true
		case 1:
			pos = i
			break loop
		}
	}
	if pos >= maxThreads {
		return false
	}
	if len(*ops) < maxThreads {
		*ops = append(*ops, tableOperation{})
	}
	copy((*ops)[pos+1:len(*ops)], (*ops)[pos:len(*ops)-1])
	(*ops)[pos] = newOp
	return true
}

// nextTableOperations schedules the next merge and delete operations given the
// sets of complete and partial tables and the target set. Requirements cascade
// top-down: every table missing at a higher level requires the tables covering
// its block range at all lower levels. Merges are scheduled newest-first from
// complete, still-required sources; at most one delete candidate per level is
// added per pass so deletions cannot starve merges. The second return value is
// the residual set of required level-0 tables, whose indices are block numbers
// still missing for indexing.
func (p *Params) nextTableOperations(complete, partial, target tableSet, lowLevelMergeThreads, mergeThreads int) ([]tableOperation, common.RangeSet[uint64]) {
	var (
		bestLowLevelOps, bestOps []tableOperation
		required                 common.RangeSet[uint64]
	)
	for i := len(p.tableLevels) - 1; i >= 0; i-- {
		required = required.Union(target[i])
		if remove := complete[i].Union(partial[i]).Difference(required); !remove.IsEmpty() {
			// Note that we deliberately only add one delete operation candidate
			// per level in order to avoid delete operations always interrupting
			// all merge operations
			op := tableOperation{
				operation: opDelete,
				id: tableID{
					level: i,
					index: remove.Last(),
				},
			}
			p.addToOps(&bestLowLevelOps, op, lowLevelMergeThreads, true)
			p.addToOps(&bestOps, op, mergeThreads, false)
		}
		required = required.Difference(complete[i])
		if i > 0 {
			merge := required.Intersection(shiftRangeSetLevel(complete[i-1], p.tableLevels[i-1], p.tableLevels[i], false))
			for !merge.IsEmpty() {
				op := tableOperation{
					operation: opMerge,
					id: tableID{
						level: i,
						index: merge.Last(),
					},
				}
				add1 := p.addToOps(&bestLowLevelOps, op, lowLevelMergeThreads, true)
				add2 := p.addToOps(&bestOps, op, mergeThreads, false)
				if !add1 && !add2 {
					break
				}
				merge = merge.Difference(common.SingleRangeSet[uint64](common.NewRange[uint64](merge.Last(), 1)))
			}
			required = shiftRangeSetLevel(required, p.tableLevels[i], p.tableLevels[i-1], false)
		}
	}
	ops := bestLowLevelOps
	for _, op := range bestOps {
		if !p.addToOps(&ops, op, mergeThreads, true) {
			break
		}
	}
	return ops, required
}

// shiftRangeSetLevel maps a set of table indices from one hierarchy level to
// another. With partial set the mapping is optimistic (a lower table counts
// towards a higher one as soon as their ranges overlap), otherwise only fully
// covered mappings are returned.
func shiftRangeSetLevel(rs common.RangeSet[uint64], from, to tableLevel, partial bool) (result common.RangeSet[uint64]) {
	for _, r := range rs {
		rr := shiftRangeLevel(r, from, to, partial)
		if !rr.IsEmpty() {
			result = result.Union(common.SingleRangeSet[uint64](rr))
		}
	}
	return result
}

func shiftRangeLevel(r common.Range[uint64], from, to tableLevel, partial bool) common.Range[uint64] {
	first := r.First() * from.blockCount
	if !partial {
		first += to.blockCount - 1
	}
	first /= to.blockCount
	afterLast := r.AfterLast() * from.blockCount
	if partial {
		afterLast += to.blockCount - 1
	}
	afterLast /= to.blockCount
	if afterLast <= first {
		return common.Range[uint64]{}
	}
	return common.NewRange[uint64](first, afterLast-first)
}
