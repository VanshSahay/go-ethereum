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

package common

import (
	"iter"
	"sort"
)

// RangeSet is an ordered, gap-less representation of a set of integers.
type RangeSet[T uint32 | uint64] []Range[T]

func (a RangeSet[T]) Includes(v T) bool {
	for _, r := range a {
		if r.Includes(v) {
			return true
		}
	}
	return false
}

type rangeBoundary[T uint32 | uint64] struct {
	v T
	d int
}

type rangeBoundaries[T uint32 | uint64] []rangeBoundary[T]

func (rb *rangeBoundaries[T]) add(r Range[T], d int) {
	*rb = append((*rb), rangeBoundary[T]{v: r.First(), d: d}, rangeBoundary[T]{v: r.AfterLast(), d: -d})
}

func (rb rangeBoundaries[T]) makeSet(threshold int) RangeSet[T] {
	res := make(RangeSet[T], 0, len(rb)/2)
	sort.Slice(rb, func(i, j int) bool {
		return rb[i].v < rb[j].v
	})
	var (
		sum     int
		lastCmp bool
		start   T
	)
	for i, r := range rb {
		sum += r.d
		cmp := sum >= threshold
		if cmp != lastCmp && (i == len(rb)-1 || rb[i+1].v != r.v) {
			if cmp {
				start = r.v
			} else {
				res = append(res, NewRange[T](start, r.v-start))
			}
			lastCmp = cmp
		}
	}
	return res
}

func (a RangeSet[T]) Intersection(b RangeSet[T]) RangeSet[T] {
	if len(a) == 0 || len(b) == 0 {
		return nil
	}
	rb := make(rangeBoundaries[T], 0, (len(a)+len(b))*2)
	for _, r := range a {
		rb.add(r, 1)
	}
	for _, r := range b {
		rb.add(r, 1)
	}
	return rb.makeSet(2)
}

func (a RangeSet[T]) Difference(b RangeSet[T]) RangeSet[T] {
	if len(a) == 0 {
		return nil
	}
	if len(b) == 0 {
		return a
	}
	rb := make(rangeBoundaries[T], 0, (len(a)+len(b))*2)
	for _, r := range a {
		rb.add(r, 1)
	}
	for _, r := range b {
		rb.add(r, -1)
	}
	return rb.makeSet(1)
}

func (a RangeSet[T]) Union(b RangeSet[T]) RangeSet[T] {
	if len(a) == 0 {
		return b
	}
	if len(b) == 0 {
		return a
	}
	rb := make(rangeBoundaries[T], 0, (len(a)+len(b))*2)
	for _, r := range a {
		rb.add(r, 1)
	}
	for _, r := range b {
		rb.add(r, 1)
	}
	return rb.makeSet(1)
}

// Iter iterates all integers in the range set.
func (r RangeSet[T]) Iter() iter.Seq[T] {
	return func(yield func(T) bool) {
		for _, rr := range r {
			for i := range rr.Iter() {
				if !yield(i) {
					break
				}
			}
		}
	}
}

func (a RangeSet[T]) Count() T {
	var count T
	for _, r := range a {
		count += r.Count()
	}
	return count
}

func (a RangeSet[T]) SingleRange() Range[T] {
	if len(a) > 1 {
		panic("singleRange called for non-continuous RangeSet")
	}
	if len(a) == 1 {
		return a[0]
	}
	return NewRange[T](0, 0)
}

func SingleRangeSet[T uint32 | uint64](r Range[T]) RangeSet[T] {
	if r.IsEmpty() {
		return nil
	}
	return RangeSet[T]{r}
}

func (a RangeSet[T]) Equal(b RangeSet[T]) bool {
	if len(a) != len(b) {
		return false
	}
	for i, r := range a {
		if b[i] != r {
			return false
		}
	}
	return true
}

func (a RangeSet[T]) IsEmpty() bool {
	return len(a) == 0
}

func (a RangeSet[T]) Last() T {
	if len(a) == 0 {
		panic("last item of empty range set is not allowed")
	}
	return a[len(a)-1].Last()
}

func (a RangeSet[T]) LastSection() Range[T] {
	if len(a) == 0 {
		return Range[T]{}
	}
	return a[len(a)-1]
}
