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

package common

import (
	"math/rand"
	"testing"
)

const rangeSetUniverse = 48

type bitmap [rangeSetUniverse]bool

// fromBitmap builds the range set holding the set bits of the bitmap.
func fromBitmap(b bitmap) RangeSet[uint64] {
	var rs RangeSet[uint64]
	for i := uint64(0); i < rangeSetUniverse; {
		if !b[i] {
			i++
			continue
		}
		j := i
		for j < rangeSetUniverse && b[j] {
			j++
		}
		rs = rs.Union(SingleRangeSet(NewRange(i, j-i)))
		i = j
	}
	return rs
}

func randomBitmap(rng *rand.Rand) bitmap {
	var b bitmap
	density := rng.Intn(5) + 1
	for i := range b {
		b[i] = rng.Intn(6) < density
	}
	return b
}

func checkAgainstBitmap(t *testing.T, name string, rs RangeSet[uint64], want bitmap) {
	t.Helper()
	var count uint64
	for i := range uint64(rangeSetUniverse) {
		if rs.Includes(i) != want[i] {
			t.Fatalf("%s: Includes(%d) = %v, want %v (set %v)", name, i, rs.Includes(i), want[i], rs)
		}
		if want[i] {
			count++
		}
	}
	if rs.Count() != count {
		t.Fatalf("%s: Count = %d, want %d", name, rs.Count(), count)
	}
	if rs.IsEmpty() != (count == 0) {
		t.Fatalf("%s: IsEmpty = %v with %d elements", name, rs.IsEmpty(), count)
	}
	// the ranges must be sorted, non-empty and separated by gaps
	for i, r := range rs {
		if r.IsEmpty() {
			t.Fatalf("%s: empty range in %v", name, rs)
		}
		if i > 0 && rs[i-1].AfterLast() >= r.First() {
			t.Fatalf("%s: ranges not normalized in %v", name, rs)
		}
	}
	// the iteration yields the elements in ascending order
	next := uint64(0)
	for v := range rs.Iter() {
		for next < v {
			if want[next] {
				t.Fatalf("%s: Iter skipped %d", name, next)
			}
			next++
		}
		if !want[v] {
			t.Fatalf("%s: Iter yielded %d which is not in the set", name, v)
		}
		next = v + 1
	}
	for ; next < rangeSetUniverse; next++ {
		if want[next] {
			t.Fatalf("%s: Iter ended before %d", name, next)
		}
	}
}

// TestRangeSetAlgebra compares the set operations against a bitmap oracle.
func TestRangeSetAlgebra(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for range 500 {
		a, b := randomBitmap(rng), randomBitmap(rng)
		ra, rb := fromBitmap(a), fromBitmap(b)
		checkAgainstBitmap(t, "a", ra, a)

		var union, inter, diff bitmap
		for i := range a {
			union[i] = a[i] || b[i]
			inter[i] = a[i] && b[i]
			diff[i] = a[i] && !b[i]
		}
		checkAgainstBitmap(t, "union", ra.Union(rb), union)
		checkAgainstBitmap(t, "intersection", ra.Intersection(rb), inter)
		checkAgainstBitmap(t, "difference", ra.Difference(rb), diff)
		if !ra.Equal(fromBitmap(a)) {
			t.Fatalf("set %v not equal to itself rebuilt", ra)
		}
	}
}

// TestRangeSetIterEarlyBreak pins that stopping an iteration early stops it:
// the iterator must not call the yield function again after it returned false.
func TestRangeSetIterEarlyBreak(t *testing.T) {
	rs := SingleRangeSet(NewRange[uint64](1, 3)).
		Union(SingleRangeSet(NewRange[uint64](10, 3))).
		Union(SingleRangeSet(NewRange[uint64](20, 3)))
	for stop := 1; stop <= 9; stop++ {
		var got []uint64
		for v := range rs.Iter() {
			got = append(got, v)
			if len(got) == stop {
				break
			}
		}
		if len(got) != stop {
			t.Fatalf("stopped after %d elements, iterated %d: %v", stop, len(got), got)
		}
	}
}
