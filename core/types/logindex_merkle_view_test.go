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

package types

import (
	"crypto/sha256"
	"encoding/binary"
	"math/bits"
	"testing"
)

// TestMerkleNodeHashRoot pins the interior-node view against the vector-pinned
// root computation: the node at tree index 1 is the un-mixed tree root, and
// mixing in the little-endian entry count yields the table root.
func TestMerkleNodeHashRoot(t *testing.T) {
	for _, n := range []int{1, 2, 3, 5, 8, 17, 100, 1000} {
		entries := syntheticEntries(n)
		wantRoot := merkleizeEntries(entries)
		node, err := MerkleNodeHash(entries, 1)
		if err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}
		// The table root is the tree node with the entry count mixed in.
		var countEnc [32]byte
		binary.LittleEndian.PutUint64(countEnc[:8], uint64(n))
		folded := sha256.Sum256(append(node[:], countEnc[:]...))
		if folded != wantRoot {
			t.Errorf("n=%d: mixed node 1 = %x, want %x", n, folded, wantRoot)
		}
		if n < 2 {
			// A single-entry tree has height 0: node 1 is the leaf itself and
			// there are no children.
			if node != EntryLeafHash(entries[0]) {
				t.Errorf("n=1: node 1 = %x, want the leaf hash", node)
			}
			continue
		}
		left, err := MerkleNodeHash(entries, 2)
		if err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}
		right, err := MerkleNodeHash(entries, 3)
		if err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}
		if tree := sha256.Sum256(append(left[:], right[:]...)); tree != node {
			t.Errorf("n=%d: folded children = %x, want node 1 %x", n, tree, node)
		}
	}
}

// TestMerkleNodeHashLeavesAndZero pins the leaf and zero-subtree resolution:
// leaves hash their entry, subtrees entirely beyond the last entry resolve to
// the zero ladder at the exact height they would span.
func TestMerkleNodeHashLeavesAndZero(t *testing.T) {
	entries := syntheticEntries(17)
	h := uint(64 - bits.LeadingZeros64(uint64(len(entries)-1)))
	leafOffset := uint64(1) << h
	for i := range entries {
		got, err := MerkleNodeHash(entries, leafOffset+uint64(i))
		if err != nil {
			t.Fatalf("leaf %d: %v", i, err)
		}
		if want := EntryLeafHash(entries[i]); got != want {
			t.Errorf("leaf %d: %x, want %x", i, got, want)
		}
	}
	// The first zero leaf right after the last real entry.
	got, err := MerkleNodeHash(entries, leafOffset+uint64(len(entries)))
	if err != nil {
		t.Fatal(err)
	}
	if want := MerkleZeroHash(0); got != want {
		t.Errorf("zero leaf: %x, want %x", got, want)
	}
	// A height-1 subtree whose two leaves are both beyond the last entry:
	// the sibling of the node covering the last real leaf and the first zero.
	got, err = MerkleNodeHash(entries, (leafOffset+uint64(len(entries)))/2+1)
	if err != nil {
		t.Fatal(err)
	}
	if want := MerkleZeroHash(1); got != want {
		t.Errorf("zero subtree: %x, want %x", got, want)
	}
}

// TestMerkleNodeHashErrors pins the invalid index rejection.
func TestMerkleNodeHashErrors(t *testing.T) {
	entries := syntheticEntries(4)
	if _, err := MerkleNodeHash(entries, 0); err == nil {
		t.Error("tree index 0: expected error")
	}
	if _, err := MerkleNodeHash(nil, 1); err == nil {
		t.Error("empty entry list: expected error")
	}
	if _, err := MerkleNodeHash(entries, 1<<32); err == nil {
		t.Error("tree index beyond leaf level: expected error")
	}
}
