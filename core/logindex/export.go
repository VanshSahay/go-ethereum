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
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/core/types"
)

// ExportTableRoots computes the roots of every complete table of the given
// sizes in the chain ending at head, for example to hardcode them into a
// historic index contract (out-of-protocol operation). Tables start at
// aligned first blocks from 1 on, like the tables the protocol publishes.
// The roots are derived from the chain's headers and receipts alone.
func ExportTableRoots(chain AncestorReader, head *types.Header, sizes []uint64) ([]TableWrite, error) {
	if head == nil || head.Number.Sign() == 0 {
		return nil, errors.New("nothing to export")
	}
	headNumber := head.Number.Uint64()
	headers := make([]*types.Header, headNumber+1) // by block number
	headers[headNumber] = head
	for n := headNumber; n > 1; n-- {
		parent := chain.GetHeader(headers[n].ParentHash, n-1)
		if parent == nil {
			return nil, fmt.Errorf("header %d not available", n-1)
		}
		headers[n-1] = parent
	}
	var writes []TableWrite
	for _, size := range sizes {
		if size == 0 {
			return nil, errors.New("zero table size")
		}
		for first := max(size, 1); first+size-1 <= headNumber; first += size {
			b := types.NewIndexBuilder()
			for n := first; n < first+size; n++ {
				receipts, err := chain.GetIndexReceipts(headers[n].Hash(), n)
				if err != nil {
					return nil, fmt.Errorf("receipts of block %d: %w", n, err)
				}
				b.AddBlockEntries(headers[n].ParentHash, n, receipts)
			}
			writes = append(writes, TableWrite{FirstBlock: first, TableSize: size, Root: b.Build()})
		}
	}
	return writes, nil
}
