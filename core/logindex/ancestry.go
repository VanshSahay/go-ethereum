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

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/lru"
	"github.com/ethereum/go-ethereum/core/types"
)

// AncestorReader gives access to the history of the chain a block is being
// built on: the data the higher-level index tables are derived from.
type AncestorReader interface {
	// GetHeader returns the header with the given hash and number.
	GetHeader(hash common.Hash, number uint64) *types.Header

	// GetIndexReceipts returns the receipts of the given block with the
	// transaction hashes filled in, or an error if they are not available.
	GetIndexReceipts(hash common.Hash, number uint64) (types.Receipts, error)
}

// ErrNoAncestry is returned when a higher-level table is due for publication
// but the block history it is derived from cannot be reached, for example in
// stateless execution.
var ErrNoAncestry = errors.New("EIP-8304: block history not available to derive the due index table")

// DeriveTableWrites computes the index table roots committed by the block
// with the given number, parent hash and receipts: the level-0 table of the
// block itself and every higher-level table whose publication deadline falls
// on this block. The result is a pure function of the block's ancestry and
// of the activation rule: no local index state is consulted, so every node
// derives the same writes whatever it has indexed or how it got its chain.
//
// A table is only published if EIP-8304 is active at its first block (isActive
// is evaluated on that block's header). A due table whose history cannot be
// read is an error, never a silent omission.
func DeriveTableWrites(chain AncestorReader, isActive func(*types.Header) bool, number uint64, parentHash common.Hash, receipts types.Receipts) ([]TableWrite, error) {
	writes := []TableWrite{{FirstBlock: number, TableSize: 1, Root: BuildLevel0Root(number, parentHash, receipts)}}
	for level := 1; level < len(TableSizes); level++ {
		size := TableSizes[level]
		// the table whose publication deadline falls on this block: its
		// range ended size/4 blocks ago
		delay := size + size/4 - 1
		if number <= delay {
			continue
		}
		firstBlock := number - delay
		if firstBlock%size != 0 {
			continue
		}
		if chain == nil {
			return nil, ErrNoAncestry
		}
		root, published, err := deriveTableRoot(chain, isActive, number, parentHash, firstBlock, size)
		if err != nil {
			return nil, err
		}
		if published {
			writes = append(writes, TableWrite{FirstBlock: firstBlock, TableSize: size, Root: root})
		}
	}
	return writes, nil
}

// deriveTableRoot computes the root of the table covering [firstBlock,
// firstBlock+size) of the chain ending at the block with the given parent
// hash. It reports false if the table is not published because EIP-8304 was
// not active at its first block.
func deriveTableRoot(chain AncestorReader, isActive func(*types.Header) bool, number uint64, parentHash common.Hash, firstBlock, size uint64) (common.Hash, bool, error) {
	// The table is a function of the chain ending at the parent and the
	// activation rule, and blocks never change once they exist: a block that is
	// derived again (built by the miner, then imported; re-imported after a
	// reorg) reuses the result.
	key := derivedKey{parentHash, size}
	if cached, ok := derivedRoots.Get(key); ok {
		return cached.root, cached.published, nil
	}
	root, published, err := computeTableRoot(chain, isActive, number, parentHash, firstBlock, size)
	if err == nil {
		derivedRoots.Add(key, derivedRoot{root, published})
	}
	return root, published, err
}

type derivedKey struct {
	parent common.Hash
	size   uint64
}

type derivedRoot struct {
	root      common.Hash
	published bool
}

// derivedRoots caches derived higher-level table roots.
var derivedRoots = lru.NewCache[derivedKey, derivedRoot](256)

func computeTableRoot(chain AncestorReader, isActive func(*types.Header) bool, number uint64, parentHash common.Hash, firstBlock, size uint64) (common.Hash, bool, error) {
	// walk the ancestry from the parent down to the first block of the table
	headers := make([]*types.Header, 0, number-firstBlock)
	hash := parentHash
	for n := number - 1; n >= firstBlock; n-- {
		header := chain.GetHeader(hash, n)
		if header == nil {
			return common.Hash{}, false, fmt.Errorf("EIP-8304: header %d (%x) not available", n, hash[:4])
		}
		headers = append(headers, header)
		hash = header.ParentHash
	}
	// headers[len-1-k] is the header of block firstBlock+k
	first := headers[len(headers)-1]
	if !isActive(first) {
		return common.Hash{}, false, nil
	}
	b := types.NewIndexBuilder()
	for k := uint64(0); k < size; k++ {
		header := headers[uint64(len(headers))-1-k]
		receipts, err := chain.GetIndexReceipts(header.Hash(), firstBlock+k)
		if err != nil {
			return common.Hash{}, false, fmt.Errorf("EIP-8304: receipts of block %d: %w", firstBlock+k, err)
		}
		b.AddBlockEntries(header.ParentHash, firstBlock+k, receipts)
	}
	return b.Build(), true, nil
}
