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
	"github.com/ethereum/go-ethereum/core/types"
)

// TableWrite describes a table root that is to be written to the index
// contract by the block's post-processing system calls.
type TableWrite struct {
	FirstBlock uint64
	TableSize  uint64
	Root       common.Hash
}

// PublicationSchedule returns the block number at which the table of the
// given size whose range starts at firstBlock is committed on-chain, per the
// EIP-8304 indexing rules: higher-level tables are added after processing
// block first_block + table_size + table_size/4 - 1.
func PublicationSchedule(tableSize, firstBlock uint64) uint64 {
	return firstBlock + tableSize + tableSize/4 - 1
}

// BuildLevel0Root computes the level-0 table root of a single block without
// any indexer state: the SHA2-256 binary tree hash of the block's sorted
// entries with the entry count mixed in.
func BuildLevel0Root(blockNumber uint64, parentHash common.Hash, receipts types.Receipts) common.Hash {
	return types.IndexTableRoot(blockEntries(blockNumber, parentHash, receipts))
}
