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
	"github.com/ethereum/go-ethereum/log"
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

// TableWritesForBlock builds the index table roots committed during the
// processing of the given block: the level-0 table covering the block itself
// and, whenever the publication schedule fires, the due higher-level table.
// The level-0 root depends only on the block number, the parent hash and the
// receipts, never on the producing block's own hash.
//
// The level-0 writer is registered as pending and finalized later by
// AddBlockData with the real block hash; until then only the root is known.
// Higher-level tables are merged on the spot when not already available.
func (ix *Indexer) TableWritesForBlock(blockNumber uint64, parentHash common.Hash, receipts types.Receipts) ([]TableWrite, error) {
	ix.lock.Lock()
	if ix.hasProcessedBlock {
		if err := ix.storage.deleteTable(tableID{level: 0, index: ix.processedBlockNumber}); err != nil && err != errTableNotFound {
			ix.lock.Unlock()
			return nil, err
		}
		ix.hasProcessedBlock = false
	}
	indexHeadHash := ix.headBlockHash
	// Mark the block pending before the writer is created: the index head
	// stays at the parent until AddBlockData seals it, so the scheduler would
	// otherwise see the new level-0 table as unrequired while it is being
	// filled. It is resolved by AddBlockData with the real block hash.
	ix.hasProcessedBlock = true
	ix.processedBlockNumber = blockNumber
	ix.processedBlockId = common.Hash{}
	ix.lock.Unlock()

	if indexHeadHash == (common.Hash{}) {
		// Fresh indexer: adopt the parent as head anchor so that the level-0
		// chain of custody can start at any height.
		ix.lock.Lock()
		if ix.headBlock == 0 {
			ix.headBlock, ix.headBlockHash = blockNumber-1, parentHash
		}
		ix.lock.Unlock()
	} else if parentHash != indexHeadHash {
		// Speculative or out-of-order processing (side chain, replay): the
		// level-0 root is still consensus-exact, but higher-level tables
		// depend on the maintained table state and are skipped.
		ix.lock.Lock()
		ix.hasProcessedBlock = false
		ix.lock.Unlock()
		return []TableWrite{{FirstBlock: blockNumber, TableSize: 1, Root: BuildLevel0Root(blockNumber, parentHash, receipts)}}, nil
	}
	ix.storage.deleteTablesFromBlock(blockNumber)

	entries := blockEntries(blockNumber, parentHash, receipts)
	id := tableID{level: 0, index: blockNumber}
	tw, err := ix.storage.addNewTableWriter(id, uint64(len(entries)))
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if err := tw.addEntry(entry); err != nil {
			ix.storage.deleteTable(id)
			return nil, err
		}
	}
	root := tw.root()

	writes := []TableWrite{{FirstBlock: blockNumber, TableSize: 1, Root: root}}
	for level := 1; level < len(TableSizes); level++ {
		size := TableSizes[level]
		// the table whose publication deadline falls on this block: its
		// range ended ts + ts/4 - 1 blocks ago
		delay := size + size/4 - 1
		if blockNumber <= delay {
			continue
		}
		firstBlock := blockNumber - delay
		// level tables are aligned: first_block must be a multiple of ts
		if firstBlock%size != 0 || PublicationSchedule(size, firstBlock) != blockNumber {
			continue
		}
		id := tableID{level: level, index: firstBlock / size}
		tr, err := ix.storage.getTableReader(id)
		if err != nil {
			// Not merged yet: merge on the spot. This needs the fully
			// covered source tables; on a fresh indexer close to the fork
			// they may not all be indexed yet, in which case the publication
			// is skipped and the table state catches up through the feed.
			// A concurrent background merge of the same table may claim it
			// first, so the reader is re-checked after every attempt.
			for attempt := 0; attempt < 3; attempt++ {
				if _, mergeErr := ix.mergeTable(id, func() bool { return false }); mergeErr != nil && attempt == 2 {
					log.Warn("Skipping index table publication", "level", id.level, "index", id.index, "error", mergeErr)
				}
				if tr, err = ix.storage.getTableReader(id); err == nil {
					break
				}
			}
			if err != nil {
				continue
			}
		}
		writes = append(writes, TableWrite{FirstBlock: firstBlock, TableSize: size, Root: tr.TableRoot})
	}
	return writes, nil
}
