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
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/lru"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
)

const (
	headCacheSize   = 4
	maxMergeThreads = 1
)

// Config contains the configuration options for the indexer.
type Config struct {
	History  uint64 // number of historical blocks to index
	Disabled bool   // disables indexing completely
}

// Indexer builds and maintains the EIP-8304 index table hierarchy for the
// canonical chain. Level-0 tables are created one per block; the scheduler
// merges them into higher levels in the background as their ranges complete.
type Indexer struct {
	lock         sync.Mutex
	params       *Params
	config       Config
	storage      *tableStorage
	mergeThreads int

	currentOps           []tableOperation
	headBlock            uint64
	headBlockHash        common.Hash
	finalBlock           uint64
	cutoffBlock          uint64
	hasProcessedBlock    bool
	processedBlockNumber uint64
	processedBlockId     common.Hash
	recentHeads          *lru.Cache[common.Hash, *cachedBlockData]

	shutdown      bool
	updateMergeCh []chan struct{}
	mergeWg       sync.WaitGroup
}

type cachedBlockData struct {
	header         *types.Header
	body           *types.Body
	receipts       types.Receipts
	canonicalUntil uint64
}

// NewMemoryIndexer creates an indexer that keeps all tables in RAM. Used by
// tests, chain generation and the parallel state processor; the file backed
// constructor is added with persistent storage.
func NewMemoryIndexer() *Indexer {
	params := DefaultParams()
	ix := &Indexer{
		params:        params,
		storage:       newTableStorage(params),
		mergeThreads:  maxMergeThreads,
		currentOps:    make([]tableOperation, maxMergeThreads),
		recentHeads:   lru.NewCache[common.Hash, *cachedBlockData](headCacheSize),
		updateMergeCh: make([]chan struct{}, maxMergeThreads),
	}
	for i := range ix.updateMergeCh {
		ix.updateMergeCh[i] = make(chan struct{}, 1)
	}
	ix.mergeWg.Add(maxMergeThreads)
	for i := range maxMergeThreads {
		go ix.mergeLoop(i)
	}
	return ix
}

// AddBlockData indexes a block that has become part of the canonical chain. If
// a level-0 table was already built for this block during state processing,
// the pending writer is finalized with the real block hash; otherwise the
// table is built from the given data.
func (ix *Indexer) AddBlockData(header *types.Header, body *types.Body, receipts types.Receipts) {
	ix.lock.Lock()
	if ix.shutdown {
		ix.lock.Unlock()
		return
	}
	if body == nil || receipts == nil {
		ix.lock.Unlock()
		return
	}
	blockNumber := header.Number.Uint64()
	if blockNumber >= ix.headBlock {
		ix.headBlock = blockNumber
		ix.headBlockHash = header.Hash()
		ix.recentHeads.Add(header.Hash(), &cachedBlockData{header: header, body: body, receipts: receipts, canonicalUntil: blockNumber})
	}
	if blockNumber < ix.headBlock {
		// unexpected block, do not create table
		ix.lock.Unlock()
		return
	}
	tw, err := ix.getPartialBlockTableWriter(header)
	ix.lock.Unlock()
	if err == nil {
		err = ix.processBlockTable(tw, header, body, receipts)
	}
	if err == nil {
		ix.lock.Lock()
		ix.updateTableOperations()
		ix.lock.Unlock()
	}
	if err != nil {
		log.Error("Failed to add block data to log index", "number", header.Number.Uint64(), "error", err)
	}
}

// getPartialBlockTableWriter resolves the pending writer created during state
// processing, if any. A writer whose block id does not match the actual header
// (superseded proposal) is deleted so the table is rebuilt from the delivered
// data.
func (ix *Indexer) getPartialBlockTableWriter(header *types.Header) (*tableWriter, error) {
	var tw *tableWriter
	if ix.hasProcessedBlock && ix.processedBlockNumber == header.Number.Uint64() {
		if header.Hash() == ix.processedBlockId {
			var err error
			if tw, err = ix.storage.getTableWriter(tableID{level: 0, index: ix.processedBlockNumber}); err != nil {
				return nil, err
			}
		} else {
			if err := ix.storage.deleteTable(tableID{level: 0, index: ix.processedBlockNumber}); err != nil {
				return nil, err
			}
		}
		ix.hasProcessedBlock = false
	}
	return tw, nil
}

// processBlockTable finalizes the pending level-0 writer or builds the table
// from the given block data.
func (ix *Indexer) processBlockTable(tw *tableWriter, header *types.Header, body *types.Body, receipts types.Receipts) error {
	blockNumber := header.Number.Uint64()
	id := tableID{level: 0, index: blockNumber}
	if tw == nil {
		complete, partial := ix.storage.tables()
		if partial.includes(id) {
			if err := ix.storage.deleteTable(id); err != nil {
				return err
			}
		}
		if complete.includes(id) {
			return nil
		}
		entries := blockEntries(blockNumber, header.ParentHash, receipts)
		var err error
		if tw, err = ix.storage.addNewTableWriter(id, uint64(len(entries))); err != nil {
			return err
		}
		for _, entry := range entries {
			if err := tw.addEntry(entry); err != nil {
				ix.storage.deleteTable(id)
				return err
			}
		}
	}
	tw.setMeta(TableMeta{
		LastBlockNumber: blockNumber,
		BlockCount:      1,
		LastBlockHash:   header.Hash(),
		ParentHash:      header.ParentHash,
	})
	for {
		done, err := tw.finalize()
		if err != nil {
			ix.storage.deleteTable(id)
			return err
		}
		if done {
			break
		}
	}
	return ix.storage.finalizeTableWriter(id)
}

// updateTableOperations re-runs the merge scheduler and wakes the merge loop
// when the scheduled operations changed.
func (ix *Indexer) updateTableOperations() {
	completeSet, partialSet := ix.storage.tables()
	targetSet := ix.makeTargetSet(completeSet)
	tableOps, _ := ix.params.nextTableOperations(completeSet, partialSet, targetSet, ix.mergeThreads, ix.mergeThreads)
	updateOps := make([]bool, ix.mergeThreads)
	for i, co := range ix.currentOps {
		var found bool
	innerLoop:
		for j, to := range tableOps {
			if co == to {
				tableOps[j] = tableOperation{}
				found = true
				break innerLoop
			}
		}
		if !found {
			ix.currentOps[i] = tableOperation{}
			updateOps[i] = true
		}
	}
	var i int
	for _, to := range tableOps {
		if to == (tableOperation{}) {
			continue
		}
		for ix.currentOps[i] != (tableOperation{}) {
			i++
		}
		ix.currentOps[i] = to
		updateOps[i] = true
		i++
	}
	for i, update := range updateOps {
		if update {
			select {
			case ix.updateMergeCh[i] <- struct{}{}:
			default:
			}
		}
	}
}

// makeTargetSet computes the tables worth having: every table whose block
// range is fully covered by the indexed range is targeted at every level, so
// the scheduler builds the complete pyramid bottom-up. The range starts at
// block 1: the genesis block has no index table, so tables containing it
// (level index 0 at every level above zero) are never targeted and can never
// block the scheduler. Local tables are not pruned; retention is local policy,
// the 1024-table rings live in the index contract.
func (ix *Indexer) makeTargetSet(complete tableSet) tableSet {
	if ix.headBlock == 0 {
		return ix.params.newTableSet()
	}
	rangeStart := max(ix.tailBlock(), 1)
	rangeEnd := max(ix.finalBlock, ix.headBlock)
	blockRange := common.SingleRangeSet[uint64](common.NewRange[uint64](rangeStart, rangeEnd+1-rangeStart))
	target := ix.params.newTableSet()
	for i := len(ix.params.tableLevels) - 1; i >= 0; i-- {
		target[i] = shiftRangeSetLevel(blockRange, ix.params.tableLevels[0], ix.params.tableLevels[i], false)
	}
	return target
}

// Revert rewinds the index head to the given header and amputates all tables
// covering blocks after it.
func (ix *Indexer) Revert(header *types.Header) {
	ix.lock.Lock()
	defer ix.lock.Unlock()

	if ix.shutdown {
		return
	}
	blockNumber := header.Number.Uint64()
	if blockNumber >= ix.headBlock {
		log.Error("Invalid indexer revert", "from", ix.headBlock, "to", blockNumber)
		return
	}
	ix.headBlock = blockNumber
	ix.headBlockHash = header.Hash()
	ix.cutoffBlock = min(ix.cutoffBlock, ix.headBlock+1)
	ix.storage.deleteTablesFromBlock(blockNumber + 1)
	ix.updateTableOperations()
	for _, key := range ix.recentHeads.Keys() {
		bd, _ := ix.recentHeads.Get(key)
		if bd.canonicalUntil > blockNumber {
			bd.canonicalUntil = blockNumber
		}
	}
}

func (ix *Indexer) tailBlock() uint64 {
	if ix.config.History == 0 {
		return ix.cutoffBlock
	}
	return max(ix.cutoffBlock, max(ix.headBlock, ix.config.History-1)-ix.config.History+1)
}

// SetHistoryCutoff trims the indexing target range from below.
func (ix *Indexer) SetHistoryCutoff(blockNumber uint64) {
	ix.lock.Lock()
	defer ix.lock.Unlock()

	if ix.shutdown {
		return
	}
	ix.cutoffBlock = min(blockNumber, ix.headBlock+1)
	ix.updateTableOperations()
}

// SetFinalized updates the finalized head, extending the target range if the
// finalized head is ahead.
func (ix *Indexer) SetFinalized(blockNumber uint64) {
	ix.lock.Lock()
	defer ix.lock.Unlock()

	if ix.shutdown {
		return
	}
	ix.finalBlock = blockNumber
	ix.updateTableOperations()
}

// Stop shuts down the merge loop and closes the storage.
func (ix *Indexer) Stop() {
	ix.lock.Lock()
	if ix.shutdown {
		ix.lock.Unlock()
		return
	}
	ix.shutdown = true
	ix.lock.Unlock()
	for _, ch := range ix.updateMergeCh {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	ix.mergeWg.Wait()
}
