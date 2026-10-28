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

	// BlockHashAt optionally returns the canonical hash of a block number,
	// used to validate persisted tables against the chain after a restart.
	// When nil, unvalidated tables are dropped on startup.
	BlockHashAt func(uint64) common.Hash
}

// Indexer builds and maintains the EIP-8304 index table hierarchy for the
// canonical chain. Level-0 tables are created one per block; the scheduler
// merges them into higher levels in the background as their ranges complete.
type Indexer struct {
	lock         sync.Mutex
	params       *Params
	config       Config
	storage      *tableStorage
	files        *tableFiles // nil in memory mode
	mergeThreads int

	currentOps    []tableOperation
	headBlock     uint64
	headBlockHash common.Hash
	finalBlock    uint64
	cutoffBlock   uint64
	recentHeads   *lru.Cache[common.Hash, *cachedBlockData]

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
// tests, chain generation and the parallel state processor.
func NewMemoryIndexer() *Indexer {
	params := DefaultParams()
	return newIndexer(params, Config{}, nil, newTableStorage(params))
}

// NewMemoryIndexerWithParams is NewMemoryIndexer for a custom table hierarchy.
func NewMemoryIndexerWithParams(params *Params) *Indexer {
	return newIndexer(params, Config{}, nil, newTableStorage(params))
}

// NewIndexer creates a file backed indexer storing tables under path and
// reloading any tables persisted there by a previous run. The indexer head is
// restored from the loaded tables so the scheduler cannot mistake the indexed
// range for untargeted; the startup validation may still rewind it if the
// newest tables fail the chain-of-custody check.
func NewIndexer(params *Params, config Config, path string) (*Indexer, error) {
	files, err := newTableFiles(path, 2000000000, 96)
	if err != nil {
		return nil, err
	}
	storage, err := newTableStorageFromFiles(params, files)
	if err != nil {
		files.close()
		return nil, err
	}
	ix := newIndexer(params, config, files, storage)
	if number, hash, found := storage.maxLastBlock(); found {
		ix.headBlock = number
		ix.headBlockHash = hash
	}
	return ix, nil
}

func newIndexer(params *Params, config Config, files *tableFiles, storage *tableStorage) *Indexer {
	ix := &Indexer{
		params:        params,
		config:        config,
		storage:       storage,
		files:         files,
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

// deliverInitBlock performs the startup chain-of-custody validation of the
// persisted tables. needs ix.lock.
func (ix *Indexer) deliverInitBlock() {
	number, request := ix.storage.requestInitBlockHash()
	if !request {
		return
	}
	if ix.config.BlockHashAt == nil {
		log.Warn("Dropping unvalidated index tables: no block hash source configured")
		ix.storage.dropPreInit()
		return
	}
	ix.storage.deliverInitBlockHash(number, ix.config.BlockHashAt(number))
}

// AddBlockData indexes a block that has become part of the canonical chain.
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
	switch {
	case blockNumber < ix.headBlock || (blockNumber == ix.headBlock && ix.headBlockHash != header.Hash()):
		// Canonical head moved (reorg): rewind and amputate every table
		// covering the reorg height or beyond, inclusive — the table at the
		// reorg height itself belongs to the old fork.
		ix.headBlock = blockNumber
		ix.headBlockHash = header.Hash()
		ix.storage.deleteTablesFromBlock(blockNumber)
		ix.recentHeads.Add(header.Hash(), &cachedBlockData{header: header, body: body, receipts: receipts, canonicalUntil: blockNumber})
		for _, key := range ix.recentHeads.Keys() {
			if bd, _ := ix.recentHeads.Get(key); bd.canonicalUntil > blockNumber {
				bd.canonicalUntil = blockNumber
			}
		}
	case blockNumber == ix.headBlock && ix.headBlockHash == header.Hash():
		ix.lock.Unlock()
		return // already indexed
	default:
		ix.headBlock = blockNumber
		ix.headBlockHash = header.Hash()
		ix.recentHeads.Add(header.Hash(), &cachedBlockData{header: header, body: body, receipts: receipts, canonicalUntil: blockNumber})
	}
	ix.lock.Unlock()
	err := ix.processBlockTable(header, receipts)
	if err == nil {
		ix.lock.Lock()
		ix.updateTableOperations()
		ix.lock.Unlock()
	}
	if err != nil {
		log.Error("Failed to add block data to log index", "number", header.Number.Uint64(), "error", err)
	}
}

// processBlockTable builds the level-0 table of the block from its receipts.
func (ix *Indexer) processBlockTable(header *types.Header, receipts types.Receipts) error {
	blockNumber := header.Number.Uint64()
	id := tableID{level: 0, index: blockNumber}
	complete, partial, _ := ix.storage.tables()
	if partial.includes(id) {
		if err := ix.storage.deleteTable(id); err != nil {
			return err
		}
	}
	if complete.includes(id) {
		return nil
	}
	entries := blockEntries(blockNumber, header.ParentHash, receipts)
	tw, err := ix.storage.addNewTableWriter(id, uint64(len(entries)))
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := tw.addEntry(entry); err != nil {
			ix.storage.deleteTable(id)
			return err
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
	completeSet, partialSet, initPhase := ix.storage.tables()
	if initPhase {
		ix.deliverInitBlock()
		return
	}
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

// ringSlots is the number of table roots the index contract keeps per level.
const ringSlots = 1024

// makeTargetSet computes the tables worth having: every table whose block
// range is fully covered by the retained range is targeted, so the scheduler
// builds the complete pyramid bottom-up. The range starts at block 1: the
// genesis block has no index table, so tables containing it (level index 0 at
// every level above zero) are never targeted and can never block the
// scheduler.
//
// A level only keeps the tables the index contract can still serve: the
// contract holds 1024 roots per level, so a table older than 1025 table sizes
// (plus the publication lag) is unprovable at its level and its range is
// covered by the higher levels. The scheduler deletes complete tables outside
// the target as soon as no incomplete higher-level table needs them as a
// merge source, which cuts the storage of the lower levels to their windows.
// Historic hierarchies keep everything: their contract has no ring.
func (ix *Indexer) makeTargetSet(complete tableSet) tableSet {
	if ix.headBlock == 0 {
		return ix.params.newTableSet()
	}
	rangeStart := max(ix.tailBlock(), 1)
	rangeEnd := max(ix.finalBlock, ix.headBlock)
	target := ix.params.newTableSet()
	for i := len(ix.params.tableLevels) - 1; i >= 0; i-- {
		start := rangeStart
		if !ix.params.historic {
			count := ix.params.tableLevels[i].blockCount
			span := ringSlots*count + count + count/4
			if ix.headBlock+1 > span {
				start = max(start, ix.headBlock+1-span)
			}
		}
		if start > rangeEnd {
			continue
		}
		blockRange := common.SingleRangeSet[uint64](common.NewRange[uint64](start, rangeEnd+1-start))
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

// GetRangeReaders returns the complete tables covering the given block range,
// highest level first, clamped to the canonical segment of the reference head.
// When publishedBefore is nonzero, tables published after that block are
// excluded: their ranges are covered by the published lower-level tables.
func (ix *Indexer) GetRangeReaders(refBlockHash common.Hash, blockRange common.Range[uint64], publishedBefore uint64) []*TableReader {
	ix.lock.Lock()
	defer ix.lock.Unlock()

	if refBd, ok := ix.recentHeads.Get(refBlockHash); ok {
		if refBd.canonicalUntil < blockRange.Last() {
			blockRange.SetLast(refBd.canonicalUntil)
		}
	}
	if blockRange.IsEmpty() {
		return nil
	}
	if ix.params.historic {
		publishedBefore = 0 // the roots are not on a publication schedule
	}
	return ix.storage.getRangeReaders(blockRange, publishedBefore)
}

// HeadBlock returns the block number of the index head.
func (ix *Indexer) HeadBlock() uint64 {
	ix.lock.Lock()
	defer ix.lock.Unlock()
	return ix.headBlock
}

// HeadHash returns the block hash of the index head.
func (ix *Indexer) HeadHash() common.Hash {
	ix.lock.Lock()
	defer ix.lock.Unlock()
	return ix.headBlockHash
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
	if ix.files != nil {
		ix.storage.close()
		ix.files.close()
	}
}

// MissingBlocks returns the blocks of the retained range [tail, head] that no
// complete table covers, for example after a crash lost unflushed small
// tables. They can be repaired with Backfill.
func (ix *Indexer) MissingBlocks() common.RangeSet[uint64] {
	ix.lock.Lock()
	defer ix.lock.Unlock()

	if ix.shutdown || ix.headBlock == 0 {
		return nil
	}
	complete, _, initPhase := ix.storage.tables()
	if initPhase {
		return nil
	}
	// only blocks some level still wants a table for: the lower levels drop
	// the old blocks on purpose (see makeTargetSet)
	var missing common.RangeSet[uint64]
	for level, rs := range ix.makeTargetSet(complete) {
		missing = missing.Union(shiftRangeSetLevel(rs, ix.params.tableLevels[level], ix.params.tableLevels[0], false))
	}
	for level, rs := range complete {
		covered := shiftRangeSetLevel(rs, ix.params.tableLevels[level], ix.params.tableLevels[0], false)
		missing = missing.Difference(covered)
	}
	return missing
}

// Backfill builds the level-0 table of a block below the index head that is
// missing. The head is not moved; the block must be on the chain the index
// follows.
func (ix *Indexer) Backfill(header *types.Header, receipts types.Receipts) {
	ix.lock.Lock()
	if ix.shutdown || header.Number.Uint64() >= ix.headBlock {
		ix.lock.Unlock()
		return
	}
	ix.lock.Unlock()
	err := ix.processBlockTable(header, receipts)
	if err == nil {
		ix.lock.Lock()
		ix.updateTableOperations()
		ix.lock.Unlock()
	} else {
		log.Error("Failed to backfill log index block", "number", header.Number, "error", err)
	}
}
