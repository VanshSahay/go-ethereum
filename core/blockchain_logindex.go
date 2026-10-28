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

package core

import (
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/logindex"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
)

const (
	// defaultLogIndexCatchup is the number of blocks below the head a fresh
	// or lagging log index catches up when no history length is configured.
	defaultLogIndexCatchup = 1 << 16

	// logIndexPollInterval is the fallback period at which the log index
	// re-checks the head, covering head changes that emit no head event.
	logIndexPollInterval = 5 * time.Second
)

// logIndexHistory is the number of recent blocks the log index keeps tables
// for: older ranges are trimmed, bounding its storage.
func (cfg *BlockChainConfig) logIndexHistory() uint64 {
	if cfg.LogIndexHistory == 0 {
		return defaultLogIndexCatchup
	}
	return cfg.LogIndexHistory
}

// The log index only serves queries: the table roots committed on chain are
// derived from the block history (see DeriveLogIndexWrites), never from the
// index. It therefore follows the canonical head asynchronously, outside the
// chain mutex, and reconciles itself against the chain whatever happened to
// it: new blocks, reorgs of any depth, sync gaps or a restart.

// startLogIndexer launches the goroutine keeping the log index on the
// canonical head.
func (bc *BlockChain) startLogIndexer() {
	bc.logIndexQuit = make(chan struct{})
	bc.logIndexWg.Add(1)
	go bc.logIndexLoop()
}

// stopLogIndexer stops the follower goroutine and then the index itself.
func (bc *BlockChain) stopLogIndexer() {
	if bc.logIndex == nil {
		return
	}
	if bc.logIndexQuit != nil {
		close(bc.logIndexQuit)
		bc.logIndexWg.Wait()
	}
	bc.logIndex.Stop()
}

func (bc *BlockChain) logIndexLoop() {
	defer bc.logIndexWg.Done()

	heads := make(chan ChainHeadEvent, 16)
	sub := bc.chainHeadFeed.Subscribe(heads)
	defer sub.Unsubscribe()
	ticker := time.NewTicker(logIndexPollInterval)
	defer ticker.Stop()

	bc.SyncLogIndex()
	for {
		select {
		case <-bc.logIndexQuit:
			return
		case <-heads:
		case <-ticker.C:
		}
		bc.SyncLogIndex()
	}
}

// SyncLogIndex brings the log index to the current canonical head and
// returns once it is there (or the head data is not available). It is safe to
// call concurrently; queries use it to get a fresh index on demand.
func (bc *BlockChain) SyncLogIndex() {
	if bc.logIndex == nil {
		return
	}
	bc.logIndexMu.Lock()
	defer bc.logIndexMu.Unlock()

	if head := bc.CurrentBlock(); head != nil {
		bc.reconcileLogIndex(head, false)
	}
}

// quickSyncBlocks bounds the work a query does to bring the index to the head.
const quickSyncBlocks = 64

// SyncLogIndexQuick is the query path's version of SyncLogIndex: it takes the
// few blocks between the index and the head if that is all there is to do and
// the follower is not busy, and otherwise leaves the catching up to the
// follower instead of making the query wait for it.
func (bc *BlockChain) SyncLogIndexQuick() {
	if bc.logIndex == nil || !bc.logIndexMu.TryLock() {
		return
	}
	defer bc.logIndexMu.Unlock()

	if head := bc.CurrentBlock(); head != nil {
		bc.reconcileLogIndex(head, true)
	}
}

// reconcileLogIndex rewinds the index to the common ancestor of its head and
// the given canonical head and feeds the blocks above the ancestor, oldest
// first. Blocks are read by hash from the database, so a concurrent reorg
// cannot mix chains.
func (bc *BlockChain) reconcileLogIndex(head *types.Header, quick bool) {
	ix := bc.logIndex
	if ix.HeadHash() == head.Hash() {
		if !quick {
			bc.backfillLogIndex(head)
		}
		return
	}
	limit := int(bc.cfg.logIndexHistory())
	if quick {
		limit = quickSyncBlocks
	}
	var old *types.Header
	if hash := ix.HeadHash(); hash != (common.Hash{}) {
		old = bc.GetHeader(hash, ix.HeadBlock())
	}
	var (
		path  []*types.Header // blocks above the common ancestor, newest first
		cur   = head
		found bool
	)
	for len(path) < limit {
		if old != nil && old.Hash() == cur.Hash() {
			found = true
			break
		}
		if old != nil && old.Number.Cmp(cur.Number) > 0 {
			old = bc.GetHeader(old.ParentHash, old.Number.Uint64()-1)
			continue
		}
		path = append(path, cur)
		if cur.Number.Sign() == 0 {
			break
		}
		if cur = bc.GetHeader(cur.ParentHash, cur.Number.Uint64()-1); cur == nil {
			break
		}
	}
	if quick && !found {
		return // too far behind for a query to wait for: the follower catches up
	}
	if found && old != nil && ix.HeadBlock() > old.Number.Uint64() {
		ix.Revert(old)
	}
	for i := len(path) - 1; i >= 0; i-- {
		select {
		case <-bc.logIndexQuit:
			return
		default:
		}
		header := path[i]
		if header.Number.Sign() == 0 {
			continue // the genesis block has no entries to index
		}
		body := bc.GetBody(header.Hash())
		receipts, err := bc.GetIndexReceipts(header.Hash(), header.Number.Uint64())
		if body == nil || err != nil {
			log.Warn("Log index cannot read block data", "number", header.Number, "hash", header.Hash(), "err", err)
			return
		}
		ix.AddBlockData(header, body, receipts)
	}
}

// logIndexBackfillBatch bounds the blocks repaired per reconciliation.
const logIndexBackfillBatch = 4096

// backfillLogIndex repairs holes in the retained range of the index, oldest
// first, reading the blocks of the canonical chain ending at head.
func (bc *BlockChain) backfillLogIndex(head *types.Header) {
	ix := bc.logIndex
	missing := ix.MissingBlocks()
	if missing.IsEmpty() {
		return
	}
	done := 0
	for n := range missing.Iter() {
		select {
		case <-bc.logIndexQuit:
			return // shutting down: do not hold up the chain's stop
		default:
		}
		if done >= logIndexBackfillBatch {
			return
		}
		hash := bc.GetCanonicalHash(n)
		header := bc.GetHeader(hash, n)
		if header == nil || ix.HeadHash() != head.Hash() {
			return
		}
		receipts, err := bc.GetIndexReceipts(hash, n)
		if err != nil {
			continue // receipts pruned: the block stays unindexed
		}
		ix.Backfill(header, receipts)
		done++
	}
}

// indexHistoryWindow is the number of blocks below a block whose receipts the
// EIP-8304 table derivation can need: the largest table's range plus its
// publication delay.
var indexHistoryWindow = func() uint64 {
	size := logindex.TableSizes[len(logindex.TableSizes)-1]
	return size + size/4 - 1
}()

// checkIndexHistory warns at startup when EIP-8304 is active at the head but
// the receipts the table derivation reads are missing from the database, for
// example after history pruning or a sync that skipped them. Blocks on which a
// table whose range covers a missing block falls due cannot be processed until
// the receipts are back; the other blocks are unaffected.
func (bc *BlockChain) checkIndexHistory() {
	head := bc.CurrentBlock()
	if head == nil || !bc.chainConfig.IsEIP8304(head.Number, head.Time) {
		return
	}
	var missing []uint64
	for n := head.Number.Uint64(); n > 0 && head.Number.Uint64()-n < indexHistoryWindow; n-- {
		hash := bc.GetCanonicalHash(n)
		if hash == (common.Hash{}) {
			continue
		}
		header := bc.GetHeader(hash, n)
		if header == nil || !bc.chainConfig.IsEIP8304(header.Number, header.Time) {
			break // below the activation: no table covers it
		}
		if body := bc.GetBody(hash); body != nil && len(body.Transactions) > 0 && !rawdb.HasReceipts(bc.db, hash, n) {
			missing = append(missing, n)
		}
	}
	if len(missing) > 0 {
		log.Warn("EIP-8304 table derivation needs receipts that are missing", "blocks", len(missing), "newest", missing[0], "oldest", missing[len(missing)-1], "window", indexHistoryWindow)
	}
}
