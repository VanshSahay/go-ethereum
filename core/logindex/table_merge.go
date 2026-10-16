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
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
)

func (ix *Indexer) mergeLoop(threadIndex int) {
	defer ix.mergeWg.Done()

	for {
		ix.lock.Lock()
		currentOp, shutdown := ix.currentOps[threadIndex], ix.shutdown
		ix.lock.Unlock()
		for !shutdown && currentOp.operation == opNone {
			<-ix.updateMergeCh[threadIndex]
			ix.lock.Lock()
			currentOp, shutdown = ix.currentOps[threadIndex], ix.shutdown
			ix.lock.Unlock()
		}
		if shutdown {
			return
		}
		switch currentOp.operation {
		case opDelete:
			if err := ix.storage.deleteTable(currentOp.id); err != nil {
				r := ix.params.blockRange(currentOp.id)
				log.Error("Failed to delete index table", "start", r.First(), "count", r.Count(), "error", err)
			}
			ix.lock.Lock()
			ix.updateTableOperations()
			ix.lock.Unlock()
		case opMerge:
			_, err := ix.mergeTable(currentOp.id, func() bool {
				select {
				case <-ix.updateMergeCh[threadIndex]:
					return true
				default:
					return false
				}
			})
			if err != nil {
				r := ix.params.blockRange(currentOp.id)
				log.Error("Failed to merge index table", "start", r.First(), "count", r.Count(), "error", err)
				// back off before the operation is rescheduled, so a
				// permanently failing merge cannot spin the thread
				time.Sleep(100 * time.Millisecond)
			}
			// reschedule in every case: a failed operation must not wedge
			// the thread against the operations the scheduler wants next
			ix.lock.Lock()
			ix.updateTableOperations()
			ix.lock.Unlock()
		}
	}
}

// mergeTable merges the fully covered source tables one level below id into
// the destination table, streaming the sorted entries k-way. An interrupted
// merge leaves a partial writer behind and resumes from it: the resume point
// in every source is reconstructed from the writer's last entry via SeekEntry
// and validated against the number of entries already written.
func (ix *Indexer) mergeTable(id tableID, stopFn func() bool) (finalized bool, finalErr error) {
	if id.level == 0 {
		panic("cannot merge table on the lowest level")
	}
	// the table may have been completed by a concurrent merge while this
	// operation was scheduled
	if _, err := ix.storage.getTableReader(id); err == nil {
		return true, nil
	}
	sourceIndices := shiftRangeLevel(common.NewRange[uint64](id.index, 1), ix.params.tableLevels[id.level], ix.params.tableLevels[id.level-1], false)
	readers := make([]*TableReader, sourceIndices.Count())
	var entryCount uint64
	for i := range readers {
		tr, err := ix.storage.getTableReader(tableID{level: id.level - 1, index: sourceIndices.First() + uint64(i)})
		if err != nil {
			return false, err
		}
		entryCount += tr.EntryCount
		readers[i] = tr
	}
	tw, err := ix.storage.getTableWriter(id)
	if err == errTableNotFound {
		// re-check after the sources were opened: a concurrent merge may have
		// completed the table in the meantime
		if _, err := ix.storage.getTableReader(id); err == nil {
			return true, nil
		}
		tw, err = ix.storage.addNewTableWriter(id, entryCount)
		if err != nil {
			return false, err
		}
		// initialize table metadata
		r := ix.params.blockRange(id)
		tw.setMeta(TableMeta{
			LastBlockNumber: r.Last(),
			BlockCount:      r.Count(),
			LastBlockHash:   readers[len(readers)-1].Meta.LastBlockHash,
			ParentHash:      readers[0].Meta.ParentHash,
		})
	}
	if err != nil {
		return false, err
	}
	defer func() {
		if !finalized {
			err := ix.storage.releaseTableWriter(id)
			if finalErr == nil {
				finalErr = err
			}
		}
	}()
	if tw.entryCount() != entryCount {
		return false, errors.New("entry count mismatch")
	}
	lastEntry, nextEntry := tw.lastAndNextEntry()
	if tw.getPhase() == wpWriteEntries && nextEntry != entryCount {
		nextReadPosition := make([]uint64, len(readers))
		nextReadEntry := make([]types.IndexEntry, len(readers))
		if nextEntry != 0 {
			// find next read position in each source reader
			if lastEntry == nil {
				return false, errors.New("last entry not found")
			}
			var checkNextEntry uint64
			for i, tr := range readers {
				pos, found, err := tr.SeekEntry(lastEntry)
				if err != nil {
					return false, err
				}
				if found {
					pos++
				}
				nextReadPosition[i] = pos
				checkNextEntry += pos
			}
			if checkNextEntry != nextEntry {
				return false, errors.New("next entry mismatch")
			}
		}
		for i, tr := range readers {
			if nextReadPosition[i] < tr.EntryCount {
				var err error
				nextReadEntry[i], err = tr.GetEntry(nextReadPosition[i])
				if err != nil {
					return false, err
				}
			}
		}
		for nextEntry < entryCount {
			if nextEntry%10000 == 0 && stopFn() {
				return false, nil
			}
			var (
				bestIndex int
				bestEntry types.IndexEntry
			)
			for i, entry := range nextReadEntry {
				if entry != nil && (bestEntry == nil || types.CompareEntries(entry, bestEntry) < 0) {
					bestIndex, bestEntry = i, entry
				}
			}
			if err := tw.addEntry(bestEntry); err != nil {
				return false, err
			}
			nextEntry++
			nextReadPosition[bestIndex]++
			if nextReadPosition[bestIndex] < readers[bestIndex].EntryCount {
				var err error
				nextReadEntry[bestIndex], err = readers[bestIndex].GetEntry(nextReadPosition[bestIndex])
				if err != nil {
					return false, err
				}
			} else {
				nextReadEntry[bestIndex] = nil
			}
		}
	}
	for {
		if stopFn() {
			return false, nil
		}
		done, err := tw.finalize()
		if err != nil {
			return false, err
		}
		if done {
			break
		}
	}
	if tw.getPhase() != wpFinalized {
		panic("invalid table write phase")
	}
	if err := ix.storage.finalizeTableWriter(id); err != nil {
		return false, err
	}
	return true, nil
}
