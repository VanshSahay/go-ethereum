// Copyright 2025 The go-ethereum Authors
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
	"sync"

	"github.com/ethereum/go-ethereum/common"
)

// LogIndexState tracks the in-progress ChainedTable builds across blocks.
type LogIndexState struct {
	// Hook is an optional callback for tests.
	Hook func(hook string, args ...interface{})

	// ChainParents holds the current parent root for each level (0-4).
	ChainParents [5]common.Hash

	// ScheduledRoots stores computed table roots awaiting publication.
	// Key: (level << 56 | blockNumber)
	ScheduledRoots map[uint64]common.Hash
}

// NewLogIndexState creates a fresh state (all zero parents, no scheduled roots).
func NewLogIndexState() *LogIndexState {
	return &LogIndexState{
		ScheduledRoots: make(map[uint64]common.Hash),
	}
}

// scheduleKey encodes a (level, blockNumber) pair into a single uint64 key.
func scheduleKey(level uint8, blockNum uint64) uint64 {
	return uint64(level)<<56 | blockNum
}

// ScheduleTable stores a table root for later publication.
func (s *LogIndexState) ScheduleTable(level uint8, blockNum uint64, root common.Hash) {
	s.ScheduledRoots[scheduleKey(level, blockNum)] = root
}

// GetScheduledTable retrieves and removes a scheduled table root.
func (s *LogIndexState) GetScheduledTable(level uint8, blockNum uint64) (common.Hash, bool) {
	root, ok := s.ScheduledRoots[scheduleKey(level, blockNum)]
	if ok {
		delete(s.ScheduledRoots, scheduleKey(level, blockNum))
	}
	return root, ok
}

// UpdateChainParent sets the current chain parent for a level.
func (s *LogIndexState) UpdateChainParent(level uint8, root common.Hash) {
	s.ChainParents[level] = root
}

// GetChainParent returns the current chain parent for a level.
func (s *LogIndexState) GetChainParent(level uint8) common.Hash {
	return s.ChainParents[level]
}

// in-memory store keyed by block number
var logIndexStateStore = make(map[uint64]*LogIndexState)
var logIndexStateLock sync.RWMutex

// LoadLogIndexState loads the state for a given block number.
// Returns a fresh state if none exists.
func LoadLogIndexState(blockNumber uint64) *LogIndexState {
	logIndexStateLock.RLock()
	state, ok := logIndexStateStore[blockNumber]
	logIndexStateLock.RUnlock()
	if ok {
		return state
	}
	return NewLogIndexState()
}

// SaveLogIndexState saves the state for a given block number.
func SaveLogIndexState(blockNumber uint64, state *LogIndexState) {
	logIndexStateLock.Lock()
	logIndexStateStore[blockNumber] = state
	logIndexStateLock.Unlock()
}
