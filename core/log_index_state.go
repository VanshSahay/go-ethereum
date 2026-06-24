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
	"github.com/ethereum/go-ethereum/common"
)

// LogIndexState persists the in-progress ChainedTable builds across blocks.
// It tracks scheduled table roots (computed at the "schedule" block, published
// one delay later) and the current parent root for each of the 4 chains.
type LogIndexState struct {
	// ScheduledRoots maps (chainIndex << 56 | blockNumber) to the table root
	// computed at the schedule block. The key encoding ensures unique keys
	// for any (chain, block) pair.
	ScheduledRoots map[uint64]common.Hash

	// ChainParents holds the current parent root for each chain (0-3).
	// This is the Table root from the most recently published table in the chain,
	// or the zero hash for the initial (fork-boundary) state.
	ChainParents [4]common.Hash
}

// NewLogIndexState creates a new LogIndexState with zero parents and an
// empty scheduled roots map. This is the state at the fork boundary.
func NewLogIndexState() *LogIndexState {
	return &LogIndexState{
		ScheduledRoots: make(map[uint64]common.Hash),
	}
}

// scheduleKey encodes a (chainIndex, blockNumber) pair into a single uint64 key.
func scheduleKey(chainIdx uint8, blockNum uint64) uint64 {
	return (uint64(chainIdx) << 56) | blockNum
}

// ScheduleTable stores a table root for later publication.
func (s *LogIndexState) ScheduleTable(chainIdx uint8, blockNum uint64, root common.Hash) {
	s.ScheduledRoots[scheduleKey(chainIdx, blockNum)] = root
}

// GetScheduledTable retrieves a previously scheduled table root.
func (s *LogIndexState) GetScheduledTable(chainIdx uint8, blockNum uint64) (common.Hash, bool) {
	root, ok := s.ScheduledRoots[scheduleKey(chainIdx, blockNum)]
	return root, ok
}

// UpdateChainParent updates the parent root for a chain after publishing.
func (s *LogIndexState) UpdateChainParent(chainIdx uint8, root common.Hash) {
	s.ChainParents[chainIdx] = root
}

// GetChainParent returns the current parent root for a chain.
func (s *LogIndexState) GetChainParent(chainIdx uint8) common.Hash {
	return s.ChainParents[chainIdx]
}
