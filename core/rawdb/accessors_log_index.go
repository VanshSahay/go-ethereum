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

package rawdb

import (
	"encoding/json"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethdb"
)

// LogIndexStateRecord is the JSON-serialized form of the LogIndexState stored
// in the database. It avoids import cycles (rawdb cannot depend on core).
type LogIndexStateRecord struct {
	ChainParents   [4]common.Hash            `json:"chainParents"`
	ScheduledRoots map[uint64]common.Hash `json:"scheduledRoots"`
}

// WriteLogIndexState stores the log index state for the given block number.
func WriteLogIndexState(db ethdb.KeyValueWriter, number uint64, parents [4]common.Hash, scheduled map[uint64]common.Hash) error {
	rec := &LogIndexStateRecord{
		ChainParents:   parents,
		ScheduledRoots: scheduled,
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return db.Put(logIndexStateKey(number), data)
}

// ReadLogIndexState retrieves the log index state for the given block number.
// Returns nil if no state is found.
func ReadLogIndexState(db ethdb.KeyValueReader, number uint64) (parents [4]common.Hash, scheduled map[uint64]common.Hash, err error) {
	data, err := db.Get(logIndexStateKey(number))
	if err != nil {
		return [4]common.Hash{}, nil, nil // not found is not an error
	}
	var rec LogIndexStateRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return [4]common.Hash{}, nil, err
	}
	return rec.ChainParents, rec.ScheduledRoots, nil
}

// DeleteLogIndexState removes the log index state for the given block number.
func DeleteLogIndexState(db ethdb.KeyValueWriter, number uint64) error {
	return db.Delete(logIndexStateKey(number))
}
