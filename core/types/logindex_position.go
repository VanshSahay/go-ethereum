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

package types

// IndexPosition identifies the block-level location an index entry points to:
// the block number, the transaction index within the block and the log index
// relative to the transaction. Block entries carry no position tail; their
// position is the block number alone. For transaction entries the log index
// field carries the cumulative log count of the block before the transaction.
type IndexPosition struct {
	BlockNumber uint64
	TxIndex     uint32
	LogIndex    uint32
}

// Compare orders positions field-wise, matching the big-endian encoding order
// of the position tail.
func (p IndexPosition) Compare(q IndexPosition) int {
	if p.BlockNumber != q.BlockNumber {
		if p.BlockNumber < q.BlockNumber {
			return -1
		}
		return 1
	}
	if p.TxIndex != q.TxIndex {
		if p.TxIndex < q.TxIndex {
			return -1
		}
		return 1
	}
	if p.LogIndex != q.LogIndex {
		if p.LogIndex < q.LogIndex {
			return -1
		}
		return 1
	}
	return 0
}

// Position returns the decoded position fields of the entry. Block entries
// return the block number with zero tx/log fields.
func (e IndexEntry) Position() (IndexPosition, error) {
	return PositionFromEntry(e)
}

// PositionFromEntry decodes the position fields of an index entry. Block
// entries return the block number with zero tx/log fields.
func PositionFromEntry(entry IndexEntry) (IndexPosition, error) {
	_, _, blockNum, txIdx, logIdx, err := EntryFields(entry)
	if err != nil {
		return IndexPosition{}, err
	}
	return IndexPosition{BlockNumber: blockNum, TxIndex: txIdx, LogIndex: logIdx}, nil
}
