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
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/logindex"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params"
)

// TableWrite describes a table root that should be written to the index contract.
type TableWrite = logindex.TableWrite

// BuildLogIndexForBlock builds the EIP-8304 level-0 log index table for the given
// block without any indexer state. parentHash is the hash of the parent block,
// whose block entry is added with the spec's one-block delay (none for the
// genesis block). The table root is the SHA2-256 binary tree hash of the sorted
// entries with the entry count mixed in (see core/types/logindex_merkle.go).
func BuildLogIndexForBlock(blockNumber uint64, parentHash common.Hash, receipts types.Receipts) []TableWrite {
	return []TableWrite{{FirstBlock: blockNumber, TableSize: 1, Root: logindex.BuildLevel0Root(blockNumber, parentHash, receipts)}}
}

// DeriveLogIndexWrites derives the EIP-8304 table writes committed by a block
// from the history of the chain it extends: the level-0 table of the block and
// every higher-level table that falls due. The chain must implement
// logindex.AncestorReader to serve the due higher-level tables; without it a
// block on which one is due fails with logindex.ErrNoAncestry instead of
// getting a wrong root.
func DeriveLogIndexWrites(chain any, config *params.ChainConfig, number uint64, parentHash common.Hash, receipts types.Receipts) ([]TableWrite, error) {
	ancestry, _ := chain.(logindex.AncestorReader)
	isActive := func(h *types.Header) bool { return config.IsEIP8304(h.Number, h.Time) }
	return logindex.DeriveTableWrites(ancestry, isActive, number, parentHash, receipts)
}

// readIndexReceipts loads the receipts of a stored block with the transaction
// hashes filled in, which is all the index entries need. The receipts are
// copied so cached raw receipts are never modified.
func readIndexReceipts(db ethdb.Reader, hash common.Hash, number uint64) (types.Receipts, error) {
	body := rawdb.ReadBody(db, hash, number)
	if body == nil {
		return nil, fmt.Errorf("body of block %d not found", number)
	}
	raw := rawdb.ReadRawReceipts(db, hash, number)
	if len(raw) != len(body.Transactions) {
		return nil, fmt.Errorf("block %d: %d receipts for %d transactions", number, len(raw), len(body.Transactions))
	}
	receipts := make(types.Receipts, len(raw))
	for i, r := range raw {
		c := *r
		c.TxHash = body.Transactions[i].Hash()
		receipts[i] = &c
	}
	return receipts, nil
}

// GetIndexReceipts implements logindex.AncestorReader.
func (hc *HeaderChain) GetIndexReceipts(hash common.Hash, number uint64) (types.Receipts, error) {
	return readIndexReceipts(hc.chainDb, hash, number)
}

// GetIndexReceipts implements logindex.AncestorReader.
func (bc *BlockChain) GetIndexReceipts(hash common.Hash, number uint64) (types.Receipts, error) {
	return bc.hc.GetIndexReceipts(hash, number)
}
