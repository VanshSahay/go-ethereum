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

package eth

import (
	"context"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/rpc"
)

// LogProofAPI provides trustless log index proof endpoints for EIP-7745b.
type LogProofAPI struct {
	chain    *core.BlockChain
	chainDb  ethdb.Database
}

// NewLogProofAPI creates a new LogProofAPI instance.
func NewLogProofAPI(chain *core.BlockChain, chainDb ethdb.Database) *LogProofAPI {
	return &LogProofAPI{chain: chain, chainDb: chainDb}
}

// LogProofArgs specifies the parameters for eth_getLogProof.
type LogProofArgs struct {
	Addresses []common.Address `json:"addresses"`
	Topics    [][]common.Hash  `json:"topics"`
	FromBlock rpc.BlockNumber  `json:"fromBlock"`
	ToBlock   rpc.BlockNumber  `json:"toBlock"`
	RefHead   common.Hash      `json:"refHead"`
}

// LogProofResult is the response for eth_getLogProof.
type LogProofResult struct {
	Proof         *types.LogIndexProof `json:"proof"`
	MatchingLogs  []*types.Log         `json:"matchingLogs"`
	FromBlock     hexutil.Uint64       `json:"fromBlock"`
	ToBlock       hexutil.Uint64       `json:"toBlock"`
}

// GetLogProof generates a trustless Merkle proof for log queries against the
// EIP-7745b LogIndex. The proof can be verified against only the block header's
// LogIndex without trusting the serving node.
func (api *LogProofAPI) GetLogProof(ctx context.Context, args LogProofArgs) (*LogProofResult, error) {
	currentHeader := api.chain.CurrentBlock()

	// Resolve reference head — must be a recent block
	refHead := currentHeader
	if args.RefHead != (common.Hash{}) {
		refHead = api.chain.GetHeaderByHash(args.RefHead)
		if refHead == nil {
			return nil, fmt.Errorf("reference head not found: %s", args.RefHead.Hex())
		}
	}

	// Check that the reference head has LogIndex (post-fork)
	if refHead.LogIndex == nil {
		return nil, errors.New("reference head block is pre-EIP-7745b, no LogIndex available")
	}

	// Resolve block range
	fromBlock := args.FromBlock.Int64()
	toBlock := args.ToBlock.Int64()
	currentNum := int64(currentHeader.Number.Uint64())

	if fromBlock < 0 {
		fromBlock = currentNum
	}
	if toBlock < 0 {
		toBlock = currentNum
	}

	// Collect matching logs and index entries across the block range
	var allMatchingLogs []*types.Log
	var allEntries []types.IndexEntry

	for num := uint64(fromBlock); num <= uint64(toBlock); num++ {
		header := api.chain.GetHeaderByNumber(num)
		if header == nil {
			continue
		}
		receipts := rawdb.ReadReceipts(api.chainDb, header.Hash(), num, header.Time, api.chain.Config())
		if receipts == nil {
			continue
		}

		// Build entries for this block
		builder := types.NewIndexBuilder(common.Hash{})
		builder.AddBlockEntries(num, receipts)
		builder.Build()
		allEntries = append(allEntries, builder.Entries()...)

		// Collect matching logs
		for _, receipt := range receipts {
			for _, log := range receipt.Logs {
				if matchesFilter(log, args.Addresses, args.Topics) {
					log.BlockNumber = num
					log.BlockHash = header.Hash()
					log.TxHash = receipt.TxHash
					log.TxIndex = receipt.TransactionIndex
					allMatchingLogs = append(allMatchingLogs, log)
				}
			}
		}
	}

	if len(allMatchingLogs) == 0 {
		return &LogProofResult{
			FromBlock:    hexutil.Uint64(fromBlock),
			ToBlock:      hexutil.Uint64(toBlock),
			MatchingLogs: nil,
		}, nil
	}

	// Sort the merged entries
	sortEntries(allEntries)

	// Build the proof against the reference head
	proof := types.GenerateLogProof(
		refHead,
		[][]types.IndexEntry{allEntries, nil, nil, nil}, // chain 0 only for single-block proof
		allMatchingLogs,
		func(e types.IndexEntry) bool {
			return entryMatchesFilter(e, args.Addresses, args.Topics)
		},
	)

	return &LogProofResult{
		Proof:        proof,
		MatchingLogs: allMatchingLogs,
		FromBlock:    hexutil.Uint64(fromBlock),
		ToBlock:      hexutil.Uint64(toBlock),
	}, nil
}

// matchesFilter checks if a log matches the given addresses and topics.
func matchesFilter(log *types.Log, addresses []common.Address, topics [][]common.Hash) bool {
	// Check address
	if len(addresses) > 0 {
		match := false
		for _, addr := range addresses {
			if log.Address == addr {
				match = true
				break
			}
		}
		if !match {
			return false
		}
	}

	// Check topics
	for i, topicGroup := range topics {
		if len(topicGroup) == 0 {
			continue
		}
		if i >= len(log.Topics) {
			return false
		}
		match := false
		for _, topic := range topicGroup {
			if log.Topics[i] == topic {
				match = true
				break
			}
		}
		if !match {
			return false
		}
	}
	return true
}

// entryMatchesFilter checks if an index entry matches the filter criteria.
func entryMatchesFilter(e types.IndexEntry, addresses []common.Address, topics [][]common.Hash) bool {
	typ, val, _, _, _ := e.EntryFields()

	switch typ {
	case types.EntryTypeLogAddress:
		for _, addr := range addresses {
			if val == common.BytesToHash(addr.Bytes()) {
				return true
			}
		}
	case types.EntryTypeLogTopic0, types.EntryTypeLogTopic1, types.EntryTypeLogTopic2, types.EntryTypeLogTopic3:
		topicIdx := int(typ) - int(types.EntryTypeLogTopic0)
		if topicIdx < len(topics) {
			for _, topic := range topics[topicIdx] {
				if val == topic {
					return true
				}
			}
		}
	}
	return false
}

// sortEntries sorts a slice of IndexEntry in lexicographic order.
func sortEntries(entries []types.IndexEntry) {
	for i := 0; i < len(entries); i++ {
		for j := i + 1; j < len(entries); j++ {
			if types.CompareEntries(entries[i], entries[j]) > 0 {
				entries[i], entries[j] = entries[j], entries[i]
			}
		}
	}
}
