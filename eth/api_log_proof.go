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
	"sort"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rpc"
)

// blockChain wraps the subset of core.BlockChain methods needed by LogProofAPI.
type blockChain interface {
	CurrentBlock() *types.Header
	GetBlockByNumber(number uint64) *types.Block
	GetBlockByHash(hash common.Hash) *types.Block
	GetReceiptsByHash(hash common.Hash) types.Receipts
}

// LogProofAPI provides the eth_getLogProof RPC endpoint for EIP-8304 trustless
// log verification. A light client can pass its trusted table root to verify
// log inclusion or exclusion over a block range without syncing full state.
type LogProofAPI struct {
	chain blockChain
}

// NewLogProofAPI creates a new LogProofAPI backed by the given chain.
func NewLogProofAPI(chain blockChain) *LogProofAPI {
	return &LogProofAPI{chain: chain}
}

// LogProofArgs are the arguments for eth_getLogProof.
type LogProofArgs struct {
	Addresses []common.Address `json:"addresses"`
	Topics    [][]common.Hash  `json:"topics"`
	FromBlock rpc.BlockNumber  `json:"fromBlock"`
	ToBlock   rpc.BlockNumber  `json:"toBlock"`
	RefHead   common.Hash      `json:"refHead"`
}

// LogProofResult is the response for eth_getLogProof.
type LogProofResult struct {
	Proof        *types.LogIndexProof `json:"proof"`
	MatchingLogs []*types.Log         `json:"matchingLogs"`
	FromBlock    hexutil.Uint64       `json:"fromBlock"`
	ToBlock      hexutil.Uint64       `json:"toBlock"`
}

// errRefHeadNotFound is returned when the reference head block cannot be located.
var errRefHeadNotFound = errors.New("reference head block not found")

// GetLogProof returns a trustless proof of log inclusion/exclusion over a block
// range. The caller provides filter criteria (addresses, topics, block range)
// and an optional reference head block hash. The response includes:
//   - A proof containing the sorted index entries and match boundaries
//   - The matching log objects
//   - The resolved block range
//
// The proof can be verified against a trusted table root obtained from the
// EIP-8304 on-chain contract.
func (api *LogProofAPI) GetLogProof(ctx context.Context, args LogProofArgs) (*LogProofResult, error) {
	// Resolve refHead — default to the current chain head
	refHead := args.RefHead
	var refHeader *types.Header
	if refHead == (common.Hash{}) {
		refHeader = api.chain.CurrentBlock()
	} else {
		block := api.chain.GetBlockByHash(refHead)
		if block == nil {
			return nil, errRefHeadNotFound
		}
		refHeader = block.Header()
	}

	// Resolve block numbers relative to the reference head
	currentNum := refHeader.Number.Uint64()
	fromBlock := resolveBlockNumber(args.FromBlock, currentNum)
	toBlock := resolveBlockNumber(args.ToBlock, currentNum)

	// Collect entries and matching logs across the block range
	var allEntries []types.IndexEntry
	var matchingLogs []*types.Log

	for num := fromBlock; num <= toBlock; num++ {
		block := api.chain.GetBlockByNumber(num)
		if block == nil {
			continue
		}
		receipts := api.chain.GetReceiptsByHash(block.Hash())
		if receipts == nil {
			continue
		}
		// Build entries for this block
		ib := types.NewIndexBuilder()
		ib.AddBlockEntries(num, receipts)
		allEntries = append(allEntries, ib.Entries()...)

		// Collect matching logs
		for _, r := range receipts {
			for _, log := range r.Logs {
				if matchesFilter(log, args.Addresses, args.Topics) {
					matchingLogs = append(matchingLogs, log)
				}
			}
		}
	}

	// Sort all entries lexicographically
	sort.Slice(allEntries, func(i, j int) bool {
		return types.CompareEntries(allEntries[i], allEntries[j]) < 0
	})

	// Compute the table root from the sorted entries (PoC: Keccak256)
	var buf []byte
	for _, e := range allEntries {
		buf = append(buf, e[:]...)
	}
	tableRoot := crypto.Keccak256Hash(buf)

	// Build the match function and generate the proof
	matchFn := buildMatchFn(args.Addresses, args.Topics)
	proof := types.GenerateLogProof(refHeader.Hash(), refHeader.Number.Uint64(), tableRoot,
		allEntries, matchingLogs, matchFn)

	return &LogProofResult{
		Proof:        proof,
		MatchingLogs: matchingLogs,
		FromBlock:    hexutil.Uint64(fromBlock),
		ToBlock:      hexutil.Uint64(toBlock),
	}, nil
}

// resolveBlockNumber resolves an rpc.BlockNumber to an absolute block number.
// Special block numbers (latest, pending, finalized, safe) are resolved against
// the current chain head. Earliest resolves to block 0.
func resolveBlockNumber(num rpc.BlockNumber, current uint64) uint64 {
	switch num {
	case rpc.EarliestBlockNumber:
		return 0
	case rpc.LatestBlockNumber, rpc.PendingBlockNumber:
		return current
	case rpc.FinalizedBlockNumber, rpc.SafeBlockNumber:
		return current // PoC simplification: treat as latest
	default:
		if num < 0 {
			return current
		}
		return uint64(num)
	}
}

// matchesFilter checks whether a log matches the given address and topic filters.
// Addresses are OR-ed; topics are AND-ed across positions and OR-ed within each
// position (standard Ethereum log filter semantics).
func matchesFilter(log *types.Log, addresses []common.Address, topics [][]common.Hash) bool {
	// Check address filter (OR within the list)
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
	// Check topic filters (AND across positions, OR within each position)
	for i, sub := range topics {
		if len(sub) == 0 {
			continue
		}
		match := false
		for _, topic := range sub {
			if i < len(log.Topics) && log.Topics[i] == topic {
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

// buildMatchFn creates an entry matcher that matches any entry whose type and
// value correspond to one of the addresses or topics in the filter criteria.
func buildMatchFn(addresses []common.Address, topics [][]common.Hash) func(types.IndexEntry) bool {
	return func(entry types.IndexEntry) bool {
		typ, val, _, _, _ := types.EntryFields(entry)
		// Match address entries
		if typ == types.EntryTypeLogAddress {
			for _, addr := range addresses {
				if val == common.BytesToHash(addr.Bytes()) {
					return true
				}
			}
		}
		// Match topic entries
		for topicIdx, topicList := range topics {
			if topicIdx >= 4 {
				break
			}
			for _, topic := range topicList {
				if typ == types.EntryType(int(types.EntryTypeLogTopic0)+topicIdx) && val == topic {
					return true
				}
			}
		}
		return false
	}
}
