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

package ethapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/logindex"
	"github.com/ethereum/go-ethereum/core/logindex/logquery"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
)

// LogIndexBackend is the collection of functions the pureth RPC API needs.
type LogIndexBackend interface {
	CurrentBlock() *types.Header
	HeaderByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*types.Header, error)
	LogIndexMatcher() *logquery.Matcher
	LogIndexChainView(refHeader *types.Header) logquery.ChainView
	LogIndexTableRoots(sizes []uint64) ([]logindex.TableWrite, error)
}

// PurethQueryArgs describes a proven log query: an optional reference head
// (defaults to the current head), a search pattern, the block range and an
// optional result limit.
//
// The pattern is either the pattern grammar JSON or an eth_getLogs style
// filter (address and topics). A completely empty filter is rejected:
// proving every log of every block is not a sensible query.
type PurethQueryArgs struct {
	RefBlock      *rpc.BlockNumberOrHash `json:"refBlock"`
	ReferenceHead *rpc.BlockNumberOrHash `json:"referenceHead"` // alias of refBlock
	Pattern       *json.RawMessage       `json:"pattern"`
	Address       *common.Address        `json:"address"`
	Addresses     []common.Address       `json:"addresses"`
	Topics        [][]common.Hash        `json:"topics"`
	FirstBlock    *hexutil.Uint64        `json:"firstBlock"`
	LastBlock     *hexutil.Uint64        `json:"lastBlock"`
	Limit         *hexutil.Uint64        `json:"limit"`
	LimitLatest   bool                   `json:"limitLatest"`
	// Encoding selects the proof encoding: "json" (default) or "rlp", the
	// compact binary form returned as proofRlp.
	Encoding string `json:"encoding"`
}

// PurethQueryResult is the query result with its proof: the matching logs,
// the block range they span and the self-contained proof that verifies them
// without trusting the serving node.
type PurethQueryResult struct {
	Logs       []*types.Log         `json:"logs"`
	FirstBlock hexutil.Uint64       `json:"firstBlock"`
	LastBlock  hexutil.Uint64       `json:"lastBlock"`
	Proof      *logquery.QueryProof `json:"proof,omitempty"`
	ProofRLP   hexutil.Bytes        `json:"proofRlp,omitempty"`
}

// maxPurethLogs is the most logs a single proven query returns. A cut result
// is trimmed to the limit and its proven range ends at the block of its last
// log (lastBlock), which may be only partly included: the next page starts at
// that block again.
const maxPurethLogs = 10_000

// PurethAPI exposes the trustless log index queries.
type PurethAPI struct {
	backend LogIndexBackend
}

// NewPurethAPI creates a new pureth RPC API instance.
func NewPurethAPI(backend LogIndexBackend) *PurethAPI {
	return &PurethAPI{backend: backend}
}

// GetLogsWithProofV1 runs the query against the index tables and returns the
// matching logs together with a proof verifying them end to end against the
// reference header.
func (api *PurethAPI) GetLogsWithProofV1(ctx context.Context, args PurethQueryArgs) (*PurethQueryResult, error) {
	matcher := api.backend.LogIndexMatcher()
	if matcher == nil {
		return nil, errors.New("log index is not enabled")
	}
	if args.Encoding != "" && args.Encoding != "json" && args.Encoding != "rlp" {
		return nil, fmt.Errorf("unknown proof encoding %q", args.Encoding)
	}
	if args.RefBlock != nil && args.ReferenceHead != nil {
		return nil, errors.New("refBlock and referenceHead are aliases, specify only one")
	}
	refBlock := args.RefBlock
	if refBlock == nil {
		refBlock = args.ReferenceHead
	}
	refHeader, err := api.refHeader(ctx, refBlock)
	if err != nil {
		return nil, err
	}
	if args.Address != nil && len(args.Addresses) > 0 {
		return nil, errors.New("specify either address or addresses")
	}
	var pattern logquery.PatternMatcher
	if args.Pattern != nil {
		if pattern, err = logquery.NewPatternMatcherFromJSON(*args.Pattern); err != nil {
			return nil, err
		}
	} else {
		var addresses []common.Address
		if args.Address != nil {
			addresses = []common.Address{*args.Address}
		}
		if pattern, err = logquery.NewLegacyMatcher(addresses, args.Topics); err != nil {
			return nil, err
		}
	}
	// the default range covers every indexed block below the reference head
	// and the result set is unlimited
	query := logquery.FilterQuery{
		Pattern:     pattern,
		FirstBlock:  1,
		LastBlock:   refHeader.Number.Uint64(),
		Limit:       maxPurethLogs,
		LimitLatest: args.LimitLatest,
	}
	if args.FirstBlock != nil {
		query.FirstBlock = uint64(*args.FirstBlock)
	}
	if args.LastBlock != nil {
		query.LastBlock = uint64(*args.LastBlock)
	}
	if args.Limit != nil {
		query.Limit = uint64(*args.Limit)
	}
	if query.Limit == 0 {
		return nil, errors.New("limit must be positive")
	}
	if query.Limit > maxPurethLogs {
		return nil, fmt.Errorf("limit %d exceeds the maximum of %d; page through the range starting each page at the returned lastBlock", query.Limit, maxPurethLogs)
	}
	if query.FirstBlock == 0 {
		return nil, errors.New("firstBlock must be at least 1")
	}
	if query.FirstBlock > query.LastBlock {
		return nil, fmt.Errorf("invalid block range: firstBlock %d is after lastBlock %d", query.FirstBlock, query.LastBlock)
	}
	if query.LastBlock > refHeader.Number.Uint64() {
		return nil, fmt.Errorf("lastBlock %d is above the reference head %d", query.LastBlock, refHeader.Number)
	}
	logs, resultRange, proof, err := matcher.GetMatches(ctx, api.backend.LogIndexChainView(refHeader), query, true)
	if err != nil {
		return nil, err
	}
	if resultRange.IsEmpty() {
		return nil, errors.New("no block range could be proven")
	}
	result := &PurethQueryResult{
		Logs:       logs,
		FirstBlock: hexutil.Uint64(resultRange.First()),
		LastBlock:  hexutil.Uint64(resultRange.Last()),
	}
	if args.Encoding == "rlp" {
		if result.ProofRLP, err = rlp.EncodeToBytes(proof); err != nil {
			return nil, err
		}
	} else {
		result.Proof = proof
	}
	return result, nil
}

// refHeader resolves the canonical reference head the proof is anchored to.
// Pending blocks, unknown blocks and blocks above the current head are rejected,
// and a block hash must be on the canonical chain.
func (api *PurethAPI) refHeader(ctx context.Context, refBlock *rpc.BlockNumberOrHash) (*types.Header, error) {
	head := api.backend.CurrentBlock()
	if refBlock == nil {
		return head, nil
	}
	query := *refBlock
	if number, ok := query.Number(); ok && number == rpc.PendingBlockNumber {
		return nil, errors.New("the reference head cannot be pending")
	}
	if _, ok := query.Hash(); ok {
		query.RequireCanonical = true
	}
	header, err := api.backend.HeaderByNumberOrHash(ctx, query)
	if err != nil {
		return nil, err
	}
	if header == nil {
		return nil, errors.New("reference head not found")
	}
	if header.Number.Cmp(head.Number) > 0 {
		return nil, errors.New("the reference head is above the current head")
	}
	return header, nil
}

// TableRoot is the root of one index table.
type TableRoot struct {
	FirstBlock hexutil.Uint64 `json:"firstBlock"`
	TableSize  hexutil.Uint64 `json:"tableSize"`
	Root       common.Hash    `json:"root"`
}

// maxExportSizes bounds the table size list of an export request.
const maxExportSizes = 16

// GetTableRootsV1 returns the roots of every complete table of the given sizes
// up to the current head, derived from the chain's blocks and receipts. They
// are the content to hardcode into a historic index contract (see
// logquery.HistoricStorage) when the index runs out of protocol.
func (api *PurethAPI) GetTableRootsV1(ctx context.Context, sizes []hexutil.Uint64) ([]TableRoot, error) {
	if len(sizes) == 0 || len(sizes) > maxExportSizes {
		return nil, fmt.Errorf("between 1 and %d table sizes are required", maxExportSizes)
	}
	raw := make([]uint64, len(sizes))
	for i, size := range sizes {
		raw[i] = uint64(size)
	}
	writes, err := api.backend.LogIndexTableRoots(raw)
	if err != nil {
		return nil, err
	}
	roots := make([]TableRoot, len(writes))
	for i, w := range writes {
		roots[i] = TableRoot{hexutil.Uint64(w.FirstBlock), hexutil.Uint64(w.TableSize), w.Root}
	}
	return roots, nil
}
