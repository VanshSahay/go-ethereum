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

package logquery

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"slices"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/triedb/database"
)

// testChain is a deterministic chain of blocks with logs, feeding both a
// memory indexer and the query's chain view.
type testChain struct {
	blocks   int
	headers  []*types.Header
	bodies   []*types.Body
	receipts []types.Receipts
}

var (
	testWETH = common.HexToAddress("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2")
	testUSDT = common.HexToAddress("0xdac17f958d2ee523a2206206994597c13d831ec7")
	testXfer = common.HexToHash("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")
)

func newTestChain(blocks int) *testChain {
	tc := &testChain{
		blocks:   blocks,
		headers:  make([]*types.Header, blocks+1),
		bodies:   make([]*types.Body, blocks+1),
		receipts: make([]types.Receipts, blocks+1),
	}
	parent := common.Hash{}
	for i := 1; i <= blocks; i++ {
		header := &types.Header{
			Number:     big.NewInt(int64(i)),
			ParentHash: parent,
			Time:       uint64(i),
		}
		tc.headers[i] = header
		// two transactions per block, each with logs of varying addresses
		txs := make([]*types.Transaction, 2)
		receipts := make(types.Receipts, 2)
		var logs1, logs2 []*types.Log
		for j := 0; j < 3; j++ {
			logs1 = append(logs1, &types.Log{
				Address: testWETH,
				Topics:  []common.Hash{testXfer, {byte(i)}},
			})
			if i%2 == 0 {
				logs2 = append(logs2, &types.Log{
					Address: testUSDT,
					Topics:  []common.Hash{testXfer, {byte(i), byte(j)}},
				})
			}
		}
		body := &types.Body{}
		var signer types.Signer = types.LatestSignerForChainID(big.NewInt(1))
		key, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		tx1, _ := types.SignNewTx(key, signer, &types.LegacyTx{Nonce: uint64(i * 2), Gas: 21000, GasPrice: big.NewInt(1)})
		tx2, _ := types.SignNewTx(key, signer, &types.LegacyTx{Nonce: uint64(i*2 + 1), Gas: 21000, GasPrice: big.NewInt(1)})
		txs[0], txs[1] = tx1, tx2
		body.Transactions = txs
		receipts[0] = &types.Receipt{TxHash: tx1.Hash(), Logs: logs1}
		receipts[1] = &types.Receipt{TxHash: tx2.Hash(), Logs: logs2}
		// assign cumulative indexes the way processing would
		var offset uint32
		for k, r := range receipts {
			for _, l := range r.Logs {
				l.TxIndex = uint(k)
			}
			offset += uint32(len(r.Logs))
		}
		tc.bodies[i] = body
		tc.receipts[i] = receipts
		header.ReceiptHash = types.DeriveSha(receipts, trie.NewStackTrie(nil))
		parent = header.Hash()
	}
	return tc
}

// feed indexes the chain into a memory indexer.
func (tc *testChain) feed(ix *memoryIndexer) {
	for i := 1; i <= tc.blocks; i++ {
		ix.AddBlockData(tc.headers[i], tc.bodies[i], tc.receipts[i])
	}
}

// view implements chainView over the test chain.
type view struct{ tc *testChain }

func (v *view) HeadNumber() uint64                  { return uint64(v.tc.blocks) }
func (v *view) Header(n uint64) *types.Header       { return v.tc.headers[n] }
func (v *view) Body(n uint64) *types.Body           { return v.tc.bodies[n] }
func (v *view) RawReceipts(n uint64) types.Receipts { return v.tc.receipts[n] }

// bruteForce returns the logs matching an eth_getLogs style filter, in order.
func (tc *testChain) bruteForce(addresses []common.Address, topics [][]common.Hash) []*types.Log {
	var logs []*types.Log
	for i := 1; i <= tc.blocks; i++ {
		var offset uint32
		for txi, r := range tc.receipts[i] {
			for _, l := range r.Logs {
				if legacyMatch(l, addresses, topics) {
					clone := *l
					clone.BlockNumber = uint64(i)
					clone.BlockHash = tc.headers[i].Hash()
					clone.TxIndex = uint(txi)
					clone.TxHash = tc.bodies[i].Transactions[txi].Hash()
					clone.Index = uint(offset) + uint(l.TxIndex*0) // block-global index below
					clone.Index = uint(blockGlobalIndex(tc, i, txi, l))
					logs = append(logs, &clone)
				}
			}
			offset += uint32(len(r.Logs))
		}
	}
	return logs
}

// blockGlobalIndex computes the block-global log index of the log at the
// given transaction and per-transaction position.
func blockGlobalIndex(tc *testChain, block, txi int, l *types.Log) int {
	index := 0
	for k := 0; k < txi; k++ {
		index += len(tc.receipts[block][k].Logs)
	}
	for j, log := range tc.receipts[block][txi].Logs {
		if log == l {
			return index + j
		}
	}
	return index
}

func legacyMatch(l *types.Log, addresses []common.Address, topics [][]common.Hash) bool {
	if len(addresses) > 0 && !slices.Contains(addresses, l.Address) {
		return false
	}
	for i, topicList := range topics {
		if len(topicList) == 0 {
			continue
		}
		if i >= len(l.Topics) || !slices.Contains(topicList, l.Topics[i]) {
			return false
		}
	}
	return true
}

// TestPatternJSONRoundTrip pins the pattern grammar: every combinator parses,
// round-trips through JSON and rejects malformed input.
func TestPatternJSONRoundTrip(t *testing.T) {
	m, err := NewPatternMatcherFromJSON(json.RawMessage(`{"field":"address","value":"0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"}`))
	if err != nil {
		t.Fatal(err)
	}
	enc, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	m2, err := NewPatternMatcherFromJSON(enc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := json.Marshal(m2); err != nil {
		t.Fatal(err)
	}
	const addr = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"
	if _, err := NewPatternMatcherFromJSON(json.RawMessage(`{"anyOf":[{"field":"address","value":"` + addr + `"},{"field":"topics[0]","value":"0x02"}]}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := NewPatternMatcherFromJSON(json.RawMessage(`{"allOf":[{"field":"address","value":"` + addr + `"},{"offset":{"field":"topics[0]","value":"0x02"},"amount":1}]}`)); err != nil {
		t.Fatal(err)
	}
	nested := strings.Repeat(`{"anyOf":[`, maxPatternDepth+2) + `{"field":"topics[0]","value":"0x02"}` + strings.Repeat(`]}`, maxPatternDepth+2)
	for _, bad := range []json.RawMessage{
		json.RawMessage(nested),                               // nested too deeply
		json.RawMessage(`{"field":"address","value":"0x01"}`), // short address
		json.RawMessage(`{"field":"address","value":"0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2aa"}`), // 21 byte address
		json.RawMessage(`{"field":"block","value":"0x01"}`),                                           // unsupported field
		json.RawMessage(`{"field":"transaction","value":"0x01"}`),                                     // unsupported field
		json.RawMessage(`{"offset":{"field":"topics[0]","value":"0x02"},"amount":4294967296}`),        // offset out of range
		json.RawMessage(`{}`),                                   // empty
		json.RawMessage(`{"field":"address"}`),                  // value missing
		json.RawMessage(`{"field":"unknown","value":"0x01"}`),   // bad field
		json.RawMessage(`{"field":"topics[7]","value":"0x01"}`), // bad topic index
		json.RawMessage(`{"field":"address","value":"zz"}`),     // bad hex
		json.RawMessage(`{"anyOf":[],"allOf":[]}`),              // both combinators
		json.RawMessage(`{"offset":{},"amount":1}`),             // empty offset
	} {
		if _, err := NewPatternMatcherFromJSON(bad); err == nil {
			t.Errorf("pattern %s: expected error", bad)
		}
	}
	if _, err := NewLegacyMatcher(nil, nil); !errors.Is(err, ErrMatchAll) {
		t.Errorf("empty legacy matcher: %v, want ErrMatchAll", err)
	}
}

// TestMatcherVsBruteForce runs address and topic queries through the matcher
// and compares against brute-force log filtering.
func TestMatcherVsBruteForce(t *testing.T) {
	tc := newTestChain(300)
	ix := newMemoryIndexerForTest()
	tc.feed(ix)

	v := &view{tc}
	tests := []struct {
		name      string
		addresses []common.Address
		topics    [][]common.Hash
	}{
		{"address", []common.Address{testWETH}, nil},
		{"address2", []common.Address{testUSDT}, nil},
		{"both addresses", []common.Address{testWETH, testUSDT}, nil},
		{"topic0", nil, [][]common.Hash{{testXfer}}},
		{"address+topic", []common.Address{testWETH}, [][]common.Hash{{testXfer}}},
		{"topic1", nil, [][]common.Hash{{}, {{byte(4)}}}},
	}
	for _, tt := range tests {
		matcher, err := NewLegacyMatcher(tt.addresses, tt.topics)
		if err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}
		m := NewMatcher(ix, nil)
		logs, resultRange, _, err := m.GetMatches(context.Background(), v, FilterQuery{
			Pattern:    matcher,
			FirstBlock: 1,
			LastBlock:  uint64(tc.blocks),
			Limit:      math.MaxUint64,
		}, false)
		if err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}
		want := tc.bruteForce(tt.addresses, tt.topics)
		if len(logs) != len(want) {
			t.Fatalf("%s: %d logs, want %d", tt.name, len(logs), len(want))
		}
		for i := range logs {
			if logs[i].BlockNumber != want[i].BlockNumber || logs[i].Address != want[i].Address ||
				logs[i].TxIndex != want[i].TxIndex || logs[i].Index != want[i].Index {
				t.Errorf("%s: log %d mismatch: got (block %d, tx %d, index %d), want (block %d, tx %d, index %d)",
					tt.name, i, logs[i].BlockNumber, logs[i].TxIndex, logs[i].Index,
					want[i].BlockNumber, want[i].TxIndex, want[i].Index)
			}
		}
		// no limit was reached, so the proven range is the requested one
		if resultRange.First() != 1 || resultRange.Last() != uint64(tc.blocks) {
			t.Errorf("%s: proven range %v, want [1..%d]", tt.name, resultRange, tc.blocks)
		}
	}
}

// TestMatcherLimit pins the result limit and the limitLatest reversal.
func TestMatcherLimit(t *testing.T) {
	tc := newTestChain(300)
	ix := newMemoryIndexerForTest()
	tc.feed(ix)

	matcher, err := NewLegacyMatcher([]common.Address{testWETH}, nil)
	if err != nil {
		t.Fatal(err)
	}
	v := &view{tc}
	m := NewMatcher(ix, nil)
	logs, _, _, err := m.GetMatches(context.Background(), v, FilterQuery{
		Pattern: matcher, FirstBlock: 1, LastBlock: uint64(tc.blocks), Limit: 7,
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 7 {
		t.Fatalf("%d logs, want 7 (oldest first)", len(logs))
	}
	wantAll := tc.bruteForce([]common.Address{testWETH}, nil)
	for i, l := range logs {
		if l.BlockNumber != wantAll[i].BlockNumber {
			t.Errorf("log %d: block %d, want %d (oldest first)", i, l.BlockNumber, wantAll[i].BlockNumber)
		}
	}
	latest, _, _, err := m.GetMatches(context.Background(), v, FilterQuery{
		Pattern: matcher, FirstBlock: 1, LastBlock: uint64(tc.blocks), Limit: 7, LimitLatest: true,
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	for i, l := range latest {
		want := wantAll[len(wantAll)-7+i]
		if l.BlockNumber != want.BlockNumber {
			t.Errorf("latest log %d: block %d, want %d (newest first)", i, l.BlockNumber, want.BlockNumber)
		}
	}
}

// TestReceiptsTrieProof pins that the collected receipts proof reconstructs
// the header's receipts root for the proven transactions.
func TestReceiptsTrieProof(t *testing.T) {
	tc := newTestChain(10)
	proof := newBlockProof(tc.headers[5], 7)
	for txi := range tc.receipts[5] {
		proof.matchingTxs[uint32(txi)] = matchingTx{txEntryIndex: uint64(txi)}
	}
	proof.createProof(tc.receipts[5])
	proofMap := make(map[common.Hash][]byte)
	for hash, blob := range proof.receiptsProof {
		proofMap[hash] = blob
	}
	tr, err := trie.New(trie.TrieID(tc.headers[5].ReceiptHash), proofNodeDatabase(proofMap))
	if err != nil {
		t.Fatal(err)
	}
	for txi := range tc.receipts[5] {
		key := rlp.AppendUint64(nil, uint64(txi))
		blob, err := tr.Get(key)
		if err != nil {
			t.Fatalf("receipt %d: %v", txi, err)
		}
		if len(blob) == 0 {
			t.Fatalf("receipt %d: empty proof value", txi)
		}
	}
}

// proofNodeDatabase adapts a proof map to the trie node database interface.
type proofNodeDatabase map[common.Hash][]byte

func (t proofNodeDatabase) Node(owner common.Hash, path []byte, hash common.Hash) ([]byte, error) {
	if blob, ok := t[hash]; ok {
		return blob, nil
	}
	return nil, errors.New("node not found in proof")
}

func (t proofNodeDatabase) NodeReader(root common.Hash) (database.NodeReader, error) {
	return t, nil
}

var _ = hexutil.Bytes{}
