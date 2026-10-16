package logquery

import (
	"context"
	"math"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// TestMatcherAlternatingTopics queries one of two alternating topics and pins
// that the scan does not stop at the first non-matching entry.
func TestMatcherAlternatingTopics(t *testing.T) {
	tc := newTestChain(30)
	// replace every log with two LOG1-style logs: topic 0x11 and topic 0x22
	tA := common.Hash{0x11}
	tB := common.Hash{0x22}
	for i := 1; i <= 30; i++ {
		var logs []*types.Log
		for j := 0; j < 2; j++ {
			logs = append(logs, &types.Log{
				Address: testWETH,
				Topics:  []common.Hash{tA, tB},
			})
		}
		_ = logs
	}
	ix := newMemoryIndexerForTest()
	// feed blocks whose receipts carry a matching and a non-matching log per
	// transaction, alternating which of the two topics the first log carries
	for i := 1; i <= 30; i++ {
		txs := tc.bodies[i].Transactions
		receipts := make(types.Receipts, len(txs))
		for j := range txs {
			first := tA
			if (i+j)%2 == 0 {
				first = tB
			}
			receipts[j] = &types.Receipt{
				TxHash: txs[j].Hash(),
				Logs: []*types.Log{
					{Address: testWETH, Topics: []common.Hash{first}},
					{Address: testWETH, Topics: []common.Hash{tB}},
				},
			}
		}
		tc.receipts[i] = receipts
		ix.AddBlockData(tc.headers[i], tc.bodies[i], receipts)
	}
	matcher, err := NewLegacyMatcher(nil, [][]common.Hash{{tA}})
	if err != nil {
		t.Fatal(err)
	}
	v := &view{tc}
	m := NewMatcher(ix, nil)
	logs, _, _, err := m.GetMatches(context.Background(), v, FilterQuery{
		Pattern: matcher, FirstBlock: 1, LastBlock: 30, Limit: math.MaxUint64,
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	// exactly one transaction per block carries the queried topic
	want := 30
	if len(logs) != want {
		var blocks []uint64
		for _, l := range logs {
			blocks = append(blocks, l.BlockNumber)
		}
		t.Fatalf("%d logs matched, want %d: blocks %v", len(logs), want, blocks)
	}
}

// TestMatcherSingleTxPerBlock mirrors the devnet shape: one transaction per
// block emitting a matching and a non-matching log.
func TestMatcherSingleTxPerBlock(t *testing.T) {
	tc := newTestChain(12)
	tA := common.Hash{0x11}
	tB := common.Hash{0x22}
	ix := newMemoryIndexerForTest()
	for i := 1; i <= 12; i++ {
		txs := tc.bodies[i].Transactions
		receipts := make(types.Receipts, len(txs))
		receipts[0] = &types.Receipt{
			TxHash: txs[0].Hash(),
			Logs: []*types.Log{
				{Address: testWETH, Topics: []common.Hash{tA}},
				{Address: testWETH, Topics: []common.Hash{tB}},
			},
		}
		for j := 1; j < len(txs); j++ {
			receipts[j] = &types.Receipt{TxHash: txs[j].Hash()}
		}
		tc.receipts[i] = receipts
		ix.AddBlockData(tc.headers[i], tc.bodies[i], receipts)
	}
	matcher, err := NewLegacyMatcher(nil, [][]common.Hash{{tA}})
	if err != nil {
		t.Fatal(err)
	}
	v := &view{tc}
	m := NewMatcher(ix, nil)
	logs, _, _, err := m.GetMatches(context.Background(), v, FilterQuery{
		Pattern: matcher, FirstBlock: 1, LastBlock: 12, Limit: math.MaxUint64,
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 12 {
		t.Fatalf("%d logs matched, want 12", len(logs))
	}
}

// TestMatcherManyTxsOneBlock mirrors a spam block: many transactions in one
// block each emitting a matching and a non-matching log.
func TestMatcherManyTxsOneBlock(t *testing.T) {
	tc := newTestChain(6)
	tA := common.Hash{0x11}
	tB := common.Hash{0x22}
	ix := newMemoryIndexerForTest()
	for i := 1; i <= 6; i++ {
		txs := tc.bodies[i].Transactions
		if i != 3 {
			continue
		}
		receipts := make(types.Receipts, len(txs))
		for j := range txs {
			receipts[j] = &types.Receipt{
				TxHash: txs[j].Hash(),
				Logs: []*types.Log{
					{Address: testWETH, Topics: []common.Hash{tA}},
					{Address: testWETH, Topics: []common.Hash{tB}},
				},
			}
		}
		tc.receipts[i] = receipts
		ix.AddBlockData(tc.headers[i], tc.bodies[i], receipts)
	}
	matcher, err := NewLegacyMatcher(nil, [][]common.Hash{{tA}})
	if err != nil {
		t.Fatal(err)
	}
	v := &view{tc}
	m := NewMatcher(ix, nil)
	logs, _, _, err := m.GetMatches(context.Background(), v, FilterQuery{
		Pattern: matcher, FirstBlock: 1, LastBlock: 6, Limit: math.MaxUint64,
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 2 {
		t.Fatalf("%d logs matched, want 2", len(logs))
	}
}
