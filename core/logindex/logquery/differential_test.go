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
	"fmt"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

const (
	topicA = "0x1111111111111111111111111111111111111111111111111111111111111111"
	topicB = "0x2222222222222222222222222222222222222222222222222222222222222222"
)

// diffEmitterCode emits four logs per call:
//
//	log 0: LOG1(A)
//	log 1: LOG2(A, B)
//	log 2: LOG1(B)
//	log 3: LOG0
func diffEmitterCode() []byte {
	push := func(topic string) string { return "7f" + strings.TrimPrefix(topic, "0x") }
	code := push(topicA) + "5f5fa1" + // LOG1(A)
		push(topicB) + push(topicA) + "5f5fa2" + // LOG2(A, B): topic0 = A, topic1 = B
		push(topicB) + "5f5fa1" + // LOG1(B)
		"5f5fa0" + // LOG0
		"00"
	return common.FromHex(code)
}

// diffLogsPerTx is the number of logs the emitter produces per call.
const diffLogsPerTx = 4

// diffPattern is a search pattern together with the log indexes of one call
// that match it, derived by hand from the emitter layout rather than from the
// matcher under test.
type diffPattern struct {
	name    string
	json    func(emitter common.Address) string
	matches []int
}

var diffPatterns = []diffPattern{
	{"address", func(e common.Address) string { return addrLeaf(e) }, []int{0, 1, 2, 3}},
	{"topic0=A", func(common.Address) string { return topicLeaf(0, topicA) }, []int{0, 1}},
	{"topic0=B", func(common.Address) string { return topicLeaf(0, topicB) }, []int{2}},
	{"topic1=B", func(common.Address) string { return topicLeaf(1, topicB) }, []int{1}},
	{"topic0=A and topic1=B", func(common.Address) string {
		return `{"allOf":[` + topicLeaf(0, topicA) + `,` + topicLeaf(1, topicB) + `]}`
	}, []int{1}},
	{"topic0=A or topic0=B", func(common.Address) string {
		return `{"anyOf":[` + topicLeaf(0, topicA) + `,` + topicLeaf(0, topicB) + `]}`
	}, []int{0, 1, 2}},
	{"address and topic0=B", func(e common.Address) string {
		return `{"allOf":[` + addrLeaf(e) + `,` + topicLeaf(0, topicB) + `]}`
	}, []int{2}},
	// log i matches when log i+1 has topic0 = A
	{"offset +1 of topic0=A", func(common.Address) string {
		return `{"offset":` + topicLeaf(0, topicA) + `,"amount":1}`
	}, []int{0}},
	// log i matches when log i-1 has topic0 = B
	{"offset -1 of topic0=B", func(common.Address) string {
		return `{"offset":` + topicLeaf(0, topicB) + `,"amount":-1}`
	}, []int{3}},
	// log i matches when log i+3 exists
	{"offset +3 of address", func(e common.Address) string {
		return `{"offset":` + addrLeaf(e) + `,"amount":3}`
	}, []int{0}},
	// log i matches when log i-1 exists: its candidates reach past the last log
	{"offset -1 of address", func(e common.Address) string {
		return `{"offset":` + addrLeaf(e) + `,"amount":-1}`
	}, []int{1, 2, 3}},
	{"matches nothing", func(common.Address) string { return topicLeaf(0, "0x33") }, nil},
}

func addrLeaf(e common.Address) string {
	return fmt.Sprintf(`{"field":"address","value":"%s"}`, e.Hex())
}

func topicLeaf(i int, topic string) string {
	return fmt.Sprintf(`{"field":"topics[%d]","value":"%s"}`, i, topic)
}

// expectedLog identifies a log by its position.
type expectedLog struct {
	block, tx uint64
	index     uint64 // block-global log index
}

// expectedMatches lists the logs a pattern matches in [first, last], in
// ascending order, by brute force over the chain's transactions.
func expectedMatches(rtc *rtChain, dp diffPattern, first, last uint64) []expectedLog {
	var out []expectedLog
	for n := first; n <= last; n++ {
		header := rtc.bc.GetHeaderByNumber(n)
		for tx := range rtc.bc.GetBody(header.Hash()).Transactions {
			for _, i := range dp.matches {
				out = append(out, expectedLog{n, uint64(tx), uint64(tx*diffLogsPerTx + i)})
			}
		}
	}
	return out
}

// TestDifferentialQueries compares the prover and the verifier against brute
// force over many patterns, ranges, limits and directions, on a chain whose
// blocks hold one to three calls of an emitter with a known log layout.
func TestDifferentialQueries(t *testing.T) {
	// the default windows cover the whole test chain at once; tiny windows
	// exercise the window boundaries of the scan
	for _, window := range []uint64{0, 1, 5} {
		t.Run(fmt.Sprintf("window=%d", window), func(t *testing.T) { testDifferentialQueries(t, window) })
	}
}

func testDifferentialQueries(t *testing.T, window uint64) {
	rtc := newRTChainWith(t, 40, diffEmitterCode(), func(block int) int { return block%3 + 1 })
	rtc.matcher.ScanWindow = window
	emitter := crypto.CreateAddress(rtSender, 1)
	trusted := rtc.bc.CurrentBlock()
	opts := DefaultVerifyOptions(rtc.bc.Config())

	ranges := [][2]uint64{{1, 39}, {7, 25}, {16, 40}, {3, 3}}
	limits := []uint64{rtMaxUint64, 5, 23}
	if testing.Short() {
		ranges, limits = ranges[:2], limits[:2]
	}
	var queries, nonEmpty int
	for _, dp := range diffPatterns {
		pattern, err := NewPatternMatcherFromJSON(json.RawMessage(dp.json(emitter)))
		if err != nil {
			t.Fatalf("%s: %v", dp.name, err)
		}
		for _, rng := range ranges {
			for _, limit := range limits {
				for _, latest := range []bool{false, true} {
					name := fmt.Sprintf("%s [%d..%d] limit %d latest %v", dp.name, rng[0], rng[1], limit, latest)
					req := FilterQuery{Pattern: pattern, FirstBlock: rng[0], LastBlock: rng[1], Limit: limit, LimitLatest: latest}

					want := expectedMatches(rtc, dp, rng[0], min(rng[1], trusted.Number.Uint64()))
					if uint64(len(want)) > limit {
						if latest {
							want = want[uint64(len(want))-limit:]
						} else {
							want = want[:limit]
						}
					}
					served, proven, proof, err := rtc.matcher.GetMatches(context.Background(), &rtView{rtc}, req, true)
					if err != nil {
						t.Errorf("%s: get matches: %v", name, err)
						continue
					}
					checkLogs(t, name+" (served)", served, want)

					// the proof must survive the wire and verify to the same logs
					blob, err := json.Marshal(proof)
					if err != nil {
						t.Fatal(err)
					}
					var decoded QueryProof
					if err := json.Unmarshal(blob, &decoded); err != nil {
						t.Fatalf("%s: %v", name, err)
					}
					res, err := decoded.Verify(trusted, req, opts)
					if err != nil {
						t.Errorf("%s: verify: %v", name, err)
						continue
					}
					checkLogs(t, name+" (verified)", res.Logs, want)
					queries++
					if len(want) > 0 {
						nonEmpty++
					}
					if res.FirstBlock != proven.First() || res.LastBlock != proven.Last() {
						t.Errorf("%s: verified range %d..%d, served %d..%d", name, res.FirstBlock, res.LastBlock, proven.First(), proven.Last())
					}
					// a complete answer covers the requested range
					if uint64(len(want)) < limit && (res.FirstBlock != rng[0] || res.LastBlock != min(rng[1], trusted.Number.Uint64())) {
						t.Errorf("%s: complete answer covers %d..%d", name, res.FirstBlock, res.LastBlock)
					}
				}
			}
		}
	}
	want := len(diffPatterns) * len(ranges) * len(limits) * 2
	if queries != want {
		t.Errorf("ran %d queries, want %d", queries, want)
	}
	if nonEmpty < queries/2 {
		t.Errorf("only %d of %d queries had results", nonEmpty, queries)
	}
	t.Logf("%d queries verified (%d with results)", queries, nonEmpty)
}

func checkLogs(t *testing.T, name string, got []*types.Log, want []expectedLog) {
	t.Helper()
	have := make([]expectedLog, 0, len(got))
	for _, l := range got {
		have = append(have, expectedLog{l.BlockNumber, uint64(l.TxIndex), uint64(l.Index)})
	}
	if len(have) != len(want) {
		t.Errorf("%s: %d logs, want %d", name, len(have), len(want))
		return
	}
	for i := range want {
		// the block-global index of a log is its offset inside the block, which
		// depends on the preceding transactions' logs
		if have[i].block != want[i].block || have[i].tx != want[i].tx || have[i].index != want[i].index {
			t.Errorf("%s: log %d is %+v, want %+v", name, i, have[i], want[i])
			return
		}
	}
}

// TestBroadQueryWithSmallLimit pins that a query whose pattern matches far more
// candidates than the matcher is willing to derive still works when its limit
// is reached early, and fails only when the cap is really exceeded.
func TestBroadQueryWithSmallLimit(t *testing.T) {
	rtc := newRTChainWith(t, 40, diffEmitterCode(), func(block int) int { return block%3 + 1 })
	emitter := crypto.CreateAddress(rtSender, 1)
	pattern, err := NewPatternMatcherFromJSON(json.RawMessage(addrLeaf(emitter)))
	if err != nil {
		t.Fatal(err)
	}
	trusted, opts := rtc.bc.CurrentBlock(), DefaultVerifyOptions(rtc.bc.Config())

	// the address matches 4 logs per call and 1-3 calls per block: well over
	// 60 candidates in the first 10 blocks, so a cap of 100 per window of 4
	// blocks is enough for a small limit but not for the whole range
	rtc.matcher.MaxCandidates = 100
	rtc.matcher.ScanWindow = 4
	for _, latest := range []bool{false, true} {
		req := FilterQuery{Pattern: pattern, FirstBlock: 1, LastBlock: 39, Limit: 5, LimitLatest: latest}
		logs, _, proof, err := rtc.matcher.GetMatches(context.Background(), &rtView{rtc}, req, true)
		if err != nil {
			t.Fatalf("latest=%v: %v", latest, err)
		}
		if len(logs) != 5 {
			t.Fatalf("latest=%v: %d logs, want 5", latest, len(logs))
		}
		res, err := proof.Verify(trusted, req, opts)
		if err != nil {
			t.Fatalf("latest=%v: verify: %v", latest, err)
		}
		if len(res.Logs) != 5 {
			t.Errorf("latest=%v: verified %d logs", latest, len(res.Logs))
		}
	}
	// without a limit the whole range has to be derived and the cap bites
	req := FilterQuery{Pattern: pattern, FirstBlock: 1, LastBlock: 39, Limit: 10_000}
	if _, _, _, err := rtc.matcher.GetMatches(context.Background(), &rtView{rtc}, req, true); err == nil {
		t.Error("an unlimited broad query was served past the candidate cap")
	}
}

// TestCursorPagination pages through results with a small limit, resuming each
// page at the cursor of the previous one: every page verifies, no log is
// repeated or skipped, and the pages add up to the unlimited result, in both
// scan directions and across all patterns.
func TestCursorPagination(t *testing.T) {
	rtc := newRTChainWith(t, 40, diffEmitterCode(), func(block int) int { return block%3 + 1 })
	emitter := crypto.CreateAddress(rtSender, 1)
	trusted := rtc.bc.CurrentBlock()
	opts := DefaultVerifyOptions(rtc.bc.Config())
	last := trusted.Number.Uint64()

	for _, dp := range diffPatterns {
		pattern, err := NewPatternMatcherFromJSON(json.RawMessage(dp.json(emitter)))
		if err != nil {
			t.Fatal(err)
		}
		want := expectedMatches(rtc, dp, 1, last)
		for _, latest := range []bool{false, true} {
			for _, limit := range []uint64{1, 3, 7} {
				name := fmt.Sprintf("%s limit %d latest %v", dp.name, limit, latest)
				var (
					pages  [][]*types.Log
					first  = uint64(1)
					lastB  = last
					cursor *Cursor
				)
				for page := 0; ; page++ {
					if page > len(want)+2 {
						t.Fatalf("%s: pagination does not terminate", name)
					}
					req := FilterQuery{Pattern: pattern, FirstBlock: first, LastBlock: lastB, Limit: limit, LimitLatest: latest, Cursor: cursor}
					served, _, proof, err := rtc.matcher.GetMatches(context.Background(), &rtView{rtc}, req, true)
					if err != nil {
						t.Fatalf("%s page %d: %v", name, page, err)
					}
					blob, err := json.Marshal(proof)
					if err != nil {
						t.Fatal(err)
					}
					var decoded QueryProof
					if err := json.Unmarshal(blob, &decoded); err != nil {
						t.Fatalf("%s page %d: %v", name, page, err)
					}
					res, err := decoded.Verify(trusted, req, opts)
					if err != nil {
						t.Fatalf("%s page %d: verify: %v", name, page, err)
					}
					if len(res.Logs) != len(served) {
						t.Fatalf("%s page %d: verified %d logs, served %d", name, page, len(res.Logs), len(served))
					}
					pages = append(pages, res.Logs)
					if uint64(len(res.Logs)) < limit {
						break
					}
					if latest {
						oldest := res.Logs[0]
						lastB, cursor = oldest.BlockNumber, &Cursor{Block: oldest.BlockNumber, LogIndex: uint64(oldest.Index)}
					} else {
						newest := res.Logs[len(res.Logs)-1]
						first, cursor = newest.BlockNumber, &Cursor{Block: newest.BlockNumber, LogIndex: uint64(newest.Index)}
					}
				}
				var all []*types.Log
				if latest {
					for i := len(pages) - 1; i >= 0; i-- {
						all = append(all, pages[i]...)
					}
				} else {
					for _, p := range pages {
						all = append(all, p...)
					}
				}
				checkLogs(t, name, all, want)
			}
		}
	}
}

// TestAllOfSkipsHugeRuns pins that an allOf does not read the run of a child
// that cannot pay for itself: a busy address next to a rare topic is served
// under a candidate cap far below the address's run.
func TestAllOfSkipsHugeRuns(t *testing.T) {
	rtc := newRTChainWith(t, 40, diffEmitterCode(), func(block int) int { return block%3 + 1 })
	emitter := crypto.CreateAddress(rtSender, 1)
	trusted, opts := rtc.bc.CurrentBlock(), DefaultVerifyOptions(rtc.bc.Config())

	// topic0=B is on one log per call, the address on four
	pattern, err := NewPatternMatcherFromJSON(json.RawMessage(fmt.Sprintf(`{"allOf":[%s,%s]}`, addrLeaf(emitter), topicLeaf(0, topicB))))
	if err != nil {
		t.Fatal(err)
	}
	rtc.matcher.MaxCandidates = 100
	req := FilterQuery{Pattern: pattern, FirstBlock: 1, LastBlock: 39, Limit: 1000}
	logs, _, proof, err := rtc.matcher.GetMatches(context.Background(), &rtView{rtc}, req, true)
	if err != nil {
		t.Fatalf("the cheap child should have served the query: %v", err)
	}
	res, err := proof.Verify(trusted, req, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) == 0 || len(res.Logs) != len(logs) {
		t.Fatalf("served %d logs, verified %d", len(logs), len(res.Logs))
	}
	// the address alone is over the cap
	alone, err := NewPatternMatcherFromJSON(json.RawMessage(addrLeaf(emitter)))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := rtc.matcher.GetMatches(context.Background(), &rtView{rtc}, FilterQuery{Pattern: alone, FirstBlock: 1, LastBlock: 39, Limit: 1000}, true); err == nil {
		t.Error("the address alone fits the cap, the test does not exercise the skip")
	}
}
