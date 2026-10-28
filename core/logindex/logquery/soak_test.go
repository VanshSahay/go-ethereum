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
	"testing"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// TestSoakPastLevelRetention runs proven queries on a chain longer than the
// level-0 ring (1025 blocks), so the old blocks are only held by the higher
// levels: ranges in the pruned part, straddling the pruning edge and in the
// recent part must all be served, verified and equal to a brute-force scan,
// with and without cursor paging. It is the in-process counterpart of the
// retention step of the devnet check, which needs over an hour of real slots.
func TestSoakPastLevelRetention(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a 1300-block chain")
	}
	const blocks = 1300
	rtc := newRTChainWith(t, blocks, diffEmitterCode(), func(block int) int { return block % 2 })
	emitter := crypto.CreateAddress(rtSender, 1)
	trusted := rtc.bc.CurrentBlock()
	opts := DefaultVerifyOptions(rtc.bc.Config())
	last := trusted.Number.Uint64()

	// ranges: deep in the pruned part, across the level-0 edge (the head minus
	// 1025 blocks), and the recent part
	edge := last - 1025
	ranges := [][2]uint64{{16, 200}, {edge - 40, edge + 40}, {last - 100, last}, {16, last}}

	for _, dp := range diffPatterns[:3] {
		pattern, err := NewPatternMatcherFromJSON(json.RawMessage(dp.json(emitter)))
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range ranges {
			want := expectedMatches(rtc, dp, r[0], r[1])
			if len(want) == 0 {
				t.Fatalf("%s %d..%d: the brute-force scan finds nothing, the test would be vacuous", dp.name, r[0], r[1])
			}
			for _, limit := range []uint64{rtMaxUint64, 97} {
				name := fmt.Sprintf("%s %d..%d limit %d", dp.name, r[0], r[1], limit)
				var (
					got    []*types.Log
					first  = r[0]
					cursor *Cursor
				)
				for page := 0; ; page++ {
					if page > len(want)/int(min(limit, 1<<20))+3 {
						t.Fatalf("%s: pagination does not terminate", name)
					}
					req := FilterQuery{Pattern: pattern, FirstBlock: first, LastBlock: r[1], Limit: limit, Cursor: cursor}
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
					got = append(got, res.Logs...)
					if uint64(len(res.Logs)) < limit {
						break
					}
					newest := res.Logs[len(res.Logs)-1]
					first, cursor = newest.BlockNumber, &Cursor{Block: newest.BlockNumber, LogIndex: uint64(newest.Index)}
				}
				checkLogs(t, name, got, want)
			}
		}
	}
}
