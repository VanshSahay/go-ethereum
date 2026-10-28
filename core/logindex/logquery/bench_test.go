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

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

// BenchmarkProvenQuery measures serving and verifying a proven query over a
// 1300-block chain (past the level-0 ring) and reports the proof size in both
// encodings, for a rare topic, a common one and the busy address.
func BenchmarkProvenQuery(b *testing.B) {
	rtc := newRTChainWith(b, 1300, diffEmitterCode(), func(block int) int { return block%3 + 1 })
	emitter := crypto.CreateAddress(rtSender, 1)
	trusted, opts := rtc.bc.CurrentBlock(), DefaultVerifyOptions(rtc.bc.Config())
	last := trusted.Number.Uint64()

	for _, tc := range []struct{ name, json string }{
		{"rare-topic1", topicLeaf(1, topicB)},
		{"common-topic0", topicLeaf(0, topicA)},
		{"address", addrLeaf(emitter)},
	} {
		pattern, err := NewPatternMatcherFromJSON(json.RawMessage(tc.json))
		if err != nil {
			b.Fatal(err)
		}
		req := FilterQuery{Pattern: pattern, FirstBlock: 16, LastBlock: last, Limit: 10000}
		b.Run(tc.name+"/serve", func(b *testing.B) {
			var proof *QueryProof
			var n int
			for i := 0; i < b.N; i++ {
				logs, _, p, err := rtc.matcher.GetMatches(context.Background(), &rtView{rtc}, req, true)
				if err != nil {
					b.Fatal(err)
				}
				proof, n = p, len(logs)
			}
			blobJSON, _ := json.Marshal(proof)
			blobRLP, _ := rlp.EncodeToBytes(proof)
			b.ReportMetric(float64(n), "logs")
			b.ReportMetric(float64(len(blobJSON)), "json-bytes")
			b.ReportMetric(float64(len(blobRLP)), "rlp-bytes")
			b.ReportMetric(float64(provenEntryCount(proof)), "entries")
		})
		b.Run(tc.name+"/verify", func(b *testing.B) {
			_, _, proof, err := rtc.matcher.GetMatches(context.Background(), &rtView{rtc}, req, true)
			if err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := proof.Verify(trusted, req, opts); err != nil {
					b.Fatal(fmt.Errorf("verify: %w", err))
				}
			}
		})
	}
}
