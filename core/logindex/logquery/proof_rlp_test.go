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

// TestProofRLPRoundTrip pins that the binary form carries the whole proof: it
// decodes and verifies to the same logs as the JSON form, and it is smaller.
func TestProofRLPRoundTrip(t *testing.T) {
	rtc := newRTChainWith(t, 40, diffEmitterCode(), func(block int) int { return block%3 + 1 })
	emitter := crypto.CreateAddress(rtSender, 1)
	pattern, err := NewPatternMatcherFromJSON(json.RawMessage(fmt.Sprintf(`{"allOf":[%s,%s]}`, addrLeaf(emitter), topicLeaf(0, topicA))))
	if err != nil {
		t.Fatal(err)
	}
	req := FilterQuery{Pattern: pattern, FirstBlock: 1, LastBlock: 30, Limit: 40}
	logs, _, proof, err := rtc.matcher.GetMatches(context.Background(), &rtView{rtc}, req, true)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := rlp.EncodeToBytes(proof)
	if err != nil {
		t.Fatal(err)
	}
	var decoded QueryProof
	if err := rlp.DecodeBytes(blob, &decoded); err != nil {
		t.Fatal(err)
	}
	trusted, opts := rtc.bc.CurrentBlock(), DefaultVerifyOptions(rtc.bc.Config())
	res, err := decoded.Verify(trusted, req, opts)
	if err != nil {
		t.Fatalf("verify decoded proof: %v", err)
	}
	if len(res.Logs) != len(logs) || len(logs) == 0 {
		t.Fatalf("verified %d logs, served %d", len(res.Logs), len(logs))
	}
	jsonBlob, _ := json.Marshal(proof)
	t.Logf("proof size: json %d bytes, rlp %d bytes (%.0f%%)", len(jsonBlob), len(blob), 100*float64(len(blob))/float64(len(jsonBlob)))
	if len(blob) >= len(jsonBlob) {
		t.Errorf("rlp proof (%d) not smaller than json (%d)", len(blob), len(jsonBlob))
	}
	// truncated and bit-flipped encodings never panic
	for i := 0; i < len(blob); i += 97 {
		var p QueryProof
		_ = rlp.DecodeBytes(blob[:i], &p)
		mut := append([]byte(nil), blob...)
		mut[i] ^= 0xff
		if err := rlp.DecodeBytes(mut, &p); err == nil {
			_, _ = p.Verify(trusted, req, opts)
		}
	}
}
