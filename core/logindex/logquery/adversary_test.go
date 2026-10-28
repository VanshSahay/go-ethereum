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

	"github.com/ethereum/go-ethereum/core/logindex/logquery/adversary"
	"github.com/ethereum/go-ethereum/crypto"
)

// TestAdversaryModes runs every rewrite of the devnet's adversarial proxy
// against a real proof: the honest result verifies, every attack is rejected.
func TestAdversaryModes(t *testing.T) {
	rtc := newRTChainWith(t, 40, diffEmitterCode(), func(block int) int { return block%3 + 1 })
	emitter := crypto.CreateAddress(rtSender, 1)
	pattern, err := NewPatternMatcherFromJSON(json.RawMessage(fmt.Sprintf(`{"allOf":[%s,%s]}`, addrLeaf(emitter), topicLeaf(0, topicA))))
	if err != nil {
		t.Fatal(err)
	}
	req := FilterQuery{Pattern: pattern, FirstBlock: 1, LastBlock: 30, Limit: 10_000}
	logs, resultRange, proof, err := rtc.matcher.GetMatches(context.Background(), &rtView{rtc}, req, true)
	if err != nil {
		t.Fatal(err)
	}
	result, err := json.Marshal(map[string]any{
		"logs":       logs,
		"firstBlock": fmt.Sprintf("0x%x", resultRange.First()),
		"lastBlock":  fmt.Sprintf("0x%x", resultRange.Last()),
		"proof":      proof,
	})
	if err != nil {
		t.Fatal(err)
	}
	trusted, opts := rtc.bc.CurrentBlock(), DefaultVerifyOptions(rtc.bc.Config())

	for _, mode := range adversary.Modes {
		doc, err := adversary.Decode(result)
		if err != nil {
			t.Fatal(err)
		}
		if err := adversary.Apply(mode, doc); err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		blob, err := json.Marshal(doc["proof"])
		if err != nil {
			t.Fatal(err)
		}
		var p QueryProof
		if err := json.Unmarshal(blob, &p); err != nil {
			if mode == "none" {
				t.Fatalf("honest proof does not decode: %v", err)
			}
			continue // a proof that does not even decode is rejected too
		}
		_, err = p.Verify(trusted, req, opts)
		switch {
		case mode == "none" && err != nil:
			t.Errorf("honest proof rejected: %v", err)
		case mode != "none" && err == nil:
			t.Errorf("%s: attacked proof was accepted", mode)
		case mode != "none":
			t.Logf("%s: rejected: %v", mode, err)
		}
	}
	if err := adversary.Apply("nonsense", map[string]any{"proof": map[string]any{}}); err == nil {
		t.Error("unknown mode accepted")
	}
}
