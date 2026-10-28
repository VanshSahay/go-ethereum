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
)

// provenEntryCount is the number of table entries a proof carries.
func provenEntryCount(p *QueryProof) (n int) {
	for _, tp := range p.TableQueryProofs {
		n += len(tp.ProvenEntries)
	}
	return n
}

// TestCompositePatternProofCost pins that composing patterns never makes the
// proof bigger than the cheapest equivalent form: a busy leaf (the address, on
// four logs per call) inside an allOf or next to cheaper alternatives is not
// read, and a leaf shared by several branches of an anyOf is proven once. This
// is what a general gate-network optimizer would also have to reach, so a
// regression here means the cost model got worse.
func TestCompositePatternProofCost(t *testing.T) {
	rtc := newRTChainWith(t, 200, diffEmitterCode(), func(block int) int { return block%3 + 1 })
	emitter := crypto.CreateAddress(rtSender, 1)
	trusted, opts := rtc.bc.CurrentBlock(), DefaultVerifyOptions(rtc.bc.Config())

	cost := func(js string) int {
		t.Helper()
		pattern, err := NewPatternMatcherFromJSON(json.RawMessage(js))
		if err != nil {
			t.Fatal(err)
		}
		req := FilterQuery{Pattern: pattern, FirstBlock: 1, LastBlock: 199, Limit: 100000}
		logs, _, proof, err := rtc.matcher.GetMatches(context.Background(), &rtView{rtc}, req, true)
		if err != nil {
			t.Fatal(err)
		}
		res, err := proof.Verify(trusted, req, opts)
		if err != nil {
			t.Fatalf("%s: verify: %v", js, err)
		}
		if len(res.Logs) != len(logs) {
			t.Fatalf("%s: verified %d logs, served %d", js, len(res.Logs), len(logs))
		}
		return provenEntryCount(proof)
	}
	addr, b1, b0 := addrLeaf(emitter), topicLeaf(1, topicB), topicLeaf(0, topicB)
	either := fmt.Sprintf(`{"anyOf":[%s,%s]}`, b1, b0)

	for _, tc := range []struct {
		name      string
		got, want string
	}{
		{"allOf drops the busy leaf", fmt.Sprintf(`{"allOf":[%s,%s]}`, addr, b1), b1},
		{"anyOf of allOfs sharing the busy leaf", fmt.Sprintf(`{"anyOf":[{"allOf":[%s,%s]},{"allOf":[%s,%s]}]}`, addr, b1, addr, b0), either},
		{"allOf of a busy leaf and an anyOf", fmt.Sprintf(`{"allOf":[%s,%s]}`, addr, either), either},
	} {
		if got, want := cost(tc.got), cost(tc.want); got > want {
			t.Errorf("%s: %d proven entries, the equivalent cheapest form needs %d", tc.name, got, want)
		}
	}
}
