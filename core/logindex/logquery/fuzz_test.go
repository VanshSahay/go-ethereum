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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

// mutation sites: every array element and object member of the decoded proof
type site struct {
	array  []interface{}
	object map[string]interface{}
	index  int
	key    string
}

func collectSites(v interface{}, out *[]site) {
	switch v := v.(type) {
	case []interface{}:
		for i, child := range v {
			*out = append(*out, site{array: v, index: i})
			collectSites(child, out)
		}
	case map[string]interface{}:
		for key, child := range v {
			*out = append(*out, site{object: v, key: key})
			collectSites(child, out)
		}
	}
}

// mutate applies one structural change to the decoded proof, chosen by the
// fuzzer: deleting, retyping, overwriting, duplicating or swapping a member.
func mutate(doc interface{}, pick, op uint32, value uint64) {
	var sites []site
	collectSites(doc, &sites)
	if len(sites) == 0 {
		return
	}
	s := sites[int(pick)%len(sites)]
	set := func(v interface{}) {
		if s.array != nil {
			s.array[s.index] = v
		} else {
			s.object[s.key] = v
		}
	}
	get := func() interface{} {
		if s.array != nil {
			return s.array[s.index]
		}
		return s.object[s.key]
	}
	switch op % 7 {
	case 0: // delete (objects) or null out (arrays)
		if s.object != nil {
			delete(s.object, s.key)
		} else {
			set(nil)
		}
	case 1: // overwrite with a number
		set(json.Number(fmt.Sprint(value)))
	case 2: // overwrite with a string
		set(fmt.Sprintf("0x%x", value))
	case 3: // flip a byte of a hex string
		if str, ok := get().(string); ok && len(str) > 2 {
			b := []byte(str)
			i := 2 + int(value%uint64(len(b)-2))
			b[i] = "0123456789abcdef"[(value>>8)%16]
			set(string(b))
		}
	case 4: // toggle booleans, negate numbers
		switch v := get().(type) {
		case bool:
			set(!v)
		case json.Number:
			set(json.Number("0"))
		}
	case 5: // duplicate an array element
		if s.array != nil && s.index > 0 {
			s.array[s.index] = s.array[s.index-1]
		}
	case 6: // swap with the neighbor
		if s.array != nil && s.index > 0 {
			s.array[s.index], s.array[s.index-1] = s.array[s.index-1], s.array[s.index]
		}
	}
}

// FuzzVerify checks the verifier's soundness and robustness: a structurally
// mutated proof must never panic, and if it still verifies it must prove
// exactly the logs of the honest proof.
func FuzzVerify(f *testing.F) {
	rtc := newRTChainWith(f, 40, diffEmitterCode(), func(block int) int { return block%3 + 1 })
	emitter := crypto.CreateAddress(rtSender, 1)
	pattern, err := NewPatternMatcherFromJSON(json.RawMessage(fmt.Sprintf(`{"allOf":[%s,%s]}`, addrLeaf(emitter), topicLeaf(0, topicA))))
	if err != nil {
		f.Fatal(err)
	}
	req := FilterQuery{Pattern: pattern, FirstBlock: 1, LastBlock: 30, Limit: 40}
	logs, _, proof, err := rtc.matcher.GetMatches(context.Background(), &rtView{rtc}, req, true)
	if err != nil {
		f.Fatal(err)
	}
	honest, err := json.Marshal(proof)
	if err != nil {
		f.Fatal(err)
	}
	trusted, opts := rtc.bc.CurrentBlock(), DefaultVerifyOptions(rtc.bc.Config())
	want := make([]string, len(logs))
	for i, l := range logs {
		want[i] = fmt.Sprintf("%d/%d/%d", l.BlockNumber, l.TxIndex, l.Index)
	}

	for pick := uint32(0); pick < 64; pick += 7 {
		for op := uint32(0); op < 7; op++ {
			f.Add(pick, op, uint64(pick)*131+uint64(op))
		}
	}
	f.Fuzz(func(t *testing.T, pick, op uint32, value uint64) {
		dec := json.NewDecoder(bytes.NewReader(honest))
		dec.UseNumber()
		var doc interface{}
		if err := dec.Decode(&doc); err != nil {
			t.Fatal(err)
		}
		mutate(doc, pick, op, value)
		blob, err := json.Marshal(doc)
		if err != nil {
			t.Skip()
		}
		var p QueryProof
		if err := json.Unmarshal(blob, &p); err != nil {
			t.Skip() // not a proof at all
		}
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("verify panicked on %s: %v", blob[:min(len(blob), 200)], r)
			}
		}()
		res, err := p.Verify(trusted, req, opts)
		if err != nil {
			return
		}
		if len(res.Logs) != len(want) {
			t.Fatalf("mutated proof verified with %d logs, honest has %d", len(res.Logs), len(want))
		}
		for i, l := range res.Logs {
			if got := fmt.Sprintf("%d/%d/%d", l.BlockNumber, l.TxIndex, l.Index); got != want[i] {
				t.Fatalf("mutated proof verified with log %d = %s, honest has %s", i, got, want[i])
			}
		}
	})
}
