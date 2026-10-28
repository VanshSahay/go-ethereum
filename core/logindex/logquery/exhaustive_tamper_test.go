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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

// flipLeaf returns a modified copy of a proof leaf: a hex or base64 string
// with its middle byte inverted, or a number plus one. It reports false for
// leaves it leaves alone (short quantities, booleans, null).
func flipLeaf(v interface{}) (interface{}, bool) {
	switch v := v.(type) {
	case string:
		if strings.HasPrefix(v, "0x") {
			if len(v) < 10 {
				return nil, false
			}
			b, err := hex.DecodeString(v[2:])
			if err != nil || len(b) == 0 {
				return nil, false
			}
			b[len(b)/2] ^= 0xff
			return "0x" + hex.EncodeToString(b), true
		}
		b, err := base64.StdEncoding.DecodeString(v)
		if err != nil || len(b) < 4 {
			return nil, false
		}
		b[len(b)/2] ^= 0xff
		return base64.StdEncoding.EncodeToString(b), true
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			return nil, false
		}
		return json.Number(fmt.Sprint(n + 1)), true
	}
	return nil, false
}

// proofLeaf is a modifiable string or number of a decoded proof.
type proofLeaf struct {
	path string
	set  func(interface{})
	get  func() interface{}
}

// collectLeaves lists the modifiable leaves of a decoded proof in a fixed
// order (sorted object keys). The "hash" member of a header is derived on
// decoding and skipped.
func collectLeaves(doc interface{}) []proofLeaf {
	var out []proofLeaf
	var walk func(v interface{}, path string)
	walk = func(v interface{}, path string) {
		switch c := v.(type) {
		case []interface{}:
			for i := range c {
				p := fmt.Sprintf("%s[%d]", path, i)
				if _, ok := flipLeaf(c[i]); ok {
					out = append(out, proofLeaf{p, func(n interface{}) { c[i] = n }, func() interface{} { return c[i] }})
				} else {
					walk(c[i], p)
				}
			}
		case map[string]interface{}:
			keys := make([]string, 0, len(c))
			for k := range c {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				p := path + "." + k
				if k == "hash" {
					continue
				}
				if _, ok := flipLeaf(c[k]); ok {
					out = append(out, proofLeaf{p, func(n interface{}) { c[k] = n }, func() interface{} { return c[k] }})
				} else {
					walk(c[k], p)
				}
			}
		}
	}
	walk(doc, "")
	return out
}

// TestVerifyRejectsEverySingleChange modifies every string and number of an
// honest proof, one at a time, and requires that the verifier either rejects
// the result or proves exactly the honest logs: a change that is accepted and
// alters the result would be a soundness hole, one that is accepted without
// effect is reported, because it names material the verifier does not bind.
// The "hash" member of a header is derived on decoding and skipped.
func TestVerifyRejectsEverySingleChange(t *testing.T) {
	rtc := newRTChainWith(t, 70, diffEmitterCode(), func(block int) int { return block%3 + 1 })
	emitter := crypto.CreateAddress(rtSender, 1)
	pattern, err := NewPatternMatcherFromJSON(json.RawMessage(fmt.Sprintf(`{"allOf":[%s,%s]}`, addrLeaf(emitter), topicLeaf(0, topicA))))
	if err != nil {
		t.Fatal(err)
	}
	req := FilterQuery{Pattern: pattern, FirstBlock: 1, LastBlock: 60, Limit: 40}
	logs, _, proof, err := rtc.matcher.GetMatches(context.Background(), &rtView{rtc}, req, true)
	if err != nil {
		t.Fatal(err)
	}
	honest, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	trusted, opts := rtc.bc.CurrentBlock(), DefaultVerifyOptions(rtc.bc.Config())
	want := make([]string, len(logs))
	for i, l := range logs {
		want[i] = fmt.Sprintf("%d/%d/%d", l.BlockNumber, l.TxIndex, l.Index)
	}

	decode := func() map[string]interface{} {
		dec := json.NewDecoder(bytes.NewReader(honest))
		dec.UseNumber()
		var doc map[string]interface{}
		if err := dec.Decode(&doc); err != nil {
			t.Fatal(err)
		}
		return doc
	}
	// the leaves are numbered in a fixed order; each modification is applied
	// to a fresh decode at its position
	numLeaves := len(collectLeaves(decode()))
	if numLeaves < 100 {
		t.Fatalf("only %d leaves: the test would not cover the proof", numLeaves)
	}
	var accepted []string
	for n := 0; n < numLeaves; n++ {
		doc := decode()
		fresh := collectLeaves(doc)
		flipped, _ := flipLeaf(fresh[n].get())
		fresh[n].set(flipped)
		blob, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		var p QueryProof
		if err := json.Unmarshal(blob, &p); err != nil {
			continue // no longer a proof
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("verify panicked after modifying %s: %v", fresh[n].path, r)
				}
			}()
			res, err := p.Verify(trusted, req, opts)
			if err != nil {
				return
			}
			got := make([]string, len(res.Logs))
			for i, l := range res.Logs {
				got[i] = fmt.Sprintf("%d/%d/%d", l.BlockNumber, l.TxIndex, l.Index)
			}
			if strings.Join(got, ",") != strings.Join(want, ",") {
				t.Errorf("modifying %s changed the verified result", fresh[n].path)
				return
			}
			accepted = append(accepted, fresh[n].path)
		}()
	}
	t.Logf("%d leaves modified, %d accepted without effect", numLeaves, len(accepted))
	for _, path := range accepted {
		t.Errorf("modifying %s is accepted: the verifier does not bind it", path)
	}
}
