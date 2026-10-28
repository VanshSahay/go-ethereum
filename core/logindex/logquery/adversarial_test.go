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
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// advFixture is an honest proof over the round-trip chain together with the
// trust anchors a verifier would hold.
type advFixture struct {
	trusted *types.Header
	req     FilterQuery
	opts    VerifyOptions
	blob    []byte // the honest proof as JSON
	logs    int
}

func newAdvFixture(t *testing.T) *advFixture {
	t.Helper()
	rtc := newRTChain(t, 40)
	emitter := crypto.CreateAddress(rtSender, 1)
	pattern, err := NewLegacyMatcher([]common.Address{emitter}, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := FilterQuery{Pattern: pattern, FirstBlock: 1, LastBlock: 39, Limit: rtMaxUint64}
	logs, _, proof, err := rtc.matcher.GetMatches(context.Background(), &rtView{rtc}, req, true)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	return &advFixture{
		trusted: rtc.bc.CurrentBlock(),
		req:     req,
		opts:    DefaultVerifyOptions(rtc.bc.Config()),
		blob:    blob,
		logs:    len(logs),
	}
}

// proof returns a fresh copy of the honest proof.
func (f *advFixture) proof(t *testing.T) *QueryProof {
	t.Helper()
	var p QueryProof
	if err := json.Unmarshal(f.blob, &p); err != nil {
		t.Fatal(err)
	}
	return &p
}

// mustReject runs Verify on a mutated proof and requires an error. A panic
// fails the test.
func (f *advFixture) mustReject(t *testing.T, name string, mutate func(p *QueryProof)) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s: verify panicked: %v", name, r)
		}
	}()
	p := f.proof(t)
	mutate(p)
	res, err := p.Verify(f.trusted, f.req, f.opts)
	if err == nil {
		t.Errorf("%s: forged proof verified (%d logs)", name, len(res.Logs))
		return
	}
	t.Logf("%s: rejected: %v", name, err)
}

func TestAdversarialHonestBaseline(t *testing.T) {
	f := newAdvFixture(t)
	res, err := f.proof(t).Verify(f.trusted, f.req, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Logs) != f.logs || f.logs == 0 {
		t.Fatalf("verified %d logs, want %d", len(res.Logs), f.logs)
	}
}

// TestAdversarialAnchors pins that the proof is bound to the caller's trusted
// header and request, not to what the proof itself claims.
func TestAdversarialAnchors(t *testing.T) {
	f := newAdvFixture(t)

	// a different trusted header
	other := types.CopyHeader(f.trusted)
	other.Number.Add(other.Number, common.Big1)
	if _, err := f.proof(t).Verify(other, f.req, f.opts); err == nil {
		t.Error("proof verified against a different trusted header")
	}
	if _, err := f.proof(t).Verify(nil, f.req, f.opts); err == nil {
		t.Error("proof verified without a trusted header")
	}

	// a different request than the one the proof answers
	otherPattern, _ := NewLegacyMatcher([]common.Address{{0xde, 0xad}}, nil)
	for name, req := range map[string]FilterQuery{
		"pattern":  {Pattern: otherPattern, FirstBlock: f.req.FirstBlock, LastBlock: f.req.LastBlock, Limit: f.req.Limit},
		"limit":    {Pattern: f.req.Pattern, FirstBlock: f.req.FirstBlock, LastBlock: f.req.LastBlock, Limit: 5},
		"latest":   {Pattern: f.req.Pattern, FirstBlock: f.req.FirstBlock, LastBlock: f.req.LastBlock, Limit: f.req.Limit, LimitLatest: true},
		"no limit": {Pattern: f.req.Pattern, FirstBlock: f.req.FirstBlock, LastBlock: f.req.LastBlock},
		"nil":      {FirstBlock: f.req.FirstBlock, LastBlock: f.req.LastBlock, Limit: f.req.Limit},
	} {
		if _, err := f.proof(t).Verify(f.trusted, req, f.opts); err == nil {
			t.Errorf("proof verified for a different %s", name)
		}
	}

	// a request range the proven range is not inside of
	narrow := f.req
	narrow.FirstBlock, narrow.LastBlock = 20, 30
	if _, err := f.proof(t).Verify(f.trusted, narrow, f.opts); err == nil {
		t.Error("proof verified for a request range it does not lie in")
	}
	inverted := f.req
	inverted.FirstBlock, inverted.LastBlock = 30, 10
	if _, err := f.proof(t).Verify(f.trusted, inverted, f.opts); err == nil {
		t.Error("inverted request range accepted")
	}
}

// TestAdversarialIndexContract pins the contract allowlist and the table
// parameter checks that keep a prover from naming its own index contract or
// aliasing a different ring slot.
func TestAdversarialIndexContract(t *testing.T) {
	f := newAdvFixture(t)

	f.mustReject(t, "contract index out of range", func(p *QueryProof) {
		p.TableQueryProofs[0].IndexContract = 99
	})
	f.mustReject(t, "contract not accepted", func(p *QueryProof) {
		p.IndexContracts[0] = common.Address{0xba, 0xd0}
	})
	f.mustReject(t, "extra contracts listed", func(p *QueryProof) {
		p.IndexContracts = append(p.IndexContracts, make([]common.Address, len(p.TableQueryProofs)+1)...)
	})

	// the allowlist expects the reference bytecode
	wrongCode := f.opts
	wrongCode.IndexContracts = map[common.Address]common.Hash{}
	for addr := range f.opts.IndexContracts {
		wrongCode.IndexContracts[addr] = common.Hash{0x01}
	}
	if _, err := f.proof(t).Verify(f.trusted, f.req, wrongCode); err == nil {
		t.Error("proof verified against a different expected code hash")
	}
	if _, err := f.proof(t).Verify(f.trusted, f.req, VerifyOptions{ChainConfig: f.opts.ChainConfig}); err == nil {
		t.Error("proof verified with an empty contract allowlist")
	}

	f.mustReject(t, "table size zero", func(p *QueryProof) {
		p.TableQueryProofs[len(p.TableQueryProofs)-1].TableSize = 0
	})
	f.mustReject(t, "table size overflow alias", func(p *QueryProof) {
		p.TableQueryProofs[0].TableSize = 1<<54 + 1
		p.TableQueryProofs[0].FirstBlock = 0
	})
	f.mustReject(t, "unprotocol table size", func(p *QueryProof) {
		p.TableQueryProofs[0].TableSize = 3
	})
	f.mustReject(t, "misaligned first block", func(p *QueryProof) {
		for i := range p.TableQueryProofs {
			if p.TableQueryProofs[i].TableSize > 1 {
				p.TableQueryProofs[i].FirstBlock++
				return
			}
		}
		t.Skip("no multi-block table in the proof")
	})
	f.mustReject(t, "table not yet published", func(p *QueryProof) {
		last := &p.TableQueryProofs[len(p.TableQueryProofs)-1]
		last.FirstBlock += 1024
		last.TableSize = 1
	})
}
