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
	"math"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// advFixture is an honest proof over the round-trip chain together with the
// trust anchors a verifier would hold.
type advFixture struct {
	rtc     *rtChain
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
		rtc:     rtc,
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

// reader returns the index table a table proof was made from.
func (f *advFixture) reader(t *testing.T, tqp *tableQueryProof) *tableProver {
	t.Helper()
	for _, tr := range f.rtc.bc.LogIndex().GetRangeReaders(f.trusted.Hash(), common.NewRange[uint64](tqp.FirstBlock, tqp.TableSize), 0) {
		if br := tr.BlockRange(); br.First() == tqp.FirstBlock && br.Count() == tqp.TableSize {
			return newTableProver(tr)
		}
	}
	t.Fatalf("table [%d, %d) not found", tqp.FirstBlock, tqp.TableSize)
	return nil
}

// rebuild replaces the proven entries of a table proof with the ones selected
// by keep and re-derives a valid multiproof for them from the real table, as a
// prover that wants to hide entries would.
func (f *advFixture) rebuild(t *testing.T, tqp *tableQueryProof, keep func(i int, entry types.IndexEntry) bool) {
	t.Helper()
	tp := f.reader(t, tqp)
	var (
		indices []uint64
		entries []types.IndexEntry
		hashes  []common.Hash
		last    = uint64(math.MaxUint64)
		err     error
	)
	for i, entry := range tqp.ProvenEntries {
		if !keep(i, entry) {
			continue
		}
		idx := tqp.EntryIndices[i]
		if hashes, err = tp.makeProofHashes(hashes, last, idx); err != nil {
			t.Fatal(err)
		}
		indices, entries, last = append(indices, idx), append(entries, entry), idx
	}
	if hashes, err = tp.makeProofHashes(hashes, last, math.MaxUint64); err != nil {
		t.Fatal(err)
	}
	tqp.EntryIndices, tqp.ProvenEntries, tqp.ProofHashes = indices, entries, hashes
}

// resultTable returns the index of the first table proof with block results.
func resultTable(t *testing.T, p *QueryProof) int {
	t.Helper()
	for i := range p.TableQueryProofs {
		if len(p.TableQueryProofs[i].BlockResults) > 0 {
			return i
		}
	}
	t.Fatal("no table with results")
	return 0
}

// TestAdversarialOmission pins the completeness of the results: a prover that
// leaves out receipts, blocks or index entries must be caught, however
// consistently it rewrites the rest of the proof.
func TestAdversarialOmission(t *testing.T) {
	f := newAdvFixture(t)

	f.mustReject(t, "drop every block result", func(p *QueryProof) {
		tqp := &p.TableQueryProofs[resultTable(t, p)]
		tqp.BlockResults, tqp.ResultCount = nil, 0
	})
	f.mustReject(t, "drop one block result", func(p *QueryProof) {
		tqp := &p.TableQueryProofs[resultTable(t, p)]
		tqp.BlockResults = tqp.BlockResults[1:]
	})
	f.mustReject(t, "clear the proven receipts of a block", func(p *QueryProof) {
		tqp := &p.TableQueryProofs[resultTable(t, p)]
		tqp.BlockResults[0].ProvenReceipts = nil
	})
	f.mustReject(t, "lower the result count", func(p *QueryProof) {
		tqp := &p.TableQueryProofs[resultTable(t, p)]
		tqp.ResultCount--
	})

	// hide the whole run of one block: drop its address entries, its block
	// result and its results from the count, then rebuild a valid multiproof
	// over the remaining entries
	forge := func(t *testing.T, p *QueryProof) string {
		tqp := &p.TableQueryProofs[resultTable(t, p)]
		hidden := tqp.BlockResults[0].Header.Number.Uint64()
		var dropped uint64
		f.rebuild(t, tqp, func(i int, entry types.IndexEntry) bool {
			typ, _, block, _, _, err := types.EntryFields(entry)
			if err != nil {
				t.Fatal(err)
			}
			if typ == types.EntryTypeLogAddress && block == hidden {
				dropped++
				return false
			}
			return true
		})
		if dropped == 0 {
			t.Fatal("no entries to hide")
		}
		tqp.BlockResults = tqp.BlockResults[1:]
		tqp.ResultCount -= dropped
		return "hidden block"
	}
	func() {
		p := f.proof(t)
		forge(t, p)
		_, err := p.Verify(f.trusted, f.req, f.opts)
		if err == nil {
			t.Error("a prover hiding a block's entries and receipts verified")
		} else if !strings.Contains(err.Error(), "bound") {
			t.Errorf("hidden run rejected for the wrong reason: %v", err)
		}
	}()

	// removing single entries of a run leaves a gap or an unbounded edge
	for name, pick := range map[string]func(addrs []int) int{
		"first entry of the run":  func(a []int) int { return a[0] },
		"middle entry of the run": func(a []int) int { return a[len(a)/2] },
		"last entry of the run":   func(a []int) int { return a[len(a)-1] },
	} {
		f.mustReject(t, name, func(p *QueryProof) {
			tqp := &p.TableQueryProofs[resultTable(t, p)]
			var addrs []int
			for i, entry := range tqp.ProvenEntries {
				if typ, _, _, _, _, _ := types.EntryFields(entry); typ == types.EntryTypeLogAddress {
					addrs = append(addrs, i)
				}
			}
			if len(addrs) < 3 {
				t.Skip("run too short")
			}
			drop := pick(addrs)
			f.rebuild(t, tqp, func(i int, _ types.IndexEntry) bool { return i != drop })
		})
	}

	// an empty proof of absence needs adjacent enclosing entries: claiming the
	// table has no entries of the value at all must fail while it has some
	f.mustReject(t, "claim an empty run", func(p *QueryProof) {
		tqp := &p.TableQueryProofs[resultTable(t, p)]
		f.rebuild(t, tqp, func(int, types.IndexEntry) bool { return false })
		tqp.BlockResults, tqp.ResultCount = nil, 0
	})
}

// limitedFixture is like advFixture with a result limit that cuts the result
// set in the middle of a block (three logs per block, limit 8).
func newLimitedFixture(t *testing.T, latest bool) *advFixture {
	t.Helper()
	f := newAdvFixture(t)
	f.req.Limit, f.req.LimitLatest = 8, latest
	logs, _, proof, err := f.rtc.matcher.GetMatches(context.Background(), &rtView{f.rtc}, f.req, true)
	if err != nil {
		t.Fatal(err)
	}
	if f.blob, err = json.Marshal(proof); err != nil {
		t.Fatal(err)
	}
	f.logs = len(logs)
	return f
}

// TestAdversarialRange pins that a prover cannot shrink the answered range
// unless the result limit forces it to.
func TestAdversarialRange(t *testing.T) {
	// without a reached limit the whole requested range must be answered
	f := newAdvFixture(t)
	f.mustReject(t, "shrink the range without reaching the limit", func(p *QueryProof) {
		const cut = 20
		p.Query.LastBlock = cut
		for i := range p.TableQueryProofs {
			tqp := &p.TableQueryProofs[i]
			kept := tqp.BlockResults[:0]
			for _, br := range tqp.BlockResults {
				if br.Header.Number.Uint64() <= cut {
					kept = append(kept, br)
				}
			}
			tqp.BlockResults, tqp.ResultCount = kept, uint64(3*len(kept)) // three logs per block
		}
	})
	f.mustReject(t, "move the start of the range", func(p *QueryProof) {
		p.Query.FirstBlock++
	})

	for _, latest := range []bool{false, true} {
		name := map[bool]string{false: "oldest first", true: "latest first"}[latest]
		fl := newLimitedFixture(t, latest)
		res, err := fl.proof(t).Verify(fl.trusted, fl.req, fl.opts)
		if err != nil {
			t.Fatalf("%s: honest limited proof: %v", name, err)
		}
		if len(res.Logs) != 8 {
			t.Fatalf("%s: %d logs, want exactly the limit of 8", name, len(res.Logs))
		}
		// the proven range ends at the block of the last returned log
		if latest && res.FirstBlock != res.Logs[0].BlockNumber || !latest && res.LastBlock != res.Logs[7].BlockNumber {
			t.Errorf("%s: proven range %d..%d does not end at the cut block", name, res.FirstBlock, res.LastBlock)
		}
		fl.mustReject(t, name+": extend the range past the cut", func(p *QueryProof) {
			if latest {
				p.Query.FirstBlock = fl.req.FirstBlock
			} else {
				p.Query.LastBlock = min(fl.req.LastBlock, fl.trusted.Number.Uint64())
			}
		})
		fl.mustReject(t, name+": cut the range one block short", func(p *QueryProof) {
			if latest {
				p.Query.FirstBlock++
			} else {
				p.Query.LastBlock--
			}
		})
		// a limited answer is only valid for the limit it was made for
		other := fl.req
		other.Limit = 9
		if _, err := fl.proof(t).Verify(fl.trusted, other, fl.opts); err == nil {
			t.Errorf("%s: proof for limit 8 verified for limit 9", name)
		}
	}
}
