package logquery

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// TestMidRangeQuery pins that queries whose result range ends before the
// reference head, or whose result limit truncates the scan, still produce
// verifiable proofs: the tables covering the head are always part of the
// proof and chain it to the reference header.
func TestMidRangeQuery(t *testing.T) {
	rtc := newRTChain(t, 40)
	v := &rtView{rtc}
	opts := DefaultVerifyOptions(rtc.bc.Config())
	trusted := rtc.bc.CurrentBlock()

	emitterAddr := crypto.CreateAddress(rtSender, 1)
	matcher, err := NewLegacyMatcher([]common.Address{emitterAddr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	run := func(name string, lastBlock, limit uint64, latest bool, exact bool) {
		t.Helper()
		req := FilterQuery{
			Pattern:     matcher,
			FirstBlock:  1,
			LastBlock:   lastBlock,
			Limit:       limit,
			LimitLatest: latest,
		}
		logs, _, proof, err := rtc.matcher.GetMatches(context.Background(), v, req, true)
		if err != nil {
			t.Fatalf("%s: get matches: %v", name, err)
		}
		enc, err := json.Marshal(proof)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var decoded QueryProof
		if err := json.Unmarshal(enc, &decoded); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		res, err := decoded.Verify(trusted, req, opts)
		if err != nil {
			t.Fatalf("%s: verify: %v", name, err)
		}
		verified := res.Logs
		if exact && len(verified) != len(logs) {
			t.Fatalf("%s: verified %d logs, want %d", name, len(verified), len(logs))
		}
		if !exact && len(verified) < len(logs) {
			t.Fatalf("%s: verified %d logs, want at least %d", name, len(verified), len(logs))
		}
	}
	run("mid-range", 25, rtMaxUint64, false, true)
	run("ending at head", 40, rtMaxUint64, false, true)
	run("mid-range limited", 25, 7, false, false)
	run("mid-range latest", 25, 5, true, false)

	// a query with no matches at all must still verify with zero results
	absent, err := NewLegacyMatcher(nil, [][]common.Hash{{{0xde, 0xad}}})
	if err != nil {
		t.Fatal(err)
	}
	absentReq := FilterQuery{
		Pattern:    absent,
		FirstBlock: 1,
		LastBlock:  40,
		Limit:      rtMaxUint64,
	}
	logs, _, proof, err := rtc.matcher.GetMatches(context.Background(), v, absentReq, true)
	if err != nil {
		t.Fatalf("absent: get matches: %v", err)
	}
	if len(logs) != 0 {
		t.Fatalf("absent: %d logs, want 0", len(logs))
	}
	res, err := proof.Verify(trusted, absentReq, opts)
	if err != nil {
		t.Fatalf("absent: verify: %v", err)
	}
	if len(res.Logs) != 0 {
		t.Fatalf("absent: %d verified, want 0", len(res.Logs))
	}
}
