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
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/beacon"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

var rtMaxUint64 = ^uint64(0)

// rtEmitterCode emits 3 LOG0 events per call (the calling contract's address
// is the log address; LOG0 carries no topics).
//
// runtime: three sequential (PUSH1 n, PUSH0, PUSH0, LOG0) groups with 1-byte
// payloads, then STOP.
var rtEmitterCode = common.FromHex("60015f5fa060025f5fa060035f5fa000")

// rtKey is the sender key for the query chain's transactions.
var rtKey, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
var rtSender = crypto.PubkeyToAddress(rtKey.PublicKey)

// rtChain is a full chain with the index contract deployed, the table roots
// written by the producer through the real system calls, and the matcher
// wired to the chain's index and contract prover backend.
type rtChain struct {
	bc      *core.BlockChain
	matcher *Matcher
}

func newRTChain(t testing.TB, blocks int) *rtChain {
	t.Helper()
	return newRTChainWith(t, blocks, rtEmitterCode, func(int) int { return 1 })
}

// newRTChainWith builds the chain with the given emitter runtime code and a
// per-block number of transactions calling it.
func newRTChainWith(t testing.TB, blocks int, code []byte, txsPerBlock func(block int) int) *rtChain {
	t.Helper()
	config := *params.MergedTestChainConfig
	config.AmsterdamTime = new(uint64)
	alloc := core.SystemContractAllocs()
	alloc[params.IndexContractAddress] = types.Account{
		Nonce:   1,
		Code:    params.IndexContractCode,
		Balance: common.Big0,
	}
	emitterAddr := crypto.CreateAddress(rtSender, 1)
	alloc[emitterAddr] = types.Account{Code: code}
	alloc[rtSender] = types.Account{Balance: new(big.Int).Lsh(big.NewInt(1), 60)}
	genesis := &core.Genesis{Config: &config, Alloc: alloc}
	engine := beacon.New(ethash.NewFaker())
	bc, err := core.NewBlockChain(rawdb.NewMemoryDatabase(), genesis, engine, &core.BlockChainConfig{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { bc.Stop() })
	if bc.LogIndex() == nil {
		t.Fatal("chain has no log index")
	}
	var nonce uint64
	_, genBlocks, _ := core.GenerateChainWithGenesis(genesis, engine, blocks, func(i int, gen *core.BlockGen) {
		signer := types.LatestSigner(&config)
		gasPrice := new(big.Int).Add(gen.BaseFee(), big.NewInt(1))
		for range txsPerBlock(i + 1) {
			tx, _ := types.SignNewTx(rtKey, signer, &types.LegacyTx{
				Nonce:    nonce,
				To:       &emitterAddr,
				Gas:      100_000,
				GasPrice: gasPrice,
			})
			nonce++
			gen.AddTx(tx)
		}
	})
	if _, err := bc.InsertChain(genBlocks); err != nil {
		t.Fatalf("insert chain: %v", err)
	}
	return &rtChain{bc: bc, matcher: NewMatcher(bc.LogIndex(), &rtBackend{bc: bc})}
}

// rtView adapts the round-trip chain to the query's chain view interface.
type rtView struct{ rtc *rtChain }

func (v *rtView) HeadNumber() uint64 { return v.rtc.bc.CurrentBlock().Number.Uint64() }

func (v *rtView) Header(n uint64) *types.Header {
	h := v.rtc.bc.GetHeaderByNumber(n)
	if h == nil {
		panic("header not found")
	}
	return h
}

func (v *rtView) Body(n uint64) *types.Body {
	h := v.rtc.bc.GetHeaderByNumber(n)
	if h == nil {
		return nil
	}
	return v.rtc.bc.GetBody(h.Hash())
}

func (v *rtView) RawReceipts(n uint64) types.Receipts {
	h := v.rtc.bc.GetHeaderByNumber(n)
	if h == nil {
		return nil
	}
	return v.rtc.bc.GetRawReceipts(h.Hash(), n)
}

// rtBackend adapts the chain to the contract prover backend.
type rtBackend struct{ bc *core.BlockChain }

func (b *rtBackend) ChainConfig() *params.ChainConfig { return b.bc.Config() }

func (b *rtBackend) StateProverAt(header *types.Header, proofNodes, proofCodes map[common.Hash][]byte) (*state.StateDB, error) {
	return b.bc.StateProverAt(header, proofNodes, proofCodes)
}

// TestQueryProofRoundTrip generates an indexed chain, runs a proven query
// across multiple tables, round-trips the proof through JSON and verifies it
// independently, then runs the tamper matrix.
func TestQueryProofRoundTrip(t *testing.T) {
	rtc := newRTChain(t, 40)
	v := &rtView{rtc}
	opts := DefaultVerifyOptions(rtc.bc.Config())

	// match the emitter's address: every LOG0 it emits carries that address
	emitterAddr := crypto.CreateAddress(rtSender, 1)
	matcher, err := NewLegacyMatcher([]common.Address{emitterAddr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// query through head-1: the last block's level-0 table root is not yet
	// readable via the contract's get() at the reference head (the one-block
	// publication lag the golden contract test pins)
	req := FilterQuery{
		Pattern:    matcher,
		FirstBlock: 1,
		LastBlock:  39,
		Limit:      rtMaxUint64,
	}
	logs, _, proof, err := rtc.matcher.GetMatches(context.Background(), v, req, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) == 0 {
		t.Fatal("no logs matched")
	}
	if proof == nil {
		t.Fatal("no proof returned")
	}
	enc, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	var decoded QueryProof
	if err := json.Unmarshal(enc, &decoded); err != nil {
		t.Fatal(err)
	}
	trusted := rtc.bc.CurrentBlock()
	res, err := decoded.Verify(trusted, req, opts)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(res.Logs) != len(logs) {
		t.Fatalf("verified %d logs, want %d", len(res.Logs), len(logs))
	}
	tamper := func(mutate func(p *QueryProof)) error {
		p := decoded
		mutate(&p)
		_, err := p.Verify(trusted, req, opts)
		return err
	}
	if err := tamper(func(p *QueryProof) {
		p.TableQueryProofs[0].ProvenEntries[0][5] ^= 0xff
	}); err == nil {
		t.Error("tampered proven entry: expected verify error")
	}
	if err := tamper(func(p *QueryProof) {
		p.TableQueryProofs[0].ProofHashes[0][3] ^= 0xff
	}); err == nil {
		t.Error("tampered proof hash: expected verify error")
	}
	if err := tamper(func(p *QueryProof) {
		p.TableQueryProofs[0].BlockResults[0].ReceiptsProof[0][2] ^= 0xff
	}); err == nil {
		t.Error("tampered receipts proof: expected verify error")
	}
}
