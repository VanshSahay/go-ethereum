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

package eth

import (
	"context"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus/beacon"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/logindex"
	"github.com/ethereum/go-ethereum/core/logindex/logquery"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
)

var (
	apiEmitterCode = common.FromHex("60015f5fa060025f5fa060035f5fa000") // three LOG0 events per call
	apiKey, _      = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	apiSender      = crypto.PubkeyToAddress(apiKey.PublicKey)
)

// newAPIChain builds an indexed chain with the emitter contract deployed and
// the API backend wired to it.
func newAPIChain(t *testing.T, blocks int, disableIndex bool) (*core.BlockChain, *EthAPIBackend, common.Address) {
	t.Helper()
	config := *params.MergedTestChainConfig
	if !disableIndex {
		// a disabled index cannot produce the index system calls the chain
		// maker would emit for an Amsterdam chain
		config.AmsterdamTime = new(uint64)
		config.EIP8304Time = new(uint64)
	}
	alloc := core.SystemContractAllocs()
	alloc[params.IndexContractAddress] = types.Account{Nonce: 1, Code: params.IndexContractCode}
	emitterAddr := crypto.CreateAddress(apiSender, 1)
	alloc[emitterAddr] = types.Account{Code: apiEmitterCode}
	alloc[apiSender] = types.Account{Balance: new(big.Int).Lsh(big.NewInt(1), 60)}
	genesis := &core.Genesis{Config: &config, Alloc: alloc}
	engine := beacon.New(ethash.NewFaker())
	chainConfig := &core.BlockChainConfig{LogIndexDisabled: disableIndex}
	bc, err := core.NewBlockChain(rawdb.NewMemoryDatabase(), genesis, engine, chainConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { bc.Stop() })
	_, genBlocks, _ := core.GenerateChainWithGenesis(genesis, engine, blocks, func(i int, gen *core.BlockGen) {
		signer := types.LatestSigner(&config)
		tx, _ := types.SignNewTx(apiKey, signer, &types.LegacyTx{
			Nonce:    uint64(i),
			To:       &emitterAddr,
			Gas:      100_000,
			GasPrice: new(big.Int).Add(gen.BaseFee(), big.NewInt(1)),
		})
		gen.AddTx(tx)
	})
	if _, err := bc.InsertChain(genBlocks); err != nil {
		t.Fatalf("insert chain: %v", err)
	}
	backend := &EthAPIBackend{eth: &Ethereum{blockchain: bc}}
	return bc, backend, emitterAddr
}

// TestPurethGetLogsWithProof runs a proven query through the RPC API, verifies
// the JSON-encoded proof independently and cross-checks the result against a
// brute-force scan of the local receipts.
func TestPurethGetLogsWithProof(t *testing.T) {
	bc, backend, emitterAddr := newAPIChain(t, 40, false)
	api := ethapi.NewPurethAPI(backend)

	result, err := api.GetLogsWithProofV1(context.Background(), ethapi.PurethQueryArgs{
		Address: &emitterAddr,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Logs) == 0 {
		t.Fatal("no logs matched")
	}
	for _, l := range result.Logs {
		if l.Address != emitterAddr {
			t.Errorf("log address %v, want %v", l.Address, emitterAddr)
		}
	}
	if result.Proof == nil {
		t.Fatal("no proof returned")
	}

	// the proof must survive JSON encoding and verify independently
	enc, err := json.Marshal(result.Proof)
	if err != nil {
		t.Fatal(err)
	}
	var decoded logquery.QueryProof
	if err := json.Unmarshal(enc, &decoded); err != nil {
		t.Fatal(err)
	}
	pattern, err := logquery.NewLegacyMatcher([]common.Address{emitterAddr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	trusted := bc.CurrentBlock()
	opts := logquery.DefaultVerifyOptions(bc.Config())
	verifiedRes, err := decoded.Verify(trusted, logquery.FilterQuery{
		Pattern:    pattern,
		FirstBlock: 1,
		LastBlock:  trusted.Number.Uint64(),
		Limit:      10_000,
	}, opts)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	verified := verifiedRes.Logs
	if len(verified) != len(result.Logs) {
		t.Fatalf("verified %d logs, want %d", len(verified), len(result.Logs))
	}
	for i, l := range verified {
		if l.BlockHash != result.Logs[i].BlockHash || l.Index != result.Logs[i].Index {
			t.Errorf("verified log %d mismatch", i)
		}
	}

	// cross-check against a brute-force scan of the receipts
	var want int
	for i := uint64(1); i <= 40; i++ {
		header := bc.GetHeaderByNumber(i)
		for _, receipt := range bc.GetRawReceipts(header.Hash(), i) {
			for _, l := range receipt.Logs {
				if l.Address == emitterAddr {
					want++
				}
			}
		}
	}
	if want != len(result.Logs) {
		t.Fatalf("%d logs matched, want %d", len(result.Logs), want)
	}

	// a historical reference head must work too
	refNumber := bc.CurrentBlock().Number.Uint64() - 10
	num := rpc.BlockNumber(refNumber)
	ref := rpc.BlockNumberOrHash{BlockNumber: &num}
	histResult, err := api.GetLogsWithProofV1(context.Background(), ethapi.PurethQueryArgs{
		RefBlock: &ref,
		Address:  &emitterAddr,
	})
	if err != nil {
		t.Fatalf("historical ref: %v", err)
	}
	if uint64(histResult.LastBlock) > refNumber {
		t.Errorf("historical result reaches block %d, want <= %d", histResult.LastBlock, refNumber)
	}
	encHist, err := json.Marshal(histResult.Proof)
	if err != nil {
		t.Fatal(err)
	}
	var histProof logquery.QueryProof
	if err := json.Unmarshal(encHist, &histProof); err != nil {
		t.Fatal(err)
	}
	histRes, err := histProof.Verify(bc.GetHeaderByNumber(refNumber), logquery.FilterQuery{
		Pattern:    pattern,
		FirstBlock: 1,
		LastBlock:  refNumber,
		Limit:      10_000,
	}, opts)
	if err != nil {
		t.Fatalf("historical verify: %v", err)
	}
	if len(histRes.Logs) != len(histResult.Logs) {
		t.Fatalf("historical verified %d logs, want %d", len(histRes.Logs), len(histResult.Logs))
	}
}

// TestPurethQueryRejects pins the reject paths: a match-all filter, a
// malformed pattern and a disabled index.
func TestPurethQueryRejects(t *testing.T) {
	_, backend, _ := newAPIChain(t, 10, false)
	api := ethapi.NewPurethAPI(backend)

	// empty filter: match-all is rejected
	if _, err := api.GetLogsWithProofV1(context.Background(), ethapi.PurethQueryArgs{}); err == nil {
		t.Error("empty filter accepted")
	}
	// malformed pattern
	bad := json.RawMessage(`{"field":"unknown","value":"0x01"}`)
	if _, err := api.GetLogsWithProofV1(context.Background(), ethapi.PurethQueryArgs{Pattern: &bad}); err == nil {
		t.Error("malformed pattern accepted")
	}
	// unknown reference block
	unknown := rpc.BlockNumberOrHash{BlockHash: &common.Hash{}, RequireCanonical: true}
	if _, err := api.GetLogsWithProofV1(context.Background(), ethapi.PurethQueryArgs{
		RefBlock: &unknown,
		Address:  &common.Address{1},
	}); err == nil {
		t.Error("unknown reference block accepted")
	}

	// pending, above-head, inverted, empty and zero-limit requests
	addr := &common.Address{1}
	pending := rpc.BlockNumberOrHash{BlockNumber: ptr(rpc.PendingBlockNumber)}
	above := rpc.BlockNumberOrHash{BlockNumber: ptr(rpc.BlockNumber(1000))}
	hu := func(v uint64) *hexutil.Uint64 { x := hexutil.Uint64(v); return &x }
	for name, args := range map[string]ethapi.PurethQueryArgs{
		"pending ref":    {RefBlock: &pending, Address: addr},
		"above-head ref": {RefBlock: &above, Address: addr},
		"both refs":      {RefBlock: &pending, ReferenceHead: &above, Address: addr},
		"inverted range": {Address: addr, FirstBlock: hu(5), LastBlock: hu(3)},
		"zero first":     {Address: addr, FirstBlock: hu(0)},
		"last above ref": {Address: addr, LastBlock: hu(1000)},
		"zero limit":     {Address: addr, Limit: hu(0)},
		"limit too high": {Address: addr, Limit: hu(10_001)},
		"address twice":  {Address: addr, Addresses: []common.Address{{2}}},
	} {
		if _, err := api.GetLogsWithProofV1(context.Background(), args); err == nil {
			t.Errorf("%s accepted", name)
		}
	}

	// disabled index
	_, disabledBackend, emitterAddr := newAPIChain(t, 10, true)
	disabledAPI := ethapi.NewPurethAPI(disabledBackend)
	if _, err := disabledAPI.GetLogsWithProofV1(context.Background(), ethapi.PurethQueryArgs{Address: &emitterAddr}); err == nil {
		t.Error("query succeeded with the log index disabled")
	}
}

func ptr[T any](v T) *T { return &v }

// TestPurethRLPEncoding pins the binary proof encoding option: the proof is
// returned as proofRlp only, decodes, and verifies like the JSON form.
func TestPurethRLPEncoding(t *testing.T) {
	bc, backend, emitterAddr := newAPIChain(t, 40, false)
	api := ethapi.NewPurethAPI(backend)

	result, err := api.GetLogsWithProofV1(context.Background(), ethapi.PurethQueryArgs{Address: &emitterAddr, Encoding: "rlp"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Proof != nil || len(result.ProofRLP) == 0 {
		t.Fatalf("expected only proofRlp, got proof=%v rlp=%d bytes", result.Proof != nil, len(result.ProofRLP))
	}
	var decoded logquery.QueryProof
	if err := rlp.DecodeBytes(result.ProofRLP, &decoded); err != nil {
		t.Fatal(err)
	}
	pattern, err := logquery.NewLegacyMatcher([]common.Address{emitterAddr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	trusted := bc.CurrentBlock()
	res, err := decoded.Verify(trusted, logquery.FilterQuery{Pattern: pattern, FirstBlock: 1, LastBlock: trusted.Number.Uint64(), Limit: 10_000}, logquery.DefaultVerifyOptions(bc.Config()))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(res.Logs) != len(result.Logs) {
		t.Errorf("verified %d logs, served %d", len(res.Logs), len(result.Logs))
	}
	if _, err := api.GetLogsWithProofV1(context.Background(), ethapi.PurethQueryArgs{Address: &emitterAddr, Encoding: "xml"}); err == nil {
		t.Error("unknown encoding accepted")
	}
}

// TestPurethTableRoots pins the table root export used to seed a historic
// index contract: the roots match the level-0 derivation and the producer's
// own table writes.
func TestPurethTableRoots(t *testing.T) {
	bc, backend, _ := newAPIChain(t, 10, false)
	api := ethapi.NewPurethAPI(backend)

	roots, err := api.GetTableRootsV1(context.Background(), []hexutil.Uint64{1, 4})
	if err != nil {
		t.Fatal(err)
	}
	if len(roots) != 10+1 { // ten level-0 tables and the 4-block table at 4
		t.Fatalf("exported %d roots", len(roots))
	}
	for _, r := range roots {
		if r.TableSize != 1 {
			continue
		}
		n := uint64(r.FirstBlock)
		header := bc.GetHeaderByNumber(n)
		want := logindex.BuildLevel0Root(n, header.ParentHash, bc.GetReceiptsByHash(header.Hash()))
		if r.Root != want {
			t.Errorf("block %d: exported root %x, want %x", n, r.Root, want)
		}
	}
	if _, err := api.GetTableRootsV1(context.Background(), nil); err == nil {
		t.Error("empty size list accepted")
	}
}

// TestPurethCursorPaging pages through the results with a small limit using
// the returned cursor: the pages add up to the unpaged result without
// duplicates, every page proof verifies, and a replayed cursor is bound to the
// request.
func TestPurethCursorPaging(t *testing.T) {
	bc, backend, emitterAddr := newAPIChain(t, 40, false)
	api := ethapi.NewPurethAPI(backend)
	ctx := context.Background()

	full, err := api.GetLogsWithProofV1(ctx, ethapi.PurethQueryArgs{Address: &emitterAddr})
	if err != nil {
		t.Fatal(err)
	}
	if full.NextCursor != nil || len(full.Logs) < 10 {
		t.Fatalf("unexpected unpaged result: %d logs, cursor %v", len(full.Logs), full.NextCursor)
	}
	pattern, err := logquery.NewLegacyMatcher([]common.Address{emitterAddr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	trusted := bc.CurrentBlock()
	opts := logquery.DefaultVerifyOptions(bc.Config())

	const limit = 4
	var (
		got    []*types.Log
		first  = hexutil.Uint64(1)
		lim    = hexutil.Uint64(limit)
		cursor *ethapi.PurethCursor
	)
	for page := 0; page < len(full.Logs); page++ {
		res, err := api.GetLogsWithProofV1(ctx, ethapi.PurethQueryArgs{Address: &emitterAddr, FirstBlock: &first, Limit: &lim, Cursor: cursor})
		if err != nil {
			t.Fatalf("page %d: %v", page, err)
		}
		req := logquery.FilterQuery{Pattern: pattern, FirstBlock: uint64(first), LastBlock: trusted.Number.Uint64(), Limit: limit}
		if cursor != nil {
			req.Cursor = &logquery.Cursor{Block: uint64(cursor.Block), LogIndex: uint64(cursor.LogIndex)}
		}
		if _, err := res.Proof.Verify(trusted, req, opts); err != nil {
			t.Fatalf("page %d: verify: %v", page, err)
		}
		// the same proof does not answer a request with another cursor
		other := req
		other.Cursor = &logquery.Cursor{Block: 1, LogIndex: 0}
		if _, err := res.Proof.Verify(trusted, other, opts); err == nil {
			t.Fatalf("page %d: proof verified against another cursor", page)
		}
		got = append(got, res.Logs...)
		if res.NextCursor == nil {
			break
		}
		cursor, first = res.NextCursor, res.NextCursor.Block
	}
	if len(got) != len(full.Logs) {
		t.Fatalf("pages hold %d logs, the unpaged result %d", len(got), len(full.Logs))
	}
	for i := range got {
		if got[i].BlockNumber != full.Logs[i].BlockNumber || got[i].Index != full.Logs[i].Index {
			t.Fatalf("log %d is block %d index %d, want block %d index %d", i, got[i].BlockNumber, got[i].Index, full.Logs[i].BlockNumber, full.Logs[i].Index)
		}
	}
}
