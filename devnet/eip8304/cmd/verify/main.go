// verify is a standalone EIP-8304 query proof verifier: it reads a proof JSON
// produced by pureth_getLogsWithProofV1 (or any other prover), verifies it end
// to end and prints the proven logs. It never talks to a node: the proof and
// the reference header it is anchored to are the only inputs.
//
// Usage:
//
//	go run ./devnet/eip8304/cmd/verify <proof.json> [tamper <index>]
//
// With the tamper argument the JSON blob at the given index of the raw proof
// document is flipped, demonstrating that verification rejects modified
// proofs.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/core/logindex/logquery"
	"github.com/ethereum/go-ethereum/params"
)

// devnetBackend satisfies the verifier's config lookup. The contract's get()
// executes identically on any modern rule set; the test config has every fork
// active from genesis so small devnet block numbers do not replay old rules.
type devnetBackend struct{}

func (devnetBackend) ChainConfig() *params.ChainConfig { return params.MergedTestChainConfig }

func main() {
	if len(os.Args) < 2 {
		fatal("usage: verify <proof.json> [tamper <index>]")
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		fatal(err)
	}
	if len(os.Args) == 4 && os.Args[2] == "tamper" {
		var idx int
		if _, err := fmt.Sscanf(os.Args[3], "%d", &idx); err != nil {
			fatal(err)
		}
		raw, err = tamper(raw, idx)
		if err != nil {
			fatal(err)
		}
	}
	var proof logquery.QueryProof
	if err := json.Unmarshal(raw, &proof); err != nil {
		fatal(err)
	}
	logs, err := proof.Verify(devnetBackend{})
	if err != nil {
		fmt.Printf("VERIFY: FAIL: %v\n", err)
		os.Exit(1)
	}
	ref := proof.RefHeader
	fmt.Printf("VERIFY: PASS\n")
	fmt.Printf("reference: block #%d %s\n", ref.Number, ref.Hash().Hex())
	fmt.Printf("query range: %d..%d, tables: %d\n", proof.Query.FirstBlock, proof.Query.LastBlock, len(proof.TableQueryProofs))
	fmt.Printf("proven logs: %d\n", len(logs))
	for i, l := range logs {
		if i >= 5 {
			fmt.Printf("  ... and %d more\n", len(logs)-5)
			break
		}
		fmt.Printf("  block #%d tx %s index %d addr %s\n", l.BlockNumber, l.TxHash.Hex()[:18]+"…", l.Index, l.Address.Hex()[:12]+"…")
	}
}

// tamper flips one byte of the hex string at the given top-level JSON array
// index, producing a proof that must be rejected.
func tamper(raw []byte, idx int) ([]byte, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	blob, ok := doc["proof"]
	if !ok {
		// a bare proof document
		blob = json.RawMessage(raw)
		doc = map[string]json.RawMessage{"proof": blob}
	}
	// collect every hex string in the proof document
	var hexStrings []string
	forEachJSONString(blob, func(s string) {
		if strings.HasPrefix(s, "0x") && len(s) >= 10 {
			hexStrings = append(hexStrings, s)
		}
	})
	if idx >= len(hexStrings) {
		return nil, fmt.Errorf("tamper index %d out of range, %d hex strings found", idx, len(hexStrings))
	}
	target := hexStrings[idx]
	b, err := hex.DecodeString(target[2:])
	if err != nil {
		return nil, err
	}
	b[len(b)/2] ^= 0xff
	replacement := "0x" + hex.EncodeToString(b)
	fmt.Printf("tampering: %s -> %s\n", target[:min(len(target), 20)]+"…", replacement[:min(len(replacement), 20)]+"…")
	patched := strings.Replace(string(blob), target, replacement, 1)
	doc["proof"] = json.RawMessage(patched)
	return json.Marshal(doc)
}

func forEachJSONString(v json.RawMessage, fn func(string)) {
	var value interface{}
	if err := json.Unmarshal(v, &value); err != nil {
		return
	}
	walk(value, fn)
}

func walk(value interface{}, fn func(string)) {
	switch v := value.(type) {
	case string:
		fn(v)
	case []interface{}:
		for _, item := range v {
			walk(item, fn)
		}
	case map[string]interface{}:
		for _, item := range v {
			walk(item, fn)
		}
	}
}

func fatal(err interface{}) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
