// verify is a standalone EIP-8304 query proof verifier: it reads a proof JSON
// produced by pureth_getLogsWithProofV1 (or any other prover), verifies it end
// to end against a trusted reference block hash and the query the caller asked
// for, and prints the proven logs. It never talks to a node.
//
// Usage:
//
//	verify -ref-hash <hash> -query <query.json> [-network mainnet|sepolia|devnet] <proof.json> [tamper <index>]
//
// The query file holds the request: {"pattern": {...}, "firstBlock": n,
// "lastBlock": n, "limit": n, "limitLatest": bool}. With the tamper argument
// one byte of the proof material at the given index is flipped, demonstrating
// that verification rejects modified proofs.
package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/logindex/logquery"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
)

// networkConfig resolves the chain config the index contract's get() executes
// under. The devnet config has every fork active from genesis so small devnet
// block numbers do not replay old rules.
func networkConfig(name string) (*params.ChainConfig, error) {
	switch name {
	case "mainnet":
		return params.MainnetChainConfig, nil
	case "sepolia":
		return params.SepoliaChainConfig, nil
	case "devnet":
		return params.MergedTestChainConfig, nil
	}
	return nil, fmt.Errorf("unknown network %q", name)
}

func main() {
	var (
		refHash = flag.String("ref-hash", "", "trusted reference block hash the proof is anchored to")
		queryFn = flag.String("query", "", "file with the requested query")
		network = flag.String("network", "mainnet", "chain config: mainnet, sepolia or devnet")

		historic      = flag.String("historic-contract", "", "address of a trusted historic (out-of-protocol) index contract")
		historicSizes = flag.String("historic-sizes", "1,4,16,64,256", "table sizes the historic contract holds roots for")
		historicLast  = flag.Uint64("historic-last", 0, "last block the historic contract holds roots for")
	)
	flag.Parse()
	args := flag.Args()
	if len(args) < 1 || *refHash == "" || *queryFn == "" {
		fatal("usage: verify -ref-hash <hash> -query <query.json> [-network n] <proof.json> [tamper <index>]")
	}
	config, err := networkConfig(*network)
	if err != nil {
		fatal(err)
	}
	queryBlob, err := os.ReadFile(*queryFn)
	if err != nil {
		fatal(err)
	}
	var req logquery.FilterQuery
	if err := json.Unmarshal(queryBlob, &req); err != nil {
		fatal(err)
	}
	raw, err := os.ReadFile(args[0])
	if err != nil {
		fatal(err)
	}
	var tamperIdx = -1
	if len(args) == 3 && args[1] == "tamper" {
		if _, err := fmt.Sscanf(args[2], "%d", &tamperIdx); err != nil {
			fatal(err)
		}
	}
	proof, err := loadProof(raw, tamperIdx)
	if err != nil {
		fatal(err)
	}
	// the header embedded in the proof is only used once its hash matches the
	// trusted one
	if proof.RefHeader.Hash() != common.HexToHash(*refHash) {
		fmt.Printf("VERIFY: FAIL: proof reference header %s is not the trusted %s\n", proof.RefHeader.Hash().Hex(), *refHash)
		os.Exit(1)
	}
	opts := logquery.DefaultVerifyOptions(config)
	if *historic != "" {
		var sizes []uint64
		for _, field := range strings.Split(*historicSizes, ",") {
			var size uint64
			if _, err := fmt.Sscanf(strings.TrimSpace(field), "%d", &size); err != nil {
				fatal(err)
			}
			sizes = append(sizes, size)
		}
		opts.HistoricContracts = map[common.Address]logquery.HistoricContract{
			common.HexToAddress(*historic): {
				CodeHash:   crypto.Keccak256Hash(logquery.HistoricContractCode),
				TableSizes: sizes,
				LastBlock:  *historicLast,
			},
		}
	}
	res, err := proof.Verify(&proof.RefHeader, req, opts)
	if err != nil {
		fmt.Printf("VERIFY: FAIL: %v\n", err)
		os.Exit(1)
	}
	ref := proof.RefHeader
	fmt.Printf("VERIFY: PASS\n")
	fmt.Printf("reference: block #%d %s\n", ref.Number, ref.Hash().Hex())
	fmt.Printf("proven range: %d..%d, tables: %d\n", res.FirstBlock, res.LastBlock, len(proof.TableQueryProofs))
	fmt.Printf("proven logs: %d\n", len(res.Logs))
	for i, l := range res.Logs {
		if i >= 5 {
			fmt.Printf("  ... and %d more\n", len(res.Logs)-5)
			break
		}
		fmt.Printf("  block #%d tx %s index %d addr %s\n", l.BlockNumber, l.TxHash.Hex()[:18]+"…", l.Index, l.Address.Hex()[:12]+"…")
	}
}

// loadProof reads a proof in any of its forms: a JSON proof document (bare or
// wrapped in an RPC result with a "proof" member), an RPC result carrying the
// binary form in "proofRlp", or a bare hex string of the RLP encoding. A
// non-negative tamperIdx corrupts the proof material before decoding.
func loadProof(raw []byte, tamperIdx int) (*logquery.QueryProof, error) {
	text := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	var binary []byte
	if strings.HasPrefix(text, "0x") {
		b, err := hex.DecodeString(text[2:])
		if err != nil {
			return nil, err
		}
		binary = b
	} else {
		var doc map[string]json.RawMessage
		if err := json.Unmarshal(raw, &doc); err != nil {
			return nil, err
		}
		if blob, ok := doc["proofRlp"]; ok {
			var s string
			if err := json.Unmarshal(blob, &s); err != nil {
				return nil, err
			}
			b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
			if err != nil {
				return nil, err
			}
			binary = b
		}
	}
	var proof logquery.QueryProof
	if binary != nil {
		if tamperIdx >= 0 {
			binary[tamperIdx%len(binary)] ^= 0xff
			fmt.Printf("tampering: byte %d of the binary proof\n", tamperIdx%len(binary))
		}
		if err := rlp.DecodeBytes(binary, &proof); err != nil {
			return nil, err
		}
		return &proof, nil
	}
	if tamperIdx >= 0 {
		var err error
		if raw, err = tamper(raw, tamperIdx); err != nil {
			return nil, err
		}
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err == nil {
		if blob, ok := doc["proof"]; ok {
			raw = blob
		}
	}
	if err := json.Unmarshal(raw, &proof); err != nil {
		return nil, err
	}
	return &proof, nil
}

// tamper flips one byte of the hex string at the given index of the proof
// document, producing a proof that must be rejected. The strings are numbered
// in a fixed order (sorted object keys) so an index names the same string on
// every run. Three kinds are not proof material and are skipped: the query and
// the reference header (the claim's inputs: modifying them yields a different,
// self-consistent claim rather than a broken proof) and the "hash" member of a
// header, which is derived from the header's other fields and ignored on
// decoding.
func tamper(raw []byte, idx int) ([]byte, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	blob, ok := doc["proof"]
	if !ok {
		// a bare proof document
		blob = raw
	}
	decoder := json.NewDecoder(strings.NewReader(string(blob)))
	decoder.UseNumber()
	var root map[string]interface{}
	if err := decoder.Decode(&root); err != nil {
		return nil, err
	}
	type site struct {
		get func() string
		set func(string)
	}
	var sites []site
	var walk func(value interface{}, top bool)
	walk = func(value interface{}, top bool) {
		switch v := value.(type) {
		case []interface{}:
			for i := range v {
				if s, ok := v[i].(string); ok {
					if _, ok := flipByte(s); ok {
						sites = append(sites, site{func() string { return v[i].(string) }, func(n string) { v[i] = n }})
					}
					continue
				}
				walk(v[i], false)
			}
		case map[string]interface{}:
			keys := make([]string, 0, len(v))
			for key := range v {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				if top && (key == "query" || key == "refHeader") || key == "hash" {
					continue
				}
				if s, ok := v[key].(string); ok {
					if _, ok := flipByte(s); ok {
						sites = append(sites, site{func() string { return v[key].(string) }, func(n string) { v[key] = n }})
					}
					continue
				}
				walk(v[key], false)
			}
		}
	}
	walk(root, true)
	if idx >= len(sites) {
		return nil, fmt.Errorf("tamper index %d out of range, %d hex strings found", idx, len(sites))
	}
	target := sites[idx].get()
	replacement, _ := flipByte(target)
	fmt.Printf("tampering: %s -> %s\n", target[:min(len(target), 20)]+"…", replacement[:min(len(replacement), 20)]+"…")
	sites[idx].set(replacement)
	return json.Marshal(root)
}

// flipByte returns the string with the middle byte of its binary content
// inverted: the content of a 0x hex string, or of a base64 string (the encoding
// of the proof's table entries and hashes). It reports false for strings that
// are neither, like short quantities.
func flipByte(s string) (string, bool) {
	if strings.HasPrefix(s, "0x") {
		if len(s) < 10 {
			return "", false
		}
		b, err := hex.DecodeString(s[2:])
		if err != nil || len(b) == 0 {
			return "", false
		}
		b[len(b)/2] ^= 0xff
		return "0x" + hex.EncodeToString(b), true
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) < 4 {
		return "", false
	}
	b[len(b)/2] ^= 0xff
	return base64.StdEncoding.EncodeToString(b), true
}

func fatal(err interface{}) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
