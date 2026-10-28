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

// Package adversary rewrites the JSON result of a proven log query the way a
// malicious prover would. It exists for tests and for the devnet's adversarial
// proxy: every mode other than "none" yields a result that a correct verifier
// must reject.
package adversary

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Modes lists the supported rewrites.
var Modes = []string{
	"none",           // forward the result unchanged
	"drop-block",     // omit a block's results and its logs from the proof
	"forge-contract", // claim the table roots live in another contract
	"bad-ref",        // alter the reference header
	"truncate-range", // claim a shorter proven range than the proof covers
	"flip-hash",      // corrupt a table proof hash
}

type object = map[string]any

// Decode parses an RPC result keeping numbers exact.
func Decode(blob []byte) (object, error) {
	dec := json.NewDecoder(strings.NewReader(string(blob)))
	dec.UseNumber()
	var out object
	if err := dec.Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// Apply rewrites a decoded pureth_getLogsWithProofV1 result in place.
func Apply(mode string, result object) error {
	if mode == "none" {
		return nil
	}
	proof, ok := result["proof"].(object)
	if !ok {
		return errors.New("result has no proof")
	}
	tables, _ := proof["tableQueryProofs"].([]any)
	switch mode {
	case "drop-block":
		for _, t := range tables {
			table, _ := t.(object)
			blocks, _ := table["blockResults"].([]any)
			if len(blocks) == 0 {
				continue
			}
			header, _ := blocks[0].(object)["header"].(object)
			number, _ := header["number"].(string)
			table["blockResults"] = blocks[1:]
			removed := 0
			if logs, ok := result["logs"].([]any); ok {
				kept := logs[:0:0]
				for _, l := range logs {
					if l.(object)["blockNumber"] == number {
						removed++
						continue
					}
					kept = append(kept, l)
				}
				result["logs"] = kept
			}
			if count, ok := table["resultCount"].(json.Number); ok {
				n, _ := count.Int64()
				table["resultCount"] = json.Number(fmt.Sprint(max(0, n-int64(removed))))
			}
			return nil
		}
		return errors.New("no block results to drop")
	case "forge-contract":
		contracts, _ := proof["indexContracts"].([]any)
		if len(contracts) == 0 {
			return errors.New("no index contracts")
		}
		contracts[0] = "0x000000000000000000000000000000000000dEaD"
	case "bad-ref":
		header, _ := proof["refHeader"].(object)
		if header == nil {
			return errors.New("no reference header")
		}
		header["stateRoot"] = flipHex(header["stateRoot"])
	case "truncate-range":
		query, _ := proof["query"].(object)
		last, ok := query["lastBlock"].(json.Number)
		if !ok {
			return errors.New("no query range")
		}
		n, _ := last.Int64()
		query["lastBlock"] = json.Number(fmt.Sprint(n - 1))
		result["lastBlock"] = fmt.Sprintf("0x%x", n-1)
	case "flip-hash":
		for _, t := range tables {
			table, _ := t.(object)
			if hashes, _ := table["proofHashes"].([]any); len(hashes) > 0 {
				hashes[0] = flipHex(hashes[0])
				return nil
			}
		}
		return errors.New("no proof hashes")
	default:
		return fmt.Errorf("unknown mode %q", mode)
	}
	return nil
}

// flipHex returns the hex string with one byte inverted.
func flipHex(v any) any {
	s, _ := v.(string)
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil || len(b) == 0 {
		return v
	}
	b[len(b)/2] ^= 0xff
	return "0x" + hex.EncodeToString(b)
}
