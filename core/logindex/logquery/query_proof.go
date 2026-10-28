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
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"sort"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/triedb"
	"github.com/ethereum/go-ethereum/triedb/database"
)

// VerifyOptions configures the trust anchors of the verifier.
type VerifyOptions struct {
	// ChainConfig supplies the rules the index contract's get() executes under.
	ChainConfig *params.ChainConfig

	// IndexContracts lists the accepted index contracts. The value is the code
	// hash the contract must have in the reference state; the zero hash accepts
	// any code.
	IndexContracts map[common.Address]common.Hash
}

// DefaultVerifyOptions accepts exactly the protocol's index contract with its
// reference bytecode.
func DefaultVerifyOptions(config *params.ChainConfig) VerifyOptions {
	return VerifyOptions{
		ChainConfig: config,
		IndexContracts: map[common.Address]common.Hash{
			params.IndexContractAddress: crypto.Keccak256Hash(params.IndexContractCode),
		},
	}
}

// Result is the verified outcome of a query proof: the proven logs and the
// block range the proof covers. The range can be narrower than the requested
// one only when the result limit was reached.
type Result struct {
	Logs       []*types.Log
	FirstBlock uint64
	LastBlock  uint64
}

// Verify checks the query proof against a trusted reference header and the
// query the caller asked for, and returns the proven logs:
//
//  1. the proof is anchored to the trusted header and answers the requested
//     query (pattern, limit, direction) over a sub-range of the requested range;
//  2. the table proofs are adjacent, use protocol table sizes at aligned first
//     blocks and cover the proven range;
//  3. each table root is reconstructed from the proven entries and the
//     multiproof hashes, and cross-checked against the root stored in an
//     accepted index contract, read from the trusted state;
//  4. the block entries pin the proven block headers;
//  5. the receipts are decoded from the receipts trie proofs and every log
//     re-evaluated against the query pattern;
//  6. the inclusion/exclusion cross-check: for every proven log position,
//     the pattern's verdict must agree with the positions implied by the
//     proven index entries — a claimed match needs an inclusion proof and a
//     claimed non-match needs an exclusion proof.
func (p *QueryProof) Verify(trusted *types.Header, req FilterQuery, opts VerifyOptions) (*Result, error) {
	if trusted == nil || trusted.Number == nil {
		return nil, errors.New("missing trusted reference header")
	}
	if p.RefHeader.Number == nil || p.RefHeader.Hash() != trusted.Hash() {
		return nil, errors.New("proof reference header does not match the trusted header")
	}
	refNumber := trusted.Number.Uint64()
	if refNumber == 0 {
		return nil, errors.New("the genesis block cannot be a reference header")
	}
	if err := p.checkQuery(req, refNumber); err != nil {
		return nil, err
	}
	if len(p.TableQueryProofs) == 0 {
		return nil, errors.New("no table proofs")
	}
	if len(p.IndexContracts) > len(p.TableQueryProofs) {
		return nil, errors.New("unused index contracts in proof")
	}
	// the tables must be valid, adjacent and cover the proven range; the
	// parameters are validated before any arithmetic is done on them
	paths := make([]tablePath, len(p.TableQueryProofs))
	for i := range p.TableQueryProofs {
		tqp := &p.TableQueryProofs[i]
		path, err := checkTable(tqp.TableSize, tqp.FirstBlock, refNumber)
		if err != nil {
			return nil, err
		}
		paths[i] = path
		if i > 0 {
			prev := &p.TableQueryProofs[i-1]
			if prev.FirstBlock+prev.TableSize != tqp.FirstBlock {
				return nil, errors.New("table proofs are not adjacent")
			}
		}
	}
	first := p.TableQueryProofs[0].FirstBlock
	lastTqp := &p.TableQueryProofs[len(p.TableQueryProofs)-1]
	last := lastTqp.FirstBlock + lastTqp.TableSize - 1
	if p.Query.FirstBlock < first || p.Query.LastBlock > last {
		return nil, errors.New("table proofs do not cover the query range")
	}
	var (
		allLogs      []*types.Log
		blockEntryOf = make(map[uint64]common.Hash) // block number -> proven block hash
		nodes        = toNodeMap(p.ContractProofNodes)
		codes        = toNodeMap(p.ContractProofCodes)
	)
	for ti := range p.TableQueryProofs {
		tqp := &p.TableQueryProofs[ti]
		path := paths[ti]
		tableRoot, err := tqp.calculateTableRoot()
		if err != nil {
			return nil, err
		}
		if int(tqp.IndexContract) >= len(p.IndexContracts) {
			return nil, errors.New("index contract reference out of range")
		}
		contract := p.IndexContracts[tqp.IndexContract]
		codeHash, accepted := opts.IndexContracts[contract]
		if !accepted {
			return nil, errors.New("index contract is not accepted")
		}
		stateDb, err := state.New(p.RefHeader.Root, state.NewMPTDatabase(triedb.NewProofReader(nodes, &triedb.Config{}), state.NewProofCodeReader(codes)))
		if err != nil {
			return nil, err
		}
		if codeHash != (common.Hash{}) && stateDb.GetCodeHash(contract) != codeHash {
			return nil, errors.New("index contract code does not match")
		}
		var contractRoot common.Hash
		if path == pathRaw {
			contractRoot, err = getTableRootRaw(stateDb, contract, tqp.FirstBlock, tqp.TableSize)
		} else {
			contractRoot, err = getTableRoot(stateDb, opts.ChainConfig, &p.RefHeader, contract, tqp.FirstBlock, tqp.TableSize)
		}
		if err != nil {
			return nil, err
		}
		if err := stateDb.Error(); err != nil {
			return nil, err
		}
		// an unset slot reads as the zero hash: a table the contract has no
		// root for cannot be proven, not even as an empty one
		if contractRoot == (common.Hash{}) {
			return nil, errors.New("index contract has no root for the table")
		}
		if tableRoot != contractRoot {
			return nil, errors.New("table root mismatch")
		}
		logs, blockHashes, _, _, err := tqp.verify(&p.Query, p.Query.FirstBlock, p.Query.LastBlock)
		if err != nil {
			return nil, err
		}
		allLogs = append(allLogs, logs...)
		for number, hash := range blockHashes {
			if prev, ok := blockEntryOf[number]; ok && prev != hash {
				return nil, errors.New("conflicting block entries")
			}
			blockEntryOf[number] = hash
		}
	}
	// the proven chain must reach the reference head: the last table proves
	// the head's parent block entry, whose content and block number must
	// match the reference header exactly
	if blockEntryOf[refNumber-1] != p.RefHeader.ParentHash {
		return nil, errors.New("proven chain does not reach the reference head")
	}
	// every block result's header must be pinned by a proven block entry; the
	// head itself is pinned by the reference header
	for ti := range p.TableQueryProofs {
		tqp := &p.TableQueryProofs[ti]
		for i := range tqp.BlockResults {
			if tqp.BlockResults[i].Header.Number == nil {
				return nil, errors.New("block result without a number")
			}
			if tqp.BlockResults[i].Header.Hash() == p.RefHeader.Hash() {
				continue // anchored by the reference header
			}
			number := tqp.BlockResults[i].Header.Number.Uint64()
			if blockEntryOf[number] != tqp.BlockResults[i].Header.Hash() {
				return nil, errors.New("unproven block in table proof")
			}
		}
	}
	return &Result{Logs: allLogs, FirstBlock: p.Query.FirstBlock, LastBlock: p.Query.LastBlock}, nil
}

// checkQuery binds the proof to the query the caller asked for: the pattern,
// limit and direction must be the requested ones and the proven range must lie
// inside the requested range.
func (p *QueryProof) checkQuery(req FilterQuery, refNumber uint64) error {
	if req.Pattern == nil || p.Query.Pattern == nil {
		return errors.New("missing query pattern")
	}
	want, err := json.Marshal(normalizePattern(req.Pattern))
	if err != nil {
		return err
	}
	got, err := json.Marshal(normalizePattern(p.Query.Pattern))
	if err != nil {
		return err
	}
	if !bytes.Equal(want, got) {
		return errors.New("proof answers a different pattern")
	}
	if p.Query.Limit != req.Limit || p.Query.LimitLatest != req.LimitLatest {
		return errors.New("proof answers a different limit")
	}
	if req.Limit == 0 {
		return errors.New("zero result limit")
	}
	reqLast := min(req.LastBlock, refNumber)
	if req.FirstBlock > reqLast {
		return errors.New("empty query range")
	}
	if p.Query.FirstBlock > p.Query.LastBlock || p.Query.FirstBlock < req.FirstBlock || p.Query.LastBlock > reqLast {
		return errors.New("proven range is outside the requested range")
	}
	return nil
}

func toNodeMap(list []hexutil.Bytes) map[common.Hash][]byte {
	m := make(map[common.Hash][]byte, len(list))
	for _, node := range list {
		m[crypto.Keccak256Hash(node)] = node
	}
	return m
}

// txMeta is the proven metadata of a transaction entry: its hash and the
// cumulative log count of the block before it.
type txMeta struct {
	hash      common.Hash
	logOffset uint32
}

// verify checks one table's proof and returns the re-evaluated logs, the
// proven block hashes by number, the proven transaction hashes by
// (block<<32|tx) key and the per-block re-evaluated logs.
func (tqp *tableQueryProof) verify(query *FilterQuery, queryFirst, queryLast uint64) ([]*types.Log, map[uint64]common.Hash, map[uint64]txMeta, map[uint64][]*types.Log, error) {
	if len(tqp.ProvenEntries) != len(tqp.EntryIndices) {
		return nil, nil, nil, nil, errors.New("entry count and entry index count mismatch")
	}
	var (
		provenBlocks = make(map[uint64]common.Hash)
		provenTxs    = make(map[uint64]txMeta)
	)
	last := tqp.FirstBlock + tqp.TableSize - 1
	for i, entryIndex := range tqp.EntryIndices {
		if i > 0 && entryIndex <= tqp.EntryIndices[i-1] {
			return nil, nil, nil, nil, errors.New("entry indices are not strictly ascending")
		}
		if entryIndex >= tqp.EntryCount {
			return nil, nil, nil, nil, errors.New("entry index out of range")
		}
		if i > 0 && types.CompareEntries(tqp.ProvenEntries[i-1], tqp.ProvenEntries[i]) >= 0 {
			return nil, nil, nil, nil, errors.New("proven entries are not strictly ascending")
		}
		typ, content, blockNum, txIdx, logIdx, err := types.EntryFields(tqp.ProvenEntries[i])
		if err != nil {
			return nil, nil, nil, nil, err
		}
		// a table holds the block entries of the blocks before its own blocks
		// (the entry of block n lives in the table that contains block n+1) and
		// the transaction and log entries of its own blocks
		if blockNum == math.MaxUint64 {
			return nil, nil, nil, nil, errors.New("entry block number out of range")
		}
		switch typ {
		case types.EntryTypeBlock:
			if blockNum+1 < tqp.FirstBlock || blockNum+1 > last {
				return nil, nil, nil, nil, errors.New("block entry outside the table range")
			}
			if _, dup := provenBlocks[blockNum]; dup {
				return nil, nil, nil, nil, errors.New("duplicate block entry")
			}
			provenBlocks[blockNum] = common.Hash(content)
		case types.EntryTypeTransaction:
			if blockNum < tqp.FirstBlock || blockNum > last {
				return nil, nil, nil, nil, errors.New("transaction entry outside the table range")
			}
			key := uint64(blockNum)<<32 | uint64(txIdx)
			if _, dup := provenTxs[key]; dup {
				return nil, nil, nil, nil, errors.New("duplicate transaction entry")
			}
			// the transaction entry's log index field carries the cumulative
			// log count of the block before the transaction
			provenTxs[key] = txMeta{hash: common.Hash(content), logOffset: logIdx}
		default:
			if blockNum < tqp.FirstBlock || blockNum > last {
				return nil, nil, nil, nil, errors.New("log entry outside the table range")
			}
		}
	}
	var (
		allLogs  []*types.Log
		matchPos []types.IndexPosition
		results  = make(map[uint64][]*types.Log)
	)
	for i := range tqp.BlockResults {
		br := &tqp.BlockResults[i]
		if br.Header.Number == nil {
			return nil, nil, nil, nil, errors.New("block result without a number")
		}
		number := br.Header.Number.Uint64()
		if number < tqp.FirstBlock || number >= tqp.FirstBlock+tqp.TableSize {
			return nil, nil, nil, nil, errors.New("block result outside the table range")
		}
		if number < queryFirst || number > queryLast {
			return nil, nil, nil, nil, errors.New("block result outside the query range")
		}
		if i > 0 && number <= tqp.BlockResults[i-1].Header.Number.Uint64() {
			return nil, nil, nil, nil, errors.New("block results are not ascending")
		}
		for _, txi := range br.ProvenReceipts {
			meta, ok := provenTxs[uint64(number)<<32|uint64(txi)]
			if !ok {
				return nil, nil, nil, nil, errors.New("receipt transaction not proven by an index entry")
			}
			receipt, err := br.getProvenReceipt(txi)
			if err != nil {
				return nil, nil, nil, nil, err
			}
			blockLogs := make([]*types.Log, 0, len(receipt.Logs))
			for i, log := range receipt.Logs {
				clone := *log
				clone.TxHash = meta.hash
				clone.TxIndex = uint(txi)
				clone.BlockHash = br.Header.Hash()
				clone.BlockNumber = number
				clone.BlockTimestamp = br.Header.Time
				clone.Index = uint(meta.logOffset) + uint(i)
				blockLogs = append(blockLogs, &clone)
			}
			results[uint64(number)<<32|uint64(txi)] = blockLogs
		}
	}
	// the potential match set implied by the proven entries, for the scanned
	// part of the table (the intersection of the table with the query range)
	begin := types.IndexPosition{BlockNumber: max(tqp.FirstBlock, queryFirst)}
	end := types.IndexPosition{BlockNumber: min(tqp.FirstBlock+tqp.TableSize-1, queryLast), TxIndex: math.MaxUint32, LogIndex: math.MaxUint32}
	potential := query.Pattern.proofMatches(tqp, begin, end)
	// the inclusion/exclusion cross-check: for every proven log position,
	// the pattern's verdict must agree with the potential set membership
	// walk the proven results in ascending position order so the inclusion
	// and exclusion sides are compared in the same order
	keys := make([]uint64, 0, len(results))
	for key := range results {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	for _, key := range keys {
		blockNumber := uint64(key >> 32)
		blockLogs := results[key]
		for i, log := range blockLogs {
			pos := types.IndexPosition{BlockNumber: blockNumber, TxIndex: uint32(log.TxIndex), LogIndex: uint32(i)}
			matched := query.Pattern.matchLogs(blockLogs, i)
			contained := potential.contains(pos)
			if matched != contained {
				return nil, nil, nil, nil, fmt.Errorf("inclusion and exclusion proofs do not match at block #%d tx %d log %d (pattern=%v entries=%v)", blockNumber, pos.TxIndex, pos.LogIndex, matched, contained)
			}
			if matched {
				allLogs = append(allLogs, log)
				matchPos = append(matchPos, pos)
			}
		}
	}
	return allLogs, provenBlocks, provenTxs, results, nil
}

// lastProvenBlock returns the header hash of the table's last proven block
// when it sits at the table's last position: the next table's parent block
// entry chains to it.
func (tqp *tableQueryProof) lastProvenBlock() common.Hash {
	if len(tqp.BlockResults) == 0 {
		return common.Hash{}
	}
	last := tqp.BlockResults[len(tqp.BlockResults)-1]
	if last.Header.Number.Uint64() == tqp.FirstBlock+tqp.TableSize-1 {
		return last.Header.Hash()
	}
	return common.Hash{}
}

// calculateTableRoot reconstructs the table root from the proven entries and
// the multiproof hashes: leaves sit at 2^treeHeight + entryIndex, interior
// nodes are sha256(left || right) with zero-subtree padding, and the
// little-endian entry count is mixed into the root.
func (tqp *tableQueryProof) calculateTableRoot() (common.Hash, error) {
	if len(tqp.ProvenEntries) != len(tqp.EntryIndices) {
		return common.Hash{}, errors.New("entry count and entry index count mismatch")
	}
	treeHeight := 64 - bits.LeadingZeros64(max(tqp.EntryCount, 1)-1)
	leafOffset := uint64(1) << treeHeight
	hashes := make(map[uint64]common.Hash)
	lastIndex := uint64(math.MaxUint64)

	var proofHashPtr int
	loadProofHashes := func(a, b uint64) error {
		return iterateProofIndices(treeHeight, a, b, func(gti uint64) error {
			if proofHashPtr >= len(tqp.ProofHashes) {
				return errors.New("not enough proof hashes")
			}
			hashes[gti] = tqp.ProofHashes[proofHashPtr]
			proofHashPtr++
			return nil
		})
	}
	for i, entryIndex := range tqp.EntryIndices {
		if (i > 0 && entryIndex <= lastIndex) || entryIndex >= tqp.EntryCount {
			return common.Hash{}, errors.New("invalid entry index")
		}
		hashes[leafOffset+entryIndex] = types.EntryLeafHash(tqp.ProvenEntries[i])
		if err := loadProofHashes(lastIndex, entryIndex); err != nil {
			return common.Hash{}, err
		}
		lastIndex = entryIndex
	}
	if err := loadProofHashes(lastIndex, uint64(math.MaxUint64)); err != nil {
		return common.Hash{}, err
	}
	if proofHashPtr != len(tqp.ProofHashes) {
		return common.Hash{}, errors.New("too many proof hashes")
	}
	var getHash func(gti uint64) (common.Hash, error)
	getHash = func(gti uint64) (common.Hash, error) {
		if hash, ok := hashes[gti]; ok {
			return hash, nil
		}
		if gti == 0 || gti >= uint64(1)<<63 {
			return common.Hash{}, errors.New("cannot reconstruct table root")
		}
		left, err := getHash(gti * 2)
		if err != nil {
			return common.Hash{}, err
		}
		right, err := getHash(gti*2 + 1)
		if err != nil {
			return common.Hash{}, err
		}
		hasher := sha256.New()
		hasher.Write(left[:])
		hasher.Write(right[:])
		var result common.Hash
		hasher.Sum(result[:0])
		return result, nil
	}
	var entryCountNode [32]byte
	binary.LittleEndian.PutUint64(entryCountNode[:8], tqp.EntryCount)
	treeRoot, err := getHash(1)
	if err != nil {
		return common.Hash{}, err
	}
	hasher := sha256.New()
	hasher.Write(treeRoot[:])
	hasher.Write(entryCountNode[:])
	var tableRoot common.Hash
	hasher.Sum(tableRoot[:0])
	return tableRoot, nil
}

// getProvenReceipt decodes a proven transaction's receipt from the receipts
// trie proof.
func (br *blockResults) getProvenReceipt(txIndex uint32) (*types.Receipt, error) {
	tr, err := trie.New(trie.TrieID(br.Header.ReceiptHash), proofNodeDB(br.receiptsProofMap()))
	if err != nil {
		return nil, err
	}
	key := rlp.AppendUint64(nil, uint64(txIndex))
	blob, err := tr.Get(key)
	if err != nil {
		return nil, err
	}
	receipt := new(types.Receipt)
	if err := receipt.UnmarshalBinary(blob); err != nil {
		return nil, err
	}
	return receipt, nil
}

func (br *blockResults) receiptsProofMap() map[common.Hash][]byte {
	m := make(map[common.Hash][]byte, len(br.ReceiptsProof))
	for _, node := range br.ReceiptsProof {
		m[crypto.Keccak256Hash(node)] = node
	}
	return m
}

// proofNodeDB adapts the node list to the trie node database interface.
type proofNodeDB map[common.Hash][]byte

func (t proofNodeDB) Node(owner common.Hash, path []byte, hash common.Hash) ([]byte, error) {
	if blob, ok := t[hash]; ok {
		return blob, nil
	}
	return nil, errors.New("node not found in receipts proof")
}

func (t proofNodeDB) NodeReader(root common.Hash) (database.NodeReader, error) {
	return t, nil
}
