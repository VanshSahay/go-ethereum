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

	// HistoricContracts lists accepted out-of-protocol index contracts, which
	// are trusted by configuration for the table ranges they hold.
	HistoricContracts map[common.Address]HistoricContract
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
	// the coverage tables must be valid, adjacent and cover the proven range;
	// they are followed by pin tables that only supply block entries. The
	// parameters are validated before any arithmetic is done on them.
	paths := make([]tablePath, len(p.TableQueryProofs))
	coverage := 0
	for i := range p.TableQueryProofs {
		tqp := &p.TableQueryProofs[i]
		if int(tqp.IndexContract) >= len(p.IndexContracts) {
			return nil, errors.New("index contract reference out of range")
		}
		var (
			path tablePath
			err  error
		)
		if spec, ok := opts.HistoricContracts[p.IndexContracts[tqp.IndexContract]]; ok {
			path, err = checkHistoricTable(spec, tqp.TableSize, tqp.FirstBlock, refNumber)
		} else {
			path, err = checkTable(tqp.TableSize, tqp.FirstBlock, refNumber)
		}
		if err != nil {
			return nil, err
		}
		paths[i] = path
		if tqp.Pin {
			if tqp.ResultCount != 0 || len(tqp.BlockResults) != 0 {
				return nil, errors.New("results in a pin table")
			}
			continue
		}
		if coverage != i {
			return nil, errors.New("coverage table after a pin table")
		}
		if i > 0 {
			prev := &p.TableQueryProofs[i-1]
			if prev.FirstBlock+prev.TableSize != tqp.FirstBlock {
				return nil, errors.New("table proofs are not adjacent")
			}
		}
		coverage++
	}
	if coverage == 0 {
		return nil, errors.New("no table proofs")
	}
	firstTqp, lastTqp := &p.TableQueryProofs[0], &p.TableQueryProofs[coverage-1]
	// every coverage table must overlap the proven range and together they
	// must contain all of it
	if p.Query.FirstBlock < firstTqp.FirstBlock || p.Query.FirstBlock > firstTqp.FirstBlock+firstTqp.TableSize-1 {
		return nil, errors.New("the first table proof does not contain the start of the query range")
	}
	if p.Query.LastBlock > lastTqp.FirstBlock+lastTqp.TableSize-1 || p.Query.LastBlock < lastTqp.FirstBlock {
		return nil, errors.New("the last table proof does not contain the end of the query range")
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
		if spec, ok := opts.HistoricContracts[contract]; ok {
			codeHash, accepted = spec.CodeHash, true
		}
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
		var tr *tableResult
		if tqp.Pin {
			tr, err = tqp.verifyPin()
		} else {
			tr, err = tqp.verify(&p.Query, p.Query.FirstBlock, p.Query.LastBlock)
		}
		if err != nil {
			return nil, err
		}
		allLogs = append(allLogs, tr.logs...)
		for number, hash := range tr.blocks {
			if prev, ok := blockEntryOf[number]; ok && prev != hash {
				return nil, errors.New("conflicting block entries")
			}
			blockEntryOf[number] = hash
		}
	}
	// every block result's header must be pinned by a proven block entry: the
	// roots of all tables are read from the trusted state, so their block
	// entries are canonical. The reference block itself is pinned by the
	// trusted header.
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
	allLogs, err := p.applyLimit(allLogs, req, refNumber)
	if err != nil {
		return nil, err
	}
	return &Result{Logs: allLogs, FirstBlock: p.Query.FirstBlock, LastBlock: p.Query.LastBlock}, nil
}

// applyLimit enforces the result limit semantics on the verified logs, which
// are in ascending position order:
//
//   - fewer logs than the limit: the result is complete only if the proof
//     covers the whole requested range, so a prover cannot answer a narrower
//     range without having reached the limit;
//   - the limit is reached: exactly the oldest (or, with LimitLatest, the
//     newest) limit logs are returned and the proven range ends at the block
//     of the last returned log. The proof covers that whole block, so the
//     logs beyond the limit that share it are dropped here.
func (p *QueryProof) applyLimit(logs []*types.Log, req FilterQuery, refNumber uint64) ([]*types.Log, error) {
	reqLast := min(req.LastBlock, refNumber)
	if uint64(len(logs)) < req.Limit {
		if p.Query.FirstBlock != req.FirstBlock || p.Query.LastBlock != reqLast {
			return nil, errors.New("proof covers less than the requested range without reaching the result limit")
		}
		return logs, nil
	}
	if req.LimitLatest {
		logs = logs[uint64(len(logs))-req.Limit:]
		if p.Query.FirstBlock != logs[0].BlockNumber || p.Query.LastBlock != reqLast {
			return nil, errors.New("proven range does not end at the block of the last returned log")
		}
		return logs, nil
	}
	logs = logs[:req.Limit]
	if p.Query.FirstBlock != req.FirstBlock || p.Query.LastBlock != logs[len(logs)-1].BlockNumber {
		return nil, errors.New("proven range does not end at the block of the last returned log")
	}
	return logs, nil
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
	if (p.Query.Cursor == nil) != (req.Cursor == nil) || p.Query.Cursor != nil && *p.Query.Cursor != *req.Cursor {
		return errors.New("proof answers a different cursor")
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

// txKey identifies a transaction of the proven blocks.
type txKey struct {
	block uint64
	tx    uint32
}

// txMeta is the proven metadata of a transaction entry: its hash and the
// cumulative log count of the block before it.
type txMeta struct {
	hash      common.Hash
	logOffset uint32
}

// tableResult is the verified outcome of one table proof.
type tableResult struct {
	logs   []*types.Log           // matching logs in position order
	blocks map[uint64]common.Hash // proven block entries by block number
}

// checkEntries validates the proven entries of a table proof against the table
// parameters and returns the block entries and transaction entries among them.
func (tqp *tableQueryProof) checkEntries() (map[uint64]common.Hash, map[txKey]txMeta, error) {
	if len(tqp.ProvenEntries) != len(tqp.EntryIndices) {
		return nil, nil, errors.New("entry count and entry index count mismatch")
	}
	var (
		provenBlocks = make(map[uint64]common.Hash)
		provenTxs    = make(map[txKey]txMeta)
		last         = tqp.FirstBlock + tqp.TableSize - 1
	)
	for i, entryIndex := range tqp.EntryIndices {
		if i > 0 && entryIndex <= tqp.EntryIndices[i-1] {
			return nil, nil, errors.New("entry indices are not strictly ascending")
		}
		if entryIndex >= tqp.EntryCount {
			return nil, nil, errors.New("entry index out of range")
		}
		if i > 0 && types.CompareEntries(tqp.ProvenEntries[i-1], tqp.ProvenEntries[i]) >= 0 {
			return nil, nil, errors.New("proven entries are not strictly ascending")
		}
		typ, content, blockNum, txIdx, logIdx, err := types.EntryFields(tqp.ProvenEntries[i])
		if err != nil {
			return nil, nil, err
		}
		// a table holds the block entries of the blocks before its own blocks
		// (the entry of block n lives in the table that contains block n+1) and
		// the transaction and log entries of its own blocks
		if blockNum == math.MaxUint64 {
			return nil, nil, errors.New("entry block number out of range")
		}
		switch typ {
		case types.EntryTypeBlock:
			if blockNum+1 < tqp.FirstBlock || blockNum+1 > last {
				return nil, nil, errors.New("block entry outside the table range")
			}
			if _, dup := provenBlocks[blockNum]; dup {
				return nil, nil, errors.New("duplicate block entry")
			}
			provenBlocks[blockNum] = common.Hash(content)
		case types.EntryTypeTransaction:
			if blockNum < tqp.FirstBlock || blockNum > last {
				return nil, nil, errors.New("transaction entry outside the table range")
			}
			key := txKey{blockNum, txIdx}
			if _, dup := provenTxs[key]; dup {
				return nil, nil, errors.New("duplicate transaction entry")
			}
			// the transaction entry's log index field carries the cumulative
			// log count of the block before the transaction
			provenTxs[key] = txMeta{hash: common.Hash(content), logOffset: logIdx}
		default:
			if blockNum < tqp.FirstBlock || blockNum > last {
				return nil, nil, errors.New("log entry outside the table range")
			}
		}
	}
	return provenBlocks, provenTxs, nil
}

// verifyPin checks a pin table, which supplies block entries only.
func (tqp *tableQueryProof) verifyPin() (*tableResult, error) {
	blocks, _, err := tqp.checkEntries()
	if err != nil {
		return nil, err
	}
	return &tableResult{blocks: blocks}, nil
}

// verify checks one table's proof against the query over the proven range and
// returns its matching logs and block entries. The entry checks are local to
// the table; the cross-table checks are done by the caller.
func (tqp *tableQueryProof) verify(query *FilterQuery, rangeFirst, rangeLast uint64) (*tableResult, error) {
	provenBlocks, provenTxs, err := tqp.checkEntries()
	if err != nil {
		return nil, err
	}
	last := tqp.FirstBlock + tqp.TableSize - 1
	res := &tableResult{blocks: provenBlocks}

	// the part of the table inside the proven range; a table outside of it
	// only anchors block headers and proves no results
	scanFirst, scanLast := max(tqp.FirstBlock, rangeFirst), min(last, rangeLast)
	if scanFirst > scanLast {
		return nil, errors.New("coverage table outside the proven range")
	}

	// decode the proven receipts: each needs a proven transaction entry, which
	// supplies the transaction hash and the block-global log index offset
	receiptLogs := make(map[txKey][]*types.Log)
	for i := range tqp.BlockResults {
		br := &tqp.BlockResults[i]
		if br.Header.Number == nil {
			return nil, errors.New("block result without a number")
		}
		number := br.Header.Number.Uint64()
		if number < scanFirst || number > scanLast {
			return nil, errors.New("block result outside the proven range")
		}
		if i > 0 && number <= tqp.BlockResults[i-1].Header.Number.Uint64() {
			return nil, errors.New("block results are not ascending")
		}
		for j, txi := range br.ProvenReceipts {
			if j > 0 && txi <= br.ProvenReceipts[j-1] {
				return nil, errors.New("proven receipts are not ascending")
			}
			meta, ok := provenTxs[txKey{number, txi}]
			if !ok {
				return nil, errors.New("receipt transaction not proven by an index entry")
			}
			receipt, err := br.getProvenReceipt(txi)
			if err != nil {
				return nil, err
			}
			logs := make([]*types.Log, len(receipt.Logs))
			for k, log := range receipt.Logs {
				clone := *log
				clone.TxHash = meta.hash
				clone.TxIndex = uint(txi)
				clone.BlockHash = br.Header.Hash()
				clone.BlockNumber = number
				clone.BlockTimestamp = br.Header.Time
				clone.Index = uint(meta.logOffset) + uint(k)
				logs[k] = &clone
			}
			receiptLogs[txKey{number, txi}] = logs
		}
	}

	// the candidate positions the proven entries leave open: every one of them
	// needs its receipt, and the results are the candidates whose log matches
	begin := types.IndexPosition{BlockNumber: scanFirst}
	end := types.IndexPosition{BlockNumber: scanLast, TxIndex: math.MaxUint32, LogIndex: math.MaxUint32}
	candidates, bounded := query.Pattern.candidates(tqp, begin, end)
	if !bounded {
		return nil, errors.New("the proven entries do not bound the pattern's matches")
	}
	for _, pos := range candidates {
		logs, ok := receiptLogs[txKey{pos.BlockNumber, pos.TxIndex}]
		if !ok {
			return nil, fmt.Errorf("missing receipt proof for candidate at block #%d tx %d log %d", pos.BlockNumber, pos.TxIndex, pos.LogIndex)
		}
		// a candidate derived through an offset matcher can lie beyond the
		// receipt's last log; a log that does not exist is never a result
		if int(pos.LogIndex) < len(logs) && query.Pattern.matchLogs(logs, int(pos.LogIndex)) {
			log := logs[pos.LogIndex]
			if !query.Cursor.excludes(log.BlockNumber, uint64(log.Index), query.LimitLatest) {
				res.logs = append(res.logs, log)
			}
		}
	}
	if uint64(len(res.logs)) != tqp.ResultCount {
		return nil, errors.New("result count does not match the proven results")
	}
	return res, nil
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
