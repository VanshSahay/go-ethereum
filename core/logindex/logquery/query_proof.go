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
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"math/bits"
	"sort"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/logindex"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/triedb"
	"github.com/ethereum/go-ethereum/triedb/database"
)

// Verify checks the query proof end to end and returns the proven logs:
//
//  1. the table proofs are adjacent and cover the query range;
//  2. each table root is reconstructed from the proven entries and the
//     multiproof hashes, and cross-checked against the index contract's
//     stored root executed on the proof-reconstructed state;
//  3. the block entries chain the proven blocks, with the last block of the
//     last table anchored by the reference header;
//  4. the receipts are decoded from the receipts trie proofs and every log
//     re-evaluated against the query pattern;
//  5. the inclusion/exclusion cross-check: for every proven log position,
//     the pattern's verdict must agree with the positions implied by the
//     proven index entries — a claimed match needs an inclusion proof and a
//     claimed non-match needs an exclusion proof.
func (p *QueryProof) Verify(backend contractVerifierBackend) ([]*types.Log, error) {
	if len(p.TableQueryProofs) == 0 {
		return nil, errors.New("no table proofs")
	}
	for i := 1; i < len(p.TableQueryProofs); i++ {
		prev, cur := &p.TableQueryProofs[i-1], &p.TableQueryProofs[i]
		if prev.FirstBlock+prev.TableSize != cur.FirstBlock {
			return nil, errors.New("table proofs are not adjacent")
		}
	}
	first := p.TableQueryProofs[0].FirstBlock
	lastTqp := &p.TableQueryProofs[len(p.TableQueryProofs)-1]
	last := lastTqp.FirstBlock + lastTqp.TableSize - 1
	if p.Query.FirstBlock < first {
		return nil, errors.New("table proofs do not cover the query range")
	}
	queryLast := min(p.Query.LastBlock, p.RefHeader.Number.Uint64())
	if queryLast > last {
		return nil, errors.New("table proofs do not cover the query range")
	}
	var (
		allLogs       []*types.Log
		totalResults  uint64
		provenTxs     = make(map[uint64]common.Hash) // (block<<32|tx) -> tx hash, from proven tx entries
		blockEntryOf  = make(map[uint64]common.Hash) // block number -> proven block hash
		provenResults = make(map[uint64][]*types.Log)
	)
	for ti := range p.TableQueryProofs {
		tqp := &p.TableQueryProofs[ti]
		tableRoot, err := tqp.calculateTableRoot()
		if err != nil {
			return nil, err
		}
		contract := p.IndexContracts[tqp.IndexContract]
		stateDb, err := state.New(p.RefHeader.Root, state.NewMPTDatabase(triedb.NewProofReader(toNodeMap(p.ContractProofNodes), &triedb.Config{}), state.NewProofCodeReader(toNodeMap(p.ContractProofCodes))))
		if err != nil {
			return nil, err
		}
		// tables inside their get() confirmation delay read the root from the
		// raw storage slot; older tables execute get() on the proven state
		var contractRoot common.Hash
		if logindex.PublicationSchedule(tqp.TableSize, tqp.FirstBlock)+1 > p.RefHeader.Number.Uint64() {
			contractRoot = getTableRootRaw(stateDb, contract, tqp.FirstBlock, tqp.TableSize)
		} else {
			contractRoot, err = getProvenTableRootState(stateDb, backend.ChainConfig(), &p.RefHeader, contract, tqp.FirstBlock, tqp.TableSize)
			if err != nil {
				return nil, err
			}
		}
		if tableRoot != contractRoot {
			return nil, errors.New("table root mismatch")
		}
		logs, blockHashes, txHashes, results, err := tqp.verify(&p.Query, first, queryLast)
		if err != nil {
			return nil, err
		}
		allLogs = append(allLogs, logs...)
		totalResults += uint64(len(logs))
		for number, hash := range blockHashes {
			blockEntryOf[number] = hash
		}
		for key, hash := range txHashes {
			provenTxs[key] = hash
		}
		for key, logs := range results {
			provenResults[key] = logs
		}
	}
	// the proven chain must reach the reference head: the last table proves
	// the head's parent block entry, whose content and block number must
	// match the reference header exactly
	if blockEntryOf[p.RefHeader.Number.Uint64()-1] != p.RefHeader.ParentHash {
		return nil, errors.New("proven chain does not reach the reference head")
	}
	// every block result's header must be pinned by a proven block entry; the
	// head itself is pinned by the reference header
	for ti := range p.TableQueryProofs {
		tqp := &p.TableQueryProofs[ti]
		for i := range tqp.BlockResults {
			if tqp.BlockResults[i].Header.Hash() == p.RefHeader.Hash() {
				continue // anchored by the reference header
			}
			number := tqp.BlockResults[i].Header.Number.Uint64()
			if blockEntryOf[number] != tqp.BlockResults[i].Header.Hash() {
				return nil, errors.New("unproven block in table proof")
			}
		}
	}
	return allLogs, nil
}

// countResults sums the per-table result counts.
func countResults(p *QueryProof) int {
	var count int
	for i := range p.TableQueryProofs {
		count += int(p.TableQueryProofs[i].ResultCount)
	}
	return count
}

func toNodeMap(list []hexutil.Bytes) map[common.Hash][]byte {
	m := make(map[common.Hash][]byte, len(list))
	for _, node := range list {
		m[crypto.Keccak256Hash(node)] = node
	}
	return m
}

// verify checks one table's proof and returns the re-evaluated logs, the
// proven block hashes by number, the proven transaction hashes by
// (block<<32|tx) key and the per-block re-evaluated logs.
func (tqp *tableQueryProof) verify(query *FilterQuery, queryFirst, queryLast uint64) ([]*types.Log, map[uint64]common.Hash, map[uint64]common.Hash, map[uint64][]*types.Log, error) {
	if len(tqp.ProvenEntries) != len(tqp.EntryIndices) {
		return nil, nil, nil, nil, errors.New("entry count and entry index count mismatch")
	}
	var (
		provenBlocks = make(map[uint64]common.Hash)
		provenTxs    = make(map[uint64]common.Hash)
	)
	for i, entryIndex := range tqp.EntryIndices {
		if i > 0 && entryIndex <= tqp.EntryIndices[i-1] {
			return nil, nil, nil, nil, errors.New("entry indices are not strictly ascending")
		}
		if entryIndex >= tqp.EntryCount {
			return nil, nil, nil, nil, errors.New("entry index out of range")
		}
		typ, content, blockNum, txIdx, _, err := types.EntryFields(tqp.ProvenEntries[i])
		if err != nil {
			return nil, nil, nil, nil, err
		}
		switch typ {
		case types.EntryTypeBlock:
			provenBlocks[blockNum] = common.Hash(content)
		case types.EntryTypeTransaction:
			provenTxs[uint64(blockNum)<<32|uint64(txIdx)] = common.Hash(content)
		}
	}
	var (
		allLogs  []*types.Log
		matchPos []types.IndexPosition
		results  = make(map[uint64][]*types.Log)
	)
	for i := range tqp.BlockResults {
		br := &tqp.BlockResults[i]
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
			txHash, ok := provenTxs[uint64(number)<<32|uint64(txi)]
			if !ok {
				return nil, nil, nil, nil, errors.New("receipt transaction not proven by an index entry")
			}
			receipt, err := br.getProvenReceipt(txi)
			if err != nil {
				return nil, nil, nil, nil, err
			}
			blockLogs := make([]*types.Log, 0, len(receipt.Logs))
			for _, log := range receipt.Logs {
				clone := *log
				clone.TxHash = txHash
				clone.TxIndex = uint(txi)
				clone.BlockHash = br.Header.Hash()
				clone.BlockNumber = number
				clone.BlockTimestamp = br.Header.Time
				blockLogs = append(blockLogs, &clone)
			}
			results[uint64(number)<<32|uint64(txi)] = blockLogs
		}
	}
	// the potential match set implied by the proven entries, for the whole
	// table range (the query range is already checked above)
	begin := types.IndexPosition{BlockNumber: tqp.FirstBlock}
	end := types.IndexPosition{BlockNumber: tqp.FirstBlock + tqp.TableSize - 1, TxIndex: math.MaxUint32, LogIndex: math.MaxUint32}
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
				return nil, nil, nil, nil, errors.New("inclusion and exclusion proofs do not match")
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
