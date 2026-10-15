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
	"errors"
	"math"
	"math/bits"
	"slices"
	"sort"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/logindex"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

// tableProver accumulates the proof material of one index table: the block
// proofs of every block with matching results and the entry indexes that are
// proven (all touched entries; the cost optimizer of the reference design is
// deliberately omitted, proven supersets are always sound).
type tableProver struct {
	reader      *logindex.TableReader
	treeHeight  int
	blockProofs map[uint64]*blockProof
	resultCount int
}

func newTableProver(reader *logindex.TableReader) *tableProver {
	return &tableProver{
		reader:     reader,
		treeHeight: 64 - bits.LeadingZeros64(max(reader.EntryCount, 1)-1),
	}
}

func (tp *tableProver) addBlockProofs(newProofs map[uint64]*blockProof, newResults int) {
	tp.resultCount += newResults
	if tp.blockProofs == nil {
		tp.blockProofs = newProofs
		return
	}
	for number, newProof := range newProofs {
		if proof, ok := tp.blockProofs[number]; ok {
			proof.merge(newProof)
		} else {
			tp.blockProofs[number] = newProof
		}
	}
}

// finalize assembles the table query proof: the entry indexes of the parent
// block entry, the block entries of every proven block except the last one
// (anchored by the reference header instead) and the transaction entries of
// every proven transaction, each with its multiproof section.
func (tp *tableProver) finalize(proveParentBlock common.Hash) (tableQueryProof, common.Hash, error) {
	var proveLastBlock common.Hash
	blockNumbers := make([]uint64, 0, len(tp.blockProofs))
	for number := range tp.blockProofs {
		blockNumbers = append(blockNumbers, number)
	}
	sort.Slice(blockNumbers, func(i, j int) bool {
		return blockNumbers[i] < blockNumbers[j]
	})
	proof := tableQueryProof{
		FirstBlock:   tp.reader.BlockRange().First(),
		TableSize:    tp.reader.BlockRange().Count(),
		EntryCount:   tp.reader.EntryCount,
		ResultCount:  uint64(tp.resultCount),
		BlockResults: make([]blockResults, len(blockNumbers)),
	}
	var err error
	if proveParentBlock != (common.Hash{}) {
		parentEntry := types.EncodeEntry(types.EntryTypeBlock, proveParentBlock[:], tp.reader.BlockRange().First()-1, 0, 0)
		entryIndex, found, seekErr := tp.reader.SeekEntry(parentEntry)
		if seekErr != nil {
			return tableQueryProof{}, common.Hash{}, err
		}
		if !found {
			return tableQueryProof{}, common.Hash{}, errors.New("parent block entry not found")
		}
		proof.EntryIndices = append(proof.EntryIndices, entryIndex)
	}
	for _, blockNumber := range blockNumbers {
		bp := tp.blockProofs[blockNumber]
		if blockNumber != tp.reader.BlockRange().Last() {
			proof.EntryIndices = append(proof.EntryIndices, bp.blockEntryIndex)
		} else {
			proveLastBlock = bp.header.Hash()
		}
		for _, mtx := range bp.matchingTxs {
			proof.EntryIndices = append(proof.EntryIndices, mtx.txEntryIndex)
		}
	}
	sort.Slice(proof.EntryIndices, func(i, j int) bool {
		return proof.EntryIndices[i] < proof.EntryIndices[j]
	})
	for i, number := range blockNumbers {
		bp := tp.blockProofs[number]
		br := blockResults{
			Header:         *bp.header,
			ProvenReceipts: make([]uint32, 0, len(bp.matchingTxs)),
			ReceiptsProof:  bp.receiptsProof.proofForStorage(),
		}
		for txi := range bp.matchingTxs {
			br.ProvenReceipts = append(br.ProvenReceipts, uint32(txi))
		}
		slices.Sort(br.ProvenReceipts)
		proof.BlockResults[i] = br
	}
	proof.ProvenEntries = make([]types.IndexEntry, len(proof.EntryIndices))
	lastIndex := uint64(math.MaxUint64)
	for i, entryIndex := range proof.EntryIndices {
		entry, err := tp.reader.GetEntry(entryIndex)
		if err != nil {
			return tableQueryProof{}, common.Hash{}, err
		}
		proof.ProvenEntries[i] = entry
		if proof.ProofHashes, err = tp.makeProofHashes(proof.ProofHashes, lastIndex, entryIndex); err != nil {
			return tableQueryProof{}, common.Hash{}, err
		}
		lastIndex = entryIndex
	}
	proof.ProofHashes, err = tp.makeProofHashes(proof.ProofHashes, lastIndex, uint64(math.MaxUint64))
	if err != nil {
		return tableQueryProof{}, common.Hash{}, err
	}
	return proof, proveLastBlock, nil
}

// makeProofHashes appends the non-leaf tree node hashes between proven entry
// indexes a and b (inclusive bounds convention: MaxUint64 marks the end).
func (tp *tableProver) makeProofHashes(hashes []common.Hash, a, b uint64) ([]common.Hash, error) {
	if err := iterateProofIndices(tp.treeHeight, a, b, func(gti uint64) error {
		hash, err := tp.reader.GetHash(gti)
		if err != nil {
			return err
		}
		hashes = append(hashes, hash)
		return nil
	}); err != nil {
		return nil, err
	}
	return hashes, nil
}

// iterateProofIndices enumerates the tree node indexes of the multiproof
// between proven entry indexes a and b: each 0 bit of a and each 1 bit of b
// below their shared binary prefix corresponds to one proven sibling subtree.
func iterateProofIndices(treeHeight int, a, b uint64, callback func(uint64) error) error {
	switch {
	case a == math.MaxUint64 && b == math.MaxUint64:
		// no entries proven; merkle multiproof is just the root hash
		return callback(1)
	case a == math.MaxUint64:
		// b has no left neighbor; each 1 bit in b corresponds to a proven hash
		return iterateProofIndicesUp(treeHeight, 0, b, callback)
	case b == math.MaxUint64:
		// a has no right neighbor; each 0 bit in a corresponds to a proven hash
		return iterateProofIndicesDown(treeHeight, 0, a, callback)
	default:
		if a == b {
			return nil
		}
		if a > b {
			panic("iterateProofIndices: invalid index order")
		}
		// we ignore the shared binary prefix plus the first different bit (0 in a, 1 in b)
		splitHeight := treeHeight + bits.LeadingZeros64(a^b) - 63
		if err := iterateProofIndicesDown(treeHeight, splitHeight, a, callback); err != nil {
			return err
		}
		return iterateProofIndicesUp(treeHeight, splitHeight, b, callback)
	}
}

func iterateProofIndicesUp(treeHeight, fromHeight int, entryIndex uint64, callback func(uint64) error) error {
	for h := fromHeight; h < treeHeight; h++ { // h == 0 corresponds to entryIndex MSB
		if entryIndex&(uint64(1)<<(treeHeight-1-h)) != 0 {
			if err := callback((entryIndex>>(treeHeight-1-h) ^ 1) + uint64(1)<<(h+1)); err != nil {
				return err
			}
		}
	}
	return nil
}

func iterateProofIndicesDown(treeHeight, toHeight int, entryIndex uint64, callback func(uint64) error) error {
	for h := treeHeight - 1; h >= toHeight; h-- { // h == 0 corresponds to entryIndex MSB
		if entryIndex&(uint64(1)<<(treeHeight-1-h)) == 0 {
			if err := callback((entryIndex>>(treeHeight-1-h) ^ 1) + uint64(1)<<(h+1)); err != nil {
				return err
			}
		}
	}
	return nil
}

// trieProofWriter collects trie node blobs keyed by their hash.
type trieProofWriter map[common.Hash][]byte

func (t trieProofWriter) Put(key []byte, value []byte) error {
	if len(key) != common.HashLength {
		panic("invalid proof database key")
	}
	var hash common.Hash
	copy(hash[:], key)
	t[hash] = slices.Clone(value)
	return nil
}

func (t trieProofWriter) Delete(key []byte) error { panic("not implemented") }

func (t trieProofWriter) proofForStorage() []hexutil.Bytes {
	proof := make([]hexutil.Bytes, len(t))
	proofHashes := make([]common.Hash, 0, len(t))
	for hash := range t {
		proofHashes = append(proofHashes, hash)
	}
	sort.Slice(proofHashes, func(i, j int) bool {
		return proofHashes[i].Cmp(proofHashes[j]) < 0
	})
	for i, hash := range proofHashes {
		proof[i] = t[hash]
	}
	return proof
}

type blockProof struct {
	header          *types.Header
	blockEntryIndex uint64 // MaxUint64 if block is last in table
	matchingTxs     map[uint32]matchingTx
	receiptsProof   trieProofWriter
}

type matchingTx struct {
	txEntryIndex      uint64
	receiptProofAdded bool
}

func newBlockProof(header *types.Header, blockEntryIndex uint64) *blockProof {
	return &blockProof{
		header:          header,
		blockEntryIndex: blockEntryIndex,
		matchingTxs:     make(map[uint32]matchingTx),
		receiptsProof:   make(trieProofWriter),
	}
}

func (bp *blockProof) merge(bp2 *blockProof) {
	if bp.header.Hash() != bp2.header.Hash() || bp.blockEntryIndex != bp2.blockEntryIndex {
		panic("invalid block proof merge")
	}
	for txi, mtx2 := range bp2.matchingTxs {
		if mtx, ok := bp.matchingTxs[txi]; ok {
			if mtx.txEntryIndex != mtx2.txEntryIndex {
				panic("invalid matching tx proof merge")
			}
			if mtx2.receiptProofAdded && !mtx.receiptProofAdded {
				bp.matchingTxs[txi] = mtx2
			}
		} else {
			bp.matchingTxs[txi] = mtx2
		}
	}
	for hash, blob := range bp2.receiptsProof {
		bp.receiptsProof[hash] = blob
	}
}

// createProof generates the receipts trie multiproof of the matching
// transactions: the receipt trie is rebuilt with a path-filtered stack trie
// callback, collecting the nodes on the rlp(txIndex) key paths of every
// proven transaction.
func (bp *blockProof) createProof(receipts types.Receipts) {
	proveHexKeys := make(map[string]struct{})
	proveHexKeys[""] = struct{}{}
	var indexBuf, indexHex []byte
	for txi, mtx := range bp.matchingTxs {
		if mtx.receiptProofAdded {
			continue
		}
		indexBuf = appendUint64(indexBuf[:0], uint64(txi))
		indexHex = indexHex[:0]
		for _, b := range indexBuf {
			indexHex = append(indexHex, b/16)
			proveHexKeys[string(indexHex)] = struct{}{}
			indexHex = append(indexHex, b%16)
			proveHexKeys[string(indexHex)] = struct{}{}
		}
		mtx.receiptProofAdded = true
		bp.matchingTxs[txi] = mtx
	}
	types.DeriveSha(receipts, trie.NewStackTrie(func(path []byte, hash common.Hash, blob []byte) {
		if _, ok := proveHexKeys[string(path)]; ok {
			bp.receiptsProof[hash] = slices.Clone(blob)
			delete(proveHexKeys, string(path))
		}
	}))
}

func appendUint64(dst []byte, v uint64) []byte {
	// the receipts trie key is the minimal rlp encoding of the tx index
	return rlp.AppendUint64(dst, v)
}

// makeQueryProof assembles the query proof from the per-table provers:
// adjacent tables are chained through their parent block entries and each
// table root is proven against the reference header's state.
func makeQueryProof(refHeader *types.Header, query *FilterQuery, firstBlock, lastBlock uint64, backend contractProverBackend, provers []*tableProver, lastBlockProver *tableProver) (*QueryProof, error) {
	proof := &QueryProof{
		Query:            *query,
		RefHeader:        *refHeader,
		TableQueryProofs: make([]tableQueryProof, len(provers)),
	}
	proof.Query.FirstBlock, proof.Query.LastBlock = firstBlock, lastBlock
	proofNodes := make(trieProofWriter)
	proofCodes := make(trieProofWriter)
	var proveParentBlock common.Hash
	for i, prover := range provers {
		if i != 0 && prover.reader.BlockRange().First() != provers[i-1].reader.BlockRange().AfterLast() {
			return nil, errors.New("prover block ranges are not continuous")
		}
		if prover == lastBlockProver && proveParentBlock == (common.Hash{}) {
			break
		}
		tproof, proveLastBlock, err := prover.finalize(proveParentBlock)
		if err != nil {
			return nil, err
		}
		proveParentBlock = proveLastBlock
		tproof.IndexContract = proof.addOrGetIndexContract(prover.reader.IndexContract)
		proof.TableQueryProofs[i] = tproof
		// generate state proof nodes for the table root
		tableRoot, err := proveTableRoot(backend, refHeader, prover.reader.IndexContract, prover.reader.BlockRange().First(), prover.reader.BlockRange().Count(), proofNodes, proofCodes)
		if err != nil {
			return nil, err
		}
		if tableRoot != prover.reader.TableRoot {
			return nil, errors.New("local table root does not match index contract")
		}
	}
	if proveParentBlock != (common.Hash{}) && proveParentBlock != refHeader.Hash() {
		return nil, errors.New("could not prove last block of last table")
	}
	proof.ContractProofNodes = proofNodes.proofForStorage()
	proof.ContractProofCodes = proofCodes.proofForStorage()
	return proof, nil
}
