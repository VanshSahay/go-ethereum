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
	"encoding/json"
	"errors"
	"io"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
)

// The binary form of a query proof is its RLP encoding. It carries the same
// content as the JSON form, minus the JSON overhead (hex strings, field
// names), and is what proof-size comparisons should be made with. The search
// pattern is embedded in its canonical JSON form.

type rlpQuery struct {
	Pattern     []byte
	FirstBlock  uint64
	LastBlock   uint64
	Limit       uint64
	LimitLatest bool
	Cursor      []uint64 // empty, or block and log index
}

type rlpBlockResults struct {
	Header         *types.Header
	ProvenReceipts []uint32
	ReceiptsProof  [][]byte
}

type rlpTableProof struct {
	FirstBlock    uint64
	TableSize     uint64
	EntryCount    uint64
	IndexContract uint32
	EntryIndices  []uint64
	ProvenEntries [][]byte
	ProofHashes   []common.Hash
	ResultCount   uint64
	BlockResults  []rlpBlockResults
	Pin           bool
}

type rlpQueryProof struct {
	Query              rlpQuery
	RefHeader          *types.Header
	IndexContracts     []common.Address
	ContractProofNodes [][]byte
	ContractProofCodes [][]byte
	Tables             []rlpTableProof
}

func bytesList(in []hexutil.Bytes) [][]byte {
	out := make([][]byte, len(in))
	for i, b := range in {
		out[i] = b
	}
	return out
}

func hexList(in [][]byte) []hexutil.Bytes {
	out := make([]hexutil.Bytes, len(in))
	for i, b := range in {
		out[i] = b
	}
	return out
}

// EncodeRLP implements rlp.Encoder.
func (p *QueryProof) EncodeRLP(w io.Writer) error {
	pattern, err := json.Marshal(p.Query.Pattern)
	if err != nil {
		return err
	}
	var cursor []uint64
	if c := p.Query.Cursor; c != nil {
		cursor = []uint64{c.Block, c.LogIndex}
	}
	enc := rlpQueryProof{
		Query: rlpQuery{
			Pattern:     pattern,
			FirstBlock:  p.Query.FirstBlock,
			LastBlock:   p.Query.LastBlock,
			Limit:       p.Query.Limit,
			LimitLatest: p.Query.LimitLatest,
			Cursor:      cursor,
		},
		RefHeader:          &p.RefHeader,
		IndexContracts:     p.IndexContracts,
		ContractProofNodes: bytesList(p.ContractProofNodes),
		ContractProofCodes: bytesList(p.ContractProofCodes),
		Tables:             make([]rlpTableProof, len(p.TableQueryProofs)),
	}
	for i := range p.TableQueryProofs {
		t := &p.TableQueryProofs[i]
		et := rlpTableProof{
			FirstBlock:    t.FirstBlock,
			TableSize:     t.TableSize,
			EntryCount:    t.EntryCount,
			IndexContract: t.IndexContract,
			EntryIndices:  t.EntryIndices,
			ProvenEntries: make([][]byte, len(t.ProvenEntries)),
			ProofHashes:   t.ProofHashes,
			ResultCount:   t.ResultCount,
			BlockResults:  make([]rlpBlockResults, len(t.BlockResults)),
			Pin:           t.Pin,
		}
		for j, e := range t.ProvenEntries {
			et.ProvenEntries[j] = e
		}
		for j := range t.BlockResults {
			br := &t.BlockResults[j]
			et.BlockResults[j] = rlpBlockResults{
				Header:         &br.Header,
				ProvenReceipts: br.ProvenReceipts,
				ReceiptsProof:  bytesList(br.ReceiptsProof),
			}
		}
		enc.Tables[i] = et
	}
	return rlp.Encode(w, &enc)
}

// DecodeRLP implements rlp.Decoder.
func (p *QueryProof) DecodeRLP(s *rlp.Stream) error {
	var dec rlpQueryProof
	if err := s.Decode(&dec); err != nil {
		return err
	}
	if dec.RefHeader == nil {
		return errors.New("missing reference header")
	}
	pattern, err := NewPatternMatcherFromJSON(dec.Query.Pattern)
	if err != nil {
		return err
	}
	var cursor *Cursor
	switch len(dec.Query.Cursor) {
	case 0:
	case 2:
		cursor = &Cursor{Block: dec.Query.Cursor[0], LogIndex: dec.Query.Cursor[1]}
	default:
		return errors.New("invalid cursor")
	}
	*p = QueryProof{
		Query: FilterQuery{
			Pattern:     pattern,
			FirstBlock:  dec.Query.FirstBlock,
			LastBlock:   dec.Query.LastBlock,
			Limit:       dec.Query.Limit,
			LimitLatest: dec.Query.LimitLatest,
			Cursor:      cursor,
		},
		RefHeader:          *dec.RefHeader,
		IndexContracts:     dec.IndexContracts,
		ContractProofNodes: hexList(dec.ContractProofNodes),
		ContractProofCodes: hexList(dec.ContractProofCodes),
		TableQueryProofs:   make([]tableQueryProof, len(dec.Tables)),
	}
	for i, et := range dec.Tables {
		t := tableQueryProof{
			FirstBlock:    et.FirstBlock,
			TableSize:     et.TableSize,
			EntryCount:    et.EntryCount,
			IndexContract: et.IndexContract,
			EntryIndices:  et.EntryIndices,
			ProvenEntries: make([]types.IndexEntry, len(et.ProvenEntries)),
			ProofHashes:   et.ProofHashes,
			ResultCount:   et.ResultCount,
			BlockResults:  make([]blockResults, len(et.BlockResults)),
			Pin:           et.Pin,
		}
		for j, e := range et.ProvenEntries {
			t.ProvenEntries[j] = e
		}
		for j, br := range et.BlockResults {
			if br.Header == nil {
				return errors.New("missing block header")
			}
			t.BlockResults[j] = blockResults{
				Header:         *br.Header,
				ProvenReceipts: br.ProvenReceipts,
				ReceiptsProof:  hexList(br.ReceiptsProof),
			}
		}
		p.TableQueryProofs[i] = t
	}
	return nil
}
