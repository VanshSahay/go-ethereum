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

package logindex

import (
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// heavyFeed makes a chain of blocks with txs transactions of logs logs each.
func heavyFeed(blocks, txs, logs int) *testFeed {
	f := &testFeed{headers: make([]*types.Header, blocks+1), receipts: make([]types.Receipts, blocks+1)}
	parent := common.Hash{}
	for i := 1; i <= blocks; i++ {
		header := &types.Header{Number: big.NewInt(int64(i)), ParentHash: parent, Time: uint64(i)}
		f.headers[i] = header
		receipts := make(types.Receipts, txs)
		for t := range receipts {
			var txHash common.Hash
			binary.BigEndian.PutUint64(txHash[24:], uint64(i)*1000+uint64(t))
			receipt := &types.Receipt{TxHash: txHash}
			for l := 0; l < logs; l++ {
				topic := common.Hash{byte(i), byte(t), byte(l)}
				receipt.Logs = append(receipt.Logs, &types.Log{
					Address: common.Address{byte(l), byte(t)},
					Topics:  []common.Hash{{0xdd}, topic},
				})
			}
			receipts[t] = receipt
		}
		f.receipts[i] = receipts
		parent = header.Hash()
	}
	return f
}

// BenchmarkDeriveTableWrites measures the worst block for the derivation: the
// one on which the 256-block table falls due, with 100 transactions of 5 logs
// in every block ("cold" derives, "cached" finds the result of a previous
// derivation of the same block).
func BenchmarkDeriveTableWrites(b *testing.B) {
	const number = 575
	f := heavyFeed(number+1, 100, 5)
	parent, receipts := f.headers[number].ParentHash, f.receipts[number]
	b.Run("cold", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			resetDerivedRoots()
			if _, err := DeriveTableWrites(feedChain{f}, alwaysActive, number, parent, receipts); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("cached", func(b *testing.B) {
		resetDerivedRoots()
		for i := 0; i < b.N; i++ {
			if _, err := DeriveTableWrites(feedChain{f}, alwaysActive, number, parent, receipts); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkExportTableRoots measures the root export of the 12-level
// out-of-protocol hierarchy over a 20000-block chain.
func BenchmarkExportTableRoots(b *testing.B) {
	const blocks = 20000
	f := heavyFeed(blocks, 5, 3)
	sizes := []uint64{1, 4, 16, 64, 256, 1024, 4096, 16384}
	for i := 0; i < b.N; i++ {
		writes, err := ExportTableRoots(feedChain{f}, f.headers[blocks], sizes)
		if err != nil {
			b.Fatal(err)
		}
		if len(writes) == 0 {
			b.Fatal("no roots")
		}
	}
}
