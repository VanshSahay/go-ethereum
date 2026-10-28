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
	"encoding/binary"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/logindex"
	"github.com/ethereum/go-ethereum/crypto"
)

// HistoricContractCode is the runtime code of a minimal historic index
// contract. It answers the protocol's get(first_block, table_size) call
// (64 bytes of calldata, no selector) from a flat mapping filled at
// deployment, reverting for an unknown table:
//
//	CALLDATACOPY(0, 0, 64)
//	root = SLOAD(KECCAK256(0, 64))
//	if root == 0 { REVERT }
//	return root
var HistoricContractCode = common.FromHex(
	"60405f5f37" + // PUSH1 0x40, PUSH0, PUSH0, CALLDATACOPY
		"60405f2054" + // PUSH1 0x40, PUSH0, KECCAK256, SLOAD
		"80601157" + // DUP1, PUSH1 0x11, JUMPI
		"5f5ffd" + // PUSH0, PUSH0, REVERT
		"5b5f52" + // JUMPDEST, PUSH0, MSTORE
		"60205ff3") // PUSH1 0x20, PUSH0, RETURN

// HistoricSlot returns the storage slot of a table root in the historic
// contract: keccak256(first_block ‖ table_size), both as 32-byte words.
func HistoricSlot(firstBlock, tableSize uint64) common.Hash {
	var key [64]byte
	binary.BigEndian.PutUint64(key[24:32], firstBlock)
	binary.BigEndian.PutUint64(key[56:64], tableSize)
	return crypto.Keccak256Hash(key[:])
}

// HistoricStorage returns the contract storage holding the given table roots,
// for use in a genesis allocation or a state override.
func HistoricStorage(writes []logindex.TableWrite) map[common.Hash]common.Hash {
	storage := make(map[common.Hash]common.Hash, len(writes))
	for _, w := range writes {
		storage[HistoricSlot(w.FirstBlock, w.TableSize)] = w.Root
	}
	return storage
}

// HistoricInitCode returns contract creation code that stores the given table
// roots and deploys HistoricContractCode, for chains that add the contract
// with a transaction instead of a genesis allocation.
func HistoricInitCode(writes []logindex.TableWrite) []byte {
	var code []byte
	for _, w := range writes {
		code = append(code, 0x7f) // PUSH32 root
		code = append(code, w.Root[:]...)
		slot := HistoricSlot(w.FirstBlock, w.TableSize)
		code = append(code, 0x7f) // PUSH32 slot
		code = append(code, slot[:]...)
		code = append(code, 0x55) // SSTORE
	}
	// copy the runtime code behind the epilogue into memory and return it
	const epilogue = 11
	runtime := HistoricContractCode
	offset := len(code) + epilogue
	code = append(code, 0x60, byte(len(runtime))) // PUSH1 len
	code = append(code, 0x61, byte(offset>>8), byte(offset))
	code = append(code, 0x5f, 0x39)               // PUSH0, CODECOPY
	code = append(code, 0x60, byte(len(runtime))) // PUSH1 len
	code = append(code, 0x5f, 0xf3)               // PUSH0, RETURN
	return append(code, runtime...)
}
