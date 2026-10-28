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
	"errors"
	"math/bits"
	"slices"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/logindex"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
)

// getGasLimit bounds the execution of the index contract's get() on the
// verifier side: the real contract uses a few thousand gas, so a contract
// that needs more is not the index contract.
const getGasLimit = 1_000_000

// ringSlots is the number of table roots the index contract stores per level.
const ringSlots = 1024

// tablePath tells how the root of a published table is read from the reference
// state.
type tablePath int

const (
	// pathGet executes the contract's get(): the table is past its one block
	// publication lag.
	pathGet tablePath = iota
	// pathRaw reads the storage slot directly: the table's root was set by the
	// system call of the reference block itself, where get() still reverts.
	pathRaw
)

// publicationBlock returns the block at which the table is committed to the
// index contract: first_block + table_size + table_size/4 - 1. It reports false
// on overflow.
func publicationBlock(tableSize, firstBlock uint64) (uint64, bool) {
	sum, carry := bits.Add64(firstBlock, tableSize+tableSize/4-1, 0)
	return sum, carry == 0
}

// checkTable validates the table parameters a proof claims and decides how its
// root is read at the given reference block. Only the protocol table sizes at
// aligned first blocks can have a root in the index contract, and only tables
// published at or before the reference block.
func checkTable(tableSize, firstBlock, refNumber uint64) (tablePath, error) {
	if !slices.Contains(logindex.TableSizes, tableSize) {
		return 0, errors.New("invalid table size")
	}
	if firstBlock%tableSize != 0 {
		return 0, errors.New("table is not aligned to its size")
	}
	published, ok := publicationBlock(tableSize, firstBlock)
	if !ok || published > refNumber {
		return 0, errors.New("table is not published at the reference block")
	}
	if published == refNumber {
		return pathRaw, nil
	}
	return pathGet, nil
}

// HistoricContract describes an out-of-protocol index contract: a contract
// holding the roots of the tables of a past block range under the same get()
// interface as the protocol's contract, but without publication schedule or
// ring window. It is the verifier's side of a hierarchy made with
// logindex.NewHistoricParams.
type HistoricContract struct {
	// CodeHash is the code hash the contract must have in the reference
	// state; the zero hash accepts any code.
	CodeHash common.Hash
	// TableSizes lists the table sizes the contract holds roots for.
	TableSizes []uint64
	// LastBlock is the last block the contract holds table roots for.
	LastBlock uint64
}

// checkHistoricTable validates the table parameters a proof claims against a
// historic contract: a listed size at an aligned first block, entirely behind
// the reference block. The root is always read through get().
func checkHistoricTable(spec HistoricContract, tableSize, firstBlock, refNumber uint64) (tablePath, error) {
	if !slices.Contains(spec.TableSizes, tableSize) {
		return 0, errors.New("invalid table size")
	}
	if firstBlock%tableSize != 0 {
		return 0, errors.New("table is not aligned to its size")
	}
	end, carry := bits.Add64(firstBlock, tableSize, 0)
	if carry != 0 || end > refNumber || end-1 > spec.LastBlock {
		return 0, errors.New("table is not behind the reference block or past the contract's coverage")
	}
	return pathGet, nil
}

type contractVerifierBackend interface {
	ChainConfig() *params.ChainConfig
}

type contractProverBackend interface {
	contractVerifierBackend
	StateProverAt(header *types.Header, proofNodes, proofCodes map[common.Hash][]byte) (*state.StateDB, error)
}

// proveTableRoot retrieves the table root stored in the index contract from a
// state reconstructed from the given proof maps.
func proveTableRoot(backend contractProverBackend, refHead *types.Header, contract common.Address, firstBlock, tableSize uint64, proofNodes, proofCodes map[common.Hash][]byte) (common.Hash, error) {
	statedb, err := backend.StateProverAt(refHead, proofNodes, proofCodes)
	if err != nil {
		return common.Hash{}, err
	}
	return getTableRoot(statedb, backend.ChainConfig(), refHead, contract, firstBlock, tableSize)
}

// getTableRoot executes the index contract's get() call on the given state and
// returns the stored table root.
func getTableRoot(statedb *state.StateDB, chainConfig *params.ChainConfig, refHead *types.Header, contract common.Address, firstBlock, tableSize uint64) (common.Hash, error) {
	chainCtx := &chainContext{chainConfig: chainConfig, head: refHead, engine: ethash.NewFaker()}
	context := core.NewEVMBlockContext(refHead, chainCtx, new(common.Address))
	evm := vm.NewEVM(context, statedb, chainCtx.chainConfig, vm.Config{})
	var callData [64]byte
	binary.BigEndian.PutUint64(callData[24:32], firstBlock)
	binary.BigEndian.PutUint64(callData[56:64], tableSize)
	result, _, err := evm.Call(contract, contract, callData[:], vm.NewGasBudget(getGasLimit, getGasLimit), common.U2560)
	if err != nil {
		return common.Hash{}, err
	}
	if len(result) != common.HashLength {
		return common.Hash{}, errors.New("invalid return data size")
	}
	var tableRoot common.Hash
	copy(tableRoot[:], result)
	return tableRoot, nil
}

// IndexSlot returns the storage slot of the table root for the given table
// per the EIP-8304 ring-buffer layout: table_size*1024 + (first_block/ts)%1024.
// It reports false for a zero table size or when the slot index overflows.
func IndexSlot(tableSize, firstBlock uint64) (common.Hash, bool) {
	if tableSize == 0 {
		return common.Hash{}, false
	}
	hi, lo := bits.Mul64(tableSize, ringSlots)
	if hi != 0 {
		return common.Hash{}, false
	}
	sum, carry := bits.Add64(lo, (firstBlock/tableSize)%ringSlots, 0)
	if carry != 0 {
		return common.Hash{}, false
	}
	var slot common.Hash
	binary.BigEndian.PutUint64(slot[common.HashLength-8:], sum)
	return slot, true
}

// getTableRootRaw reads the table root directly from the contract's storage
// slot on the given state, bypassing the get() freshness window: the slot is
// set by the system call in the table's publication block regardless of the
// window, so the root of a table published in the reference block is provable
// this way.
func getTableRootRaw(statedb *state.StateDB, contract common.Address, firstBlock, tableSize uint64) (common.Hash, error) {
	slot, ok := IndexSlot(tableSize, firstBlock)
	if !ok {
		return common.Hash{}, errors.New("invalid table slot")
	}
	return statedb.GetState(contract, slot), nil
}

// chainContext is a minimal consensus context serving only the reference head.
type chainContext struct {
	chainConfig *params.ChainConfig
	head        *types.Header
	engine      consensus.Engine
}

func (c *chainContext) Engine() consensus.Engine {
	return c.engine
}

func (c *chainContext) GetHeader(hash common.Hash, number uint64) *types.Header {
	if hash == c.head.Hash() && number == c.head.Number.Uint64() {
		return c.head
	}
	return nil
}

func (c *chainContext) Config() *params.ChainConfig {
	return c.chainConfig
}

func (c *chainContext) CurrentHeader() *types.Header {
	return c.head
}

func (c *chainContext) GetHeaderByNumber(number uint64) *types.Header {
	if number == c.head.Number.Uint64() {
		return c.head
	}
	return nil
}

func (c *chainContext) GetHeaderByHash(hash common.Hash) *types.Header {
	if hash == c.head.Hash() {
		return c.head
	}
	return nil
}
