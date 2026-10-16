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
	"math"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/triedb"
	"math/big"
)

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
	result, _, err := evm.Call(contract, contract, callData[:], vm.NewGasBudget(math.MaxUint64, math.MaxUint64), common.U2560)
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
func IndexSlot(tableSize, firstBlock uint64) common.Hash {
	return common.BigToHash(new(big.Int).SetUint64(tableSize*1024 + (firstBlock/tableSize)%1024))
}

// getTableRootRaw reads the table root directly from the contract's storage
// slot on the given state, bypassing the get() freshness window: the slot is
// set by the system call in the table's publication block regardless of the
// window, so the freshest table's root is provable this way.
func getTableRootRaw(statedb *state.StateDB, contract common.Address, firstBlock, tableSize uint64) common.Hash {
	return statedb.GetState(contract, IndexSlot(tableSize, firstBlock))
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

// getProvenTableRoot retrieves the table root by executing the index
// contract's get() on the state reconstructed from the contract state proof.
func getProvenTableRoot(backend contractVerifierBackend, refHead *types.Header, contract common.Address, firstBlock, tableSize uint64, proofNodes, proofCodes map[common.Hash][]byte) (common.Hash, error) {
	stateDb, err := provenState(backend, refHead, proofNodes, proofCodes)
	if err != nil {
		return common.Hash{}, err
	}
	return getTableRoot(stateDb, backend.ChainConfig(), refHead, contract, firstBlock, tableSize)
}

// getProvenTableRootState is getProvenTableRoot over an already-reconstructed
// state.
func getProvenTableRootState(stateDb *state.StateDB, chainConfig *params.ChainConfig, refHead *types.Header, contract common.Address, firstBlock, tableSize uint64) (common.Hash, error) {
	return getTableRoot(stateDb, chainConfig, refHead, contract, firstBlock, tableSize)
}

// provenState reconstructs the reference head's state from the proof maps.
func provenState(backend contractVerifierBackend, refHead *types.Header, proofNodes, proofCodes map[common.Hash][]byte) (*state.StateDB, error) {
	proofDb := triedb.NewProofReader(proofNodes, &triedb.Config{})
	codeDb := state.NewProofCodeReader(proofCodes)
	return state.New(refHead.Root, state.NewMPTDatabase(proofDb, codeDb))
}
