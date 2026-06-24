// Copyright 2025 The go-ethereum Authors
// This file is part of the go-ethereum library.

package types

import (
	"math/big"
	"sort"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
)

func TestEncodeEntry(t *testing.T) {
	val := common.HexToHash("0xdeadbeef00000000000000000000000000000000000000000000000000000000")
	entry := EncodeEntry(EntryTypeLogAddress, val, 42, 3, 7)

	typ, outVal, blockNum, txIdx, logIdx := entry.EntryFields()

	if typ != EntryTypeLogAddress {
		t.Errorf("expected type %d, got %d", EntryTypeLogAddress, typ)
	}
	if outVal != val {
		t.Errorf("expected value %x, got %x", val, outVal)
	}
	if blockNum != 42 {
		t.Errorf("expected blockNum 42, got %d", blockNum)
	}
	if txIdx != 3 {
		t.Errorf("expected txIdx 3, got %d", txIdx)
	}
	if logIdx != 7 {
		t.Errorf("expected logIdx 7, got %d", logIdx)
	}
}

func TestEncodeEntryBlockType(t *testing.T) {
	blockHash := common.HexToHash("0xabcdef0000000000000000000000000000000000000000000000000000000000")
	entry := EncodeEntry(EntryTypeBlock, blockHash, 100, 0, 0)

	typ, val, blockNum, _, _ := entry.EntryFields()

	if typ != EntryTypeBlock {
		t.Errorf("expected type 0 (Block), got %d", typ)
	}
	if val != blockHash {
		t.Errorf("expected value %x, got %x", blockHash, val)
	}
	if blockNum != 100 {
		t.Errorf("expected blockNum 100, got %d", blockNum)
	}
}

func TestCompareEntries(t *testing.T) {
	a := EncodeEntry(EntryTypeLogAddress, common.Hash{}, 0, 0, 0)
	b := EncodeEntry(EntryTypeLogAddress, common.Hash{}, 1, 0, 0)

	if cmp := CompareEntries(a, b); cmp >= 0 {
		t.Errorf("a should be less than b, got %d", cmp)
	}
	if cmp := CompareEntries(b, a); cmp <= 0 {
		t.Errorf("b should be greater than a, got %d", cmp)
	}
	if cmp := CompareEntries(a, a); cmp != 0 {
		t.Errorf("a should equal a, got %d", cmp)
	}
}

func TestCompareEntriesDifferentTypes(t *testing.T) {
	a := EncodeEntry(EntryTypeBlock, common.Hash{}, 0, 0, 0)
	b := EncodeEntry(EntryTypeTransaction, common.Hash{}, 0, 0, 0)

	if cmp := CompareEntries(a, b); cmp >= 0 {
		t.Errorf("Block entry should sort before Transaction entry, got %d", cmp)
	}
}

func TestSortEntries(t *testing.T) {
	entries := []IndexEntry{
		EncodeEntry(EntryTypeLogAddress, common.HexToHash("0x03"), 3, 0, 0),
		EncodeEntry(EntryTypeLogAddress, common.HexToHash("0x01"), 1, 0, 0),
		EncodeEntry(EntryTypeLogAddress, common.HexToHash("0x02"), 2, 0, 0),
	}

	sort.Slice(entries, func(i, j int) bool {
		return CompareEntries(entries[i], entries[j]) < 0
	})

	_, val, _, _, _ := entries[0].EntryFields()
	if val.Hex() != common.HexToHash("0x01").Hex() {
		t.Errorf("expected first entry value 0x01, got %x", val)
	}
}

func TestSortEntriesTypePriority(t *testing.T) {
	entries := []IndexEntry{
		EncodeEntry(EntryTypeLogAddress, common.Hash{}, 0, 0, 0),   // type 2
		EncodeEntry(EntryTypeBlock, common.Hash{}, 0, 0, 0),        // type 0
		EncodeEntry(EntryTypeTransaction, common.Hash{}, 0, 0, 0),  // type 1
	}

	sort.Slice(entries, func(i, j int) bool {
		return CompareEntries(entries[i], entries[j]) < 0
	})

	typ, _, _, _, _ := entries[0].EntryFields()
	if typ != EntryTypeBlock {
		t.Errorf("expected Block first, got type %d", typ)
	}
	typ, _, _, _, _ = entries[1].EntryFields()
	if typ != EntryTypeTransaction {
		t.Errorf("expected Transaction second, got type %d", typ)
	}
	typ, _, _, _, _ = entries[2].EntryFields()
	if typ != EntryTypeLogAddress {
		t.Errorf("expected LogAddress third, got type %d", typ)
	}
}

func TestZeroLogIndex(t *testing.T) {
	z := ZeroLogIndex()
	if z.Chain0.Table != (common.Hash{}) {
		t.Error("ZeroLogIndex Chain0.Table should be zero")
	}
	if !z.Equal(ZeroLogIndex()) {
		t.Error("ZeroLogIndex should equal itself")
	}
}

func TestLogIndexRLPRoundtrip(t *testing.T) {
	original := &LogIndex{
		Chain0: ChainedTableRoot{
			Table:  common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111"),
			Parent: common.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222"),
		},
		Chain1: ChainedTableRoot{
			Table:  common.HexToHash("0x3333333333333333333333333333333333333333333333333333333333333333"),
			Parent: common.HexToHash("0x4444444444444444444444444444444444444444444444444444444444444444"),
		},
		Chain2: ChainedTableRoot{
			Table:  common.HexToHash("0x5555555555555555555555555555555555555555555555555555555555555555"),
			Parent: common.HexToHash("0x6666666666666666666666666666666666666666666666666666666666666666"),
		},
		Chain3: ChainedTableRoot{
			Table:  common.HexToHash("0x7777777777777777777777777777777777777777777777777777777777777777"),
			Parent: common.HexToHash("0x8888888888888888888888888888888888888888888888888888888888888888"),
		},
	}

	data, err := rlp.EncodeToBytes(original)
	if err != nil {
		t.Fatalf("RLP encode failed: %v", err)
	}

	var decoded LogIndex
	if err := rlp.DecodeBytes(data, &decoded); err != nil {
		t.Fatalf("RLP decode failed: %v", err)
	}

	if !original.Equal(decoded) {
		t.Errorf("RLP roundtrip mismatch:\n  original: %+v\n  decoded: %+v", original, decoded)
	}
}

func TestLogIndexRLPRoundtripZero(t *testing.T) {
	original := ZeroLogIndex()

	data, err := rlp.EncodeToBytes(original)
	if err != nil {
		t.Fatalf("RLP encode failed: %v", err)
	}

	var decoded LogIndex
	if err := rlp.DecodeBytes(data, &decoded); err != nil {
		t.Fatalf("RLP decode failed: %v", err)
	}

	if !original.Equal(decoded) {
		t.Errorf("Zero RLP roundtrip mismatch")
	}
}

func TestHeaderRLPRoundtripPreFork(t *testing.T) {
	// Pre-EIP-7745b: bloom present, LogIndex nil
	header := &Header{
		ParentHash:  common.HexToHash("0x01"),
		UncleHash:   EmptyUncleHash,
		Coinbase:    common.HexToAddress("0x02"),
		Root:        common.HexToHash("0x03"),
		TxHash:      EmptyTxsHash,
		ReceiptHash: EmptyReceiptsHash,
		Bloom:       Bloom{},
		Difficulty:  big.NewInt(1),
		Number:      big.NewInt(100),
		GasLimit:    30000000,
		GasUsed:     1000000,
		Time:        1234567890,
		Extra:       nil,
		MixDigest:   common.Hash{},
		Nonce:       BlockNonce{},
	}

	data, err := rlp.EncodeToBytes(header)
	if err != nil {
		t.Fatalf("RLP encode pre-fork failed: %v", err)
	}

	var decoded Header
	if err := rlp.DecodeBytes(data, &decoded); err != nil {
		t.Fatalf("RLP decode pre-fork failed: %v", err)
	}

	if decoded.LogIndex != nil {
		t.Error("pre-fork header LogIndex should be nil")
	}
	if decoded.Bloom != header.Bloom {
		t.Error("pre-fork bloom mismatch")
	}
}

func TestHeaderRLPRoundtripPostFork(t *testing.T) {
	// Post-EIP-7745b: LogIndex present, bloom zero
	header := &Header{
		ParentHash:  common.HexToHash("0x01"),
		UncleHash:   EmptyUncleHash,
		Coinbase:    common.HexToAddress("0x02"),
		Root:        common.HexToHash("0x03"),
		TxHash:      EmptyTxsHash,
		ReceiptHash: EmptyReceiptsHash,
		Bloom:       Bloom{},
		Difficulty:  big.NewInt(1),
		Number:      big.NewInt(100),
		GasLimit:    30000000,
		GasUsed:     1000000,
		Time:        1234567890,
		Extra:       nil,
		MixDigest:   common.Hash{},
		Nonce:       BlockNonce{},
		LogIndex: &LogIndex{
			Chain0: ChainedTableRoot{
				Table:  common.HexToHash("0xaa"),
				Parent: common.HexToHash("0xbb"),
			},
		},
	}

	data, err := rlp.EncodeToBytes(header)
	if err != nil {
		t.Fatalf("RLP encode post-fork failed: %v", err)
	}

	var decoded Header
	if err := rlp.DecodeBytes(data, &decoded); err != nil {
		t.Fatalf("RLP decode post-fork failed: %v", err)
	}

	if decoded.LogIndex == nil {
		t.Fatal("post-fork header LogIndex should not be nil")
	}
	if !decoded.LogIndex.Equal(*header.LogIndex) {
		t.Errorf("post-fork LogIndex mismatch:\n  expected: %+v\n  got: %+v", header.LogIndex, decoded.LogIndex)
	}
}

func TestHeaderRLPRoundtripWithOptionalFields(t *testing.T) {
	baseFee := big.NewInt(1000000000)

	// Minimal optional fields: just BaseFee
	header := &Header{
		ParentHash:  common.HexToHash("0x01"),
		UncleHash:   EmptyUncleHash,
		Coinbase:    common.HexToAddress("0x02"),
		Root:        common.HexToHash("0x03"),
		TxHash:      EmptyTxsHash,
		ReceiptHash: EmptyReceiptsHash,
		Bloom:       Bloom{},
		Difficulty:  big.NewInt(1),
		Number:      big.NewInt(200),
		GasLimit:    30000000,
		GasUsed:     1000000,
		Time:        1234567890,
		Extra:       nil,
		MixDigest:   common.Hash{},
		Nonce:       BlockNonce{},
		BaseFee:     baseFee,
	}

	data, err := rlp.EncodeToBytes(header)
	if err != nil {
		t.Fatalf("RLP encode with optional fields failed: %v", err)
	}

	var decoded Header
	if err := rlp.DecodeBytes(data, &decoded); err != nil {
		t.Fatalf("RLP decode with optional fields failed: %v", err)
	}

	if decoded.BaseFee == nil || decoded.BaseFee.Cmp(baseFee) != 0 {
		t.Error("BaseFee mismatch")
	}
}

func TestHeaderRLPRoundtripAllOptionals(t *testing.T) {
	baseFee := big.NewInt(1000000000)
	wHash := common.HexToHash("0xaa")
	blobGasUsed := uint64(131072)
	excessBlobGas := uint64(65536)
	beaconRoot := common.HexToHash("0xbb")
	reqHash := common.HexToHash("0xcc")
	balHash := common.HexToHash("0xdd")
	slot := uint64(42)

	header := &Header{
		ParentHash:        common.HexToHash("0x01"),
		UncleHash:         EmptyUncleHash,
		Coinbase:          common.HexToAddress("0x02"),
		Root:              common.HexToHash("0x03"),
		TxHash:            EmptyTxsHash,
		ReceiptHash:       EmptyReceiptsHash,
		Bloom:             Bloom{},
		Difficulty:        big.NewInt(1),
		Number:            big.NewInt(200),
		GasLimit:          30000000,
		GasUsed:           1000000,
		Time:              1234567890,
		Extra:             nil,
		MixDigest:         common.Hash{},
		Nonce:             BlockNonce{},
		BaseFee:           baseFee,
		WithdrawalsHash:   &wHash,
		BlobGasUsed:       &blobGasUsed,
		ExcessBlobGas:     &excessBlobGas,
		ParentBeaconRoot:  &beaconRoot,
		RequestsHash:      &reqHash,
		BlockAccessListHash: &balHash,
		SlotNumber:        &slot,
	}

	data, err := rlp.EncodeToBytes(header)
	if err != nil {
		t.Fatalf("RLP encode all optionals failed: %v", err)
	}

	var decoded Header
	if err := rlp.DecodeBytes(data, &decoded); err != nil {
		t.Fatalf("RLP decode all optionals failed: %v", err)
	}

	if decoded.BaseFee == nil || decoded.BaseFee.Cmp(baseFee) != 0 {
		t.Error("BaseFee mismatch")
	}
	if decoded.SlotNumber == nil || *decoded.SlotNumber != slot {
		t.Error("SlotNumber mismatch")
	}
}
