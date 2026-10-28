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
	"context"
	"encoding/json"
	"errors"
	"math"
	"slices"
	"sort"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/logindex"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
)

// FilterQuery describes a log query: a search pattern, the block range it is
// applied to, and an optional result limit (oldest-first, or newest-first
// with LimitLatest).
type FilterQuery struct {
	Pattern     PatternMatcher `json:"pattern"`
	FirstBlock  uint64         `json:"firstBlock"`
	LastBlock   uint64         `json:"lastBlock"`
	Limit       uint64         `json:"limit"`
	LimitLatest bool           `json:"limitLatest"`
}

// MarshalJSON encodes the query with the pattern's own marshaling.
func (q FilterQuery) MarshalJSON() ([]byte, error) {
	pattern, err := json.Marshal(q.Pattern)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Pattern     json.RawMessage `json:"pattern"`
		FirstBlock  uint64          `json:"firstBlock"`
		LastBlock   uint64          `json:"lastBlock"`
		Limit       uint64          `json:"limit"`
		LimitLatest bool            `json:"limitLatest"`
	}{pattern, q.FirstBlock, q.LastBlock, q.Limit, q.LimitLatest})
}

// UnmarshalJSON decodes the query, reconstructing the pattern from its JSON
// form via the pattern grammar.
func (q *FilterQuery) UnmarshalJSON(data []byte) error {
	var p struct {
		Pattern     json.RawMessage `json:"pattern"`
		FirstBlock  uint64          `json:"firstBlock"`
		LastBlock   uint64          `json:"lastBlock"`
		Limit       uint64          `json:"limit"`
		LimitLatest bool            `json:"limitLatest"`
	}
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	matcher, err := NewPatternMatcherFromJSON(p.Pattern)
	if err != nil {
		return err
	}
	q.Pattern, q.FirstBlock, q.LastBlock, q.Limit, q.LimitLatest = matcher, p.FirstBlock, p.LastBlock, p.Limit, p.LimitLatest
	return nil
}

// logIndex provides access to the index tables covering a block range.
type logIndex interface {
	GetRangeReaders(common.Hash, common.Range[uint64], uint64) []*logindex.TableReader
}

// ChainView provides read access to the chain data of the reference head.
type ChainView interface {
	HeadNumber() uint64
	Header(uint64) *types.Header
	Body(uint64) *types.Body
	RawReceipts(uint64) types.Receipts
}

// Matcher runs log queries against the index tables and, when asked, assembles
// the query proof. The implementation is deliberately single-threaded: one
// table after another, in range order.
type Matcher struct {
	logIndex              logIndex
	contractProverBackend contractProverBackend

	// MaxCandidates bounds the number of candidate positions a single table
	// scan may derive: a query matching more than that is too broad to serve.
	MaxCandidates int

	// Historic lists the out-of-protocol index contracts the matcher's index
	// holds tables for; their roots are read without the publication schedule.
	Historic map[common.Address]HistoricContract
}

// DefaultMaxCandidates is the candidate bound of a matcher made by NewMatcher.
const DefaultMaxCandidates = 1 << 20

// ErrQueryTooBroad is returned when a query derives more candidate positions
// from the index than the matcher is willing to process.
var ErrQueryTooBroad = errors.New("query is too broad")

func NewMatcher(logIndex logIndex, contractProverBackend contractProverBackend) *Matcher {
	return &Matcher{
		logIndex:              logIndex,
		contractProverBackend: contractProverBackend,
		MaxCandidates:         DefaultMaxCandidates,
	}
}

// GetMatches runs the query and returns the matching logs, the block range
// they are proven for and, when prove is set, the self-contained query proof.
//
// At most query.Limit logs are returned, the oldest ones or, with LimitLatest,
// the newest ones. When the limit is reached the proven range is cut at the
// block holding the last returned log (the whole block is proven, so the
// verifier trims the surplus logs of that block identically); otherwise the
// proven range is the requested range and the result is complete.
func (mc *Matcher) GetMatches(ctx context.Context, chainView ChainView, query FilterQuery, prove bool) ([]*types.Log, common.Range[uint64], *QueryProof, error) {
	if query.Pattern == nil {
		return nil, common.Range[uint64]{}, nil, errors.New("missing query pattern")
	}
	if query.Limit == 0 {
		return nil, common.Range[uint64]{}, nil, errors.New("zero result limit")
	}
	headBlock := chainView.HeadNumber()
	refHeader := chainView.Header(headBlock)
	refBlockHash := refHeader.Hash()
	firstBlock := query.FirstBlock
	lastBlock := min(query.LastBlock, headBlock)
	if firstBlock > lastBlock {
		return nil, common.Range[uint64]{}, nil, errors.New("empty block range")
	}
	blockRange := common.NewRange[uint64](firstBlock, lastBlock+1-firstBlock)
	var publishedBefore uint64
	if prove {
		publishedBefore = refHeader.Number.Uint64()
	}
	readers := mc.logIndex.GetRangeReaders(refBlockHash, blockRange, publishedBefore)
	if len(readers) == 0 {
		return nil, common.Range[uint64]{}, nil, errors.New("required block range is not indexed")
	}
	sort.Slice(readers, func(i, j int) bool {
		if query.LimitLatest {
			return readers[i].BlockRange().First() > readers[j].BlockRange().First()
		}
		return readers[i].BlockRange().First() < readers[j].BlockRange().First()
	})
	if err := checkCoverage(readers, query.LimitLatest, blockRange); err != nil {
		return nil, common.Range[uint64]{}, nil, err
	}
	maxResults := math.MaxInt
	if query.Limit < uint64(math.MaxInt) {
		maxResults = int(query.Limit)
	}
	var (
		allLogs  []*types.Log // in scan order
		provers  []*tableProver
		limited  bool   // the result limit was reached
		cutBlock uint64 // the block the limit was reached in
	)
	for _, tr := range readers {
		var prover *tableProver
		if prove {
			prover = newTableProver(tr)
		}
		if err := ctx.Err(); err != nil {
			return nil, common.Range[uint64]{}, nil, err
		}
		br := tr.BlockRange().Intersection(blockRange)
		if br.IsEmpty() || limited {
			continue // beyond the cut: not part of the proven range
		}
		mp := &matcherProcess{
			chainView:   chainView,
			reader:      tr,
			prover:      prover,
			pattern:     query.Pattern,
			reverse:     query.LimitLatest,
			maxRun:      mc.MaxCandidates,
			blockProofs: make(map[uint64]*blockProof),
		}
		begin := types.IndexPosition{BlockNumber: br.First()}
		end := types.IndexPosition{BlockNumber: br.Last(), TxIndex: math.MaxUint32, LogIndex: math.MaxUint32}
		cut, err := mp.scan(ctx, query.Pattern, begin, end, maxResults-len(allLogs))
		if err != nil {
			return nil, common.Range[uint64]{}, nil, err
		}
		if prover != nil {
			prover.addBlockProofs(mp.blockProofs, len(mp.matches))
		}
		allLogs = append(allLogs, mp.matches...)
		if prove {
			provers = append(provers, prover)
		}
		if cut != nil {
			limited, cutBlock = true, *cut
		}
	}
	if len(allLogs) > maxResults {
		allLogs = allLogs[:maxResults]
	}
	provenFirst, provenLast := firstBlock, lastBlock
	if limited {
		if query.LimitLatest {
			provenFirst = cutBlock
		} else {
			provenLast = cutBlock
		}
	}
	if query.LimitLatest {
		last := len(allLogs) - 1
		for i := 0; i < last-i; i++ {
			allLogs[i], allLogs[last-i] = allLogs[last-i], allLogs[i]
		}
		// the provers were collected newest first
		last = len(provers) - 1
		for i := 0; i < last-i; i++ {
			provers[i], provers[last-i] = provers[last-i], provers[i]
		}
	}
	var proof *QueryProof
	if prove {
		pin, err := mc.pinRequest(refHeader, provers)
		if err != nil {
			return nil, common.Range[uint64]{}, nil, err
		}
		if proof, err = makeQueryProof(ctx, refHeader, &query, provenFirst, provenLast, mc.contractProverBackend, mc.Historic, provers, pin); err != nil {
			return nil, common.Range[uint64]{}, nil, err
		}
	}
	return allLogs, common.NewRange[uint64](provenFirst, provenLast+1-provenFirst), proof, nil
}

// pinRequest tells whether the block hash of the last proven result needs a
// pin table. The block entry of block n is stored in the table that contains
// block n+1, so a result in the last block of the last coverage table can only
// be pinned by another table, unless it is the reference block itself.
func (mc *Matcher) pinRequest(refHeader *types.Header, provers []*tableProver) (*pinRequest, error) {
	if len(provers) == 0 {
		return nil, nil
	}
	last := provers[len(provers)-1]
	number := last.reader.BlockRange().Last()
	bp, ok := last.blockProofs[number]
	if !ok || number >= refHeader.Number.Uint64() {
		return nil, nil
	}
	readers := mc.logIndex.GetRangeReaders(refHeader.Hash(), common.NewRange[uint64](number+1, 1), refHeader.Number.Uint64())
	if len(readers) != 1 {
		return nil, errors.New("no published table contains the block after the last result block")
	}
	return &pinRequest{prover: newTableProver(readers[0]), number: number, hash: bp.header.Hash()}, nil
}

// checkCoverage verifies that the readers, sorted in scan order, form one
// continuous range that contains the requested range.
func checkCoverage(readers []*logindex.TableReader, reverse bool, want common.Range[uint64]) error {
	var covered common.RangeSet[uint64]
	for i, tr := range readers {
		if i > 0 {
			prev := readers[i-1].BlockRange()
			if reverse && prev.First() != tr.BlockRange().AfterLast() || !reverse && prev.AfterLast() != tr.BlockRange().First() {
				return errors.New("required block range is not indexed")
			}
		}
		covered = covered.Union(common.SingleRangeSet[uint64](tr.BlockRange()))
	}
	if !common.SingleRangeSet[uint64](want).Difference(covered).IsEmpty() {
		return errors.New("required block range is not indexed")
	}
	return nil
}

// readerSource implements runSource over a table reader. When recording it
// notes the table indices of the entries a run is made of together with its
// two bounding neighbors: exactly the entries a proof needs to show the run
// complete.
type readerSource struct {
	ctx     context.Context
	reader  *logindex.TableReader
	record  bool
	maxRun  int // longest run the source may return; zero means unbounded
	touched []uint64
	err     error
}

func (rs *readerSource) mark() int { return len(rs.touched) }

func (rs *readerSource) drop(from, to int) {
	rs.touched = slices.Delete(rs.touched, from, to)
}

func (rs *readerSource) valueRun(typ uint32, content []byte, begin, end types.IndexPosition) (indexPositionSet, bool) {
	if rs.err != nil {
		return nil, false
	}
	start, _, err := rs.reader.SeekEntry(valueBoundary(typ, content, begin))
	if err != nil {
		rs.err = err
		return nil, false
	}
	high := valueBoundary(typ, content, end)
	var (
		run indexPositionSet
		i   = start
	)
	for ; i < rs.reader.EntryCount; i++ {
		if i%1024 == 0 {
			if err := rs.ctx.Err(); err != nil {
				rs.err = err
				return nil, false
			}
		}
		entry, err := rs.reader.GetEntry(i)
		if err != nil {
			rs.err = err
			return nil, false
		}
		if types.CompareEntries(entry, high) > 0 {
			break
		}
		pos, err := types.PositionFromEntry(entry)
		if err != nil {
			rs.err = err
			return nil, false
		}
		run = append(run, pos)
		if rs.maxRun > 0 && len(run) > rs.maxRun {
			rs.err = ErrQueryTooBroad
			return nil, false
		}
	}
	if rs.record {
		if start > 0 {
			rs.touched = append(rs.touched, start-1)
		}
		for j := start; j < i; j++ {
			rs.touched = append(rs.touched, j)
		}
		if i < rs.reader.EntryCount {
			rs.touched = append(rs.touched, i)
		}
	}
	return run, true
}

// matcherProcess evaluates a pattern on one index table: it derives the
// candidate positions from the table's entry runs, loads the block data of the
// candidates and, when proving, collects the proof material of the blocks and
// transactions they point to.
type matcherProcess struct {
	chainView ChainView
	reader    *logindex.TableReader
	prover    *tableProver
	pattern   PatternMatcher
	reverse   bool
	maxRun    int

	matches        []*types.Log // matching logs in scan order
	blockProofs    map[uint64]*blockProof
	curHeader      *types.Header
	curBody        *types.Body
	curReceipts    types.Receipts
	curBlockProof  *blockProof
	curLogsOffsets []uint32 // block-global log index of each transaction's first log
}

// scan evaluates the pattern on the table between begin and end. It stops
// after the block in which the number of matches reaches limit has been fully
// processed and returns that block number, or nil if the limit was not
// reached.
func (mp *matcherProcess) scan(ctx context.Context, pattern PatternMatcher, begin, end types.IndexPosition, limit int) (*uint64, error) {
	src := &readerSource{ctx: ctx, reader: mp.reader, record: mp.prover != nil, maxRun: mp.maxRun}
	candidates, ok := pattern.candidates(src, begin, end)
	if src.err != nil {
		return nil, src.err
	}
	if !ok {
		return nil, errors.New("the pattern cannot be evaluated on the index")
	}
	if mp.maxRun > 0 && len(candidates) > mp.maxRun {
		return nil, ErrQueryTooBroad
	}
	var cut *uint64
	for n := range candidates {
		pos := candidates[n]
		if mp.reverse {
			pos = candidates[len(candidates)-1-n]
		}
		if cut != nil && pos.BlockNumber != *cut {
			break
		}
		if n%256 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		matched, err := mp.processCandidate(pos)
		if err != nil {
			return nil, err
		}
		if matched && cut == nil && len(mp.matches) >= limit {
			block := pos.BlockNumber
			cut = &block
		}
	}
	if err := mp.finishBlock(); err != nil {
		return nil, err
	}
	if mp.prover != nil {
		touched := src.touched
		if cut != nil {
			// only the part of the table up to the cut block is proven: record
			// the entries of that shorter range instead
			cutBegin, cutEnd := begin, end
			if mp.reverse {
				cutBegin = types.IndexPosition{BlockNumber: *cut}
			} else {
				cutEnd = types.IndexPosition{BlockNumber: *cut, TxIndex: math.MaxUint32, LogIndex: math.MaxUint32}
			}
			cutSrc := &readerSource{ctx: ctx, reader: mp.reader, record: true, maxRun: mp.maxRun}
			pattern.candidates(cutSrc, cutBegin, cutEnd)
			if cutSrc.err != nil {
				return nil, cutSrc.err
			}
			touched = cutSrc.touched
		}
		mp.prover.valueEntries = touched
	}
	return cut, nil
}

// loadBlock loads the chain data of the block of a candidate and initializes
// its block proof when proving.
func (mp *matcherProcess) loadBlock(number uint64) error {
	if mp.curHeader != nil {
		if mp.curHeader.Number.Uint64() == number {
			return nil
		}
		if err := mp.finishBlock(); err != nil {
			return err
		}
	}
	header := mp.chainView.Header(number)
	if header == nil {
		return errors.New("header of block #" + itoa(number) + " not found")
	}
	body := mp.chainView.Body(number)
	if body == nil {
		return errors.New("body of block #" + itoa(number) + " not found")
	}
	receipts := mp.chainView.RawReceipts(number)
	if receipts == nil {
		return errors.New("receipts of block #" + itoa(number) + " not found")
	}
	if len(receipts) != len(body.Transactions) {
		return errors.New("receipt count of block #" + itoa(number) + " does not match its transactions")
	}
	if err := receipts.DeriveFields(mp.chainConfig(), header.Hash(), number, header.Time, header.BaseFee, nil, body.Transactions); err != nil {
		return err
	}
	mp.curHeader, mp.curBody, mp.curReceipts = header, body, receipts
	mp.curLogsOffsets = make([]uint32, len(receipts))
	var offset uint32
	for i, receipt := range receipts {
		mp.curLogsOffsets[i] = offset
		offset += uint32(len(receipt.Logs))
	}
	if mp.prover != nil {
		// candidate in a block that is not proven yet; initialize its block proof
		if number == mp.reader.BlockRange().Last() {
			mp.curBlockProof = newBlockProof(header, math.MaxUint64)
		} else {
			blockEntry := types.EncodeEntry(types.EntryTypeBlock, header.Hash().Bytes(), number, 0, 0)
			blockEntryIndex, found, err := mp.reader.SeekEntry(blockEntry)
			if err != nil {
				return err
			}
			if !found {
				return errors.New("could not find block entry index")
			}
			mp.curBlockProof = newBlockProof(header, blockEntryIndex)
		}
	}
	return nil
}

// finishBlock records the receipts proof of the pending block.
func (mp *matcherProcess) finishBlock() error {
	if mp.curHeader == nil {
		return nil
	}
	if mp.curBlockProof != nil {
		mp.curBlockProof.createProof(mp.curReceipts)
		mp.blockProofs[mp.curHeader.Number.Uint64()] = mp.curBlockProof
		mp.curBlockProof = nil
	}
	mp.curHeader, mp.curBody, mp.curReceipts, mp.curLogsOffsets = nil, nil, nil, nil
	return nil
}

// chainConfig returns the chain config used to derive the receipt fields;
// derivation needs it only for blob fee computation, which is nil here (the
// derived log fields do not depend on gas prices).
func (mp *matcherProcess) chainConfig() *params.ChainConfig {
	return params.MainnetChainConfig
}

func itoa(n uint64) string {
	return strconv.FormatUint(n, 10)
}

// processCandidate loads the candidate's transaction, registers its proof
// material and records the log if it matches the pattern. A candidate whose
// log index lies beyond the receipt's logs (a position derived through an
// offset matcher) matches nothing, but its transaction is still proven.
func (mp *matcherProcess) processCandidate(pos types.IndexPosition) (bool, error) {
	if err := mp.loadBlock(pos.BlockNumber); err != nil {
		return false, err
	}
	if int(pos.TxIndex) >= len(mp.curReceipts) {
		return false, errors.New("transaction index out of range")
	}
	receipt := mp.curReceipts[pos.TxIndex]
	if mp.prover != nil {
		blockProof := mp.curBlockProof
		if _, ok := blockProof.matchingTxs[pos.TxIndex]; !ok {
			// candidate in a transaction that is not proven yet; initialize its proof
			txEntry := types.EncodeEntry(types.EntryTypeTransaction, receipt.TxHash[:], pos.BlockNumber, pos.TxIndex, mp.curLogsOffsets[pos.TxIndex])
			txEntryIndex, found, err := mp.reader.SeekEntry(txEntry)
			if err != nil {
				return false, err
			}
			if !found {
				return false, errors.New("could not find transaction entry index at block " + itoa(pos.BlockNumber) + " tx " + itoa(uint64(pos.TxIndex)))
			}
			blockProof.matchingTxs[pos.TxIndex] = matchingTx{txEntryIndex: txEntryIndex}
		}
	}
	// the pattern is evaluated on the receipt's logs exactly as the verifier
	// evaluates it on the proven receipt
	if int(pos.LogIndex) >= len(receipt.Logs) {
		return false, nil
	}
	return mp.recordMatch(pos, receipt), nil
}

// recordMatch appends the log at the position to the matches if it matches.
func (mp *matcherProcess) recordMatch(pos types.IndexPosition, receipt *types.Receipt) bool {
	if !mp.pattern.matchLogs(receipt.Logs, int(pos.LogIndex)) {
		return false
	}
	log := receipt.Logs[pos.LogIndex]
	mp.matches = append(mp.matches, &types.Log{
		Address:        log.Address,
		Topics:         log.Topics,
		Data:           log.Data,
		BlockNumber:    pos.BlockNumber,
		TxHash:         receipt.TxHash,
		TxIndex:        uint(pos.TxIndex),
		BlockHash:      mp.curHeader.Hash(),
		BlockTimestamp: mp.curHeader.Time,
		Index:          uint(mp.curLogsOffsets[pos.TxIndex]) + uint(pos.LogIndex),
	})
	return true
}
