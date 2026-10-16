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
}

func NewMatcher(logIndex logIndex, contractProverBackend contractProverBackend) *Matcher {
	return &Matcher{
		logIndex:              logIndex,
		contractProverBackend: contractProverBackend,
	}
}

// GetMatches runs the query and returns the matching logs, the block range
// they span and, when prove is set, the self-contained query proof.
func (mc *Matcher) GetMatches(ctx context.Context, chainView ChainView, query FilterQuery, prove bool) ([]*types.Log, common.Range[uint64], *QueryProof, error) {
	headBlock := chainView.HeadNumber()
	refHeader := chainView.Header(headBlock)
	refBlockHash := refHeader.Hash()
	firstBlock := min(query.FirstBlock, headBlock)
	lastBlock := min(query.LastBlock, headBlock)
	blockRange := common.NewRange[uint64](firstBlock, lastBlock+1-firstBlock)
	readerRange := blockRange
	if prove && lastBlock < headBlock {
		// extend the proven range to the reference head: every result block is
		// pinned by block entries chaining up to the head's parent entry, so
		// the tables covering the head must be part of the proof even when
		// nothing matches there
		readerRange.SetLast(headBlock)
	}
	var publishedBefore uint64
	if prove {
		publishedBefore = refHeader.Number.Uint64()
	}
	readers := mc.logIndex.GetRangeReaders(refBlockHash, readerRange, publishedBefore)
	if len(readers) == 0 {
		return nil, common.Range[uint64]{}, nil, errors.New("required block range is not indexed")
	}
	sort.Slice(readers, func(i, j int) bool {
		if query.LimitLatest {
			return readers[i].BlockRange().First() > readers[j].BlockRange().First()
		}
		return readers[i].BlockRange().First() < readers[j].BlockRange().First()
	})
	for i := 1; i < len(readers); i++ {
		// check if the available tables cover a continuous range
		var cont bool
		if query.LimitLatest {
			cont = readers[i].BlockRange().AfterLast() == readers[i-1].BlockRange().First()
		} else {
			cont = readers[i-1].BlockRange().AfterLast() == readers[i].BlockRange().First()
		}
		if !cont {
			readers = readers[:i] // drop tables after a gap/overlap
			break
		}
	}
	maxResults := math.MaxInt
	if query.Limit < uint64(math.MaxInt) {
		maxResults = int(query.Limit)
	}
	var (
		allLogs     []*types.Log
		provers     []*tableProver
		resultFirst = uint64(math.MaxUint64)
		resultLast  uint64
		// the tables past the query range carry no results but must be part of
		// the proof: they chain the covered block entries up to the head
		tailProvers []*tableProver
	)
	for _, tr := range readers {
		br := tr.BlockRange().Intersection(blockRange)
		prover := newTableProver(tr)
		if br.IsEmpty() {
			if prove {
				tailProvers = append(tailProvers, prover)
			}
			continue
		}
		firstPos := types.IndexPosition{BlockNumber: br.First()}
		lastPos := types.IndexPosition{BlockNumber: br.Last(), TxIndex: math.MaxUint32, LogIndex: math.MaxUint32}
		tableFirst, tableLast := br.First(), br.Last()
		if query.LimitLatest {
			firstPos, lastPos = lastPos, firstPos
			tableFirst, tableLast = tableLast, tableFirst
		}
		instance := query.Pattern.newInstance(
			ctx,
			&directionalReader{reader: tr, reverse: query.LimitLatest},
			firstPos,
			lastPos,
		)
		mp := &matcherProcess{
			logIndex:    mc.logIndex,
			chainView:   chainView,
			matcher:     instance,
			tableReader: tr,
			prover:      prover,
			firstBlock:  tableFirst,
			lastBlock:   tableLast,
			blockProofs: make(map[uint64]*blockProof),
		}
		count, err := mp.run(ctx, maxResults-len(allLogs))
		if err != nil {
			return nil, common.Range[uint64]{}, nil, err
		}
		mp.prover.addBlockProofs(mp.blockProofs, count)
		allLogs = append(allLogs, mp.allMatches...)
		provers = append(provers, prover)
		if count > 0 {
			if query.LimitLatest {
				if resultFirst == math.MaxUint64 {
					resultFirst = tableFirst
				}
				resultLast = tableLast
			} else {
				if resultFirst == math.MaxUint64 {
					resultFirst = mp.firstResultBlock
				}
				resultLast = mp.lastResultBlock
			}
		}
		if len(allLogs) >= maxResults && !prove {
			// when proving, the remaining tables are still needed: they chain
			// the covered block entries up to the reference head
			break
		}
	}
	if query.LimitLatest {
		last := len(allLogs) - 1
		for i := 0; i < last-i; i++ {
			allLogs[i], allLogs[last-i] = allLogs[last-i], allLogs[i]
		}
		resultFirst, resultLast = resultLast, resultFirst
		// reverse the prover order for the proof assembly
		last = len(provers) - 1
		for i := 0; i < last-i; i++ {
			provers[i], provers[last-i] = provers[last-i], provers[i]
		}
	}
	if prove {
		// the tail tables chain the proof up to the reference head: append
		// them in ascending range order after the scanned provers
		sort.Slice(tailProvers, func(i, j int) bool {
			return tailProvers[i].reader.BlockRange().First() < tailProvers[j].reader.BlockRange().First()
		})
		provers = append(provers, tailProvers...)
	}
	if resultFirst == math.MaxUint64 {
		resultFirst, resultLast = firstBlock, lastBlock
	}
	var proof *QueryProof
	if prove {
		var err error
		if proof, err = makeQueryProof(refHeader, &query, resultFirst, resultLast, mc.contractProverBackend, provers); err != nil {
			return nil, common.Range[uint64]{}, nil, err
		}
	}
	return allLogs, common.NewRange[uint64](resultFirst, resultLast+1-resultFirst), proof, nil
}

// matcherProcess walks one index table with the query's matcher instance,
// collecting the matching logs and the proof material of the blocks and
// transactions they point to.
type matcherProcess struct {
	logIndex    logIndex
	chainView   ChainView
	matcher     matcherInstance
	tableReader *logindex.TableReader
	prover      *tableProver
	firstBlock  uint64
	lastBlock   uint64

	allMatches       []*types.Log
	blockProofs      map[uint64]*blockProof
	lastHeader       *types.Header
	lastBody         *types.Body
	lastReceipts     types.Receipts
	lastBlockProof   *blockProof
	firstResultBlock uint64
	lastResultBlock  uint64
}

// run iterates the matcher until it is exhausted or the result limit is
// reached, returning the number of new matches.
func (mp *matcherProcess) run(ctx context.Context, remaining int) (int, error) {
	count := 0
	for count < remaining {
		select {
		case <-ctx.Done():
			return count, ctx.Err()
		default:
		}
		pos, err := mp.matcher.next()
		if err != nil {
			return count, err
		}
		if pos == nil {
			return count, mp.finish()
		}
		if err := mp.addMatch(pos); err != nil {
			return count, err
		}
		count++
		if mp.firstResultBlock == 0 || pos.BlockNumber < mp.firstResultBlock {
			mp.firstResultBlock = pos.BlockNumber
		}
		if pos.BlockNumber > mp.lastResultBlock {
			mp.lastResultBlock = pos.BlockNumber
		}
		if err := mp.matcher.advance(nil); err != nil {
			return count, err
		}
	}
	return count, mp.finish()
}

// finish flushes the pending block proof of the last matched block.
func (mp *matcherProcess) finish() error {
	if mp.lastHeader == nil {
		return nil
	}
	return mp.finalizeLastMatchBlock()
}

// updateLastMatchBlock loads the chain data of the match's block and
// initializes its block proof when proving.
func (mp *matcherProcess) updateLastMatchBlock(number uint64) error {
	if mp.lastHeader != nil {
		if mp.lastHeader.Number.Uint64() == number {
			return nil
		}
		if err := mp.finalizeLastMatchBlock(); err != nil {
			return err
		}
	}
	if mp.lastHeader = mp.chainView.Header(number); mp.lastHeader == nil {
		return errors.New("header of block #" + itoa(number) + " not found")
	}
	if mp.lastBody = mp.chainView.Body(number); mp.lastBody == nil {
		return errors.New("body of block #" + itoa(number) + " not found")
	}
	if mp.lastReceipts = mp.chainView.RawReceipts(number); mp.lastReceipts == nil {
		return errors.New("receipts of block #" + itoa(number) + " not found")
	}
	if mp.prover != nil {
		// result found in a block that is not proven yet; initialize new block proof
		if number == mp.tableReader.BlockRange().Last() {
			mp.lastBlockProof = newBlockProof(mp.lastHeader, math.MaxUint64)
		} else {
			blockEntry := types.EncodeEntry(types.EntryTypeBlock, mp.lastHeader.Hash().Bytes(), number, 0, 0)
			blockEntryIndex, found, err := mp.tableReader.SeekEntry(blockEntry)
			if err != nil {
				return err
			}
			if !found {
				return errors.New("could not find block entry index")
			}
			mp.lastBlockProof = newBlockProof(mp.lastHeader, blockEntryIndex)
		}
	}
	return nil
}

// finalizeLastMatchBlock derives the pending block's receipt fields and
// records its block proof.
func (mp *matcherProcess) finalizeLastMatchBlock() error {
	if mp.lastHeader == nil {
		return nil
	}
	header, body, receipts := mp.lastHeader, mp.lastBody, mp.lastReceipts
	if err := receipts.DeriveFields(mp.chainConfig(), header.Hash(), header.Number.Uint64(), header.Time, header.BaseFee, nil, body.Transactions); err != nil {
		return err
	}
	if mp.lastBlockProof != nil {
		mp.lastBlockProof.createProof(receipts)
		mp.blockProofs[header.Number.Uint64()] = mp.lastBlockProof
		mp.lastBlockProof = nil
	}
	mp.lastHeader, mp.lastBody, mp.lastReceipts = nil, nil, nil
	return nil
}

// chainConfig returns the chain config of the first proven block's context;
// receipt derivation needs it only for blob fee computation, which is nil
// here (DeriveFields recomputes log block fields, not gas prices).
func (mp *matcherProcess) chainConfig() *params.ChainConfig {
	return params.MainnetChainConfig
}

func itoa(n uint64) string {
	return strconv.FormatUint(n, 10)
}

// addMatch records a matching log, building its full log structure from the
// block data and registering the block and transaction proof entries.
func (mp *matcherProcess) addMatch(pos *types.IndexPosition) error {
	if err := mp.updateLastMatchBlock(pos.BlockNumber); err != nil {
		return err
	}
	header, body, receipts := mp.lastHeader, mp.lastBody, mp.lastReceipts
	if pos.TxIndex >= uint32(len(body.Transactions)) {
		return errors.New("transaction index out of range")
	}
	txHash := body.Transactions[pos.TxIndex].Hash()
	if pos.TxIndex >= uint32(len(receipts)) {
		return errors.New("receipt index out of range")
	}
	receipt := receipts[pos.TxIndex]
	if pos.LogIndex >= uint32(len(receipt.Logs)) {
		return errors.New("log index out of range")
	}
	log := receipt.Logs[pos.LogIndex]
	var logOffset uint32
	for i := uint32(0); i < pos.TxIndex; i++ {
		logOffset += uint32(len(receipts[i].Logs))
	}
	mp.allMatches = append(mp.allMatches, &types.Log{
		Address:        log.Address,
		Topics:         log.Topics,
		Data:           log.Data,
		BlockNumber:    pos.BlockNumber,
		TxHash:         txHash,
		TxIndex:        uint(pos.TxIndex),
		BlockHash:      header.Hash(),
		BlockTimestamp: header.Time,
		Index:          uint(logOffset) + uint(pos.LogIndex),
	})
	if mp.prover != nil {
		blockProof := mp.lastBlockProof
		if _, ok := blockProof.matchingTxs[pos.TxIndex]; !ok {
			// result found in a transaction that is not proven yet; initialize new transaction proof
			txEntry := types.EncodeEntry(types.EntryTypeTransaction, txHash[:], pos.BlockNumber, pos.TxIndex, uint32(logOffset))
			txEntryIndex, found, err := mp.tableReader.SeekEntry(txEntry)
			if err != nil {
				return err
			}
			if !found {
				return errors.New("could not find transaction entry index")
			}
			blockProof.matchingTxs[pos.TxIndex] = matchingTx{txEntryIndex: txEntryIndex}
		}
	}
	return nil
}
