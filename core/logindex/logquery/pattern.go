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
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/logindex"
	"github.com/ethereum/go-ethereum/core/types"
)

// ErrMatchAll is returned for match-all queries: proving "everything" without
// any filter criterion is not a meaningful query.
var ErrMatchAll = errors.New("match-all queries not allowed")

// PatternMatcher defines a general abstraction for any matcher configuration
// that can instantiate a matcher instance operating on a single index table.
type PatternMatcher interface {
	newInstance(ctx context.Context, reader *directionalReader, first, last types.IndexPosition) matcherInstance
	matchLogs(logs []*types.Log, index int) bool
	proofMatches(tqp *tableQueryProof, begin, end types.IndexPosition) indexPositionSet
	json.Marshaler
}

// matcherInstance iterates over matching index positions of a single table in
// the specified range.
type matcherInstance interface {
	next() (*types.IndexPosition, error)
	advance(*types.IndexPosition) error
}

// matcherValue is the searchable content a matcher looks for: an entry type
// plus the raw content bytes (32 for block/transaction/topic, 20 for address).
type matcherValue struct {
	typ     uint32
	content []byte
}

// entryPrefixMatches tells whether the entry's type id and content match the
// matcher value, ignoring the position tail.
func (v matcherValue) entryPrefixMatches(entry types.IndexEntry) bool {
	if len(entry) != types.EntryTypeSize+len(v.content)+entryPositionTail(types.EntryType(v.typ)) {
		return false
	}
	if uint32(entry[0])<<8|uint32(entry[1]) != v.typ {
		return false
	}
	return slices.Equal(entry[types.EntryTypeSize:types.EntryTypeSize+len(v.content)], v.content)
}

func entryPositionTail(typ types.EntryType) int {
	if typ == types.EntryTypeBlock {
		return types.BlockNumberSize
	}
	return types.BlockNumberSize + types.TxIndexSize + types.LogIndexSize
}

// boundaryEntry builds the raw encoding of the value with the position tail
// set to p, used as a SeekEntry boundary.
func (v matcherValue) boundaryEntry(p types.IndexPosition) types.IndexEntry {
	return types.EncodeEntry(types.EntryType(v.typ), v.content, p.BlockNumber, p.TxIndex, p.LogIndex)
}

// entryPosition decodes the position of a table entry, panicking on malformed
// input: the entries always originate from the indexer's own tables.
func entryPosition(entry types.IndexEntry) types.IndexPosition {
	pos, err := types.PositionFromEntry(entry)
	if err != nil {
		panic("malformed index entry: " + err.Error())
	}
	return pos
}

// findInEntries binary searches sorted entries. Returns the smallest index
// whose entry is >= target and whether it is an exact match.
func findInEntries(entries []types.IndexEntry, target types.IndexEntry) (int, bool) {
	min, max := 0, len(entries)
	for min < max {
		mid := (min + max) / 2
		switch types.CompareEntries(entries[mid], target) {
		case -1:
			min = mid + 1
		case 0:
			return mid, true
		case 1:
			max = mid
		}
	}
	return min, false
}

// NewPatternMatcherFromJSON parses the recursive search pattern grammar: a
// leaf is {"field": "block|transaction|address|topics[i]", "value": hex},
// combinators are {"anyOf": [...]} / {"allOf": [...]} and a positional
// reference is {"offset": <pattern>, "amount": int}.
func NewPatternMatcherFromJSON(msg json.RawMessage) (PatternMatcher, error) {
	var p struct {
		Type   *string           `json:"field"`
		Value  *string           `json:"value"`
		Offset *json.RawMessage  `json:"offset"`
		Amount *int              `json:"amount"`
		AnyOf  []json.RawMessage `json:"anyOf"`
		AllOf  []json.RawMessage `json:"allOf"`
	}
	if err := json.Unmarshal(msg, &p); err != nil {
		return nil, err
	}
	if p.Type != nil || p.Value != nil {
		if p.Type == nil {
			return nil, errors.New("entry type missing")
		}
		if p.Value == nil {
			return nil, errors.New("entry value missing")
		}
		if len(p.AnyOf) != 0 || len(p.AllOf) != 0 || p.Offset != nil || p.Amount != nil {
			return nil, errors.New("both type/value and combinator fields specified")
		}
		value, err := hexutil.Decode(*p.Value)
		if err != nil {
			return nil, errors.New("invalid entry value hex string")
		}
		if len(value) > 32 {
			return nil, errors.New("entry value is longer than 32 bytes")
		}
		var (
			typ     uint32
			content []byte
		)
		switch {
		case *p.Type == "block":
			typ = uint32(types.EntryTypeBlock)
			content = make([]byte, 32)
			copy(content[32-len(value):], value)
		case *p.Type == "transaction":
			typ = uint32(types.EntryTypeTransaction)
			content = make([]byte, 32)
			copy(content[32-len(value):], value)
		case *p.Type == "address":
			typ = uint32(types.EntryTypeLogAddress)
			content = make([]byte, common.AddressLength)
			if len(value) == 32 {
				// the JSON round-trip emits left-padded 32-byte values
				copy(content, value[common.AddressLength:])
			} else {
				copy(content[common.AddressLength-len(value):], value)
			}
		case len(*p.Type) > 8 && (*p.Type)[:7] == "topics[" && (*p.Type)[len(*p.Type)-1:] == "]":
			topicIndex, err := strconv.Atoi((*p.Type)[7 : len(*p.Type)-1])
			if err != nil || topicIndex < 0 || topicIndex >= logindex.MaxTopicCount {
				return nil, errors.New("invalid topic index")
			}
			typ = uint32(types.EntryTypeLogTopic0) + uint32(topicIndex)
			content = make([]byte, 32)
			copy(content[32-len(value):], value)
		default:
			return nil, errors.New("unknown entry type")
		}
		return &singleMatcher{value: matcherValue{typ: typ, content: content}}, nil
	}
	if p.Offset != nil || p.Amount != nil {
		if p.Offset == nil {
			return nil, errors.New("offset type missing")
		}
		if p.Amount == nil {
			return nil, errors.New("amount value missing")
		}
		if len(p.AnyOf) != 0 || len(p.AllOf) != 0 {
			return nil, errors.New("both type/value and combinator fields specified")
		}
		child, err := NewPatternMatcherFromJSON(*p.Offset)
		if err != nil {
			return nil, err
		}
		return &offsetMatcher{child: child, offset: *p.Amount}, nil
	}
	if len(p.AnyOf) != 0 && len(p.AllOf) != 0 {
		return nil, errors.New("both anyOf and allOf fields specified")
	}
	if len(p.AnyOf) != 0 {
		m := make(matchAny, len(p.AnyOf))
		for i, msg := range p.AnyOf {
			pm, perr := NewPatternMatcherFromJSON(msg)
			if perr != nil {
				return nil, perr
			}
			m[i] = pm
		}
		return m, nil
	}
	if len(p.AllOf) != 0 {
		m := make(matchAll, len(p.AllOf))
		for i, msg := range p.AllOf {
			pm, perr := NewPatternMatcherFromJSON(msg)
			if perr != nil {
				return nil, perr
			}
			m[i] = pm
		}
		return m, nil
	}
	return nil, errors.New("empty pattern matcher is not allowed")
}

// NewLegacyMatcher builds a pattern from eth_getLogs style filter criteria:
// any of the given addresses with all of the given topic positions matching.
// Empty criteria yield ErrMatchAll.
func NewLegacyMatcher(addresses []common.Address, topics [][]common.Hash) (PatternMatcher, error) {
	matcher := make(matchAll, 0, len(topics)+1)
	if len(addresses) > 0 {
		matchAddress := make(matchAny, len(addresses))
		for i, address := range addresses {
			matchAddress[i] = &singleMatcher{value: matcherValue{
				typ:     uint32(types.EntryTypeLogAddress),
				content: address[:],
			}}
		}
		matcher = append(matcher, matchAddress)
	}
	for i, topicList := range topics {
		if len(topicList) > 0 {
			matchTopic := make(matchAny, len(topicList))
			for j, topic := range topicList {
				matchTopic[j] = &singleMatcher{value: matcherValue{
					typ:     uint32(types.EntryTypeLogTopic0) + uint32(i),
					content: topic[:],
				}}
			}
			matcher = append(matcher, matchTopic)
		}
	}
	if len(matcher) > 0 {
		return matcher, nil
	}
	return nil, ErrMatchAll
}

// singleMatcher matches a single log value.
type singleMatcher struct {
	value matcherValue
}

// singleMatcherInstance iterates the entries of one table matching the value,
// between the first and last positions.
type singleMatcherInstance struct {
	value       matcherValue
	ctx         context.Context
	reader      *directionalReader
	entryPtr    uint64
	initialized bool
	isEmpty     bool
	first, last types.IndexPosition
	currentPos  *types.IndexPosition
}

func (m *singleMatcher) newInstance(ctx context.Context, reader *directionalReader, first, last types.IndexPosition) matcherInstance {
	mi := &singleMatcherInstance{
		value:  m.value,
		ctx:    ctx,
		reader: reader,
		first:  first,
		last:   last,
	}
	if firstEntry, firstExists := reader.firstEntry(); firstExists {
		mi.entryPtr = firstEntry
	} else {
		mi.isEmpty = true
	}
	return mi
}

func (m *singleMatcher) matchLogs(logs []*types.Log, index int) bool {
	if index < 0 || index >= len(logs) {
		return false
	}
	log := logs[index]
	switch {
	case m.value.typ == uint32(types.EntryTypeLogAddress):
		return slices.Equal(log.Address[:], m.value.content)
	case m.value.typ >= uint32(types.EntryTypeLogTopic0) && m.value.typ < uint32(types.EntryTypeLogTopic0)+logindex.MaxTopicCount:
		i := int(m.value.typ) - int(types.EntryTypeLogTopic0)
		return len(log.Topics) > i && slices.Equal(log.Topics[i][:], m.value.content)
	default:
		panic("matchLogs only allowed for address/topic matchers")
	}
}

func (m *singleMatcher) proofMatches(tqp *tableQueryProof, begin, end types.IndexPosition) indexPositionSet {
	return tqp.getValueMatches(m.value.typ, m.value.content, begin, end)
}

func (m *singleMatcher) MarshalJSON() ([]byte, error) {
	enc := struct {
		Type  string      `json:"field"`
		Value common.Hash `json:"value"`
	}{}
	enc.Value = common.Hash{}
	copy(enc.Value[32-len(m.value.content):], m.value.content)
	switch {
	case m.value.typ == uint32(types.EntryTypeBlock):
		enc.Type = "block"
	case m.value.typ == uint32(types.EntryTypeTransaction):
		enc.Type = "transaction"
	case m.value.typ == uint32(types.EntryTypeLogAddress):
		enc.Type = "address"
	case m.value.typ >= uint32(types.EntryTypeLogTopic0) && m.value.typ < uint32(types.EntryTypeLogTopic0)+logindex.MaxTopicCount:
		enc.Type = "topics[" + strconv.Itoa(int(m.value.typ)-int(types.EntryTypeLogTopic0)) + "]"
	default:
		enc.Type = "unknown"
	}
	return json.Marshal(enc)
}

func (m *singleMatcherInstance) init() error {
	m.initialized = true
	if err := m.advance(&m.first); err != nil {
		m.initialized = false
		return err
	}
	return nil
}

// next returns the next matching position.
func (m *singleMatcherInstance) next() (*types.IndexPosition, error) {
	if !m.initialized {
		if err := m.init(); err != nil {
			return nil, err
		}
	}
	if m.currentPos == nil {
		if m.isEmpty {
			return nil, nil
		}
		entry, err := m.reader.getEntry(m.entryPtr)
		if err != nil {
			return nil, err
		}
		pos := entryPosition(entry)
		if !m.value.entryPrefixMatches(entry) || m.reader.comparePosition(&pos, &m.last) > 0 {
			m.isEmpty = true
			return nil, nil
		}
		m.currentPos = &pos
	}
	return m.currentPos, nil
}

// advance moves the iterator to the next matching position at or after the
// given position, or to the next entry when findPos is nil.
func (m *singleMatcherInstance) advance(findPos *types.IndexPosition) error {
	select {
	case <-m.ctx.Done():
		return m.ctx.Err()
	default:
	}
	if !m.initialized {
		if err := m.init(); err != nil {
			return err
		}
	}
	if m.isEmpty {
		return nil
	}
	m.currentPos = nil
	if findPos == nil {
		if nextEntry, ok := m.reader.prevNextEntry(m.entryPtr, true); ok {
			m.entryPtr = nextEntry
		} else {
			m.isEmpty = true
		}
		return nil
	}
	if m.reader.comparePosition(findPos, &m.last) > 0 {
		findPos = &m.last
	}
	target := m.value.boundaryEntry(*findPos)
	newEntryPtr, valid, err := m.reader.entryAtOrAfter(target)
	if err != nil {
		return err
	}
	if valid {
		m.entryPtr = newEntryPtr
	} else {
		m.isEmpty = true
	}
	return nil
}

// offsetMatcher matches the child pattern at the given log index offset
// relative to its own matches.
type offsetMatcher struct {
	child  PatternMatcher
	offset int
}

type offsetMatcherInstance struct {
	childInstance matcherInstance
	offset        int
	currentPos    *types.IndexPosition
	isEmpty       bool
}

func addOffset(pos *types.IndexPosition, offset int) bool {
	logIndex := int64(pos.LogIndex) + int64(offset)
	if logIndex < 0 {
		pos.LogIndex = 0
		return true
	}
	if logIndex > math.MaxUint32 {
		pos.LogIndex = math.MaxUint32
		return true
	}
	pos.LogIndex = uint32(logIndex)
	return false
}

func (m *offsetMatcher) newInstance(ctx context.Context, reader *directionalReader, first, last types.IndexPosition) matcherInstance {
	addOffset(&first, m.offset)
	addOffset(&last, m.offset)
	return &offsetMatcherInstance{
		childInstance: m.child.newInstance(ctx, reader, first, last),
		offset:        m.offset,
	}
}

func (m *offsetMatcher) matchLogs(logs []*types.Log, index int) bool {
	index += m.offset
	if index < 0 || index >= len(logs) {
		return false
	}
	return m.child.matchLogs(logs, index)
}

func (m *offsetMatcher) proofMatches(tqp *tableQueryProof, begin, end types.IndexPosition) indexPositionSet {
	addOffset(&begin, m.offset)
	addOffset(&end, m.offset)
	ips := m.child.proofMatches(tqp, begin, end)
	for i := range ips {
		addOffset(&ips[i].p, -m.offset)
	}
	return ips.filter(1)
}

func (m *offsetMatcher) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Offset PatternMatcher `json:"offset"`
		Amount int            `json:"amount"`
	}{
		Offset: m.child,
		Amount: m.offset,
	})
}

func (m *offsetMatcherInstance) next() (*types.IndexPosition, error) {
	if m.isEmpty {
		return nil, nil
	}
	if m.currentPos == nil {
		for {
			pos, err := m.childInstance.next()
			if err != nil {
				return nil, err
			}
			if pos == nil {
				m.isEmpty = true
				return nil, nil
			}
			current := *pos
			if !addOffset(&current, -m.offset) {
				m.currentPos = &current
				break
			}
			if err := m.childInstance.advance(nil); err != nil {
				return nil, err
			}
		}
	}
	return m.currentPos, nil
}

func (m *offsetMatcherInstance) advance(findPos *types.IndexPosition) error {
	if m.isEmpty {
		return nil
	}
	m.currentPos = nil
	if findPos == nil {
		return m.childInstance.advance(nil)
	}
	fpos := *findPos
	addOffset(&fpos, m.offset)
	return m.childInstance.advance(&fpos)
}

// matchAny combines a set of matchers and matches where any of them does.
type matchAny []PatternMatcher

type matchAnyInstance struct {
	children   []matcherInstance
	reader     *directionalReader
	currentPos *types.IndexPosition
	isEmpty    bool
}

func (m matchAny) newInstance(ctx context.Context, reader *directionalReader, first, last types.IndexPosition) matcherInstance {
	if len(m) == 1 {
		return m[0].newInstance(ctx, reader, first, last)
	}
	mi := &matchAnyInstance{
		children: make([]matcherInstance, len(m)),
		reader:   reader,
	}
	for i, mm := range m {
		mi.children[i] = mm.newInstance(ctx, reader, first, last)
	}
	return mi
}

func (m matchAny) matchLogs(logs []*types.Log, index int) bool {
	for _, mm := range m {
		if mm.matchLogs(logs, index) {
			return true
		}
	}
	return false
}

func (m matchAny) proofMatches(tqp *tableQueryProof, begin, end types.IndexPosition) indexPositionSet {
	childResults := make([]indexPositionSet, len(m))
	for i, mm := range m {
		childResults[i] = mm.proofMatches(tqp, begin, end)
	}
	return ipsUnion(childResults)
}

func (m matchAny) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		AnyOf []PatternMatcher `json:"anyOf"`
	}{m})
}

func (m *matchAnyInstance) next() (*types.IndexPosition, error) {
	if m.isEmpty || m.currentPos != nil {
		return m.currentPos, nil
	}
	for _, cm := range m.children {
		pos, err := cm.next()
		if err != nil {
			return nil, err
		}
		if pos != nil && (m.currentPos == nil || m.reader.comparePosition(m.currentPos, pos) == 1) {
			m.currentPos = pos
		}
	}
	m.isEmpty = m.currentPos == nil
	return m.currentPos, nil
}

func (m *matchAnyInstance) advance(findPos *types.IndexPosition) error {
	if m.isEmpty {
		return nil
	}
	if findPos == nil {
		currentPos, err := m.next()
		if err != nil {
			return err
		}
		if currentPos == nil {
			return nil
		}
		m.currentPos = nil
		for _, cm := range m.children {
			pos, _ := cm.next()
			if pos != nil && *pos == *currentPos {
				if err := cm.advance(nil); err != nil {
					return err
				}
			}
		}
		return nil
	}
	m.currentPos = nil
	for _, cm := range m.children {
		if err := cm.advance(findPos); err != nil {
			return err
		}
	}
	return nil
}

// matchAll combines a set of matchers and matches where all of them do.
type matchAll []PatternMatcher

type matchAllInstance struct {
	children   []matcherInstance
	reader     *directionalReader
	currentPos *types.IndexPosition
	isEmpty    bool
}

func (m matchAll) newInstance(ctx context.Context, reader *directionalReader, first, last types.IndexPosition) matcherInstance {
	if len(m) == 1 {
		return m[0].newInstance(ctx, reader, first, last)
	}
	mi := &matchAllInstance{
		children: make([]matcherInstance, len(m)),
		reader:   reader,
	}
	for i, mm := range m {
		mi.children[i] = mm.newInstance(ctx, reader, first, last)
	}
	return mi
}

func (m matchAll) matchLogs(logs []*types.Log, index int) bool {
	for _, mm := range m {
		if !mm.matchLogs(logs, index) {
			return false
		}
	}
	return true
}

func (m matchAll) proofMatches(tqp *tableQueryProof, begin, end types.IndexPosition) indexPositionSet {
	childResults := make([]indexPositionSet, len(m))
	for i, mm := range m {
		childResults[i] = mm.proofMatches(tqp, begin, end)
	}
	return ipsIntersection(childResults)
}

func (m matchAll) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		AllOf []PatternMatcher `json:"allOf"`
	}{m})
}

func (m *matchAllInstance) next() (*types.IndexPosition, error) {
	if m.isEmpty || m.currentPos != nil {
		return m.currentPos, nil
	}
	for {
		match := true
		var next *types.IndexPosition
		for i, cm := range m.children {
			pos, err := cm.next()
			if err != nil {
				return nil, err
			}
			if pos == nil {
				m.isEmpty = true
				return nil, nil
			}
			if i == 0 {
				next = pos
			} else {
				switch m.reader.comparePosition(next, pos) {
				case 1:
					match = false
				case -1:
					next = pos
					match = false
				}
			}
		}
		if match {
			m.currentPos = next
			return next, nil
		}
		for _, cm := range m.children {
			if pos, _ := cm.next(); *pos != *next {
				if err := cm.advance(next); err != nil {
					return nil, err
				}
			}
		}
	}
}

func (m *matchAllInstance) advance(findPos *types.IndexPosition) error {
	if m.isEmpty {
		return nil
	}
	if findPos == nil {
		if _, err := m.next(); err != nil {
			return err
		}
	}
	m.currentPos = nil
	for _, cm := range m.children {
		if err := cm.advance(findPos); err != nil {
			return err
		}
	}
	return nil
}

// directionalReader iterates a table's entries forward or in reverse.
type directionalReader struct {
	reader  *logindex.TableReader
	reverse bool
}

func (dr *directionalReader) firstEntry() (uint64, bool) {
	if dr.reader.EntryCount == 0 {
		return 0, false
	}
	if dr.reverse {
		return dr.reader.EntryCount - 1, true
	}
	return 0, true
}

func (dr *directionalReader) prevNextEntry(entryIndex uint64, next bool) (uint64, bool) {
	if dr.reverse == next {
		if entryIndex == 0 {
			return 0, false
		}
		return entryIndex - 1, true
	}
	if entryIndex+1 >= dr.reader.EntryCount {
		return 0, false
	}
	return entryIndex + 1, true
}

func (dr *directionalReader) entryAtOrAfter(target types.IndexEntry) (uint64, bool, error) {
	pos, found, err := dr.reader.SeekEntry(target)
	if err != nil {
		return 0, false, err
	}
	if dr.reverse {
		if !found {
			if pos == 0 {
				return 0, false, nil
			}
			pos--
		}
		return pos, true, nil
	}
	if pos >= dr.reader.EntryCount {
		return 0, false, nil
	}
	return pos, true, nil
}

func (dr *directionalReader) comparePosition(a, b *types.IndexPosition) int {
	cmp := a.Compare(*b)
	if dr.reverse {
		return -cmp
	}
	return cmp
}

func (dr *directionalReader) getEntry(index uint64) (types.IndexEntry, error) {
	return dr.reader.GetEntry(index)
}
