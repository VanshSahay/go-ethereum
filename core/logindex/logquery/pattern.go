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
	"bytes"
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

const (
	// maxPatternDepth and maxPatternNodes bound the size of a search pattern
	// parsed from untrusted JSON.
	maxPatternDepth = 16
	maxPatternNodes = 1024

	// maxOffsetAmount bounds the log index offset of an offset matcher.
	maxOffsetAmount = math.MaxInt32
)

// ErrMatchAll is returned for match-all queries: proving every log of every
// block without any filter criterion is not a meaningful query.
var ErrMatchAll = errors.New("match-all queries not allowed")

// PatternMatcher is a search pattern over the logs of a block range. A pattern
// is evaluated in two independent ways that must agree:
//
//   - matchLogs decides whether a log of a receipt matches, from the receipt
//     alone;
//   - candidates derives from index entry runs a set of log positions that is
//     guaranteed to contain every matching position.
//
// A result is a candidate position whose log matches. The prover builds the
// proof from the candidates and the verifier recomputes them from the proven
// entries, so a position the entries do not rule out can only be accepted or
// rejected on the strength of its receipt.
type PatternMatcher interface {
	matchLogs(logs []*types.Log, index int) bool
	candidates(src runSource, begin, end types.IndexPosition) (indexPositionSet, bool)
	json.Marshaler
}

// runSource supplies the entry runs a pattern is evaluated on: the proven
// entries of a table proof on the verifier side, the table reader on the
// prover side.
type runSource interface {
	// valueRun returns the positions of all entries of the given type and
	// content within [begin, end], in ascending order. It reports false when
	// the source cannot guarantee that the run is complete.
	valueRun(typ uint32, content []byte, begin, end types.IndexPosition) (indexPositionSet, bool)
}

// matcherValue is the searchable content of a leaf matcher: an entry type plus
// the raw content bytes (20 for an address, 32 for a topic).
type matcherValue struct {
	typ     uint32
	content []byte
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
// leaf is {"field": "address|topics[i]", "value": hex}, combinators are
// {"anyOf": [...]} / {"allOf": [...]} and a positional reference is
// {"offset": <pattern>, "amount": int}.
func NewPatternMatcherFromJSON(msg json.RawMessage) (PatternMatcher, error) {
	nodes := 0
	return parsePattern(msg, 0, &nodes)
}

func parsePattern(msg json.RawMessage, depth int, nodes *int) (PatternMatcher, error) {
	if depth > maxPatternDepth {
		return nil, errors.New("pattern is nested too deeply")
	}
	if *nodes++; *nodes > maxPatternNodes {
		return nil, errors.New("pattern is too large")
	}
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
		return newLeafMatcher(*p.Type, value)
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
		if *p.Amount > maxOffsetAmount || *p.Amount < -maxOffsetAmount {
			return nil, errors.New("offset amount out of range")
		}
		child, err := parsePattern(*p.Offset, depth+1, nodes)
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
			pm, err := parsePattern(msg, depth+1, nodes)
			if err != nil {
				return nil, err
			}
			m[i] = pm
		}
		return m, nil
	}
	if len(p.AllOf) != 0 {
		m := make(matchAll, len(p.AllOf))
		for i, msg := range p.AllOf {
			pm, err := parsePattern(msg, depth+1, nodes)
			if err != nil {
				return nil, err
			}
			m[i] = pm
		}
		return m, nil
	}
	return nil, errors.New("empty pattern matcher is not allowed")
}

// newLeafMatcher builds a leaf matcher from its field name and value. An
// address is exactly 20 bytes (or 20 bytes right-padded with zeros to 32); a
// topic is up to 32 bytes, right-padded with zeros.
func newLeafMatcher(field string, value []byte) (PatternMatcher, error) {
	if len(value) > common.HashLength {
		return nil, errors.New("entry value is longer than 32 bytes")
	}
	switch {
	case field == "address":
		content := make([]byte, common.AddressLength)
		switch {
		case len(value) == common.AddressLength:
			copy(content, value)
		case len(value) == common.HashLength && !slices.ContainsFunc(value[common.AddressLength:], func(b byte) bool { return b != 0 }):
			copy(content, value[:common.AddressLength])
		default:
			return nil, errors.New("invalid address length")
		}
		return &singleMatcher{value: matcherValue{typ: uint32(types.EntryTypeLogAddress), content: content}}, nil
	case len(field) > 8 && field[:7] == "topics[" && field[len(field)-1:] == "]":
		topicIndex, err := strconv.Atoi(field[7 : len(field)-1])
		if err != nil || topicIndex < 0 || topicIndex >= logindex.MaxTopicCount {
			return nil, errors.New("invalid topic index")
		}
		content := make([]byte, common.HashLength)
		copy(content, value)
		return &singleMatcher{value: matcherValue{typ: uint32(types.EntryTypeLogTopic0) + uint32(topicIndex), content: content}}, nil
	}
	return nil, errors.New("unknown entry type")
}

// normalizePattern collapses single-element combinators so that equivalent
// patterns written differently (for example a lone leaf versus the allOf/anyOf
// nesting an eth_getLogs style filter is lowered to) compare equal.
func normalizePattern(m PatternMatcher) PatternMatcher {
	switch m := m.(type) {
	case matchAny:
		children := make(matchAny, len(m))
		for i, child := range m {
			children[i] = normalizePattern(child)
		}
		if len(children) == 1 {
			return children[0]
		}
		return children
	case matchAll:
		children := make(matchAll, len(m))
		for i, child := range m {
			children[i] = normalizePattern(child)
		}
		if len(children) == 1 {
			return children[0]
		}
		return children
	case *offsetMatcher:
		return &offsetMatcher{child: normalizePattern(m.child), offset: m.offset}
	}
	return m
}

// NewLegacyMatcher builds a pattern from eth_getLogs style filter criteria:
// any of the given addresses with all of the given topic positions matching.
// Empty criteria yield ErrMatchAll.
func NewLegacyMatcher(addresses []common.Address, topics [][]common.Hash) (PatternMatcher, error) {
	if len(topics) > logindex.MaxTopicCount {
		return nil, errors.New("too many topic positions")
	}
	matcher := make(matchAll, 0, len(topics)+1)
	if len(addresses) > 0 {
		matchAddress := make(matchAny, len(addresses))
		for i, address := range addresses {
			matchAddress[i] = &singleMatcher{value: matcherValue{
				typ:     uint32(types.EntryTypeLogAddress),
				content: slices.Clone(address[:]),
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
					content: slices.Clone(topic[:]),
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

// singleMatcher matches a single log value: an address or a topic.
type singleMatcher struct {
	value matcherValue
}

func (m *singleMatcher) matchLogs(logs []*types.Log, index int) bool {
	if index < 0 || index >= len(logs) {
		return false
	}
	log := logs[index]
	if m.value.typ == uint32(types.EntryTypeLogAddress) {
		return bytes.Equal(log.Address[:], m.value.content)
	}
	i := int(m.value.typ) - int(types.EntryTypeLogTopic0)
	return len(log.Topics) > i && bytes.Equal(log.Topics[i][:], m.value.content)
}

func (m *singleMatcher) candidates(src runSource, begin, end types.IndexPosition) (indexPositionSet, bool) {
	return src.valueRun(m.value.typ, m.value.content, begin, end)
}

func (m *singleMatcher) MarshalJSON() ([]byte, error) {
	enc := struct {
		Type  string        `json:"field"`
		Value hexutil.Bytes `json:"value"`
	}{Value: m.value.content}
	if m.value.typ == uint32(types.EntryTypeLogAddress) {
		enc.Type = "address"
	} else {
		enc.Type = "topics[" + strconv.Itoa(int(m.value.typ)-int(types.EntryTypeLogTopic0)) + "]"
	}
	return json.Marshal(enc)
}

// offsetMatcher matches the child pattern at the given log index offset
// relative to its own matches: it matches log i of a receipt when the child
// matches log i+offset. It never matches when i+offset is negative.
type offsetMatcher struct {
	child  PatternMatcher
	offset int
}

// addOffset shifts the log index of a position, reporting true when the result
// is outside the log index range (the position is then clamped).
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

func (m *offsetMatcher) matchLogs(logs []*types.Log, index int) bool {
	index += m.offset
	if index < 0 || index >= len(logs) {
		return false
	}
	return m.child.matchLogs(logs, index)
}

func (m *offsetMatcher) candidates(src runSource, begin, end types.IndexPosition) (indexPositionSet, bool) {
	// the child is evaluated over the shifted range; a clamped bound only
	// widens the child's range, which is harmless
	addOffset(&begin, m.offset)
	addOffset(&end, m.offset)
	set, ok := m.child.candidates(src, begin, end)
	if !ok {
		return nil, false
	}
	shifted := make(indexPositionSet, 0, len(set))
	for _, p := range set {
		// a child position that maps to a negative log index cannot be
		// matched by this pattern
		if !addOffset(&p, -m.offset) {
			shifted = append(shifted, p)
		}
	}
	return shifted, true
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

// matchAny combines a set of matchers and matches where any of them does.
type matchAny []PatternMatcher

func (m matchAny) matchLogs(logs []*types.Log, index int) bool {
	for _, mm := range m {
		if mm.matchLogs(logs, index) {
			return true
		}
	}
	return false
}

// candidates is the union of the children's candidates; every child must be
// bounded, otherwise a match could hide in the unbounded one.
func (m matchAny) candidates(src runSource, begin, end types.IndexPosition) (indexPositionSet, bool) {
	sets := make([]indexPositionSet, len(m))
	for i, mm := range m {
		set, ok := mm.candidates(src, begin, end)
		if !ok {
			return nil, false
		}
		sets[i] = set
	}
	return ipsUnion(sets), true
}

func (m matchAny) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		AnyOf []PatternMatcher `json:"anyOf"`
	}{m})
}

// matchAll combines a set of matchers and matches where all of them do.
type matchAll []PatternMatcher

func (m matchAll) matchLogs(logs []*types.Log, index int) bool {
	for _, mm := range m {
		if !mm.matchLogs(logs, index) {
			return false
		}
	}
	return true
}

// candidates is the intersection of the candidates of the bounded children: a
// match matches every child, so one bounded child is enough to bound the
// pattern, and each further bounded child only narrows the set.
func (m matchAll) candidates(src runSource, begin, end types.IndexPosition) (indexPositionSet, bool) {
	var sets []indexPositionSet
	for _, mm := range m {
		if set, ok := mm.candidates(src, begin, end); ok {
			sets = append(sets, set)
		}
	}
	if len(sets) == 0 {
		return nil, false
	}
	return ipsIntersection(sets), true
}

func (m matchAll) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		AllOf []PatternMatcher `json:"allOf"`
	}{m})
}
