package logquery

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/logindex"
	"github.com/ethereum/go-ethereum/core/types"
)

// logindexTableReader is the table reader type used in test signatures.
type logindexTableReader = logindex.TableReader

// memoryIndexer wraps the logindex memory indexer, exposing the
// GetRangeReaders the Matcher consumes.
type memoryIndexer struct {
	ix *logindex.Indexer
}

func newMemoryIndexerForTest() *memoryIndexer {
	return &memoryIndexer{ix: logindex.NewMemoryIndexer()}
}

func (m *memoryIndexer) AddBlockData(header *types.Header, body *types.Body, receipts types.Receipts) {
	m.ix.AddBlockData(header, body, receipts)
}

func (m *memoryIndexer) GetRangeReaders(refBlockHash common.Hash, blockRange common.Range[uint64], publishedBefore uint64) []*logindex.TableReader {
	// refBlockHash is not used in memory mode (no persisted state validation)
	return m.ix.GetRangeReaders(refBlockHash, blockRange, publishedBefore)
}

var _ = common.Hash{}
