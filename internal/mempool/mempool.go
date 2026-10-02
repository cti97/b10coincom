// Package mempool holds validated transactions waiting to be included in a
// block.
package mempool

import (
	"errors"
	"sync"

	"github.com/cti97/b10coincom/internal/types"
)

var (
	ErrDuplicate = errors.New("mempool: transaction already present")
	ErrFull      = errors.New("mempool: at capacity")
)

// Mempool is a bounded, deduplicated set of pending transactions. It is
// safe for concurrent use: mu guards every field, because one process may
// serve the RPC server (Add via POST /tx, Len via GET /status) while the
// node loop runs Take.
type Mempool struct {
	max  int
	mu   sync.RWMutex
	txs  []types.Tx
	seen map[[32]byte]struct{}
}

func New(max int) *Mempool {
	return &Mempool{max: max, seen: make(map[[32]byte]struct{})}
}

// Add validates signatures and inserts transactions, returning one error per
// input in the same order. Insertion of one transaction never blocks another.
func (m *Mempool) Add(txs []types.Tx) []error {
	m.mu.Lock()
	defer m.mu.Unlock()
	errs := make([]error, len(txs))
	for i := range txs {
		tx := txs[i]
		if err := tx.VerifySignature(); err != nil {
			errs[i] = err
			continue
		}
		id := tx.ID()
		if _, dup := m.seen[id]; dup {
			errs[i] = ErrDuplicate
			continue
		}
		if len(m.txs) >= m.max {
			errs[i] = ErrFull
			continue
		}
		m.txs = append(m.txs, tx)
		m.seen[id] = struct{}{}
	}
	return errs
}

// Take removes and returns up to max transactions.
func (m *Mempool) Take(max int) []types.Tx {
	m.mu.Lock()
	defer m.mu.Unlock()
	if max > len(m.txs) {
		max = len(m.txs)
	}
	out := make([]types.Tx, max)
	copy(out, m.txs[:max])
	for i := range out {
		delete(m.seen, out[i].ID())
	}
	m.txs = append([]types.Tx(nil), m.txs[max:]...)
	return out
}

// Remove drops a transaction by ID, used when a block includes it.
func (m *Mempool) Remove(id [32]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.seen[id]; !ok {
		return
	}
	delete(m.seen, id)
	for i := range m.txs {
		if m.txs[i].ID() == id {
			m.txs = append(m.txs[:i], m.txs[i+1:]...)
			return
		}
	}
}

func (m *Mempool) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.txs)
}
