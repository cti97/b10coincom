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

// MaxFaucetClaimsPerBlock bounds how many faucet claims the pool will hand to a
// single block. A claim costs a full Argon2id evaluation to verify - ~0.125 s
// at the testnet tuning (8 MiB × 1 pass; a Pi-4 estimate pending
// re-measurement, cost basis in Testnet's tuning comment) - while costing a
// submitter one Ed25519 signature, so without a bound a pool at the node's
// 10,000-transaction capacity full of signature-valid claims with garbage
// proofs would hand block production ~21 min of Argon2id work per block.
// Ordinary transactions are not bounded here: they are cheap to validate and
// the block size limits already cap them.
//
// The value 8 is a judgment call, not a derivation. At the testnet tuning it
// permits a worst-case block of 8 × ~0.125 s = ~1.0 s of Argon2id work against
// the 2_000 ms block interval, so it caps the amplification a flooder can force
// at roughly half the interval - unproven claims still fill the pool, but no
// block can be made to cost more than that ~1.0 s to accept or reject. Both
// figures are Pi-4 estimates pending re-measurement (Testnet's tuning comment
// carries the arithmetic), so the margin rides on one unverified number.
const MaxFaucetClaimsPerBlock = 8

// Mempool is a bounded, deduplicated set of pending transactions. It is
// safe for concurrent use: mu guards every field, because one process may
// serve the RPC server (Add via POST /tx, Len via GET /status) while the
// node loop runs Take.
type Mempool struct {
	max int
	// genesisHash is the chain identifier every transaction's signature is
	// bound to (audit S-1). Admission verifies against it, so a transaction
	// signed for another chain never enters this pool - it is refused for what
	// it is, at the door, rather than by the state machine later.
	genesisHash [32]byte
	mu          sync.RWMutex
	txs         []types.Tx
	seen        map[[32]byte]struct{}
}

// New builds a pool of max transactions for the chain identified by
// genesisHash. The identifier is a constructor argument, not a setter, so a
// pool can never be built and then wrongly wired: the compiler demands it.
func New(max int, genesisHash [32]byte) *Mempool {
	return &Mempool{max: max, genesisHash: genesisHash, seen: make(map[[32]byte]struct{})}
}

// Add validates signatures and inserts transactions, returning one error per
// input in the same order. Insertion of one transaction never blocks another.
func (m *Mempool) Add(txs []types.Tx) []error {
	m.mu.Lock()
	defer m.mu.Unlock()
	errs := make([]error, len(txs))
	for i := range txs {
		tx := txs[i]
		if err := tx.VerifySignature(m.genesisHash); err != nil {
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

// Take removes and returns up to max transactions, in insertion order. At
// most MaxFaucetClaimsPerBlock of them are faucet claims: each claim costs a
// full Argon2id evaluation to verify, so claims encountered beyond that bound
// are skipped and left in the pool for a later block instead of being handed
// over or dropped. A non-positive max removes nothing and returns an empty
// slice.
func (m *Mempool) Take(max int) []types.Tx {
	m.mu.Lock()
	defer m.mu.Unlock()
	if max <= 0 {
		return []types.Tx{}
	}
	var out, keep []types.Tx
	claims := 0
	for _, tx := range m.txs {
		// The total still respects max, and once it is reached everything
		// remaining stays in the pool - claims and transfers alike.
		if len(out) >= max {
			keep = append(keep, tx)
			continue
		}
		if tx.Type == types.TxFaucetClaim {
			claims++
			if claims > MaxFaucetClaimsPerBlock {
				keep = append(keep, tx)
				continue
			}
		}
		out = append(out, tx)
	}
	for i := range out {
		delete(m.seen, out[i].ID())
	}
	m.txs = keep
	// Preserve the pre-bounding contract: Take always returns a non-nil
	// slice, empty when the pool is empty or nothing qualified.
	if out == nil {
		out = []types.Tx{}
	}
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
