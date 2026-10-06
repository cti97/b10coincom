// Package mempool holds validated transactions waiting to be included in a
// block.
//
// Admission is STATEFUL (audit R-1). A transaction is judged against the head
// state a block would execute now, before the pool pays for anything, so a
// faucet claim whose epoch, claim marker, nonce or cheap outer puzzle is wrong
// never enters - and never costs the node an Argon2id evaluation later. The
// pool also reserves capacity for ordinary transfers so a claim flood cannot
// wedge the ingest path.
package mempool

import (
	"errors"
	"fmt"
	"sync"

	"github.com/cti97/b10coincom/internal/faucet"
	"github.com/cti97/b10coincom/internal/state"
	"github.com/cti97/b10coincom/internal/types"
)

var (
	ErrDuplicate = errors.New("mempool: transaction already present")
	ErrFull      = errors.New("mempool: at capacity")
	// ErrClaimPoolFull reports that the faucet-claim sub-pool is full. The pool
	// reserves room for ordinary transfers, so this is the bound a claim flood
	// hits instead of consuming the whole pool (audit R-1).
	ErrClaimPoolFull = errors.New("mempool: faucet-claim sub-pool is full")
	// ErrSenderLimit reports that one sender already holds its share of the
	// pool. Counting pending transactions per sender is what makes the cap
	// stateful: a stateless per-transaction ceiling is bypassed by sending more
	// transactions, a per-sender count is not (audit R-1).
	ErrSenderLimit = errors.New("mempool: too many pending transactions from this sender")
	// ErrBadPrePuzzle reports a faucet claim that did not solve the cheap outer
	// puzzle. It is rejected after ONE BLAKE3 hash, never an Argon2id
	// evaluation (audit R-1/S-4).
	ErrBadPrePuzzle = errors.New("mempool: faucet claim does not solve the cheap outer puzzle")
)

// MaxFaucetClaimsPerBlock bounds how many faucet claims the pool will hand to a
// single block. A claim costs a full Argon2id evaluation to verify - ~0.125 s
// at the testnet tuning (8 MiB x 1 pass; a Pi-4 estimate pending
// re-measurement, cost basis in Testnet's tuning comment) - and a block is
// attacker-chosen input, so without a bound a pool full of claims that passed
// the cheap outer puzzle would still hand block production a large multiple of
// Argon2id work per block. Ordinary transactions are not bounded here: they are
// cheap to validate and the block size limits already cap them.
//
// The value 8 is a judgment call, not a derivation. At the testnet tuning it
// permits a worst-case block of 8 x ~0.125 s = ~1.0 s of Argon2id work against
// the 2_000 ms block interval, so it caps the amplification a flooder can force
// at roughly half the interval. Both figures are Pi-4 estimates pending
// re-measurement (Testnet's tuning comment carries the arithmetic), so the
// margin rides on one unverified number.
const MaxFaucetClaimsPerBlock = 8

// MaxFaucetClaimsPerPool is the most faucet claims the pool holds at once,
// independent of its total capacity. The pool keeps the remaining slots for
// ordinary transfers, which is what stops a claim flood from making every
// honest POST /tx return ErrFull for the 1,250 blocks (about 42 minutes) it
// takes Take to drain a full pool at MaxFaucetClaimsPerBlock per block (audit
// R-1).
//
// The pool takes at most max/8 claims for capacities below
// 8*MaxFaucetClaimsPerPool, so a small pool still keeps most of its slots for
// transfers. The value 64 is a judgment call: at 8 claims per block it drains
// in 8 blocks (~16 s at the 2_000 ms interval), which bounds how long a claim
// flood can occupy the sub-pool.
const MaxFaucetClaimsPerPool = 64

// MaxClaimAgeBlocks is how many times Take may pass a faucet claim over before
// the pool drops it. Take runs once per block, so this is an age in blocks. It
// exists so a claim stuck behind a saturated per-block claim bound cannot hold
// a sub-pool slot forever (audit R-1).
//
// It is deliberately larger than the number of blocks a claim needs to drain a
// full sub-pool (MaxFaucetClaimsPerPool / MaxFaucetClaimsPerBlock = 8): an
// honest claim is handed to a block within a few blocks and is never skipped
// 32 times, so ageing never removes a pending transaction that a block would
// have taken. Nothing is ever evicted to make room for an arriving
// transaction; a full pool refuses it instead, so a fresh flood can never
// displace an older honest transaction.
const MaxClaimAgeBlocks = 32

// MaxPendingTransfersPerSender bounds how many ordinary transfers one sender
// may hold in the pool. The bound is on the sender's pending COUNT, not on one
// transaction, so more transactions do not bypass it. It does not stop a
// sender with many keys: every address gets its own allowance, and deriving
// fresh addresses is free (audit R-1, stated rather than implied).
const MaxPendingTransfersPerSender = 64

// maxPendingClaimsPerSender bounds faucet claims per address. One is enough:
// the state machine already allows one claim per key per epoch, and the pool
// admits a claim only for the current or the next epoch, so a second pending
// claim from the same key can only be a duplicate of that rule.
const maxPendingClaimsPerSender = 1

// HeadView returns the chain's head state and head height. The pool calls it
// once per Add batch, BEFORE any costly verification, to judge a transaction
// against the state a block would execute now (audit R-1). It is a function,
// not an interface, so a test can construct exactly the head it wants from a
// plain state.State and the pool imports no chain.
type HeadView func() (*state.State, uint64)

// entry is one pending transaction plus the bookkeeping admission and ageing
// need: its ID (computed once, at admission, so Remove/forget/Take never
// re-encode and re-hash the transaction - audit O-9), its sender (the address
// its signature is bound to) and how many times Take has passed it over.
type entry struct {
	tx      types.Tx
	id      [32]byte
	sender  types.Address
	skipped uint32
}

// Mempool is a bounded, deduplicated set of pending transactions. It is
// safe for concurrent use: mu guards every field, because one process may
// serve the RPC server (Add via POST /tx, Len via GET /status) while the
// node loop runs Take.
type Mempool struct {
	max         int
	maxClaims   int
	genesisHash [32]byte
	// head is the stateful view admission is judged against. It is set once at
	// construction and never replaced; the chain it closes over advances under
	// its own lock, and HeadView returns a consistent (state, height) pair.
	head HeadView
	// preTarget is the cheap outer puzzle's target admission checks a faucet
	// claim against. It is a LOCAL POLICY default (faucet.PreTarget), not a
	// genesis parameter: it changes no transaction byte and no state root. It
	// is a field, not a constant read at the call site, so a test can lower it
	// to isolate the stateful checks from the puzzle cost; the shipped value is
	// pinned by TestDefaultPreTargetIsTheFaucetPolicy.
	preTarget [32]byte
	// verifyHook, when non-nil, replaces the real signature check in verify. It
	// exists so a test can inject a blocking check and prove deterministically
	// that verification happens OUTSIDE the pool lock (audit S-10). It is nil in
	// production and unexported, so no caller outside this package can weaken
	// admission.
	verifyHook func(*types.Tx) error

	mu   sync.RWMutex
	txs  []entry
	seen map[[32]byte]struct{}
	// claims is the number of pending faucet claims; pending counts every
	// pending transaction per sender and pendingClaims only the claims.
	claims        int
	pending       map[types.Address]int
	pendingClaims map[types.Address]int
	// pendingNonces records the nonces of ordinary transfers already in the
	// pool, per sender. A transfer is admitted against head state, and head
	// state only advances when a block executes: two transactions from one
	// sender carrying the SAME nonce both pass the "not below the head nonce"
	// floor, so without this set both would sit in the pool, be handed to two
	// different block builders, and one would fail at execution time - or, on
	// one proposer, produce a block whose transactions cannot all apply. The
	// per-sender cap already bounds how MANY transfers one sender holds; this
	// set makes the nonces distinct. (audit S-9)
	pendingNonces map[types.Address]map[uint64]struct{}
}

// New builds a pool of max transactions for the chain identified by
// genesisHash, admitting against head. The view is a required constructor
// argument, not a setter, so a pool can never be built and then run without
// the stateful admission the chain depends on; passing nil panics, which is a
// wiring bug caught at startup rather than a silent hole in the ingest path.
func New(max int, genesisHash [32]byte, head HeadView) *Mempool {
	if head == nil {
		panic("mempool: New requires a head-state view; a pool that cannot see head state cannot admit (audit R-1)")
	}
	if max < 0 {
		max = 0
	}
	return &Mempool{
		max:           max,
		maxClaims:     claimCapacity(max),
		genesisHash:   genesisHash,
		head:          head,
		preTarget:     faucet.PreTarget(),
		seen:          make(map[[32]byte]struct{}),
		pending:       make(map[types.Address]int),
		pendingClaims: make(map[types.Address]int),
		pendingNonces: make(map[types.Address]map[uint64]struct{}),
	}
}

// claimCapacity is how many faucet claims a pool of max total slots will hold:
// at most MaxFaucetClaimsPerPool, and never more than one eighth of a smaller
// pool, so the majority of every pool stays available to ordinary transfers.
func claimCapacity(max int) int {
	c := MaxFaucetClaimsPerPool
	if eighth := max / 8; eighth < c {
		c = eighth
	}
	if c < 1 {
		c = 1
	}
	if c > max {
		c = max
	}
	return c
}

// verify runs one transaction's signature check. It is the only place the
// chain identifier meets the transaction, and it is a method so the test hook
// above can substitute a deterministic check without a caller ever being able
// to (audit S-10).
func (m *Mempool) verify(tx *types.Tx) error {
	if m.verifyHook != nil {
		return m.verifyHook(tx)
	}
	return tx.VerifySignature(m.genesisHash)
}

// Add validates and inserts transactions, returning one error per input in the
// same order. Insertion of one transaction never blocks another.
//
// Each transaction is checked in order: signature, duplicate, total capacity,
// then the stateful rule for its type. The head state is snapshotted once for
// the batch, because admission is a policy against the state the transactions
// arrived into and one consistent snapshot is what a batch deserves.
func (m *Mempool) Add(txs []types.Tx) []error {
	// Phase 1, WITHOUT the pool lock: every signature check. Ed25519
	// verification dominates the cost of admission, and a batch may carry
	// MaxTxsPerBlock = 10,000 transactions (the consensus driver's re-add after
	// a failed block). Holding the write lock across them - the pre-fix shape -
	// blocked /status (Len's RLock) and Take for seconds (audit S-10). m.verify
	// is immutable after New, so reading it here is safe.
	sigErrs := make([]error, len(txs))
	for i := range txs {
		sigErrs[i] = m.verify(&txs[i])
	}

	// Phase 2, under the lock: the cheap stateful admission and the inserts.
	// Everything that touches the pool's own maps - dedup, capacity, the
	// per-sender counts, the pending-nonce set - is serialised here, and the
	// head snapshot is taken here so a batch is judged against one consistent
	// state, exactly as before.
	m.mu.Lock()
	defer m.mu.Unlock()
	errs := make([]error, len(txs))
	st, headHeight := m.head()
	for i := range txs {
		if err := sigErrs[i]; err != nil {
			errs[i] = err
			continue
		}
		tx := txs[i]
		id := tx.ID()
		if _, dup := m.seen[id]; dup {
			errs[i] = ErrDuplicate
			continue
		}
		if len(m.txs) >= m.max {
			errs[i] = ErrFull
			continue
		}
		sender := tx.From
		switch tx.Type {
		case types.TxFaucetClaim:
			if err := m.admitClaim(&tx, st, headHeight); err != nil {
				errs[i] = err
				continue
			}
		case types.TxTransfer:
			if err := m.admitTransfer(&tx, st); err != nil {
				errs[i] = err
				continue
			}
		}
		m.insert(tx, id, sender)
	}
	return errs
}

// admitTransfer applies the stateful transfer rules. The per-sender cap is
// counted from the pool's own state, so it cannot be bypassed by sending more
// transactions; the nonce floor refuses a transfer whose replay counter has
// already been spent by the head state. A future nonce is still admitted: it
// may become applicable when its predecessors land, and the block filter is
// what evicts a transaction that never does.
func (m *Mempool) admitTransfer(tx *types.Tx, st *state.State) error {
	if m.pending[tx.From] >= MaxPendingTransfersPerSender {
		return fmt.Errorf("%w: %d pending from %x", ErrSenderLimit, m.pending[tx.From], tx.From[:])
	}
	if acc := st.Get(tx.From); tx.Nonce < acc.Nonce {
		return fmt.Errorf("%w: nonce %d, account nonce is %d", state.ErrBadNonce, tx.Nonce, acc.Nonce)
	}
	// The same nonce already pending from this sender: the two transactions
	// are distinct (their IDs differ, so dedup does not catch them) but only
	// one can ever execute at that nonce. Refuse the second here rather than
	// let a block carry a transaction it cannot apply. (audit S-9)
	if set := m.pendingNonces[tx.From]; set != nil {
		if _, dup := set[tx.Nonce]; dup {
			return fmt.Errorf("%w: nonce %d is already pending from %x", state.ErrBadNonce, tx.Nonce, tx.From[:])
		}
	}
	return nil
}

// admitClaim runs the cheap, stateful checks a faucet claim must pass before
// the pool keeps it. Every check here is a map lookup, a type comparison or one
// BLAKE3 hash; none is an Argon2id evaluation. That ordering is the fix: the
// expensive proof is only ever evaluated later, by a block builder, and only
// for claims that already cleared this door.
func (m *Mempool) admitClaim(tx *types.Tx, st *state.State, headHeight uint64) error {
	// The claim sub-pool is a separate bound from total capacity: it is what
	// leaves room for transfers under a claim flood.
	if m.claims >= m.maxClaims {
		return fmt.Errorf("%w: %d claims already pending", ErrClaimPoolFull, m.claims)
	}
	if m.pendingClaims[tx.From] >= maxPendingClaimsPerSender {
		return fmt.Errorf("%w: %d pending claim(s) from %x", ErrSenderLimit, m.pendingClaims[tx.From], tx.From[:])
	}

	p := st.Params()
	if p.EpochBlocks == 0 {
		return fmt.Errorf("%w: claims are not parameterised on this chain", state.ErrWrongEpoch)
	}
	// The claim must carry the epoch of the block that could apply it next, or
	// the epoch that is current now (a claim solved just before the head
	// advanced). Epoch(h) = h/EpochBlocks + 1.
	nextHeight := headHeight + 1
	headEpoch := headHeight/p.EpochBlocks + 1
	nextEpoch := nextHeight/p.EpochBlocks + 1
	if tx.Epoch != headEpoch && tx.Epoch != nextEpoch {
		return fmt.Errorf("%w: claim for epoch %d; current %d, next %d",
			state.ErrWrongEpoch, tx.Epoch, headEpoch, nextEpoch)
	}

	acc := st.Get(tx.From)
	// One claim per key per epoch. The state machine enforces this at apply
	// time; refusing it here is the same rule, applied before the claim can
	// occupy a slot or cost a puzzle.
	if acc.ClaimedEpoch >= tx.Epoch {
		return fmt.Errorf("%w: last claimed in epoch %d, claim is for epoch %d",
			state.ErrClaimTooSoon, acc.ClaimedEpoch, tx.Epoch)
	}
	// A claim spends the account's replay counter like any transaction. The
	// per-sender cap above means no other claim from this key is pending, so
	// the claim's nonce must match the head state exactly.
	if tx.Nonce != acc.Nonce+uint64(m.pendingClaims[tx.From]) {
		return fmt.Errorf("%w: got %d, want %d", state.ErrBadNonce, tx.Nonce, acc.Nonce)
	}
	// The cheap outer puzzle (audit S-4): one BLAKE3 hash rejects a claim whose
	// nonce never solved it. This is where the audit's flood - fresh keys,
	// random PowNonce - dies, for the cost of a hash rather than a puzzle.
	if !faucet.MeetsTarget(faucet.PreDigest(tx.PubKey, tx.Epoch, tx.PowNonce), m.preTarget) {
		return ErrBadPrePuzzle
	}
	return nil
}

// insert records an admitted transaction and its bookkeeping. The ID is
// passed in (already computed by Add) so it is encoded and hashed exactly
// once per transaction, not again on every lookup.
func (m *Mempool) insert(tx types.Tx, id [32]byte, sender types.Address) {
	m.txs = append(m.txs, entry{tx: tx, id: id, sender: sender})
	m.seen[id] = struct{}{}
	m.pending[sender]++
	if tx.Type == types.TxTransfer {
		set := m.pendingNonces[sender]
		if set == nil {
			set = make(map[uint64]struct{})
			m.pendingNonces[sender] = set
		}
		set[tx.Nonce] = struct{}{}
	}
	if tx.Type == types.TxFaucetClaim {
		m.claims++
		m.pendingClaims[sender]++
	}
}

// forget removes one entry's bookkeeping. The caller removes the entry itself.
func (m *Mempool) forget(e entry) {
	delete(m.seen, e.id)
	if n := m.pending[e.sender]; n <= 1 {
		delete(m.pending, e.sender)
	} else {
		m.pending[e.sender] = n - 1
	}
	if e.tx.Type == types.TxTransfer {
		if set := m.pendingNonces[e.sender]; set != nil {
			delete(set, e.tx.Nonce)
			if len(set) == 0 {
				delete(m.pendingNonces, e.sender)
			}
		}
	}
	if e.tx.Type == types.TxFaucetClaim {
		m.claims--
		if n := m.pendingClaims[e.sender]; n <= 1 {
			delete(m.pendingClaims, e.sender)
		} else {
			m.pendingClaims[e.sender] = n - 1
		}
	}
}

// Take removes and returns up to max transactions, in insertion order. At
// most MaxFaucetClaimsPerBlock of them are faucet claims: each claim costs a
// full Argon2id evaluation to verify, so claims encountered beyond that bound
// are skipped and left in the pool for a later block instead of being handed
// over or dropped. A non-positive max removes nothing and returns an empty
// slice.
//
// A claim that Take passes over ages: after MaxClaimAgeBlocks skips it is
// dropped. Only claims age, and only from being skipped - the policy never
// evicts a transaction to make room for a newer one, so a fresh flood cannot
// push out an older honest transaction.
func (m *Mempool) Take(max int) []types.Tx {
	m.mu.Lock()
	defer m.mu.Unlock()
	if max <= 0 {
		return []types.Tx{}
	}
	var out []types.Tx
	keep := m.txs[:0]
	claims := 0
	for i := range m.txs {
		e := m.txs[i]
		// The total still respects max, and once it is reached everything
		// remaining stays in the pool - claims and transfers alike. A claim
		// past the per-block claim bound is skipped by the same path.
		if len(out) >= max || (e.tx.Type == types.TxFaucetClaim && claims >= MaxFaucetClaimsPerBlock) {
			if e.tx.Type == types.TxFaucetClaim {
				e.skipped++
				if e.skipped > MaxClaimAgeBlocks {
					m.forget(e)
					continue
				}
			}
			keep = append(keep, e)
			continue
		}
		if e.tx.Type == types.TxFaucetClaim {
			claims++
		}
		out = append(out, e.tx)
		m.forget(e)
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
//
// The scan is O(n) in the pool size (audit O-9). That is accepted rather than
// fixed: the pool is bounded (1,000 on a real node), Remove is not on the
// block-production path (the driver's selection relies on Take/filters, not
// this), and an index from ID to slot would have to be rebuilt on every
// removal anyway - a linked list is the only structure that would make it
// constant time, at the cost of worse cache behaviour everywhere else. The
// previously quadratic-looking part - recomputing each entry's ID() while
// scanning - is gone: the ID is now stored in the entry.
func (m *Mempool) Remove(id [32]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.seen[id]; !ok {
		return
	}
	for i := range m.txs {
		if m.txs[i].id == id {
			m.forget(m.txs[i])
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
