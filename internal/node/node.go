// Package node wires the chain, mempool and block production together.
// In M1 a single node produces blocks unilaterally: agreement between
// validators arrives in M3.
package node

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/mempool"
	"github.com/cti97/b10coincom/internal/types"
)

// Node produces blocks on a timer.
type Node struct {
	chain    *chain.Chain
	proposer ed25519.PrivateKey
	mempool  *mempool.Mempool
	now      func() time.Time
	// logf is the producer's log sink. It is a field, not a call to the log
	// package in Run, so a test can assert that a failing tick logs exactly
	// once per episode without swapping the process-global logger out from
	// under any other test in the same binary (audit S-3).
	logf func(format string, args ...any)
}

func New(c *chain.Chain, proposer ed25519.PrivateKey, mp *mempool.Mempool) *Node {
	return &Node{chain: c, proposer: proposer, mempool: mp, now: time.Now, logf: log.Printf}
}

// RunOnce produces at most one block from the current mempool and appends
// it. On success every call appends exactly one block — empty when the
// mempool is empty — so the chain advances once per tick regardless (the
// brief's test requires a block at height 1 with an empty mempool).
//
// An error return without an append is also possible in principle: the
// Probe branch below returns (nil, err) if the empty transition at head+1
// fails. That transition is a clone, a height set and an emission credit
// with no transactions to apply — none of which can fail — so the branch
// is defensive and, as of M2, unreachable.
//
// A transaction that cannot apply is evicted ALONE: it must not discard its
// valid siblings, and it must not leave them to fail with it in a later
// batch (Take removes everything it returned, so a transaction dropped here
// is gone for good - unless its nonce is merely AHEAD of the running state,
// which is returned and re-added; see below and audit S-17. Claims past
// MaxFaucetClaimsPerBlock are never returned - they stay in the pool
// untouched, outside this eviction path entirely).
//
// Transactions the block could not take but that remain eligible are put
// straight back: those the BYTE BUDGET could not hold (audit S-3) and those
// whose nonce is still ahead of the running state (audit S-17). Both are valid
// and eligible and belong in a later block, and SelectApplicable reports them
// rather than dropping them. The re-add happens BEFORE Build, while the pool's
// nonce floor is still the pre-block one - a re-add after Append would be
// refused, because the block that did not carry them moved the nonce floor
// past them (and a future-nonce transaction would be refused as spent).
func (n *Node) RunOnce(timestamp int64) (*types.Block, error) {
	if timestamp == 0 {
		timestamp = n.now().Unix()
	}
	// The filter's base and the one-at-a-time application live in
	// Chain.SelectApplicable, WHICH IS THE POINT: the driver that proposes for
	// consensus must select a block's transactions by exactly this policy, and
	// a policy written twice here and there could drift into a fork. Only the
	// bookkeeping around it is node's own.
	candidates := n.mempool.Take(types.MaxTxsPerBlock)
	valid, retry, err := n.chain.SelectApplicable(candidates)
	if err != nil {
		// Nothing applies at a state whose head+1 transition fails; park
		// the candidates back in the mempool rather than lose them.
		return nil, reAdd(n.mempool, candidates, err)
	}
	if len(retry) > 0 {
		// Return everything this block could not carry but that is still
		// eligible: the byte budget's tail and the nonce-ahead candidates
		// (audit S-3, S-17). A failure here is reported rather than
		// swallowed: it means the pool refused a transaction it had already
		// admitted, so the block attempt is abandoned and everything still in
		// hand goes back with it. Returning the error costs one tick; ignoring
		// it would lose the transaction silently.
		if rerr := reAdd(n.mempool, retry, nil); rerr != nil {
			return nil, reAdd(n.mempool, valid, rerr)
		}
	}

	b, err := n.chain.Build(n.proposer, valid, timestamp)
	if err != nil {
		return nil, reAdd(n.mempool, valid, err)
	}
	if err := n.chain.Append(b); err != nil {
		return nil, reAdd(n.mempool, valid, err)
	}
	return b, nil
}

// reAdd puts txs back into the mempool after a failed block attempt and
// returns the block failure unchanged when nothing was stranded. If any
// re-add fails beyond a duplicate, the transaction would be lost silently,
// so the returned error is wrapped with the count and the re-add reasons.
// An ErrDuplicate is NOT a loss — mempool.Add reports it when the
// transaction is already present (for example a client re-submitted the same
// transaction between Take and this re-add), and it remains eligible for a
// later block — so only the other failures inflate the count. The caller
// still sees the original cause first, and errors.Is against it keeps
// working. No logging framework or new dependency is involved.
func reAdd(mp *mempool.Mempool, txs []types.Tx, cause error) error {
	errs := mp.Add(txs)
	stranded := make([]error, 0, len(errs))
	for i := range errs {
		if errs[i] != nil && !errors.Is(errs[i], mempool.ErrDuplicate) {
			stranded = append(stranded, errs[i])
		}
	}
	if len(stranded) == 0 {
		return cause
	}
	if cause == nil {
		// A re-add with no previous failure (the over-budget path): there is no
		// cause to wrap, and fmt's %w with a nil error prints "%!w(<nil>)".
		return fmt.Errorf("%d of %d valid transactions could not be re-added to the mempool and are lost: %v",
			len(stranded), len(txs), stranded)
	}
	return fmt.Errorf("%w (in addition, %d of %d valid transactions could not be re-added to the mempool and are lost: %v)",
		cause, len(stranded), len(txs), stranded)
}

// Run produces blocks every interval until ctx is cancelled.
//
// ERROR POLICY (audit S-3, superseding O-7): a RunOnce error is LOGGED ONCE and
// the loop carries on to the next tick. It is NOT returned to main.
//
// The pre-fix policy exited the process on the first failure, on the reasoning
// that an error this loop can see is not transient and guessing wrong would
// hide a real fault. That reasoning had one gap that mattered: it made a
// PRODUCER bound (a block the node could not build) into an outage for every
// node holding a full mempool, and an outage is the wrong answer to "this tick
// could not build". A producer that cannot build should try again - the pool is
// re-derived on every attempt and the head does not move, so the next tick is a
// genuinely different attempt, and a bound that was momentarily too tight (the
// byte budget, a re-add race, a transient store write) heals itself.
//
// The log is LATCHED to one line per failure episode: the condition is retried
// every tick, and a line per tick at a two-second interval would bury it. A
// success clears the latch, so a node that fails, recovers and fails again says
// so twice. Nothing is swallowed - the line carries the error and the retry
// interval - and ctx cancellation is still returned, so a clean shutdown is
// still distinguishable from a running node.
func (n *Node) Run(ctx context.Context, interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var failing bool
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if _, err := n.RunOnce(0); err != nil {
				if !failing {
					failing = true
					if n.logf != nil {
						n.logf("b10coin: block production failed; retrying every %s until one succeeds (this line is logged once per failure episode): %v", interval, err)
					}
				}
				continue
			}
			failing = false
		}
	}
}
