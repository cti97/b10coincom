// Package node wires the chain, mempool and block production together.
// In M1 a single node produces blocks unilaterally: agreement between
// validators arrives in M3.
package node

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
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
}

func New(c *chain.Chain, proposer ed25519.PrivateKey, mp *mempool.Mempool) *Node {
	return &Node{chain: c, proposer: proposer, mempool: mp, now: time.Now}
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
// is gone for good. Claims past MaxFaucetClaimsPerBlock are never returned -
// they stay in the pool untouched, outside this eviction path entirely).
func (n *Node) RunOnce(timestamp int64) (*types.Block, error) {
	if timestamp == 0 {
		timestamp = n.now().Unix()
	}
	// Take removes what it returns, but it does NOT drain the pool: claims
	// past the per-block claim bound stay pending for a later block. What
	// Take did return is gone once handed over, so anything dropped below
	// is lost for good: keep only the transactions that apply cleanly, in
	// order, against a running copy of the state. One state-invalid
	// transaction must not discard the valid ones beside it or wedge the
	// node.
	//
	// The filter's base is Chain.Probe(nil) - the state a block at head+1
	// with no transactions would produce: the SAME transition Build runs,
	// height advanced and emission credited. Hand-cloning the head state
	// (the old filter) probed a claim against the head's epoch and a
	// pre-emission faucet balance, and silently evicted valid claims.
	// Candidates then apply on top of the base cumulative - each accepted
	// transaction is inside the running state the next probe starts from,
	// so a candidate may chain onto its accepted siblings (transfers with
	// nonces 0 and 1 both survive; probing each against the bare head state
	// would evict the second). Equivalent-but-quadratic alternative: probing
	// every candidate through Probe(accepted... + candidate) re-derives and
	// re-verifies the accepted prefix's signatures per candidate, which on a
	// full MaxTxsPerBlock mempool is hours of ed25519 per block - a DoS the
	// one-base form avoids.
	candidates := n.mempool.Take(types.MaxTxsPerBlock)
	probe, err := n.chain.Probe(nil)
	if err != nil {
		// Nothing applies at a state whose head+1 transition fails; park
		// the candidates back in the mempool rather than lose them.
		return nil, reAdd(n.mempool, candidates, err)
	}
	valid := make([]types.Tx, 0, len(candidates))
	for i := range candidates {
		next, err := probe.ApplyBlock([]types.Tx{candidates[i]})
		if err != nil {
			continue // evict: it cannot apply at this state
		}
		probe = next
		valid = append(valid, candidates[i])
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
	return fmt.Errorf("%w (in addition, %d of %d valid transactions could not be re-added to the mempool and are lost: %v)",
		cause, len(stranded), len(txs), stranded)
}

// Run produces blocks every interval until ctx is cancelled.
func (n *Node) Run(ctx context.Context, interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if _, err := n.RunOnce(0); err != nil {
				return err
			}
		}
	}
}
