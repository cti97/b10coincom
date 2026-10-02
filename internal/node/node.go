// Package node wires the chain, mempool and block production together.
// In M1 a single node produces blocks unilaterally: agreement between
// validators arrives in M3.
package node

import (
	"context"
	"crypto/ed25519"
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
// it. Every call appends exactly one block — empty when the mempool is
// empty — so the chain advances once per tick regardless (the brief's test
// requires a block at height 1 with an empty mempool).
//
// A transaction that cannot apply is evicted ALONE: it must not discard its
// valid siblings, and it must not leave them to fail with it in a later
// batch (Take drains the mempool, so a transaction dropped here is gone for
// good).
func (n *Node) RunOnce(timestamp int64) (*types.Block, error) {
	if timestamp == 0 {
		timestamp = n.now().Unix()
	}
	// Take drains the mempool, so anything dropped below is gone for good:
	// keep only the transactions that apply cleanly, in order, against a
	// running copy of the state. One state-invalid transaction must not
	// discard the valid ones beside it or wedge the node.
	candidates := n.mempool.Take(types.MaxTxsPerBlock)
	probe := n.chain.State().Clone()
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
		// Do not silently lose valid work.
		_ = n.mempool.Add(valid)
		return nil, err
	}
	if err := n.chain.Append(b); err != nil {
		_ = n.mempool.Add(valid)
		return nil, err
	}
	return b, nil
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
