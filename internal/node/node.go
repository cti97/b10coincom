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
func (n *Node) RunOnce(timestamp int64) (*types.Block, error) {
	if timestamp == 0 {
		timestamp = n.now().Unix()
	}
	txs := n.mempool.Take(types.MaxTxsPerBlock)
	b, err := n.chain.Build(n.proposer, txs, timestamp)
	if err != nil {
		return nil, err
	}
	if err := n.chain.Append(b); err != nil {
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
