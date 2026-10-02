// Package devnet runs a self-contained local chain. It is the single
// acceptance check for M0-M1: one call builds a chain, includes a real
// transfer, persists it and reports a reproducible state root.
package devnet

import (
	"errors"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/mempool"
	"github.com/cti97/b10coincom/internal/node"
	"github.com/cti97/b10coincom/internal/types"
)

var ErrNoBlocks = errors.New("devnet: Blocks must be greater than zero")

// Options configures a devnet run.
type Options struct {
	Dir    string
	Blocks uint64
}

// Summary reports what a run produced.
type Summary struct {
	ChainID     string
	Height      uint64
	StateRoot   [32]byte
	TxsIncluded int
}

// Run creates a fresh devnet and drives it to o.Blocks. One transfer is
// seeded before the first block, so the state transition path is exercised
// rather than only empty blocks.
func Run(o Options) (Summary, error) {
	if o.Blocks == 0 {
		return Summary{}, ErrNoBlocks
	}
	g := genesis.Devnet()
	c, err := chain.Open(g, o.Dir)
	if err != nil {
		return Summary{}, err
	}
	defer c.Close()

	_, priv := genesis.DevValidatorKey()
	mp := mempool.New(1000)
	n := node.New(c, priv, mp)

	tx, err := devTransfer(c, 250*genesis.SparksPerB10)
	if err != nil {
		return Summary{}, err
	}
	if err := mp.Add([]types.Tx{*tx})[0]; err != nil {
		return Summary{}, err
	}

	included := 0
	for h := uint64(1); h <= o.Blocks; h++ {
		b, err := n.RunOnce(g0Time + int64(h))
		if err != nil {
			return Summary{}, err
		}
		included += len(b.Txs)
	}

	return Summary{
		ChainID:     g.ChainID,
		Height:      c.Height(),
		StateRoot:   c.State().Root(),
		TxsIncluded: included,
	}, nil
}

// Replay reopens an existing devnet directory and reports the replayed state.
func Replay(dir string) (Summary, error) {
	g := genesis.Devnet()
	c, err := chain.Open(g, dir)
	if err != nil {
		return Summary{}, err
	}
	defer c.Close()
	return Summary{
		ChainID:   g.ChainID,
		Height:    c.Height(),
		StateRoot: c.State().Root(),
	}, nil
}

// devTransfer builds a signed transfer from dev account 0 to dev account 1.
func devTransfer(c *chain.Chain, amount uint64) (*types.Tx, error) {
	fromPub, fromPriv := genesis.DevAccountKey(0)
	toPub, _ := genesis.DevAccountKey(1)
	from := types.AddressFromPub(fromPub)
	tx := &types.Tx{
		Type:   types.TxTransfer,
		From:   from,
		PubKey: fromPub,
		Nonce:  c.State().Get(from).Nonce,
		To:     types.AddressFromPub(toPub),
		Amount: amount,
	}
	sigHash := tx.SigningHash()
	tx.Sig = crypto.Sign(fromPriv, sigHash[:])
	return tx, nil
}

// g0Time is the deterministic base timestamp for devnet blocks.
const g0Time = 1_700_000_000
