package node

import (
	"testing"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/mempool"
	"github.com/cti97/b10coincom/internal/types"
)

func TestRunOnceProducesAndAppends(t *testing.T) {
	c, err := chain.Open(genesis.Devnet(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, priv := genesis.DevValidatorKey()

	n := New(c, priv, mempool.New(100))
	b, err := n.RunOnce(1_700_000_100)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if b.Header.Height != 1 {
		t.Fatalf("height = %d, want 1", b.Header.Height)
	}
	if c.Height() != 1 {
		t.Fatalf("chain height = %d, want 1", c.Height())
	}
}

func TestRunOnceIncludesMempoolTransactions(t *testing.T) {
	c, err := chain.Open(genesis.Devnet(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, priv := genesis.DevValidatorKey()

	// Build a signed transfer from devnet dev account 0 to account 1.
	fromPub, fromPriv := genesis.DevAccountKey(0)
	toPub, _ := genesis.DevAccountKey(1)
	from := types.AddressFromPub(fromPub)
	tx := &types.Tx{
		Type:   types.TxTransfer,
		From:   from,
		PubKey: fromPub,
		Nonce:  c.State().Get(from).Nonce,
		To:     types.AddressFromPub(toPub),
		Amount: 10 * genesis.SparksPerB10,
	}
	sigHash := tx.SigningHash()
	tx.Sig = crypto.Sign(fromPriv, sigHash[:])

	mp := mempool.New(100)
	if err := mp.Add([]types.Tx{*tx})[0]; err != nil {
		t.Fatalf("mempool.Add: %v", err)
	}
	if mp.Len() != 1 {
		t.Fatalf("mempool length = %d, want 1", mp.Len())
	}

	n := New(c, priv, mp)
	before := c.State().Get(types.AddressFromPub(toPub)).Balance

	b, err := n.RunOnce(1_700_000_100)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(b.Txs) != 1 {
		t.Fatalf("block contains %d txs, want 1", len(b.Txs))
	}
	if got := c.State().Get(types.AddressFromPub(toPub)).Balance; got != before+10*genesis.SparksPerB10 {
		t.Fatalf("recipient balance = %d, want %d", got, before+10*genesis.SparksPerB10)
	}
	if mp.Len() != 0 {
		t.Fatalf("mempool should be drained, length = %d", mp.Len())
	}
}
