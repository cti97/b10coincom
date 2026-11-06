package node

// Audit S-17, end to end through the shipped producer path (RunOnce: Take ->
// SelectApplicable -> Build -> Append). The pool admits a transaction whose
// nonce is ahead of its account's because it may become applicable; the defect
// was that a block attempt which took it before its predecessor DESTROYED it -
// Take had removed it, SelectApplicable evicted it, and nothing put it back.
// The fix keeps it in the pool and lets a later block carry it.
//
// The batch is constructed, never provoked by a race: the future-nonce
// transaction is admitted first, then a block is produced, then its
// predecessor is submitted.

import (
	"testing"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/mempool"
	"github.com/cti97/b10coincom/internal/types"
)

// TestAFutureNonceGapSurvivesToALaterBlock is the finding's reproduction and
// its fix in one test: a devnet sender's nonce-1 transfer is in the pool while
// the account's nonce is still 0, one producer tick runs, and the transaction
// must still be pending - then the nonce-0 predecessor arrives and the next
// block carries both in nonce order.
func TestAFutureNonceGapSurvivesToALaterBlock(t *testing.T) {
	g := genesis.Devnet()
	c, err := chain.Open(g, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, proposer := genesis.DevValidatorKey()
	pub, key := genesis.DevAccountKey(0)
	from := types.AddressFromPub(pub)
	toPub, _ := genesis.DevAccountKey(1)
	to := types.AddressFromPub(toPub)

	transfer := func(nonce uint64) types.Tx {
		tx := types.Tx{
			Type: types.TxTransfer, From: from, PubKey: pub, Nonce: nonce,
			Fee: g.Params.MinFeeSparks, To: to, Amount: 1,
		}
		h := tx.SigningHash(g.Hash())
		tx.Sig = crypto.Sign(key, h[:])
		return tx
	}

	future := transfer(1)
	mp := mempool.New(100, g.Hash(), c.AdmissionHead)
	if err := mp.Add([]types.Tx{future})[0]; err != nil {
		t.Fatalf("the pool refused a future nonce, which is the premise: %v", err)
	}
	n := New(c, proposer, mp)

	b, err := n.RunOnce(1_700_000_100)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if c.Height() != 1 {
		t.Fatalf("chain height = %d, want 1: the producer must still make its block", c.Height())
	}
	if len(b.Txs) != 0 {
		t.Fatalf("the block carries %d txs, want 0: the nonce is still a gap", len(b.Txs))
	}
	if mp.Len() != 1 {
		t.Fatalf("pool holds %d txs after the block, want the future-nonce transaction to SURVIVE (audit S-17: it used to be destroyed here with no error)", mp.Len())
	}

	// The predecessor arrives only now. Insertion order is [nonce 1, nonce 0],
	// so this also exercises the per-sender ordering: the block must carry both.
	if err := mp.Add([]types.Tx{transfer(0)})[0]; err != nil {
		t.Fatalf("the predecessor was refused: %v", err)
	}
	b, err = n.RunOnce(1_700_000_101)
	if err != nil {
		t.Fatalf("RunOnce (predecessor): %v", err)
	}
	if len(b.Txs) != 2 {
		t.Fatalf("the block carries %d txs, want both: the survived transaction and its predecessor", len(b.Txs))
	}
	if b.Txs[0].Nonce != 0 || b.Txs[1].Nonce != 1 {
		t.Fatalf("the block carries nonces %d then %d, want 0 then 1", b.Txs[0].Nonce, b.Txs[1].Nonce)
	}
	if mp.Len() != 0 {
		t.Fatalf("pool holds %d txs after the block, want 0", mp.Len())
	}
	if acc := c.State().Get(from); acc.Nonce != 2 {
		t.Fatalf("the sender's account nonce = %d after both transfers, want 2", acc.Nonce)
	}
}
