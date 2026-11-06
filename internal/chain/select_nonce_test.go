package chain

// Audit S-17, at the selection policy. The pool admits a transaction whose
// nonce is ahead of its sender's account nonce because it may become
// applicable; before this, a Take batch whose same-sender entries arrived out
// of nonce order had the gapped transaction evicted and nothing put it back,
// so it was destroyed with no error to anyone. These tests construct the batch
// directly (a state, not a race) and pin both halves of the fix: the batch is
// ordered per sender before selection, and a candidate whose predecessor is
// simply absent is handed back rather than dropped.

import (
	"crypto/ed25519"
	"testing"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/state"
	"github.com/cti97/b10coincom/internal/types"
)

// nonceSender is one funded key in the fixture below.
type nonceSender struct {
	addr types.Address
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

// fundedTransfer returns one signed transfer from a funded sender.
func fundedTransfer(g *genesis.Genesis, s nonceSender, to types.Address, nonce, amount uint64) types.Tx {
	tx := types.Tx{
		Type: types.TxTransfer, From: s.addr, PubKey: s.pub, Nonce: nonce,
		Fee: g.Params.MinFeeSparks, To: to, Amount: amount,
	}
	h := tx.SigningHash(g.Hash())
	tx.Sig = crypto.Sign(s.priv, h[:])
	return tx
}

// nonceFixture opens a devnet chain whose head state funds n fresh senders and
// returns the chain, the genesis, the senders and a recipient address. Each
// sender starts at nonce 0, so a candidate at nonce 1 is "the future" the pool
// admits.
func nonceFixture(t *testing.T, n int) (*Chain, *genesis.Genesis, []nonceSender, types.Address) {
	t.Helper()
	g := genesis.Devnet()
	c, err := Open(g, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	st := c.State().Clone()
	senders := make([]nonceSender, n)
	for i := 0; i < n; i++ {
		pub, priv, err := crypto.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		addr := types.AddressFromPub(pub)
		st.Set(addr, state.Account{Balance: 100})
		senders[i] = nonceSender{addr: addr, pub: pub, priv: priv}
	}
	var recipient types.Address
	recipient[0] = 0xCD
	c.state = st
	return c, g, senders, recipient
}

// TestSelectApplicableOrdersEachSendersNonceChain: a sender's nonce-2 arrives
// before its nonce-1, with another sender's transaction between them. The
// filter must apply the chain in nonce order WITHOUT moving either transaction
// across the other sender's, and must select all three.
func TestSelectApplicableOrdersEachSendersNonceChain(t *testing.T) {
	c, g, senders, recipient := nonceFixture(t, 2)
	a, b := senders[0], senders[1]
	txA1 := fundedTransfer(g, a, recipient, 1, 1)
	txB0 := fundedTransfer(g, b, recipient, 0, 1)
	txA0 := fundedTransfer(g, a, recipient, 0, 1)

	// The batch as the pool could hand it over: A's future nonce first, then B,
	// then A's predecessor.
	candidates := []types.Tx{txA1, txB0, txA0}
	selected, retry, err := c.SelectApplicable(candidates)
	if err != nil {
		t.Fatal(err)
	}
	if len(retry) != 0 {
		t.Fatalf("retry = %d transactions, want 0: every candidate applies once ordered", len(retry))
	}
	if len(selected) != 3 {
		t.Fatalf("selected %d of 3 candidates: the nonce chain did not apply", len(selected))
	}
	if selected[0].From != a.addr || selected[0].Nonce != 0 {
		t.Fatalf("selected[0] = %s nonce %d, want the sender's nonce-1 PREDECESSOR first", selected[0].From, selected[0].Nonce)
	}
	// B keeps its position between the two: ordering only permutes a sender's
	// OWN entries, so no cross-sender relationship changes.
	if selected[1].From != b.addr || selected[1].Nonce != 0 {
		t.Fatalf("selected[1] = %s nonce %d, want the other sender's transaction still between the pair", selected[1].From, selected[1].Nonce)
	}
	if selected[2].From != a.addr || selected[2].Nonce != 1 {
		t.Fatalf("selected[2] = %s nonce %d, want the future nonce now applicable", selected[2].From, selected[2].Nonce)
	}
}

// TestSelectApplicableReturnsAFutureNonceToTheCaller: when the predecessor is
// NOT in the batch at all (a real gap, not just a bad order), the transaction
// is still eligible in a later block, so it must come back in retry - the list
// both producers re-add - rather than be discarded. A candidate the state
// refused for a reason that no later block can fix (no funds) stays evicted.
func TestSelectApplicableReturnsAFutureNonceToTheCaller(t *testing.T) {
	c, g, senders, recipient := nonceFixture(t, 2)
	gap, broke := senders[0], senders[1]
	future := fundedTransfer(g, gap, recipient, 2, 1)

	// Give the second sender too little for one transfer (amount 1 + fee 1).
	st := c.State().Clone()
	acc := st.Get(broke.addr)
	acc.Balance = 0
	st.Set(broke.addr, acc)
	c.state = st
	unfunded := fundedTransfer(g, broke, recipient, 0, 1)

	selected, retry, err := c.SelectApplicable([]types.Tx{future, unfunded})
	if err != nil {
		t.Fatal(err)
	}
	if len(selected) != 0 {
		t.Fatalf("selected = %d, want 0: neither candidate can apply at this state", len(selected))
	}
	if len(retry) != 1 || retry[0].ID() != future.ID() {
		t.Fatalf("retry = %d transactions, want exactly the future-nonce one: a gap that arrives early must survive to a later block", len(retry))
	}
	if retry[0].Nonce != 2 {
		t.Fatalf("retry[0] nonce = %d, want the future nonce 2", retry[0].Nonce)
	}
}

// TestOrderBySenderNonceLeavesAnOrderedBatchAlone: the common case is the
// shipped path (a correct wallet submits in nonce order, and insertion order
// is submission order), so an ordered batch must be untouched.
func TestOrderBySenderNonceLeavesAnOrderedBatchAlone(t *testing.T) {
	_, g, senders, recipient := nonceFixture(t, 1)
	s := senders[0]
	txs := []types.Tx{
		fundedTransfer(g, s, recipient, 0, 1),
		fundedTransfer(g, s, recipient, 1, 1),
		fundedTransfer(g, s, recipient, 2, 1),
	}
	before := make([]types.Tx, len(txs))
	copy(before, txs)
	orderBySenderNonce(txs)
	for i := range txs {
		if txs[i].ID() != before[i].ID() {
			t.Fatalf("orderBySenderNonce moved an already-ordered entry at %d", i)
		}
	}
}
