package mempool

import (
	"testing"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/types"
)

func mkTx(t *testing.T, nonce uint64) types.Tx {
	t.Helper()
	pub, priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	_, otherPub, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	tx := &types.Tx{
		Type:   types.TxTransfer,
		From:   types.AddressFromPub(pub),
		PubKey: pub,
		Nonce:  nonce,
		To:     types.AddressFromPub(otherPub),
		Amount: 1,
	}
	sigHash := tx.SigningHash()
	tx.Sig = crypto.Sign(priv, sigHash[:])
	return *tx
}

func TestMempoolAddAndTake(t *testing.T) {
	m := New(10)
	errs := m.Add([]types.Tx{mkTx(t, 0), mkTx(t, 1)})
	for i, err := range errs {
		if err != nil {
			t.Fatalf("Add[%d]: %v", i, err)
		}
	}
	if m.Len() != 2 {
		t.Fatalf("Len = %d, want 2", m.Len())
	}
	got := m.Take(10)
	if len(got) != 2 {
		t.Fatalf("Take returned %d txs, want 2", len(got))
	}
	if m.Len() != 0 {
		t.Fatalf("Take must drain; Len = %d", m.Len())
	}
}

func TestMempoolDeduplicates(t *testing.T) {
	m := New(10)
	tx := mkTx(t, 0)
	if err := m.Add([]types.Tx{tx})[0]; err != nil {
		t.Fatal(err)
	}
	if err := m.Add([]types.Tx{tx})[0]; err == nil {
		t.Fatal("expected a duplicate to be rejected")
	}
	if m.Len() != 1 {
		t.Fatalf("Len = %d, want 1", m.Len())
	}
}

func TestMempoolRejectsBadSignature(t *testing.T) {
	m := New(10)
	tx := mkTx(t, 0)
	tx.Sig[0] ^= 0xFF
	if err := m.Add([]types.Tx{tx})[0]; err == nil {
		t.Fatal("expected a bad signature to be rejected")
	}
}

func TestMempoolRespectsCapacity(t *testing.T) {
	m := New(2)
	_ = m.Add([]types.Tx{mkTx(t, 0), mkTx(t, 1), mkTx(t, 2)})
	if m.Len() > 2 {
		t.Fatalf("Len = %d exceeds capacity 2", m.Len())
	}
}

func TestMempoolRemove(t *testing.T) {
	m := New(10)
	tx := mkTx(t, 0)
	_ = m.Add([]types.Tx{tx})
	m.Remove(tx.ID())
	if m.Len() != 0 {
		t.Fatalf("Len = %d after Remove, want 0", m.Len())
	}
}
