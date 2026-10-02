package state

import (
	"errors"
	"testing"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/types"
)

// keypair returns a fresh address/public/private triple.
func keypair(t *testing.T) (types.Address, []byte, []byte) {
	t.Helper()
	pub, priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return types.AddressFromPub(pub), pub, priv
}

// transfer builds a signed transfer.
func transfer(t *testing.T, fromPub, fromPriv []byte, from types.Address, nonce, amount uint64, to types.Address) *types.Tx {
	t.Helper()
	tx := &types.Tx{
		Type:   types.TxTransfer,
		From:   from,
		PubKey: fromPub,
		Nonce:  nonce,
		To:     to,
		Amount: amount,
	}
	sigHash := tx.SigningHash()
	tx.Sig = crypto.Sign(fromPriv, sigHash[:])
	return tx
}

func TestApplyTransferMovesFundsAndBumpsNonce(t *testing.T) {
	from, pub, priv := keypair(t)
	to, _, _ := keypair(t)

	s := New()
	s.Set(from, Account{Balance: 1000})

	if err := s.ApplyTx(transfer(t, pub, priv, from, 0, 400, to)); err != nil {
		t.Fatalf("ApplyTx: %v", err)
	}
	if got := s.Get(from); got.Balance != 600 || got.Nonce != 1 {
		t.Fatalf("sender = %+v, want balance 600 nonce 1", got)
	}
	if got := s.Get(to); got.Balance != 400 || got.Nonce != 0 {
		t.Fatalf("recipient = %+v, want balance 400 nonce 0", got)
	}
}

func TestApplyTransferRejectsReplayedNonce(t *testing.T) {
	from, pub, priv := keypair(t)
	to, _, _ := keypair(t)

	s := New()
	s.Set(from, Account{Balance: 1000})

	if err := s.ApplyTx(transfer(t, pub, priv, from, 0, 100, to)); err != nil {
		t.Fatal(err)
	}
	// Replaying nonce 0 must fail: this is the double-spend guard.
	if err := s.ApplyTx(transfer(t, pub, priv, from, 0, 100, to)); !errors.Is(err, ErrBadNonce) {
		t.Fatalf("expected ErrBadNonce, got %v", err)
	}
}

func TestApplyTransferRejectsSkippedNonce(t *testing.T) {
	from, pub, priv := keypair(t)
	to, _, _ := keypair(t)

	s := New()
	s.Set(from, Account{Balance: 1000})

	if err := s.ApplyTx(transfer(t, pub, priv, from, 5, 100, to)); !errors.Is(err, ErrBadNonce) {
		t.Fatalf("expected ErrBadNonce, got %v", err)
	}
}

func TestApplyTransferRejectsInsufficientFunds(t *testing.T) {
	from, pub, priv := keypair(t)
	to, _, _ := keypair(t)

	s := New()
	s.Set(from, Account{Balance: 99})

	if err := s.ApplyTx(transfer(t, pub, priv, from, 0, 100, to)); !errors.Is(err, ErrInsufficientFunds) {
		t.Fatalf("expected ErrInsufficientFunds, got %v", err)
	}
}

func TestApplyTransferRejectsZeroAmount(t *testing.T) {
	from, pub, priv := keypair(t)
	to, _, _ := keypair(t)

	s := New()
	s.Set(from, Account{Balance: 100})

	if err := s.ApplyTx(transfer(t, pub, priv, from, 0, 0, to)); !errors.Is(err, ErrZeroAmount) {
		t.Fatalf("expected ErrZeroAmount, got %v", err)
	}
}

func TestApplyTransferRejectsSelfTransfer(t *testing.T) {
	from, pub, priv := keypair(t)

	s := New()
	s.Set(from, Account{Balance: 100})

	if err := s.ApplyTx(transfer(t, pub, priv, from, 0, 10, from)); !errors.Is(err, ErrSelfTransfer) {
		t.Fatalf("expected ErrSelfTransfer, got %v", err)
	}
}

func TestApplyTransferRejectsBadSignature(t *testing.T) {
	from, pub, priv := keypair(t)
	to, _, _ := keypair(t)

	s := New()
	s.Set(from, Account{Balance: 100})

	tx := transfer(t, pub, priv, from, 0, 10, to)
	tx.Sig[0] ^= 0xFF
	if err := s.ApplyTx(tx); !errors.Is(err, types.ErrBadSignature) {
		t.Fatalf("expected ErrBadSignature, got %v", err)
	}
}

// A failed transaction must leave no trace: state is all-or-nothing per tx.
func TestFailedTxDoesNotMutateState(t *testing.T) {
	from, pub, priv := keypair(t)
	to, _, _ := keypair(t)

	s := New()
	s.Set(from, Account{Balance: 100})
	before := s.Root()

	if err := s.ApplyTx(transfer(t, pub, priv, from, 0, 1000, to)); err == nil {
		t.Fatal("expected failure")
	}
	if s.Root() != before {
		t.Fatal("state changed after a failed transaction")
	}
}

// ApplyBlock is atomic: if any transaction fails, none are applied.
func TestApplyBlockIsAtomic(t *testing.T) {
	from, pub, priv := keypair(t)
	to, _, _ := keypair(t)

	s := New()
	s.Set(from, Account{Balance: 100})
	before := s.Root()

	txs := []types.Tx{
		*transfer(t, pub, priv, from, 0, 50, to),
		*transfer(t, pub, priv, from, 1, 9999, to), // fails
	}
	if _, err := s.ApplyBlock(txs); !errors.Is(err, ErrInsufficientFunds) {
		t.Fatalf("expected ErrInsufficientFunds, got %v", err)
	}
	if s.Root() != before {
		t.Fatal("state changed after a failed block")
	}
}

func TestApplyBlockReturnsNewStateOnSuccess(t *testing.T) {
	from, pub, priv := keypair(t)
	to, _, _ := keypair(t)

	s := New()
	s.Set(from, Account{Balance: 100})
	before := s.Root()

	next, err := s.ApplyBlock([]types.Tx{*transfer(t, pub, priv, from, 0, 50, to)})
	if err != nil {
		t.Fatal(err)
	}
	if next.Get(to).Balance != 50 {
		t.Fatalf("new state has wrong balance: %+v", next.Get(to))
	}
	if s.Root() != before {
		t.Fatal("ApplyBlock mutated the original state")
	}
}

func TestRootIsOrderIndependentAndSensitive(t *testing.T) {
	a, _, _ := keypair(t)
	b, _, _ := keypair(t)

	s1 := New()
	s1.Set(a, Account{Balance: 1})
	s1.Set(b, Account{Balance: 2})

	s2 := New()
	s2.Set(b, Account{Balance: 2})
	s2.Set(a, Account{Balance: 1})

	if s1.Root() != s2.Root() {
		t.Fatal("state root depends on insertion order")
	}

	s3 := New()
	s3.Set(a, Account{Balance: 1})
	s3.Set(b, Account{Balance: 3})
	if s1.Root() == s3.Root() {
		t.Fatal("state root ignored a balance change")
	}
}

func TestZeroAccountsArePruned(t *testing.T) {
	a, _, _ := keypair(t)
	s := New()
	s.Set(a, Account{})
	if s.Len() != 0 {
		t.Fatalf("zero account was retained: len=%d", s.Len())
	}
	if s.Root() != (New()).Root() {
		t.Fatal("zero account changed the root")
	}
}
