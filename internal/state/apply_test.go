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
	// 32 accounts inserted in opposite orders. With this many entries the
	// chance that two independent map iterations agree is negligible, so an
	// unsorted Root() cannot pass by luck on any Go runtime.
	const n = 32
	addrs := make([]types.Address, n)
	for i := range addrs {
		pub, _, err := crypto.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		addrs[i] = types.AddressFromPub(pub)
	}

	forward := New()
	backward := New()
	for i := 0; i < n; i++ {
		forward.Set(addrs[i], Account{Balance: uint64(i + 1)})
		backward.Set(addrs[n-1-i], Account{Balance: uint64(n - i)})
	}
	if forward.Root() != backward.Root() {
		t.Fatal("state root depends on insertion order")
	}

	// Sensitivity: a single balance change must move the root.
	altered := New()
	for i := 0; i < n; i++ {
		altered.Set(addrs[i], Account{Balance: uint64(i + 1)})
	}
	altered.Set(addrs[0], Account{Balance: 999})
	if forward.Root() == altered.Root() {
		t.Fatal("state root ignored a balance change")
	}
}

// TestRootGoldenVector freezes the exact root for a fixed state. It is the
// only test that pins the leaf encoding (balance then nonce), the Merkle
// construction and the "b10coin-account" domain label: change any of them and
// this value changes, which is precisely the point.
//
// To produce the expected value: write this test with a zero `want`, run it,
// and paste the 32 bytes the failure reports. Then confirm the vector is
// load-bearing by temporarily changing the domain label in state.go and
// watching this test fail, before reverting that change.
func TestRootGoldenVector(t *testing.T) {
	s := New()
	s.Set(types.Address{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}, Account{Balance: 1000, Nonce: 7})
	s.Set(types.Address{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}, Account{Balance: 0, Nonce: 3})
	s.Set(types.Address{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, Account{Balance: 18446744073709551615, Nonce: 0})

	var want = [32]byte{
		0x69, 0x38, 0x3e, 0xe3, 0xc1, 0xb9, 0x2d, 0xa5, 0x0c, 0x46, 0xbc, 0xa8, 0x97, 0x47, 0x6d, 0xc1,
		0xde, 0xde, 0xd1, 0xec, 0x5b, 0x47, 0x08, 0x6d, 0xee, 0xc2, 0xa0, 0x9e, 0x7d, 0x37, 0x29, 0x5e,
	}
	if got := s.Root(); got != want {
		t.Fatalf("golden root changed:\n got %x\nwant %x", got, want)
	}
}

// TestRootGoldenVectorFourAccounts freezes a second root with FOUR accounts,
// so the Merkle tree has a different shape (4 leaves -> two internal nodes)
// than the three-leaf vector above. It includes deliberately kept-boundary
// entries: a zero-balance, non-zero-nonce account (retained, unlike a fully
// zero account, which Set prunes) sitting beside funded ones.
//
// This vector was captured ONCE from the implementation and is frozen. DO
// NOT re-capture it from a fresh run to make a failing test pass — a changed
// root is a consensus-encoding change and needs a deliberate look at what
// moved, exactly as for the three-account vector above.
func TestRootGoldenVectorFourAccounts(t *testing.T) {
	s := New()
	s.Set(types.Address{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11}, Account{Balance: 42, Nonce: 1})
	s.Set(types.Address{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22}, Account{Balance: 0, Nonce: 9})
	s.Set(types.Address{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33}, Account{Balance: 7_777_777})
	s.Set(types.Address{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa}, Account{Balance: 123_456_789, Nonce: 5})

	var want = [32]byte{
		0xd7, 0xc4, 0x15, 0x6e, 0xb3, 0xc1, 0x39, 0xae, 0x21, 0x5b, 0xfb, 0xdb, 0xc9, 0x29, 0x85, 0x4f,
		0xb6, 0x62, 0x10, 0xce, 0x80, 0x9a, 0x63, 0x2f, 0xfb, 0x99, 0x0d, 0x6b, 0x3f, 0xe6, 0x43, 0xcd,
	}
	if got := s.Root(); got != want {
		t.Fatalf("four-account golden root changed:\n got %x\nwant %x", got, want)
	}
}

// An unsupported transaction type must be rejected. The signature is valid, so
// execution reaches the type switch rather than failing the signature check
// first.
func TestApplyTxRejectsUnsupportedType(t *testing.T) {
	from, pub, priv := keypair(t)
	to, _, _ := keypair(t)

	s := New()
	s.Set(from, Account{Balance: 100})

	tx := transfer(t, pub, priv, from, 0, 10, to)
	tx.Type = types.TxType(99)
	sigHash := tx.SigningHash()
	tx.Sig = crypto.Sign(priv, sigHash[:])

	if err := s.ApplyTx(tx); !errors.Is(err, ErrUnsupportedTxType) {
		t.Fatalf("expected ErrUnsupportedTxType, got %v", err)
	}
}

// TotalBalance is required API surface: the supply-invariant check consumes it.
func TestTotalBalance(t *testing.T) {
	a, _, _ := keypair(t)
	b, _, _ := keypair(t)

	if got := New().TotalBalance(); got != 0 {
		t.Fatalf("empty state TotalBalance = %d, want 0", got)
	}

	s := New()
	s.Set(a, Account{Balance: 400})
	s.Set(b, Account{Balance: 600})
	if got := s.TotalBalance(); got != 1000 {
		t.Fatalf("TotalBalance = %d, want 1000", got)
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
