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
// only test that pins the leaf encoding (balance, nonce, then claimed epoch),
// the Merkle construction and the "b10coin-account" domain label: change any
// of them and this value changes, which is precisely the point.
//
// To produce the expected value: write this test with a zero `want`, run it,
// and paste the 32 bytes the failure reports. Then confirm the vector is
// load-bearing by temporarily changing the domain label in state.go and
// watching this test fail, before reverting that change.
//
// SUPERSEDED (M0-M1, two-field leaf): 69383ee3c1b92da50c46bca897476dc1deded1ec5b47086deec2a09e7d37295e
// Re-derived in M2 because the account leaf gained ClaimedEpoch. This is a
// deliberate format change, not a re-capture of an unexplained failure - the
// do-not-recapture rule still holds for every other reason. The first account
// also gained ClaimedEpoch: 1 so the pinned value commits a NON-ZERO marker:
// zeroing the ClaimedEpoch field out of the leaf encoding must move this root.
func TestRootGoldenVector(t *testing.T) {
	s := New()
	s.Set(types.Address{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}, Account{Balance: 1000, Nonce: 7, ClaimedEpoch: 1})
	s.Set(types.Address{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}, Account{Balance: 0, Nonce: 3})
	s.Set(types.Address{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, Account{Balance: 18446744073709551615, Nonce: 0})

	var want = [32]byte{
		0x08, 0x9d, 0x2f, 0x56, 0x8d, 0x54, 0x7c, 0x73, 0x56, 0x1a, 0xd5, 0x65, 0x3e, 0xe3, 0xca, 0xbe,
		0x5e, 0x3b, 0x67, 0xfc, 0x50, 0x85, 0x64, 0x4c, 0x61, 0x2c, 0xe7, 0x31, 0xfe, 0xd1, 0x95, 0x9a,
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
//
// SUPERSEDED (M0-M1, two-field leaf): d7c4156eb3c139ae215bfbdbc929854fb66210ce809a632ffb990d6b3fe643cd
// Re-derived in M2 because the account leaf gained ClaimedEpoch. This is a
// deliberate format change, not a re-capture of an unexplained failure - the
// do-not-recapture rule still holds for every other reason. The last account
// also gained ClaimedEpoch: 3 so the pinned value commits a NON-ZERO marker:
// zeroing the ClaimedEpoch field out of the leaf encoding must move this root.
func TestRootGoldenVectorFourAccounts(t *testing.T) {
	s := New()
	s.Set(types.Address{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11}, Account{Balance: 42, Nonce: 1})
	s.Set(types.Address{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22}, Account{Balance: 0, Nonce: 9})
	s.Set(types.Address{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33}, Account{Balance: 7_777_777})
	s.Set(types.Address{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa}, Account{Balance: 123_456_789, Nonce: 5, ClaimedEpoch: 3})

	var want = [32]byte{
		0xd0, 0xda, 0x0f, 0x2d, 0xfa, 0xee, 0x53, 0xe2, 0x2a, 0x63, 0xf7, 0x96, 0x95, 0x8b, 0xe3, 0x52,
		0xd5, 0xaa, 0x60, 0x4e, 0x7c, 0xc2, 0x81, 0xf3, 0xdc, 0x02, 0x9c, 0xcf, 0x6d, 0xa5, 0xb3, 0x72,
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

// An account that has claimed in epoch 0 has non-zero committed state and must
// survive pruning, or the one-claim-per-epoch rule would reset on every prune.
func TestClaimMarkerSurvivesPruning(t *testing.T) {
	a, _, _ := keypair(t)
	s := New()
	s.Set(a, Account{ClaimedEpoch: 1})
	if s.Len() != 1 {
		t.Fatalf("an account holding only a claim marker was pruned: len=%d", s.Len())
	}
	if s.Root() == New().Root() {
		t.Fatal("the claim marker is not committed into the state root")
	}
}
