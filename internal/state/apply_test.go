package state

import (
	"errors"
	"math"
	"testing"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/faucet"
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

// An account that has claimed (ClaimedEpoch: 1, the first epoch — epochs are
// 1-based) has non-zero committed state and must survive pruning, or the
// one-claim-per-epoch rule would reset on every prune.
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

// testParams mirrors the faucet package's test tuning: trivial Argon2 cost and
// an easy target, so a solve takes a couple of attempts rather than seconds.
func testParams(t *testing.T) Params {
	t.Helper()
	var target [32]byte
	for i := range target {
		target[i] = 0xFF
	}
	target[0] = 0x7F
	return Params{
		FaucetAddress: types.AddressFromPub([]byte("the-faucet-has-no-private-key")),
		ClaimAmount:   100,
		EpochBlocks:   10,
		PowArgon2:     faucet.Argon2Params{MemoryKiB: 64, Iterations: 1, Parallelism: 1},
		PowTarget:     target,
	}
}

// solvedClaim builds a claim for a fresh key whose proof-of-work ACTUALLY meets
// the target for the epoch it carries, so that a test using it can only fail on
// the rule it names.
func solvedClaim(t *testing.T, p Params, epoch, nonce uint64) *types.Tx {
	t.Helper()
	pub, priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pow, ok := faucet.Solve(pub, epoch, p.PowTarget, p.PowArgon2, 1_000_000)
	if !ok {
		t.Fatal("could not solve the test puzzle")
	}
	tx := &types.Tx{
		Type: types.TxFaucetClaim, From: types.AddressFromPub(pub), PubKey: pub,
		Nonce: nonce, Epoch: epoch, PowNonce: pow,
	}
	sigHash := tx.SigningHash()
	tx.Sig = crypto.Sign(priv, sigHash[:])
	return tx
}

func TestClaimCreditsClaimantAndDebitsFaucet(t *testing.T) {
	p := testParams(t)
	s := NewWithParams(p)
	s.Set(p.FaucetAddress, Account{Balance: 1_000})

	tx := solvedClaim(t, p, 1, 0)
	claimant := tx.From

	if err := s.ApplyTx(tx); err != nil {
		t.Fatalf("ApplyTx: %v", err)
	}
	if got := s.Get(claimant).Balance; got != p.ClaimAmount {
		t.Fatalf("claimant balance = %d, want %d", got, p.ClaimAmount)
	}
	if got := s.Get(p.FaucetAddress).Balance; got != 1_000-p.ClaimAmount {
		t.Fatalf("faucet balance = %d, want %d", got, 1_000-p.ClaimAmount)
	}
	if got := s.Get(claimant).ClaimedEpoch; got != 1 {
		t.Fatalf("claim marker = %d, want 1", got)
	}
}

// Two solved claims from ONE key in the SAME epoch. The first advances the nonce
// and sets the marker, so the second must be rejected by the EPOCH rule - which
// is why its account nonce is deliberately 1, matching the account, and its
// puzzle is genuinely solved for the epoch it carries, so neither the nonce
// check nor the puzzle check can be what rejects it.
func TestClaimRejectsSecondClaimInTheSameEpoch(t *testing.T) {
	p := testParams(t)
	s := NewWithParams(p)
	s.Set(p.FaucetAddress, Account{Balance: 1_000})

	pub, priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	// Solve WITH the epoch the claim carries (1): PowDigest binds the epoch into
	// the preimage, so a nonce found for any other epoch fails the target check.
	firstNonce, ok := faucet.Solve(pub, 1, p.PowTarget, p.PowArgon2, 1_000_000)
	if !ok {
		t.Fatal("could not solve the first test puzzle")
	}
	first := &types.Tx{Type: types.TxFaucetClaim, From: types.AddressFromPub(pub), PubKey: pub,
		Nonce: 0, Epoch: 1, PowNonce: firstNonce}
	firstHash := first.SigningHash()
	first.Sig = crypto.Sign(priv, firstHash[:])
	if err := s.ApplyTx(first); err != nil {
		t.Fatalf("first claim: %v", err)
	}

	secondNonce, ok := faucet.Solve(pub, 1, p.PowTarget, p.PowArgon2, 1_000_000)
	if !ok {
		t.Fatal("could not solve the second test puzzle")
	}
	second := &types.Tx{Type: types.TxFaucetClaim, From: types.AddressFromPub(pub), PubKey: pub,
		Nonce: 1, Epoch: 1, PowNonce: secondNonce}
	secondHash := second.SigningHash()
	second.Sig = crypto.Sign(priv, secondHash[:])

	before := s.Root()
	if err := s.ApplyTx(second); !errors.Is(err, ErrClaimTooSoon) {
		t.Fatalf("expected ErrClaimTooSoon, got %v", err)
	}
	// A rejected claim must leave the state EXACTLY as the first claim left it:
	// the claimant's balance, nonce and marker, and the faucet's balance.
	if s.Root() != before {
		t.Fatal("a rejected claim changed the state")
	}
	if got := s.Get(types.AddressFromPub(pub)).Balance; got != p.ClaimAmount {
		t.Fatalf("a rejected claim changed the balance: got %d, want %d", got, p.ClaimAmount)
	}
}

// Find a nonce that does NOT meet the target, so that only the puzzle check can
// reject an otherwise perfectly formed and correctly signed claim.
func TestClaimRejectsBadProofOfWork(t *testing.T) {
	p := testParams(t)
	s := NewWithParams(p)
	s.Set(p.FaucetAddress, Account{Balance: 1_000})

	pub, priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	var badNonce uint64
	for k := uint64(0); ; k++ {
		if !faucet.MeetsTarget(faucet.PowDigest(pub, 1, k, p.PowArgon2), p.PowTarget) {
			badNonce = k
			break
		}
	}
	tx := &types.Tx{Type: types.TxFaucetClaim, From: types.AddressFromPub(pub), PubKey: pub,
		Nonce: 0, Epoch: 1, PowNonce: badNonce}
	sigHash := tx.SigningHash()
	tx.Sig = crypto.Sign(priv, sigHash[:])

	before := s.Root()
	if err := s.ApplyTx(tx); !errors.Is(err, ErrBadProofOfWork) {
		t.Fatalf("expected ErrBadProofOfWork, got %v", err)
	}
	// Like every other reject test: a rejected claim must leave the state
	// completely unchanged.
	if s.Root() != before {
		t.Fatal("a rejected claim changed the state")
	}
}

// Fund the faucet with LESS than one claim, so only the balance rule can reject.
func TestClaimRejectsWhenTheFaucetIsEmpty(t *testing.T) {
	p := testParams(t)
	s := NewWithParams(p)
	s.Set(p.FaucetAddress, Account{Balance: p.ClaimAmount - 1})

	tx := solvedClaim(t, p, 1, 0)
	before := s.Root()
	if err := s.ApplyTx(tx); !errors.Is(err, ErrFaucetEmpty) {
		t.Fatalf("expected ErrFaucetEmpty, got %v", err)
	}
	if s.Root() != before {
		t.Fatal("a rejected claim changed the state")
	}
	if got := s.Get(tx.From).Balance; got != 0 {
		t.Fatalf("a rejected claim credited the claimant: %d", got)
	}
}

// The faucet address is derived from the genesis hash, not from a public key, so
// no private key exists for it and no signature can ever be produced. Paying a
// claim therefore debits an account without its owner's signature - the single
// such place in the codebase. This test pins that the debit needs no signature
// from the faucet: the only signature on the transaction is the claimant's.
func TestClaimDebitsTheFaucetWithoutItsSignature(t *testing.T) {
	p := testParams(t)
	s := NewWithParams(p)
	s.Set(p.FaucetAddress, Account{Balance: 1_000})

	tx := solvedClaim(t, p, 1, 0)
	if tx.From == p.FaucetAddress {
		t.Fatal("fixture error: the claimant is the faucet address")
	}
	sigHash := tx.SigningHash()
	if !crypto.Verify(tx.PubKey, sigHash[:], tx.Sig) {
		t.Fatal("fixture error: the claim is not validly signed by its claimant")
	}
	if err := s.ApplyTx(tx); err != nil {
		t.Fatalf("ApplyTx: %v", err)
	}
	if got := s.Get(p.FaucetAddress).Balance; got != 1_000-p.ClaimAmount {
		t.Fatalf("the faucet was not debited: %d", got)
	}
}

// A zero-valued parameter set must fail the claim cleanly. argon2.IDKey PANICS on
// zero rounds, and state.New() deliberately leaves claims unusable, so without this
// guard an unparameterized state would crash the node instead of rejecting the claim.
func TestClaimRejectsZeroValuedPuzzleParameters(t *testing.T) {
	s := New() // no params: claims must be unusable, not fatal
	pub, priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	tx := &types.Tx{Type: types.TxFaucetClaim, From: types.AddressFromPub(pub), PubKey: pub,
		Nonce: 0, Epoch: 1, PowNonce: 0}
	sigHash := tx.SigningHash()
	tx.Sig = crypto.Sign(priv, sigHash[:])

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("claiming against an unparameterized state panicked: %v", r)
		}
	}()
	if err := s.ApplyTx(tx); !errors.Is(err, ErrBadProofOfWork) {
		t.Fatalf("expected ErrBadProofOfWork, got %v", err)
	}
}

// A zero EpochBlocks would make the epoch derivation DIVIDE BY ZERO - a
// crashed node, not a clean rejection - so the parameter guard covers it like
// the Argon2 fields. Shipped genesis values are 1_000 and 10_000, but a
// malformed genesis (or any direct NewWithParams caller) must not be able to
// panic the transition function either.
func TestClaimRejectsAZeroEpochLength(t *testing.T) {
	p := testParams(t)
	p.EpochBlocks = 0
	s := NewWithParams(p)
	pub, priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	tx := &types.Tx{Type: types.TxFaucetClaim, From: types.AddressFromPub(pub), PubKey: pub,
		Nonce: 0, Epoch: 1, PowNonce: 0}
	sigHash := tx.SigningHash()
	tx.Sig = crypto.Sign(priv, sigHash[:])

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("claiming against a state with EpochBlocks == 0 panicked: %v", r)
		}
	}()
	if err := s.ApplyTx(tx); !errors.Is(err, ErrBadProofOfWork) {
		t.Fatalf("expected ErrBadProofOfWork, got %v", err)
	}
}

// The claim must carry the CURRENT epoch: epoch(h) = h/EpochBlocks + 1, which is
// 1-BASED. A solution solved for a later epoch cannot be spent early, and a
// stale epoch cannot be spent late. Every puzzle here is genuinely solved for
// the epoch its claim carries, so only the epoch rule can reject.
func TestClaimRequiresTheCurrentEpoch(t *testing.T) {
	p := testParams(t)
	s := NewWithParams(p)
	s.Set(p.FaucetAddress, Account{Balance: 1_000})

	// Height 0 is in epoch 1 (0/10+1), so an epoch-2 claim is EARLY.
	early := solvedClaim(t, p, 2, 0)
	if err := s.ApplyTx(early); !errors.Is(err, ErrWrongEpoch) {
		t.Fatalf("expected ErrWrongEpoch for an early claim, got %v", err)
	}
	if s.Get(early.From).Balance != 0 {
		t.Fatal("a rejected early claim credited the claimant")
	}

	// Height 9 is the LAST block of epoch 1: 9/10+1 = 1. A solved epoch-1 claim
	// succeeds there - this pins the 1-based boundary (a 0-based rule would
	// derive epoch 0 at height 9 and refuse the claim).
	s.SetHeight(9)
	lastOfFirstEpoch := solvedClaim(t, p, 1, 0)
	if err := s.ApplyTx(lastOfFirstEpoch); err != nil {
		t.Fatalf("claim on the last block of epoch 1: %v", err)
	}

	// Height 10 is the FIRST block of epoch 2: 10/10+1 = 2.
	s.SetHeight(10)
	// A fresh key's STALE epoch-1 claim, still correctly signed and solved, and
	// the same key's nonce at 0, so only the epoch rule can reject it.
	stale := solvedClaim(t, p, 1, 0)
	if err := s.ApplyTx(stale); !errors.Is(err, ErrWrongEpoch) {
		t.Fatalf("expected ErrWrongEpoch for a stale-epoch claim, got %v", err)
	}
	current := solvedClaim(t, p, 2, 0)
	if err := s.ApplyTx(current); err != nil {
		t.Fatalf("claim on the first block of epoch 2: %v", err)
	}
	if got := s.Get(current.From).ClaimedEpoch; got != 2 {
		t.Fatalf("claim marker = %d, want 2", got)
	}
}

// A key that claims in a LATER epoch is paid again, and its credit ACCUMULATES
// rather than being overwritten. This is the only test that pins the mandated
// nonce bump and the += on the credit: every other claim test starts its
// claimant at balance 0 with nonce 0, so `+=` and `=` are indistinguishable
// there, and removing `claimant.Nonce++` leaves the whole suite green.
func TestClaimPaysAgainInALaterEpochAndAccumulates(t *testing.T) {
	p := testParams(t)
	s := NewWithParams(p)
	s.Set(p.FaucetAddress, Account{Balance: 10_000})

	pub, priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	claim := func(epoch, nonce uint64) {
		t.Helper()
		pow, ok := faucet.Solve(pub, epoch, p.PowTarget, p.PowArgon2, 1_000_000)
		if !ok {
			t.Fatal("could not solve the test puzzle")
		}
		tx := &types.Tx{Type: types.TxFaucetClaim, From: types.AddressFromPub(pub), PubKey: pub,
			Nonce: nonce, Epoch: epoch, PowNonce: pow}
		sigHash := tx.SigningHash()
		tx.Sig = crypto.Sign(priv, sigHash[:])
		if err := s.ApplyTx(tx); err != nil {
			t.Fatalf("claim(epoch=%d, nonce=%d): %v", epoch, nonce, err)
		}
	}

	claim(1, 0)
	// Height 10 is the FIRST block of epoch 2 (10/10+1), the same boundary the
	// current-epoch test pins: without moving the height the epoch-2 claim
	// would be rejected as EARLY rather than exercised.
	s.SetHeight(10)
	claim(2, 1)

	acc := s.Get(types.AddressFromPub(pub))
	if acc.Balance != 2*p.ClaimAmount {
		t.Fatalf("balance = %d, want %d - the credit did not accumulate", acc.Balance, 2*p.ClaimAmount)
	}
	if acc.Nonce != 2 {
		t.Fatalf("nonce = %d, want 2 - the mandated nonce bump is missing", acc.Nonce)
	}
	if acc.ClaimedEpoch != 2 {
		t.Fatalf("claim marker = %d, want 2", acc.ClaimedEpoch)
	}
	if got := s.Get(p.FaucetAddress).Balance; got != 10_000-2*p.ClaimAmount {
		t.Fatalf("faucet balance = %d, want %d", got, 10_000-2*p.ClaimAmount)
	}
}

// The height is EXECUTION CONTEXT, never committed state: it must not enter the
// state root (the block header already commits to it), and Clone must carry it,
// or a cloned transition (ApplyBlock) would derive claim epochs from a height
// that is not the block's.
func TestHeightIsExecutionContextOnly(t *testing.T) {
	a, _, _ := keypair(t)
	s := New()
	s.Set(a, Account{Balance: 5})

	s.SetHeight(7)
	withHeight7 := s.Root()
	s.SetHeight(300)
	if s.Root() != withHeight7 {
		t.Fatal("the height is hashed into the state root")
	}
	if s.Clone().height != 300 {
		t.Fatal("Clone did not carry the height")
	}
}

// The claimant-credit overflow guard must run BEFORE the faucet debit. Both
// of this file's entry points' doc comments promise that every validation
// runs before the first write, so a rejected claim must leave the state -
// INCLUDING the faucet - completely unchanged; a guard below the debit would
// leave the faucet debited and the claimant uncredited on an (unreachable,
// while supply is bounded) overflow - a partial application.
func TestClaimBalanceOverflowRejectsBeforeTheDebit(t *testing.T) {
	p := testParams(t)
	s := NewWithParams(p)
	s.Set(p.FaucetAddress, Account{Balance: 1_000})

	tx := solvedClaim(t, p, 1, 0)
	claimant := tx.From
	// A balance that cannot take p.ClaimAmount more sparks: only the
	// claimant-credit overflow guard can reject this otherwise perfectly
	// formed claim.
	s.Set(claimant, Account{Balance: math.MaxUint64})
	before := s.Root()
	if err := s.ApplyTx(tx); !errors.Is(err, ErrBalanceOverflow) {
		t.Fatalf("expected ErrBalanceOverflow, got %v", err)
	}
	if got := s.Get(p.FaucetAddress).Balance; got != 1_000 {
		t.Fatalf("the faucet balance = %d, want 1_000 - the faucet was debited before the overflow guard ran", got)
	}
	if s.Root() != before {
		t.Fatal("an overflowed claim changed the state")
	}
}

// A block is attacker-chosen input. Validating one faucet claim costs every validator a
// full Argon2id evaluation before it can be accepted or rejected, so unbounded the cost
// of deciding a block is its claim count alone - one malicious proposer could price a
// block with thousands of puzzle evaluations on every validator. A block over the bound
// must therefore be INVALID, not merely slow: the count is rejected before the first
// puzzle is evaluated, so nothing above the bound is ever paid for.
//
// The tests below set the bound explicitly rather than inheriting any package
// default, so the expectation is independent of the shipped genesis constants.
const testClaimBound = 8

// signedClaim builds a claim from a fresh key whose signature is valid but
// whose puzzle is garbage (PowNonce 0). Its only use is proving that
// ApplyBlock rejects on the COUNT before evaluating anything - the puzzle is
// never reached.
func signedClaim(t *testing.T, epoch, nonce uint64) *types.Tx {
	t.Helper()
	pub, priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	tx := &types.Tx{
		Type: types.TxFaucetClaim, From: types.AddressFromPub(pub), PubKey: pub,
		Nonce: nonce, Epoch: epoch, PowNonce: 0,
	}
	sigHash := tx.SigningHash()
	tx.Sig = crypto.Sign(priv, sigHash[:])
	return tx
}

// One block carrying testClaimBound+1 GENUINELY SOLVED, validly signed claims:
// every puzzle below the bound would verify, so only the count rule can reject
// the block. Remove the count check and this block is accepted wholesale -
// which is the amplification attack: bound claims cost bound Argon2id
// evaluations on every validator, per block.
func TestApplyBlockRejectsABlockWithTooManyClaims(t *testing.T) {
	p := testParams(t)
	p.MaxClaimsPerBlock = testClaimBound
	s := NewWithParams(p)
	s.Set(p.FaucetAddress, Account{Balance: 100 * testClaimBound})

	txs := make([]types.Tx, 0, testClaimBound+1)
	for i := 0; i <= testClaimBound; i++ {
		txs = append(txs, *solvedClaim(t, p, 1, 0))
	}
	before := s.Root()
	if _, err := s.ApplyBlock(txs); !errors.Is(err, ErrTooManyClaims) {
		t.Fatalf("expected ErrTooManyClaims for %d claims against a bound of %d, got %v",
			testClaimBound+1, testClaimBound, err)
	}
	if s.Root() != before {
		t.Fatal("a block rejected for too many claims changed the state")
	}
}

// The bound is checked BEFORE the first puzzle is evaluated, or it bounds
// nothing: the attacker still extracts the work and only the verdict changes.
// This test pins the PLACEMENT, not just the verdict, by making evaluation
// itself observable: the puzzle parameters are deliberately zeroed, so the
// first line of applyFaucetClaim rejects ANY evaluated claim with
// ErrBadProofOfWork - without running Argon2id. Every transaction in the
// block is therefore a tripwire. Correctly placed, the count check fires
// first and the error is ErrTooManyClaims; a check moved after the
// transaction loop, or inside applyFaucetClaim below its guard, evaluates
// tx 0 first and returns ErrBadProofOfWork - and this test fails.
func TestApplyBlockCountsClaimsBeforeEvaluatingAnyTransaction(t *testing.T) {
	p := testParams(t)
	p.MaxClaimsPerBlock = testClaimBound
	p.PowArgon2 = faucet.Argon2Params{} // any evaluated claim would trip the zero-param guard
	p.EpochBlocks = 0
	s := NewWithParams(p)

	txs := make([]types.Tx, 0, testClaimBound+1)
	for i := 0; i <= testClaimBound; i++ {
		txs = append(txs, *signedClaim(t, 1, 0))
	}
	if _, err := s.ApplyBlock(txs); !errors.Is(err, ErrTooManyClaims) {
		t.Fatalf("expected ErrTooManyClaims before any claim was evaluated, got %v", err)
	}
}

// A block carrying EXACTLY the bound is valid: the bound is inclusive, so the
// off-by-one is pinned in both directions - a check that rejects at the bound
// fails this test (TestApplyBlockAcceptsABlockAtTheClaimBound), and a check
// that accepts one past the bound fails
// TestApplyBlockRejectsABlockWithTooManyClaims. Every claim here is genuinely
// solved and from its own fresh key, so acceptance proves the whole block
// really applied rather than failing for some unrelated rule.
func TestApplyBlockAcceptsABlockAtTheClaimBound(t *testing.T) {
	p := testParams(t)
	p.MaxClaimsPerBlock = testClaimBound
	s := NewWithParams(p)
	s.Set(p.FaucetAddress, Account{Balance: testClaimBound * p.ClaimAmount})

	txs := make([]types.Tx, 0, testClaimBound)
	for i := 0; i < testClaimBound; i++ {
		txs = append(txs, *solvedClaim(t, p, 1, 0))
	}
	next, err := s.ApplyBlock(txs)
	if err != nil {
		t.Fatalf("a block at the claim bound must be accepted: %v", err)
	}
	if got := next.Get(p.FaucetAddress).Balance; got != 0 {
		t.Fatalf("faucet balance = %d, want 0 - the bound claims were not all paid", got)
	}
	for _, tx := range txs {
		if got := next.Get(tx.From).Balance; got != p.ClaimAmount {
			t.Fatalf("claimant %x balance = %d, want %d", tx.From, got, p.ClaimAmount)
		}
	}
}

// A block UNDER the bound with no claims at all is unaffected by the rule:
// the default zero bound means "not engaged" for states constructed without
// parameters, so this pins that the count check never fires on claim-free
// blocks (and never divides the bound space into anything surprising).
func TestApplyBlockAcceptsAClaimFreeBlockWithTheBoundUnset(t *testing.T) {
	p := testParams(t) // MaxClaimsPerBlock deliberately left 0: bound not engaged
	s := NewWithParams(p)

	from, pub, priv := keypair(t)
	to, _, _ := keypair(t)
	s.Set(from, Account{Balance: 100})
	txs := []types.Tx{*transfer(t, pub, priv, from, 0, 40, to)}
	next, err := s.ApplyBlock(txs)
	if err != nil {
		t.Fatalf("a claim-free block must be accepted with the bound unset: %v", err)
	}
	if next.Get(to).Balance != 40 {
		t.Fatalf("recipient balance = %d, want 40", next.Get(to).Balance)
	}
}
