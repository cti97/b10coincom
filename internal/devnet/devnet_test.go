package devnet

import (
	"errors"
	"testing"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/faucet"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/mempool"
	"github.com/cti97/b10coincom/internal/node"
	"github.com/cti97/b10coincom/internal/state"
	"github.com/cti97/b10coincom/internal/types"
)

// The acceptance criterion for M1: one call produces a real chain of 100
// blocks, including a transfer, and the state is reproducible.
func TestDevnetProduces100Blocks(t *testing.T) {
	got, err := Run(Options{Dir: t.TempDir(), Blocks: 100})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got.Height != 100 {
		t.Fatalf("height = %d, want 100", got.Height)
	}
	if got.TxsIncluded == 0 {
		t.Fatal("no transactions were included; transfer path is untested")
	}
	if got.StateRoot == ([32]byte{}) {
		t.Fatal("state root is empty")
	}
}

// Running twice from scratch must produce an identical final state root.
// This is the determinism guarantee the whole design rests on.
func TestDevnetIsDeterministic(t *testing.T) {
	a, err := Run(Options{Dir: t.TempDir(), Blocks: 50})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Run(Options{Dir: t.TempDir(), Blocks: 50})
	if err != nil {
		t.Fatal(err)
	}
	if a.StateRoot != b.StateRoot {
		t.Fatalf("two runs disagree:\n %x\n %x", a.StateRoot, b.StateRoot)
	}
}

// Determinism must hold THROUGH the faucet too: a run that solves puzzles and
// pays claims must be reproducible like a plain run. That only holds because
// the claimant keys are DERIVED, not random (Solve's upward nonce scan and
// Ed25519 are deterministic), so two runs agree on everything a claim moved.
func TestDevnetClaimRunIsReproducible(t *testing.T) {
	aDir := t.TempDir()
	a, err := Run(Options{Dir: aDir, Blocks: 8, Claims: 3})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	b, err := Run(Options{Dir: t.TempDir(), Blocks: 8, Claims: 3})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if a.Claimed != 3 {
		t.Fatalf("fixture error: claimed = %d, want 3; the reproducibility comparison is vacuous", a.Claimed)
	}
	// The double-claim blocks the scenario produces are part of what the two
	// runs must agree on: three paid claims, three refusals.
	if a.DoubleClaimsRefused != a.Claimed {
		t.Fatalf("fixture error: refused %d double claims for %d paid claims; the anti-farming proof did not run",
			a.DoubleClaimsRefused, a.Claimed)
	}
	if a.StateRoot != b.StateRoot {
		t.Fatalf("two claim runs disagree:\n %x\n %x", a.StateRoot, b.StateRoot)
	}
	if a.ClaimedBalance != b.ClaimedBalance || a.FaucetBalance != b.FaucetBalance || a.EmittedTotal != b.EmittedTotal {
		t.Fatalf("two claim runs disagree on the faucet ledgers:\n claimed %d, faucet %d, emitted %d\n claimed %d, faucet %d, emitted %d",
			a.ClaimedBalance, a.FaucetBalance, a.EmittedTotal,
			b.ClaimedBalance, b.FaucetBalance, b.EmittedTotal)
	}
	// A replayed RUN WITH CLAIMS must agree with what the run reported:
	// roots, the claim count, and TxsIncluded (the claim txs belong to it in
	// both, so a run that stopped counting claims or a replay that
	// overcounted fail here, not silently).
	replayed, err := Replay(aDir)
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if replayed.StateRoot != a.StateRoot {
		t.Fatal("replay of a claim run reached a different root")
	}
	if replayed.Claimed != a.Claimed {
		t.Fatalf("replay claimed = %d, run reported %d", replayed.Claimed, a.Claimed)
	}
	if replayed.TxsIncluded != a.TxsIncluded {
		t.Fatalf("replay TxsIncluded = %d, run reported %d (the claim txs must count in both)", replayed.TxsIncluded, a.TxsIncluded)
	}
	if replayed.FaucetBalance != a.FaucetBalance || replayed.EmittedTotal != a.EmittedTotal {
		t.Fatalf("replay ledgers diverged:\n faucet %d, emitted %d\n faucet %d, emitted %d",
			replayed.FaucetBalance, replayed.EmittedTotal, a.FaucetBalance, a.EmittedTotal)
	}
}

// Reopening an existing devnet directory must replay to the same root.
func TestDevnetReplayMatches(t *testing.T) {
	dir := t.TempDir()
	first, err := Run(Options{Dir: dir, Blocks: 20})
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := Replay(dir)
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if replayed.StateRoot != first.StateRoot {
		t.Fatal("replay produced a different state root")
	}
	if replayed.Height != first.Height {
		t.Fatalf("replay height = %d, want %d", replayed.Height, first.Height)
	}
	// A replayed hard zero would be indistinguishable from a chain that
	// genuinely included nothing: Replay must report the same non-zero count
	// the run did, recomputed from the stored blocks.
	if first.TxsIncluded == 0 {
		t.Fatal("test setup: the run included no transactions")
	}
	if replayed.TxsIncluded != first.TxsIncluded {
		t.Fatalf("replay TxsIncluded = %d, run reported %d", replayed.TxsIncluded, first.TxsIncluded)
	}
}

func TestDevnetRejectsZeroBlocks(t *testing.T) {
	if _, err := Run(Options{Dir: t.TempDir(), Blocks: 0}); err == nil {
		t.Fatal("expected an error for zero blocks")
	}
}

func TestDevnetClaimsFromTheFaucet(t *testing.T) {
	s, err := Run(Options{Dir: t.TempDir(), Blocks: 20, Claims: 1})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if s.Claimed != 1 {
		t.Fatalf("claimed = %d, want 1", s.Claimed)
	}
	if s.ClaimedBalance != s.ClaimAmount {
		t.Fatalf("claimant balance = %d, want the claim amount %d", s.ClaimedBalance, s.ClaimAmount)
	}
	// The run is the anti-farming proof too: the paid claim's same-epoch
	// double claim must have been attempted and refused, so the refusal
	// count can be neither zero (the proof did not run) nor larger than one
	// paid claim.
	if s.DoubleClaimsRefused != s.Claimed {
		t.Fatalf("refused double claims = %d, claim paid = %d; the scenario must refuse exactly one double claim per paid claim",
			s.DoubleClaimsRefused, s.Claimed)
	}
	// Every paid attempt takes exactly two blocks — the claim's and the
	// refused double's — so the height pins the scenario's shape.
	if want := 20 + s.Claimed + s.DoubleClaimsRefused; s.Height != want {
		t.Fatalf("height = %d, want %d (blocks, plus one block per claim attempt and per refused double claim)",
			s.Height, want)
	}
}

// Emission is the only thing that funds the faucet, so the credits must exactly
// account for what was paid out: emitted - claimed*amount == the faucet balance.
// A claim paid from nowhere - or a miscounted emission - would break this
// identity, which is why the balance check is over the EXACT sums, not a range.
//
// NOTE on the plan's "many claim attempts ... most must be refused" intent:
// against the corrected 1-b10 fixture claim amount, the eight attempts on a
// 10-block run are all actually payable (the run's 26 blocks — attempts plus
// their double-claim refusals — emit 13.5 b10, covering 8 b10 of claims with
// plenty to spare), so this body exercises the exact ledgers rather than a
// refusal. Refusals are pinned at the state layer by
// TestClaimRejectsWhenTheFaucetIsEmpty.
func TestFaucetIsNeverOverdrawn(t *testing.T) {
	// Many claim attempts against the emission of only a few blocks.
	s, err := Run(Options{Dir: t.TempDir(), Blocks: 10, Claims: 8})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	want := s.EmittedTotal - s.Claimed*s.ClaimAmount
	if s.FaucetBalance != want {
		t.Fatalf("faucet balance = %d, want emitted %d - claimed %d x %d = %d",
			s.FaucetBalance, s.EmittedTotal, s.Claimed, s.ClaimAmount, want)
	}
	if s.Claimed*s.ClaimAmount > s.EmittedTotal {
		t.Fatalf("paid out %d sparks from an emission of only %d",
			s.Claimed*s.ClaimAmount, s.EmittedTotal)
	}
	// The identity is only load-bearing if claims actually happened: with all
	// eight attempts payable, fewer claims here would mean the claim path broke.
	if s.Claimed != 8 {
		t.Fatalf("fixture error: claimed = %d, want all 8 attempts paid", s.Claimed)
	}
}

func TestDevnetGenesisIsDevnetNotTestnet(t *testing.T) {
	s, err := Run(Options{Dir: t.TempDir(), Blocks: 1})
	if err != nil {
		t.Fatal(err)
	}
	if s.ChainID != genesis.Devnet().ChainID {
		t.Fatalf("chain ID = %q, want the devnet chain", s.ChainID)
	}
}

// The anti-farming rule, end to end: one key, one claim per epoch. The second
// claim is solved and signed just as carefully as the first, so only the epoch
// marker can reject it.
func TestDevnetRefusesASecondClaimInTheSameEpoch(t *testing.T) {
	dir := t.TempDir()
	g := genesis.Devnet()
	c, err := chain.Open(g, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, priv := genesis.DevValidatorKey()
	mp := mempool.New(100)
	n := node.New(c, priv, mp)

	pub, key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	params := state.Params{
		FaucetAddress: g.FaucetAddress(),
		ClaimAmount:   g.Params.ClaimAmountSparks,
		EpochBlocks:   g.Params.EpochBlocks,
		PowArgon2:     g.Params.FaucetPowArgon2,
		PowTarget:     g.Params.FaucetPowTarget,
	}

	// Block 1 funds the faucet with its emission, so a claim can be paid.
	if _, err := n.RunOnce(g0Time + 1); err != nil {
		t.Fatal(err)
	}
	// Epochs are 1-BASED. Using the 0-based form here makes the first claim carry an
	// epoch the rule rejects with ErrWrongEpoch, so it would never be paid.
	epoch := c.Height()/params.EpochBlocks + 1

	claim := func(nonce uint64) *types.Tx {
		pow, ok := faucet.Solve(pub, epoch, params.PowTarget, params.PowArgon2, 5_000_000)
		if !ok {
			t.Fatal("could not solve the devnet puzzle")
		}
		tx := &types.Tx{
			Type: types.TxFaucetClaim, From: types.AddressFromPub(pub), PubKey: pub,
			Nonce: nonce, Epoch: epoch, PowNonce: pow,
		}
		sigHash := tx.SigningHash()
		tx.Sig = crypto.Sign(key, sigHash[:])
		return tx
	}

	first := claim(c.State().Get(types.AddressFromPub(pub)).Nonce)
	if errs := mp.Add([]types.Tx{*first}); errs[0] != nil {
		t.Fatalf("mempool.Add: %v", errs[0])
	}
	if _, err := n.RunOnce(g0Time + 2); err != nil {
		t.Fatalf("first claim block: %v", err)
	}
	if got := c.State().Get(types.AddressFromPub(pub)).Balance; got != params.ClaimAmount {
		t.Fatalf("claimant balance = %d, want %d", got, params.ClaimAmount)
	}

	second := claim(c.State().Get(types.AddressFromPub(pub)).Nonce)
	if errs := mp.Add([]types.Tx{*second}); errs[0] != nil {
		t.Fatalf("mempool.Add: %v", errs[0])
	}
	// RunOnce evicts a transaction that cannot apply rather than failing, so the
	// block is produced but must not contain the claim.
	b, err := n.RunOnce(g0Time + 3)
	if err != nil {
		t.Fatalf("second claim block: %v", err)
	}
	if len(b.Txs) != 0 {
		t.Fatalf("the second same-epoch claim was included: %d txs", len(b.Txs))
	}
	if got := c.State().Get(types.AddressFromPub(pub)).Balance; got != params.ClaimAmount {
		t.Fatalf("a refused claim still paid out: balance = %d, want %d", got, params.ClaimAmount)
	}
	if got := c.State().Get(types.AddressFromPub(pub)).ClaimedEpoch; got != epoch {
		t.Fatalf("claim marker = %d, want %d", got, epoch)
	}

	// The empty block proves the claim was REFUSED, but not why. Pin the
	// sentinel: the same transaction, applied directly to a CLONED state (the
	// live chain is untouched), must fail with the rule's own ErrClaimTooSoon.
	// The clone carries the state's execution height, so the epoch check
	// passes and the refusal can only come from the claim marker — a test
	// that stopped at the empty block would also pass against a claim
	// rejected for any other reason, and would pass while a 0-based epoch
	// (rejected as ErrWrongEpoch, hence never payable) masqueraded as the
	// anti-farming rule working.
	if err := c.State().Clone().ApplyTx(second); !errors.Is(err, state.ErrClaimTooSoon) {
		t.Fatalf("the second same-epoch claim failed for the wrong reason: %v", err)
	}
}
