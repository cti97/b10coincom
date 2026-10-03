package devnet

import (
	"testing"

	"github.com/cti97/b10coincom/internal/genesis"
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
	run := func() Summary {
		s, err := Run(Options{Dir: t.TempDir(), Blocks: 8, Claims: 3})
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		return s
	}
	a, b := run(), run()
	if a.Claimed != 3 {
		t.Fatalf("fixture error: claimed = %d, want 3; the reproducibility comparison is vacuous", a.Claimed)
	}
	if a.StateRoot != b.StateRoot {
		t.Fatalf("two claim runs disagree:\n %x\n %x", a.StateRoot, b.StateRoot)
	}
	if a.ClaimedBalance != b.ClaimedBalance || a.FaucetBalance != b.FaucetBalance || a.EmittedTotal != b.EmittedTotal {
		t.Fatalf("two claim runs disagree on the faucet ledgers:\n claimed %d, faucet %d, emitted %d\n claimed %d, faucet %d, emitted %d",
			a.ClaimedBalance, a.FaucetBalance, a.EmittedTotal,
			b.ClaimedBalance, b.FaucetBalance, b.EmittedTotal)
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
}

// Emission is the only thing that funds the faucet, so the credits must exactly
// account for what was paid out: emitted - claimed*amount == the faucet balance.
// A claim paid from nowhere - or a miscounted emission - would break this
// identity, which is why the balance check is over the EXACT sums, not a range.
//
// NOTE on the plan's "many claim attempts ... most must be refused" intent:
// against the corrected 1-b10 fixture claim amount, the eight attempts on a
// 10-block run are all actually payable (19 blocks' worth of emission covers
// 8 b10 of claims with 1.5 b10 to spare), so this body exercises the exact
// ledgers rather than a refusal. Refusals are pinned at the state layer by
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
