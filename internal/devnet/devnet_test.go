package devnet

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	mp := mempool.New(100, g.Hash(), c.AdmissionHead)
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
		pow, ok := faucet.SolveClaim(pub, epoch, params.PowTarget, params.PowArgon2, 5_000_000)
		if !ok {
			t.Fatal("could not solve the devnet puzzle")
		}
		tx := &types.Tx{
			Type: types.TxFaucetClaim, From: types.AddressFromPub(pub), PubKey: pub,
			Nonce: nonce, Epoch: epoch, PowNonce: pow,
		}
		sigHash := tx.SigningHash(g.Hash())
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
	// Since audit R-1 the mempool enforces the one-claim-per-epoch rule at
	// ADMISSION: the second claim is refused at the door, so the pool never
	// holds it and never pays for its puzzle. The rule's own sentinel pins the
	// reason, exactly as the direct-state check at the end of this test does.
	if err := mp.Add([]types.Tx{*second})[0]; !errors.Is(err, state.ErrClaimTooSoon) {
		t.Fatalf("second same-epoch claim at admission: err = %v, want state.ErrClaimTooSoon", err)
	}
	// The block is still produced (Take returns nothing) and must not contain
	// the claim.
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

// --- The multi-validator devnet (M3) ---

// The milestone's acceptance: four validators must AGREE, not merely each
// build blocks. A single node producing blocks proves nothing about consensus.
//
// Killing mutant A (compiled): drive reports Agreed unconditionally true. The
// forked-committee test below owns that kill; this test would happily pass
// with a lying Agreed, which is exactly why it also pins the pieces a lying
// boolean hides: the committee DROVEN (four chain directories on disk), the
// committee REPORTED (one height per index, all four present), the committee's
// own chain ID, and the longest height.
func TestRunMultiWithFourValidatorsAgrees(t *testing.T) {
	dir := t.TempDir()
	s, err := RunMulti(Options{Dir: dir, Blocks: 50, Validators: 4})
	if err != nil {
		t.Fatalf("RunMulti: %v", err)
	}
	if s.Validators != 4 {
		t.Fatalf("validators = %d, want 4", s.Validators)
	}
	// Index by index, not by ranging the map: a run that drove two validators
	// while reporting four would still cover whatever the map happens to hold.
	if len(s.ValidatorHeights) != 4 {
		t.Fatalf("ValidatorHeights holds %d entries, want one per driven validator", len(s.ValidatorHeights))
	}
	for i := 0; i < 4; i++ {
		h, ok := s.ValidatorHeights[i]
		if !ok {
			t.Fatalf("no height reported for validator %d", i)
		}
		if h < 50 {
			t.Fatalf("validator %d finalised only %d of 50 blocks", i, h)
		}
	}
	if !s.Agreed {
		t.Fatal("the validators did not agree on a single chain")
	}
	if s.Height != 50 {
		t.Fatalf("Height = %d, want the longest validator's height 50", s.Height)
	}
	// The chain ID literal pins the harness's committee naming (simGenesis
	// derives it from the size): a devnet that reported a stale or invented
	// chain ID fails here.
	if s.ChainID != "b10coin-simnet-4" {
		t.Fatalf("chain ID = %q, want the four-validator committee's own %q", s.ChainID, "b10coin-simnet-4")
	}
	// The committee the run REPORTS is the committee it DROVE: four validators,
	// four chain directories on disk under the run's directory.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	dirs := 0
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "v") {
			dirs++
		}
	}
	if dirs != 4 {
		t.Fatalf("found %d validator chain directories under the run's dir, want 4", dirs)
	}
}

// RunMulti with Validators: 1 behaves deliberately, not accidentally: it does
// NOT fall back to the single-node Run. They are different code paths over
// different genesis — Run drives the devnet fixture (one signer, no round
// protocol, transaction and claim paths); RunMulti drives the real four-phase
// round even with nobody to disagree with, over the committee's own chain
// b10coin-simnet-1. So the flag means what it says — "run consensus with N
// validators" — and --validators 1 is observable as the one-member committee,
// not as the devnet fixture wearing a different flag. Agreement is VACUOUSLY
// true for one validator (one history trivially is the one history; the
// harness's prefix check degenerates to a self-comparison), and this test
// asserts that documented reading rather than pretending the check compared
// anything.
func TestRunMultiWithOneValidatorDrivesAOneMemberCommitteeNotTheSingleNodeRun(t *testing.T) {
	s, err := RunMulti(Options{Dir: t.TempDir(), Blocks: 20, Validators: 1})
	if err != nil {
		t.Fatalf("RunMulti: %v", err)
	}
	if s.Validators != 1 || len(s.ValidatorHeights) != 1 {
		t.Fatalf("validators = %d with %d heights, want exactly the one-validator committee",
			s.Validators, len(s.ValidatorHeights))
	}
	if got := s.ValidatorHeights[0]; got < 20 {
		t.Fatalf("the single validator finalised only %d of 20 blocks", got)
	}
	if !s.Agreed {
		t.Fatal("a one-validator run's single history trivially agrees; the check reported otherwise")
	}
	// The load-bearing assertion: a fallback to Run would report the devnet
	// fixture's chain ID, not the committee's own.
	if s.ChainID != "b10coin-simnet-1" {
		t.Fatalf("chain ID = %q, want %q — a value of %q here would mean the single-node devnet fixture ran instead of a one-validator committee",
			s.ChainID, "b10coin-simnet-1", "b10coin-devnet-1")
	}
}

// The milestone's central liveness property at n=4, exercised through the
// devnet's own surface: with one validator powered off for the whole run, the
// three online validators hold EXACTLY two thirds of TOTAL voting power (the
// bar itself, with no vote to spare) and the chain must still finalise
// o.Blocks. The offline validator keeps its committee seat — the bar is
// unmoved by the outage — and, with no catch-up in M3, its height stays frozen
// at zero; its frozen history must remain a strict prefix of the longest
// chain, so the run still reports agreement.
//
// Killing mutant E (compiled): RunMulti ignores OfflineValidators. Then all
// four validators run, and the frozen assertion fails first (validator 3
// reaches 30 instead of standing at 0).
func TestRunMultiWithAValidatorOfflineStillAdvances(t *testing.T) {
	s, err := RunMulti(Options{Dir: t.TempDir(), Blocks: 30, Validators: 4, OfflineValidators: []int{3}})
	if err != nil {
		t.Fatalf("RunMulti: %v (3 of 4 online is exactly the two-thirds-of-TOTAL bar; the chain must advance)", err)
	}
	for i := 0; i < 3; i++ {
		if got := s.ValidatorHeights[i]; got < 30 {
			t.Fatalf("validator %d finalised only %d of 30 blocks with a validator offline", i, got)
		}
	}
	if got := s.ValidatorHeights[3]; got != 0 {
		t.Fatalf("OFFLINE validator 3 committed %d blocks; a powered-off validator can take no part in the rounds", got)
	}
	if !s.Agreed {
		t.Fatal("the frozen validator's history must remain a strict prefix of the longest chain (behind, never forked); the run reported disagreement")
	}
}

// RunMulti refuses what it cannot honestly do: no committee, no blocks, no
// claims (the claim scenario has no transaction path into a consensus-only
// committee, so accepting --claims here would silently drop it and print
// claims paid = 0 like a broken faucet).
func TestRunMultiRejectsImpossibleOptions(t *testing.T) {
	if _, err := RunMulti(Options{Dir: t.TempDir(), Blocks: 5, Validators: 0}); !errors.Is(err, ErrNoValidators) {
		t.Fatalf("Validators: 0 must fail with ErrNoValidators, got %v", err)
	}
	if _, err := RunMulti(Options{Dir: t.TempDir(), Blocks: 0, Validators: 4}); !errors.Is(err, ErrNoBlocks) {
		t.Fatalf("Blocks: 0 must fail with ErrNoBlocks, got %v", err)
	}
	if _, err := RunMulti(Options{Dir: t.TempDir(), Blocks: 5, Validators: 4, Claims: 1}); !errors.Is(err, ErrClaimsAreMultiUnsupported) {
		t.Fatalf("Claims in a multi-validator run must fail with ErrClaimsAreMultiUnsupported, got %v", err)
	}
	// An out-of-range offline index is a caller bug and fails before any run.
	if _, err := RunMulti(Options{Dir: t.TempDir(), Blocks: 5, Validators: 4, OfflineValidators: []int{7}}); err == nil {
		t.Fatal("an OfflineValidators index outside the committee must fail the run")
	}
}

// forkNet is the stand-in that lets the disagreement path be tested at all.
// Honest simnet validators never disagree — one history is the safety property
// the protocol guarantees — so there is no committee the real harness could
// build that would make Agreed report false. The disagreement is instead
// injected at the layer underneath: two REAL chains opened from the same
// genesis, a conflicting block appended to each at height 1 — a fork no honest
// committee can produce and exactly what a broken tally would produce —
// served through the same multiNet contract RunMulti drives. AssertPrefix
// mirrors simnet.AssertPrefix's documented contract: validator i's whole
// history must be an exact prefix of the longest chain's, block for block.
type forkNet struct {
	chains []*chain.Chain
}

func (f *forkNet) RunBlocks(target uint64) (map[uint64]uint64, error) {
	hs := make(map[uint64]uint64, len(f.chains))
	for i, c := range f.chains {
		hs[uint64(i)] = c.Height()
	}
	return hs, nil
}

func (f *forkNet) AssertPrefix(i int) error {
	if i < 0 || i >= len(f.chains) {
		return fmt.Errorf("validator index %d out of range", i)
	}
	ref, refHeight := f.chains[0], f.chains[0].Height()
	for _, c := range f.chains {
		if c.Height() > refHeight {
			ref, refHeight = c, c.Height()
		}
	}
	c := f.chains[i]
	if c.Height() > refHeight {
		return fmt.Errorf("validator %d stands above the longest chain: it committed blocks nobody else did", i)
	}
	for h := uint64(0); h <= c.Height(); h++ {
		bi, err := c.BlockAt(h)
		if err != nil {
			return err
		}
		br, err := ref.BlockAt(h)
		if err != nil {
			return err
		}
		if bi.ID() != br.ID() {
			return fmt.Errorf("validator %d DIVERGED at height %d: a fork, not a lag", i, h)
		}
	}
	return nil
}

// forkedCommittee builds the two-chain fixture. With fork, the chains commit
// conflicting blocks at height 1 (different timestamps, different block IDs);
// without it, both commit byte-identical blocks — the positive control that
// proves the detector fires on divergence and not on the fixture itself.
func forkedCommittee(t *testing.T, fork bool) *forkNet {
	t.Helper()
	g := genesis.Devnet()
	_, priv := genesis.DevValidatorKey()
	root := t.TempDir()
	a, err := chain.Open(g, filepath.Join(root, "a"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	b, err := chain.Open(g, filepath.Join(root, "b"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })

	// Timestamps must be strictly greater than the genesis time (audit S-8:
	// chain.Append enforces monotonicity now). The fork is still carried by a
	// timestamp difference: fork gives the two chains different blocks at
	// height 1, and the control keeps them byte-identical.
	parent := a.Head().Header.Timestamp
	tsB := parent + 1
	if fork {
		tsB = parent + 2
	}
	bA, err := a.Build(priv, nil, parent+1)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Append(bA); err != nil {
		t.Fatal(err)
	}
	bB, err := b.Build(priv, nil, tsB)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Append(bB); err != nil {
		t.Fatal(err)
	}
	if fork && bA.ID() == bB.ID() {
		t.Fatal("test setup: the two chains did not fork; the disagreement drive would assert nothing")
	}
	if !fork && bA.ID() != bB.ID() {
		t.Fatal("test setup: the control chains committed different blocks at height 1")
	}
	return &forkNet{chains: []*chain.Chain{a, b}}
}

// THE test that proves Agreed can be false. Two validators hold conflicting
// blocks at height 1; the driver must name the divergence, fail the run, and
// report Agreed == false. A boolean hardcoded to true (mutant A) fails here —
// both on the error and on !s.Agreed.
func TestDriveReportsAgreedFalseAndFailsWhenValidatorsDisagree(t *testing.T) {
	s, err := drive(forkedCommittee(t, true), Options{Blocks: 1, Validators: 2})
	if err == nil {
		t.Fatal("a network whose validators hold conflicting blocks at height 1 must FAIL the run, not merely report itself")
	}
	if !strings.Contains(err.Error(), "DIVERGED at height 1") {
		t.Fatalf("the divergence error must name the fork site, got: %v", err)
	}
	if s.Agreed {
		t.Fatal("Agreed reported true for validators holding conflicting blocks at height 1")
	}
	if s.Validators != 2 || len(s.ValidatorHeights) != 2 {
		t.Fatalf("the failed run's summary must still report the committee it drove: got %d validators, %d heights",
			s.Validators, len(s.ValidatorHeights))
	}

	// Positive control: the SAME driver over byte-identical chains reports
	// agreement with no error, so the refusal above is the fork and not a
	// detector that fires at everything.
	s, err = drive(forkedCommittee(t, false), Options{Blocks: 1, Validators: 2})
	if err != nil {
		t.Fatalf("two byte-identical chains must agree: %v", err)
	}
	if !s.Agreed {
		t.Fatal("the disagreement detector fired on chains that are identical")
	}
}
