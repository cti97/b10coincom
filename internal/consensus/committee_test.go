package consensus

import (
	"testing"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/genesis"
)

// ed25519FromSeed exists only so the fixture reads cleanly.
func ed25519FromSeed(seed [32]byte) ed25519PrivateKey { return ed25519NewKeyFromSeed(seed[:]) }

// evenCommittee builds n validators of equal power, with deterministic keys so a
// failure is reproducible.
func evenCommittee(t *testing.T, n int, power uint64) Config {
	t.Helper()
	vals := make([]genesis.Validator, 0, n)
	for i := 0; i < n; i++ {
		vals = append(vals, testValidator(i, power))
	}
	c := Config{Committee: vals, TimeoutBase: 1, TimeoutStep: 1, PowerCapNum: 1, PowerCapDen: 4}
	if err := c.Validate(); err != nil {
		t.Fatalf("even committee rejected: %v", err)
	}
	return c
}

// testValidator derives validator idx's key the one way every consensus test
// fixture must use. Task 4+ add testCommitteeKey with the IDENTICAL derivation;
// TestFixtureKeyDerivationMatchesSharedHelper pins that the two never diverge
// - a mismatch would make every tally test fail with a signature error instead
// of testing what it names.
func testValidator(idx int, power uint64) genesis.Validator {
	h := crypto.HashParts([]byte("b10coin-test-validator"), []byte{byte(idx)})
	priv := ed25519FromSeed(h)
	return genesis.Validator{PubKey: priv.Public().(ed25519PublicKey), Power: power}
}

// sharedDerivation writes out the shared derivation independently of
// testValidator, so the tripwire test below has a second expression to differ
// against.
func sharedDerivation(idx int) ed25519PrivateKey {
	h := crypto.HashParts([]byte("b10coin-test-validator"), []byte{byte(idx)})
	return ed25519NewKeyFromSeed(h[:])
}

func TestFixtureKeyDerivationMatchesSharedHelper(t *testing.T) {
	for i := 0; i < 8; i++ {
		got := string(testValidator(i, 1).PubKey)
		want := string(sharedDerivation(i).Public().(ed25519PublicKey))
		if got != want {
			t.Fatalf("testValidator(%d) diverged from the shared derivation: tally tests would fail with signature errors instead of testing what they name", i)
		}
	}
}

func TestQuorumIsTwoThirdsPlusOne(t *testing.T) {
	cases := []struct {
		total uint64
		want  uint64
	}{
		{4, 3},    // n=4 equal power: >2/3 means at least 3
		{21, 15},  // 21 validators: 2*21/3 + 1 = 15
		{100, 67}, // 2*100/3 + 1 = 67
		{3, 3},    // 2*3/3 + 1 = 3
	}
	for _, tc := range cases {
		if got := quorumFor(tc.total); got != tc.want {
			t.Errorf("quorumFor(%d) = %d, want %d", tc.total, got, tc.want)
		}
	}
}

// Two thirds of TOTAL power, not of online power: an offline validator must make
// quorum HARDER, not easier. If the threshold tracked online weight, taking a
// third of the set offline would lower the bar enough to commit alone.
func TestQuorumDoesNotShrinkWhenValidatorsGoOffline(t *testing.T) {
	c := evenCommittee(t, 4, 1)
	if got := c.Quorum(); got != 3 {
		t.Fatalf("quorum of a 4-validator committee = %d, want 3", got)
	}
}

func TestValidateRejectsAnOverPoweredValidator(t *testing.T) {
	c := evenCommittee(t, 4, 1)
	c.Committee[0].Power = 100 // far above a quarter of the total
	if err := c.Validate(); err == nil {
		t.Fatal("expected a committee with one validator above the power cap to be rejected")
	}
}

func TestValidateRejectsAnEmptyCommittee(t *testing.T) {
	c := Config{TimeoutBase: 1, TimeoutStep: 1, PowerCapNum: 1, PowerCapDen: 4}
	if err := c.Validate(); err == nil {
		t.Fatal("expected an empty committee to be rejected")
	}
}

// The property every validator must agree on without communicating: a proposer
// selection divergence would not lose safety but would stall liveness every round.
func TestProposerIsDeterministicAcrossValidators(t *testing.T) {
	c := evenCommittee(t, 4, 1)
	parent := crypto.HashParts([]byte("parent"))
	for h := uint64(0); h < 5; h++ {
		for r := uint32(0); r < 3; r++ {
			first := c.Proposer(h, r, parent)
			for i := 0; i < 10; i++ {
				if string(c.Proposer(h, r, parent)) != string(first) {
					t.Fatalf("proposer selection is not deterministic at (%d,%d)", h, r)
				}
			}
		}
	}
}

func TestProposerChangesWithHeightRoundAndParent(t *testing.T) {
	c := evenCommittee(t, 4, 1)
	p := crypto.HashParts([]byte("parent"))
	q := crypto.HashParts([]byte("other"))

	base := c.Proposer(1, 0, p)
	// Across enough heights and rounds the proposer must vary, or one validator
	// would propose every block and the others would never get their turn.
	distinct := map[string]bool{string(base): true}
	for h := uint64(0); h < 32; h++ {
		for r := uint32(0); r < 4; r++ {
			distinct[string(c.Proposer(h, r, p))] = true
		}
	}
	if len(distinct) < 3 {
		t.Fatalf("proposer selection used only %d of 4 validators across 128 rounds", len(distinct))
	}
	if string(c.Proposer(1, 0, p)) == string(c.Proposer(1, 0, q)) &&
		string(c.Proposer(1, 0, p)) == string(c.Proposer(2, 0, p)) {
		t.Fatal("proposer ignored height and parent entirely")
	}
	// The assertions above only catch a mutant dropping BOTH fields: a proposer
	// seeded on height but not round (or round but not height) still varies
	// across this loop and trips at most two of the three equalities. Each field
	// must reach the seed ON ITS OWN, so pin them individually - dropping even
	// one must fail (a round-only and a height-only mutant survived here before
	// these two checks existed).
	roundMatters, heightMatters := false, false
	for h := uint64(0); h < 16; h++ {
		if string(c.Proposer(h, 0, p)) != string(c.Proposer(h, 1, p)) {
			roundMatters = true
		}
		if string(c.Proposer(h, 0, p)) != string(c.Proposer(h+1, 0, p)) {
			heightMatters = true
		}
	}
	if !roundMatters {
		t.Fatal("proposer ignored the round: the seed depends only on height and parent")
	}
	if !heightMatters {
		t.Fatal("proposer ignored the height: the seed depends only on round and parent")
	}
}

// Weighted selection must favour the heavier validator, or power would be
// decorative.
//
// DEVIATION from the brief's fixture: the brief built this committee through
// evenCommittee(t, 2, 1), whose cap is 1/4 of total power. A two-validator
// committee can never satisfy a 1/4 cap - each validator necessarily holds 1/2 -
// and the mutated 3:1 split holds 3/4, so the brief's fixture aborts inside
// evenCommittee before the weighting is ever exercised. The cap MUST reject
// such a committee (that is exactly what TestValidateRejectsAnOverPowered-
// Validator pins and what keeps a single operator under one third), so the
// fixture was wrong, not Validate. This test builds the same 3:1 committee
// directly and widens only this fixture's cap to 3/4; what is pinned here is
// the weighting: 3 of 4 power must propose more than half the time, which
// uniform round-robin (1:1 = exactly half) fails.
func TestProposerFavoursHeavierValidators(t *testing.T) {
	c := Config{
		Committee:   []genesis.Validator{testValidator(0, 3), testValidator(1, 1)},
		TimeoutBase: 1, TimeoutStep: 1,
		PowerCapNum: 3, PowerCapDen: 4,
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	parent := crypto.HashParts([]byte("parent"))
	counts := map[string]int{}
	for h := uint64(0); h < 400; h++ {
		counts[string(c.Proposer(h, 0, parent))]++
	}
	first := string(c.Committee[0].PubKey)
	// 250, not 400/2: 400/2 IS the uniform-selection expectation, so an unweighted
	// mutant lands ~1 sigma above it (208 of 400 measured here) and survives. 250
	// sits five sigmas above the uniform mean (200+/-10) and five sigmas below the
	// 3:1 expectation (300+/-9): it kills uniform selection without failing the
	// weighted implementation.
	if counts[first] <= 250 {
		t.Fatalf("a validator with 3 of 4 power proposed only %d of 400 times", counts[first])
	}
}
