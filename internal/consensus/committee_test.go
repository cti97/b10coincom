package consensus

import (
	"errors"
	"math/big"
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

// testValidator derives validator idx's key through the derivation every
// test fixture in this package must use. testCommitteeKey (testkeys_test.go)
// is the cross-task helper carrying that same derivation; the tripwire below
// pins the two to each other, so a later task changing EITHER derivation
// breaks this test here, instead of surfacing later as unexplained signature
// failures in the tally tests.
func testValidator(idx int, power uint64) genesis.Validator {
	h := crypto.HashParts([]byte("b10coin-test-validator"), []byte{byte(idx)})
	priv := ed25519FromSeed(h)
	return genesis.Validator{PubKey: priv.Public().(ed25519PublicKey), Power: power}
}

// The tripwire must face the real helper, not a copy of its expression: a
// second literal in this file would keep passing while testCommitteeKey
// drifted away underneath it.
func TestFixtureKeyDerivationMatchesSharedHelper(t *testing.T) {
	for i := 0; i < 8; i++ {
		got := string(testValidator(i, 1).PubKey)
		want := string(testCommitteeKey(i).Public().(ed25519PublicKey))
		if got != want {
			t.Fatalf("testValidator(%d) diverged from testCommitteeKey; a task changed one of the two derivations - tally tests would fail with signature errors instead of testing what they name", i)
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

// The overflow-free quorumFor must return the EXACT threshold (smallest q
// above 2*total/3) for every total. The formulation it replaced, 2*total/3+1,
// wraps for total >= 2^63: nine equal validators of 3.7e18 power - a committee
// genesis.Validate accepts - made 2*total wrap, and the resulting threshold
// covered only ~11% of the true voting power, letting two of the nine commit
// alone. The reference computes the same quantity in big.Int, where nothing
// wraps.
func TestQuorumForMatchesBigReferenceEverywhere(t *testing.T) {
	three := big.NewInt(3)
	ref := func(total uint64) uint64 {
		q := new(big.Int).Lsh(new(big.Int).SetUint64(total), 1) // 2*total, exact
		q.Div(q, three)
		q.Add(q, big.NewInt(1)) // strictly above 2*total/3
		if !q.IsUint64() {
			t.Fatalf("reference quorum for total %d does not fit uint64", total)
		}
		return q.Uint64()
	}

	totals := map[uint64]bool{0: true, 1: true, 2: true, 3: true, 4: true, 21: true, 100: true}
	totals[21_000_000*genesis.SparksPerB10] = true // the supply cap ≈ 2^51: the edge the shipped domain can reach
	for i := uint64(0); i < 4; i++ {
		totals[(1<<61)+i] = true
		totals[(1<<62)+i] = true
		totals[(1<<63)+i] = true
		totals[(1<<63)-i] = true
		totals[^uint64(0)-i] = true
	}
	// the total the reviewer's committee wraps to: TotalPower(9 x 3.7e18)
	totals[14_853_255_926_290_448_384] = true

	// every total up to 2000, plus a stride sweep over the whole uint64 range
	// (odd stride, coprime with 3) so both residues of total mod 3 are hit at
	// every magnitude - the q++ branch fires only for total%3 == 2.
	for i := uint64(0); i <= 2000; i++ {
		totals[i] = true
	}
	stride := ^uint64(0) / 500
	for i := uint64(0); i <= 500; i++ {
		totals[i*stride] = true
	}

	for total := range totals {
		if got, want := quorumFor(total), ref(total); got != want {
			t.Errorf("quorumFor(%d) = %d, big reference = %d", total, got, want)
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

// The spec's ceiling is 1/4; a configured ratio above it makes the cap
// decorative at the config layer and must be rejected - but only from four
// validators up, where such a ratio can actually be enforced (see Validate's
// doc).
func TestValidateRejectsACapAboveTheQuarterCeiling(t *testing.T) {
	// 1/4 itself passes on n=4 (evenCommittee already validated it).
	pin := evenCommittee(t, 4, 1)

	c := pin
	c.PowerCapNum, c.PowerCapDen = 3, 4
	if err := c.Validate(); !errors.Is(err, ErrBadConfig) {
		t.Fatalf("cap 3/4 on a 4-validator committee: got %v, want ErrBadConfig", err)
	}

	// The ceiling cross-multiplication must be overflow-free: 4*2^62 wraps to
	// 0 in uint64, so a naive `num*4 > den` would ACCEPT a cap of 2^62/3 - a
	// ratio around 6e17:1, nowhere near 1/4.
	c = pin
	c.PowerCapNum, c.PowerCapDen = 1<<62, 3
	if err := c.Validate(); !errors.Is(err, ErrBadConfig) {
		t.Fatalf("overflowing ceiling product 2^62/3: got %v, want ErrBadConfig", err)
	}
}

// Below four validators the ceiling cannot bind: the largest holder holds at
// least total/3, so no ratio under 1/3 is satisfiable there and committees
// with one or two validators must keep working with bigger caps.
func TestPowerCapCeilingIsNotEnforcedBelowFourValidators(t *testing.T) {
	// n=1: the single validator holds all the power; only caps reaching 1/1
	// (the controller's single-validator fixtures) can hold.
	one := Config{
		Committee:   []genesis.Validator{testValidator(0, 1)},
		TimeoutBase: 1, TimeoutStep: 1,
		PowerCapNum: 1, PowerCapDen: 1,
	}
	if err := one.Validate(); err != nil {
		t.Fatalf("n=1 committee with cap 1/1 rejected: %v", err)
	}

	// n=2: each validator holds exactly 1/2; the weighting fixture's 3/4 cap
	// must survive the ceiling check.
	two := Config{
		Committee:   []genesis.Validator{testValidator(0, 3), testValidator(1, 1)},
		TimeoutBase: 1, TimeoutStep: 1,
		PowerCapNum: 3, PowerCapDen: 4,
	}
	if err := two.Validate(); err != nil {
		t.Fatalf("n=2 committee with cap 3/4 rejected: %v - the ceiling must bind only from n=4", err)
	}
	// ...while the per-validator check still applies below n=4: a validator
	// holding 3/4 of the power is above the configured cap of 1/2.
	two.PowerCapNum, two.PowerCapDen = 1, 2
	err := two.Validate()
	if !errors.Is(err, ErrPowerCap) {
		t.Fatalf("n=2 committee with a validator of 3/4 under cap 1/2: got %v, want ErrPowerCap", err)
	}
	if errors.Is(err, ErrBadConfig) {
		t.Fatal("n=2 with cap 1/2 must fail the per-validator comparison, not the ceiling check")
	}
}

func TestValidateRejectsTimeoutsThatDoNotGrow(t *testing.T) {
	c := evenCommittee(t, 4, 1)
	for _, tc := range []struct {
		name       string
		base, step int64
	}{
		{"zero base expires instantly every round", 0, 100},
		{"negative base", -1, 100},
		{"negative step shrinks each round", 100, -1},
	} {
		mut := c
		mut.TimeoutBase, mut.TimeoutStep = tc.base, tc.step
		if err := mut.Validate(); !errors.Is(err, ErrBadConfig) {
			t.Errorf("%s: TimeoutBase=%d TimeoutStep=%d: got %v, want ErrBadConfig", tc.name, tc.base, tc.step, err)
		}
	}
}

func TestValidateRejectsAZeroPowerCapDenominator(t *testing.T) {
	c := evenCommittee(t, 4, 1)
	c.PowerCapDen = 0
	if err := c.Validate(); !errors.Is(err, ErrBadConfig) {
		t.Fatalf("zero power-cap denominator: got %v, want ErrBadConfig", err)
	}
}

// A zero-power validator used to surface as ErrEmptyCommittee - the wrong
// category: the committee is not empty, one of its entries is malformed.
func TestValidateReportsAZeroPowerValidatorAsZeroPower(t *testing.T) {
	c := evenCommittee(t, 8, 1) // 8x1: zeroing one leaves 1/7 per holder, under the 1/4 cap
	c.Committee[7].Power = 0
	err := c.Validate()
	if !errors.Is(err, ErrZeroPower) {
		t.Fatalf("zero-power validator reported as %v, want ErrZeroPower", err)
	}
	if errors.Is(err, ErrEmptyCommittee) {
		t.Fatal("a zero-power validator in an 8-validator committee must not be reported as an empty committee")
	}
}

// A committee whose powers sum past 2^64 must be refused outright: on the
// wrapped sum the cap comparison, the quorum threshold and the proposer pick
// are all computed from a lie. (genesis.Validate does not bound the power
// sum, so this is the one guard against it.)
func TestValidateRejectsATotalPowerSumThatWraps(t *testing.T) {
	c := Config{
		Committee: []genesis.Validator{
			testValidator(0, 1<<63), testValidator(1, 1<<63), // sum = 2^64: wraps to 0
		},
		TimeoutBase: 1, TimeoutStep: 1,
		PowerCapNum: 1, PowerCapDen: 1, // 1/1 is the only cap two validators can satisfy
	}
	if err := c.Validate(); !errors.Is(err, ErrPowerOverflow) {
		t.Fatalf("power sum 2^64 (wraps) reported as %v, want ErrPowerOverflow", err)
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
	// 250, not 400/2: 400/2 IS the uniform-selection expectation, so an unweighted
	// mutant lands ~1 sigma above it (208 of 400 measured here) and survives. 250
	// sits five sigmas above the uniform mean (200+/-10) and five sigmas below the
	// 3:1 expectation (300+/-9): it kills uniform selection without failing the
	// weighted implementation. Seat 0 holds 3 of 4 power here.
	if got := counts[string(c.Committee[0].PubKey)]; got <= 250 {
		t.Fatalf("a validator with 3 of 4 power proposed only %d of 400 times", got)
	}
}
