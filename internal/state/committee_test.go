package state

// Tests for M5 Task 2: the committee is derived from committed state.
//
// Every test here CONSTRUCTS the state it derives from (SetBond for a bond map
// no transaction path could build, ApplyTx for the ones it could) and calls
// Committee() directly. Nothing here depends on a clock, a port, a buffer or a
// goroutine: there is nothing to race, so a result cannot depend on scheduling.

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"slices"
	"testing"

	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/types"
)

// committeeParams is a state parameterised for the derivation only. Committee
// reads CommitteeSize and the bond map; the staking values are irrelevant to it
// and are set by the tests that apply transactions.
func committeeParams(seats int) Params { return Params{CommitteeSize: seats} }

// stakeSpec is one candidate: the key the seat carries and its locked amount.
type stakeSpec struct {
	pub    []byte
	amount uint64
}

// committeeState builds a state holding one bond per spec, inserted in the
// order given. The address is derived from the key, exactly as applyBond would
// have keyed it.
func committeeState(t *testing.T, seats int, specs []stakeSpec) *State {
	t.Helper()
	s := NewWithParams(committeeParams(seats))
	for _, sp := range specs {
		s.SetBond(types.AddressFromPub(sp.pub), Bond{Validator: sp.pub, Amount: sp.amount})
	}
	return s
}

// distinctKeys returns n fresh keypairs.
func distinctKeys(t *testing.T, n int) [][]byte {
	t.Helper()
	keys := make([][]byte, n)
	for i := range keys {
		_, pub, _ := keypair(t)
		keys[i] = pub
	}
	return keys
}

// committeeKeys is the ordered public keys of a committee.
func committeeKeys(c []genesis.Validator) [][]byte {
	out := make([][]byte, len(c))
	for i := range c {
		out[i] = c[i].PubKey
	}
	return out
}

// committeePowers is the ordered powers of a committee.
func committeePowers(c []genesis.Validator) []uint64 {
	out := make([]uint64, len(c))
	for i := range c {
		out[i] = c[i].Power
	}
	return out
}

func equalKeySlices(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

func formatCommittee(c []genesis.Validator) string {
	var buf bytes.Buffer
	for i := range c {
		fmt.Fprintf(&buf, "%x:%d ", c[i].PubKey, c[i].Power)
	}
	return buf.String()
}

// TestCommitteeIsTheTopNByStake pins §6.5's ranking: the seats are the top
// CommitteeSize candidates by bonded stake, in descending stake order. Powers
// are asserted separately because the cap legitimately rewrites them (here it
// cannot bind: three seats is below powerCapMinSeats).
func TestCommitteeIsTheTopNByStake(t *testing.T) {
	keys := distinctKeys(t, 5)
	specs := []stakeSpec{
		{keys[0], 5},
		{keys[1], 4},
		{keys[2], 3},
		{keys[3], 2},
		{keys[4], 1},
	}
	s := committeeState(t, 3, specs)

	committee, err := s.Committee()
	if err != nil {
		t.Fatalf("Committee: %v", err)
	}
	if len(committee) != 3 {
		t.Fatalf("seats = %d, want 3 (CommitteeSize)", len(committee))
	}
	wantKeys := [][]byte{keys[0], keys[1], keys[2]}
	if got := committeeKeys(committee); !equalKeySlices(got, wantKeys) {
		t.Fatalf("seat order = %x, want the top three by stake %x", got, wantKeys)
	}
	wantPowers := []uint64{5, 4, 3}
	if got := committeePowers(committee); fmt.Sprint(got) != fmt.Sprint(wantPowers) {
		t.Fatalf("powers = %v, want %v (three seats: the 1/4 cap does not apply)", got, wantPowers)
	}
}

// TestCommitteeSeatsExactlyTheTopTwentyOne is §6.5's actual shape with a field
// larger than the committee: 25 candidates, 21 seats, and the four smallest
// stakes are the ones left out.
func TestCommitteeSeatsExactlyTheTopTwentyOne(t *testing.T) {
	const candidates = 25
	const seats = 21
	keys := distinctKeys(t, candidates)
	specs := make([]stakeSpec, candidates)
	for i := range specs {
		// Stake descends with the index, so the expected seat order is keys[0..20].
		specs[i] = stakeSpec{pub: keys[i], amount: uint64(candidates - i)}
	}
	s := committeeState(t, seats, specs)

	committee, err := s.Committee()
	if err != nil {
		t.Fatalf("Committee: %v", err)
	}
	if len(committee) != seats {
		t.Fatalf("seats = %d, want %d", len(committee), seats)
	}
	if got, want := committeeKeys(committee), keys[:seats]; !equalKeySlices(got, want) {
		t.Fatalf("seats = %x, want the top %d by stake", got, seats)
	}
	var total uint64
	for i, v := range committee {
		total += v.Power
		if want := uint64(candidates - i); v.Power != want {
			t.Fatalf("seat %d power = %d, want %d (no clamp binds here: T/4 = %d)",
				i, v.Power, want, total/4)
		}
	}
	// The four lowest stakes must not be seated.
	seated := map[string]bool{}
	for _, v := range committee {
		seated[string(v.PubKey)] = true
	}
	for _, k := range keys[seats:] {
		if seated[string(k)] {
			t.Fatalf("the committee seated a candidate outside the top %d", seats)
		}
	}
}

// tieBreakKeyLo / tieBreakKeyHi and their addresses are a HARD-CODED pair
// (found once, then fixed) with the property the tie-break test needs: the
// address bytes order OPPOSITE to the public-key bytes.
//
//	tieBreakKeyLo < tieBreakKeyHi  (bytes.Compare on the keys)
//	tieBreakAddrLo > tieBreakAddrHi (bytes.Compare on the addresses)
//
// so a sort by address bytes - or by the address string - seats the wrong
// winner among equal stakes, and only §6.3's key-bytes tie-break seats the
// right one. The test re-derives both addresses and re-checks the property
// rather than trusting these comments.
var (
	tieBreakKeyLo  = mustHex("74ee8a926b61cb0941f4aa037bf101a3121caab9344bbc6ef4f5beb5d6ac5ebe")
	tieBreakKeyHi  = mustHex("acbb6a4840e3368877dbb1dbf1c7a6ed681d97a8a69f75e96264d58074cbae2f")
	tieBreakAddrLo = types.AddressFromPub(tieBreakKeyLo)
	tieBreakAddrHi = types.AddressFromPub(tieBreakKeyHi)
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// TestTheTieBreakIsThePublicKeyBytes pins the tie-break against the tempting
// wrong one. Both candidates hold the same stake, so the ranking is decided by
// the tie-break alone; the winner must be the smaller PUBLIC KEY, which here
// carries the LARGER address.
func TestTheTieBreakIsThePublicKeyBytes(t *testing.T) {
	// The pair's property, re-derived: key order and address order disagree.
	if bytes.Compare(tieBreakKeyLo, tieBreakKeyHi) >= 0 {
		t.Fatalf("fixture is wrong: tieBreakKeyLo is not the smaller key")
	}
	if bytes.Compare(tieBreakAddrLo[:], tieBreakAddrHi[:]) <= 0 {
		t.Fatalf("fixture is wrong: the addresses do not order opposite to the keys, so this test cannot distinguish the tie-breaks")
	}

	const stake = 1_000 * genesis.SparksPerB10
	s := committeeState(t, 1, []stakeSpec{
		{pub: tieBreakKeyHi, amount: stake},
		{pub: tieBreakKeyLo, amount: stake},
	})
	committee, err := s.Committee()
	if err != nil {
		t.Fatalf("Committee: %v", err)
	}
	if len(committee) != 1 {
		t.Fatalf("seats = %d, want 1", len(committee))
	}
	if !bytes.Equal(committee[0].PubKey, tieBreakKeyLo) {
		t.Fatalf("seated %x, want the smaller public key %x: the tie-break is on KEY bytes, "+
			"not on address bytes (%x vs %x)", committee[0].PubKey, tieBreakKeyLo,
			tieBreakAddrLo[:], tieBreakAddrHi[:])
	}

	// The seat set is the same whichever insertion order the map was built in.
	reversed := committeeState(t, 1, []stakeSpec{
		{pub: tieBreakKeyLo, amount: stake},
		{pub: tieBreakKeyHi, amount: stake},
	})
	again, err := reversed.Committee()
	if err != nil {
		t.Fatalf("Committee (reversed insertion): %v", err)
	}
	if !equalKeySlices(committeeKeys(again), committeeKeys(committee)) {
		t.Fatalf("insertion order changed the tie-break: %x vs %x", committeeKeys(again), committeeKeys(committee))
	}
}

// TestCommitteeIsIndependentOfInsertionOrder is the determinism test.
//
// Go randomises a map's iteration order on every range, so two states holding
// the SAME bonds can yield them in different orders on every call. The
// derivation must not care. The state is constructed, never provoked: the same
// five bonds are inserted forwards and backwards, each derived 100 times, and
// every result must equal the first - and the two states must agree with each
// other. One call is a weak test because a single map iteration can happen to
// come out sorted; 100 calls over a five-entry map has no realistic false pass
// (the chance that 100 independent shuffled iterations agree by luck is
// negligible), and the backwards-insertion state has a different map layout
// again.
func TestCommitteeIsIndependentOfInsertionOrder(t *testing.T) {
	keys := distinctKeys(t, 5)
	amounts := []uint64{50, 40, 30, 20, 10}
	forward := make([]stakeSpec, 5)
	backward := make([]stakeSpec, 5)
	for i := range forward {
		forward[i] = stakeSpec{pub: keys[i], amount: amounts[i]}
		backward[len(backward)-1-i] = stakeSpec{pub: keys[i], amount: amounts[i]}
	}

	first := committeeState(t, 3, forward)
	want, err := first.Committee()
	if err != nil {
		t.Fatalf("Committee: %v", err)
	}
	reverse := committeeState(t, 3, backward)

	for i := 0; i < 100; i++ {
		got, err := first.Committee()
		if err != nil {
			t.Fatalf("Committee (forward, call %d): %v", i, err)
		}
		if formatCommittee(got) != formatCommittee(want) {
			t.Fatalf("call %d over the SAME state derived a different committee:\n got %s\nwant %s",
				i, formatCommittee(got), formatCommittee(want))
		}
		got, err = reverse.Committee()
		if err != nil {
			t.Fatalf("Committee (backward, call %d): %v", i, err)
		}
		if formatCommittee(got) != formatCommittee(want) {
			t.Fatalf("call %d over the SAME bonds inserted backwards derived a different committee:\n got %s\nwant %s",
				i, formatCommittee(got), formatCommittee(want))
		}
	}
}

// TestCommitteeIsIndependentOfEveryShuffledInsertionOrder widens the previous
// test from two orders to many: 64 states built from the same eight bonds, each
// in a different permutation (a fixed PRNG seed, so the test is reproducible),
// must all derive the identical committee. This is the "across many shuffles of
// the underlying map/iteration order" property constructed rather than hoped
// for: the shuffles are the test's input, not a side effect of the runtime.
func TestCommitteeIsIndependentOfEveryShuffledInsertionOrder(t *testing.T) {
	keys := distinctKeys(t, 8)
	amounts := []uint64{80, 70, 60, 50, 40, 30, 20, 10}
	want, err := committeeState(t, 8, func() []stakeSpec {
		specs := make([]stakeSpec, 8)
		for i := range specs {
			specs[i] = stakeSpec{pub: keys[i], amount: amounts[i]}
		}
		return specs
	}()).Committee()
	if err != nil {
		t.Fatalf("Committee: %v", err)
	}

	rng := rand.New(rand.NewSource(20261011))
	for round := 0; round < 64; round++ {
		specs := make([]stakeSpec, 8)
		for i := range specs {
			specs[i] = stakeSpec{pub: keys[i], amount: amounts[i]}
		}
		rng.Shuffle(len(specs), func(i, j int) { specs[i], specs[j] = specs[j], specs[i] })
		got, err := committeeState(t, 8, specs).Committee()
		if err != nil {
			t.Fatalf("shuffle %d: Committee: %v", round, err)
		}
		if formatCommittee(got) != formatCommittee(want) {
			t.Fatalf("shuffle %d derived a different committee:\n got %s\nwant %s",
				round, formatCommittee(got), formatCommittee(want))
		}
	}
}

// TestCommitteeDoesNotReadTheStateHeight is the purity check that is easiest to
// get wrong: the derivation is a function of committed state, and the state's
// height is EXECUTION CONTEXT (not committed, not in the root, different on two
// nodes deriving the same epoch). Two states identical but for the height must
// derive the same committee.
func TestCommitteeDoesNotReadTheStateHeight(t *testing.T) {
	keys := distinctKeys(t, 5)
	specs := []stakeSpec{
		{keys[0], 500}, {keys[1], 400}, {keys[2], 300}, {keys[3], 200}, {keys[4], 100},
	}
	a := committeeState(t, 5, specs)
	b := committeeState(t, 5, specs)
	for _, h := range []uint64{0, 1, 999, 1_000, math.MaxUint64} {
		b.SetHeight(h)
		ca, err := a.Committee()
		if err != nil {
			t.Fatalf("Committee (a): %v", err)
		}
		cb, err := b.Committee()
		if err != nil {
			t.Fatalf("Committee (b at height %d): %v", h, err)
		}
		if formatCommittee(ca) != formatCommittee(cb) {
			t.Fatalf("height %d changed the committee:\n a %s\n b %s",
				h, formatCommittee(ca), formatCommittee(cb))
		}
	}
}

// TestCommitteeReturnsCopies: the derived committee must not alias committed
// state, or a caller could mutate a bond's key through the returned slice.
func TestCommitteeReturnsCopies(t *testing.T) {
	keys := distinctKeys(t, 4)
	specs := []stakeSpec{{keys[0], 10}, {keys[1], 9}, {keys[2], 8}, {keys[3], 7}}
	s := committeeState(t, 4, specs)
	committee, err := s.Committee()
	if err != nil {
		t.Fatalf("Committee: %v", err)
	}
	original := append([]byte(nil), committee[0].PubKey...)
	for i := range committee[0].PubKey {
		committee[0].PubKey[i] ^= 0xFF
	}
	bond, ok := s.BondOf(types.AddressFromPub(original))
	if !ok {
		t.Fatalf("bond disappeared from state")
	}
	if !bytes.Equal(bond.Validator, original) {
		t.Fatalf("the committee aliased committed state: mutating it changed the bond key %x -> %x",
			original, bond.Validator)
	}
}

// TestTheCapHoldsAfterClamping is the sharpest arithmetic in the task. One
// holder at 10^12 sparks against three at 1 spark: a single pre-cap pass would
// leave that holder at ~100% of the clamped total (it would still commit
// alone), while the fixed point of p <- (p+3)/4 is 1, so the dominant holder
// must end at exactly the small holders' power.
func TestTheCapHoldsAfterClamping(t *testing.T) {
	keys := distinctKeys(t, 4)
	const dominant = 1_000_000_000_000 // 10^12 sparks
	s := committeeState(t, 4, []stakeSpec{
		{pub: keys[0], amount: dominant},
		{pub: keys[1], amount: 1},
		{pub: keys[2], amount: 1},
		{pub: keys[3], amount: 1},
	})
	committee, err := s.Committee()
	if err != nil {
		t.Fatalf("Committee: %v", err)
	}
	if len(committee) != 4 {
		t.Fatalf("seats = %d, want 4", len(committee))
	}
	var total uint64
	for _, v := range committee {
		total += v.Power
	}
	if total != 4 {
		t.Fatalf("total power = %d, want 4: the fixed point of p <- (p+3)/4 is 1 for every seat", total)
	}
	for i, v := range committee {
		if v.Power != 1 {
			t.Fatalf("seat %d power = %d, want 1 (the dominant holder must end at the small holders' power, "+
				"not at a single pre-cap clamp of %d)", i, v.Power, dominant/4)
		}
		// The cap, restated as the share the config layer checks.
		if v.Power*powerCapDivisor > total {
			t.Fatalf("seat %d holds %d of %d, above 1/%d", i, v.Power, total, powerCapDivisor)
		}
	}
}

// TestTheFixedPointConvergesForADominantTrio is the pass-count pin. Three seats
// at one large value and one far below it is the SLOWEST case for the clamp:
// the gap shrinks by 3/4 a pass, not by 4, so this vector needs ~121 passes at
// 2^51 and 148 at 2^64. The plan's 64-pass cap would return
// ErrPowerCapNotConverged for a committee a real chain can reach (the shipped
// supply cap is 2.1e15 = 2^50.9 sparks); committeeMaxCapPasses is 256 for that
// reason, and this test is what fails if it is lowered back.
func TestTheFixedPointConvergesForADominantTrio(t *testing.T) {
	const big = 1<<51 - 1 // just under the 2.1e15-spark supply cap
	keys := distinctKeys(t, 4)
	s := committeeState(t, 4, []stakeSpec{
		{pub: keys[0], amount: big},
		{pub: keys[1], amount: big},
		{pub: keys[2], amount: big},
		{pub: keys[3], amount: 1},
	})
	committee, err := s.Committee()
	if err != nil {
		t.Fatalf("Committee: %v (three dominant seats are the slowest clamp case, not a non-convergent one)", err)
	}
	var total uint64
	for _, v := range committee {
		total += v.Power
	}
	for i, v := range committee {
		if v.Power*powerCapDivisor > total {
			t.Fatalf("seat %d holds %d of %d, above 1/%d", i, v.Power, total, powerCapDivisor)
		}
	}
}

// TestTheCapClampsTheSeatRatherThanExcludingIt makes the two possible cap
// behaviours visible, because the difference is invisible when every candidate
// is seated: with FIVE candidates and FOUR seats, a validator far above the cap
// either keeps its seat at the capped power (the brief's rule - the cap is
// applied after selecting) or is dropped in favour of the fifth candidate (the
// rule nobody implementing this followed). The seated set here must still be
// the top four by stake.
func TestTheCapClampsTheSeatRatherThanExcludingIt(t *testing.T) {
	keys := distinctKeys(t, 5)
	s := committeeState(t, 4, []stakeSpec{
		{pub: keys[0], amount: 1000},
		{pub: keys[1], amount: 10},
		{pub: keys[2], amount: 9},
		{pub: keys[3], amount: 8},
		{pub: keys[4], amount: 7}, // the fifth: outside the seats, and stays outside
	})
	committee, err := s.Committee()
	if err != nil {
		t.Fatalf("Committee: %v", err)
	}
	if len(committee) != 4 {
		t.Fatalf("seats = %d, want 4", len(committee))
	}
	// keys[0] holds 96% of the stake before the cap. Under clamping it keeps
	// the seat; under exclusion the fifth candidate (keys[4]) would take it.
	if !bytes.Equal(committee[0].PubKey, keys[0]) {
		t.Fatalf("the dominant validator was dropped from the seats: got %x at seat 0, want %x",
			committee[0].PubKey, keys[0])
	}
	for _, v := range committee {
		if bytes.Equal(v.PubKey, keys[4]) {
			t.Fatalf("an over-cap seat was replaced by the fifth candidate: the cap is applied AFTER selecting, " +
				"so it reduces the seat's power and never changes who was seated")
		}
	}
	// The clamp does rewrite the dominant seat's power: every seated power ends
	// equal, because the fixed point of [1000,10,9,8] is [8,8,8,8].
	want := []uint64{8, 8, 8, 8}
	if got := committeePowers(committee); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("powers = %v, want %v", got, want)
	}
}

// TestApplyPowerCapIsOrderIndependent: every clamp in a pass is against the
// same T, so permuting the input permutes the output and cannot change the
// result. This is why the fixed point does not depend on the order validators
// are visited in.
func TestApplyPowerCapIsOrderIndependent(t *testing.T) {
	in := []uint64{1_000_000_000_000, 3, 2, 1, 1}
	want, err := applyPowerCap(in)
	if err != nil {
		t.Fatalf("applyPowerCap: %v", err)
	}
	perms := [][]uint64{
		{1, 2, 1, 3, 1_000_000_000_000},
		{3, 1, 1_000_000_000_000, 1, 2},
		{2, 3, 1, 1_000_000_000_000, 1},
	}
	for _, p := range perms {
		got, err := applyPowerCap(p)
		if err != nil {
			t.Fatalf("applyPowerCap(%v): %v", p, err)
		}
		// Compare as multisets: the output is the input's permutation.
		if a, b := sortedPowers(got), sortedPowers(want); !slices.Equal(a, b) {
			t.Fatalf("permutation %v clamped to %v, but the canonical order clamped to %v", p, got, want)
		}
	}
}

func sortedPowers(in []uint64) []uint64 {
	out := slices.Clone(in)
	slices.Sort(out)
	return out
}

// TestApplyPowerCapLeavesACompliantCommitteeAlone: when no seat is over the
// ratio the clamp must be the identity, or it would shrink a valid committee
// on every derivation.
func TestApplyPowerCapLeavesACompliantCommitteeAlone(t *testing.T) {
	in := []uint64{4, 4, 4, 4} // each exactly 1/4 of the total
	got, err := applyPowerCap(in)
	if err != nil {
		t.Fatalf("applyPowerCap: %v", err)
	}
	if fmt.Sprint(got) != fmt.Sprint(in) {
		t.Fatalf("applyPowerCap(%v) = %v, want the input: equality with 1/4 is legal", in, got)
	}
}

// TestTheCommitteePowerOverflowIsRefused: four bonds at MaxUint64 sum past
// uint64. A wrapped total would make every share wrong, so it is an error.
func TestTheCommitteePowerOverflowIsRefused(t *testing.T) {
	keys := distinctKeys(t, 4)
	s := committeeState(t, 4, []stakeSpec{
		{pub: keys[0], amount: math.MaxUint64},
		{pub: keys[1], amount: math.MaxUint64},
		{pub: keys[2], amount: math.MaxUint64},
		{pub: keys[3], amount: math.MaxUint64},
	})
	if _, err := s.Committee(); !errors.Is(err, ErrCommitteePowerOverflow) {
		t.Fatalf("Committee on an overflowing total = %v, want ErrCommitteePowerOverflow", err)
	}
}

// TestAWithdrawnValidatorIsNotACandidate walks the whole exit: bond, unbond the
// bond, withdraw at the release height, and derive at each step. The address is
// gone from the bond map as soon as it unbonds - the cooldown's coins are not
// candidates - and a withdrawn seat can never come back.
func TestAWithdrawnValidatorIsNotACandidate(t *testing.T) {
	const bond = 1_000 * genesis.SparksPerB10
	p := stakingParams()
	p.CommitteeSize = 2
	s := NewWithParams(p)

	stayAddr, stayPub, stayPriv := keypair(t)
	s.Set(stayAddr, Account{Balance: bond + 1})
	if err := s.ApplyTx(bondTx(t, stayPub, stayPriv, stayAddr, 0, bond, 1)); err != nil {
		t.Fatalf("fixture bond (staying validator): %v", err)
	}
	goAddr, goPub, goPriv := keypair(t)
	s.Set(goAddr, Account{Balance: bond + 1})
	if err := s.ApplyTx(bondTx(t, goPub, goPriv, goAddr, 0, bond, 1)); err != nil {
		t.Fatalf("fixture bond (departing validator): %v", err)
	}

	before, err := s.Committee()
	if err != nil {
		t.Fatalf("Committee before the exit: %v", err)
	}
	if len(before) != 2 {
		t.Fatalf("seats before the exit = %d, want 2", len(before))
	}

	// Unbond everything. The coins are neither spendable nor counted from here.
	if err := s.ApplyTx(unbondTx(t, goPub, goPriv, goAddr, 1, bond)); err != nil {
		t.Fatalf("unbond: %v", err)
	}
	afterUnbond, err := s.Committee()
	if err != nil {
		t.Fatalf("Committee after the unbond: %v", err)
	}
	if len(afterUnbond) != 1 || !bytes.Equal(afterUnbond[0].PubKey, stayPub) {
		t.Fatalf("seats after the unbond = %s, want only the staying validator: an unbonding record is not a candidate",
			formatCommittee(afterUnbond))
	}

	// Withdraw at the release height: the coins return to spendable and the
	// seat is still gone.
	s.SetHeight(s.height + stakeCooldown)
	if err := s.ApplyTx(withdrawTx(t, goPub, goPriv, goAddr, 2)); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	afterWithdraw, err := s.Committee()
	if err != nil {
		t.Fatalf("Committee after the withdraw: %v", err)
	}
	if len(afterWithdraw) != 1 || !bytes.Equal(afterWithdraw[0].PubKey, stayPub) {
		t.Fatalf("seats after the withdraw = %s, want only the staying validator", formatCommittee(afterWithdraw))
	}
	if got := s.Bonded(goAddr); got != 0 {
		t.Fatalf("the withdrawn validator still holds a bond of %d sparks", got)
	}
}

// TestCommitteeSizeZeroIsRefused: a zero seat count is an error about the
// state, not an empty committee discovered later by the engine.
func TestCommitteeSizeZeroIsRefused(t *testing.T) {
	keys := distinctKeys(t, 1)
	s := committeeState(t, 0, []stakeSpec{{pub: keys[0], amount: 10}})
	committee, err := s.Committee()
	if !errors.Is(err, ErrZeroCommittee) {
		t.Fatalf("Committee with CommitteeSize 0 = (%v, %v), want ErrZeroCommittee", committee, err)
	}
	if committee != nil {
		t.Fatalf("Committee with CommitteeSize 0 returned a committee: %s", formatCommittee(committee))
	}
}

// TestNoCandidatesIsRefused: no bond to seat is an error, not an empty slice.
func TestNoCandidatesIsRefused(t *testing.T) {
	s := NewWithParams(committeeParams(5))
	committee, err := s.Committee()
	if !errors.Is(err, ErrNoCandidates) {
		t.Fatalf("Committee with no bonds = (%v, %v), want ErrNoCandidates", committee, err)
	}
	if committee != nil {
		t.Fatalf("Committee with no bonds returned a committee: %s", formatCommittee(committee))
	}

	// A bond at zero is pruned by SetBond and is not a candidate either.
	keys := distinctKeys(t, 1)
	zero := committeeState(t, 5, []stakeSpec{{pub: keys[0], amount: 0}})
	if _, err := zero.Committee(); !errors.Is(err, ErrNoCandidates) {
		t.Fatalf("Committee with only a zero bond = %v, want ErrNoCandidates", err)
	}
}

// TestFewerCandidatesThanSeatsSeatsThemAll: the committee size is a ceiling,
// not a quota.
func TestFewerCandidatesThanSeatsSeatsThemAll(t *testing.T) {
	keys := distinctKeys(t, 3)
	s := committeeState(t, 21, []stakeSpec{
		{pub: keys[0], amount: 30},
		{pub: keys[1], amount: 20},
		{pub: keys[2], amount: 10},
	})
	committee, err := s.Committee()
	if err != nil {
		t.Fatalf("Committee: %v", err)
	}
	if len(committee) != 3 {
		t.Fatalf("seats = %d, want 3 (there are only three candidates)", len(committee))
	}
	if got, want := committeeKeys(committee), keys; !equalKeySlices(got, want) {
		t.Fatalf("seats = %x, want %x in stake order", got, want)
	}
}
