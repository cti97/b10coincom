package consensus

import (
	"errors"
	"testing"
)

func voteFrom(t *testing.T, cfg Config, idx int, typ MsgType, height uint64, round uint32, id [32]byte) *Vote {
	t.Helper()
	// Re-sign with the committee member's own key so the tally's signature check
	// and committee check both pass for the validator we intend.
	pub := cfg.Committee[idx].PubKey
	v := &Vote{Type: typ, Height: height, Round: round, BlockID: id, Validator: pub}
	v.Sig = testSign(t, idx, v.SigningHash())
	return v
}

func TestTallyCountsWeightOncePerValidator(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	var id [32]byte
	id[0] = 1
	vs := NewVoteSet(cfg, 1, 0, MsgPrevote)

	for i := 0; i < 3; i++ {
		added, err := vs.Add(voteFrom(t, cfg, i, MsgPrevote, 1, 0, id))
		if err != nil || !added {
			t.Fatalf("validator %d: added=%v err=%v", i, added, err)
		}
	}
	if got := vs.PowerFor(id); got != 3 {
		t.Fatalf("power for the block = %d, want 3", got)
	}
	if !vs.HasQuorum(id) {
		t.Fatal("3 of 4 votes should meet the quorum of 3")
	}
}

// A validator that votes twice must not be counted twice. Double-counting would
// let two validators manufacture a quorum of four.
func TestTallyIgnoresAValidatorsSecondVote(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	var id [32]byte
	id[0] = 1
	vs := NewVoteSet(cfg, 1, 0, MsgPrevote)

	if _, err := vs.Add(voteFrom(t, cfg, 0, MsgPrevote, 1, 0, id)); err != nil {
		t.Fatal(err)
	}
	added, err := vs.Add(voteFrom(t, cfg, 0, MsgPrevote, 1, 0, id))
	if err != nil {
		t.Fatalf("a duplicate must be ignored, not rejected as an error: %v", err)
	}
	if added {
		t.Fatal("a validator's second vote was counted again")
	}
	if got := vs.PowerFor(id); got != 1 {
		t.Fatalf("power = %d after a duplicate, want 1", got)
	}
}

// A validator that equivocates - voting for two different blocks at one height and
// round - must have its weight counted ONCE, not once per block. Keying the
// duplicate check on the vote rather than the VOTER would let two colluding
// validators manufacture a quorum the rest of the committee never gave, which is
// the exact failure this type exists to prevent.
func TestTallyCountsAnEquivocatingValidatorOnlyOnce(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	var a, b [32]byte
	a[0], b[0] = 1, 2
	vs := NewVoteSet(cfg, 1, 0, MsgPrevote)

	// Validator 0 first prevotes block A, then equivocates with a prevote for
	// block B. The first vote wins; B must receive nothing.
	if _, err := vs.Add(voteFrom(t, cfg, 0, MsgPrevote, 1, 0, a)); err != nil {
		t.Fatal(err)
	}
	if _, err := vs.Add(voteFrom(t, cfg, 0, MsgPrevote, 1, 0, b)); err != nil {
		t.Fatalf("an equivocating vote must be ignored, not rejected: %v", err)
	}
	if got := vs.PowerFor(a); got != 1 {
		t.Fatalf("the equivocator's first vote was not counted: PowerFor(A) = %d, want 1", got)
	}
	if got := vs.PowerFor(b); got != 0 {
		t.Fatalf("the equivocator's second vote was counted for B: PowerFor(B) = %d, want 0", got)
	}
	if vs.HasQuorum(b) {
		t.Fatal("block B reached quorum that the committee never gave")
	}
}

func TestTallyRejectsBadSignatureAndNonMembers(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	var id [32]byte
	id[0] = 1

	vs := NewVoteSet(cfg, 1, 0, MsgPrevote)
	bad := voteFrom(t, cfg, 0, MsgPrevote, 1, 0, id)
	bad.Height = 99 // invalidates the signature
	if _, err := vs.Add(bad); !errors.Is(err, ErrBadVoteSignature) {
		t.Fatalf("expected ErrBadVoteSignature, got %v", err)
	}

	stranger, priv := testKey(t)
	sv := &Vote{Type: MsgPrevote, Height: 1, Round: 0, BlockID: id, Validator: stranger}
	h := sv.SigningHash()
	sv.Sig = testSignRaw(t, priv, h)
	if _, err := vs.Add(sv); !errors.Is(err, ErrNotValidator) {
		t.Fatalf("expected ErrNotValidator, got %v", err)
	}
}

// A vote with no validator key is malformed, not badly signed: there is no key
// against which any signature could verify. It gets its own sentinel rather than
// collapsing into ErrBadVoteSignature, so a caller can tell "this vote should
// never have been constructed" from "this vote's signature failed".
func TestTallyRejectsAVoteWithNoValidatorKey(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	var id [32]byte
	id[0] = 1
	vs := NewVoteSet(cfg, 1, 0, MsgPrevote)

	v := &Vote{Type: MsgPrevote, Height: 1, Round: 0, BlockID: id}
	if got, err := vs.Add(v); got || !errors.Is(err, ErrMissingValidatorKey) {
		t.Fatalf("expected ErrMissingValidatorKey, got added=%v err=%v", got, err)
	}
}

// Add becomes a network-facing entry point in M4; malformed input must error,
// not panic.
func TestTallyRejectsANilVote(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	vs := NewVoteSet(cfg, 1, 0, MsgPrevote)

	if got, err := vs.Add(nil); got || !errors.Is(err, ErrNilVote) {
		t.Fatalf("expected ErrNilVote, got added=%v err=%v", got, err)
	}
}

func TestTallyRejectsVotesForAnotherHeightOrRound(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	var id [32]byte
	id[0] = 1

	vs := NewVoteSet(cfg, 5, 2, MsgPrevote)
	if _, err := vs.Add(voteFrom(t, cfg, 0, MsgPrevote, 6, 2, id)); !errors.Is(err, ErrWrongHeightRound) {
		t.Fatalf("a vote for another height must fail with ErrWrongHeightRound, got %v", err)
	}
	if _, err := vs.Add(voteFrom(t, cfg, 0, MsgPrevote, 5, 3, id)); !errors.Is(err, ErrWrongHeightRound) {
		t.Fatalf("a vote for another round must fail with ErrWrongHeightRound, got %v", err)
	}
}

// Nil votes are tallied separately: they matter for advancing a round, but they
// must never be mistaken for a vote for a real block.
func TestTallySeparatesNilVotes(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	var id [32]byte
	id[0] = 1
	vs := NewVoteSet(cfg, 1, 0, MsgPrevote)

	if _, err := vs.Add(voteFrom(t, cfg, 0, MsgPrevote, 1, 0, id)); err != nil {
		t.Fatal(err)
	}
	if _, err := vs.Add(voteFrom(t, cfg, 1, MsgPrevote, 1, 0, [32]byte{})); err != nil {
		t.Fatal(err)
	}
	if got := vs.PowerFor(id); got != 1 {
		t.Fatalf("block power = %d, want 1", got)
	}
	if got := vs.NilPower(); got != 1 {
		t.Fatalf("nil power = %d, want 1", got)
	}
}

func TestAnyQuorumFindsTheBlockWithEnoughPower(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	var a, b [32]byte
	a[0], b[0] = 1, 2
	vs := NewVoteSet(cfg, 1, 0, MsgPrevote)

	for i := 0; i < 3; i++ {
		if _, err := vs.Add(voteFrom(t, cfg, i, MsgPrevote, 1, 0, a)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := vs.Add(voteFrom(t, cfg, 3, MsgPrevote, 1, 0, b)); err != nil {
		t.Fatal(err)
	}

	got, ok := vs.AnyQuorum()
	if !ok {
		t.Fatal("expected a quorum for block A")
	}
	if got != a {
		t.Fatalf("AnyQuorum returned the wrong block")
	}
}

// The brief's AnyQuorum test leaves only ONE block with quorum, so it cannot
// distinguish a first-seen iterator from a map-order one: map iteration returns
// the same single quorum block whichever order it walks (the map-iterating
// mutant survives that test - see task-4-report.md). On an honest committee two
// blocks can never both hold quorum (2*quorum > total power for every quorum
// above 2*total/3), so a multi-quorum tally is only reachable through corrupt
// or Byzantine state - which is exactly when a split committee must still agree
// on ONE block. The pins are inserted directly (package-internal test); what is
// pinned is the deterministic first-seen choice.
func TestAnyQuorumReturnsFirstSeenQuorumBlockEvenWhenSeveralHaveQuorum(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	var x, y, z [32]byte
	x[0], y[0], z[0] = 0xA0, 0xA1, 0xA2
	vs := NewVoteSet(cfg, 1, 0, MsgPrevote)
	for _, id := range [][32]byte{x, y, z} { // first-seen order: x, then y, then z
		vs.order = append(vs.order, id)
		vs.power[id] = cfg.Quorum()
	}

	first, ok := vs.AnyQuorum()
	if !ok || first != x {
		t.Fatalf("AnyQuorum returned %v (ok=%v), want the first-seen quorum block", first, ok)
	}
	// Go randomizes map iteration per range statement, so a map-backed AnyQuorum
	// varies WITHIN one process. Asserting constancy across many calls is therefore
	// what catches it; a single pair of calls lets the mutant survive a majority of
	// runs (measured: 56%), which is not a guard.
	const trials = 100
	for i := 0; i < trials; i++ {
		got, ok := vs.AnyQuorum()
		if !ok {
			t.Fatalf("trial %d: expected a quorum for the first-seen block", i)
		}
		if got != first {
			t.Fatalf("trial %d: AnyQuorum returned %x, want the first-seen %x - it is not iterating in first-seen order", i, got, first)
		}
	}
}
