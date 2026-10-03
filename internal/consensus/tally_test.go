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

func TestTallyRejectsVotesForAnotherHeightOrRound(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	var id [32]byte
	id[0] = 1

	vs := NewVoteSet(cfg, 5, 2, MsgPrevote)
	if _, err := vs.Add(voteFrom(t, cfg, 0, MsgPrevote, 6, 2, id)); err == nil {
		t.Fatal("a vote for another height must be rejected")
	}
	if _, err := vs.Add(voteFrom(t, cfg, 0, MsgPrevote, 5, 3, id)); err == nil {
		t.Fatal("a vote for another round must be rejected")
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
// pinned is the deterministic first-seen choice, plus its stability within a
// single run, so map iteration order kills this test ~8/9 of every run instead
// of never.
func TestAnyQuorumReturnsFirstSeenQuorumBlockEvenWhenSeveralHaveQuorum(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	var x, y, z [32]byte
	x[0], y[0], z[0] = 0xA0, 0xA1, 0xA2
	vs := NewVoteSet(cfg, 1, 0, MsgPrevote)
	for _, id := range [][32]byte{x, y, z} { // first-seen order: x, then y, then z
		vs.order = append(vs.order, id)
		vs.power[id] = cfg.Quorum()
	}

	got, ok := vs.AnyQuorum()
	if !ok || got != x {
		t.Fatalf("AnyQuorum returned %v (ok=%v), want the first-seen quorum block", got, ok)
	}
	again, _ := vs.AnyQuorum()
	if again != got {
		t.Fatalf("AnyQuorum is not stable within one run: %v then %v", got, again)
	}
}
