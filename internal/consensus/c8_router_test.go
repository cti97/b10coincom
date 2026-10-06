package consensus

// Audit C-8's router pins. The finding: every consensus-tagged frame paid
// DecodeVote + Verify (and DecodeProposal + Verify) BEFORE its key was checked
// against the committee, so a self-signed stranger forced an Ed25519
// evaluation per frame and the frame then reached the engine. The fix checks
// the committee key set first, adds a height window for votes, and corrects
// the router's comment. These tests count Ed25519 evaluations through
// crypto.VerifyHook - an observation point production never sets - and assert
// the frame never returns true from Route.

import (
	"testing"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/transport"
)

// TestANonMemberVoteCostsNoVerificationAndNeverReachesTheEngine: the stranger
// signs with its OWN key, so Verify alone passes; membership is what it cannot
// pass. The reordered router must refuse it before the signature check.
func TestANonMemberVoteCostsNoVerificationAndNeverReachesTheEngine(t *testing.T) {
	rig := newRouterRig(t)
	strangerPub, strangerPriv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	v := &Vote{Type: MsgPrevote, Height: rig.ch.Height() + 1, Round: 1, Validator: strangerPub}
	h := v.SigningHash()
	v.Sig = crypto.Sign(strangerPriv, h[:])
	if err := v.Verify(); err != nil {
		t.Fatalf("fixture: the stranger's self-signed vote must verify (its own key signs it): %v", err)
	}

	verifications := 0
	crypto.VerifyHook = func() { verifications++ }
	defer func() { crypto.VerifyHook = nil }()

	if rig.rt.Route(transport.Message{From: "stranger", Data: EncodeVote(v)}) {
		t.Fatal("a self-signed NON-MEMBER vote reached the engine")
	}
	if verifications != 0 {
		t.Fatalf("a non-member vote forced %d Ed25519 verification(s), want 0: membership must be checked first", verifications)
	}
	if got := rig.rt.RefusedBeforeVerify(); got != 1 {
		t.Fatalf("RefusedBeforeVerify() = %d, want 1: the refusal did not run where this test can see it", got)
	}

	// Non-vacuity: a MEMBER's valid vote at the live height IS verified once
	// and routed, so a hook that never fires cannot pass this test.
	var id [32]byte
	id[0] = 7
	member := voteFrom(t, rig.cfg, 0, MsgPrevote, rig.ch.Height()+1, 2, id)
	if !rig.rt.Route(transport.Message{From: "v0", Data: EncodeVote(member)}) {
		t.Fatal("a member's valid vote was not routed to the engine")
	}
	if verifications != 1 {
		t.Fatalf("a member's valid vote cost %d verification(s), want exactly 1: the reorder must keep authentication", verifications)
	}
}

// TestAVoteOutsideTheHeightWindowCostsNoVerification: the engine judges only
// head and head+1 (the height it just committed and the one it is in), so a
// member's vote for a height far outside that window is dead weight. It must
// be refused WITHOUT its signature being evaluated, and it must not reach the
// engine - the second half of the C-8 fix that does not depend on membership.
func TestAVoteOutsideTheHeightWindowCostsNoVerification(t *testing.T) {
	rig := newRouterRig(t)
	var id [32]byte
	id[0] = 1
	far := rig.ch.Height() + 100

	verifications := 0
	crypto.VerifyHook = func() { verifications++ }
	defer func() { crypto.VerifyHook = nil }()

	// A MEMBER signs this one, so membership cannot be what refuses it; the
	// height window is the only gate under test.
	member := voteFrom(t, rig.cfg, 0, MsgPrevote, far, 0, id)
	if rig.rt.Route(transport.Message{From: "v0", Data: EncodeVote(member)}) {
		t.Fatal("a vote for a height the engine cannot judge reached the engine")
	}
	if verifications != 0 {
		t.Fatalf("an out-of-window member vote forced %d verification(s), want 0", verifications)
	}
	if got := rig.rt.RefusedBeforeVerify(); got != 1 {
		t.Fatalf("RefusedBeforeVerify() = %d, want 1", got)
	}

	// In-window control at the SAME member and key shape: head+1 passes and is
	// verified once.
	inWindow := voteFrom(t, rig.cfg, 0, MsgPrevote, rig.ch.Height()+1, 0, id)
	if !rig.rt.Route(transport.Message{From: "v0", Data: EncodeVote(inWindow)}) {
		t.Fatal("an in-window member vote was not routed: the window is over-tight")
	}
	if verifications != 1 {
		t.Fatalf("the in-window vote cost %d verification(s), want exactly 1", verifications)
	}
}

// TestANonMemberProposalCostsNoVerification: a proposal's signer key sits
// after the block, so the decode is unavoidable; the membership check still
// runs before the signature, which is the expensive half of judging the
// decoded frame. A self-signed stranger's proposal never reaches the engine.
func TestANonMemberProposalCostsNoVerification(t *testing.T) {
	rig := newRouterRig(t)
	strangerPub, strangerPriv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	blk, err := rig.ch.Build(rig.priv, nil, rig.ch.Head().Header.Timestamp+1)
	if err != nil {
		t.Fatal(err)
	}
	p := &Proposal{Height: rig.ch.Height() + 1, Round: 0, Block: *blk, ValidRound: -1, Validator: strangerPub}
	ph := p.SigningHash()
	p.Sig = crypto.Sign(strangerPriv, ph[:])
	if err := p.Verify(); err != nil {
		t.Fatalf("fixture: the stranger's self-signed proposal must verify: %v", err)
	}

	verifications := 0
	crypto.VerifyHook = func() { verifications++ }
	defer func() { crypto.VerifyHook = nil }()

	if rig.rt.Route(transport.Message{From: "stranger", Data: EncodeProposal(p)}) {
		t.Fatal("a self-signed NON-MEMBER proposal reached the engine")
	}
	if verifications != 0 {
		t.Fatalf("a non-member proposal forced %d Ed25519 verification(s), want 0", verifications)
	}
	if got := rig.rt.RefusedBeforeVerify(); got != 1 {
		t.Fatalf("RefusedBeforeVerify() = %d, want 1", got)
	}

	// Non-vacuity: a MEMBER's proposal is verified once and routed.
	if !rig.rt.Route(transport.Message{From: "v0", Data: EncodeProposal(rig.signedProposal(rig.ch.Height()+1, 0))}) {
		t.Fatal("a member's proposal was not routed")
	}
	if verifications != 1 {
		t.Fatalf("a member's proposal cost %d verification(s), want exactly 1", verifications)
	}
}
