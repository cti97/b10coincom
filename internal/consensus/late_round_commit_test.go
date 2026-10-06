package consensus

// A late precommit quorum must still be appendable (audit C-3's own feature,
// and the park it introduced).
//
// C-3 lets a quorum that completes for a round the engine has already LEFT
// commit the height: the round's precommit tallies are retained for
// pastVoteRounds rounds instead of being discarded on the round change. That
// is correct safety-wise - a commit is a commit whenever it is noticed - but it
// made a liveness hole reachable. enterRound clears e.proposal, so the engine
// that commits round r after entering round r+1 holds the committed ID and no
// block BYTES; Driver.flush requires bytes, appends nothing, and leaves the
// engine in step StepCommit, which OnTimeout refuses to advance. Proposals are
// not retransmitted, so the height parks. That is the CI failure's exact shape:
// the engine agrees on a height ("consensus agreed") and the CHAIN never moves
// past it, at whichever nodes hit the race - and if every node does, no peer is
// ahead and catch-up cannot recover either.
//
// The fix retains the round's accepted proposal bytes with its tallies
// (roundSets.proposal, bounded by the same round window) and has the driver
// append the committed block from any retained copy (Engine.committedBlock).
//
// The whole-committee shape, which is what the CI failure shows, turns on the
// LATE JOINER the failing test adds. The joiner rebuilds its driver mid-run, so
// at the moment the committee moves to a new height its engine can be drawn as
// that height's round-1 proposer while still holding NO round-0 lock. It then
// proposes a DIFFERENT block, every node that did lock accepts it as e.proposal
// ("first proposal wins"), the delayed round-0 quorum commits the locked block,
// and every one of those nodes now holds a committed ID whose bytes it cannot
// offer and a stale proposal that blocks the round's own re-proposal. If every
// node that locked is in that state, quorum is unreachable, no peer is ahead,
// and catch-up cannot recover: the chain freezes at the height it had reached.
//
// This test CONSTRUCTS that state - it does not race a clock, a buffer or a
// flood: round 0's proposal is accepted, the engine enters round 1, round 1's
// (different) proposal is accepted, and only then is the round-0 precommit
// quorum delivered.

import (
	"fmt"
	"testing"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/transport/sim"
	"github.com/cti97/b10coincom/internal/types"
)

func TestAPastRoundQuorumStillAppendsTheCommittedBlock(t *testing.T) {
	// A four-validator committee (quorum 3). The driver holds the seat drawn
	// as the round-0 proposer, so its own build is a block Append accepts.
	vals := make([]genesis.Validator, 0, 4)
	for i := 0; i < 4; i++ {
		vals = append(vals, testValidator(i, 1))
	}
	g := genesis.Devnet()
	g.Validators = vals
	g.Params.CommitteeSize = 4

	ch, err := chain.Open(g, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ch.Close() }()

	parent := ch.Head().ID()
	cfg := Config{Committee: g.Validators, TimeoutBase: roundBase, TimeoutStep: roundStep, PowerCapNum: 1, PowerCapDen: 4}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	propIdx := cfg.IndexOf(cfg.Proposer(1, 0, parent))
	if propIdx < 0 {
		t.Fatal("fixture: no round-0 proposer")
	}
	priv := testCommitteeKey(propIdx)

	net := sim.New(sim.Options{Seed: 1, Latency: 1})
	net.AddPeer(fmt.Sprintf("v%d", propIdx))
	rec := &recordingTransport{Transport: net.TransportFor(fmt.Sprintf("v%d", propIdx))}
	d := NewDriver(cfg, ch, priv, rec, nil)

	// Round 0's proposal arrives and is accepted, which retains its bytes with
	// round 0's tallies.
	blk, err := d.eng.propose(1, 0, parent)
	if err != nil {
		t.Fatalf("the fixture could not build the round-0 block: %v", err)
	}
	env := &Proposal{Height: 1, Round: 0, Block: blk, ValidRound: -1, Validator: d.eng.pub}
	env.Sig = signProposal(t, cfg, env)
	if err := d.eng.onProposal(env); err != nil {
		t.Fatalf("the round-0 proposal was refused: %v", err)
	}
	id := blk.ID()
	if d.eng.proposal == nil || d.eng.proposal.ID() != id {
		t.Fatal("fixture: the round-0 proposal was not accepted")
	}

	// Round 0 runs out before its precommit quorum completes: the engine
	// enters round 1 and e.proposal is cleared. The round-0 tallies - and,
	// with the fix, the retained bytes - survive the audit C-3 window.
	d.eng.enterRound(1)
	if d.eng.proposal != nil {
		t.Fatal("fixture: enterRound kept e.proposal; the park this test constructs depends on it being cleared")
	}
	if d.eng.sets[0] == nil || d.eng.sets[0].proposal == nil {
		t.Fatal("the round-0 proposal bytes were not retained with the round-0 tallies: a late quorum can never be appended")
	}

	// Round 1's proposer is a validator that did NOT lock on the round-0
	// block (the reconstructed late joiner, or any seat that missed the
	// round-0 polka), so it proposes a DIFFERENT block. The engine accepts it
	// "first proposal wins" - and now e.proposal names a block that is not
	// the one round 0 will commit.
	blk2 := blk
	blk2.Header.Timestamp = blk.Header.Timestamp + 1
	env2 := &Proposal{Height: 1, Round: 1, Block: blk2, ValidRound: -1, Validator: cfg.Proposer(1, 1, parent)}
	env2.Sig = signProposal(t, cfg, env2)
	if err := d.eng.onProposal(env2); err != nil {
		t.Fatalf("the round-1 proposal was refused: %v", err)
	}
	if d.eng.proposal == nil || d.eng.proposal.ID() == id {
		t.Fatal("fixture: the round-1 proposal did not become e.proposal")
	}

	// The delayed round-0 precommit quorum finally arrives: three seats
	// precommitted the round-0 block. C-3 commits it even though the engine
	// has left round 0.
	for i := 0; i < 4; i++ {
		if i == propIdx {
			continue
		}
		v := &Vote{Type: MsgPrecommit, Height: 1, Round: 0, BlockID: id, Validator: testValidator(i, 1).PubKey}
		h := v.SigningHash()
		v.Sig = crypto.Sign(testCommitteeKey(i), h[:])
		if err := d.eng.onVote(v); err != nil {
			t.Fatalf("the precommit from seat %d was refused: %v", i, err)
		}
	}
	if cid, ok := d.eng.Committed(); !ok || cid != id {
		t.Fatalf("the delayed round-0 quorum did not commit the block: committed=%v id=%x", ok, cid[:8])
	}
	if d.eng.proposal == nil || d.eng.proposal.ID() == id {
		t.Fatal("fixture: e.proposal is not the stale round-1 block, so the append does not depend on the retained bytes")
	}

	// The driver must still append the committed block: the chain advances and
	// holds the very block the quorum committed. Without the retained copy the
	// driver offers the stale round-1 block, refuses to append, and the engine
	// is in StepCommit - the height parks forever.
	d.flush()
	if ch.Height() != 1 {
		t.Fatalf("the committed height never appended: chain height %d, want 1 (a late quorum parked the node)", ch.Height())
	}
	got, err := ch.BlockAt(1)
	if err != nil {
		t.Fatalf("reading the appended block: %v", err)
	}
	if got.ID() != id {
		gotID := got.ID()
		t.Fatalf("appended %x, want the committed %x", gotID[:8], id[:8])
	}
}

// committedBlock is the driver's byte source; an engine that holds the bytes
// nowhere hands back nil, and that is the only case that may park. This pins
// the three bounded copies it consults so a later edit cannot quietly reduce
// the recovery to "whatever e.proposal happens to be".
func TestCommittedBlockFindsEveryRetainedCopy(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	var parent [32]byte
	parent[0] = 0x5a
	var blk types.Block
	blk.Header.Height = 1
	blk.Header.ParentHash = parent
	id := blk.ID()

	e := NewEngine(cfg, 1, parent, testCommitteeKey(0), func(uint64, uint32, [32]byte) (types.Block, error) { return blk, nil })

	// Nothing held: nil.
	if e.committedBlock(id) != nil {
		t.Fatal("committedBlock invented bytes the engine does not hold")
	}
	// The committing round's retained copy.
	e.commitRound = 0
	e.setsFor(0).proposal = &blk
	if got := e.committedBlock(id); got == nil || got.ID() != id {
		t.Fatal("committedBlock did not find the committing round's retained copy")
	}
	// The proof-of-lock copy (C-2), with no round copy at all.
	e.sets[0].proposal = nil
	e.lockedBlock = &blk
	if got := e.committedBlock(id); got == nil || got.ID() != id {
		t.Fatal("committedBlock did not find the proof-of-lock copy")
	}
	// A different ID is never matched by a wrong copy.
	var other types.Block
	other.Header.Height = 1
	other.Header.ParentHash = parent
	other.Header.Timestamp = 9
	if e.committedBlock(other.ID()) != nil {
		t.Fatal("committedBlock returned a block whose ID is not the committed one")
	}
}
