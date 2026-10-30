package devnet

// Constructed-state proof for the stall report.
//
// These tests do NOT provoke a stall with a timing race. Each one BUILDS the
// state the report is supposed to describe - a round whose votes stay short of
// quorum, a round with no proposal, a round whose frames were refused at the
// router or dropped by the engine, an absent seat drawn as proposer - and then
// asserts that the report names that state in words. A timing race would prove
// only that a report can be printed; a constructed state proves it can be read
// correctly.
//
// Every validator here runs with its tick and wave loops an hour apart, so the
// only clock the driver sees is the test's own virtual clock: nothing advances
// except through the calls below.

import (
	"crypto/ed25519"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cti97/b10coincom/internal/consensus"
	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/simnet"
	"github.com/cti97/b10coincom/internal/transport"
)

// quietValidators starts total validators that listen on nothing, dial nothing
// and tick an hour apart: a completely deterministic committee whose only
// state changes are the ones a test makes.
func quietValidators(t *testing.T, total int) []*Validator {
	t.Helper()
	vs := make([]*Validator, total)
	for i := range vs {
		v, err := StartValidator(ValidatorConfig{
			Dir:        t.TempDir(),
			Index:      i,
			Validators: total,
			TickEvery:  time.Hour,
			WaveEvery:  time.Hour,
		})
		if err != nil {
			t.Fatalf("starting quiet validator %d: %v", i, err)
		}
		vs[i] = v
	}
	t.Cleanup(func() { closeAll(vs) })
	return vs
}

// seatVote builds and signs one committee vote, encoded as it travels.
func seatVote(t *testing.T, seat int, typ consensus.MsgType, height uint64, round uint32, blockID [32]byte) []byte {
	t.Helper()
	priv := simnet.ValidatorKey(seat)
	pub, _ := priv.Public().(ed25519.PublicKey)
	v := &consensus.Vote{Type: typ, Height: height, Round: round, BlockID: blockID, Validator: pub}
	h := v.SigningHash()
	v.Sig = crypto.Sign(priv, h[:])
	return consensus.EncodeVote(v)
}

// strangerVote builds a correctly signed vote from a key that is NOT in the
// committee: the shape the router refuses before paying for a verification.
func strangerVote(t *testing.T) []byte {
	t.Helper()
	pub, priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	v := &consensus.Vote{Type: consensus.MsgPrevote, Height: 1, Validator: pub}
	h := v.SigningHash()
	v.Sig = crypto.Sign(priv, h[:])
	return consensus.EncodeVote(v)
}

// feed delivers one frame through the node's real receive path, so the router
// counters and the driver see exactly what a socket reader would hand them.
func feed(v *Validator, frame []byte) {
	v.route(transport.Message{Data: frame})
}

// reachRound drives every live validator to round want with the test's virtual
// clock. A fresh driver arms its round-0 deadline on its first Tick and fires
// on the next, so want+1 ticks are enough; the loop asserts the landing instead
// of trusting the arithmetic.
func reachRound(t *testing.T, vs []*Validator, want uint32) {
	t.Helper()
	var now int64
	for i := 0; i <= int(want)+2; i++ {
		now += 1_000_000 // far past any round's timeout at this devnet's ladder
		for _, v := range vs {
			if v == nil {
				continue
			}
			v.mu.Lock()
			v.drv.Tick(now)
			v.drv.Observe()
			v.mu.Unlock()
		}
		at := true
		for _, v := range vs {
			if v != nil && v.Round() != want {
				at = false
			}
		}
		if at {
			return
		}
	}
	t.Fatalf("could not land the committee on round %d (rounds: %v round0: %d)", want, roundsOf(vs), vs[0].Round())
}

func roundsOf(vs []*Validator) []uint32 {
	out := make([]uint32, 0, len(vs))
	for _, v := range vs {
		if v != nil {
			out = append(out, v.Round())
		}
	}
	return out
}

// TestStallReportNamesFramesLost constructs the delivery half: one frame the
// router refused as a non-member, one VERIFIED frame delivered twice (the
// second is a duplicate), one garbage frame, and one vote that reached the
// engine for a round far ahead of it (the engine's wrong-round counter). The
// report must say frames arrived, how many, and where each one was lost.
func TestStallReportNamesFramesLost(t *testing.T) {
	vs := quietValidators(t, 4)
	v := vs[0]

	feed(v, strangerVote(t)) // router refused, before verify
	good := seatVote(t, 1, consensus.MsgPrevote, 1, 0, [32]byte{7})
	feed(v, good)                                                     // delivered and tallied
	feed(v, good)                                                     // duplicate: dedup refuses
	feed(v, []byte{0xEE})                                             // decodes as nothing: unknown
	feed(v, seatVote(t, 2, consensus.MsgPrevote, 1, 50, [32]byte{8})) // wrong round: engine drops

	if got := v.FramesIn(); got != 2 {
		t.Fatalf("frames handed to the driver = %d, want 2 (the valid round-0 vote and the wrong-round vote); the refused, duplicate and garbage frames must not reach the engine", got)
	}
	rep := stallReport(vs)
	t.Logf("stall report (frames lost):%s", rep)
	for _, want := range []string{
		"frames=2",
		"router[refused=1 dup=1 unknown=1]",
		"drops[otherheight=0 early=1 late=0",
	} {
		if !strings.Contains(rep, want) {
			t.Fatalf("the report does not name the frame loss (%q missing):%s", want, rep)
		}
	}
}

// TestStallReportNamesVotesShortOfQuorum constructs the tally half: two of
// four validators prevote one block at height 1, round 0, one vote short of the
// quorum of three. The report must print the counted votes, the power reached,
// the quorum, and the per-block-ID split.
func TestStallReportNamesVotesShortOfQuorum(t *testing.T) {
	vs := quietValidators(t, 4)
	v := vs[0]

	id := [32]byte{0xAB, 0xAB, 0xAB, 0xAB}
	feed(v, seatVote(t, 1, consensus.MsgPrevote, 1, 0, id))
	feed(v, seatVote(t, 2, consensus.MsgPrevote, 1, 0, id))

	rep := stallReport(vs)
	t.Logf("stall report (votes short of quorum):%s", rep)
	for _, want := range []string{
		"prevote votes=2 power=2 quorum=3",
		"ids=[abababab:2]",
		"r0 h1",
	} {
		if !strings.Contains(rep, want) {
			t.Fatalf("the report does not name the short-of-quorum tally (%q missing):%s", want, rep)
		}
	}
	// The distinction is only real if the same line would show a quorum when
	// the third vote arrives: that is the threshold, not a hard-coded label.
	feed(v, seatVote(t, 3, consensus.MsgPrevote, 1, 0, id))
	if rep := stallReport(vs); !strings.Contains(rep, "prevote votes=3 power=3 quorum=3") {
		t.Fatalf("a third prevote did not move the reported tally to quorum:%s", rep)
	}
}

// TestStallReportNamesProposalAbsenceAndNilPrevote constructs the proposal
// half. Round 0 receives nothing: the report must say proposal=absent and the
// engine's own prevote=none at step=propose. The timeout then makes the engine
// prevote NIL in round 0 and enter round 1; the same round must now read
// selfprevote=nil at step=prevote. Finally a real block from round 1's drawn
// proposer is delivered: the report must flip to proposal=block= and
// selfprevote=block=, proving it reports the fact rather than a constant.
func TestStallReportNamesProposalAbsenceAndNilPrevote(t *testing.T) {
	vs := quietValidators(t, 4)
	reachRound(t, vs, 0)

	rep := stallReport(vs)
	t.Logf("stall report (no proposal yet):%s", rep)
	if !strings.Contains(rep, "proposal=absent") || !strings.Contains(rep, "selfprevote=none") {
		t.Fatalf("a round that received no proposal is not reported as absent/unvoted:%s", rep)
	}

	reachRound(t, vs, 1)
	rep = stallReport(vs)
	t.Logf("stall report (nil prevote after timeout):%s", rep)
	for _, want := range []string{
		"r0 h1 proposer=",
		"proposal=absent",
		"selfprevote=nil",
		"step=prevote",
	} {
		if !strings.Contains(rep, want) {
			t.Fatalf("the round that timed out without a proposal is not reported as a nil prevote (%q missing):%s", want, rep)
		}
	}

	// Build a real block for round 1 from the committee's drawn proposer and
	// deliver it through the node's own receive path.
	v := vs[0]
	head := v.Chain().Head()
	pub := v.cfgC.Proposer(1, 1, head.ID())
	seat := genesis.SeatOfPubKey(v.g.Validators, pub)
	if seat < 0 {
		t.Fatal("the drawn proposer is not a committee seat")
	}
	blk, err := v.Chain().Build(simnet.ValidatorKey(seat), nil, head.Header.Timestamp+1)
	if err != nil {
		t.Fatalf("building round 1's proposal: %v", err)
	}
	p := &consensus.Proposal{Height: 1, Round: 1, Block: *blk, ValidRound: -1, Validator: pub}
	h := p.SigningHash()
	p.Sig = crypto.Sign(simnet.ValidatorKey(seat), h[:])
	feed(v, consensus.EncodeProposal(p))

	rep = stallReport(vs)
	t.Logf("stall report (proposal delivered):%s", rep)
	id := blk.ID()
	prefix := fmt.Sprintf("block=%x", id[:4])
	for _, want := range []string{
		"r1 h1 proposer=",
		"proposal=" + prefix,
		"selfprevote=" + prefix,
	} {
		if !strings.Contains(rep, want) {
			t.Fatalf("a delivered, valid proposal is not reported as arrived and prevoted (%q missing):%s", want, rep)
		}
	}
}

// TestStallReportNamesTheProposerDraw constructs the draw half. Three of a
// four-seat committee run; the report must name the seat drawn for each round,
// and mark a draw that lands on the missing fourth seat as (absent) - which is
// the fact "the absent seat proposed everything" is read from at a glance.
func TestStallReportNamesTheProposerDraw(t *testing.T) {
	vs := quietValidators(t, 4)
	live := vs[:3]
	// 24 rounds of history is exactly the ring's bound, so every round the
	// report shows can be asserted against the draw the committee computed.
	const rounds = 23
	reachRound(t, live, rounds)

	headID := vs[0].Chain().Head().ID()
	absentDraws := 0
	for r := uint32(0); r <= rounds; r++ {
		pub := vs[0].cfgC.Proposer(1, r, headID)
		seat := genesis.SeatOfPubKey(vs[0].g.Validators, pub)
		if seat < 0 {
			t.Fatalf("round %d drew a proposer outside the committee", r)
		}
		if seat == 3 {
			absentDraws++
		}
		rep := stallReport(live)
		if want := fmt.Sprintf("r%d h1 proposer=seat%d", r, seat); !strings.Contains(rep, want) {
			t.Fatalf("the report does not name round %d's drawn proposer (%q missing):%s", r, want, rep)
		}
		if r == rounds {
			t.Logf("stall report (proposer draw, round %d):%s", rounds, rep)
		}
	}
	if absentDraws == 0 {
		t.Fatalf("no round in 0..%d drew the absent seat; the (absent) marking cannot be asserted", rounds)
	}
	if rep := stallReport(live); !strings.Contains(rep, "proposer=seat3(absent)") {
		t.Fatalf("the report does not mark a drawn absent seat (proposer=seat3(absent) missing):%s", rep)
	}
}

// TestStallReportIsRaceSafeWhileDriversTick polls the report continuously while
// two drivers tick in their own goroutines - the read-while-write shape the poll
// helpers have when a real run times out. Run under -race, it pins that every
// accessor the report uses takes the driver mutex and that DiagRounds hands
// back a copy rather than the live ring.
func TestStallReportIsRaceSafeWhileDriversTick(t *testing.T) {
	vs := make([]*Validator, 2)
	for i := range vs {
		v, err := StartValidator(ValidatorConfig{
			Dir:        t.TempDir(),
			Index:      i,
			Validators: 4,
			TickEvery:  2 * time.Millisecond,
			WaveEvery:  time.Hour,
		})
		if err != nil {
			t.Fatalf("starting validator %d: %v", i, err)
		}
		vs[i] = v
	}
	defer closeAll(vs)

	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
				_ = stallReport(vs)
			}
		}
	}()
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) && vs[0].Round() == 0 && vs[1].Round() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	close(done)
	wg.Wait()
	if vs[0].Round() == 0 && vs[1].Round() == 0 {
		t.Fatal("neither driver advanced a round, so the poll never raced a state change")
	}
}

// TestStallReportWouldHaveAnsweredTheCIShape reconstructs exactly the shape the
// CI failure printed - heights [0 0 0], round 108, no park, no sync drops, no
// adoption - with three live members of a four-seat committee, and shows the
// report a rerun would now leave behind. The ring shows rounds 85..108: every
// one has no proposal, zero votes, and a nil prevote from each live member, and
// the draws name the seats (including the absent one) that were asked to
// propose.
func TestStallReportWouldHaveAnsweredTheCIShape(t *testing.T) {
	vs := quietValidators(t, 4)
	live := vs[:3]
	reachRound(t, live, 108)

	msg := reachError(live, 8, time.Minute).Error()
	t.Logf("what CI would now print:%s", msg)
	for _, want := range []string{
		"heights [0 0 0]",
		"[0 108 false 0 0 0]",
		"frames=0",
		"router[refused=0 dup=0 unknown=0]",
		"proposal=absent",
		"prevote votes=0 power=0 quorum=3",
		"selfprevote=nil",
		"r85 h1", // the oldest round the 24-entry ring holds
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("the reconstructed CI shape is not self-explaining (%q missing):%s", want, msg)
		}
	}
	if strings.Contains(msg, "r84 h1") {
		t.Fatalf("the round ring is not bounded to 24 entries:%s", msg)
	}
	if len(live[0].DiagRounds()) != 24 {
		t.Fatalf("the recent-round ring holds %d entries, want 24", len(live[0].DiagRounds()))
	}
	if !strings.Contains(msg, "proposer=seat3(absent)") {
		t.Logf("note: no draw in rounds 85..108 landed on the absent seat; earlier draws still name the seats")
	}
}
