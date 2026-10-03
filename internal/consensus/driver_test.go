package consensus

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/transport"
	"github.com/cti97/b10coincom/internal/transport/sim"
	"github.com/cti97/b10coincom/internal/types"
)

// The driver tests run the real protocol path over the deterministic sim on
// virtual time, in lockstep: one virtual tick advances the driver's clock and
// the network together, exactly the way the Task 8 harness (RunBlocks) will
// drive it. Latency of one virtual millisecond is three orders of magnitude
// below the round timeout, so a proposal's round trips complete inside a round
// instead of racing it.
const (
	driveStep = int64(10) // virtual ms between drive iterations
	roundBase = int64(10) // TimeoutBase for every driver fixture
	roundStep = int64(10) // TimeoutStep for every driver fixture
	netStep   = 10 * time.Millisecond
)

// recordingTransport wraps the sim endpoint the driver is wired to and keeps
// every payload the driver hands to Broadcast. It is the seam that lets the
// tests observe exactly what Drain produced and where it went.
type recordingTransport struct {
	transport.Transport
	broadcasts [][]byte
}

func (r *recordingTransport) Broadcast(data []byte) error {
	r.broadcasts = append(r.broadcasts, append([]byte(nil), data...))
	return r.Transport.Broadcast(data)
}

// wireContent classifies one recorded payload. The engine's output space is
// proposals and votes; anything undecodable stays unclassified and fails the
// assertions that need it.
type wireContent struct {
	prop *Proposal
	vote *Vote
}

func decodeWire(t *testing.T, raw []byte) wireContent {
	t.Helper()
	if p, err := DecodeProposal(raw); err == nil {
		return wireContent{prop: p}
	}
	if v, err := DecodeVote(raw); err == nil {
		return wireContent{vote: v}
	}
	return wireContent{}
}

func countWire(t *testing.T, rec *recordingTransport) (proposals []*Proposal, votes []*Vote) {
	t.Helper()
	for _, raw := range rec.broadcasts {
		if c := decodeWire(t, raw); c.prop != nil {
			proposals = append(proposals, c.prop)
		} else if c.vote != nil {
			votes = append(votes, c.vote)
		}
	}
	return proposals, votes
}

// drive steps the driver and the network in lockstep: each iteration advances
// the driver's clock by driveStep and the simulated network by the same 10ms,
// then one extra half-step Tick so anything a delivery flushed can react while
// the round's timer cannot fire early (deadline re-arms are multiples of 10).
// until stops the loop early, the way a test waits for one commit.
func drive(t *testing.T, d *Driver, net *sim.Net, iterations int, until func() bool) {
	t.Helper()
	for i := 0; i < iterations; i++ {
		now := int64(i) * driveStep
		d.Tick(now)
		net.Advance(netStep)
		d.Tick(now + driveStep/2)
		if until != nil && until() {
			return
		}
	}
}

// oneValidatorFixture is the brief's single-validator fixture: quorum is 1, so
// the validator's own prevote and precommit each reach the threshold and the
// appendix path runs for real, no multi-node harness needed.
//
// The 1/4 power cap must be configured as 1/1 here, not the spec's 1/4: below
// four validators the largest holder always holds at least total/3, so a 1/4
// cap is satisfiable nowhere and cfg.Validate would reject the fixture before
// the test could run.
//
// The fixture also adds one relay peer. The engine tallies votes ONLY as they
// arrive through OnMessage and the sim never echoes a sender's own broadcast,
// so a one-validator committee would otherwise never see its own prevote
// return and could never tally its own weight into the quorum of 1. The relay
// replays everything v0 broadcasts back into v0 through the sim: the driver
// still only ever calls Broadcast, and the commit below arises from the
// unmodified StartProposing -> prevote -> precommit -> commit path, just with
// the whole committee being the proposer it is also delivering to.
func oneValidatorFixture(t *testing.T) (d *Driver, ch *chain.Chain, rec *recordingTransport, net *sim.Net, pub ed25519.PublicKey, priv ed25519.PrivateKey, g *genesis.Genesis, dir string) {
	t.Helper()
	pub, priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	g = genesis.Devnet()
	g.Validators = []genesis.Validator{{PubKey: pub, Power: 1}}
	g.Params.CommitteeSize = 1

	dir = t.TempDir()
	ch, err = chain.Open(g, dir)
	if err != nil {
		t.Fatal(err)
	}

	cfg := Config{Committee: g.Validators, TimeoutBase: roundBase, TimeoutStep: roundStep, PowerCapNum: 1, PowerCapDen: 1}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}

	net = sim.New(sim.Options{Seed: 1, Latency: 1})
	net.AddPeer("v0")
	rec = &recordingTransport{Transport: net.TransportFor("v0")}
	d = NewDriver(cfg, ch, priv, rec)

	// The relay: peer "loop" re-broadcasts whatever it receives, so v0's own
	// messages return to it with real transport latency.
	net.AddPeer("loop")
	relay := net.TransportFor("loop")
	relay.OnMessage(func(m transport.Message) {
		_ = relay.Broadcast(m.Data)
	})
	return d, ch, rec, net, pub, priv, g, dir
}

// blockedQuorumFixture is a two-validator committee with only one driver: with
// power 1 of 2 the driver can never hold the quorum of 2, no matter how many
// rounds churn. Its peer is a live transport destination that never replies.
// This is the fixture Design Decision 8 needs: a height that cannot be decided
// must leave the chain exactly where it started.
func blockedQuorumFixture(t *testing.T) (d *Driver, ch *chain.Chain, rec *recordingTransport, net *sim.Net, pub ed25519.PublicKey) {
	t.Helper()
	priv := testCommitteeKey(0)
	peer := testCommitteeKey(1)
	pub = priv.Public().(ed25519.PublicKey)

	g := genesis.Devnet()
	g.Validators = []genesis.Validator{
		{PubKey: pub, Power: 1},
		{PubKey: peer.Public().(ed25519.PublicKey), Power: 1},
	}
	g.Params.CommitteeSize = 2

	var err error
	ch, err = chain.Open(g, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	cfg := Config{Committee: g.Validators, TimeoutBase: roundBase, TimeoutStep: roundStep, PowerCapNum: 1, PowerCapDen: 1}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}

	net = sim.New(sim.Options{Seed: 1, Latency: 1})
	net.AddPeer("v0")
	net.AddPeer("ghost") // listens, never sends: the absent second validator
	rec = &recordingTransport{Transport: net.TransportFor("v0")}
	d = NewDriver(cfg, ch, priv, rec)
	return d, ch, rec, net, pub
}

// A one-validator committee has a quorum of 1, so it can drive itself all the
// way to a commit. That makes the whole append-on-commit path testable without
// the multi-node harness, and it is a POSITIVE test: the chain must actually
// advance, by exactly one block, exactly once.
func TestDriverAppendsOnCommit(t *testing.T) {
	d, ch, rec, net, _, _, g, dir := oneValidatorFixture(t)

	before := ch.Height()
	if before != 0 {
		t.Fatalf("expected a fresh chain at height 0, got %d", before)
	}
	parentID := ch.Head().ID()

	drive(t, d, net, 200, func() bool { return ch.Height() > before })

	if ch.Height() != before+1 {
		t.Fatalf("the chain did not advance past height %d: the commit path never appended (height %d, %d messages broadcast)",
			before, ch.Height(), len(rec.broadcasts))
	}
	head, err := ch.BlockAt(ch.Height())
	if err != nil {
		t.Fatal(err)
	}
	if head.Header.Height != before+1 {
		t.Fatalf("appended a block at height %d, want %d", head.Header.Height, before+1)
	}
	if head.Header.ParentHash != parentID {
		t.Fatalf("the committed block parents %x, want the chain head before the commit (%x)",
			head.Header.ParentHash[:8], parentID[:8])
	}
	// And it must not overshoot: committing appends EXACTLY one block. A
	// double append that slipped past the chain's own guards would leave a
	// block at the next height too.
	if _, err := ch.BlockAt(before + 2); err == nil {
		t.Fatalf("a block exists at height %d: the commit appended more than once", before+2)
	}
	// The block is durably stored exactly once: reopen the same directory and
	// the store must replay to exactly one block past the genesis.
	if err := ch.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := chain.Open(g, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.Height() != before+1 {
		t.Fatalf("replayed chain sits at height %d, want %d: the commit did not append exactly one durably stored block",
			reopened.Height(), before+1)
	}
}

// The engine never speculatively applies a block, so the chain may not move
// until a commit exists - Design Decision 8. With a quorum this driver can
// never reach, the height churns through rounds, votes fly, and the chain must
// not move by a single block: not at proposal receipt, not at precommit, not
// ever.
func TestDriverLeavesChainUntouchedWithoutQuorum(t *testing.T) {
	d, ch, rec, net, _ := blockedQuorumFixture(t)

	parentID := ch.Head().ID()
	drive(t, d, net, 300, func() bool {
		if ch.Height() != 0 {
			t.Fatalf("the chain moved to height %d at a height that cannot reach quorum", ch.Height())
		}
		return false
	})
	if ch.Height() != 0 {
		t.Fatalf("chain height is %d, want 0", ch.Height())
	}
	if ch.Head().ID() != parentID {
		t.Fatal("the chain head changed although nothing was ever committed")
	}
	if _, err := ch.BlockAt(1); err == nil {
		t.Fatal("a block was stored although no commit ever happened")
	}
	if d.eng.Height() != 1 {
		t.Fatalf("the driver abandoned the undecided height for height %d", d.eng.Height())
	}

	// The fixture must have been LIVE, or the invariant above is vacuous: the
	// driver must have proposed (rounds where it held proposership) and cast a
	// nil prevote (rounds it could not), all without touching the chain.
	proposals, votes := countWire(t, rec)
	if len(proposals) == 0 {
		t.Fatal("no proposal was ever broadcast: the fixture never exercised a held proposal")
	}
	nils := 0
	for _, v := range votes {
		if v.Type == MsgPrevote && v.IsNil() {
			nils++
		}
	}
	if nils == 0 {
		t.Fatal("no nil prevote was ever broadcast: stalled rounds were never left behind")
	}
}

// A rejected Append must leave the driver at the same height rather than
// advancing or corrupting state. The engine cannot validate a block's state
// root (it holds no state by design), so the realistic way a commit fails is
// exactly this: a block the engine accepted that the chain refuses. The driver
// must not swap in a new engine for the next height - the height is not
// decided for THIS node, and silently moving on would diverge it from every
// peer that did accept the block.
func TestDriverRejectedAppendStaysAtSameHeight(t *testing.T) {
	d, ch, _, net, pub, priv, _, _ := oneValidatorFixture(t)

	// A proposal whose state root is a lie. It passes every engine-level check
	// (envelope signature, membership, justification) because the engine owns
	// no state to check it against; chain.Append rejects it on the root.
	head0 := ch.Head()
	lied := &types.Block{Header: types.Header{
		Height:     head0.Header.Height + 1,
		ParentHash: head0.ID(),
		StateRoot:  [32]byte{0xde, 0xad, 0xbe, 0xef},
		TxRoot:     types.ComputeTxRoot(nil),
		Timestamp:  head0.Header.Timestamp + 1,
		Proposer:   pub,
	}}
	liedHeaderHash := lied.Header.SigningHash()
	lied.Sig = crypto.Sign(priv, liedHeaderHash[:])
	prop := &Proposal{
		Height:     lied.Header.Height,
		Round:      0,
		Block:      *lied,
		ValidRound: -1,
		Validator:  pub,
	}
	propHash := prop.SigningHash()
	prop.Sig = crypto.Sign(priv, propHash[:])

	engAtStart := d.eng
	d.OnMessage(transport.Message{From: "v0", Data: EncodeProposal(prop)})

	drive(t, d, net, 50, func() bool { return d.eng.hasCommitted })
	if !d.eng.hasCommitted {
		t.Fatal("the engine never reached its own commit: the test did not exercise the real append path")
	}
	if ch.Height() != 0 {
		t.Fatalf("the chain advanced to height %d although Append must reject the lied-about block", ch.Height())
	}
	if d.Height() != 0 {
		t.Fatalf("driver height is %d, want 0", d.Height())
	}
	if _, err := ch.BlockAt(1); err == nil {
		t.Fatal("the rejected block was durably stored")
	}
	if d.eng != engAtStart {
		t.Fatal("the driver swapped in a new engine although Append rejected the block: the next height would start from a chain state the validator never agreed to")
	}
	if d.eng.Height() != 1 {
		t.Fatalf("the driver moved to height %d; a rejected append must stay at the undecided height", d.eng.Height())
	}

	// The stall is stable, not a pending retry that leaks an append: keep
	// driving and the chain stays exactly where it was.
	drive(t, d, net, 20, nil)
	if ch.Height() != 0 || d.eng != engAtStart || !d.eng.hasCommitted {
		t.Fatalf("the driver did not stay put after the rejected append: height %d, engine swapped %v, still committed %v",
			ch.Height(), d.eng != engAtStart, !d.eng.hasCommitted)
	}
}

// The driver owns the outgoing queue: everything Drain returns must reach the
// transport, and a broadcast goes to Broadcast rather than being dropped. The
// commits the other tests observe are only possible because these messages
// really left the driver, so this test names the seam directly.
func TestDriverForwardsDrainedMessagesToTransport(t *testing.T) {
	d, ch, rec, net, pub, _, _, _ := oneValidatorFixture(t)

	drive(t, d, net, 200, func() bool { return ch.Height() > 0 })
	if ch.Height() != 1 {
		t.Fatalf("the driver did not commit (height %d, %d broadcasts)", ch.Height(), len(rec.broadcasts))
	}

	// A full proposal -> prevote -> precommit round broadcast at least three
	// messages, every one of them through Broadcast.
	if len(rec.broadcasts) < 3 {
		t.Fatalf("only %d messages reached the transport; a proposal, a prevote and a precommit must all leave the driver", len(rec.broadcasts))
	}
	proposals, votes := countWire(t, rec)
	if len(proposals) == 0 {
		t.Fatal("no decodable proposal ever reached the transport")
	}
	if proposals[0].Height != 1 || string(proposals[0].Validator) != string(pub) {
		t.Fatalf("the proposal that reached the transport names (h=%d, validator=%d bytes), want (1, the driver's key)",
			proposals[0].Height, len(proposals[0].Validator))
	}
	var sawPrevote, sawPrecommit bool
	for _, v := range votes {
		if v.Height != 1 || string(v.Validator) != string(pub) {
			continue
		}
		switch v.Type {
		case MsgPrevote:
			sawPrevote = true
		case MsgPrecommit:
			sawPrecommit = true
		}
	}
	if !sawPrevote || !sawPrecommit {
		t.Fatalf("the transport saw prevote=%v precommit=%v from the driver: the vote path did not broadcast", sawPrevote, sawPrecommit)
	}

	// The block that got committed IS one of the proposals that went out over
	// the transport: what the engine proposed, what it tallied, what it told
	// the network about, and what it appended are all the same block.
	head, err := ch.BlockAt(1)
	if err != nil {
		t.Fatal(err)
	}
	committedID := head.ID()
	for _, p := range proposals {
		if p.Block.ID() == committedID {
			return
		}
	}
	t.Fatalf("no broadcast proposal carries the committed block ID %x: the commit cannot have come from the proposal path", committedID[:8])
}

// A round that cannot reach quorum still ends: the driver passes the CURRENT
// height and round to OnTimeout - never pre-incremented. OnTimeout's contract
// is "the round you are in ran out of time" and the ENGINE advances the round;
// a driver that pre-increments would fire timeouts the engine reads as stale
// re-fires for a round it has not entered, so no round would ever be left
// behind. This exact defect was removed from the engine's caller by Task 6's
// review.
func TestDriverEndsTheRoundItIsInOnTimeout(t *testing.T) {
	d, ch, rec, net, _ := blockedQuorumFixture(t)

	drive(t, d, net, 300, func() bool {
		if ch.Height() != 0 {
			t.Fatalf("the chain moved to height %d without a reachable quorum", ch.Height())
		}
		return false
	})

	if r := d.eng.Round(); r < 8 {
		t.Fatalf("the engine sat at round %d for 3000 virtual ms: the driver is not ending the rounds its engine is in", r)
	}
	// Each settled round left its weight behind with exactly one signed nil
	// prevote for the round that ended. Under a pre-incremented round the
	// engine would emit none of these (every timeout ignored as stale).
	nilRounds := map[uint32]bool{}
	for _, raw := range rec.broadcasts {
		c := decodeWire(t, raw)
		if c.vote == nil || c.vote.Type != MsgPrevote || !c.vote.IsNil() || c.vote.Height != d.eng.Height() {
			continue
		}
		nilRounds[c.vote.Round] = true
	}
	if len(nilRounds) < 3 {
		t.Fatalf("only rounds %v emitted the nil prevote of a stalled round; rounds whose timeouts the engine ignored are missing from the list", keysOf(nilRounds))
	}
}

func keysOf(m map[uint32]bool) []uint32 {
	out := make([]uint32, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}
