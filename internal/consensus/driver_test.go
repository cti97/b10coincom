package consensus

import (
	"crypto/ed25519"
	"fmt"
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
// until stops the loop EARLY, the way a test waits for one commit. It is
// checked after every Tick, not once per iteration: with a validator's own
// vote tallied (review finding F1) a one-validator committee commits on every
// Tick, so a test that pins post-commit state (the re-armed timeout of review
// finding F2) must observe it on the exact Tick that appended, before the next
// half-Tick can commit yet another height.
func drive(t *testing.T, d *Driver, net *sim.Net, iterations int, until func() bool) {
	t.Helper()
	for i := 0; i < iterations; i++ {
		now := int64(i) * driveStep
		d.Tick(now)
		if until != nil && until() {
			return
		}
		net.Advance(netStep)
		d.Tick(now + driveStep/2)
		if until != nil && until() {
			return
		}
	}
}

// oneValidatorFixture is the brief's single-validator fixture: quorum is 1, so
// the validator's own prevote and precommit each reach the threshold and the
// append path runs for real, no multi-node harness needed.
//
// The 1/4 power cap must be configured as 1/1 here, not the spec's 1/4: below
// four validators the largest holder always holds at least total/3, so a 1/4
// cap is satisfiable nowhere and cfg.Validate would reject the fixture before
// the test could run.
//
// Review finding F1 removed this fixture's original relay peer. The relay
// existed only to loop v0's broadcasts back to it: the engine used to tally
// votes solely as they arrived through OnMessage, the sim never echoes a
// sender's own broadcast, and a one-validator committee could therefore never
// tally its own weight into a quorum of 1. The engine now delivers its own
// vote to its own tally through the same OnMessage path a received vote takes,
// so the commit below arises from the unmodified StartProposing -> prevote ->
// precommit -> commit path with nothing but the driver's Broadcast between
// them - the fixture no longer masks, with test-only traffic, a tally the
// network would not really perform.
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
// advance. Review finding F2 extended it from stopping at the FIRST commit to
// driving to before+2: stopping at the first commit let a mutant that deletes
// the post-commit engine swap (`d.eng = NewEngine(...)` in flush) pass every
// driver test, leaving Design Decision 8's "then advances to the next height"
// pinned by nothing.
func TestDriverAppendsOnCommit(t *testing.T) {
	d, ch, rec, net, _, _, g, dir := oneValidatorFixture(t)

	before := ch.Height()
	if before != 0 {
		t.Fatalf("expected a fresh chain at height 0, got %d", before)
	}
	parentID := ch.Head().ID()

	// Drive to before+2, not to the first commit: the commit at before+1 must
	// be FOLLOWED by a second one, appended by the fresh engine the driver
	// swapped in over the block just committed.
	drive(t, d, net, 200, func() bool { return ch.Height() >= before+2 })

	if ch.Height() != before+2 {
		t.Fatalf("the chain did not advance to height %d: the commit path never appended twice (height %d, %d messages broadcast)",
			before+2, ch.Height(), len(rec.broadcasts))
	}
	// The parent chain must really link back: the first appended block parents
	// the chain head the driver started from, and the second parents the first.
	first, err := ch.BlockAt(before + 1)
	if err != nil {
		t.Fatal(err)
	}
	if first.Header.Height != before+1 {
		t.Fatalf("appended a block at height %d, want %d", first.Header.Height, before+1)
	}
	if first.Header.ParentHash != parentID {
		t.Fatalf("the committed block parents %x, want the chain head before the commit (%x)",
			first.Header.ParentHash[:8], parentID[:8])
	}
	second, err := ch.BlockAt(before + 2)
	if err != nil {
		t.Fatal(err)
	}
	firstID := first.ID()
	if second.Header.ParentHash != firstID {
		t.Fatalf("the second committed block parents %x, want the first committed block (%x): the chain did not advance twice over a correct parent chain",
			second.Header.ParentHash[:8], firstID[:8])
	}
	// And it must not overshoot: two committed heights append EXACTLY two
	// blocks. A double append that slipped past the chain's own guards would
	// leave a block at the next height too.
	if _, err := ch.BlockAt(before + 3); err == nil {
		t.Fatalf("a block exists at height %d: the commit path appended more than it committed", before+3)
	}
	// After the commit that replaced the engine, the new engine's round 0 is
	// armed with a full TimeoutBase from the CURRENT clock reading. Pinning
	// this kills the `timeoutAt = 0` mutant: a reset that forgets the elapsed
	// time arms the deadline in the past, and the very next Tick fires a
	// timeout the fresh round has not earned - the new engine burns its round-0
	// proposal on an instant timeout (its round-trips race in the same Tick)
	// instead of getting the armed window.
	if want := d.now + d.cfg.TimeoutBase; d.timeoutAt != want {
		t.Fatalf("after the commit the new engine's timeout is armed at %d, want the current reading plus one TimeoutBase (%d)",
			d.timeoutAt, want)
	}
	// The blocks are durably stored exactly once: reopen the same directory and
	// the store must replay to exactly two blocks past the genesis.
	if err := ch.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := chain.Open(g, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.Height() != before+2 {
		t.Fatalf("replayed chain sits at height %d, want %d: the commits did not append exactly two durably stored blocks",
			reopened.Height(), before+2)
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

// fourValidatorsOneSilentFixture builds a four-validator committee with real
// drivers on validators 0..2 and a SILENT fourth: peer "v3" is registered on
// the network but has no driver, no engine and no chain - it listens and never
// emits. That is the review's High finding (F1) measured end to end: three live
// validators against a quorum of 3 of TOTAL power, which must still commit.
func fourValidatorsOneSilentFixture(t *testing.T) (ds []*Driver, chs []*chain.Chain, net *sim.Net) {
	t.Helper()
	vals := make([]genesis.Validator, 0, 4)
	for i := 0; i < 4; i++ {
		vals = append(vals, testValidator(i, 1))
	}
	g := genesis.Devnet()
	g.Validators = vals
	g.Params.CommitteeSize = 4

	// n = 4 is the first size where the spec's 1/4 power cap can bind, and 1/4
	// of 4 is exactly one honest validator's power, so the cap sits at its
	// ceiling here: 1/4.
	cfg := Config{Committee: g.Validators, TimeoutBase: roundBase, TimeoutStep: roundStep, PowerCapNum: 1, PowerCapDen: 4}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}

	net = sim.New(sim.Options{Seed: 1, Latency: 1})
	for i := 0; i < 4; i++ {
		net.AddPeer(fmt.Sprintf("v%d", i))
	}
	for i := 0; i < 3; i++ {
		ch, err := chain.Open(g, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		d := NewDriver(cfg, ch, testCommitteeKey(i), net.TransportFor(fmt.Sprintf("v%d", i)))
		ds = append(ds, d)
		chs = append(chs, ch)
	}
	// v3 gets no driver: the sim drops deliveries to a handler-less endpoint,
	// which is exactly what a silent validator is.
	return ds, chs, net
}

// A validator's own vote must count toward its own tally, or a validator's
// ceiling is n-1 and not n. The review measured the consequence on four
// validators with one silent: the three live validators each saw only the other
// two (2 of the quorum of 3), never committed, and every live chain sat at
// height 0 - the committee tolerated ZERO silent validators, and Task 9's
// TestScenarioOneOfflineStillAdvances could never pass. Tolerating a silent
// validator is the entire point of BFT.
//
// With the self-tally in place, the three live validators - each one counting
// its own vote through the same path a received vote takes - hold exactly the
// quorum of 3 whenever a live validator proposes (the silent one is drawn as
// proposer in about a quarter of rounds; those rounds end on the timeout and
// the committee moves on). The test drives the real protocol over the sim on
// virtual time and requires not merely SOME progress but CONSENSUS: the three
// live chains must agree, block for block.
func TestFourValidatorsOneSilentStillCommitHeights(t *testing.T) {
	ds, chs, net := fourValidatorsOneSilentFixture(t)
	defer func() {
		for _, ch := range chs {
			_ = ch.Close()
		}
	}()

	const iterations = 600 // 6000 virtual ms: dozens of rounds
	for i := 0; i < iterations; i++ {
		now := int64(i) * driveStep
		for _, d := range ds {
			d.Tick(now)
		}
		net.Advance(netStep)
		for _, d := range ds {
			d.Tick(now + driveStep/2)
		}
	}

	h := chs[0].Height()
	const minHeight = 3
	if h < minHeight {
		t.Fatalf("with one validator silent, the three live ones still reached only height %d (want >= %d): "+
			"a validator's own vote is not being counted toward its own tally", h, minHeight)
	}
	for i, ch := range chs[1:] {
		if ch.Height() != h {
			t.Fatalf("live validator %d sits at height %d while validator 0 sits at %d: the live validators diverged",
				i+1, ch.Height(), h)
		}
		head0 := chs[0].Head().ID()
		if id := ch.Head().ID(); id != head0 {
			t.Fatalf("live validator %d head %x differs from validator 0's head %x at the same height: divergent commits",
				i+1, id[:8], head0[:8])
		}
	}
	// Nothing may exist at the height after the live validators' head: each
	// height commits exactly once, appending exactly one block.
	for _, ch := range chs {
		if _, err := ch.BlockAt(ch.Height() + 1); err == nil {
			t.Fatalf("a block exists at height %d: the commit path appended more than once", ch.Height()+1)
		}
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

// stalledTransport is a transport that records broadcasts and delivers
// nothing: a node whose peers are all absent. Every message the engine or
// driver emits under it is on record, and every message that "arrives" is one
// the test injected by hand.
type stalledTransport struct {
	broadcasts [][]byte
}

func (s *stalledTransport) Broadcast(data []byte) error {
	s.broadcasts = append(s.broadcasts, append([]byte(nil), data...))
	return nil
}
func (s *stalledTransport) OnMessage(fn func(transport.Message)) {}
func (s *stalledTransport) Peers() []transport.PeerID            { return []transport.PeerID{"v0", "v1"} }
func (s *stalledTransport) Close() error                         { return nil }

// restartCommittee is two equal validators: the fresh engine's quorum of 2
// needs BOTH precommits, so one validator's precommit locks it WITHOUT
// committing - the exact mid-height state a crashed validator is found in.
// The keys are the deterministic committee keys, identical across both runs,
// so the restarted validator is the same committee member.
func restartCommittee(t *testing.T) (cfg Config, pub0 ed25519.PublicKey, priv0 ed25519.PrivateKey, g *genesis.Genesis) {
	t.Helper()
	pub0 = testCommitteeKey(0).Public().(ed25519.PublicKey)
	priv0 = testCommitteeKey(0)
	pub1 := testCommitteeKey(1).Public().(ed25519.PublicKey)
	g = genesis.Devnet()
	g.Validators = []genesis.Validator{{PubKey: pub0, Power: 1}, {PubKey: pub1, Power: 1}}
	g.Params.CommitteeSize = 2
	cfg = Config{Committee: g.Validators, TimeoutBase: roundBase, TimeoutStep: roundStep, PowerCapNum: 1, PowerCapDen: 1}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return cfg, pub0, priv0, g
}

func precommitFor(t *testing.T, rec *stalledTransport, height uint64, round uint32, id [32]byte) *Vote {
	t.Helper()
	for _, raw := range rec.broadcasts {
		c := decodeWire(t, raw)
		if c.vote != nil && c.vote.Type == MsgPrecommit &&
			c.vote.Height == height && c.vote.Round == round && c.vote.BlockID == id {
			return c.vote
		}
	}
	return nil
}

func nonNilPrevoteFor(t *testing.T, rec *stalledTransport, height uint64, round uint32, id [32]byte) *Vote {
	t.Helper()
	for _, raw := range rec.broadcasts {
		c := decodeWire(t, raw)
		if c.vote != nil && c.vote.Type == MsgPrevote && !c.vote.IsNil() &&
			c.vote.Height == height && c.vote.Round == round && c.vote.BlockID == id {
			return c.vote
		}
	}
	return nil
}

// The locking rule's safety argument assumes a locked validator STAYS locked.
// Without persisting the lock, a validator that precommitted and then
// restarted re-entered the height UNLOCKED and would help commit a
// conflicting block - which is precisely the case the locking rule exists to
// prevent, and the hole this test exists to keep closed.
//
// The two runs share nothing but the on-disk directory: the first run's
// chain is Closed (a process exit), its driver, engine and transport are
// dropped wholesale, and the second run replays the chain from disk and
// builds a brand-new driver through the ordinary NewDriver path. The
// conflicting proposal genuinely carries NO justification (nil slice,
// ValidRound -1): it is the Design Decision 11 counterexample, arriving at an
// engine that did not exist when the promise was made.
func TestRestartedValidatorRefusesToPrevoteAConflictingBlock(t *testing.T) {
	cfg, pub0, priv0, g := restartCommittee(t)

	// ---- Run 1: lock on B at height 1, then stop mid-height. ----
	dir := t.TempDir()
	ch1, err := chain.Open(g, dir)
	if err != nil {
		t.Fatal(err)
	}
	parent := ch1.Head().ID()
	tp1 := &stalledTransport{}
	d1 := NewDriver(cfg, ch1, priv0, tp1)
	d1Engine := d1.eng // kept only to prove the restart built a different engine

	// Walk the rounds until this validator is drawn as proposer at (1, r),
	// then play the rest of the committee with one signed prevote for the
	// proposal it just received. No sim is needed: the injected vote carries
	// the real committee key, i.e. it faces exactly the trust boundary the
	// tally enforces on the wire. The clock stays at 5ms - below the round
	// timeout - so no tick can propose AND timeout in one call; a manual
	// OnTimeout leaves each round the engine did not lock in, which is what
	// keeps the injected prevote in the round it belongs to.
	now := int64(5)
	var lockRoundInt int64 = -1
	var lockID [32]byte
	for r := uint32(0); r < 64 && lockRoundInt < 0; r++ {
		d1.Tick(now)
		if string(cfg.Proposer(d1.eng.Height(), r, parent)) == string(pub0) &&
			d1.eng.Round() == r && d1.eng.proposal != nil {
			// v0 proposed B and prevoted it this round (its own prevote is
			// tallied). One peer signature completes the prevote polka, which
			// completes the precommit - and precommitting IS locking.
			d1.OnMessage(transport.Message{From: "v1", Data: EncodeVote(
				voteFrom(t, cfg, 1, MsgPrevote, d1.eng.Height(), r, d1.eng.proposal.ID()))})
			if d1.eng.lk.locked() {
				lockRoundInt = d1.eng.lk.round()
				lockID = d1.eng.lk.blockID()
			}
		}
		if lockRoundInt < 0 {
			d1.eng.OnTimeout(TimeoutEvent{Height: d1.eng.Height(), Round: d1.eng.Round(), Step: d1.eng.Step()})
		}
	}
	if lockRoundInt < 0 {
		t.Fatalf("in 64 rounds the fixture never reached one this validator proposed in: no lock was taken to restart from")
	}
	lockRound := uint32(lockRoundInt)

	// Non-vacuity, run 1: the promise is real - a precommit for B actually
	// left this validator - and the height did NOT commit (the chain head
	// never moved), so the restart must re-judge this very height.
	if ch1.Height() != 0 {
		t.Fatalf("height committed during the lock run: %d (the fixture must stop mid-height)", ch1.Height())
	}
	if d1eng := d1.eng; d1eng.hasCommitted {
		t.Fatal("the engine committed although the peer's precommit never arrived; a commit here would make the restart vacuous")
	}
	if precommitFor(t, tp1, 1, lockRound, lockID) == nil {
		t.Fatalf("no precommit for the locked block (%x at round %d) was broadcast: the promise never reached the wire", lockID[:8], lockRound)
	}
	// The promise must already be durable while the engine is alive - the
	// moment the lock moved, before any restart enters the picture.
	if got, ok := ch1.LockAt(1); !ok || got.Round != lockRound || got.BlockID != lockID {
		t.Fatalf("the lock was not persisted on the move: LockAt(1) = %+v,%v, want round %d block %x", got, ok, lockRound, lockID[:8])
	}

	// ---- Stop: everything in memory is gone; only the directory remains. ----
	if err := ch1.Close(); err != nil {
		t.Fatal(err)
	}
	d1, ch1, tp1 = nil, nil, nil

	// ---- Run 2: restart from the same directory, from scratch. ----
	ch2, err := chain.Open(g, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer ch2.Close()
	if ch2.Height() != 0 {
		t.Fatalf("the replayed chain sits at height %d; the restart must re-judge the undecided height 1", ch2.Height())
	}
	tp2 := &stalledTransport{}
	d2 := NewDriver(cfg, ch2, priv0, tp2)

	// The restored lock, checked the instant the engine exists - before the
	// engine has seen one message or one tick, i.e. before anything in run 2
	// could have reconstructed the promise from protocol traffic instead of
	// disk.
	if !d2.eng.lk.locked() {
		t.Fatal("the restarted validator re-entered the height it had precommitted UNLOCKED: it will now prevote a conflicting block")
	}
	if d2.eng.lk.round() != int64(lockRound) || d2.eng.lk.blockID() != lockID {
		gotLockID := d2.eng.lk.blockID()
		t.Fatalf("restored lock = (round %d, block %x), want (round %d, block %x): the promise came back wrong",
			d2.eng.lk.round(), gotLockID[:8], lockRound, lockID[:8])
	}
	if d2.eng != nil && d2.eng == d1Engine {
		t.Fatal("the restart reused the old engine object: the in-memory state was never really discarded")
	}
	if len(tp2.broadcasts) != 0 {
		t.Fatalf("the fresh engine emitted %d message(s) at construction; nothing may leave before it judges anything", len(tp2.broadcasts))
	}
	if got, _ := ch2.LockAt(1); got.Round != lockRound || got.BlockID != lockID {
		t.Fatalf("the store no longer carries the promise: LockAt(1) = %+v", got)
	}

	// ---- The conflicting block, with NO justification, at the height held. ----
	badBlock := conflictingBlock(t, cfg, 1, 0, parent, 0xB7)
	badProp := &Proposal{
		Height: 1, Round: 0, Block: badBlock,
		ValidRound:    -1,
		Justification: nil, // NO justification: a claim with no evidence behind it
		Validator:     cfg.Proposer(1, 0, parent),
	}
	badProp.Sig = signProposal(t, cfg, badProp)

	// Vacuity guards, stated where they matter:
	if badProp.Justification != nil || badProp.ValidRound != -1 {
		t.Fatal("the conflicting proposal must genuinely carry no justification")
	}
	if badBlock.ID() == lockID {
		t.Fatal("the conflicting block must genuinely differ from the locked one")
	}
	d2.OnMessage(transport.Message{From: "v1", Data: EncodeProposal(badProp)})

	// A validator that holds a proposal the lock refuses prevotes NIL - the
	// refusal must speak. What it must NEVER do is prevote the conflict.
	sawNonNilAfterConflict := false
	sawNilPrevote := false
	for _, raw := range tp2.broadcasts {
		c := decodeWire(t, raw)
		if c.vote == nil || c.vote.Type != MsgPrevote {
			continue
		}
		if c.vote.IsNil() {
			sawNilPrevote = true
			if c.vote.Height != 1 || c.vote.Round != 0 {
				t.Fatalf("the nil prevote must be at (height 1, round 0), got (h=%d, r=%d)", c.vote.Height, c.vote.Round)
			}
			continue
		}
		sawNonNilAfterConflict = true
		t.Fatalf("a restarted validator prevoted conflicting block %x, which its persistent promise refuses", c.vote.BlockID[:4])
	}
	if sawNonNilAfterConflict {
		t.Fatal("a fresh (unrestored) engine reaches this line: the conflicting prevote is what a restart must not emit")
	}
	if !sawNilPrevote {
		t.Fatal("no nil prevote was broadcast for the refused proposal: a silent refusal leaves the validator's weight out of the nil tally")
	}

	// ---- The restored lock is a REAL lock: it survives the round change, ----
	// and it still releases the validator on verified evidence from a round
	// strictly beyond its promise - persistence must not revoke liveness.
	d2.eng.OnTimeout(TimeoutEvent{Height: d2.eng.Height(), Round: d2.eng.Round(), Step: d2.eng.Step()})
	if !d2.eng.lk.locked() || d2.eng.lk.blockID() != lockID || d2.eng.lk.round() != int64(lockRound) {
		survivedID := d2.eng.lk.blockID()
		t.Fatalf("the restored lock did not survive enterRound: now locked=%v (round %d, block %x)",
			d2.eng.lk.locked(), d2.eng.lk.round(), survivedID[:8])
	}

	newBlock := conflictingBlock(t, cfg, 1, 1, parent, 0xA7)
	newID := newBlock.ID()
	if newID == lockID || newID == badBlock.ID() {
		t.Fatal("the justified block must genuinely differ from both the locked and the refused one")
	}
	// Evidence of the polka that legitimately moves the validator: quorum
	// prevotes for the conflicting block at a round strictly greater than the
	// stored lock. The quorum of 2 needs both committee members' signatures,
	// and this test holds both keys - which is exactly why it can fabricate
	// evidence the verification gate will accept.
	propRound := lockRound + 1
	goodProp := &Proposal{
		Height: 1, Round: 1, Block: newBlock, ValidRound: int64(propRound), Validator: cfg.Proposer(1, 1, parent),
		Justification: encodeJustification([]*Vote{
			voteFrom(t, cfg, 0, MsgPrevote, 1, propRound, newID),
			voteFrom(t, cfg, 1, MsgPrevote, 1, propRound, newID),
		}),
	}
	goodProp.Sig = signProposal(t, cfg, goodProp)
	if len(goodProp.Justification) == 0 {
		t.Fatal("the justified proposal must genuinely carry its polka")
	}
	d2.OnMessage(transport.Message{From: "v1", Data: EncodeProposal(goodProp)})
	if nonNilPrevoteFor(t, tp2, 1, 1, newID) == nil {
		t.Fatal("a restored lock that refuses verified evidence from a strictly newer round would turn persistence into a permanent stop")
	}

	// Nothing in run 2 moved the chain or the promise: no quorum was reached,
	// so the height stays undecided for the restarted validator.
	if ch2.Height() != 0 {
		t.Fatalf("the restarted validator's chain moved to height %d at a height it never reached quorum for", ch2.Height())
	}
	if d2.eng.lk.blockID() != lockID {
		t.Fatal("prevoting the justified block must not itself move the lock")
	}
}
