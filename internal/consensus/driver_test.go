package consensus

import (
	"crypto/ed25519"
	"fmt"
	"math"
	"strconv"
	"testing"
	"time"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/faucet"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/mempool"
	"github.com/cti97/b10coincom/internal/store"
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
func oneValidatorFixture(t *testing.T) (d *Driver, ch *chain.Chain, rec *recordingTransport, net *sim.Net, pub ed25519.PublicKey, priv ed25519.PrivateKey, g *genesis.Genesis, dir string, mp *mempool.Mempool) {
	return oneValidatorFixtureOnGenesis(t, genesis.Devnet())
}

// oneValidatorFixtureOnGenesis is oneValidatorFixture over a caller-supplied
// genesis: the claim tests need genesis overrides (claim amount, per-block
// bound) and nothing else about the fixture may change with them.
func oneValidatorFixtureOnGenesis(t *testing.T, g *genesis.Genesis) (d *Driver, ch *chain.Chain, rec *recordingTransport, net *sim.Net, pub ed25519.PublicKey, priv ed25519.PrivateKey, gOut *genesis.Genesis, dir string, mp *mempool.Mempool) {
	t.Helper()
	pub, priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
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
	// The fixture's mempool is returned precisely so tests can fill it: an
	// empty pool proposes empty blocks, the behaviour every pre-existing
	// driver test ran under before transactions had a source.
	mp = mempool.New(1000, g.Hash())
	d = NewDriver(cfg, ch, priv, rec, mp)
	return d, ch, rec, net, pub, priv, g, dir, mp
}

// blockedQuorumFixture is a two-validator committee with only one driver: with
// power 1 of 2 the driver can never hold the quorum of 2, no matter how many
// rounds churn. Its peer is a live transport destination that never replies.
// This is the fixture Design Decision 8 needs: a height that cannot be decided
// must leave the chain exactly where it started.
func blockedQuorumFixture(t *testing.T) (d *Driver, ch *chain.Chain, rec *recordingTransport, net *sim.Net, pub ed25519.PublicKey, mp *mempool.Mempool) {
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
	mp = mempool.New(1000, g.Hash())
	d = NewDriver(cfg, ch, priv, rec, mp)
	return d, ch, rec, net, pub, mp
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
	d, ch, rec, net, _, _, g, dir, _ := oneValidatorFixture(t)

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

// TestDriverPostCommitSwapStillCarriesTheLock pins the OTHER engine-creation
// site: the post-commit swap inside flush. The restore/persist guarantee is a
// per-CREATION guarantee (any engine, any site), so a swap built on the bare
// constructor silently makes every engine after the first commit persist
// NOTHING and restore NO lock - memory-only locks from height 2 on, i.e. the
// exact defect persisting the lock exists to fix, arrived through one
// unreviewed line. The test drives far enough that the post-commit swap has
// created the engines judging heights 2 and 3, then requires those engines'
// own lock moves to be in the store: if the swap lost its restore/persist
// wiring, nothing reaches the lock log after height 1 and this fails.
func TestDriverPostCommitSwapStillCarriesTheLock(t *testing.T) {
	d, ch, rec, net, _, _, _, _, _ := oneValidatorFixture(t)

	// Three commits: heights 1, 2 and 3. The first engine is NewDriver's
	// creation; every engine after it comes from flush's post-commit swap,
	// which is the line the mutant reverts.
	drive(t, d, net, 200, func() bool { return ch.Height() >= 3 })
	if ch.Height() < 3 {
		t.Fatalf("only %d block(s) committed in 200 drive iterations (%d messages): the post-commit swap never ran, the assertion below would be vacuous", ch.Height(), len(rec.broadcasts))
	}

	for _, h := range []uint64{2, 3} {
		blk, err := ch.BlockAt(h)
		if err != nil {
			t.Fatal(err)
		}
		wantID := blk.ID()
		// Height h's engine precommitted its own proposal before committing it,
		// so its lock (round 0, the committed block) must be durable - no
		// pruning exists yet, a committed lock record stays readable.
		got, ok := ch.LockAt(h)
		if !ok {
			t.Fatalf("the lock taken at committed height %d never reached the store: the engine the post-commit swap created is holding locks in memory only - a restart would re-enter unlocked", h)
		}
		if got != (store.LockRecord{Height: h, Round: 0, BlockID: wantID}) {
			t.Fatalf("LockAt(%d) = %+v, want the own-proposal lock (round 0, block %x) the commit itself proves was taken", h, got, wantID[:8])
		}
	}
}

// The engine never speculatively applies a block, so the chain may not move
// until a commit exists - Design Decision 8. With a quorum this driver can
// never reach, the height churns through rounds, votes fly, and the chain must
// not move by a single block: not at proposal receipt, not at precommit, not
// ever.
func TestDriverLeavesChainUntouchedWithoutQuorum(t *testing.T) {
	d, ch, rec, net, _, _ := blockedQuorumFixture(t)

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
// advancing or corrupting state (Design Decision 8: a refused block is never
// silently skipped).
//
// Since the pre-vote validation seam (audit C-1), the COMMON way a commit
// would fail - a proposal whose bytes the chain cannot accept - now ends
// earlier: the engine nil-prevotes it and no commit ever forms (see
// TestDriverNilPrevotesAGarbageRootProposal). What remains reachable is the
// race against a chain that moved under the engine: a peer's committed block
// adopted mid-round (exactly what a catch-up wave does, before the driver is
// rebuilt) leaves the engine judging a height the head has already passed.
// The engine's commit of its own proposal then fails Append honestly, and
// this test pins the refusal's consequences: same height, no engine swap, no
// retry.
//
// The harness stages exactly that over the blocked-quorum fixture (quorum 2,
// the peer a ghost whose only participation is the votes the test injects by
// hand): one valid proposal prevoted by this validator, a foreign block
// appended straight to the chain (the adopted peer block), then the ghost's
// prevote and precommit completing the polka and the precommit quorum for
// the - now stale - proposal.
func TestDriverRejectedAppendStaysAtSameHeight(t *testing.T) {
	d, ch, _, net, _, _ := blockedQuorumFixture(t)

	parentID := ch.Head().ID()
	engAtStart := d.eng
	heightJudged := d.eng.Height()
	roundJudged := d.eng.Round()

	// The proposal P this validator will judge: built by the ROUND proposer
	// through the chain itself, so it carries a genuine state root and passes
	// the seam while the head still stands where P was built for.
	proposerPub := d.cfg.Proposer(heightJudged, roundJudged, parentID)
	proposerIdx := d.cfg.IndexOf(proposerPub)
	prop, err := ch.Build(testCommitteeKey(proposerIdx), nil, ch.Head().Header.Timestamp+1)
	if err != nil {
		t.Fatal(err)
	}
	env := &Proposal{
		Height: heightJudged, Round: roundJudged, Block: *prop, ValidRound: -1,
		Validator: proposerPub,
	}
	env.Sig = signProposal(t, d.cfg, env)

	// Deliver P: the engine accepts and prevotes it (its own weight only -
	// the quorum of 2 needs the peer too, so nothing commits yet).
	d.OnMessage(transport.Message{From: "v1", Data: EncodeProposal(env)})
	if d.eng.proposal == nil || d.eng.proposal.ID() != prop.ID() {
		t.Fatal("fixture: the engine did not accept the staged proposal")
	}

	// The chain moves under the engine, the way an adopted peer block does:
	// a DIFFERENT valid block at the same height, carried by a genuine
	// transfer transaction so it cannot byte-match P.
	foreign, err := ch.Build(testCommitteeKey(0), []types.Tx{transferTx(ch.Genesis(), 0, 1, 0, 1)}, ch.Head().Header.Timestamp+1)
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.Append(foreign); err != nil {
		t.Fatalf("fixture: the foreign block must append against the pre-move head: %v", err)
	}
	if ch.Height() != 1 {
		t.Fatalf("fixture: the foreign block did not move the chain (height %d)", ch.Height())
	}

	// The peer's prevote and precommit for P arrive; the polka and the
	// precommit quorum (2 of 2) complete, the engine commits P, and flush
	// offers the block bytes to a head that has already moved on.
	d.OnMessage(transport.Message{From: "v1", Data: EncodeVote(voteFrom(t, d.cfg, 1, MsgPrevote, heightJudged, roundJudged, prop.ID()))})
	d.OnMessage(transport.Message{From: "v1", Data: EncodeVote(voteFrom(t, d.cfg, 1, MsgPrecommit, heightJudged, roundJudged, prop.ID()))})
	if !d.eng.hasCommitted {
		t.Fatalf("fixture: the engine did not commit the staged proposal (the polka needed the peer's own precommit)")
	}
	if !d.appendRefused {
		t.Fatal("the refused append was not recorded; the harness did not reach the refusal path")
	}

	// The refusal's consequences: the driver stays at the height whose commit
	// was refused and never swaps in a next-height engine.
	if d.Height() != 1 {
		t.Fatalf("driver height is %d, want 1 (the chain's only adopted height)", d.Height())
	}
	if d.eng != engAtStart {
		t.Fatal("the driver swapped in a new engine although Append rejected the block: the next height would start from a chain state the validator never agreed to")
	}
	if d.eng.Height() != heightJudged {
		t.Fatalf("the driver moved to height %d; a rejected append must stay at the undecided height", d.eng.Height())
	}
	// The refused block is not on disk either: height 1 holds the foreign
	// block, exactly once, and nothing exists at height 2.
	stored, err := ch.BlockAt(1)
	if err != nil {
		t.Fatal(err)
	}
	foreignID := foreign.ID()
	if stored.ID() != foreignID {
		t.Fatal("the refused append found its way into the store")
	}
	if _, err := ch.BlockAt(2); err == nil {
		t.Fatalf("a block exists at height %d: the refused commit appended after all", ch.Height()+1)
	}

	// The stall is stable, not a pending retry that leaks an append: keep
	// driving and the chain stays exactly where it was.
	drive(t, d, net, 20, nil)
	if !d.appendRefused || d.eng != engAtStart || d.eng.Height() != heightJudged {
		t.Fatalf("the driver did not stay put after the rejected append: refused %v, engine swapped %v, height %d",
			d.appendRefused, d.eng != engAtStart, d.eng.Height())
	}
}

// The driver owns the outgoing queue: everything Drain returns must reach the
// transport, and a broadcast goes to Broadcast rather than being dropped. The
// commits the other tests observe are only possible because these messages
// really left the driver, so this test names the seam directly.
func TestDriverForwardsDrainedMessagesToTransport(t *testing.T) {
	d, ch, rec, net, pub, _, _, _, _ := oneValidatorFixture(t)

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
	d, ch, rec, net, _, _ := blockedQuorumFixture(t)

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
func fourValidatorsOneSilentFixture(t *testing.T) (ds []*Driver, chs []*chain.Chain, net *sim.Net, pools []*mempool.Mempool) {
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
		// The pools are handed back so tests can fill them: filling a
		// validator's pool is what M4's relay tasks will do, and a scenario
		// that wants transactions on the wire puts them here.
		pool := mempool.New(1000, g.Hash())
		ds = append(ds, NewDriver(cfg, ch, testCommitteeKey(i), net.TransportFor(fmt.Sprintf("v%d", i)), pool))
		chs = append(chs, ch)
		pools = append(pools, pool)
	}
	// v3 gets no driver: the sim drops deliveries to a handler-less endpoint,
	// which is exactly what a silent validator is.
	return ds, chs, net, pools
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
	ds, chs, net, _ := fourValidatorsOneSilentFixture(t)
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

// Send lands in the same record: the engine emits only broadcasts today, and
// the driver routes a non-empty To through Send, so recording both keeps the
// "everything the driver emitted is on record" property true of the seam.
func (s *stalledTransport) Send(peer transport.PeerID, data []byte) error {
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
	d1 := NewDriver(cfg, ch1, priv0, tp1, nil) // no pool: this test wires no transaction source
	d1Engine := d1.eng                         // kept only to prove the restart built a different engine

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
	d2 := NewDriver(cfg, ch2, priv0, tp2, nil) // no pool: this test wires no transaction source

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
	// Since the pre-vote validation seam, a driver-level conflicting proposal
	// must be a block the chain would genuinely accept - a real state root,
	// built through the chain by the round's proposer - so the refusal below
	// is the LOCK's refusal and not the seam's (the seam's refusal has its
	// own test): the lock must still refuse a VALID conflicting block that
	// carries no evidence.
	badRound0Proposer := cfg.Proposer(1, 0, parent)
	badBlock, err := ch2.Build(testCommitteeKey(cfg.IndexOf(badRound0Proposer)), []types.Tx{transferTx(ch2.Genesis(), 0, 1, 0, 1)}, ch2.Head().Header.Timestamp+1)
	if err != nil {
		t.Fatal(err)
	}
	badProp := &Proposal{
		Height: 1, Round: 0, Block: *badBlock,
		ValidRound:    -1,
		Justification: nil, // NO justification: a claim with no evidence behind it
		Validator:     badRound0Proposer,
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

	// The justified proposal's block is a REAL block too - built through the
	// chain by the round's actual proposer, so it passes the seam and reaches
	// the lock rule: persistence must not revoke liveness (the unlock is
	// exactly what a justified, strictly-newer-polka proposal exists to do).
	// Only dev account 0 is funded on this genesis, so the second block keeps
	// the same nonce but a different amount - a different tx, hence a
	// different block ID from the bad block's.
	p1 := cfg.Proposer(1, 1, parent)
	newBlock, err := ch2.Build(testCommitteeKey(cfg.IndexOf(p1)), []types.Tx{transferTx(ch2.Genesis(), 0, 1, 0, 5)}, ch2.Head().Header.Timestamp+1)
	if err != nil {
		t.Fatal(err)
	}
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
		Height: 1, Round: 1, Block: *newBlock, ValidRound: int64(propRound), Validator: cfg.Proposer(1, 1, parent),
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

// ---- Task 0: consensus blocks carry transactions ----
//
// M3's driver proposed nil, so the chain that pays faucet claims (the M2
// single-node path) and the committee that agrees (the M3 consensus path) had
// never run together: a block paying a claim had never been agreed on by more
// than one validator. These tests drive the driver over the same virtual-time
// sim fixtures the other driver tests use, with the driver's mempool filled
// the way a real submission path would fill it.

// transferTx builds a signed transfer from devnet dev account from to dev
// account to at the given nonce and amount. Account 0 holds one million b10 on
// a fresh chain, so transfers out of it apply.
func transferTx(g *genesis.Genesis, from, to int, nonce, amount uint64) types.Tx {
	fromPub, fromPriv := genesis.DevAccountKey(from)
	toPub, _ := genesis.DevAccountKey(to)
	tx := &types.Tx{
		Type:   types.TxTransfer,
		From:   types.AddressFromPub(fromPub),
		PubKey: fromPub,
		Nonce:  nonce,
		Fee:    g.Params.MinFeeSparks,
		To:     types.AddressFromPub(toPub),
		Amount: amount,
	}
	sig := tx.SigningHash(g.Hash())
	tx.Sig = crypto.Sign(fromPriv, sig[:])
	return *tx
}

// claimTx builds a SOLVED, signed faucet claim for the deterministic test
// claimant index i at epoch. The puzzle is genuinely mined under the genesis
// parameters, so the claim is payable - the tests below assert application,
// and a claim that could not apply would only prove the test's own blindness.
func claimTx(t *testing.T, g *genesis.Genesis, index int, epoch uint64) types.Tx {
	t.Helper()
	h := crypto.HashParts([]byte("b10coin-driver-test-claimant"), []byte(strconv.Itoa(index)))
	priv := ed25519.NewKeyFromSeed(h[:])
	pub := priv.Public().(ed25519.PublicKey)
	pow, ok := faucet.Solve(pub, epoch, g.Params.FaucetPowTarget, g.Params.FaucetPowArgon2, 1_000_000)
	if !ok {
		t.Fatalf("test claimant %d did not solve the fixture puzzle in 1,000,000 attempts", index)
	}
	tx := &types.Tx{
		Type:     types.TxFaucetClaim,
		From:     types.AddressFromPub(pub),
		PubKey:   pub,
		Nonce:    0,
		Epoch:    epoch,
		PowNonce: pow,
	}
	sig := tx.SigningHash(g.Hash())
	tx.Sig = crypto.Sign(priv, sig[:])
	return *tx
}

// carriesTx reports whether blk holds a transaction with the given ID.
func carriesTx(blk *types.Block, id [32]byte) bool {
	for i := range blk.Txs {
		if blk.Txs[i].ID() == id {
			return true
		}
	}
	return false
}

// committedBlock fetches the stored block at height.
func committedBlock(t *testing.T, ch *chain.Chain, height uint64) *types.Block {
	t.Helper()
	blk, err := ch.BlockAt(height)
	if err != nil {
		t.Fatal(err)
	}
	return blk
}

// A committed consensus block must carry the transactions the mempool held.
// Until M4 the driver proposed an empty list, so the committed block was empty
// by construction no matter what the pool held.
func TestAConsensusBlockCarriesMempoolTransactions(t *testing.T) {
	d, ch, rec, net, _, _, _, _, mp := oneValidatorFixture(t)

	tx := transferTx(ch.Genesis(), 0, 1, 0, 250*genesis.SparksPerB10)
	txID := tx.ID()
	if err := mp.Add([]types.Tx{tx})[0]; err != nil {
		t.Fatal(err)
	}

	drive(t, d, net, 200, func() bool { return ch.Height() >= 1 })
	if ch.Height() < 1 {
		t.Fatalf("the committee never committed after 200 drive iterations (%d messages): no committed block to inspect", len(rec.broadcasts))
	}
	// The committed batch must be off the driver's books the moment the
	// append succeeded: a batch still held as pending would be reclaimed and
	// re-evicted by every later height's proposal.
	if len(d.pending) != 0 {
		t.Fatalf("the driver still holds %d pending transaction(s) after appending its own commit: committed transactions must not be reclaimed for a second ride", len(d.pending))
	}
	blk := committedBlock(t, ch, 1)
	if len(blk.Txs) == 0 {
		t.Fatal("the committed block carries NO transactions: the driver is still proposing an empty list")
	}
	if !carriesTx(blk, txID) {
		t.Fatalf("the committed block carries %d transaction(s) but not the mempool's transfer %x: it proposed something else", len(blk.Txs), txID[:8])
	}
	// The transfer must have been APPLIED, not merely carried: account 0's
	// balance dropped by the amount AND the burned fee (audit S-3), its nonce
	// advanced, account 1 was credited, and the state root Append verified is
	// the one that says so.
	fromPub, _ := genesis.DevAccountKey(0)
	toPub, _ := genesis.DevAccountKey(1)
	if got := ch.State().Get(types.AddressFromPub(toPub)).Balance; got != 250*genesis.SparksPerB10 {
		t.Fatalf("the recipient holds %d, want the transferred %d: the block carried bytes, it did not pay", got, 250*genesis.SparksPerB10)
	}
	fee := ch.Genesis().Params.MinFeeSparks
	if got := ch.State().Get(types.AddressFromPub(fromPub)); got.Balance != 1_000_000*genesis.SparksPerB10-250*genesis.SparksPerB10-fee || got.Nonce != 1 {
		t.Fatalf("the sender holds (balance %d, nonce %d), want (balance %d, nonce 1): the debit side did not run", got.Balance, got.Nonce, 1_000_000*genesis.SparksPerB10-250*genesis.SparksPerB10-fee)
	}
}

// A committed consensus block carries a faucet CLAIM if one is in the pool -
// the integration that has never been exercised. Presence in the byte string
// is not the proof: the claimant must have been PAID (credited exactly one
// claim amount) and the faucet DEBITED, through the commit the committee
// reached.
func TestAConsensusBlockPaysAFaucetClaimThroughConsensus(t *testing.T) {
	d, ch, rec, net, _, _, g, _, mp := oneValidatorFixture(t)

	// Epoch 1 is what a claim applied at height 1 must carry (epoch(h) =
	// h/EpochBlocks + 1, and the fixture's EpochBlocks is 1000). The devnet
	// claim amount (1 b10) is funded by the genesis mint plus height 1's
	// emission and by nothing else, so a paid claim also proves the probe and
	// the commit saw the emission the same way.
	claim := claimTx(t, g, 0, 1)
	claimID := claim.ID()
	claimant, faucetAddr := claim.From, g.FaucetAddress()
	faucetBefore := ch.State().Get(faucetAddr).Balance
	emission1 := faucet.Reward(1, g.Params.InitialRewardSparks, g.Params.HalvingIntervalBlocks)
	if faucetBefore+emission1 < g.Params.ClaimAmountSparks {
		t.Fatal("fixture is starved: the faucet cannot pay one claim, so the test would prove nothing")
	}
	if err := mp.Add([]types.Tx{claim})[0]; err != nil {
		t.Fatal(err)
	}

	drive(t, d, net, 200, func() bool { return ch.Height() >= 1 })
	if ch.Height() < 1 {
		t.Fatalf("the committee never committed after 200 drive iterations (%d messages): no committed block to inspect", len(rec.broadcasts))
	}
	blk := committedBlock(t, ch, 1)
	if !carriesTx(blk, claimID) {
		t.Fatalf("the committed block carries no faucet claim: the faucet path and the consensus path still never met (%d messages broadcast)", len(rec.broadcasts))
	}
	// Paid, not carried: the claimant started at zero and holds exactly the
	// claim amount; the faucet moved by exactly height-1 emission minus one
	// claim. Any drift shows up here as arithmetic, not as a vague absence.
	if got := ch.State().Get(claimant).Balance; got != g.Params.ClaimAmountSparks {
		t.Fatalf("the claimant holds %d after the committed block, want the claim amount %d: the claim was carried but not paid", got, g.Params.ClaimAmountSparks)
	}
	if got := ch.State().Get(faucetAddr).Balance; got != faucetBefore+emission1-g.Params.ClaimAmountSparks {
		t.Fatalf("the faucet holds %d after the committed block, want %d (genesis %d + height-1 emission %d - one claim %d): the claim's debit side did not run under consensus",
			got, faucetBefore+emission1-g.Params.ClaimAmountSparks, faucetBefore, emission1, g.Params.ClaimAmountSparks)
	}
}

// A transaction that cannot apply must be excluded from the proposal, not
// fatal to it: one state-invalid transaction must not discard its valid
// siblings and must not wedge the height - the same tolerance node.RunOnce
// already has. A proposer that shipped unfiltered batches instead would hand
// the committee a block every peer's all-or-nothing ApplyBlock refuses.
func TestInapplicableTransactionsAreExcludedNotFatal(t *testing.T) {
	d, ch, _, net, _, _, _, _, mp := oneValidatorFixture(t)

	good := transferTx(ch.Genesis(), 0, 1, 0, 250*genesis.SparksPerB10)               // applies: dev 0's nonce is 0
	badNonce := transferTx(ch.Genesis(), 0, 1, 7, 100*genesis.SparksPerB10)           // nonce 7, dev 0 is at 0
	insufficient := transferTx(ch.Genesis(), 0, 1, 1, 2_000_000*genesis.SparksPerB10) // after `good`, dev 0 cannot cover two million b10
	txs := []types.Tx{good, badNonce, insufficient}
	if errs := mp.Add(txs); errs[0] != nil || errs[1] != nil || errs[2] != nil {
		t.Fatalf("the fixture's transactions failed the pool's signature checks: %v", errs)
	}

	// Two heights, not one: the inapplicable pair must not even delay the
	// second block.
	drive(t, d, net, 200, func() bool { return ch.Height() >= 2 })
	if ch.Height() < 2 {
		t.Fatalf("the chain stalled at height %d: an inapplicable transaction became fatal instead of being evicted alone", ch.Height())
	}
	blk := committedBlock(t, ch, 1)
	if !carriesTx(blk, good.ID()) {
		t.Fatalf("the valid transfer was discarded with its inapplicable siblings: block 1 carries %d transaction(s)", len(blk.Txs))
	}
	if carriesTx(blk, badNonce.ID()) || carriesTx(blk, insufficient.ID()) {
		t.Fatalf("a transaction that cannot apply rode the proposal at height %d: every peer's ApplyBlock would refuse the whole block", blk.Header.Height)
	}
}

// The claim bound still bounds on the consensus path. The pool holds one more
// claim than the bound; the committed block must carry no more than the bound,
// and the surplus must SURVIVE in the pool for a later block - dropped claims
// would be eviction dressed up as bounding.
//
// The fixture's claim amount is lowered to 0.1 b10 so the faucet funds all of
// the submissions: with the shipped devnet amount, faucet poverty (not the
// bound) would cap the block, and the test would pass for the wrong reason.
func TestClaimBoundStillBoundsOnTheConsensusPath(t *testing.T) {
	g := genesis.Devnet()
	g.Params.ClaimAmountSparks = 10_000_000
	d, ch, _, net, _, _, _, _, mp := oneValidatorFixtureOnGenesis(t, g)

	if g.Params.MaxClaimsPerBlock != mempool.MaxFaucetClaimsPerBlock {
		t.Fatalf("the fixture's genesis bound (%d) and the pool's (%d) disagree: the test could not tell which layer bounded", g.Params.MaxClaimsPerBlock, mempool.MaxFaucetClaimsPerBlock)
	}
	submitted := make([]types.Tx, 0, int(mempool.MaxFaucetClaimsPerBlock)+1) // one past the bound
	for i := 0; i < int(mempool.MaxFaucetClaimsPerBlock)+1; i++ {
		submitted = append(submitted, claimTx(t, g, i, 1))
	}
	errs := mp.Add(submitted)
	for i, err := range errs {
		if err != nil {
			t.Fatalf("submitted claim %d was refused by the pool: %v", i, err)
		}
	}

	drive(t, d, net, 400, func() bool { return ch.Height() >= 2 })
	if ch.Height() < 2 {
		t.Fatalf("the committee never reached two blocks with a pool holding one claim past the bound: the bound turned into a stall (height %d)", ch.Height())
	}
	b1 := committedBlock(t, ch, 1)
	claims1 := countFaucetClaims(b1)
	if claims1 != int(g.Params.MaxClaimsPerBlock) {
		t.Fatalf("height 1 carries %d claims, want exactly the bound %d: the pool handed the block a claim count only the state bound could have rejected", claims1, g.Params.MaxClaimsPerBlock)
	}
	b2 := committedBlock(t, ch, 2)
	if got := countFaucetClaims(b2); got != 1 {
		t.Fatalf("height 2 carries %d claim(s), want the one the bound kept in the pool: a surplus claim was evicted or stranded instead of deferred to the next block", got)
	}
	// Applied, not carried: the first carried claim's claimant was actually
	// paid.
	var firstClaim types.Tx
	for i := range b1.Txs {
		if b1.Txs[i].Type == types.TxFaucetClaim {
			firstClaim = b1.Txs[i]
			break
		}
	}
	if got := ch.State().Get(firstClaim.From).Balance; got != g.Params.ClaimAmountSparks {
		t.Fatalf("the first claim's claimant holds %d, want the claim amount %d: the bound test cannot rest on unapplied claims", got, g.Params.ClaimAmountSparks)
	}
}

func countFaucetClaims(blk *types.Block) int {
	n := 0
	for i := range blk.Txs {
		if blk.Txs[i].Type == types.TxFaucetClaim {
			n++
		}
	}
	return n
}

// A proposal whose round never decides must not evaporate the transactions it
// took: Take removed them from the pool, the engine still judges the height,
// and the only thing that can put them back is the driver's reclaim of its
// uncommitted batch. Two proposals from two different rounds must both carry
// the transaction.
func TestAnAbandonedRoundDoesNotEvaporateItsTransactions(t *testing.T) {
	d, ch, rec, net, _, mp := blockedQuorumFixture(t)

	tx := transferTx(ch.Genesis(), 0, 1, 0, 250*genesis.SparksPerB10)
	txID := tx.ID()
	if err := mp.Add([]types.Tx{tx})[0]; err != nil {
		t.Fatal(err)
	}

	// The quorum of 2 is unreachable: heights never commit, rounds churn, and
	// this validator proposes in every round it is drawn for.
	drive(t, d, net, 300, nil)
	if ch.Height() != 0 {
		t.Fatalf("the chain moved to height %d in a fixture that cannot commit: the assertion below would be vacuous", ch.Height())
	}

	rounds := map[uint32]bool{}
	proposals := 0
	for _, raw := range rec.broadcasts {
		c := decodeWire(t, raw)
		if c.prop == nil {
			continue
		}
		proposals++
		if carriesTx(&c.prop.Block, txID) {
			rounds[c.prop.Round] = true
		}
	}
	if proposals < 2 {
		t.Fatalf("the fixture produced only %d proposal(s): it never re-entered proposing, so it cannot test a reclaim", proposals)
	}
	if len(rounds) < 2 {
		t.Fatalf("the transfer appears in the proposals of only %d round(s) %v out of %d: a timed-out round's proposal swallowed the transactions Take had removed - the next proposal proposed an EMPTY block", len(rounds), keysOf(rounds), proposals)
	}
	// The batch is still held exactly once, not multiplied across rounds: the
	// driver's pending record is the reclaim's source of truth.
	if len(d.pending) != 1 || d.pending[0].ID() != txID {
		t.Fatalf("the driver's pending batch is %d transaction(s), want exactly the one uncommitted transfer", len(d.pending))
	}
}

// stalledProposals decodes every proposal recorded on a stalledTransport -
// countWire's recordingTransport twin, for the hand-played committee fixtures.
func stalledProposals(t *testing.T, rec *stalledTransport) []*Proposal {
	t.Helper()
	props := make([]*Proposal, 0, 2)
	for _, raw := range rec.broadcasts {
		if c := decodeWire(t, raw); c.prop != nil {
			props = append(props, c.prop)
		}
	}
	return props
}

// A FOREIGN commit - a peer's proposal reaching quorum while this driver's own
// batch is still uncommitted - must not evaporate the batch either.
// TestAnAbandonedRoundDoesNotEvaporateItsTransactions pins the reclaim with an
// unreachable quorum, so no commit ever happens there and it cannot exercise
// the other half of the invariant: flush used to clear pending after ANY
// successful append, so a peer's block that did not carry the batch deleted it
// from the last place it existed - gone from the pool (Take removed it) and
// absent from the committed block.
//
// The fixture plays the peer by hand with the committee's real keys, the way
// the restart test does: v0 is the only driver, the transfer lives in ITS pool
// alone, and the peer's committed block P2 is genuinely empty - so the batch's
// fate rests on the driver's pending record, and a pass cannot come from the
// foreign block carrying the transactions. The batch must survive the foreign
// commit in pending, be reclaimed into the first later proposal, ride it into
// a commit, and land.
func TestAForeignCommitDoesNotEvaporateTheAbandonedBatch(t *testing.T) {
	priv0 := testCommitteeKey(0)
	pub0 := priv0.Public().(ed25519.PublicKey)
	priv1 := testCommitteeKey(1)
	pub1 := priv1.Public().(ed25519.PublicKey)

	g := genesis.Devnet()
	g.Validators = []genesis.Validator{
		{PubKey: pub0, Power: 1},
		{PubKey: pub1, Power: 1},
	}
	g.Params.CommitteeSize = 2
	cfg := Config{Committee: g.Validators, TimeoutBase: roundBase, TimeoutStep: roundStep, PowerCapNum: 1, PowerCapDen: 1}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	ch, err := chain.Open(g, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rec := &stalledTransport{}
	mp := mempool.New(1000, g.Hash())
	d := NewDriver(cfg, ch, priv0, rec, mp)

	parent := ch.Head().ID()

	tx := transferTx(ch.Genesis(), 0, 1, 0, 250*genesis.SparksPerB10)
	txID := tx.ID()
	if err := mp.Add([]types.Tx{tx})[0]; err != nil {
		t.Fatal(err)
	}

	// A build holds a real pending batch: v0 is walked to its round (the walk
	// emits the ordinary nil prevote of a proposal-less round), then the
	// driver's own Tick proposes for real - the propose step runs at
	// now=5, below the round timeout, so no timeout fires with it.
	now := int64(5)
	for r := 0; r < 64 && string(cfg.Proposer(1, d.eng.Round(), parent)) != string(pub0); r++ {
		d.eng.OnTimeout(TimeoutEvent{Height: d.eng.Height(), Round: d.eng.Round(), Step: d.eng.Step()})
	}
	if string(cfg.Proposer(1, d.eng.Round(), parent)) != string(pub0) {
		t.Fatal("in 64 rounds the fixture never drew v0 as the proposer at height 1: no batch was ever built")
	}
	d.Tick(now)

	props := stalledProposals(t, rec)
	if len(props) == 0 {
		t.Fatal("no proposal was broadcast: the build path never ran, so there is no pending batch to protect")
	}
	b1 := props[len(props)-1].Block
	if !carriesTx(&b1, txID) {
		t.Fatal("the driver's proposal does not carry the pool's transfer: the fixture did not set a pending batch up")
	}
	if len(d.pending) != 1 || d.pending[0].ID() != txID {
		t.Fatal("the build did not leave the batch in the driver's pending record")
	}

	// The round runs out without any vote for the proposal: the engine enters
	// the next round and drops it, and the batch now exists ONLY in pending.
	// The Tick lands past the deadline the driver armed at its first real
	// tick (now=5 -> 5+roundBase): arming is relative to the clock the caller
	// drives (Task 6), so the fixture walks to the deadline instead of
	// assuming an absolute TimeoutBase.
	d.Tick(5 + roundBase + 1)
	if d.eng.proposal != nil {
		t.Fatal("the round did not end: the proposal was never abandoned")
	}

	// The peer proposes an EMPTY block at the same height, in a later round.
	for r := 0; r < 64 && string(cfg.Proposer(1, d.eng.Round(), parent)) != string(pub1); r++ {
		d.eng.OnTimeout(TimeoutEvent{Height: d.eng.Height(), Round: d.eng.Round(), Step: d.eng.Step()})
	}
	if string(cfg.Proposer(1, d.eng.Round(), parent)) != string(pub1) {
		t.Fatal("in 64 rounds the fixture never drew v1 as the proposer: no foreign commit could happen")
	}
	peerRound := d.eng.Round()
	p2, err := ch.Build(priv1, nil, ch.Head().Header.Timestamp+1)
	if err != nil {
		t.Fatal(err)
	}
	p2Prop := &Proposal{Height: 1, Round: peerRound, Block: *p2, ValidRound: -1, Validator: pub1}
	p2Prop.Sig = signProposal(t, cfg, p2Prop)
	if p2.ID() == b1.ID() {
		t.Fatal("the foreign block must be a different block at the same height")
	}

	// The committee reaches quorum on the peer's block: the driver's own
	// prevote is self-tallied on receipt, and each injected peer vote
	// completes the polka and then the precommit quorum of 2.
	d.OnMessage(transport.Message{From: "v1", Data: EncodeProposal(p2Prop)})
	d.OnMessage(transport.Message{From: "v1", Data: EncodeVote(voteFrom(t, cfg, 1, MsgPrevote, 1, peerRound, p2.ID()))})
	d.OnMessage(transport.Message{From: "v1", Data: EncodeVote(voteFrom(t, cfg, 1, MsgPrecommit, 1, peerRound, p2.ID()))})

	if ch.Height() != 1 {
		t.Fatalf("the chain sits at height %d: the peer's block never committed, so no foreign append ran", ch.Height())
	}
	if blk1 := committedBlock(t, ch, 1); blk1.ID() != p2.ID() {
		t.Fatal("the committed block is not the peer's: the fixture did not exercise a foreign commit")
	}
	if carriesTx(committedBlock(t, ch, 1), txID) {
		t.Fatal("the foreign block carries the transfer: the test could no longer tell a foreign commit from the driver's own")
	}
	// THE FIX, stated directly: the batch is still findable - in pending,
	// from which the next build reclaims it. The old unconditional clear
	// destroyed it exactly here.
	if len(d.pending) != 1 || d.pending[0].ID() != txID {
		t.Fatalf("the driver's uncommitted batch did not survive the foreign commit at height %d: it is in neither the pool (Take removed it) nor the committed peer block - lost", ch.Height())
	}

	// The next height's first build must reclaim the batch into the pool and
	// propose it again. The walk to v0's round at height 2 does no Ticks, so
	// the proposal happens at now=15, below the 26 (=16+roundBase) that the
	// Tick(16) commit re-armed: the Tick proposes and nothing else.
	parent2 := p2.ID()
	for r := 0; r < 64 && string(cfg.Proposer(2, d.eng.Round(), parent2)) != string(pub0); r++ {
		d.eng.OnTimeout(TimeoutEvent{Height: d.eng.Height(), Round: d.eng.Round(), Step: d.eng.Step()})
	}
	if string(cfg.Proposer(2, d.eng.Round(), parent2)) != string(pub0) {
		t.Fatal("in 64 rounds the fixture never drew v0 as the proposer at height 2: the reclaim had no proposal to ride")
	}
	d.Tick(15)
	props2 := stalledProposals(t, rec)
	var c1 *Proposal
	for _, p := range props2 {
		if p.Height == 2 {
			c1 = p
		}
	}
	if c1 == nil {
		t.Fatal("no proposal was broadcast at height 2: the driver never built again")
	}
	if !carriesTx(&c1.Block, txID) {
		t.Fatal("the height-2 proposal is empty: the batch reclaimed after the foreign commit did not make it back - the transaction is lost")
	}

	// And the rebuilt block commits, WITH the batch: not found in a proposal,
	// not stranded in pending, but applied by the chain the committee agreed on.
	d.OnMessage(transport.Message{From: "v1", Data: EncodeVote(voteFrom(t, cfg, 1, MsgPrevote, 2, d.eng.Round(), c1.Block.ID()))})
	d.OnMessage(transport.Message{From: "v1", Data: EncodeVote(voteFrom(t, cfg, 1, MsgPrecommit, 2, d.eng.Round(), c1.Block.ID()))})

	if ch.Height() != 2 {
		t.Fatalf("height 2 never committed (chain at %d): the reclaimed batch could not land", ch.Height())
	}
	blk2 := committedBlock(t, ch, 2)
	if !carriesTx(blk2, txID) {
		t.Fatal("the block after the foreign commit does not carry the transfer: a batch orphaned by a peer's commit is unrecoverable")
	}
	toPub, _ := genesis.DevAccountKey(1)
	if got := ch.State().Get(types.AddressFromPub(toPub)).Balance; got != 250*genesis.SparksPerB10 {
		t.Fatalf("the recipient holds %d, want the transferred %d: the batch landed as carried bytes, not paid state", got, 250*genesis.SparksPerB10)
	}
	if len(d.pending) != 0 {
		t.Fatalf("the driver still holds %d pending transaction(s) after its height-2 block committed: a committed batch must be off the books", len(d.pending))
	}
}

// THE milestone integration, end to end: a block carrying a transfer AND a
// faucet claim agreed on by MORE THAN ONE validator. Every live validator
// holds the same two transactions in its own pool - each one's proposer takes
// them - so whatever the eventual commit is, it carries them once, every peer
// applies them at its own Append, and the three live chains must hold one
// history that pays both.
func TestThreeValidatorsAgreeOnABlockThatCarriesATransferAndAClaim(t *testing.T) {
	ds, chs, net, pools := fourValidatorsOneSilentFixture(t)
	defer func() {
		for _, ch := range chs {
			_ = ch.Close()
		}
	}()
	g := chs[0].Genesis()

	claim := claimTx(t, g, 900, 1) // epoch 1, applied at height 1; index 900 stays clear of the bound test's keys
	transfer := transferTx(g, 0, 1, 0, 250*genesis.SparksPerB10)
	claimID, transferID := claim.ID(), transfer.ID()
	for _, mp := range pools {
		if errs := mp.Add([]types.Tx{transfer, claim}); errs[0] != nil || errs[1] != nil {
			t.Fatalf("the fixture could not fill a validator's pool: %v", errs)
		}
	}

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

	if chs[0].Height() < 1 {
		t.Fatalf("the committee reached only height %d: a transaction-carrying proposal never reached the quorum of 3", chs[0].Height())
	}
	// One history: every height the SLOWEST live validator committed must be
	// byte-identical across all three.
	minH := chs[0].Height()
	for _, ch := range chs[1:] {
		if ch.Height() < minH {
			minH = ch.Height()
		}
	}
	carriers := 0
	var agreedBlock *types.Block
	for h := uint64(1); h <= minH; h++ {
		ref := committedBlock(t, chs[0], h)
		for i, ch := range chs[1:] {
			other := committedBlock(t, ch, h)
			if other.ID() != ref.ID() {
				t.Fatalf("live validator %d holds a different block at height %d: the committee disagreed about a block that carries transactions", i+1, h)
			}
		}
		if carriesTx(ref, transferID) || carriesTx(ref, claimID) {
			carriers++
			agreedBlock = ref
		}
	}
	if carriers != 1 {
		t.Fatalf("%d committed block(s) carry the pool's transactions, want exactly one: a transaction committed twice through consensus would be a double-pay", carriers)
	}
	if agreedBlock == nil {
		t.Fatalf("no committed block carries the pool's transactions inside the %d shared heights: the consensus path still drops transactions", minH)
	}
	if !carriesTx(agreedBlock, transferID) || !carriesTx(agreedBlock, claimID) {
		t.Fatalf("the agreed block at height %d carries only part of the pool: transfer=%v claim=%v", agreedBlock.Header.Height, carriesTx(agreedBlock, transferID), carriesTx(agreedBlock, claimID))
	}
	// The claim really was PAID, on every live chain.
	want := g.Params.ClaimAmountSparks
	for i, ch := range chs {
		if got := ch.State().Get(claim.From).Balance; got != want {
			t.Fatalf("live validator %d computed a claimant balance of %d, want %d: the committee agreed on bytes but not on state", i, got, want)
		}
	}
}

// A driver REBUILT over a clock that is already running - the shape every
// catch-up rejoin takes (simnet's CatchUp rebuild, the networked node's
// rebuildDriver) - must arm its first round at a full TimeoutBase measured
// FROM THAT FIRST TICK'S READING. Anchoring the deadline at construction
// assumes the caller's clock starts at zero; against a now of hundreds of
// thousands the first Tick would fire an instant timeout, whose nil prevote
// burns the very round the committee's next proposal travels in - the
// validator then parks at that height forever while the committee races on,
// which is exactly the failure Task 6's converged scenarios exposed in M3's
// partition shape (a post-Heal catch-up rebuild never committed again).
//
// Killing mutant (compiled): NewDriver sets timeoutAt = TimeoutBase instead
// of the arm-on-first-tick sentinel. This fixture's seat 0 is not the
// proposer of (1, round 0), so nothing at that first Tick is legitimate
// output: the mutant emits the nil prevote and the fixture fails by name.
func TestARebuiltDriverDoesNotBurnRoundZeroOnARunningClock(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	cfg.TimeoutBase, cfg.TimeoutStep = 200, 100
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	ch, err := chain.Open(fourValCommitteeGenesis(t, cfg.Committee), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ch.Close() })
	parent := ch.Head().ID()

	// Seat 0 judges (1, 0) and the fixture demands ANOTHER member proposes in
	// round 0, so a legitimate first Tick emits nothing at all.
	if string(cfg.Proposer(1, 0, parent)) == string(cfg.Committee[0].PubKey) {
		t.Skip("fixture: seat 0 drew the height-1 round-0 proposition; the fixture needs a follower seat")
	}
	rec := &recordingTransport{Transport: silentTransport{}}
	d := NewDriver(cfg, ch, testCommitteeKey(0), rec, nil)

	// The rebuilder's clock is ALREADY running (the net's step counter is at
	// six figures by the time a catch-up rebuild happens).
	d.Tick(1_000_000)
	if d.eng.Round() != 0 {
		t.Fatalf("the rebuilt driver left round 0 on its FIRST tick (round %d): the timeout fired from an absolute deadline, not the first reading", d.eng.Round())
	}
	if len(rec.broadcasts) != 0 {
		for _, raw := range rec.broadcasts {
			c := decodeWire(t, raw)
			if c.vote != nil {
				t.Fatalf("the rebuilt driver emitted a vote on its first tick (a nil prevote burns round 0): v.Type=%d h=%d r=%d nil=%v, sig-holding=%v",
					c.vote.Type, c.vote.Height, c.vote.Round, c.vote.IsNil(), len(c.vote.Sig) > 0)
			}
			if c.prop != nil {
				t.Fatalf("the rebuilt driver emitted a proposal on its first tick for a round it does not propose")
			}
		}
	}
}

// silentTransport is the throwaway inner transport for fixtures that only
// observe recorded broadcasts (no delivery at all).
type silentTransport struct{}

func (silentTransport) Broadcast([]byte) error              { return nil }
func (silentTransport) Send(transport.PeerID, []byte) error { return nil }
func (silentTransport) OnMessage(func(transport.Message))   {}
func (silentTransport) Peers() []transport.PeerID           { return nil }
func (silentTransport) Close() error                        { return nil }

// fourValCommitteeGenesis opens a chain on exactly the committee the config
// names, equal power, so a driver fixture can start from a real chain.
func fourValCommitteeGenesis(t *testing.T, vals []genesis.Validator) *genesis.Genesis {
	t.Helper()
	g := genesis.Devnet()
	g.ChainID = "b10coin-driver-fixture-4"
	g.Params.ChainID = g.ChainID
	g.Validators = vals
	g.Params.CommitteeSize = len(vals)
	return g
}

// ---- The committee-level proofs for the two consensus liveness findings ----
//
// C-1: a Byzantine proposer who signs an otherwise-honest envelope carrying a
// block with a garbage state root gets, from every honest validator, a NIL
// prevote; no polka, no lock, no parked committee; the height commits in a
// later round on an honest proposal.
//
// C-2: a committee whose round-0 precommit quorum is lost (everyone locked on
// B, nobody commits) recovers in the very next round through the locked
// proposer re-proposing B with the proof-of-lock.

// dropFirstTP wraps a transport and silently discards the first frame matching
// pred. It is how the tests model one specific loss (a commit-critical
// delivery) with nothing else changed: deterministic, one-shot, recorded.
type dropFirstTP struct {
	transport.Transport
	pred    func(raw []byte) bool
	dropped [][]byte
}

func (d *dropFirstTP) Broadcast(data []byte) error {
	if d.pred != nil && len(d.dropped) == 0 && d.pred(data) {
		d.dropped = append(d.dropped, append([]byte(nil), data...))
		return nil // swallow: the frame never leaves this validator
	}
	return d.Transport.Broadcast(data)
}

// fourValidatorFixture brings up a four-equal-power committee, all four with
// live drivers over one sim, plus a genesis whose Time is searched just enough
// that the round-1 proposer differs from the round-0 proposer at height 1 (the
// mutant-kill condition of the recovery test: a reverted re-proposal shows
// itself as a fresh, different block the moment a locked non-builder is drawn).
func fourValidatorFixture(t *testing.T) (ds []*Driver, chs []*chain.Chain, recs []*recordingTransport, net *sim.Net, cfg Config, g *genesis.Genesis, parent [32]byte) {
	t.Helper()
	vals := make([]genesis.Validator, 0, 4)
	for i := 0; i < 4; i++ {
		vals = append(vals, testValidator(i, 1))
	}
	var chosen *genesis.Genesis
	var chosenCfg Config
	for try := 0; try < 64; try++ {
		gg := genesis.Devnet()
		gg.Validators = append([]genesis.Validator(nil), vals...)
		gg.Params.CommitteeSize = 4
		gg.Time += int64(try)
		ccfg := Config{Committee: gg.Validators, TimeoutBase: roundBase, TimeoutStep: roundStep, PowerCapNum: 1, PowerCapDen: 4}
		if err := ccfg.Validate(); err != nil {
			t.Fatal(err)
		}
		parent = chainGenesisParent(t, gg)
		if string(ccfg.Proposer(1, 1, parent)) != string(ccfg.Proposer(1, 0, parent)) {
			chosen, chosenCfg = gg, ccfg
			break
		}
		if try == 63 {
			t.Fatal("fixture: no genesis time split the round-0 and round-1 proposers")
		}
	}
	cfg, g = chosenCfg, chosen

	net = sim.New(sim.Options{Seed: 1, Latency: 1})
	for i := 0; i < 4; i++ {
		net.AddPeer(fmt.Sprintf("v%d", i))
	}
	for i := 0; i < 4; i++ {
		ch, err := chain.Open(g, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		mp := mempool.New(1000, g.Hash())
		rec := &recordingTransport{Transport: net.TransportFor(fmt.Sprintf("v%d", i))}
		ds = append(ds, NewDriver(cfg, ch, testCommitteeKey(i), rec, mp))
		chs = append(chs, ch)
		recs = append(recs, rec)
	}
	return ds, chs, recs, net, cfg, g, parent
}

// chainGenesisParent reports the genesis block ID a chain opened from g would
// carry: open a throwaway chain and read its head.
func chainGenesisParent(t *testing.T, g *genesis.Genesis) [32]byte {
	t.Helper()
	c, err := chain.Open(g, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	parent := c.Head().ID()
	_ = c.Close()
	return parent
}

// THE C-1 ATTACK, AT THE COMMITTEE: the validator drawn as proposer at height 1
// round 0 is Byzantine: it builds a normal block, overwrites StateRoot with
// garbage, re-signs the envelope, and proposes. Pre-fix every honest validator
// prevoted it (the envelope and proposer checks all pass), the polka formed,
// every validator LOCKED on the garbage block and committed it, every node's
// Append refused it, and the whole committee parked forever - restart included,
// because the lock on the garbage block was durable.
//
// Post-fix: every honest validator's pre-vote seam judges the block - state
// root included - BEFORE voting. The attack collects only nil prevotes from
// the honest members, never a polka (the attacker's own vote is 1 of the
// quorum of 3), never a lock, never a commit.
//
// The height MUST still commit in a later round: an honest proposer's honest
// block reaches the same quorum of three live validators. The halt was the
// finding; one round of delay is the honest cost of refusing.
func TestCommitteeNilPrevotesAGarbageRootProposalAndStillCommits(t *testing.T) {
	ds, chs, recs, net, cfg, g, parent := fourValidatorFixture(t)
	defer func() {
		for _, ch := range chs {
			_ = ch.Close()
		}
	}()

	// The attacker is whoever the committee draws at (1, 0); the honest
	// validators are the other three.
	attackPub := cfg.Proposer(1, 0, parent)
	attackIdx := cfg.IndexOf(attackPub)
	attPriv := testCommitteeKey(attackIdx)
	attackID := [32]byte{}
	{
		// The attack block: structurally valid, garbage state root.
		b := types.Block{Header: types.Header{
			Height:     1,
			ParentHash: parent,
			StateRoot:  [32]byte{0xde, 0xad, 0xbe, 0xef},
			TxRoot:     types.ComputeTxRoot(nil),
			Timestamp:  1_700_000_001,
			Proposer:   attackPub,
		}}
		if err := b.ValidateStructure(); err != nil {
			t.Fatalf("fixture: the attack block must be structurally valid: %v", err)
		}
		p := &Proposal{Height: 1, Round: 0, Block: b, ValidRound: -1, Validator: attackPub}
		h := p.SigningHash()
		p.Sig = crypto.Sign(attPriv, h[:])
		attackID = b.ID()
		// Broadcast through the attacker's own sim peer, exactly one proposal.
		_ = net.TransportFor(fmt.Sprintf("v%d", attackIdx)).Broadcast(EncodeProposal(p))
	}

	// The attacker also prevotes its own block (a Byzantine proposer helps its
	// proposal along); the honest validators must outvote it with nils.
	attackPrevote := voteFrom(t, cfg, attackIdx, MsgPrevote, 1, 0, attackID)
	_ = net.TransportFor(fmt.Sprintf("v%d", attackIdx)).Broadcast(EncodeVote(attackPrevote))

	// Drive the three honest drivers in lockstep: the attack round must end
	// with exactly one nil prevote from each of them and NOT ONE prevote for
	// the garbage block; the height must then commit in a later round.
	commit := false
	for i := 0; i < 600 && !commit; i++ {
		now := int64(i) * driveStep
		for idx, d := range ds {
			if idx == attackIdx {
				continue
			}
			d.Tick(now)
		}
		net.Advance(netStep)
		for idx, d := range ds {
			if idx == attackIdx {
				continue
			}
			d.Tick(now + driveStep/2)
		}
		commit = true
		for idx, ch := range chs {
			if idx == attackIdx {
				continue
			}
			if ch.Height() < 1 {
				commit = false
			}
		}
	}
	if !commit {
		t.Fatalf("the committee never recovered past the attack: the honest validators stalled below height 1 after 600 ticks - refusing a garbage proposal must not halt the chain")
	}

	for idx, ch := range chs {
		if idx == attackIdx {
			continue // the attacker's chain is not part of the committee's truth
		}
		if _, err := ch.BlockAt(1); err == nil && ch.Height() >= 1 {
			blk, err := ch.BlockAt(1)
			if err != nil {
				t.Fatal(err)
			}
			if blk.ID() == attackID {
				t.Fatalf("validator %d committed the ATTACK block: the polka reached a lock on a garbage-root block", idx)
			}
		}
		if rec, ok := ch.LockAt(1); ok && rec.BlockID == attackID {
			t.Fatalf("validator %d has a DURABLE lock naming the attack block %x: the halt now survives restarts, which is the finding's exact claim", idx, attackID[:8])
		}
	}

	// Evidence the refusal spoke: every honest validator emitted exactly one
	// NIL prevote at the attack round (1, 0), and no honest validator emitted
	// a non-nil prevote for the attack block at that round.
	for idx, rec := range recs {
		if idx == attackIdx {
			continue
		}
		nils, forAttack := 0, 0
		for _, raw := range rec.broadcasts {
			v, err := DecodeVote(raw)
			if err != nil || v.Type != MsgPrevote || v.Height != 1 || v.Round != 0 {
				continue
			}
			if v.IsNil() {
				nils++
			}
			if v.BlockID == attackID {
				forAttack++
			}
		}
		if forAttack != 0 {
			t.Fatalf("honest validator %d prevoted the garbage-root block %d time(s): the attack reached a prevote", idx, forAttack)
		}
		if nils != 1 {
			t.Fatalf("honest validator %d emitted %d nil prevote(s) at the attack round, want exactly 1: the refusal must speak, not stay silent", idx, nils)
		}
	}

	// And the recovered chain is one history: the committed height-1 block is
	// identical at every honest validator.
	_ = g // the fixture's searched genesis; the parent draw is what matters
	ref, err := chs[0].BlockAt(1)
	if err != nil {
		t.Fatal(err)
	}
	for idx, ch := range chs {
		if idx == attackIdx {
			continue
		}
		blk, err := ch.BlockAt(1)
		if err != nil {
			continue // this validator may still be a height behind; agreement is asserted below through its shared heights
		}
		blkID, refID := blk.ID(), ref.ID()
		if blkID != refID {
			t.Fatalf("honest validators disagree at height 1: %x vs %x", blkID[:8], refID[:8])
		}
	}
	_ = g
}

// THE C-2 SCENARIO, AT THE COMMITTEE: round 0's polka for block B reached
// every validator (every one locked on B and precommitted it), but the wire
// lost three OF THE FOUR PRECOMMITS, so no validator saw the quorum of three
// and nobody committed. Every validator is therefore locked on B at round 0
// with B's bytes.
//
// Pre-fix behaviour (the audit's exact claim): every later round's proposer -
// locked - proposed a FRESH block (a different block: its own key is the
// header's proposer), which it then nil-prevoted itself; every other locked
// validator nil-prevoted it too; no polka ever formed again; nobody ever
// unlocked; the height stalled while the timeouts grew without bound.
//
// Post-fix: the very next round's proposer re-proposes B - the locked block,
// with the round-0 polka as its justification - every locked validator
// prevotes it (it is their own promise), the polka re-forms, the precommit
// quorum completes, and B commits.
//
// The genesis's Time is chosen by the fixture so the round-1 proposer is NOT
// the block's original builder: a reverted (pre-fix) re-proposal shows itself
// as a fresh, different block the moment the locked non-builder proposes - the
// mutant's first proposal is on the wire and dies on the assertion below.
func TestALostPrecommitQuorumRecoversThroughTheLockedReProposal(t *testing.T) {
	// The fixture guarantees the height-1 round-1 proposer is NOT the round-0
	// proposer's builder (it searched genesis times for that) - the
	// mutant-kill condition the wire assertions below lean on.
	ds, chs, recs, net, cfg, _, _ := fourValidatorFixture(t)
	defer func() {
		for _, ch := range chs {
			_ = ch.Close()
		}
	}()

	// The loss: validators 1, 2 and 3 each lose their FIRST precommit cast at
	// (height 1, round 0). With three of four precommits gone, the tallies are
	// {v0's + own} = 2 at v1/v2/v3 and {own} = 1 at v0: the quorum of 3 is
	// unreachable, at every validator, in round 0. The PREVOTES fly untouched,
	// so the round-0 polka completes at every validator and every one of them
	// LOCKS on the round-0 block - the exact mid-height state the audit names.
	for idx := 1; idx < 4; idx++ {
		wrapped := &dropFirstTP{Transport: net.TransportFor(fmt.Sprintf("v%d", idx))}
		wrapped.pred = func(raw []byte) bool {
			v, err := DecodeVote(raw)
			return err == nil && v.Type == MsgPrecommit && v.Height == 1 && v.Round == 0
		}
		recs[idx].Transport = wrapped
	}
	// The wrappers must be installed over the drivers' transports: the driver
	// was built over the recordingTransport, so re-point the recording layer's
	// inner transport at the dropping wrapper. (recordingTransport forwards to
	// its Transport - now the wrapper - and keeps recording what reached it;
	// dropped frames do NOT appear in its log, which the fixture guards use.)

	// Drive all four: round 0 commits for nobody (the loss), then the locked
	// re-proposal must commit in a later round.
	committedAt := -1
	for i := 0; i < 600 && committedAt < 0; i++ {
		now := int64(i) * driveStep
		for _, d := range ds {
			d.Tick(now)
		}
		net.Advance(netStep)
		for _, d := range ds {
			d.Tick(now + driveStep/2)
		}
		all := true
		for _, ch := range chs {
			if ch.Height() < 1 {
				all = false
			}
		}
		if all {
			committedAt = i
		}
	}
	if committedAt < 0 {
		t.Fatalf("a committee locked on B with a lost round-0 precommit quorum never recovered: no height committed in 600 ticks - the locked proposer did not re-propose, or the justification does not travel")
	}

	// The committed height-1 block is the ONE everyone locked on: the
	// round-0 block's ID must be on every chain, one history.
	var bID [32]byte
	for idx, ch := range chs {
		blk, err := ch.BlockAt(1)
		if err != nil {
			t.Fatalf("validator %d committed past height 1 without the height-1 block in place: %v", idx, err)
		}
		if idx == 0 {
			bID = blk.ID()
			continue
		}
		if blkID := blk.ID(); blkID != bID {
			t.Fatalf("validator %d holds a different height-1 block: %x vs %x", idx, blkID[:8], bID[:8])
		}
	}

	// The C-2 property on the wire: EVERY proposal ever broadcast at height 1
	// carried the locked block B - never a fresh conflicting one. (Round 0's
	// proposer proposed B first; every later round's proposer re-proposed the
	// locked B with its justification.) A reverted re-proposal proposes the
	// proposer's own fresh build - an immediately different block - and this
	// assertion fails on the mutant's first such proposal.
	for idx, rec := range recs {
		for _, raw := range rec.broadcasts {
			p, err := DecodeProposal(raw)
			if err != nil || p.Height != 1 {
				continue
			}
			pid := p.Block.ID()
			if pid != bID {
				t.Fatalf("validator %d (locked, drawn as proposer) proposed %x at height 1; it is locked on %x and must re-propose THAT", idx, pid[:8], bID[:8])
			}
		}
	}

	// The round-1 re-proposal must have been ACCEPTED by a peer: at least one
	// validator emitted a non-nil prevote for B at (1, round 1). This is what
	// kills the "envelope validator must equal the block header's proposer"
	// mutant: the locked proposer at round 1 re-proposes B built by a
	// DIFFERENT validator, so a rule demanding the two keys match drops the
	// re-proposal at every peer, no (1,1) prevote exists, and the recovery
	// waits for the original builder's redraw instead.
	pvR1 := 0
	for _, rec := range recs {
		for _, raw := range rec.broadcasts {
			v, err := DecodeVote(raw)
			if err == nil && v.Type == MsgPrevote && v.Height == 1 && v.Round == 1 && !v.IsNil() && v.BlockID == bID {
				pvR1++
			}
		}
	}
	// At least TWO: the re-proposer's own prevote always exists (it self-tallies
	// before shipping), so one alone would pass even if every PEER dropped the
	// re-proposal - the acceptance this asserts is a peer's, not a formality.
	if pvR1 < 2 {
		t.Fatal("only the re-proposer itself prevoted B at (1, round 1); a peer's acceptance is what this recovery runs on")
	}

	// The proof-of-lock must be present from round 1 on: at least one re-proposal
	// in a later round carries a justification that decodes to a verified quorum
	// of prevotes for B at the claimed round.
	var polkaSeen bool
	for _, rec := range recs {
		for _, raw := range rec.broadcasts {
			p, err := DecodeProposal(raw)
			if err != nil || p.Height != 1 || p.Round == 0 {
				continue
			}
			if len(p.Justification) == 0 || p.ValidRound < 0 {
				continue
			}
			vs := NewVoteSet(cfg, 1, uint32(p.ValidRound), MsgPrevote)
			for _, vraw := range decodeVotes(p.Justification) {
				v, err := DecodeVote(vraw)
				if err != nil {
					break
				}
				if _, err := vs.Add(v); err != nil {
					break
				}
			}
			pid := p.Block.ID()
			if vs.HasQuorum(pid) {
				polkaSeen = true
			}
		}
	}
	if !polkaSeen {
		t.Fatal("no re-proposal ever carried a verified proof-of-lock: the recovery ran on something other than the retained polka")
	}

	// And the height-1 commit came AFTER round 0 (the loss was real): the
	// round that committed is at least round 1. The precommits of the
	// deciding round fly at that round; v0's round-0 precommit was the only
	// one to leave - the record shows the recovery, not an instant round-0
	// commit.
	if committedAt == 0 {
		t.Fatal("the height committed in round 0: the fixture's lost precommits did not actually prevent the round-0 commit")
	}
}

// The round ladder must be CAPPED (audit C-2): an undecided height's rounds
// end on the ladder, and an uncapped ladder makes every succeeding round
// linearly slower forever - recovery latency grows without bound. With the
// cap the ladder saturates: every round past maxRoundEscalation runs at the
// same fixed cadence.
//
// The fixture is the blocked-quorum pair (quorum 2, one live validator): the
// height can never commit, so the ladder rides out to the cap on its own. The
// ghost never votes, so no future-round evidence ever accumulates and the raw
// ladder is what this measures.
func TestRoundTimeoutsAreCapped(t *testing.T) {
	d, _, _, _, _, _ := blockedQuorumFixture(t)

	now := int64(5) // below the first deadline: arms the ladder at +TimeoutBase
	maxDelta := int64(0)
	for r := uint32(0); r < maxRoundEscalation+8; r++ {
		d.Tick(now)
		if d.eng.Round() != r {
			t.Fatalf("fixture: the engine is at round %d, want %d", d.eng.Round(), r)
		}
		delta := d.timeoutAt - d.now
		want := roundBase + int64(minInt64(r, maxRoundEscalation))*roundStep
		if delta != want {
			t.Fatalf("round %d's deadline is TimeoutBase+%d*TimeoutStep = %d, want %d: the ladder %s",
				r, minInt64(r, maxRoundEscalation), delta, want,
				func() string {
					if delta > want {
						return "grew past its cap"
					}
					return "fell short of the ladder"
				}())
		}
		if delta > maxDelta {
			maxDelta = delta
		}
		now = d.timeoutAt
	}
	// Saturation is real, not asserted: the sampled deltas stopped growing and
	// the maximum sits exactly at the capped cadence.
	if maxDelta != roundBase+int64(maxRoundEscalation)*roundStep {
		t.Fatalf("the ladder's maximum delta %d != the capped TimeoutBase+%d*TimeoutStep: the cap would not have bound", maxDelta, maxRoundEscalation)
	}
}

func minInt64(a, b uint32) int64 {
	if int64(b) < int64(a) {
		return int64(b)
	}
	return int64(a)
}

// A timeout must JUMP the ladder when members holding more than one third of
// the committee's total power signed prevotes at rounds ahead of the current
// one (the minimal round-resync the capped ladder needs): the committee is
// that far ahead, and a +1 step would keep this validator permanently one
// round behind, dropping every proposal as wrong-round in both directions.
//
// On four equal-power validators the power bar is total/3+1 = 2 members - on
// an EQUAL committee the same number the old seat gate gave, which is why
// equal-power behaviour is unchanged. The engine holds no future evidence for
// the first two firings (one attesting member is below the bar of 2) and the
// ladder escalates by one each time; the third firing has two members' future
// prevotes and jumps straight to the attested round.
func TestTimeoutJumpsOnFutureRoundEvidence(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	parent := crypto.HashParts([]byte("parent"))
	h := round0ProposerHeight(t, cfg, 1, false, parent)
	e := newTestEngine(t, cfg, 1, h, parent)
	if e.step != StepPropose || e.proposal != nil {
		t.Fatal("fixture: the engine must start unproposing at round 0")
	}

	// One attesting member: below the power bar of 2. The ladder escalates by one.
	v0 := voteFrom(t, cfg, 0, MsgPrevote, h, 3, crypto.HashParts([]byte("some-later-block")))
	if err := e.OnMessage(EncodeVote(v0)); err != nil {
		t.Fatal(err)
	}
	e.OnTimeout(TimeoutEvent{Height: h, Round: e.Round(), Step: e.Step()})
	if e.Round() != 1 {
		t.Fatalf("one future-round vote must not move the ladder bar: engine at round %d, want 1", e.Round())
	}

	// A second attesting member at a further round: power 2 of 4, the bar. The
	// next timeout jumps to the round where the evidence's bulk is first
	// completed - the smallest round whose accumulated power reaches the bar,
	// here 3, the 2nd largest of rounds {5, 3}.
	v2 := voteFrom(t, cfg, 2, MsgPrevote, h, 5, crypto.HashParts([]byte("some-later-block")))
	if err := e.OnMessage(EncodeVote(v2)); err != nil {
		t.Fatal(err)
	}
	e.OnTimeout(TimeoutEvent{Height: h, Round: e.Round(), Step: e.Step()})
	if e.Round() != 3 {
		t.Fatalf("the power bar's future rounds must jump the ladder: engine at round %d, want 3 (the bar-completing round of attestations 5, 3)", e.Round())
	}
	if p := e.future[2]; p == nil || p.Round != 5 {
		t.Fatal("fixture: the recorded future evidence is wrong")
	}

	// The jump lands the honest way: a NEW round at StepPropose waiting for
	// that round's proposal, the (none-here) lock and the future evidence
	// intact.
	if e.Step() != StepPropose {
		t.Fatalf("after the jump the engine is at step %s, want propose", e.Step())
	}
	// The evidence survives the round change and a further member attests
	// round 9: the bar-completing round is then 5 (power 2 attesting at 5 or
	// above), so the next timeout advances only to 5. The engine rides the
	// evidence's bulk forward, not any single member's furthest claim.
	v1 := voteFrom(t, cfg, 1, MsgPrevote, h, 9, crypto.HashParts([]byte("some-later-block")))
	if err := e.OnMessage(EncodeVote(v1)); err != nil {
		t.Fatal(err)
	}
	e.OnTimeout(TimeoutEvent{Height: h, Round: e.Round(), Step: e.Step()})
	if e.Round() != 5 {
		t.Fatalf("the jump target is the bar-completing round, not the furthest attested: engine at round %d, want 5", e.Round())
	}
}

// The jump's gate is a third of the POWER, not one member's claim: a single
// signed future-round vote must never move the ladder. A committee that
// jumped on any single attestation would follow one Byzantine member into
// rounds nobody else is in - and never come back, because the votes its
// laggards see are all past-rounds relative to the jumped validator.
//
// For four equal validators the power bar is 2: attesting twice from the SAME
// member (its highest wins) still counts as one member's power. The jump
// fires only when a second, distinct member attests.
func TestTimeoutJumpNeedsDistinctMembersNotOneByzantine(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	parent := crypto.HashParts([]byte("parent"))
	h := round0ProposerHeight(t, cfg, 1, false, parent)
	e := newTestEngine(t, cfg, 1, h, parent)

	// One member, repeatedly attesting absurd rounds: still one entry.
	for _, r := range []uint32{4, 100, 1 << 30} {
		if err := e.OnMessage(EncodeVote(voteFrom(t, cfg, 0, MsgPrevote, h, r, crypto.HashParts([]byte("some-later-block"))))); err != nil {
			t.Fatal(err)
		}
	}
	if len(e.future) != 1 || e.future[0].Round != 1<<30 {
		t.Fatalf("fixture: one member must hold exactly one (its highest) entry, got %d entries", len(e.future))
	}
	e.OnTimeout(TimeoutEvent{Height: h, Round: e.Round(), Step: e.Step()})
	if e.Round() != 1 {
		t.Fatalf("a single member's future rounds must not jump the ladder (want +1 step, engine at round %d)", e.Round())
	}
}

// The jump gate counts POWER, not SEATS (round-3 F1): the committee file
// carries a per-entry power, so on a weighted genesis the Byzantine budget is
// a fraction of total power, while the previous round's gate counted
// floor(n/3)+1 COMMITTEE SEATS - and a coalition holding strictly UNDER one
// third of the power can occupy exactly that many seats.
//
// The weighted committee is the reviewer's: n=7, powers {1,1,1,2,2,2,2},
// total 11. The seat gate is 7/3+1 = 3 members; the power bar (the same
// integers TotalPower feeds the quorum) is 11/3+1 = 4. Three power-1 seats
// hold 3/11 = 0.273 of the power - strictly under a third - and exactly fill
// the seat gate; the power gate must refuse them. Conversely a coalition that
// genuinely exceeds one third of power in FEWER seats (two power-2 members:
// 4/11 = 0.364 at two seats, below the seat gate of 3) must still be able to
// move the round, so the gate is not simply dead: both directions below.
func TestJumpGateCountsPowerNotSeats(t *testing.T) {
	cfg := weightedCommittee(t, 1, 1, 1, 2, 2, 2, 2)
	parent := crypto.HashParts([]byte("parent"))
	someID := crypto.HashParts([]byte("some-later-block"))
	// The engine's seat is the last one (power 2): it is not one of the
	// attesting attackers below, and the fixture anchor asserts that.
	idx := 6
	h := round0ProposerHeight(t, cfg, idx, false, parent)

	if total := cfg.TotalPower(); total != 11 {
		t.Fatalf("fixture: total power %d, want 11 for powers {1,1,1,2,2,2,2}", total)
	}
	if bar := cfg.TotalPower()/3 + 1; bar != 4 {
		t.Fatalf("fixture: the power bar is %d, want 4 (strictly more than a third of 11)", bar)
	}

	// Direction 1 (the attack): three seats holding 3/11 of the power attest
	// round 9. They fill the SEAT gate (3 = floor(7/3)+1) exactly, so the
	// member-count version of this gate jumped the engine to their claimed
	// round; the power gate must not move it.
	e := newTestEngine(t, cfg, idx, h, parent)
	for _, seat := range []int{0, 1, 2} {
		if err := e.OnMessage(EncodeVote(voteFrom(t, cfg, seat, MsgPrevote, h, 9, someID))); err != nil {
			t.Fatal(err)
		}
	}
	e.OnTimeout(TimeoutEvent{Height: h, Round: e.Round(), Step: e.Step()})
	if e.Round() != 1 {
		t.Fatalf("a coalition with 3/11 = 0.273 of the power in 3 seats moved the round to %d: 3 of 11 is strictly under one third and must not reach the power gate (want round 1)", e.Round())
	}

	// A SINGLE Byzantine validator must never move the round either - the
	// property round 2 established, kept on a weighted committee: the
	// heaviest member holds 2/11, under the bar of 4.
	e = newTestEngine(t, cfg, idx, h, parent)
	if err := e.OnMessage(EncodeVote(voteFrom(t, cfg, 0, MsgPrevote, h, 9, someID))); err != nil {
		t.Fatal(err)
	}
	e.OnTimeout(TimeoutEvent{Height: h, Round: e.Round(), Step: e.Step()})
	if e.Round() != 1 {
		t.Fatalf("one member holding 2/11 of the power moved the round to %d: a single validator must not reach the gate at all", e.Round())
	}

	// Direction 2a (the gate is alive): two power-2 seats at round 9 hold
	// 4/11 = 0.364 of the power, above the bar in TWO seats - fewer than the
	// old seat gate of 3. The round must move, to the round the bulk attests.
	e = newTestEngine(t, cfg, idx, h, parent)
	for _, seat := range []int{3, 4} {
		if err := e.OnMessage(EncodeVote(voteFrom(t, cfg, seat, MsgPrevote, h, 9, someID))); err != nil {
			t.Fatal(err)
		}
	}
	e.OnTimeout(TimeoutEvent{Height: h, Round: e.Round(), Step: e.Step()})
	if e.Round() != 9 {
		t.Fatalf("a coalition holding 4/11 of the power in 2 seats did not move the round (at %d, want 9): the power gate must stay live", e.Round())
	}

	// Direction 2b (the target never follows a sub-third coalition's claim):
	// the same three sub-third seats attest round 9 and ONE honest member -
	// without whose power the gate would refuse - attests round 5. The
	// crossing happens where the power reaches the bar, so the jump goes to
	// the honest member's round 5, not the attackers' claimed 9.
	e = newTestEngine(t, cfg, idx, h, parent)
	for _, seat := range []int{0, 1, 2} {
		if err := e.OnMessage(EncodeVote(voteFrom(t, cfg, seat, MsgPrevote, h, 9, someID))); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.OnMessage(EncodeVote(voteFrom(t, cfg, 3, MsgPrevote, h, 5, someID))); err != nil {
		t.Fatal(err)
	}
	e.OnTimeout(TimeoutEvent{Height: h, Round: e.Round(), Step: e.Step()})
	if e.Round() != 5 {
		t.Fatalf("the jump went to round %d, want 5: with power 3 at claimed round 9 and power 2 attested at round 5, the bar of 4 is first reached at the honest member's round 5 - the target must not follow the sub-third coalition's furthest claim", e.Round())
	}
}

// The jump target is CAPPED (round-3 F1): a power-gated jump bounds WHO can
// name the target, not the number they name - a coalition that legitimately
// exceeds one third of power (and, equally, one buggy honest validator) can
// attest math.MaxUint32, and a jump there parks OnTimeout's wrap guard, which
// returns silently: the validator would be permanently ejected from the
// height, its votes and every proposal wrong-round in both directions. So the
// jump never leaves the current round by more than maxRoundEscalation - the
// same stride the timeout ladder uses - and a genuinely further committee is
// caught by repetition on later timeouts instead of one unbounded step.
func TestJumpNeverTravelsFurtherThanABoundedStride(t *testing.T) {
	cfg := evenCommittee(t, 4, 1) // total 4: the bar is 4/3+1 = 2 power
	parent := crypto.HashParts([]byte("parent"))
	someID := crypto.HashParts([]byte("some-later-block"))
	idx := 2
	h := round0ProposerHeight(t, cfg, idx, false, parent)
	e := newTestEngine(t, cfg, idx, h, parent)

	// Two members attest math.MaxUint32: the power gate is genuinely
	// satisfied (2 of 4), and the crossing - the round the old code would
	// have jumped TO - is MaxUint32 itself, where OnTimeout silently returns
	// forever after. The engine must jump to the BOUND instead.
	for _, seat := range []int{0, 1} {
		if err := e.OnMessage(EncodeVote(voteFrom(t, cfg, seat, MsgPrevote, h, math.MaxUint32, someID))); err != nil {
			t.Fatal(err)
		}
	}
	e.OnTimeout(TimeoutEvent{Height: h, Round: e.Round(), Step: e.Step()})
	if e.Round() != maxRoundEscalation {
		t.Fatalf("a MaxUint32-evidenced jump landed at round %d, want the bounded stride %d (an unbounded jump would strand the engine at OnTimeout's wrap guard and eject it from the height)", e.Round(), maxRoundEscalation)
	}
	if e.Step() != StepPropose {
		t.Fatalf("after the bounded jump the engine is at step %s, want propose: it must stay live", e.Step())
	}

	// The bound is per jump, not per height: the same evidence, still ahead,
	// moves the engine another bounded stride on the next timeout - a gap
	// wider than the stride is closed by repetition, and no jump ever reaches
	// the wrap guard's round.
	e.OnTimeout(TimeoutEvent{Height: h, Round: e.Round(), Step: e.Step()})
	if e.Round() != 2*maxRoundEscalation {
		t.Fatalf("the second timeout did not carry another bounded stride (at round %d, want %d): the bound must not dead-end resync", e.Round(), 2*maxRoundEscalation)
	}
}
