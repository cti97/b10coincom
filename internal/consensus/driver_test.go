package consensus

import (
	"crypto/ed25519"
	"fmt"
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
	mp = mempool.New(1000)
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
	mp = mempool.New(1000)
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
// advancing or corrupting state. The engine cannot validate a block's state
// root (it holds no state by design), so the realistic way a commit fails is
// exactly this: a block the engine accepted that the chain refuses. The driver
// must not swap in a new engine for the next height - the height is not
// decided for THIS node, and silently moving on would diverge it from every
// peer that did accept the block.
func TestDriverRejectedAppendStaysAtSameHeight(t *testing.T) {
	d, ch, _, net, pub, priv, _, _, _ := oneValidatorFixture(t)

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
		pool := mempool.New(1000)
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
func transferTx(from, to int, nonce, amount uint64) types.Tx {
	fromPub, fromPriv := genesis.DevAccountKey(from)
	toPub, _ := genesis.DevAccountKey(to)
	tx := &types.Tx{
		Type:   types.TxTransfer,
		From:   types.AddressFromPub(fromPub),
		PubKey: fromPub,
		Nonce:  nonce,
		To:     types.AddressFromPub(toPub),
		Amount: amount,
	}
	sig := tx.SigningHash()
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
	sig := tx.SigningHash()
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

	tx := transferTx(0, 1, 0, 250*genesis.SparksPerB10)
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
	// balance dropped by the amount and its nonce advanced, account 1 was
	// credited, and the state root Append verified is the one that says so.
	fromPub, _ := genesis.DevAccountKey(0)
	toPub, _ := genesis.DevAccountKey(1)
	if got := ch.State().Get(types.AddressFromPub(toPub)).Balance; got != 250*genesis.SparksPerB10 {
		t.Fatalf("the recipient holds %d, want the transferred %d: the block carried bytes, it did not pay", got, 250*genesis.SparksPerB10)
	}
	if got := ch.State().Get(types.AddressFromPub(fromPub)); got.Balance != 1_000_000*genesis.SparksPerB10-250*genesis.SparksPerB10 || got.Nonce != 1 {
		t.Fatalf("the sender holds (balance %d, nonce %d), want (balance %d, nonce 1): the debit side did not run", got.Balance, got.Nonce, 1_000_000*genesis.SparksPerB10-250*genesis.SparksPerB10)
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

	good := transferTx(0, 1, 0, 250*genesis.SparksPerB10)               // applies: dev 0's nonce is 0
	badNonce := transferTx(0, 1, 7, 100*genesis.SparksPerB10)           // nonce 7, dev 0 is at 0
	insufficient := transferTx(0, 1, 1, 2_000_000*genesis.SparksPerB10) // after `good`, dev 0 cannot cover two million b10
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

	tx := transferTx(0, 1, 0, 250*genesis.SparksPerB10)
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
	mp := mempool.New(1000)
	d := NewDriver(cfg, ch, priv0, rec, mp)

	parent := ch.Head().ID()

	tx := transferTx(0, 1, 0, 250*genesis.SparksPerB10)
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
	transfer := transferTx(0, 1, 0, 250*genesis.SparksPerB10)
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
