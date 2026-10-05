package consensus

// The BLOCK_SYNC tests run against the REAL sim transport - not a test double
// that delivers inside Send. Neither shipped transport delivers synchronously
// (sim and tcp both enqueue, per their own no-synchronous-delivery contract),
// so a double that calls Receive from within Send structurally cannot see the
// requester's real problem: the answer arrives LATER, while the pull waits.
// The rig below drives the genuine sim.Net: Send enqueues, a pump goroutine
// owns the network and advances it, deliveries happen inside Advance and
// nowhere else, and the puller's requests are answered by honest server
// syncers (or a hostile route) exactly the way the node's connection loop will
// wire it.
//
// Under the -race detector the two-goroutine shape is also what keeps the run
// honest: the sim net is touched by the pump only; chains are mutex-guarded;
// the pull blocks on the reply channel until the network actually delivers.

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/transport"
	"github.com/cti97/b10coincom/internal/transport/sim"
	"github.com/cti97/b10coincom/internal/types"
	"github.com/cti97/b10coincom/internal/wire"
)

const (
	syncPullerID = "v3" // the behind validator: a committee member that fell behind
	syncServerID = "v0" // the ahead validator: serves
)

// ---------------------------------------------------------------- the rig

// syncNet owns a real sim.Net and the pump goroutine that advances it. Every
// sim access outside drive-phase setup happens on the pump; the simnet
// contract (single-threaded network, delivery only on Advance) is preserved
// exactly, just on a goroutine that is not the test's.
type syncNet struct {
	t   *testing.T
	net *sim.Net
	// mu serializes every sim access: the pump holds it around Advance (and
	// around each command), and the test-goroutine syncers send through
	// pumpBound, which takes it. The sim's own single-threaded contract is
	// thus preserved when a requester waits on another goroutine - exactly
	// what a real transport's reader loop does.
	mu   sync.Mutex
	eps  map[string]transport.Transport
	cmds chan func()
	stop chan struct{}
	done chan struct{}
}

func newSyncNet(t *testing.T, seed int64, latencyMS, jitterMS int64) *syncNet {
	r := &syncNet{t: t, eps: map[string]transport.Transport{}}
	r.net = sim.New(sim.Options{
		Seed:    seed,
		Latency: time.Duration(latencyMS) * time.Millisecond,
		Jitter:  time.Duration(jitterMS) * time.Millisecond,
	})
	r.cmds = make(chan func(), 64)
	return r
}

func (r *syncNet) addPeer(id string) transport.Transport {
	r.net.AddPeer(id)
	r.eps[id] = r.net.TransportFor(id)
	return r.eps[id]
}

// start hands the net to the pump: from here, only the pump goroutine touches
// it. halt reverses it.
func (r *syncNet) start() {
	r.stop = make(chan struct{})
	r.done = make(chan struct{})
	go func() {
		defer close(r.done)
		for {
			select {
			case <-r.stop:
				return
			case fn := <-r.cmds:
				r.mu.Lock()
				fn() // commands run serialized with the deliveries
				r.mu.Unlock()
				continue
			default:
			}
			r.mu.Lock()
			r.net.Advance(2 * time.Millisecond)
			r.mu.Unlock()
		}
	}()
}

// halt stops the pump and waits for it, so nothing the test reads afterwards
// can race the network. Halting twice is a no-op.
func (r *syncNet) halt() {
	if r.stop == nil {
		return
	}
	close(r.stop)
	<-r.done
	r.stop = nil
}

// run executes fn on the pump goroutine, serialized with the deliveries.
func (r *syncNet) run(fn func()) {
	if r.stop == nil {
		r.t.Fatal("syncNet.run before start: the network must be owned while this runs")
	}
	r.cmds <- fn
}

// runSync is run with an ACK: it waits until the pump has executed fn, so a
// caller can make a delivery a fact rather than a race.
func (r *syncNet) runSync(fn func()) {
	if r.stop == nil {
		r.t.Fatal("syncNet.runSync before start: the network must be owned while this runs")
	}
	done := make(chan struct{})
	r.cmds <- func() {
		fn()
		close(done)
	}
	<-done
}

// settle delivers everything the network has queued RIGHT NOW, on the pump
// goroutine, and returns once the pump has done it. It is installed as
// Syncer.afterSend by the rigs, so a pull's answer is delivered - by the
// honest server or the hostile one - BEFORE the pull begins waiting. A test's
// outcome therefore depends on constructed state, never on a pump goroutine
// winning a race against ReplyWait (F5). One Advance is enough: a handler that
// answers during the delivery enqueues its response at the same virtual
// instant, and Advance keeps delivering everything due.
func (r *syncNet) settle() { r.runSync(func() { r.net.Advance(0) }) }

// pumpBound wraps a peer's endpoint for a syncer the TEST goroutine drives:
// every send takes the pump's lock, so the puller's request is serialized
// with the deliveries exactly as the sim's single-threaded contract demands.
// The honest server side needs no wrapper: its Handle/Send always run inside
// the pump's own Advance.
type pumpBound struct {
	r     *syncNet
	inner transport.Transport
}

func (b pumpBound) Broadcast(data []byte) error {
	b.r.mu.Lock()
	defer b.r.mu.Unlock()
	return b.inner.Broadcast(data)
}

func (b pumpBound) Send(p transport.PeerID, data []byte) error {
	b.r.mu.Lock()
	defer b.r.mu.Unlock()
	return b.inner.Send(p, data)
}

func (b pumpBound) OnMessage(fn func(transport.Message)) { b.inner.OnMessage(fn) }
func (b pumpBound) Peers() []transport.PeerID            { return b.inner.Peers() }
func (b pumpBound) Close() error                         { return b.inner.Close() }

// routeResp is the puller-side wiring the node's connection loop will do: a
// frame that decodes as a BLOCK_SYNC_RESP is filed into the syncer, anything
// else is ignored. seen, when given, is closed the first time a response is
// delivered.
func routeResp(s *Syncer, seen chan struct{}) func(transport.Message) {
	return func(m transport.Message) {
		if _, err := wire.DecodeBlockSyncResp(m.Data); err != nil {
			return
		}
		s.Receive(m.From, m.Data)
		if seen != nil {
			select {
			case <-seen:
			default:
				close(seen)
			}
		}
	}
}

// routeHonest is the honest node's connection-loop wiring: a frame is
// dispatched by what it VERIFIES as, never by its first byte. The consensus
// vote tags (1, 2, 3) and the wire message tags (HELLO 1, SyncReq 2, SyncResp
// 3) share the numeric space - a router keyed on tag bytes alone would fold
// one stream into the other and, on a prevote-tagged sync frame, silently eat
// every vote. So: a verified vote or proposal goes to the driver; a verified
// BLOCK_SYNC request goes to the syncer, whose answer is unicasted back;
// anything else is not this node's to judge. The verification is the same
// signature discipline every role applies to its own stream.
func routeHonest(vals []genesis.Validator, ep transport.Transport, d *Driver, srv *Syncer, logReq func(*wire.BlockSyncReq)) func(transport.Message) {
	return func(m transport.Message) {
		if v, err := DecodeVote(m.Data); err == nil && v.Verify() == nil {
			d.OnMessage(m)
			return
		}
		if p, err := DecodeProposal(m.Data); err == nil && p.Verify() == nil {
			d.OnMessage(m)
			return
		}
		req, err := wire.DecodeBlockSyncReq(m.Data)
		if err != nil || verifySyncReq(req, vals) != nil {
			return
		}
		if logReq != nil {
			logReq(req)
		}
		if resp, ok := srv.Handle(m.Data); ok {
			_ = ep.Send(m.From, resp)
		}
	}
}

// ---------------------------------------------------------------- fixtures

// fourValGenesis is the 4x1-power committee the certificate arithmetic needs:
// quorum 3 of 4, so sub-quorum evidence is nameable precisely.
func fourValGenesis(t *testing.T) *genesis.Genesis {
	t.Helper()
	g := genesis.Devnet()
	g.ChainID = "b10coin-sync-test-4"
	g.Params.ChainID = g.ChainID
	vals := make([]genesis.Validator, 4)
	for i := range vals {
		vals[i] = genesis.Validator{PubKey: testCommitteeKey(i).Public().(ed25519PublicKey), Power: 1}
	}
	g.Validators = vals
	g.Params.CommitteeSize = 4
	return g
}

// craftPrecommit signs validator idx's precommit for blk at (height, round):
// the wire form one live precommit takes.
func craftPrecommit(t *testing.T, idx int, blk *types.Block, height uint64, round uint32) *Vote {
	t.Helper()
	pub := testCommitteeKey(idx).Public().(ed25519PublicKey)
	v := &Vote{Type: MsgPrecommit, Height: height, Round: round, BlockID: blk.ID(), Validator: pub}
	v.Sig = testSignRaw(t, testCommitteeKey(idx), v.SigningHash())
	return v
}

// quorumCertFor signs the fixture's quorum (k0,k1,k2 of four) for blk.
func quorumCertFor(t *testing.T, blk *types.Block, height uint64, round uint32) []*Vote {
	t.Helper()
	return []*Vote{
		craftPrecommit(t, 0, blk, height, round),
		craftPrecommit(t, 1, blk, height, round),
		craftPrecommit(t, 2, blk, height, round),
	}
}

func encodedVotes(votes []*Vote) [][]byte {
	raw := make([][]byte, 0, len(votes))
	for _, v := range votes {
		raw = append(raw, EncodeVote(v))
	}
	return raw
}

// testNonce is a per-test-process unique nonce source: the syncer remembers
// served (requester, nonce) pairs, so every helper-built request must carry a
// distinct one or the second Answer of the same shape would be refused as a
// replay.
var testNonce atomic.Uint64

// unitResp frames a response with NO responder signature: exactly what a relay
// stranger can build from a request it saw in the clear (the nonce is public,
// and the relay forwards the request to everyone). It is the forged envelope
// the F1 refusal tests use; the certificate gate never sees it.
func unitResp(nonce uint64, units ...wire.BlockSyncUnit) []byte {
	return wire.EncodeBlockSyncResp(&wire.BlockSyncResp{Nonce: nonce, Units: units})
}

// signedResp frames the answer member priv's Answer would send for req: the
// same units plus the responder key and a signature over the request and the
// served bytes. It is the honest envelope (round 7, F1).
func signedResp(priv ed25519PrivateKey, req *wire.BlockSyncReq, units ...wire.BlockSyncUnit) []byte {
	resp := &wire.BlockSyncResp{Nonce: req.Nonce, Units: units, Responder: priv.Public().(ed25519PublicKey)}
	h := syncRespHash(req, resp)
	resp.Sig = crypto.Sign(priv, h[:])
	return wire.EncodeBlockSyncResp(resp)
}

// committeePub returns seat i's validator public key.
func committeePub(i int) ed25519PublicKey { return testCommitteeKey(i).Public().(ed25519PublicKey) }

// ---------------------------------------------------------------- committee

// committeeRig is a real consensus committee - the majority, on real drivers
// over the real sim network, committing real blocks with real precommit
// votes, each commit's certificate archived into the validator's own syncer
// through the same Driver.CommitWitness seam the node wiring will use - plus
// one committee member that fell behind: pullCh holds no blocks and no driver
// ticks for it, exactly the validator a catch-up pull is for.
type committeeRig struct {
	t       *testing.T
	rig     *syncNet
	g       *genesis.Genesis
	chains  []*chain.Chain       // the majority's chains
	drivers []*Driver            // the majority's engines
	servers []*Syncer            // the majority's answerers
	reqs    []*wire.BlockSyncReq // every request the serving peer received
	pullCh  *chain.Chain         // the behind member's chain
	pull    *Syncer              // the behind member's syncer
}

// newCommitteeRig brings up `majority` validators committing real blocks on
// the sim network, partitioned away from the behind member. The majority is
// driven synchronously (the sim's own single-threaded contract, no pump
// running yet) to driveTo.
func newCommitteeRig(t *testing.T, majority int, driveTo uint64) *committeeRig {
	t.Helper()
	c := &committeeRig{t: t}
	c.g = fourValGenesis(t)
	c.rig = newSyncNet(t, 7, 2, 0) // seeded, latency, no jitter: sync round trips stay ordered

	// The behind member's chain exists from genesis; its key signs the pull.
	pullChain, err := chain.Open(c.g, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c.pullCh = pullChain
	pullEP := c.rig.addPeer(syncPullerID)
	c.pull = NewSyncer(pullChain, pumpBound{r: c.rig, inner: pullEP}, testCommitteeKey(3))
	c.pull.Peer = syncServerID
	c.pull.Expect = committeePub(0)
	// Deliver each window's answer by construction before the pull waits, so
	// no assertion here rests on the pump beating ReplyWait (F5).
	c.pull.afterSend = func() { c.rig.settle() }
	pullEP.OnMessage(routeResp(c.pull, nil))

	majorityIDs := make([]string, 0, majority)
	for i := 0; i < majority; i++ {
		id := fmt.Sprintf("v%d", i)
		majorityIDs = append(majorityIDs, id)
		ch, err := chain.Open(c.g, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		c.chains = append(c.chains, ch)
		ep := c.rig.addPeer(id)
		// The answerer's archive sits next to its chain; the driver below
		// feeds it every commit's precommit votes through the seam.
		srv := NewSyncer(ch, ep, testCommitteeKey(i))
		c.servers = append(c.servers, srv)
		cfg := Config{
			Committee:   c.g.Validators, // all four: v3 keeps its seat, cut away
			TimeoutBase: 60, TimeoutStep: 20,
			PowerCapNum: 1, PowerCapDen: 4,
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("fixture: the committee config does not validate: %v", err)
		}
		drv := NewDriver(cfg, ch, testCommitteeKey(i), ep, nil) // nil pool: empty blocks, the M3 behaviour
		drv.CommitWitness = srv.RecordCommit
		c.drivers = append(c.drivers, drv)
		ep.OnMessage(routeHonest(c.g.Validators, ep, drv, srv, func(req *wire.BlockSyncReq) {
			c.reqs = append(c.reqs, req)
		}))
	}

	// The behind member sits in a partition while the committee runs - the
	// outage a reconnecting validator returns from - and heals before the
	// pull. Both cut and heal happen before the pump owns the network.
	c.rig.net.Partition([]string{syncPullerID}, majorityIDs)
	c.drive(driveTo)
	c.rig.net.Heal()
	return c
}

// drive advances the rig's clock until every majority chain holds target
// blocks - synchronously, before any pump: the sim is single-threaded here
// like everywhere else in this project.
func (c *committeeRig) drive(target uint64) {
	c.t.Helper()
	now := int64(0)
	reached := func() bool {
		for _, ch := range c.chains {
			if ch.Height() < target {
				return false
			}
		}
		return true
	}
	for step := 0; step < 50_000 && !reached(); step++ {
		now += 10
		for _, d := range c.drivers {
			d.Tick(now)
		}
		c.rig.net.Advance(10 * time.Millisecond)
	}
	if !reached() {
		heights := make([]uint64, len(c.chains))
		for i, ch := range c.chains {
			heights[i] = ch.Height()
		}
		c.t.Fatalf("the committee did not reach height %d (heights %v): the fixture is broken, not the sync", target, heights)
	}
}

func (c *committeeRig) halt() { c.rig.halt() }

// assertConverged is the e2e assertion: the member that pulled holds the SAME
// chain as every member that committed it - same height, same head identity -
// and every block it adopted parents its predecessor, exactly as a committed
// prefix would.
func (c *committeeRig) assertConverged(where string) {
	c.t.Helper()
	for i, ch := range c.chains {
		if c.pullCh.Height() != ch.Height() {
			c.t.Fatalf("%s: the puller is at height %d, validator %d at %d: not converged", where, c.pullCh.Height(), i, ch.Height())
		}
		if c.pullCh.Head().ID() != ch.Head().ID() {
			got, want := c.pullCh.Head().ID(), ch.Head().ID()
			c.t.Fatalf("%s: the puller's head is %x, validator %d's %x: the chains do not agree on the head block", where, got[:8], i, want[:8])
		}
	}
	genesisBlk, err := c.pullCh.BlockAt(0)
	if err != nil {
		c.t.Fatal(err)
	}
	prevID := genesisBlk.ID()
	for h := uint64(1); h <= c.pullCh.Height(); h++ {
		blk, err := c.pullCh.BlockAt(h)
		if err != nil {
			c.t.Fatalf("block %d did not survive the pull: %v", h, err)
		}
		if blk.Header.ParentHash != prevID {
			c.t.Fatalf("adopted block %d parents %x, want the block it was pulled behind (%x)", h, blk.Header.ParentHash[:8], prevID[:8])
		}
		prevID = blk.ID()
	}
}

// ------------------------------------------------------------- cert world

// certWorld is the hostile world: one chain to catch up with and one endpoint
// that answers every request with test-chosen bytes - signed as a committee
// member, because an authenticated member is the adversary the certificate
// gate exists for, and because an UNSIGNED answer is now refused at the
// envelope (round 7, F1) before the certificate is ever considered. The
// stranger's unsigned envelope has its own refusal test below.
type certWorld struct {
	t      *testing.T
	rig    *syncNet
	g      *genesis.Genesis
	pullCh *chain.Chain
	pull   *Syncer
	answer func(req *wire.BlockSyncReq) []byte // set before rig.start()
	reqN   atomic.Int64                        // requests the hostile endpoint received
}

func newCertWorld(t *testing.T) *certWorld {
	t.Helper()
	w := &certWorld{t: t}
	w.g = fourValGenesis(t)
	pullCh, err := chain.Open(w.g, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	w.pullCh = pullCh
	w.rig = newSyncNet(t, 11, 0, 0)
	pullEP := w.rig.addPeer("pull")
	atkEP := w.rig.addPeer("attacker")
	w.pull = NewSyncer(pullCh, pumpBound{r: w.rig, inner: pullEP}, testCommitteeKey(2)) // a committee member's key: requests authenticate
	// The hostile endpoint answers as member 3; the pull is pinned to that
	// identity, so the answer is authenticated and the CERTIFICATE gate is
	// what judges its units.
	w.pull.Peer = "attacker"
	w.pull.Expect = committeePub(3)
	w.pull.afterSend = func() { w.rig.settle() }
	pullEP.OnMessage(routeResp(w.pull, nil))
	atkEP.OnMessage(func(m transport.Message) {
		if len(m.Data) == 0 || m.Data[0] != byte(wire.MsgBlockSyncReq) {
			return
		}
		w.reqN.Add(1)
		req, _ := wire.DecodeBlockSyncReq(m.Data)
		if w.answer == nil {
			return
		}
		if raw := w.answer(req); raw != nil {
			_ = atkEP.Send(m.From, raw)
		}
	})
	return w
}

// halt stops the world's pump; reads of its state are safe afterwards.
func (w *certWorld) halt() { w.rig.halt() }

// assertUnchanged pins where a refused pull must leave the chain: nothing
// adopted, nothing moved.
func (w *certWorld) assertUnchanged(where string, height uint64, headID [32]byte) {
	w.t.Helper()
	if w.pullCh.Height() != height {
		w.t.Fatalf("%s: the height moved to %d: the served block got into the chain", where, w.pullCh.Height())
	}
	if w.pullCh.Head().ID() != headID {
		moved := w.pullCh.Head().ID()
		w.t.Fatalf("%s: the head moved to %x: the chain changed under a refused block", where, moved[:8])
	}
}

// ------------------------------------------------------------ small pins

// syncSignReq signs a request the way PullAndAdopt does, for tests that talk
// to Answer directly. The nonce is unique per call: the syncer's replay set
// keys on (requester, nonce), so a repeated fixture request must not reuse one.
func syncSignReq(t *testing.T, priv ed25519PrivateKey, from, to uint64) *wire.BlockSyncReq {
	t.Helper()
	req := &wire.BlockSyncReq{From: from, To: to, Nonce: testNonce.Add(1), Requester: priv.Public().(ed25519PublicKey)}
	h := syncReqHash(req)
	req.Sig = crypto.Sign(priv, h[:])
	return req
}

// ------------------------------------------------------------------ tests

// TestASyncerPullsAndAdoptsMissedBlocks is the flagship of both findings: a
// committee member partitioned from genesis (chain at height 0) rejoins after
// the majority has committed, and ONE PullAndAdopt invocation - synchronous
// wait for an asynchronously delivered answer, every certificate re-tallied,
// every block appended - reaches the committee's height. Before this fix the
// same call returned "caught up" while three blocks behind, over this very
// transport, and a second call consumed the stale response.
func TestASyncerPullsAndAdoptsMissedBlocks(t *testing.T) {
	c := newCommitteeRig(t, 3, 3)
	defer c.halt()

	// The network comes alive: from here deliveries happen only on the pump.
	c.rig.start()
	// One invocation, start to finish.
	if err := c.pull.PullAndAdopt(1); err != nil {
		t.Fatalf("an honest pull of certified, committed blocks failed: %v", err)
	}
	c.halt()
	c.assertConverged("after one pull")

	// Every adopted block carries the quorum evidence it was adopted on, in
	// the puller's own archive: real committee precommits for the exact
	// blocks now in the chain.
	for h := uint64(1); h <= c.pullCh.Height(); h++ {
		blk, err := c.pullCh.BlockAt(h)
		if err != nil {
			t.Fatal(err)
		}
		rec, ok := c.pull.certificateAt(h)
		if !ok {
			t.Fatalf("adopted block %d left no certificate in the puller's archive: it could not serve onward at all", h)
		}
		seen := map[string]bool{}
		for _, raw := range rec.encoded {
			v, err := DecodeVote(raw)
			if err != nil {
				t.Fatalf("archived certificate vote at height %d does not decode: %v", h, err)
			}
			if err := v.Verify(); err != nil {
				t.Fatalf("archived certificate vote at height %d does not verify: %v", h, err)
			}
			if v.BlockID != blk.ID() {
				adopted := blk.ID()
				t.Fatalf("archived certificate for height %d precommits block %x, not the adopted block %x", h, v.BlockID[:8], adopted[:8])
			}
			idx := Config{Committee: c.g.Validators}.IndexOf(v.Validator)
			if idx < 0 || idx > 2 {
				t.Fatalf("height %d's certificate carries a vote from outside the committing majority (index %d)", h, idx)
			}
			if seen[string(v.Validator)] {
				t.Fatalf("height %d's certificate carries validator %d's vote twice", h, idx)
			}
			seen[string(v.Validator)] = true
		}
	}

	// The pull SIGNED its requests as the committee member it is: each
	// recorded frame authenticates the way a consensus message does.
	if len(c.reqs) == 0 {
		t.Fatal("no BLOCK_SYNC request ever went out")
	}
	for i, req := range c.reqs {
		if err := verifySyncReq(req, c.g.Validators); err != nil {
			t.Fatalf("recorded request %d does not authenticate: %v", i, err)
		}
	}
}

// TestTheSamePullReachesThePeerHeightAcrossSeveralWindows pins window
// chaining over the real transport: a windows-of-2 pull of a 5-block range
// sends exactly three requests ([1,2],[3,4],[5,...]) and converges.
func TestTheSamePullReachesThePeerHeightAcrossSeveralWindows(t *testing.T) {
	c := newCommitteeRig(t, 3, 5)
	defer c.halt()
	c.pull.MaxBlocksPerResponse = 2
	c.rig.start()

	if err := c.pull.PullAndAdopt(1); err != nil {
		t.Fatalf("a three-window pull failed: %v", err)
	}
	c.halt()
	c.assertConverged("after three windows")

	if len(c.reqs) != 3 {
		t.Fatalf("pulling 5 blocks in windows of 2 sent %d requests", len(c.reqs))
	}
	for i, want := range []uint64{1, 3, 5} {
		if c.reqs[i].From != want {
			t.Fatalf("request %d asked from %d, want %d", i, c.reqs[i].From, want)
		}
	}
}

// -------------------------------------------------------------- F1 proofs

// TestPullAndAdoptRefusesAZeroVoteBlock is the reviewer's attack: one
// committee member Builds a state-valid block at head+1 over the puller's own
// head, signs it, and holds it with ZERO votes - no live engine would ever
// commit it. Pre-fix, PullAndAdopt adopted it and stood on the attacker's
// one-validator fork; now the pull refuses it, loudly, and the chain does not
// move.
func TestPullAndAdoptRefusesAZeroVoteBlock(t *testing.T) {
	w := newCertWorld(t)
	defer w.rig.halt()

	// The attack block: committee member 3 signs it via chain.Build; nothing
	// anywhere precommits it.
	atk, err := w.pullCh.Build(testCommitteeKey(3), nil, w.pullCh.Head().Header.Timestamp+1)
	if err != nil {
		t.Fatal(err)
	}
	height, headID := w.pullCh.Height(), w.pullCh.Head().ID()

	w.answer = func(req *wire.BlockSyncReq) []byte {
		return signedResp(testCommitteeKey(3), req, wire.BlockSyncUnit{Block: atk.Encode(), Round: 7}) // one block, zero votes
	}
	w.rig.start()
	err = w.pull.PullAndAdopt(1)
	if err == nil {
		t.Fatal("a zero-vote block was adopted: the pull trusted the proposer's signature for a quorum commitment")
	}
	if !errors.Is(err, ErrBadSyncCommit) {
		t.Fatalf("the pull refused the attack for the wrong reason (%v), want ErrBadSyncCommit", err)
	}
	if !strings.Contains(err.Error(), "no precommit votes") {
		t.Fatalf("the refusal (%v) does not name the missing votes", err)
	}
	w.assertUnchanged("after the refused attack", height, headID)
}

// TestPullAndAdoptRefusesACertificateShortOfQuorum walks the sub-quorum and
// malformed classes: a certificate must be re-tallied through the ordinary
// VoteSet and REACH quorum, or it proves nothing.
func TestPullAndAdoptRefusesACertificateShortOfQuorum(t *testing.T) {
	t.Run("two of four precommits", func(t *testing.T) {
		w := newCertWorld(t)
		defer w.rig.halt()
		atk, err := w.pullCh.Build(testCommitteeKey(3), nil, w.pullCh.Head().Header.Timestamp+1)
		if err != nil {
			t.Fatal(err)
		}
		// Two VALID, correctly signed, correctly placed precommits: still
		// below the quorum of three the live commit rule needs.
		cert := []*Vote{craftPrecommit(t, 0, atk, 1, 7), craftPrecommit(t, 1, atk, 1, 7)}
		w.answer = func(req *wire.BlockSyncReq) []byte {
			return signedResp(testCommitteeKey(3), req, wire.BlockSyncUnit{Block: atk.Encode(), Round: 7, Votes: encodedVotes(cert)})
		}
		w.rig.start()
		height, headID := w.pullCh.Height(), w.pullCh.Head().ID()
		err = w.pull.PullAndAdopt(1)
		if !errors.Is(err, ErrBadSyncCommit) || !strings.Contains(err.Error(), "quorum") {
			t.Fatalf("2-of-4 precommits gave (%v), want a sub-quorum ErrBadSyncCommit", err)
		}
		w.assertUnchanged("after the sub-quorum refusal", height, headID)
	})

	t.Run("the same vote counted three times", func(t *testing.T) {
		w := newCertWorld(t)
		defer w.rig.halt()
		atk, err := w.pullCh.Build(testCommitteeKey(3), nil, w.pullCh.Head().Header.Timestamp+1)
		if err != nil {
			t.Fatal(err)
		}
		// One validator's precommit carried three times is still ONE
		// validator's weight - the tally's one-vote-per-validator rule is
		// what stops two colluders manufacturing a quorum the committee
		// never gave.
		v := craftPrecommit(t, 0, atk, 1, 7)
		w.answer = func(req *wire.BlockSyncReq) []byte {
			return signedResp(testCommitteeKey(3), req, wire.BlockSyncUnit{Block: atk.Encode(), Round: 7, Votes: encodedVotes([]*Vote{v, v, v})})
		}
		w.rig.start()
		height, headID := w.pullCh.Height(), w.pullCh.Head().ID()
		err = w.pull.PullAndAdopt(1)
		if !errors.Is(err, ErrBadSyncCommit) {
			t.Fatalf("a tripled vote gave (%v), want ErrBadSyncCommit", err)
		}
		w.assertUnchanged("after the tripled-vote refusal", height, headID)
	})

	t.Run("a stranger's precommit inside the certificate", func(t *testing.T) {
		w := newCertWorld(t)
		defer w.rig.halt()
		atk, err := w.pullCh.Build(testCommitteeKey(3), nil, w.pullCh.Head().Header.Timestamp+1)
		if err != nil {
			t.Fatal(err)
		}
		_, strangerPriv, err := crypto.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		sv := &Vote{Type: MsgPrecommit, Height: 1, Round: 7, BlockID: atk.ID(), Validator: strangerPriv.Public().(ed25519PublicKey)}
		sHash := sv.SigningHash()
		sv.Sig = crypto.Sign(strangerPriv, sHash[:])
		if _, err := certVoteSet(w.g.Validators, 1, 7).Add(sv); !errors.Is(err, ErrNotValidator) {
			t.Fatalf("fixture: the stranger's vote was not refused as non-member (%v)", err)
		}
		cert := []*Vote{craftPrecommit(t, 0, atk, 1, 7), craftPrecommit(t, 1, atk, 1, 7), sv}
		w.answer = func(req *wire.BlockSyncReq) []byte {
			return signedResp(testCommitteeKey(3), req, wire.BlockSyncUnit{Block: atk.Encode(), Round: 7, Votes: encodedVotes(cert)})
		}
		w.rig.start()
		height, headID := w.pullCh.Height(), w.pullCh.Head().ID()
		err = w.pull.PullAndAdopt(1)
		if !errors.Is(err, ErrBadSyncCommit) {
			t.Fatalf("a non-member's vote gave (%v), want ErrBadSyncCommit", err)
		}
		w.assertUnchanged("after the non-member refusal", height, headID)
	})

	t.Run("votes cast at another round than declared", func(t *testing.T) {
		w := newCertWorld(t)
		defer w.rig.halt()
		atk, err := w.pullCh.Build(testCommitteeKey(3), nil, w.pullCh.Head().Header.Timestamp+1)
		if err != nil {
			t.Fatal(err)
		}
		// The votes genuinely exist - at round 9 - but the unit names round
		// 7: re-tallying at the named round refuses the mismatch, so a
		// certificate cannot relocate its own votes.
		cert := []*Vote{craftPrecommit(t, 0, atk, 1, 9), craftPrecommit(t, 1, atk, 1, 9), craftPrecommit(t, 2, atk, 1, 9)}
		w.answer = func(req *wire.BlockSyncReq) []byte {
			return signedResp(testCommitteeKey(3), req, wire.BlockSyncUnit{Block: atk.Encode(), Round: 7, Votes: encodedVotes(cert)})
		}
		w.rig.start()
		height, headID := w.pullCh.Height(), w.pullCh.Head().ID()
		err = w.pull.PullAndAdopt(1)
		if !errors.Is(err, ErrBadSyncCommit) || !strings.Contains(err.Error(), "another height or round") {
			t.Fatalf("misplaced votes gave (%v), want a placement ErrBadSyncCommit", err)
		}
		w.assertUnchanged("after the wrong-round refusal", height, headID)
	})

	t.Run("quorum for a different block", func(t *testing.T) {
		w := newCertWorld(t)
		defer w.rig.halt()
		atk, err := w.pullCh.Build(testCommitteeKey(3), nil, w.pullCh.Head().Header.Timestamp+1)
		if err != nil {
			t.Fatal(err)
		}
		other, err := w.pullCh.Build(testCommitteeKey(0), nil, w.pullCh.Head().Header.Timestamp+2)
		if err != nil {
			t.Fatal(err)
		}
		if other.ID() == atk.ID() {
			t.Fatal("fixture: the distractor block is the attack block")
		}
		// A full quorum precommitted a DIFFERENT block: none of it is
		// evidence for the bytes that were served.
		cert := quorumCertFor(t, other, 1, 7)
		w.answer = func(req *wire.BlockSyncReq) []byte {
			return signedResp(testCommitteeKey(3), req, wire.BlockSyncUnit{Block: atk.Encode(), Round: 7, Votes: encodedVotes(cert)})
		}
		w.rig.start()
		height, headID := w.pullCh.Height(), w.pullCh.Head().ID()
		err = w.pull.PullAndAdopt(1)
		if !errors.Is(err, ErrBadSyncCommit) || !strings.Contains(err.Error(), "quorum") {
			t.Fatalf("votes for another block gave (%v), want a quorum ErrBadSyncCommit", err)
		}
		w.assertUnchanged("after the cross-block refusal", height, headID)
	})

	t.Run("certificate votes that do not even decode", func(t *testing.T) {
		w := newCertWorld(t)
		defer w.rig.halt()
		atk, err := w.pullCh.Build(testCommitteeKey(3), nil, w.pullCh.Head().Header.Timestamp+1)
		if err != nil {
			t.Fatal(err)
		}
		w.answer = func(req *wire.BlockSyncReq) []byte {
			return signedResp(testCommitteeKey(3), req, wire.BlockSyncUnit{Block: atk.Encode(), Round: 7, Votes: [][]byte{{0x01}, {0x02}, {0x03}}})
		}
		w.rig.start()
		height, headID := w.pullCh.Height(), w.pullCh.Head().ID()
		err = w.pull.PullAndAdopt(1)
		if !errors.Is(err, ErrBadSyncCommit) || !strings.Contains(err.Error(), "does not decode") {
			t.Fatalf("undecodable votes gave (%v), want a decode ErrBadSyncCommit", err)
		}
		w.assertUnchanged("after the undecodable-vote refusal", height, headID)
	})
}

// TestPullAndAdoptAdoptsAProperlyCertifiedBlock is the positive half of F1:
// the same attack-shaped block, presented with a quorum's real precommits, IS
// adopted - the fix refuses the claim, not the mechanism.
func TestPullAndAdoptAdoptsAProperlyCertifiedBlock(t *testing.T) {
	w := newCertWorld(t)
	defer w.rig.halt()

	blk, err := w.pullCh.Build(testCommitteeKey(0), nil, w.pullCh.Head().Header.Timestamp+1)
	if err != nil {
		t.Fatal(err)
	}
	// A quorum precommits it at round 7: three of four, real signatures,
	// correct placement. It is exactly the evidence a live commit would have
	// produced.
	cert := quorumCertFor(t, blk, 1, 7)
	w.answer = func(req *wire.BlockSyncReq) []byte {
		return signedResp(testCommitteeKey(3), req, wire.BlockSyncUnit{Block: blk.Encode(), Round: 7, Votes: encodedVotes(cert)})
	}
	w.rig.start()

	id := blk.ID()
	if err := w.pull.PullAndAdopt(1); err != nil {
		t.Fatalf("a certified block was refused: %v", err)
	}
	if w.pullCh.Height() != 1 || w.pullCh.Head().ID() != id {
		t.Fatalf("the certified block did not land: height %d", w.pullCh.Height())
	}
	// And it archived the certificate, so it can serve onward.
	if _, ok := w.pull.certificateAt(1); !ok {
		t.Fatal("the adopted block's certificate was not archived")
	}
}

// TestThePullStopsAtTheFirstUncertifiedUnit pins stop-rather-than-skip: an
// answer of [certified, uncertified, certified] must adopt exactly the first
// block, refuse the second, and adopt NOTHING after it - a skipped block
// would leave a hole no later block links across.
func TestThePullStopsAtTheFirstUncertifiedUnit(t *testing.T) {
	w := newCertWorld(t)
	defer w.rig.halt()

	b1, err := w.pullCh.Build(testCommitteeKey(0), nil, w.pullCh.Head().Header.Timestamp+1)
	if err != nil {
		t.Fatal(err)
	}
	cert := quorumCertFor(t, b1, 1, 5)
	w.answer = func(req *wire.BlockSyncReq) []byte {
		return signedResp(testCommitteeKey(3), req,
			wire.BlockSyncUnit{Block: b1.Encode(), Round: 5, Votes: encodedVotes(cert)}, // certified
			wire.BlockSyncUnit{Block: b1.Encode(), Round: 5},                            // zero votes
			wire.BlockSyncUnit{Block: b1.Encode(), Round: 5, Votes: encodedVotes(cert)},
		)
	}
	w.rig.start()
	err = w.pull.PullAndAdopt(1)
	if !errors.Is(err, ErrBadSyncCommit) {
		t.Fatalf("an uncertified second unit gave (%v), want ErrBadSyncCommit", err)
	}
	// Exactly the certified first block landed; the pull stopped on the
	// second and nothing else was offered again.
	if w.pullCh.Height() != 1 || w.pullCh.Head().ID() != b1.ID() {
		headNow := w.pullCh.Head().ID()
		want := b1.ID()
		t.Fatalf("the chain stands at height %d with head %x, want exactly the one certified block (%x)",
			w.pullCh.Height(), headNow[:8], want[:8])
	}
	// No new window was requested: the pull is over on the first failure.
	if n := w.reqN.Load(); n != 1 {
		t.Fatalf("%d requests went out; the pull must stop at the first refused unit", n)
	}
}

// TestACertifiedPoisonBlockStillFailsAppend proves the two gates COMPOSE: a
// block may carry a genuine quorum certificate and still be refused by
// chain.Append - certificates do not lower the state gate, and the state gate
// does not wave certificates through.
func TestACertifiedPoisonBlockStillFailsAppend(t *testing.T) {
	cases := []struct {
		name   string
		poison func(t *testing.T, w *certWorld) *types.Block
	}{
		{
			name: "a block the state machine refuses",
			poison: func(t *testing.T, w *certWorld) *types.Block {
				// Decodes, passes structure, carries a valid committee
				// PROPOSER signature - and its transfer's signature is
				// garbage; only the state machine inside Append can tell.
				head := w.pullCh.Head()
				st, err := w.pullCh.Probe(nil)
				if err != nil {
					t.Fatal(err)
				}
				sender, _, err := crypto.GenerateKey()
				if err != nil {
					t.Fatal(err)
				}
				badTx := types.Tx{
					Type:   types.TxTransfer,
					From:   types.AddressFromPub(sender),
					PubKey: sender,
					Nonce:  0,
					To:     types.AddressFromPub(testCommitteeKey(0).Public().(ed25519PublicKey)),
					Amount: 7,
					Sig:    []byte("a signature nobody's key produced"),
				}
				bad := &types.Block{
					Header: types.Header{
						Height:     head.Header.Height + 1,
						ParentHash: head.ID(),
						StateRoot:  st.Root(),
						TxRoot:     types.ComputeTxRoot([]types.Tx{badTx}),
						Timestamp:  head.Header.Timestamp + 1,
						Proposer:   testCommitteeKey(3).Public().(ed25519PublicKey),
					},
					Txs: []types.Tx{badTx},
				}
				if badTx.VerifySignature(w.pullCh.Genesis().Hash()) == nil {
					t.Fatal("fixture: the poisoned transaction unexpectedly verifies")
				}
				if _, err := w.pullCh.Probe(bad.Txs); err == nil {
					t.Fatal("fixture: the poisoned block's transaction unexpectedly applies")
				}
				h := bad.Header.SigningHash()
				bad.Sig = crypto.Sign(testCommitteeKey(3), h[:])
				if err := w.pullCh.Append(bad); err == nil {
					t.Fatal("fixture: the poisoned block unexpectedly appends locally")
				}
				return bad
			},
		},
		{
			name: "a block whose proposer signature is broken",
			poison: func(t *testing.T, w *certWorld) *types.Block {
				// A PERFECT block whose proposer signature does not verify -
				// the class a fast-path adoption skipping Append's signature
				// check would happily install.
				good, err := w.pullCh.Build(testCommitteeKey(3), nil, w.pullCh.Head().Header.Timestamp+1)
				if err != nil {
					t.Fatal(err)
				}
				h := good.Header.SigningHash()
				_, strangerPriv, err := crypto.GenerateKey()
				if err != nil {
					t.Fatal(err)
				}
				good.Sig = crypto.Sign(strangerPriv, h[:])
				if err := w.pullCh.Append(good); err == nil {
					t.Fatal("fixture: a broken-signature block unexpectedly appends")
				}
				return good
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newCertWorld(t)
			defer w.rig.halt()
			bad := tc.poison(t, w)
			// The certificate is REAL - a quorum of the committee signed
			// precommits for exactly these bytes - and the pull still must
			// not adopt: the certificate gate passes, Append's does not.
			w.answer = func(req *wire.BlockSyncReq) []byte {
				return signedResp(testCommitteeKey(3), req, wire.BlockSyncUnit{Block: bad.Encode(), Round: 2, Votes: encodedVotes(quorumCertFor(t, bad, bad.Header.Height, 2))})
			}
			w.rig.start()
			height, headID := w.pullCh.Height(), w.pullCh.Head().ID()
			err := w.pull.PullAndAdopt(1)
			if err == nil {
				t.Fatal("a certified poison block was adopted: the certificate did not stop before Append")
			}
			if !strings.Contains(err.Error(), "does not adopt") {
				t.Fatalf("the pull stopped for the wrong reason (%v), not the state gate's refusal", err)
			}
			w.assertUnchanged("after the certified poison was refused", height, headID)
		})
	}
}

// TestSyncerRefusesBytesThatAreNotABlock: served garbage decodes to nothing,
// certificate or no certificate.
func TestSyncerRefusesBytesThatAreNotABlock(t *testing.T) {
	w := newCertWorld(t)
	defer w.rig.halt()
	w.answer = func(req *wire.BlockSyncReq) []byte {
		return signedResp(testCommitteeKey(3), req, wire.BlockSyncUnit{Block: []byte{0xde, 0xad}, Round: 1})
	}
	w.rig.start()
	height, headID := w.pullCh.Height(), w.pullCh.Head().ID()
	if err := w.pull.PullAndAdopt(1); !errors.Is(err, ErrBadSyncResp) {
		t.Fatalf("served garbage gave (%v), want ErrBadSyncResp", err)
	}
	w.halt()
	w.assertUnchanged("after the undecodable block was refused", height, headID)
}

// ------------------------------------------------------- F2-adjacent pins

// TestAStaleResponseDoesNotAnswerANewPull is the regression pin for the
// uncorrelated-response defect: a response delivered while NO pull waited is
// dropped by Receive (there is no request for it to answer and no slot for it
// to sit in), so the next pull - which carries a nonce this frame was never
// the answer to - reads silence rather than the stale frame.
func TestAStaleResponseDoesNotAnswerANewPull(t *testing.T) {
	w := newCertWorld(t)
	defer w.rig.halt()

	// A properly certified unit for height 1, delivered BEFORE any pull waits
	// for it: whatever it is, it answers nothing.
	blk, err := w.pullCh.Build(testCommitteeKey(0), nil, w.pullCh.Head().Header.Timestamp+1)
	if err != nil {
		t.Fatal(err)
	}
	stale := signedResp(testCommitteeKey(3),
		&wire.BlockSyncReq{From: 1, To: 1, Nonce: 1, Requester: testCommitteeKey(2).Public().(ed25519PublicKey)},
		wire.BlockSyncUnit{Block: blk.Encode(), Round: 3, Votes: encodedVotes(quorumCertFor(t, blk, 1, 3))})

	delivered := make(chan struct{})
	route := routeResp(w.pull, delivered)
	w.rig.eps["pull"].OnMessage(func(m transport.Message) { route(m) })

	w.rig.start()
	// Deliver it while no pull is in flight.
	w.rig.run(func() { _ = w.rig.eps["attacker"].Send("pull", stale) })
	select {
	case <-delivered:
	case <-time.After(2 * time.Second):
		t.Fatal("the stale frame was never delivered")
	}

	// The attacker goes silent for the real request; the pull must report
	// caught-up (nil) rather than consume the pre-filed frame. The reply is
	// delivered by afterSend/settle, so the short ReplyWait only bounds a wait
	// that has NO responder left to race (F5).
	w.pull.ReplyWait = 20 * time.Millisecond
	height, headID := w.pullCh.Height(), w.pullCh.Head().ID()
	if err := w.pull.PullAndAdopt(1); err != nil {
		t.Fatalf("the stale file was consumed and errored the pull (%v): a filed frame answered a request it was not for", err)
	}
	w.halt()
	w.assertUnchanged("after the stale slot was drained", height, headID)
}

// TestAnUndecodableResponseFrameIsSilence: garbage that does not decode as a
// response is dropped by Receive - a pull in flight reads silence (nil), and
// the chain does not move. The frame DID reach this node and went through the
// wire; the drop is the decoder's, not the routing's.
func TestAnUndecodableResponseFrameIsSilence(t *testing.T) {
	w := newCertWorld(t)
	defer w.rig.halt()
	w.answer = func(req *wire.BlockSyncReq) []byte { return []byte{0x01} } // not a BLOCK_SYNC response
	// The frame is delivered by afterSend/settle before the wait; the short
	// ReplyWait only bounds a wait with no responder left (F5).
	w.pull.ReplyWait = 20 * time.Millisecond
	w.rig.start()
	height, headID := w.pullCh.Height(), w.pullCh.Head().ID()
	if err := w.pull.PullAndAdopt(1); err != nil {
		t.Fatalf("an undecodable response frame produced an error (%v); it is dropped and reads as silence", err)
	}
	if n := w.reqN.Load(); n != 1 {
		t.Fatalf("%d requests were seen; the pull must have gone to the wire once", n)
	}
	w.halt()
	w.assertUnchanged("after the undecodable frame was dropped", height, headID)
}

// ------------------------------------------------- convergence-adjacent

// TestSyncerAdoptsNothingWhenAlreadyCurrent, over the real transport: a
// converged member re-pulls and reads silence every time, and never asks for
// an adopted range.
func TestSyncerAdoptsNothingWhenAlreadyCurrent(t *testing.T) {
	c := newCommitteeRig(t, 3, 3)
	defer c.halt()
	c.rig.start()

	if err := c.pull.PullAndAdopt(1); err != nil {
		t.Fatalf("the first pull failed: %v", err)
	}
	c.assertConverged("after the first pull")
	height := c.pullCh.Height()

	// Each re-pull's request is delivered by afterSend/settle (committeeRig),
	// so these are all asked deterministically; the short ReplyWait bounds
	// only the silent answers of an already-caught-up peer (F5).
	c.pull.ReplyWait = 20 * time.Millisecond
	for _, from := range []uint64{0, 1, 2, 3} {
		if err := c.pull.PullAndAdopt(from); err != nil {
			t.Fatalf("PullAndAdopt(%d) on a current chain errored: %v", from, err)
		}
	}
	c.halt()
	if c.pullCh.Height() != height || c.pullCh.Head().ID() != c.chains[0].Head().ID() {
		t.Fatal("pulling on a current chain changed the chain")
	}
	// The peer was ASKED (there is no local fact about the peer's height),
	// and every ask named the height above the head - never a range the
	// chain already holds. One authenticated request from the first pull,
	// then one per re-pull.
	if len(c.reqs) != 5 {
		t.Fatalf("%d requests recorded, want 5 (the first pull plus one per re-pull)", len(c.reqs))
	}
	for i, req := range c.reqs[1:] {
		if req.From != height+1 {
			t.Fatalf("re-pull request %d asked from %d on a chain current at %d: an adopted range was re-asked", i, req.From, height)
		}
	}
}

// TestSyncerRePullingTheSameRangeTwiceChangesNothing, over the real
// transport: the adopted prefix is skipped and the peer - which has nothing
// more - answers with silence.
func TestSyncerRePullingTheSameRangeTwiceChangesNothing(t *testing.T) {
	c := newCommitteeRig(t, 3, 2)
	defer c.halt()
	c.rig.start()

	if err := c.pull.PullAndAdopt(1); err != nil {
		t.Fatalf("first pull failed: %v", err)
	}
	c.assertConverged("after the first pull")
	height := c.pullCh.Height()

	// The re-pull's request is delivered by afterSend/settle; the short
	// ReplyWait bounds only the already-caught-up peer's silence (F5).
	c.pull.ReplyWait = 20 * time.Millisecond
	if err := c.pull.PullAndAdopt(1); err != nil {
		t.Fatalf("re-pull of an adopted range errored: %v", err)
	}
	c.halt()
	if c.pullCh.Height() != height || c.pullCh.Head().ID() != c.chains[0].Head().ID() {
		t.Fatal("the re-pull changed the chain")
	}
	if len(c.reqs) != 2 {
		t.Fatalf("two pulls produced %d requests", len(c.reqs))
	}
	firstFrom, secondFrom := c.reqs[0].From, c.reqs[1].From
	if firstFrom != 1 {
		t.Fatalf("the first pull asked from %d, want 1", firstFrom)
	}
	if secondFrom != height+1 {
		t.Fatalf("the re-pull asked from %d, want the height above the new head (%d): adopted blocks were re-asked", secondFrom, height+1)
	}
}

// TestSyncerPullFromAPartitionedPeerIsAnError, on the REAL transport's own
// partition: a Send the transport refuses is the caller's problem - the pull
// returns the error rather than reading silence as caught-up.
func TestSyncerPullFromAPartitionedPeerIsAnError(t *testing.T) {
	c := newCommitteeRig(t, 3, 3)
	defer c.halt()
	// Re-cut the puller away from the server after the drive, before the
	// pull: the transport refuses the Send itself.
	c.rig.net.Partition([]string{syncPullerID}, []string{syncServerID})
	c.rig.start()
	if err := c.pull.PullAndAdopt(1); err == nil {
		t.Fatal("the transport refused the send and the pull reported success")
	}
	// The partition never delivered: nothing adopted.
	if c.pullCh.Height() != 0 {
		t.Fatalf("the puller adopted across a partition (height %d)", c.pullCh.Height())
	}
}

// --------------------------------------------------------- local refusals

// TestPullAndAdoptDisabledIsErrSyncDisabled: an unbounded-off syncer serves
// nothing and must offer to pull nothing.
func TestPullAndAdoptDisabledIsErrSyncDisabled(t *testing.T) {
	g := fourValGenesis(t)
	ch, err := chain.Open(g, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := NewSyncer(ch, nil, testCommitteeKey(0)) // no transport reached at all: disabled must trip first
	s.MaxBlocksPerResponse = 0
	if err := s.PullAndAdopt(1); !errors.Is(err, ErrSyncDisabled) {
		t.Fatalf("a disabled syncer gave (%v), want ErrSyncDisabled", err)
	}
}

// TestPullAndAdoptWithoutAPeerIsErrNoSyncPeer: nothing to send to is refused
// before the wire, by the transport's own empty peer list.
func TestPullAndAdoptWithoutAPeerIsErrNoSyncPeer(t *testing.T) {
	t.Helper()
	g := fourValGenesis(t)
	ch, err := chain.Open(g, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// A real sim net where the ONLY registered peer is the sender itself:
	// Peers() is then empty, which is the honest shape of "no one to ask".
	rig := newSyncNet(t, 3, 0, 0)
	ep := rig.addPeer("pull")
	s := NewSyncer(ch, pumpBound{r: rig, inner: ep}, testCommitteeKey(0))
	rig.start()
	defer rig.halt()
	if err := s.PullAndAdopt(1); !errors.Is(err, ErrNoSyncPeer) {
		t.Fatalf("a pull without any peer gave (%v), want ErrNoSyncPeer", err)
	}
}

// TestPullAndAdoptAboveItsHeadIsRefusedLocally pins the fix of the
// silence-instead-of-documented-error defect: a `from` above head+1 can never
// adopt anything (Append requires exactly head+1), so the pull refuses
// LOCALLY with ErrRangeAhead before any wire traffic, instead of honouring
// the range as written, going silent at the peer, and returning as if caught
// up.
func TestPullAndAdoptAboveItsHeadIsRefusedLocally(t *testing.T) {
	w := newCertWorld(t)
	defer w.rig.halt()
	w.rig.start()
	height, headID := w.pullCh.Height(), w.pullCh.Head().ID()
	for _, from := range []uint64{2, 5, math.MaxUint64} {
		err := w.pull.PullAndAdopt(from)
		if !errors.Is(err, ErrRangeAhead) {
			t.Fatalf("PullAndAdopt(%d) with head at %d gave (%v), want ErrRangeAhead", from, height, err)
		}
	}
	// Before ANY wire traffic: the hostile endpoint received nothing.
	if n := w.reqN.Load(); n != 0 {
		t.Fatalf("%d requests reached the peer: the refusal must be local", n)
	}
	w.halt()
	w.assertUnchanged("after the above-head refusals", height, headID)
}

// ------------------------------------------------------- answerer-level

// TestAnAnswererRefusesARangeItHoldsNoCertificateFor: the serving half of the
// certificate rule - a chain of blocks grown WITHOUT the commit evidence
// cannot be served at all, and a partially-archived range is refused whole,
// never served short past an uncertified height (a short answer is how a
// puller learns "caught up"; that must never be a lie).
func TestAnAnswererRefusesARangeItHoldsNoCertificateFor(t *testing.T) {
	g := fourValGenesis(t)
	serverCh, err := chain.Open(g, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// Grown by plain Build/Append: state-valid, signed, and NEVER committed
	// by a quorum - a chain of exactly the reviewer's attack blocks.
	for i := 0; i < 3; i++ {
		b, err := serverCh.Build(testCommitteeKey(1), nil, serverCh.Head().Header.Timestamp+1)
		if err != nil {
			t.Fatal(err)
		}
		if err := serverCh.Append(b); err != nil {
			t.Fatal(err)
		}
	}
	srv := NewSyncer(serverCh, nil, testCommitteeKey(1))

	// No archive: nothing at all can be served.
	ask := func(from, to uint64) error {
		_, err := srv.Answer(syncSignReq(t, testCommitteeKey(0), from, to))
		return err
	}
	if err := ask(1, 3); !errors.Is(err, ErrBadSyncCommit) {
		t.Fatalf("serving an uncertified chain gave (%v), want ErrBadSyncCommit", err)
	}

	// A certificate for one height makes exactly that height servable - and
	// nothing past it.
	b1, err := serverCh.BlockAt(1)
	if err != nil {
		t.Fatal(err)
	}
	srv.RecordCommit(1, 4, quorumCertFor(t, b1, 1, 4))
	if err := ask(1, 1); err != nil {
		t.Fatalf("the certified height was refused: %v", err)
	}
	if err := ask(1, 2); !errors.Is(err, ErrBadSyncCommit) {
		t.Fatalf("a range crossing into uncertified heights gave (%v), want ErrBadSyncCommit", err)
	}
	if err := ask(3, 3); !errors.Is(err, ErrBadSyncCommit) {
		t.Fatalf("the uncertified height alone gave (%v), want ErrBadSyncCommit", err)
	}
}

// certServeFixture is a chain grown to `to` blocks - by plain Build/Append,
// then certified height by height into the SERVING syncer's archive with a
// synthesized quorum - a server that CAN answer, for the range/bound tests.
type certServeFixture struct {
	t         *testing.T
	chain     *chain.Chain
	server    *Syncer
	pullerKey ed25519PrivateKey
}

func newCertServeFixture(t *testing.T, to uint64) *certServeFixture {
	t.Helper()
	g := fourValGenesis(t)
	ch, err := chain.Open(g, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv := NewSyncer(ch, nil, testCommitteeKey(1))
	for h := uint64(1); h <= to; h++ {
		b, err := ch.Build(testCommitteeKey(1), nil, ch.Head().Header.Timestamp+1)
		if err != nil {
			t.Fatal(err)
		}
		if err := ch.Append(b); err != nil {
			t.Fatal(err)
		}
		// Certify every height it grows, the way a live commit would have.
		srv.RecordCommit(h, 2, quorumCertFor(t, b, h, 2))
	}
	return &certServeFixture{t: t, chain: ch, server: srv, pullerKey: testCommitteeKey(0)}
}

// TestSyncerRefusesRangesBeyondTheBound: the ANSWER side's bound, unchanged
// by the certificate - the count is refused before any allocation.
func TestSyncerRefusesRangesBeyondTheBound(t *testing.T) {
	f := newCertServeFixture(t, 6)
	f.server.MaxBlocksPerResponse = 4 // the bound under test is the answerer's

	ask := func(from, to uint64) (*wire.BlockSyncResp, error) {
		return f.server.Answer(syncSignReq(t, f.pullerKey, from, to))
	}

	// Width 5 over a bound of 4: refused with the bound error, not served
	// short.
	if _, err := ask(1, 5); !errors.Is(err, ErrRangeTooBig) {
		t.Fatalf("a range of 5 over a bound of 4 gave %v, want ErrRangeTooBig", err)
	}
	// The bound holds even when the chain HAS the blocks and their
	// certificates: removing the check must be observable, which requires the
	// chain to be able to answer.
	if f.chain.Height() < 6 {
		t.Fatalf("fixture: chain height %d cannot expose an unbounded answer", f.chain.Height())
	}
	// Bound EXACTLY: a range as wide as the bound is served whole.
	resp, err := ask(1, 4)
	if err != nil {
		t.Fatalf("a range exactly at the bound was refused: %v", err)
	}
	if uint64(len(resp.Units)) != 4 {
		t.Fatalf("a bound-wide answer served %d units", len(resp.Units))
	}
	// And the count is bounded BEFORE allocation: a range that is both over
	// the bound and astronomically wide must return the bound error - the
	// arithmetic must never form the wrapped count that width MaxUint64+1
	// would produce.
	if _, err := ask(0, math.MaxUint64); !errors.Is(err, ErrRangeTooBig) {
		t.Fatalf("the maximal range gave %v, want ErrRangeTooBig", err)
	}
}

// TestSyncerRefusesImpossibleRanges: the ANSWER side's range semantics,
// unchanged by the certificate.
func TestSyncerRefusesImpossibleRanges(t *testing.T) {
	f := newCertServeFixture(t, 6)
	f.server.MaxBlocksPerResponse = 4

	ask := func(from, to uint64) (*wire.BlockSyncResp, error) {
		return f.server.Answer(syncSignReq(t, f.pullerKey, from, to))
	}

	// Backwards = the wire's only zero-length shape. Ranges are inclusive on
	// both ends, so To==From asks exactly one block; the only range that
	// selects nothing is To<From.
	if _, err := ask(3, 2); !errors.Is(err, ErrBadSyncRange) {
		t.Fatalf("a backwards range gave %v, want ErrBadSyncRange", err)
	}
	// The "give me nothing above the head" shape a confused requester sends:
	// From one past the head, To the head. It selects nothing - refused.
	if _, err := ask(7, 6); !errors.Is(err, ErrBadSyncRange) {
		t.Fatalf("the empty range above the head gave %v, want ErrBadSyncRange", err)
	}
	// A single block is a legal range, not a zero-length one.
	if resp, err := ask(3, 3); err != nil || len(resp.Units) != 1 {
		t.Fatalf("a one-block range gave (%d units, %v)", len(resp.Units), err)
	}
	// Starting above the local height: refused with its own error, not
	// answered empty and not served short.
	if _, err := ask(7, 9); !errors.Is(err, ErrRangeAhead) {
		t.Fatalf("a range starting above the head gave %v, want ErrRangeAhead", err)
	}
	// A range that only EXTENDS past the height is served short (certified
	// through every height it holds) - that is how a windowed pull learns
	// its peer ran out.
	resp, err := ask(5, 8)
	if err != nil {
		t.Fatalf("a range extending past the head was refused: %v", err)
	}
	if len(resp.Units) != 2 {
		t.Fatalf("heights 5..6 of a height-6 chain served %d units", len(resp.Units))
	}
	// Ordering pin: the bound is decided BEFORE the height lookup and any
	// allocation, so a range that is both oversized and future-named comes
	// back as the BOUND error.
	if _, err := ask(7, math.MaxUint64); !errors.Is(err, ErrRangeTooBig) {
		t.Fatalf("an oversized future range gave %v, want the bound error first", err)
	}
}

// TestSyncerServesTheEncodedRangeItWasAskedFor: Answer returns decodeable
// certified units whose blocks equal BlockAt for the heights asked, each
// certificate re-tallying to quorum for the served block through the
// ordinary vote path.
func TestSyncerServesTheEncodedRangeItWasAskedFor(t *testing.T) {
	f := newCertServeFixture(t, 6)
	resp, err := f.server.Answer(syncSignReq(t, f.pullerKey, 2, 5))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Units) != 4 {
		t.Fatalf("served %d units for heights 2..5", len(resp.Units))
	}
	for i, u := range resp.Units {
		blk, err := types.DecodeBlock(u.Block)
		if err != nil {
			t.Fatalf("served bytes for block %d do not decode: %v", i, err)
		}
		want, err := f.chain.BlockAt(uint64(2 + i))
		if err != nil {
			t.Fatal(err)
		}
		if blk.ID() != want.ID() {
			gotID, wantID := blk.ID(), want.ID()
			t.Fatalf("served block at height %d is %x, the chain holds %x", 2+i, gotID[:8], wantID[:8])
		}
		// The certificate must be present and must re-tally against the
		// served block through the ordinary vote path.
		if len(u.Votes) == 0 {
			t.Fatalf("served block %d carries no certificate", 2+i)
		}
		vs := certVoteSet(f.chain.Genesis().Validators, blk.Header.Height, u.Round)
		for _, raw := range u.Votes {
			v, err := DecodeVote(raw)
			if err != nil {
				t.Fatalf("served certificate vote does not decode: %v", err)
			}
			if _, err := vs.Add(v); err != nil {
				t.Fatalf("served certificate vote does not tally: %v", err)
			}
		}
		if !vs.HasQuorum(blk.ID()) {
			t.Fatal("the served certificate does not prove a quorum for the served block")
		}
	}
}

// TestSyncerRefusesUnsignedOrForeignRequests: the request-side
// authentication, unchanged by the certificate.
func TestSyncerRefusesUnsignedOrForeignRequests(t *testing.T) {
	f := newCertServeFixture(t, 2)
	ask := func(req *wire.BlockSyncReq) error {
		_, err := f.server.Answer(req)
		return err
	}

	// Unsigned.
	req := syncSignReq(t, f.pullerKey, 1, 2)
	req.Sig = nil
	if !errors.Is(ask(req), ErrBadSyncAuth) {
		t.Fatalf("an unsigned request gave %v, want ErrBadSyncAuth", ask(req))
	}
	// Signed by a key outside the validator set.
	_, strangerPriv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	req = syncSignReq(t, strangerPriv, 1, 2)
	if !errors.Is(ask(req), ErrBadSyncAuth) {
		t.Fatalf("a stranger's request gave %v, want ErrBadSyncAuth", ask(req))
	}
	// A real signature over different terms (replay bait): sign one range,
	// present another.
	req = syncSignReq(t, f.pullerKey, 1, 2)
	req.To = 2
	req.From = 2
	if !errors.Is(ask(req), ErrBadSyncAuth) {
		t.Fatalf("a re-ranged signature gave %v, want ErrBadSyncAuth", ask(req))
	}
	// And the frame layer: a frame that does not decode, and a frame whose
	// range is refused, both send nothing.
	if _, ok := f.server.Handle([]byte{0x01}); ok {
		t.Fatal("Handle answered a frame that is not a BLOCK_SYNC request")
	}
	if _, ok := f.server.Handle(wire.EncodeBlockSyncReq(func() *wire.BlockSyncReq {
		r := syncSignReq(t, f.pullerKey, 1, 2)
		r.Sig = nil
		return r
	}())); ok {
		t.Fatal("Handle answered an unauthenticated request instead of refusing it")
	}
}

// TestACaughtUpNodeServesItsCertificatesOnward: the member that caught up by
// pulling is able to catch the NEXT member up - it serves the very
// certificates it was adopted on, so catch-up chains instead of dead-ending
// at whichever validators were always live.
func TestACaughtUpNodeServesItsCertificatesOnward(t *testing.T) {
	c := newCommitteeRig(t, 3, 2)
	defer c.halt()
	c.rig.start()
	if err := c.pull.PullAndAdopt(1); err != nil {
		t.Fatalf("the middle node's catch-up failed: %v", err)
	}
	c.assertConverged("after the middle node's catch-up")

	// The next node: chain at genesis, a member's key, pointing at the node
	// that just caught up - which must now ANSWER from its own archive.
	c.halt() // rewire and extend the net only while the pump is off

	farCh, err := chain.Open(c.g, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	farEP := c.rig.addPeer("far")
	far := NewSyncer(farCh, pumpBound{r: c.rig, inner: farEP}, testCommitteeKey(2))
	far.Peer = syncPullerID
	// The caught-up member answers as seat 3 (syncPullerID is v3); pin the
	// answer to that identity, and deliver it before the wait (F1/F5).
	far.Expect = c.g.Validators[3].PubKey
	far.afterSend = func() { c.rig.settle() }
	farEP.OnMessage(routeResp(far, nil))
	// Serve from the caught-up member: its server role is its own syncer.
	pullEP := c.rig.eps[syncPullerID]
	pullEP.OnMessage(func(m transport.Message) {
		if len(m.Data) > 0 && m.Data[0] == byte(wire.MsgBlockSyncReq) {
			if resp, ok := c.pull.Handle(m.Data); ok {
				_ = pullEP.Send(m.From, resp)
			}
		}
	})
	c.rig.start()

	if err := far.PullAndAdopt(1); err != nil {
		t.Fatalf("the far node's catch-up through the caught-up member failed: %v", err)
	}
	if farCh.Height() != c.pullCh.Height() {
		t.Fatalf("the far node is at height %d, the caught-up member at %d", farCh.Height(), c.pullCh.Height())
	}
	if farCh.Head().ID() != c.pullCh.Head().ID() {
		t.Fatal("the far node's head does not match the caught-up member's head")
	}
}

// ------------------------------------------------- C-4/C-5 correlation pins

// TestReceiveCorrelatesNonceAndSender is the C-5 proof at the boundary where a
// response enters the syncer: only the asked peer's correctly SIGNED answer to
// the request actually in flight is filed. Four wrong frames are built from
// the same certified bytes and each is dropped for its own reason:
//
//   - the asked peer with the WRONG nonce (a late reply to another request);
//   - a peer that was NOT asked with the RIGHT nonce;
//   - the asked peer with the right nonce but an UNSIGNED envelope (the relay
//     stranger's forged answer, round 7 F1);
//   - any frame at all while no request is in flight.
func TestReceiveCorrelatesNonceAndSender(t *testing.T) {
	f := newCertServeFixture(t, 2)
	s := f.server

	// Construct the in-flight state: request nonce 7 was sent to peer v0,
	// expecting member 0's signed answer. (The pull registers exactly this
	// state before Send.)
	req := &wire.BlockSyncReq{From: 1, To: 1, Nonce: 7, Requester: f.pullerKey.Public().(ed25519PublicKey)}
	ch := make(chan *wire.BlockSyncResp, 1)
	s.reqMu.Lock()
	s.waiting = &pendingReply{req: req, peer: "v0", expect: committeePub(0), ch: ch}
	s.reqMu.Unlock()

	unit := wire.BlockSyncUnit{Block: []byte{0x01}}
	// wrongNonce is a member-0-signed answer to a DIFFERENT request (nonce 6):
	// the only thing wrong with it is its correlation.
	wrongNonce := signedResp(testCommitteeKey(0),
		&wire.BlockSyncReq{From: 1, To: 1, Nonce: 6, Requester: req.Requester}, unit)
	// rightReq is the honest answer to the in-flight request.
	rightReq := signedResp(testCommitteeKey(0), req, unit)
	// forged is what the relay stranger can build: the right nonce, no key.
	forged := unitResp(7, unit)

	// (a) The asked peer, the wrong nonce: a reply to a request that is not
	// the one in flight. Consuming it would be the C-5 defect - a retry
	// answered by the previous attempt's frame.
	s.Receive("v0", wrongNonce)
	if got := len(ch); got != 0 {
		t.Fatalf("the asked peer's nonce-6 reply was consumed as the answer to the nonce-7 request: a reply answered a request it was not for")
	}

	// (b) A peer that was never asked, with the matching nonce and a valid
	// signature: it knows the nonce (the request travels the wire), but it is
	// not the transport the pull chose, so it cannot answer.
	s.Receive("v9", rightReq)
	if got := len(ch); got != 0 {
		t.Fatalf("a reply from peer v9 was consumed while the pull was waiting on v0: a peer that was not asked answered")
	}

	// (c) The asked peer, the matching nonce, but no responder signature: the
	// relay stranger's forged answer. It must not be consumed (round 7, F1).
	s.Receive("v0", forged)
	if got := len(ch); got != 0 {
		t.Fatalf("an unsigned forged reply with the right nonce was consumed while the pull waited: a stranger with no committee key answered a request")
	}

	// (d) The asked peer, the matching nonce, signed by the member the pull
	// did NOT select (member 1 while member 0 was chosen): the relay name
	// cannot attribute it, the signature can, and it is the wrong member.
	s.Receive("v0", signedResp(testCommitteeKey(1), req, unit))
	if got := len(ch); got != 0 {
		t.Fatalf("a reply signed by a member other than the selected one was consumed: the responder pin did not hold")
	}

	// (e) The asked peer with the matching nonce and the selected member's
	// signature: filed.
	s.Receive("v0", rightReq)
	if got := len(ch); got != 1 {
		t.Fatalf("the asked peer's matching signed reply was not filed (%d filed)", got)
	}

	// (f) No request in flight: an otherwise perfect reply answers nothing.
	<-ch
	s.reqMu.Lock()
	s.waiting = nil
	s.reqMu.Unlock()
	s.Receive("v0", rightReq)
	if got := len(ch); got != 0 {
		t.Fatalf("a reply was filed while no request was in flight")
	}
}

// -------------------------------------------------- F1 relay-answer proofs

// TestARelayStrangersForgedAnswerDoesNotCrowdOutTheHonestOne is the reviewer's
// attack in the relay's own shape (round 7, F1). The pull sends ONE request to
// the shared transport name "relay:<addr>"; the endpoint behind that name
// first emits the stranger's forged answer (the right nonce, seen in the
// clear, but no committee key and no units) and then the selected member's
// properly signed answer. Pre-fix the forged frame won the one-slot reply
// channel, the pull read "caught up" and the honest answer was discarded.
// Post-fix the forged frame is refused at the envelope, so the honest answer
// is filed and its certified block is adopted.
func TestARelayStrangersForgedAnswerDoesNotCrowdOutTheHonestOne(t *testing.T) {
	const relayName = transport.PeerID("relay:198.51.100.9:9000")

	g := fourValGenesis(t)
	pullCh, err := chain.Open(g, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rig := newSyncNet(t, 13, 0, 0)
	pullEP := rig.addPeer("pull")
	relayEP := rig.addPeer(string(relayName))
	pull := NewSyncer(pullCh, pumpBound{r: rig, inner: pullEP}, testCommitteeKey(2))
	pull.Peer = relayName
	pull.Expect = committeePub(0)
	pull.afterSend = func() { rig.settle() }
	pullEP.OnMessage(routeResp(pull, nil))

	blk, err := pullCh.Build(testCommitteeKey(0), nil, pullCh.Head().Header.Timestamp+1)
	if err != nil {
		t.Fatal(err)
	}
	cert := quorumCertFor(t, blk, 1, 3)
	unit := wire.BlockSyncUnit{Block: blk.Encode(), Round: 3, Votes: encodedVotes(cert)}

	relayEP.OnMessage(func(m transport.Message) {
		req, err := wire.DecodeBlockSyncReq(m.Data)
		if err != nil {
			return
		}
		// The stranger first: the right nonce, no key, NOTHING to serve.
		_ = relayEP.Send(m.From, unitResp(req.Nonce))
		// The honest selected member second: the certified block, signed.
		_ = relayEP.Send(m.From, signedResp(testCommitteeKey(0), req, unit))
	})

	rig.start()
	defer rig.halt()
	if err := pull.PullAndAdopt(1); err != nil {
		t.Fatalf("the honest relay answer was refused: %v", err)
	}
	if pullCh.Height() != 1 || pullCh.Head().ID() != blk.ID() {
		t.Fatalf("the honest relay answer was not adopted (height %d): the stranger's forged empty answer crowded it out", pullCh.Height())
	}
}

// TestARelayStrangersForgedAnswerAloneIsRefused: with ONLY the forged answer
// on the wire, the pull reads silence (nothing adopted, no error) - the
// stranger cannot make the chain move, and the pull does not consume the frame
// as an answer. Paired with the crowd-out test above, this pins both
// directions of F1 at the relay boundary.
func TestARelayStrangersForgedAnswerAloneIsRefused(t *testing.T) {
	const relayName = transport.PeerID("relay:198.51.100.9:9000")

	g := fourValGenesis(t)
	pullCh, err := chain.Open(g, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rig := newSyncNet(t, 17, 0, 0)
	pullEP := rig.addPeer("pull")
	relayEP := rig.addPeer(string(relayName))
	pull := NewSyncer(pullCh, pumpBound{r: rig, inner: pullEP}, testCommitteeKey(2))
	pull.Peer = relayName
	pull.Expect = committeePub(0)
	pull.afterSend = func() { rig.settle() }
	pull.ReplyWait = time.Millisecond // the forged frame is already drained; nothing else exists to wait for
	pullEP.OnMessage(routeResp(pull, nil))

	blk, err := pullCh.Build(testCommitteeKey(0), nil, pullCh.Head().Header.Timestamp+1)
	if err != nil {
		t.Fatal(err)
	}
	unit := wire.BlockSyncUnit{Block: blk.Encode(), Round: 3, Votes: encodedVotes(quorumCertFor(t, blk, 1, 3))}

	relayEP.OnMessage(func(m transport.Message) {
		req, err := wire.DecodeBlockSyncReq(m.Data)
		if err != nil {
			return
		}
		// Only the forged envelope: right nonce, no key, and a genuine
		// certificate - so nothing but the signature check can refuse it.
		_ = relayEP.Send(m.From, unitResp(req.Nonce, unit))
	})

	rig.start()
	defer rig.halt()
	height, headID := pullCh.Height(), pullCh.Head().ID()
	if err := pull.PullAndAdopt(1); err != nil {
		t.Fatalf("the forged answer produced an error (%v); it must read as silence", err)
	}
	if pullCh.Height() != height || pullCh.Head().ID() != headID {
		t.Fatalf("the chain moved on a stranger's forged answer (height %d)", pullCh.Height())
	}
}

// TestTheAnswererSignsAsItsMemberIdentity is the answer half of F1: Answer's
// envelope carries the responder key and a signature that verifies against
// the request and the served bytes, and the puller's pin refuses the same
// envelope when a DIFFERENT member was selected.
func TestTheAnswererSignsAsItsMemberIdentity(t *testing.T) {
	f := newCertServeFixture(t, 2)
	req := syncSignReq(t, f.pullerKey, 1, 1)
	resp, err := f.server.Answer(req)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Responder) == 0 || len(resp.Sig) == 0 {
		t.Fatal("the answer carried no responder key or signature")
	}
	if err := verifySyncResp(req, resp, committeePub(1), f.chain.Genesis().Validators); err != nil {
		t.Fatalf("the answer did not verify as the member that produced it: %v", err)
	}
	if err := verifySyncResp(req, resp, committeePub(0), f.chain.Genesis().Validators); !errors.Is(err, ErrBadSyncRespAuth) {
		t.Fatalf("the answer verified against a DIFFERENT selected member (%v): the responder pin did not hold", err)
	}
}

// TestALateReplyAfterARetryAnswersNothing is the timing half of the C-5 proof,
// over the real (asynchronous) sim transport: the first window's request is
// withheld past ReplyWait, the retry goes out with a FRESH nonce, and only
// then does the first request's answer arrive. It must not be consumed as the
// retry's answer, and the certified block it carries must not be adopted.
func TestALateReplyAfterARetryAnswersNothing(t *testing.T) {
	w := newCertWorld(t)
	defer w.rig.halt()

	blk, err := w.pullCh.Build(testCommitteeKey(0), nil, w.pullCh.Head().Header.Timestamp+1)
	if err != nil {
		t.Fatal(err)
	}
	unit := wire.BlockSyncUnit{Block: blk.Encode(), Round: 3, Votes: encodedVotes(quorumCertFor(t, blk, 1, 3))}

	var firstNonce uint64
	calls := 0
	w.answer = func(req *wire.BlockSyncReq) []byte {
		calls++
		if calls == 1 {
			firstNonce = req.Nonce
			return nil // withhold the first answer, forcing the pull's timeout
		}
		// The retry is answered by the FIRST request's frame, arriving late:
		// a valid signature by member 3 over a request whose nonce is the
		// first request's, so the ONLY reason to refuse it is correlation.
		return signedResp(testCommitteeKey(3),
			&wire.BlockSyncReq{From: req.From, To: req.To, Nonce: firstNonce, Requester: req.Requester}, unit)
	}
	// The answer is delivered by afterSend (settle), not raced against
	// ReplyWait; the withheld first window still reads silence because no
	// response exists for it (F5).
	w.pull.ReplyWait = 20 * time.Millisecond
	w.rig.start()
	height, headID := w.pullCh.Height(), w.pullCh.Head().ID()

	if err := w.pull.PullAndAdopt(1); err != nil {
		t.Fatalf("the withheld first pull errored instead of reading silence: %v", err)
	}
	if err := w.pull.PullAndAdopt(1); err != nil {
		t.Fatalf("the retry errored: %v", err)
	}
	w.halt()
	w.assertUnchanged("after a late reply to an earlier request was refused", height, headID)
	if calls != 2 {
		t.Fatalf("%d requests reached the peer, want 2 (the withheld original and the retry)", calls)
	}
}

// TestPullRefusesAUnitOutsideTheRequestedWindow pins the range half of C-5: a
// response may carry only blocks the request named. The served block here is
// well-formed and one height past the window; a pull that ignored the range
// would refuse it later for its missing votes, so the RANGE must be the reason
// it dies - the distinction the mutant moves.
func TestPullRefusesAUnitOutsideTheRequestedWindow(t *testing.T) {
	w := newCertWorld(t)
	defer w.rig.halt()

	far, err := w.pullCh.Build(testCommitteeKey(0), nil, w.pullCh.Head().Header.Timestamp+1)
	if err != nil {
		t.Fatal(err)
	}
	far.Header.Height = w.pull.MaxBlocksPerResponse + 1 // one past the window [1, MaxBlocksPerResponse]
	w.answer = func(req *wire.BlockSyncReq) []byte {
		return signedResp(testCommitteeKey(3), req, wire.BlockSyncUnit{Block: far.Encode(), Round: 1})
	}
	// The out-of-window unit is delivered by afterSend/settle BEFORE the wait,
	// so ErrSyncUnitOutOfRange is the reason the pull stops; the ReplyWait
	// value cannot flip the outcome and a slow runner cannot turn it into
	// silence (F5).
	w.pull.ReplyWait = 100 * time.Millisecond
	w.rig.start()
	height, headID := w.pullCh.Height(), w.pullCh.Head().ID()

	err = w.pull.PullAndAdopt(1)
	if !errors.Is(err, ErrSyncUnitOutOfRange) {
		t.Fatalf("an out-of-window unit gave (%v), want ErrSyncUnitOutOfRange", err)
	}
	w.halt()
	w.assertUnchanged("after the out-of-window unit was refused", height, headID)
}

// TestSyncerRateLimitsARequester is the C-4 rate-limit pin: a requester gets a
// bounded number of answers per window, and the bucket is per requester KEY -
// one flooder cannot spend an honest peer's budget.
func TestSyncerRateLimitsARequester(t *testing.T) {
	f := newCertServeFixture(t, 2)
	f.server.RateLimit = 3
	f.server.RateWindow = time.Minute // never resets mid-test

	ask := func(priv ed25519PrivateKey) error {
		_, err := f.server.Answer(syncSignReq(t, priv, 1, 1))
		return err
	}
	for i := 0; i < 3; i++ {
		if err := ask(f.pullerKey); err != nil {
			t.Fatalf("request %d inside the per-requester budget was refused: %v", i+1, err)
		}
	}
	if err := ask(f.pullerKey); !errors.Is(err, ErrSyncRateLimited) {
		t.Fatalf("a request over the per-requester budget gave (%v), want ErrSyncRateLimited", err)
	}
	if err := ask(testCommitteeKey(1)); err != nil {
		t.Fatalf("a DIFFERENT requester was refused because another had spent its budget: %v", err)
	}
}

// TestSyncerRefusesAReplayedRequest is the C-4 replay pin: the same signed
// request served once cannot be served again while it is fresh, so one captured
// frame cannot make the node repeat the full answer work.
func TestSyncerRefusesAReplayedRequest(t *testing.T) {
	f := newCertServeFixture(t, 2)
	req := syncSignReq(t, f.pullerKey, 1, 1)
	if _, err := f.server.Answer(req); err != nil {
		t.Fatalf("the first request was refused: %v", err)
	}
	if _, err := f.server.Answer(req); !errors.Is(err, ErrSyncReplayed) {
		t.Fatalf("the same signed request served a second time gave (%v), want ErrSyncReplayed", err)
	}
}

// TestTheAnswererEchoesTheRequestNonce pins the wire half of the correlation:
// Answer's response carries the request's nonce, so the puller's Receive has
// something to match. A response with no echoed nonce correlates with nothing.
func TestTheAnswererEchoesTheRequestNonce(t *testing.T) {
	f := newCertServeFixture(t, 2)
	req := syncSignReq(t, f.pullerKey, 1, 1)
	resp, err := f.server.Answer(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Nonce != req.Nonce {
		t.Fatalf("the answer echoed nonce %d, want the request's %d", resp.Nonce, req.Nonce)
	}
}

// TestCertificatesSurviveARestartAndAreServedAgain is the C-7 pin, end to end:
// a committee member commits blocks with real quorum certificates, the node is
// CLOSED, and a process that shares nothing with it - a reopened chain and a
// fresh syncer - still serves the certificate for a block it adopted before it
// restarted. Before the fix the archive was a map in that process's memory, so
// a rolling restart of the committee left nobody able to serve the history
// committed before the restarts, and a lagging or new validator could never
// catch up on those heights.
func TestCertificatesSurviveARestartAndAreServedAgain(t *testing.T) {
	dir := t.TempDir()
	g := fourValGenesis(t)

	ch, err := chain.Open(g, dir)
	if err != nil {
		t.Fatal(err)
	}
	const certRound = 3
	var committed []*types.Block
	for h := uint64(1); h <= 2; h++ {
		b, err := ch.Build(testCommitteeKey(1), nil, ch.Head().Header.Timestamp+1)
		if err != nil {
			t.Fatal(err)
		}
		if err := ch.Append(b); err != nil {
			t.Fatal(err)
		}
		// The certificate goes to the store's certificate log - the same
		// crash-tolerant directory the block it certifies lives in - and the
		// process's own archive is not consulted again afterwards.
		NewSyncer(ch, nil, testCommitteeKey(1)).RecordCommit(h, certRound, quorumCertFor(t, b, h, certRound))
		committed = append(committed, b)
	}
	if _, ok := ch.CertAt(1); !ok {
		t.Fatal("the certificate for height 1 did not reach the store's log")
	}
	if err := ch.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := chain.Open(g, dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	if reopened.Height() != 2 {
		t.Fatalf("replayed height = %d, want 2", reopened.Height())
	}

	// A syncer built AFTER the restart, sharing nothing with the one that
	// recorded the certificate, answers for the earlier height.
	srv := NewSyncer(reopened, nil, testCommitteeKey(1))
	resp, err := srv.Answer(syncSignReq(t, testCommitteeKey(0), 1, 1))
	if err != nil {
		t.Fatalf("a restarted validator could not serve a certificate it holds: %v", err)
	}
	if len(resp.Units) != 1 {
		t.Fatalf("the restarted answer carried %d units, want 1", len(resp.Units))
	}
	unit := resp.Units[0]
	if unit.Round != certRound {
		t.Fatalf("the served certificate names round %d, want %d", unit.Round, certRound)
	}
	if len(unit.Votes) == 0 {
		t.Fatal("the served unit carries no precommit votes at all")
	}
	want := committed[0].ID()
	for i, raw := range unit.Votes {
		v, err := DecodeVote(raw)
		if err != nil {
			t.Fatalf("served certificate vote %d does not decode: %v", i+1, err)
		}
		if err := v.Verify(); err != nil {
			t.Fatalf("served certificate vote %d does not verify: %v", i+1, err)
		}
		if v.BlockID != want {
			t.Fatalf("the restarted node served a certificate for block %x, not the adopted block %x", v.BlockID[:8], want[:8])
		}
	}
}

// TestAwaitReplyHonoursTheInjectedWait pins the T-2 seam contract: when
// WaitReply is set, awaitReply calls it with the RESOLVED ReplyWait and
// returns its result verbatim, so a harness whose transport runs on a virtual
// clock can supply the pull's deadline itself. It also pins the default the
// seam receives when ReplyWait is left at zero, so the two cannot drift.
//
// Killing mutant (compile-confirmed, behaviour-changing): delete the
// `if s.WaitReply != nil` branch from awaitReply. The seam is then never
// called, gotWait stays zero and the test fails on the first assertion -
// while the production wall-clock path still compiles and works, which is
// exactly what makes the mutant a silent regression rather than a build
// error. (The simnet virtual implementation this seam exists for is proven by
// the identical-blocks-through-CatchUp test and the repeated -race runs in
// the round-13 report.)
func TestAwaitReplyHonoursTheInjectedWait(t *testing.T) {
	s := &Syncer{ReplyWait: 3 * time.Second}
	canned := &wire.BlockSyncResp{}
	var gotWait time.Duration
	var calls int
	s.WaitReply = func(_ <-chan *wire.BlockSyncResp, wait time.Duration) *wire.BlockSyncResp {
		calls++
		gotWait = wait
		return canned
	}
	ch := make(chan *wire.BlockSyncResp, 1)
	if got := s.awaitReply(ch); got != canned {
		t.Fatalf("awaitReply returned the seam's result as %p, want %p", got, canned)
	}
	if calls != 1 || gotWait != 3*time.Second {
		t.Fatalf("the seam was called %d time(s) with wait %v, want 1 call with 3s", calls, gotWait)
	}

	// Zero ReplyWait must reach the seam as the documented default, never as
	// a zero deadline that would reinstall the synchronous read.
	s.ReplyWait = 0
	s.WaitReply = func(_ <-chan *wire.BlockSyncResp, wait time.Duration) *wire.BlockSyncResp {
		gotWait = wait
		return nil
	}
	if got := s.awaitReply(make(chan *wire.BlockSyncResp, 1)); got != nil {
		t.Fatalf("the seam's nil (silence) was returned as %p, want nil", got)
	}
	if gotWait != DefaultReplyWait {
		t.Fatalf("a zero ReplyWait reached the seam as %v, want DefaultReplyWait %v", gotWait, DefaultReplyWait)
	}
}
