package devnet

// tcpnode.go is the networked validator of M4 Task 6: one process running the
// real consensus stack over a real transport. The CLI's `--peers`/`--relay`
// path and the in-process TCP integration test drive exactly this code, which
// is the point of the boundary the M3/M4 milestones kept: the engine's round
// protocol, the quorum rule and the certificate gate are untouched - the
// NETWORK is.
//
// Structure of one validator:
//
//   - a tcp.TcpTransport (the shipped socket transport), its listener optional
//     and its dial list given by the caller (the CLI joins --peers and
//     --relay, dialling peers directly and the relay through ConnectRelay:
//     a relay connection must NOT run the ID handshake - the relay forwards
//     everyone's frames, so "the first frame" is stranger-selectable, which
//     is exactly the N-1 defect);
//   - a consensus.Syncer over that transport, doing both catch-up halves:
//     ANSWERING (the router feeds it BLOCK_SYNC requests, it serves certified
//     heights) and PULLING (the wave loop pulls from the tallest peer);
//   - a consensus.MessageRouter splitting consensus frames from wire frames.
//     The two message unions share the numeric range 1-3, so routing is by
//     VERIFIED decode, never by a bare tag comparison (see the router's doc);
//   - a consensus.Driver whose OnMessage the router hands consensus frames
//     to, and whose commit witness archives every commit's certificate
//     (Design Decision 8) so the chain this node holds is pullable by a peer;
//   - the loops: the tick loop (the driver's clock at TickEvery), the wave
//     loop (HELLO heights out, catch-up pull in), and the bounded pool of
//     BLOCK_SYNC workers the router hands requests to (audit C-4), so serving
//     a request never runs on the transport's dispatch goroutine.
//
// Two concurrency rules keep the engine's single-threaded model intact over
// sockets, which the in-process simulator never had to care about:
//
//   - ONE mutex (mu) serialises every driver operation - the tick loop's
//     Tick and the reader goroutines' message dispatch through route. The
//     socket transport may deliver from many readers; the engine must never
//     be re-entered mid-step, or state transitions depend on goroutine
//     scheduling rather than message order. The sync workers are outside
//     this rule by construction: they read the chain and the syncer archive
//     and never touch the engine.
//   - The pull NEVER holds mu. It touches only the chain (whose own lock
//     serialises Append against the driver's) and the syncer (whose one
//     in-flight request is the pull's). The interleavings a commit and an
//     adoption can form are all safe - a collision at one height fails the
//     loser's Append against the chain, which is the gate, not a bug - with
//     ONE consequence handled explicitly: after a pull adopts anything, the
//     driver is REBUILT (rebuildDriver), because its engine still judges a
//     height the chain has already decided. A stale engine keeps round-looping
//     forever at a height nobody is at; the rebuild is the rejoin.

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/consensus"
	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/mempool"
	"github.com/cti97/b10coincom/internal/simnet"
	"github.com/cti97/b10coincom/internal/transport"
	"github.com/cti97/b10coincom/internal/transport/tcp"
	"github.com/cti97/b10coincom/internal/types"
	"github.com/cti97/b10coincom/internal/wire"
)

const (
	// Round timeouts in WALL milliseconds - the same defaults every simnet
	// scenario drives, now over sockets. A healthy commit completes in one
	// round; escalation is the timeout ladder.
	consensusTimeoutBaseMS = int64(200)
	consensusTimeoutStepMS = int64(100)

	// defaultTickEvery is the driver's tick cadence: well inside one round's
	// timeout, so a proposal's propose phase runs before its timer fires.
	defaultTickEvery = 50 * time.Millisecond
	// defaultWaveEvery is the HELLO/catch-up cadence. Peer heights travel as
	// signed hints; a node that falls behind learns within one wave and
	// pulls, so this is the reconnect-to-consensus latency, not a
	// correctness parameter.
	defaultWaveEvery = 500 * time.Millisecond

	// networkedMempoolCapacity is each networked validator's pool. The driver
	// takes from it for proposals; the node's RPC fills it.
	networkedMempoolCapacity = 1000

	// syncWorkers and syncQueueDepth bound the async BLOCK_SYNC server (audit
	// C-4): requests are served on their own goroutines so a slow answer
	// cannot hold the transport's dispatch lock, the pool is small so a flood
	// cannot spend the node's CPU on serving, and the queue is bounded so the
	// work waiting to be served has a ceiling. A full queue is a dropped
	// request - the asker reads silence and retries on a later wave.
	syncWorkers    = 2
	syncQueueDepth = 16

	// peerHeightTTL is how many waves a HELLO's height stays usable without
	// being refreshed. A peer that vanished stops being selected within this
	// many waves rather than holding its old entry forever (audit C-6).
	peerHeightTTL = 4
	// peerDemoteWaves is how many waves a peer is skipped after a pull from
	// it failed to substantiate the height it announced. This is the rotation
	// that stops one lying member from monopolising every catch-up wave
	// (audit C-6).
	peerDemoteWaves = 4
)

// ValidatorConfig configures one networked validator. It has two modes:
//
//   - GENESIS-FILE MODE (real keys): Genesis names the shared committee
//     document (public keys) and Key is THIS validator's held private key.
//     The seat is the position its public key occupies in that document, and
//     a key that is not in it REFUSES TO START (audit A-1): silently signing
//     as a seat the key does not hold is the exact failure the committee
//     file exists to prevent.
//   - FIXTURE MODE (devnet only): Genesis nil. The committee is the derived
//     simnet fixture (simnet.Committee(Validators), chain b10coin-simnet-N)
//     and the seat key is derived from the Index — which means every member
//     key is PUBLICLY DERIVABLE by anyone with the repository. This mode
//     exists for local development and the acceptance runs; callers must
//     mark it loudly (the CLI prints a warning) and never point it at a
//     network whose reach extends beyond the operator's own machines.
//
// Seats must be distinct - two processes claiming one seat are refused each
// other's connections by the transport's self-connection guard.
type ValidatorConfig struct {
	// Dir holds this validator's chain (its own directory; like simnet, one
	// directory per member).
	Dir string
	// Genesis is the shared committee document (nil: fixture mode). It
	// replaces the committee-size flag as the committee's source of truth.
	Genesis *genesis.Genesis
	// Key is this validator's Ed25519 private key. Required in genesis-file
	// mode; ignored (derived instead) in fixture mode.
	Key ed25519.PrivateKey
	// Index is this node's seat in the fixture committee (fixture mode
	// only; in genesis-file mode the seat is derived from the key and a
	// nonzero value here is refused as a contradiction).
	Index int
	// Validators is the fixture committee size (fixture mode only).
	Validators int
	// Listen is the P2P listen address; empty means "dial only". A node
	// behind NAT with a relay has no listener by design.
	Listen string
	// Relay is the relay address (or addresses) to dial. Each is maintained
	// through the transport's relay mode - no ID read, registered under
	// tcp.RelayPeerName(addr) - so a stranger's frames through the relay can
	// neither name the connection nor silence it (audit N-1). Kept separate
	// from the direct peer list because the two dial modes differ by
	// construction; an address given as both a peer and a relay keeps
	// whichever registration it got first.
	Relay []string
	// TickEvery is the driver's tick cadence (zero: defaultTickEvery).
	TickEvery time.Duration
	// WaveEvery is the HELLO/catch-up cadence (zero: defaultWaveEvery).
	WaveEvery time.Duration
}

// peerAttestation is what one peer's HELLO leaves behind (audit C-6): the
// height it last announced, the highest height a pull from it actually
// reached, whether any pull has proven it at all, the wave it was last
// refreshed in, and the wave until which selection skips it.
type peerAttestation struct {
	height        uint64 // latest announced height
	substantiated uint64 // highest height a pull from this peer reached
	proven        bool   // a pull from this peer has completed (successfully or not)
	seen          uint64 // wave of the latest HELLO
	demoted       uint64 // skip selection while demoted > the current wave
}

// Validator is one running networked validator.
type Validator struct {
	cfg   ValidatorConfig
	g     *genesis.Genesis
	ch    *chain.Chain
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
	pool  *mempool.Mempool
	sy    *consensus.Syncer
	rt    *consensus.MessageRouter
	ttp   *tcp.TcpTransport
	drvTP *driverTP
	cfgC  consensus.Config
	drv   *consensus.Driver

	// mu serialises every driver operation (see the package-level rules above).
	mu sync.Mutex

	// peerH is the state each peer's HELLO leaves behind, keyed by the
	// transport-level name. On a DIRECT link that name is the peer's own
	// handshake ID (forgeable - it is a routing key, not a proof). Through a
	// relay every frame arrives under the ONE fixed connection name
	// tcp.RelayPeerName(addr), which announces nothing about who is behind
	// it and is stable across reconnects (audit N-1: never derived from any
	// frame's bytes). Either way it is a signed hint only: it decides
	// whether to pull and from whom - nothing else.
	//
	// The state remembers more than the latest height (audit C-6): when the
	// announcement was last refreshed (so a vanished peer expires), how far a
	// pull from that peer ever substantiated (so an announcement above what
	// the peer can serve is capped for selection), and until when the peer is
	// demoted (so a peer whose pull proved nothing is rotated away from).
	peerHMu sync.Mutex
	peerH   map[transport.PeerID]*peerAttestation
	// wave counts catch-up waves. It advances once per maybeCatchUp, and is
	// the clock peerHeightTTL and peerDemoteWaves are measured in.
	wave uint64

	// pull is the catch-up pull (from a height, to the adopted head): the
	// syncer's PullAndAdopt unless a test installs a seam. Nil means
	// v.sy.PullAndAdopt.
	pull func(from uint64) error

	// syncQ and syncWG are the bounded async BLOCK_SYNC server (audit C-4):
	// the router hands requests here instead of serving them on the
	// transport's dispatch goroutine.
	syncQ       chan transport.Message
	syncWG      sync.WaitGroup
	syncDropped atomic.Uint64

	// adopted counts blocks brought in by catch-up pulls: the observable a
	// convergence test reads to prove the joiner ADOPTED rather than voted.
	adopted atomic.Uint64

	// closing gates the dispatch path: Close sets it (under mu, so a reader
	// goroutine already inside a driver operation finishes first), and every
	// route() afterwards refuses to touch the engine, the router or the
	// chain. This is the ordering that keeps a shutdown from tearing the
	// chain out from under a live dispatch - a socket transport's readers
	// exit only when their sockets die, which is AFTER Close has begun, and
	// the persisted-lock write a last dispatch would attempt against a
	// closed chain store panics (the panic is the persistence rule's, not
	// this bug's - the fix is to stop dispatching before closing).
	closing atomic.Bool

	// stop ends the loops; once closed, Close idempotence follows.
	stop     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
	closed   atomic.Bool
}

// driverTP is the Transport consensus.NewDriver registers over. Broadcast,
// Send, Peers and Close forward to the router (and through it to the real
// transport); OnMessage stores the driver's callback ATOMICALLY, because a
// rebuild happens under the driver mutex while reader goroutines may be
// mid-dispatch - the new callback and the frame in flight then pair up
// whichever way the atoms land, and both pairings are sound (a frame may be
// driven by the old engine for one message, exactly the stray vote a restart
// also emits).
type driverTP struct {
	inner transport.Transport
	msg   atomic.Pointer[func(transport.Message)]

	// voteMu guards the outgoing-vote heights recorded by Broadcast: the
	// observable a convergence test reads to tell "the returned member is
	// voting at the committee's current height again" from "a passenger
	// whose stale engine votes only at the height it parked at" - the
	// rebuild-skip failure shape leaves the chain healthy through pulls and
	// this node's vote-weight permanently out of the tally.
	voteMu      sync.Mutex
	voteHeights []uint64
}

func (l *driverTP) Broadcast(data []byte) error {
	if v, err := consensus.DecodeVote(data); err == nil {
		l.voteMu.Lock()
		l.voteHeights = append(l.voteHeights, v.Height)
		l.voteMu.Unlock()
	}
	return l.inner.Broadcast(data)
}
func (l *driverTP) Send(p transport.PeerID, d []byte) error { return l.inner.Send(p, d) }

// VotedHeights copies the recorded outgoing-vote heights.
func (l *driverTP) VotedHeights() []uint64 {
	l.voteMu.Lock()
	defer l.voteMu.Unlock()
	return append([]uint64(nil), l.voteHeights...)
}
func (l *driverTP) Peers() []transport.PeerID            { return l.inner.Peers() }
func (l *driverTP) Close() error                         { return l.inner.Close() }
func (l *driverTP) OnMessage(fn func(transport.Message)) { l.msg.Store(&fn) }

// StartValidator brings up one validator: opens its chain on the committee
// genesis, builds the consensus stack over a real TCP transport, and starts
// the tick and wave goroutines. It does NOT dial: call Connect once the
// committee's addresses are known (the CLI does it right after; the mesh
// tests collect every listener's port first).
func StartValidator(cfg ValidatorConfig) (*Validator, error) {
	var g *genesis.Genesis
	seat := cfg.Index
	switch {
	case cfg.Genesis != nil:
		// Genesis-file mode. Contradictory fixture fields are refused, not
		// ignored: a flag set alongside --genesis names a committee the file
		// did not choose, and a flag that lies about which committee runs is
		// worse than an error.
		if cfg.Index != 0 || cfg.Validators != 0 {
			return nil, fmt.Errorf("devnet: the committee comes from the genesis file; --index and --validators are fixture-mode flags and must not be set alongside it")
		}
		if cfg.Key == nil {
			return nil, fmt.Errorf("devnet: a genesis-file committee needs this validator's key: give a key file's private key (see b10coin keygen)")
		}
		g = cfg.Genesis
		pub, _ := cfg.Key.Public().(ed25519.PublicKey)
		found := genesis.SeatOfPubKey(g.Validators, pub)
		if found < 0 {
			// THE refusal the audit asked for: a key outside the committee
			// must not sign as any seat, and there is no seat-zero default
			// to fall back to. Say what was checked and what fixes it.
			return nil, fmt.Errorf("devnet: refusing to start: this validator's public key (%x) is not listed in the committee's genesis (%d seats named); a member key must be generated per machine (b10coin keygen) and its public key added to the file every validator shares",
				pub, len(g.Validators))
		}
		seat = found
		// Normalise the config so the seat reporting (Seat) reflects the
		// DERIVED seat, not the fixture flag that was correctly zero.
		cfg.Index = seat
	case cfg.Validators >= 1 && cfg.Validators <= 255 && cfg.Index >= 0 && cfg.Index < cfg.Validators:
		// Fixture mode, as before M4 A-1: derived committee, derived keys.
		g = simnet.Committee(cfg.Validators)
	default:
		return nil, fmt.Errorf("devnet: fixture committee size must be 1..255 and the seat in range, got size %d seat %d", cfg.Validators, cfg.Index)
	}
	n := len(g.Validators)
	if cfg.TickEvery <= 0 {
		cfg.TickEvery = defaultTickEvery
	}
	if cfg.WaveEvery <= 0 {
		cfg.WaveEvery = defaultWaveEvery
	}

	priv := cfg.Key
	if priv == nil {
		priv = simnet.ValidatorKey(seat)
	}
	pub, _ := priv.Public().(ed25519.PublicKey)
	// The belt over the seat selection: whatever mode chose the key, the
	// engine signs with the key at this committee POSITION, so the position's
	// listed public key must be this key's. (In fixture mode the derived key
	// trivially matches; in genesis-file mode the seat was found BY the key,
	// so this can only fire on a constructed-by-hand genesis. It is here so
	// that no future seat-selection path can ever pair a position with a
	// different key silently.)
	if n <= seat {
		return nil, fmt.Errorf("devnet: committee seat %d out of range 0..%d", seat, n-1)
	}
	if string(g.Validators[seat].PubKey) != string(pub) {
		return nil, fmt.Errorf("devnet: committee seat %d holds a key that is not this validator's", seat)
	}

	// The committee's power cap: the spec's 1/4 for four or more members,
	// 1/1 below (small fixtures cannot satisfy 1/4). Sized by the committee
	// that actually runs, whatever named it.
	capNum, capDen := uint64(1), uint64(4)
	if n < 4 {
		capNum, capDen = 1, 1
	}
	ccfg := consensus.Config{
		Committee:   g.Validators,
		TimeoutBase: consensusTimeoutBaseMS,
		TimeoutStep: consensusTimeoutStepMS,
		PowerCapNum: capNum, PowerCapDen: capDen,
	}
	if err := ccfg.Validate(); err != nil {
		return nil, err
	}

	ch, err := chain.Open(g, cfg.Dir)
	if err != nil {
		return nil, err
	}
	tp, err := tcp.New(tcp.Options{LocalID: transport.PeerID(fmt.Sprintf("v%d", cfg.Index))})
	if err != nil {
		_ = ch.Close()
		return nil, err
	}
	if cfg.Listen != "" {
		if err := tp.Listen(cfg.Listen); err != nil {
			_ = tp.Close()
			_ = ch.Close()
			return nil, fmt.Errorf("devnet: P2P listen on %s: %w", cfg.Listen, err)
		}
	}

	pool := mempool.New(networkedMempoolCapacity)
	sy := consensus.NewSyncer(ch, tp, priv)
	rt := consensus.NewMessageRouter(sy)
	rt.SendReply = tp.Send
	// The driver sees the DRIVER transport (sends go straight to tcp; the
	// OnMessage registration is swallowed into the atomic slot route()
	// invokes), never the raw transport, or NewDriver's registration would
	// overwrite the router's.
	dtp := &driverTP{inner: tp}
	drv := consensus.NewDriver(ccfg, ch, priv, dtp, pool)
	// CommitWitness: every commit this node makes is archived with its
	// precommit votes, so the chain it holds is pullable by a catching-up
	// peer (Design Decision 8). Without it, Answer refuses every range.
	drv.CommitWitness = sy.RecordCommit

	v := &Validator{
		cfg:   cfg,
		g:     g,
		ch:    ch,
		priv:  priv,
		pub:   pub,
		pool:  pool,
		sy:    sy,
		rt:    rt,
		ttp:   tp,
		drvTP: dtp,
		cfgC:  ccfg,
		drv:   drv,
		peerH: make(map[transport.PeerID]*peerAttestation),
		syncQ: make(chan transport.Message, syncQueueDepth),
		stop:  make(chan struct{}),
	}
	// A BLOCK_SYNC request is answered by the bounded worker pool, never on
	// the transport's dispatch goroutine (audit C-4): serving one costs disk
	// reads and quorum-many verifies per height, and that work on the
	// dispatch goroutine would hold every consensus frame behind it.
	rt.AsyncServe = v.enqueueSync
	tp.OnMessage(v.route)
	// The router's height observer: the wave loop pulls from what this sees.
	rt.OnHello = v.observeHello
	for i := 0; i < syncWorkers; i++ {
		v.syncWG.Add(1)
		go v.syncWorker()
	}
	v.wg.Add(2)
	go v.tickLoop()
	go v.waveLoop()
	return v, nil
}

// Connect adds DIRECT peer addresses to this validator's permanent dial
// list. The maintainer dials and redials with backoff, so a peer that is not
// up yet is waited for, not failed.
func (v *Validator) Connect(addrs ...string) error {
	for _, a := range addrs {
		if a == "" {
			continue
		}
		if err := v.ttp.AddPeer(a); err != nil {
			return err
		}
	}
	return nil
}

// ConnectRelay registers relay addresses: the same permanent maintainer and
// backoff as Connect, but through the transport's RELAY dial mode - the
// connection announces the local ID, never reads one back, and is named
// relay:<addr>, so no frame the relay forwards can be mistaken for the
// peer's identity (audit N-1). The CLI's --relay lands here.
func (v *Validator) ConnectRelay(addrs ...string) error {
	for _, a := range addrs {
		if a == "" {
			continue
		}
		if err := v.ttp.AddRelay(a); err != nil {
			return err
		}
	}
	return nil
}

// Addr reports the P2P listener's address ("ip:port"), or "" when the
// validator does not listen.
func (v *Validator) Addr() string {
	if a := v.ttp.Addr(); a != nil {
		return a.String()
	}
	return ""
}

// Height reports this validator's chain height (committed blocks only).
func (v *Validator) Height() uint64 { return v.ch.Height() }

// Seat reports this validator's committee index (genesis-file mode derives it
// from the key's position; fixture mode stores it).
func (v *Validator) Seat() int { return v.cfg.Index }

// Chain exposes the validator's chain for tests and the CLI's RPC server.
func (v *Validator) Chain() *chain.Chain { return v.ch }

// Pool exposes the validator's mempool for the CLI's RPC server.
func (v *Validator) Pool() *mempool.Mempool { return v.pool }

// BlocksAdopted counts blocks the catch-up pull brought in. A convergence
// test reads it to distinguish "adopted the committee's blocks" from "voted
// its way up", which an empty chain can never do.
func (v *Validator) BlocksAdopted() uint64 { return v.adopted.Load() }

// PeerCount reports the transport's current connection count (diagnostics;
// the star-through-relay shape connects by ONE name that is not a validator).
func (v *Validator) PeerCount() int { return len(v.ttp.Peers()) }

// VotedHeights reports the heights of the consensus votes this validator has
// put on the wire (its driver's own votes). A member that returned from
// catch-up must vote at the committee's current height again; that is what
// the returning-weight assertions read.
func (v *Validator) VotedHeights() []uint64 { return v.drvTP.VotedHeights() }

// route is the transport's OnMessage callback. It classifies by verified
// decode and, for consensus frames, hands the message to the active driver
// under mu - the serialisation that keeps the engine single-threaded across
// the tick goroutine and every reader goroutine.
func (v *Validator) route(m transport.Message) {
	if v.closing.Load() {
		return
	}
	if !v.rt.Route(m) {
		return
	}
	if f := v.drvTP.msg.Load(); f != nil {
		v.mu.Lock()
		defer v.mu.Unlock()
		if v.closing.Load() {
			return
		}
		(*f)(m)
	}
}

// tickLoop is the driver's clock: TickEvery of REAL time per tick, the
// monotonic counter the driver's virtual milliseconds read.
func (v *Validator) tickLoop() {
	defer v.wg.Done()
	ticker := time.NewTicker(v.cfg.TickEvery)
	defer ticker.Stop()
	var now int64
	for {
		select {
		case <-v.stop:
			return
		case <-ticker.C:
			now += int64(v.cfg.TickEvery / time.Millisecond)
			v.mu.Lock()
			v.drv.Tick(now)
			v.mu.Unlock()
		}
	}
}

// waveLoop is the catch-up heartbeat: announce this node's height, then pull
// from the tallest peer known to be ahead of us.
func (v *Validator) waveLoop() {
	defer v.wg.Done()
	ticker := time.NewTicker(v.cfg.WaveEvery)
	defer ticker.Stop()
	for {
		select {
		case <-v.stop:
			return
		case <-ticker.C:
			v.broadcastHello()
			v.maybeCatchUp()
		}
	}
}

// broadcastHello puts this node's signed height on the wire. The signature is
// domain-separated and carried so a receiver can refuse unvouched height
// announcements; full peer authentication is a later milestone's work.
func (v *Validator) broadcastHello() {
	h := &wire.Hello{
		ChainID:   v.g.ChainID,
		Validator: v.pub,
		Height:    v.ch.Height(),
	}
	hh := helloHash(h)
	h.Sig = crypto.Sign(v.priv, hh[:])
	_ = v.ttp.Broadcast(wire.EncodeHello(h))
}

// helloHash is the HELLO signature's domain-separated hash, defined here (the
// node layer owns the announcement policy; the wire layer only frames it).
func helloHash(h *wire.Hello) [32]byte {
	e := types.NewEncoder()
	e.VarBytes([]byte(h.ChainID))
	e.VarBytes(h.Validator)
	e.U64(h.Height)
	return crypto.HashParts([]byte("b10coin-hello"), e.Bytes())
}

// observeHello records a peer's attested height, refusing announcements from
// another committee, non-member signatures, and unvouched heights. The only
// decision a hello may influence is WHICH peer to pull from, and adoption
// still runs the certificate gate. The earlier reading - "a stranger inflating
// heights" - was wrong on the code: a non-member is refused HERE, before
// recordHeight, so the only actor who can inflate an entry is a signed
// committee member. The rotation below (C-6) is what handles that member.
func (v *Validator) observeHello(from transport.PeerID, h *wire.Hello) {
	if h.ChainID != v.g.ChainID {
		return
	}
	member := false
	for i := range v.g.Validators {
		if bytes.Equal(v.g.Validators[i].PubKey, h.Validator) {
			member = true
			break
		}
	}
	if !member {
		return
	}
	hh := helloHash(h)
	if !crypto.Verify(h.Validator, hh[:], h.Sig) {
		return
	}
	v.recordHeight(from, h.Height)
}

// beginWave advances the catch-up wave counter. Every wave boundary moves the
// window in which a peer's announcement expires and a demotion lapses.
func (v *Validator) beginWave() {
	v.peerHMu.Lock()
	v.wave++
	v.peerHMu.Unlock()
}

// recordHeight keeps a peer's LATEST attestation - not its maximum ever (audit
// C-6): a peer that re-announces a smaller, honest height can drop, and a
// vanished peer's entry expires on the wave clock rather than standing forever.
func (v *Validator) recordHeight(from transport.PeerID, height uint64) {
	v.peerHMu.Lock()
	defer v.peerHMu.Unlock()
	st := v.peerH[from]
	if st == nil {
		st = &peerAttestation{}
		v.peerH[from] = st
	}
	st.height = height
	st.seen = v.wave
}

// peerWindow is the selection cap's unit: one response window, read off the
// syncer so the cap tracks the bound the pull actually uses.
func (v *Validator) peerWindow() uint64 {
	if v.sy != nil && v.sy.MaxBlocksPerResponse > 0 {
		return v.sy.MaxBlocksPerResponse
	}
	return consensus.DefaultMaxBlocksPerResponse
}

// tallestPeer returns the tallest peer whose attestation is still usable: not
// expired, not demoted, and capped by what that peer has ever substantiated
// (audit C-6). An unproven peer is worth exactly one window - enough to try,
// never enough to dwarf a peer that has served real blocks.
func (v *Validator) tallestPeer() (transport.PeerID, uint64) {
	v.peerHMu.Lock()
	defer v.peerHMu.Unlock()
	win := v.peerWindow()
	var best transport.PeerID
	var bestH uint64
	for id, st := range v.peerH {
		if st.seen+peerHeightTTL < v.wave {
			continue // not refreshed within a few waves: expired
		}
		if st.demoted > v.wave {
			continue // a pull from this peer proved nothing: rotate away
		}
		h := st.height
		if !st.proven {
			if h > win {
				h = win
			}
		} else if h > st.substantiated+win {
			h = st.substantiated + win
		}
		if h > bestH {
			best, bestH = id, h
		}
	}
	return best, bestH
}

// demotePeer skips a peer for a few waves after a pull from it failed to
// substantiate its announcement, and records how far that pull actually
// reached so the cap lowers with it.
func (v *Validator) demotePeer(peer transport.PeerID, reached uint64) {
	v.peerHMu.Lock()
	defer v.peerHMu.Unlock()
	st := v.peerH[peer]
	if st == nil {
		return
	}
	st.demoted = v.wave + peerDemoteWaves
	st.proven = true
	st.substantiated = reached
}

// substantiatePeer records a pull that reached the peer's attested height and
// clears any demotion: a peer that served what it claimed is trusted again.
func (v *Validator) substantiatePeer(peer transport.PeerID, reached uint64) {
	v.peerHMu.Lock()
	defer v.peerHMu.Unlock()
	st := v.peerH[peer]
	if st == nil {
		return
	}
	st.proven = true
	if reached > st.substantiated {
		st.substantiated = reached
	}
	st.demoted = 0
}

// maybeCatchUp pulls from the tallest attested peer when it stands above our
// head, and - the load-bearing half - rebuilds the driver over the adopted
// head, because the engine still judges the pre-pull height and would park
// there forever once the committee moved on (see this file's rules).
//
// A pull that substantiates nothing while the peer stands above us - silence,
// a refused window, a transport error, or no block adopted at all - DEMOTES
// that peer for a few waves (audit C-6), so a member announcing an
// unserveable height cannot make every wave wait on it while truthful peers
// are passed over. A pull that reaches the attested height substantiates and
// clears the demotion, so a merely slow peer is not distrusted forever.
func (v *Validator) maybeCatchUp() {
	v.beginWave()
	peer, peerH := v.tallestPeer()
	mine := v.ch.Height()
	if peer == "" || peerH <= mine {
		return
	}
	before := mine
	v.sy.Peer = peer
	pull := v.pull
	if pull == nil {
		pull = v.sy.PullAndAdopt
	}
	err := pull(before + 1)
	after := v.ch.Height()
	if after > before {
		v.rebuildDriver()
		v.adopted.Add(after - before)
	}
	if err != nil || (after < peerH && after == before) {
		v.demotePeer(peer, after)
		return
	}
	v.substantiatePeer(peer, after)
}

// enqueueSync hands a BLOCK_SYNC request to the async server (installed as
// MessageRouter.AsyncServe). It NEVER blocks: the queue is bounded, and a full
// queue drops the request (the asker reads silence and retries on a later
// wave) rather than stalling the transport's dispatch goroutine.
func (v *Validator) enqueueSync(m transport.Message) {
	if v.closing.Load() {
		return
	}
	select {
	case v.syncQ <- m:
	default:
		v.syncDropped.Add(1)
	}
}

// syncWorker serves BLOCK_SYNC requests off the transport's dispatch
// goroutine. It touches only the syncer and the chain, both of which are
// guarded independently of the driver mutex, so serving cannot re-enter the
// engine.
func (v *Validator) syncWorker() {
	defer v.syncWG.Done()
	for {
		select {
		case <-v.stop:
			return
		case m := <-v.syncQ:
			if frame, ok := v.sy.Handle(m.Data); ok && v.rt.SendReply != nil {
				_ = v.rt.SendReply(m.From, frame)
			}
		}
	}
}

// SyncRequestsDropped counts BLOCK_SYNC requests shed by the bounded async
// queue. A nonzero count is the observable that the serving bound bit.
func (v *Validator) SyncRequestsDropped() uint64 { return v.syncDropped.Load() }

// rebuildDriver replaces the driver with one judging the chain's CURRENT head.
// The old engine's volatile round state is discarded the way a restart's is;
// its persisted locks (if any) are per-height and restored by the fresh
// engine automatically when they still matter.
func (v *Validator) rebuildDriver() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.drv = consensus.NewDriver(v.cfgC, v.ch, v.priv, v.drvTP, v.pool)
	v.drv.CommitWitness = v.sy.RecordCommit
}

// Close stops the loops, closes the transport and the chain, and is
// idempotent.
func (v *Validator) Close() error {
	// The ORDER is the safety story: the closing flag goes up first (under
	// mu, so the one dispatch already in flight finishes before the flag is
	// set); the wave loop is waited out - a catch-up pull in flight runs to
	// its own deadline and its appends land BEFORE the chain closes - then
	// the async sync workers (a request being served finishes its own chain
	// reads), the transport's sockets die (and the reader goroutines with
	// them), and only then does the chain close, with no dispatch left that
	// could still write.
	v.mu.Lock()
	v.closing.Store(true)
	v.mu.Unlock()
	v.stopOnce.Do(func() { close(v.stop) })
	v.wg.Wait()
	v.syncWG.Wait()
	_ = v.ttp.Close()
	if v.closed.Swap(true) {
		return nil
	}
	return v.ch.Close()
}
