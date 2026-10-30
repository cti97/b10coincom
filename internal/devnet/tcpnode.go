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
//     The two message unions once shared the numeric range 1-3; audit N-5
//     renumbered the wire tags to a disjoint range (wire.WireTagFloor), and
//     routing still goes by VERIFIED decode, never by a bare tag comparison
//     (see the router's doc);
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
	"crypto/ed25519"
	"fmt"
	"log"
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
//     The seat is the position its public key occupies in that document. A
//     key that is in neither that document nor the committee at the chain's
//     head+1 REFUSES TO START (audit A-1): silently signing as a seat the
//     key does not hold is the exact failure the committee file exists to
//     prevent. A key that joined the committee AFTER genesis - bonded, and
//     seated by an epoch boundary the chain has already crossed - is admitted
//     through the head+1 half (audit RT-1), because rotation-in is exactly
//     the seat the consensus layer already knows how to use.
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
	// nonzero value here is refused as a contradiction). In genesis-file
	// mode the derived value is -1 when the key holds no GENESIS seat but is
	// admitted by the committee at head+1 (a validator that bonded after
	// genesis, audit RT-1); Seat reports that -1 and the per-height seat is
	// the chain's to answer.
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
	// RelayAccessToken, when non-empty, is the pre-shared first frame sent on
	// every relay dial (audit N-8): the credential a relay started with
	// Options.AccessToken requires before it registers the link. It is NOT a
	// consensus secret - the relay only compares bytes by length and equality
	// - and an empty value keeps the previous behaviour.
	RelayAccessToken []byte
	// AllowLocalPeerHints is the DEVNET ACCEPTANCE EXCEPTION for PEER_EXCHANGE:
	// it permits a hint naming a loopback, private or link-local address, which
	// the default policy refuses (see validatePeerHint). It exists because the
	// acceptance mesh runs every validator on one host behind 127.0.0.1, and a
	// single-host devnet has no public address to advertise; the tests set it
	// and say so. It is NOT set by the CLI and must never be set on a node
	// whose reach extends beyond the operator's own machine: it is the one knob
	// that turns a peer's hint into a dial at the operator's own network.
	AllowLocalPeerHints bool
	// TickEvery is the driver's tick cadence (zero: defaultTickEvery).
	TickEvery time.Duration
	// WaveEvery is the HELLO/catch-up cadence (zero: defaultWaveEvery).
	WaveEvery time.Duration
}

// peerAttestation is what one peer's HELLO leaves behind (audit C-6): the
// height it last announced, the highest height a pull from it actually
// reached, whether any pull has proven it at all, the wave it was last
// refreshed in, the wave until which selection skips it, and the transport
// name its latest HELLO arrived on (the address a pull is sent to).
type peerAttestation struct {
	height        uint64           // latest announced height
	substantiated uint64           // highest height a pull from this peer reached (a HIGH-WATER mark: a transient failure never lowers it - F3)
	proven        bool             // a pull from this peer has completed (successfully or not)
	seen          uint64           // wave of the latest HELLO
	demoted       uint64           // skip selection while demoted > the current wave
	via           transport.PeerID // transport name the latest HELLO arrived on
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
	// dedup is the router's seen-set (audit N-7): the wave loop Forget()s
	// below the committed height so a long-lived node does not accumulate
	// keys for every height it ever decided.
	dedup *transport.Dedup

	// mu serialises every driver operation (see the package-level rules above).
	mu sync.Mutex

	// peerH is the state each peer's HELLO leaves behind, keyed by the SIGNED
	// MEMBER IDENTITY (the HELLO's validator public key) - never by the
	// transport name (round 7, F1/F2). On a DIRECT link the transport name is
	// the peer's own handshake ID (forgeable - it is a routing key, not a
	// proof). Through a relay every frame arrives under the ONE fixed
	// connection name tcp.RelayPeerName(addr), which announces nothing about
	// who is behind it and is stable across reconnects (audit N-1: never
	// derived from any frame's bytes). Either way the name is shared - a relay
	// stranger and every honest member behind that relay carry it - so keying
	// selection or demotion on it attributes one member's failure to all of
	// them. A HELLO is signed and member-checked before it reaches here, so
	// the key is authenticated and a member can only ever own one entry: the
	// map is bounded by the committee size (F2), and demoting one member
	// leaves the honest members behind the same relay name untouched (F1's
	// granularity). Each entry remembers the transport name its latest HELLO
	// arrived on, which is where a pull for that member is sent.
	//
	// The state remembers more than the latest height (audit C-6): when the
	// announcement was last refreshed (so a vanished peer expires), how far a
	// pull from that member ever substantiated (so an announcement above what
	// it can serve is capped for selection), and until when the member is
	// demoted (so a member whose pull proved nothing is rotated away from).
	peerHMu sync.Mutex
	peerH   map[string]*peerAttestation
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

	// hints is the PEER_EXCHANGE dial book: the bounded set of addresses this
	// node learned from peers and the per-wave adoption window. peerAdd is the
	// ONE dial path it may use - tcp.TcpTransport.AddPeer in a running node,
	// and a recording seam in the tests that must count dials without touching
	// a network (it is a field so a raw dial cannot hide inside the handler).
	hints   peerHints
	peerAdd func(addr string) error
	// peerRemove retires the maintainer for a learned address whose handshake
	// never completed (audit PX-1). It is a field for the same reason peerAdd
	// is: the policy test must be able to count retirements without a
	// network, and a raw RemovePeer must not hide inside the eviction path.
	peerRemove func(addr string) bool

	// The PEER_EXCHANGE observables. Adopted/refused/duplicate/over-budget
	// describe the node's receive policy; sent describes its own advertising.
	// None of them is a consensus signal (design decision 5).
	hintsSeen       atomic.Uint64
	hintsRefused    atomic.Uint64
	hintsDuplicates atomic.Uint64
	hintsAdopted    atomic.Uint64
	hintsOverBudget atomic.Uint64
	hintsEvicted    atomic.Uint64
	hintsSent       atomic.Uint64

	// adopted counts blocks brought in by catch-up pulls: the observable a
	// convergence test reads to prove the joiner ADOPTED rather than voted.
	adopted atomic.Uint64

	// framesIn counts verified consensus frames this node handed to its
	// driver. It is the "did peer frames arrive at all" half of the stall
	// report: a round with zero frames and a round whose frames were all
	// dropped by the engine look the same from the committed height, and they
	// are different faults. Read with atomic because route runs on several
	// transport reader goroutines.
	framesIn atomic.Uint64

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
// genesis, admits this validator's key (a genesis seat, or - audit RT-1 - a
// seat in the committee at head+1), builds the consensus stack over a real TCP
// transport, and starts the tick and wave goroutines. It does NOT dial: call
// Connect once the committee's addresses are known (the CLI does it right
// after; the mesh tests collect every listener's port first).
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
		// The genesis position, or -1 for a key that joined the committee
		// AFTER genesis (audit RT-1). A -1 is not a refusal here: whether the
		// key is allowed to run depends on the chain this node holds, which
		// is not open yet. See the admission below.
		seat = genesis.SeatOfPubKey(g.Validators, pub)
		// Normalise the config so the seat reporting (Seat) reflects the
		// DERIVED seat, not the fixture flag that was correctly zero. A
		// rotated-in key has no genesis position and keeps -1.
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
	// different key silently.) A rotated-in key has no genesis position to
	// belt: its seat is judged by the chain below, exactly as the driver
	// judges every later height.
	if seat >= 0 {
		if n <= seat {
			return nil, fmt.Errorf("devnet: committee seat %d out of range 0..%d", seat, n-1)
		}
		if string(g.Validators[seat].PubKey) != string(pub) {
			return nil, fmt.Errorf("devnet: committee seat %d holds a key that is not this validator's", seat)
		}
	}

	// The committee's power cap: the spec's 1/4 for four or more members,
	// 1/1 below (small fixtures cannot satisfy 1/4). Sized by the committee
	// that actually runs, whatever named it. The DRIVER recomputes it for the
	// per-height committee (a rotation can change the seat count); this is the
	// startup sanity check on the GENESIS set, and both use the one rule.
	capNum, capDen := consensus.PowerCapFor(n)
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
	// ROTATION-IN ADMISSION (audit RT-1). A key that is not in the genesis
	// list may still run this node: if it holds a seat in the committee that
	// judges the height this node will extend from - head+1, the height the
	// driver's first engine judges - it can vote there, and refusing it is
	// exactly the entry-point hole that left a bonded outsider's seat with no
	// signer while its power silently raised the quorum bar.
	//
	// The check is made AFTER the chain is opened because the seat is a
	// function of COMMITTED STATE, not of the genesis document: only the
	// chain can answer it. It is head+1 and not "any height" on purpose. A
	// key bonded but not yet seated (its epoch boundary has not arrived) has
	// no voting duty yet and no chain that can judge it either; it must be
	// started after the boundary that seats it, which is what the end-to-end
	// test does. The genesis list stays the driver's base config
	// (ccfg.Committee above) exactly as before - this decides WHO MAY RUN,
	// not who may sign.
	if g != nil && seat < 0 {
		next := ch.Height() + 1
		vals, cerr := ch.CommitteeAt(next)
		if cerr != nil || genesis.SeatOfPubKey(vals, pub) < 0 {
			_ = ch.Close()
			// THE refusal: a key outside both the genesis committee and the
			// committee at head+1 must not sign as any seat, and there is no
			// seat-zero default to fall back to. Say what was checked and
			// what fixes it.
			reason := "holds no seat there"
			if cerr != nil {
				reason = "the committee for that height cannot be derived: " + cerr.Error()
			}
			return nil, fmt.Errorf("devnet: refusing to start: this validator's public key (%x) is not listed in the committee's genesis (%d seats named) and %s in the committee at height %d; a member key must be generated per machine (b10coin keygen) and its public key added to the file every validator shares, or the key must be bonded and seated by the epoch boundary it starts after",
				pub, len(g.Validators), reason, next)
		}
	}
	// The per-height committee source (M5 Task 3): every engine this driver
	// builds asks the chain for the epoch's seats, and every other reader
	// (router membership, certificate gate, HELLO admission, BLOCK_SYNC) asks
	// the same chain. Committee above stays the genesis set - the base a
	// driver's membership gate checks - and is never the set used to judge a
	// height once this seam is wired.
	ccfg.CommitteeFor = ch.CommitteeAt
	// admitHello is the transport's admission policy (audit N-3/N-7): an
	// INBOUND socket becomes a peer only once it has delivered a HELLO signed
	// by a member of THIS chain's committee. Before that it is absent from
	// Peers(), receives no Broadcast, and its frames never reach the router -
	// so a scanner, a misconfigured node or a stranger replaying a peer's
	// transport name cannot make this validator copy every frame for it. The
	// policy lives here, not in the transport, because it needs the committee
	// and the chain id; the transport only calls it.
	//
	// Membership is per the committee of the HEIGHT THE HELLO ANNOUNCES (M5
	// rotation), widened by committeeMemberAt to the genesis and head sets so
	// the rotation does not lock out the peers it creates. Admission is a DoS
	// bound, never a safety gate: every admitted frame still faces the
	// router's per-height membership, and every adopted block the certificate
	// gate.
	admitHello := func(frame []byte) bool {
		h, err := wire.DecodeHello(frame)
		if err != nil {
			return false
		}
		if h.ChainID != g.ChainID {
			return false
		}
		if !committeeMemberAt(ch, g, h.Validator, h.Height) {
			return false
		}
		hh := helloHash(h)
		return crypto.Verify(h.Validator, hh[:], h.Sig)
	}
	// The transport name this node announces. A genesis seat keeps the "vN"
	// form every deployment and test already names it by. A key that joined
	// after genesis has no genesis position, and reusing a committee index
	// would collide with the genesis validator that still holds that name -
	// a name collision is a self-connection refusal for one side and a
	// registry fight for the other - so the name is derived from the key:
	// stable across restarts, outside the "vN" space, and distinct for every
	// key.
	localID := transport.PeerID(fmt.Sprintf("v%d", cfg.Index))
	if cfg.Index < 0 {
		localID = transport.PeerID(fmt.Sprintf("k%x", pub[:6]))
	}
	tp, err := tcp.New(tcp.Options{
		LocalID:          localID,
		Admit:            admitHello,
		RelayAccessToken: cfg.RelayAccessToken,
	})
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

	pool := mempool.New(networkedMempoolCapacity, g.Hash(), ch.AdmissionHead)
	sy := consensus.NewSyncer(ch, tp, priv)
	rt := consensus.NewMessageRouter(sy)
	rt.SendReply = tp.Send
	// The seen-set for VERIFIED consensus messages (audit N-7). The router
	// consults it strictly after verification, so a forged frame cannot
	// poison an honest vote's key; the wave loop Forget()s below the committed
	// height so the set stays bounded, and the set itself is height-sharded.
	dedup := transport.NewDedup(0)
	rt.Dedup = dedup
	// The driver sees the DRIVER transport (sends go straight to tcp; the
	// OnMessage registration is swallowed into the atomic slot route()
	// invokes), never the raw transport, or NewDriver's registration would
	// overwrite the router's.
	dtp := &driverTP{inner: tp}
	drv, err := consensus.NewDriver(ccfg, ch, priv, dtp, pool)
	if err != nil {
		_ = tp.Close()
		_ = ch.Close()
		return nil, err
	}
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
		dedup: dedup,
		// The learned-address book starts empty; nothing is dialled from a hint
		// until a peer advertises it through an attested connection.
		hints: peerHints{
			learned: make(map[string]*learnedHint),
			sources: make(map[string]int),
		},
		peerAdd:    tp.AddPeer,
		peerRemove: tp.RemovePeer,
		peerH:      make(map[string]*peerAttestation),
		syncQ:      make(chan transport.Message, syncQueueDepth),
		stop:       make(chan struct{}),
	}
	// A BLOCK_SYNC request is answered by the bounded worker pool, never on
	// the transport's dispatch goroutine (audit C-4): serving one costs disk
	// reads and quorum-many verifies per height, and that work on the
	// dispatch goroutine would hold every consensus frame behind it.
	rt.AsyncServe = v.enqueueSync
	tp.OnMessage(v.route)
	// The router's height observer: the wave loop pulls from what this sees.
	rt.OnHello = v.observeHello
	// The mesh hint's observer. It applies the dial policy and calls AddPeer;
	// it runs on the transport's dispatch goroutine, so it stays bounded - see
	// observePeerExchange.
	rt.OnPeerExchange = v.observePeerExchange
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

// Round reports the round this validator's current consensus engine is in,
// read under the driver mutex so a poller in another goroutine sees the engine
// the driver is actually using. See consensus.Driver.Round for why a stalled
// run needs it: the committed height alone cannot distinguish a parked node
// (AppendRefused, a round that stopped) from one churning its round ladder past
// the committee's.
func (v *Validator) Round() uint32 {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.drv == nil {
		return 0
	}
	return v.drv.Round()
}

// AppendRefused reports whether this validator's driver has parked: its engine
// committed a block the chain refused, so it has stopped offering that height
// and will not advance past it (Design Decision 8). A false here on a node that
// is not advancing is the other half of the diagnosis - the height is
// undecidable, not refused.
func (v *Validator) AppendRefused() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.drv != nil && v.drv.AppendRefused()
}

// Seat reports this validator's GENESIS committee index (genesis-file mode
// derives it from the key's position; fixture mode stores it). It is -1 for a
// key that joined after genesis (audit RT-1): such a key's seat is a per-epoch
// property of committed state, so it is read from Chain().CommitteeAt for the
// height in question rather than reported as one fixed number.
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

// FramesIn reports how many verified consensus frames this validator handed to
// its driver. Together with the router counters it separates "no frames
// arrived" from "frames arrived and were refused, duplicated, or dropped by
// the engine": a zero here on a node with peers is a delivery fault, a
// nonzero here with zero tallied votes is a judging fault.
func (v *Validator) FramesIn() uint64 { return v.framesIn.Load() }

// Step reports the driver's current consensus step, read under the driver
// mutex exactly as Round and AppendRefused are. On a stalled node "propose"
// with no proposal received is a different fault from "prevote" with a tally
// short of quorum.
func (v *Validator) Step() consensus.Step {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.drv == nil {
		return consensus.StepPropose
	}
	return v.drv.DiagStep()
}

// DiagRounds returns a copy of the driver's bounded recent-round history: the
// proposer drawn, whether a proposal arrived, what the engine prevoted, and
// the two tallies per round. See consensus.Driver.Observe.
func (v *Validator) DiagRounds() []consensus.DiagRound {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.drv == nil {
		return nil
	}
	// Fold the engine's CURRENT state into the ring before copying it. The
	// harness observes after every operation, so this is normally a no-op;
	// it guarantees a poll taken between two ticks never reports a round
	// older than the engine it is looking at.
	v.drv.Observe()
	return v.drv.DiagRounds()
}

// DiagCounters reports the engine's frame-drop counters (per height).
func (v *Validator) DiagCounters() consensus.DiagCounters {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.drv == nil {
		return consensus.DiagCounters{}
	}
	return v.drv.DiagCounters()
}

// Quorum reports the quorum threshold at the height the engine is judging.
func (v *Validator) Quorum() uint64 {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.drv == nil {
		return 0
	}
	return v.drv.DiagQuorum()
}

// TotalPower reports the committee's total voting power at the height the
// engine is judging; printed beside Quorum so a power sum means something.
func (v *Validator) TotalPower() uint64 {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.drv == nil {
		return 0
	}
	return v.drv.DiagTotalPower()
}

// Router counters. They are atomics on the router and safe to read from the
// poll goroutine; the report prints them per validator because the refused and
// duplicate counts are per node, not per committee.
func (v *Validator) RefusedBeforeVerify() uint64 { return v.rt.RefusedBeforeVerify() }
func (v *Validator) DuplicatesDropped() uint64   { return v.rt.DuplicatesDropped() }
func (v *Validator) UnknownDropped() uint64      { return v.rt.UnknownDropped() }

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
		v.framesIn.Add(1)
		(*f)(m)
		// Record what the engine retained after this frame. The observe call
		// is diagnostic only and runs under the same lock as the driver
		// operation, so it can never read a half-driven engine.
		v.drv.Observe()
	}
}

// consensusClock is the driver's virtual-millisecond clock. It ACCUMULATES
// each real tick's full duration and converts the running total to
// milliseconds, rather than adding TickEvery/time.Millisecond per tick.
// The old form truncated a sub-millisecond TickEvery to zero, so the driver's
// clock never advanced and consensus time froze (audit O-11); accumulating
// means 5 ticks of 200µs advance the clock exactly as far as one 1ms tick.
type consensusClock struct{ elapsed time.Duration }

func (c *consensusClock) tick(every time.Duration) int64 {
	c.elapsed += every
	return int64(c.elapsed / time.Millisecond)
}

// tickLoop is the driver's clock: TickEvery of REAL time per tick, the
// monotonic counter the driver's virtual milliseconds read.
func (v *Validator) tickLoop() {
	defer v.wg.Done()
	ticker := time.NewTicker(v.cfg.TickEvery)
	defer ticker.Stop()
	var clock consensusClock
	for {
		select {
		case <-v.stop:
			return
		case <-ticker.C:
			now := clock.tick(v.cfg.TickEvery)
			v.mu.Lock()
			v.drv.Tick(now)
			v.drv.Observe()
			v.mu.Unlock()
		}
	}
}

// waveLoop is the catch-up heartbeat: announce this node's height, then pull
// from the tallest peer known to be ahead of us. It also prunes the dedup
// seen-set below the committed height (audit N-7): Forget is bucket-grained,
// so this is O(live heights) and the set cannot grow with the run.
//
// Every peerExchangeEveryWaves-th wave it also advertises this node's listening
// address (PEER_EXCHANGE), which is what lets peers on the relay star find each
// other directly. The cadence is a BOUND, not a nicety: an advertisement per
// frame would make the message an amplifier, while a direct link is worth
// forming within seconds rather than instantly (design decision 5: the mesh is
// an optimization, the relay and the signed HELLO are the guarantees).
func (v *Validator) waveLoop() {
	defer v.wg.Done()
	ticker := time.NewTicker(v.cfg.WaveEvery)
	defer ticker.Stop()
	waves := 0
	for {
		select {
		case <-v.stop:
			return
		case <-ticker.C:
			waves++
			v.broadcastHello()
			if waves%peerExchangeEveryWaves == 0 {
				v.sendPeerExchange()
			}
			v.maybeCatchUp()
			if v.dedup != nil {
				v.dedup.Forget(v.ch.Height())
			}
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

// committeeMemberAt reports whether pub may participate in this node's
// peer-to-peer traffic: it holds a seat in the committee that judges height,
// OR it held a genesis seat, OR it holds one at our current head.
//
// THE UNION IS FOR THE ROTATION ITSELF, and it is deliberately not a single
// height's set. Admission bounds who may send this node frames, and the
// rotation creates two peers a single-height check would lock out:
//
//   - a validator whose seat ENDED at the boundary is absent from the new
//     epoch's committee, so a strict check refuses its HELLO and it can never
//     reconnect to follow the chain - the very node rotation produces;
//   - a validator whose seat BEGAN after genesis is absent from the genesis
//     set, so a peer still behind the boundary would refuse it;
//   - a peer announcing a height whose deciding state we do not hold yet
//     (ahead of an epoch boundary) cannot be checked at that height at all,
//     and refusing it would refuse the pull that carries us across.
//
// The genesis and head sets cover all three. NOTHING HERE IS A SAFETY
// DECISION: every frame still faces the router's per-height membership check,
// and every block is adopted only through the certificate gate at its own
// height. A peer admitted under the union cannot change this chain's state by
// claiming a seat; it can at most waste bytes, which the transport's
// per-connection admission and the BLOCK_SYNC rate limits bound.
func committeeMemberAt(ch *chain.Chain, g *genesis.Genesis, pub []byte, height uint64) bool {
	if genesis.SeatOfPubKey(g.Validators, pub) >= 0 {
		return true
	}
	if vals, err := ch.CommitteeAt(height); err == nil && genesis.SeatOfPubKey(vals, pub) >= 0 {
		return true
	}
	if vals, err := ch.CommitteeAt(ch.Height()); err == nil && genesis.SeatOfPubKey(vals, pub) >= 0 {
		return true
	}
	return false
}

// observeHello records a peer's attested height, refusing announcements from
// another committee, non-member signatures, and unvouched heights. The only
// decision a hello may influence is WHICH peer to pull from, and adoption
// still runs the certificate gate. The earlier reading - "a stranger inflating
// heights" - was wrong on the code: a non-member is refused HERE, before
// recordHeight, so the only actor who can inflate an entry is a signed
// committee member. The rotation below (C-6) is what handles that member.
//
// Membership is per the height the HELLO announces (M5 rotation), through the
// same committeeMemberAt the transport's admission uses: a rotated-in validator
// becomes a pull target as soon as its epoch is derivable, and a rotated-out
// genesis seat stays one (it still holds history, and it is the peer this node
// may have to follow from). Without the per-height half the new epoch's seats
// could never be selected.
func (v *Validator) observeHello(from transport.PeerID, h *wire.Hello) {
	if h.ChainID != v.g.ChainID {
		return
	}
	if !committeeMemberAt(v.ch, v.g, h.Validator, h.Height) {
		return
	}
	hh := helloHash(h)
	if !crypto.Verify(h.Validator, hh[:], h.Sig) {
		return
	}
	// A verified HELLO on this connection also proves any LEARNED address this
	// connection belongs to: it has a real member behind it, so its maintainer
	// must never be retired by the hint eviction clock (audit PX-1).
	v.markHintProven(from)
	// Keyed on the signed member identity, with the transport name kept only
	// as the address a pull for this member is sent to (round 7, F1/F2).
	v.recordHeight(string(h.Validator), from, h.Height)
}

// beginWave advances the catch-up wave counter. Every wave boundary moves the
// window in which a peer's announcement expires, a demotion lapses, and a
// learned address that has never completed a handshake is retired (audit
// PX-1: the wave clock is the eviction clock).
func (v *Validator) beginWave() {
	v.peerHMu.Lock()
	v.wave++
	wave := v.wave
	v.peerHMu.Unlock()
	v.expireUnprovenHints(wave)
}

// recordHeight keeps a member's LATEST attestation (audit C-6) under its
// signed member key (who), and remembers the transport name (via) the HELLO
// arrived on as the address a pull for that member goes to. Because who is the
// authenticated validator key, one member can only ever own one entry however
// many transport names it replays a HELLO under, so the table is bounded by
// the committee's size - a churning member cannot grow it (round 7, F2). It
// also prunes entries whose announcement has expired, so the live table tracks
// the members actually heard from rather than every member ever heard.
func (v *Validator) recordHeight(who string, via transport.PeerID, height uint64) {
	v.peerHMu.Lock()
	defer v.peerHMu.Unlock()
	for id, st := range v.peerH {
		if st.seen+peerHeightTTL < v.wave {
			delete(v.peerH, id)
		}
	}
	st := v.peerH[who]
	if st == nil {
		st = &peerAttestation{}
		v.peerH[who] = st
	}
	st.height = height
	st.via = via
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

// tallestPeer returns the tallest MEMBER whose attestation is still usable:
// not expired, not demoted, and capped by what that member has ever
// substantiated (audit C-6). It returns the member's signed key (who), the
// transport name its HELLO arrived on (via, where the pull is sent), and the
// height it is trusted up to. Selection is deterministic: ties break on the
// lexicographically smaller key, never on map iteration order. An unproven
// member is worth exactly one window - enough to try, never enough to dwarf a
// member that has served real blocks. Because the key is the member identity,
// demoting one member cannot skip the honest members sharing its relay name
// (round 7, F1).
func (v *Validator) tallestPeer() (who string, via transport.PeerID, h uint64) {
	v.peerHMu.Lock()
	defer v.peerHMu.Unlock()
	win := v.peerWindow()
	for id, st := range v.peerH {
		if st.seen+peerHeightTTL < v.wave {
			continue // not refreshed within a few waves: expired
		}
		if st.demoted > v.wave {
			continue // a pull from this member proved nothing: rotate away
		}
		ch := st.height
		if !st.proven {
			if ch > win {
				ch = win
			}
		} else if ch > st.substantiated+win {
			ch = st.substantiated + win
		}
		if ch > h || (ch == h && (who == "" || id < who)) {
			who, via, h = id, st.via, ch
		}
	}
	return who, via, h
}

// demotePeer skips a member for a few waves after a pull from it failed to
// substantiate its announcement. It records how far that pull actually
// reached, but ONLY as a high-water update: substantiated is documented as the
// highest height a pull from this member ever reached, and a transient failure
// must not drop the selection cap it earned (round 7, F3). A member that once
// served 100 and then blips keeps a cap of at least 100; the demotion, not a
// lowered cap, is what rotates it away meanwhile.
func (v *Validator) demotePeer(who string, reached uint64) {
	v.peerHMu.Lock()
	defer v.peerHMu.Unlock()
	st := v.peerH[who]
	if st == nil {
		return
	}
	st.demoted = v.wave + peerDemoteWaves
	st.proven = true
	if reached > st.substantiated {
		st.substantiated = reached
	}
}

// substantiatePeer records a pull that reached the member's attested height and
// clears any demotion: a member that served what it claimed is trusted again.
// substantiated is the high-water mark, never lowered.
func (v *Validator) substantiatePeer(who string, reached uint64) {
	v.peerHMu.Lock()
	defer v.peerHMu.Unlock()
	st := v.peerH[who]
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
// A pull that substantiates nothing while the member stands above us - silence,
// a refused window, a transport error, or no block adopted at all - DEMOTES
// that MEMBER for a few waves (audit C-6, round 7 F1): keyed on the signed
// identity, so a member announcing an unserveable height cannot make every
// wave wait on it while truthful peers - including others behind the same
// relay name - are passed over. A pull that reaches the attested height
// substantiates and clears the demotion, so a merely slow member is not
// distrusted forever.
func (v *Validator) maybeCatchUp() {
	v.beginWave()
	who, via, peerH := v.tallestPeer()
	mine := v.ch.Height()
	if who == "" || peerH <= mine {
		return
	}
	before := mine
	// The pull goes to the transport name the member's HELLO arrived on, and
	// it will accept an answer ONLY from that member's signed key: on a relay
	// the name is shared, so the expectation is the identity (round 7, F1).
	v.sy.Peer = via
	v.sy.Expect = ed25519.PublicKey(who)
	pull := v.pull
	if pull == nil {
		pull = v.sy.PullAndAdopt
	}
	err := pull(before + 1)
	after := v.ch.Height()
	if after > before {
		if rerr := v.rebuildDriver(); rerr != nil {
			// Unreachable for a validator the constructor already admitted
			// (same config, same key): treat it as a failed catch-up - demote
			// the member and let a later wave retry - rather than panic or
			// keep an engine that judges a head the chain has left.
			v.demotePeer(who, after)
			return
		}
		v.adopted.Add(after - before)
	}
	if err != nil || (after < peerH && after == before) {
		// Demote the MEMBER, not the transport name: an honest member behind
		// the same relay must not be penalised for this one's failure (F1).
		v.demotePeer(who, after)
		return
	}
	v.substantiatePeer(who, after)
}

// enqueueSync hands a BLOCK_SYNC request to the async server (installed as
// MessageRouter.AsyncServe). It NEVER blocks: the queue is bounded, and a full
// queue drops the request (the asker reads silence and retries on a later
// wave) rather than stalling the transport's dispatch goroutine. A drop is
// LOGGED as well as counted (round 7, F4): SyncRequestsDropped is the
// operator's checkable bound, and a bound a reader cannot see is not a
// documented bound.
func (v *Validator) enqueueSync(m transport.Message) {
	if v.closing.Load() {
		return
	}
	select {
	case v.syncQ <- m:
	default:
		n := v.syncDropped.Add(1)
		log.Printf("b10coin: BLOCK_SYNC request from %q dropped: the serving queue is full (%d dropped so far)", m.From, n)
	}
}

// syncWorker serves BLOCK_SYNC requests off the transport's dispatch
// goroutine. It touches only the syncer and the chain, both of which are
// guarded independently of the driver mutex, so serving cannot re-enter the
// engine. The served-request counter is incremented HERE, after Handle
// answered, never at handoff (round 7, F4).
func (v *Validator) syncWorker() {
	defer v.syncWG.Done()
	for {
		select {
		case <-v.stop:
			return
		case m := <-v.syncQ:
			if frame, ok := v.sy.Handle(m.Data); ok {
				v.rt.NoteServed()
				if v.rt.SendReply != nil {
					_ = v.rt.SendReply(m.From, frame)
				}
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
func (v *Validator) rebuildDriver() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	d, err := consensus.NewDriver(v.cfgC, v.ch, v.priv, v.drvTP, v.pool)
	if err != nil {
		return err
	}
	d.CommitWitness = v.sy.RecordCommit
	v.drv = d
	return nil
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
