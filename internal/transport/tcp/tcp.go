// Package tcp is the real-socket transport behind the swappable Transport
// boundary. It exists because the simulator, for all its determinism, runs
// zero goroutines and touches zero sockets - and the Pi acceptance runs both.
// The one property this layer must get right above every other: a peer that
// stops reading must not be able to stall the consensus loop of the node
// sending to it. Consensus is a tight loop; one wedged socket halting it is a
// self-denial-of-service. So the shape is:
//
//   - ONE goroutine per connection: a reader that frames and dispatches to
//     OnMessage, and a writer that drains a bounded queue onto the socket;
//   - Broadcast and Send only ENQUEUE. If a peer's queue is full the frame is
//     dropped (Send reports the drop; Broadcast does not - gossip is
//     redundant by design and the driver ignores its error), and the caller
//     returns in microseconds whatever the peer is doing;
//   - every connection dials back with exponential, jittered backoff, with
//     the jitter from one explicitly seeded *rand.Rand so tests can assert
//     the delay sequence instead of hoping.
//
// Identification: the first frame on a connection is the sender's ID, sent
// unconditionally by both sides, so neither waits for the other. This is a
// transport-level name, NOT authentication - a hostile dialer can claim any
// ID, and verifying whoever owns an ID is the wire layer's signed HELLO plus
// the relay/peer policy of later tasks. The transport only refuses IDs that
// are USELESS: the local node's own ID (a validator must never be fed its own
// messages back - it already holds its own votes, and re-feeding them would
// double-count the one vote per validator the tally relies on), and a second
// connection to a peer already connected. Which of two connections to the same
// peer survives is decided by a deterministic rank, stated at
// newcomerWins/ErrDuplicatePeer and computed IDENTICALLY at both ends of the
// pair - two nodes that list each other at boot otherwise race their cross
// dials and can end, each side evicting the other's winner, with none.
package tcp

import (
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cti97/b10coincom/internal/transport"
	"github.com/cti97/b10coincom/internal/wire"
)

const (
	// DefaultMaxFrameBytes bounds a frame at 1 MiB. Consensus messages are
	// hundreds of bytes; only a BLOCK_SYNC response (Task 4) approaches
	// block payloads, and a devnet block is well under this. Every node in
	// an honest run uses the same default, but the knob exists because a
	// peer with a smaller bound must be able to say "too big, try less"
	// without being disconnected for it (the oversized frame is skipped, and
	// the connection lives on - see the reader).
	DefaultMaxFrameBytes = 1 << 20
	// DefaultWriteQueueSize is the bound that keeps Broadcast from ever
	// waiting on a slow peer: 128 frames is far beyond everything one round
	// of consensus produces, so an honest peer never drops, and a wedged
	// peer costs the sender buffered memory only.
	//
	// The worst case, spelled out with the arithmetic because the bound is
	// in FRAMES, not bytes: 128 frames x (DefaultMaxFrameBytes 1 MiB
	// payload + a frame header) = just over 128 MiB of bufferable memory PER
	// WEDGED PEER CONNECTION, if every queued frame were at today's size
	// limit. With current consensus traffic (hundreds of bytes per frame)
	// the same 128-frame bound caps a wedged peer at tens of KiB. When Task
	// 4 puts block-sized frames on the wire, this number - or a byte-level
	// companion bound - must be revisited along with it; until then the
	// frame bound is the one the drop policy and the slow-reader test
	// assert. Shrinking it is always safe for the no-block property.
	DefaultWriteQueueSize = 128
	// DefaultHandshakeTimeout bounds how long a connection may take to
	// introduce itself before it is closed. A socket that opens and then
	// speaks nothing is either a port scanner or a stuck peer; both deserve
	// a deadline, not a reader goroutine held forever.
	DefaultHandshakeTimeout = 5 * time.Second
	// DefaultDialTimeout bounds one outbound TCP connect.
	DefaultDialTimeout = 5 * time.Second
	// DefaultBackoffBase/Max are the reconnection curve. Doubled with jitter
	// up to a 30 s ceiling: fast for a peer that blipped, patient for one
	// that restarted, never a busy redial loop against a dead address.
	DefaultBackoffBase = 100 * time.Millisecond
	DefaultBackoffMax  = 30 * time.Second
	// acceptRetryDelay spaces out retries when Accept fails while the
	// transport is still open (e.g. a transient fd exhaustion), instead of
	// hot-looping on a persistent error.
	acceptRetryDelay = 100 * time.Millisecond
)

// Errors returned by the transport's methods and adopt path.
var (
	// ErrClosed is returned by any method that cannot run because Close
	// already ran.
	ErrClosed = errors.New("tcp: transport is closed")
	// ErrUnknownPeer is returned by Send for a peer that is not connected -
	// including the local node's own ID, which can never be a peer (self
	// connections are refused at the handshake). "Unknown" is honest: the
	// transport is not asserting the peer will never exist, only that it is
	// not there NOW, and Send's caller owns the retry.
	ErrUnknownPeer = errors.New("tcp: not connected to this peer")
	// ErrQueueFull is returned by Send when the peer's bounded write queue is
	// full and the frame was dropped. Broadcast drops silently instead: gossip
	// is redundant, and an error here would push every sender into
	// slow-peer handling that the bound exists to make unnecessary.
	ErrQueueFull = errors.New("tcp: the peer's write queue is full; frame dropped")
	// ErrSelfConnection is returned when a handshake reveals the other end
	// claims the local node's own ID. The connection is closed. It does not
	// matter whether it is a misconfigured loopback dial or a squatter
	// claiming our ID: a message fed back from "ourselves" would double-count
	// this validator's votes.
	ErrSelfConnection = errors.New("tcp: refusing a connection to the local node itself")
	// ErrDuplicatePeer is returned when a connection's handshake names a peer
	// that already has a live connection that outranks it, so the NEW
	// connection is the one closed. Exactly one connection survives every
	// duplicate - the policy is at newcomerWins, and it is computed
	// identically at both ends of the pair, so a cross-dial (two nodes that
	// list each other at boot) leaves one healthy link, not zero. The loser's
	// registry entry is released: when the loser was the incumbent, its
	// registration transfers to the winner's side, whose maintainer is the
	// one keeping the link alive.
	ErrDuplicatePeer = errors.New("tcp: a live connection to this peer already exists")
)

// Options configures a TCP transport. Every duration and bound has a default;
// only LocalID is required, because a connection that cannot say who it is
// cannot be told apart from any other.
type Options struct {
	// LocalID is this node's identity on the wire: it is sent as the first
	// frame of every outgoing connection and read as the first frame of
	// every incoming one. It must be non-empty (the frame layer refuses
	// zero-length frames), and it is a NAME, not a proof - see the package
	// comment.
	LocalID transport.PeerID
	// MaxFrameBytes is the largest frame the reader will accept, enforced by
	// wire.ReadFrame before any allocation (a hostile 4-byte length prefix
	// must not `make` a 4 GiB buffer). Default DefaultMaxFrameBytes.
	MaxFrameBytes int
	// WriteQueueSize is the per-connection writer queue bound. Default
	// DefaultWriteQueueSize.
	WriteQueueSize int
	// HandshakeTimeout bounds the identity exchange. Default
	// DefaultHandshakeTimeout.
	HandshakeTimeout time.Duration
	// DialTimeout bounds one outbound TCP connect. Default
	// DefaultDialTimeout.
	DialTimeout time.Duration
	// BackoffBase and BackoffMax are the reconnection curve. Defaults
	// DefaultBackoffBase and DefaultBackoffMax.
	BackoffBase time.Duration
	BackoffMax  time.Duration
	// Rand is the source of the reconnection jitter. An explicitly seeded
	// *rand.Rand makes the delay sequence a function of that seed, so a test
	// asserts the delays rather than hoping they grew; if nil, one is seeded
	// from the clock, which is the right choice for a node that runs
	// unattended (its jitter sequence is then as unique as its start time).
	Rand *rand.Rand
}

// withDefaults applies every zero value so the connection machinery below can
// assume a sane, fully-specified configuration.
func (o Options) withDefaults() Options {
	if o.MaxFrameBytes <= 0 {
		o.MaxFrameBytes = DefaultMaxFrameBytes
	}
	if o.WriteQueueSize <= 0 {
		o.WriteQueueSize = DefaultWriteQueueSize
	}
	if o.HandshakeTimeout <= 0 {
		o.HandshakeTimeout = DefaultHandshakeTimeout
	}
	if o.DialTimeout <= 0 {
		o.DialTimeout = DefaultDialTimeout
	}
	if o.BackoffBase <= 0 {
		o.BackoffBase = DefaultBackoffBase
	}
	if o.BackoffMax < o.BackoffBase {
		// A ceiling below the floor would make the curve a flat line at an
		// arbitrary point; raise the ceiling to the floor instead.
		o.BackoffMax = o.BackoffBase
	}
	if o.Rand == nil {
		o.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))
	}
	return o
}

// conn is one live TCP connection. Its immutable fields (remote, nc, tq,
// dead) are fixed before the reader and writer goroutines start; mutable
// state is either atomic (dropped), protected by the transport's mutex
// (registry membership), or owned by exactly one goroutine.
type conn struct {
	remote transport.PeerID
	nc     net.Conn
	// tq is the BOUNDED write queue - the whole point of the writer design.
	// The writer is the only reader; enqueue never blocks (select/default).
	tq chan []byte
	// addr is where an outbound connection came from, for logging context.
	addr string
	// dialled records whether the LOCAL end of this connection is the side
	// that dialled (true) or the side that accepted (false). It is fixed at
	// construction and is half of the duplicate-rank decision: see
	// newcomerWins for why both ends must agree on which copy of a
	// duplicated peer connection survives.
	dialled bool
	// dead is closed exactly once, by finish, when the connection is over.
	// A connection's maintainer goroutine sleeps on it.
	dead chan struct{}
	// finishOnce makes finish idempotent: both the reader and the writer can
	// discover the connection is over (a read error and a write error are
	// often the same event), and exactly one of them must clean up.
	finishOnce sync.Once
	// dropped counts frames refused because the queue was full. Same-package
	// tests read it; a metrics story would hang off it later.
	dropped atomic.Uint64
	// superseded is set under the transport's mutex, strictly BEFORE finish
	// closes dead, when this conn was replaced in the registry by a
	// higher-ranked connection to the same peer, and it is READ under the
	// same mutex too. The mutex is the synchronisation, not the channel: the
	// maintainer wakes on close(dead), but a dying loser's own reader can
	// fire that close (its socket died of the same eviction) BEFORE the
	// winner's adopt has written the flag - the race detector caught exactly
	// that read racing the write - so the channel close is only the wake-up
	// and every access to the flag is mutex-guarded. The maintainer checks
	// it after <-dead: a superseded conn must not be redialled, or the old
	// and new connections would keep evicting each other forever (four
	// goroutines, one socket, all churning).
	superseded bool
}

// finish tears the connection down exactly once: unblock the maintainer, make
// any blocked socket call error out, and remove the conn from the registry.
//
// The teardown is ONE critical section: close(dead), the socket close and the
// registry exit hold the transport's mutex together. Splitting them leaves a
// window - dead but still named in the registry - in which Send resolves a
// corpse: the frame is enqueued, the call reports nil, and the writer (already
// past its dead check) never writes it. A unicast lost that way is invisible
// at every layer above (Send succeeded; the peer never saw a byte), which is
// exactly the shape CI reported for the cross-dial: each side showed one
// healthy connection, a's Send succeeded, and b decoded nothing. Atomicity
// closes it by construction: a registry entry is either not-yet-dying (its
// writer is running) or not-in-the-registry.
func (t *TcpTransport) finish(c *conn) {
	c.finishOnce.Do(func() {
		t.mu.Lock()
		close(c.dead)
		_ = c.nc.Close()
		if t.conns[c.remote] == c {
			delete(t.conns, c.remote)
		}
		t.mu.Unlock()
	})
}

// enqueue puts one copy of data on the connection's write queue, or drops it
// if the queue is full. It NEVER blocks: that is the property that keeps a
// wedged peer from stalling the sender's consensus loop. The copy is the
// Transport contract: the caller's buffer is theirs to reuse the moment the
// call returns, and the queue holds bytes past that return.
func (c *conn) enqueue(data []byte) bool {
	cp := append([]byte(nil), data...)
	select {
	case c.tq <- cp:
		return true
	default:
		c.dropped.Add(1)
		return false
	}
}

// outbound is one configured remote address the transport keeps a connection
// to, dialling again with backoff whenever the connection dies - including
// redialling the relay after it restarts, which is the spec's section 6.6
// reconnection requirement.
type outbound struct {
	addr string
}

// TcpTransport moves opaque bytes over real TCP.
type TcpTransport struct {
	opts Options
	// backoff is shared by every maintainer: one rng, one delay curve, seeded
	// from Options.Rand. Next takes its lock, so the maintainers' interleaved
	// draws are safe though not individually ordered - jitter needs
	// unpredictability per attempt, not a schedule.
	backoff *Backoff

	mu        sync.Mutex
	lsn       net.Listener
	conns     map[transport.PeerID]*conn
	outbounds map[string]*outbound
	onMessage func(transport.Message)
	// dispatchMu serialises OnMessage callback invocation (and guards the
	// callback slot itself). At most one callback runs at a time, because
	// the ONLY consumer, consensus's driver, is a single-threaded state
	// machine - the very property replay depends on. The price is documented
	// in dispatch.
	dispatchMu sync.Mutex

	quit      chan struct{}
	closeOnce sync.Once
	closed    atomic.Bool
	closeErr  error
	// wg counts the accept loop and the maintainer goroutines - the ones
	// Close must wait for. The per-connection reader/writer goroutines are
	// deliberately NOT counted: Close must not hang on a goroutine parked
	// inside a user callback; closing the socket is what stops them, and the
	// CloseIsIdempotent test watches goroutine counts to prove it happens.
	wg sync.WaitGroup

	// droppedOversized counts frames refused by the size bound and skipped.
	droppedOversized atomic.Uint64
	// lastRedialDelay records the delay the maintainer most recently backed
	// off before redialling. Observability first - a peer flapping forever on
	// a stuck 30s curve is diagnosable from this one number - and it is what
	// lets the reconnection test MEASURE the curve a fixed seed produces
	// instead of inferring it from arrival times.
	lastRedialDelay atomic.Int64
}

// New returns a stopped transport. Nothing runs - no goroutine, no socket -
// until Listen or Dial/AddPeer is called.
func New(opts Options) (*TcpTransport, error) {
	if opts.LocalID == "" {
		// Refuse it here rather than at connect time: an empty LocalID is a
		// construction bug, and every connection it would open is doomed.
		return nil, fmt.Errorf("tcp: LocalID must be non-empty")
	}
	o := opts.withDefaults()
	return &TcpTransport{
		opts:      o,
		backoff:   NewBackoff(o.BackoffBase, o.BackoffMax, o.Rand),
		conns:     make(map[transport.PeerID]*conn),
		outbounds: make(map[string]*outbound),
		quit:      make(chan struct{}),
	}, nil
}

// Listen accepts inbound connections on addr. It returns error only for a
// failed net.Listen (a taken port, say) or a double Listen; once it returns
// nil, the transport answers dials until Close.
func (t *TcpTransport) Listen(addr string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed.Load() {
		return ErrClosed
	}
	if t.lsn != nil {
		return fmt.Errorf("tcp: already listening on %s", t.lsn.Addr())
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	t.lsn = l
	t.wg.Add(1)
	go t.acceptLoop(l)
	return nil
}

// Addr reports the listener's address. The tests dial 127.0.0.1:0 and learn
// the real port here - hardcoding a port would collide with a concurrent
// test run, which is exactly how flaky suites are born.
func (t *TcpTransport) Addr() net.Addr {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.lsn == nil {
		return nil
	}
	return t.lsn.Addr()
}

func (t *TcpTransport) acceptLoop(l net.Listener) {
	defer t.wg.Done()
	for {
		nc, err := l.Accept()
		if err != nil {
			if t.closed.Load() {
				return // the listener was closed on purpose
			}
			// A live transport must keep accepting: retry rather than let a
			// transient Accept failure (fd pressure) silently strip this
			// node of ALL inbound connectivity.
			select {
			case <-t.quit:
				return
			case <-time.After(acceptRetryDelay):
				continue
			}
		}
		// adopt performs the handshake, which blocks on the remote speaking
		// - it must never run on the accept loop itself, or one slow dialer
		// would block every other inbound connection. The goroutine IS
		// tracked on the same WaitGroup Close waits on (registered under the
		// mutex, refused if Close already ran, mirroring registerOutbound),
		// so an inbound handshake in flight can neither outlive Close nor
		// slip past Close's wait - and Close's latency when one is in flight
		// is bounded by the handshake deadline, not unbounded.
		t.mu.Lock()
		if t.closed.Load() {
			t.mu.Unlock()
			nc.Close()
			continue
		}
		addr := nc.RemoteAddr().String()
		t.wg.Add(1)
		go func() {
			defer t.wg.Done()
			// An inbound failure is the dialer's problem by definition:
			// there is no registered maintainer to redial a stranger.
			_, _ = t.adopt(nc, addr, false)
		}()
		t.mu.Unlock()
	}
}

// Dial connects to addr now and, once connected, keeps the peer connected:
// if the connection dies, it is redialled with backoff until Close. The
// returned error is the FIRST dial's outcome - a later failure surfaces only
// as the peer dropping in and out of Peers(). Calling Dial twice for the same
// address is idempotent (one maintainer per address).
func (t *TcpTransport) Dial(addr string) error {
	res := make(chan error, 1) // buffered: the maintainer must never park on us
	spawned, err := t.registerOutbound(addr, res)
	if err != nil {
		return err
	}
	if !spawned {
		return nil // already registered: exactly what idempotent means here
	}
	return <-res // the first dial's answer; the maintainer keeps running
}

// AddPeer registers addr as a remote this transport should always be
// connected to, and starts maintaining it - the configured-peer form of Dial.
// It never blocks on the network: the first dial happens on the maintainer
// goroutine and retries with backoff, which is what a node wants from its
// static peer list at boot, when a peer may be down for minutes.
func (t *TcpTransport) AddPeer(addr string) error {
	_, err := t.registerOutbound(addr, nil)
	return err
}

// registerOutbound deduplicates by address and spawns the maintainer. The
// wg.Add happens under the same lock as the registration, and Close sets its
// closed flag before taking the lock to snapshot-and-wait, so a maintainer
// can never be spawned "after" Close finished waiting on zero goroutines -
// the classic Add-after-Wait race, refused here by construction, not by
// counting on -race to find it.
func (t *TcpTransport) registerOutbound(addr string, first chan<- error) (bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed.Load() {
		return false, ErrClosed
	}
	if _, ok := t.outbounds[addr]; ok {
		return false, nil
	}
	ob := &outbound{addr: addr}
	t.outbounds[addr] = ob
	t.wg.Add(1)
	go t.maintain(ob, first)
	return true, nil
}

// maintain is the reconnection loop for one address: dial, handshake, hold
// until the connection dies, then redial after a growing, jittered delay.
// Three findings end the loop: the transport closing (quit); the peer
// proving already-connected - duplicate or self - where redialling would
// only re-create a connection the registry just refused (that link belongs
// to whichever side's rank won it, and its maintainer is the one feeding
// it); or the connection being superseded, which is the same case seen from
// the losing maintainer's side of the handshake.
//
// EVERY one of those exits releases the address registration (the deferred
// forgetOutbound): a maintainer that stops running while its registration
// survives would leave Dial/AddPeer reporting a maintainer that does not
// exist, and behind that lie, a peer set nothing ever refills.
func (t *TcpTransport) maintain(ob *outbound, first chan<- error) {
	defer t.wg.Done()
	addr := ob.addr
	// The release is identity-checked, so a dying maintainer can never
	// delete a registration a racing AddPeer just created for the same
	// address - only exactly this maintainer's registration goes.
	defer t.forgetOutbound(ob)
	attempt := 0
	report := func(err error) {
		if first != nil {
			first <- err
			first = nil
		}
	}
	for {
		nc, err := net.DialTimeout("tcp", addr, t.opts.DialTimeout)
		if err != nil {
			report(err)
		} else {
			// adopt owns nc from here; on failure it closed it.
			c, err := t.adopt(nc, addr, true)
			report(err)
			if err == nil {
				attempt = 0 // a live connection resets the curve: one success outranks every prior failure
				select {
				case <-c.dead:
					// The flag is mutex-guarded on BOTH sides (see
					// conn.superseded): close(dead) is only the wake-up -
					// a concurrent socket death may have fired it before
					// the winner's adopt even wrote the flag - so the read
					// takes the same lock the write took.
					t.mu.Lock()
					wasSuperseded := c.superseded
					t.mu.Unlock()
					if wasSuperseded {
						// Replaced by a higher-ranked connection to this
						// peer. The winner keeps the link, so this side
						// stops maintaining it - and the deferred release
						// above makes the stop honest: the registration
						// goes with the maintainer instead of masking the
						// absence of any redial behind a claimed one.
						return
					}
				case <-t.quit:
					return
				}
			} else if errors.Is(err, ErrSelfConnection) || errors.Is(err, ErrDuplicatePeer) {
				// Dormant, not failed: there is nothing to connect to that
				// is not already connected by a higher-ranked connection,
				// maintained on this side or the far one. Redialling here
				// would churn - each attempt opens a socket the registry
				// immediately refuses.
				return
			}
		}
		attempt++
		delay := t.backoff.Next(attempt)
		t.lastRedialDelay.Store(int64(delay))
		select {
		case <-t.quit:
			return
		case <-time.After(delay):
		}
	}
}

// forgetOutbound releases ob's address registration when its maintainer exits
// for good - dormant, superseded, or the transport closing - so a later
// Dial/AddPeer of the same address is answered by a maintainer that exists
// rather than waved off as idempotent by a stale entry.
func (t *TcpTransport) forgetOutbound(ob *outbound) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if cur := t.outbounds[ob.addr]; cur == ob {
		delete(t.outbounds, ob.addr)
	}
}

// adopt performs the identity handshake and installs the connection.
//
// Both sides write their ID FIRST, unconditionally and before reading, so
// neither can block the other: a cross-dial (A dials B while B dials A)
// completes without any lockstep. The read carries the handshake deadline -
// after it, the reader owns the socket and may block forever, because a live
// connection is idle most of the time and that is not an error.
//
// dialled says whether THIS end is the side that opened the connection (the
// maintainer's dial) or the side that accepted it; it feeds the duplicate
// rank, which needs the direction to stay decidable identically at both ends.
func (t *TcpTransport) adopt(nc net.Conn, addr string, dialled bool) (*conn, error) {
	if err := nc.SetWriteDeadline(time.Now().Add(t.opts.HandshakeTimeout)); err != nil {
		nc.Close()
		return nil, err
	}
	if err := wire.WriteFrame(nc, []byte(t.opts.LocalID)); err != nil {
		nc.Close()
		return nil, fmt.Errorf("tcp: writing handshake to %s: %w", addr, err)
	}
	if err := nc.SetWriteDeadline(time.Time{}); err != nil {
		nc.Close()
		return nil, err
	}

	if err := nc.SetReadDeadline(time.Now().Add(t.opts.HandshakeTimeout)); err != nil {
		nc.Close()
		return nil, err
	}
	hello, err := wire.ReadFrame(nc, t.opts.MaxFrameBytes)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("tcp: reading handshake from %s: %w", addr, err)
	}
	// A live connection may be silent for hours: the deadline exists for the
	// handshake only.
	if err := nc.SetReadDeadline(time.Time{}); err != nil {
		nc.Close()
		return nil, err
	}
	// wire.ReadFrame refuses zero-length frames, so hello cannot be empty:
	// the handshake cannot introduce an "" peer. It can introduce a LIE, but
	// a transport-level name is only a routing key - authentication is the
	// signed HELLO of later tasks.
	id := transport.PeerID(hello)

	c := &conn{
		remote:  id,
		nc:      nc,
		tq:      make(chan []byte, t.opts.WriteQueueSize),
		dead:    make(chan struct{}),
		addr:    addr,
		dialled: dialled,
	}

	t.mu.Lock()
	if t.closed.Load() {
		t.mu.Unlock()
		nc.Close()
		return nil, ErrClosed
	}
	if id == t.opts.LocalID {
		t.mu.Unlock()
		nc.Close()
		return nil, fmt.Errorf("%w (%q on %s)", ErrSelfConnection, id, addr)
	}
	existing := t.conns[id]
	if existing != nil && !newcomerWins(t.opts.LocalID, existing, c) {
		// The incumbent outranks the newcomer: the newcomer loses, the
		// incumbent stays EXACTLY as it was (still installed, still healthy,
		// still maintained by whichever side holds it). This is the branch
		// a maintainer's re-dial lands in when the peer's own dial won the
		// link: its registration was released on exit, so the registry no
		// longer claims what it did not keep.
		t.mu.Unlock()
		nc.Close()
		return nil, fmt.Errorf("%w (%q on %s)", ErrDuplicatePeer, id, addr)
	}
	if existing != nil {
		// The newcomer outranks the incumbent, so the newcomer WINS the
		// registry and exactly one healthy connection exists afterwards:
		// the loser is marked under this same critical section (F3: no
		// unsynchronised write to superseded, ever), removed from the
		// registry by THIS install, and only then closed by finish - whose
		// registry delete is a no-op, because the entry now holds the
		// winner. The loser's maintainer, if any, wakes on <-dead and reads
		// superseded under the same mutex this write took, then goes
		// dormant: the winner's side keeps the link, and
		// this side's registration is released with it (see maintain).
		existing.superseded = true
	}
	t.conns[id] = c
	t.mu.Unlock()
	if existing != nil {
		t.finish(existing)
	}

	go t.writer(c)
	go t.reader(c)
	return c, nil
}

// newcomerWins decides which of two connections to the same peer keeps the
// registry, and it must answer IDENTICALLY at both ends of the pair - that is
// the whole point. Two nodes that list each other at boot cross-dial: each
// end sees {its own dial, the peer's dial} for the same ID. If each end picked
// a winner by arrival order, the picks would be independent coin flips; when
// they disagree, each side evicts the other's winner, both sockets half-close,
// and the pair sits with zero connections and no maintainer - a silent,
// permanent partition on an ordinary startup. The rank below is a function of
// facts both ends compute the same way:
//
//   - the endpoints' IDs and the DIRECTION of each connection: of a matched
//     pair, the socket dialled by the lexicographically SMALLER peer ID wins.
//     local<remote means our own dial outranks their dial; local>remote means
//     their dial outranks ours. Whichever way it falls, both sides land on
//     the SAME socket, and it is the smaller node's outbound - so the link
//     always keeps a maintainer (the dialling side's);
//   - same direction on both candidates (two of our own dials, or two of
//     theirs): the incumbent wins. First established stays; re-dial races
//     cannot churn the registry by re-running the same replacement.
func newcomerWins(local transport.PeerID, existing, newcomer *conn) bool {
	if existing.dialled != newcomer.dialled {
		if local < existing.remote {
			return newcomer.dialled // we are the smaller end: our dial wins
		}
		return !newcomer.dialled // we are the larger end: their dial wins
	}
	return false // same direction on both: the incumbent stays
}

// reader is the per-connection read goroutine: frame, dispatch, repeat, until
// the framing fails. It owns the socket for reading for the connection's
// lifetime.
func (t *TcpTransport) reader(c *conn) {
	for {
		payload, err := wire.ReadFrame(c.nc, t.opts.MaxFrameBytes)
		if err != nil {
			var otl *wire.FrameTooLarge
			if errors.As(err, &otl) {
				if t.skipOversized(c, otl) {
					continue
				}
				break
			}
			// EOF, reset, truncation, a zero-length frame, a malformed
			// header: framing is unsalvageable (there is no knowing where the
			// next frame begins), so the connection ends. A reconnecting peer
			// redials through its maintainer; the consensus layer tolerates
			// the loss.
			break
		}
		t.dispatch(transport.Message{From: c.remote, Data: payload})
	}
	t.finish(c)
}

// skipOversized discards exactly the bytes of a frame the bound refused, so
// the stream re-synchronises on the next frame and the connection lives. The
// length prefix that made the frame oversized is also the only information
// needed to skip it - the same fact that makes the pre-allocation bound in
// wire.ReadFrame safe to enforce before allocating.
//
// The trade, written down: an attacker can claim a 4 GiB length and then drip
// bytes forever, keeping THIS reader busy - but per-connection goroutines
// contain it, no memory is allocated for the skipped bytes, and every other
// peer is unaffected. Killing the connection instead would punish the
// honest-but-misconfigured case (a peer whose MaxFrameBytes is bigger than
// ours sending a large frame) with a severed link: consensus tolerates a lost
// frame vastly better than a lost peer.
func (t *TcpTransport) skipOversized(c *conn, otl *wire.FrameTooLarge) bool {
	if _, err := io.CopyN(io.Discard, c.nc, otl.Declared); err != nil {
		// The declared payload never fully arrived, so framing is broken
		// after all: end the connection.
		return false
	}
	t.droppedOversized.Add(1)
	return true
}

// dispatch hands one message to the OnMessage callback. At most one callback
// runs at a time (the lock is held across the call, not just the fetch):
// consensus's engine is single-threaded, and concurrent delivery from two
// readers would corrupt it - a bug -race would only find in Task 6.
//
// The cost of that choice is honest: a callback that blocks stalls delivery
// for the WHOLE transport, exactly once per received frame. That is the
// documented price of a single-threaded engine; the SENDING side is what the
// bounded queues protect, and that is the property this task is judged on.
func (t *TcpTransport) dispatch(m transport.Message) {
	t.dispatchMu.Lock()
	defer t.dispatchMu.Unlock()
	if t.onMessage != nil {
		t.onMessage(m)
	}
}

// writer is the per-connection write goroutine: drain the queue onto the
// socket, one framed payload at a time, and exit when the connection is over.
func (t *TcpTransport) writer(c *conn) {
	for {
		select {
		case <-c.dead:
			return
		case b := <-c.tq:
			if err := wire.WriteFrame(c.nc, b); err != nil {
				// The socket failed; close it, which wakes the reader into
				// finish (a no-op if we got here second).
				t.finish(c)
				return
			}
		}
	}
}

// Broadcast enqueues data to every connected peer except the sender, copying
// it first: the caller may reuse the buffer the moment this returns, and the
// queue holds bytes long after. It returns in bounded time WHATEVER the
// peers are doing - a queue-full peer is a dropped frame, not a blocked
// caller (Send's ErrQueueFull documents the policy for the caller who cares;
// gossip does not).
//
// "Except the sender" needs no check here, precisely because it is enforced
// one layer down: a connection that announces itself with this node's own ID
// is refused at the handshake (ErrSelfConnection), so the registry this
// iterates can never contain the sender. The test TestBroadcastSkipsTheSender
// pins that end of the invariant.
func (t *TcpTransport) Broadcast(data []byte) error {
	t.mu.Lock()
	targets := make([]*conn, 0, len(t.conns))
	for _, c := range t.conns {
		targets = append(targets, c)
	}
	t.mu.Unlock()
	for _, c := range targets {
		c.enqueue(data)
	}
	return nil
}

// Send enqueues data to exactly one peer: the unicast a BLOCK_SYNC
// request/response travels on. An unknown peer (or a full queue) is an error,
// never a silent success - the syncer owns the retry, and it can only retry
// what it knows failed.
//
// The whole Send happens under the transport's mutex - the same critical
// section finish uses to close a connection and remove it from the registry -
// so the lookup, the liveness check and the enqueue are ATOMIC. A nil return
// means the frame was accepted into a connection whose writer was running at
// enqueue time; there is no state in which Send resolves a connection the
// transport has already torn down. What a nil return does NOT promise is the
// frame's delivery THROUGH a link that dies moment later: that is TCP's
// reality, and it is the caller's retry plus the one-maintainer-per-link
// redial that recover from it (see maintain). Broadcast keeps its weaker
// best-effort contract by design: gossip is redundant, a drop costs nothing.
func (t *TcpTransport) Send(peer transport.PeerID, data []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	c := t.conns[peer]
	if c == nil {
		return fmt.Errorf("%w: %q", ErrUnknownPeer, peer)
	}
	// Unreachable by construction - finish removes the registry entry in the
	// same critical section that closes dead - but retained as the gate the
	// invariant is READ through: a Send must refuse a torn-down connection
	// rather than enqueue into it, whatever future edits do to finish's
	// ordering.
	select {
	case <-c.dead:
		return fmt.Errorf("%w: %q", ErrUnknownPeer, peer)
	default:
	}
	if !c.enqueue(data) {
		return fmt.Errorf("%w (%q)", ErrQueueFull, peer)
	}
	return nil
}

// OnMessage registers the (single) receive callback under the same mutex that
// serialises dispatch, so a re-registration is instantly coherent with the
// readers.
func (t *TcpTransport) OnMessage(fn func(transport.Message)) {
	t.dispatchMu.Lock()
	defer t.dispatchMu.Unlock()
	t.onMessage = fn
}

// Peers lists the connected peers sorted by ID. Deterministic order is not a
// nicety: consensus iterates peers by position, and map-ordered output would
// permute state transitions between runs - the sim's own Peers() doc says
// exactly why that breaks replay.
func (t *TcpTransport) Peers() []transport.PeerID {
	t.mu.Lock()
	defer t.mu.Unlock()
	ids := make([]transport.PeerID, 0, len(t.conns))
	for id := range t.conns {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

// Close idempotently shuts the transport down. What it STOPS and WAITS for:
// the listener, every live connection, and every goroutine that can be blocked
// on the wire - the accept loop, every maintainer, and any inbound connection
// still mid-handshake (all counted on the same WaitGroup). What it stops but
// does NOT wait for: the per-connection readers and writers - nothing waits on
// a goroutine that may be parked inside a user callback - their sockets are
// closed, every blocking call they are inside errors out, and they exit.
// Consequences, stated plainly: Close's return can be held for up to about
// HandshakeTimeout (an inbound handshake that is still reading) plus
// DialTimeout (a maintainer mid-redial), never longer - every wait is deadline-
// or quit-bounded. Once Close returns, the transport reports closed to every
// method, new dials are refused, and the goroutines it waited for are gone.
func (t *TcpTransport) Close() error {
	t.closeOnce.Do(func() {
		// The closed flag goes up BEFORE the snapshot+wait, so a Dial/AddPeer
		// racing Close either registers its goroutine before the wait (and is
		// counted) or sees closed and refuses. See registerOutbound.
		t.closed.Store(true)
		close(t.quit)
		t.mu.Lock()
		lsn := t.lsn
		t.lsn = nil
		conns := make([]*conn, 0, len(t.conns))
		for _, c := range t.conns {
			conns = append(conns, c)
		}
		t.mu.Unlock()

		if lsn != nil {
			t.closeErr = lsn.Close()
		}
		for _, c := range conns {
			t.finish(c)
		}
		t.wg.Wait()
	})
	return t.closeErr
}
