// Package relay is the M4 outbound-dial relay: the piece that makes a home
// Raspberry Pi reachable without a hole punched in anything. The asymmetry it
// exists for (design section 6.6): inbound to a home Pi is blocked by NAT and
// firewalls - and under CGNAT there is no public IP to forward to at all -
// while outbound connect is, almost everywhere, free. So every validator
// dials OUT to this process on a cheap VPS, and the relay forwards frames
// between every other registered connection. No port forwarding, no NAT
// traversal code, CGNAT irrelevant.
//
// The trust property, which this package is shaped to never undermine: every
// consensus message is signed with the sender's Ed25519 key, so a malicious
// relay can censor or delay but CANNOT forge a vote or a proposal. Safety is
// never at risk from the relay; liveness is. The one rule that follows, and
// the design's own words: the relay must parse nothing beyond the frame
// length. It is length-delimited forwarding and nothing else - a relay that
// understood consensus would be a relay that could be WRONG about it, a
// second implementation of the wire semantics living outside the wire
// package, wrong in a way no validator ever sees.
//
// Shape, mirroring the transport's answer to the same problem (one goroutine
// per direction, a bounded write queue, never block the forwarding path):
//
//   - one reader goroutine per connection: ReadFrame, then drop the payload
//     onto every OTHER connection's write queue;
//   - one writer goroutine per connection: drain the queue onto the socket;
//   - enqueue never blocks - a peer whose socket is wedged eats a dropped
//     frame, never a stalled relay;
//   - every read runs under a per-frame read deadline and every accepted
//     socket gets TCP keepalive: a stranger that dials and then stalls, and
//     a peer that vanished without closing, both have their connection and
//     registry slot reaped by the socket itself - the relay learns nothing
//     about the traffic by doing it.
//
// Delivery semantics, stated once because they are the contract every caller
// gets: the fan-out set is the registry AT FORWARDING TIME. A peer's
// connection joins the registry when Accept registers it, which is strictly
// after the peer's dial returned - a frame that reaches the relay while a
// peer's dial sits in the accept backlog is not delivered to that peer, and
// is not queued up for it either. That is message-bus semantics, and it is
// the only semantics a relay that parses nothing and buffers nothing can
// honestly have: shrinking the window would require either a frame buffer
// with delivery policy or knowledge of how many peers are expected, and both
// are things the relay is too dumb to hold. The node layer above (signed
// HELLO, repeated round broadcasts, catch-up pulls) is what makes early-join
// losses harmless; every consensus frame lost this way is a liveness loss the
// round protocol already pays for. What this package guarantees is per
// (sender, receiver) pair: once both are registered, frames arrive in the
// order the sender wrote them, and every queue is bounded.
package relay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cti97/b10coincom/internal/wire"
)

// acceptRetryDelay spaces out retries when Accept fails while the relay is
// still open (transient fd exhaustion, say), instead of hot-looping on a
// persistent error.
const acceptRetryDelay = 100 * time.Millisecond

const (
	// DefaultMaxFrameBytes bounds a frame at 1 MiB, the same bound the TCP
	// transport defaults to: one number for every wire participant, so no
	// honest validator ever sends a frame the relay must refuse. The relay's
	// copy is checked by wire.ReadFrame BEFORE allocation, so a hostile
	// length prefix costs four bytes of header, never four gibibytes of
	// buffer. An operator MAY set it higher, never lower than the validators'
	// bound: a relay stricter than its validators severs every frame that
	// fits at the ends but not in the middle, and the reconnect churn that
	// follows would look like flapping peers, not like a misconfigured knob.
	DefaultMaxFrameBytes = 1 << 20
	// DefaultMaxConns bounds the registry at 256 connections. The honest
	// population is one small validator set; the bound exists for everyone
	// else, because the relay authenticates nothing - it cannot tell a
	// validator from a stranger, that is what "knows nothing" costs - and a
	// stranger with a loop of dials must not own the goroutines and buffers
	// of an unbounded accept loop. A dialed-when-full connection is closed
	// immediately; the honest validator's outbound backoff redials it later.
	// The operational defence for a real deployment sits IN FRONT of the
	// relay, not in it: a VPS firewall allowlisting validator IPs, which is
	// exactly the access policy the relay itself is too dumb to have.
	DefaultMaxConns = 256
	// DefaultWriteQueueSize is the per-connection writer queue bound, the
	// whole point of the writer design: forwarding ENQUEUES, so a wedged
	// reader cannot hold the relay hostage. 64 frames at the frame cap is
	// 64 MiB per wedged connection in the absolute worst case (every queued
	// frame at today's size limit); at real consensus traffic - hundreds of
	// bytes per frame, BLOCK_SYNC responses in the kilobytes - the same
	// bound caps a wedged peer at a few MiB. Halved from the transport's
	// 128 on the same reasoning that gave the transport its frame cap: this
	// is the most exposed process in the project and it runs on the cheapest
	// machine. Honest validators drop nothing: relaying kilobytes per second
	// never approaches 64 backlogged frames.
	DefaultWriteQueueSize = 64
	// DefaultReadTimeout is the per-frame READ DEADLINE: the socket-level
	// bound on how long ONE frame (its 4-byte header plus its full payload)
	// may take to arrive before the connection is ended and its registry
	// slot released. This is the timer a stranger's silence runs against -
	// a client that dials, writes a header and then stalls was previously
	// able to pin exactly one reader goroutine, one frame buffer and one
	// registry slot FOREVER (256 conns x 1 MiB is ~256 MiB the GC could not
	// reclaim, held with nothing but four-byte writes).
	//
	// It parses nothing: the deadline is armed on the socket before the
	// header read and refreshed on every completed frame, so the question it
	// answers is only "has this connection stopped speaking ENTIRELY for
	// this long?" - a peer actively sending is never cut off, and neither
	// the payload nor the framing is inspected.
	//
	// 2 minutes sits well above anything an honest validator does: the node
	// layer over a relay speaks at a cadence of milliseconds to seconds
	// (ticks every 50 ms, round timeouts at 200 ms + 100 ms per escalation,
	// wave rebroadcasts every 500 ms - internal/devnet/tcpnode.go). Silence
	// of a full two minutes is a dead or wedged connection, not a
	// participating one; when it expires the connection is ENDED and its
	// slot is RELEASED the same instant (the reader's finish). A validator
	// redials through its own outbound backoff.
	DefaultReadTimeout = 2 * time.Minute
	// DefaultKeepAlive is the TCP keepalive probe period set on every
	// accepted connection, so a HALF-OPEN connection - a peer that vanished
	// without closing (power cut, wifi loss), its socket open but never
	// answering - is reaped by the socket itself, with no code watching. A
	// peer that is alive answers every probe with a bare ACK; a dead one
	// stops answering and the kernel tears the connection down after the
	// OS's probe count. 15s also sits under common NAT-mapping idle
	// timeouts (30-60s+), which a home validator's mapping needs refreshing
	// during quiet periods. (Go's net package already enables keepalives
	// with this value by default; declaring it here is the same guarantee
	// made explicit and operator-tunable instead of an accident of the
	// toolchain.)
	DefaultKeepAlive = 15 * time.Second
)

// ErrClosed is returned by Listen after Close: a closed relay is closed, not
// half-revivable.
var ErrClosed = errors.New("relay: the relay is closed")

// Options configures a relay. Every bound has a default; a zero or negative
// value means "use the default", the same convention the TCP transport
// options follow.
type Options struct {
	// MaxFrameBytes is the largest frame any connection may send, enforced
	// by wire.ReadFrame before any allocation. Default DefaultMaxFrameBytes.
	MaxFrameBytes int
	// MaxConns is the registry bound. Default DefaultMaxConns.
	MaxConns int
	// WriteQueueSize is the per-connection writer queue bound. Default
	// DefaultWriteQueueSize.
	WriteQueueSize int
	// ReadTimeout is the per-frame read deadline: the longest a single frame
	// (header plus full payload) may take to arrive before the connection is
	// ended and its slot released. Armed on the socket before each header
	// read, refreshed on every completed frame - no byte beyond the frame
	// length is inspected. Default DefaultReadTimeout.
	ReadTimeout time.Duration
	// KeepAlive is the TCP keepalive probe period for accepted connections,
	// how they shed half-open peers in minutes. Default DefaultKeepAlive.
	KeepAlive time.Duration
}

func (o Options) withDefaults() Options {
	if o.MaxFrameBytes <= 0 {
		o.MaxFrameBytes = DefaultMaxFrameBytes
	}
	if o.MaxConns <= 0 {
		o.MaxConns = DefaultMaxConns
	}
	if o.WriteQueueSize <= 0 {
		o.WriteQueueSize = DefaultWriteQueueSize
	}
	if o.ReadTimeout <= 0 {
		o.ReadTimeout = DefaultReadTimeout
	}
	if o.KeepAlive <= 0 {
		o.KeepAlive = DefaultKeepAlive
	}
	return o
}

// Stats is a point-in-time reading of the relay's counters: the minimum an
// unattended process on a €4 VPS needs to be diagnosable over its operator's
// SSH session.
type Stats struct {
	// Conns is the number of currently registered connections.
	Conns int
	// Forwarded counts frames enqueued for onward delivery.
	Forwarded uint64
	// Dropped counts frames lost to a full write queue. A steady nonzero
	// value is the diagnosis for one thing: a peer that is not keeping up.
	// The bound held (nobody else stalled) but the relay is now the one
	// censoring, which is liveness pressure a validator set feels.
	Dropped uint64
	// RefusedConns counts dials closed for exceeding MaxConns.
	RefusedConns uint64
}

// conn is one accepted connection. The relay knows its peers by NOTHING but
// the connection itself: no ID, no HELLO, no handshake. Identification is the
// signed traffic's business, and a relay that checked identities would have
// to parse at least the first frame to do it - the exact line this package
// refuses to cross.
type conn struct {
	nc net.Conn
	// wq is the BOUNDED write queue. The writer is its only reader; enqueue
	// never blocks (select/default), which is the property that keeps a slow
	// peer from stalling the relay for everyone else.
	wq chan []byte
	// dead is closed exactly once, by finish, when the connection is over.
	dead chan struct{}
	// once makes finish idempotent: reader, writer and Close can all
	// discover the end of the connection, and exactly one cleans up.
	once sync.Once
}

// finish tears one connection down exactly once: close the socket (unblocking
// every goroutine parked on it), close dead (unblocking the writer), and drop
// the connection from the registry.
func (r *Relay) finish(c *conn) {
	c.once.Do(func() {
		close(c.dead)
		_ = c.nc.Close()
		r.mu.Lock()
		delete(r.conns, c)
		r.mu.Unlock()
	})
}

// Relay is the middlebox: a listener, a registry, and per-connection
// goroutines that move opaque frames. It holds no identities, no state about
// the chain, and no opinion about the bytes.
type Relay struct {
	opts Options

	mu    sync.Mutex
	lsn   net.Listener
	conns map[*conn]struct{}

	quit      chan struct{}
	closed    atomic.Bool
	closeOnce sync.Once
	// wg counts the accept loop and every per-connection reader and writer.
	// Unlike the transport, the relay CAN wait for all of them at Close: its
	// goroutines never run caller code (everything is a socket call), so
	// closing the sockets unblocks each one deterministically.
	wg sync.WaitGroup

	forwarded atomic.Uint64
	dropped   atomic.Uint64
	refused   atomic.Uint64
}

// New returns a relay with all bounds defaulted. Nothing runs and nothing is
// open until Listen.
func New(opts Options) *Relay {
	return &Relay{
		opts:  opts.withDefaults(),
		conns: make(map[*conn]struct{}),
		quit:  make(chan struct{}),
	}
}

// Listen accepts connections on addr until Close. It returns error only for a
// failed net.Listen, a double Listen, or a Listen after Close.
func (r *Relay) Listen(addr string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed.Load() {
		return ErrClosed
	}
	if r.lsn != nil {
		return fmt.Errorf("relay: already listening on %s", r.lsn.Addr())
	}
	// TCP keepalive is set here, at listener construction, on every
	// connection this listener ever accepts: the half-open reaping is
	// socket-level (Option comment), never code watching a byte.
	lc := net.ListenConfig{KeepAlive: r.opts.KeepAlive}
	l, err := lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		return err
	}
	r.lsn = l
	r.wg.Add(1)
	go r.acceptLoop(l)
	return nil
}

// Addr reports the listener's address.
func (r *Relay) Addr() net.Addr {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.lsn == nil {
		return nil
	}
	return r.lsn.Addr()
}

// Stats returns a point-in-time reading of the relay's counters.
func (r *Relay) Stats() Stats {
	r.mu.Lock()
	conns := len(r.conns)
	r.mu.Unlock()
	return Stats{
		Conns:        conns,
		Forwarded:    r.forwarded.Load(),
		Dropped:      r.dropped.Load(),
		RefusedConns: r.refused.Load(),
	}
}

func (r *Relay) acceptLoop(l net.Listener) {
	defer r.wg.Done()
	for {
		nc, err := l.Accept()
		if err != nil {
			if r.closed.Load() {
				return // the listener was closed on purpose
			}
			// A live relay must keep accepting: retry rather than let a
			// transient Accept failure (fd pressure) silently strip every
			// validator of its one outbound lifeline. The retry is spaced:
			// a persistently failing Accept must not become a hot loop.
			select {
			case <-r.quit:
				return
			case <-time.After(acceptRetryDelay):
				continue
			}
		}
		r.mu.Lock()
		if r.closed.Load() {
			r.mu.Unlock()
			nc.Close()
			continue
		}
		if len(r.conns) >= r.opts.MaxConns {
			r.mu.Unlock()
			r.refused.Add(1)
			nc.Close()
			continue
		}
		c := &conn{
			nc:   nc,
			wq:   make(chan []byte, r.opts.WriteQueueSize),
			dead: make(chan struct{}),
		}
		r.conns[c] = struct{}{}
		// Registered under the same lock that Close's snapshot takes, before
		// the goroutines start: a Close racing an accept either sees the
		// connection in the registry (and finishes it) or finds the closed
		// flag up and closes the raw socket itself. The wait below is
		// therefore never outrun by a spawn.
		r.wg.Add(2)
		go r.reader(c)
		go r.writer(c)
		r.mu.Unlock()
	}
}

// reader is the per-connection read goroutine: read one frame, hand it to
// every other connection, repeat, until the framing fails. It interprets
// NOTHING in the payload - that discipline is the package's entire worth, and
// it lives in what this loop does NOT contain: no decode, no tag check, no
// dedup, no "obvious fix" for malformed traffic beyond ending one connection.
func (r *Relay) reader(c *conn) {
	defer r.wg.Done()
	defer r.finish(c)
	for {
		// The per-frame read deadline is armed BEFORE the header and refreshed
		// for every frame, so it measures one frame's whole silence - from
		// starting to read out a frame to having it completely - and never a
		// connection's total age: a peer actively sending frames renews this
		// timer at every frame and is never cut off. Both timers are socket
		// level: they parse nothing, decide nothing about the payload - they
		// only bound how long a stranger may hold a goroutine, a frame buffer
		// and a registry slot without delivering a complete frame. On expiry
		// the connection is ENDED and its slot is RELEASED, below, the same
		// path any other framing failure takes.
		if err := c.nc.SetReadDeadline(time.Now().Add(r.opts.ReadTimeout)); err != nil {
			break // the socket itself is gone; the deferred finish cleans up
		}
		// ReadFrame checks the declared length against the bound BEFORE
		// allocating, so the hostile four-byte header of an oversized frame
		// is refused without ever materialising the buffer it promised.
		payload, err := wire.ReadFrame(c.nc, r.opts.MaxFrameBytes)
		if err != nil {
			var otl *wire.FrameTooLarge
			if errors.As(err, &otl) {
				// The TCP transport skips an oversized frame and keeps the
				// connection: its peers are configured nodes whose bounds
				// may merely disagree, and a severed link costs consensus
				// more than a skipped frame. The relay grants no such
				// charity: every connection is a stranger until the wire
				// proves otherwise (which it cannot - the relay does not
				// look), a frame over the SHARED bound is a protocol
				// violation by construction, and the skip alternative lets
				// a hostile peer pin one goroutine and drip bytes forever.
				// Ending the connection costs a redial; keeping it costs an
				// unguarded read loop.
				break
			}
			// Read errors beyond a declared-too-large frame: EOF, reset,
			// truncation mid-payload, the read deadline expiring above -
			// framing is unsalvageable: there is no knowing where the next
			// frame begins, so the connection ends. (A zero-length frame
			// would be perfectly delimited - its header says so - and is
			// refused anyway because wire.ReadFrame folds n == 0 into
			// ErrShortFrame beside real truncation, and the relay takes a
			// frame error at face value. An empty frame is not a message.)
			// A validator redials through its own outbound backoff.
			break
		}
		r.forward(c, payload)
	}
}

// forward delivers one payload to every OTHER registered connection by
// enqueuing it on their writers - never waiting, never parsing.
//
// The payload slice is shared, not copied, and that is deliberate:
// wire.ReadFrame allocated it fresh for this frame, the writers only read,
// and each writer serialises its own writes onto its own socket. One
// allocation per frame serves the whole fan-out.
//
// Per-conn enqueues keep the sender's order everywhere: a single reader per
// connection enqueues in arrival order, and a single writer per target
// drains in queue order - per (sender, receiver) pair, frames arrive in the
// order the sender wrote them.
func (r *Relay) forward(sender *conn, payload []byte) {
	r.mu.Lock()
	targets := make([]*conn, 0, len(r.conns))
	for c := range r.conns {
		if c != sender {
			targets = append(targets, c)
		}
	}
	r.mu.Unlock()
	for _, c := range targets {
		select {
		case c.wq <- payload:
			r.forwarded.Add(1)
		default:
			r.dropped.Add(1)
		}
	}
}

// writer is the per-connection write goroutine: drain the queue onto the
// socket until the connection is over. A blocked write means a peer that has
// stopped reading; it harms exactly this goroutine and this socket, and
// finish sweeps the rest away.
func (r *Relay) writer(c *conn) {
	defer r.wg.Done()
	for {
		select {
		case <-c.dead:
			return
		case b := <-c.wq:
			if err := wire.WriteFrame(c.nc, b); err != nil {
				// The socket failed; close it, which wakes the reader into
				// finish (a no-op if we got here second).
				r.finish(c)
				return
			}
		}
	}
}

// Close idempotently shuts the relay down: the listener stops accepting,
// every live connection's socket is closed (which unblocks every reader and
// writer parked on it), and Close waits for every goroutine it started. The
// wait is bounded by nothing the network controls - a closed socket returns
// from any pending call promptly - so Close is a real guarantee, not a best
// effort.
func (r *Relay) Close() {
	r.closeOnce.Do(func() {
		r.closed.Store(true)
		close(r.quit)
		r.mu.Lock()
		lsn := r.lsn
		r.lsn = nil
		conns := make([]*conn, 0, len(r.conns))
		for c := range r.conns {
			conns = append(conns, c)
		}
		r.mu.Unlock()
		if lsn != nil {
			_ = lsn.Close()
		}
		for _, c := range conns {
			r.finish(c)
		}
		r.wg.Wait()
	})
}
