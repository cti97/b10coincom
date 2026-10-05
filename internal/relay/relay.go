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
// Every bound below is therefore STRUCTURAL - byte budgets, socket
// deadlines, endpoint counts - never payload-shaped: the relay parses the
// frame length and nothing beyond it, and audit N-2's fixes stay inside
// that discipline. The bounds, in the order the traffic meets them:
//
//   - the frame-length cap, checked before any allocation;
//   - per-frame READ and WRITE deadlines, each measuring only socket-level
//     silence or stall: a peer that keeps speaking and reading is never cut
//     off, and a peer that does either halfway is ENDED with its slot and
//     its queued bytes released - nothing is pinned forever by a peer that
//     keeps one five-byte frame alive (audit N-2);
//   - a byte-bounded per-connection write queue with a per-sender fair
//     share (Options.WriteQueueBytes, newSendQ): no wedge can hold more
//     than the budget's bytes, and one sender cannot occupy all of a
//     receiver's budget and thereby censor another sender's frames;
//   - MaxConns and MaxConnsPerIP at accept: a stranger is bounded in how
//     many slots it can hold, total and per source IP.
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
	"net/netip"
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
	// DefaultMaxConns bounds the registry. Audit N-2 lowered this from 256:
	// the honest population of one relay is its validator set - a handful of
	// members plus their reconnect blips - so every slot beyond a few dozen
	// is stranger-collateral the 1 GB-class VPS pays for. A dial arriving
	// when full is closed immediately; the honest validator's outbound
	// backoff redials it later. (The operational defence for a real
	// deployment sits IN FRONT of the relay, not in it: the source-IP
	// allowlist, which is exactly the access policy the relay itself is too
	// dumb to have.)
	DefaultMaxConns = 32
	// DefaultMaxConnsPerIP caps how many registry slots ONE source IP may
	// hold (audit N-2's third attack: with no per-IP cap, one host held all
	// the slots and pushed honest validators into RefusedConns). 8 covers a
	// validator's flapping reconnects and a restart storm behind one NAT
	// address with room to spare; a loopback-heavy test sets it explicitly,
	// because every dial it makes is from one IP. Grouped by canonical IP -
	// connHost - which examines no frame bytes.
	DefaultMaxConnsPerIP = 8
	// DefaultWriteTimeout is the per-frame WRITE deadline: the socket-level
	// bound on how long ONE frame may remain unwritten before the connection
	// is ended and its registry slot, queued bytes and goroutines are
	// released. This is the timer a peer that stops reading runs against -
	// pre-fix (audit N-2) the writer had no deadline, so a sink that never
	// read backpressured the writer into an indefinite block while its full
	// queue pinned its bytes forever, kept alive indefinitely by a five-byte
	// keepalive frame refreshing the READ deadline. Now the pin is bounded:
	// a queue backed up behind a non-reading peer ends the connection on
	// this timer, whatever its keepalives say.
	//
	// It parses nothing: the deadline is armed on the socket before the
	// frame write and re-armed per frame, so the question it answers is only
	// "has this connection stopped accepting ENTIRELY for this long?" - a
	// peer keeping up is never cut off, and neither the payload nor the
	// framing is inspected.
	//
	// 30 seconds sits well above any honest link: a full 1 MiB frame is
	// written inside it at ~280 kbit/s, and every honest peer's write is a
	// few kilobytes.
	DefaultWriteTimeout = 30 * time.Second
	// DefaultWriteQueueBytes is the per-connection write-queue bound in
	// PAYLOAD BYTES - a byte budget, not a frame count. This is the bound the
	// audit's N-2 rebuilt: the pre-fix bound was in FRAMES (64 of them), and
	// the documented memory claim omitted that whole factor. The old bound's
	// worst case: 64 frames x MaxFrameBytes 1 MiB = 64 MiB pinned PER wedged
	// connection, and MaxConns of them - 256 x 64 MiB = 16 GiB - held
	// indefinitely by a sink that never read, against a documented claim of
	// 256 MiB. A byte budget makes the per-connection pin independent of how
	// many frames the bytes arrive in, and the write deadline above reclaims
	// it in bounded time.
	//
	// 2 MiB sits far above honest backlog: relaying kilobytes per second, a
	// queue's steady state is hundreds of bytes; a FULL budget is a wedged
	// reader, and every byte of it is reclaimed by the write deadline.
	DefaultWriteQueueBytes = 2 << 20
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
	// MaxConnsPerIP is how many registry slots one source IP may hold,
	// enforced at accept before registration. Default DefaultMaxConnsPerIP.
	MaxConnsPerIP int
	// WriteQueueBytes is the per-connection writer queue bound in payload
	// bytes, which also floors itself at MaxFrameBytes (a queue smaller than
	// one maximum frame could never forward a full frame at all). Default
	// DefaultWriteQueueBytes; see Options.MaxPinnedBytes for the aggregate
	// arithmetic this participates in.
	WriteQueueBytes int
	// WriteTimeout is the per-frame write deadline for the connection's
	// writer. Default DefaultWriteTimeout.
	WriteTimeout time.Duration
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
	if o.MaxConnsPerIP <= 0 {
		o.MaxConnsPerIP = DefaultMaxConnsPerIP
	}
	if o.WriteQueueBytes <= 0 {
		o.WriteQueueBytes = DefaultWriteQueueBytes
	}
	if o.WriteQueueBytes < o.MaxFrameBytes {
		// A queue smaller than one maximum frame can never forward a full
		// frame at all, which is a misconfiguration masquerading as a bound;
		// floor it at the frame cap instead. (Ordered AFTER the zero-default
		// above, so an unset budget still lands at the default, not here.)
		o.WriteQueueBytes = o.MaxFrameBytes
	}
	if o.WriteTimeout <= 0 {
		o.WriteTimeout = DefaultWriteTimeout
	}
	if o.ReadTimeout <= 0 {
		o.ReadTimeout = DefaultReadTimeout
	}
	if o.KeepAlive <= 0 {
		o.KeepAlive = DefaultKeepAlive
	}
	return o
}

// MaxPinnedBytes derives the aggregate memory the relay can pin for
// frames - the number the README, --help and the systemd unit's MemoryMax
// all have to agree on, COMPUTED rather than asserted, because a documented
// bound whose arithmetic a reader cannot re-run is not a documented bound.
// (Audit N-2's origin: the old claim was max-conns x max-frame-bytes of
// memory, which omitted the write-queue factor entirely - 256 MiB claimed
// where 256 x 64 frames x 1 MiB = 16 GiB was reachable.)
//
// The bound on one connection is the sum of what ONE hand can hold at the
// same instant:
//
//   - its write queue: at most WriteQueueBytes of queued payloads - the
//     byte budget is the bound, whatever frame sizes the bytes ride in;
//
//   - the one frame in the writer's hand: at most MaxFrameBytes, possibly
//     half-written into the kernel while a non-reading peer holds the rest
//     back (reclaimed by the write deadline, but pinned until then);
//
//   - the one frame in the reader's hand: at most MaxFrameBytes, from the
//     read that produced the most recent forward.
//
//     per conn <= WriteQueueBytes + 2 * MaxFrameBytes
//     aggregate = MaxConns * (WriteQueueBytes + 2 * MaxFrameBytes)
//
// Payload slices are SHARED across a fan-out's targets (one allocation per
// received frame, referenced by every target's queue), so this bound is an
// upper bound, not an account of copies: the distinct bytes are never more
// than one reader-plus-queue's worth per connection. At the DEFAULTS:
//
//	32 conns x (2 MiB queue + 2 x 1 MiB hands) = 32 x 4 MiB = 128 MiB.
//
// which is the figure the documents quote, derived from these very fields -
// change a default and the documents' number moves with it.
func (o Options) MaxPinnedBytes() int {
	return o.MaxConns * (o.WriteQueueBytes + 2*o.MaxFrameBytes)
}

// connHost extracts the canonical source-IP grouping key from a remote
// address: its host part with IPv4-mapped IPv6 unmapped to plain IPv4, so
// one host dialing over both stacks is ONE group, always. It reads no frame
// bytes - the per-IP cap counts ENDPOINTS - and an address that fails to
// parse falls through as its own group, so an unknown form can never hide
// inside a real IP's budget.
func connHost(ra net.Addr) string {
	if ra == nil {
		return ""
	}
	remote := ra.String()
	if ap, err := netip.ParseAddrPort(remote); err == nil {
		return ap.Addr().Unmap().String()
	}
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	if ip, perr := netip.ParseAddr(host); perr == nil {
		host = ip.Unmap().String()
	}
	return host
}

// Stats is a point-in-time reading of the relay's counters: the minimum an
// unattended process on a €4 VPS needs to be diagnosable over its operator's
// SSH session.
type Stats struct {
	// Conns is the number of currently registered connections.
	Conns int
	// Forwarded counts frames enqueued for onward delivery.
	Forwarded uint64
	// Dropped counts frames lost to a full (or fair-share-exhausted) write
	// queue. A steady nonzero value is the diagnosis for one thing: a peer
	// that is not keeping up - or, with the per-sender share, one sender
	// monopolising the queue it is being held to. The bound held (nobody
	// else stalled) but the relay is now the one censoring, which is
	// liveness pressure a validator set feels.
	Dropped uint64
	// RefusedConns counts dials closed at accept, for either refusing rule:
	// over MaxConns, or past MaxConnsPerIP from one source.
	RefusedConns uint64
}

// sentFrame is one queued payload and the sender whose fair share it was
// admitted against; the share is refunded when the writer takes the frame.
type sentFrame struct {
	sender *conn
	b      []byte
}

// sendQ is the byte-bounded write queue: a FIFO of frames whose TOTAL queued
// payload bytes never exceed limit, and in which no single sender ever
// occupies more than share of those bytes (audit N-2: byte-bounded queues,
// per-sender fair share). push never blocks and never allocates for the
// drop decision - a frame that cannot fit is refused at the door - and pop
// is non-blocking; the writer sleeps on ready, which fires exactly on an
// empty-to-non-empty transition, so a push can never wake it to nothing nor
// leave it asleep with frames waiting.
type sendQ struct {
	limit int // total queued payload bytes admitted
	share int // per-sender cap on queued payload bytes

	mu    sync.Mutex
	ents  []sentFrame
	bytes int
	from  map[*conn]int // queued bytes per sender, refunded on pop
	ready chan struct{} // cap 1: signalled on empty -> non-empty
}

// newSendQ derives the bounds from the options: limit is the byte budget as
// given (already floored at MaxFrameBytes by withDefaults); share is half
// the budget with a floor of one maximum frame, so a legitimate largest
// frame always has room to be admitted even when no other sender is queued.
func newSendQ(limit, maxFrameBytes int) *sendQ {
	share := limit / 2
	if share < maxFrameBytes {
		share = maxFrameBytes
	}
	return &sendQ{
		limit: limit,
		share: share,
		from:  make(map[*conn]int),
		ready: make(chan struct{}, 1),
	}
}

// push admits one frame from sender if it fits in the budget AND in the
// sender's share of it, and returns whether it was admitted. It never
// blocks: an admitted frame is appended and (only on the empty-to-non-empty
// transition) signalled; a refused frame costs a boolean, which is what
// keeps a wedged receiver from stalling the sender's forwarding path.
func (s *sendQ) push(sender *conn, b []byte) bool {
	s.mu.Lock()
	ok := len(b) <= s.limit &&
		s.bytes+len(b) <= s.limit &&
		s.from[sender]+len(b) <= s.share
	if ok {
		s.ents = append(s.ents, sentFrame{sender: sender, b: b})
		s.bytes += len(b)
		s.from[sender] += len(b)
		if len(s.ents) == 1 { // the transitions the writer can be asleep across
			select {
			case s.ready <- struct{}{}:
			default: // a token is already pending: the wake is not lost
			}
		}
	}
	s.mu.Unlock()
	return ok
}

// pop takes the oldest admitted frame, refunding its bytes to the budget and
// to its sender's share. It is non-blocking: nothing to take returns false,
// and the writer goes back to sleep on ready.
func (s *sendQ) pop() (sentFrame, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.ents) == 0 {
		return sentFrame{}, false
	}
	f := s.ents[0]
	s.ents[0] = sentFrame{}
	s.ents = s.ents[1:]
	s.bytes -= len(f.b)
	s.from[f.sender] -= len(f.b)
	if s.from[f.sender] <= 0 {
		delete(s.from, f.sender) // dead senders leave no map entries behind
	}
	return f, true
}

// conn is one accepted connection. The relay knows its peers by NOTHING but
// the connection itself: no ID, no HELLO, no handshake. Identification is the
// signed traffic's business, and a relay that checked identities would have
// to parse at least the first frame to do it - the exact line this package
// refuses to cross.
type conn struct {
	nc net.Conn
	// q is the BOUNDED byte-budgeted write queue (see sendQ). The writer is
	// its only consumer; push never blocks, which is the property that keeps
	// a slow peer from stalling the relay for everyone else.
	q *sendQ
	// ip is the canonical source IP this connection came from, grouped for
	// the per-IP cap at accept (audit N-2). Empty for a connection that
	// never went through accept - only the queue-level tests build those.
	ip string
	// dead is closed exactly once, by finish, when the connection is over.
	dead chan struct{}
	// once makes finish idempotent: reader, writer and Close can all
	// discover the end of the connection, and exactly one cleans up.
	once sync.Once
}

// finish tears one connection down exactly once: close the socket (unblocking
// every goroutine parked on it), close dead (unblocking the writer), and drop
// the connection from the registry and from its IP's count.
func (r *Relay) finish(c *conn) {
	c.once.Do(func() {
		close(c.dead)
		_ = c.nc.Close()
		r.mu.Lock()
		delete(r.conns, c)
		if r.perIP[c.ip] > 0 {
			r.perIP[c.ip]-- // the accept-time cap sees the freed slot again
			if r.perIP[c.ip] == 0 {
				delete(r.perIP, c.ip)
			}
		}
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
	// perIP counts live conns by canonical source IP - the accept-time cap's
	// bookkeeping, decremented by finish.
	perIP map[string]int

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
		perIP: make(map[string]int),
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
		if err := r.admit(nc); err != nil {
			// A refusal by BOUND (registry full, or one source IP at its
			// cap) is counted; a close because the relay is shutting down
			// is not a refusal, only a shutdown.
			if !errors.Is(err, ErrClosed) {
				r.refused.Add(1)
			}
			nc.Close()
		}
	}
}

// admit applies the accept-time refusal rules in order - relay closed, then
// MaxConns, then MaxConnsPerIP (audit N-2: no single source may hold every
// slot; the per-IP count is kept under the same mutex the registry is) -
// and registers the accepted connection with its two goroutines. The
// registration stays under the same lock Close's snapshot takes, so a Close
// racing an accept either sees the connection (and finishes it) or finds
// the closed flag up and closes the raw socket itself.
func (r *Relay) admit(nc net.Conn) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed.Load() {
		return ErrClosed
	}
	if len(r.conns) >= r.opts.MaxConns {
		return fmt.Errorf("relay: registry full (%d)", r.opts.MaxConns)
	}
	host := connHost(nc.RemoteAddr())
	if r.perIP[host] >= r.opts.MaxConnsPerIP {
		return fmt.Errorf("relay: source %s holds %d slots already (cap %d)", host, r.perIP[host], r.opts.MaxConnsPerIP)
	}
	c := &conn{
		nc:   nc,
		q:    newSendQ(r.opts.WriteQueueBytes, r.opts.MaxFrameBytes),
		dead: make(chan struct{}),
		ip:   host,
	}
	r.conns[c] = struct{}{}
	r.perIP[host]++
	r.wg.Add(2)
	go r.reader(c)
	go r.writer(c)
	return nil
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
// enqueuing it on their byte-budgeted queues - never waiting, never parsing.
//
// The payload slice is shared, not copied, and that is deliberate:
// wire.ReadFrame allocated it fresh for this frame, the writers only read,
// and each writer serialises its own writes onto its own socket. One
// allocation per frame serves the whole fan-out. Every target's queue
// refunds the frame's bytes to its sender's share when the writer takes the
// frame out, so no sender's occupancy outlives its frames.
//
// Per-conn enqueues keep the sender's order everywhere: a single reader per
// connection enqueues in arrival order, and a single writer per target
// drains in queue order - per (sender, receiver) pair, frames arrive in the
// order the sender wrote them. A frame refused by a queue's budget or by
// its sender's share is a Dropped counter increment and nothing else.
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
		if c.q.push(sender, payload) {
			r.forwarded.Add(1)
		} else {
			r.dropped.Add(1)
		}
	}
}

// writer is the per-connection write goroutine: drain the queue onto the
// socket until the connection is over, every frame under its own write
// deadline. A blocked write means a peer that has stopped reading; the
// deadline is what turns that from "this goroutine is parked forever and
// its queue's bytes are pinned forever" (the pre-fix state, audit N-2)
// into a bounded stall: the frame that cannot be written within
// WriteTimeout ends the connection, finish releases the slot, the queued
// bytes and the IP's count, and the reader unblocks into the same teardown.
func (r *Relay) writer(c *conn) {
	defer r.wg.Done()
	for {
		select {
		case <-c.dead:
			return
		case <-c.q.ready:
			for {
				f, ok := c.q.pop()
				if !ok {
					break // drained; sleep until the next push signals
				}
				if err := c.nc.SetWriteDeadline(time.Now().Add(r.opts.WriteTimeout)); err != nil {
					r.finish(c)
					return
				}
				if err := wire.WriteFrame(c.nc, f.b); err != nil {
					// Socket failure or deadline expiry on a peer that has
					// stopped reading - the same ending either way: nothing
					// is parsed, nothing is retried, the slot is released.
					r.finish(c)
					return
				}
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
