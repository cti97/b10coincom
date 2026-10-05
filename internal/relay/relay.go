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
//   - per-frame READ deadline, plus a per-connection WRITE deadline anchored
//     to the instant the write queue became non-empty: a peer that keeps
//     speaking is never cut off, but a peer that stops reading - or reads so
//     slowly the backlog never clears - is ENDED with its slot, its queued
//     bytes and its entry ring released, so nothing is pinned forever by a
//     peer that keeps one five-byte frame alive (audit N-2);
//   - a write queue bounded BOTH in payload bytes (Options.WriteQueueBytes)
//     and in frame count (Options.WriteQueueFrames), with a fair share keyed
//     on the SENDER's source group (newSendQ): no queued byte budget can
//     bound the queue's per-frame entry memory, so the count is an explicit
//     ring, and one sender - one source group, not one connection - cannot
//     occupy all of a receiver's budget and thereby censor another sender's
//     frames. The share is a fraction of the RECEIVER'S OWN queue capacity
//     divided among the sender groups that can contend for it (shareFor),
//     never a fixed cap on throughput: the sole sender of a queue faces a
//     share of the whole capacity and, while the queue has room, loses
//     nothing;
//   - MaxConns and MaxConnsPerIP at accept, the latter grouped by source
//     PREFIX (IPv6 /64, IPv4 /24): a stranger is bounded in how many slots it
//     can hold, total and per group, so one routed prefix cannot bypass the
//     cap by rotating addresses.
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
	"bytes"
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

// accessTokenTimeout bounds how long an accepted connection may take to
// present the pre-shared access token (audit N-8) before it is closed. It is
// short because the honest client sends the token immediately on connect; a
// socket that is silent for this long is a scanner. The read is otherwise
// bounded by Options.ReadTimeout, which is far too long to hold a handshake.
const accessTokenTimeout = 5 * time.Second

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
	// DefaultMaxConnsPerIP caps how many registry slots ONE SOURCE PREFIX may
	// hold (audit N-2's third attack: with no per-source cap, one host held all
	// the slots and pushed honest validators into RefusedConns; and with the
	// cap keyed on the full address, a routed IPv6 /64 bypassed it by
	// rotating addresses). 8 covers a validator's flapping reconnects and a
	// restart storm behind one NAT address with room to spare; a
	// loopback-heavy test sets it explicitly, because every dial it makes is
	// from one group. Grouped by connGroup - IPv6 /64, IPv4 /24, or the host
	// for an unparseable address - which examines no frame bytes.
	DefaultMaxConnsPerIP = 8
	// DefaultWriteTimeout is the per-connection write deadline: the bound on
	// how long a connection's QUEUE may stay backed up before the connection
	// is ended and its registry slot, queued bytes, entry ring and goroutines
	// are released. Two failures made this necessary (audit N-2): pre-fix the
	// writer had no deadline at all, so a sink that never read backpressured
	// the writer into an indefinite block while its full queue pinned its
	// bytes forever, kept alive by a five-byte keepalive frame refreshing the
	// READ deadline; and even the first write-deadline fix only covered a
	// single write that stalled for the WHOLE timeout, so a sink that accepted
	// a trickle of every frame made progress by the letter of that rule while
	// its queue never drained. The deadline is therefore anchored to the
	// instant the queue first became non-empty (sendQ.writeDeadline): a
	// connection must get its queue back to EMPTY within WriteTimeout, whether
	// the peer reads not at all or reads too slowly for the backlog to clear.
	// A peer that drains as it goes empties the queue constantly and is never
	// cut off; a queue that stays non-empty for the whole timeout is, by
	// construction, a connection not keeping up.
	//
	// It parses nothing: the deadline is a socket deadline plus a timestamp on
	// an already-queued frame, so the question it answers is only "has this
	// connection's backlog drained within the bound?" - and neither the
	// payload nor the framing is inspected.
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
	// DefaultWriteQueueFrames caps the FRAME COUNT of each connection's write
	// queue, independently of the byte budget above, and it exists because a
	// byte budget alone cannot bound a queue's ENTRY memory: the smallest
	// legal frame is one payload byte (wire.ReadFrame refuses only zero), so
	// a 2 MiB budget admits ~2,097,152 entries, and each entry in the queue's
	// ring costs queuedFrameEntryBytes - about 64 MiB of entry array per
	// connection for a queue the byte budget calls 2 MiB. That missing term
	// is audit N-2's re-opened measurement: 8 connections from one source IP
	// (within MaxConnsPerIP) reached ~231.6 MiB, and the full registry over
	// 1 GiB, against the 128 MiB documented. The frame cap makes the entry
	// memory structural: WriteQueueFrames x queuedFrameEntryBytes is counted
	// into Options.MaxPinnedBytes, so the number the docs quote includes it.
	//
	// 4096 is a companion to the 2 MiB byte budget at the honest frame size
	// (relaying hundreds of bytes to kilobytes per frame, a full 2 MiB
	// backlog is a few thousand frames), and it leaves the byte budget the
	// binding bound for any frame above ~512 bytes. The relay still parses
	// nothing: this counts frames, never their content.
	DefaultWriteQueueFrames = 4096
	// queuedFrameEntryBytes is the exact in-memory cost of ONE entry in a
	// connection's queue ring - a sender pointer plus a payload slice header.
	// It is stated as a constant so the derivation can include it, and pinned
	// against the real struct by a test (unsafe.Sizeof), so the documented
	// arithmetic cannot drift from the type. The payload bytes themselves are
	// counted separately by WriteQueueBytes.
	queuedFrameEntryBytes = 32
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
	// MaxConnsPerIP is how many registry slots one source PREFIX may hold,
	// enforced at accept before registration. Default DefaultMaxConnsPerIP.
	MaxConnsPerIP int
	// WriteQueueBytes is the per-connection writer queue bound in payload
	// bytes, which also floors itself at MaxFrameBytes (a queue smaller than
	// one maximum frame could never forward a full frame at all). Default
	// DefaultWriteQueueBytes; see Options.MaxPinnedBytes for the aggregate
	// arithmetic this participates in. It is a budget on the PAYLOAD bytes
	// only; WriteQueueFrames bounds the entry memory those bytes ride in.
	WriteQueueBytes int
	// WriteQueueFrames is the per-connection FRAME COUNT bound on the writer
	// queue. It exists because the byte budget above cannot bound the queue's
	// entry memory: the minimum legal frame is one byte, so a byte budget
	// admits as many entries as it has bytes. Default
	// DefaultWriteQueueFrames; the entry cost is counted into
	// Options.MaxPinnedBytes.
	WriteQueueFrames int
	// WriteTimeout is the per-connection write deadline for the connection's
	// writer: the queue must drain to empty within it. Default
	// DefaultWriteTimeout.
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
	// AccessToken, when non-empty, is a PRE-SHARED FIRST FRAME (audit N-8):
	// a newly accepted connection must present exactly these bytes as its
	// first frame or it is closed and counted as unauthorized. It is the
	// in-process access control that works where an IP allowlist cannot -
	// behind CGNAT, or when a home validator's outbound address rotates -
	// and it keeps the relay's "parses nothing" posture by construction: the
	// check is a length-and-equality comparison of raw frame bytes, never a
	// decode, so the relay still understands nothing about consensus.
	//
	// The token frame is CONSUMED, not forwarded, and a connection that has
	// not presented it is never registered: it cannot receive another peer's
	// frames and cannot forward anything. Empty disables the check (the
	// pre-existing behaviour), so an existing deployment that adds no token
	// is unchanged.
	AccessToken []byte
	// AccessTimeout bounds how long an accepted connection may take to
	// present AccessToken before it is closed. Default accessTokenTimeout.
	// It is short because an honest client sends the token immediately; a
	// socket silent for this long is a scanner.
	AccessTimeout time.Duration
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
	if o.WriteQueueFrames <= 0 {
		o.WriteQueueFrames = DefaultWriteQueueFrames
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
	if o.AccessTimeout <= 0 {
		o.AccessTimeout = accessTokenTimeout
	}
	return o
}

// MaxPinnedBytes derives the aggregate memory the relay can pin for
// frames - the number the README, --help and the systemd unit's MemoryMax
// all have to agree on, COMPUTED rather than asserted, because a documented
// bound whose arithmetic a reader cannot re-run is not a documented bound.
// (Audit N-2's history: the first claim was max-conns x max-frame-bytes of
// memory, omitting the write-queue factor entirely - 256 MiB claimed where
// 256 x 64 frames x 1 MiB = 16 GiB was reachable. The first correction still
// omitted the queue's PER-FRAME ENTRY cost, so a byte budget of 2 MiB could
// carry ~2 million entries - ~64 MiB of entry array - and 8 connections from
// one source IP measured 231.6 MiB against a 128 MiB claim. This derivation
// has all three terms.)
//
// The bound on one connection is the sum of what it can hold at the same
// instant:
//
//   - its write queue's PAYLOAD: at most WriteQueueBytes, whatever frame
//     sizes the bytes ride in;
//
//   - its write queue's ENTRY RING: at most WriteQueueFrames entries, each
//     exactly queuedFrameEntryBytes (a sender pointer plus a payload slice
//     header). This is the term the byte budget cannot bound, because the
//     minimum legal frame is one byte;
//
//   - the one frame in the writer's hand: at most MaxFrameBytes, possibly
//     half-written into the kernel while a non-reading peer holds the rest
//     back (reclaimed by the write deadline, but pinned until then);
//
//   - the one frame in the reader's hand: at most MaxFrameBytes, from the
//     read that produced the most recent forward.
//
//     per conn  <= WriteQueueBytes + WriteQueueFrames*queuedFrameEntryBytes + 2*MaxFrameBytes
//     aggregate  = MaxConns * that
//
// Payload slices are SHARED across a fan-out's targets (one allocation per
// received frame, referenced by every target's queue), so this bound is an
// upper bound, not an account of copies: the distinct bytes are never more
// than one reader-plus-queue's worth per connection. At the DEFAULTS:
//
//	32 conns x (2 MiB payload + 4096 x 32 B entries + 2 x 1 MiB hands)
//	  = 32 x (2 MiB + 128 KiB + 2 MiB)
//	  = 32 x 4.125 MiB = 132 MiB.
//
// which is the figure the documents quote, derived from these very fields -
// change a default and the documents' number moves with it. The per-queue
// sender-accounting map is bounded by the connections that can feed one
// queue (at most MaxConns entries) and is covered by the MemoryMax headroom,
// not itemised here.
func (o Options) MaxPinnedBytes() int {
	return o.MaxConns * (o.WriteQueueBytes + o.WriteQueueFrames*queuedFrameEntryBytes + 2*o.MaxFrameBytes)
}

// connGroup extracts the source GROUPING key from a remote address - the
// input to both the per-group accept cap and the fair-share account, so the
// two bounds group senders identically. It is the IPv6 /64 or IPv4 /24
// network prefix, MASKED, with an IPv4-mapped IPv6 unmapped to plain IPv4
// first, so one host dialing over both stacks is ONE group and a routed
// prefix (the audit's bypass: an IPv6 /64 the attacker can rotate through)
// is ONE group too. An address that fails to parse falls through as its own
// group, so an unknown form can never hide inside a real group's budget. It
// reads no frame bytes - the cap counts ENDPOINTS, the share counts LENGTHS -
// and it never inspects a payload.
func connGroup(ra net.Addr) string {
	if ra == nil {
		return ""
	}
	remote := ra.String()
	if ap, err := netip.ParseAddrPort(remote); err == nil {
		return groupOf(ap.Addr())
	}
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	if ip, perr := netip.ParseAddr(host); perr == nil {
		return groupOf(ip)
	}
	return host
}

// groupOf renders one parsed address as its grouping prefix: the IPv4 /24,
// or the IPv6 /64, masked so every address in the prefix maps to one string.
func groupOf(ip netip.Addr) string {
	ip = ip.Unmap()
	bits := 64
	if ip.Is4() {
		bits = 24
	}
	return netip.PrefixFrom(ip, bits).Masked().String()
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
	// Unauthorized counts dials closed because they did not present the
	// configured AccessToken first (audit N-8). It is zero when no token is
	// configured; a steady nonzero value is a stranger (or a validator with a
	// stale token) probing the relay.
	Unauthorized uint64
}

// sentFrame is one queued payload and the sender whose fair share it was
// admitted against; the share is refunded when the writer takes the frame.
type sentFrame struct {
	sender *conn
	b      []byte
}

// shareAccount is the fair-share identity a sender's queued bytes are charged
// to. It is the sender's source GROUP - connGroup, so two connections from
// one host (or one routed prefix) share ONE account and cannot split a
// receiver's budget between them, which was audit N-2's censorship bypass: a
// per-CONNECTION share let two attacker connections each stay inside their
// own share and together fill the receiver's queue. A hand-built connection
// with no source address (the socket-free queue tests) is its own account.
type shareAccount struct {
	group string // non-empty for an accepted connection: its source prefix
	c     *conn  // identity fallback for a connection with no address
}

// shareAccountOf returns the account sender's frames are charged to.
func shareAccountOf(c *conn) shareAccount {
	if c.srcGroup != "" {
		return shareAccount{group: c.srcGroup}
	}
	return shareAccount{c: c}
}

// sendQ is the bounded write queue: a FIFO of frames whose TOTAL queued
// payload bytes never exceed limit AND whose entry count never exceeds
// maxFrames, and in which no single SENDER (shareAccount - a source group,
// not a connection) ever occupies more than its allowance of the bytes (audit
// N-2: byte-bounded queues, per-frame entry bound, per-sender fair share).
// The allowance is contention-relative, not a flat division: while no OTHER
// account holds a byte the sender may use the whole budget, and once another
// account is holding bytes the sender is held to its equal share of the
// queue's OWN limit (shareFor). A queue with one sender therefore admits up to
// its whole budget and loses nothing while the receiver has room; the equal
// share reserves room for the other registered senders only once the queue is
// really shared, which is the crowding-out the share exists to stop. What this
// does NOT bound is a flooder that fills the queue before another sender has
// queued anything: that sender's first frames drop until the backlog drains,
// and a receiver too slow to drain it is ended by the WriteTimeout reaper (see
// writer).
//
// The queue is a fixed ring of maxFrames entries allocated once at accept, so
// its entry memory is exactly maxFrames x queuedFrameEntryBytes - the term a
// byte budget alone cannot bound, because the minimum legal frame is one
// byte. push never blocks and never allocates for the drop decision - a frame
// that cannot fit is refused at the door - and pop is non-blocking; the
// writer sleeps on ready, which fires exactly on an empty-to-non-empty
// transition, so a push can never wake it to nothing nor leave it asleep with
// frames waiting.
//
// oldest records the instant the queue last became non-empty (zero while it
// is empty). It anchors the writer's progress deadline: the queue must drain
// back to empty within WriteTimeout of that instant, so a peer that accepts
// a trickle of every frame - making each individual write "succeed" - is
// still ended once its backlog has failed to clear (audit N-2's slow sink).
type sendQ struct {
	limit         int // total queued payload bytes admitted
	maxFrameBytes int // the frame bound the share floors itself at
	maxFrames     int // entry-ring length: the per-frame memory bound

	mu     sync.Mutex
	ents   []sentFrame // ring buffer, fixed length maxFrames
	head   int         // index of the oldest entry
	n      int         // live entries
	bytes  int
	from   map[shareAccount]int // queued bytes per sender account, refunded on pop
	oldest time.Time            // when the queue became non-empty; zero when empty
	ready  chan struct{}        // cap 1: signalled on empty -> non-empty
}

// newSendQ derives the bounds from the options: limit is the byte budget as
// given (already floored at MaxFrameBytes by withDefaults); maxFrames is the
// frame-count bound (already defaulted). The per-sender share is NOT a fixed
// constant here: it is computed per push by shareFor from the number of
// sender accounts contending for THIS queue's capacity, so a single
// uncontended sender may use the whole budget.
func newSendQ(limit, maxFrameBytes, maxFrames int) *sendQ {
	if maxFrames < 1 {
		// A non-positive entry bound would make the ring empty and every
		// push a modulo-by-zero; floor it at one entry, the smallest queue
		// that can carry anything at all.
		maxFrames = 1
	}
	return &sendQ{
		limit:         limit,
		maxFrameBytes: maxFrameBytes,
		maxFrames:     maxFrames,
		ents:          make([]sentFrame, maxFrames),
		from:          make(map[shareAccount]int),
		ready:         make(chan struct{}, 1),
	}
}

// shareFor returns the allowance one sender account is held to when
// `senders` distinct accounts can contend for this queue: an equal fraction
// (1/senders) of the queue's OWN byte capacity, floored at one maximum frame
// so a legitimate largest frame always has room even when the division would
// round it below a frame, and never above the queue's own budget. push applies
// this only once another account is actually holding bytes; while none is, the
// lone sender's allowance is the whole budget, so a sender is not throttled by
// peers that are registered but not queueing.
//
// Dividing the receiver's capacity - rather than capping a sender at a fixed
// in-flight number - is what keeps the share from throttling a healthy flow:
// with one sender the fraction is the whole budget, so a sender loses nothing
// while the receiver has room; the fraction bites only where two or more
// sender accounts actually hold bytes in that room, which is the contention
// the share exists to bound. It still parses nothing: the count is endpoint
// identities, not payload.
func (s *sendQ) shareFor(senders int) int {
	if senders < 1 {
		senders = 1
	}
	share := s.limit / senders
	if share < s.maxFrameBytes {
		share = s.maxFrameBytes
	}
	if share > s.limit {
		share = s.limit
	}
	return share
}

// push admits one frame from sender if it fits in the byte budget, in the
// frame-count bound, AND in the sender's contention-relative allowance of the
// bytes. The allowance is the sender's equal share (shareFor, over the
// `senders` the fan-out derived from the registry) once another account is
// actually holding bytes in this queue, and the whole budget while none is -
// so a lone sender among registered-but-idle peers gets the whole queue, and
// the share reserves room for the other registered senders only once the
// queue is really shared. (The naive "max(share, limit - bytesByOthers)" is
// NOT used: since the byte budget already caps the total at limit, that bound
// reduces to "whatever room others are not holding", and the share never
// binds at all.) It never blocks: an admitted frame is placed in the ring and
// (only on the empty-to-non-empty transition) signalled; a refused frame
// costs a boolean, which is what keeps a wedged receiver from stalling the
// sender's forwarding path.
func (s *sendQ) push(sender *conn, b []byte, senders int) bool {
	acct := shareAccountOf(sender)
	share := s.shareFor(senders)
	s.mu.Lock()
	// Actual contention is the bytes another account is holding in this
	// queue. While there are none, the one sender using the queue may take
	// the whole budget; the equal share is what it is held to only once the
	// queue is really shared.
	allow := share
	if s.bytes-s.from[acct] == 0 {
		allow = s.limit
	}
	ok := len(b) <= s.limit &&
		s.bytes+len(b) <= s.limit &&
		s.n < s.maxFrames &&
		s.from[acct]+len(b) <= allow
	if ok {
		if s.n == 0 {
			s.oldest = time.Now()
		}
		s.ents[(s.head+s.n)%s.maxFrames] = sentFrame{sender: sender, b: b}
		s.n++
		s.bytes += len(b)
		s.from[acct] += len(b)
		if s.n == 1 { // the transitions the writer can be asleep across
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
// to its sender account. It is non-blocking: nothing to take returns false,
// and the writer goes back to sleep on ready.
func (s *sendQ) pop() (sentFrame, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.n == 0 {
		return sentFrame{}, false
	}
	f := s.ents[s.head]
	s.ents[s.head] = sentFrame{}
	s.head = (s.head + 1) % s.maxFrames
	s.n--
	s.bytes -= len(f.b)
	acct := shareAccountOf(f.sender)
	s.from[acct] -= len(f.b)
	if s.from[acct] <= 0 {
		delete(s.from, acct) // drained senders leave no map entries behind
	}
	if s.n == 0 {
		s.oldest = time.Time{} // empty: the next push starts a new epoch
	}
	return f, true
}

// writeDeadline returns the absolute instant by which the queue must have
// drained to EMPTY, and whether a frame is queued at all. The anchor is the
// instant the queue became non-empty, NOT "now": re-arming a fresh
// now+timeout per frame is precisely the hole audit N-2 re-opened, because a
// sink that accepts a little of every frame makes each write "succeed" while
// the backlog never clears. The writer arms the socket with this deadline and
// refuses to write past it, so the whole backlog is bounded by one
// WriteTimeout from its arrival however steadily the peer trickles.
func (s *sendQ) writeDeadline(timeout time.Duration) (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.n == 0 {
		return time.Time{}, false
	}
	return s.oldest.Add(timeout), true
}

// queued reports the live entry count - the ring's length bound made readable
// for the tests that assert a constructed full queue.
func (s *sendQ) queued() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.n
}

// occupancy reports how many queued bytes one sender is charged with, for the
// tests that assert the fair share directly.
func (s *sendQ) occupancy(sender *conn) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.from[shareAccountOf(sender)]
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
	// srcGroup is the canonical source PREFIX this connection came from
	// (connGroup: IPv6 /64, IPv4 /24, or the host for an unparseable
	// address), grouped for the accept-time cap AND used as the fair-share
	// account so both bounds group senders identically (audit N-2). Empty for
	// a connection that never went through accept - only the queue-level
	// tests build those, and they are their own share account.
	srcGroup string
	// dead is closed exactly once, by finish, when the connection is over.
	dead chan struct{}
	// once makes finish idempotent: reader, writer and Close can all
	// discover the end of the connection, and exactly one cleans up.
	once sync.Once
}

// finish tears one connection down exactly once: close the socket (unblocking
// every goroutine parked on it), close dead (unblocking the writer), and drop
// the connection from the registry and from its source group's count.
func (r *Relay) finish(c *conn) {
	c.once.Do(func() {
		close(c.dead)
		_ = c.nc.Close()
		r.mu.Lock()
		delete(r.conns, c)
		if r.perGroup[c.srcGroup] > 0 {
			r.perGroup[c.srcGroup]-- // the accept-time cap sees the freed slot again
			if r.perGroup[c.srcGroup] == 0 {
				delete(r.perGroup, c.srcGroup)
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
	// perGroup counts live conns by canonical source PREFIX - the
	// accept-time cap's bookkeeping, decremented by finish.
	perGroup map[string]int
	// handshaking holds accepted sockets that have not yet presented the
	// access token (audit N-8), so Close can close them instead of waiting
	// out accessTokenTimeout. A connection is in this set only between
	// Accept and admit; it is never registered and never forwarded.
	handshaking map[net.Conn]struct{}

	quit      chan struct{}
	closed    atomic.Bool
	closeOnce sync.Once
	// wg counts the accept loop, every token handshake, and every
	// per-connection reader and writer. Unlike the transport, the relay CAN
	// wait for all of them at Close: its goroutines never run caller code
	// (everything is a socket call), so closing the sockets unblocks each one
	// deterministically.
	wg sync.WaitGroup

	forwarded    atomic.Uint64
	dropped      atomic.Uint64
	refused      atomic.Uint64
	unauthorized atomic.Uint64
}

// New returns a relay with all bounds defaulted. Nothing runs and nothing is
// open until Listen.
func New(opts Options) *Relay {
	return &Relay{
		opts:        opts.withDefaults(),
		conns:       make(map[*conn]struct{}),
		perGroup:    make(map[string]int),
		handshaking: make(map[net.Conn]struct{}),
		quit:        make(chan struct{}),
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
		Unauthorized: r.unauthorized.Load(),
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
		// handshake performs the access-token read when a token is
		// configured, which BLOCKS on the remote speaking - it must never run
		// on the accept loop, or one silent dialer would stall every other
		// connection. The handshake goroutine is counted on the same
		// WaitGroup Close waits on, and the socket is tracked in
		// r.handshaking so Close can close it rather than wait out the token
		// deadline.
		r.wg.Add(1)
		go r.handshake(nc)
	}
}

// handshake presents the access-token gate (audit N-8) and then admits the
// connection. With no token configured it is the admit call alone. With a
// token, the FIRST frame must equal it EXACTLY - length and bytes - and is
// then consumed, never forwarded. The check reads only the frame length
// (wire.ReadFrame) and compares raw bytes: the relay decodes nothing, so its
// "parses nothing" posture is intact. A connection that fails, or says
// nothing within accessTokenTimeout, is closed and counted as unauthorized;
// it is NEVER registered, so it can neither receive nor forward a frame.
func (r *Relay) handshake(nc net.Conn) {
	defer r.wg.Done()
	if len(r.opts.AccessToken) > 0 {
		r.mu.Lock()
		if r.closed.Load() {
			r.mu.Unlock()
			nc.Close()
			return
		}
		r.handshaking[nc] = struct{}{}
		r.mu.Unlock()
		defer func() {
			r.mu.Lock()
			delete(r.handshaking, nc)
			r.mu.Unlock()
		}()

		if err := nc.SetReadDeadline(time.Now().Add(r.opts.AccessTimeout)); err != nil {
			r.unauthorized.Add(1)
			nc.Close()
			return
		}
		frame, err := wire.ReadFrame(nc, r.opts.MaxFrameBytes)
		// Length-and-equality only: no decode, no interpretation. A token of
		// a different length is refused without a byte comparison.
		if err != nil || len(frame) != len(r.opts.AccessToken) || !bytes.Equal(frame, r.opts.AccessToken) {
			r.unauthorized.Add(1)
			nc.Close()
			return
		}
		// The token frame is consumed; clear the deadline so the reader arms
		// its own per-frame one.
		if err := nc.SetReadDeadline(time.Time{}); err != nil {
			nc.Close()
			return
		}
	}
	if err := r.admit(nc); err != nil {
		// A refusal by BOUND (registry full, or one source IP at its cap) is
		// counted; a close because the relay is shutting down is not a
		// refusal, only a shutdown.
		if !errors.Is(err, ErrClosed) {
			r.refused.Add(1)
		}
		nc.Close()
	}
}

// admit applies the accept-time refusal rules in order - relay closed, then
// MaxConns, then MaxConnsPerIP (audit N-2: no single source may hold every
// slot; the per-GROUP count is kept under the same mutex the registry is) -
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
	group := connGroup(nc.RemoteAddr())
	if r.perGroup[group] >= r.opts.MaxConnsPerIP {
		return fmt.Errorf("relay: source group %s holds %d slots already (cap %d)", group, r.perGroup[group], r.opts.MaxConnsPerIP)
	}
	c := &conn{
		nc:       nc,
		q:        newSendQ(r.opts.WriteQueueBytes, r.opts.MaxFrameBytes, r.opts.WriteQueueFrames),
		dead:     make(chan struct{}),
		srcGroup: group,
	}
	r.conns[c] = struct{}{}
	r.perGroup[group]++
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
//
// The share each target charges this sender is capacity-relative: the
// receiver's own queue budget divided among the distinct sender ACCOUNTS
// (source groups) that can contend for it, i.e. every registered connection
// except the receiver's own account. The whole registry is read under one
// lock alongside the target snapshot. A receiver that is the only member of
// its own account is not one of its senders, so its account is not counted;
// a receiver with a sibling in its account (another connection from the same
// host) IS contended by that sibling and counts it. The count is connection
// identities, never payload: the relay still parses nothing.
func (r *Relay) forward(sender *conn, payload []byte) {
	r.mu.Lock()
	targets := make([]*conn, 0, len(r.conns))
	accounts := make(map[shareAccount]int, len(r.conns))
	for c := range r.conns {
		accounts[shareAccountOf(c)]++
		if c != sender {
			targets = append(targets, c)
		}
	}
	r.mu.Unlock()
	for _, c := range targets {
		if c.q.push(sender, payload, sendersFor(c, accounts)) {
			r.forwarded.Add(1)
		} else {
			r.dropped.Add(1)
		}
	}
}

// sendersFor reports how many distinct sender accounts can contend for the
// queue of receiver c, given the registry's per-account connection counts
// (accounts, built by forward under the registry lock and used by the
// socket-free share tests identically). The receiver's own account is not one
// of its senders when this connection is that account's only member; when a
// sibling connection shares the account, the account IS a sender and is
// counted. The sender of the frame under consideration is always still in the
// registry, so the result is never below one - a queue with one contending
// account charges that sender its whole capacity.
func sendersFor(c *conn, accounts map[shareAccount]int) int {
	senders := len(accounts)
	if accounts[shareAccountOf(c)] == 1 {
		senders--
	}
	return senders
}

// writer is the per-connection write goroutine: drain the queue onto the
// socket until the connection is over, every frame under the queue's PROGRESS
// deadline. A blocked write means a peer that has stopped reading; the
// deadline is what turns that from "this goroutine is parked forever and its
// queue's bytes are pinned forever" (the pre-fix state, audit N-2) into a
// bounded stall - but the deadline is anchored to when the queue first became
// non-empty, not re-armed from "now" on each frame, or a sink that accepts a
// trickle of every frame would make each write succeed while never letting
// the backlog clear (the second N-2 shape). The frame that cannot be written
// within that deadline, or a queue still non-empty when the deadline has
// passed, ends the connection: finish releases the slot, the queued bytes,
// the entry ring and the group's count, and the reader unblocks into the same
// teardown. A peer that drains as it goes empties the queue and starts a fresh
// deadline on the next burst, so an honest flow is never cut off.
func (r *Relay) writer(c *conn) {
	defer r.wg.Done()
	for {
		select {
		case <-c.dead:
			return
		case <-c.q.ready:
			for {
				deadline, ok := c.q.writeDeadline(r.opts.WriteTimeout)
				if !ok {
					break // drained; sleep until the next push signals
				}
				if !time.Now().Before(deadline) {
					// The backlog has failed to clear within WriteTimeout of
					// its arrival, however steadily the peer trickled.
					r.finish(c)
					return
				}
				f, ok := c.q.pop()
				if !ok {
					break
				}
				if err := c.nc.SetWriteDeadline(deadline); err != nil {
					r.finish(c)
					return
				}
				if err := wire.WriteFrame(c.nc, f.b); err != nil {
					// Socket failure, or the progress deadline expiring on a
					// peer that has stopped reading - the same ending either
					// way: nothing is parsed, nothing is retried, the slot is
					// released.
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
		// Sockets still presenting the access token are not registered, so
		// the conns snapshot misses them: close them here too, or Close would
		// wait out accessTokenTimeout for each. Their handshake goroutines
		// then unblock into the ErrClosed path.
		handshaking := make([]net.Conn, 0, len(r.handshaking))
		for nc := range r.handshaking {
			handshaking = append(handshaking, nc)
		}
		r.mu.Unlock()
		if lsn != nil {
			_ = lsn.Close()
		}
		for _, nc := range handshaking {
			_ = nc.Close()
		}
		for _, c := range conns {
			r.finish(c)
		}
		r.wg.Wait()
	})
}
