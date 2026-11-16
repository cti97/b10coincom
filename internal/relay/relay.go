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
//   - a SIZE RESERVATION inside that same byte budget (testrun N-1): a frame
//     larger than smallFrameBytes may not occupy the queue's last
//     smallFrameReserveBytes, and the writer takes consensus-sized frames
//     before bulk. It is the one classification the relay makes, and it reads
//     a length the relay already parses. It exists because the fair share
//     above cannot help: the same peers both vote and serve catch-up, so the
//     traffic that crowds a receiver's queue out comes from the very senders
//     whose votes it drowns, and a BLOCK_SYNC response plus a second one fills
//     a 2 MiB queue by itself. Total bytes and frames are unchanged - the
//     reservation is a sub-limit on bulk, not new capacity - and a frame
//     cannot buy the reserved room without carrying fewer bytes, which is what
//     a consensus frame does and a catch-up response cannot;
//   - MaxConns and MaxConnsPerIP at accept, the latter grouped by source
//     PREFIX (IPv6 /64, IPv4 /24): a stranger is bounded in how many slots it
//     can hold, total and per group, so one routed prefix cannot bypass the
//     cap by rotating addresses. Both caps bind the instant the socket is
//     accepted and count a socket that is still presenting its access token
//     (audit F1): the slot, the goroutine and the frame buffer exist before
//     the token is read, so a silent dialer is capped like any other.
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
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"runtime/debug"
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

// DefaultAccessTimeout is the exported name for the gate's answer deadline, so
// the command's --access-timeout default cannot drift from the package's
// (audit N-7: the deploy README documented a flag that did not exist, and the
// value was already a field).
const DefaultAccessTimeout = accessTokenTimeout

const (
	// DefaultMaxFrameBytes is wire.MaxFrameBytes - one max-size block plus
	// the envelope a message may wrap around it - which is also the TCP
	// transport's default: one number for every wire participant, so no
	// honest validator ever sends a frame the relay must refuse. It is
	// ALIASED to the wire constant rather than written down again (audit
	// S-2): a relay at 1 MiB while a proposal may encode to 1,048,580 bytes
	// severs exactly the max-size blocks a validator is entitled to propose,
	// and the reconnect churn that follows looks like flapping peers, not
	// like a bound that was one number too small. The relay's copy is checked
	// by wire.ReadFrame BEFORE allocation, so a hostile length prefix costs
	// four bytes of header, never four gibibytes of buffer. An operator MAY
	// set it higher, never lower than the validators' bound: a relay stricter
	// than its validators severs every frame that fits at the ends but not in
	// the middle.
	DefaultMaxFrameBytes = wire.MaxFrameBytes
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
	// worst case: 64 frames x MaxFrameBytes (one max-size block plus its
	// envelope, a little over 1 MiB) = ~68 MiB pinned PER wedged
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
	// smallFrameBytes is the largest frame the write queue treats as
	// consensus-sized, and it is the ONE frame property the reservation below
	// sorts by. It is a SIZE, not a type: the relay reads a frame's length
	// before it allocates anything (wire.ReadFrame), so classifying by length
	// is the same class of observation as the byte budget itself - and it is
	// the only class of observation that can tell the two honest flows apart,
	// because they differ in size by construction and in nothing else the
	// relay is allowed to see.
	//
	// THE ARITHMETIC. Everything the consensus path depends on must fit under
	// it: a vote is tag + height + round + 32-byte block ID + 32-byte key +
	// 64-byte Ed25519 signature plus varint prefixes and the envelope, ~150
	// bytes (consensus.EncodeVote); a HELLO is <= 64 bytes of socket binding
	// plus chain id, key and signature, ~250 bytes (wire.MaxHelloNonceBytes);
	// a BLOCK_SYNC request and a PEER_EXCHANGE are a few hundred bytes; and a
	// proposal is an envelope plus a block plus a justification of at most
	// quorum prevotes - an empty devnet block is ~250 bytes and seven
	// justification votes are ~1 KiB, so a transaction-free proposal is
	// ~1.5 KiB. 4 KiB clears all of them with room for a short transaction
	// list, and everything above it carries real block weight: a BLOCK_SYNC
	// response serving DefaultMaxBlocksPerResponse (64) devnet blocks is
	// ~160 KiB and may be wire.MaxFrameBytes in one frame. A frame over the
	// line is bulk BY CONSTRUCTION - it cannot be made small without carrying
	// fewer bytes - which is what makes the reservation ungameable.
	smallFrameBytes = 4 << 10
	// smallFrameReserveBytes is the part of a connection's write-queue byte
	// budget that ONLY frames of at most smallFrameBytes may occupy: bulk is
	// capped at WriteQueueBytes - smallFrameReserveBytes, so the last of it is
	// always available to a consensus frame however much catch-up traffic the
	// relay is carrying.
	//
	// WHY THIS SIZE. The delay that the reservation exists to remove is the
	// queued bytes divided by the RECEIVER's own relay byte budget
	// (tcp.DefaultRelayBytesPerSec, 512 KiB/s - the rate at which a node's
	// relay reader actually services the socket, and therefore the rate at
	// which the relay's writer can put bytes on the wire). 64 KiB at 512
	// KiB/s is 125 ms, inside one base round timeout of the shipped ladder
	// (200 ms: internal/devnet's consensusTimeoutBaseMS); 128 KiB would be
	// 250 ms and past it. It is also ~1.6 s of the whole committee's consensus
	// traffic at 10 seats (10 nodes x ~650 bytes per height x 6 heights/s is
	// ~40 KiB/s), and it holds ~330 vote-sized frames, so a burst of votes is
	// absorbed rather than refused. A quarter of the budget is the ceiling on
	// it, so a small queue reserves proportionally and no queue reserves more
	// than bulk can spare.
	//
	// IT IS A SUB-LIMIT, NEVER NEW CAPACITY: the queue's byte budget, its frame
	// bound and its entry ring are all exactly what they were, and everything
	// reserved for consensus is subtracted from what bulk may hold, so
	// Options.MaxPinnedBytes is unchanged to the byte.
	smallFrameReserveBytes = 64 << 10
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
	// AccessToken, when non-empty, is the PRE-SHARED KEY of a challenge-response
	// gate (audit N-8, PX-3, D-1): a newly accepted connection is greeted with
	// RelayGateGreeting and a fresh random challenge, must answer
	// HMAC-SHA-256(token, challenge), and only then is sent
	// HMAC-SHA-256(token, challenge ‖ answer) and registered. A socket that
	// fails any step is closed and counted unauthorized, and the token bytes
	// are NEVER written. It is the in-process access control that works where
	// an IP allowlist cannot - behind CGNAT, or when a home validator's
	// outbound address rotates - and it keeps the relay's "parses nothing"
	// posture by construction: the check is a length-and-equality comparison
	// of raw frame bytes plus one HMAC over bytes the relay already holds,
	// never a decode, so the relay still understands nothing about consensus.
	//
	// The answer is CONSUMED, not forwarded, and a connection that has not
	// completed the exchange is never registered: it cannot receive another
	// peer's frames and cannot forward anything. Empty disables the check (the
	// pre-existing behaviour), so an existing deployment that adds no token is
	// unchanged.
	AccessToken []byte
	// AccessTimeout bounds how long an accepted connection may take to answer
	// the gate challenge before it is closed. Default accessTokenTimeout.
	// It is short because an honest client answers immediately; a socket silent
	// for this long is a scanner.
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
//	32 conns x (2 MiB payload + 4096 x 32 B entries + 2 x 1.0625 MiB hands)
//	  = 32 x (2 MiB + 128 KiB + 2.125 MiB)
//	  = 32 x 4.25 MiB = 136 MiB.
//
// which is the figure the documents quote, derived from these very fields -
// change a default and the documents' number moves with it. The per-queue
// sender-accounting map is bounded by the connections that can feed one
// queue (at most MaxConns entries) and is covered by the MemoryMax headroom,
// not itemised here.
//
// A socket still presenting its access token is counted against MaxConns from
// the instant of accept (audit F1), and it holds strictly LESS than the term
// above: no sendQ and no entry ring yet, and at most the one frame buffer
// wire.ReadFrame allocated for the token - which is unreferenced the instant
// the comparison completes, before the reader goroutine exists, so it never
// stands beside a second live buffer. It IS the reader term's one frame per
// connection. So handshake memory needs no term of its own: the aggregate is
// still MaxConns x the per-conn bound, with the handshaking population inside
// the same MaxConns. The handshake goroutine's stack is outside every frame
// bound, exactly as a reader's or writer's is.
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
	// Conns is the number of currently REGISTERED connections - the length of
	// the registry, which is what the fan-out set is drawn from. It is a
	// BOOKKEEPING count: it says what the relay believes it holds, never
	// whether a socket is still there. Read it beside Live, which is the
	// socket-lifecycle count, and Handshaking, which is the accepted sockets
	// that are not registered yet (audit F1's population). A `conns` read as
	// "sockets" is how the 2026-11-15 incident was misdiagnosed for two days:
	// the line said conns=3 on a host whose `ss` showed none.
	Conns int
	// Handshaking is the number of accepted sockets still presenting the
	// access token: counted against BOTH caps (audit F1) but absent from
	// Conns, so a line that omits it hides part of what the relay holds.
	Handshaking int
	// Accepted counts sockets the accept loop has taken from the listener, and
	// Closed counts sockets this process has closed. They are maintained at
	// the SOCKET's lifecycle, not at the registry's - a close is counted by
	// the call that actually closes the socket - which is what makes them
	// comparable with the registry counts instead of a restatement of them.
	Accepted uint64
	Closed   uint64
	// Live is Accepted minus Closed: the sockets this process has NOT closed.
	// Conns+Handshaking is what the caps believe they hold, so the two must be
	// equal whenever the books are straight; ConnBookkeepingIssue is that
	// comparison and is what the stats tick logs. A negative Live is also a
	// finding: it means a socket was closed twice, which would under-count a
	// source group and let more than --max-conns-per-ip in.
	Live int64
	// LongestSilence is how long the quietest REGISTERED connection has gone
	// without delivering a complete frame. It is measured from the reader's
	// own progress (conn.lastFrame), so it is an OBSERVATION, not a
	// derivation from the counters: a connection whose reader is wedged -
	// the incident's signature - shows an age far past --read-timeout, which
	// no healthy connection can reach because the reader's own deadline ends
	// it at exactly that bound. Zero while the registry is empty.
	LongestSilence time.Duration
	// Forwarded counts frames enqueued for onward delivery.
	Forwarded uint64
	// Dropped counts frames lost to a full (or fair-share-exhausted) write
	// queue. A steady nonzero value is the diagnosis for one thing: a peer
	// that is not keeping up - or, with the per-sender share, one sender
	// monopolising the queue it is being held to. The bound held (nobody
	// else stalled) but the relay is now the one censoring, which is
	// liveness pressure a validator set feels.
	//
	// Dropped is the TOTAL. The seven fields below split it by the reason the
	// frame was dropped, so "the relay dropped it" can be read as WHICH bound
	// bit before anyone reasons about a fix. They always sum to Dropped (a
	// dropped frame has exactly one reason); a divergence between the seven and
	// Dropped is itself a finding - a path that is not attributed.
	// This is the instrumentation the 2026-11-15 stall needed: the queue's
	// rejection path was a boolean, so an operator could see frames vanish but
	// not which limit did it.
	Dropped uint64
	// DroppedShare counts refusals of the sender account's fair share.
	DroppedShare uint64
	// DroppedBytes counts refusals by the queue's byte budget (including a
	// frame larger than the whole budget, which can never fit anywhere).
	DroppedBytes uint64
	// DroppedFrames counts refusals by the entry-ring frame bound.
	DroppedFrames uint64
	// DroppedLane counts refusals of a BULK frame by the audit N-1 size
	// reservation: the frame would have crossed into bytes only
	// consensus-sized frames may occupy. This is the counter that says the
	// reservation is what shed a frame - and a consensus-sized frame can never
	// be charged here.
	DroppedLane uint64
	// DroppedOther counts a drop no known bound claimed. It is unreachable by
	// construction, so a nonzero value means a refusal path was added without
	// being attributed - the exact silence this field exists to prevent.
	DroppedOther uint64
	// DroppedOnClose counts frames that were ADMITTED to a connection's write
	// queue and then abandoned when that connection ended for an ordinary
	// reason (the peer closed, the reader's deadline fired, the relay shut
	// down). Before this, they were counted Forwarded at enqueue and discarded
	// by finish with no other counter, so the relay over-reported delivery:
	// the 2026-11-15 stall read "forwarded climbing, dropped=0" while
	// consensus frames that had been queued for a torn-down link were gone.
	// Forwarded now equals delivered plus the abandoned terms; a nonzero value
	// is a receiver that did not drain its link, not a healthy relay.
	DroppedOnClose uint64
	// DroppedReap counts frames abandoned by the WRITE-DEADLINE reaper - the
	// writer's own teardown, taken when the receiver stalled: the queue was
	// non-empty for a whole WriteTimeout and nothing new had arrived for it.
	// It is kept separate from DroppedOnClose because the reaper is a distinct
	// decision (this receiver is not draining; nothing is still arriving),
	// while a close is just the link ending. The frame in the writer's hand
	// when its write deadline expires is charged here too. Both terms are
	// subsets of Dropped and both mean what the 2026-11-15 incident needed:
	// admitted and not delivered is dropped, never forwarded. This is the path
	// the live stall exercised (queues of 60-66 KB against a 30 s write
	// timeout in 572 of 1,019 samples), so it must never be silent.
	DroppedReap uint64
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

// rejectReason names WHY push refused a frame. A refusal is a dropped frame -
// forward never retries - so every refusal must be attributable: a boolean at
// the door is what let the 2026-11-15 stall be reported as "forwarded climbing,
// dropped=0" while frames vanished. Exactly one reason applies to a refused
// frame, and the per-reason counters on Stats are these reasons.
type rejectReason uint8

const (
	rejectNone rejectReason = iota
	// rejectByteBudget: the frame would put the queue past its total byte
	// budget (or is itself larger than the whole budget, so no queue state
	// could ever admit it).
	rejectByteBudget
	// rejectFrameCount: the entry ring is full (maxFrames live entries).
	rejectFrameCount
	// rejectSenderShare: the frame would take the SENDER ACCOUNT past its
	// allowance (shareFor). With three or more contending accounts this is the
	// bound a greedy sender meets first; a consensus-sized frame below the
	// share can never be charged here.
	rejectSenderShare
	// rejectReservedLane: a BULK frame (larger than smallFrameBytes) would
	// cross into the bytes the audit N-1 reservation keeps for
	// consensus-sized frames. By construction this can never refuse a frame
	// of smallFrameBytes or less.
	rejectReservedLane
	// rejectConnClosed: the frame was ADMITTED to a queue and then abandoned
	// when its connection ended (finish). It is the one drop that used to be
	// silent: Forwarded had already counted the frame at enqueue, so the relay
	// reported it as forwarded while it was discarded. A frame is never
	// "forwarded" and lost - it is forwarded and delivered, or it is dropped.
	rejectConnClosed
	// rejectReap: the frame was in the WRITER'S HAND (already popped, so no
	// longer in the queue) when its write deadline expired - the receiver
	// stalled past WriteTimeout. It is counted here, never left to a teardown
	// that can only see the queue: a popped frame is invisible to abandon, so
	// this is the one frame a reaping exit could otherwise drop uncounted.
	rejectReap
	// rejectOther: a refusal no known bound claimed. Unreachable by
	// construction; counted rather than folded into another reason, so an
	// unattributed path shows up as itself instead of inflating a bound that
	// did not cause it.
	rejectOther
)

// String is the log spelling of a rejection reason.
func (r rejectReason) String() string {
	switch r {
	case rejectByteBudget:
		return "byte budget"
	case rejectFrameCount:
		return "frame-count limit"
	case rejectSenderShare:
		return "per-sender share"
	case rejectReservedLane:
		return "consensus reservation (bulk frame)"
	case rejectConnClosed:
		return "connection closed with the frame queued"
	case rejectReap:
		return "write deadline reaped the connection (the frame was in the writer's hand)"
	case rejectOther:
		return "UNATTRIBUTED (a drop path is not accounted)"
	default:
		return "unknown"
	}
}

// pushRejection describes one refused frame for the drop line. It is filled
// only when push refuses; the zero value is not a refusal.
type pushRejection struct {
	reason rejectReason
	size   int // the refused frame's payload bytes
	queued int // the queue's bytes at the refusal
	limit  int // the queue's byte budget
	allow  int // the refusing sender account's allowance at the refusal
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
// The allowance is contention-relative AND contention-sticky: while no OTHER
// account has ever held a byte and no push has ever been REFUSED room, the
// sender may use the whole budget; once a push has been refused while another
// account held bytes - the one observable that says the queue is really
// shared - every sender is held to its equal share of the queue's OWN limit
// (shareFor) for the queue's lifetime. A queue with one sender therefore
// admits up to its whole budget and loses nothing while the receiver has room;
// the equal share reserves room for the other registered senders only once the
// queue is really shared, which is the crowding-out the share exists to stop.
//
// What this closes (audit F2, the fourth failure here): a flooder that fills
// the queue BEFORE another sender has queued anything used to keep the whole
// budget for itself, because it was still the only account holding bytes, and
// its refill would beat the honest sender to the room every time - the honest
// sender's frames refused indefinitely, 100 rounds out of 100. The refusal
// itself is now the evidence: the instant an honest frame is denied room by
// another account's occupancy, the reservation becomes unconditional, the
// squatter can no longer refill past its share, and the writer's drain ages its
// occupancy back down to that share. What this does NOT bound is a flooder
// whose share IS the whole queue (the only contending account) keeping a
// receiver too slow to drain backlogged: that receiver is the one not keeping
// up, and it is the reaper's (see writer).
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
	// smallMax is the size at or under which a frame is consensus-sized
	// (smallFrameBytes). It is read on every push and every pop and is a
	// length, never a payload byte.
	smallMax int
	// reserve is the part of limit that only consensus-sized frames may
	// occupy, and bulkLimit is limit-reserve: the most payload bulk frames
	// may hold between them. Both are derived once, here, so a reader can
	// re-run the arithmetic from the two options above.
	reserve   int
	bulkLimit int

	mu     sync.Mutex
	ents   []sentFrame // ring buffer, fixed length maxFrames
	head   int         // index of the oldest entry
	n      int         // live entries
	bytes  int
	from   map[shareAccount]int // queued bytes per sender account, refunded on pop
	oldest time.Time            // when the queue became non-empty; zero when empty
	// lastPush is when the most recent frame was ADMITTED (zero while empty).
	// The writer reads it beside oldest to attribute a stalled drain (audit
	// F3): a queue that has taken no new frame for a whole WriteTimeout and
	// still has not emptied is the RECEIVER's backlog; one that is merely
	// kept full by continuing arrivals is the SENDER's, and must not cost the
	// receiver its link.
	lastPush time.Time
	// contended records that at least one push has been refused room while
	// another account held bytes in this queue. Once true it stays true for
	// the queue's lifetime: the equal share then applies unconditionally, so a
	// sender that squatted on the whole budget before contention appeared
	// cannot keep refilling past its share (audit F2). A queue that has never
	// been refused room keeps the whole-budget allowance for its sole sender.
	contended bool
	// smallN is how many of the n live entries are consensus-sized (at most
	// smallMax bytes). It exists so the writer can skip the search for a
	// consensus frame entirely on the bulk-only queues that carry catch-up
	// traffic, which is the common case during a catch-up and the one where
	// the search would be longest.
	smallN int
	ready  chan struct{} // cap 1: signalled on empty -> non-empty
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
	// The reservation is a QUARTER of the budget at most, so an operator who
	// shrinks --write-queue-bytes cannot accidentally reserve all of it; and
	// never less than one byte, so the boundary stays a boundary even for the
	// socket-free queue tests' three-entry budgets.
	reserve := smallFrameReserveBytes
	if quarter := limit / 4; reserve > quarter {
		reserve = quarter
	}
	if reserve < 1 {
		reserve = 1
	}
	return &sendQ{
		limit:         limit,
		maxFrameBytes: maxFrameBytes,
		maxFrames:     maxFrames,
		smallMax:      smallFrameBytes,
		reserve:       reserve,
		bulkLimit:     limit - reserve,
		ents:          make([]sentFrame, maxFrames),
		from:          make(map[shareAccount]int),
		ready:         make(chan struct{}, 1),
	}
}

// small reports whether a frame of n bytes is consensus-sized, i.e. may use
// the reserved part of the budget and is written before bulk. It reads a
// length; it is the only classification the relay makes, and it needs no byte
// of the payload to answer.
func (s *sendQ) small(n int) bool { return n <= s.smallMax }

// shareFor returns the allowance one sender account is held to when
// `senders` distinct accounts can contend for this queue: an equal fraction
// (1/senders) of the queue's OWN byte capacity, floored at one maximum frame
// so a legitimate largest frame always has room even when the division would
// round it below a frame, and never above the queue's own budget. push applies
// this unconditionally once the queue has been observed CONTENDED - at least
// one push has been refused while another account held bytes - and falls back
// to the whole budget only while no refusal has ever happened and no other
// account holds a byte. So the sole sender of a queue that has never been
// crowded faces the whole capacity and loses nothing, which is the property
// TestRelayASingleSenderAmongIdlePeersUsesTheWholeQueue pins; but a sender
// that filled the queue first (while it was the only one holding anything)
// loses the whole-budget allowance the moment a second account is refused
// room, instead of keeping the reservation it squatted on indefinitely (audit
// F2: the fourth failure in this area, and the first one whose shape is
// "flood first, then the honest sender arrives").
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
//
// THE SIZE RESERVATION (testrun N-1). A frame larger than smallFrameBytes may
// not occupy the queue's last smallFrameReserveBytes, whatever the byte budget
// and the sender's share would otherwise allow; a consensus-sized frame may use
// the whole budget exactly as before. So the reservation is never new capacity
// and never a weaker bound - it takes room from bulk and gives none to
// anybody - and it is ungameable without parsing: a frame is small only by
// BEING small, and the length it is classified on is the length the relay must
// already read to bound the frame at all. A peer that wants the reserved room
// has to carry fewer bytes in the frame, which is exactly what a consensus
// frame does and what a catch-up response cannot.
//
// The refusal of a BULK frame by that reservation deliberately does not set
// s.contended: the contention the share exists to answer is one account
// crowding another out, and the reservation refusing bulk is the queue being
// partitioned, not shared. Only a refusal that the share or the ring caused,
// with another account holding bytes, turns the sticky share on.
func (s *sendQ) push(sender *conn, b []byte, senders int) bool {
	ok, _ := s.tryPush(sender, b, senders)
	return ok
}

// tryPush is push with its refusal attributed: on false it returns the ONE
// bound that refused the frame, so forward can count and log the drop instead
// of discarding the why. push stays a boolean for the queue-level callers that
// only care whether the frame got in.
func (s *sendQ) tryPush(sender *conn, b []byte, senders int) (bool, pushRejection) {
	acct := shareAccountOf(sender)
	share := s.shareFor(senders)
	small := s.small(len(b))
	s.mu.Lock()
	// Actual contention is the bytes another account is holding in this
	// queue - OR the fact that this queue has already denied someone room
	// because of them (s.contended). While neither has ever happened, the one
	// sender using the queue may take the whole budget; the equal share is
	// what it is held to once the queue is really shared. The sticky half is
	// what stops a flood-first squatter: it loses the whole-budget allowance
	// the moment the sender it crowded out is refused, and the writer's drain
	// then ages its occupancy back to its share (audit F2).
	allow := share
	if !s.contended && s.bytes-s.from[acct] == 0 {
		allow = s.limit
	}
	// laneRefused is true only when the RESERVATION is what denies this frame
	// room - a bulk frame that would cross into the reserved bytes. It is
	// separated from a budget refusal because the two are attributed
	// differently: the reservation is the queue being partitioned, while a
	// budget refusal with another account holding bytes is the queue being
	// shared (audit F2's sticky share). A consensus-sized frame's lane IS the
	// whole budget, so the reservation can never refuse one.
	overBudget := s.bytes+len(b) > s.limit
	laneRefused := !small && !overBudget && s.bytes+len(b) > s.bulkLimit
	tooBig := len(b) > s.limit
	full := s.n >= s.maxFrames
	overShare := s.from[acct]+len(b) > allow
	ok := !tooBig && !overBudget && !laneRefused && !full && !overShare
	if ok {
		now := time.Now()
		if s.n == 0 {
			s.oldest = now
		}
		s.lastPush = now
		s.ents[(s.head+s.n)%s.maxFrames] = sentFrame{sender: sender, b: b}
		s.n++
		if small {
			s.smallN++
		}
		s.bytes += len(b)
		s.from[acct] += len(b)
		if s.n == 1 { // the transitions the writer can be asleep across
			select {
			case s.ready <- struct{}{}:
			default: // a token is already pending: the wake is not lost
			}
		}
	} else if !laneRefused && s.bytes-s.from[acct] > 0 {
		// This sender was refused room that ANOTHER account is holding:
		// that is the queue being shared, and it is the observable that
		// turns the equal share on for good (audit F2). A refusal with no
		// other account in the queue (the sender is at its own share, or the
		// ring is full of its own frames) says nothing about sharing and does
		// not set it - and neither does the reservation, which is the queue
		// being partitioned rather than shared (testrun N-1).
		s.contended = true
	}
	rej := pushRejection{
		reason: rejectNone,
		size:   len(b),
		queued: s.bytes,
		limit:  s.limit,
		allow:  allow,
	}
	if !ok {
		// One reason, in the order the frame meets the bounds. The lane is
		// reported before the total budget because a bulk frame that crosses
		// the lane AND leaves the budget is still the reservation's decision:
		// the reserved bytes are not bulk's to spend.
		switch {
		case laneRefused:
			rej.reason = rejectReservedLane
		case tooBig || overBudget:
			rej.reason = rejectByteBudget
		case full:
			rej.reason = rejectFrameCount
		case overShare:
			rej.reason = rejectSenderShare
		default:
			// Unreachable while ok is the conjunction above, but named rather
			// than left as a silent zero: a future edit that refuses a frame
			// for a new reason without extending this switch shows up in
			// DroppedOther instead of hiding inside a bound that did not fire.
			rej.reason = rejectOther
		}
	}
	s.mu.Unlock()
	return ok, rej
}

// smallPos returns the ring OFFSET (from head) of the oldest consensus-sized
// entry, or -1 when none is queued. The scan is bounded by smallN's caller:
// the writer only asks when smallN says there is one to find, and then only
// walks the bulk frames in front of it.
func (s *sendQ) smallPos() int {
	if s.smallN == 0 {
		return -1
	}
	for i := 0; i < s.n; i++ {
		if s.small(len(s.ents[(s.head+i)%s.maxFrames].b)) {
			return i
		}
	}
	return -1
}

// promote moves the entry at ring offset i (i > 0) to the head, shifting the
// entries in front of it one place later. It preserves the relative order of
// EVERY other entry: only a consensus-sized frame overtakes anything, and what
// it overtakes is bulk. So per-sender order among consensus frames is
// untouched, per-sender order among bulk frames is untouched, and the only
// order the queue no longer keeps is bulk-before-consensus from the same
// sender - which the wire does not depend on (votes are tallied by height,
// round and block ID, and a BLOCK_SYNC response is matched by nonce), and which
// is the delay this exists to remove.
func (s *sendQ) promote(i int) {
	if i <= 0 {
		return
	}
	at := func(k int) int { return (s.head + k) % s.maxFrames }
	saved := s.ents[at(i)]
	for k := i; k > 0; k-- {
		s.ents[at(k)] = s.ents[at(k-1)]
	}
	s.ents[at(0)] = saved
}

// pop takes the next frame to write, refunding its bytes to the budget and to
// its sender account. It is non-blocking: nothing to take returns false, and
// the writer goes back to sleep on ready.
//
// The WRITE ORDER is the other half of the reservation: when any
// consensus-sized frame is queued it is taken first (oldest such frame first),
// so bulk - which the puller re-requests and can therefore wait - never delays
// a vote by more than the consensus frames queued ahead of it. Without this,
// reserving the room would only convert a lost vote into a late one: the vote
// would sit behind every byte of bulk already in the queue, and the receiver's
// own relay byte budget paces that drain at 512 KiB/s.
//
// The irreducible residual, stated rather than glossed: a consensus frame that
// arrives while a bulk frame is ALREADY being written waits for the rest of
// that frame, because a socket cannot carry two frames at once. That is one
// frame's drain (typically ~160 KiB = ~0.3 s at a node's 512 KiB/s relay read
// budget, at worst one MaxFrameBytes frame) instead of the whole queue, and no
// parse-free queue can shorten it further: the alternative is fragmenting
// frames, which is the one thing the wire's framing forbids.
func (s *sendQ) pop() (sentFrame, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.n == 0 {
		return sentFrame{}, false
	}
	if i := s.smallPos(); i > 0 {
		s.promote(i)
	}
	f := s.ents[s.head]
	s.ents[s.head] = sentFrame{}
	s.head = (s.head + 1) % s.maxFrames
	s.n--
	if s.small(len(f.b)) {
		s.smallN--
	}
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

// abandon empties the queue and reports what it held. finish calls it when a
// connection ends, so every frame still queued is COUNTED as dropped instead
// of vanishing: a frame the relay admitted and then could not deliver is not a
// forwarded frame, and a relay that reports one as forwarded over-states the
// only thing its counters exist to show. The writer may have a frame in its
// hand (already popped, not yet written); that one is charged by the writer
// when the write fails, so the two halves add up to what was undelivered.
func (s *sendQ) abandon() (frames, bytes int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	frames, bytes = s.n, s.bytes
	for i := 0; i < s.n; i++ {
		s.ents[(s.head+i)%s.maxFrames] = sentFrame{}
	}
	s.head, s.n, s.bytes, s.smallN = 0, 0, 0, 0
	if len(s.from) != 0 {
		s.from = make(map[shareAccount]int)
	}
	s.oldest = time.Time{}
	return frames, bytes
}

// writeDeadline returns the absolute instant by which the queue must have
// drained to EMPTY, and whether a frame is queued at all. The anchor is the
// instant the queue became non-empty, NOT "now": re-arming a fresh
// now+timeout per frame is precisely the hole audit N-2 re-opened, because a
// sink that accepts a little of every frame makes each write "succeed" while
// the backlog never clears. The writer arms the socket with this deadline and
// refuses to write past it, so the whole backlog is bounded by one
// WriteTimeout from its arrival however steadily the peer trickles.
//
// It is a READING, not the whole reaping rule: receiverStalled below says
// whether the expiry is grounds to end the connection or evidence that a
// sender owns this backlog (audit F3).
func (s *sendQ) writeDeadline(timeout time.Duration) (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.n == 0 {
		return time.Time{}, false
	}
	return s.oldest.Add(timeout), true
}

// receiverStalled reports whether this queue's backlog belongs to the
// RECEIVER (audit F3): it has been continuously non-empty for at least
// timeout AND no frame has been admitted within that same window. Only then
// is the drain failing for a reason the receiver owns - nothing is still
// arriving, and the queue still will not clear.
//
// The second half is the attribution fix. A queue kept full by frames that
// keep ARRIVING has a SENDER's backlog: the byte budget and the per-sender
// share (audit F2) are what answer it, and the writer drops what does not fit
// while still writing what does. Ending the receiver's connection there is
// exactly the third-party lever audit F3 names - a flooder sustaining an
// honest validator's backlog past WriteTimeout would make the relay tear that
// validator's link down, and the validator redials into the same flood
// (flapping rather than dormancy, but the flooder's goal either way). The
// relay parses nothing here either: "a frame was admitted within the last
// WriteTimeout" is a timestamp on the queue, never a byte of payload.
func (s *sendQ) receiverStalled(timeout time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.n == 0 {
		return false
	}
	now := time.Now()
	return now.Sub(s.oldest) >= timeout && now.Sub(s.lastPush) >= timeout
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
	// lastFrame is the unix-nano instant of the last COMPLETE frame this
	// connection's reader delivered, stored at admit and refreshed after every
	// frame. It is the relay's one OBSERVED liveness fact per connection: the
	// reader's socket deadline guarantees a live reader cannot leave it older
	// than ReadTimeout (a frame in progress is bounded by the same deadline),
	// so an age beyond that means the reader is no longer reading. The stats
	// tick reports the oldest one and says so loudly, which is the check the
	// 2026-11-15 incident needed: the registry said 3 connections while the
	// host held none, and nothing in the counters could tell.
	lastFrame atomic.Int64
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

// teardown tears one connection down exactly once: drop the connection from
// the registry and from its source group's count, close dead (unblocking the
// writer), and close the socket (unblocking every goroutine parked on it).
//
// All of it is ONE critical section, exactly as the transport's finish already
// is (audit N-14): the registry delete and the connection's death are atomic, so
// a fan-out holding the registry lock either sees a live connection or does not
// see it at all. The pre-fix order closed dead and the socket BEFORE taking the
// lock, leaving a window in which the registry still named a corpse; forward
// then picked it as a target and counted a frame the dead writer could never
// write, so Stats.Forwarded over-reported.
//
// The accounting is the SAME on every exit that can abandon queued frames:
// finish (the ordinary close) and finishReaped (the write-deadline reap) both
// drain the queue through sendQ.abandon before the socket is closed. The frame
// in the writer's hand is not in the queue (pop took it), so the writer charges
// it itself before calling either - otherwise that one frame per teardown
// would still be lost silently, which is exactly the hole this closes.
func (r *Relay) finish(c *conn) { r.teardown(c, false) }

// finishReaped is finish for the WRITE-DEADLINE REAP: the writer ended a
// connection because its receiver stalled (receiverStalled), not because the
// link was done. The abandoned frames are counted and attributed to the reap
// rather than to an ordinary close, so the counters say which decision lost
// them. The teardown itself is identical - one registry delete, one abandon,
// one socket close - so no exit can bypass the accounting by taking this path.
func (r *Relay) finishReaped(c *conn) { r.teardown(c, true) }

func (r *Relay) teardown(c *conn, reaped bool) {
	c.once.Do(func() {
		r.mu.Lock()
		delete(r.conns, c)
		r.decGroupLocked(c.srcGroup) // the accept-time cap sees the freed slot again
		frames, bytes := c.q.abandon()
		close(c.dead)
		r.closeSocket(c.nc)
		r.mu.Unlock()
		if frames > 0 {
			r.recordAbandoned(c, frames, bytes, reaped)
		}
	})
}

// recordAbandoned accounts the frames a teardown discarded: each is a Dropped
// frame (they were counted Forwarded at enqueue, and never reached the wire).
// One line per teardown rather than one per frame: a receiver that stops
// draining loses its whole backlog at once, and that event is the diagnosis.
func (r *Relay) recordAbandoned(c *conn, frames, bytes int, reaped bool) {
	r.dropped.Add(uint64(frames))
	where := "a hand-built connection"
	if c.nc != nil {
		where = c.nc.RemoteAddr().String()
	}
	why := "the connection closed with them still queued, so they were never written"
	if reaped {
		r.droppedReap.Add(uint64(frames))
		why = "the write deadline reaped the connection (it did not drain within WriteTimeout), so they were never written"
	} else {
		r.droppedClose.Add(uint64(frames))
	}
	r.dropLine(fmt.Sprintf("b10coin: relay: DROPPED %d queued frame(s) (%d bytes) for %s: %s",
		frames, bytes, where, why))
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
	// access token (audit N-8), keyed to the source group whose accept-time
	// slot they hold, so Close can close them instead of waiting out
	// accessTokenTimeout. A connection is in this set only between accept and
	// admit; it is never registered and never forwarded. It IS counted
	// against BOTH caps from the moment of accept: the resource being bounded
	// is the socket, its goroutine, its frame buffer and its slot - all of
	// which exist before the token is read - so a silent dialer cannot
	// escape the cap by staying silent (audit F1).
	handshaking map[net.Conn]string

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
	droppedShare atomic.Uint64
	droppedBytes atomic.Uint64
	droppedFrame atomic.Uint64
	droppedLane  atomic.Uint64
	droppedClose atomic.Uint64
	droppedReap  atomic.Uint64
	droppedOther atomic.Uint64
	refused      atomic.Uint64
	unauthorized atomic.Uint64
	// readerPanics counts per-connection readers that recovered from a panic
	// (audit S-9). One panic costs one connection, never the process.
	readerPanics atomic.Uint64
	// accepted counts sockets the accept loop has taken from the listener;
	// closedSockets counts sockets this process has closed (see closeSocket,
	// which counts only the call that actually closed one). The two are
	// maintained at the SOCKET's lifecycle rather than at the registry's, so
	// their difference can be compared with the registry's slot count instead
	// of restating it - ConnBookkeepingIssue is that comparison.
	accepted      atomic.Uint64
	closedSockets atomic.Uint64

	// refusalMu guards the gate-refusal line's rate limiter, and is separate
	// from r.mu so a refusal never contends with the registry lock. The
	// refusal path is reachable by anyone who can open a socket, so it is the
	// one log line in this process that an attacker can trigger at will: it is
	// rate-limited, and the suppressed count keeps it honest.
	refusalMu         sync.Mutex
	refusalLast       time.Time
	refusalSuppressed int

	// dropMu guards the drop line's rate limiter, separate from r.mu and from
	// refusalMu: a drop is produced under the registry lock (forward holds it
	// across the fan-out), so logging from there must not re-enter anything.
	// The line is rate-limited because a wedged receiver makes every frame a
	// drop - the one time the message is most useful is also the one time an
	// unthrottled line would flood the journal.
	dropMu         sync.Mutex
	dropLast       time.Time
	dropSuppressed int
}

// New returns a relay with all bounds defaulted. Nothing runs and nothing is
// open until Listen.
func New(opts Options) *Relay {
	return &Relay{
		opts:        opts.withDefaults(),
		conns:       make(map[*conn]struct{}),
		perGroup:    make(map[string]int),
		handshaking: make(map[net.Conn]string),
		quit:        make(chan struct{}),
	}
}

// Listen accepts connections on addr until Close. It returns error for a
// failed net.Listen, a double Listen, a Listen after Close, or an access token
// shorter than wire.MinRelayAccessTokenBytes.
func (r *Relay) Listen(addr string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed.Load() {
		return ErrClosed
	}
	if r.lsn != nil {
		return fmt.Errorf("relay: already listening on %s", r.lsn.Addr())
	}
	if n := len(r.opts.AccessToken); n > 0 && n < wire.MinRelayAccessTokenBytes {
		// Refused at STARTUP, before a listener exists, not at each dial: a
		// token shorter than the floor is brute-forced by dialling it (a
		// 1-byte token falls in 256 attempts), and a relay that came up anyway
		// would advertise a gate it cannot defend. New cannot report this (it
		// returns no error), so Listen - the call that makes the relay
		// reachable - is where the configuration is refused. cmd/b10coin-relay
		// checks the flag too, so an operator gets the message before this.
		return fmt.Errorf("relay: access token is %d bytes; at least %d are required (a short token is brute-forced by dialling)",
			n, wire.MinRelayAccessTokenBytes)
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

// Stats returns a point-in-time reading of the relay's counters: the registry
// and handshake populations under the registry lock, the per-connection
// freshness observation, and the atomics the hot path maintains.
func (r *Relay) Stats() Stats {
	r.mu.Lock()
	conns := len(r.conns)
	handshaking := len(r.handshaking)
	var oldest int64 // the smallest lastFrame: the quietest registered connection
	for c := range r.conns {
		if ts := c.lastFrame.Load(); ts != 0 && (oldest == 0 || ts < oldest) {
			oldest = ts
		}
	}
	r.mu.Unlock()
	var silence time.Duration
	if oldest != 0 {
		silence = time.Since(time.Unix(0, oldest))
	}
	accepted := r.accepted.Load()
	closed := r.closedSockets.Load()
	return Stats{
		Conns:          conns,
		Handshaking:    handshaking,
		Accepted:       accepted,
		Closed:         closed,
		Live:           int64(accepted) - int64(closed),
		LongestSilence: silence,
		Forwarded:      r.forwarded.Load(),
		Dropped:        r.dropped.Load(),
		DroppedShare:   r.droppedShare.Load(),
		DroppedBytes:   r.droppedBytes.Load(),
		DroppedFrames:  r.droppedFrame.Load(),
		DroppedLane:    r.droppedLane.Load(),
		DroppedOnClose: r.droppedClose.Load(),
		DroppedReap:    r.droppedReap.Load(),
		DroppedOther:   r.droppedOther.Load(),
		RefusedConns:   r.refused.Load(),
		Unauthorized:   r.unauthorized.Load(),
	}
}

// closeSocket closes one accepted socket and counts the close - but only the
// call that actually closed it. A second Close on the same socket returns an
// error (net.ErrClosed) and is not counted, which is what keeps the count
// honest on the paths where two goroutines can reach the same socket: Close
// closes every handshaking socket while its own handshake goroutine is still
// running, and that goroutine closes it again on the way out.
//
// Every socket the relay closes goes through here (accept refusal, each gate
// exit, a refused admit, finish, and Close's handshake sweep), so Accepted
// minus Closed is the number of sockets this process still holds. That is the
// number the stats line must show beside the registry's slot count: the
// incident's line reported the SLOT count (conns=3) as if it were the socket
// count, and no counter could contradict it.
func (r *Relay) closeSocket(nc net.Conn) {
	if err := nc.Close(); err == nil {
		r.closedSockets.Add(1)
	}
}

// ConnBookkeepingIssue compares what the relay BELIEVES it holds with what it
// has actually done with sockets, and reports the disagreement in one line.
// It is the check the stats tick runs (cmd/b10coin-relay's logStats), and it
// answers the question the 2026-11-15 incident could not: is `conns` a socket
// count or a registry count that has outlived its sockets?
//
// Two comparisons, both cheap and both on data the relay already maintains:
//
//   - the CAPS' POPULATION against the SOCKET LIFECYCLE: the caps count
//     len(conns)+len(handshaking) slots, and Accepted-Closed counts the sockets
//     the process has not closed. Every accepted socket is in exactly one of
//     the two populations or has been closed exactly once, so the two must be
//     equal. A leaked slot (a socket closed without its release), a double
//     release (an under-count, which would let more than --max-conns-per-ip
//     in), and a connection whose goroutines are gone all land here.
//
//   - the READ DEADLINE against OBSERVED TRAFFIC: every reader arms a
//     per-frame deadline of ReadTimeout, so a registered connection cannot go
//     longer than that without a complete frame - the reader would have ended
//     it. A registered connection older than twice that is a reader that is no
//     longer reading, which is exactly "the registry holds a socket that is
//     not there". Twice, not once, because a frame IN PROGRESS may legally
//     consume the whole ReadTimeout before completing.
//
// A disagreement that a re-reading two milliseconds later no longer sees is
// not reported: a socket counted at accept but not yet reserved, or a finish
// between its two counters, is a nanosecond-wide window in the accept loop or
// the teardown, and a real leak survives a re-read. So the normal path costs
// one Stats read, and the check never sleeps unless something already looks
// wrong.
func (r *Relay) ConnBookkeepingIssue() (string, bool) {
	check := func(st Stats) (string, bool) {
		if slots := st.Conns + st.Handshaking; int64(slots) != st.Live {
			return fmt.Sprintf("the caps count %d slots (conns=%d handshaking=%d) but the socket lifecycle counts %d live (accepted=%d closed=%d): %s",
				slots, st.Conns, st.Handshaking, st.Live, st.Accepted, st.Closed,
				slotsLeakWords(slots, st.Live)), true
		}
		if limit := 2 * r.opts.ReadTimeout; limit > 0 && st.LongestSilence > limit {
			return fmt.Sprintf("a registered connection has delivered no frame for %s, past twice --read-timeout (%s): its reader's own deadline should have ended it, so the registry is holding a connection that is not reading",
				st.LongestSilence.Round(time.Second), r.opts.ReadTimeout), true
		}
		return "", false
	}
	if _, bad := check(r.Stats()); !bad {
		return "", false
	}
	time.Sleep(2 * time.Millisecond)
	return check(r.Stats())
}

// slotsLeakWords names the DIRECTION of a slot/socket disagreement, because
// the two directions are different bugs: too few slots is a double release
// (the caps stop binding), and too many is a slot whose socket is already
// closed (the incident's over-count).
func slotsLeakWords(slots int, live int64) string {
	if int64(slots) > live {
		return fmt.Sprintf("%d slot(s) more than sockets - a slot outlived the socket it was taken for", int64(slots)-live)
	}
	return fmt.Sprintf("%d socket(s) more than slots - a slot was released twice, so the caps under-count", live-int64(slots))
}

// ReaderPanics reports how many per-connection readers recovered from a panic
// (audit S-9). One is one connection closed, not one relay lost.
func (r *Relay) ReaderPanics() uint64 { return r.readerPanics.Load() }

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
		// The cap binds HERE, under the registry lock and BEFORE any
		// per-connection goroutine, socket deadline or handshake state
		// exists (audit F1). The N-8 gate moved the token read off the accept
		// loop - correctly, it blocks on the remote - but it left the cap in
		// admit, which runs only after that read returns: with a token
		// configured, silent dials held a goroutine, a frame buffer and a
		// socket for AccessTimeout each, unbounded by MaxConns and
		// unaccounted in MaxPinnedBytes. N-8's regression, undone: the slot
		// is RESERVED at accept (r.handshaking + r.perGroup, the same two
		// numbers admit used to check) and the handshake goroutine is only
		// spawned once the reservation is held. A socket in handshake is the
		// resource, so it counts: the cap is the cap on sockets, not on
		// sockets that have already said something.
		// The socket exists from here, whether or not the caps want it, so it
		// is counted here: a refused dial is a socket this process opened and
		// closed, and the lifecycle count must see both halves.
		r.accepted.Add(1)
		group := connGroup(nc.RemoteAddr())
		r.mu.Lock()
		if err := r.acceptCapLocked(group); err != nil {
			r.mu.Unlock()
			if !errors.Is(err, ErrClosed) {
				r.refused.Add(1)
			}
			r.closeSocket(nc)
			continue
		}
		r.handshaking[nc] = group
		r.perGroup[group]++
		// handshake performs the access-token read when a token is
		// configured, which BLOCKS on the remote speaking - it must never run
		// on the accept loop, or one silent dialer would stall every other
		// connection. The handshake goroutine is counted on the same
		// WaitGroup Close waits on, and the socket is tracked in
		// r.handshaking (with its reserved slot) so Close can close it rather
		// than wait out the token deadline.
		r.wg.Add(1)
		r.mu.Unlock()
		go r.handshake(nc, group)
	}
}

// acceptCapLocked applies the accept-time refusal rules in order - relay
// closed, then MaxConns, then MaxConnsPerIP (audit N-2: no single source may
// hold every slot; the per-GROUP count is kept under the same mutex the
// registry is, and releaseHandshake and finish both give the slot back).
// BOTH caps count a HANDSHAKING socket exactly as they count a registered
// one, because both bound the same thing: a live socket with a goroutine and
// a slot. r.mu must be held.
func (r *Relay) acceptCapLocked(group string) error {
	if r.closed.Load() {
		return ErrClosed
	}
	if len(r.conns)+len(r.handshaking) >= r.opts.MaxConns {
		return fmt.Errorf("relay: registry full (%d)", r.opts.MaxConns)
	}
	if r.perGroup[group] >= r.opts.MaxConnsPerIP {
		return fmt.Errorf("relay: source group %s holds %d slots already (cap %d)", group, r.perGroup[group], r.opts.MaxConnsPerIP)
	}
	return nil
}

// decGroupLocked returns one accept-time slot to a source group - the single
// place the per-group count is decremented, used by both finish (a registered
// connection ends) and releaseHandshake (a handshaking socket ends), so the
// two paths can never drift. r.mu must be held.
func (r *Relay) decGroupLocked(group string) {
	if r.perGroup[group] > 0 {
		r.perGroup[group]--
		if r.perGroup[group] == 0 {
			delete(r.perGroup, group)
		}
	}
}

// releaseHandshake drops a handshaking socket's accept-time reservation: its
// handshaking entry and its per-group slot are freed together, so the cap
// sees the slot again the instant the token is refused, the read fails, or
// the relay shuts down. It is a no-op for a socket that has already been
// admitted (the entry is gone) or was never reserved.
func (r *Relay) releaseHandshake(nc net.Conn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if group, ok := r.handshaking[nc]; ok {
		delete(r.handshaking, nc)
		r.decGroupLocked(group)
	}
}

// handshake presents the access-token gate (audit N-8) and then admits the
// connection whose accept-time slot the caller has already reserved against
// both caps (audit F1). With no token configured it is the admit call alone.
//
// With a token, the exchange is four frames and no decoding at any point
// (audit PX-3, D-1): the relay writes the FIXED greeting FIRST, then a 32-byte
// random nonce followed by this socket's own local address - the challenge;
// the connection's FIRST inbound frame must then be the HMAC-SHA-256 of that
// challenge under the token, and it is consumed, never forwarded; and only on
// a match does the relay write RelayGateConfirmation, an HMAC over the
// challenge and that proof. That last frame is what lets the node tell a gated
// relay from BOTH a dead socket and a stranger looping the first three frames
// through an ungated relay (audit D-1). The challenge costs one extra bounded
// write on a socket that is already open, before the relay knows anything about
// the peer; the token is never sent, so forwarding the node's answer to every
// peer forwards no secret.
//
// The relay still calls no decoder anywhere in this path: it reads a frame
// (wire.ReadFrame), compares raw bytes in constant time (subtle.
// ConstantTimeCompare), and writes two constant-width frames and one fixed
// constant. Its "parses nothing" posture is intact by construction. A
// connection that fails, or says nothing within accessTokenTimeout, is closed,
// counted as unauthorized, and its reserved slot is RELEASED; it is NEVER
// registered, so it can neither receive nor forward a frame.
//
// The frames are a wire-format fact shared with the node side, so they come
// from internal/wire (RelayGateGreeting/RelayGateConfirmation), which both ends
// already import - one source of truth, no import of the transport layer here.
func (r *Relay) handshake(nc net.Conn, group string) {
	defer r.wg.Done()
	if len(r.opts.AccessToken) > 0 {
		// Announce gating before asking for anything. A node that reads this
		// knows the relay will ask for a proof; a node that does not get it
		// refuses to answer (tcp.adoptRelay). The write is bounded like every
		// other handshake write on this socket.
		if err := writeGateFrame(nc, wire.RelayGateGreeting, r.opts.WriteTimeout); err != nil {
			// A failed gate WRITE is a dying socket, not a refused token
			// (audit D-5): counting it as unauthorized made a healthy relay
			// look like it was turning valid tokens away whenever a peer
			// disconnected mid-handshake.
			r.releaseHandshake(nc)
			r.closeSocket(nc)
			return
		}
		// The challenge (audit PX-3): 32 fresh random bytes, then this
		// connection's own local address. It is BUILT, never parsed - the
		// relay is not interpreting anything, it is choosing a nonce and
		// stating which of its sockets the answer is for. The node hashes the
		// bytes exactly as sent, so the two ends agree without the relay
		// understanding an address format.
		challenge := make([]byte, wire.RelayGateNonceBytes, wire.MaxRelayGateChallengeBytes)
		if _, err := rand.Read(challenge); err != nil {
			r.unauthorized.Add(1)
			r.releaseHandshake(nc)
			r.closeSocket(nc)
			return
		}
		if la := nc.LocalAddr(); la != nil {
			challenge = append(challenge, la.String()...)
		}
		if err := writeGateFrame(nc, challenge, r.opts.WriteTimeout); err != nil {
			r.releaseHandshake(nc) // dying socket, not a refused token (audit D-5)
			r.closeSocket(nc)
			return
		}
		if err := nc.SetReadDeadline(time.Now().Add(r.opts.AccessTimeout)); err != nil {
			r.unauthorized.Add(1)
			r.releaseHandshake(nc)
			r.closeSocket(nc)
			return
		}
		// The answer is one fixed-width MAC (audit PX-3): the read bound is
		// the MAC's own width, so nothing is allocated from a declared
		// length, and there is nothing to decode - it is compared as bytes.
		// The comparison is constant-time (audit F5), and because the expected
		// value is an HMAC keyed by the token, the token itself never touches
		// the wire and a captured answer is worthless on another connection.
		frame, err := wire.ReadFrame(nc, wire.RelayGateMACBytes)
		expected := wire.RelayGateProof(r.opts.AccessToken, challenge)
		if err != nil || len(frame) != len(expected) ||
			subtle.ConstantTimeCompare(frame, expected) != 1 {
			r.logGateRefusal(nc.RemoteAddr(), frame, err)
			r.unauthorized.Add(1)
			r.releaseHandshake(nc)
			r.closeSocket(nc)
			return
		}
		// The proof matched. Confirm it BEFORE clearing the deadline, so a node
		// with a wrong token (which the relay closes above, without an ack) is
		// distinguishable from one that was admitted: the node's read of this
		// frame is its only signal. The confirmation is keyed by the token
		// (audit D-1), so a stranger on an ungated relay cannot produce it by
		// looping the greeting and a challenge. A write failure here is a dying
		// socket, not a refused token, so it is not counted as unauthorized.
		confirmation := wire.RelayGateConfirmation(r.opts.AccessToken, challenge, frame)
		if err := writeGateFrame(nc, confirmation, r.opts.WriteTimeout); err != nil {
			r.releaseHandshake(nc)
			r.closeSocket(nc)
			return
		}
		// Both gate frames are done; clear the deadlines so the reader and
		// writer arm their own per-frame ones.
		if err := nc.SetReadDeadline(time.Time{}); err != nil {
			r.releaseHandshake(nc)
			r.closeSocket(nc)
			return
		}
		if err := nc.SetWriteDeadline(time.Time{}); err != nil {
			r.releaseHandshake(nc)
			r.closeSocket(nc)
			return
		}
	}
	if err := r.admit(nc, group); err != nil {
		// The only refusal admit can still return is a shutdown: the two
		// bounds were applied at accept, before the handshake could block.
		// admit has already released the reservation on that path.
		if !errors.Is(err, ErrClosed) {
			r.refused.Add(1)
		}
		r.closeSocket(nc)
	}
}

// gateRefusalLogInterval is the floor between two gate-refusal lines. The
// refusal path is reachable by anyone who can open a socket, so this line is
// rate-limited instead of per-connection: a flood must not turn the operator's
// log into the flood. Suppressed refusals are counted and named on the next
// emitted line, so a quiet log still reports a rising rate.
const gateRefusalLogInterval = time.Second

// logGateRefusal writes one bounded, rate-limited line saying WHY a socket was
// refused at the gate. Before it existed the gate only incremented
// `unauthorized`, and that silence is why the 2026-11-14 outage
// (docs/bug-2026-11-14-relay-gate.md) took eight wrong diagnoses: every counter
// reading was compatible with every hypothesis.
//
// Nothing here decodes the frame - it is quoted, not interpreted, and the read
// that produced it was bounded to the MAC's own width, so the longest frame
// this can print is 32 bytes. The two shapes worth naming are the ones that
// actually occur:
//
//   - a SHORT first frame. On this wire a 2-byte opening frame is a node's
//     transport ID ("v0", "v1", ...), which means the dialer has no access
//     token and its relay path announced its identity instead of answering the
//     challenge. That is the 2026-11-14 outage exactly, and it is an operator
//     configuration error on the DIALER, not on this relay.
//   - a right-sized MAC that did not compare. A wrong token, or a proof minted
//     for another connection's challenge.
func (r *Relay) logGateRefusal(remote net.Addr, frame []byte, err error) {
	r.refusalMu.Lock()
	now := time.Now()
	if !r.refusalLast.IsZero() && now.Sub(r.refusalLast) < gateRefusalLogInterval {
		r.refusalSuppressed++
		r.refusalMu.Unlock()
		return
	}
	suppressed := r.refusalSuppressed
	r.refusalSuppressed = 0
	r.refusalLast = now
	r.refusalMu.Unlock()

	var why string
	switch {
	case err != nil:
		// Two shapes: a dialer that said nothing until the deadline, and one
		// whose first frame could not even be a proof (a consensus frame from a
		// link that never ran the gate, or an oversized declaration). Neither
		// ever sends a proof, and a node without an access token never can.
		if te, ok := err.(net.Error); ok && te.Timeout() {
			why = fmt.Sprintf("no %d-byte gate proof arrived within --access-timeout; a dialer with no access token never sends one", wire.RelayGateMACBytes)
		} else {
			why = fmt.Sprintf("the first frame is not a %d-byte gate proof (%v); a dialer with no access token cannot send one, so this is whatever its link wrote first", wire.RelayGateMACBytes, err)
		}
	case len(frame) < wire.RelayGateMACBytes:
		why = fmt.Sprintf("frameLen=%d wantLen=%d frame=%q; a frame this short is a transport ID, so the dialer has NO access token configured (--relay-access-token-file) and announced its identity instead of a proof", len(frame), wire.RelayGateMACBytes, frame)
	default:
		why = fmt.Sprintf("frameLen=%d wantLen=%d; the proof did not match this connection's challenge (a wrong token, or a proof minted for another connection)", len(frame), wire.RelayGateMACBytes)
	}
	if suppressed > 0 {
		log.Printf("b10coin-relay: gate refused %s: %s (and %d more since the last line)", remote, why, suppressed)
		return
	}
	log.Printf("b10coin-relay: gate refused %s: %s", remote, why)
}

// writeGateFrame writes one gate frame under a write deadline, so a peer that
// has stopped reading cannot park the handshake goroutine on a 20-byte write.
// The greeting is a constant; the challenge is 32 random bytes the relay
// generated plus its own local address; the confirmation is an HMAC over bytes
// the relay already holds. None of them contains a token byte or anything a
// peer sent, and nothing on the other side requires decoding them. The deadline
// is cleared by the caller once the gate is done, because the connection's
// reader and writer arm their own.
func writeGateFrame(nc net.Conn, frame []byte, timeout time.Duration) error {
	if err := nc.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	return wire.WriteFrame(nc, frame)
}

// admit converts an accepted socket whose accept-time slot is ALREADY
// RESERVED (r.handshaking + r.perGroup, taken by acceptLoop under
// acceptCapLocked) into a registered connection with its two goroutines. The
// reservation becomes the registration in one critical section: the
// handshaking entry is deleted and the conn takes its place in r.conns, so the
// sum the caps count never dips and never doubles. On a shutdown the
// reservation is released instead, so a Close racing this admit leaves no
// slot behind. The registration stays under the same lock Close's snapshot
// takes, so a Close racing an accept either sees the connection (and finishes
// it) or finds the closed flag up and closes the raw socket itself.
func (r *Relay) admit(nc net.Conn, group string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed.Load() {
		if g, ok := r.handshaking[nc]; ok {
			delete(r.handshaking, nc)
			r.decGroupLocked(g)
		}
		return ErrClosed
	}
	delete(r.handshaking, nc) // the reservation is now the registration
	c := &conn{
		nc:       nc,
		q:        newSendQ(r.opts.WriteQueueBytes, r.opts.MaxFrameBytes, r.opts.WriteQueueFrames),
		dead:     make(chan struct{}),
		srcGroup: group,
	}
	// A connection is FRESH at admit: the reader's first deadline starts now,
	// so "no frame yet" must not read as "silent since the epoch".
	c.lastFrame.Store(time.Now().UnixNano())
	r.conns[c] = struct{}{}
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
	// A panic in ONE connection's read path closes that connection and keeps
	// the relay serving everyone else (audit S-9): the relay is the shared
	// link every validator behind it depends on, so losing the process to one
	// stranger's bytes is the worst outcome available. The reader owns only
	// its own socket and framing buffer; the registry is reached under r.mu
	// (finish and forward each hold it for the whole operation they need), and
	// a panic mid-fan-out costs the remaining targets one frame - a DROPPED
	// frame, which is an outcome this relay already permits - not an
	// inconsistent registry. A relay that parsed would have a decoder to blame
	// here; this one has none, so the line names the connection and the panic
	// and the count makes it testable.
	defer func() {
		if p := recover(); p != nil {
			r.readerPanics.Add(1)
			log.Printf("b10coin: relay: recovered a panic in the read loop of %s (connection closed, relay kept running - audit S-9): %v\n%s",
				c.nc.RemoteAddr(), p, debug.Stack())
		}
	}()
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
		// The one observation the reader publishes: this connection delivered
		// a COMPLETE frame now. Stored before the fan-out so a slow fan-out
		// never makes a reading connection look silent.
		c.lastFrame.Store(time.Now().UnixNano())
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
// lock alongside the target snapshot, and the enqueue happens UNDER that same
// lock, so the selection and the admission are atomic with finish's registry
// delete (audit N-14) - a connection is enqueued for only while it is in the
// registry, and finish removes it before closing dead. push never blocks, so
// holding the lock across the fan-out costs no wait on a peer. A receiver that
// is the only member of its own account is not one of its senders, so its
// account is not counted; a receiver with a sibling in its account (another
// connection from the same host) IS contended by that sibling and counts it.
// The count is connection identities, never payload: the relay still parses
// nothing.
func (r *Relay) forward(sender *conn, payload []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	accounts := make(map[shareAccount]int, len(r.conns))
	for c := range r.conns {
		accounts[shareAccountOf(c)]++
	}
	for c := range r.conns {
		if c == sender {
			continue
		}
		// Unreachable while finish deletes the registry entry under this same
		// lock, but retained as the gate the "no frame is counted for a
		// torn-down connection" invariant is READ through (audit N-14), the
		// way the transport's Send keeps its dead check: a corpse must never
		// inflate Forwarded, whatever a future edit does to finish's order.
		select {
		case <-c.dead:
			continue
		default:
		}
		ok, rej := c.q.tryPush(sender, payload, sendersFor(c, accounts))
		if ok {
			r.forwarded.Add(1)
			continue
		}
		r.recordDrop(c, rej)
	}
}

// recordDrop accounts one frame that push REFUSED: it is a dropped frame, not
// a forwarded one, and it is charged to the bound that refused it. Before this,
// a refusal was a bare boolean and the relay could not say which limit shed a
// frame; "forwarded climbs, dropped=0" was the shape of a silent loss.
//
// The line is deliberately about the QUEUE, not the payload: reason, the
// frame's payload length, the queue's byte/entry state and the sender
// account's allowance. The relay still parses nothing - a length is the same
// observation the byte budget already makes.
func (r *Relay) recordDrop(target *conn, rej pushRejection) {
	r.dropped.Add(1)
	switch rej.reason {
	case rejectSenderShare:
		r.droppedShare.Add(1)
	case rejectByteBudget:
		r.droppedBytes.Add(1)
	case rejectFrameCount:
		r.droppedFrame.Add(1)
	case rejectReservedLane:
		r.droppedLane.Add(1)
	case rejectConnClosed:
		r.droppedClose.Add(1)
	case rejectReap:
		r.droppedReap.Add(1)
	case rejectOther:
		r.droppedOther.Add(1)
	}

	where := "a hand-built connection"
	if target.nc != nil {
		where = target.nc.RemoteAddr().String()
	}
	r.dropLine(fmt.Sprintf("b10coin: relay: DROPPED a %d-byte frame for %s: refused by the %s (queue %d/%d bytes, allowance %d)",
		rej.size, where, rej.reason, rej.queued, rej.limit, rej.allow))
}

// recordInHandDrop accounts the single frame the writer had already POPPED when
// the connection ended under it. sendQ.abandon can only count what is still in
// the queue, and pop removed this frame, so without this the one frame in the
// writer's hand would be the frame every teardown loses silently. The queue
// reading is taken here (not from the refusal path) so the line says what the
// queue still held when the frame was charged.
func (r *Relay) recordInHandDrop(target *conn, n int, reason rejectReason) {
	r.recordDrop(target, pushRejection{
		reason: reason,
		size:   n,
		queued: target.q.queued(),
		limit:  target.q.limit,
	})
}

// dropLine writes one drop/teardown line, at most one per second: the moment
// the message is most useful (a receiver that stopped draining, or a churn of
// reset dials) is also the moment an unthrottled line would flood the journal.
// The COUNTERS are never throttled - only the line - so the suppressed count
// stays exact and the summary says how many lines were folded into this one.
func (r *Relay) dropLine(msg string) {
	r.dropMu.Lock()
	now := time.Now()
	if !r.dropLast.IsZero() && now.Sub(r.dropLast) < time.Second {
		r.dropSuppressed++
		r.dropMu.Unlock()
		return
	}
	suppressed := r.dropSuppressed
	r.dropSuppressed = 0
	r.dropLast = now
	r.dropMu.Unlock()
	if suppressed > 0 {
		msg += fmt.Sprintf(" (%d more drop lines suppressed in the last second)", suppressed)
	}
	log.Print(msg)
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
//
// The expiry alone is not grounds to end the connection (audit F3): it is read
// through receiverStalled, which asks whether the backlog is the RECEIVER's
// (nothing has arrived for a whole WriteTimeout and the queue still will not
// clear) or a SENDER's (frames keep arriving, and only the byte budget and the
// per-sender share can answer that). A sender-caused backlog must not cost the
// receiver its link; the write that follows is then bounded by a fresh
// deadline of its own, so a receiver that genuinely stops reading mid-frame is
// still ended by the timeout on that write. The relay still parses nothing:
// both questions are timestamps on an already-queued frame.
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
				if c.q.receiverStalled(r.opts.WriteTimeout) {
					// The backlog has failed to clear within WriteTimeout of
					// its arrival AND nothing new has arrived within that
					// window: the receiver is the one not keeping up, however
					// steadily it trickled. End it through the REAP teardown,
					// which abandons the queue and counts every frame it holds
					// (DroppedReap): this is the live stall's path, and it must
					// never discard a backlog silently.
					r.finishReaped(c)
					return
				}
				f, ok := c.q.pop()
				if !ok {
					break
				}
				writeDeadline := deadline
				if !time.Now().Before(deadline) {
					// The queue has been non-empty past WriteTimeout, but
					// frames are still arriving: the backlog belongs to a
					// SENDER (audit F3), so the receiver must not pay for it
					// with its link. Bound THIS write instead of the queue.
					writeDeadline = time.Now().Add(r.opts.WriteTimeout)
				}
				if err := c.nc.SetWriteDeadline(writeDeadline); err != nil {
					// The socket is already going away, but the frame in hand
					// was POPPED, so abandon cannot see it: charge it here or
					// this exit loses exactly one frame silently. Every exit
					// that abandons frames counts them.
					r.recordInHandDrop(c, len(f.b), rejectConnClosed)
					r.finish(c)
					return
				}
				if err := wire.WriteFrame(c.nc, f.b); err != nil {
					// Socket failure, or the write deadline expiring on a peer
					// that has stopped reading. The frame in hand is not in the
					// queue (pop took it), so it is accounted HERE whatever the
					// ending: a frame that was admitted and not written is a
					// Dropped frame, never a silent one. A deadline expiry is
					// the reaper's decision, so it is attributed to the reap
					// (and the rest of the queue to the same reason); any other
					// socket failure is an ordinary close.
					reason := rejectConnClosed
					reaped := false
					if ne, ok := err.(net.Error); ok && ne.Timeout() {
						reason, reaped = rejectReap, true
					}
					r.recordInHandDrop(c, len(f.b), reason)
					if reaped {
						r.finishReaped(c)
					} else {
						r.finish(c)
					}
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
			r.closeSocket(nc)
		}
		for _, c := range conns {
			r.finish(c)
		}
		r.wg.Wait()
	})
}
