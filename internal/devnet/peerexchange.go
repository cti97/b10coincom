package devnet

// PEER_EXCHANGE at the node layer: the dial policy, and the three bounds that
// keep the mesh from becoming an amplifier.
//
// The wire layer (internal/wire/peerexchange.go) frames a list of strings; it
// validates none of them. Everything a hostile list can DO is decided here,
// where the node knows its own listener, its own committee and its own dial
// path. Design decision 5 is the frame's meaning: an advertised address is a
// HINT TO DIAL, never a peer, never a vote and never evidence about the chain.
// The only admission path stays admitHello - chain id, a committee seat at the
// announced height, and a signature over the HELLO hash - and the only dial
// path stays tcp.TcpTransport.AddPeer, with its one-maintainer-per-address,
// jittered backoff and rank rules untouched.
//
// # Why a hint is not operator intent
//
// An operator names its own network with --peers; a peer may not. So a hint
// must be a literal IP:port (a hostname would move the target after the check,
// via DNS), a real port, not the node's own listener, not the reserved
// relay:<addr> name, and - unless this is a devnet that says so explicitly -
// not loopback, private, link-local or unspecified. Refusing the local ranges
// is what stops a compromised member from aiming a validator at the operator's
// LAN or at the node itself; an operator can still do that deliberately.
//
// # The bounds, and why an honest peer is not starved
//
//   - LIST: at most wire.MaxPeerExchangeAddrs (8) addresses per frame, each at
//     most wire.MaxListenAddrBytes (255), enforced by the decoder before a
//     slice is grown.
//   - SEND RATE: at most one PEER_EXCHANGE per peerExchangeEveryWaves (4)
//     waves, i.e. one frame per 2 s at the default 500 ms wave. A node
//     advertises only its own listener, so the traffic is O(peers) tiny frames
//     per 2 s - a constant, not a function of how much the node receives.
//   - ADMISSION RATE: at most maxNewPeerHintsPerWave (8) NEW addresses are
//     adopted node-wide per wave, whatever the source, and at most
//     maxLearnedPeerAddrs (32) are ever dialled from hints over the process's
//     life. The lifetime budget is 32 = the 21-seat committee's 20 other
//     members + slack; configured peers are never counted or displaced.
//
// The receive path cannot starve an honest peer: it does O(8) bounded string
// parses and map lookups, calls a non-blocking AddPeer, and never blocks or
// dials inline, so no frame is delayed behind it. The dial budget can be spent
// by an already-admitted member, and when it is, the node loses direct links
// (the mesh) - it does NOT lose admission, the relay link, or consensus,
// because those never depend on a hint. A duplicate address consumes no
// budget, so repeats are free to ignore and costly to nobody.
//
// The authority for a hint is the connection, but NOT every connection: only
// one that has carried a signed, committee-checked HELLO (attestedConnection).
// A dialled connection is admitted by the transport at install - the node
// chose to dial it - so without this gate a stranger reached at a hinted
// address could advertise further addresses and grow the dial set itself. It
// cannot vote (the router's membership check refuses its key), and with this
// gate it cannot advertise either.

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"

	"github.com/cti97/b10coincom/internal/transport"
	"github.com/cti97/b10coincom/internal/wire"
)

const (
	// peerExchangeEveryWaves is the send bound: one advertisement every fourth
	// wave. It is a rate, not a correctness parameter - the mesh is an
	// optimization and a late advertisement only delays a direct link - and it
	// is what keeps the message from being a per-frame amplifier.
	peerExchangeEveryWaves = 4
	// maxNewPeerHintsPerWave bounds how many NEW addresses one wave may turn
	// into dials, however many frames or sources arrive in it. One frame can
	// therefore never spend a large share of the lifetime budget, and a frame
	// flood adds work proportional to the transport's existing frame bound,
	// not dials.
	maxNewPeerHintsPerWave = 8
	// maxLearnedPeerAddrs bounds the addresses this node will ever DIAL because
	// a peer advertised them. 32 covers the 21-seat committee's 20 other
	// members with slack, and - unlike a concurrent cap - it needs no way to
	// cancel a maintainer, because a dialed address's maintainer lives until
	// Close by design (audit N-1). Operator-configured peers are outside it.
	maxLearnedPeerAddrs = 32
)

// Hint-refusal reasons. They are distinct so a test can name WHY an address
// was refused rather than only that the dial counter did not move.
var (
	errHintReservedName = errors.New("devnet: a peer hint may not use the reserved relay:<addr> name")
	errHintNotIPPort    = errors.New("devnet: a peer hint must be a literal IP:port")
	errHintPortZero     = errors.New("devnet: a peer hint's port must be 1..65535")
	errHintUnspecified  = errors.New("devnet: a peer hint may not name an unspecified address")
	errHintSelf         = errors.New("devnet: a peer hint may not name this node's own listen address")
	errHintMulticast    = errors.New("devnet: a peer hint may not name a multicast address")
	errHintLocal        = errors.New("devnet: a peer hint may not name a loopback, private or link-local address")
)

// validatePeerHint turns one advertised string into the address this node may
// dial, or names why it may not. own is the node's own listen address ("" when
// it does not listen); allowLocal is the devnet acceptance exception described
// on ValidatorConfig.
//
// The returned AddrPort is canonical: the address is Unmap()ed (so ::ffff:127.0.0.1
// is judged as the IPv4 address it is) and the port is preserved. The caller
// dials its String().
func validatePeerHint(raw, own string, allowLocal bool) (netip.AddrPort, error) {
	if len(raw) == 0 || len(raw) > wire.MaxListenAddrBytes {
		// The decoder already bounded this; the check is here because a policy
		// function must not trust its caller's bounds.
		return netip.AddrPort{}, errHintNotIPPort
	}
	// The relay name is reserved for the transport's own outbound registration
	// (audit N-1). A hint is never allowed to name it, whether or not the rest
	// would parse: refusing it explicitly is the policy, not an accident of
	// name resolution.
	if strings.HasPrefix(raw, "relay:") {
		return netip.AddrPort{}, errHintReservedName
	}
	// A literal IP:port and nothing else. ParseAddrPort refuses a hostname, an
	// empty host, a missing port and a port above 65535; that is what keeps the
	// target from moving after this check.
	ap, err := netip.ParseAddrPort(raw)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("%w: %q", errHintNotIPPort, raw)
	}
	if ap.Port() == 0 {
		return netip.AddrPort{}, errHintPortZero
	}
	ip := ap.Addr().Unmap()
	if ip.IsUnspecified() {
		return netip.AddrPort{}, errHintUnspecified
	}
	if own != "" {
		if ownAP, err := netip.ParseAddrPort(own); err == nil {
			ownIP := ownAP.Addr().Unmap()
			if ip == ownIP && ap.Port() == ownAP.Port() {
				return netip.AddrPort{}, errHintSelf
			}
		}
	}
	// Multicast is never a unicast endpoint, so it is refused even in the
	// devnet exception.
	if ip.IsMulticast() {
		return netip.AddrPort{}, errHintMulticast
	}
	if !allowLocal && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast()) {
		return netip.AddrPort{}, errHintLocal
	}
	return netip.AddrPortFrom(ip, ap.Port()), nil
}

// peerHints is the learned-address bookkeeping. It is guarded by its own mutex
// because the receive path runs on the transport's dispatch goroutine while
// the wave loop sends; neither holds the driver mutex.
type peerHints struct {
	mu sync.Mutex
	// learned is keyed by the canonical address string and bounded by
	// maxLearnedPeerAddrs: every entry in it is an address this node called
	// AddPeer for, so the map's size is the dial bound made visible.
	learned map[string]struct{}
	// wave and admitted are the per-wave adoption window
	// (maxNewPeerHintsPerWave). admitted resets when the wave advances.
	wave     uint64
	admitted int
}

// advertisableAddr is what this node may put in a PEER_EXCHANGE: its own
// listener, when it has one at a CONCRETE address. An unspecified listener
// (0.0.0.0, [::]) means "every interface" and names no reachable endpoint, so
// advertising it would only send peers a dial that cannot complete; behind NAT
// a node listens on nothing and advertises nothing, exactly as §6.6's staged
// strategy expects. The address is canonicalised the same way hints are, so
// the self-check compares like with like.
func (v *Validator) advertisableAddr() string {
	a := v.ttp.Addr()
	if a == nil {
		return ""
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return ""
	}
	ip := ap.Addr().Unmap()
	if ip.IsUnspecified() || ap.Port() == 0 {
		return ""
	}
	return netip.AddrPortFrom(ip, ap.Port()).String()
}

// attestedConnection reports whether from has carried a signed committee HELLO
// recently enough to be authoritative for a hint. On a relay every member's
// HELLO arrives under the one relay:<addr> name, so the relay connection is
// attested by any member's HELLO - which is exactly the authority the message
// claims. A stranger this node dialled at a hinted address has no HELLO and
// therefore cannot advertise further.
func (v *Validator) attestedConnection(from transport.PeerID) bool {
	v.peerHMu.Lock()
	defer v.peerHMu.Unlock()
	for _, st := range v.peerH {
		if st.via == from && st.seen+peerHeightTTL >= v.wave {
			return true
		}
	}
	return false
}

// sendPeerExchange advertises this node's listening address, if it has one.
// It is called from the wave loop at the peerExchangeEveryWaves cadence; the
// test seam calls it directly to construct a wave instead of waiting.
func (v *Validator) sendPeerExchange() {
	addr := v.advertisableAddr()
	if addr == "" {
		return
	}
	frame := wire.EncodePeerExchange(&wire.PeerExchange{Addrs: []string{addr}})
	if err := v.ttp.Broadcast(frame); err != nil {
		return
	}
	v.hintsSent.Add(1)
}

// observePeerExchange is the router's OnPeerExchange callback: it never blocks,
// never dials inline, and never touches the engine. Every bound it applies is
// a fixed number, and every refusal is counted rather than logged (the
// transport's dispatch goroutine must not do I/O).
func (v *Validator) observePeerExchange(from transport.PeerID, p *wire.PeerExchange) {
	if p == nil || v.closing.Load() {
		return
	}
	v.hintsSeen.Add(1)
	if !v.attestedConnection(from) {
		v.hintsRefused.Add(1)
		return
	}
	own := v.advertisableAddr()
	wave := v.currentWave()

	b := &v.hints
	b.mu.Lock()
	defer b.mu.Unlock()
	if wave != b.wave {
		b.wave = wave
		b.admitted = 0
	}
	for _, raw := range p.Addrs {
		ap, err := validatePeerHint(raw, own, v.cfg.AllowLocalPeerHints)
		if err != nil {
			v.hintsRefused.Add(1)
			continue
		}
		key := ap.String()
		if _, ok := b.learned[key]; ok {
			// Already known: no dial, no budget. A peer re-advertising the same
			// address forever costs one map lookup per entry.
			v.hintsDuplicates.Add(1)
			continue
		}
		if b.admitted >= maxNewPeerHintsPerWave {
			v.hintsRefused.Add(1)
			continue
		}
		if len(b.learned) >= maxLearnedPeerAddrs {
			v.hintsOverBudget.Add(1)
			continue
		}
		// The ONE dial path (design decision 5): the same maintainer --peers
		// uses, one per address, backoff and retry forever, refusal to admit
		// untouched. A learned address that is down costs a retrying maintainer,
		// not a permanent exit (audit N-1).
		if err := v.peerAdd(key); err != nil {
			v.hintsRefused.Add(1)
			continue
		}
		b.learned[key] = struct{}{}
		b.admitted++
		v.hintsAdopted.Add(1)
	}
}

// currentWave reads the wave counter the receive path measures its per-wave
// window in.
func (v *Validator) currentWave() uint64 {
	v.peerHMu.Lock()
	defer v.peerHMu.Unlock()
	return v.wave
}

// PeerHintsSeen reports how many PEER_EXCHANGE frames reached the node's dial
// policy, attested or not. It is a mesh-formation observable, never a liveness
// one.
func (v *Validator) PeerHintsSeen() uint64 { return v.hintsSeen.Load() }

// PeerHintsAdopted reports how many advertised addresses this node turned into
// dials. It is a mesh-formation observable, never a liveness one.
func (v *Validator) PeerHintsAdopted() uint64 { return v.hintsAdopted.Load() }

// PeerHintsRefused reports how many advertised addresses this node refused:
// unparseable, local, its own, reserved, from an unattested connection, or over
// a per-wave budget.
func (v *Validator) PeerHintsRefused() uint64 { return v.hintsRefused.Load() }

// PeerHintsDuplicates reports how many advertised addresses were already
// learned. A duplicate causes no dial and consumes no budget.
func (v *Validator) PeerHintsDuplicates() uint64 { return v.hintsDuplicates.Load() }

// PeerHintsOverBudget reports how many otherwise-valid hints were refused
// because the lifetime dial budget (maxLearnedPeerAddrs) was already spent.
func (v *Validator) PeerHintsOverBudget() uint64 { return v.hintsOverBudget.Load() }

// PeerExchangesSent reports how many PEER_EXCHANGE frames this node broadcast.
func (v *Validator) PeerExchangesSent() uint64 { return v.hintsSent.Load() }

// LearnedPeerAddrs reports how many distinct addresses this node has dialled
// from hints: the lifetime budget made observable.
func (v *Validator) LearnedPeerAddrs() int {
	v.hints.mu.Lock()
	defer v.hints.mu.Unlock()
	return len(v.hints.learned)
}
