package devnet

// PEER_EXCHANGE at the node layer: the signed-frame authority, the dial policy,
// and the bounds that keep the mesh from becoming an amplifier.
//
// The wire layer (internal/wire/peerexchange.go) frames a signed list of
// strings; it validates none of them. Everything a hostile list can DO is
// decided here, where the node knows its own listener, its own committee and
// its own dial path. Design decision 5 is the frame's meaning: an advertised
// address is a HINT TO DIAL, never a peer, never a vote and never evidence
// about the chain. The only admission path stays admitHello - chain id, a
// committee seat at the announced height, and a signature over the HELLO hash -
// and the only dial path stays tcp.TcpTransport.AddPeer, with its
// one-maintainer-per-address, jittered backoff and rank rules.
//
// # Why a hint is not operator intent
//
// An operator names its own network with --peers; a peer may not. So a hint
// must be a literal IP:port (a hostname would move the target after the check,
// via DNS), a real port, not the node's own listener, not the reserved
// relay:<addr> name, not the ADDRESS of the relay this node dials (compared
// parsed and canonical: the outbound registry is keyed by the literal string,
// so a different spelling of one endpoint used to open a second, direct-mode
// connection to the relay - audit PX-6), and - unless this is a devnet that says
// so explicitly - not a local-only address. Refusing the local ranges is what
// stops a compromised member from aiming a validator at the operator's LAN or
// at the node itself; an operator can still do that deliberately.
//
// "Local-only" is wider than the standard library's predicates (audit PX-7):
// loopback, RFC 1918 private, link-local, CGNAT 100.64/10, 0.0.0.0/8,
// 192.0.0.0/24, 198.18/15, 240.0.0.0/4 (which contains the broadcast address),
// IPv6 site-local fec0::/10, and a NAT64 address whose embedded IPv4 is any of
// those. Every address is canonicalised (v4-mapped unmapped, zone dropped)
// BEFORE it is charged a budget slot, so one target is one slot however it is
// spelled. The zone is dropped rather than refused because it names an
// interface on the sender's machine and can mean nothing here; the address is
// still judged by its ranges, so a zone cannot smuggle a local address past the
// filter.
//
// # The authority is the SIGNATURE, never the connection (audit PX-1)
//
// The earlier design took the authority for a hint from the CONNECTION it
// arrived on: a connection that had carried a signed committee HELLO was
// "attested", and any attested connection could advertise. On the relay that
// was every relay sender, because every member's HELLO arrives under the one
// relay:<addr> name - and a token-less relay admits strangers, so a stranger
// with a frame was a hint authority. One frame of eight public addresses made
// every validator open eight maintainers that retried forever, and four waves
// filled the 32-address lifetime budget, poisoning the mesh until restart.
//
// The frame now carries the advertising member's key, the height it advertises
// at, and a signature over (chain id, height, address list); observePeerExchange
// verifies the signature and requires the key to hold a seat at that height
// (committeeMemberAt, the same union HELLO admission uses). A relay can forward
// the bytes but cannot forge the signature, so on the relay the authority is
// exactly the member that signed - which is what the message always claimed. A
// captured frame replayed by a stranger is a hint the member itself sent, so a
// replay buys no new authority.
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
//     adopted PER ADVERTISING MEMBER per wave. The unit is the SIGNED KEY, not
//     the connection and not the node: on the relay every member shares one
//     connection, and a node-wide window let one member spend the allowance
//     the others needed (audit PX-1). Per key, one member's flood cannot deny
//     another's advertisement. At most maxLearnedPeerAddrs (32) are ever
//     dialled from hints at once; the lifetime budget is 32 = the 21-seat
//     committee's 20 other members + slack. Configured peers are never counted
//     or displaced.
//   - EVICTION: a learned address whose handshake never completes is retired
//     after hintHandshakeGraceWaves (8) waves - removed from the book, which
//     returns its slot to the lifetime budget, and its maintainer is cancelled
//     (tcp.TcpTransport.RemovePeer), which stops the redials. An address that
//     has EVER produced a signed committee HELLO is proven and never evicted,
//     so a peer that blips keeps its maintainer and the N-1 "a failed dial is
//     an ordinary failure" rule still holds for real peers.
//
// The receive path cannot starve an honest peer: it does O(8) bounded string
// parses and map lookups, one signature verification and a non-blocking
// AddPeer, and never blocks or dials inline, so no frame is delayed behind it.
// The dial budget can be spent by a seated member, and when it is, the node
// loses direct links (the mesh) - it does NOT lose admission, the relay link,
// or consensus, because those never depend on a hint. A duplicate address
// consumes no budget, so repeats are free to ignore and costly to nobody.

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"strings"
	"sync"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/transport"
	"github.com/cti97/b10coincom/internal/types"
	"github.com/cti97/b10coincom/internal/wire"
)

const (
	// peerExchangeEveryWaves is the send bound: one advertisement every fourth
	// wave. It is a rate, not a correctness parameter - the mesh is an
	// optimization and a late advertisement only delays a direct link - and it
	// is what keeps the message from being a per-frame amplifier.
	peerExchangeEveryWaves = 4
	// maxNewPeerHintsPerWave bounds how many NEW addresses ONE advertising
	// member may turn into dials in one wave, however many frames it sends.
	// One frame can therefore never spend a large share of the lifetime
	// budget, and a member's flood cannot spend another member's allowance:
	// the window is keyed by the signed key (audit PX-1), because on the relay
	// every member shares one connection.
	maxNewPeerHintsPerWave = 8
	// maxLearnedPeerAddrs bounds how many addresses this node will ever DIAL
	// at once because a peer advertised them. 32 covers the 21-seat
	// committee's 20 other members with slack. Unlike the per-member window it
	// is a NODE-WIDE total: it is the amplification bound, not a fairness one.
	// An address that never completes a handshake is evicted (see
	// hintHandshakeGraceWaves), so the total is not "for the process's life" -
	// it is the number of learned addresses the node keeps at any moment.
	maxLearnedPeerAddrs = 32
	// hintHandshakeGraceWaves is how long a learned address may go without
	// producing a signed committee HELLO before it is evicted: 4 s at the
	// default wave, i.e. several redials of the maintainer's backoff curve. It
	// is the bound that makes an attacker's addresses cost a few dials instead
	// of a permanent slot (audit PX-1); an address that HAS completed a
	// handshake is proven and is never evicted.
	hintHandshakeGraceWaves = 8
)

// Hint-refusal reasons. They are distinct so a test can name WHY an address
// was refused rather than only that the dial counter did not move.
var (
	errHintReservedName = errors.New("devnet: a peer hint may not use the reserved relay:<addr> name")
	errHintReservedAddr = errors.New("devnet: a peer hint may not name the relay this node dials, or this node's own advertised address")
	errHintNotIPPort    = errors.New("devnet: a peer hint must be a literal IP:port")
	errHintPortZero     = errors.New("devnet: a peer hint's port must be 1..65535")
	errHintUnspecified  = errors.New("devnet: a peer hint may not name an unspecified address")
	errHintSelf         = errors.New("devnet: a peer hint may not name this node's own listen address")
	errHintMulticast    = errors.New("devnet: a peer hint may not name a multicast address")
	errHintLocal        = errors.New("devnet: a peer hint may not name a loopback, private or link-local address")
)

// Local-only IPv4/IPv6 ranges that the standard library's predicates do not
// cover. IsPrivate is RFC 1918 only, IsLoopback and IsLinkLocalUnicast are
// their own small sets, and everything here is still "not a peer this node
// may dial" (audit PX-7). The broadcast address is inside 240/4, so it needs
// no entry of its own.
var (
	hintLocalV4 = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),     // "this network" (RFC 1122): only 0.0.0.0 is unspecified
		netip.MustParsePrefix("100.64.0.0/10"), // CGNAT (RFC 6598) - the home-node deployment's own range
		netip.MustParsePrefix("192.0.0.0/24"),  // IETF protocol assignments (RFC 6890)
		netip.MustParsePrefix("198.18.0.0/15"), // benchmarking (RFC 2544)
		netip.MustParsePrefix("240.0.0.0/4"),   // reserved, including 255.255.255.255
	}
	hintLocalV6 = []netip.Prefix{
		netip.MustParsePrefix("fec0::/10"), // site-local (RFC 3879, deprecated but still address space)
	}
	// nat64WellKnown embeds an IPv4 address in its low 32 bits (RFC 6052). A
	// peer addressed as 64:ff9b::7f00:1 is 127.0.0.1, so the embedded address
	// gets the same local-range judgement as a literal IPv4 one.
	nat64WellKnown = netip.MustParsePrefix("64:ff9b::/96")
)

// isLocalHintAddr reports whether ip is a target the default policy refuses:
// loopback, private, link-local, or any of the ranges above. It is consulted
// only when local hints are NOT allowed, after the unspecified and multicast
// refusals (which are their own reasons and apply even then). A NAT64 address
// is judged by the IPv4 address in its low 32 bits, so 64:ff9b::7f00:1 counts as
// loopback.
func isLocalHintAddr(ip netip.Addr) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() {
		return true
	}
	if ip.Is4() {
		for _, p := range hintLocalV4 {
			if p.Contains(ip) {
				return true
			}
		}
		return false
	}
	for _, p := range hintLocalV6 {
		if p.Contains(ip) {
			return true
		}
	}
	if nat64WellKnown.Contains(ip) {
		b := ip.As16()
		return isLocalHintAddr(netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}))
	}
	return false
}

// canonicalHintAddr is the one spelling of an address that the hint book, the
// dial path and the reserved-address comparison all use: the IPv4 form when the
// address is v4-mapped, and NO ZONE.
//
// The zone is dropped, not refused (audit PX-7). A zone names an interface on
// the SENDER's machine ("%en0", "%25eth0"), so it can never be meaningful to
// the receiver; keeping it would make one endpoint look like a fresh target
// per spelling and spend one lifetime-budget slot each. Dropping it is what
// makes one target cost one slot. The address itself is still judged by its
// ranges, so a zone cannot smuggle a link-local address past the filter.
func canonicalHintAddr(ip netip.Addr) netip.Addr {
	return ip.Unmap().WithZone("")
}

// validatePeerHint turns one advertised string into the address this node may
// dial, or names why it may not. own is the node's own listen address ("" when
// it does not listen); reserved holds addresses a hint may never name - the
// relays this node dials and the address it advertises (see
// Validator.hintReservedAddrs); allowLocal is the devnet acceptance exception
// described on ValidatorConfig.
//
// The returned AddrPort is canonical (canonicalHintAddr) and the port is
// preserved. The caller dials its String().
func validatePeerHint(raw, own string, reserved []netip.AddrPort, allowLocal bool) (netip.AddrPort, error) {
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
	ip := canonicalHintAddr(ap.Addr())
	if ip.IsUnspecified() {
		return netip.AddrPort{}, errHintUnspecified
	}
	if own != "" {
		if ownAP, err := netip.ParseAddrPort(own); err == nil {
			ownIP := canonicalHintAddr(ownAP.Addr())
			if ip == ownIP && ap.Port() == ownAP.Port() {
				return netip.AddrPort{}, errHintSelf
			}
		}
	}
	// The configured relay's own address is reserved as well as its name
	// (audit PX-6). The outbound registry is keyed by the literal address
	// string, so a hint that spells the same endpoint differently (a v4-mapped
	// form, a different zone, a padded port) used to open a SECOND connection
	// to the relay - in direct mode, so on a gated relay it is refused forever
	// and redialled forever. Comparing PARSED, canonical addresses rather than
	// strings is what closes that: the two spellings are the same endpoint.
	// A relay configured by hostname cannot be compared without resolving it
	// (and resolving a target on the dial path is what the literal-IP rule
	// exists to prevent); such an address is still covered by its relay:<addr>
	// name, and the deploy recipe uses literals.
	for _, r := range reserved {
		if ip == canonicalHintAddr(r.Addr()) && ap.Port() == r.Port() {
			return netip.AddrPort{}, errHintReservedAddr
		}
	}
	// Multicast is never a unicast endpoint, so it is refused even in the
	// devnet exception.
	if ip.IsMulticast() {
		return netip.AddrPort{}, errHintMulticast
	}
	if !allowLocal && isLocalHintAddr(ip) {
		return netip.AddrPort{}, errHintLocal
	}
	return netip.AddrPortFrom(ip, ap.Port()), nil
}

// learnedHint is one address this node dialled because a member advertised it.
// since is the wave it was learned in (the eviction clock); proven records
// that a signed committee HELLO has arrived on a connection to that address,
// which makes it a peer the node keeps dialling through its maintainer - a
// proven address is never evicted, so an ordinary blip is still retried.
type learnedHint struct {
	since  uint64
	proven bool
}

// peerHints is the learned-address bookkeeping. It is guarded by its own mutex
// because the receive path runs on the transport's dispatch goroutine while
// the wave loop sends.
type peerHints struct {
	mu sync.Mutex
	// learned is keyed by the canonical address string and bounded by
	// maxLearnedPeerAddrs: every entry in it is an address this node called
	// AddPeer for, so the map's size is the dial bound made visible.
	learned map[string]*learnedHint
	// sources is the per-wave, PER ADVERTISING MEMBER adoption window
	// (maxNewPeerHintsPerWave each). It is keyed by the signed validator key
	// rather than the connection, because on the relay every member's frames
	// arrive on one connection and a connection-keyed window would let one
	// member spend the others' allowance. cleared when wave advances.
	sources map[string]int
	// wave is the wave the windows above belong to.
	wave uint64
}

// listenerAddr is this node's own listener, canonical, or "" when it does not
// listen or the address does not parse. It is what a hint must not name
// (errHintSelf); it is NOT necessarily what this node advertises, because a
// wildcard bind names no reachable endpoint (see advertisableAddr).
func (v *Validator) listenerAddr() string {
	a := v.ttp.Addr()
	if a == nil {
		return ""
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return ""
	}
	return netip.AddrPortFrom(canonicalHintAddr(ap.Addr()), ap.Port()).String()
}

// advertisableAddr is what this node may put in a PEER_EXCHANGE: --advertise
// when the operator gave one, else its own listener when that listener is at a
// CONCRETE address.
//
// An unspecified listener (0.0.0.0, [::]) means "every interface" and names no
// reachable endpoint, so advertising it would only send peers a dial that
// cannot complete. That is the port-forwarded home node's shape, and it is why
// --advertise exists (audit PX-8): the operator knows the public IP:port the
// router forwards to, the bind address does not. Behind NAT with no listener a
// node still advertises nothing, exactly as §6.6's staged strategy expects. The
// address is canonicalised the same way hints are, so the self-check compares
// like with like.
func (v *Validator) advertisableAddr() string {
	if v.advertise != "" {
		return v.advertise
	}
	a := v.ttp.Addr()
	if a == nil {
		return ""
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return ""
	}
	ip := canonicalHintAddr(ap.Addr())
	if ip.IsUnspecified() || ap.Port() == 0 {
		return ""
	}
	return netip.AddrPortFrom(ip, ap.Port()).String()
}

// reserveRelayAddr records a configured relay's parsed address so no hint may
// name it (audit PX-6). A relay address that does not parse as a literal
// IP:port (a hostname) cannot be compared without resolving it, and resolving a
// dial target is exactly what the literal-IP rule refuses; it stays covered by
// its relay:<addr> name instead.
func (v *Validator) reserveRelayAddr(raw string) {
	ap, err := netip.ParseAddrPort(strings.TrimSpace(raw))
	if err != nil {
		return
	}
	ap = netip.AddrPortFrom(canonicalHintAddr(ap.Addr()), ap.Port())
	v.relayMu.Lock()
	defer v.relayMu.Unlock()
	for _, have := range v.relayAddrs {
		if have == ap {
			return // StartValidator reserves cfg.Relay, then the CLI re-adds it
		}
	}
	v.relayAddrs = append(v.relayAddrs, ap)
}

// hintReservedAddrs is the parsed set a hint may never name: the relays this
// node dials, plus the address it advertises (a hint naming that address would
// have this node dial itself through its own public endpoint). The slice is a
// copy, so the receive path holds no lock and cannot race a later ConnectRelay.
func (v *Validator) hintReservedAddrs() []netip.AddrPort {
	v.relayMu.Lock()
	out := append([]netip.AddrPort(nil), v.relayAddrs...)
	v.relayMu.Unlock()
	if a := v.advertisableAddr(); a != "" {
		if ap, err := netip.ParseAddrPort(a); err == nil {
			out = append(out, netip.AddrPortFrom(canonicalHintAddr(ap.Addr()), ap.Port()))
		}
	}
	return out
}

// peerExchangeHash is the domain-separated hash a PEER_EXCHANGE signs: the
// chain id (so a frame cannot be transplanted between chains), the height it
// was advertised at (so the receiver knows which committee judges the
// advertiser), and the address list in its canonical order. It lives here, not
// in wire, for the same reason helloHash does: the node layer owns the policy
// that the signature expresses, and the wire layer only frames bytes.
func peerExchangeHash(chainID string, height uint64, addrs []string) [32]byte {
	e := types.NewEncoder()
	e.VarBytes([]byte(chainID))
	e.U64(height)
	e.Len(len(addrs))
	for _, a := range addrs {
		e.VarBytes([]byte(a))
	}
	return crypto.HashParts([]byte("b10coin-peer-exchange"), e.Bytes())
}

// sendPeerExchange advertises this node's listening address, if it has one,
// signed by this node's key at its current height - the authority the receiver
// checks. It is called from the wave loop at the peerExchangeEveryWaves
// cadence; the test seam calls it directly to construct a wave instead of
// waiting.
//
// It advertises EXACTLY ONE address: this node's own listener, never an
// address it learned. That is what bounds the message against amplification
// and keeps every advertised address attributable to the member that signs it,
// and it has a consequence the 2026-10-30 Docker run found (audit M-2, third
// variant): a node can only ever learn the address of a node it is ALREADY
// connected to, so the hint set equals the link set and a `--peers` CHAIN never
// becomes a mesh. A relay masks this - every member shares the relay's link, so
// one broadcast reaches everyone - but with no relay and a chain, the graph
// stays a chain and the committee never reaches quorum. TestPeerExchangeDoesNotMeshAChain
// pins the limitation; the README documents it. Making advertisements carry the
// advertiser's PROVEN neighbours as well (one more hop) is the change that would
// mesh a chain, and it needs its own eviction policy for second-hand addresses,
// so it is deliberately not done here.
func (v *Validator) sendPeerExchange() {
	addr := v.advertisableAddr()
	if addr == "" {
		// A listener exists but names nothing a peer could dial: say so ONCE
		// (audit PX-8). The silence used to be total - `--listen
		// 0.0.0.0:7001` behind a forwarded port advertised nothing and no line
		// anywhere said so - so the operator's only clue was a mesh that never
		// formed. The fix is --advertise; this is the line that tells them.
		// A dial-only node (no listener at all) is silent by design and does
		// not log.
		if v.ttp.Addr() != nil && v.advertiseWarned.CompareAndSwap(false, true) {
			log.Printf("b10coin: PEER_EXCHANGE is advertising nothing: this node listens on %q, which is not a concrete address a peer can dial. Give --advertise IP:PORT (the public address a peer should use, e.g. the port your router forwards) to join the direct mesh; the relay keeps working either way.", v.ttp.Addr())
		}
		return
	}
	p := &wire.PeerExchange{
		Height:    v.ch.Height(),
		Validator: append([]byte(nil), v.pub...),
		Addrs:     []string{addr},
	}
	h := peerExchangeHash(v.g.ChainID, p.Height, p.Addrs)
	p.Sig = crypto.Sign(v.priv, h[:])
	if err := v.ttp.Broadcast(wire.EncodePeerExchange(p)); err != nil {
		return
	}
	v.hintsSent.Add(1)
}

// hintAuthority reports whether p was signed by a member that may advertise:
// the key must hold a seat at the height it advertised at (the same union
// HELLO admission uses - genesis, the committee at that height, and the
// committee at our head) and the signature must verify over this chain's id,
// that height and these addresses.
//
// This is a POLICY function and does not trust the decoder's bounds: a
// caller-built frame can reach it in a test, and a future decoder change must
// not be able to turn a short key into a verification against a prefix.
func (v *Validator) hintAuthority(p *wire.PeerExchange) bool {
	if len(p.Validator) != ed25519.PublicKeySize || len(p.Sig) != ed25519.SignatureSize {
		return false
	}
	// Membership first: a stranger's frame is refused without spending a
	// signature verification, and the committee lookup is what makes a relay
	// forwarder no more authoritative than the bytes it copied.
	if !committeeMemberAt(v.ch, v.g, p.Validator, p.Height) {
		return false
	}
	h := peerExchangeHash(v.g.ChainID, p.Height, p.Addrs)
	return crypto.Verify(p.Validator, h[:], p.Sig)
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
	if !v.hintAuthority(p) {
		v.hintsRefused.Add(1)
		return
	}
	// own is the LISTENER, not the advertised override: the self-check is about
	// the socket this node holds. The advertised address is in reserved, so a
	// hint naming the public endpoint of this node's own forwarded port is
	// refused too (it would otherwise dial this node through its own router).
	own := v.listenerAddr()
	reserved := v.hintReservedAddrs()
	wave := v.currentWave()

	// The window is the ADVERTISING MEMBER's, keyed by the signed key: on the
	// relay every member shares one connection, so a connection-keyed window
	// would let the first sender spend the allowance of the others (audit
	// PX-1).
	source := string(p.Validator)

	b := &v.hints
	b.mu.Lock()
	defer b.mu.Unlock()
	if wave != b.wave {
		b.wave = wave
		clear(b.sources)
	}
	admitted, seen := b.sources[source]
	if !seen {
		b.sources[source] = 0
	}
	for _, raw := range p.Addrs {
		ap, err := validatePeerHint(raw, own, reserved, v.cfg.AllowLocalPeerHints)
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
		if admitted >= maxNewPeerHintsPerWave {
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
		// not a permanent exit (audit N-1) - until the eviction clock below
		// retires an address that NEVER completed a handshake (audit PX-1).
		//
		// learned=true is audit PX-2's whole point: this dial exists because a
		// PEER named the address, so the transport holds it out of Peers() and
		// off every Broadcast until a signed committee HELLO bound to the
		// connection's nonce arrives.
		if err := v.peerAdd(key, true); err != nil {
			v.hintsRefused.Add(1)
			continue
		}
		b.learned[key] = &learnedHint{since: wave}
		admitted++
		b.sources[source] = admitted
		v.hintsAdopted.Add(1)
	}
}

// markHintProven records that a signed committee HELLO arrived on the
// connection under transport name from, and that the connection's address is
// one this node learned from a hint: that address is a real peer and its
// maintainer must never be retired. The address lookup happens OUTSIDE the
// hint mutex (PeerAddr takes the transport mutex; the receive path takes them
// in the other order) and a relay name simply does not match any learned
// address.
func (v *Validator) markHintProven(from transport.PeerID) {
	addr, ok := v.ttp.PeerAddr(from)
	if !ok {
		return
	}
	v.hints.mu.Lock()
	if h := v.hints.learned[addr]; h != nil {
		h.proven = true
	}
	v.hints.mu.Unlock()
}

// expireUnprovenHints retires learned addresses whose handshake never
// completed. It is called once per wave (from beginWave) with the wave number
// that has just begun: an address learned before wave-hintHandshakeGraceWaves
// that has never carried a signed committee HELLO is removed from the book -
// returning its lifetime-budget slot - and its maintainer is cancelled, so the
// redials against it stop (audit PX-1).
//
// The removals run outside the book's mutex: peerRemove takes the transport's,
// and the dial path takes them in the opposite order.
func (v *Validator) expireUnprovenHints(wave uint64) {
	b := &v.hints
	var stale []string
	b.mu.Lock()
	for key, h := range b.learned {
		if h.proven || wave-h.since < hintHandshakeGraceWaves {
			continue
		}
		delete(b.learned, key)
		stale = append(stale, key)
	}
	b.mu.Unlock()
	for _, key := range stale {
		if v.peerRemove != nil {
			v.peerRemove(key)
		}
		v.hintsEvicted.Add(1)
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
// policy, signed or not. It is a mesh-formation observable, never a liveness
// one.
func (v *Validator) PeerHintsSeen() uint64 { return v.hintsSeen.Load() }

// PeerHintsAdopted reports how many advertised addresses this node turned into
// dials. It is a mesh-formation observable, never a liveness one.
func (v *Validator) PeerHintsAdopted() uint64 { return v.hintsAdopted.Load() }

// PeerHintsRefused reports how many advertised addresses this node refused:
// not signed by a member seated at the advertised height, unparseable, local,
// its own, reserved, or over a per-member per-wave budget.
func (v *Validator) PeerHintsRefused() uint64 { return v.hintsRefused.Load() }

// PeerHintsDuplicates reports how many advertised addresses were already
// learned. A duplicate causes no dial and consumes no budget.
func (v *Validator) PeerHintsDuplicates() uint64 { return v.hintsDuplicates.Load() }

// PeerHintsOverBudget reports how many otherwise-valid hints were refused
// because the node-wide lifetime dial budget (maxLearnedPeerAddrs) was already
// spent.
func (v *Validator) PeerHintsOverBudget() uint64 { return v.hintsOverBudget.Load() }

// PeerHintsEvicted reports how many learned addresses were retired because
// their handshake never completed. A nonzero count with a healthy mesh is
// normal churn; the point is that the slot (and the maintainer) is released
// rather than held until restart.
func (v *Validator) PeerHintsEvicted() uint64 { return v.hintsEvicted.Load() }

// PeerExchangesSent reports how many PEER_EXCHANGE frames this node broadcast.
func (v *Validator) PeerExchangesSent() uint64 { return v.hintsSent.Load() }

// LearnedPeerAddrs reports how many distinct addresses this node holds from
// hints: the lifetime budget made observable.
func (v *Validator) LearnedPeerAddrs() int {
	v.hints.mu.Lock()
	defer v.hints.mu.Unlock()
	return len(v.hints.learned)
}
