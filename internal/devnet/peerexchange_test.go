package devnet

// PEER_EXCHANGE's node-layer pins: the dial policy, the three bounds, and the
// one thing the message must never become - a way into the engine.
//
// Every test here CONSTRUCTS its state: a frozen node (TickEvery and WaveEvery
// at an hour) for the policy tests, a recording dial seam where the assertion is
// "this address was / was not dialled", and a wave counter advanced by hand
// where the assertion is a per-wave bound. None waits for a buffer to fill or a
// timer to race; the socket tests wait on an observable (a peer appearing, an
// accept count) with a deadline, never on a sleep followed by a guess.

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/cti97/b10coincom/internal/consensus"
	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/relay"
	"github.com/cti97/b10coincom/internal/simnet"
	"github.com/cti97/b10coincom/internal/transport"
	"github.com/cti97/b10coincom/internal/transport/tcp"
	"github.com/cti97/b10coincom/internal/wire"
)

// startFrozen starts one validator whose loops never tick: the state the policy
// tests construct, so height, round and wave cannot move underneath them.
func startFrozen(t *testing.T, allowLocal bool) *Validator {
	t.Helper()
	v, err := StartValidator(ValidatorConfig{
		Dir:                 t.TempDir(),
		Index:               0,
		Validators:          4,
		Listen:              "127.0.0.1:0",
		AllowLocalPeerHints: allowLocal,
		TickEvery:           time.Hour,
		WaveEvery:           time.Hour,
	})
	if err != nil {
		t.Fatalf("starting a frozen validator: %v", err)
	}
	t.Cleanup(func() { _ = v.Close() })
	return v
}

// recordPeerDial replaces the one dial path with a recorder. It is installed
// before any traffic exists, and the tests that use it drive observePeerExchange
// on their own goroutine, so there is no concurrent read of the field.
func recordPeerDial(v *Validator) *[]string {
	dials := &[]string{}
	v.peerAdd = func(addr string) error {
		*dials = append(*dials, addr)
		return nil
	}
	return dials
}

// memberHint builds the frame a SEATED member sends: signed with that member's
// fixture key, over this node's chain id, at this node's height. The node's two
// checks - a seat at the advertised height, and a signature over (chain, height,
// addresses) - both pass, which is what makes the address policy below the only
// thing left to refuse (audit PX-1).
func memberHint(t *testing.T, v *Validator, seat int, addrs []string) *wire.PeerExchange {
	t.Helper()
	priv := simnet.ValidatorKey(seat)
	p := &wire.PeerExchange{
		Height:    v.Height(),
		Validator: priv.Public().(ed25519.PublicKey),
		Addrs:     addrs,
	}
	h := peerExchangeHash(v.g.ChainID, p.Height, p.Addrs)
	p.Sig = crypto.Sign(priv, h[:])
	return p
}

// strangerHint is the frame a RELAY STRANGER can produce: well formed, signed
// by a key of its own that holds no seat. Before the audit's fix this frame was
// authoritative the moment it arrived on a connection that had carried any
// member's HELLO - which on a relay is every connection. Now it is refused by
// the membership half of hintAuthority.
func strangerHint(t *testing.T, v *Validator, addrs []string) *wire.PeerExchange {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := &wire.PeerExchange{Height: v.Height(), Validator: pub, Addrs: addrs}
	h := peerExchangeHash(v.g.ChainID, p.Height, p.Addrs)
	p.Sig = crypto.Sign(priv, h[:])
	return p
}

// TestAPeerHintMustBeALiteralIPPort is the policy table: every shape a hostile
// hint can take, and the exact reason it is refused. "A hint is not operator
// intent" is a rule about the address STRING, so it is pinned without a socket.
func TestAPeerHintMustBeALiteralIPPort(t *testing.T) {
	own := "203.0.113.7:9"
	cases := []struct {
		name       string
		raw        string
		allowLocal bool
		want       string // canonical address, or "" when refused
		wantErr    error
	}{
		// Loopback, private and link-local are refused from a hint although an
		// operator may name them with --peers.
		{"loopback v4", "127.0.0.1:1", false, "", errHintLocal},
		{"loopback v6", "[::1]:1", false, "", errHintLocal},
		{"private 10/8", "10.0.0.5:9", false, "", errHintLocal},
		{"private 192.168/16", "192.168.1.9:6003", false, "", errHintLocal},
		{"link-local", "169.254.1.1:9", false, "", errHintLocal},
		// A hostname would move the target after the check.
		{"hostname", "example.com:9", false, "", errHintNotIPPort},
		{"no port", "203.0.113.4", false, "", errHintNotIPPort},
		{"empty", "", false, "", errHintNotIPPort},
		{"too long", "203.0.113.4:9" + string(make([]byte, wire.MaxListenAddrBytes)), false, "", errHintNotIPPort},
		// A port is a real one, never 0.
		{"port zero", "203.0.113.4:0", false, "", errHintPortZero},
		// "Every interface" is not an endpoint.
		{"unspecified v4", "0.0.0.0:9", false, "", errHintUnspecified},
		{"unspecified v6", "[::]:9", false, "", errHintUnspecified},
		// The reserved name is refused explicitly, before any parsing.
		{"reserved relay v4", "relay:203.0.113.4:9", false, "", errHintReservedName},
		{"reserved relay v6", "relay:[::1]:9", false, "", errHintReservedName},
		// This node's own listener is refused even when local hints are allowed.
		{"own address", own, true, "", errHintSelf},
		// Multicast is never a unicast peer, exception or not.
		{"multicast", "224.0.0.1:9", true, "", errHintMulticast},
		// Literal public endpoints are accepted, canonicalised.
		{"public v4", "203.0.113.4:6001", false, "203.0.113.4:6001", nil},
		{"public v6", "[2001:db8::7]:6002", false, "[2001:db8::7]:6002", nil},
		{"v4-mapped v6", "[::ffff:203.0.113.4]:6001", false, "203.0.113.4:6001", nil},
		// The devnet acceptance exception relaxes only the local-range rule.
		{"loopback allowed", "127.0.0.1:1", true, "127.0.0.1:1", nil},
		{"private allowed", "10.0.0.5:9", true, "10.0.0.5:9", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := validatePeerHint(tc.raw, own, tc.allowLocal)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("validatePeerHint(%q) = (%v, %v), want %v", tc.raw, got, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("validatePeerHint(%q) = %v, want %q", tc.raw, err, tc.want)
			}
			if got.String() != tc.want {
				t.Fatalf("validatePeerHint(%q) = %q, want the canonical %q", tc.raw, got.String(), tc.want)
			}
		})
	}
}

// TestAPeerExchangeCannotAimTheNodeAtItsOwnNetwork is the brief's own-network
// case at the handler: the five refused shapes produce NO dial, and one public
// IP:port produces EXACTLY ONE - counted on the recording seam, so the test
// never sends a packet to the public address it names.
func TestAPeerExchangeCannotAimTheNodeAtItsOwnNetwork(t *testing.T) {
	v := startFrozen(t, false)
	dials := recordPeerDial(v)
	v.observePeerExchange("v1", memberHint(t, v, 1, []string{
		"127.0.0.1:1",
		"[::1]:1",
		"10.0.0.5:9",
		"169.254.1.1:9",
		"example.com:9",
	}))
	if len(*dials) != 0 {
		t.Fatalf("a local, link-local, loopback or hostname hint produced %d dial(s) (%v); a peer may not aim this node at its own network", len(*dials), *dials)
	}
	if got := v.PeerHintsAdopted(); got != 0 {
		t.Fatalf("PeerHintsAdopted = %d after five refused hints, want 0", got)
	}
	if got := v.PeerHintsRefused(); got != 5 {
		t.Fatalf("PeerHintsRefused = %d, want 5", got)
	}

	v.observePeerExchange("v1", memberHint(t, v, 1, []string{"203.0.113.4:6001"}))
	if len(*dials) != 1 || (*dials)[0] != "203.0.113.4:6001" {
		t.Fatalf("a public hint produced dials %v, want exactly [203.0.113.4:6001]", *dials)
	}
	if got := v.PeerHintsAdopted(); got != 1 {
		t.Fatalf("PeerHintsAdopted = %d, want 1", got)
	}
}

// TestALearnedAddressThatIsMyOwnOrADuplicateOrAReservedNameIsIgnored covers the
// remaining untrusted shapes AT THE HANDLER, where the dial counter can see
// them: the node's own address (even with the devnet exception on), a repeated
// advertisement, an unparseable string, and one wearing the reserved relay:
// name. The first is refused, the second is ignored without a second dial, and
// the last two are refused.
func TestALearnedAddressThatIsMyOwnOrADuplicateOrAReservedNameIsIgnored(t *testing.T) {
	v := startFrozen(t, true)
	dials := recordPeerDial(v)

	// The same address as this node's own listener: refused even though the
	// devnet exception would otherwise accept a loopback hint.
	v.observePeerExchange("v1", memberHint(t, v, 1, []string{v.Addr()}))
	if len(*dials) != 0 {
		t.Fatalf("a hint naming this node's own listen address (%q) produced %v; self-dial is refused", v.Addr(), *dials)
	}

	// A valid public address is dialled once...
	v.observePeerExchange("v1", memberHint(t, v, 1, []string{"203.0.113.4:6001"}))
	// ...and re-advertising it is ignored: no second dial, no budget spent.
	v.observePeerExchange("v1", memberHint(t, v, 1, []string{"203.0.113.4:6001"}))
	if len(*dials) != 1 {
		t.Fatalf("a duplicate hint produced dials %v, want the one first dial", *dials)
	}
	if got := v.PeerHintsDuplicates(); got != 1 {
		t.Fatalf("PeerHintsDuplicates = %d, want 1", got)
	}

	// Unparseable and reserved-name hints never reach the dial path.
	v.observePeerExchange("v1", memberHint(t, v, 1, []string{"relay:203.0.113.4:6001", "not an address"}))
	if len(*dials) != 1 {
		t.Fatalf("reserved/unparseable hints produced dials %v, want only the earlier public one", *dials)
	}
	if got := v.PeerHintsRefused(); got != 3 { // own address + the two above
		t.Fatalf("PeerHintsRefused = %d, want 3", got)
	}
}

// TestOnePeerCannotSpendMoreThanThePerWaveOrLifetimeBudget pins the two
// adoption bounds with their numbers, by advancing the wave by hand:
//
//   - one frame's eight addresses are adopted, and a SECOND frame in the same
//     wave is refused wholesale - a peer can add maxNewPeerHintsPerWave (8) new
//     addresses per wave, however many frames it sends;
//   - four waves can add 4*8 = 32, and the 33rd distinct address is refused with
//     PeerHintsOverBudget - the lifetime dial budget.
func TestOnePeerCannotSpendMoreThanThePerWaveOrLifetimeBudget(t *testing.T) {
	v := startFrozen(t, false)
	dials := recordPeerDial(v)

	// One wave's worth, then a second frame in the SAME wave.
	waveAddrs := func(base int) []string {
		out := make([]string, 0, maxNewPeerHintsPerWave)
		for i := 0; i < maxNewPeerHintsPerWave; i++ {
			out = append(out, fmt.Sprintf("203.0.113.%d:6%03d", base+i, base+i))
		}
		return out
	}
	v.observePeerExchange("v1", memberHint(t, v, 1, waveAddrs(10)))
	if got := len(*dials); got != maxNewPeerHintsPerWave {
		t.Fatalf("one frame produced %d dials, want %d", got, maxNewPeerHintsPerWave)
	}
	v.observePeerExchange("v1", memberHint(t, v, 1, waveAddrs(20)))
	if got := len(*dials); got != maxNewPeerHintsPerWave {
		t.Fatalf("a second frame in one wave produced %d dials total, want %d: the per-wave budget did not bind", got, maxNewPeerHintsPerWave)
	}

	// Three more waves fill the lifetime budget (4 waves x 8). The member
	// re-advertises each wave, as an honest peer would.
	for _, base := range []int{30, 40, 50} {
		v.beginWave()
		v.observePeerExchange("v1", memberHint(t, v, 1, waveAddrs(base)))
	}
	if got := v.LearnedPeerAddrs(); got != maxLearnedPeerAddrs {
		t.Fatalf("LearnedPeerAddrs = %d after four waves, want the lifetime budget %d", got, maxLearnedPeerAddrs)
	}
	if got := len(*dials); got != maxLearnedPeerAddrs {
		t.Fatalf("dials = %d, want %d", got, maxLearnedPeerAddrs)
	}

	// The next wave's valid addresses are refused: the budget is lifetime, and
	// an over-budget refusal is counted separately so an operator can see it.
	v.beginWave()
	v.observePeerExchange("v1", memberHint(t, v, 1, waveAddrs(60)))
	if got := len(*dials); got != maxLearnedPeerAddrs {
		t.Fatalf("dials = %d after the budget was spent, want it capped at %d", got, maxLearnedPeerAddrs)
	}
	if got := v.PeerHintsOverBudget(); got != maxNewPeerHintsPerWave {
		t.Fatalf("PeerHintsOverBudget = %d, want %d", got, maxNewPeerHintsPerWave)
	}
}

// TestPeerExchangeSendRateIsBounded pins the send bound: a node with a listener
// advertises at most once per peerExchangeEveryWaves waves, and a node with no
// listener (behind NAT, dial-only) advertises nothing at all - an empty frame
// is not a no-op, it is a bug the decoder refuses.
func TestPeerExchangeSendRateIsBounded(t *testing.T) {
	wave := 10 * time.Millisecond
	period := time.Duration(peerExchangeEveryWaves) * wave
	sending, err := StartValidator(ValidatorConfig{
		Dir:        t.TempDir(),
		Index:      0,
		Validators: 4,
		Listen:     "127.0.0.1:0",
		WaveEvery:  wave,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sending.Close()

	// The bound is structural (one send per 4 waves); the ASSERTION is an upper
	// bound with slack, so a loaded machine can only send fewer. A node that
	// sent on every wave would be far over it.
	window := 12 * period
	time.Sleep(window)
	got := sending.PeerExchangesSent()
	ceiling := uint64(window/period) + 2
	if got == 0 {
		t.Fatalf("a listening node sent no PEER_EXCHANGE in %s: the mesh would never form", window)
	}
	if got > ceiling {
		t.Fatalf("a node sent %d PEER_EXCHANGE frames in %s; the send bound is one per %d waves (%s), so at most ~%d",
			got, window, peerExchangeEveryWaves, period, ceiling)
	}

	// No listener: no advertisement. This is the NAT shape §6.6 describes, and
	// the reason the sender emits nothing rather than an empty list.
	mute, err := StartValidator(ValidatorConfig{
		Dir:        t.TempDir(),
		Index:      1,
		Validators: 4,
		WaveEvery:  wave,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer mute.Close()
	time.Sleep(2 * period)
	if got := mute.PeerExchangesSent(); got != 0 {
		t.Fatalf("a dial-only node (no listener) sent %d PEER_EXCHANGE frames, want 0", got)
	}
	if got := mute.advertisableAddr(); got != "" {
		t.Fatalf("a dial-only node advertises %q, want nothing", got)
	}
}

// waitPeer polls until id is one of v's connected peers.
func waitPeer(t *testing.T, v *Validator, id transport.PeerID, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		for _, p := range v.ttp.Peers() {
			if p == id {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("peer %q did not appear within %s; peers are %v", id, timeout, v.ttp.Peers())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func hasPeer(v *Validator, id transport.PeerID) bool {
	for _, p := range v.ttp.Peers() {
		if p == id {
			return true
		}
	}
	return false
}

// TestALearnedAddressIsNotAPeerUntilItSaysHello is the admission boundary of
// design decision 5, stated the way the CODE behaves rather than the way a
// first draft of the brief described it.
//
// A hint can make this node DIAL a stranger, and a dialled connection is
// admitted by the transport at install (the node chose to dial it), so the
// stranger appears in Peers() by its handshake name. What it does NOT get is
// any committee authority: a self-signed vote it sends is refused by the
// router BEFORE verification and never reaches the engine, and a PEER_EXCHANGE
// it sends is refused because its connection never carried a signed committee
// HELLO (attestedConnection) - so a stranger cannot grow the dial set further.
// The HELLO is what makes a peer, exactly as the signed-committee-HELLO rule
// says; the transport name is only a routing key.
func TestALearnedAddressIsNotAPeerUntilItSaysHello(t *testing.T) {
	v, err := StartValidator(ValidatorConfig{
		Dir:                 t.TempDir(),
		Index:               0,
		Validators:          4,
		Listen:              "127.0.0.1:0",
		AllowLocalPeerHints: true,
		WaveEvery:           20 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	// A bare transport at the hinted address: it speaks the ID handshake (so the
	// dial completes) but holds no committee key and never sends a signed HELLO.
	stranger, err := tcp.New(tcp.Options{LocalID: "stranger"})
	if err != nil {
		t.Fatal(err)
	}
	defer stranger.Close()
	if err := stranger.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}

	// A member advertises the stranger's address to v.
	v.observePeerExchange("v1", memberHint(t, v, 1, []string{stranger.Addr().String()}))

	// The hint DID cause a dial: the transport name appears.
	waitPeer(t, v, "stranger", 5*time.Second)
	if got := v.LearnedPeerAddrs(); got != 1 {
		t.Fatalf("LearnedPeerAddrs = %d, want 1", got)
	}

	// A valid-looking vote signed by the stranger's OWN key is refused before
	// verification: the signature proves consistency, never membership.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	forged := &consensus.Vote{Type: consensus.MsgPrevote, Height: v.Height() + 1, Round: 0, Validator: pub}
	fh := forged.SigningHash()
	forged.Sig = crypto.Sign(priv, fh[:])
	before := v.rt.RefusedBeforeVerify()
	_ = stranger.Broadcast(consensus.EncodeVote(forged))
	deadline := time.Now().Add(5 * time.Second)
	for v.rt.RefusedBeforeVerify() == before {
		if time.Now().After(deadline) {
			t.Fatal("a self-signed vote from the learned address was not refused before verification")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// And the stranger cannot advertise: its hint is well formed and signed by
	// its OWN key, and that key holds no seat, so it is refused instead of
	// dialled (audit PX-1 - the connection it arrives on is irrelevant now).
	refusedBefore := v.PeerHintsRefused()
	_ = stranger.Broadcast(wire.EncodePeerExchange(strangerHint(t, v, []string{"203.0.113.9:6001"})))
	for v.PeerHintsRefused() == refusedBefore {
		if time.Now().After(deadline) {
			t.Fatal("an unattested connection's PEER_EXCHANGE was not refused")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := v.LearnedPeerAddrs(); got != 1 {
		t.Fatalf("LearnedPeerAddrs = %d after an unattested advertisement, want 1", got)
	}
}

// TestALearnedAddressThatIsDownIsRetriedNotAbandoned pins the maintainer rule
// from N-1 through the hint path: a dial failure is an ordinary failure. A
// refusing listener first PROVES the redial (two accepts = one failure and one
// retry, with no timing assumption); then a real peer at the same address
// proves the maintainer did not exit, because the next retry lands.
func TestALearnedAddressThatIsDownIsRetriedNotAbandoned(t *testing.T) {
	refuse, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := refuse.Addr().String()
	accepted := make(chan struct{}, 32)
	go func() {
		for {
			c, err := refuse.Accept()
			if err != nil {
				return
			}
			accepted <- struct{}{}
			c.Close() // the handshake ends in EOF: an ordinary dial failure
		}
	}()

	v, err := StartValidator(ValidatorConfig{
		Dir:                 t.TempDir(),
		Index:               0,
		Validators:          4,
		Listen:              "127.0.0.1:0",
		AllowLocalPeerHints: true,
		WaveEvery:           time.Hour, // frozen: the hint is the only dial source
	})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	v.observePeerExchange("v1", memberHint(t, v, 1, []string{addr}))
	if got := v.LearnedPeerAddrs(); got != 1 {
		t.Fatalf("LearnedPeerAddrs = %d, want 1", got)
	}

	// One accept is the first dial; a second is the maintainer RETRYING after
	// that dial failed. A one-shot dial (the mutant) produces exactly one.
	for i := 0; i < 2; i++ {
		select {
		case <-accepted:
		case <-time.After(10 * time.Second):
			t.Fatalf("the learned address was accepted %d time(s); a failed dial was not retried", i)
		}
	}

	// Replace the refusing listener with a real peer on the same address. The
	// maintainer's next backoff retry must land: a dial failure never exits.
	_ = refuse.Close()
	var late *tcp.TcpTransport
	for i := 0; i < 100; i++ {
		late, err = tcp.New(tcp.Options{LocalID: "late"})
		if err != nil {
			t.Fatal(err)
		}
		if err = late.Listen(addr); err == nil {
			break
		}
		_ = late.Close()
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("could not rebind %s for the recovering peer: %v", addr, err)
	}
	defer late.Close()
	waitPeer(t, v, "late", 10*time.Second)
}

// TestAPeerExchangeMovesNoConsensusState is design decision 5's negative: the
// frame is delivered to the node and the node's height, round and outgoing
// votes are untouched, and it left no key in the consensus seen-set. The loops
// are frozen so the only thing that could move them is the frame itself.
func TestAPeerExchangeMovesNoConsensusState(t *testing.T) {
	v := startFrozen(t, false)
	dials := recordPeerDial(v)

	height, round, voted := v.Height(), v.Round(), len(v.VotedHeights())
	v.route(transport.Message{From: "v1", Data: wire.EncodePeerExchange(memberHint(t, v, 1, []string{"203.0.113.4:6001"}))})
	if len(*dials) != 1 {
		t.Fatalf("the frame did not reach the node's dial policy (dials %v)", *dials)
	}
	if got := v.rt.PeerExchangesSeen(); got != 1 {
		t.Fatalf("PeerExchangesSeen = %d, want 1", got)
	}
	if v.Height() != height || v.Round() != round || len(v.VotedHeights()) != voted {
		t.Fatalf("a PEER_EXCHANGE moved consensus state: height %d->%d, round %d->%d, votes %d->%d",
			height, v.Height(), round, v.Round(), voted, len(v.VotedHeights()))
	}
	if got := v.rt.DuplicatesDropped(); got != 0 {
		t.Fatalf("DuplicatesDropped = %d, want 0: address traffic entered the consensus seen-set", got)
	}
	if got := v.rt.UnknownDropped(); got != 0 {
		t.Fatalf("UnknownDropped = %d, want 0", got)
	}
}

// TestTwoValidatorsBehindTheRelayLearnEachOtherAndConnectDirectly is the mesh:
// two validators that know ONLY the relay's address learn each other's
// listening addresses from the advertised frames and open a direct link. The
// waves are driven by hand (both loops are frozen) so the "before" state is
// constructed, not raced: after the relay links are up, each node knows exactly
// one peer - the relay - and neither was ever told the other's address.
func TestTwoValidatorsBehindTheRelayLearnEachOtherAndConnectDirectly(t *testing.T) {
	rl := relay.New(relay.Options{})
	defer rl.Close()
	if err := rl.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	raddr := rl.Addr().String()
	relayName := tcp.RelayPeerName(raddr)

	start := func(index int) *Validator {
		v, err := StartValidator(ValidatorConfig{
			Dir:                 t.TempDir(),
			Index:               index,
			Validators:          2,
			Listen:              "127.0.0.1:0",
			AllowLocalPeerHints: true,
			WaveEvery:           time.Hour, // the test drives the waves
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = v.Close() })
		if err := v.ConnectRelay(raddr); err != nil {
			t.Fatal(err)
		}
		return v
	}
	a, b := start(0), start(1)
	waitPeer(t, a, relayName, 5*time.Second)
	waitPeer(t, b, relayName, 5*time.Second)

	// Constructed "before": each knows only the relay, and neither has the
	// other's direct name.
	if len(a.ttp.Peers()) != 1 || len(b.ttp.Peers()) != 1 {
		t.Fatalf("each node should know only the relay before the exchange, got %v and %v", a.ttp.Peers(), b.ttp.Peers())
	}
	if hasPeer(a, "v1") || hasPeer(b, "v0") {
		t.Fatal("the validators were already directly connected before any advertisement")
	}

	// One wave, driven by hand: signed HELLOs first (so the relay connection is
	// attested on both sides), then the advertisements.
	a.broadcastHello()
	b.broadcastHello()
	a.sendPeerExchange()
	b.sendPeerExchange()
	if a.PeerExchangesSent() != 1 || b.PeerExchangesSent() != 1 {
		t.Fatalf("each node should have advertised once, got %d and %d", a.PeerExchangesSent(), b.PeerExchangesSent())
	}

	// B's dial to A installs immediately (a dialled connection is admitted by
	// the transport at install); A admits B only when B's signed HELLO arrives
	// on the new socket, and a cross-dial (both sides advertised each other, so
	// both dial) can leave a fresh inbound socket waiting for exactly that
	// frame. Drive the wave - the node's own wave loop would - until both
	// directions are admitted. This is a bounded poll on an observable, not a
	// sleep: every iteration re-sends the HELLO any new socket needs.
	deadline := time.Now().Add(15 * time.Second)
	for {
		a.broadcastHello()
		b.broadcastHello()
		if hasPeer(a, "v1") && hasPeer(b, "v0") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the direct link was dialled but never admitted both ways: a peers %v, b peers %v", a.ttp.Peers(), b.ttp.Peers())
		}
		time.Sleep(20 * time.Millisecond)
	}

	// The mesh, not a replacement: each node holds the relay link AND the
	// direct one, and each learned exactly one address (the other's).
	for name, v := range map[string]*Validator{"a": a, "b": b} {
		peers := v.ttp.Peers()
		if !hasPeer(v, relayName) {
			t.Fatalf("%s lost the relay link after the direct one formed: %v", name, peers)
		}
		if got := v.LearnedPeerAddrs(); got != 1 {
			t.Fatalf("%s learned %d addresses, want exactly the other validator's", name, got)
		}
	}
	if !hasPeer(a, "v1") || !hasPeer(b, "v0") {
		t.Fatalf("the direct link did not form: a peers %v, b peers %v", a.ttp.Peers(), b.ttp.Peers())
	}
	// And the direct link carries consensus: both sides keep a common history.
	waitConvergedEqual(t, []*Validator{a, b}, 1, 30*time.Second)
	assertIdenticalHistory(t, []*Validator{a, b}, a.Height())
}

// TestAMeshedVoteIsCountedOnce is the mesh's dedup wiring: a vote broadcast by
// A reaches C twice (once over the relay, once over the new direct link), the
// router drops the second copy as a duplicate, and the engine is handed the
// frame ONCE. The consensus ticks are frozen (both nodes' TickEvery and
// WaveEvery are an hour) so the only frames in flight are the two the test
// constructed - "two copies arrive" is a fact of the two paths, not a race with
// the live protocol.
//
// The power-once half is a property of the tally's per-validator VoteSet; what
// this test pins is that PEER_EXCHANGE wiring did not drop the dedup set on the
// way in (rt.Dedup), which is what keeps the second copy off the engine.
func TestAMeshedVoteIsCountedOnce(t *testing.T) {
	rl := relay.New(relay.Options{})
	defer rl.Close()
	if err := rl.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	raddr := rl.Addr().String()
	relayName := tcp.RelayPeerName(raddr)

	start := func(index int) *Validator {
		v, err := StartValidator(ValidatorConfig{
			Dir:        t.TempDir(),
			Index:      index,
			Validators: 2,
			Listen:     "127.0.0.1:0",
			TickEvery:  time.Hour,
			WaveEvery:  time.Hour,
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = v.Close() })
		if err := v.ConnectRelay(raddr); err != nil {
			t.Fatal(err)
		}
		return v
	}
	a, c := start(0), start(1)
	waitPeer(t, a, relayName, 5*time.Second)
	waitPeer(t, c, relayName, 5*time.Second)

	if err := a.Connect(c.Addr()); err != nil {
		t.Fatal(err)
	}
	waitPeer(t, a, "v1", 5*time.Second) // A's dial installs C's name at A
	a.broadcastHello()                  // C's inbound connection is admitted by a signed HELLO
	waitPeer(t, c, "v0", 5*time.Second)

	if c.rt.Dedup == nil {
		t.Fatal("the node router has no seen-set: the mesh would hand the engine every duplicate")
	}

	// One vote, sent once, over two paths: the relay conn and the direct one.
	vote := &consensus.Vote{Type: consensus.MsgPrevote, Height: 1, Round: 0, Validator: a.pub}
	vh := vote.SigningHash()
	vote.Sig = crypto.Sign(a.priv, vh[:])
	if err := a.ttp.Broadcast(consensus.EncodeVote(vote)); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for c.rt.DuplicatesDropped() < 1 {
		if time.Now().After(deadline) {
			t.Fatalf("C received the meshed vote twice but recorded no duplicate: the dedup set is not on the mesh path (peers %v)", c.ttp.Peers())
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Exactly one duplicate: the second copy of this one vote. (Frozen ticks
	// mean no other verified vote exists to duplicate.)
	time.Sleep(50 * time.Millisecond)
	if got := c.rt.DuplicatesDropped(); got != 1 {
		t.Fatalf("C dropped %d duplicates, want exactly 1 (one vote, two paths)", got)
	}
	if got := c.rt.PeerExchangesSeen(); got != 0 {
		t.Fatalf("a vote changed PeerExchangesSeen to %d", got)
	}
}
