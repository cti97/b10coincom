package devnet

// PX-1's acceptance evidence, node layer.
//
// The audit's attack: PEER_EXCHANGE carried a bare address list, and its
// authority was the CONNECTION - "attested" if any member's HELLO had arrived
// on it within four waves. On a relay every member's HELLO arrives under the
// one relay:<addr> name, so every relay sender was a hint authority, including
// a stranger on a token-less relay. One frame of eight attacker addresses made
// every validator open eight maintainers that retried forever, and the 32-slot
// lifetime budget never evicted, so the honest mesh stayed poisoned until
// restart.
//
// The fix chosen here is the audit's option (a): the frame is signed by the
// advertising member over (chain id, height, address list), and the key must
// hold a seat at that height. The relay is not asked to understand anything -
// it forwards the bytes exactly as before - and the documented relay
// rendezvous keeps working (TestTwoValidatorsBehindTheRelayLearnEachOtherAnd
// ConnectDirectly goes through this same verification path). What the
// signature does NOT stop, stated plainly: a SEATED member can still advertise
// junk addresses (bounded per member per wave, and evicted when they never
// complete a handshake), and a stranger who can replay a member's HELLO is
// still admitted as a peer (PX-2) - but the replayed HELLO no longer confers
// any hint authority, because the authority is the signature.

import (
	"fmt"
	"testing"
	"time"

	"github.com/cti97/b10coincom/internal/relay"
	"github.com/cti97/b10coincom/internal/transport/tcp"
	"github.com/cti97/b10coincom/internal/wire"
)

// eightPublicHints is an attacker's list: eight literals that pass the address
// policy (public, routable-looking, not this node's own endpoint), so the ONLY
// thing that can refuse them is the authority check.
func eightPublicHints() []string {
	out := make([]string, 0, wire.MaxPeerExchangeAddrs)
	for i := 0; i < wire.MaxPeerExchangeAddrs; i++ {
		out = append(out, fmt.Sprintf("203.0.113.%d:6001", 1+i))
	}
	return out
}

// TestARelayStrangerCannotAdvertise is the attack, on a REAL relay.
//
// The state is constructed, not raced: the relay is a real one with no token
// (the recipe's supported shape), a real committee member advertises its HELLO
// so the relay link is exactly as attestable as the old code required, and a
// bare transport - the stranger - connects to the same relay and sends a
// well-formed PEER_EXCHANGE signed by its OWN key. Under the old rule that
// frame was authoritative; under the signed rule its key holds no seat, so no
// address is adopted and no dial is made.
func TestARelayStrangerCannotAdvertise(t *testing.T) {
	rl := relay.New(relay.Options{})
	defer rl.Close()
	if err := rl.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	raddr := rl.Addr().String()

	v, err := StartValidator(ValidatorConfig{
		Dir:        t.TempDir(),
		Index:      0,
		Validators: 4,
		Listen:     "127.0.0.1:0",
		// Public addresses only: the attacker's hints are otherwise legal, so
		// the refusal below is the AUTHORITY check and nothing else.
		AllowLocalPeerHints: false,
		TickEvery:           time.Hour,
		WaveEvery:           time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	dials := recordPeerDial(v)

	member, err := StartValidator(ValidatorConfig{
		Dir:        t.TempDir(),
		Index:      1,
		Validators: 4,
		Listen:     "127.0.0.1:0",
		TickEvery:  time.Hour,
		WaveEvery:  time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer member.Close()

	if err := v.ConnectRelay(raddr); err != nil {
		t.Fatal(err)
	}
	if err := member.ConnectRelay(raddr); err != nil {
		t.Fatal(err)
	}
	waitPeer(t, v, tcp.RelayPeerName(raddr), 5*time.Second)
	waitPeer(t, member, tcp.RelayPeerName(raddr), 5*time.Second)

	// The member's HELLO is what made the relay connection attested under the
	// old rule. Sending it now proves the "before" precondition still holds
	// (V admits the membership-checked HELLO) and changes nothing about a
	// hint's authority.
	member.broadcastHello()
	waitFor(t, "the member's HELLO to be admitted over the relay", 5*time.Second, func() bool {
		v.peerHMu.Lock()
		defer v.peerHMu.Unlock()
		return len(v.peerH) > 0
	})

	// The stranger: a bare transport, no committee key, connected to the same
	// token-less relay.
	stranger, err := tcp.New(tcp.Options{LocalID: "stranger"})
	if err != nil {
		t.Fatal(err)
	}
	defer stranger.Close()
	// Relay dial mode: the relay reads the first frame for a registration
	// name and answers nothing, so the DIRECT handshake above would time out.
	if err := stranger.DialRelay(raddr); err != nil {
		t.Fatalf("the stranger could not reach the token-less relay: %v", err)
	}

	// A well-formed frame signed by a key of its own: exactly what a stranger
	// can produce. Repeat until the node's policy has seen it (the relay may
	// not have registered the stranger on the first attempt) - a bounded poll
	// on a positive counter, never a sleep.
	attack := wire.EncodePeerExchange(strangerHint(t, v, eightPublicHints()))
	waitFor(t, "the node's hint policy to see the stranger's frame", 10*time.Second, func() bool {
		before := v.PeerHintsSeen()
		_ = stranger.Broadcast(attack)
		time.Sleep(10 * time.Millisecond)
		return v.PeerHintsSeen() > before
	})

	// NOTHING was dialled, nothing was learned, and the frame is counted as a
	// refusal (the operator can see the attack rather than silence).
	if len(*dials) != 0 {
		t.Fatalf("a relay stranger made the node dial %d address(es): %v", len(*dials), *dials)
	}
	if got := v.LearnedPeerAddrs(); got != 0 {
		t.Fatalf("LearnedPeerAddrs = %d after a stranger's advertisement, want 0: the mesh is poisoned", got)
	}
	if got := v.PeerHintsRefused(); got == 0 {
		t.Fatal("the stranger's frame was not counted as refused")
	}
	if got := v.PeerHintsAdopted(); got != 0 {
		t.Fatalf("PeerHintsAdopted = %d after a stranger's advertisement, want 0", got)
	}

	// THE HONEST HALF, same relay, same node: a SEATED member's signed frame is
	// accepted and dialled. That is what proves the fix did not simply switch
	// PEER_EXCHANGE off on the relay deployment - the rendezvous still works,
	// it just cannot be driven by someone who holds no seat.
	dialsBefore := len(*dials)
	honest := memberHint(t, v, 2, []string{"203.0.113.200:6001"})
	v.observePeerExchange("v2", honest)
	if got := len(*dials); got != dialsBefore+1 {
		t.Fatalf("a seated member's signed hint produced %d new dial(s), want 1", got-dialsBefore)
	}
	if got := v.PeerHintsAdopted(); got != 1 {
		t.Fatalf("PeerHintsAdopted = %d after one honest hint, want 1", got)
	}
}

// TestAHintMustBeSignedByASeat pins the authority rule at the handler, without
// a socket: the three shapes that must be refused are a frame signed by a
// non-member, a frame whose signature does not verify, and a frame whose
// signature was made for a DIFFERENT address list or height (the replay that
// would otherwise let a captured signature be re-pointed).
func TestAHintMustBeSignedByASeat(t *testing.T) {
	v := startFrozen(t, false)
	dials := recordPeerDial(v)

	// A non-member's own well-formed signature.
	v.observePeerExchange("v1", strangerHint(t, v, []string{"203.0.113.4:6001"}))
	// A member's signature over a different list: the address is swapped after
	// signing, which is the cheapest forgery a relay forwarder could attempt.
	swapped := memberHint(t, v, 1, []string{"203.0.113.4:6001"})
	swapped.Addrs = []string{"203.0.113.5:6001"}
	v.observePeerExchange("v1", swapped)
	// A member's signature at a different height: the height is part of the
	// signed payload, so moving it invalidates the signature.
	reheighted := memberHint(t, v, 1, []string{"203.0.113.4:6001"})
	reheighted.Height++
	v.observePeerExchange("v1", reheighted)
	// A truncated signature: refused by the policy's own width check, which is
	// there so a caller-built frame cannot be verified against a prefix.
	truncated := memberHint(t, v, 1, []string{"203.0.113.4:6001"})
	truncated.Sig = truncated.Sig[:len(truncated.Sig)-1]
	v.observePeerExchange("v1", truncated)

	if len(*dials) != 0 {
		t.Fatalf("refused frames produced %d dial(s): %v", len(*dials), *dials)
	}
	if got := v.PeerHintsRefused(); got != 4 {
		t.Fatalf("PeerHintsRefused = %d, want 4 (non-member, swapped list, moved height, truncated signature)", got)
	}

	// And the genuine frame for that same list IS accepted, so the refusals
	// above are the signature and not the address.
	v.observePeerExchange("v1", memberHint(t, v, 1, []string{"203.0.113.4:6001"}))
	if len(*dials) != 1 || (*dials)[0] != "203.0.113.4:6001" {
		t.Fatalf("a member's signed hint produced dials %v, want exactly [203.0.113.4:6001]", *dials)
	}
	if got := v.PeerHintsAdopted(); got != 1 {
		t.Fatalf("PeerHintsAdopted = %d, want 1", got)
	}
}

// TestOneMemberCannotSpendAnotherMembersPerWaveBudget is the audit's "make the
// per-wave budget per source" requirement. ONE wave, two SEATED members: the
// first member's two frames are held to its own eight, and the second member's
// eight are still adopted. Under the old node-wide window the second member
// got nothing, which is how one relay sender denied the mesh to everyone.
func TestOneMemberCannotSpendAnotherMembersPerWaveBudget(t *testing.T) {
	v := startFrozen(t, false)
	dials := recordPeerDial(v)

	waveAddrs := func(base int) []string {
		out := make([]string, 0, maxNewPeerHintsPerWave)
		for i := 0; i < maxNewPeerHintsPerWave; i++ {
			out = append(out, fmt.Sprintf("203.0.113.%d:6%03d", base+i, base+i))
		}
		return out
	}
	// First member, two frames in the SAME wave: exactly one frame's worth.
	v.observePeerExchange("v1", memberHint(t, v, 1, waveAddrs(10)))
	v.observePeerExchange("v1", memberHint(t, v, 1, waveAddrs(20)))
	if got := len(*dials); got != maxNewPeerHintsPerWave {
		t.Fatalf("one member's two frames produced %d dials in one wave, want %d", got, maxNewPeerHintsPerWave)
	}

	// Second member, same wave: its own allowance is untouched.
	v.observePeerExchange("v2", memberHint(t, v, 2, waveAddrs(30)))
	if got := len(*dials); got != 2*maxNewPeerHintsPerWave {
		t.Fatalf("the second member got %d dial(s); it must have its own %d, total %d (one source spent the node-wide allowance)",
			got-maxNewPeerHintsPerWave, maxNewPeerHintsPerWave, 2*maxNewPeerHintsPerWave)
	}
	if got := v.LearnedPeerAddrs(); got != 2*maxNewPeerHintsPerWave {
		t.Fatalf("LearnedPeerAddrs = %d, want %d", got, 2*maxNewPeerHintsPerWave)
	}
	// A THIRD frame from a THIRD member in the same wave is still admitted:
	// the window is per member, not a node-wide count of eight.
	v.observePeerExchange("v3", memberHint(t, v, 3, waveAddrs(40)))
	if got := len(*dials); got != 3*maxNewPeerHintsPerWave {
		t.Fatalf("a third member's frame produced a total of %d dials, want %d", got, 3*maxNewPeerHintsPerWave)
	}
}

// TestALearnedAddressThatNeverCompletesIsEvicted is the eviction half. The
// clock is the WAVE COUNTER the node already advances, so the test constructs
// the age instead of waiting for it: two addresses are learned, one is marked
// proven (as observeHello marks a real peer's), and the wave is advanced past
// the grace. The unproven address is evicted - removed from the book and its
// maintainer retired - and the proven one is not.
func TestALearnedAddressThatNeverCompletesIsEvicted(t *testing.T) {
	v := startFrozen(t, true)
	dials := recordPeerDial(v)
	var removed []string
	v.peerRemove = func(addr string) bool {
		removed = append(removed, addr)
		return true
	}

	v.observePeerExchange("v1", memberHint(t, v, 1, []string{"127.0.0.1:9", "127.0.0.1:10"}))
	if len(*dials) != 2 || v.LearnedPeerAddrs() != 2 {
		t.Fatalf("setup: dials %v, learned %d, want two of each", *dials, v.LearnedPeerAddrs())
	}
	// The second address carried a signed committee HELLO on a connection to
	// it: it is a real peer (this is exactly what markHintProven records).
	v.hints.mu.Lock()
	v.hints.learned["127.0.0.1:10"].proven = true
	v.hints.mu.Unlock()

	// One wave short of the grace: nothing is retired.
	for i := 0; i < hintHandshakeGraceWaves-1; i++ {
		v.beginWave()
	}
	if got := v.PeerHintsEvicted(); got != 0 {
		t.Fatalf("PeerHintsEvicted = %d before the grace elapsed, want 0", got)
	}
	if got := v.LearnedPeerAddrs(); got != 2 {
		t.Fatalf("LearnedPeerAddrs = %d before the grace elapsed, want 2", got)
	}

	// The wave that reaches the grace retires the unproven address only.
	v.beginWave()
	if got := v.PeerHintsEvicted(); got != 1 {
		t.Fatalf("PeerHintsEvicted = %d at the grace, want 1", got)
	}
	if len(removed) != 1 || removed[0] != "127.0.0.1:9" {
		t.Fatalf("retired addresses = %v, want exactly [127.0.0.1:9]", removed)
	}
	if got := v.LearnedPeerAddrs(); got != 1 {
		t.Fatalf("LearnedPeerAddrs = %d after the eviction, want 1 (the proven address stays)", got)
	}
	// Ten more waves: a proven address is never evicted, however quiet it is.
	for i := 0; i < 10; i++ {
		v.beginWave()
	}
	if got := v.LearnedPeerAddrs(); got != 1 {
		t.Fatalf("LearnedPeerAddrs = %d after ten further waves, want the proven address kept", got)
	}
	if got := v.PeerHintsEvicted(); got != 1 {
		t.Fatalf("PeerHintsEvicted = %d, want 1: a proven address was evicted", got)
	}
	// The eviction frees a lifetime slot: a NEW address from a later wave is
	// still adopted rather than refused over budget.
	v.observePeerExchange("v1", memberHint(t, v, 1, []string{"127.0.0.1:11"}))
	if got := v.LearnedPeerAddrs(); got != 2 {
		t.Fatalf("LearnedPeerAddrs = %d after a new hint, want 2: the evicted slot was not freed", got)
	}
}

// TestALearnedAddressThatCompletesItsHandshakeIsNeverEvicted proves the same
// rule the other way round, with a REAL socket: the node dials a seated peer's
// advertised address, the peer's signed HELLO arrives on that connection, and
// the address survives the eviction clock. Without the via-address proof in
// markHintProven this test fails: the address would look "never completed" and
// its maintainer would be cancelled after the grace.
func TestALearnedAddressThatCompletesItsHandshakeIsNeverEvicted(t *testing.T) {
	v, err := StartValidator(ValidatorConfig{
		Dir:                 t.TempDir(),
		Index:               0,
		Validators:          2,
		Listen:              "127.0.0.1:0",
		AllowLocalPeerHints: true,
		TickEvery:           time.Hour, // no consensus: only the HELLO path runs
		WaveEvery:           time.Hour, // the test advances the eviction clock
	})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	peer, err := StartValidator(ValidatorConfig{
		Dir:        t.TempDir(),
		Index:      1,
		Validators: 2,
		Listen:     "127.0.0.1:0",
		TickEvery:  time.Hour,
		WaveEvery:  20 * time.Millisecond, // its HELLOs are what prove the address
	})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()

	// Seat 1 (the peer itself) advertises its own listener to v.
	v.observePeerExchange("v1", memberHint(t, v, 1, []string{peer.Addr()}))
	if got := v.LearnedPeerAddrs(); got != 1 {
		t.Fatalf("LearnedPeerAddrs = %d, want 1", got)
	}
	// The peer's inbound connection is admitted by V's HELLO (the transport
	// gates an inbound socket until the node's Admit policy accepts a frame),
	// so drive V's HELLO while waiting: the peer then broadcasts its own
	// every 20 ms, and that is what proves the address.
	waitFor(t, "the learned address to complete a signed HELLO", 10*time.Second, func() bool {
		v.broadcastHello()
		v.hints.mu.Lock()
		defer v.hints.mu.Unlock()
		h := v.hints.learned[peer.Addr()]
		return h != nil && h.proven
	})

	for i := 0; i < 3*hintHandshakeGraceWaves; i++ {
		v.beginWave()
	}
	if got := v.PeerHintsEvicted(); got != 0 {
		t.Fatalf("PeerHintsEvicted = %d after the grace, want 0: a peer that completed its handshake was retired", got)
	}
	if got := v.LearnedPeerAddrs(); got != 1 {
		t.Fatalf("LearnedPeerAddrs = %d, want the proven address kept", got)
	}
	// The connection itself is still a peer: eviction never touched a link
	// that works.
	waitPeer(t, v, "v1", 5*time.Second)

	// The authority check still comes first for the same address: a
	// non-member re-advertising it is refused, never a duplicate.
	refused := v.PeerHintsRefused()
	v.observePeerExchange("v1", strangerHint(t, v, []string{peer.Addr()}))
	if got := v.PeerHintsRefused(); got != refused+1 {
		t.Fatalf("PeerHintsRefused = %d after a non-member re-advertised a known address, want %d", got, refused+1)
	}
	if got := v.LearnedPeerAddrs(); got != 1 {
		t.Fatalf("LearnedPeerAddrs = %d, want the one proven address", got)
	}
}
