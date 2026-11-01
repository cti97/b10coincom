package devnet

// Audit N-6: D-4's eviction clock retired a LIVE peer whose own inbound dial
// won newcomerWins. The learned entry is keyed by the address this node dials,
// but the surviving connection at this node is the peer's ACCEPTED socket,
// registered under its ephemeral remote address, so an address match said "the
// peer is gone" while it was right there. The entry was then retired after
// hintProvenLifetimeWaves, re-learned from the next advertisement: benign
// churn that contradicted "cannot evict a live peer" and inflated
// PeerHintsEvicted. The fix matches on the peer's admitted key.
//
// The state is CONSTRUCTED, not raced: P dials V first and is admitted, THEN V
// learns P's address. V's learned dial to that address can never displace the
// admitted inbound connection (a learned connection never outranks one that is
// not, and the cross-dial rank agrees), so V keeps the ephemeral-address
// connection deterministically. The eviction clock is advanced by hand.

import (
	"testing"
	"time"
)

func TestALivePeerWhoseOwnInboundDialWonIsNotRetired(t *testing.T) {
	v, err := StartValidator(ValidatorConfig{
		Dir:                 t.TempDir(),
		Index:               1, // "v1": the larger ID, so the peer's dial wins here
		Validators:          2,
		Listen:              "127.0.0.1:0",
		AllowLocalPeerHints: true,
		TickEvery:           time.Hour,
		WaveEvery:           time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	p, err := StartValidator(ValidatorConfig{
		Dir:        t.TempDir(),
		Index:      0, // "v0"
		Validators: 2,
		Listen:     "127.0.0.1:0",
		TickEvery:  time.Hour,
		WaveEvery:  time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	// P's OWN inbound dial reaches V and is admitted there before any hint
	// exists. This is the connection that will survive.
	if err := p.ttp.AddPeer(v.Addr()); err != nil {
		t.Fatalf("P's configured dial of V: %v", err)
	}
	waitFor(t, "P's own dial to be admitted at V", 10*time.Second, func() bool {
		p.broadcastHello() // P's HELLO is what V's admission gate requires
		return hasPeer(v, "v0")
	})

	// Only NOW does V learn P's advertised address. The gated learned dial will
	// keep losing to the admitted inbound socket.
	v.observePeerExchange("v0", memberHint(t, v, 0, []string{p.Addr()}))
	key := p.Addr()
	var removed []string
	v.peerRemove = func(addr string) bool {
		removed = append(removed, addr)
		return true
	}
	if got := v.LearnedPeerAddrs(); got != 1 {
		t.Fatalf("setup: LearnedPeerAddrs = %d, want 1", got)
	}

	// The peer's HELLOs arrive on the INBOUND connection and must prove the
	// address by key, even though that connection's registry name is the
	// ephemeral address.
	waitFor(t, "the learned address to be proven by the peer's admitted key", 10*time.Second, func() bool {
		v.broadcastHello()
		p.broadcastHello()
		v.hints.mu.Lock()
		defer v.hints.mu.Unlock()
		h := v.hints.learned[key]
		return h != nil && h.proven
	})

	// The construction check: V's live peer is the peer's own inbound socket,
	// registered under an ephemeral address - not the address V learned.
	addr, ok := v.ttp.PeerAddr("v0")
	if !ok || addr == key {
		t.Fatalf("the construction did not produce the N-6 shape: peer registered at %q, learned address %q", addr, key)
	}

	// Age the proven stamp past the lifetime WITHOUT closing the link. Before
	// the fix the address match found no connection at `key` and retired a live
	// peer; now the admitted key is found and nothing is retired.
	v.hints.mu.Lock()
	v.hints.learned[key].lastProven = v.currentWave()
	v.hints.mu.Unlock()
	v.expireUnprovenHints(v.currentWave() + hintProvenLifetimeWaves + 1)

	if got := v.LearnedPeerAddrs(); got != 1 {
		t.Fatalf("LearnedPeerAddrs = %d, want 1: a live admitted peer was retired because its socket is registered under its ephemeral address (audit N-6)", got)
	}
	if len(removed) != 0 {
		t.Fatalf("retired %v, want nothing: the peer is still connected (audit N-6)", removed)
	}
	if got := v.PeerHintsEvicted(); got != 0 {
		t.Fatalf("PeerHintsEvicted = %d, want 0: a live peer inflated the churn counter", got)
	}
}
