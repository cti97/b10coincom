package tcp

// RemovePeer is the transport's half of audit PX-1's eviction rule: the node's
// own hint policy retires a learned address whose signed committee HELLO never
// completed, and the only way to stop its maintainer redialling forever is for
// the transport to have a deliberate exit. These tests pin that exit without
// weakening the N-1 rule it must not touch - nothing a PEER sends may end a
// maintainer - so they also pin that the removal is explicit and re-addable.

import (
	"testing"
	"time"
)

func TestRemovePeerEndsTheMaintainerAndClosesItsConnection(t *testing.T) {
	peer := listen(t, Options{LocalID: "peer"})
	tp := listen(t, Options{LocalID: "t"})
	addr := peer.Addr().String()
	if err := tp.AddPeer(addr); err != nil {
		t.Fatal(err)
	}
	waitPeersIs(t, tp, "[peer]")
	waitPeersIs(t, peer, "[t]")

	if !tp.Maintains(addr) {
		t.Fatal("AddPeer registered no maintainer")
	}
	if got, ok := tp.PeerAddr("peer"); !ok || got != addr {
		t.Fatalf("PeerAddr(peer) = (%q, %v), want (%q, true): the address a learned entry is keyed by", got, ok, addr)
	}

	// The retirement: registered -> not registered, live link -> closed, and
	// the PEER's side sees the socket end too (this is a real connection
	// close, not just a bookkeeping delete).
	if !tp.RemovePeer(addr) {
		t.Fatal("RemovePeer reported no registration for a maintained address")
	}
	if tp.Maintains(addr) {
		t.Fatal("the maintainer is still registered after RemovePeer")
	}
	waitPeersIs(t, tp, "[]")
	waitPeersIs(t, peer, "[]")
	if _, ok := tp.PeerAddr("peer"); ok {
		t.Fatal("PeerAddr still resolves a connection RemovePeer closed")
	}
	// Idempotent: the second call finds nothing to retire and says so.
	if tp.RemovePeer(addr) {
		t.Fatal("a second RemovePeer reported a registration it had already released")
	}

	// The address can be dialled again: the dead maintainer's deferred release
	// is identity-checked, so it cannot delete the new registration.
	if err := tp.AddPeer(addr); err != nil {
		t.Fatal(err)
	}
	if !tp.Maintains(addr) {
		t.Fatal("a re-added address has no maintainer")
	}
	waitPeersIs(t, tp, "[peer]")
}

func TestRemovePeerIsNotReachableFromTheWire(t *testing.T) {
	// The N-1 invariant this API must not weaken: a peer's refusal, duplicate
	// claim, supersede or socket death all back off and RETRY, so a peer can
	// never leave an address redialless. The only caller of RemovePeer in the
	// tree is the node's own hint policy; the transport itself never calls it.
	// This test pins the observable half: after a peer's connection dies on
	// its own, the maintainer is still registered and the address is still
	// dialled.
	peer := listen(t, Options{LocalID: "peer"})
	tp := listen(t, Options{LocalID: "t"})
	addr := peer.Addr().String()
	if err := tp.AddPeer(addr); err != nil {
		t.Fatal(err)
	}
	waitPeersIs(t, tp, "[peer]")

	// The peer goes away on its own (not via RemovePeer).
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the dead peer to leave the registry", 5*time.Second, func() bool { return len(tp.Peers()) == 0 })
	if !tp.Maintains(addr) {
		t.Fatal("a peer's own disconnect deregistered its maintainer: that is the N-1 bug RemovePeer must not introduce")
	}
}

func TestRemovePeerStopsAMaintainerThatIsBackingOff(t *testing.T) {
	// Nothing listens at this address, so every dial fails at once and the
	// maintainer spends its life in the backoff wait - the state a retirement
	// is most likely to find it in on a real network (a learned address that
	// never answers). The assertion is a POSITIVE observable, not "no redial
	// happened in N seconds": the goroutine must be GONE.
	tp := listen(t, Options{LocalID: "t", BackoffBase: 50 * time.Millisecond, BackoffMax: 50 * time.Millisecond})
	addr := "127.0.0.1:1" // reserved and closed: a dial here cannot succeed
	if err := tp.AddPeer(addr); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the maintainer to start backing off", 5*time.Second, func() bool {
		return tp.MaintainerCount() == 1
	})
	if !tp.RemovePeer(addr) {
		t.Fatal("RemovePeer reported no registration")
	}
	waitFor(t, "the retired maintainer to exit", 5*time.Second, func() bool {
		return tp.MaintainerCount() == 0
	})
	if tp.Maintains(addr) {
		t.Fatal("the registration survived the retirement")
	}
}
