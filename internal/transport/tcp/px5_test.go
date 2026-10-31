package tcp

// PX-5: a hint may dial this node, but a hint-originated connection must never
// hold a peer's NAME against the peer itself.
//
// The defect the audit named (PX-5): a hint names an attacker's listener; the
// listener announces a predictable validator ID ("v1"); install's duplicate
// rank prefers the dial at the smaller-ID end, so the squatter's UNMITTED
// connection takes the name "v1" and the genuine v1 - which reaches this node
// by dialling IT, i.e. as an accepted socket that can only be admitted after
// install - is refused on every redial. The relay link survives, so the mesh
// degrades rather than partitions.
//
// The state is CONSTRUCTED, never raced: the squatter installs first and the
// test waits until its connection is in the registry before the genuine peer
// dials. Nothing here depends on which of two dials wins a timing contest.

import (
	"bufio"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cti97/b10coincom/internal/wire"
)

func TestAHintedSquatterCannotHoldAnHonestPeersName(t *testing.T) {
	// The admission gate stays SHUT until the genuine peer has dialled, so the
	// genuine socket is unadmitted at install - exactly the state in which the
	// old rank let the squatter keep the name forever. Opening it later models
	// the genuine peer's signed HELLO arriving, without needing the node layer.
	var gate atomic.Bool
	a := listen(t, Options{
		LocalID: "v0",
		Admit:   func([]byte, []byte) bool { return gate.Load() },
	})

	// The squatter: a real transport that announces the predictable name.
	squatter := listen(t, Options{LocalID: "v1"})
	if err := a.AddLearnedPeer(squatter.Addr().String()); err != nil {
		t.Fatalf("AddLearnedPeer: %v", err)
	}
	// Constructed "before": the squatter holds "v1" and is NOT a peer.
	waitFor(t, "the hinted squatter to hold the name v1", 5*time.Second, func() bool {
		a.mu.Lock()
		defer a.mu.Unlock()
		c := a.conns["v1"]
		return c != nil && c.learned && !c.admitted.Load()
	})
	if got := a.Peers(); len(got) != 0 {
		t.Fatalf("the squatter is already a peer: %v", got)
	}

	// The genuine v1 reaches this node the way peers do: it dials the listener.
	honest := listen(t, Options{LocalID: "v1"})
	if err := honest.AddPeer(a.Addr().String()); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	gate.Store(true)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		tick := time.NewTicker(20 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				// The admitting frame of the node layer is a signed HELLO; the
				// transport only sees bytes, so any frame the gate accepts
				// stands in for it. A refused socket reports an error; its
				// maintainer redials on the backoff curve.
				_ = honest.Send("v0", []byte("hello"))
			}
		}
	}()

	waitFor(t, "the genuine v1 to take the name and be admitted", 15*time.Second, func() bool {
		a.mu.Lock()
		c := a.conns["v1"]
		ok := c != nil && c.admitted.Load() && !c.learned && c.addr != squatter.Addr().String()
		a.mu.Unlock()
		return ok
	})
	if got := a.Peers(); len(got) != 1 || got[0] != "v1" {
		t.Fatalf("Peers() = %v, want exactly the genuine v1", got)
	}
	// The squatter's maintainer is still registered - a hint is never allowed
	// to end a maintainer (audit N-1) - but it no longer holds the name, and
	// every retry loses to a non-learned connection.
	if !a.Maintains(squatter.Addr().String()) {
		t.Fatalf("the learned maintainer retired; only the node's own policy may do that")
	}
	a.mu.Lock()
	holder := a.conns["v1"]
	a.mu.Unlock()
	if holder == nil || holder.learned {
		t.Fatalf("the name v1 is held by a learned connection after the genuine peer arrived")
	}
}

// TestAHintedListenerCannotEvictAnHonestLinkMidHandshake is the EVICTION half
// of PX-5, which the admission asymmetry (audit F4) already half-closed: the
// squatter cannot displace an admitted link, but it could displace the honest
// peer's socket while that socket was still waiting for its admitting frame,
// because install runs BEFORE admission and the rank alone then decided the
// name. The squatter's handshake is driven SYNCHRONOUSLY here (the test's raw
// listener is the far end, and adopt is called directly), so the eviction
// attempt has no timing of its own to lose.
func TestAHintedListenerCannotEvictAnHonestLinkMidHandshake(t *testing.T) {
	var gate atomic.Bool // shut: the honest socket is installed but unadmitted
	a := listen(t, Options{
		LocalID: "v0",
		Admit:   func([]byte, []byte) bool { return gate.Load() },
	})

	// The genuine v1 connects (a peer dialling this node is an accepted socket,
	// and it is admitted only once a frame passes the gate).
	honest := listen(t, Options{LocalID: "v1"})
	if err := honest.AddPeer(a.Addr().String()); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	var honestAddr string
	waitFor(t, "the genuine peer's inbound socket to install", 5*time.Second, func() bool {
		a.mu.Lock()
		defer a.mu.Unlock()
		c := a.conns["v1"]
		if c == nil || c.admitted.Load() {
			return false
		}
		honestAddr = c.addr
		return true
	})

	// The squatter's endpoint: a raw listener that announces the predictable
	// name. This node DIALS it (the learned path), so the handshake is this
	// node's write-then-read on a socket the test hands to adopt.
	sl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sl.Close() })
	// announced closes once the squatter has read this node's ID and answered
	// with the predictable name: the eviction attempt has then been MADE, and
	// whatever follows (this end closing the socket on refusal) is the answer.
	announced := make(chan struct{})
	squatterErr := make(chan error, 1)
	go func() {
		nc, err := sl.Accept()
		if err != nil {
			squatterErr <- err
			return
		}
		defer nc.Close()
		br := bufio.NewReader(nc)
		if _, err := wire.ReadFrame(br, maxHandshakeIDBytes); err != nil { // "v0"
			squatterErr <- err
			return
		}
		if err := wire.WriteFrame(nc, []byte("v1")); err != nil {
			squatterErr <- err
			return
		}
		close(announced)
		// The refusal path closes the socket before the nonce exchange, so a
		// read error here is the expected outcome; keep the side honest anyway.
		_ = nc.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, _ = wire.ReadFrame(br, connectionNonceBytes)
	}()

	nc, err := net.Dial("tcp", sl.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	// dialled=true, gated=true: exactly the shape AddLearnedPeer produces.
	if _, err := a.adopt(nc, "squatter", true, true); !errors.Is(err, ErrDuplicatePeer) {
		t.Fatalf("a hint-dialled squatter announcing v1 was installed while the honest peer's socket was unadmitted (err = %v); it took the name", err)
	}
	select {
	case err := <-squatterErr:
		t.Fatalf("the squatter's handshake side failed before announcing its name: %v", err)
	case <-announced:
	case <-time.After(5 * time.Second):
		t.Fatal("the squatter never completed its side of the handshake")
	}

	a.mu.Lock()
	holder := a.conns["v1"]
	a.mu.Unlock()
	if holder == nil || holder.addr != honestAddr {
		t.Fatalf("the name v1 moved to %v; the honest link at %s was evicted", holder, honestAddr)
	}

	// The genuine link then admits, once its frame passes the gate: it was never
	// displaced, so it becomes the peer without redialling.
	gate.Store(true)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		tick := time.NewTicker(20 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				_ = honest.Send("v0", []byte("hello"))
			}
		}
	}()
	waitFor(t, "the genuine v1 to be admitted", 10*time.Second, func() bool {
		a.mu.Lock()
		defer a.mu.Unlock()
		c := a.conns["v1"]
		return c != nil && c.addr == honestAddr && c.admitted.Load()
	})
}
