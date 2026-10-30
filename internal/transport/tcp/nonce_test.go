package tcp

// The per-connection challenge (audit PX-2) is the material a HELLO signature is
// bound to, so its two properties are pinned directly rather than inferred from
// a replay test: both ends must AGREE on the pair, and the two values must be
// FRESH (distinct across connections and across ends). A relay connection has
// neither, and reports nil rather than a fake value - the caller must be able to
// tell "no peer challenge" from "a challenge that happens to be empty".

import (
	"bytes"
	"testing"
	"time"
)

func TestADirectConnectionExchangesTwoDistinctAgreedChallenges(t *testing.T) {
	a := listen(t, Options{LocalID: "a"})
	b := listen(t, Options{LocalID: "b"})
	if err := a.AddPeer(b.Addr().String()); err != nil {
		t.Fatal(err)
	}
	if err := b.AddPeer(a.Addr().String()); err != nil {
		t.Fatal(err)
	}
	// Exactly one of the cross-dials survives the rank; whichever it is, each
	// side must hold the pair (our challenge, theirs) for the peer name.
	waitFor(t, "both sides to register one connection to the other", 5*time.Second, func() bool {
		return len(a.Peers()) == 1 && len(b.Peers()) == 1
	})

	aPeer := a.Peers()[0]
	bPeer := b.Peers()[0]
	aOurs, aTheirs, ok := a.ConnNonces(aPeer)
	if !ok {
		t.Fatalf("no nonces for a's peer %q", aPeer)
	}
	bOurs, bTheirs, ok := b.ConnNonces(bPeer)
	if !ok {
		t.Fatalf("no nonces for b's peer %q", bPeer)
	}
	if len(aOurs) != connectionNonceBytes || len(bOurs) != connectionNonceBytes {
		t.Fatalf("challenge widths: a %d B, b %d B, want %d", len(aOurs), len(bOurs), connectionNonceBytes)
	}
	// Agreement: what a must echo is exactly what b checks, and vice versa.
	if !bytes.Equal(aTheirs, bOurs) {
		t.Fatal("a's peer challenge is not the value b generated: the two ends disagree on the HELLO binding")
	}
	if !bytes.Equal(bTheirs, aOurs) {
		t.Fatal("b's peer challenge is not the value a generated: the two ends disagree on the HELLO binding")
	}
	if bytes.Equal(aOurs, bOurs) {
		t.Fatal("both ends generated the SAME challenge: a captured HELLO would be replayable across the pair's directions")
	}

	// And a fresh connection gets a fresh challenge, so a captured HELLO for the
	// old socket is useless on the new one.
	oldA := append([]byte(nil), aOurs...)
	aPeerName := aPeer
	_ = a.Close()
	reopened := listen(t, Options{LocalID: "a"})
	if err := reopened.AddPeer(b.Addr().String()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the reopened a to register a fresh connection", 5*time.Second, func() bool {
		for _, p := range reopened.Peers() {
			if ours, _, ok := reopened.ConnNonces(p); ok && !bytes.Equal(ours, oldA) {
				return true
			}
		}
		return false
	})
	_ = aPeerName
}
