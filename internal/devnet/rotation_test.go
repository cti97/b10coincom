package devnet

// The C-6 pins (audit round 6): peer-height selection under a lying member.
// They are unit-scale and deterministic - a quiet validator, a hand-built peer
// table, and a pull seam - so the rotation is exercised by CONSTRUCTED state,
// never by a real socket's timing. The end-to-end catch-up path stays covered
// by tcp_test.go's late-joiner tests.

import (
	"testing"
	"time"

	"github.com/cti97/b10coincom/internal/transport"
)

// startQuietValidator starts one fixture-mode validator with no listener and
// hour-long loops: these tests drive maybeCatchUp by hand, and no automatic
// wave or tick may race them.
func startQuietValidator(t *testing.T) *Validator {
	t.Helper()
	v, err := StartValidator(ValidatorConfig{
		Dir:        t.TempDir(),
		Index:      0,
		Validators: 4,
		TickEvery:  time.Hour,
		WaveEvery:  time.Hour,
	})
	if err != nil {
		t.Fatalf("starting a quiet validator: %v", err)
	}
	t.Cleanup(func() { _ = v.Close() })
	return v
}

// TestALyingHeightIsRotatedAwayFrom is the C-6 proof. A signed committee member
// announces a colossal height it cannot serve; pulling from it adopts nothing.
// The next wave must NOT pick it again: it is demoted, and the truthful taller
// peer is chosen - and the truthful peer is not itself demoted for having been
// selected (the fix rotates away from a liar, it does not distrust everyone).
func TestALyingHeightIsRotatedAwayFrom(t *testing.T) {
	v := startQuietValidator(t)

	const liar = transport.PeerID("v2")
	const truth = transport.PeerID("v1")
	v.recordHeight(liar, 1<<62) // signed by a member, unserveable
	v.recordHeight(truth, 3)    // a real peer, three blocks ahead

	var picked []transport.PeerID
	v.pull = func(from uint64) error {
		picked = append(picked, v.sy.Peer)
		if v.sy.Peer == truth {
			// Substantiate the truthful peer's attestation by actually
			// adopting the blocks it claims.
			for v.ch.Height() < 3 {
				blk, err := v.ch.Build(v.priv, nil, v.ch.Head().Header.Timestamp+1)
				if err != nil {
					return err
				}
				if err := v.ch.Append(blk); err != nil {
					return err
				}
			}
		}
		return nil
	}

	v.maybeCatchUp()
	if len(picked) != 1 || picked[0] != liar {
		t.Fatalf("wave 1 pulled from %v, want the tallest attested peer %q", picked, liar)
	}
	v.maybeCatchUp()
	if len(picked) != 2 || picked[1] != truth {
		t.Fatalf("wave 2 pulled from %v, want the truthful peer %q after the liar was demoted - the lying height still monopolised the pull target", picked, truth)
	}
	if got := v.Height(); got != 3 {
		t.Fatalf("the truthful peer's blocks were not adopted: height %d", got)
	}
	// The liar is not reselected while its demotion stands.
	v.maybeCatchUp()
	if len(picked) != 2 {
		t.Fatalf("a third wave pulled from %v: the demoted liar was chosen again", picked)
	}
}

// TestAStalePeerHeightExpires is the other half of C-6: an entry not refreshed
// within a few waves stops being selectable, so a vanished peer cannot hold the
// pull target forever.
func TestAStalePeerHeightExpires(t *testing.T) {
	v := startQuietValidator(t)
	v.recordHeight("v9", 100)
	if p, h := v.tallestPeer(); p != "v9" || h == 0 {
		t.Fatalf("a freshly recorded height was not selectable: (%q, %d)", p, h)
	}
	for i := 0; i < peerHeightTTL+1; i++ {
		v.beginWave()
	}
	if p, _ := v.tallestPeer(); p != "" {
		t.Fatalf("a peer height not refreshed for %d waves was still selected (%q)", peerHeightTTL+1, p)
	}
}

// TestTheAsyncSyncQueueIsBounded pins C-4's bounded worker queue without
// sockets or floods: with no worker draining, the queue accepts exactly its
// depth and sheds the rest instead of blocking the caller.
func TestTheAsyncSyncQueueIsBounded(t *testing.T) {
	v := &Validator{syncQ: make(chan transport.Message, 2)}
	v.enqueueSync(transport.Message{})
	v.enqueueSync(transport.Message{})
	v.enqueueSync(transport.Message{}) // over depth: shed, never block
	if got := len(v.syncQ); got != 2 {
		t.Fatalf("the bounded queue holds %d, want its depth 2", got)
	}
	if got := v.SyncRequestsDropped(); got != 1 {
		t.Fatalf("SyncRequestsDropped = %d, want 1", got)
	}
}
