package devnet

// The C-6 pins (audit round 6) plus the F1/F2/F3 pins (round 7): peer-height
// selection under a lying member, keyed on the SIGNED member identity rather
// than the transport name. They are unit-scale and deterministic - a quiet
// validator, a hand-built peer table, and a pull seam - so the rotation is
// exercised by CONSTRUCTED state, never by a real socket's timing. The
// end-to-end catch-up path stays covered by tcp_test.go's late-joiner tests
// and relay_auth_test.go's relay-stranger test.

import (
	"strconv"
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

// memberKey is the peer-table key one seat's signed HELLO produces.
func memberKey(v *Validator, seat int) string { return string(v.g.Validators[seat].PubKey) }

// TestALyingHeightIsRotatedAwayFrom is the C-6 proof. A signed committee member
// announces a colossal height it cannot serve; pulling from it adopts nothing.
// The next wave must NOT pick it again: it is demoted, and the truthful taller
// peer is chosen - and the truthful peer is not itself demoted for having been
// selected (the fix rotates away from a liar, it does not distrust everyone).
func TestALyingHeightIsRotatedAwayFrom(t *testing.T) {
	v := startQuietValidator(t)

	liar := memberKey(v, 2)
	truth := memberKey(v, 1)
	v.recordHeight(liar, "v2", 1<<62) // signed by a member, unserveable
	v.recordHeight(truth, "v1", 3)    // a real peer, three blocks ahead

	type pick struct {
		who string
		via transport.PeerID
	}
	var picked []pick
	v.pull = func(from uint64) error {
		picked = append(picked, pick{who: string(v.sy.Expect), via: v.sy.Peer})
		if string(v.sy.Expect) == truth {
			// Substantiate the truthful member's attestation by actually
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
	if len(picked) != 1 || picked[0].who != liar || picked[0].via != "v2" {
		t.Fatalf("wave 1 pulled from %v, want the tallest attested member (seat 2 via v2)", picked)
	}
	v.maybeCatchUp()
	if len(picked) != 2 || picked[1].who != truth || picked[1].via != "v1" {
		t.Fatalf("wave 2 pulled from %v, want the truthful member (seat 1 via v1) after the liar was demoted - the lying height still monopolised the pull target", picked)
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
	who := memberKey(v, 2)
	v.recordHeight(who, "v9", 100)
	if p, via, h := v.tallestPeer(); p != who || via != "v9" || h == 0 {
		t.Fatalf("a freshly recorded height was not selectable: (%q via %q, %d)", p, via, h)
	}
	for i := 0; i < peerHeightTTL+1; i++ {
		v.beginWave()
	}
	if p, _, _ := v.tallestPeer(); p != "" {
		t.Fatalf("a peer height not refreshed for %d waves was still selected (%q)", peerHeightTTL+1, p)
	}
}

// TestOneMembersFailureDoesNotDemoteOthersBehindTheSameRelay is the F1
// granularity proof (round 7): on a relay every member arrives under the SAME
// transport name, so if selection and demotion are keyed on the name, one bad
// actor penalises every honest member behind that relay. Keyed on the signed
// member identity, the liar is demoted and the honest member sharing its relay
// name stays selectable.
func TestOneMembersFailureDoesNotDemoteOthersBehindTheSameRelay(t *testing.T) {
	v := startQuietValidator(t)
	liar := memberKey(v, 2)
	honest := memberKey(v, 1)

	// Both members announce through the ONE relay transport name.
	const relay = transport.PeerID("relay:198.51.100.7:9000")
	v.recordHeight(liar, relay, 100) // taller, but unserveable
	v.recordHeight(honest, relay, 3) // shorter, but real

	// The pull from the liar substantiates nothing (a silent relay stranger,
	// an unserveable height): the seam adopts nothing.
	v.pull = func(from uint64) error { return nil }
	v.maybeCatchUp()

	v.peerHMu.Lock()
	liarSt, honestSt := v.peerH[liar], v.peerH[honest]
	wave := v.wave
	v.peerHMu.Unlock()
	if liarSt == nil {
		t.Fatal("the lying member has no own entry: selection is keyed on the shared transport name, not the member identity")
	}
	if liarSt.demoted <= wave {
		t.Fatalf("the lying member was not demoted (demoted=%d wave=%d)", liarSt.demoted, wave)
	}
	if honestSt == nil {
		t.Fatal("the honest member has no own entry: selection is keyed on the shared transport name, not the member identity")
	}
	if honestSt.demoted != 0 {
		t.Fatalf("the HONEST member behind the same relay name was demoted (demoted=%d): one bad actor penalised its honest peers", honestSt.demoted)
	}
	// The honest member is still selectable, and still through the relay name.
	who, via, h := v.tallestPeer()
	if who != honest || via != relay || h == 0 {
		t.Fatalf("the honest member behind the relay was not selected after the liar's failure: (%q via %q, %d)", who, via, h)
	}
	// And the failure did not demote the shared transport name for everyone:
	// the honest member's entry carries no demotion to inherit.
	if honestSt.via != relay {
		t.Fatalf("the honest member's entry moved off the relay name (%q)", honestSt.via)
	}
}

// TestAChurningMemberCannotGrowThePeerTable is the F2 bound (round 7): the
// table is keyed on the SIGNED member identity, so one member replaying one
// signed HELLO over connection churn under arbitrarily many transport names
// still owns exactly ONE entry. The bound is the committee's size - a member
// cannot forge another member's key, so no actor can add an entry that is not
// a distinct committee seat - which is why the bound cannot starve an honest
// member: every honest member always has room for its own entry.
func TestAChurningMemberCannotGrowThePeerTable(t *testing.T) {
	v := startQuietValidator(t)
	member := memberKey(v, 2)
	for i := 0; i < 10_000; i++ {
		v.recordHeight(member, transport.PeerID("relay:10.0.0."+strconv.Itoa(i%256)+":9000"), 7)
	}
	v.peerHMu.Lock()
	got := len(v.peerH)
	v.peerHMu.Unlock()
	if got != 1 {
		t.Fatalf("a churning member grew the peer table to %d entries, want 1 (the table is bounded by the committee, not by transport names)", got)
	}
	// The whole committee can never exceed its own size.
	for seat := range v.g.Validators {
		v.recordHeight(memberKey(v, seat), transport.PeerID("relay:10.0.0.1:9000"), uint64(seat+1))
	}
	v.peerHMu.Lock()
	got = len(v.peerH)
	v.peerHMu.Unlock()
	if got > len(v.g.Validators) {
		t.Fatalf("the peer table holds %d entries for a %d-member committee: the bound is not the committee size", got, len(v.g.Validators))
	}
}

// TestExpiredPeerEntriesArePruned is the other half of F2: an entry whose
// announcement has expired is deleted, so the table tracks the members
// actually heard from rather than every member ever heard.
func TestExpiredPeerEntriesArePruned(t *testing.T) {
	v := startQuietValidator(t)
	v.recordHeight(memberKey(v, 1), "v1", 3)
	v.recordHeight(memberKey(v, 2), "v2", 4)
	for i := 0; i <= peerHeightTTL; i++ {
		v.beginWave()
	}
	// A fresh announcement prunes the two stale ones as a side effect.
	v.recordHeight(memberKey(v, 0), "v0", 5)
	v.peerHMu.Lock()
	got := len(v.peerH)
	v.peerHMu.Unlock()
	if got != 1 {
		t.Fatalf("after expiry the peer table holds %d entries, want 1 (the two stale entries should be pruned)", got)
	}
}

// TestADemotionKeepsTheHighWaterMark is the F3 proof (round 7): substantiated
// means "the highest height a pull from this member reached", so a transient
// failure must not overwrite it downward. Constructed directly: a member that
// proved height 5, then failed a pull that reached only 2, must still hold 5.
func TestADemotionKeepsTheHighWaterMark(t *testing.T) {
	v := startQuietValidator(t)
	who := memberKey(v, 1)
	v.recordHeight(who, "v1", 5)
	v.substantiatePeer(who, 5)

	v.beginWave()
	v.demotePeer(who, 2) // a transient failure whose pull reached only height 2

	v.peerHMu.Lock()
	st := v.peerH[who]
	got, demoted := st.substantiated, st.demoted
	wave := v.wave
	v.peerHMu.Unlock()
	if got != 5 {
		t.Fatalf("a transient failure dropped the member's substantiated high-water mark to %d, want 5: the selection cap collapsed with it", got)
	}
	if demoted <= wave {
		t.Fatalf("the failure did not demote the member (demoted=%d wave=%d)", demoted, wave)
	}
	// After the demotion lapses, the cap still reflects the proven height:
	// the member is selectable for at least what it once served. Its HELLO
	// keeps arriving each wave (so the entry does not expire), but a fresh
	// HELLO must not clear the demotion.
	for i := uint64(0); i < peerDemoteWaves+1; i++ {
		v.beginWave()
		v.recordHeight(who, "v1", 5)
	}
	_, _, h := v.tallestPeer()
	if h < 5 {
		t.Fatalf("after the demotion lapsed the member was capped at %d, want at least its proven 5", h)
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
