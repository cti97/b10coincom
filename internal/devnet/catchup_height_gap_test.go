package devnet

// THE OBSERVED-CASE TEST (2026-11-15): a validator one block behind its
// committee.
//
// Found on real hardware: three validators, quorum 3 of 3, one wiped. Two at
// height 1, the wiped one at height 0, and its own diagnostic said
//
//	peers=2[seat0/relay:... h=1, seat1/relay:... h=1]
//	no block for 25 rounds at height 0 (round 25, step propose): ...
//	tallies r24: proposal=absent; prevote votes=1 power=1 quorum=3 nil=1
//
// It knew both peers were at height 1 and could neither commit at height 0 nor
// obtain block 1 from them. The live run could not be diagnosed from the
// outside, so this is the same shape in the harness: it distinguishes "the
// catch-up path covers one-height gaps" from "it does not" with the wire, the
// certificate gate and the driver rebuild all real.
//
// WHAT IS PINNED, in order:
//
//  1. the wiped seat ADOPTS block 1 from a peer (BlocksAdopted, and its height
//     and block 1 are the committee's) - this is the mechanism the live node
//     needed;
//  2. it re-enters consensus over the adopted head and the committee commits
//     again (height 2 is only reachable with quorum 3 of 3), which is the
//     rebuild that keeps it from being a passenger at a stale height.
//
// The gap is ONE HEIGHT on purpose: the round ladder closes divergence in
// ROUNDS at one height (driver.go's Tick comment), and nothing in it can close
// a missing BLOCK - so if this fails, the node has no other way up and the gap
// is permanent, exactly as observed.

import (
	"testing"
	"time"

	"github.com/cti97/b10coincom/internal/relay"
)

// restartWiped returns a validator for the same SEAT (seat, of total seats) in
// a FRESH data directory, after wiping the old one: the "wiped node" of the
// live run, with the same key (the fixture key is derived from the seat) and
// no history at all.
func restartWiped(t *testing.T, seat, total int) *Validator {
	t.Helper()
	dir := t.TempDir()
	v, err := StartValidator(ValidatorConfig{
		Dir:        dir,
		Index:      seat,
		Validators: total,
		Listen:     "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("restarting seat %d on a wiped directory: %v", seat, err)
	}
	return v
}

// TestAWipedValidatorOneHeightBehindCatchesUp is the live observation, in the
// harness. A committee of 3 (quorum 3, so NO block commits without all three)
// reaches height 1; seat 2 is closed and its directory wiped; it comes back at
// height 0 while its peers stand at 1 and are parked there because the quorum
// is exactly the three seats.
func TestAWipedValidatorOneHeightBehindCatchesUp(t *testing.T) {
	const seats = 3
	vs := make([]*Validator, seats)
	for i := 0; i < seats; i++ {
		vs[i] = startListening(t, i, seats)
	}
	defer closeAll(vs)
	if err := connectMesh(vs); err != nil {
		t.Fatal(err)
	}
	// Height 1 exists only because ALL THREE committed it: this is the
	// quorum-3-of-3 shape, and it is the one the live run had.
	waitAllReach(t, vs, 1, 60*time.Second)

	// The wipe: seat 2 goes away with its directory, and returns empty.
	if err := vs[2].Close(); err != nil {
		t.Fatalf("closing seat 2: %v", err)
	}
	vs[2] = restartWiped(t, 2, seats)
	if got := vs[2].Height(); got != 0 {
		t.Fatalf("the wiped seat started at height %d, want 0", got)
	}
	if err := vs[2].Connect(vs[0].Addr(), vs[1].Addr()); err != nil {
		t.Fatal(err)
	}

	// 1. THE ADOPTION. The peers are at height 1 and their engines judge
	// height 2, so no live vote will ever reach the wiped seat's height-1
	// rounds: block 1 can only arrive through a certificate-gated pull.
	waitAdopted(t, vs[2], 1, 30*time.Second)
	if got := vs[2].Height(); got != 1 {
		t.Fatalf("the wiped seat stands at height %d after adopting, want 1", got)
	}
	ref, err := vs[0].Chain().BlockAt(1)
	if err != nil {
		t.Fatal(err)
	}
	got, err := vs[2].Chain().BlockAt(1)
	if err != nil {
		t.Fatalf("the adopted block 1: %v", err)
	}
	gid, rid := got.ID(), ref.ID()
	if gid != rid {
		t.Fatalf("the wiped seat adopted block %x at height 1, but the committee holds %x", gid[:8], rid[:8])
	}
	if root, want := vs[2].Chain().State().Root(), vs[0].Chain().State().Root(); root != want {
		t.Fatalf("the wiped seat's state root after adopting = %x, want %x", root[:8], want[:8])
	}
	assertIdenticalHistory(t, vs, 1)

	// 2. THE RE-ENTRY. Block 2 needs all three seats, so the committee moving
	// again proves the adopted head became a live engine's head - not a
	// passenger that syncs while voting at a height nobody judges.
	waitAllReach(t, vs, 2, 120*time.Second)
	assertIdenticalHistory(t, vs, 2)
}

// TestAWipedValidatorOneHeightBehindThroughARelay is the same shape over the
// topology the live run used: every seat dials OUT to one dumb relay, so each
// member arrives under the single relay:<addr> name and a BLOCK_SYNC answer has
// to be attributed by its signed envelope rather than by a transport name
// (round 7, F1). The live diagnostic listed both peers as seatN/relay:..., so
// this is the variant that matches it; the mesh test above isolates the same
// mechanism where the transport name is real.
func TestAWipedValidatorOneHeightBehindThroughARelay(t *testing.T) {
	const seats = 3
	rl := relay.New(relay.Options{})
	defer rl.Close()
	if err := rl.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	raddr := rl.Addr().String()

	vs := make([]*Validator, seats)
	for i := 0; i < seats; i++ {
		v, err := StartValidator(ValidatorConfig{Dir: t.TempDir(), Index: i, Validators: seats})
		if err != nil {
			t.Fatalf("starting seat %d: %v", i, err)
		}
		vs[i] = v
		if err := v.ConnectRelay(raddr); err != nil {
			t.Fatalf("seat %d dialling the relay: %v", i, err)
		}
	}
	defer closeAll(vs)
	waitAllReach(t, vs, 1, 60*time.Second)

	if err := vs[2].Close(); err != nil {
		t.Fatalf("closing seat 2: %v", err)
	}
	vs[2] = restartWiped(t, 2, seats)
	if err := vs[2].ConnectRelay(raddr); err != nil {
		t.Fatalf("the wiped seat re-dialling the relay: %v", err)
	}

	waitAdopted(t, vs[2], 1, 30*time.Second)
	if got := vs[2].Height(); got != 1 {
		t.Fatalf("the wiped seat stands at height %d after adopting through the relay, want 1", got)
	}
	assertIdenticalHistory(t, vs, 1)
	waitAllReach(t, vs, 2, 120*time.Second)
	assertIdenticalHistory(t, vs, 2)
}

// TestAWipedValidatorCatchesUpAfterItsPeersRanTheLadder is the live TIMING, not
// just the live shape: the wiped seat returns after its peers have spent a
// while climbing the timeout ladder at the next height (the live node was at
// round 25 when it printed, so the peers' engines were deep into their own
// ladder at height 2). If the pull depended on the peers being near round 0 -
// or on their engines still being near the gap - this is where it would show.
func TestAWipedValidatorCatchesUpAfterItsPeersRanTheLadder(t *testing.T) {
	const seats = 3
	vs := make([]*Validator, seats)
	for i := 0; i < seats; i++ {
		vs[i] = startListening(t, i, seats)
	}
	defer closeAll(vs)
	if err := connectMesh(vs); err != nil {
		t.Fatal(err)
	}
	waitAllReach(t, vs, 1, 60*time.Second)

	if err := vs[2].Close(); err != nil {
		t.Fatalf("closing seat 2: %v", err)
	}
	vs[2] = nil
	// The peers now sit at height 2 with no quorum (the wiped seat IS the
	// quorum), climbing rounds. Long enough to be well past the eight-round
	// stall threshold and into the tens of rounds, as the live node was.
	time.Sleep(30 * time.Second)

	vs[2] = restartWiped(t, 2, seats)
	if err := vs[2].Connect(vs[0].Addr(), vs[1].Addr()); err != nil {
		t.Fatal(err)
	}
	waitAdopted(t, vs[2], 1, 30*time.Second)
	if got := vs[2].Height(); got != 1 {
		t.Fatalf("the wiped seat stands at height %d after adopting, want 1", got)
	}
	assertIdenticalHistory(t, vs, 1)
}
