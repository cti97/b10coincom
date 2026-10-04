package devnet

// The WIRE proof, brief Task 6 Step 1. The simulator proves the PROTOCOL; this
// proves the WIRE: four validators, four real TCP connections on 127.0.0.1, one
// process — the same consensus code (Driver over Engine), the same catch-up
// (Syncer) and the same node-layer wiring the CLI's --peers path runs on the
// Pis, over sockets instead of a virtual network.
//
// What each test names, and the one thing that must break for it to fail (the
// mutants are compiled, placed, run and reported in task-6-report.md):
//
//   - TestFourValidatorsFinaliseOverRealTCP — consensus frames must reach the
//     engine over sockets. The vote/wire tag collision (both namespaces use
//     1/2/3) means a router that routes by a bare tag comparison, or that
//     never hands consensus frames to the driver at all, starves the engine
//     and the run never reaches the target.
//   - TestAValidatorThatJoinsLateCatchesUpOverTCP — the HELLO-driven
//     catch-up wave plus the post-adoption driver rebuild. A late joiner
//     stands at height 0 against peers at height >= 6; no peer's engine will
//     vote at its height 1 (messages carry heights, and the peers have moved
//     on), so the ONLY path up is an adopted, certificate-gated pull —
//     without catch-up, or without the rebuild that re-arms the engine at the
//     adopted head, the joiner parks forever.
//   - TestFourValidatorsFinaliseThroughTheRelayStar — the relay integration:
//     validators dial OUT to one dumb forwarder (the topology the Pi run will
//     actually use). A runtime or CLI mutant that drops the relay dial leaves
//     an empty peer set and heights frozen at 0.

import (
	"testing"
	"time"

	"github.com/cti97/b10coincom/internal/relay"
)

// startListening starts one networked validator listening on its own loopback
// port, dialing nothing: the caller collects the whole committee's addresses
// first, then connectMesh joins them in a full mesh.
func startListening(t *testing.T, index, total int) *Validator {
	t.Helper()
	v, err := StartValidator(ValidatorConfig{
		Dir:        t.TempDir(),
		Index:      index,
		Validators: total,
		Listen:     "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("starting validator %d: %v", index, err)
	}
	return v
}

// connectMesh dials every other validator's listener from every validator.
// The transports' own cross-dial duplicate resolution (the identical rank at
// both ends) is what leaves exactly one healthy link per pair.
func connectMesh(vs []*Validator) error {
	for i, v := range vs {
		var addrs []string
		for j, w := range vs {
			if i != j {
				addrs = append(addrs, w.Addr())
			}
		}
		if err := v.Connect(addrs...); err != nil {
			return err
		}
	}
	return nil
}

// closeAll tears every validator down; it tolerates nil slots so a deferred
// call is safe while one is still being started.
func closeAll(vs []*Validator) {
	for _, v := range vs {
		if v != nil {
			_ = v.Close()
		}
	}
}

func heightsOf(vs []*Validator) []uint64 {
	out := make([]uint64, len(vs))
	for i, v := range vs {
		out[i] = v.Height()
	}
	return out
}

func minMax(hs []uint64) (min, max uint64) {
	min, max = hs[0], hs[0]
	for _, h := range hs[1:] {
		if h < min {
			min = h
		}
		if h > max {
			max = h
		}
	}
	return min, max
}

// waitAllReach polls until every validator named by the slice stands at or
// above target.
func waitAllReach(t *testing.T, vs []*Validator, target uint64, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		hs := heightsOf(vs)
		if min, _ := minMax(hs); min >= target {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("validators did not reach height %d in %s; heights %v", target, timeout, hs)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// waitConvergedEqual polls until every validator stands at ONE height H with
// H >= target, and returns H. EQUALITY — not merely "all at or past target" —
// is the convergence claim: a validator that fell behind must have adopted
// the blocks it missed, because catch-up is the only way a shorter history
// meets a longer one at the same height on a live network.
func waitConvergedEqual(t *testing.T, vs []*Validator, target uint64, timeout time.Duration) uint64 {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		hs := heightsOf(vs)
		if min, max := minMax(hs); min == max && min >= target {
			return min
		}
		if time.Now().After(deadline) {
			t.Fatalf("the committee did not converge to a common height >= %d in %s; heights %v", target, timeout, hs)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// waitAdopted polls until the validator has adopted at least want blocks.
// The counter trails its own chain by microseconds — the wave's add runs
// when the whole pull returns, and a height the chain already holds is
// visible within that same tick — so this is bounded patience over an
// eventually-consistent pair, not a sleep-and-hope.
func waitAdopted(t *testing.T, v *Validator, want uint64, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if got := v.BlocksAdopted(); got >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("validator adopted only %d blocks within %s (want >= %d); catch-up did not carry it up", v.BlocksAdopted(), timeout, want)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// assertVotesAtOrAbove polls until the validator's own outgoing votes include
// one at or above `height`: the returning member's weight is back in the
// consensus at the committee's current height, not a passenger learning by
// pull while its stale engine votes at a long-past height.
func assertVotesAtOrAbove(t *testing.T, v *Validator, height uint64, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		for _, vh := range v.VotedHeights() {
			if vh >= height {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no outgoing vote at or above height %d within %s: the returning member's vote-weight is not back in the tally", height, timeout)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// assertIdenticalHistory requires every validator to hold the identical block
// at every height 0..through: the per-height agreement walk, over real
// sockets. A fork at ANY committed height — the safety property — fails here
// by name.
func assertIdenticalHistory(t *testing.T, vs []*Validator, through uint64) {
	t.Helper()
	for h := uint64(0); h <= through; h++ {
		ref, err := vs[0].Chain().BlockAt(h)
		if err != nil {
			t.Fatalf("reading validator 0 at height %d: %v", h, err)
		}
		for i, v := range vs[1:] {
			b, err := v.Chain().BlockAt(h)
			if err != nil {
				t.Fatalf("reading validator %d at height %d: %v", i+1, h, err)
			}
			if b.ID() != ref.ID() {
				id1, id2 := ref.ID(), b.ID()
				t.Fatalf("SAFETY VIOLATION: validators 0 and %d hold conflicting blocks at height %d: %x vs %x",
					i+1, h, id1[:8], id2[:8])
			}
		}
	}
}

// The brief's flagship: four validators, four real TCP connections (a full
// mesh of 127.0.0.1:0 listeners and dials), one process, finalising 20 blocks
// and agreeing on every one of them.
func TestFourValidatorsFinaliseOverRealTCP(t *testing.T) {
	vs := make([]*Validator, 4)
	for i := range vs {
		vs[i] = startListening(t, i, 4)
	}
	defer closeAll(vs)
	if err := connectMesh(vs); err != nil {
		t.Fatal(err)
	}

	h := waitConvergedEqual(t, vs, 20, 90*time.Second)
	assertIdenticalHistory(t, vs, h)
}

// A validator that misses blocks catches up and converges — M3's deferred
// scenario 1, now over sockets. Three validators mesh and commit; the fourth
// joins AFTER with an empty chain. Its engine's height-1 rounds can never
// reach quorum against peers already at 6+, so convergence proves the
// catch-up path (HELLO heights -> pull -> certificate-gated adoption ->
// driver rebuild), not the round protocol.
func TestAValidatorThatJoinsLateCatchesUpOverTCP(t *testing.T) {
	vs := make([]*Validator, 4)
	for i := 0; i < 3; i++ {
		vs[i] = startListening(t, i, 4)
	}
	defer closeAll(vs)
	if err := connectMesh(vs[:3]); err != nil {
		t.Fatal(err)
	}
	waitAllReach(t, vs[:3], 6, 60*time.Second)

	late, err := StartValidator(ValidatorConfig{
		Dir:        t.TempDir(),
		Index:      3,
		Validators: 4,
		Listen:     "127.0.0.1:0",
	})
	if err != nil {
		t.Fatal(err)
	}
	vs[3] = late
	addrs := make([]string, 0, 3)
	for _, v := range vs[:3] {
		addrs = append(addrs, v.Addr())
	}
	if err := late.Connect(addrs...); err != nil {
		t.Fatal(err)
	}

	// The late joiner converges to the SAME height the committee is at.
	h := waitConvergedEqual(t, vs, 8, 120*time.Second)

	// And it got there by ADOPTING the committee's blocks, not by its own
	// consensus, which an empty chain joining a taller committee cannot run:
	// no peer's engine accepts another height, so nobody votes at its height
	// 1. (The counter trails the chain by microseconds - poll it.)
	waitAdopted(t, late, 1, 5*time.Second)

	// And it is a MEMBER again, not a spectator that happened to sync. Two
	// legs name it:
	//   - the whole committee, rebuilt engine included, keeps committing;
	//   - the returning member VOTES AT THE COMMITTEE'S CURRENT HEIGHT again.
	// The second is the leg that pins the rebuild: a rebuild-skip mutant
	// stays a PASSENGER - its chain keeps up through catch-up pulls forever
	// (every wave adopts what it is missing), so heights alone cannot tell
	// the shapes apart, but its vote-weight is permanently out of the tally:
	// its engine still votes only at the height it parked at.
	waitAllReach(t, vs, h+6, 120*time.Second)
	assertIdenticalHistory(t, vs, h+6)
	assertVotesAtOrAbove(t, late, uint64(h), 120*time.Second)
}

// Four validators through the relay star — the topology the Pi run will use.
// Every validator dials OUT to one dumb forwarder and consensus flows over
// the forwarded stream; the fourth joins late through the same relay and
// must catch up over it too, first-response-filed-wins with every answer
// certificate-gated.
func TestFourValidatorsFinaliseThroughTheRelayStar(t *testing.T) {
	rl := relay.New(relay.Options{})
	defer rl.Close()
	if err := rl.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	raddr := rl.Addr().String()

	vs := make([]*Validator, 4)
	for i := 0; i < 3; i++ {
		v, err := StartValidator(ValidatorConfig{Dir: t.TempDir(), Index: i, Validators: 4})
		if err != nil {
			t.Fatal(err)
		}
		vs[i] = v
		if err := v.Connect(raddr); err != nil {
			t.Fatal(err)
		}
	}
	defer closeAll(vs)
	waitAllReach(t, vs[:3], 4, 120*time.Second)

	late, err := StartValidator(ValidatorConfig{Dir: t.TempDir(), Index: 3, Validators: 4})
	if err != nil {
		t.Fatal(err)
	}
	vs[3] = late
	if err := late.Connect(raddr); err != nil {
		t.Fatal(err)
	}

	h := waitConvergedEqual(t, vs, 6, 150*time.Second)
	// (The counter trails the chain by microseconds - poll it.)
	waitAdopted(t, late, 1, 5*time.Second)
	// And it is a MEMBER again through the same relay: the committee keeps
	// committing and the returned member votes at the current height again
	// (the passenger-shape killer; see the mesh test's note).
	waitAllReach(t, vs, h+6, 150*time.Second)
	assertIdenticalHistory(t, vs, h+6)
	assertVotesAtOrAbove(t, late, uint64(h), 150*time.Second)
}

// A validator shutting down UNDER TRAFFIC must not tear the chain out from
// under a dispatch that is mid-flight: a socket transport's reader goroutine
// exits only when its sockets die, which is after Close began, and a last
// persisted-lock write attempted against an already-closed chain store fails
// (and panics, by the persistence rule). The closing gate is the fix; this
// test is its regression pin: three rounds of committee traffic with one
// member closing mid-traffic, its Close returning cleanly, the survivors
// re-meshing afterwards.
//
// Killing mutant (compiled): the closing gate removed (route stops checking,
// Close stops flagging) — the race re-opens; under -race with repeat runs the
// panicking persistLock kills the test process, which IS the failure.
func TestValidatorCloseUnderTrafficDoesNotTearTheChain(t *testing.T) {
	for round := 0; round < 3; round++ {
		vs := make([]*Validator, 4)
		for i := range vs {
			vs[i] = startListening(t, i, 4)
		}
		if err := connectMesh(vs); err != nil {
			t.Fatal(err)
		}
		// Let real traffic hot up: some heights committed, votes flying.
		waitAllReach(t, vs, 3, 60*time.Second)

		// Close one member while the committee is committing.
		if err := vs[2].Close(); err != nil {
			t.Fatalf("round %d: the closing validator returned %v; a shutdown race would have panicked the process instead", round, err)
		}
		// Its chain must be closed and its height final.
		finalHeight := vs[2].Height()
		if finalHeight == 0 {
			t.Fatalf("round %d: validator 2 closed with an empty chain; the test closed too early to be meaningful", round)
		}
		if h := vs[2].Height(); h != finalHeight {
			t.Fatalf("round %d: validator 2's height moved %d -> %d after Close", round, finalHeight, h)
		}
		// The survivors must not care (their maintainer reconnects it; a
		// dead peer is a dropped frame, and the committee carries on).
		waitAllReach(t, []*Validator{vs[0], vs[1], vs[3]}, finalHeight+2, 90*time.Second)
		closeAll(vs)
	}
}
