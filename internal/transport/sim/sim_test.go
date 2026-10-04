package sim

import (
	"fmt"
	"sort"
	"testing"
	"time"
)

// collect returns a helper that records every message a peer receives.
func collect(n *Net, id string) *[]string {
	got := new([]string)
	n.TransportFor(id).OnMessage(func(m Message) {
		*got = append(*got, string(m.Data))
	})
	return got
}

// The core promise of the simulator, pinned from both sides:
//
//  1. The same seed replays identically, so a failing scenario can be replayed
//     exactly.
//  2. The seed actually DRIVES the draws: two different seeds must produce
//     different delivery orders. Side 1 alone proves only that two runs agree —
//     a mutant that never applies jitter (at += 0) passed it 30/30, because two
//     runs of any deterministic implementation always agree.
//
// Why these parameters make side 2 meaningful: eleven peers, ten of which each
// broadcast one distinct message to "a" before time advances. Every arrival at
// "a" is 10ms plus an independent nanosecond-granularity draw from a 5ms
// window, so exact ties essentially cannot occur and the arrival order at "a"
// is the rank order of 10 independent draws — one of 10! ≈ 3.6M equally likely
// orders per seed. Two fixed seeds colliding is therefore ≈ 3e-7 per asserted
// pair (≈ 2e-20 across the three pairs below), and if a pair ever does collide
// the test FAILS rather than skipping. A no-jitter implementation cannot pass
// at all: with every arrival at exactly Latency, the (at, seq) tie-break makes
// arrival order equal send order for every seed, so the different-seeds
// assertion fails deterministically.
func TestSameSeedReplaysIdentically(t *testing.T) {
	senders := []string{"b", "c", "d", "e", "f", "g", "h", "i", "j", "k"}
	run := func(seed int64) []string {
		n := New(Options{Seed: seed, Latency: 10 * time.Millisecond, Jitter: 5 * time.Millisecond})
		for _, id := range append([]string{"a"}, senders...) {
			n.AddPeer(id)
		}
		var seen []string
		n.TransportFor("a").OnMessage(func(m Message) { seen = append(seen, string(m.Data)) })
		for i, id := range senders {
			n.TransportFor(id).Broadcast([]byte(fmt.Sprintf("m%d-from-%s", i, id)))
		}
		n.Advance(time.Second)
		return seen
	}

	// Side 1: same seed, byte-identical replay.
	first, second := run(42), run(42)
	if fmt.Sprint(first) != fmt.Sprint(second) {
		t.Fatalf("same seed diverged:\n %v\n %v", first, second)
	}
	if len(first) != len(senders) {
		t.Fatalf("expected %d deliveries, got %d", len(senders), len(first))
	}

	// Side 2: the seed drives the draws. Cache per-seed orders; every pair
	// below must differ.
	orders := map[int64][]string{42: first, 43: run(43), 44: run(44)}
	for _, pair := range [][2]int64{{42, 43}, {42, 44}, {43, 44}} {
		if fmt.Sprint(orders[pair[0]]) == fmt.Sprint(orders[pair[1]]) {
			t.Fatalf("seeds %d and %d produced the SAME delivery order %v: the seed is not driving the draws (a no-jitter implementation would pass here)", pair[0], pair[1], orders[pair[0]])
		}
	}
}

func TestBroadcastSkipsTheSender(t *testing.T) {
	n := New(Options{Seed: 1, Latency: time.Millisecond})
	for _, id := range []string{"a", "b"} {
		n.AddPeer(id)
	}
	gotA := collect(n, "a")
	gotB := collect(n, "b")
	n.TransportFor("a").Broadcast([]byte("hello"))
	n.Advance(50 * time.Millisecond)

	if len(*gotA) != 0 {
		t.Fatalf("the sender received its own broadcast: %v", *gotA)
	}
	if len(*gotB) != 1 || (*gotB)[0] != "hello" {
		t.Fatalf("the peer did not receive the broadcast: %v", *gotB)
	}
}

// 100% loss must deliver nothing, which is how a scenario takes a validator
// fully offline without removing it from the peer set.
func TestFullPacketLossDeliversNothing(t *testing.T) {
	n := New(Options{Seed: 7, Latency: time.Millisecond, DropPercent: 100})
	for _, id := range []string{"a", "b"} {
		n.AddPeer(id)
	}
	got := collect(n, "b")
	for i := 0; i < 20; i++ {
		n.TransportFor("a").Broadcast([]byte("dropped"))
	}
	n.Advance(time.Second)
	if len(*got) != 0 {
		t.Fatalf("messages were delivered under 100%% loss: %v", *got)
	}
}

// A partition must cut the two groups apart, and healing it must restore delivery.
func TestPartitionCutsDeliveryAndHeals(t *testing.T) {
	n := New(Options{Seed: 3, Latency: time.Millisecond})
	for _, id := range []string{"a", "b", "c"} {
		n.AddPeer(id)
	}
	gotA := collect(n, "a")

	n.Partition([]string{"a"}, []string{"b", "c"})
	n.TransportFor("b").Broadcast([]byte("blocked"))
	n.Advance(50 * time.Millisecond)
	if len(*gotA) != 0 {
		t.Fatalf("a message crossed a partition: %v", *gotA)
	}

	n.Heal()
	n.TransportFor("b").Broadcast([]byte("through"))
	n.Advance(50 * time.Millisecond)
	if len(*gotA) != 1 || (*gotA)[0] != "through" {
		t.Fatalf("delivery did not resume after healing: %v", *gotA)
	}
}

// Broadcast must not deliver synchronously: a transport that re-entered the
// caller during Broadcast would make consensus's transition order depend on the
// transport's internals.
func TestBroadcastDoesNotDeliverSynchronously(t *testing.T) {
	n := New(Options{Seed: 5, Latency: 0})
	for _, id := range []string{"a", "b"} {
		n.AddPeer(id)
	}
	got := collect(n, "b")
	n.TransportFor("a").Broadcast([]byte("now"))
	if len(*got) != 0 {
		t.Fatal("Broadcast delivered synchronously; it must queue")
	}
	n.Advance(time.Millisecond)
	if len(*got) != 1 {
		t.Fatal("the queued message was never delivered")
	}
}

// The Transport contract requires a deterministically ordered Peers(): consensus
// will iterate peers by position, so neither map iteration randomness nor
// AddPeer insertion order may reach the returned slice. This pins sortedness,
// call-to-call stability, and insertion-order independence.
func TestPeersIsSortedStableAndInsertionOrderIndependent(t *testing.T) {
	set := []string{"p9", "p4", "p0", "p7", "p2", "p6", "p1", "p8", "p3", "p5"}
	build := func(order []string) *Net {
		n := New(Options{Seed: 12})
		for _, id := range order {
			n.AddPeer(id)
		}
		return n
	}
	forward := build(set)
	backward := make([]string, len(set))
	for i, id := range set {
		backward[len(set)-1-i] = id
	}
	reverse := build(backward)

	for _, me := range []string{"p0", "p4", "p9"} {
		want := append([]string(nil), set...)
		sort.Strings(want)
		for i, id := range want {
			if id == me {
				want = append(want[:i], want[i+1:]...)
				break
			}
		}

		got := forward.TransportFor(me).Peers()
		if len(got) != len(set)-1 {
			t.Fatalf("Peers() for %q returned %d peers, want %d (everyone except self)", me, len(got), len(set)-1)
		}
		for i := range want {
			if string(got[i]) != want[i] {
				t.Fatalf("Peers() for %q = %v, want sorted %v", me, got, want)
			}
		}
		for call := 0; call < 10; call++ {
			if again := forward.TransportFor(me).Peers(); fmt.Sprint(again) != fmt.Sprint(got) {
				t.Fatalf("Peers() for %q changed between calls: %v then %v", me, got, again)
			}
		}
		if other := reverse.TransportFor(me).Peers(); fmt.Sprint(other) != fmt.Sprint(got) {
			t.Fatalf("Peers() for %q depended on AddPeer insertion order: %v vs %v", me, got, other)
		}
	}
}

// Now() must be pure virtual time: it moves only when Advance moves it and
// never reads the wall clock, or a scenario's schedule would depend on how long
// the process happened to take. The one short real sleep below is the point of
// the test: real time passes, the reported time must not move.
func TestNowIsVirtualTimeOnly(t *testing.T) {
	n := New(Options{Seed: 2, Latency: 10 * time.Millisecond, Jitter: 2 * time.Millisecond})
	for _, id := range []string{"a", "b", "c"} {
		n.AddPeer(id)
	}
	got := collect(n, "b")

	if n.Now() != 0 {
		t.Fatalf("a fresh network reports Now()==%v, want 0", n.Now())
	}
	n.TransportFor("a").Broadcast([]byte("m"))
	if n.Now() != 0 {
		t.Fatalf("Broadcast moved virtual time to %v", n.Now())
	}

	time.Sleep(25 * time.Millisecond)
	if n.Now() != 0 {
		t.Fatalf("Now() reached %v without Advance: it is reading the wall clock", n.Now())
	}

	n.Advance(0)
	if n.Now() != 0 {
		t.Fatalf("Advance(0) moved Now() to %v", n.Now())
	}

	n.Advance(250 * time.Millisecond)
	if n.Now() != 250*time.Millisecond {
		t.Fatalf("after Advance(250ms) Now() is %v, want exactly 250ms", n.Now())
	}
	if len(*got) != 1 {
		t.Fatalf("the message was not delivered within the Advance window: %v", *got)
	}
}

// TestSendIsTheUnicastSyncNeeds: one named peer receives the payload, at the
// very next Advance (stamped at virtual now, no latency window), everyone
// else receives nothing, and an unknown or partitioned peer is an error
// rather than a silently swallowed message.
func TestSendIsTheUnicastSyncNeeds(t *testing.T) {
	n := New(Options{Seed: 1, Latency: time.Millisecond, Jitter: 2 * time.Millisecond})
	for _, id := range []string{"a", "b", "c"} {
		n.AddPeer(id)
	}
	gotA, gotC := collect(n, "a"), collect(n, "c")

	// Not synchronous: the same re-entry rule as Broadcast applies to Send,
	// because the driver sends mid-step.
	n.TransportFor("b").Send("a", []byte("uni"))
	if len(*gotA) != 0 {
		t.Fatal("Send delivered synchronously; it must queue")
	}
	n.Advance(50 * time.Millisecond)
	if len(*gotA) != 1 || (*gotA)[0] != "uni" {
		t.Fatalf("a did not receive the unicast: %v", *gotA)
	}
	if len(*gotC) != 0 {
		t.Fatalf("unicast reached a bystander: %v", *gotC)
	}

	if err := n.TransportFor("a").Send("nobody", []byte("?")); err == nil {
		t.Fatal("Send to an unknown peer must error, never silently succeed")
	}

	// The local endpoint is not a peer either - the TCP transport errors on
	// Send to self (a validator never messages itself over the wire), so the
	// sim must agree: the two transports have to be interchangeable.
	if err := n.TransportFor("a").Send("a", []byte("?")); err == nil {
		t.Fatal("Send to self must error, matching the TCP transport")
	}

	// A partition is a partition for Send too: b cannot sync from a peer on
	// the far side of it.
	n.Partition([]string{"c"}, []string{"a", "b"})
	if err := n.TransportFor("b").Send("c", []byte("?")); err == nil {
		t.Fatal("Send across a partition must error, not drop invisibly")
	}
	n.Advance(50 * time.Millisecond)
	if len(*gotC) != 0 {
		t.Fatalf("a unicast crossed a partition: %v", *gotC)
	}
}

// TestSendConsumesNoRandomness pins the determinism promise the sim's Send
// doc makes: a unicast consumes NO rng draw (no latency, no jitter, no loss),
// so adding Sends to a scenario cannot shift any other delivery. The same
// seed, one network with 50 Sends and one without: the broadcast's arrival
// must be byte-identical, including its virtual delivery time.
func TestSendConsumesNoRandomness(t *testing.T) {
	type arrival struct {
		at   time.Duration
		data string
	}
	run := func(withSends bool) []arrival {
		n := New(Options{Seed: 7, Latency: 10 * time.Millisecond, Jitter: 5 * time.Millisecond})
		for _, id := range []string{"a", "b"} {
			n.AddPeer(id)
		}
		var out []arrival
		n.TransportFor("a").OnMessage(func(m Message) {
			out = append(out, arrival{n.Now(), string(m.Data)})
		})
		if withSends {
			for i := 0; i < 50; i++ {
				if err := n.TransportFor("b").Send("a", []byte("u")); err != nil {
					t.Fatal(err)
				}
			}
		}
		n.TransportFor("b").Broadcast([]byte("m"))
		n.Advance(time.Second)
		return out
	}
	with, without := run(true), run(false)

	// The broadcast arrives identically in both runs - same time, same order
	// - despite 50 extra unicasts beforehand. Any rng consumption in Send
	// would have shifted the broadcast's jitter draw and its arrival.
	broadcastWith, broadcastWithout := ([]arrival)(nil), ([]arrival)(nil)
	unicasts := 0
	for _, ar := range with {
		if ar.data == "m" {
			broadcastWith = append(broadcastWith, ar)
		} else {
			unicasts++
		}
	}
	for _, ar := range without {
		if ar.data == "m" {
			broadcastWithout = append(broadcastWithout, ar)
		}
	}
	if unicasts != 50 {
		t.Fatalf("want 50 unicast deliveries, got %d", unicasts)
	}
	if fmt.Sprint(broadcastWith) != fmt.Sprint(broadcastWithout) || len(broadcastWith) != 1 {
		t.Fatalf("the broadcast's arrival changed when Sends were added: %v vs %v - Send consumed randomness", broadcastWith, broadcastWithout)
	}
	// The unicast is immediate: stamped at now (0), so every one delivers
	// before the broadcast's latency+jitter window can.
	if with[0].data != "u" || with[49].data != "u" || with[0].at != 0 || with[49].at != 0 {
		t.Fatalf("unicasts did not deliver at virtual now in send order: %v then %v", with[0], with[49])
	}
	if with[50].data != "m" {
		t.Fatalf("the broadcast did not follow the unicasts: %v", with[50])
	}
}
