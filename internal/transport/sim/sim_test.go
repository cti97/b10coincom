package sim

import (
	"fmt"
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

// The whole point of the simulator: the same seed produces the same delivery
// order, so a failing consensus run can be replayed exactly.
func TestSameSeedReplaysIdentically(t *testing.T) {
	run := func() []string {
		n := New(Options{Seed: 42, Latency: 10 * time.Millisecond, Jitter: 5 * time.Millisecond})
		for _, id := range []string{"a", "b", "c", "d"} {
			n.AddPeer(id)
		}
		var seen []string
		n.TransportFor("a").OnMessage(func(m Message) { seen = append(seen, string(m.Data)) })
		n.TransportFor("b").Broadcast([]byte("x"))
		n.TransportFor("c").Broadcast([]byte("y"))
		n.TransportFor("d").Broadcast([]byte("z"))
		n.Advance(100 * time.Millisecond)
		return seen
	}
	first, second := run(), run()
	if fmt.Sprint(first) != fmt.Sprint(second) {
		t.Fatalf("same seed diverged:\n %v\n %v", first, second)
	}
	if len(first) == 0 {
		t.Fatal("no messages were delivered at all")
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
