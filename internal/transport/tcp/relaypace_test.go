package tcp

// Audit PX-4's second half: the relay-mode BYTE budget DELAYS, it never drops.
// Two pins, because "did not drop" and "did delay" are different claims:
//
//   - the bucket's arithmetic, driven by a constructed clock - the leaky bucket
//     charges a frame on arrival and returns exactly the wait that pays the
//     debt back at the configured rate, so the delay is a number a test can
//     compute rather than a stopwatch it has to trust;
//   - the reader's use of it, over a real socket: a relay connection with a tiny
//     budget still dispatches EVERY frame - none is shed, unlike the direct
//     frame bucket - and the paced counter must move, which is what proves the
//     delay path ran instead of the budget being a no-op.

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/cti97/b10coincom/internal/transport"
	"github.com/cti97/b10coincom/internal/wire"
)

func TestTheRelayByteBucketPaysItsDebtAtTheConfiguredRate(t *testing.T) {
	b := newByteBucket(1000, 1000) // 1000 B/s, burst 1000 B
	now := time.Unix(0, 0)
	b.now = func() time.Time { return now }
	b.last = now // the constructor stamped the real clock; drive both from the fake

	if got := b.reserve(600); got != 0 {
		t.Fatalf("the first 600 B of a 1000 B burst waited %v, want 0", got)
	}
	if got := b.reserve(600); got != 200*time.Millisecond {
		t.Fatalf("the second 600 B waited %v, want 200ms (200 B of debt at 1000 B/s)", got)
	}
	if got := b.reserve(600); got != 800*time.Millisecond {
		t.Fatalf("the third 600 B waited %v, want 800ms (800 B of debt at 1000 B/s)", got)
	}
	// Time passing pays debt down: 200ms buys 200 bytes of the 800 owed.
	now = now.Add(200 * time.Millisecond)
	if got := b.reserve(0); got != 600*time.Millisecond {
		t.Fatalf("after 200ms the remaining debt waited %v, want 600ms", got)
	}
	// A full burst of time refills the bucket to the burst and no further: the
	// leaky bucket never banks more than its headroom.
	now = now.Add(time.Second)
	if got := b.reserve(0); got != 0 {
		t.Fatalf("a refilled bucket still waited %v, want 0", got)
	}
	if got := b.reserve(5000); got <= 0 {
		t.Fatalf("a frame larger than the burst waited %v; it must be paced (a positive wait), never refused", got)
	}
}

func TestARelayFloodIsPacedNotShed(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	tp, err := New(Options{
		LocalID: "validator", IdleReadTimeout: time.Hour, WriteTimeout: time.Second,
		// A budget deliberately far below the frame bucket's default: 16 frames
		// of 500 B would be 8000 B, and only 1000 B is free.
		RelayBytesPerSec: 200_000, RelayBytesBurst: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tp.Close()

	var mu sync.Mutex
	var got [][]byte
	tp.OnMessage(func(m transport.Message) {
		mu.Lock()
		got = append(got, append([]byte(nil), m.Data...))
		mu.Unlock()
	})

	addr := "relay.example.net:7001"
	c, err := tp.install(server, addr, true, true, false, RelayPeerName(addr))
	if err != nil {
		t.Fatal(err)
	}
	tp.start(c)
	if c.relayBudget == nil {
		t.Fatal("a relay connection has no byte budget: audit PX-4's bound is not wired")
	}

	const frames, size = 16, 500
	go func() {
		payload := bytes.Repeat([]byte{0xAB}, size)
		for i := 0; i < frames; i++ {
			if err := wire.WriteFrame(client, payload); err != nil {
				return
			}
		}
	}()

	waitFor(t, fmt.Sprintf("%d relay frames to be dispatched (paced, not dropped)", frames), 10*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(got) == frames
	})
	mu.Lock()
	delivered := len(got)
	mu.Unlock()
	if delivered != frames {
		t.Fatalf("%d of %d relay frames were dispatched: the byte budget DROPPED instead of pacing", delivered, frames)
	}
	if n := c.rateLimited.Load(); n != 0 {
		t.Fatalf("%d frames were shed on the relay connection: the frame bucket must stay exempt there", n)
	}
	if n := c.relayPaced.Load(); n == 0 {
		t.Fatal("no frame was paced: the relay byte budget is a no-op, so the bound is asserted by nothing")
	}
	if got := tp.RelayPacedFrames(); got == 0 {
		t.Fatal("RelayPacedFrames = 0, want the paced frames to be observable")
	}
}
