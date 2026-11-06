package node

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/mempool"
)

// TestRunRetriesABuildFailureInsteadOfExiting is audit S-3's second half: a
// producer that cannot build must log and try the next tick. Pre-fix the first
// RunOnce error was returned to main, which exited the process - so a transient
// producer failure (a full mempool, a bound momentarily too tight) became a
// node outage.
//
// The failure is CONSTRUCTED, not provoked: the proposer key is the wrong
// length, so chain.Build refuses every attempt deterministically. The loop is
// driven by counting attempts through the clock seam and cancelling once
// several have happened, so the test does not depend on how many ticks a wall
// clock happened to fit.
func TestRunRetriesABuildFailureInsteadOfExiting(t *testing.T) {
	c, err := chain.Open(genesis.Devnet(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	mp := mempool.New(100, c.Genesis().Hash(), c.AdmissionHead)
	n := New(c, ed25519.PrivateKey([]byte("too short to be a key")), mp)

	var mu sync.Mutex
	var lines []string
	n.logf = func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, fmt.Sprintf(format, args...))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var attempts atomic.Int64
	n.now = func() time.Time {
		if attempts.Add(1) >= 3 {
			cancel()
		}
		return time.Unix(1_700_000_000, 0)
	}

	err = n.Run(ctx, time.Millisecond)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v, want context.Canceled: a failed tick ended the loop instead of retrying", err)
	}
	if got := attempts.Load(); got < 3 {
		t.Fatalf("the loop made %d attempt(s); the fixture needs at least 3 to show a retry", got)
	}
	mu.Lock()
	got := len(lines)
	first := ""
	if got > 0 {
		first = lines[0]
	}
	mu.Unlock()
	if got != 1 {
		t.Fatalf("a failing producer logged %d lines, want exactly 1 per failure episode: %v", got, lines)
	}
	if !strings.Contains(first, "proposer key") {
		t.Fatalf("the one log line does not carry the failure: %q", first)
	}
	if c.Height() != 0 {
		t.Fatalf("the chain advanced to height %d under a producer that cannot build", c.Height())
	}
}
