package simnet

// The negative test for the SHIPPED comparator. AssertPrefix (simnet.go) is what
// Agreed is computed from: RunMulti calls simnet.AssertPrefix(i) for every
// validator and fails the run when it errors. Until this test existed, the only
// proof that Agreed can ever be false lived in internal/devnet's forkNet test
// double - a hand-written copy of the comparison, not the shipped method - so a
// comparator neutered to `return nil` stayed invisible: the whole suite stayed
// green and the multi-validator acceptance run still printed agreed yes. This
// test is the correction of record: it manufactures the divergence against a
// REAL simnet.Net and requires the real AssertPrefix to reject it.

import (
	"bytes"
	"crypto/ed25519"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cti97/b10coincom/internal/chain"
)

// TestAssertPrefixCatchesADurableFork proves the shipped AssertPrefix fails on
// a forked validator's durable history - not on a double's re-implementation
// of it.
//
// An honest committee never disagrees, so the divergence is manufactured at the
// durable-history level, the same machinery the Task 9 fix round used: one
// validator's stored blocks are RELINKED onto an internally consistent
// alternative chain. The shared prefix below the fork point is re-appended
// byte-identical; the blocks above it are rebuilt with the same height, parent
// linkage, state root, transaction root and proposer key, differing only in
// timestamp, so every replacement block carries a genuine validator signature
// and the relinked history survives chain.Open's replay - a durable, restartable
// fork, exactly the state a broken consensus would one day produce, not a
// corrupted record a replay check would reject.
//
// The fixture's own guards (prefix identical below the swap point, conflicting
// blocks from the fork height on) and the in-memory net left untouched by the
// swap (the relinked chain is never driven; the other three validators' chains
// stay honest) keep the assertion honest: if the fixture were not a real fork,
// the final check would assert nothing.
//
// Killing the F1 mutant: `return nil` at the top of AssertPrefix makes this
// test fail with "AssertPrefix passed on a forked validator". All other tests
// survive that mutant - the honest scenarios assert err == nil, which a neutered
// comparator also returns - so this is the suite's only guard against the
// "always true" comparator.
func TestAssertPrefixCatchesADurableForkInARealNet(t *testing.T) {
	n, err := New(4, Options{TempDir: t.TempDir(), Seed: 4, LatencyMS: 5, TimeoutBase: 200, TimeoutStep: 100})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()

	if _, err := n.RunBlocks(8); err != nil {
		t.Fatal(err)
	}
	// Positive control: on the honest network the shipped comparator passes.
	if err := n.AssertPrefix(0); err != nil {
		t.Fatalf("the honest network must pass its own prefix assertion before the relink: %v", err)
	}

	// Build the alternative chain in its own directory under the net's temp
	// dir: heights 1..5 re-appended from validator 0's real blocks, heights
	// 6..7 rebuilt onto it, so the fork point is height 6 over a shared 0..5.
	const forkAt = uint64(6)
	altDir := filepath.Join(n.opts.TempDir, "fork-alt")
	alt, err := chain.Open(n.genesis(), altDir)
	if err != nil {
		t.Fatal(err)
	}
	for h := uint64(1); h < forkAt; h++ {
		real, err := n.ch[0].BlockAt(h)
		if err != nil {
			t.Fatal(err)
		}
		if err := alt.Append(real); err != nil {
			t.Fatalf("re-appending the real block at height %d to the alternative chain: %v", h, err)
		}
	}
	for h := forkAt; h <= forkAt+1; h++ {
		real, err := n.ch[0].BlockAt(h)
		if err != nil {
			t.Fatal(err)
		}
		priv := proposerKey(t, real.Header.Proposer)
		replacement, err := alt.Build(priv, real.Txs, real.Header.Timestamp+1000)
		if err != nil {
			t.Fatal(err)
		}
		if replacement.ID() == real.ID() {
			t.Fatalf("test setup: the replacement block at height %d is identical to the real one; nothing would fork", h)
		}
		if err := alt.Append(replacement); err != nil {
			t.Fatal(err)
		}
	}

	// The relinked history is durable, not an in-memory artefact: close it and
	// reopen it through chain.Open, whose replay re-checks every stored block's
	// position, predecessor linkage and recomputed state root.
	altHead, altHeight := alt.Head().ID(), alt.Height()
	if err := alt.Close(); err != nil {
		t.Fatal(err)
	}
	forked, err := chain.Open(n.genesis(), altDir)
	if err != nil {
		t.Fatalf("the relinked history must survive chain.Open's replay (a durable fork, not a corrupted record): %v", err)
	}
	if forked.Height() != altHeight || forked.Head().ID() != altHead {
		t.Fatalf("replay lost the relinked head: height %d id %x, want height %d id %x",
			forked.Height(), forked.Head().ID(), altHeight, altHead[:8])
	}

	// Swap: validator 0 now PRESENTS the forked durable history, while its
	// peers keep the honest one. The original chain is closed (validator 0's
	// driver is never driven again in this test) and the reopened one joins
	// the net, so the net's own Close closes it exactly once.
	old := n.ch[0]
	n.ch[0] = forked
	_ = old.Close()

	// Fixture guards: the fork is real and confined - prefix identical,
	// fork window conflicting - checked against an untouched honest peer.
	for h := uint64(0); h < forkAt; h++ {
		a, err := forked.BlockAt(h)
		if err != nil {
			t.Fatal(err)
		}
		b, err := n.ch[1].BlockAt(h)
		if err != nil {
			t.Fatal(err)
		}
		if a.ID() != b.ID() {
			t.Fatalf("test setup: the shared prefix differs at height %d; the fixture is not a confined fork", h)
		}
	}
	for h := forkAt; h <= forkAt+1; h++ {
		a, err := forked.BlockAt(h)
		if err != nil {
			t.Fatal(err)
		}
		b, err := n.ch[1].BlockAt(h)
		if err != nil {
			t.Fatal(err)
		}
		if a.ID() == b.ID() {
			t.Fatalf("test setup: no conflicting block at height %d; the fixture is not a fork", h)
		}
	}

	// The payoff: the SHIPPED comparator must name the divergence. With the
	// neutered comparator this assertion is what fails the suite.
	err = n.AssertPrefix(0)
	if err == nil {
		t.Fatal("AssertPrefix passed on a forked validator: the shipped comparator accepts a diverged durable history")
	}
	if !strings.Contains(err.Error(), "DIVERGED") {
		t.Fatalf("AssertPrefix rejected the fork with an unexpected error (want the divergence diagnosis, a fork not a lag): %v", err)
	}
}

// proposerKey maps a block's proposer public key back to the simnet key that
// owns it, so a relinked block can be re-signed by the key that signed the
// original - the fork must be internally consistent, not corrupted.
func proposerKey(t *testing.T, pub []byte) ed25519.PrivateKey {
	t.Helper()
	for i := 0; i < 255; i++ {
		priv := simKey(i)
		if owner, ok := priv.Public().(ed25519.PublicKey); ok && bytes.Equal([]byte(owner), pub) {
			return priv
		}
	}
	t.Fatalf("proposer %x is not a simnet validator key", pub[:8])
	return nil
}
