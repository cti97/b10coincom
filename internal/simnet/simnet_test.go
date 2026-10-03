package simnet

import (
	"crypto/ed25519"
	"testing"
)

// The happy path the spec requires: four validators finalise many blocks.
func TestFourValidatorsFinaliseBlocks(t *testing.T) {
	n, err := New(4, Options{TempDir: t.TempDir(), Seed: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()

	heights, err := n.RunBlocks(20)
	if err != nil {
		t.Fatalf("RunBlocks: %v", err)
	}
	for i := 0; i < 4; i++ {
		if heights[uint64(i)] < 20 {
			t.Fatalf("validator %d finalised only %d of 20 blocks", i, heights[uint64(i)])
		}
	}
	// Every validator must agree on the same chain, or they did not really agree.
	if err := n.AssertSameChain(); err != nil {
		t.Fatal(err)
	}
}

// The harness's central claim: the same seed and options reproduce the run. Two
// independently constructed networks must reach identical heights AND identical
// blocks - matching heights alone would let two different chains pass, since
// height is only a count. Block-for-block identity is what makes a failing
// consensus run replayable from its seed.
func TestSameSeedReproducesIdenticalBlocks(t *testing.T) {
	// Jitter is on because it reorders delivery - the hardest case for replay.
	// DropPercent is deliberately zero: an M3 driver whose quorum-committing
	// proposal is lost parks at that height permanently (a refused commitment is
	// never skipped), so loss is outside what the harness may exercise for
	// liveness; the plan's scenarios likewise run latency and jitter only.
	n1, err := New(4, Options{TempDir: t.TempDir(), Seed: 7, LatencyMS: 5, JitterMS: 5})
	if err != nil {
		t.Fatal(err)
	}
	defer n1.Close()
	n2, err := New(4, Options{TempDir: t.TempDir(), Seed: 7, LatencyMS: 5, JitterMS: 5})
	if err != nil {
		t.Fatal(err)
	}
	defer n2.Close()

	h1, err := n1.RunBlocks(5)
	if err != nil {
		t.Fatalf("first run stalled: %v", err)
	}
	h2, err := n2.RunBlocks(5)
	if err != nil {
		t.Fatalf("second run stalled: %v", err)
	}
	for i := 0; i < 4; i++ {
		if h1[uint64(i)] != h2[uint64(i)] {
			t.Fatalf("same seed, different heights: validator %d reached %d then %d", i, h1[uint64(i)], h2[uint64(i)])
		}
	}
	// Compare every committed block the two runs share, not just the counts.
	for i := 0; i < 4; i++ {
		common := h1[uint64(i)]
		if h2[uint64(i)] < common {
			common = h2[uint64(i)]
		}
		for h := uint64(0); h <= common; h++ {
			b1, err := n1.ch[i].BlockAt(h)
			if err != nil {
				t.Fatal(err)
			}
			b2, err := n2.ch[i].BlockAt(h)
			if err != nil {
				t.Fatal(err)
			}
			if b1.ID() != b2.ID() {
				id1, id2 := b1.ID(), b2.ID()
				t.Fatalf("same seed, different blocks: validator %d at height %d has %x then %x",
					i, h, id1[:8], id2[:8])
			}
		}
	}
}

// AssertSameChain must actually detect disagreement, or Task 9's safety
// scenarios rest on a function nothing proves works. Four validators are moved
// onto DIFFERENT blocks at height 1 straight from genesis (each chain builds its
// own height-1 block with its own proposer key and timestamp, bypassing
// consensus), so the lowest common height is 1 and the heads already disagree.
func TestAssertSameChainDetectsDisagreement(t *testing.T) {
	n, err := New(4, Options{TempDir: t.TempDir(), Seed: 9})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()

	for i := 0; i < 4; i++ {
		head := n.ch[i].Head()
		// The timestamp varies per validator, so the four height-1 blocks differ
		// in header - and therefore in block ID - even before the proposers do.
		b, err := n.ch[i].Build(n.keys[i].priv, nil, head.Header.Timestamp+1+int64(i))
		if err != nil {
			t.Fatalf("building divergent block for validator %d: %v", i, err)
		}
		if err := n.ch[i].Append(b); err != nil {
			t.Fatalf("appending divergent block for validator %d: %v", i, err)
		}
	}

	if err := n.AssertSameChain(); err == nil {
		t.Fatal("AssertSameChain accepted four validators on four different height-1 blocks")
	}
}

// A powered-off validator must stay in the committee: an outage must make quorum
// harder (its weight simply goes missing), not easier. TakeOffline that removed
// a member would lower the bar for everyone left, which is precisely the bug
// this test exists to catch.
func TestTakeOfflineDoesNotShrinkCommittee(t *testing.T) {
	n, err := New(4, Options{TempDir: t.TempDir(), Seed: 11})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()

	sizeBefore := len(n.cfg.Committee)
	powerBefore := n.cfg.TotalPower()
	quorumBefore := n.cfg.Quorum()
	keyBefore := n.cfg.IndexOf(n.keys[1].priv.Public().(ed25519.PublicKey))

	n.TakeOffline(1)

	if got := len(n.cfg.Committee); got != sizeBefore {
		t.Fatalf("committee size %d after taking a validator offline, want %d", got, sizeBefore)
	}
	if got := n.cfg.TotalPower(); got != powerBefore {
		t.Fatalf("total power %d after taking a validator offline, want %d", got, powerBefore)
	}
	if got := n.cfg.Quorum(); got != quorumBefore {
		t.Fatalf("quorum %d after taking a validator offline, want %d", got, quorumBefore)
	}
	if got := n.cfg.IndexOf(n.keys[1].priv.Public().(ed25519.PublicKey)); got != keyBefore {
		t.Fatalf("offline validator's committee index = %d, want %d (it must stay a member)", got, keyBefore)
	}
}

// The equivocator seam must produce votes a recipient will actually tally: the
// forged prevote carries a key that IS in the committee and a signature that
// verifies against it. A forge that ships a stranger's key dies as ErrNotValidator
// and the Byzantine scenario would pass without ever reaching the quorum logic.
func TestMakeEquivocatorForgesWithACommitteeKey(t *testing.T) {
	n, err := New(4, Options{TempDir: t.TempDir(), Seed: 13})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()

	n.MakeEquivocator(3)
	if _, err := n.RunBlocks(2); err != nil {
		t.Fatalf("RunBlocks with an equivocator installed: %v", err)
	}

	eq, ok := n.equivs[3]
	if !ok {
		t.Fatal("no equivocator was installed for validator 3")
	}
	if len(eq.forged) == 0 {
		t.Fatal("the equivocator sent no forged prevote in two blocks of consensus")
	}
	for _, v := range eq.forged {
		idx := n.cfg.IndexOf(v.Validator)
		if idx < 0 {
			t.Fatalf("forged prevote was signed with a key that is NOT in the committee (index %d): "+
				"peers would reject it as a non-member and the Byzantine scenario would test nothing", idx)
		}
		if err := v.Verify(); err != nil {
			t.Fatalf("forged prevote's signature does not verify: %v", err)
		}
		if v.IsNil() {
			t.Fatal("forged prevote is nil; it must conflict with a real block ID")
		}
		if v.BlockID != eq.forgeID {
			t.Fatal("forged prevote does not carry the equivocator's forged block ID")
		}
	}
}
