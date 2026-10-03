package simnet

import (
	"crypto/ed25519"
	"fmt"
	"strings"
	"testing"

	"github.com/cti97/b10coincom/internal/consensus"
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
//
// The forge must also LEAVE THE VALIDATOR: the wrapper's own log records what it
// decided to send; a mutant that forges locally and never broadcasts would keep
// that log identical while the honest wire stayed clean. So the assertions below
// require the forged bytes on validator 3's OUTGOING tap (its wire) AND inside
// another validator's received log (delivery to a peer) - a Byzantine
// equivocation that reaches nobody is not an equivocation.
func TestMakeEquivocatorForgesWithACommitteeKey(t *testing.T) {
	n, err := New(4, Options{TempDir: t.TempDir(), Seed: 13})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()

	if err := n.MakeEquivocator(3); err != nil {
		t.Fatalf("MakeEquivocator: %v", err)
	}
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

	// The forged prevote must reach the WIRE: it must appear among the
	// equivocator's outgoing payloads, not just in the wrapper's local record.
	onWire := 0
	for _, raw := range n.taps[3].sent {
		v, err := consensus.DecodeVote(raw)
		if err != nil || v.Type != consensus.MsgPrevote || v.BlockID != eq.forgeID {
			continue
		}
		if idx := n.cfg.IndexOf(v.Validator); idx != 3 {
			t.Fatalf("forged prevote on the wire carries validator index %d, want 3", idx)
		}
		if err := v.Verify(); err != nil {
			t.Fatalf("forged prevote on the wire does not verify: %v", err)
		}
		onWire++
	}
	if onWire == 0 {
		t.Fatal("no forged prevote ever reached the wire: the equivocation stayed local and the Byzantine scenario would be vacuous")
	}

	// ... and be DELIVERED to a peer: some validator other than 3 must have
	// consumed the forged bytes from the network.
	delivered := false
	for j := 0; j < 3; j++ {
		for _, raw := range n.taps[j].recv {
			v, err := consensus.DecodeVote(raw)
			if err != nil || v.Type != consensus.MsgPrevote || v.BlockID != eq.forgeID {
				continue
			}
			if idx := n.cfg.IndexOf(v.Validator); idx != 3 {
				continue
			}
			delivered = true
			break
		}
		if delivered {
			break
		}
	}
	if !delivered {
		t.Fatal("no peer ever received the forged prevote; a broadcast that never arrives cannot force the one-vote-per-validator tally the scenario hinges on")
	}
}

// THE milestone's first liveness claim, stated honestly: with one of four
// validators offline from the start, the other three must still be more than
// two thirds of TOTAL power (3 of a quorum of exactly 3 for n=4) and commit.
// The offline validator must contribute NOTHING - it neither sends nor
// receives, so its tap must stay empty and its height may never move. Before
// the link cut, "offline" skipped only the tick: the validator went on
// prevoting, precommitting and appending over received messages, so this
// scenario passed and its committee checks could not see that.
func TestThreeOfFourValidatorsCommitWithOneOffline(t *testing.T) {
	n, err := New(4, Options{TempDir: t.TempDir(), Seed: 11})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()

	n.TakeOffline(3)
	silentHeight := n.ch[3].Height()

	heights, err := n.RunBlocks(10)
	if err != nil {
		t.Fatalf("the chain stalled with one of four validators offline: %v", err)
	}
	for i := 0; i < 3; i++ {
		if heights[uint64(i)] < 10 {
			t.Fatalf("validator %d finalised only %d of 10 blocks with one validator offline", i, heights[uint64(i)])
		}
	}
	// The claimed 3-of-4 quorum must have been hit with the silent third gone:
	// three ONLINE validators at target is exactly quorum(total=4) - there was
	// no spare vote to hide behind.
	if err := n.AssertSameChain(); err != nil {
		t.Fatal(err)
	}
	if got := n.ch[3].Height(); got != silentHeight {
		t.Fatalf("OFFLINE validator 3 committed while offline: %d -> %d", silentHeight, got)
	}
	if len(n.taps[3].sent) != 0 {
		t.Fatalf("OFFLINE validator 3 put %d messages on the wire; a powered-off machine sends nothing", len(n.taps[3].sent))
	}
	if len(n.taps[3].recv) != 0 {
		t.Fatalf("OFFLINE validator 3's driver consumed %d messages; a powered-off machine receives nothing", len(n.taps[3].recv))
	}
}

// THE milestone's second liveness claim: with two of four validators offline,
// 2 of 4 total power is below the two-thirds quorum of 3, so the chain must
// stall - and the stalled run must say so EARLY rather than burn the whole
// step budget before erroring. Before the link cut this scenario did not
// stall: the two "offline" validators kept voting, and quorum stayed reachable
// (measured during review: heights {3,3,3,3} became {4,4,4,4}).
func TestTwoOfflineValidatorsStall(t *testing.T) {
	n, err := New(4, Options{TempDir: t.TempDir(), Seed: 12})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()

	n.TakeOffline(2)
	n.TakeOffline(3)
	before := n.Heights()

	steps := 0
	_, err = n.RunBlocks(5)
	if err == nil {
		t.Fatal("the chain advanced with only half the voting power online; two thirds was not enforced")
	}
	// The error must name its steps, and those steps must be a small fraction
	// of the budget - a genuinely stalled run that spends runBlocksStepBudget
	// steps before erroring makes Task 9's determinism sweeps unusable.
	if _, perr := fmt.Sscanf(err.Error(), "simnet: stalled below height 5 after %d steps", &steps); perr != nil {
		t.Fatalf("stall error does not name its step count: %v (error itself: %v)", perr, err)
	}
	if steps > runBlocksStepBudget/10 {
		t.Fatalf("a stalled run burned %d steps before erroring; the stall detector must end it within %d", steps, runBlocksStepBudget/10)
	}

	// Nothing anywhere may have committed: the silent two cannot have voted
	// (their taps are empty), and the remaining pair cannot reach quorum 3.
	after := n.Heights()
	for i := 0; i < 4; i++ {
		if after[uint64(i)] != before[uint64(i)] {
			t.Fatalf("stalled run moved validator %d's height %d -> %d", i, before[uint64(i)], after[uint64(i)])
		}
	}
	if len(n.taps[2].sent) != 0 || len(n.taps[3].sent) != 0 {
		t.Fatalf("OFFLINE validators put messages on the wire: v2 sent %d, v3 sent %d", len(n.taps[2].sent), len(n.taps[3].sent))
	}
	if len(n.taps[2].recv) != 0 || len(n.taps[3].recv) != 0 {
		t.Fatalf("OFFLINE validators' drivers consumed messages: v2 %d, v3 %d", len(n.taps[2].recv), len(n.taps[3].recv))
	}
}

// The direct mechanism proof for "offline means offline", mid-run: a running
// network is wound up, then two validators are powered off; from that moment
// they must neither send nor receive, and the run ends in an EARLY stall
// error. In-flight messages the honest pair already holds are free to finish
// one pending height (those votes were cast before the power-off), so the
// ONLINE validators' heights are deliberately not asserted frozen - only the
// offline pair's contributions are.
func TestOfflineValidatorSendsAndReceivesNothingAfterTakeOffline(t *testing.T) {
	n, err := New(4, Options{TempDir: t.TempDir(), Seed: 13})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()

	if _, err := n.RunBlocks(3); err != nil {
		t.Fatal(err)
	}
	n.TakeOffline(2)
	n.TakeOffline(3)
	sent2, got2 := len(n.taps[2].sent), len(n.taps[2].recv)
	sent3, got3 := len(n.taps[3].sent), len(n.taps[3].recv)
	height2, height3 := n.ch[2].Height(), n.ch[3].Height()

	_, err = n.RunBlocks(8)
	if err == nil {
		t.Fatal("the chain kept committing after two of four validators were powered off")
	}
	if len(n.taps[2].sent) != sent2 || len(n.taps[3].sent) != sent3 {
		t.Fatalf("OFFLINE validator kept SENDING after the cut: v2 %d -> %d, v3 %d -> %d",
			sent2, len(n.taps[2].sent), sent3, len(n.taps[3].sent))
	}
	if len(n.taps[2].recv) != got2 || len(n.taps[3].recv) != got3 {
		t.Fatalf("OFFLINE validator kept RECEIVING after the cut: v2 %d -> %d, v3 %d -> %d",
			got2, len(n.taps[2].recv), got3, len(n.taps[3].recv))
	}
	if h := n.ch[2].Height(); h != height2 {
		t.Fatalf("OFFLINE validator 2 committed while offline: %d -> %d", height2, h)
	}
	if h := n.ch[3].Height(); h != height3 {
		t.Fatalf("OFFLINE validator 3 committed while offline: %d -> %d", height3, h)
	}
	// What is left running must still be one chain.
	if err := n.AssertSameChain(); err != nil {
		t.Fatal(err)
	}
}

// F2: RunBlocks waits on every online validator, so a validator that is online
// but partitioned away would block the call even while the majority progresses.
// RunBlocksAmong must let the majority reach its target while the cut-off
// validator sits stuck below it - and a wait set containing an offline
// validator must be refused up front, not discovered at the stall limit.
func TestRunBlocksAmongWaitsOnlyForTheNamedValidators(t *testing.T) {
	n, err := New(4, Options{TempDir: t.TempDir(), Seed: 14})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()

	// Shared prefix first, so the minority's committed blocks are real ones.
	if _, err := n.RunBlocks(3); err != nil {
		t.Fatal(err)
	}
	n.Partition([]int{0, 1, 2}, []int{3})
	heights, err := n.RunBlocksAmong(6, []int{0, 1, 2})
	if err != nil {
		t.Fatalf("the majority partition could not make progress: %v", err)
	}
	for i := 0; i < 3; i++ {
		if heights[uint64(i)] < 6 {
			t.Fatalf("majority member %d finalised only %d of 6 blocks", i, heights[uint64(i)])
		}
	}
	// The cut-off validator must not have committed anything new on its own:
	// a validator that reaches nobody holds one vote against quorum 3.
	if h := n.ch[3].Height(); h >= 6 {
		t.Fatalf("partitioned validator 3 reached height %d on its own; a minority of one cannot reach quorum", h)
	}
	// Everyone still agrees on the prefix they share.
	if err := n.AssertSameChain(); err != nil {
		t.Fatal(err)
	}

	// Waiting on an offline validator can never succeed and is a caller bug.
	n.TakeOffline(0)
	if _, err := n.RunBlocksAmong(7, []int{0, 1, 2}); err == nil || !strings.Contains(err.Error(), "offline") {
		t.Fatalf("RunBlocksAmong accepted a wait set containing an offline validator: err=%v", err)
	}
	if _, err := n.RunBlocksAmong(7, nil); err == nil || !strings.Contains(err.Error(), "empty wait set") {
		t.Fatalf("RunBlocksAmong accepted an empty wait set: err=%v", err)
	}
}

// F4: the arm that distinguishes "lowest common height" from "the heads". Four
// validators commit a shared prefix, then one is partitioned away while the
// majority advances: the four sit at DIFFERENT heights over an IDENTICAL
// shared prefix, which a heads comparison would reject as a fork.
func TestAssertSameChainPassesAcrossDifferentHeights(t *testing.T) {
	n, err := New(4, Options{TempDir: t.TempDir(), Seed: 15})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()

	if _, err := n.RunBlocks(3); err != nil {
		t.Fatal(err)
	}
	n.Partition([]int{0, 1, 2}, []int{3})
	if _, err := n.RunBlocksAmong(6, []int{0, 1, 2}); err != nil {
		t.Fatal(err)
	}

	if err := n.AssertSameChain(); err != nil {
		t.Fatalf("AssertSameChain rejected validators at different heights over an identical shared prefix: %v", err)
	}
}

// F4: with fewer than two validators online there is nothing to agree about,
// and a silent pass would be a vacuous success. One online validator must
// return an explicit error, and so must none.
func TestAssertSameChainRefusesTooFewOnline(t *testing.T) {
	n, err := New(4, Options{TempDir: t.TempDir(), Seed: 16})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()

	n.TakeOffline(1)
	n.TakeOffline(2)
	n.TakeOffline(3)
	if err := n.AssertSameChain(); err == nil {
		t.Fatal("AssertSameChain passed with one online validator; agreement with nobody to agree with is vacuous")
	}
	n.TakeOffline(0)
	if err := n.AssertSameChain(); err == nil {
		t.Fatal("AssertSameChain passed with no online validators")
	}
}
