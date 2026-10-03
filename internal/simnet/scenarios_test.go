package simnet

// The six consensus scenarios design spec section 9.1 requires. This file IS the
// milestone's evidence: the scenarios are the proof that the protocol is safe and
// live under injected failure, so every assertion here pins a property the spec
// names, and every scenario's killing mutation is recorded in the task report.
//
// What each scenario may honestly assert is scoped by two milestone limits
// (docs/plans/2026-10-03-m3-bft-consensus.md, "Honest limits of the MILESTONE"):
//
//   - M3 has NO block catch-up. Transport offers only Broadcast, so a validator
//     that falls behind - partitioned away, or restarted mid-epoch - cannot adopt
//     the blocks it missed. Scenarios 4 and 6 therefore assert that a lagging
//     validator's history is a strict PREFIX of the longest chain (behind, never
//     forked) and must NOT demand reconvergence; that is M4's block-sync work.
//   - DropPercent cannot be used here. A validator whose quorum-committing
//     proposal is lost holds no block bytes, cannot append, and parks at that
//     height forever: there is no recovery path in M3. Every scenario below runs
//     drop-free with latency only, so a stall means consensus, not a lost packet.
//
// AssertPrefix is defined in this file because the plan's interface list places
// it in the simnet package but the Task 8 harness landed without it; defining it
// here keeps the change inside this file, the only file this task owns.

import (
	"crypto/ed25519"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/consensus"
	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/types"
)

// assertAgreedOnEverySharedHeight is the safety assertion the scenarios rest on.
// AssertSameChain compares the single LOWEST common height; this helper walks
// EVERY height up to the lowest and requires all validators to hold the same
// block ID at each one. "No two validators commit conflicting blocks at one
// height" is the spec's safety property, and this makes it visible height by
// height rather than at one sampled height. Offline validators are included:
// their history is frozen, committed-before-the-outage blocks, and a scenario
// fails loudly if an outage ever let a validator hold something different.
func assertAgreedOnEverySharedHeight(t *testing.T, n *Net, where string) {
	t.Helper()
	lowest := n.ch[0].Height()
	for _, c := range n.ch[1:] {
		if c.Height() < lowest {
			lowest = c.Height()
		}
	}
	for h := uint64(0); h <= lowest; h++ {
		ref, err := n.ch[0].BlockAt(h)
		if err != nil {
			t.Fatalf("%s: reading validator 0 at height %d: %v", where, h, err)
		}
		for i := 1; i < len(n.ch); i++ {
			b, err := n.ch[i].BlockAt(h)
			if err != nil {
				t.Fatalf("%s: reading validator %d at height %d: %v", where, i, h, err)
			}
			if b.ID() != ref.ID() {
				id1, id2 := ref.ID(), b.ID()
				t.Fatalf("%s: SAFETY VIOLATION: validators 0 and %d hold conflicting blocks at height %d: %x vs %x",
					where, i, h, id1[:8], id2[:8])
			}
		}
	}
}

// AssertPrefix reports whether validator i's history is an exact prefix of the
// longest chain in the network: for every height i has committed, i's block must
// be the identical block the longest chain holds at that height, and i's head may
// not stand above the longest chain's head (a validator taller than everyone else
// holds blocks nobody else committed, which is a fork by definition).
//
// This is the honest safety assertion for a LAGGING validator under the M3
// milestone limits: with no block catch-up, a validator isolated behind the
// quorum cannot adopt the blocks it missed, so the strongest claim a scenario can
// make about it is "behind, never forked". Requiring it to reconverge would
// assert a mechanism M3 does not have.
func (n *Net) AssertPrefix(i int) error {
	if i < 0 || i >= len(n.ch) {
		return fmt.Errorf("simnet: AssertPrefix: validator index %d out of range 0..%d", i, len(n.ch)-1)
	}
	// The longest chain is the reference: the majority's chain, which the
	// scenarios keep advancing while i sits behind.
	refHeight := uint64(0)
	var ref *chain.Chain
	for _, c := range n.ch {
		if c.Height() > refHeight {
			refHeight, ref = c.Height(), c
		}
	}
	if ref == nil {
		return fmt.Errorf("simnet: AssertPrefix: no validator chain to compare against")
	}
	c := n.ch[i]
	if c.Height() > refHeight {
		return fmt.Errorf("simnet: validator %d stands at height %d, above the longest chain at %d: it committed blocks the network never agreed on",
			i, c.Height(), refHeight)
	}
	for h := uint64(0); h <= c.Height(); h++ {
		bi, err := c.BlockAt(h)
		if err != nil {
			return fmt.Errorf("simnet: reading validator %d at height %d: %w", i, h, err)
		}
		br, err := ref.BlockAt(h)
		if err != nil {
			return fmt.Errorf("simnet: reading the longest chain at height %d: %w", h, err)
		}
		if bi.ID() != br.ID() {
			id1, id2 := bi.ID(), br.ID()
			return fmt.Errorf("simnet: validator %d DIVERGED at height %d: %x vs the longest chain's %x - a fork, not a lag",
				i, h, id1[:8], id2[:8])
		}
	}
	return nil
}

// stallShape asserts that a stalled run ended the honest way: the run error
// reports the EARLY stall detection - the wait set made no height progress for
// the full consecutive-step limit - rather than burning the whole step budget.
// This is what makes scenario 3's stall mean "quorum is unreachable" and not
// "the simulation ran out of patience": no height moved anywhere in the wait set
// for hundreds of virtual-time steps against a two-thirds bar that could not be
// met, which rules out a slow-timeout crawl as the cause.
func stallShape(t *testing.T, err error, target uint64) int {
	t.Helper()
	if err == nil {
		t.Fatalf("expected the run to stall below height %d, but it succeeded", target)
	}
	var steps int
	if _, perr := fmt.Sscanf(err.Error(), "simnet: stalled below height %d after %d steps: nothing in the wait set progressed for %d consecutive steps",
		new(uint64), &steps, new(int)); perr != nil {
		t.Fatalf("the run failed, but not with the early no-progress stall the unreachable quorum produces: %v", err)
	}
	return steps
}

// signVote / signProposal / encodeJustification build the consensus wire
// messages the justification-gate drive feeds to an engine by hand. The keys
// come from the harness's own deterministic committee, which is what makes the
// signatures verifiably from members of good standing - the same standing
// MakeEquivocator's forged votes insist on.
func signVote(v *consensus.Vote, priv ed25519.PrivateKey) {
	h := v.SigningHash()
	v.Sig = crypto.Sign(priv, h[:])
}

func signProposal(p *consensus.Proposal, priv ed25519.PrivateKey) {
	h := p.SigningHash()
	p.Sig = crypto.Sign(priv, h[:])
}

// encodeJustification renders prevotes in the wire shape verifyJustification
// decodes: a varint count followed by that many length-prefixed encoded votes.
// The consensus package's own encoder is unexported, so the scenario renders the
// same shape through the types encoder directly.
func encodeJustification(votes []*consensus.Vote) []byte {
	e := types.NewEncoder()
	e.Len(len(votes))
	for _, v := range votes {
		e.VarBytes(consensus.EncodeVote(v))
	}
	return e.Bytes()
}

// 1. Happy path: four validators finalise 1,000 blocks and agree on every one
// of them.
//
// Killing mutant (Task 9 report, M1): maybePrecommit stops emitting precommits;
// no commit quorum can ever complete, and the 1,000-block run stalls at height.
func TestScenarioHappyPath(t *testing.T) {
	n, err := New(4, Options{TempDir: t.TempDir(), Seed: 1, LatencyMS: 5, TimeoutBase: 200, TimeoutStep: 100})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()

	heights, err := n.RunBlocks(1000)
	if err != nil {
		t.Fatalf("happy path stalled: %v", err)
	}
	for i := 0; i < 4; i++ {
		if got := heights[uint64(i)]; got < 1000 {
			t.Fatalf("validator %d finalised only %d of 1,000 blocks", i, got)
		}
	}
	if err := n.AssertSameChain(); err != nil {
		t.Fatal(err)
	}
	assertAgreedOnEverySharedHeight(t, n, "happy path")
}

// 2. One validator offline: 3 of 4 is still more than two thirds of TOTAL power,
// so the chain advances - and the offline validator contributes nothing.
//
// The margin is exact, not comfortable: the committee keeps four members, so the
// quorum stays 3 and the three live validators are exactly AT the bar. There is
// no spare vote to hide a miscount behind.
//
// Killing mutant (M2): quorum is required from the FULL committee (unanimity);
// 3 of 4 can never reach it and the scenario's run fails.
func TestScenarioOneOfflineStillAdvances(t *testing.T) {
	n, err := New(4, Options{TempDir: t.TempDir(), Seed: 2, LatencyMS: 5, TimeoutBase: 200, TimeoutStep: 100})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()

	// The committee and its bar must be untouched by the outage: the offline
	// validator's WEIGHT leaves the tally, never its membership.
	if got := len(n.cfg.Committee); got != 4 {
		t.Fatalf("committee has %d members, want 4: TakeOffline must not shrink the set", got)
	}
	if got := n.cfg.Quorum(); got != 3 {
		t.Fatalf("quorum = %d, want 3: two thirds of 4 total power", got)
	}
	n.TakeOffline(3)
	silentHeight := n.ch[3].Height()

	heights, err := n.RunBlocks(20)
	if err != nil {
		t.Fatalf("the chain stalled with only one validator offline: %v", err)
	}
	for i := 0; i < 3; i++ {
		if got := heights[uint64(i)]; got < 20 {
			t.Fatalf("validator %d finalised only %d of 20 blocks with one validator offline", i, got)
		}
	}
	if err := n.AssertSameChain(); err != nil {
		t.Fatal(err)
	}
	// The powered-off validator must have contributed NOTHING: its weight
	// genuinely left the tally, so this 20-block run is a true 3-of-4 result.
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

// 3. Two validators offline: 2 of 4 is BELOW two thirds, so the chain must stall
// - and must never commit conflicting blocks while doing so.
//
// The scenario states the arithmetic it tests, then makes the network prove it
// twice:
//
//   - Phase A is the spec's shape, four validators: quorum 3, reachable weight
//     2, shortfall 1. At n=4 the two-thirds bar (3) coincides with a simple
//     majority (3), so the stall alone cannot tell WHICH bar stopped the chain.
//   - Phase B is the same scenario on five validators: 3 of 5 online is 60%, a
//     simple majority of 5 (3) but BELOW the two-thirds quorum of 4. There the
//     stall is attributable to the two-thirds rule alone: under a simple-majority
//     bar the chain would have advanced. That phase is what the simple-majority
//     mutant kills.
//
// Both phases end in the harness's early no-progress stall (see stallShape),
// which is the signature of an unreachable quorum rather than a timing artifact,
// and both assert the offline pair stayed SILENT (frozen taps) - an outage that
// merely mutes its members' ticks while leaving their links live would describe
// a different network.
//
// Killing mutants (M3, M4): with quorum at a simple majority, phase B's trio
// commits and the run succeeds. With TakeOffline leaving the validator voting,
// the stall itself survives - a validator that cannot tick also cannot follow
// the rounds the others move to, so its stranded votes never re-enter the race -
// but the frozen-tap assertions (here and in scenario 2) catch the mutant.
func TestScenarioTwoOfflineStallsWithoutForks(t *testing.T) {
	stallPhase := func(t *testing.T, size int, seed int64, offline []int) {
		t.Helper()
		n, err := New(size, Options{TempDir: t.TempDir(), Seed: seed, LatencyMS: 5, TimeoutBase: 200, TimeoutStep: 100})
		if err != nil {
			t.Fatal(err)
		}
		defer n.Close()

		if _, err := n.RunBlocks(3); err != nil {
			t.Fatal(err)
		}
		quorum := n.cfg.Quorum()
		for _, i := range offline {
			n.TakeOffline(i)
		}
		online := size - len(offline)
		// State the reason the run must stall, as numbers: the tally's bar and
		// the weight that can ever reach it.
		if online >= int(quorum) {
			t.Fatalf("test setup: %d of %d online is not below quorum %d; this scenario would not test the bar", online, size, quorum)
		}
		before := n.Heights()
		// "Offline" must mean silent: from the moment of the power-off, the
		// validator's tap must stay frozen. Messages already in flight are
		// discarded below the tap, so nothing the validator did not send before
		// the cut may appear, and its driver - with no tick and no deliveries -
		// can flush nothing.
		sentAtCut := make(map[int]int, len(offline))
		recvAtCut := make(map[int]int, len(offline))
		for _, i := range offline {
			sentAtCut[i] = len(n.taps[i].sent)
			recvAtCut[i] = len(n.taps[i].recv)
		}

		_, err = n.RunBlocks(6)
		steps := stallShape(t, err, 6)
		if steps > runBlocksStepBudget/10 {
			t.Fatalf("a stalled run burned %d steps before erroring; the wait set made no progress and the run must say so early", steps)
		}

		// No committed history may have been rewritten: a height going
		// BACKWARDS is what a fork looks like from the outside.
		for i, h := range n.Heights() {
			if h < before[uint64(i)] {
				t.Fatalf("validator %d lost height: %d -> %d", i, before[uint64(i)], h)
			}
		}
		// The offline pair must have stayed out of the tally: any message from
		// or to them after the cut means "powered off" was really "listening
		// quietly", and the quorum arithmetic above would describe a network
		// that no longer exists.
		for _, i := range offline {
			if got := len(n.taps[i].sent); got != sentAtCut[i] {
				t.Fatalf("OFFLINE validator %d sent %d messages after the cut; a powered-off machine sends nothing", i, got-sentAtCut[i])
			}
			if got := len(n.taps[i].recv); got != recvAtCut[i] {
				t.Fatalf("OFFLINE validator %d's driver consumed %d messages after the cut; a powered-off machine receives nothing", i, got-recvAtCut[i])
			}
		}
		if err := n.AssertSameChain(); err != nil {
			t.Fatal(err)
		}
		assertAgreedOnEverySharedHeight(t, n, fmt.Sprintf("two-offline stall (%d of %d online)", online, size))
	}

	t.Run("four validators: 2 of 4 below quorum 3", func(t *testing.T) {
		stallPhase(t, 4, 3, []int{2, 3})
	})
	t.Run("five validators: 3 of 5 is a majority yet below quorum 4", func(t *testing.T) {
		stallPhase(t, 5, 33, []int{3, 4})
	})
}

// 4. Partition then heal: no safety violation while split, the majority proceeds
// on its own, and the lagging validator ends up BEHIND the longest chain - a
// strict prefix of it - rather than forked.
//
// WHAT THIS SCENARIO CAN HONESTLY ASSERT, and what it cannot: M3 has NO block
// catch-up, so after Heal() the isolated validator still cannot adopt the blocks
// it missed (Transport has no unicast sync). "The chain resumes" is therefore
// asserted about the majority, and the isolated validator's state is asserted as
// lag-not-fork: its height frozen at the partition, its history a prefix of the
// majority's chain (AssertPrefix), and no conflicting block anywhere. Demanding
// reconvergence would need block sync, which is M4's networking work.
//
// Killing mutant (M5): AssertPrefix short-circuited to nil. The scenario still
// passes, because the freeze and the every-height agreement walk pin the same
// property through independent paths - the report records the probe and the
// fork-injection demonstration that shows the scenario catches a real divergence
// with AssertPrefix neutered.
func TestScenarioPartitionThenHeal(t *testing.T) {
	n, err := New(4, Options{TempDir: t.TempDir(), Seed: 4, LatencyMS: 5, TimeoutBase: 200, TimeoutStep: 100})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()

	if _, err := n.RunBlocks(3); err != nil {
		t.Fatal(err)
	}
	// A 1-vs-3 split: the majority side can still commit (3 of 4 = quorum), the
	// minority cannot (1 of 4 < 3).
	n.Partition([]int{0}, []int{1, 2, 3})
	laggedHeight := n.ch[0].Height()

	// RunBlocksAmong waits only on the named set, because the cut-off validator
	// cannot advance and must not block the call - that is the whole situation
	// under test.
	if _, err := n.RunBlocksAmong(8, []int{1, 2, 3}); err != nil {
		t.Fatalf("the majority partition could not make progress on its own: %v", err)
	}

	// The isolated third must not have moved: a validator that reaches nobody
	// holds one vote against quorum 3 and can never commit.
	if got := n.ch[0].Height(); got != laggedHeight {
		t.Fatalf("partitioned validator 0 committed on its own: %d -> %d; a minority of one cannot reach quorum", laggedHeight, got)
	}

	n.Heal()
	// Healing restores CONNECTIVITY, not catch-up: the majority resumes, and
	// validator 0 stays behind it (see the milestone-limits comment above).
	if _, err := n.RunBlocksAmong(12, []int{1, 2, 3}); err != nil {
		t.Fatalf("the chain did not resume after healing: %v", err)
	}

	// The lagging validator is behind, never forked.
	if err := n.AssertPrefix(0); err != nil {
		t.Fatalf("the partitioned validator diverged instead of merely lagging: %v", err)
	}
	if err := n.AssertSameChain(); err != nil {
		t.Fatalf("a safety violation across the partition: %v", err)
	}
	assertAgreedOnEverySharedHeight(t, n, "partition then heal")
}

// 5. A Byzantine validator equivocates: every prevote it sends is duplicated, on
// the wire, as a prevote for a DIFFERENT block ID signed with its own committee
// key. One Byzantine of four is below the one-third bar, so the chain must still
// advance, and no two validators may ever commit conflicting blocks at one
// height.
//
// The tally's one-vote-per-validator rule deduplicates the equivocal pair at the
// same (height, round), so the forged vote cannot inflate any tally - the
// scenario asserts what that defence must deliver: the equivocation is genuinely
// ON THE WIRE (committee-key-signed, conflicting, and received by a peer), the
// chain keeps advancing anyway, and agreement survives.
//
// The second half of the scenario pins the milestone's central safety mechanism,
// the justification gate, directly: a locked validator is fed a conflicting
// proposal whose claimed polka is NOT backed by the prevotes it carries, and
// must NOT prevote it - the lock yields only to EVIDENCE. A positive control
// shows the same engine, same lock, DOES prevote when the proposal carries a
// real quorum of prevotes, so the silence is the gate and not a broken engine.
//
// Killing mutants (M6, M7): with justification verification bypassed, the
// locked validator prevotes the unevidenced proposal and the drive fails; with
// the forged vote never broadcast, the wire assertions fail.
func TestScenarioByzantineEquivocatorDoesNotFork(t *testing.T) {
	n, err := New(4, Options{TempDir: t.TempDir(), Seed: 5, LatencyMS: 5, TimeoutBase: 200, TimeoutStep: 100})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()

	// Validator 3 turns Byzantine: every non-nil prevote it broadcasts is
	// duplicated as a conflicting prevote, signed with the key it genuinely
	// owns - two equally valid, mutually conflicting votes from one validator.
	if err := n.MakeEquivocator(3); err != nil {
		t.Fatalf("MakeEquivocator: %v", err)
	}

	if _, err := n.RunBlocks(30); err != nil {
		t.Fatalf("one Byzantine validator stalled the chain: %v", err)
	}

	// The equivocation must be REAL: the forged prevote appears on validator 3's
	// own wire, carries its committee key and a verifying signature, and names a
	// block nobody proposed - and at least one honest validator received it.
	eq, ok := n.equivs[3]
	if !ok {
		t.Fatal("no equivocator was installed for validator 3")
	}
	forgedOnWire := 0
	for _, raw := range n.taps[3].sent {
		v, derr := consensus.DecodeVote(raw)
		if derr != nil || v.Type != consensus.MsgPrevote || v.BlockID != eq.forgeID {
			continue
		}
		if idx := n.cfg.IndexOf(v.Validator); idx != 3 {
			t.Fatalf("forged prevote on the wire carries validator index %d, want 3", idx)
		}
		if verr := v.Verify(); verr != nil {
			t.Fatalf("forged prevote on the wire does not verify as validator 3's own signature: %v", verr)
		}
		forgedOnWire++
	}
	if forgedOnWire == 0 {
		t.Fatal("no forged prevote ever reached validator 3's wire: the equivocation stayed local and the Byzantine scenario would be vacuous")
	}
	delivered := 0
	for _, raw := range n.taps[0].recv {
		v, derr := consensus.DecodeVote(raw)
		if derr == nil && v.Type == consensus.MsgPrevote && v.BlockID == eq.forgeID && n.cfg.IndexOf(v.Validator) == 3 {
			delivered++
		}
	}
	if delivered == 0 {
		t.Fatal("no honest validator received the forged prevote; a broadcast that never arrives cannot stress the one-vote-per-validator tally")
	}

	// One Byzantine of four must not break safety OR stall liveness.
	if err := n.AssertSameChain(); err != nil {
		t.Fatalf("a Byzantine equivocator produced a conflicting commit: %v", err)
	}
	assertAgreedOnEverySharedHeight(t, n, "byzantine equivocator")

	// --- The justification gate is load-bearing. ---
	//
	// A local replica of one validator's engine, driven by hand over the same
	// committee: locked on block B, then offered a conflicting proposal whose
	// claimed polka lacks the prevotes to prove it. The engine's response is
	// read from its outbound queue, so the assertion is about what it would
	// actually send.
	h, parent := n.ch[0].Height()+1, n.ch[0].Head().ID()
	cfg := n.cfg
	proposerOf := func(round uint32) int { return cfg.IndexOf(cfg.Proposer(h, round, parent)) }
	// The replica's key must differ from the proposers it will judge, so it is
	// unambiguously in the follower's seat.
	actor := -1
	for i := 0; i < 4; i++ {
		if i != proposerOf(0) && i != proposerOf(2) {
			actor = i
			break
		}
	}
	eng := consensus.NewEngine(cfg, h, parent, n.keys[actor].priv, nil)

	signedVote := func(signer int, round uint32, id [32]byte) *consensus.Vote {
		v := &consensus.Vote{Type: consensus.MsgPrevote, Height: h, Round: round, BlockID: id, Validator: n.keys[signer].priv.Public().(ed25519.PublicKey)}
		signVote(v, n.keys[signer].priv)
		return v
	}
	round0Block, err := n.ch[0].Build(n.keys[proposerOf(0)].priv, nil, parentTimestamp(n)+1)
	if err != nil {
		t.Fatal(err)
	}
	pB := &consensus.Proposal{Height: h, Round: 0, Block: *round0Block, ValidRound: -1, Validator: n.keys[proposerOf(0)].priv.Public().(ed25519.PublicKey)}
	signProposal(pB, n.keys[proposerOf(0)].priv)
	if err := eng.OnMessage(consensus.EncodeProposal(pB)); err != nil {
		t.Fatal(err)
	}
	// Two peers prevote B; with the engine's own prevote that is the quorum of
	// 3, so the engine precommits B - and precommitting IS locking.
	peers := make([]int, 0, 3)
	for i := 0; i < 4; i++ {
		if i != actor {
			peers = append(peers, i)
		}
	}
	for _, i := range peers[:2] {
		if err := eng.OnMessage(consensus.EncodeVote(signedVote(i, 0, round0Block.ID()))); err != nil {
			t.Fatal(err)
		}
	}
	eng.Drain()
	if !eng.Locked() {
		t.Fatal("the replica engine did not lock on B; the gate drive below would not exercise an unlock")
	}

	// Two rounds pass without a decided alternative (the timeouts leave behind
	// only nil prevotes for rounds the engine held no proposal in).
	eng.OnTimeout(consensus.TimeoutEvent{Height: h, Round: eng.Round(), Step: eng.Step()})
	eng.Drain()
	eng.OnTimeout(consensus.TimeoutEvent{Height: h, Round: eng.Round(), Step: eng.Step()})
	eng.Drain()

	// The attack: a conflicting proposal at round 2 claiming a polka from round
	// 1 - carrying NO prevotes to prove it. This is the unlock a Byzantine
	// proposer needs: every validator locked on B would prevote a conflicting
	// block if the bare round number were trusted.
	conflict, err := n.ch[0].Build(n.keys[proposerOf(2)].priv, nil, parentTimestamp(n)+7)
	if err != nil {
		t.Fatal(err)
	}
	if conflict.ID() == round0Block.ID() {
		t.Fatal("the conflicting block is not conflicting; the drive would assert nothing")
	}
	pC := &consensus.Proposal{Height: h, Round: 2, Block: *conflict, ValidRound: 1, Validator: n.keys[proposerOf(2)].priv.Public().(ed25519.PublicKey)}
	signProposal(pC, n.keys[proposerOf(2)].priv)
	if err := eng.OnMessage(consensus.EncodeProposal(pC)); err != nil {
		t.Fatal(err)
	}
	drained := eng.Drain()
	prevoted := 0
	for _, o := range drained {
		if v, derr := consensus.DecodeVote(o.Data); derr == nil && v.Type == consensus.MsgPrevote && v.BlockID == conflict.ID() {
			prevoted++
		}
	}
	if prevoted > 0 || len(drained) > 0 {
		t.Fatalf("THE LOCK YIELDED WITHOUT EVIDENCE: the validator prevoted a conflicting proposal whose claimed polka carried no prevotes (%d prevotes for it, %d messages emitted)", prevoted, len(drained))
	}

	// Positive control: the SAME validator, still locked on B, offered a
	// conflicting proposal whose justification IS a real round-1 quorum of
	// prevotes. The lock must yield to that - evidence, honestly given. Without
	// this control, "no prevote" could pass for a silenced engine rather than a
	// working gate.
	eng.OnTimeout(consensus.TimeoutEvent{Height: h, Round: eng.Round(), Step: eng.Step()})
	eng.Drain()
	evidence, err := n.ch[0].Build(n.keys[proposerOf(eng.Round())].priv, nil, parentTimestamp(n)+13)
	if err != nil {
		t.Fatal(err)
	}
	var polka []*consensus.Vote
	for _, i := range peers {
		polka = append(polka, signedVote(i, 1, evidence.ID()))
	}
	pD := &consensus.Proposal{
		Height: h, Round: eng.Round(), Block: *evidence, ValidRound: 1,
		Justification: encodeJustification(polka),
		Validator:     n.keys[proposerOf(eng.Round())].priv.Public().(ed25519.PublicKey),
	}
	signProposal(pD, n.keys[proposerOf(eng.Round())].priv)
	if err := eng.OnMessage(consensus.EncodeProposal(pD)); err != nil {
		t.Fatal(err)
	}
	drained = eng.Drain()
	prevoted = 0
	for _, o := range drained {
		if v, derr := consensus.DecodeVote(o.Data); derr == nil && v.Type == consensus.MsgPrevote && v.BlockID == evidence.ID() {
			prevoted++
		}
	}
	if prevoted != 1 || len(drained) != 1 {
		t.Fatalf("the gate is deaf, not working: a conflicting proposal backed by a verified round-1 quorum was not prevoted (%d prevotes, %d messages) - an engine that yields to nothing would also pass the refusal above", prevoted, len(drained))
	}
	if _, committed := eng.Committed(); committed {
		t.Fatal("the replica engine committed mid-drive; the assertions above judged a round, not a decided height")
	}
}

// parentTimestamp is the timestamp block proposals in the gate drive build on:
// the parent's plus one, exactly as consensus.Driver.build derives it, so the
// constructed blocks are the blocks a real proposer would have produced.
func parentTimestamp(n *Net) int64 { return n.ch[0].Head().Header.Timestamp }

// 6. Restart mid-epoch: a validator stops, the others advance, and it reopens
// its chain from disk. Replay must re-derive the state root its peers computed,
// and the restarted - now behind - chain must be a prefix of its peers' rather
// than a fork of it.
//
// WHAT THIS SCENARIO CAN HONESTLY ASSERT: the spec requires the replay
// assertion (the state root matches), and safety requires the restarted chain to
// be a PREFIX of the peers' chain. The restarted validator is deliberately NOT
// driven to reconverge: M3 has no block catch-up, so re-entering the committee
// mid-stream would need block sync, which is M4's work. What is additionally
// asserted is that a behind-forever validator is HARMLESS: the peers keep
// committing with it re-wired into the network.
//
// Killing mutant (M8): chain.Open's replay stops applying stored blocks; the
// reopen itself fails the state-root check and the scenario never gets a chain.
func TestScenarioRestartMidEpoch(t *testing.T) {
	n, err := New(4, Options{TempDir: t.TempDir(), Seed: 6, LatencyMS: 5, TimeoutBase: 200, TimeoutStep: 100})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()

	if _, err := n.RunBlocks(5); err != nil {
		t.Fatal(err)
	}
	// Stop validator 3: power it off and close its chain. It stays in the
	// committee, so quorum does NOT become easier for the others.
	stopped := n.ch[3].Height()
	n.TakeOffline(3)
	if err := n.ch[3].Close(); err != nil {
		t.Fatal(err)
	}

	// The other three hold more than two thirds, so they keep going.
	if _, err := n.RunBlocks(12); err != nil {
		t.Fatalf("the chain stalled with one validator stopped: %v", err)
	}

	// Reopen from the same directory. Open replays every stored block and
	// re-derives the state root, so a divergence would have failed Open itself.
	reopened, err := chain.Open(n.genesis(), filepath.Join(n.opts.TempDir, "v3"))
	if err != nil {
		t.Fatalf("reopening the stopped validator failed: %v", err)
	}
	if got := reopened.Height(); got != stopped {
		t.Fatalf("replay reached height %d, want the stored height %d", got, stopped)
	}
	// The assertion the spec names: the replayed state root must equal a peer's
	// at the SAME height. Same chain means same state, or they are not
	// validating one ledger.
	peer, err := n.ch[0].BlockAt(stopped)
	if err != nil {
		t.Fatal(err)
	}
	mine, err := reopened.BlockAt(stopped)
	if err != nil {
		t.Fatal(err)
	}
	if mine.Header.StateRoot != peer.Header.StateRoot {
		id1, id2 := mine.Header.StateRoot, peer.Header.StateRoot
		t.Fatalf("replayed state root diverged at height %d:\n mine %x\n peer %x", stopped, id1[:8], id2[:8])
	}
	if mine.ID() != peer.ID() {
		id1, id2 := mine.ID(), peer.ID()
		t.Fatalf("replayed block diverged at height %d: %x vs %x (state roots matched but the blocks did not)", stopped, id1[:8], id2[:8])
	}

	// Re-wire the restarted (and now permanently behind) validator: a driver
	// that is behind must remain harmless, not disruptive. It is rebuilt over
	// transportFor(3) so the harness's recorder stays wired to the new driver,
	// and the rebuild's OnMessage registration is what lifts the power-off cut.
	n.ch[3] = reopened
	n.offline[3] = false
	n.drv[3] = consensus.NewDriver(n.cfg, reopened, n.keys[3].priv, n.transportFor(3))
	if err := n.AssertPrefix(3); err != nil {
		t.Fatalf("the restarted validator holds a conflicting history: %v", err)
	}

	// The peers must be unaffected by its return.
	if _, err := n.RunBlocksAmong(20, []int{0, 1, 2}); err != nil {
		t.Fatalf("the restarted validator disrupted the running chain: %v", err)
	}
	if got := n.ch[3].Height(); got != stopped {
		t.Fatalf("the restarted validator's height moved %d -> %d: with no catch-up it cannot advance, and anything else would be a fork", stopped, got)
	}
	if err := n.AssertPrefix(3); err != nil {
		t.Fatalf("the restarted validator diverged while sitting behind the quorum: %v", err)
	}
	if err := n.AssertSameChain(); err != nil {
		t.Fatalf("the committee disagreed after the restart: %v", err)
	}
	assertAgreedOnEverySharedHeight(t, n, "restart mid-epoch")
}
