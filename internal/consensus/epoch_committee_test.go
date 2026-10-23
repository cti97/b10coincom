package consensus

// M5 Task 3 — rotation at the epoch boundary.
//
// The task's whole shape is one sentence: consensus for height h uses the
// committee of epoch h/E, and nothing else may change it mid-epoch. These
// tests pin that sentence at the only places it can be violated:
//
//   - the boundary is EXACT (h = E-1 old set, h = E new set);
//   - every height mid-epoch sees one set, even after the bond that decides
//     the NEXT epoch is already gone from committed state;
//   - a restart rebuilds the same boundary from replay;
//   - the tallies at a height are built from exactly one set, so the other
//     epoch's weight cannot combine into a quorum;
//   - the certificate gate and the vote router ask by the height they judge;
//   - a validator whose seat ended becomes an inert follower: it tallies,
//     emits no vote, and does not stall the chain.
//
// Every fixture below CONSTRUCTS its state: a chain is opened over a genesis,
// blocks are built and appended, and the bond is removed by a signed Unbond in
// block 1. No test waits on a socket, a kernel buffer or a schedule.

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/transport"
	"github.com/cti97/b10coincom/internal/types"
)

const (
	// epochTestSeats is the acceptance fixture's starting committee: six
	// equal seats. A 6 -> 5 rotation is satisfiable under the 1/4 cap (1/5 =
	// 0.20); a 4 -> 3 rotation would not be (three equal seats are 1/3), so
	// no fixture here shrinks to three.
	epochTestSeats = 6
	// epochTestBlocks is E. Small on purpose: the boundary is at 4 and the
	// last pre-boundary height at 3.
	epochTestBlocks = 4
	// epochTestStake is one spark per seat, exactly as simnet's genesis seats
	// are powered. It keeps the arithmetic legible - the quorum is literally
	// "5 of 6" then "4 of 5" - and it is the RATIO the boundary argument turns
	// on. The shipped MIN_STAKE (1,000 b10) bond is exercised end to end by
	// internal/devnet's rotation test; nothing here needs a realistic amount.
	epochTestStake = 1
	// epochTestDeparting is the seat whose bond is removed in block 1, i.e.
	// the validator whose seat ends exactly at the boundary.
	epochTestDeparting = epochTestSeats - 1
)

// epochGenesis builds a genesis of equal-stake seats over the shared test
// committee keys, with the given epoch length.
func epochGenesis(t *testing.T, seats int, blocks uint64) *genesis.Genesis {
	t.Helper()
	g := genesis.Devnet()
	g.ChainID = fmt.Sprintf("b10coin-epoch-test-%d-%d", seats, blocks)
	g.Params.ChainID = g.ChainID
	vals := make([]genesis.Validator, seats)
	for i := range vals {
		vals[i] = genesis.Validator{PubKey: committeePub(i), Power: epochTestStake}
	}
	g.Validators = vals
	g.Params.CommitteeSize = seats
	g.Params.EpochBlocks = blocks
	return g
}

// epochUnbondTx is seat's full Unbond of its genesis bond, signed for g.
func epochUnbondTx(t *testing.T, g *genesis.Genesis, seat int) types.Tx {
	t.Helper()
	pub := committeePub(seat)
	tx := types.Tx{Type: types.TxUnbond, From: types.AddressFromPub(pub), PubKey: pub, Nonce: 0, Amount: epochTestStake}
	tx.Sig = testSign(t, seat, tx.SigningHash(g.Hash()))
	return tx
}

// epochRotationChain opens g on dir and commits blocks 1..through. Block 1
// carries the departing seat's Unbond, so from height 1 the bond is gone from
// committed state - while epoch 0's committee, decided by the GENESIS state,
// must keep it. That gap is the mid-epoch stability property in fixture form.
func epochRotationChain(t *testing.T, g *genesis.Genesis, dir string, through uint64) *chain.Chain {
	t.Helper()
	ch, err := chain.Open(g, dir)
	if err != nil {
		t.Fatalf("opening the epoch fixture chain: %v", err)
	}
	for h := uint64(1); h <= through; h++ {
		var txs []types.Tx
		if h == 1 {
			txs = []types.Tx{epochUnbondTx(t, g, epochTestDeparting)}
		}
		blk, err := ch.Build(testCommitteeKey(0), txs, ch.Head().Header.Timestamp+1)
		if err != nil {
			_ = ch.Close()
			t.Fatalf("building block %d: %v", h, err)
		}
		if err := ch.Append(blk); err != nil {
			_ = ch.Close()
			t.Fatalf("appending block %d: %v", h, err)
		}
	}
	return ch
}

// mustCommittee is CommitteeAt or a fatal error.
func mustCommittee(t *testing.T, ch *chain.Chain, h uint64) []genesis.Validator {
	t.Helper()
	vals, err := ch.CommitteeAt(h)
	if err != nil {
		t.Fatalf("CommitteeAt(%d): %v", h, err)
	}
	return vals
}

func sameCommittee(a, b []genesis.Validator) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Power != b[i].Power || !bytes.Equal(a[i].PubKey, b[i].PubKey) {
			return false
		}
	}
	return true
}

func committeeHas(vals []genesis.Validator, pub []byte) bool {
	for i := range vals {
		if bytes.Equal(vals[i].PubKey, pub) {
			return true
		}
	}
	return false
}

// committeeQuorum is the quorum a validator would build for this set: the
// two-thirds-of-total rule over the cap the seat count calls for.
func committeeQuorum(vals []genesis.Validator) uint64 {
	num, den := PowerCapFor(len(vals))
	return Config{Committee: vals, PowerCapNum: num, PowerCapDen: den}.Quorum()
}

// epochPrecommit is seat's correctly signed precommit at (height, round).
func epochPrecommit(t *testing.T, seat int, height uint64, round uint32, id [32]byte) *Vote {
	t.Helper()
	v := &Vote{Type: MsgPrecommit, Height: height, Round: round, BlockID: id, Validator: committeePub(seat)}
	v.Sig = testSign(t, seat, v.SigningHash())
	return v
}

// epochFakeTransport records what a driver broadcasts and delivers nothing.
type epochFakeTransport struct {
	mu     sync.Mutex
	frames [][]byte
}

func (t *epochFakeTransport) Send(transport.PeerID, []byte) error { return nil }
func (t *epochFakeTransport) Broadcast(data []byte) error {
	t.mu.Lock()
	t.frames = append(t.frames, append([]byte(nil), data...))
	t.mu.Unlock()
	return nil
}
func (t *epochFakeTransport) Peers() []transport.PeerID         { return nil }
func (t *epochFakeTransport) Close() error                      { return nil }
func (t *epochFakeTransport) OnMessage(func(transport.Message)) {}
func (t *epochFakeTransport) votesAt(height uint64) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for _, f := range t.frames {
		if v, err := DecodeVote(f); err == nil && v.Height == height {
			n++
		}
	}
	return n
}

// TestTheCommitteeChangesExactlyAtTheBoundary is the off-by-one pin. E = 4, so
// h = 3 is the last height of epoch 0 and h = 4 the first of epoch 1: one
// height apart, and the two adjacent heights must name DIFFERENT sets, with
// every other height of each epoch naming the same one.
//
// The mutants this kills: the epoch as h/E+1 (shifts every boundary one block
// early - at h = 3 epoch 1's set would be returned), (h+1)/E (shifts it one
// block late - h = 4 still epoch 0), and deriving from head state (at head 3
// the head state has five bonds, so epoch 0's six-seat answer would become
// five).
func TestTheCommitteeChangesExactlyAtTheBoundary(t *testing.T) {
	g := epochGenesis(t, epochTestSeats, epochTestBlocks)
	ch := epochRotationChain(t, g, t.TempDir(), epochTestBlocks-1) // head = 3
	defer ch.Close()

	oldSet := mustCommittee(t, ch, epochTestBlocks-1) // h = 3
	newSet := mustCommittee(t, ch, epochTestBlocks)   // h = 4

	if len(oldSet) != 6 || len(newSet) != 5 {
		t.Fatalf("seat counts: epoch 0 = %d, epoch 1 = %d; want 6 and 5", len(oldSet), len(newSet))
	}
	departing := committeePub(epochTestDeparting)
	if !committeeHas(oldSet, departing) {
		t.Fatal("epoch 0's committee lost the departing validator; its seats come from genesis")
	}
	if committeeHas(newSet, departing) {
		t.Fatal("epoch 1's committee still seats the validator whose bond was removed at height 1")
	}
	if got := committeeQuorum(oldSet); got != 5 {
		t.Fatalf("epoch 0 quorum = %d, want 5 of 6", got)
	}
	if got := committeeQuorum(newSet); got != 4 {
		t.Fatalf("epoch 1 quorum = %d, want 4 of 5", got)
	}

	// Every height INSIDE an epoch names that epoch's set, all the way out.
	for _, h := range []uint64{1, 2, 3} {
		if got := mustCommittee(t, ch, h); !sameCommittee(got, oldSet) {
			t.Fatalf("CommitteeAt(%d) is not epoch 0's set", h)
		}
	}
	for _, h := range []uint64{4, 5, 6, 7} {
		if got := mustCommittee(t, ch, h); !sameCommittee(got, newSet) {
			t.Fatalf("CommitteeAt(%d) is not epoch 1's set", h)
		}
	}

	// The two adjacent heights, stated on their own: this is the whole bug.
	if got := mustCommittee(t, ch, epochTestBlocks-1); !sameCommittee(got, oldSet) {
		t.Fatalf("h = E-1 = %d did not use the old set", epochTestBlocks-1)
	}
	if got := mustCommittee(t, ch, epochTestBlocks); !sameCommittee(got, newSet) {
		t.Fatalf("h = E = %d did not use the new set", epochTestBlocks)
	}

	// A future epoch is an ERROR, never a derivation from the head: epoch 2 is
	// decided by the state at height 7, which this chain has not committed.
	if _, err := ch.CommitteeAt(2 * epochTestBlocks); !errors.Is(err, chain.ErrNoCommittee) {
		t.Fatalf("CommitteeAt(%d) = %v; want chain.ErrNoCommittee (no derivation from the head)", 2*epochTestBlocks, err)
	}
}

// TestTheBoundaryCommitteeSurvivesReplay: the memo is derived state, rebuilt
// by replay. A node that restarts just before a boundary must derive the same
// next epoch's seats from the stored blocks - otherwise it forks the moment it
// judges the first height of the new epoch.
func TestTheBoundaryCommitteeSurvivesReplay(t *testing.T) {
	g := epochGenesis(t, epochTestSeats, epochTestBlocks)
	dir := t.TempDir()
	ch := epochRotationChain(t, g, dir, epochTestBlocks-1)

	want := map[uint64][]genesis.Validator{}
	for _, h := range []uint64{0, 1, 2, 3, 4, 7} {
		want[h] = mustCommittee(t, ch, h)
	}
	if err := ch.Close(); err != nil {
		t.Fatalf("closing before reopen: %v", err)
	}

	reopened, err := chain.Open(g, dir)
	if err != nil {
		t.Fatalf("reopening the chain: %v", err)
	}
	defer reopened.Close()
	if reopened.Height() != epochTestBlocks-1 {
		t.Fatalf("replayed height = %d, want %d", reopened.Height(), epochTestBlocks-1)
	}
	for h, expected := range want {
		got := mustCommittee(t, reopened, h)
		if !sameCommittee(got, expected) {
			t.Fatalf("replay derived a different committee at height %d: got %d seats, want %d", h, len(got), len(expected))
		}
	}
}

// TestAnUnbondMidEpochDoesNotChangeThatEpoch: the bond is ALREADY zero in
// committed state when heights 2 and 3 are judged, yet epoch 0's seats and
// quorum are unchanged. The set is a function of the state at E-1's
// predecessor - here genesis - not of whatever the head now holds.
//
// The mutant this kills is "recompute the committee from the head state": at
// head 3 that derivation would drop the departing seat immediately, one epoch
// early, and (the dangerous direction) a validator elected mid-epoch would be
// counted before its first block.
func TestAnUnbondMidEpochDoesNotChangeThatEpoch(t *testing.T) {
	g := epochGenesis(t, epochTestSeats, epochTestBlocks)
	ch := epochRotationChain(t, g, t.TempDir(), epochTestBlocks-1)
	defer ch.Close()

	addr := types.AddressFromPub(committeePub(epochTestDeparting))
	if got := ch.State().Bonded(addr); got != 0 {
		t.Fatalf("fixture: the departing seat still holds a bond of %d at head %d", got, ch.Height())
	}

	atTwo := mustCommittee(t, ch, 2)
	atThree := mustCommittee(t, ch, 3)
	atZero := mustCommittee(t, ch, 0)
	if !sameCommittee(atTwo, atThree) || !sameCommittee(atZero, atTwo) {
		t.Fatal("the committee moved inside epoch 0 after the bond was removed")
	}
	if !committeeHas(atThree, committeePub(epochTestDeparting)) {
		t.Fatal("epoch 0 stopped seating the departing validator before its boundary")
	}
	if got := committeeQuorum(atThree); got != 5 {
		t.Fatalf("epoch 0 quorum moved to %d mid-epoch", got)
	}
}

// TestVotesAcrossTheBoundaryDoNotCombine is the constructed safety test: the
// tallies at a height are built from exactly one committee, so the other
// epoch's weight fails membership before its power is counted.
//
// At H = E the set is epoch 1's five seats. The old epoch's votes are offered
// at H: the departing seat's is refused outright (it is not a member of the
// new set), and the four continuing seats reach the new quorum of 4. The SAME
// four votes are not a quorum of the old set, whose bar is 5. A second block
// at H can then collect at most the one remaining seat, so it cannot reach 4.
//
// The mutant this kills is a genesis-wide membership/quorum check: it would
// accept the departing vote and set the bar at 5, so four votes would not
// commit and the "four continuing seats reach quorum" assertion fails.
func TestVotesAcrossTheBoundaryDoNotCombine(t *testing.T) {
	g := epochGenesis(t, epochTestSeats, epochTestBlocks)
	ch := epochRotationChain(t, g, t.TempDir(), epochTestBlocks-1)
	defer ch.Close()

	oldSet := mustCommittee(t, ch, epochTestBlocks-1)
	newSet := mustCommittee(t, ch, epochTestBlocks)
	h := uint64(epochTestBlocks)

	cfg := Config{Committee: newSet, TimeoutBase: 2_000, TimeoutStep: 1_000}
	cfg.PowerCapNum, cfg.PowerCapDen = PowerCapFor(len(newSet))
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the boundary's committee does not validate: %v", err)
	}
	vs := NewVoteSet(cfg, h, 0, MsgPrecommit)
	blockA := crypto.HashParts([]byte("epoch-test block A at the boundary"))

	// The departing seat's old weight is not part of this height's set.
	if _, err := vs.Add(epochPrecommit(t, epochTestDeparting, h, 0, blockA)); !errors.Is(err, ErrNotValidator) {
		t.Fatalf("the leaving validator's vote at H was not refused: %v", err)
	}
	if vs.HasQuorum(blockA) {
		t.Fatal("one departing vote reached quorum at the boundary")
	}

	// The four continuing seats ARE the new quorum.
	for _, seat := range []int{0, 1, 2, 3} {
		added, err := vs.Add(epochPrecommit(t, seat, h, 0, blockA))
		if err != nil || !added {
			t.Fatalf("continuing seat %d's vote at H was not tallied: added=%v err=%v", seat, added, err)
		}
	}
	if !vs.HasQuorum(blockA) {
		t.Fatal("four continuing seats did not reach epoch 1's quorum at H")
	}

	// The same four votes are NOT a quorum at H-1, where the old set's bar is
	// 5: the bar follows the block's epoch, not one global number.
	oldVS := NewVoteSet(Config{Committee: oldSet, PowerCapNum: 1, PowerCapDen: 4}, h-1, 0, MsgPrecommit)
	blockOld := crypto.HashParts([]byte("epoch-test block at E-1"))
	for _, seat := range []int{0, 1, 2, 3} {
		if _, err := oldVS.Add(epochPrecommit(t, seat, h-1, 0, blockOld)); err != nil {
			t.Fatalf("continuing seat %d's vote at E-1 was refused: %v", seat, err)
		}
	}
	if oldVS.HasQuorum(blockOld) {
		t.Fatal("four of six reached epoch 0's quorum of five")
	}

	// ONE HEIGHT, ONE SET: a conflicting block at H cannot combine with the
	// quorum already tallied. The four signers are spent (one vote per
	// validator), the departing seat is not a member, and the one free seat
	// holds 1 of the 4 needed.
	blockB := crypto.HashParts([]byte("epoch-test conflicting block B at the boundary"))
	for _, seat := range []int{0, 1, 2, 3} {
		added, err := vs.Add(epochPrecommit(t, seat, h, 0, blockB))
		if err != nil || added {
			t.Fatalf("seat %d's second vote at H was counted: added=%v err=%v", seat, added, err)
		}
	}
	if _, err := vs.Add(epochPrecommit(t, epochTestDeparting, h, 0, blockB)); !errors.Is(err, ErrNotValidator) {
		t.Fatalf("the departing validator's vote for the conflicting block was not refused: %v", err)
	}
	if _, err := vs.Add(epochPrecommit(t, 4, h, 0, blockB)); err != nil {
		t.Fatalf("the one free seat's vote for B was refused: %v", err)
	}
	if vs.HasQuorum(blockB) {
		t.Fatal("two blocks reached quorum at one height by adding the other epoch's weight")
	}
}

// TestTheCertificateGateUsesTheBlocksEpoch: the certificate re-tally uses the
// committee of the BLOCK's height. Four continuing seats are epoch 1's quorum
// (4 of 5), so a height-4 certificate carrying those four verifies; the same
// four votes, signed for a height-3 block, are refused because epoch 0's bar
// is 5 of 6.
//
// The mutant this kills: verifyCertificate left on Genesis().Validators. With
// the genesis set every block is judged by six seats and a bar of five, so the
// height-4 certificate of four votes is refused - the first leg fails.
func TestTheCertificateGateUsesTheBlocksEpoch(t *testing.T) {
	g := epochGenesis(t, epochTestSeats, epochTestBlocks)
	ch := epochRotationChain(t, g, t.TempDir(), epochTestBlocks-1)
	defer ch.Close()
	s := NewSyncer(ch, nil, testCommitteeKey(0))

	atBoundary := &types.Block{Header: types.Header{Height: epochTestBlocks, Timestamp: 1}}
	inOldEpoch := &types.Block{Header: types.Header{Height: epochTestBlocks - 1, Timestamp: 1}}

	votesAt := func(height uint64, blk *types.Block) []*Vote {
		votes := make([]*Vote, 0, 4)
		for _, seat := range []int{0, 1, 2, 3} {
			votes = append(votes, epochPrecommit(t, seat, height, 0, blk.ID()))
		}
		return votes
	}
	if err := s.verifyCertificate(atBoundary, 0, votesAt(epochTestBlocks, atBoundary)); err != nil {
		t.Fatalf("a quorum of epoch 1's seats was refused for a height-in-epoch-1 block: %v", err)
	}
	if err := s.verifyCertificate(inOldEpoch, 0, votesAt(epochTestBlocks-1, inOldEpoch)); err == nil {
		t.Fatal("four of six was accepted as epoch 0's quorum of five")
	}

	// The departing seat is not a member at H: three continuing seats plus it
	// are three counted votes, not four, and cannot reach epoch 1's quorum.
	withDeparting := append(votesAt(epochTestBlocks, atBoundary)[:3],
		epochPrecommit(t, epochTestDeparting, epochTestBlocks, 0, atBoundary.ID()))
	if err := s.verifyCertificate(atBoundary, 0, withDeparting); err == nil {
		t.Fatal("the departing validator's vote was counted into epoch 1's certificate")
	}
}

// TestAnUnseatedEngineEmitsNothing: an engine whose key is not in its
// committee tallies inbound frames, emits nothing, and refuses its own vote
// with ErrNotValidator instead of panicking.
func TestAnUnseatedEngineEmitsNothing(t *testing.T) {
	g := epochGenesis(t, epochTestSeats, epochTestBlocks)
	ch := epochRotationChain(t, g, t.TempDir(), epochTestBlocks-1)
	defer ch.Close()

	newSet := mustCommittee(t, ch, epochTestBlocks)
	capNum, capDen := PowerCapFor(len(newSet))
	cfg := Config{Committee: newSet, TimeoutBase: 2_000, TimeoutStep: 1_000, PowerCapNum: capNum, PowerCapDen: capDen}
	e := NewEngine(cfg, epochTestBlocks, crypto.HashParts([]byte("parent")), testCommitteeKey(epochTestDeparting), nil)
	if err := e.CheckMembership(); !errors.Is(err, ErrNotValidator) {
		t.Fatalf("an engine outside the committee reports membership %v", err)
	}
	// It still tallies a valid inbound vote.
	id := crypto.HashParts([]byte("block for the unseated engine"))
	if err := e.OnMessage(EncodeVote(epochPrecommit(t, 0, epochTestBlocks, 0, id))); err != nil {
		t.Fatalf("the unseated engine refused a valid vote: %v", err)
	}
	if out := e.Drain(); len(out) != 0 {
		t.Fatalf("the unseated engine emitted %d message(s)", len(out))
	}
	// The vote it owes on a timeout is refused, not emitted: ErrNotValidator
	// is audit C-11's contract (TestANonMemberEngineReturnsAnErrorInsteadOfPanicking),
	// and the refusal is what makes a rotated-out validator inert.
	if err := e.OnTimeout(TimeoutEvent{Height: epochTestBlocks, Round: 0}); !errors.Is(err, ErrNotValidator) {
		t.Fatalf("the unseated engine's timeout = %v, want ErrNotValidator", err)
	}
	if out := e.Drain(); len(out) != 0 {
		t.Fatalf("the unseated engine emitted %d message(s) on a timeout", len(out))
	}
}

// TestAValidatorWhoseSeatEndsStopsActingAtTheBoundary: after the others commit
// past the boundary, the departing validator is still at E-1, its history is a
// prefix of theirs, and it emits no vote for E. It is not broken: its per-height
// engine is the five-seat set, so it has no seat, tallies, and stays silent.
//
// The mutant this kills: keeping d.cfg instead of building the height's config.
// With the genesis config the engine at E would still hold a seat and emit a
// nil prevote at E on its first timeout - the assertion below sees it.
func TestAValidatorWhoseSeatEndsStopsActingAtTheBoundary(t *testing.T) {
	g := epochGenesis(t, epochTestSeats, epochTestBlocks)
	departingCh := epochRotationChain(t, g, t.TempDir(), epochTestBlocks-1)
	defer departingCh.Close()

	// The rest of the committee's chain: the same pre-boundary blocks (same
	// genesis, same Unbond in block 1, same timestamps, same proposer, so
	// byte-identical) plus the boundary block the departing validator no
	// longer votes on.
	committeeCh, err := chain.Open(g, t.TempDir())
	if err != nil {
		t.Fatalf("opening the committee's chain: %v", err)
	}
	defer committeeCh.Close()
	for h := uint64(1); h <= epochTestBlocks; h++ {
		var txs []types.Tx
		if h == 1 {
			txs = []types.Tx{epochUnbondTx(t, g, epochTestDeparting)}
		}
		blk, err := committeeCh.Build(testCommitteeKey(0), txs, committeeCh.Head().Header.Timestamp+1)
		if err != nil {
			t.Fatalf("committee chain, block %d: %v", h, err)
		}
		if err := committeeCh.Append(blk); err != nil {
			t.Fatalf("committee chain, block %d: %v", h, err)
		}
	}
	for h := uint64(1); h <= epochTestBlocks-1; h++ {
		mine, err := departingCh.BlockAt(h)
		if err != nil {
			t.Fatalf("departing chain block %d: %v", h, err)
		}
		theirs, err := committeeCh.BlockAt(h)
		if err != nil {
			t.Fatalf("committee chain block %d: %v", h, err)
		}
		if mine.ID() != theirs.ID() {
			t.Fatalf("the histories diverge before the boundary at height %d", h)
		}
	}
	if committeeCh.Height() != epochTestBlocks {
		t.Fatalf("the committee did not commit past the boundary: head %d", committeeCh.Height())
	}

	cfg := Config{
		Committee:    g.Validators,
		CommitteeFor: departingCh.CommitteeAt,
		TimeoutBase:  2_000,
		TimeoutStep:  1_000,
	}
	cfg.PowerCapNum, cfg.PowerCapDen = PowerCapFor(len(g.Validators))
	tp := &epochFakeTransport{}
	drv, err := NewDriver(cfg, departingCh, testCommitteeKey(epochTestDeparting), tp, nil)
	if err != nil {
		t.Fatalf("a rotated-out validator could not build a driver: %v", err)
	}
	if got := len(drv.eng.cfg.Committee); got != 5 {
		t.Fatalf("the boundary engine was built with %d seats, want epoch 1's 5", got)
	}
	if err := drv.eng.CheckMembership(); !errors.Is(err, ErrNotValidator) {
		t.Fatalf("the boundary engine holds a seat: %v", err)
	}
	if drv.HaltError() != nil {
		t.Fatalf("the driver halted instead of following: %v", drv.HaltError())
	}

	// Drive the clock past several timeouts. Every timeout's owed vote is
	// refused (audit C-11) and nothing is emitted.
	for tick := int64(10_000); tick <= 60_000; tick += 5_000 {
		drv.Tick(tick)
	}
	if got := tp.votesAt(epochTestBlocks); got != 0 {
		t.Fatalf("the departing validator emitted %d vote(s) at the boundary height", got)
	}
	if got := departingCh.Height(); got != epochTestBlocks-1 {
		t.Fatalf("the departing validator advanced to %d without a seat; want %d", got, epochTestBlocks-1)
	}
}

// TestTheRouterRefusesTheOldEpochsVotes: the router's membership check is per
// FRAME height. With the local head at E-1 the vote window is {E-1, E}: the
// departing validator's vote at E is refused before any signature work, while
// its vote at E-1 (its own epoch) and a continuing seat's vote at E are routed
// to the engine.
//
// The mutant this kills: leaving the router's membership on the genesis set.
// Under it the departing vote at E passes membership and Route returns true.
func TestTheRouterRefusesTheOldEpochsVotes(t *testing.T) {
	g := epochGenesis(t, epochTestSeats, epochTestBlocks)
	ch := epochRotationChain(t, g, t.TempDir(), epochTestBlocks-1)
	defer ch.Close()

	r := NewMessageRouter(NewSyncer(ch, nil, testCommitteeKey(0)))
	id := crypto.HashParts([]byte("router block at the boundary"))
	route := func(v *Vote) bool {
		return r.Route(transport.Message{Data: EncodeVote(v)})
	}

	if route(epochPrecommit(t, epochTestDeparting, epochTestBlocks, 0, id)) {
		t.Fatal("the router admitted a vote at E from a validator whose seat ended at E")
	}
	if got := r.RefusedBeforeVerify(); got != 1 {
		t.Fatalf("refused-before-verify = %d, want 1 (the departing seat at E)", got)
	}
	if !route(epochPrecommit(t, 0, epochTestBlocks, 0, id)) {
		t.Fatal("the router refused a seated validator's vote at E")
	}
	if !route(epochPrecommit(t, epochTestDeparting, epochTestBlocks-1, 0, id)) {
		t.Fatal("the router refused the departing validator's vote at E-1, where it was still seated")
	}
}

// TestPowerCapFor pins the cap rule the per-height config carries: 1/4 at four
// or more seats, 1/1 below. The state derivation uses the same threshold; a
// three-seat committee under 1/4 is unsatisfiable and Config.Validate refuses
// it, so a regression here would halt a legitimate rotation.
func TestPowerCapFor(t *testing.T) {
	for n := 1; n <= 8; n++ {
		num, den := PowerCapFor(n)
		if n >= 4 {
			if num != 1 || den != 4 {
				t.Fatalf("PowerCapFor(%d) = %d/%d, want 1/4", n, num, den)
			}
			continue
		}
		if num != 1 || den != 1 {
			t.Fatalf("PowerCapFor(%d) = %d/%d, want 1/1 (1/4 cannot bind below four seats)", n, num, den)
		}
	}
}
