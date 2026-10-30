package devnet

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/simnet"
	"github.com/cti97/b10coincom/internal/state"
	"github.com/cti97/b10coincom/internal/types"
)

// nkKey is a fixed 32-byte key for a constructed committee. Nakamoto never
// verifies a signature, so these need only be distinct and orderable by bytes;
// the state tests go through AddressFromPub, which hashes any bytes.
func nkKey(b byte) []byte {
	key := make([]byte, ed25519.PublicKeySize)
	key[0] = b
	return key
}

func nkSeats(powers ...uint64) []genesis.Validator {
	out := make([]genesis.Validator, len(powers))
	for i, p := range powers {
		out[i] = genesis.Validator{PubKey: nkKey(byte(i + 1)), Power: p}
	}
	return out
}

// nkState builds committed state from a list of bond amounts: seat i's key is
// nkKey(i+1) and its bond is amounts[i]. It is constructed state, not a chain
// driven through a timing-sensitive path.
func nkState(t *testing.T, amounts ...uint64) *state.State {
	t.Helper()
	st := state.NewWithParams(state.Params{CommitteeSize: len(amounts)})
	for i, amount := range amounts {
		pub := nkKey(byte(i + 1))
		st.SetBond(types.AddressFromPub(pub), state.Bond{Validator: pub, Amount: amount})
	}
	return st
}

// TestNakamotoCountsTheSmallestShareAboveOneThird pins the definition at the
// values the plan states. The 4-equal case (2, not 1) is the strictness the
// definition turns on; 21 equal is the known figure.
func TestNakamotoCountsTheSmallestShareAboveOneThird(t *testing.T) {
	cases := []struct {
		name   string
		powers []uint64
		want   int
	}{
		{"four equal", []uint64{1, 1, 1, 1}, 2},
		{"five equal", []uint64{1, 1, 1, 1, 1}, 2},
		{"six equal", []uint64{1, 1, 1, 1, 1, 1}, 3},
		{"twenty-one equal", []uint64{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, 8},
		{"30 percent plus four at 17.5", []uint64{300, 175, 175, 175, 175}, 2},
		{"three equal (exactly one third)", []uint64{1, 1, 1}, 2},
		{"one seat", []uint64{7}, 1},
		{"empty", nil, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Nakamoto(nkSeats(tc.powers...)); got != tc.want {
				t.Fatalf("Nakamoto(%v) = %d, want %d", tc.powers, got, tc.want)
			}
		})
	}
}

// TestNakamotoThresholdIsStrictAtExactlyOneThird proves both sides of the
// boundary: exactly one third is NOT enough, one spark more IS. Both committees
// have the same total (9), so the only variable is the largest seat.
func TestNakamotoThresholdIsStrictAtExactlyOneThird(t *testing.T) {
	// 3 / 9 is exactly one third: the first seat does not clear the bar alone,
	// so the smallest coalition is two seats (6 > 3). A `>=` implementation
	// returns 1 here.
	if got := Nakamoto(nkSeats(3, 3, 3)); got != 2 {
		t.Fatalf("exactly one third: Nakamoto({3,3,3}) = %d, want 2 (equality must not count)", got)
	}
	t.Logf("exactly one third: powers {3,3,3}, total 9, threshold floor(9/3)=3; largest seat 3 is NOT > 3, so k=2")
	// 4 / 9 is one spark more than one third: the first seat alone clears it.
	// A `>` implementation returns 1, as it must.
	if got := Nakamoto(nkSeats(4, 3, 2)); got != 1 {
		t.Fatalf("one spark over one third: Nakamoto({4,3,2}) = %d, want 1", got)
	}
	t.Logf("one spark more: powers {4,3,2}, total 9, threshold 3; largest seat 4 > 3, so k=1")
}

// TestNakamotoOnACappedCommittee checks the coefficient against the 1/4 cap
// the committee derivation actually applies.
//
// THE MINIMUM ON A CAPPED COMMITTEE IS 2, NOT 4. The cap says no seat exceeds
// T/4; two such seats are T/2, which is already greater than T/3, so four
// seats are not needed to exceed one third. What the cap does rule out is k=1:
// one seat is at most T/4 < T/3. A 4-equal committee is exactly at the cap and
// returns 2, and a 6-equal committee returns 3 - both are correct, so an
// implementation returning 3 is not evidence that either rule is wrong.
func TestNakamotoOnACappedCommittee(t *testing.T) {
	// The fixed point is five EQUAL seats of 1 spark: 100 -> 26 (T=104) -> 7
	// (T=30) -> 2 (T=11) -> 1 (T=6) -> stable (T=5). Five equal seats are 2 of
	// 5 = 40% > one third, so k=2. Constructed state, no timing.
	st := nkState(t, 100, 1, 1, 1, 1)
	committee, err := st.Committee()
	if err != nil {
		t.Fatalf("Committee: %v", err)
	}
	if len(committee) != 5 {
		t.Fatalf("seats = %d, want 5", len(committee))
	}
	var total uint64
	for _, v := range committee {
		if v.Power != 1 {
			t.Fatalf("capped power = %d, want the fixed point 1 for every seat (%+v)", v.Power, committee)
		}
		total += v.Power
	}
	if total != 5 {
		t.Fatalf("total power = %d, want 5", total)
	}
	if got := Nakamoto(committee); got != 2 {
		t.Fatalf("Nakamoto on the clamped 5-seat committee = %d, want 2", got)
	}
	t.Logf("clamped 5-seat committee: powers {1,1,1,1,1}, total 5, threshold 1; k=2 (2/5 > 1/3)")

	// Four equal seats at exactly the 1/4 cap: T=4, cap 1, every seat is at the
	// cap. Two seats are T/2 > T/3, so k = 2, and no capped committee can do
	// better (one seat is T/4 < T/3).
	st4 := nkState(t, 1, 1, 1, 1)
	c4, err := st4.Committee()
	if err != nil {
		t.Fatalf("Committee (4 seats): %v", err)
	}
	for _, v := range c4 {
		if v.Power != 1 {
			t.Fatalf("4-seat capped power = %d, want 1", v.Power)
		}
	}
	if got := Nakamoto(c4); got != 2 {
		t.Fatalf("Nakamoto on the 4-equal capped committee = %d, want 2 (the capped minimum)", got)
	}
	t.Logf("4 equal caps: powers {1,1,1,1}, total 4, threshold 1; k=2 -- the true capped minimum, not 4")

	// And a 6-equal capped committee returns 3: two of six seats are exactly
	// one third (not enough), three are one half. This is the case that proves
	// "3 on a capped committee" is a correct answer, not a contradiction.
	st6 := nkState(t, 1, 1, 1, 1, 1, 1)
	c6, err := st6.Committee()
	if err != nil {
		t.Fatalf("Committee (6 seats): %v", err)
	}
	if got := Nakamoto(c6); got != 3 {
		t.Fatalf("Nakamoto on the 6-equal capped committee = %d, want 3", got)
	}
	t.Logf("6 equal caps: powers {1,1,1,1,1,1}, total 6, threshold 2; 2/6 is exactly 1/3, so k=3 (cap holds: 1 <= 6/4)")
	for _, v := range c6 {
		if 4*v.Power > 6 { // the 1/4 cap, formed against the emitted total
			t.Fatalf("seat power %d is above 1/4 of the seated total 6", v.Power)
		}
	}
}

// TestNakamotoOrdersTiesByPublicKeyBytes pins the tie-break: power descending,
// then public-key bytes ascending - the rule state's committee derivation uses.
func TestNakamotoOrdersTiesByPublicKeyBytes(t *testing.T) {
	committee := []genesis.Validator{
		{PubKey: nkKey(0x30), Power: 5},
		{PubKey: nkKey(0x10), Power: 5},
		{PubKey: nkKey(0x00), Power: 9}, // the strongest seat, whatever its key
		{PubKey: nkKey(0x20), Power: 5},
	}
	ordered := orderedSeats(committee)
	want := []byte{0x00, 0x10, 0x20, 0x30}
	for i, key := range want {
		if ordered[i].PubKey[0] != key {
			t.Fatalf("ordered seat %d has key %#x, want %#x (order %v)", i, ordered[i].PubKey[0], key, ordered)
		}
	}
	// The input was not reordered: a report must not sort committed state in
	// place.
	if committee[0].PubKey[0] != 0x30 {
		t.Fatal("orderedSeats reordered its caller's committee")
	}
}

// fixedCommitteeSource is a hand-built CommitteeSource: it lets the report be
// tested without a chain, including the refusal cases.
type fixedCommitteeSource struct {
	committee []genesis.Validator
	err       error
}

func (s fixedCommitteeSource) CommitteeAt(uint64) ([]genesis.Validator, error) {
	return s.committee, s.err
}

// TestNakamotoOverAnEmptyCommitteeRefuses: the pure function answers 0 for an
// empty committee (there is nothing to count), but the REPORT refuses - 0/0 has
// no coefficient, and a printed k=0 would look like a chain-reported number.
func TestNakamotoOverAnEmptyCommitteeRefuses(t *testing.T) {
	if got := Nakamoto(nil); got != 0 {
		t.Fatalf("Nakamoto(empty) = %d, want 0 without a panic", got)
	}
	if _, err := NakamotoAt(fixedCommitteeSource{}, 0, 4); !errors.Is(err, ErrEmptyCommittee) {
		t.Fatalf("NakamotoAt(empty) error = %v, want ErrEmptyCommittee", err)
	}
	if _, err := NakamotoRows(fixedCommitteeSource{}, 8, 4); !errors.Is(err, ErrEmptyCommittee) {
		t.Fatalf("NakamotoRows(empty) error = %v, want ErrEmptyCommittee", err)
	}
	sentinel := errors.New("the epoch was not decided")
	if _, err := NakamotoAt(fixedCommitteeSource{err: sentinel}, 0, 4); !errors.Is(err, sentinel) {
		t.Fatalf("NakamotoAt source error = %v, want the source's error", err)
	}
	if _, err := NakamotoRows(fixedCommitteeSource{}, 0, 0); !errors.Is(err, ErrNoEpochLength) {
		t.Fatalf("NakamotoRows(epoch 0) error = %v, want ErrNoEpochLength", err)
	}
}

// nkChain builds six genesis seats directly through chain.Build/Append - no
// consensus, no clock, no timing race - with an epoch length of 4 and seat 5
// unbonding at height 1. The committee therefore steps from 6 seats to 5 at
// height 4, giving the report a real committed-state history to read.
func nkChain(t *testing.T) *chain.Chain {
	t.Helper()
	g := simnet.Committee(6)
	g.Params.EpochBlocks = 4
	c, err := chain.Open(g, t.TempDir())
	if err != nil {
		t.Fatalf("opening the constructed chain: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	departing := simnet.ValidatorKey(5)
	pub := departing.Public().(ed25519.PublicKey)
	addr := types.AddressFromPub(pub)
	tx := types.Tx{Type: types.TxUnbond, From: addr, PubKey: pub, Nonce: 0, Amount: 1}
	hash := tx.SigningHash(g.Hash())
	tx.Sig = crypto.Sign(departing, hash[:])

	prev := c.Head()
	for h := uint64(1); h <= 5; h++ {
		var txs []types.Tx
		if h == 1 {
			txs = []types.Tx{tx}
		}
		b, err := c.Build(simnet.ValidatorKey(0), txs, prev.Header.Timestamp+1)
		if err != nil {
			t.Fatalf("building block %d: %v", h, err)
		}
		if err := c.Append(b); err != nil {
			t.Fatalf("appending block %d: %v", h, err)
		}
		prev = b
	}
	return c
}

// TestNakamotoIsComputedFromTheHeightsCommittee: the row for height 0 must
// report the six-seat committee that validated it, even though the head - and
// the boundary's row - is the five-seat set. Reading every row from the head
// reports 5 seats at height 0 and fails here.
func TestNakamotoIsComputedFromTheHeightsCommittee(t *testing.T) {
	c := nkChain(t)
	rows, err := NakamotoRows(c, c.Height(), 4)
	if err != nil {
		t.Fatalf("NakamotoRows: %v", err)
	}
	head, err := c.CommitteeAt(c.Height())
	if err != nil {
		t.Fatalf("CommitteeAt(head): %v", err)
	}
	if len(head) != 5 {
		t.Fatalf("head committee has %d seats, want the rotated 5", len(head))
	}
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want 3 (boundaries 0 and 4, plus head 5)", len(rows))
	}
	want := []NakamotoRow{
		{Epoch: 0, Height: 0, Seats: 6, Nakamoto: 3, TopPower: 1, TotalPower: 6},
		{Epoch: 1, Height: 4, Seats: 5, Nakamoto: 2, TopPower: 1, TotalPower: 5},
		{Epoch: 1, Height: 5, Seats: 5, Nakamoto: 2, TopPower: 1, TotalPower: 5},
	}
	if !reflect.DeepEqual(rows, want) {
		t.Fatalf("rows = %+v, want %+v", rows, want)
	}
}

// TestNakamotoSeriesIsDeterministic: the same chain prints the same series, and
// the coefficient is unchanged when equal-power seats are presented in another
// order. The tie-break is pinned by TestNakamotoOrdersTiesByPublicKeyBytes; the
// number itself is order-invariant, which is what makes it safe to report.
func TestNakamotoSeriesIsDeterministic(t *testing.T) {
	c := nkChain(t)
	first, err := NakamotoRows(c, c.Height(), 4)
	if err != nil {
		t.Fatalf("first NakamotoRows: %v", err)
	}
	second, err := NakamotoRows(c, c.Height(), 4)
	if err != nil {
		t.Fatalf("second NakamotoRows: %v", err)
	}
	if got, want := FormatNakamoto(second), FormatNakamoto(first); got != want {
		t.Fatalf("two readings of one chain disagree:\n%s\nwant:\n%s", got, want)
	}
	committee, err := c.CommitteeAt(0)
	if err != nil {
		t.Fatalf("CommitteeAt(0): %v", err)
	}
	permuted := []genesis.Validator{committee[2], committee[0], committee[5], committee[3], committee[1], committee[4]}
	if got, want := Nakamoto(permuted), Nakamoto(committee); got != want {
		t.Fatalf("Nakamoto depends on the presentation order: %d vs %d", got, want)
	}
	t.Logf("two readings of the same chain are byte-identical:\n%s", FormatNakamoto(first))
	t.Logf("permuted committee: k=%d, original: k=%d", Nakamoto(permuted), Nakamoto(committee))
}

// TestTheReportChangesNoState: building the rows reads committed state and
// nothing else; the head and root are identical before and after.
func TestTheReportChangesNoState(t *testing.T) {
	c := nkChain(t)
	height, root := c.Height(), c.State().Root()
	if _, err := NakamotoRows(c, height, 4); err != nil {
		t.Fatalf("NakamotoRows: %v", err)
	}
	if got := c.Height(); got != height {
		t.Fatalf("the report moved the head from %d to %d", height, got)
	}
	if got := c.State().Root(); got != root {
		t.Fatalf("the report changed the state root:\n got %x\nwant %x", got, root)
	}
}

// TestAPeerWithNoBondCannotMoveTheCoefficient: a connected peer that holds a
// balance but no bond is not a candidate, so it is absent from the committee
// and cannot move the number. Counting it as a seat - the Peers() mistake -
// would, which is why that mutant is killed rather than cosmetic.
func TestAPeerWithNoBondCannotMoveTheCoefficient(t *testing.T) {
	st := nkState(t, 1, 1, 1, 1, 1)
	peer := nkKey(0xEE)
	st.Set(types.AddressFromPub(peer), state.Account{Balance: 1_000_000})

	committee, err := st.Committee()
	if err != nil {
		t.Fatalf("Committee: %v", err)
	}
	if len(committee) != 5 {
		t.Fatalf("seats = %d, want 5; a bondless peer was seated", len(committee))
	}
	if got := Nakamoto(committee); got != 2 {
		t.Fatalf("Nakamoto = %d, want 2", got)
	}

	// The same five bonds without the peer's account derive the same committee:
	// the peer's balance is not a bond and does not move the coefficient.
	bare, err := nkState(t, 1, 1, 1, 1, 1).Committee()
	if err != nil {
		t.Fatalf("Committee (without the peer): %v", err)
	}
	if !reflect.DeepEqual(committee, bare) {
		t.Fatalf("the bondless peer changed the committee:\n with %+v\nwithout %+v", committee, bare)
	}

	// The counterfactual: count the peer as a sixth equal seat, as a peer-set
	// implementation would, and k moves 2 -> 3. This is the number the Peers()
	// mutant prints; the committed-state report must not.
	withPeer := append(append([]genesis.Validator(nil), committee...), genesis.Validator{PubKey: peer, Power: 1})
	if got := Nakamoto(withPeer); got != 3 {
		t.Fatalf("Nakamoto with the peer counted = %d, want 3; the counterfactual is not distinct", got)
	}
	t.Logf("committed committee: %d seats, k=2; the same bonds without the funded/bondless peer: %d seats, k=%d; counting the peer as a seat: k=3 (the Peers() mutant)",
		len(committee), len(bare), Nakamoto(bare))
}

// TestThePlotPrintsTruncatedIntegerShares: the share is 100*top/total truncated
// to an integer, never a float. 1/6 prints 16%, not 17% and not 16.666...; a
// float or rounding implementation fails the exact-match assertions.
func TestThePlotPrintsTruncatedIntegerShares(t *testing.T) {
	out := FormatNakamoto([]NakamotoRow{
		{Epoch: 0, Height: 0, Seats: 6, Nakamoto: 3, TopPower: 1, TotalPower: 6},
	})
	if !strings.Contains(out, "(16%)") {
		t.Fatalf("the plot does not print the truncated 16%% share:\n%s", out)
	}
	if strings.Contains(out, "(17%)") || strings.Contains(out, "16.6") {
		t.Fatalf("the plot printed a rounded or float share:\n%s", out)
	}
}

// TestThePlotShowsAStepAtTheBoundary is the acceptance fixture end to end: six
// seats, epoch 40, one seat unbonding mid-epoch, and the report stepping from
// 6 seats/k=3 to 5 seats/k=2 at the boundary. It asserts the ROWS, not the
// formatting, and it fails if the fixture does not actually rotate.
//
// The rotated-out validator's HEIGHT IS NOT 39. The plan says it stops at the
// boundary, but the code says it follows: an unseated driver emits no vote but
// still tallies and commits the others' blocks, and Task 3's own end-to-end
// test asserts exactly that (epoch_rotation_test.go, "the departed validator
// fell behind instead of following"). This test pins the code's behaviour: all
// six chains reach the head, and the seat count in the rows is what proves the
// rotation.
func TestThePlotShowsAStepAtTheBoundary(t *testing.T) {
	s, err := RunMulti(Options{
		Dir:          t.TempDir(),
		Blocks:       105,
		Validators:   6,
		EpochBlocks:  40,
		RotateDemo:   true,
		PlotNakamoto: true,
	})
	if err != nil {
		t.Fatalf("RunMulti (rotation fixture): %v", err)
	}
	want := []NakamotoRow{
		{Epoch: 0, Height: 0, Seats: 6, Nakamoto: 3, TopPower: 1, TotalPower: 6},
		{Epoch: 1, Height: 40, Seats: 5, Nakamoto: 2, TopPower: 1, TotalPower: 5},
		{Epoch: 2, Height: 80, Seats: 5, Nakamoto: 2, TopPower: 1, TotalPower: 5},
		{Epoch: 2, Height: 105, Seats: 5, Nakamoto: 2, TopPower: 1, TotalPower: 5},
	}
	if !reflect.DeepEqual(s.Nakamoto, want) {
		t.Fatalf("the plotted series does not show the boundary step:\n got %+v\nwant %+v", s.Nakamoto, want)
	}
	if s.Nakamoto[0].Nakamoto == s.Nakamoto[1].Nakamoto {
		t.Fatal("the fixture did not rotate: the coefficient is the same on both sides of the boundary")
	}
	t.Logf("fixture series:\n%s", FormatNakamoto(s.Nakamoto))
	t.Logf("rotated-out v5 height = %d, run head = %d, agreed = %v", s.ValidatorHeights[5], s.Height, s.Agreed)
	if !s.Agreed {
		t.Fatal("the committee does not hold one history")
	}
	// The rotated-out seat followed the chain (see the comment above); the row
	// at height 40 proves it is no longer seated.
	if got := s.ValidatorHeights[5]; got != s.Height {
		t.Fatalf("rotated-out validator height = %d, want it to follow to %d (it stops voting, not following)", got, s.Height)
	}
	for i, h := range s.ValidatorHeights {
		if h != s.Height {
			t.Fatalf("validator %d is at height %d, want %d: the fixture is not a clean rotation", i, h, s.Height)
		}
	}
}

// TestThePlotRefusesTheSingleNodeRun: the committee options are refused on Run,
// not silently ignored.
func TestThePlotRefusesTheSingleNodeRun(t *testing.T) {
	if _, err := Run(Options{Dir: t.TempDir(), Blocks: 2, PlotNakamoto: true}); !errors.Is(err, ErrCommitteeOptionsNeedRunMulti) {
		t.Fatalf("Run with PlotNakamoto error = %v, want ErrCommitteeOptionsNeedRunMulti", err)
	}
	if _, err := Run(Options{Dir: t.TempDir(), Blocks: 2, RotateDemo: true}); !errors.Is(err, ErrCommitteeOptionsNeedRunMulti) {
		t.Fatalf("Run with RotateDemo error = %v, want ErrCommitteeOptionsNeedRunMulti", err)
	}
}

// TestRunMultiRefusesAnUnplottableRotation covers the fixture's guards, so a
// run that could not show a step fails before spending the run.
func TestRunMultiRefusesAnUnplottableRotation(t *testing.T) {
	cases := []struct {
		name string
		o    Options
		want error
	}{
		{"too few seats", Options{Dir: t.TempDir(), Blocks: 50, Validators: 4, EpochBlocks: 10, RotateDemo: true}, ErrRotateNeedsCommittee},
		{"no short epoch", Options{Dir: t.TempDir(), Blocks: 50, Validators: 6, RotateDemo: true}, ErrRotateNeedsEpoch},
		{"run too short", Options{Dir: t.TempDir(), Blocks: 20, Validators: 6, EpochBlocks: 20, RotateDemo: true}, ErrRotateNeedsBlocks},
		{"offline seat", Options{Dir: t.TempDir(), Blocks: 50, Validators: 6, EpochBlocks: 10, RotateDemo: true, OfflineValidators: []int{5}}, ErrRotateWithOffline},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := RunMulti(tc.o); !errors.Is(err, tc.want) {
				t.Fatalf("RunMulti error = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestNakamotoRowsBucketsEveryBoundaryAndTheHead pins the series shape: one row
// per epoch boundary plus the head, monotone, and no duplicate when the head is
// itself a boundary.
func TestNakamotoRowsBucketsEveryBoundaryAndTheHead(t *testing.T) {
	src := fixedCommitteeSource{committee: nkSeats(1, 1, 1, 1)}
	rows, err := NakamotoRows(src, 10, 4)
	if err != nil {
		t.Fatalf("NakamotoRows: %v", err)
	}
	wantHeights := []uint64{0, 4, 8, 10}
	if len(rows) != len(wantHeights) {
		t.Fatalf("rows = %d, want %d: %+v", len(rows), len(wantHeights), rows)
	}
	for i, h := range wantHeights {
		if rows[i].Height != h {
			t.Fatalf("row %d height = %d, want %d", i, rows[i].Height, h)
		}
		if i > 0 && rows[i].Height <= rows[i-1].Height {
			t.Fatalf("rows are not monotone at %d: %+v", i, rows)
		}
	}
	// Head exactly on a boundary: no duplicated row.
	rows, err = NakamotoRows(src, 8, 4)
	if err != nil {
		t.Fatalf("NakamotoRows (boundary head): %v", err)
	}
	if got, want := len(rows), 3; got != want {
		t.Fatalf("boundary-head rows = %d, want %d: %+v", got, want, rows)
	}
}

// TestNakamotoRowsReadsEachHeight is a source-level check that the row's Seats
// and numbers come from the committee THAT height's lookup returned, not from
// one shared committee: the fake source varies by height.
func TestNakamotoRowsReadsEachHeight(t *testing.T) {
	byHeight := map[uint64][]genesis.Validator{
		0: nkSeats(1, 1, 1, 1, 1, 1),
		4: nkSeats(1, 1, 1, 1, 1),
	}
	rows, err := NakamotoRows(heightSource(byHeight), 4, 4)
	if err != nil {
		t.Fatalf("NakamotoRows: %v", err)
	}
	if rows[0].Seats != 6 || rows[1].Seats != 5 {
		t.Fatalf("rows do not carry their own height's committee: %+v", rows)
	}
}

type heightSource map[uint64][]genesis.Validator

func (s heightSource) CommitteeAt(h uint64) ([]genesis.Validator, error) {
	committee, ok := s[h]
	if !ok {
		return nil, fmt.Errorf("no committee at height %d", h)
	}
	return committee, nil
}

// TestNakamotoOverflowAndZeroPowerRefuse: a hand-built committee a chain cannot
// emit is refused by the report, never printed as a number.
func TestNakamotoOverflowAndZeroPowerRefuse(t *testing.T) {
	overflow := []genesis.Validator{{PubKey: nkKey(1), Power: ^uint64(0)}, {PubKey: nkKey(2), Power: 1}}
	if _, err := NakamotoAt(fixedCommitteeSource{committee: overflow}, 0, 4); !errors.Is(err, ErrCommitteePowerOverflow) {
		t.Fatalf("overflow error = %v, want ErrCommitteePowerOverflow", err)
	}
	zero := []genesis.Validator{{PubKey: nkKey(1), Power: 0}, {PubKey: nkKey(2), Power: 0}}
	if _, err := NakamotoAt(fixedCommitteeSource{committee: zero}, 0, 4); !errors.Is(err, ErrZeroCommitteePower) {
		t.Fatalf("zero-power error = %v, want ErrZeroCommitteePower", err)
	}
	if got := Nakamoto(zero); got != 0 {
		t.Fatalf("Nakamoto(zero-power committee) = %d, want 0", got)
	}
}

// TestSharePercentDoesNotOverflow: a top seat near the uint64 ceiling is
// formatted without wrapping a 100*power product (the report's only division).
func TestSharePercentDoesNotOverflow(t *testing.T) {
	const big = ^uint64(0)
	if got, want := sharePercent(big, big), uint64(100); got != want {
		t.Fatalf("sharePercent(MaxUint64, MaxUint64) = %d, want %d", got, want)
	}
	if got, want := sharePercent(1, 3), uint64(33); got != want {
		t.Fatalf("sharePercent(1, 3) = %d, want %d", got, want)
	}
	if got := sharePercent(0, 0); got != 0 {
		t.Fatalf("sharePercent(0, 0) = %d, want 0", got)
	}
}

// TestFormatNakamotoIsStable also checks that formatting does not mutate the
// rows, since the table is rendered after the report is built.
func TestFormatNakamotoIsStable(t *testing.T) {
	rows := []NakamotoRow{{Epoch: 0, Height: 0, Seats: 4, Nakamoto: 2, TopPower: 1, TotalPower: 4}}
	before := append([]NakamotoRow(nil), rows...)
	_ = FormatNakamoto(rows)
	if !reflect.DeepEqual(rows, before) {
		t.Fatalf("FormatNakamoto mutated its rows: %+v", rows)
	}
	if !bytes.Contains([]byte(FormatNakamoto(rows)), []byte("height")) {
		t.Fatal("the plot has no header")
	}
}
