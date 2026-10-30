package devnet

import (
	"testing"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/consensus"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/simnet"
)

// Pin for the FIRST thing a "validators did not reach height 6 ... heights
// [0 0 0]" report asks: what committee does the very first consensus height
// see? Consensus for height h validates with the committee of epoch h/EPOCH,
// so h = 0 and h = 1 are both epoch 0 and both read the set derived from the
// GENESIS state (there is no height -1). That path is where an `epoch*E - 1`
// would underflow to a huge height, or where an epoch-0 special case could
// return an empty or degenerate set - and either would make every block
// unproposable, which is exactly the reported shape (nothing commits, while
// the round ladder keeps ticking).
//
// This test CONSTRUCTS the state and asks it, rather than provoking a race:
// the four-seat simnet genesis is the fixture the networked tests run on. It
// names three separate facts the failure needs:
//
//   - height 0 sees the four genesis seats, one unit of power each - not an
//     empty set, and not a set with a zero-power seat;
//   - the quorum is 3, so the three live seats of TestAValidatorThatJoinsLate
//     CatchUpOverTCP (seats 0,1,2 up, seat 3 absent) can reach it exactly;
//   - the proposer at height 1 advances off the absent seat: over the first 64
//     rounds every live seat is drawn, so "the proposer was always seat 3" is
//     not a possible explanation for a stall.
func TestHeightZeroSeesTheGenesisCommitteeAndAReachableQuorum(t *testing.T) {
	g := simnet.Committee(4)
	ch, err := chain.Open(g, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ch.Close()

	// The genesis seats, in genesis order: the fixture the networked tests start.
	genesisSeats := g.Validators
	if len(genesisSeats) != 4 {
		t.Fatalf("fixture: generator produced %d genesis seats, want 4", len(genesisSeats))
	}

	for _, h := range []uint64{0, 1} {
		vals, err := ch.CommitteeAt(h)
		if err != nil {
			t.Fatalf("CommitteeAt(%d) = %v; the first height of epoch 0 must see the genesis committee", h, err)
		}
		if len(vals) != 4 {
			t.Fatalf("CommitteeAt(%d) seats %d validators, want the 4 genesis seats", h, len(vals))
		}
		// Membership and power, read off the COMMITTEE not off genesis: a set
		// with the right length but a stranger, or a zero-power seat, would
		// pass a length check and still be unproposable.
		for i := range vals {
			seat := genesis.SeatOfPubKey(genesisSeats, vals[i].PubKey)
			if seat < 0 {
				t.Fatalf("CommitteeAt(%d) seat %d carries key %x, which is not a genesis seat", h, i, vals[i].PubKey[:4])
			}
			if vals[i].Power != 1 {
				t.Fatalf("CommitteeAt(%d) seat %d (genesis seat %d) has power %d, want 1", h, i, seat, vals[i].Power)
			}
		}
	}

	// The three live validators must be able to commit: quorum 3 of 4.
	vals, err := ch.CommitteeAt(0)
	if err != nil {
		t.Fatal(err)
	}
	num, den := consensus.PowerCapFor(len(vals))
	cfg := consensus.Config{
		Committee:   vals,
		TimeoutBase: 200,
		TimeoutStep: 100,
		PowerCapNum: num,
		PowerCapDen: den,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the height-0 committee does not pass Config.Validate: %v", err)
	}
	if total := cfg.TotalPower(); total != 4 {
		t.Fatalf("height-0 total power = %d, want 4 (one per seat)", total)
	}
	if q := cfg.Quorum(); q != 3 {
		t.Fatalf("height-0 quorum = %d, want 3 of 4; three live seats must be able to reach it", q)
	}

	// The proposer at height 1 is drawn per round, not fixed. Seat 3 is the
	// absent validator in TestAValidatorThatJoinsLateCatchesUpOverTCP, so a
	// proposer pinned to it would starve every round; this asserts it does not.
	parent := ch.Head().ID()
	proposed := make([]int, len(genesisSeats))
	for r := uint32(0); r < 64; r++ {
		p := cfg.Proposer(1, r, parent)
		seat := genesis.SeatOfPubKey(genesisSeats, p)
		if seat < 0 {
			t.Fatalf("round %d proposed %x, which is not a committee seat", r, p[:4])
		}
		proposed[seat]++
	}
	for seat := 0; seat < 3; seat++ {
		if proposed[seat] == 0 {
			t.Fatalf("live seat %d was never drawn as proposer in 64 rounds at height 1 (draws %v): a proposer that cannot advance off the absent seat stalls every height", seat, proposed)
		}
	}
	if proposed[3] >= 64 {
		t.Fatalf("the absent seat proposed every round (%v)", proposed)
	}
}
