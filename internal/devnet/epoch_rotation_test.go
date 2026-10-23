package devnet

// The milestone's ACCEPTANCE evidence, as a test rather than a manual run:
// six validators over real TCP, a bond removed early in the run, and the
// committee stepping from six seats to five exactly at the epoch boundary the
// removal decides - while the chain keeps committing on the other side.
//
// This is the end-to-end leg. The constructed unit tests in
// internal/consensus pin the boundary arithmetic, the tally rules, the
// certificate gate and the router; this test pins that the WIRED node - real
// sockets, the real driver, the real mempool, the real state transition -
// actually rotates and keeps finalising. It is deliberately the 6 -> 5
// fixture the plan established: 1/5 = 0.20 is under the 1/4 cap, whereas a
// 4 -> 3 rotation would need three equal seats at 1/3 and no cap rule can
// satisfy 1/4 there.
//
// THE BOUNDARY IS COMPUTED FROM THE UNBOND'S OWN HEIGHT, not assumed. The
// transaction is proposed by whichever validator's round wins it, so how many
// blocks it takes to land is a liveness property of the run, not something a
// test may assume; hard-coding "it lands before E-1" would make the acceptance
// flaky under CPU load (the tx can wait a few rounds for a proposal that
// commits). The test therefore finds the block that carries the tx, takes the
// epoch of THAT height, and checks the boundary at the end of that epoch:
// epoch e's seats come from the state at e*E-1, which is before the Unbond,
// and epoch e+1's come from (e+1)*E-1, which is at or after it. The rotation
// is still exact - one adjacent height apart - it is simply the boundary that
// the committed Unbond actually decides.

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/cti97/b10coincom/internal/consensus"
	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/simnet"
	"github.com/cti97/b10coincom/internal/types"
)

const (
	rotationSeats = 6
	rotationEpoch = uint64(8)
)

// rotationGenesis is six equal MIN_STAKE seats with a short epoch. The seats'
// bonds are their genesis Power (the genesis state seeds one bond per seat),
// so the departing validator's full Unbond is exactly that amount.
func rotationGenesis(t *testing.T) *genesis.Genesis {
	t.Helper()
	g := genesis.Devnet()
	g.ChainID = "b10coin-rotation-e2e"
	g.Params.ChainID = g.ChainID
	g.Params.EpochBlocks = rotationEpoch
	g.Params.CommitteeSize = rotationSeats
	vals := make([]genesis.Validator, rotationSeats)
	for i := range vals {
		vals[i] = genesis.Validator{
			PubKey: simnet.ValidatorKey(i).Public().(ed25519.PublicKey),
			Power:  g.Params.MinStakeSparks,
		}
	}
	g.Validators = vals
	return g
}

// startRotationValidator starts one genesis-file-mode validator: its seat is
// derived from its key, and it listens on its own loopback port for the mesh.
func startRotationValidator(t *testing.T, g *genesis.Genesis, seat int) *Validator {
	t.Helper()
	v, err := StartValidator(ValidatorConfig{
		Dir:     t.TempDir(),
		Genesis: g,
		Key:     simnet.ValidatorKey(seat),
		Listen:  "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("starting rotation validator %d: %v", seat, err)
	}
	return v
}

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// quorumOf is the quorum threshold a set's powers imply, built through the
// production rule so a change to the cap or the two-thirds arithmetic is
// caught here as well.
func quorumOf(vals []genesis.Validator) uint64 {
	num, den := consensus.PowerCapFor(len(vals))
	return consensus.Config{Committee: vals, PowerCapNum: num, PowerCapDen: den}.Quorum()
}

// seatsForQuorum is how many of the fixture's EQUAL seats it takes to reach a
// set's quorum. The threshold is sparks, not a count (a two-thirds bar plus
// one spark), so "5 of 6" and "4 of 5" are stated in the seats that actually
// have to sign.
func seatsForQuorum(vals []genesis.Validator) int {
	q, power := quorumOf(vals), vals[0].Power
	return int((q + power - 1) / power)
}

// blockContaining returns the height of the block that carries txID, or 0.
// The chain's blocks are canonical, so scanning one validator's history finds
// the height every validator applied it at.
func blockContaining(t *testing.T, v *Validator, txID [32]byte) uint64 {
	t.Helper()
	for h := uint64(1); h <= v.Height(); h++ {
		blk, err := v.Chain().BlockAt(h)
		if err != nil {
			t.Fatalf("reading block %d: %v", h, err)
		}
		for i := range blk.Txs {
			if blk.Txs[i].ID() == txID {
				return h
			}
		}
	}
	return 0
}

// TestTheCommitteeRotatesAtAnEpochBoundaryEndToEnd is the milestone acceptance
// criterion: the validator set rotates at an epoch boundary, over a real
// consensus run, and blocks keep committing on the other side.
func TestTheCommitteeRotatesAtAnEpochBoundaryEndToEnd(t *testing.T) {
	g := rotationGenesis(t)
	vs := make([]*Validator, rotationSeats)
	for i := 0; i < rotationSeats; i++ {
		vs[i] = startRotationValidator(t, g, i)
	}
	defer closeAll(vs)
	if err := connectMesh(vs); err != nil {
		t.Fatalf("connecting the rotation mesh: %v", err)
	}

	// Get off height 0 before submitting, so the Unbond is proposed into a
	// running committee rather than racing the genesis.
	waitAllReach(t, vs, 2, 60*time.Second)

	const departing = rotationSeats - 1
	departingPub := simnet.ValidatorKey(departing).Public().(ed25519.PublicKey)
	departingAddr := types.AddressFromPub(departingPub)
	tx := types.Tx{
		Type:   types.TxUnbond,
		From:   departingAddr,
		PubKey: departingPub,
		Nonce:  0,
		Amount: g.Params.MinStakeSparks,
	}
	signingHash := tx.SigningHash(g.Hash())
	tx.Sig = crypto.Sign(simnet.ValidatorKey(departing), signingHash[:])
	txID := tx.ID()
	for _, v := range vs {
		if errs := v.Pool().Add([]types.Tx{tx}); len(errs) != 0 && errs[0] != nil {
			t.Fatalf("submitting the Unbond to %s: %v", v.Addr(), errs[0])
		}
	}

	// The transaction must actually commit (not merely be accepted by a pool):
	// every validator's committed state must show the bond gone.
	waitFor(t, "the Unbond to commit and clear the departing bond", 90*time.Second, func() bool {
		for _, v := range vs {
			if v.Height() < 2 || v.Chain().State().Bonded(departingAddr) != 0 {
				return false
			}
		}
		return true
	})

	// The boundary the Unbond decides: its own epoch's end.
	unbondHeight := blockContaining(t, vs[0], txID)
	if unbondHeight == 0 {
		t.Fatalf("the Unbond is cleared from state but no block in the chain carries it (height %d)", vs[0].Height())
	}
	boundaryEpoch := unbondHeight / rotationEpoch
	boundary := (boundaryEpoch + 1) * rotationEpoch
	oldBoundary := boundary - 1

	// Cross the boundary: every validator (the departing one included, as a
	// follower) reaches the first height of the new epoch.
	waitAllReach(t, vs, boundary, 120*time.Second)

	for i, v := range vs {
		lastOld, err := v.Chain().CommitteeAt(oldBoundary)
		if err != nil {
			t.Fatalf("validator %d, CommitteeAt(%d): %v", i, oldBoundary, err)
		}
		firstNew, err := v.Chain().CommitteeAt(boundary)
		if err != nil {
			t.Fatalf("validator %d, CommitteeAt(%d): %v", i, boundary, err)
		}
		if len(lastOld) != rotationSeats {
			t.Fatalf("validator %d: h = %d has %d seats, want the old %d", i, oldBoundary, len(lastOld), rotationSeats)
		}
		if len(firstNew) != rotationSeats-1 {
			t.Fatalf("validator %d: h = %d has %d seats, want the rotated %d", i, boundary, len(firstNew), rotationSeats-1)
		}
		if genesis.SeatOfPubKey(lastOld, departingPub) < 0 {
			t.Fatalf("validator %d: the old epoch does not seat the departing validator", i)
		}
		if genesis.SeatOfPubKey(firstNew, departingPub) >= 0 {
			t.Fatalf("validator %d: the new epoch still seats the departing validator", i)
		}
		if got, want := seatsForQuorum(lastOld), 5; got != want {
			t.Fatalf("validator %d: the old epoch needs %d seats to reach quorum %d, want %d (5 of 6)", i, got, quorumOf(lastOld), want)
		}
		if got, want := seatsForQuorum(firstNew), 4; got != want {
			t.Fatalf("validator %d: the new epoch needs %d seats to reach quorum %d, want %d (4 of 5)", i, got, quorumOf(firstNew), want)
		}
	}

	// And the chain keeps committing INSIDE the new epoch: this is the
	// "blocks keep committing" half of the acceptance criterion.
	waitAllReach(t, vs, boundary+4, 120*time.Second)
	assertIdenticalHistory(t, vs, boundary+4)

	// The departing validator stopped being counted exactly at the boundary:
	// it never signed a vote at or above it. Its vote weight is out of the new
	// tally even though it follows the chain.
	for _, h := range vs[departing].VotedHeights() {
		if h >= boundary {
			t.Fatalf("the departing validator voted at height %d, at or past the boundary %d", h, boundary)
		}
	}
	if got := vs[departing].Height(); got < boundary+4 {
		t.Fatalf("the departed validator fell behind instead of following: height %d, want at least %d", got, boundary+4)
	}
}
