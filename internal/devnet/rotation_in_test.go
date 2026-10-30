package devnet

// RT-1's acceptance evidence: a validator that BONDS AFTER GENESIS - a key the
// committee file does not list - is seated by the epoch boundary its bond
// decides, starts a node on the far side of that boundary, and has its votes
// COUNTED by the peers that were already running.
//
// This is the half the audit says was missing. `internal/consensus` already
// admits a key seated at head+1 (driver.go's membership gate); the node's entry
// point refused every key outside the static genesis list, so a bonded
// outsider's seat had no signer and its power silently raised the quorum bar
// for everyone. The fix is in StartValidator - the genesis list OR the
// committee at head+1, checked after the chain is opened, with the genesis list
// kept as the driver's base config - and the two tests here pin both halves:
//
//   - TestARotatedInValidatorStartsAndIsCounted: the key is admitted after the
//     boundary and its PRECOMMIT appears in a certificate whose recorded votes
//     reach that height's quorum. "Counted" is the certificate's own arithmetic
//     (RecordCommit verifies it before storing), not a height that happened to
//     advance: the remaining genesis seats can reach quorum without this seat,
//     so liveness alone would prove nothing.
//   - TestAStrangerIsStillRefusedAfterABoundary: the SAME chain at the SAME
//     head still refuses a key that is neither in genesis nor seated at
//     head+1, so the fix widens admission by exactly one committee, not into
//     "any key may run".
//
// Everything is constructed. The bond's height is read back from the chain that
// carried it (never assumed), the boundary is a pure function of that height,
// and the joining node's chain is REPLAYED from the donor's committed blocks
// (no directory copy, so no lock or round record is inherited). The only waits
// are bounded polls on positive observables - a height reached, a vote on the
// wire, a certificate recorded.

import (
	"crypto/ed25519"
	"fmt"
	"testing"
	"time"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/consensus"
	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/simnet"
	"github.com/cti97/b10coincom/internal/types"
	"strings"
)

const (
	// rotationInSeats is how many GENESIS validators run: five.
	rotationInSeats = 5
	// rotationInCommittee is the chain's committee size: SIX, i.e. one spare
	// seat. That is the shape RT-2's fix added to the committee file, and it
	// is what this test needs for a reason that is about the state, not
	// convenience: until the joining node starts, its seat is in the committee
	// and votes nothing. On a six-seat committee of equal powers the quorum is
	// four seats, so the five live genesis seats commit with ONE seat of slack
	// while they cross the boundary. With an eviction-shaped five-seat
	// committee the four live seats would be exactly the quorum, and the
	// boundary could only be crossed if every one of them agreed in every
	// round - a liveness assumption a test must not make (it was observed
	// failing under a loaded CPU). Eviction is RT-2's story, not RT-1's.
	rotationInCommittee = 6
	// rotationInEpoch is short enough that the test crosses a boundary in
	// seconds while still leaving several heights inside each epoch.
	rotationInEpoch = uint64(8)
	// rotationInTick/rotationInWave slow the fixture down so the joining node
	// can CATCH UP AND PARTICIPATE rather than chase a chain that outruns its
	// 500 ms catch-up cadence: at the defaults a 50 ms block time means ten
	// blocks commit per wave, in a real deployment two. This is a fixture
	// cadence, not a property under test; the assertions are the same at any
	// speed that lets a member join.
	rotationInTick = 150 * time.Millisecond
	rotationInWave = 100 * time.Millisecond
	// rotationInStakeFactor is what the joining key bonds: exactly MIN_STAKE,
	// so all six seats carry equal power and the cap does not bind. Any larger
	// bond would not help the seat (it is seated either way) and would make the
	// quorum arithmetic depend on the cap's fixed point instead of on the seat
	// count.
	rotationInStakeFactor = 1
)

// rotationInGenesis is five genesis seats at MIN_STAKE, a committee size of
// six (one spare), and ONE funded account: the sixth key's, with exactly
// enough for the bond plus its minimum fee. Nothing else about the chain differs from the
// rotation fixture.
func rotationInGenesis(t *testing.T) (*genesis.Genesis, ed25519.PrivateKey) {
	t.Helper()
	g := genesis.Devnet()
	g.ChainID = "b10coin-rotation-in-e2e"
	g.Params.ChainID = g.ChainID
	g.Params.EpochBlocks = rotationInEpoch
	g.Params.CommitteeSize = rotationInCommittee
	minStake := g.Params.MinStakeSparks
	vals := make([]genesis.Validator, rotationInSeats)
	for i := range vals {
		vals[i] = genesis.Validator{
			PubKey: simnet.ValidatorKey(i).Public().(ed25519.PublicKey),
			// A genesis seat's bond IS its Power (chain.genesisState).
			Power: minStake,
		}
	}
	g.Validators = vals
	joiner := simnet.ValidatorKey(rotationInSeats)
	joinerPub := joiner.Public().(ed25519.PublicKey)
	g.DevAccounts = []genesis.DevAccount{{
		PubKey:        joinerPub,
		BalanceSparks: rotationInStakeFactor*minStake + g.Params.MinFeeSparks,
	}}
	return g, joiner
}

// startRotationInValidator starts one genesis-file-mode validator at this
// test's slower cadence.
func startRotationInValidator(t *testing.T, g *genesis.Genesis, seat int) *Validator {
	t.Helper()
	v, err := StartValidator(ValidatorConfig{
		Dir:       t.TempDir(),
		Genesis:   g,
		Key:       simnet.ValidatorKey(seat),
		Listen:    "127.0.0.1:0",
		TickEvery: rotationInTick,
		WaveEvery: rotationInWave,
	})
	if err != nil {
		t.Fatalf("starting rotation-in validator %d: %v", seat, err)
	}
	return v
}

// bondTx builds and signs the joining key's Bond: rotationInStakeFactor x
// MIN_STAKE at the chain's minimum fee.
func bondTx(g *genesis.Genesis, priv ed25519.PrivateKey) types.Tx {
	pub := priv.Public().(ed25519.PublicKey)
	tx := types.Tx{
		Type:   types.TxBond,
		From:   types.AddressFromPub(pub),
		PubKey: pub,
		Nonce:  0,
		Amount: rotationInStakeFactor * g.Params.MinStakeSparks,
		Fee:    g.Params.MinFeeSparks,
	}
	h := tx.SigningHash(g.Hash())
	tx.Sig = crypto.Sign(priv, h[:])
	return tx
}

// seedChainFrom replays src's blocks 1..upTo into a FRESH directory and returns
// that directory. The joining node needs a chain that is already past the
// boundary: its first engine judges head+1, and head+1 is the height it must be
// seated at. A replayed chain is built from committed blocks only - no lock, no
// round record and no store header is inherited from the donor - so the new
// node starts with exactly the state the blocks describe.
func seedChainFrom(t *testing.T, g *genesis.Genesis, src *chain.Chain, upTo uint64) string {
	t.Helper()
	dir := t.TempDir()
	c, err := chain.Open(g, dir)
	if err != nil {
		t.Fatalf("opening the replay chain: %v", err)
	}
	for h := uint64(1); h <= upTo; h++ {
		blk, err := src.BlockAt(h)
		if err != nil {
			t.Fatalf("reading donor block %d: %v", h, err)
		}
		if err := c.Append(blk); err != nil {
			t.Fatalf("replaying donor block %d: %v", h, err)
		}
	}
	if err := c.Close(); err != nil {
		t.Fatalf("closing the replay chain: %v", err)
	}
	return dir
}

// certVotes decodes a recorded commit certificate: the cert record is
// round | count | votes, and each vote is the wire's own canonical form.
func certVotes(t *testing.T, v *Validator, h uint64) []*consensus.Vote {
	t.Helper()
	rec, ok := v.Chain().CertAt(h)
	if !ok {
		return nil
	}
	d := types.NewDecoder(rec)
	if _, err := d.U32(); err != nil { // the round the certificate was formed in
		t.Fatalf("certificate at %d: round: %v", h, err)
	}
	n, err := d.Len()
	if err != nil {
		t.Fatalf("certificate at %d: count: %v", h, err)
	}
	votes := make([]*consensus.Vote, 0, n)
	for i := 0; i < n; i++ {
		raw, err := d.VarBytes()
		if err != nil {
			t.Fatalf("certificate at %d: vote %d: %v", h, i, err)
		}
		vote, err := consensus.DecodeVote(raw)
		if err != nil {
			t.Fatalf("certificate at %d: decoding vote %d: %v", h, i, err)
		}
		votes = append(votes, vote)
	}
	if err := d.Done(); err != nil {
		t.Fatalf("certificate at %d: trailing bytes: %v", h, err)
	}
	return votes
}

// countedAt reports whether the certificate v holds at h contains pub's
// precommit AND the recorded votes' power reaches that height's quorum. The
// second half is what makes "counted" mean COUNTED: a certificate is stored
// only after RecordCommit re-verifies it against the block and the block's own
// epoch, so a vote inside one carried its weight into the decision.
func countedAt(t *testing.T, v *Validator, h uint64, pub ed25519.PublicKey) bool {
	t.Helper()
	votes := certVotes(t, v, h)
	if len(votes) == 0 {
		return false
	}
	vals, err := v.Chain().CommitteeAt(h)
	if err != nil {
		return false
	}
	quorum := consensus.Config{Committee: vals}.Quorum()
	var sum uint64
	found := false
	for _, vote := range votes {
		if vote.Height != h {
			t.Fatalf("certificate at %d carries a vote for height %d", h, vote.Height)
		}
		idx := genesis.SeatOfPubKey(vals, vote.Validator)
		if idx < 0 {
			continue // not a seat at this height: not counted
		}
		sum += vals[idx].Power
		if string(vote.Validator) == string(pub) {
			found = true
		}
	}
	return found && sum >= quorum
}

// TestARotatedInValidatorStartsAndIsCounted is RT-1's end-to-end proof.
func TestARotatedInValidatorStartsAndIsCounted(t *testing.T) {
	g, joiner := rotationInGenesis(t)
	joinerPub := joiner.Public().(ed25519.PublicKey)
	joinerAddr := types.AddressFromPub(joinerPub)

	vs := make([]*Validator, rotationInSeats)
	for i := 0; i < rotationInSeats; i++ {
		vs[i] = startRotationInValidator(t, g, i)
	}
	defer closeAll(vs)
	if err := connectMesh(vs); err != nil {
		t.Fatalf("connecting the rotation-in mesh: %v", err)
	}

	// Get off height 0, then bond. The transaction's height is read back from
	// the chain that carries it: how many rounds it waits for a proposal is a
	// liveness property, not something this test may assume.
	waitAllReach(t, vs, 2, 60*time.Second)
	tx := bondTx(g, joiner)
	for _, v := range vs {
		if errs := v.Pool().Add([]types.Tx{tx}); len(errs) != 0 && errs[0] != nil {
			t.Fatalf("submitting the Bond to %s: %v", v.Addr(), errs[0])
		}
	}
	wantBond := rotationInStakeFactor * g.Params.MinStakeSparks
	waitFor(t, "the Bond to commit and fund the joining seat", 90*time.Second, func() bool {
		for _, v := range vs {
			if v.Height() < 2 || v.Chain().State().Bonded(joinerAddr) != wantBond {
				return false
			}
		}
		return true
	})
	bondHeight := blockContaining(t, vs[0], tx.ID())
	if bondHeight == 0 {
		t.Fatalf("the Bond is in state but no block carries it (height %d)", vs[0].Height())
	}
	// Constructed boundary: the epoch end whose deciding state (boundary-1)
	// holds the Bond.
	boundary := (bondHeight/rotationInEpoch + 1) * rotationInEpoch
	waitAllReach(t, vs, boundary, 120*time.Second)

	// The rotation-IN itself: the committee that judges the new epoch seats
	// the joining key, and it displaced a genesis seat (the committee stayed
	// at five, as the chain's committee_size says).
	seated := false
	for _, v := range vs {
		next, err := v.Chain().CommitteeAt(boundary)
		if err != nil {
			t.Fatalf("CommitteeAt(%d): %v", boundary, err)
		}
		if len(next) != rotationInCommittee {
			t.Fatalf("the committee at the boundary has %d seats, want %d", len(next), rotationInCommittee)
		}
		if genesis.SeatOfPubKey(next, joinerPub) < 0 {
			t.Fatalf("the committee at height %d does not seat the bonded key: the rotation-in never happened", boundary)
		}
		seated = true
	}
	if !seated {
		t.Fatal("no validator was checked")
	}

	// THE ENTRY POINT. Before the fix this was refused with "is not listed in
	// the committee's genesis": the key is not in the genesis document at all.
	// Its node starts on a chain replayed to the boundary - it must judge
	// boundary+1, where it holds a seat - and then follows and votes.
	seed := seedChainFrom(t, g, vs[0].Chain(), boundary)
	joinerNode, err := StartValidator(ValidatorConfig{
		Dir:       seed,
		Genesis:   g,
		Key:       joiner,
		Listen:    "127.0.0.1:0",
		TickEvery: rotationInTick,
		WaveEvery: rotationInWave,
	})
	if err != nil {
		t.Fatalf("a key seated at head+1 was refused at the node entry point: %v", err)
	}
	defer joinerNode.Close()
	if got := joinerNode.Seat(); got != -1 {
		t.Fatalf("a rotated-in key reports genesis seat %d, want -1 (it has no genesis position)", got)
	}
	// Dial the peers that were already running. The joining node's HELLOs are
	// admitted by their committee-at-height check, and its votes verify against
	// the same epoch's seats.
	for _, v := range vs {
		if err := joinerNode.Connect(v.Addr()); err != nil {
			t.Fatalf("connecting the joining node to %s: %v", v.Addr(), err)
		}
	}

	// Positive, monotone observables only: the joining node reaches a height
	// PAST the boundary, and it has put a vote at or past it on the wire.
	waitFor(t, "the joining node to reach the new epoch", 120*time.Second, func() bool {
		return joinerNode.Height() >= boundary+2
	})
	waitFor(t, "the joining node to vote in the epoch it is seated in", 60*time.Second, func() bool {
		for _, h := range joinerNode.VotedHeights() {
			if h > boundary {
				return true
			}
		}
		return false
	})

	// And COUNTED: every node's recorded certificate at a height past the
	// boundary contains its precommit and reaches quorum without it being
	// possible to claim the vote was ignored.
	all := append(append([]*Validator(nil), vs...), joinerNode)
	var provenHeight uint64
	waitFor(t, "the joining validator's precommit to appear in a quorum-reaching certificate", 120*time.Second, func() bool {
		for h := boundary; h <= joinerNode.Height(); h++ {
			ok := true
			for _, v := range all {
				if v.Height() < h || !countedAt(t, v, h, joinerPub) {
					ok = false
					break
				}
			}
			if ok {
				provenHeight = h
				return true
			}
		}
		return false
	})
	t.Logf("the joining validator's precommit is in the certificate at height %d (%d of the committee's seats reached quorum with it counted)",
		provenHeight, rotationInCommittee)

	// The joining node holds the same history as the committee it joined: its
	// votes came from a chain that agrees, not from a fork of its own.
	assertIdenticalHistory(t, all, joinerNode.Height())
}

// TestAStrangerIsStillRefusedAfterABoundary pins the other half of RT-1: the
// widened check admits a key seated at head+1 and NOTHING ELSE. The chain here
// is the same constructed state as the test above (past a boundary, with the
// joining key seated), and a random key - no genesis seat, no bond, so no seat
// in any committee - is still refused, by name.
func TestAStrangerIsStillRefusedAfterABoundary(t *testing.T) {
	g, joiner := rotationInGenesis(t)
	vs := make([]*Validator, rotationInSeats)
	for i := 0; i < rotationInSeats; i++ {
		vs[i] = startRotationInValidator(t, g, i)
	}
	defer closeAll(vs)
	if err := connectMesh(vs); err != nil {
		t.Fatalf("connecting the mesh: %v", err)
	}
	waitAllReach(t, vs, 2, 60*time.Second)
	tx := bondTx(g, joiner)
	for _, v := range vs {
		if errs := v.Pool().Add([]types.Tx{tx}); len(errs) != 0 && errs[0] != nil {
			t.Fatalf("submitting the Bond to %s: %v", v.Addr(), errs[0])
		}
	}
	joinerAddr := types.AddressFromPub(joiner.Public().(ed25519.PublicKey))
	waitFor(t, "the Bond to commit", 90*time.Second, func() bool {
		for _, v := range vs {
			if v.Height() < 2 || v.Chain().State().Bonded(joinerAddr) == 0 {
				return false
			}
		}
		return true
	})
	bondHeight := blockContaining(t, vs[0], tx.ID())
	if bondHeight == 0 {
		t.Fatal("the Bond is in state but no block carries it")
	}
	boundary := (bondHeight/rotationInEpoch + 1) * rotationInEpoch
	waitAllReach(t, vs, boundary, 120*time.Second)

	// A key generated by this test and bonded by nobody.
	strangerPub, strangerPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating the stranger key: %v", err)
	}
	seed := seedChainFrom(t, g, vs[0].Chain(), boundary)
	_, err = StartValidator(ValidatorConfig{
		Dir:     seed,
		Genesis: g,
		Key:     strangerPriv,
		Listen:  "127.0.0.1:0",
	})
	if err == nil {
		t.Fatal("a key that is in neither genesis nor the committee at head+1 must still be refused")
	}
	for _, want := range []string{"not listed", "committee", fmt.Sprintf("height %d", boundary+1)} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal must name what was checked (%q missing): %v", want, err)
		}
	}
	// And the joined key's admission is not a licence for its ADDRESS: the
	// stranger's public key is not in the committee the chain derived.
	if vals, cerr := vs[0].Chain().CommitteeAt(boundary + 1); cerr != nil {
		t.Fatalf("CommitteeAt(%d): %v", boundary+1, cerr)
	} else if genesis.SeatOfPubKey(vals, strangerPub) >= 0 {
		t.Fatal("the test's 'stranger' key holds a seat; the refusal case is not constructed")
	}
}
