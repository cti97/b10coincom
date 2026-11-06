package chain_test

// Audit S-20: chain.everSeated grows without bound. It does - it is monotone on
// purpose (RT-3/RT-7) and nothing ever deletes from it - and the fix is the
// arithmetic recorded on the field, not a cap: the set is the union of the
// genesis seats and the committees the chain has recorded, so it is bounded by
//
//	len(genesis.Validators) + CommitteeSize x epochs elapsed
//
// rather than by who can afford MIN_STAKE. This test pins the two facts that
// bound rests on, because each is the thing a future change could quietly
// break and each is the thing a cap would break instead:
//
//  1. a bond ALONE does not admit a key - so the set is not "everyone who ever
//     paid MIN_STAKE", which is the unbounded reading of the finding;
//  2. the epoch boundary admits exactly the keys that TOOK a seat, and only at
//     the boundary - so growth is CommitteeSize per epoch and not per bond or
//     per block.
//
// The fixture is constructed to make both observable: five candidates at equal
// stake compete for four seats, so exactly one of the two post-genesis keys must
// LOSE the draw. A set that admitted every bond would hold both.

import (
	"crypto/ed25519"
	"testing"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/types"
)

// s20Bond commits priv's bond of `amount` sparks at the next height, proposed
// by a seated genesis key. a1Bond is this at exactly MIN_STAKE; the fixture here
// needs unequal stakes so that the seat draw has a determined winner and a
// determined loser instead of a tie broken on key bytes.
func s20Bond(t *testing.T, g *genesis.Genesis, cs []*chain.Chain, builder, priv ed25519.PrivateKey, amount uint64) {
	t.Helper()
	pub := priv.Public().(ed25519.PublicKey)
	tx := a1Sign(g, priv, types.Tx{
		Type:   types.TxBond,
		From:   types.AddressFromPub(pub),
		PubKey: pub,
		Nonce:  0,
		Amount: amount,
		Fee:    g.Params.MinFeeSparks,
	})
	a1AppendByEvery(t, cs, a1Build(t, cs[0], builder, []types.Tx{tx}))
}

func TestEverSeatedAdmitsOnlyKeysThatTookASeat(t *testing.T) {
	g, keys, winner := a1Genesis(t)
	winnerPub := winner.Public().(ed25519.PublicKey)

	// Unequal stakes, so the draw is determined rather than tie-broken: the
	// three genesis seats hold 4x MIN_STAKE, the winner 3x, the loser 1x. Four
	// seats, five candidates, and the loser is outranked by all four.
	const stake, winnerStake = 1, 3
	for i := range g.Validators {
		g.Validators[i].Power = 4 * stake * g.Params.MinStakeSparks
	}
	loserPub, loserPriv := a1Key("the key that loses the seat draw")
	g.DevAccounts = []genesis.DevAccount{
		{PubKey: winnerPub, BalanceSparks: winnerStake*stake*g.Params.MinStakeSparks + g.Params.MinFeeSparks},
		{PubKey: loserPub, BalanceSparks: stake*g.Params.MinStakeSparks + g.Params.MinFeeSparks},
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("the constructed genesis is invalid: %v", err)
	}

	cs := a1Open(t, g, a1GenesisSeats+2)

	// The genesis seats are seated from height 0 (the Open-time path).
	for i := range keys {
		pub := keys[i].Public().(ed25519.PublicKey)
		for v, c := range cs {
			if !c.EverSeated(pub) {
				t.Fatalf("validator %d does not admit genesis seat %d (%x)", v, i, pub)
			}
		}
	}

	s20Bond(t, g, cs, keys[0], winner, winnerStake*stake*g.Params.MinStakeSparks) // height 1
	s20Bond(t, g, cs, keys[0], loserPriv, stake*g.Params.MinStakeSparks)          // height 2

	// Half of fact 1, before the boundary: both keys are bonded in the state
	// every validator now holds, and neither is admitted yet.
	for i, c := range cs {
		for _, pub := range []ed25519.PublicKey{winnerPub, loserPub} {
			if c.EverSeated(pub) {
				t.Fatalf("validator %d admitted %x on its bond alone, before any committee derived from it", i, pub)
			}
		}
	}

	// Cross the boundary that derives epoch 1's seats: height 3 appends the
	// block whose state decides epoch 1 (EpochBlocks = 4). The genesis committee
	// judges every one of these heights, so any genesis key may build them.
	for cs[0].Height() < a1EpochBlocks-1 {
		a1AppendByEvery(t, cs, a1Build(t, cs[0], keys[0], nil))
	}

	vals, err := cs[0].CommitteeAt(a1EpochBlocks)
	if err != nil {
		t.Fatalf("CommitteeAt(%d) after the boundary: %v", a1EpochBlocks, err)
	}
	if len(vals) != a1CommitteeSize {
		t.Fatalf("the committee at height %d has %d seats, want %d", a1EpochBlocks, len(vals), a1CommitteeSize)
	}

	// Half of fact 1, after the boundary, and fact 2: exactly the seat takers
	// are admitted, and the loser is not - being bonded is not being seated.
	if genesis.SeatOfPubKey(vals, winnerPub) < 0 {
		t.Fatalf("the fixture no longer seats the 3x key: %v", vals)
	}
	if genesis.SeatOfPubKey(vals, loserPub) >= 0 {
		t.Fatalf("the fixture no longer excludes the 1x key: %v", vals)
	}
	for i, c := range cs {
		if !c.EverSeated(winnerPub) {
			t.Fatalf("validator %d does not admit %x, which holds a seat at height %d: "+
				"that is the RT-3 freeze this set exists to prevent", i, winnerPub, a1EpochBlocks)
		}
		if c.EverSeated(loserPub) {
			t.Fatalf("validator %d admitted %x, which bonded but LOST the seat draw: admission is the "+
				"committee's, not the bond's, and that bound is what keeps audit S-20 bounded", i, loserPub)
		}
	}
}
