package chain

// M5 Task 1 at the chain boundary: genesisState must WIRE the staking
// parameters and SEED one bond per genesis validator. Both are one-line
// omissions that compile and leave every unit test in package state green -
// staking would then be unconfigured on every real chain, and no genesis seat
// would be a candidate - so they are asserted here, through Open.

import (
	"bytes"
	"testing"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/state"
	"github.com/cti97/b10coincom/internal/types"
)

// TestGenesisSeatsAreBondedAndCommitted: a genesis validator is seated by the
// genesis hash, so it holds a bond at height 0 whose amount is its genesis
// power, and that bond is part of the genesis state root.
func TestGenesisSeatsAreBondedAndCommitted(t *testing.T) {
	g := genesis.Devnet()
	c, _ := devChain(t)

	st := c.State()
	var wantTotal uint64
	for _, v := range g.Validators {
		addr := types.AddressFromPub(v.PubKey)
		wantTotal += v.Power
		if got := st.Bonded(addr); got != v.Power {
			t.Fatalf("genesis validator %x Bonded = %d, want its genesis power %d", v.PubKey[:8], got, v.Power)
		}
		bond, ok := st.BondOf(addr)
		if !ok {
			t.Fatalf("genesis validator %x holds no bond record", v.PubKey[:8])
		}
		if bond.Height != 0 {
			t.Fatalf("genesis bond height = %d, want 0", bond.Height)
		}
		if !bytes.Equal(bond.Validator, v.PubKey) {
			t.Fatalf("genesis bond key = %x, want the validator's %x", bond.Validator, v.PubKey)
		}
	}
	if got := st.TotalBonded(); got != wantTotal {
		t.Fatalf("TotalBonded = %d, want %d", got, wantTotal)
	}
	if st.TotalUnbonding() != 0 {
		t.Fatalf("a fresh chain holds %d unbonding sparks, want 0", st.TotalUnbonding())
	}

	// The bond is COMMITTED, not merely stored: dropping it from the same
	// state moves the root, and the genesis header carries the version that
	// includes it.
	reference := genesisState(g)
	withBonds := reference.Root()
	if got := c.Head().Header.StateRoot; got != withBonds {
		t.Fatalf("genesis header root = %x, want the bonded state's %x", got, withBonds)
	}
	for _, v := range g.Validators {
		reference.SetBond(types.AddressFromPub(v.PubKey), state.Bond{}) // prunes
	}
	if reference.Root() == withBonds {
		t.Fatal("the genesis state root does not commit to the genesis bonds")
	}

	// The staking parameters are wired from genesis, not left at their zero
	// ("unconfigured") values.
	p := st.Params()
	if p.MinStake != g.Params.MinStakeSparks {
		t.Fatalf("state MinStake = %d, want the genesis value %d", p.MinStake, g.Params.MinStakeSparks)
	}
	if p.UnbondingEpochs != g.Params.UnbondingEpochs {
		t.Fatalf("state UnbondingEpochs = %d, want %d", p.UnbondingEpochs, g.Params.UnbondingEpochs)
	}
	if p.CommitteeSize != g.Params.CommitteeSize {
		t.Fatalf("state CommitteeSize = %d, want %d", p.CommitteeSize, g.Params.CommitteeSize)
	}
}

// TestARealChainBondsThenUnbondsOnTheGenesisCooldown walks a real chain's
// transition: a dev account bonds out of its spendable balance, then unbonds at
// the chain's OWN epoch length. The release height asserted here is
// height + UnbondingEpochs*EpochBlocks with the genesis values (1 +
// 2*1,000 = 2,001 on the devnet), which is the cooldown the plan's derivation
// names - and the assertion fails if any of the three parameters is left
// unwired.
func TestARealChainBondsThenUnbondsOnTheGenesisCooldown(t *testing.T) {
	c, _ := devChain(t)
	g := c.Genesis()
	pub, priv := genesis.DevAccountKey(0)
	addr := types.AddressFromPub(pub)

	sign := func(tx *types.Tx) *types.Tx {
		h := tx.SigningHash(g.Hash())
		tx.Sig = crypto.Sign(priv, h[:])
		return tx
	}

	bond := sign(&types.Tx{
		Type: types.TxBond, From: addr, PubKey: pub, Nonce: 0,
		Fee: g.Params.MinFeeSparks, Amount: g.Params.MinStakeSparks,
	})
	// Probe runs the SAME transition Build/Append would, at head+1.
	next, err := c.Probe([]types.Tx{*bond})
	if err != nil {
		t.Fatalf("a genesis-funded Bond through the chain: %v", err)
	}

	before := c.State().Get(addr).Balance
	if got := next.Get(addr).Balance; got != before-g.Params.MinStakeSparks-g.Params.MinFeeSparks {
		t.Fatalf("balance = %d, want %d (before %d minus bond %d and fee %d)",
			got, before-g.Params.MinStakeSparks-g.Params.MinFeeSparks, before, g.Params.MinStakeSparks, g.Params.MinFeeSparks)
	}
	if got := next.Bonded(addr); got != g.Params.MinStakeSparks {
		t.Fatalf("Bonded = %d, want %d", got, g.Params.MinStakeSparks)
	}

	unbond := sign(&types.Tx{
		Type: types.TxUnbond, From: addr, PubKey: pub, Nonce: 1,
		Fee: 0, Amount: g.Params.MinStakeSparks,
	})
	// Probe returns a state the caller owns and may keep applying to; its
	// height is the block the bond applied in.
	if err := next.ApplyTx(unbond); err != nil {
		t.Fatalf("Unbond against the state the chain produced: %v", err)
	}
	recs := next.UnbondingOf(addr)
	wantRelease := uint64(1) + g.Params.UnbondingEpochs*g.Params.EpochBlocks
	if len(recs) != 1 || recs[0].Amount != g.Params.MinStakeSparks || recs[0].ReleaseHeight != wantRelease {
		t.Fatalf("unbonding = %+v, want one %d-spark record releasing at %d (1 + %d epochs x %d blocks)",
			recs, g.Params.MinStakeSparks, wantRelease, g.Params.UnbondingEpochs, g.Params.EpochBlocks)
	}
	if got := next.Bonded(addr); got != 0 {
		t.Fatalf("Bonded = %d after unbonding the whole bond, want 0", got)
	}
}
