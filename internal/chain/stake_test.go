package chain

// M5 Task 1 at the chain boundary: genesisState must WIRE the staking
// parameters and SEED one bond per genesis validator. Both are one-line
// omissions that compile and leave every unit test in package state green -
// staking would then be unconfigured on every real chain, and no genesis seat
// would be a candidate - so they are asserted here, through Open.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
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

// TestACommitteeFileGenesisSeatsAtTheFloor opens the genesis the shipped
// three-Pi recipe now describes (audit RT-2): three validators at MIN_STAKE and
// one spare seat. Each seat's bond is its power — 10^11 sparks, not the one
// spark the pre-fix example produced — and the chain's committee_size has room
// for a fourth seat, so the epoch-0 committee is the three listed keys and a
// later bond is admitted beside them.
func TestACommitteeFileGenesisSeatsAtTheFloor(t *testing.T) {
	entries := make([]genesis.CommitteeEntry, 0, 3)
	pubA, _ := genesis.DevAccountKey(0)
	pubB, _ := genesis.DevAccountKey(1)
	third := make([]byte, 32)
	copy(third, pubA)
	third[0] ^= 0xff // a distinct 32-byte key; the loader only requires 32 bytes
	for i, pub := range [][]byte{pubA, pubB, third} {
		entries = append(entries, genesis.CommitteeEntry{
			Name:   "pi-" + string(rune('0'+i)),
			PubKey: hex.EncodeToString(pub),
			Power:  genesis.Devnet().Params.MinStakeSparks,
		})
	}
	raw, err := json.Marshal(genesis.CommitteeFile{
		ChainID:       "recipe-test-1",
		CommitteeSize: 4,
		Validators:    entries,
	})
	if err != nil {
		t.Fatal(err)
	}
	g, err := genesis.ParseCommitteeJSON(raw)
	if err != nil {
		t.Fatalf("the recipe's committee file must load: %v", err)
	}

	c, err := Open(g, t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { c.Close() })

	minStake := g.Params.MinStakeSparks
	st := c.State()
	for _, v := range g.Validators {
		addr := types.AddressFromPub(v.PubKey)
		if got := st.Bonded(addr); got != minStake {
			t.Fatalf("genesis seat %x Bonded = %d sparks, want its genesis power %d (MIN_STAKE); a one-spark bond here is RT-2's capture vector",
				v.PubKey[:4], got, minStake)
		}
	}
	if got := g.Params.CommitteeSize; got != 4 {
		t.Fatalf("chain committee_size = %d, want the file's 4 (3 keys + a spare seat)", got)
	}
	committee, err := c.CommitteeAt(0)
	if err != nil {
		t.Fatalf("CommitteeAt(0): %v", err)
	}
	if len(committee) != 3 {
		t.Fatalf("epoch-0 committee = %d seats, want the 3 listed keys", len(committee))
	}
	for _, v := range committee {
		if v.Power < minStake {
			t.Fatalf("epoch-0 seat %x holds %d sparks of power, below MIN_STAKE %d", v.PubKey[:4], v.Power, minStake)
		}
	}
}

// TestARealChainBondsThenUnbondsOnTheGenesisCooldown walks a real chain's
// transition: a dev account bonds out of its spendable balance, then unbonds at
// the chain's OWN epoch length. The cooldown's floor is
// height + UnbondingEpochs*EpochBlocks with the genesis values (1 +
// 2*1,000 = 2,001 on the devnet), and the release height is the epoch boundary
// at or after it (3,000 on 1,000-block epochs, audit ST-4) - and the assertion
// fails if any of the three parameters is left unwired.
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
	// The cooldown's floor is 1 + 2*1,000 = 2,001; the release height is the
	// EPOCH BOUNDARY at or after it (audit ST-4), which on the devnet's
	// 1,000-block epochs is 3,000. Rounding is upward only: the release is never
	// earlier than the cooldown.
	floor := uint64(1) + g.Params.UnbondingEpochs*g.Params.EpochBlocks
	wantRelease := uint64(3_000)
	if len(recs) != 1 || recs[0].Amount != g.Params.MinStakeSparks || recs[0].ReleaseHeight != wantRelease {
		t.Fatalf("unbonding = %+v, want one %d-spark record releasing at %d (the epoch boundary at or after %d = 1 + %d epochs x %d blocks)",
			recs, g.Params.MinStakeSparks, wantRelease, floor, g.Params.UnbondingEpochs, g.Params.EpochBlocks)
	}
	if recs[0].ReleaseHeight < floor {
		t.Fatalf("release height %d is earlier than the cooldown floor %d", recs[0].ReleaseHeight, floor)
	}
	if recs[0].ReleaseHeight%g.Params.EpochBlocks != 0 {
		t.Fatalf("release height %d is not an epoch boundary (%d-block epochs)", recs[0].ReleaseHeight, g.Params.EpochBlocks)
	}
	if got := next.Bonded(addr); got != 0 {
		t.Fatalf("Bonded = %d after unbonding the whole bond, want 0", got)
	}
}
