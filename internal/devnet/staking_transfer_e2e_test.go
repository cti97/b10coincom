package devnet

// End-to-end evidence for the two things somebody actually does with this
// chain: move sparks between accounts, and stake them. Both run through the
// WIRED node - real loopback sockets, the real driver, the real mempool, the
// real state transition - so a change that keeps internal/state's unit tests
// green but breaks the path a node really takes (admission, proposal
// selection, the apply rules) fails here instead of on a Raspberry Pi.
//
// The chain is four genesis-file seats at MIN_STAKE each with a short epoch,
// plus one funded dev account. Nothing is written into state directly: every
// balance and every bond below changes because a transaction was committed by
// a block the committee agreed on.
//
// The staking test unbonds BEFORE the first epoch boundary on purpose. A bond
// still standing at the boundary becomes a committee candidate, and a
// candidate with no process behind it would make the test measure the
// fixture's liveness rather than the stake rules. Unbonding early keeps the
// derived committee exactly the four genesis seats, which is what lets the
// chain run 80+ blocks to the release height without a stall.

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/simnet"
	"github.com/cti97/b10coincom/internal/types"
)

const (
	stakingSeats           = 4
	stakingEpoch           = uint64(40)
	stakingUnbondingEpochs = uint64(2)
)

// stakingGenesis is four equal MIN_STAKE seats, a two-epoch unbonding delay and
// one account holding 1,000,000 b10. The seats' genesis power IS their bond
// (the genesis state seeds one bond per seat), so the committee derivation has
// something real to rank even before anybody stakes.
func stakingGenesis(t *testing.T) *genesis.Genesis {
	t.Helper()
	g := genesis.Devnet()
	g.ChainID = "b10coin-staking-e2e"
	g.Params.ChainID = g.ChainID
	g.Params.EpochBlocks = stakingEpoch
	g.Params.UnbondingEpochs = stakingUnbondingEpochs
	g.Params.CommitteeSize = stakingSeats

	vals := make([]genesis.Validator, stakingSeats)
	for i := range vals {
		vals[i] = genesis.Validator{
			PubKey: simnet.ValidatorKey(i).Public().(ed25519.PublicKey),
			Power:  g.Params.MinStakeSparks,
		}
	}
	g.Validators = vals

	devPub, _ := genesis.DevAccountKey(0)
	g.DevAccounts = []genesis.DevAccount{
		{PubKey: devPub, BalanceSparks: 1_000_000 * genesis.SparksPerB10},
	}
	return g
}

// startStakingNet starts the four seats on ephemeral loopback ports and wires
// them into a full mesh, then waits for the chain to be producing blocks: a
// test that submitted a transaction before the first commit would be racing
// the driver's startup, not exercising it.
func startStakingNet(t *testing.T, g *genesis.Genesis) []*Validator {
	t.Helper()
	vs := make([]*Validator, stakingSeats)
	for i := range vs {
		v, err := StartValidator(ValidatorConfig{
			Dir:     t.TempDir(),
			Genesis: g,
			Key:     simnet.ValidatorKey(i),
			Listen:  "127.0.0.1:0",
		})
		if err != nil {
			t.Fatalf("starting staking validator %d: %v", i, err)
		}
		vs[i] = v
	}
	addrs := make([]string, 0, stakingSeats-1)
	for i, v := range vs {
		for j, w := range vs {
			if i != j {
				addrs = append(addrs, w.Addr())
			}
		}
		if err := v.Connect(addrs...); err != nil {
			t.Fatalf("connecting staking validator %d: %v", i, err)
		}
		addrs = addrs[:0]
	}
	waitFor(t, "the staking chain to produce blocks", 30*time.Second, func() bool {
		return vs[0].Height() >= 2
	})
	return vs
}

// waitForAll is waitFor over every validator: admission is checked against the
// state the receiving node has committed, so a transaction that is valid at the
// head can still be refused by a seat a block behind. Tests that submit the
// next transaction in an account's life wait for the whole committee, not just
// the node they read the nonce from.
func waitForAll(t *testing.T, vs []*Validator, what string, timeout time.Duration, cond func(*Validator) bool) {
	t.Helper()
	waitFor(t, what, timeout, func() bool {
		for _, v := range vs {
			if !cond(v) {
				return false
			}
		}
		return true
	})
}

// TestATransferMovesSparksAndPaysTheFee is the ordinary user path: a funded
// account sends one b10 to a key it has never used, a block carries it, and
// every number in the state moves by exactly the amount the rules say -
// recipient +amount, sender -(amount+fee), nonce +1, supply unchanged.
func TestATransferMovesSparksAndPaysTheFee(t *testing.T) {
	g := stakingGenesis(t)
	vs := startStakingNet(t, g)

	devPub, devPriv := genesis.DevAccountKey(0)
	from := types.AddressFromPub(devPub)
	recipientPub, _, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	to := types.AddressFromPub(recipientPub)

	st := vs[0].Chain().State()
	startBalance := st.Get(from).Balance
	supplyBefore := st.TotalBalance()
	if startBalance == 0 {
		t.Fatal("the dev account starts with no sparks; the fixture's premine did not reach the state")
	}

	const amount = 1 * genesis.SparksPerB10
	fee := g.Params.MinFeeSparks
	tx := types.Tx{
		Type:   types.TxTransfer,
		From:   from,
		PubKey: devPub,
		Nonce:  st.Get(from).Nonce,
		Fee:    fee,
		To:     to,
		Amount: amount,
	}
	hash := tx.SigningHash(g.Hash())
	tx.Sig = crypto.Sign(devPriv, hash[:])
	submitToAll(t, vs, tx)

	waitFor(t, "the transfer to be committed", 30*time.Second, func() bool {
		return vs[0].Chain().State().Get(to).Balance == amount
	})

	st = vs[0].Chain().State()
	if got := st.Get(from).Balance; got != startBalance-amount-fee {
		t.Fatalf("sender balance = %d, want %d (start %d - amount %d - fee %d)",
			got, startBalance-amount-fee, startBalance, amount, fee)
	}
	if got := st.Get(from).Nonce; got != 1 {
		t.Fatalf("sender nonce = %d, want 1", got)
	}
	if got := st.Get(to).Balance; got != amount {
		t.Fatalf("recipient balance = %d, want %d", got, amount)
	}
	// A transfer itself creates nothing. The chain's TOTAL balance still grew
	// while we waited, because every committed block mints its reward to the
	// proposer - so the invariant worth asserting is local to the transfer: the
	// sender lost amount+fee, the recipient gained amount, and the only sparks
	// that left the pair are the fee (which is burned, not credited to anyone).
	if diff := startBalance - st.Get(from).Balance - st.Get(to).Balance; diff != fee {
		t.Fatalf("sender loss minus recipient gain = %d, want exactly the fee %d", diff, fee)
	}
	if got := st.TotalBalance(); got < supplyBefore {
		t.Fatalf("total balance fell from %d to %d: blocks mint rewards, so it must never shrink",
			supplyBefore, got)
	}
}

// TestABondUnbondWithdrawLifecycleOnARealChain walks one stake through its whole
// life as three committed transactions: bond (spendable -> locked), unbond
// (locked -> unbonding, with a release height two epochs out), and withdraw
// (unbonding -> spendable, once that height is behind the chain).
func TestABondUnbondWithdrawLifecycleOnARealChain(t *testing.T) {
	g := stakingGenesis(t)
	vs := startStakingNet(t, g)

	devPub, devPriv := genesis.DevAccountKey(0)
	addr := types.AddressFromPub(devPub)
	stake := g.Params.MinStakeSparks
	fee := g.Params.MinFeeSparks

	st := vs[0].Chain().State()
	startBalance := st.Get(addr).Balance
	if startBalance <= stake+fee {
		t.Fatalf("the dev account holds %d sparks, which cannot cover a %d-spark bond", startBalance, stake)
	}

	// --- bond -------------------------------------------------------------
	bond := types.Tx{
		Type:   types.TxBond,
		From:   addr,
		PubKey: devPub,
		Nonce:  st.Get(addr).Nonce,
		Fee:    fee,
		Amount: stake,
	}
	hash := bond.SigningHash(g.Hash())
	bond.Sig = crypto.Sign(devPriv, hash[:])
	submitToAll(t, vs, bond)

	waitForAll(t, vs, "the bond to be committed by every seat", 30*time.Second, func(v *Validator) bool {
		return v.Chain().State().Bonded(addr) == stake
	})
	st = vs[0].Chain().State()
	if got := st.Get(addr).Balance; got != startBalance-stake-fee {
		t.Fatalf("balance after bond = %d, want %d (start %d - stake %d - fee %d)",
			got, startBalance-stake-fee, startBalance, stake, fee)
	}
	if got := st.Get(addr).Nonce; got != 1 {
		t.Fatalf("nonce after bond = %d, want 1", got)
	}

	// --- unbond -----------------------------------------------------------
	unbond := types.Tx{
		Type:   types.TxUnbond,
		From:   addr,
		PubKey: devPub,
		Nonce:  st.Get(addr).Nonce,
		Fee:    0, // an exit must not be taxed (see the state tests)
		Amount: stake,
	}
	hash = unbond.SigningHash(g.Hash())
	unbond.Sig = crypto.Sign(devPriv, hash[:])
	submitToAll(t, vs, unbond)

	waitForAll(t, vs, "the unbond to be committed by every seat", 30*time.Second, func(v *Validator) bool {
		return v.Chain().State().Bonded(addr) == 0
	})
	unbondHeight := blockContaining(t, vs[0], unbond.ID())
	if unbondHeight == 0 {
		t.Fatal("the unbond is gone from the bond table but no block carries it")
	}
	st = vs[0].Chain().State()
	if got := st.Get(addr).Balance; got != startBalance-stake-fee {
		t.Fatalf("balance after unbond = %d, want %d: an unbond moves no sparks until the release height",
			got, startBalance-stake-fee)
	}
	recs := st.UnbondingOf(addr)
	if len(recs) != 1 {
		t.Fatalf("unbonding records = %d, want 1", len(recs))
	}
	// The cooldown is unbondingEpochs * epochBlocks, ROUNDED UP to the next epoch
	// boundary (state.releaseHeightFor): a release is always epoch-aligned, so
	// the committee that produced it and the committee that releases it agree.
	cooldown := unbondHeight + stakingUnbondingEpochs*stakingEpoch
	wantRelease := cooldown
	if rem := cooldown % stakingEpoch; rem != 0 {
		wantRelease = cooldown + (stakingEpoch - rem)
	}
	if recs[0].Amount != stake {
		t.Fatalf("unbonding amount = %d, want the full bond %d", recs[0].Amount, stake)
	}
	if recs[0].ReleaseHeight != wantRelease {
		t.Fatalf("release height = %d, want %d (unbond at %d + %d epochs x %d blocks, rounded up to the boundary by %d)",
			recs[0].ReleaseHeight, wantRelease, unbondHeight, stakingUnbondingEpochs, stakingEpoch, wantRelease-cooldown)
	}

	// The chain has to actually reach the release height; the withdraw below is
	// only meaningful if it is applied at a height the rule allows.
	waitForAll(t, vs, "every seat to pass the release height", 120*time.Second, func(v *Validator) bool {
		return v.Height() >= wantRelease
	})

	// --- withdraw ---------------------------------------------------------
	withdraw := types.Tx{
		Type:   types.TxWithdraw,
		From:   addr,
		PubKey: devPub,
		Nonce:  st.Get(addr).Nonce,
		Fee:    0,
	}
	hash = withdraw.SigningHash(g.Hash())
	withdraw.Sig = crypto.Sign(devPriv, hash[:])
	submitToAll(t, vs, withdraw)

	waitFor(t, "the withdraw to be committed", 60*time.Second, func() bool {
		return vs[0].Chain().State().Get(addr).Balance == startBalance-fee
	})
	st = vs[0].Chain().State()
	if got := st.Bonded(addr); got != 0 {
		t.Fatalf("bond after withdraw = %d, want 0", got)
	}
	if recs := st.UnbondingOf(addr); len(recs) != 0 {
		t.Fatalf("unbonding records after withdraw = %d, want 0", len(recs))
	}
	if got := st.Get(addr).Balance; got != startBalance-fee {
		t.Fatalf("balance after withdraw = %d, want %d: the bond came back and only the bond's fee was spent",
			got, startBalance-fee)
	}
	if got := st.Get(addr).Nonce; got != 3 {
		t.Fatalf("nonce after bond+unbond+withdraw = %d, want 3", got)
	}
}
