package devnet

// Audit B-2 is documented and was deliberately not changed: StartValidator
// refuses a key that is neither in the genesis committee nor seated at head+1,
// because an out-of-seat restart has no voting duty and no seat to sign as. The
// refusal had no pinning test, so this constructs the exact shape that must be
// refused - a key that HAS been seated (so EverSeated admits it as a peer and the
// transport gates let it talk) but is unseated at head+1 after a rotation out -
// and shows both halves: the same key is admitted while it is seated at head+1,
// and refused once it is not.
//
// Constructed, not raced: two-block epochs, four blocks built by hand, no
// consensus loop and no clock.

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/simnet"
	"github.com/cti97/b10coincom/internal/types"
)

func TestAnEverSeatedButUnseatedKeyIsRefusedAtStartValidator(t *testing.T) {
	minStake := genesis.Devnet().Params.MinStakeSparks
	g := genesis.Devnet()
	g.ChainID = "b10coin-ever-seated-entry"
	g.Params.ChainID = g.ChainID
	g.Params.EpochBlocks = 2
	g.Params.CommitteeSize = 2
	gvPub, gvPriv := genesis.DevValidatorKey()
	g.Validators = []genesis.Validator{{PubKey: gvPub, Power: minStake}}
	joiner := simnet.ValidatorKey(70)
	joinerPub := joiner.Public().(ed25519.PublicKey)
	g.DevAccounts = []genesis.DevAccount{{PubKey: joinerPub, BalanceSparks: minStake + g.Params.MinFeeSparks}}
	if err := g.Validate(); err != nil {
		t.Fatalf("fixture genesis: %v", err)
	}
	dir := t.TempDir()

	c, err := chain.Open(g, dir)
	if err != nil {
		t.Fatalf("opening the fixture chain: %v", err)
	}
	appendBlock := func(priv ed25519.PrivateKey, txs []types.Tx) {
		t.Helper()
		b, err := c.Build(priv, txs, c.Head().Header.Timestamp+1)
		if err != nil {
			t.Fatalf("building height %d: %v", c.Height()+1, err)
		}
		if err := c.Append(b); err != nil {
			t.Fatalf("appending height %d: %v", b.Header.Height, err)
		}
	}
	// Height 1 bonds the joiner; height 2 fills epoch 1. The state at height 3
	// will decide epoch 2, so the joiner is seated for heights 2..3 only.
	appendBlock(gvPriv, []types.Tx{rt3BondTx(g, joiner, minStake, 0)})
	appendBlock(gvPriv, nil)
	if got := c.Height(); got != 2 {
		t.Fatalf("fixture height = %d, want 2", got)
	}
	if !c.IsSeatedAt(3, joinerPub) {
		t.Fatal("fixture: the joiner is not seated at head+1, so the positive control would prove nothing")
	}
	if err := c.Close(); err != nil {
		t.Fatalf("closing the chain before the positive control: %v", err)
	}

	// POSITIVE CONTROL: while the key is seated at head+1 it may start.
	v, err := StartValidator(ValidatorConfig{
		Dir: dir, Genesis: g, Key: joiner,
		TickEvery: time.Hour, WaveEvery: time.Hour,
	})
	if err != nil {
		t.Fatalf("a key seated at head+1 was refused: %v", err)
	}
	if err := v.Close(); err != nil {
		t.Fatalf("closing the admitted validator: %v", err)
	}

	// Rotate the joiner OUT: it proposes its own full exit at height 3, which is
	// the state that decides epoch 2.
	c, err = chain.Open(g, dir)
	if err != nil {
		t.Fatalf("reopening after the positive control: %v", err)
	}
	appendBlock(joiner, []types.Tx{rt3UnbondTx(g, joiner, minStake, 1)})
	if got := c.Height(); got != 3 {
		t.Fatalf("fixture height = %d after the exit, want 3", got)
	}
	if c.IsSeatedAt(4, joinerPub) {
		t.Fatal("fixture: the joiner is still seated at head+1 after its full exit; the refusal cannot apply")
	}
	if !c.EverSeated(joinerPub) {
		t.Fatal("fixture: the joiner holds no ever-seated record, so this is not the B-2 shape")
	}
	if err := c.Close(); err != nil {
		t.Fatalf("closing the rotated-out chain: %v", err)
	}

	// THE REFUSAL: ever-seated is an AUTHORISATION fact, not a seat.
	refused, err := StartValidator(ValidatorConfig{
		Dir: dir, Genesis: g, Key: joiner,
		TickEvery: time.Hour, WaveEvery: time.Hour,
	})
	if err == nil {
		_ = refused.Close()
		t.Fatal("StartValidator admitted an ever-seated key that is not seated at head+1: it would sign as no seat")
	}
	for _, want := range []string{
		"refusing to start",
		"not listed in the committee's genesis",
		"height 4",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal does not say %q: %v", want, err)
		}
	}
}
