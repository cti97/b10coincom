package devnet

// Audit B-1's constructed-state proof: a validator that JOINED AFTER GENESIS,
// was seated, and then ROTATED OUT must still be able to rebuild its driver over
// a head it adopted by catch-up.
//
// The defect was exactly the branch maybeCatchUp has always documented as
// unreachable: consensus.NewDriver refused a key that was (a) not seated at the
// height the fresh engine judges and (b) not in the GENESIS list cfg.IndexOf
// scans. A rotated-out POST-genesis key satisfies both, so every adopted block
// past the boundary failed the same rebuild, the error branch demoted the honest
// member that had just served the pull, and v.drv kept judging the pre-pull head
// until the key was re-seated. The test names all three symptoms.
//
// The whole state is CONSTRUCTED - no live consensus, no clock, no socket. A
// committee of ONE seat with a four-block epoch makes each rotation one Bond
// transaction, and every block is built and appended by the test:
//
//	heights 1..3  the genesis seat proposes. J's Bond (MIN_STAKE) is applied at
//	              height 1, so the state that decides epoch 1 (the one committed
//	              at height 3) seats J alone.
//	height  4     epoch 1: J is seated. The validator starts HERE, which is the
//	              entry check's requirement (head+1 seats the key).
//	heights 4..7  J proposes (it is the epoch-1 seat). K's Bond (3x MIN_STAKE)
//	              is applied at height 5, so epoch 2 - decided at height 7 -
//	              seats K alone and J holds no seat anywhere. J is nevertheless
//	              EVER SEATED, which is the only term that may admit it.
//	height  8     K proposes. The test adopts it through maybeCatchUp's pull
//	              seam, which is the adoption that used to fail the rebuild.
//
// The assertions are positive observables: the adoption COUNTS, the driver is a
// different driver (the stale one is gone), and no peer was demoted.

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/simnet"
	"github.com/cti97/b10coincom/internal/types"
)

func TestARotatedOutPostGenesisNodeRebuildsItsDriver(t *testing.T) {
	minStake := genesis.Devnet().Params.MinStakeSparks
	g := genesis.Devnet()
	g.ChainID = "b10coin-rotated-out-driver"
	g.Params.ChainID = g.ChainID
	// Four-block epochs: one boundary to seat J, one to evict it. CommitteeSize
	// 1 makes each boundary a single-seat rotation with no tie-break in play.
	g.Params.EpochBlocks = 4
	g.Params.CommitteeSize = 1
	gvPub, gvPriv := genesis.DevValidatorKey()
	g.Validators = []genesis.Validator{{PubKey: gvPub, Power: 1}}
	joiner := simnet.ValidatorKey(200)
	evictor := simnet.ValidatorKey(201)
	joinerPub := joiner.Public().(ed25519.PublicKey)
	evictorPub := evictor.Public().(ed25519.PublicKey)
	// DevAccounts are funded accounts, so each key can sign its own Bond (a
	// bond's From IS the address of its signing key).
	g.DevAccounts = []genesis.DevAccount{
		{PubKey: joinerPub, BalanceSparks: minStake + g.Params.MinFeeSparks},
		{PubKey: evictorPub, BalanceSparks: 3*minStake + g.Params.MinFeeSparks},
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
	// Epoch 1's deciding state is the one committed at height 3.
	appendBlock(gvPriv, []types.Tx{rt3BondTx(g, joiner, minStake, 0)})
	appendBlock(gvPriv, nil)
	appendBlock(gvPriv, nil)
	if vals, err := c.CommitteeAt(4); err != nil || genesis.SeatOfPubKey(vals, joinerPub) < 0 {
		t.Fatalf("fixture: epoch 1 does not seat the joiner (%v): the rotation out below would not be a rotation", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("closing the fixture chain: %v", err)
	}

	// Start the joiner's node while it IS seated at head+1, which is what the
	// entry check (RT-1, deliberately unchanged) requires. Quiet loops: nothing
	// advances except the appends below.
	v, err := StartValidator(ValidatorConfig{
		Dir: dir, Genesis: g, Key: joiner,
		TickEvery: time.Hour, WaveEvery: time.Hour,
	})
	if err != nil {
		t.Fatalf("starting the joiner while it is seated: %v", err)
	}
	t.Cleanup(func() { _ = v.Close() })
	stale := v.drv
	ch := v.Chain()

	// Advance the NODE'S chain over the epoch-2 boundary: J proposes 4..7 (it is
	// the epoch-1 seat), K's Bond lands at 5, and height 8 is K's.
	appendBlock = func(priv ed25519.PrivateKey, txs []types.Tx) {
		t.Helper()
		b, err := ch.Build(priv, txs, ch.Head().Header.Timestamp+1)
		if err != nil {
			t.Fatalf("building height %d: %v", ch.Height()+1, err)
		}
		if err := ch.Append(b); err != nil {
			t.Fatalf("appending height %d: %v", b.Header.Height, err)
		}
	}
	appendBlock(joiner, nil)
	appendBlock(joiner, []types.Tx{rt3BondTx(g, evictor, 3*minStake, 0)})
	appendBlock(joiner, nil)
	appendBlock(joiner, nil)
	if ch.Height() != 7 {
		t.Fatalf("fixture: the joiner's chain is at height %d, want 7", ch.Height())
	}
	if ch.IsSeatedAt(8, joinerPub) {
		t.Fatal("fixture: the joiner is still seated at height 8; the rotated-out state was not constructed")
	}
	if !ch.EverSeated(joinerPub) {
		t.Fatal("fixture: the joiner holds no ever-seated record, so the admission under test cannot apply")
	}
	if genesis.SeatOfPubKey(g.Validators, joinerPub) >= 0 {
		t.Fatal("fixture: the joiner is in the genesis list, so it would be admitted by the term this test exists to replace")
	}

	// An honest member announces an adoptable height; the pull adopts height 8,
	// proposed by the epoch-2 seat. This is the adoption that used to fail.
	v.recordHeight(string(evictorPub), "vK", 8)
	v.pull = func(from uint64) error {
		if from != 8 {
			return fmt.Errorf("pull asked for height %d, want 8", from)
		}
		b, err := ch.Build(evictor, nil, ch.Head().Header.Timestamp+1)
		if err != nil {
			return err
		}
		return ch.Append(b)
	}
	v.maybeCatchUp()

	if got := v.Chain().Height(); got != 8 {
		t.Fatalf("the pull did not adopt height 8 (chain at %d)", got)
	}
	if v.drv == stale {
		t.Fatal("the driver still judges the pre-pull head: rebuildDriver was refused and the stale engine was kept")
	}
	if got := v.BlocksAdopted(); got != 1 {
		t.Fatalf("the adoption did not count as one block (adopted=%d): catch-up moved the chain and the observable must say so", got)
	}
	v.peerHMu.Lock()
	demoted := v.peerH[string(evictorPub)].demoted
	v.peerHMu.Unlock()
	if demoted != 0 {
		t.Fatalf("the honest member that served the adopted block was demoted until wave %d: a local rebuild failure is not the peer's fault", demoted)
	}

	// The second reason a rebuild can be refused, and the reason the demotion
	// was wrong even with the admission fixed: the committee for the fresh
	// height cannot be derived. That is the NODE's failure (B-4's undeducible
	// epoch), not the peer's answer, so the adoption must still count and the
	// member must keep its standing. Constructed by replacing the validator's
	// per-height source; the live driver holds its own copy of the config.
	//
	// The log capture starts HERE (audit N-8): this is the first failure of the
	// episode, and the notices below count what the latch suppressed, not what
	// happened before the test started listening.
	var logs bytes.Buffer
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&logs)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	})
	rebuilt := v.drv
	origCommitteeFor := v.cfgC.CommitteeFor
	undeducible := func(h uint64) ([]genesis.Validator, error) {
		return nil, fmt.Errorf("constructed: no committee for height %d", h)
	}
	v.cfgC.CommitteeFor = undeducible
	v.recordHeight(string(evictorPub), "vK", 9)
	v.pull = func(from uint64) error {
		if from != 9 {
			return fmt.Errorf("pull asked for height %d, want 9", from)
		}
		b, err := ch.Build(evictor, nil, ch.Head().Header.Timestamp+1)
		if err != nil {
			return err
		}
		return ch.Append(b)
	}
	v.maybeCatchUp()
	if got := v.Chain().Height(); got != 9 {
		t.Fatalf("the second pull did not adopt height 9 (chain at %d)", got)
	}
	if got := v.BlocksAdopted(); got != 2 {
		t.Fatalf("an adoption over a height whose committee cannot be derived was not counted (adopted=%d, want 2): the block is in the chain", got)
	}
	if v.drv != rebuilt {
		t.Fatal("the driver was replaced although the committee for the fresh height cannot be derived")
	}
	v.peerHMu.Lock()
	demoted = v.peerH[string(evictorPub)].demoted
	v.peerHMu.Unlock()
	if demoted != 0 {
		t.Fatalf("the member was demoted for a rebuild failure caused by this node's own undeducible committee (until wave %d)", demoted)
	}

	// N-8: that failure is not silent any more, and it is logged ONCE per
	// episode rather than once per wave. Two further failed rebuilds (heights 10
	// and 11) must produce exactly one line; a successful rebuild re-arms the
	// notice, so the next failure produces one more.
	pullNext := func(want uint64) {
		t.Helper()
		v.recordHeight(string(evictorPub), "vK", want)
		v.pull = func(from uint64) error {
			if from != want {
				return fmt.Errorf("pull asked for height %d, want %d", from, want)
			}
			b, err := ch.Build(evictor, nil, ch.Head().Header.Timestamp+1)
			if err != nil {
				return err
			}
			return ch.Append(b)
		}
		v.maybeCatchUp()
		if got := v.Chain().Height(); got != want {
			t.Fatalf("the pull did not adopt height %d (chain at %d)", want, got)
		}
	}
	pullNext(10)
	pullNext(11)
	if got := strings.Count(logs.String(), "could not rebuild the consensus driver"); got != 1 {
		t.Fatalf("the refused rebuild was logged %d times over three failed waves, want once per episode: %q", got, logs.String())
	}
	if !strings.Contains(logs.String(), "stale engine keeps judging height 8") {
		t.Fatalf("the rebuild notice does not name the height the stale engine is stuck on: %q", logs.String())
	}

	// Re-armed by success: restore the real per-height source, adopt height 12
	// (the rebuild succeeds), then make it underivable again and watch a FOURTH
	// failed rebuild log its own line.
	v.cfgC.CommitteeFor = origCommitteeFor
	pullNext(12)
	v.cfgC.CommitteeFor = undeducible
	pullNext(13)
	if got := strings.Count(logs.String(), "could not rebuild the consensus driver"); got != 2 {
		t.Fatalf("the rebuild notice was logged %d times after a successful rebuild re-armed it, want 2: %q", got, logs.String())
	}
}
