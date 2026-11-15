package devnet

import (
	"testing"
	"time"

	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/simnet"
)

// M7's fixture-only epoch override. It exists so the pruning scenario can reach
// an epoch boundary in minutes rather than the ~5000 blocks the shipped fixture
// epoch (1000) would need, and it is confined to the fixture mode on purpose:
// on a real chain the epoch is a property of the shared committee document, and
// a flag that could move it would let two nodes hash different chains from one
// file.

// TestAFixtureCommitteeCanRunAShortEpoch pins the wiring: the override reaches
// the genesis the chain is opened with (and therefore the chain ID and every
// root), without changing anything about the committee itself.
func TestAFixtureCommitteeCanRunAShortEpoch(t *testing.T) {
	v, err := StartValidator(ValidatorConfig{
		Dir:         t.TempDir(),
		Index:       0,
		Validators:  2,
		EpochBlocks: 4,
		TickEvery:   time.Hour,
		WaveEvery:   time.Hour,
	})
	if err != nil {
		t.Fatalf("StartValidator with a fixture epoch: %v", err)
	}
	defer func() { _ = v.Close() }()
	g := v.Chain().Genesis()
	if g.Params.EpochBlocks != 4 {
		t.Fatalf("the fixture chain's epoch is %d, want the override 4", g.Params.EpochBlocks)
	}
	if len(g.Validators) != 2 {
		t.Fatalf("the override changed the committee: %d seats, want 2", len(g.Validators))
	}
	// The epoch override moves the GENESIS HASH: it is a different chain, which
	// is exactly why it may not be used against an existing directory whose
	// nodes disagree about it.
	if g.Hash() == fixtureGenesisWithoutOverride(t).Hash() {
		t.Fatal("the epoch override did not move the genesis hash; the directory check would not catch a mismatch")
	}
}

// fixtureGenesisWithoutOverride is simnet's committee for the same size, with
// its own epoch: the chain a node without the flag would open.
func fixtureGenesisWithoutOverride(t *testing.T) *genesis.Genesis {
	t.Helper()
	return simnet.Committee(2)
}

// TestTheFixtureEpochOverrideIsRefusedWithARealCommittee pins the refusal: a
// genesis file owns its epoch, and a flag that silently lost to it (or silently
// won) would be a chain-identity foot-gun.
func TestTheFixtureEpochOverrideIsRefusedWithARealCommittee(t *testing.T) {
	g := fixtureGenesisWithoutOverride(t)
	_, err := StartValidator(ValidatorConfig{
		Dir:         t.TempDir(),
		Genesis:     g,
		Key:         simnet.ValidatorKey(0),
		EpochBlocks: 4,
	})
	if err == nil {
		t.Fatal("StartValidator accepted --epoch-blocks alongside a genesis file")
	}
	// Below the floor, the fixture mode refuses rather than running a chain on
	// one-block epochs.
	if _, err := StartValidator(ValidatorConfig{
		Dir:         t.TempDir(),
		Index:       0,
		Validators:  1,
		EpochBlocks: 1,
	}); err == nil {
		t.Fatal("StartValidator accepted a one-block fixture epoch")
	}
}
