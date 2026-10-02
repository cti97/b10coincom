package devnet

import (
	"testing"

	"github.com/cti97/b10coincom/internal/genesis"
)

// The acceptance criterion for M1: one call produces a real chain of 100
// blocks, including a transfer, and the state is reproducible.
func TestDevnetProduces100Blocks(t *testing.T) {
	got, err := Run(Options{Dir: t.TempDir(), Blocks: 100})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got.Height != 100 {
		t.Fatalf("height = %d, want 100", got.Height)
	}
	if got.TxsIncluded == 0 {
		t.Fatal("no transactions were included; transfer path is untested")
	}
	if got.StateRoot == ([32]byte{}) {
		t.Fatal("state root is empty")
	}
}

// Running twice from scratch must produce an identical final state root.
// This is the determinism guarantee the whole design rests on.
func TestDevnetIsDeterministic(t *testing.T) {
	a, err := Run(Options{Dir: t.TempDir(), Blocks: 50})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Run(Options{Dir: t.TempDir(), Blocks: 50})
	if err != nil {
		t.Fatal(err)
	}
	if a.StateRoot != b.StateRoot {
		t.Fatalf("two runs disagree:\n %x\n %x", a.StateRoot, b.StateRoot)
	}
}

// Reopening an existing devnet directory must replay to the same root.
func TestDevnetReplayMatches(t *testing.T) {
	dir := t.TempDir()
	first, err := Run(Options{Dir: dir, Blocks: 20})
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := Replay(dir)
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if replayed.StateRoot != first.StateRoot {
		t.Fatal("replay produced a different state root")
	}
	if replayed.Height != first.Height {
		t.Fatalf("replay height = %d, want %d", replayed.Height, first.Height)
	}
}

func TestDevnetRejectsZeroBlocks(t *testing.T) {
	if _, err := Run(Options{Dir: t.TempDir(), Blocks: 0}); err == nil {
		t.Fatal("expected an error for zero blocks")
	}
}

func TestDevnetGenesisIsDevnetNotTestnet(t *testing.T) {
	s, err := Run(Options{Dir: t.TempDir(), Blocks: 1})
	if err != nil {
		t.Fatal(err)
	}
	if s.ChainID != genesis.Devnet().ChainID {
		t.Fatalf("chain ID = %q, want the devnet chain", s.ChainID)
	}
}
