package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/consensus"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/simnet"
	"github.com/cti97/b10coincom/internal/types"
)

// cmdCheckpoint exports the M7 recovery artefact:
//
//	b10coin checkpoint export --dir PATH --at H [--out FILE]
//
// The output is (height, block, state, precommit votes): the state committed at
// H and the quorum certificate that proves a committee agreed on the block
// whose header commits it. A node started with `--checkpoint FILE` verifies all
// three and then replays the blocks after H normally.
//
// IT READS A DATA DIRECTORY, NOT A RUNNING NODE, and that is deliberate. The
// export needs the state AT H, which a node only keeps at its head; producing it
// means replaying the retained blocks, and the store holds an exclusive lock on
// the directory from Open until Close. So the node must be stopped (or the
// export pointed at a replica). A running node's lock produces
// store.ErrDataDirInUse, which names the directory rather than pretending the
// checkpoint was taken.
func cmdCheckpoint(args []string) error {
	if len(args) == 0 || args[0] != "export" {
		return fmt.Errorf("usage: b10coin checkpoint export --dir PATH --at H [--out FILE] [--genesis PATH | --validators N]")
	}
	fs := flag.NewFlagSet("checkpoint export", flag.ExitOnError)
	dir := fs.String("dir", "", "data directory to export from (stop the node first: it holds the directory lock)")
	at := fs.Uint64("at", 0, "height to export (required; must hold a recorded quorum certificate)")
	out := fs.String("out", "", "file to write (default: stdout)")
	genesisPath := fs.String("genesis", "", "committee file the chain was started with (default: the devnet genesis)")
	validators := fs.Int("validators", 0, "fixture committee size, for a chain started with --validators N")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *dir == "" {
		return fmt.Errorf("checkpoint export needs --dir PATH (the data directory that holds the history)")
	}
	if *at == 0 {
		return fmt.Errorf("checkpoint export needs --at H: the height to checkpoint (height 0 is the genesis block, which every node synthesises and no certificate covers)")
	}
	var (
		g   *genesis.Genesis
		err error
	)
	switch {
	case *genesisPath != "" && *validators != 0:
		return fmt.Errorf("--genesis names the committee file and --validators names the fixture committee; give exactly one (or neither, for the devnet genesis)")
	case *genesisPath != "":
		g, err = genesis.LoadCommitteeJSON(*genesisPath)
		if err != nil {
			return err
		}
	case *validators > 0:
		if *validators > 255 {
			return fmt.Errorf("--validators %d is above the fixture ceiling of 255", *validators)
		}
		g = simnet.Committee(*validators)
	default:
		g = genesis.Devnet()
	}
	// A pruned directory needs its own checkpoint to open at all; this reads the
	// same file a node start would, and refuses a directory whose history is
	// gone without one rather than replaying from the wrong place.
	resume, err := consensus.ResumeForDir(g, *dir)
	if err != nil {
		return err
	}
	c, err := chain.OpenResume(g, *dir, resume)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	cp, err := consensus.ExportCheckpoint(c, *at)
	if err != nil {
		return err
	}
	if *out == "" {
		b, err := consensus.EncodeCheckpoint(cp)
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(append(b, '\n'))
		return err
	}
	if err := consensus.WriteCheckpointFile(*out, cp); err != nil {
		return err
	}
	// The summary goes to stderr so `--out FILE` keeps stdout clean for a shell
	// that pipes the checkpoint to another machine.
	root := ""
	if raw, derr := hex.DecodeString(cp.BlockHex); derr == nil {
		if blk, berr := types.DecodeBlock(raw); berr == nil {
			root = fmt.Sprintf(", state root %x", blk.Header.StateRoot)
		}
	}
	fmt.Fprintf(os.Stderr, "checkpoint height %d%s, %d precommit votes, written to %s\n", cp.Height, root, len(cp.VotesHex), *out)
	return nil
}
