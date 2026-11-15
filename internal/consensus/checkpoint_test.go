package consensus

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/state"
	"github.com/cti97/b10coincom/internal/types"
)

// M7 step 4/5 tests: checkpoint export and verification, the pruner's bound on
// the data directory, and the recovery proof - a wiped node given ONLY a
// checkpoint reaches the same head and the same state root as the node that
// kept its history.

// certChain builds a chain of n empty blocks over the four-validator fixture
// genesis, with an epoch length of `epoch`, and records a real quorum
// certificate for every height through the same EncodeCertificate a live
// commit uses. It returns the chain and its genesis; the chain is closed by the
// test's cleanup.
func certChain(t *testing.T, n int, epoch uint64) (*chain.Chain, *genesis.Genesis, string) {
	t.Helper()
	g := fourValGenesis(t)
	g.Params.EpochBlocks = epoch
	dir := t.TempDir()
	c, err := chain.Open(g, dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	priv := testCommitteeKey(0)
	for h := 1; h <= n; h++ {
		b, err := c.Build(priv, nil, int64(1_700_000_000+h))
		if err != nil {
			t.Fatalf("Build(%d): %v", h, err)
		}
		if err := c.Append(b); err != nil {
			t.Fatalf("Append(%d): %v", h, err)
		}
		votes := quorumCertFor(t, b, uint64(h), 0)
		if err := c.PutCert(uint64(h), EncodeCertificate(0, votes)); err != nil {
			t.Fatalf("PutCert(%d): %v", h, err)
		}
	}
	return c, g, dir
}

// TestExportCheckpointCarriesTheStateAndItsProof pins the artefact's content:
// the block at H, the state at H, the precommit votes, and - through
// VerifyCheckpoint - that the state hashes to the root that block commits and
// that the votes reach a genesis-committee quorum.
func TestExportCheckpointCarriesTheStateAndItsProof(t *testing.T) {
	c, g, _ := certChain(t, 20, 4)
	const at = 7
	cp, err := ExportCheckpoint(c, at)
	if err != nil {
		t.Fatalf("ExportCheckpoint(%d): %v", at, err)
	}
	if cp.Height != at {
		t.Fatalf("checkpoint height = %d, want %d", cp.Height, at)
	}
	if cp.Version != CheckpointVersion || cp.ChainID != g.ChainID {
		t.Fatalf("checkpoint header = version %d chain %q", cp.Version, cp.ChainID)
	}
	if len(cp.VotesHex) != 3 {
		t.Fatalf("checkpoint carries %d votes, want the 3-vote quorum", len(cp.VotesHex))
	}
	resume, err := VerifyCheckpoint(g, cp)
	if err != nil {
		t.Fatalf("VerifyCheckpoint: %v", err)
	}
	if resume.Height != at {
		t.Fatalf("verified checkpoint height = %d, want %d", resume.Height, at)
	}
	blk, err := c.BlockAt(at)
	if err != nil {
		t.Fatal(err)
	}
	if rid, bid := resume.Head.ID(), blk.ID(); rid != bid {
		t.Fatalf("the checkpoint's block is %x, want %x", rid[:8], bid[:8])
	}
	st, err := c.StateAt(at)
	if err != nil {
		t.Fatal(err)
	}
	if !resume.State.Equal(st) {
		t.Fatal("the verified checkpoint's state is not the chain's state at the horizon")
	}
	if root := resume.State.Root(); root != blk.Header.StateRoot {
		t.Fatalf("the checkpoint's state hashes to %x, but the block commits %x", root[:8], blk.Header.StateRoot[:8])
	}
	// The file form round-trips, including through the strict decoder.
	b, err := EncodeCheckpoint(cp)
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecodeCheckpoint(b)
	if err != nil {
		t.Fatalf("the encoded checkpoint does not decode: %v", err)
	}
	if _, err := VerifyCheckpoint(g, back); err != nil {
		t.Fatalf("the decoded checkpoint does not verify: %v", err)
	}
	// Trailing data is refused: a checkpoint file must not be two documents.
	if _, err := DecodeCheckpoint(append(b, []byte(" {}")...)); err == nil {
		t.Fatal("DecodeCheckpoint accepted trailing data")
	}
}

// TestCheckpointTamperingIsRefused is the trust argument as a table: every
// field an attacker could change is changed, and each change must be refused.
func TestCheckpointTamperingIsRefused(t *testing.T) {
	c, g, _ := certChain(t, 20, 4)
	base, err := ExportCheckpoint(c, 7)
	if err != nil {
		t.Fatal(err)
	}
	otherState, err := c.StateAt(3)
	if err != nil {
		t.Fatal(err)
	}
	otherBlock, err := c.BlockAt(11)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(*Checkpoint)
		want   string
	}{
		{"wrong state", func(cp *Checkpoint) {
			cp.StateHex = hexOf(otherState.Encode())
		}, "hashes to"},
		{"wrong block", func(cp *Checkpoint) {
			cp.BlockHex = hexOf(otherBlock.Encode())
		}, "height"},
		{"no votes", func(cp *Checkpoint) {
			cp.VotesHex = nil
		}, "no precommit votes"},
		{"sub-quorum votes", func(cp *Checkpoint) {
			cp.VotesHex = cp.VotesHex[:1]
		}, "quorum"},
		{"wrong round", func(cp *Checkpoint) {
			cp.Round = 9
		}, "quorum"},
		{"wrong genesis", func(cp *Checkpoint) {
			cp.GenesisHash = "00"
		}, "genesis"},
		{"wrong chain", func(cp *Checkpoint) {
			cp.ChainID = "other-chain"
		}, "chain"},
		{"wrong version", func(cp *Checkpoint) {
			cp.Version = CheckpointVersion + 1
		}, "version"},
		{"bad hex", func(cp *Checkpoint) {
			cp.StateHex = "zz"
		}, "not hex"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cp := *base
			cp.VotesHex = append([]string(nil), base.VotesHex...)
			tc.mutate(&cp)
			_, err := VerifyCheckpoint(g, &cp)
			if err == nil {
				t.Fatalf("VerifyCheckpoint accepted a checkpoint with %s", tc.name)
			}
			if !errors.Is(err, ErrBadCheckpoint) {
				t.Fatalf("%s gave %v, want ErrBadCheckpoint", tc.name, err)
			}
			if !contains(err.Error(), tc.want) {
				t.Fatalf("%s gave %q, want it to name %q", tc.name, err, tc.want)
			}
		})
	}
	// Sanity: the unmutated copy still verifies, so the table above is not
	// passing because every checkpoint fails.
	if _, err := VerifyCheckpoint(g, base); err != nil {
		t.Fatalf("the untouched checkpoint does not verify: %v", err)
	}
}

// TestCheckpointVotesFromAStrangerKeyAreRefused pins the ANCHOR rather than the
// signature math: a checkpoint signed by keys that are not genesis seats is not
// evidence, however well-formed the signatures are.
func TestCheckpointVotesFromAStrangerKeyAreRefused(t *testing.T) {
	c, g, _ := certChain(t, 20, 4)
	cp, err := ExportCheckpoint(c, 7)
	if err != nil {
		t.Fatal(err)
	}
	blk, err := c.BlockAt(7)
	if err != nil {
		t.Fatal(err)
	}
	// A "quorum" of three keys nobody's genesis listed.
	seed := crypto.HashParts([]byte("stranger"), []byte{1})
	stranger := ed25519NewKeyFromSeed(seed[:])
	votes := make([]*Vote, 0, 3)
	for i := 0; i < 3; i++ {
		v := &Vote{Type: MsgPrecommit, Height: 7, Round: 0, BlockID: blk.ID(), Validator: stranger.Public().(ed25519PublicKey)}
		h := v.SigningHash()
		v.Sig = ed25519Sign(stranger, h[:])
		votes = append(votes, v)
	}
	// Keep the state; replace only the proof.
	cp.VotesHex = nil
	for _, v := range votes {
		cp.VotesHex = append(cp.VotesHex, hexOf(EncodeVote(v)))
	}
	if _, err := VerifyCheckpoint(g, cp); err == nil {
		t.Fatal("a checkpoint proved by non-genesis keys verified")
	} else if !errors.Is(err, ErrBadCheckpoint) {
		t.Fatalf("stranger votes gave %v, want ErrBadCheckpoint", err)
	}
}

// TestExportCheckpointRefusesWithoutACertificate is plan §7's line in code:
// retention without a provable checkpoint is worse than a full disk. A chain
// with no recorded certificate for the horizon must refuse to produce one.
func TestExportCheckpointRefusesWithoutACertificate(t *testing.T) {
	c, _, _ := certChain(t, 12, 4)
	// Height 11 has a certificate; ask for a height that does not.
	if _, err := ExportCheckpoint(c, 0); err == nil {
		t.Fatal("ExportCheckpoint(0) succeeded; the genesis block has no certificate")
	}
	if _, err := ExportCheckpoint(c, 13); err == nil {
		t.Fatal("ExportCheckpoint above the head succeeded")
	}
	// A chain whose certificates were recorded only up to 8.
	c2, _, _ := certChain(t, 12, 4)
	cp, err := ExportCheckpoint(c2, 3)
	if err != nil {
		t.Fatal(err)
	}
	if cp.Height != 3 {
		t.Fatalf("exported height %d, want 3", cp.Height)
	}
}

// TestCommitteeDiffNamesEveryDifference pins the static-committee check that
// makes an exporter refuse a checkpoint its own importer could not verify.
// (The rotation itself needs staking transactions; what is tested here is the
// comparison the refusal rests on.)
func TestCommitteeDiffNamesEveryDifference(t *testing.T) {
	g := fourValGenesis(t)
	if diff := committeeDiff(g.Validators, g.Validators); diff != "" {
		t.Fatalf("a committee differs from itself: %q", diff)
	}
	// Same keys, one power changed.
	changed := append([]genesis.Validator(nil), g.Validators...)
	changed[0].Power = 5
	if diff := committeeDiff(g.Validators, changed); diff == "" {
		t.Fatal("a power change was not reported")
	}
	// A seat replaced.
	replaced := append([]genesis.Validator(nil), g.Validators...)
	replaced[3] = genesis.Validator{PubKey: make([]byte, 32), Power: 1}
	if diff := committeeDiff(g.Validators, replaced); diff == "" {
		t.Fatal("a replaced seat was not reported")
	}
	// A seat removed.
	if diff := committeeDiff(g.Validators, g.Validators[:3]); diff == "" {
		t.Fatal("a missing seat was not reported")
	}
}

// prunerFor builds a pruner over dir keeping retain blocks, with a log that
// records refusals so a test can assert WHY a prune did not happen.
func prunerFor(t *testing.T, dir string, retain uint64) *Pruner {
	t.Helper()
	p, err := NewPruner(dir, retain)
	if err != nil {
		t.Fatal(err)
	}
	p.Log = func(format string, args ...any) { t.Logf(format, args...) }
	return p
}

// appendWithCerts appends count more blocks to c, recording each one's
// certificate, and returns the new head.
func appendWithCerts(t *testing.T, c *chain.Chain, count int) uint64 {
	t.Helper()
	priv := testCommitteeKey(0)
	for i := 0; i < count; i++ {
		h := c.Height() + 1
		b, err := c.Build(priv, nil, int64(1_700_000_000)+int64(h))
		if err != nil {
			t.Fatalf("Build(%d): %v", h, err)
		}
		if err := c.Append(b); err != nil {
			t.Fatalf("Append(%d): %v", h, err)
		}
		votes := quorumCertFor(t, b, h, 0)
		if err := c.PutCert(h, EncodeCertificate(0, votes)); err != nil {
			t.Fatalf("PutCert(%d): %v", h, err)
		}
	}
	return c.Height()
}

// TestThePrunerReachesASteadyState is the disk-growth proof. A chain is run in
// phases; after every phase the pruner bounds it to keepLast blocks. If history
// were unbounded the directory would grow with the head, so the assertion is
// about the RATIO: nine times the history must not cost nine times the disk.
//
// The residual growth is real and bounded by design: M7 never rewrites a
// segment, so the segment the horizon falls inside keeps its pruned prefix
// until the next prune passes it whole. At most two segments' worth of one
// record kind is ever present, which is the "small margin" plan §6 allows.
func TestThePrunerReachesASteadyState(t *testing.T) {
	const (
		epoch   = 4
		retain  = 4 * epoch // the floor: four epochs
		phase   = 400
		phases  = 9
		maxSize = 4.0 // final/phase-1 ratio ceiling
	)
	c, _, dir := certChain(t, 0, epoch)
	p := prunerFor(t, dir, retain)

	var sizes []int64
	var stats []uint64
	for i := 0; i < phases; i++ {
		head := appendWithCerts(t, c, phase)
		st, err := p.MaybePrune(c)
		if err != nil {
			t.Fatalf("phase %d (head %d): MaybePrune: %v", i+1, head, err)
		}
		stats = append(stats, st.Blocks)
		size, err := dirSize(dir)
		if err != nil {
			t.Fatal(err)
		}
		sizes = append(sizes, size)
		t.Logf("phase %d: head %d, base %d, data dir %d bytes, %d block segments pruned", i+1, head, c.Base(), size, st.Blocks)
	}
	if sizes[0] == 0 {
		t.Fatal("the data directory is empty")
	}
	ratio := float64(sizes[len(sizes)-1]) / float64(sizes[0])
	if ratio > maxSize {
		t.Fatalf("the data directory grew by %.2fx while the chain grew %dx (sizes %v): retention is not bounding it", ratio, phases, sizes)
	}
	// The history really was pruned: the base is far above the genesis and the
	// certificate horizon moved with it.
	if c.Base() < uint64(phases*phase-retain-epoch) {
		t.Fatalf("the pruner's base is %d after %d blocks with retention %d", c.Base(), phases*phase, retain)
	}
	if _, ok := c.CertAt(c.Base() - 100); ok {
		t.Fatal("a certificate far below the horizon is still served")
	}
	// A checkpoint is on disk for the horizon, and the node can be restarted
	// from it (this is the property the disk bound must never cost).
	cp, err := ReadCheckpointFile(filepath.Join(dir, CheckpointFileName))
	if err != nil {
		t.Fatalf("no committed checkpoint after pruning: %v", err)
	}
	if cp.Height != c.Base() {
		t.Fatalf("the checkpoint is at %d but the base is %d", cp.Height, c.Base())
	}
}

// TestAWipedNodeRecoversFromACheckpointToTheSameHeadAndRoot is M7's acceptance
// test (step 5). It is not "the node starts":
//
//  1. node A builds a chain, records certificates, and prunes;
//  2. node B is an EMPTY directory that is given ONLY A's checkpoint;
//  3. B verifies it (genesis-committee quorum + state root) and resumes at the
//     horizon, then appends the retained blocks - exactly the bytes a peer
//     serves over BLOCK_SYNC, validated by the same Append a live commit uses;
//  4. after a restart from its own directory, B's HEAD and STATE ROOT must equal
//     A's, block for block.
func TestAWipedNodeRecoversFromACheckpointToTheSameHeadAndRoot(t *testing.T) {
	const (
		epoch  = 4
		retain = 4 * epoch
		total  = 120
	)
	a, g, dirA := certChain(t, total, epoch)
	pruner := prunerFor(t, dirA, retain)
	if _, err := pruner.MaybePrune(a); err != nil {
		t.Fatalf("pruning node A: %v", err)
	}
	horizon := a.Base()
	if horizon == 0 {
		t.Fatal("node A pruned nothing")
	}
	wantHeight, wantRoot := a.Height(), a.State().Root()
	wantHeadID := a.Head().ID()

	// Every block and certificate A still holds for the retained range: what a
	// peer would serve.
	blocks := make([]*typesBlockAlias, 0)
	for h := horizon + 1; h <= wantHeight; h++ {
		b, err := a.BlockAt(h)
		if err != nil {
			t.Fatalf("node A lost retained block %d: %v", h, err)
		}
		blocks = append(blocks, b)
	}

	// Node B: a wiped directory holding ONLY the checkpoint.
	dirB := t.TempDir()
	cp, err := ReadCheckpointFile(filepath.Join(dirA, CheckpointFileName))
	if err != nil {
		t.Fatalf("node A has no checkpoint to give: %v", err)
	}
	if err := InstallCheckpoint(dirB, cp); err != nil {
		t.Fatal(err)
	}
	resume, err := ResumeForDir(g, dirB)
	if err != nil {
		t.Fatalf("node B cannot verify the checkpoint: %v", err)
	}
	if resume == nil {
		t.Fatal("node B found no checkpoint to resume from")
	}
	b, err := chain.OpenResume(g, dirB, resume)
	if err != nil {
		t.Fatalf("node B cannot open from the checkpoint: %v", err)
	}
	if got := b.Height(); got != horizon {
		t.Fatalf("node B resumed at height %d, want the checkpoint's %d", got, horizon)
	}
	horizonRoot := mustStateAt(t, a, horizon).Root()
	if root := b.State().Root(); root != horizonRoot {
		t.Fatalf("node B's resumed state root is %x, want the horizon's %x", root[:8], horizonRoot[:8])
	}

	// B pulls the retained blocks forward through Append - the same validation a
	// live commit and a BLOCK_SYNC adoption go through - and records their
	// certificates, so it can serve them onward.
	for i, blk := range blocks {
		if err := b.Append(blk); err != nil {
			t.Fatalf("node B refused retained block %d: %v", horizon+1+uint64(i), err)
		}
		h := blk.Header.Height
		payload, ok := a.CertAt(h)
		if !ok {
			t.Fatalf("node A lost the certificate for retained height %d", h)
		}
		if err := b.PutCert(h, payload); err != nil {
			t.Fatal(err)
		}
	}
	if got := b.Height(); got != wantHeight {
		t.Fatalf("node B's head is %d, want %d", got, wantHeight)
	}
	if got := b.State().Root(); got != wantRoot {
		t.Fatalf("node B's state root is %x, want %x", got[:8], wantRoot[:8])
	}
	if got := b.Head().ID(); got != wantHeadID {
		t.Fatalf("node B's head block is %x, want %x", got[:8], wantHeadID[:8])
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}

	// And it PERSISTS: a restart from B's own directory resumes from B's own
	// checkpoint and reaches the same head and root again.
	resume2, err := ResumeForDir(g, dirB)
	if err != nil {
		t.Fatalf("node B cannot read its own checkpoint back: %v", err)
	}
	if resume2 == nil {
		t.Fatal("node B wrote no checkpoint of its own")
	}
	b2, err := chain.OpenResume(g, dirB, resume2)
	if err != nil {
		t.Fatalf("node B cannot restart from its own directory: %v", err)
	}
	defer func() { _ = b2.Close() }()
	if got := b2.Height(); got != wantHeight {
		t.Fatalf("after a restart node B is at %d, want %d", got, wantHeight)
	}
	if got := b2.State().Root(); got != wantRoot {
		t.Fatalf("after a restart node B's root is %x, want %x", got[:8], wantRoot[:8])
	}
	// The same head and root as the node that kept its whole history: A is
	// still on the same chain (its head state was never touched by pruning).
	aRoot, bRoot := a.State().Root(), b2.State().Root()
	if aRoot != bRoot {
		t.Fatalf("the recovered node's root %x differs from the node that kept history %x", bRoot[:8], aRoot[:8])
	}
}

// mustStateAt is StateAt that fails the test on error, for assertions inside
// long tests.
func mustStateAt(t *testing.T, c *chain.Chain, h uint64) *state.State {
	t.Helper()
	st, err := c.StateAt(h)
	if err != nil {
		t.Fatalf("StateAt(%d): %v", h, err)
	}
	return st
}

// typesBlockAlias keeps the block slice's type readable without threading a
// types import through the test body.
type typesBlockAlias = types.Block

// hexOf renders bytes as the checkpoint's hex fields do.
func hexOf(b []byte) string { return hex.EncodeToString(b) }

// contains is strings.Contains, kept local so the table above reads as prose.
func contains(s, sub string) bool { return strings.Contains(s, sub) }

// dirSize sums the regular files directly under dir (the store does not use
// subdirectories for its history), so a test can assert the steady state rather
// than trust it.
func dirSize(dir string) (int64, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	var total int64
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return 0, err
		}
		total += info.Size()
	}
	return total, nil
}
