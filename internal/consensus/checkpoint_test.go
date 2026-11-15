package consensus

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

// TestAPrunedNodeCanReExportItsOwnHorizon is the "days later" case: the export
// that moves a seat to a new machine happens from the pruned directory, long
// after the prune, when the epoch that decided the horizon's committee is no
// longer derivable (its deciding state was pruned). The export must still work:
// the committee comparison is a rotation DIAGNOSTIC, while the trust check is
// the certificate re-tallied under the genesis committee - and the horizon's
// certificate is deliberately kept by the pruner for exactly this.
func TestAPrunedNodeCanReExportItsOwnHorizon(t *testing.T) {
	const (
		epoch  = 4
		retain = 4 * epoch
		total  = 40
	)
	a, g, dir := certChain(t, total, epoch)
	p := prunerFor(t, dir, retain)
	if _, err := p.MaybePrune(a); err != nil {
		t.Fatal(err)
	}
	horizon := a.Base()
	if horizon == 0 {
		t.Fatal("nothing was pruned")
	}
	cp, err := ReadCheckpointFile(filepath.Join(dir, CheckpointFileName))
	if err != nil {
		t.Fatalf("the pruner wrote no checkpoint: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	// Reopen the PRUNED directory: the epoch that decided the horizon's
	// committee is gone, so CommitteeAt(horizon) must fail - and the export must
	// not care.
	resume, err := ResumeForDir(g, dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := chain.OpenResume(g, dir, resume)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	if _, err := b.CommitteeAt(horizon); err == nil {
		t.Fatalf("fixture: the epoch at height %d is still derivable; this test is not exercising the pruned path", horizon)
	}
	again, err := ExportCheckpoint(b, horizon)
	if err != nil {
		t.Fatalf("re-exporting the horizon from a pruned directory: %v", err)
	}
	if again.Height != cp.Height {
		t.Fatalf("the re-exported checkpoint is at %d, the pruned one at %d", again.Height, cp.Height)
	}
	if _, err := VerifyCheckpoint(g, again); err != nil {
		t.Fatalf("the re-exported checkpoint does not verify: %v", err)
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
	for i := 0; i < phases; i++ {
		head := appendWithCerts(t, c, phase)
		st, err := p.MaybePrune(c)
		if err != nil {
			t.Fatalf("phase %d (head %d): MaybePrune: %v", i+1, head, err)
		}
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
	blocks := make([]*types.Block, 0)
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
	t.Logf("RECOVERY: wiped node at height %d, root %x (pruned node %d, root %x)", b.Height(), b.State().Root(), wantHeight, wantRoot)
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

// TestAPrunedNodeSaysPlainlyItCannotServeBelowItsHorizon is plan §6's last
// acceptance line: a pruned node must either serve a peer behind its horizon or
// SAY that it cannot. Silence here would be the relay gate's defect in another
// place, so the refusal is a typed error AND a logged line - and the line is
// throttled, because a lagging peer asks again every wave.
func TestAPrunedNodeSaysPlainlyItCannotServeBelowItsHorizon(t *testing.T) {
	const (
		epoch  = 4
		retain = 4 * epoch
		total  = 120
	)
	a, _, dir := certChain(t, total, epoch)
	p := prunerFor(t, dir, retain)
	if _, err := p.MaybePrune(a); err != nil {
		t.Fatalf("pruning: %v", err)
	}
	base := a.Base()
	if base == 0 {
		t.Fatal("nothing was pruned")
	}
	sy := NewSyncer(a, nil, testCommitteeKey(0))
	var said []string
	sy.Log = func(format string, args ...any) {
		said = append(said, fmt.Sprintf(format, args...))
	}
	// A range entirely below the horizon: unservable by construction.
	req := syncSignReq(t, testCommitteeKey(0), 1, 2)
	if _, err := sy.Answer(req); !errors.Is(err, ErrRangePruned) {
		t.Fatalf("a range below the horizon gave %v, want ErrRangePruned", err)
	}
	if len(said) != 1 {
		t.Fatalf("the pruned-range refusal logged %d lines, want exactly 1", len(said))
	}
	if !strings.Contains(said[0], "pruned") || !strings.Contains(said[0], "checkpoint") {
		t.Fatalf("the refusal line reads %q; it must say the history was pruned and name the checkpoint remedy", said[0])
	}
	// A second refusal within the throttle window stays quiet.
	req2 := syncSignReq(t, testCommitteeKey(0), 3, 4)
	if _, err := sy.Answer(req2); !errors.Is(err, ErrRangePruned) {
		t.Fatalf("second pruned range gave %v, want ErrRangePruned", err)
	}
	if len(said) != 1 {
		t.Fatalf("the throttled refusal logged %d lines in total, want 1", len(said))
	}
	// A range ABOVE the horizon is still served, so the refusal is not "never
	// serve after pruning".
	good := syncSignReq(t, testCommitteeKey(0), base+1, base+2)
	resp, err := sy.Answer(good)
	if err != nil {
		t.Fatalf("a range above the horizon was refused: %v", err)
	}
	if len(resp.Units) != 2 {
		t.Fatalf("served %d units above the horizon, want 2", len(resp.Units))
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

// ---------------------------------------------------------------------------
// M8: rotation-aware checkpoints.
//
// The security argument in executable form is TestAFabricatedSelfConsistent-
// CheckpointIsAdmittedOnlyByTrust: a checkpoint whose committee, state, block
// and votes were all fabricated by an attacker passes the trust flag trivially.
// That is not a defect to hide - it is the reason the flag exists and the
// reason it is not the default.
// ---------------------------------------------------------------------------

// rotatedCertChain builds a chain of n blocks whose committee ROTATES: a
// funded post-genesis key bonds at height 1, the boundary at epoch-1 seats it,
// and every height gets a certificate signed by the committee that judged it
// (all of its seats, so quorum holds whatever the power cap does to the
// weights).
func rotatedCertChain(t *testing.T, n int, epoch uint64) (*chain.Chain, *genesis.Genesis) {
	t.Helper()
	g := fourValGenesis(t)
	g.Params.EpochBlocks = epoch
	// One spare seat so the joiner is ADDED, not an eviction: the point is a
	// committee DIFFERENT from genesis, not a specific rotation policy.
	g.Params.CommitteeSize = 5
	xpub, xpriv := genesis.DevAccountKey(0)
	keys := make(map[string]ed25519.PrivateKey)
	for i := 0; i < len(g.Validators); i++ {
		keys[string(g.Validators[i].PubKey)] = testCommitteeKey(i)
	}
	keys[string(xpub)] = xpriv

	c, err := chain.Open(g, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })

	build := func(txs []types.Tx) {
		h := c.Height() + 1
		b, err := c.Build(testCommitteeKey(0), txs, c.Head().Header.Timestamp+1)
		if err != nil {
			t.Fatalf("Build(%d): %v", h, err)
		}
		if err := c.Append(b); err != nil {
			t.Fatalf("Append(%d): %v", h, err)
		}
		vals, err := c.CommitteeAt(h)
		if err != nil {
			t.Fatalf("CommitteeAt(%d): %v", h, err)
		}
		votes := make([]*Vote, 0, len(vals))
		for _, v := range vals {
			priv, ok := keys[string(v.PubKey)]
			if !ok {
				t.Fatalf("fixture: no private key for seat %x at height %d", v.PubKey, h)
			}
			vote := &Vote{Type: MsgPrecommit, Height: h, Round: 0, BlockID: b.ID(), Validator: v.PubKey}
			sigHash := vote.SigningHash()
			vote.Sig = ed25519.Sign(priv, sigHash[:])
			votes = append(votes, vote)
		}
		if err := c.PutCert(h, EncodeCertificate(0, votes)); err != nil {
			t.Fatalf("PutCert(%d): %v", h, err)
		}
	}

	tx := &types.Tx{
		Type:   types.TxBond,
		From:   types.AddressFromPub(xpub),
		PubKey: xpub,
		Nonce:  0,
		Amount: g.Params.MinStakeSparks,
		Fee:    g.Params.MinFeeSparks,
	}
	sigHash := tx.SigningHash(g.Hash())
	tx.Sig = crypto.Sign(xpriv, sigHash[:])
	build([]types.Tx{*tx}) // height 1: the joiner bonds
	for c.Height() < uint64(n) {
		build(nil)
	}
	return c, g
}

// TestAFabricatedSelfConsistentCheckpointIsAdmittedOnlyByTrust is M8's whole
// security argument, executed. An attacker who holds three keys nobody's
// genesis lists fabricates a committee, a state, a block whose header commits
// that state's root, and votes by those keys. The file is internally perfect
// and has nothing to do with the real chain:
//
//   - without the flag it is REFUSED (the genesis anchor is the only check a
//     node with no history can make), and the error says why and what the flag
//     would cost;
//   - with --checkpoint-trust it is ADMITTED, because self-consistency is all
//     that flag checks. The test proves the weakness rather than hiding it.
func TestAFabricatedSelfConsistentCheckpointIsAdmittedOnlyByTrust(t *testing.T) {
	g := fourValGenesis(t)
	g.Params.EpochBlocks = 4
	const at = 7

	// The attacker's committee: three keys, zero genesis seats.
	vals := make([]genesis.Validator, 3)
	privs := make([]ed25519.PrivateKey, 3)
	for i := range vals {
		h := crypto.HashParts([]byte("m8-fabricated-attacker"), []byte{byte(i)})
		privs[i] = ed25519.NewKeyFromSeed(h[:])
		vals[i] = genesis.Validator{PubKey: privs[i].Public().(ed25519.PublicKey), Power: 1}
	}
	// A state of the attacker's own, not genesis and not any committed height.
	st := state.NewWithParams(chain.GenesisParams(g))
	acc := st.Get(types.AddressFromPub(vals[0].PubKey))
	acc.Balance = 999 * genesis.SparksPerB10
	st.Set(types.AddressFromPub(vals[0].PubKey), acc)

	blk := &types.Block{Header: types.Header{
		Height:    at,
		StateRoot: st.Root(),
		TxRoot:    crypto.MerkleRoot(nil),
		Timestamp: g.Time + at,
		Proposer:  vals[0].PubKey,
	}}
	votes := make([]*Vote, 0, len(vals))
	for i := range vals {
		v := &Vote{Type: MsgPrecommit, Height: at, Round: 0, BlockID: blk.ID(), Validator: vals[i].PubKey}
		vh := v.SigningHash()
		v.Sig = ed25519.Sign(privs[i], vh[:])
		votes = append(votes, v)
	}
	gh := g.Hash()
	cp := &Checkpoint{
		Version:      CheckpointVersion,
		ChainID:      g.ChainID,
		GenesisHash:  hexOf(gh[:]),
		Height:       at,
		Round:        0,
		BlockHex:     hexOf(blk.Encode()),
		StateHex:     hexOf(st.Encode()),
		CommitteeHex: encodeCommittee(vals),
		IssuedAt:     time.Now().Unix(),
		Note:         trustedCheckpointNote,
	}
	for _, v := range votes {
		cp.VotesHex = append(cp.VotesHex, hexOf(EncodeVote(v)))
	}

	// WITH the flag: admitted, root and all. This is the documented weakness.
	resume, err := VerifyTrustedCheckpoint(g, cp, TrustPolicy{MaxAgeEpochs: 4})
	if err != nil {
		t.Fatalf("the trust flag must ADMIT a fabricated, self-consistent checkpoint - that weakness is exactly what it trades for: %v", err)
	}
	if got, want := resume.State.Root(), st.Root(); got != want {
		t.Fatalf("the fabricated checkpoint resumed at root %x, want its own fabricated root %x", got[:8], want[:8])
	}
	if resume.Height != at {
		t.Fatalf("the fabricated checkpoint resumed at height %d, want %d", resume.Height, at)
	}

	// WITHOUT the flag: refused, for the right reason, naming the cost.
	_, err = VerifyCheckpoint(g, cp)
	if err == nil {
		t.Fatal("a fabricated checkpoint was admitted WITHOUT --checkpoint-trust: the genesis anchor is not being applied")
	}
	if !errors.Is(err, ErrBadCheckpoint) {
		t.Fatalf("the refusal is %v, want ErrBadCheckpoint", err)
	}
	for _, want := range []string{"--checkpoint-trust", "genesis", "fabricate", "internal consistency"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal %q does not name %q; it must say WHY and WHAT the flag would cost", err, want)
		}
	}

	// The warning the importer prints must name the TRADE, not congratulate the
	// operator on an import: it is the second of the four signals.
	notice := TrustStatement(cp)
	for _, want := range []string{"did NOT verify", "fabricate", "this is the real chain", "--checkpoint-max-age"} {
		if !strings.Contains(notice, want) {
			t.Fatalf("the import warning %q does not name %q", notice, want)
		}
	}
}

// TestATrustedCheckpointOlderThanTheBoundIsRefused is step 3's hard bound: a
// trusted checkpoint is an anchor at an instant, not forever. Without the bound
// it would pin a node to an arbitrary past fork, which is why the verifier
// refuses an unbounded policy as well as an expired file.
func TestATrustedCheckpointOlderThanTheBoundIsRefused(t *testing.T) {
	c, g, _ := certChain(t, 20, 4)
	cp, err := ExportCheckpoint(c, 7)
	if err != nil {
		t.Fatal(err)
	}
	// Fresh: a genesis-committee file also verifies on the trusted path, so the
	// bound is what makes the difference.
	if _, err := VerifyTrustedCheckpoint(g, cp, TrustPolicy{MaxAgeEpochs: 4}); err != nil {
		t.Fatalf("a freshly exported checkpoint was refused as expired: %v", err)
	}
	old := *cp
	old.IssuedAt = time.Now().Add(-time.Hour).Unix()
	_, err = VerifyTrustedCheckpoint(g, &old, TrustPolicy{MaxAgeEpochs: 4})
	if err == nil {
		t.Fatal("a trusted checkpoint issued an hour ago was admitted under a 32-second bound")
	}
	if !errors.Is(err, ErrBadCheckpoint) || !strings.Contains(err.Error(), "older than") {
		t.Fatalf("the expiry refusal is %v, want ErrBadCheckpoint naming the age", err)
	}
	// An unbounded policy is not a policy: the bound is not optional.
	if _, err := VerifyTrustedCheckpoint(g, cp, TrustPolicy{}); err == nil || !strings.Contains(err.Error(), "maximum age") {
		t.Fatalf("an unbounded trust policy gave %v, want a refusal demanding a maximum age", err)
	}
	// A file dated in the future would defeat the bound, so it is refused too.
	future := *cp
	future.IssuedAt = time.Now().Add(24 * time.Hour).Unix()
	if _, err := VerifyTrustedCheckpoint(g, &future, TrustPolicy{MaxAgeEpochs: 4}); err == nil || !strings.Contains(err.Error(), "future") {
		t.Fatalf("a forward-dated trusted checkpoint gave %v, want a refusal naming the future stamp", err)
	}
}

// TestARotatedCheckpointNeedsTrustAndThenReachesTheReplayRoot is the rotation
// round trip, in one place:
//
//   - the default exporter REFUSES a rotated horizon (M7's behaviour intact);
//   - `checkpoint export --trust` writes the rotation-aware form;
//   - the default importer REFUSES it, and the error says why and what the flag
//     would cost;
//   - a trusted import resumes at the SAME state root as replaying that height,
//     adopts the file into a wiped directory, replays the retained blocks, and
//     reaches the exporting node's exact head and state root;
//   - a restart from B's own pruned directory adopts the rotated file through
//     VerifyAdoptedCheckpoint and reports the same root again.
func TestARotatedCheckpointNeedsTrustAndThenReachesTheReplayRoot(t *testing.T) {
	const (
		epoch = 4
		total = 12
		at    = 7 // the last height of epoch 1, i.e. a real prune horizon
	)
	a, g := rotatedCertChain(t, total, epoch)
	// Fixture sanity: the horizon's committee really is not the genesis one.
	vals, err := a.CommitteeAt(at)
	if err != nil {
		t.Fatalf("CommitteeAt(%d): %v", at, err)
	}
	if committeeDiff(g.Validators, vals) == "" {
		t.Fatal("fixture: the committee at the horizon is still the genesis committee")
	}

	// 1. Default export refuses rotation: M7's refusal, unchanged.
	if _, err := ExportCheckpoint(a, at); err == nil {
		t.Fatal("the default export wrote a checkpoint for a rotated horizon")
	} else if !strings.Contains(err.Error(), "not the genesis committee") {
		t.Fatalf("the default export's refusal is %v, want it to name the rotated committee", err)
	}

	// 2. The trusted exporter writes the committee that SIGNED the height.
	cp, err := ExportTrustedCheckpoint(a, at)
	if err != nil {
		t.Fatalf("ExportTrustedCheckpoint(%d): %v", at, err)
	}
	signed, err := decodeCommittee(cp.CommitteeHex)
	if err != nil {
		t.Fatalf("the exported committee does not decode: %v", err)
	}
	if diff := committeeDiff(vals, signed); diff != "" {
		t.Fatalf("the checkpoint carries the wrong signer committee: %s", diff)
	}
	if cp.Note != trustedCheckpointNote {
		t.Fatalf("a trusted checkpoint's note does not state the trade: %q", cp.Note)
	}
	if cp.IssuedAt <= 0 {
		t.Fatal("a checkpoint carries no issue time, so no age bound can apply")
	}

	// 3. Without the flag, the rotated file is refused and the error names the
	//    exact trade.
	_, err = VerifyCheckpoint(g, cp)
	if err == nil {
		t.Fatal("a rotated checkpoint was admitted WITHOUT --checkpoint-trust")
	}
	if !errors.Is(err, ErrBadCheckpoint) {
		t.Fatalf("the refusal is %v, want ErrBadCheckpoint", err)
	}
	for _, want := range []string{"--checkpoint-trust", "AGREES WITH ITSELF", "fabricate", "--checkpoint-max-age"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the rotated refusal %q does not name %q", err, want)
		}
	}

	// 4. With the flag: the resumed state is the replayed state at the horizon.
	wantHorizonRoot := mustStateAt(t, a, at).Root()
	resume, err := VerifyTrustedCheckpoint(g, cp, TrustPolicy{MaxAgeEpochs: 4})
	if err != nil {
		t.Fatalf("VerifyTrustedCheckpoint: %v", err)
	}
	if got := resume.State.Root(); got != wantHorizonRoot {
		t.Fatalf("the trusted import's state root is %x, replay gives %x", got[:8], wantHorizonRoot[:8])
	}
	if blk, err := a.BlockAt(at); err != nil {
		t.Fatal(err)
	} else {
		got, want := resume.Head.ID(), blk.ID()
		if got != want {
			t.Fatalf("the trusted import's block is %x, want the chain's block %x", got[:8], want[:8])
		}
	}

	// 5. A wiped directory adopts it and replays the retained blocks to the
	//    exporting node's head and state root.
	dirB := t.TempDir()
	if err := InstallCheckpoint(dirB, cp); err != nil {
		t.Fatal(err)
	}
	b, err := chain.OpenResume(g, dirB, resume)
	if err != nil {
		t.Fatalf("a wiped node cannot open from the trusted checkpoint: %v", err)
	}
	if got := b.Height(); got != at {
		t.Fatalf("the wiped node resumed at height %d, want %d", got, at)
	}
	for h := uint64(at + 1); h <= total; h++ {
		blk, err := a.BlockAt(h)
		if err != nil {
			t.Fatalf("the exporting node lost retained block %d: %v", h, err)
		}
		if err := b.Append(blk); err != nil {
			t.Fatalf("the wiped node refused retained block %d: %v", h, err)
		}
	}
	wantHeadRoot := a.State().Root()
	if got := b.State().Root(); got != wantHeadRoot {
		t.Fatalf("the restored node's head root is %x, the exporting node's is %x", got[:8], wantHeadRoot[:8])
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}

	// 6. And it PERSISTS: the directory's own rotated checkpoint is adopted on
	//    restart (no flag, no age bound - the trust decision was the import).
	resume2, err := ResumeForDir(g, dirB)
	if err != nil {
		t.Fatalf("a pruned directory with a rotated checkpoint cannot restart: %v", err)
	}
	if resume2 == nil {
		t.Fatal("the pruned directory's own rotated checkpoint was not adopted on restart")
	}
	b2, err := chain.OpenResume(g, dirB, resume2)
	if err != nil {
		t.Fatalf("restart from the rotated checkpoint: %v", err)
	}
	defer func() { _ = b2.Close() }()
	if got := b2.State().Root(); got != wantHeadRoot {
		t.Fatalf("after a restart the root is %x, want %x", got[:8], wantHeadRoot[:8])
	}
	t.Logf("ROTATED ROUND TRIP: horizon %d, replay root %x, restored head %d root %x", at, wantHorizonRoot, b2.Height(), b2.State().Root())
}
