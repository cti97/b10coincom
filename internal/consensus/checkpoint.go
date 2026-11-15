package consensus

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/state"
	"github.com/cti97/b10coincom/internal/store"
	"github.com/cti97/b10coincom/internal/types"
)

// Checkpoints: M7's answer to "a node that lost history must still be able to
// rejoin".
//
// WHAT A CHECKPOINT IS, AND WHY (plan §4). A state root alone cannot resume a
// node: knowing that the state at height H hashes to R tells you nothing about
// the accounts, bonds and unbonding records you must build block H+1 on. So a
// checkpoint carries the STATE itself, and what makes it trustworthy is that
// the state HASHES to the root committed by a block whose quorum certificate
// this node can verify:
//
//	checkpoint = (height H, block H, state@H, the precommit votes for block H)
//
// Verification is then three independent checks, and each one closes a way a
// peer could lie:
//
//  1. the votes reach a quorum of the GENESIS committee for block H at its
//     round (VerifyCommitCertificate). The genesis committee is the chain's
//     trust anchor: only keys that founded the chain can produce this, and a
//     peer cannot forge their signatures. THE ANCHOR STAYS GENESIS.
//  2. the block is at height H and the state decodes to a state whose Root()
//     equals block H's committed StateRoot. A peer that swaps the state for one
//     of its own cannot make it hash to a root the committee signed.
//  3. (at the chain, in chain.OpenResume) the retained blocks then replay on
//     top of that state and must reproduce each stored header's root.
//
// ROTATION ASSUMPTION, STATED BECAUSE IT IS THE NEXT MILESTONE'S PROBLEM (plan
// §4 and §7). M7 verifies a certificate against the GENESIS committee, which is
// correct while the committee is genesis-fixed and is the only check that needs
// no light client. This repository's M5 rotation means the committee at H can
// differ from genesis: ExportCheckpoint REFUSES to write a checkpoint in that
// case rather than write one its own importer could not verify, and
// VerifyCheckpoint refuses anything the genesis committee did not sign. Once
// rotation lands on a live chain, a checkpoint format must additionally carry
// the committee at H and a light-client proof of how it rotated to it; that is
// a materially harder problem and it is deliberately NOT half-done here.
//
// The state snapshot also keeps the plan's "committee at the horizon": with the
// horizon one block BEFORE an epoch boundary (chain.PruneHistory), the snapshot
// is exactly the state that DERIVES the first retained epoch's committee, so a
// resumed node can judge the first retained block without any committee proof
// beyond its own state.

// CheckpointVersion is the on-disk format version this build writes and reads.
// A checkpoint from a different version is refused rather than guessed at: the
// file carries a state snapshot whose layout is versioned too.
const CheckpointVersion = 1

// CheckpointFileName is the file a pruned data directory carries its horizon
// checkpoint in, and the file `--checkpoint FILE` installs.
const CheckpointFileName = "checkpoint.json"

// pendingCheckpointName is the crash-safe staging name. A pruning pass writes
// this file, then drops history, then renames it over CheckpointFileName: a
// crash between the two leaves a checkpoint on disk whose horizon is the new
// base - never a pruned directory with no way to resume. It is read in
// preference to CheckpointFileName when it matches the directory's base.
const pendingCheckpointName = "checkpoint.json.pending"

// Checkpoint is the verifiable recovery artefact. It is JSON because it is a
// CONTAINER the operator may inspect and copy between machines, not a signed or
// hashed structure: nothing here is authenticated by its own bytes. The block,
// the votes and the state are authenticated by the certificate and the state
// root they hash to.
type Checkpoint struct {
	Version int `json:"version"`
	// ChainID and GenesisHash bind the file to a chain, and an import into a
	// node started with another genesis refuses before any consensus check.
	// They are a sanity binding, not the trust anchor - the votes are.
	ChainID     string `json:"chain_id"`
	GenesisHash string `json:"genesis_hash"`
	// Height H: the last height this checkpoint speaks for. Retained history
	// starts at H+1, which is an epoch boundary.
	Height uint64 `json:"height"`
	// Round is the consensus round in which block H was committed.
	Round uint32 `json:"round"`
	// BlockHex is types.Block.Encode() for block H.
	BlockHex string `json:"block_hex"`
	// StateHex is state.Encode() for the committed state at H.
	StateHex string `json:"state_hex"`
	// VotesHex are the encoded precommit votes that committed block H.
	VotesHex []string `json:"precommit_votes_hex"`
	// Note records, in the file itself, what this checkpoint does and does not
	// prove - the assumption is too important to live only in a source file.
	Note string `json:"note"`
}

const checkpointNote = "M7 checkpoint: verifiable against the GENESIS committee only. Retained history starts at height+1. Rotation-aware checkpoints (carrying the committee at height and a rotation proof) are explicitly out of scope for M7; an exporter refuses to produce one where the committee has rotated."

// ExportCheckpoint builds the checkpoint for height at from a chain that holds
// that height's block AND its quorum certificate. It refuses, with reasons, in
// exactly the cases where the artefact it would write could not be verified by
// an importer.
func ExportCheckpoint(c *chain.Chain, at uint64) (*Checkpoint, error) {
	cp, _, err := exportCheckpointAt(c, at)
	return cp, err
}

func exportCheckpointAt(c *chain.Chain, at uint64) (*Checkpoint, *state.State, error) {
	if at == 0 {
		return nil, nil, fmt.Errorf("%w: height 0 is the genesis block, which every node synthesises and no certificate covers", ErrBadCheckpoint)
	}
	g := c.Genesis()
	if head := c.Height(); at > head {
		return nil, nil, fmt.Errorf("%w: height %d is above the head %d", ErrBadCheckpoint, at, head)
	}
	// THE STATIC-COMMITTEE CHECK, made where the exporter can still see the
	// truth. The committed state at the horizon decides the FIRST RETAINED
	// epoch's committee; the certificate at the horizon was signed by the
	// epoch that ENDS there. M7 verifies that certificate against genesis, so
	// exporting a checkpoint whose horizon sits under a rotated committee would
	// produce a file this build's importer must refuse - better to refuse at the
	// source, naming rotation.
	vals, err := c.CommitteeAt(at)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: the committee at height %d cannot be derived: %v", ErrBadCheckpoint, at, err)
	}
	if diff := committeeDiff(g.Validators, vals); diff != "" {
		return nil, nil, fmt.Errorf("%w: the committee at height %d is not the genesis committee (%s). A checkpoint is verified against the GENESIS committee while the committee is genesis-fixed; rotation-aware checkpoints are the next milestone's problem (docs/plan-2026-11-15-m7-bounded-history.md §4 and §7), and this build refuses to write a checkpoint its own importer could not verify", ErrBadCheckpoint, at, diff)
	}
	payload, ok := c.CertAt(at)
	if !ok {
		return nil, nil, fmt.Errorf("%w: no quorum certificate is recorded for height %d, so nothing proves a committee committed it. A checkpoint without a certificate is a state snapshot with no authority; this node cannot produce one until it has adopted that height's certificate", ErrBadCheckpoint, at)
	}
	round, encoded, err := DecodeCertificate(payload)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: the stored certificate for height %d does not decode: %v", ErrBadCheckpoint, at, err)
	}
	blk, err := c.BlockAt(at)
	if err != nil {
		return nil, nil, err
	}
	// Verify what we are about to write: an exporter that emits a checkpoint
	// its own verifier rejects is writing a file that fails on the next machine.
	if err := VerifyCommitCertificate(g.Validators, blk, round, encoded); err != nil {
		return nil, nil, fmt.Errorf("the stored certificate for height %d does not verify against the genesis committee: %w", at, err)
	}
	st, err := c.StateAt(at)
	if err != nil {
		return nil, nil, err
	}
	if root := st.Root(); root != blk.Header.StateRoot {
		return nil, nil, fmt.Errorf("%w: the state at height %d hashes to %x, but that block commits %x", ErrBadCheckpoint, at, root[:8], blk.Header.StateRoot[:8])
	}
	cp := &Checkpoint{
		Version:     CheckpointVersion,
		ChainID:     g.ChainID,
		GenesisHash: hex.EncodeToString(hashSlice(g.Hash())),
		Height:      at,
		Round:       round,
		BlockHex:    hex.EncodeToString(blk.Encode()),
		StateHex:    hex.EncodeToString(st.Encode()),
		VotesHex:    make([]string, 0, len(encoded)),
		Note:        checkpointNote,
	}
	for _, raw := range encoded {
		cp.VotesHex = append(cp.VotesHex, hex.EncodeToString(raw))
	}
	return cp, st, nil
}

// VerifyCheckpoint authenticates a checkpoint against the genesis committee and
// returns the hand-off chain.OpenResume needs. See this file's header for what
// each check closes.
func VerifyCheckpoint(g *genesis.Genesis, cp *Checkpoint) (*chain.ResumeState, error) {
	if cp == nil {
		return nil, fmt.Errorf("%w: no checkpoint", ErrBadCheckpoint)
	}
	if cp.Version != CheckpointVersion {
		return nil, fmt.Errorf("%w: checkpoint format version %d, want %d", ErrBadCheckpoint, cp.Version, CheckpointVersion)
	}
	if cp.ChainID != g.ChainID {
		return nil, fmt.Errorf("%w: the checkpoint is for chain %q, but this node runs %q", ErrBadCheckpoint, cp.ChainID, g.ChainID)
	}
	if want := hex.EncodeToString(hashSlice(g.Hash())); cp.GenesisHash != want {
		return nil, fmt.Errorf("%w: the checkpoint names genesis %s, but this node's genesis is %s; a checkpoint from another chain cannot be adopted", ErrBadCheckpoint, cp.GenesisHash, want)
	}
	blockBytes, err := hex.DecodeString(cp.BlockHex)
	if err != nil {
		return nil, fmt.Errorf("%w: the checkpoint's block is not hex: %v", ErrBadCheckpoint, err)
	}
	blk, err := types.DecodeBlock(blockBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: the checkpoint's block does not decode: %v", ErrBadCheckpoint, err)
	}
	if blk.Header.Height != cp.Height {
		return nil, fmt.Errorf("%w: the checkpoint names height %d but its block is at height %d", ErrBadCheckpoint, cp.Height, blk.Header.Height)
	}
	stateBytes, err := hex.DecodeString(cp.StateHex)
	if err != nil {
		return nil, fmt.Errorf("%w: the checkpoint's state is not hex: %v", ErrBadCheckpoint, err)
	}
	st, err := state.DecodeState(stateBytes, chain.GenesisParams(g))
	if err != nil {
		return nil, fmt.Errorf("%w: the checkpoint's state does not decode: %v", ErrBadCheckpoint, err)
	}
	// THE CHECK THAT MAKES THE SNAPSHOT THE COMMITTED STATE: whatever the votes
	// say, the state must hash to the root the certified block commits.
	if root := st.Root(); root != blk.Header.StateRoot {
		return nil, fmt.Errorf("%w: the checkpoint's state hashes to %x, but its block commits %x: the snapshot is not the state that block committed", ErrBadCheckpoint, root[:8], blk.Header.StateRoot[:8])
	}
	encoded := make([][]byte, 0, len(cp.VotesHex))
	for i, raw := range cp.VotesHex {
		v, err := hex.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: precommit vote %d is not hex: %v", ErrBadCheckpoint, i+1, err)
		}
		encoded = append(encoded, v)
	}
	if len(encoded) == 0 {
		return nil, fmt.Errorf("%w: the checkpoint carries no precommit votes", ErrBadCheckpoint)
	}
	if err := VerifyCommitCertificate(g.Validators, blk, cp.Round, encoded); err != nil {
		return nil, err
	}
	return &chain.ResumeState{Height: cp.Height, Head: blk, State: st}, nil
}

// hashSlice renders a fixed hash as a slice, for hex-encoding without repeating
// the [:] dance at each call site.
func hashSlice(h [32]byte) []byte { return h[:] }

// shortKey renders a public key's first bytes for an error message, guarding a
// short key so a malformed committee produces an error rather than a panic.
func shortKey(k string) string {
	b := []byte(k)
	if len(b) > 4 {
		b = b[:4]
	}
	return fmt.Sprintf("%x", b)
}

// committeeDiff reports how got differs from want, or "" when they are the same
// committee: same keys, same powers, same seat count. Order is not significant.
func committeeDiff(want, got []genesis.Validator) string {
	index := func(vals []genesis.Validator) map[string]uint64 {
		m := make(map[string]uint64, len(vals))
		for _, v := range vals {
			m[string(v.PubKey)] = v.Power
		}
		return m
	}
	w, g := index(want), index(got)
	if len(w) != len(g) {
		return fmt.Sprintf("genesis has %d seats, the horizon committee has %d", len(w), len(g))
	}
	var problems []string
	for k, pw := range w {
		gpw, ok := g[k]
		switch {
		case !ok:
			problems = append(problems, fmt.Sprintf("genesis key %s is not seated at the horizon", shortKey(k)))
		case gpw != pw:
			problems = append(problems, fmt.Sprintf("genesis key %s has power %d, the horizon seats it with %d", shortKey(k), pw, gpw))
		}
	}
	for k := range g {
		if _, ok := w[k]; !ok {
			problems = append(problems, fmt.Sprintf("horizon key %s is not a genesis seat", shortKey(k)))
		}
	}
	sort.Strings(problems)
	if len(problems) > 3 {
		return strings.Join(problems[:3], "; ") + fmt.Sprintf("; and %d more", len(problems)-3)
	}
	return strings.Join(problems, "; ")
}

// DecodeCheckpoint parses a checkpoint file's bytes strictly: trailing data
// after the JSON document is refused (encoding/json's decoder allows it), so a
// file cannot be two things at once.
func DecodeCheckpoint(b []byte) (*Checkpoint, error) {
	// json.Unmarshal, not a Decoder: it refuses trailing bytes after the
	// document ("invalid character ... after top-level value"), which a stream
	// decoder would happily leave for the next reader. Unknown fields are
	// accepted so a newer writer's extra diagnostic fields do not make this
	// build reject an otherwise verifiable checkpoint; the VERSION is what
	// guards the layout.
	var cp Checkpoint
	if err := json.Unmarshal(b, &cp); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadCheckpoint, err)
	}
	return &cp, nil
}

// EncodeCheckpoint renders the file form. JSON is indented so an operator can
// read a checkpoint before trusting it; nothing here is signed bytes.
func EncodeCheckpoint(cp *Checkpoint) ([]byte, error) {
	return json.MarshalIndent(cp, "", "  ")
}

// ReadCheckpointFile reads and parses one checkpoint file.
func ReadCheckpointFile(path string) (*Checkpoint, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return DecodeCheckpoint(raw)
}

// WriteCheckpointFile writes cp to path atomically: a temporary file in the
// same directory, fsynced, then renamed over path, then the directory fsynced.
// A reader therefore sees either the old file or the new one, never a half
// written document - and a pruned directory's restart path is exactly this
// file.
func WriteCheckpointFile(path string, cp *Checkpoint) error {
	b, err := EncodeCheckpoint(cp)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if err := tmp.Chmod(0o644); err != nil {
		cleanup()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		cleanup()
		return err
	}
	if _, err := tmp.Write([]byte("\n")); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	syncCheckpointDir(dir)
	return nil
}

// syncCheckpointDir best-effort fsyncs the directory so a rename survives a
// power loss, on the platforms that support it. It mirrors the store's own
// syncDir, which is unexported and serves a different package.
func syncCheckpointDir(dir string) {
	f, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = f.Sync()
	_ = f.Close()
}

// InstallCheckpoint writes cp to dir/checkpoint.json atomically. It is what
// `--checkpoint FILE` does before the chain is opened; StartValidator verifies
// the file FIRST, so a bad checkpoint never lands in a data directory.
func InstallCheckpoint(dir string, cp *Checkpoint) error {
	// The directory may not exist yet: a checkpoint import legitimately points
	// at a fresh path, and the store would create it a moment later. Creating it
	// here keeps the two in the same order.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return WriteCheckpointFile(filepath.Join(dir, CheckpointFileName), cp)
}

// CommitPendingCheckpoint renames a staged checkpoint over the live one. It is
// idempotent when there is nothing pending.
func CommitPendingCheckpoint(dir string) error {
	pending := filepath.Join(dir, pendingCheckpointName)
	if _, err := os.Stat(pending); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if err := os.Rename(pending, filepath.Join(dir, CheckpointFileName)); err != nil {
		return err
	}
	syncCheckpointDir(dir)
	return nil
}

// ResumeForDir returns the verified hand-off a data directory carries, or nil
// when it starts at genesis.
//
// It reads a checkpoint only when the directory can actually be resumed from
// one:
//
//   - base > 1 (a pruned directory): the candidate whose Height+1 equals base is
//     the one this directory's retained history builds on. The staged pending
//     file is tried FIRST because a crash between staging and renaming leaves
//     the NEWER horizon pending while the base marker already points at it;
//     a pending file that does not match the base is a prune that never started
//     and is ignored in favour of the committed one.
//   - base == 1 and no block records on disk: a fresh directory (a checkpoint
//     import, or the last step of an interrupted one). Any checkpoint present is
//     adopted - the chain records the base marker from it.
//   - base == 1 with blocks on disk: an ordinary chain, whose checkpoint (if any)
//     is not its starting point. Nothing is resumed, and a caller-supplied one is
//     refused by chain.OpenResume rather than silently ignored.
func ResumeForDir(g *genesis.Genesis, dir string) (*chain.ResumeState, error) {
	base, err := store.BaseOf(dir)
	if err != nil {
		return nil, err
	}
	if base == 1 {
		has, err := store.BlocksPresent(dir)
		if err != nil {
			return nil, err
		}
		if has {
			return nil, nil
		}
	}
	for _, name := range []string{pendingCheckpointName, CheckpointFileName} {
		path := filepath.Join(dir, name)
		cp, err := ReadCheckpointFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if base > 1 && cp.Height+1 != base {
			// A staged checkpoint that does not match the base is a prune that
			// never started (its marker was never written); leave it alone and
			// let the committed file answer for this directory.
			continue
		}
		resume, err := VerifyCheckpoint(g, cp)
		if err != nil {
			return nil, err
		}
		// The staged file is the one this start used, so promote it now. Doing
		// it HERE - rather than unconditionally after the open - is what keeps
		// a stale staged file from overwriting a good committed checkpoint: only
		// the file that matched the base and verified is renamed.
		if name == pendingCheckpointName {
			_ = CommitPendingCheckpoint(dir)
		}
		return resume, nil
	}
	return nil, nil
}
