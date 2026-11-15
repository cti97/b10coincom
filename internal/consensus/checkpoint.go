package consensus

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/state"
	"github.com/cti97/b10coincom/internal/store"
	"github.com/cti97/b10coincom/internal/types"
)

// Checkpoints: M7's answer to "a node that lost history must still be able to
// rejoin", extended by M8 to a committee that has rotated.
//
// WHAT A CHECKPOINT IS, AND WHY (M7 plan §4). A state root alone cannot resume a
// node: knowing that the state at height H hashes to R tells you nothing about
// the accounts, bonds and unbonding records you must build block H+1 on. So a
// checkpoint carries the STATE itself, and what makes it trustworthy is that
// the state HASHES to the root committed by a block whose quorum certificate
// this node can verify:
//
//	checkpoint = (height H, block H, state@H, the precommit votes for H, the
//	              committee that signed those votes)
//
// Verification on the DEFAULT path is M7's, unchanged: the votes must reach a
// quorum of the GENESIS committee. Genesis is the chain's trust anchor, the
// only committee a node with no history can authenticate, and a peer cannot
// forge those keys' signatures.
//
// THE ROTATION TRAP (M8 plan §2), stated because it is the whole milestone. A
// checkpoint that carries its own committee VERIFIES AGAINST ITSELF. The votes
// do form a quorum of CommitteeAt(H); the state does hash to the root the
// certified block commits. But an attacker who fabricates a state, a committee
// of their own keys and matching votes produces a file that passes trivially.
// SELF-CONSISTENCY IS NOT AUTHENTICITY. There is no local way to authenticate
// a rotated checkpoint without a light client, which this build does not have.
//
// So M8 ships the honest half of the choice:
//
//   - the default path stays genesis-anchored, and REFUSES a rotated committee
//     (VerifyCheckpoint). No flag, no new trust, M7 exactly;
//   - an explicit --checkpoint-trust opt-in (VerifyTrustedCheckpoint) admits a
//     rotated committee on internal consistency ALONE, together with a hard
//     maximum age. It is a trust downgrade for a file whose provenance the
//     operator authenticated out of band, and every surface says so: the
//     file's Note, an import-time warning, the flag help and the docs.
//
// WHICH COMMITTEE THE FILE CARRIES, corrected against the M8 plan. The plan
// says the committee "is already present" because CommitteeAt(H) derives it
// from StateHex. It does not: epoch e's committee is derived from the state at
// e*EpochBlocks-1 (chain.CommitteeAt), which is EARLIER than H for every e > 0,
// and the state carried at H derives the NEXT epoch's committee - which is
// exactly why the prune horizon sits at k*E-1. The committee that signed block
// H is therefore read from the chain's per-height source
// (Chain.CommitteeAt(H)) and asserted at export by re-tallying H's certificate
// under it. It is never read from the snapshot and never supplied by a caller.
//
// The state snapshot still keeps "the committee at the horizon": with the
// horizon one block BEFORE an epoch boundary, the snapshot is exactly the state
// that DERIVES the first retained epoch's committee, so a resumed node can
// judge the first retained block without any committee proof beyond its own
// state (chain.OpenResume).

// CheckpointVersion is the on-disk format version this build writes and reads.
// Version 2 (M8) adds CommitteeHex and IssuedAt. A checkpoint from another
// version is refused rather than guessed at, in BOTH directions: the file
// carries a state snapshot whose layout is versioned too, and a v1 file has no
// committee, so it cannot answer the question v2 verification asks.
const CheckpointVersion = 2

// DefaultCheckpointMaxAgeEpochs is the default bound a trusted import applies,
// in epochs. Four is the same floor the pruner uses (MinRetainEpochs): enough
// for an operator to move a checkpoint between machines around a restart, and
// small enough that a node cannot be pinned to a long-dead fork.
const DefaultCheckpointMaxAgeEpochs = 4

// maxCheckpointCommitteeSeats is the ceiling a checkpoint committee may name.
// It matches the genesis and committee-file ceilings (255), so a file cannot
// make a verifier allocate a committee no chain could seat.
const maxCheckpointCommitteeSeats = 255

// futureCheckpointSkewSeconds is how far ahead of the verifier's clock a
// checkpoint's IssuedAt may sit. A file dated in the future would defeat the
// age bound, so it is refused; a few minutes of clock skew between two machines
// is tolerated because that is ordinary.
const futureCheckpointSkewSeconds = 5 * 60

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
// root they hash to; CommitteeHex is authenticated only as the set those votes
// are tallied against.
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
	// CommitteeHex is the committee that SIGNED block H: the epoch committee
	// of height H, encoded canonically. It is written by the exporter from the
	// chain's per-height committee source, never from the caller, and it is
	// what the trusted import tallies the votes against. A default
	// (genesis-anchored) import requires it to equal the genesis committee.
	CommitteeHex string `json:"committee_hex"`
	// IssuedAt is the exporter's wall-clock time, in Unix seconds. It exists
	// because this chain's block timestamps are LOGICAL (parent+1, audit S-8),
	// not wall-clock, so a height cannot be dated; the trusted import refuses a
	// file older than --checkpoint-max-age using this stamp. It is
	// unauthenticated: a malicious source can lie about it, which is one more
	// reason a trusted checkpoint is not evidence about the real chain.
	IssuedAt int64 `json:"issued_at"`
	// Note records, in the file itself, what this checkpoint does and does not
	// prove - the assumption is too important to live only in a source file.
	Note string `json:"note"`
}

const checkpointNote = "M8 checkpoint: verified against the GENESIS committee, this chain's trust anchor - the votes must form a quorum of the genesis keys. The file also carries the committee that signed this height (committee_hex, derived at export) and its issue time (issued_at). A checkpoint whose committee has rotated is REFUSED on this path; --checkpoint-trust is the only way to accept one, and it checks internal consistency only. Retained history starts at height+1."

const trustedCheckpointNote = "M8 rotation-aware checkpoint, written with `checkpoint export --trust`: verified against ITSELF only. The votes form a quorum of the committee in committee_hex, and the state hashes to the root that the certified block commits - nothing more. Anyone can fabricate all of those consistently with their own keys, so this file is an ANCHOR YOU CHOSE, not evidence about the real chain. A node accepts it only with an explicit --checkpoint-trust, and only until --checkpoint-max-age says it is too old. Full verification of a rotated checkpoint by a node with no history is a light client; this is not one."

// ExportCheckpoint builds the DEFAULT checkpoint for height at: the file is
// verified against the genesis committee, so it refuses - with reasons - when
// the committee at the horizon is not the genesis committee (M7's refusal,
// unchanged) and in the cases where the artefact it would write could not be
// verified by an importer.
func ExportCheckpoint(c *chain.Chain, at uint64) (*Checkpoint, error) {
	cp, _, err := exportCheckpointAt(c, at, false)
	return cp, err
}

// ExportTrustedCheckpoint builds the ROTATION-AWARE checkpoint for height at:
// it carries the committee that signed H, and an importer can only accept it
// with --checkpoint-trust. This is the explicit opt-in on the writing side; the
// file's Note states, in the file, that it is trusted rather than authenticated.
func ExportTrustedCheckpoint(c *chain.Chain, at uint64) (*Checkpoint, error) {
	cp, _, err := exportCheckpointAt(c, at, true)
	return cp, err
}

func exportCheckpointAt(c *chain.Chain, at uint64, trust bool) (*Checkpoint, *state.State, error) {
	if at == 0 {
		return nil, nil, fmt.Errorf("%w: height 0 is the genesis block, which every node synthesises and no certificate covers", ErrBadCheckpoint)
	}
	g := c.Genesis()
	if head := c.Height(); at > head {
		return nil, nil, fmt.Errorf("%w: height %d is above the head %d", ErrBadCheckpoint, at, head)
	}
	// WHICH COMMITTEE SIGNED BLOCK H, read from the chain rather than guessed
	// from the snapshot. See this file's header: the carried state at H decides
	// the NEXT epoch, not H's own. The lookup is a diagnostic on the default
	// path (M7 tolerated a pruned node's horizon being underivable) and is
	// REQUIRED on the trusted path, because the file must name the signer.
	vals, committeeErr := c.CommitteeAt(at)
	if committeeErr == nil && !trust {
		if diff := committeeDiff(g.Validators, vals); diff != "" {
			return nil, nil, fmt.Errorf("%w: the committee at height %d is not the genesis committee (%s). A default checkpoint is verified against the GENESIS committee, and these votes were not signed by it. `b10coin checkpoint export --trust` writes the rotation-aware form, which carries the committee that signed the height and is accepted ONLY by a node started with --checkpoint-trust - it proves that the file agrees with itself, not that it is the real chain", ErrBadCheckpoint, at, diff)
		}
	}
	if trust && committeeErr != nil {
		return nil, nil, fmt.Errorf("%w: the committee at height %d cannot be derived from this node's retained history (%v), so a rotation-aware checkpoint cannot assert which committee signed it. Export from a node that still holds the epoch's deciding block, or write the default checkpoint", ErrBadCheckpoint, at, committeeErr)
	}
	payload, ok := c.CertAt(at)
	if !ok {
		return nil, nil, fmt.Errorf("%w: no quorum certificate is recorded for height %d, so nothing proves a committee committed it. A checkpoint without a certificate is a state snapshot with no authority; this node cannot produce one until it has adopted that height's certificate", ErrBadCheckpoint, at)
	}
	round, encoded, err := DecodeCertificate(payload)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: the stored certificate for height %d does not decode: %v", ErrBadCheckpoint, at, err)
	}
	// The horizon's own block is not in the store once the prune has run, but
	// the chain is running on top of it: BaseSnapshot hands it back so a
	// checkpoint can be re-exported from a pruned directory (the seat-move
	// procedure in scripts/deploy/README.md).
	var blk *types.Block
	var st *state.State
	if hb, hs, ok := c.BaseSnapshot(); ok && at == c.Base() {
		blk, st = hb, hs
	} else {
		blk, err = c.BlockAt(at)
		if err != nil {
			return nil, nil, err
		}
	}
	// Verify what we are about to write: an exporter that emits a checkpoint
	// its own verifier rejects is writing a file that fails on the next machine.
	// The default path tallies under genesis (M7). The trusted path tallies
	// under the signer committee - so the committee it writes is ASSERTED to be
	// the one whose keys signed, not merely copied into a JSON field.
	committee := g.Validators
	if trust {
		committee = vals
	}
	if err := VerifyCommitCertificate(committee, blk, round, encoded); err != nil {
		if trust {
			return nil, nil, fmt.Errorf("the stored certificate for height %d does not verify under the committee this export would carry: %w", at, err)
		}
		return nil, nil, fmt.Errorf("the stored certificate for height %d does not verify against the genesis committee: %w", at, err)
	}
	if st == nil {
		st, err = c.StateAt(at)
		if err != nil {
			return nil, nil, err
		}
	}
	if root := st.Root(); root != blk.Header.StateRoot {
		return nil, nil, fmt.Errorf("%w: the state at height %d hashes to %x, but that block commits %x", ErrBadCheckpoint, at, root[:8], blk.Header.StateRoot[:8])
	}
	note := checkpointNote
	if trust {
		note = trustedCheckpointNote
	}
	cp := &Checkpoint{
		Version:      CheckpointVersion,
		ChainID:      g.ChainID,
		GenesisHash:  hex.EncodeToString(hashSlice(g.Hash())),
		Height:       at,
		Round:        round,
		BlockHex:     hex.EncodeToString(blk.Encode()),
		StateHex:     hex.EncodeToString(st.Encode()),
		VotesHex:     make([]string, 0, len(encoded)),
		CommitteeHex: encodeCommittee(committee),
		IssuedAt:     time.Now().Unix(),
		Note:         note,
	}
	for _, raw := range encoded {
		cp.VotesHex = append(cp.VotesHex, hex.EncodeToString(raw))
	}
	return cp, st, nil
}

// TrustPolicy bounds a trusted import. It has no zero-value that silently
// weakens anything: MaxAgeEpochs must be positive, because an unbounded trusted
// checkpoint is a permanent fork-pin (M8 plan §7) and this milestone forbids
// adding the bound later.
type TrustPolicy struct {
	// MaxAgeEpochs is the maximum age, in EPOCHS, of a trusted checkpoint. The
	// chain's nominal epoch duration (EpochBlocks x BlockTimeMS) converts it to
	// a wall-clock bound. Zero is refused.
	MaxAgeEpochs uint64
	// Now is the verifier's clock. The zero value means time.Now().
	Now time.Time
}

// VerifyCheckpoint authenticates a checkpoint against the genesis committee and
// returns the hand-off chain.OpenResume needs. It is M7's verifier: the votes
// must be a genesis quorum, and a rotated committee is refused with an error
// that names the trade a trusted import would make.
func VerifyCheckpoint(g *genesis.Genesis, cp *Checkpoint) (*chain.ResumeState, error) {
	return verifyCheckpoint(g, cp, checkpointAnchored, TrustPolicy{})
}

// VerifyTrustedCheckpoint admits a ROTATED checkpoint on internal consistency
// alone, and refuses it once it is older than policy.MaxAgeEpochs. This is the
// trust downgrade: it proves the file agrees with itself, never that it is the
// real chain. Only reachable from an explicit --checkpoint-trust.
func VerifyTrustedCheckpoint(g *genesis.Genesis, cp *Checkpoint, policy TrustPolicy) (*chain.ResumeState, error) {
	return verifyCheckpoint(g, cp, checkpointTrusted, policy)
}

// VerifyAdoptedCheckpoint verifies a checkpoint a data directory ALREADY
// adopted: genesis-anchored when it carries the genesis committee, and on
// internal consistency alone when it carries a rotated one. It exists for
// ResumeForDir on a pruned directory, whose anchor was trusted when it was
// imported; it must NOT be used for a file an operator just supplied, because
// then the trust decision would be silent. It applies no age bound: the bound
// belongs to the acquisition, not to every restart of the same directory.
func VerifyAdoptedCheckpoint(g *genesis.Genesis, cp *Checkpoint) (*chain.ResumeState, error) {
	return verifyCheckpoint(g, cp, checkpointAdopted, TrustPolicy{})
}

type checkpointMode int

const (
	// checkpointAnchored is M7: genesis only, rotation refused.
	checkpointAnchored checkpointMode = iota
	// checkpointTrusted is the explicit --checkpoint-trust import.
	checkpointTrusted
	// checkpointAdopted is a directory's own already-adopted anchor.
	checkpointAdopted
)

func verifyCheckpoint(g *genesis.Genesis, cp *Checkpoint, mode checkpointMode, policy TrustPolicy) (*chain.ResumeState, error) {
	if cp == nil {
		return nil, fmt.Errorf("%w: no checkpoint", ErrBadCheckpoint)
	}
	if cp.Version != CheckpointVersion {
		return nil, fmt.Errorf("%w: checkpoint format version %d, want %d. This build writes and reads the committee-carrying format only: an older file has no committee to verify against and is refused rather than guessed at", ErrBadCheckpoint, cp.Version, CheckpointVersion)
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
	vals, err := decodeCommittee(cp.CommitteeHex)
	if err != nil {
		return nil, fmt.Errorf("%w: the checkpoint's committee is unusable: %v", ErrBadCheckpoint, err)
	}
	switch mode {
	case checkpointAnchored:
		// THE TRUST ANCHOR. The votes are re-tallied under genesis, and a file
		// that carries any other committee is refused here rather than tallied
		// against itself.
		if diff := committeeDiff(g.Validators, vals); diff != "" {
			return nil, rotatedRefusal(cp, diff)
		}
	case checkpointTrusted:
		if err := checkCheckpointAge(g, cp, policy); err != nil {
			return nil, err
		}
	case checkpointAdopted:
		// Genesis when the file carries it (the strongest answer this node can
		// give), internal consistency otherwise: the trust decision was made
		// when the directory adopted the file.
	}
	if err := VerifyCommitCertificate(vals, blk, cp.Round, encoded); err != nil {
		return nil, err
	}
	return &chain.ResumeState{Height: cp.Height, Head: blk, State: st}, nil
}

// rotatedRefusal is the error an un-flagged import of a rotated checkpoint
// gets. It must say WHY the refusal exists and WHAT the flag would cost - not
// merely that a flag exists - because the flag is a trust downgrade.
func rotatedRefusal(cp *Checkpoint, diff string) error {
	return fmt.Errorf("%w: the checkpoint at height %d carries a committee that is not this chain's genesis (%s), and a default import is verified against the genesis committee - the only anchor a node with no history can authenticate. These votes are not that committee's. `--checkpoint-trust` would accept the file by checking only that IT AGREES WITH ITSELF: a quorum of the committee it carries signed the block it carries, whose header commits the state it carries. That proves internal consistency, NOT that this is the real chain - anyone can fabricate such a file with their own keys - and it is bounded only by --checkpoint-max-age. Do not pass that flag for a checkpoint whose provenance you have not authenticated out of band; a node that still has its history can simply replay", ErrBadCheckpoint, cp.Height, diff)
}

// checkCheckpointAge is the HARD bound on a trusted import. It refuses an
// unbounded policy, a file with no issue time, a file dated in the future, and
// a file older than the policy allows.
func checkCheckpointAge(g *genesis.Genesis, cp *Checkpoint, policy TrustPolicy) error {
	if policy.MaxAgeEpochs == 0 {
		return fmt.Errorf("%w: a trusted checkpoint needs a maximum age (--checkpoint-max-age); an unbounded one pins this node to an arbitrary past fork forever", ErrBadCheckpoint)
	}
	if cp.IssuedAt <= 0 {
		return fmt.Errorf("%w: the checkpoint carries no issue time, so its age cannot be bounded; a trusted checkpoint without one is a permanent fork-pin", ErrBadCheckpoint)
	}
	maxAge, err := checkpointMaxAge(g, policy.MaxAgeEpochs)
	if err != nil {
		return err
	}
	now := policy.Now
	if now.IsZero() {
		now = time.Now()
	}
	if ahead := cp.IssuedAt - now.Unix(); ahead > futureCheckpointSkewSeconds {
		return fmt.Errorf("%w: the checkpoint is dated %d seconds in the future, beyond the %d-second clock skew this verifier tolerates; a forward-dated file would defeat --checkpoint-max-age", ErrBadCheckpoint, ahead, futureCheckpointSkewSeconds)
	}
	if age := now.Unix() - cp.IssuedAt; age > int64(maxAge/time.Second) {
		return fmt.Errorf("%w: the trusted checkpoint at height %d was issued %s ago, older than the %d-epoch bound (%s). A trusted checkpoint cannot be authenticated against the real chain, so age is the only thing that stops it pinning this node to a long-dead fork; re-export it from a node you trust, or raise --checkpoint-max-age deliberately", ErrBadCheckpoint, cp.Height, time.Duration(age)*time.Second, policy.MaxAgeEpochs, maxAge)
	}
	return nil
}

// checkpointMaxAge converts an epoch bound into a wall-clock bound using the
// chain's nominal epoch duration. It refuses zero parameters (the conversion
// would be a division the chain never meant) and refuses an overflow rather
// than wrapping into a bound of a few seconds.
func checkpointMaxAge(g *genesis.Genesis, epochs uint64) (time.Duration, error) {
	blocks, blockMS := g.Params.EpochBlocks, g.Params.BlockTimeMS
	if blocks == 0 || blockMS == 0 {
		return 0, fmt.Errorf("%w: this chain's EpochBlocks (%d) or BlockTimeMS (%d) is zero, so --checkpoint-max-age cannot be converted into a wall-clock bound", ErrBadCheckpoint, blocks, blockMS)
	}
	if epochs > math.MaxUint64/blocks {
		return 0, fmt.Errorf("%w: --checkpoint-max-age %d epochs overflows the chain's epoch length %d", ErrBadCheckpoint, epochs, blocks)
	}
	ms := epochs * blocks
	if ms > math.MaxUint64/blockMS {
		return 0, fmt.Errorf("%w: --checkpoint-max-age %d epochs overflows the chain's block time %d ms", ErrBadCheckpoint, epochs, blockMS)
	}
	ms *= blockMS
	// Cap at the largest representable time.Duration; anything above it is
	// effectively unbounded, which this verifier refuses.
	if ms > uint64(math.MaxInt64/int64(time.Millisecond)) {
		return 0, fmt.Errorf("%w: --checkpoint-max-age %d epochs is longer than a time.Duration can express; the bound would silently stop bounding anything", ErrBadCheckpoint, epochs)
	}
	return time.Duration(ms) * time.Millisecond, nil
}

// TrustStatement is the sentence printed at import when a checkpoint was
// accepted by --checkpoint-trust. It names the exact trade rather than
// congratulating the operator on a successful import.
func TrustStatement(cp *Checkpoint) string {
	height := uint64(0)
	if cp != nil {
		height = cp.Height
	}
	return fmt.Sprintf("WARNING: TRUSTED CHECKPOINT at height %d - this node did NOT verify it against the chain's genesis. It was accepted because --checkpoint-trust was given and the file agrees with itself: a quorum of the committee in committee_hex signed the block in block_hex, whose header commits the state in state_hex. Anyone can fabricate that consistently with their own keys, so this proves internal consistency, NOT that this is the real chain. Treat the file as an anchor you authenticated out of band; it expires after --checkpoint-max-age.", height)
}

// encodeCommittee renders a committee canonically: seat count, then each
// (public key, power). The genesis encoder is the same shape, so a reader can
// compare a checkpoint committee with a genesis document byte for byte.
func encodeCommittee(vals []genesis.Validator) string {
	e := types.NewEncoder()
	e.Len(len(vals))
	for _, v := range vals {
		e.VarBytes(v.PubKey)
		e.U64(v.Power)
	}
	return hex.EncodeToString(e.Bytes())
}

// decodeCommittee parses encodeCommittee's output strictly. A committee is
// untrusted input - it is about to become the set a checkpoint's votes are
// tallied against - so it is bounded (seat count, key width), every power must
// be positive, and a repeated key is refused (one key holds one seat; a
// duplicate would double its power in the quorum sum).
func decodeCommittee(s string) ([]genesis.Validator, error) {
	if s == "" {
		return nil, errors.New("the checkpoint carries no committee (an empty committee_hex)")
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("committee_hex is not hex: %v", err)
	}
	d := types.NewDecoder(raw)
	n, err := d.Len()
	if err != nil {
		return nil, fmt.Errorf("seat count: %v", err)
	}
	if n <= 0 {
		return nil, fmt.Errorf("holds %d seats; a checkpoint's committee must name at least one", n)
	}
	if n > maxCheckpointCommitteeSeats {
		return nil, fmt.Errorf("%d seats is above the ceiling of %d", n, maxCheckpointCommitteeSeats)
	}
	vals := make([]genesis.Validator, 0, n)
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		pub, err := d.VarBytesMax(ed25519.PublicKeySize)
		if err != nil {
			return nil, fmt.Errorf("seat %d public key: %v", i, err)
		}
		if len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("seat %d public key is %d bytes, want %d", i, len(pub), ed25519.PublicKeySize)
		}
		power, err := d.U64()
		if err != nil {
			return nil, fmt.Errorf("seat %d power: %v", i, err)
		}
		if power == 0 {
			return nil, fmt.Errorf("seat %d has zero voting power", i)
		}
		if _, dup := seen[string(pub)]; dup {
			return nil, fmt.Errorf("seat %d repeats key %s", i, shortKey(string(pub)))
		}
		seen[string(pub)] = struct{}{}
		vals = append(vals, genesis.Validator{PubKey: pub, Power: power})
	}
	if err := d.Done(); err != nil {
		return nil, err
	}
	return vals, nil
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
		return fmt.Sprintf("genesis has %d seats, the checkpoint's committee has %d", len(w), len(g))
	}
	var problems []string
	for k, pw := range w {
		gpw, ok := g[k]
		switch {
		case !ok:
			problems = append(problems, fmt.Sprintf("genesis key %s is not in the checkpoint's committee", shortKey(k)))
		case gpw != pw:
			problems = append(problems, fmt.Sprintf("genesis key %s has power %d, the checkpoint's committee gives it %d", shortKey(k), pw, gpw))
		}
	}
	for k := range g {
		if _, ok := w[k]; !ok {
			problems = append(problems, fmt.Sprintf("checkpoint key %s is not a genesis seat", shortKey(k)))
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
//
// It refuses to overwrite a PRUNED directory's checkpoint with one that does
// not sit on that directory's base: the file is the only thing that makes the
// retained history resumable, and a mismatch used to be discovered after the
// good file had already been replaced.
func InstallCheckpoint(dir string, cp *Checkpoint) error {
	if cp != nil {
		base, err := store.BaseOf(dir)
		if err != nil {
			return err
		}
		if base > 1 && cp.Height+1 != base {
			return fmt.Errorf("%w: this directory's retained history starts at height %d, but the checkpoint is at height %d; installing it would overwrite the checkpoint this directory resumes from. Import a checkpoint only into an empty --dir", chain.ErrCheckpointMismatch, base, cp.Height)
		}
	}
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
//     and is ignored in favour of the committed one. This is the node's OWN
//     anchor, so a rotated committee is verified on internal consistency
//     (VerifyAdoptedCheckpoint): the trust decision was made when the directory
//     adopted the file, and re-applying an age bound would make a working node
//     unable to restart.
//   - base == 1 and no block records on disk: a fresh directory (a checkpoint
//     import, or the last step of an interrupted one). Any checkpoint present is
//     adopted ONLY if it verifies against genesis; a rotated one here means
//     nobody made an explicit trust decision, so it is refused (the
//     --checkpoint-trust path verifies and installs the file itself).
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
		var resume *chain.ResumeState
		if base > 1 {
			resume, err = VerifyAdoptedCheckpoint(g, cp)
		} else {
			resume, err = VerifyCheckpoint(g, cp)
		}
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
