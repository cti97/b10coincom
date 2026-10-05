package genesis

// committee_file.go loads the operator's committee file: the JSON document a
// deployment shares so every validator derives the SAME committee from a
// LIST OF PUBLIC KEYS rather than from a committee-size number.
//
// Why this file exists (audit A-1): before it, the networked node derived the
// whole committee from `--validators N` — `simnet.Committee(N)` — which both
// published the committee size in the chain ID (`b10coin-simnet-N`, echoed by
// /status) and signed every seat with a key anyone could derive from the seed
// "b10coin-simnet-validator" plus the seat number. A committee file replaces
// both: the operators generate real keys (`b10coin keygen`), publish only the
// public keys into this document, share one copy with every member, and the
// chain identity (ChainID) is whatever the operators chose — no size, no
// seed schedule.
//
// Deliberate limits, stated where the operator reads them:
//   - The file is the COMMITTEE section of the chain's genesis. Monetary and
//     protocol parameters stay the compiled-in devnet fixture values (trivial
//     puzzle, 1 b10 claims, 2 s block time) — a committee file cannot mint a
//     richer economy, and coins on any such chain remain valueless test
//     currency. Everything else the file leaves out is therefore unforgeable
//     by a rogue operator.
//   - The schema carries NO dev accounts: a premine is the devnet fixture's
//     transfer-testing device only, and a shared chain has no premine, ever.
//   - The optional "note" field is for humans; it never enters the encoded
//     genesis, so it never enters the genesis hash either.
//   - The file lists PUBLIC keys only. Private keys never appear here and
//     must be generated per machine (keygen) and never leave theirs.

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/cti97/b10coincom/internal/crypto"
)

// ErrBadCommitteeFile reports an invalid operator committee file. Parse errors
// (undecodable JSON, bad hex, short keys) and policy violations (empty chain
// ID, duplicate keys, zero power) all carry this sentinel so a caller can
// classify the failure without parsing messages.
var ErrBadCommitteeFile = errors.New("genesis: invalid committee file")

// CommitteeEntry is ONE entry in the shared committee file. Name is optional
// and purely documentary (e.g. "pi-0"); PubKey is the validator's 32-byte
// Ed25519 public key as hex; Power is that validator's voting power (>= 1).
type CommitteeEntry struct {
	Name   string `json:"name,omitempty"`
	PubKey string `json:"pubkey"`
	Power  uint64 `json:"power"`
}

// CommitteeFile is the shared JSON document from which every networked node
// derives its committee. See this file's package-level comment for what the
// file deliberately does NOT carry (parameters, premine, private keys).
type CommitteeFile struct {
	// ChainID is the chain identifier every validator will report. It is
	// chosen by the operators (any non-empty string) — unlike the fixture
	// committee, it does not encode and must not be made to reveal the
	// committee size.
	ChainID string `json:"chain_id"`
	// Note is an optional human annotation. It is deliberately NOT encoded
	// into the genesis, so it cannot affect the genesis hash: an annotation
	// that changed the chain's identity would be a consensus bug, not a note.
	Note string `json:"note,omitempty"`
	// Validators lists every seat's public key and power. ORDER MATTERS: the
	// seat's committee index is the entry's position, which pins proposer
	// draws the same way the fixture committee's index order does.
	Validators []CommitteeEntry `json:"validators"`
}

// ParseCommitteeJSON parses and validates a committee file's bytes, returning
// the Genesis every validator in that committee must open its chain with.
//
// The returned genesis carries the compiled-in devnet FIXTURE parameters (see
// the type comment), no dev accounts (no premine), and the file's chain ID and
// validator set. Its hash — and with it the protocol-owned faucet address —
// is a function of exactly those, so every member holding the same file
// opens the same chain, and nobody outside a key-holding member can sign.
func ParseCommitteeJSON(b []byte) (*Genesis, error) {
	var f CommitteeFile
	dec := json.NewDecoder(strings.NewReader(string(b)))
	// Reject anything after the top-level object: a trailing blob is either a
	// clobbered file or a hand-edit gone wrong, and silently taking the first
	// object would hide that.
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("%w: not readable JSON: %v", ErrBadCommitteeFile, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: trailing bytes after the JSON object", ErrBadCommitteeFile)
	}

	if strings.TrimSpace(f.ChainID) == "" {
		return nil, fmt.Errorf("%w: chain_id must not be empty", ErrBadCommitteeFile)
	}
	if len(f.Validators) == 0 {
		return nil, fmt.Errorf("%w: the file lists no validators (a committee of zero cannot advance)", ErrBadCommitteeFile)
	}
	if len(f.Validators) > 255 {
		// The same cap the fixture committee enforces (committee indices were
		// one byte in the fixture seed schedule); consensus itself needs no
		// byte cap, but keeping the documented committee ceiling identical
		// across both paths avoids a second, silently different limit.
		return nil, fmt.Errorf("%w: %d validators exceeds the 255-seat committee ceiling", ErrBadCommitteeFile, len(f.Validators))
	}

	vals := make([]Validator, len(f.Validators))
	seen := make(map[string]int, len(f.Validators))
	for i, e := range f.Validators {
		pub, err := hex.DecodeString(strings.TrimSpace(e.PubKey))
		if err != nil {
			return nil, fmt.Errorf("%w: validator %d (%q): pubkey is not hex: %v", ErrBadCommitteeFile, i, e.Name, err)
		}
		if len(pub) != 32 {
			return nil, fmt.Errorf("%w: validator %d (%q): pubkey is %d bytes, want 32 (an Ed25519 public key as 64 hex chars)", ErrBadCommitteeFile, i, e.Name, len(pub))
		}
		if e.Power == 0 {
			return nil, fmt.Errorf("%w: validator %d (%q): power must be at least 1", ErrBadCommitteeFile, i, e.Name)
		}
		// A duplicate public key would give one key two seats: its power sum
		// would count twice and the proposer draw would draw it twice — the
		// exact unchecked-input bug the audit's S-5 names for genesis in
		// general, refused here at the only place operators write by hand.
		if first, dup := seen[string(pub)]; dup {
			return nil, fmt.Errorf("%w: validator %d (%q) repeats the public key already listed at index %d (%q): one key holds one seat",
				ErrBadCommitteeFile, i, e.Name, first, f.Validators[first].Name)
		}
		seen[string(pub)] = i
		vals[i] = Validator{PubKey: pub, Power: e.Power}
	}

	// Fixture parameters with the file's identity: the committee section is
	// operator-provided, the rest stays the shipped fixture (see the type
	// comment), so the file cannot quietly change monetary or consensus
	// parameters. DevAccounts is nil — no premine on a shared chain.
	base := Devnet()
	g := base
	g.ChainID = f.ChainID
	g.Params.ChainID = f.ChainID
	g.Validators = vals
	g.DevAccounts = nil
	g.Params.CommitteeSize = len(vals)
	if err := g.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadCommitteeFile, err)
	}
	return g, nil
}

// LoadCommitteeJSON parses the committee file at path.
func LoadCommitteeJSON(path string) (*Genesis, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot read %s: %v", ErrBadCommitteeFile, path, err)
	}
	g, err := ParseCommitteeJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return g, nil
}

// SeatOfPubKey returns the committee index whose entry holds pub, or -1 when
// the key is not a member. The position pins the seat: the node refuses to
// start when its own key is not listed, rather than silently signing as a
// seat it does not hold (audit A-1).
func SeatOfPubKey(vals []Validator, pub []byte) int {
	for i := range vals {
		if string(vals[i].PubKey) == string(pub) {
			return i
		}
	}
	return -1
}

// committeeFileExample renders the JSON shape for documentation surfaces
// (README, deploy recipe) so the schema is written once, in code, and the
// prose samples can never drift from what the loader accepts.
func CommitteeFileExample(pubHelves ...string) string {
	entries := make([]CommitteeEntry, 0, len(pubHelves))
	for i, k := range pubHelves {
		entries = append(entries, CommitteeEntry{Name: fmt.Sprintf("pi-%d", i), PubKey: k, Power: 1})
	}
	f := CommitteeFile{ChainID: "example-committee-1", Validators: entries}
	out, _ := json.MarshalIndent(f, "", "  ")
	return string(out)
}

// guard: crypto is imported for the genesis package's other files; keep the
// explicit dependency so removing Hash support here fails visibly.
var _ = crypto.GenerateKey
