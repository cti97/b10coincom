package consensus

import (
	"errors"
	"fmt"
)

// Add's sentinels. ErrWrongHeightRound lives here, not in message.go: the
// height/round a vote belongs to is a property of the VoteSet it was offered
// to, which a standalone Vote knows nothing about.
var (
	// ErrWrongHeightRound reports a correctly signed vote for a different
	// (height, round) than this set. It is distinct from ErrBadVoteSignature so
	// callers can tell a routing mistake from a corrupted or forged vote.
	ErrWrongHeightRound = errors.New("consensus: vote is for another height or round")
	// ErrNilVote reports Add(nil). Add becomes a network-facing entry point in
	// M4, where malformed input must error, not panic.
	ErrNilVote = errors.New("consensus: vote must not be nil")
	// ErrMissingValidatorKey reports a vote with an empty validator key. There
	// is no key against which any signature could verify, so this is malformed
	// input, not a failed verification; it gets its own sentinel rather than
	// collapsing into ErrBadVoteSignature. message.go is untouched: the tally
	// guards the empty key itself so its callers can tell the two apart.
	ErrMissingValidatorKey = errors.New("consensus: vote carries no validator key")
)

// VoteSet accumulates one kind of vote for one (height, round).
//
// Weight is counted at most once per validator: a validator that votes twice is
// IGNORED rather than rejected, because a duplicate arriving over a lossy
// reordering network is ordinary, not an error. Counting it twice would let two
// colluding validators manufacture a quorum that the rest of the committee never
// gave.
type VoteSet struct {
	cfg    Config
	height uint64
	round  uint32
	typ    MsgType

	seen  map[string]int // validator key -> committee index, for one-vote-per-validator
	power map[[32]byte]uint64
	order [][32]byte // block IDs in first-seen order, so AnyQuorum is deterministic
	// votes retains the added votes themselves. The tallies above are enough
	// for the engine's decisions, but a commit certificate is made of the
	// VOTES - the driver hands them, at commit time, to whoever archives
	// certificates (the syncer serves them to catching-up peers). Retention
	// is purely observational: no decision here reads it.
	votes []*Vote
}

func NewVoteSet(cfg Config, height uint64, round uint32, typ MsgType) *VoteSet {
	return &VoteSet{
		cfg: cfg, height: height, round: round, typ: typ,
		seen:  make(map[string]int),
		power: make(map[[32]byte]uint64),
	}
}

// Add records a vote. It returns added=false with a nil error for a duplicate,
// and an error for a vote that is malformed, for the wrong place, badly signed, or
// from a non-member.
//
// The signature is checked BEFORE the height/round guard: SigningHash covers
// type, height, round, block ID and validator key, so a vote whose envelope was
// corrupted in transit fails Verify() no matter where it claims to be for. With
// the height/round check first, such a corrupted vote is misreported as a
// placement error and a test asserting ErrBadVoteSignature can never name it.
// A nil vote and a vote with no validator key are refused before Verify(), since
// neither can carry a meaningful signature (and a nil one cannot be read).
//
// MEMBERSHIP, however, is checked BEFORE Verify() (audit C-8's discipline on
// the tally path): IndexOf is a linear scan of the committee and an Ed25519
// verification is not, so a non-member must not be able to force the expensive
// check with a self-signed frame. The order is otherwise unchanged - a member's
// vote still fails Verify() before it can be misreported as a placement error,
// and the height/round guard still runs after the signature. A non-member with
// a corrupted signature now reports ErrNotValidator rather than
// ErrBadVoteSignature; the vote is refused either way, and no caller's
// behaviour depends on which of two true reasons is named.
func (vs *VoteSet) Add(v *Vote) (bool, error) {
	if v == nil {
		return false, ErrNilVote
	}
	if v.Type != vs.typ {
		return false, fmt.Errorf("consensus: vote type %d in a set for %d", v.Type, vs.typ)
	}
	if len(v.Validator) == 0 {
		return false, ErrMissingValidatorKey
	}
	idx := vs.cfg.IndexOf(v.Validator)
	if idx < 0 {
		return false, ErrNotValidator
	}
	if err := v.Verify(); err != nil {
		return false, err
	}
	if v.Height != vs.height || v.Round != vs.round {
		return false, fmt.Errorf("%w: vote for (%d,%d) in a set for (%d,%d)",
			ErrWrongHeightRound, v.Height, v.Round, vs.height, vs.round)
	}
	if _, dup := vs.seen[string(v.Validator)]; dup {
		return false, nil
	}
	vs.seen[string(v.Validator)] = idx
	vs.votes = append(vs.votes, v)

	if _, known := vs.power[v.BlockID]; !known {
		vs.order = append(vs.order, v.BlockID)
	}
	vs.power[v.BlockID] += vs.cfg.Committee[idx].Power
	return true, nil
}

// Votes returns the votes this set ADDED (added=true), in add order - one per
// validator, duplicates collapsed. It is what a commit certificate is built
// from; a set never added to holds none. The returned slice is internal
// storage: read, never write.
func (vs *VoteSet) Votes() []*Vote { return vs.votes }

// PowerFor is the weight accumulated behind a block ID. A nil ID tallies nil votes.
func (vs *VoteSet) PowerFor(blockID [32]byte) uint64 { return vs.power[blockID] }

// NilPower is the weight behind nil votes for this round.
func (vs *VoteSet) NilPower() uint64 { return vs.power[[32]byte{}] }

// HasQuorum reports whether a block has reached the two-thirds threshold.
func (vs *VoteSet) HasQuorum(blockID [32]byte) bool {
	return vs.power[blockID] >= vs.cfg.Quorum()
}

// AnyQuorum returns the first non-nil block to reach quorum, in first-seen order.
// Order is fixed rather than map-derived, so two runs agree on which block a
// validator commits to when - impossibly for an honest committee - two had quorum.
func (vs *VoteSet) AnyQuorum() ([32]byte, bool) {
	for _, id := range vs.order {
		if id == ([32]byte{}) {
			continue
		}
		if vs.HasQuorum(id) {
			return id, true
		}
	}
	return [32]byte{}, false
}
