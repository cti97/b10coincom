package consensus

import "fmt"

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
func (vs *VoteSet) Add(v *Vote) (bool, error) {
	if v.Type != vs.typ {
		return false, fmt.Errorf("consensus: vote type %d in a set for %d", v.Type, vs.typ)
	}
	if err := v.Verify(); err != nil {
		return false, err
	}
	if v.Height != vs.height || v.Round != vs.round {
		return false, fmt.Errorf("consensus: vote for (%d,%d) in a set for (%d,%d)",
			v.Height, v.Round, vs.height, vs.round)
	}
	idx := vs.cfg.IndexOf(v.Validator)
	if idx < 0 {
		return false, ErrNotValidator
	}
	if _, dup := vs.seen[string(v.Validator)]; dup {
		return false, nil
	}
	vs.seen[string(v.Validator)] = idx

	if _, known := vs.power[v.BlockID]; !known {
		vs.order = append(vs.order, v.BlockID)
	}
	vs.power[v.BlockID] += vs.cfg.Committee[idx].Power
	return true, nil
}

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
