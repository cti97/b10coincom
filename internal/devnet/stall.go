package devnet

// A node that has stopped committing says so, once.
//
// THE GAP THIS CLOSES (M5 Docker re-run, 2026-10-30: "a rolling restart stalls
// the chain for minutes, silently"). Restarting three seated validators one at
// a time left a four-seat chain at one head for 4 to 6.5 minutes and it only
// recovered when all nodes were restarted together; the same mechanism was
// reproduced without staking (32 to 48 s on four seats with one nodeless, 17 to
// 63 s on three of three). Every observable the harness had before this file
// looked the same as a merely slow run: the committed height sat still, the
// round kept climbing, nothing was parked, sync dropped nothing and the peers
// were connected. The `heights [0 0 0]` CI failure that two earlier rounds
// could not diagnose is that exact shape (see diag.go's header).
//
// WHAT IS REPORTED. A validator that has spent stallReportRounds rounds at one
// height, every one of them while the voting power it can actually SEE (its
// own seat plus the seats whose signed HELLOs it has heard within the wave
// TTL) is at least the quorum, logs one line (rounds climbed with the quorum
// out of reach do not count; see stallWatch): the round and step it is in, the prevote/precommit
// tallies with the quorum they are short of, and the peers it sees. "Sees
// quorum" is the test for "a quorum should exist": a lone survivor of a
// partitioned committee, or two live seats of three, cannot decide by
// arithmetic and a stall there is expected - the warning is for the case where
// the committee it can reach COULD commit and is not. Peers are counted by
// their SIGNED member identity, the same identity the catch-up table is keyed
// on, so the count survives a relay (through which every member shares one
// transport name) and cannot be inflated by a stranger: only a member's
// verified HELLO reaches the table.
//
// The tallies are the newest retained round that holds a VOTE, not necessarily
// the current one (see stallLine): a stalled engine sits at StepPropose in a
// round nobody else is in, and that round's empty tallies would be a constant
// that says nothing. The voted round is what separates "frames arrived, the
// committee agrees on nil and is merely out of step" from "frames are not
// arriving at all" - the distinction the CI `heights [0 0 0]` report could not
// make.
//
// ONCE. The line is emitted once per height: the watcher re-arms when the
// committed height advances. A long stall therefore costs one line, not one per
// round, and a chain that is merely slow (a round or two at a height) says
// nothing. stallReportRounds is 8 because the shipped ladder (200 ms base +
// 100 ms step) puts round 8 about 4.4 s into an undecided height - well past
// any healthy commit and well before a stall becomes "minutes".
//
// WHY THIS CANNOT CHANGE A DECISION. Everything here is a READ: the driver's
// own round and committed height, the per-round snapshot Driver.Observe already
// keeps (diag.go), and the catch-up table the wave loop already maintains. No
// consensus path calls it, no branch is added to the engine, and the report
// reads no clock of its own. It runs on the tick goroutine after the tick's
// driver work, takes the same mutex (so it can never read a half-driven
// engine), and formats under that mutex so a blocked stderr cannot hold up
// consensus.

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cti97/b10coincom/internal/consensus"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/transport"
)

// stallReportRounds is how many rounds at one height count as a stall. See the
// file comment for the arithmetic of the choice.
const stallReportRounds = 8

// stallPeer is one committee member this node can currently hear from: the seat
// it holds, the transport name its latest HELLO arrived on, and the height it
// announced there.
type stallPeer struct {
	Seat   int
	Via    transport.PeerID
	Height uint64
}

// stallWatch is the reporter's once-per-height state. It is guarded by the
// validator mutex, like every other read of the driver.
//
// The rounds counted are rounds WITH a reachable quorum, not the round number.
// A node that climbed rounds while it could not reach a quorum - its peers
// down for a restart - is in an expected stall, and the moment the quorum
// comes back it is merely about to resync; counting from round 0 made it cry
// stall at that instant (M5 network re-run, 2026-10-30: the line fired within
// a second of every restart in a one-at-a-time sequence that then recovered in
// seconds, its peers= still listing the node that had just been stopped).
// reachFrom is the round from which the quorum has been reachable at every
// observation; a fresh height starts counted from round 0, and any observation
// without a reachable quorum disarms the count until one comes back.
type stallWatch struct {
	height    uint64
	fired     bool
	observed  bool   // a round of this height has been observed
	round     uint32 // the round last observed
	reachable bool   // the quorum was reachable at every observation since reachFrom
	reachFrom uint32
}

// stallTally renders one round's tally: how many validators the engine counted,
// the power they carry against the quorum, the nil weight, and the per-block-ID
// split. A tally short of quorum is the "votes arrived but did not add up"
// distinction; the per-ID split says whether the committee was split across two
// blocks or simply silent. It is shared by the node's stall line and the
// harness's stall report so the two cannot drift into different readings of the
// same state.
func stallTally(name string, t consensus.DiagTally, quorum uint64) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s votes=%d power=%d quorum=%d", name, t.Votes, t.Total, quorum)
	var nilPower uint64
	for i := 0; i < t.N; i++ {
		if t.IDs[i].BlockID == ([32]byte{}) {
			nilPower = t.IDs[i].Power
		}
	}
	fmt.Fprintf(&b, " nil=%d", nilPower)
	if t.N > 0 {
		b.WriteString(" ids=[")
		for i := 0; i < t.N; i++ {
			if i > 0 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, "%x:%d", t.IDs[i].BlockID[:4], t.IDs[i].Votes)
		}
		b.WriteString("]")
	}
	if t.More > 0 {
		fmt.Fprintf(&b, " +%d ids", t.More)
	}
	return b.String()
}

// stallReportOnce reports the stall this validator is in, if it is in one that
// warrants a line and has not been reported at this height yet. ok=false is the
// healthy path: no stall, a stall below the round threshold, a stall where the
// reachable power cannot make a quorum, or a height already reported.
//
// It takes the validator mutex itself, so callers run it after - not inside -
// a driver operation.
func (v *Validator) stallReportOnce() (string, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.drv == nil || v.closing.Load() {
		return "", false
	}
	head, round := v.drv.Height(), v.drv.Round()
	w := &v.stall
	first := w.height != head || !w.observed
	if first {
		// A height first seen below the threshold is counted from round 0,
		// which is where it began. One first seen AT or past it - a round
		// restored from the store after a restart - is counted from where it
		// was seen: the rounds before it were spent by an earlier process, or
		// unobserved, and are no evidence of a reachable quorum failing.
		*w = stallWatch{height: head, observed: true, round: round, reachable: true}
		if round >= stallReportRounds {
			w.reachFrom = round
		}
	}
	if w.fired {
		return "", false
	}
	// While the quorum is in reach, reachability is sampled once per round
	// entered: a peer that drops out shows within a round, and a healthy tick
	// loop does not pay for a table walk on every tick. While it is NOT in
	// reach it is sampled every tick, so the count starts in the very round
	// the quorum comes back (a walk over a committee-sized table).
	if !first && round == w.round && w.reachable {
		return "", false
	}
	w.round = round
	power, quorum, total, peers, ok := v.stallQuorum(head + 1)
	if !ok || power < quorum {
		w.reachable = false
		return "", false
	}
	if !w.reachable {
		w.reachable, w.reachFrom = true, round
	}
	if round < w.reachFrom+stallReportRounds {
		return "", false
	}
	v.stall.fired = true
	// Fold the engine's current state into the ring before formatting the
	// line, exactly as DiagRounds does: a report must never name a round older
	// than the engine it is looking at. The fold is deliberately HERE and not
	// at the top of this function: every return above reports nothing, so on a
	// healthy tick this watcher costs one height/round read and a bool test,
	// and the one ring fold the tick path pays is the tickLoop's own (RT-4).
	// The harness poll needs no help - DiagRounds folds for itself.
	v.drv.Observe()
	return v.stallLine(head, round, power, total, quorum, peers), true
}

// stallQuorum sums the power this validator can reach at height: its own seat
// (when it holds one there) plus the seat of every member whose signed HELLO is
// fresh, and the quorum that power is measured against. ok=false only when the
// committee itself cannot be resolved, in which case there is nothing sound to
// report; the driver's own HaltError covers that case.
//
// A rotated-out validator holds no seat at the height it is following: its own
// power is zero there, so it reports only if the seats it can still hear from
// hold quorum by themselves - which is the honest reading, because such a node
// no longer votes and cannot be the reason a height fails to commit.
func (v *Validator) stallQuorum(height uint64) (power, quorum, total uint64, peers []stallPeer, ok bool) {
	vals, err := v.cfgC.CommitteeAt(height)
	if err != nil || len(vals) == 0 {
		vals = v.cfgC.Committee
	}
	if len(vals) == 0 {
		return 0, 0, 0, nil, false
	}
	cfg := consensus.Config{Committee: vals}
	total, quorum = cfg.TotalPower(), cfg.Quorum()
	seen := make(map[string]bool, len(vals))
	if seat := genesis.SeatOfPubKey(vals, v.pub); seat >= 0 {
		power += vals[seat].Power
		seen[string(v.pub)] = true
	}
	// The catch-up table is this node's own record of which seats it can hear
	// from: one entry per signed member identity, kept only while fresh by the
	// same TTL the pull selection uses (peerHeightTTL waves).
	v.peerHMu.Lock()
	for id, st := range v.peerH {
		if st.seen+peerHeightTTL < v.wave {
			continue // not refreshed within a few waves: expired
		}
		if seen[id] {
			continue // this node's own HELLO, or a duplicate identity
		}
		seat := genesis.SeatOfPubKey(vals, []byte(id))
		if seat < 0 {
			continue // a member of another epoch's committee: holds no power here
		}
		seen[id] = true
		power += vals[seat].Power
		peers = append(peers, stallPeer{Seat: seat, Via: st.via, Height: st.height})
	}
	v.peerHMu.Unlock()
	// Deterministic output: the table is a map, and a log line that reorders
	// itself run to run is not one you can diff.
	sort.Slice(peers, func(i, j int) bool { return peers[i].Seat < peers[j].Seat })
	return power, quorum, total, peers, true
}

// stallLine formats the one line a stalled validator emits. It is a function so
// the constructed-state test can assert every part of it without a socket, a
// clock or a race.
//
// THE TALLIES ARE THE INFORMATIVE ROUND'S, NOT NECESSARILY THE CURRENT ONE. A
// stalled engine spends most of its time at StepPropose in a round nobody else
// is in, and that round's tallies are empty by construction - printing them
// would say "zero votes" on every stall, including one where votes are flowing
// perfectly and simply are not in this round. So the line renders the newest
// retained round that actually holds a vote (the current round when it does,
// otherwise the one just left). That is the round that answers "did frames
// arrive, and did they add up": nil prevotes from every live seat mean the
// committee agrees there is nothing to commit and is merely out of step, while
// a silent tally means frames are not arriving at all. The round the engine is
// in NOW is stated separately, with its step.
func (v *Validator) stallLine(head uint64, round uint32, power, total, quorum uint64, peers []stallPeer) string {
	r, evidence := v.stallEvidenceRound(round)
	proposal, self := "absent", "none"
	if r.HasProposal {
		proposal = fmt.Sprintf("block=%x", r.ProposalID[:4])
	}
	switch {
	case r.Prevote.OwnCast && r.Prevote.OwnID == ([32]byte{}):
		self = "nil"
	case r.Prevote.OwnCast:
		self = fmt.Sprintf("block=%x", r.Prevote.OwnID[:4])
	}
	// Name the tallied round; "this round" is what a reader would otherwise
	// assume, and assuming wrongly is how the CI failure stayed unexplained.
	which := fmt.Sprintf("r%d", r.Round)
	if evidence {
		which += " (last round with a vote)"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "b10coin: no block for %d rounds at height %d (round %d, step %s): quorum reachable with %d of %d power (quorum %d), yet nothing commits; peers=%s; tallies %s: proposal=%s; %s; %s; selfprevote=%s; the round ladder is the only closer for a round divergence here, so a rolling restart can hold this for minutes - restart the committee together or expect the delay (README: rolling restart)",
		stallReportRounds, head, round, v.drv.DiagStep(),
		power, total, quorum,
		stallPeers(peers), which, proposal,
		stallTally("prevote", r.Prevote, quorum), stallTally("precommit", r.Precommit, quorum),
		self)
	return b.String()
}

// stallEvidenceRound picks the round whose tallies the line renders: the
// current round when it holds a vote, else the newest retained round behind it
// that does, else the current round (so the line still names one). evidence
// reports that the chosen round is not the current one.
func (v *Validator) stallEvidenceRound(round uint32) (consensus.DiagRound, bool) {
	var current consensus.DiagRound
	var haveCurrent bool
	var behind consensus.DiagRound
	var haveBehind bool
	for _, r := range v.drv.DiagRounds() {
		voted := r.Prevote.Votes+r.Precommit.Votes > 0
		if r.Round == round {
			current, haveCurrent = r, true
			if voted {
				return r, false
			}
			continue
		}
		if r.Round < round && voted {
			// The ring is ordered, so the last one seen is the newest.
			behind, haveBehind = r, true
		}
	}
	if haveBehind {
		return behind, true
	}
	if haveCurrent {
		return current, false
	}
	return consensus.DiagRound{Round: round}, false
}

// stallPeers renders the peers compactly: count first, then each seat with the
// transport name and announced height. Bounded by the committee size, because
// the catch-up table is (one entry per signed member identity).
func stallPeers(peers []stallPeer) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d[", len(peers))
	for i, p := range peers {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "seat%d/%s h=%d", p.Seat, p.Via, p.Height)
	}
	b.WriteString("]")
	return b.String()
}
