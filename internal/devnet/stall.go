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
// TTL) is at least the quorum, and that has spent stallReportAfter of the
// ENGINE'S OWN CLOCK at that height, logs one line (rounds climbed with the
// quorum out of reach do not count; see stallWatch): the round and step it is
// in, the prevote/precommit tallies with the quorum they are short of, and the
// peers it sees. "Sees quorum" is the test for "a quorum should exist", and it
// decides WHICH line is printed rather than whether one is: a lone survivor of
// a partitioned committee, or two live seats of three, cannot decide by
// arithmetic, and that case gets the distinct quorum-UNREACHABLE line described
// below - a line asserting that a quorum exists and is failing would be false
// there (audit B-4's rule, one set over), while silence is what made a
// permanent halt undiagnosable. Peers are counted by their SIGNED member
// identity, the same identity the catch-up table is keyed on, so the count
// survives a relay (through which every member shares one transport name) and
// cannot be inflated by a stranger: only a member's verified HELLO reaches the
// table.
//
// A HEIGHT WHOSE NEXT COMMITTEE CANNOT BE DERIVED IS REPORTED AS THAT, WITH NO
// QUORUM (audit B-4). The line used to fall back to the GENESIS committee, so on
// a chain whose next epoch could not be derived it printed a quorum measured
// against a set that may hold no seat at that height - wrong precisely in the
// case it was printed. It now prints the height, the round, the derivation
// failure and nothing numeric, because the honest statement is "this node cannot
// judge a block here", not a quorum against the wrong seats.
//
// A QUORUM THAT IS OUT OF REACH FOR A REAL REASON IS ITS OWN LINE (testrun
// 2026-11-06, S-1). Two keys bonded MIN_STAKE with no node behind either before
// a boundary left a ten-seat chain at one height for over nine minutes: the
// 1/4 cap gives two such seats 4 + 4 of 16 against eight power-1 fixture seats,
// so eight of sixteen power was live against a quorum of eleven. Nothing could
// commit - not even the Unbond that would have freed a seat - and the nodes
// logged NOTHING, because the reachable-quorum report suppresses itself when
// the power it can see is below the quorum (that suppression is deliberate and
// stays: a warning that "a quorum exists and is failing" would be false). The
// worst outcome in this file is a permanent halt with no diagnosis, so
// "quorum unreachable" now has its own line, distinct from "quorum is fine but
// nothing is committing": it names the power reachable, the quorum, the
// committee size, the seats this node hears nothing from, and the cause - it
// says the committee DERIVED, so the cause is seats with no node behind them,
// not a derivation failure (the underivable case keeps its own B-4 line
// above). It is a legitimate operator action to bond a key whose node is not
// running yet - a spare seat, a validator not started - so the line does not
// accuse; it makes the consequence visible and names the seat to start. A
// rotated-out validator does not emit it (it holds no seat at the height it is
// following: it cannot vote and cannot be the reason a height fails).
//
// BONDING IS NOT BLOCKED HERE, AND THAT IS A SCOPE DECISION, NOT AN OVERSIGHT.
// The protocol could refuse a Bond whose key has no node at all, but the chain
// cannot see "has a node": a signed HELLO is the only evidence a key is
// running, it is not in committed state, and a node that is merely restarting
// would be indistinguishable from one that never existed. A real refusal needs
// a committed liveness signal (e.g. an on-chain "this seat has signed within
// N epochs" record) or a minimum live-power check at the boundary, which is a
// consensus change with its own safety argument. Until then: report it, and
// document it.
//
// THE THRESHOLD IS ROUNDS **AND** TIME (testrun 2026-11-06, N-3). Rounds alone
// do not mean a stall: at the shipped ladder eight rounds pass in about 4.4 s,
// so the line fired on seconds-long hiccups (about 40 lines in 4 bursts during
// normal ten-seat running, 20 during the documented one-at-a-time restart whose
// longest gap was 8.4 s) while the README promised a line for a stall that
// "can hold for minutes". stallReportAfter is 30 s of the driver's own clock:
// 3.5x the 8.4 s restart gap and above the 23 s measured for restarting all ten
// together, and 4x shorter than the shortest multi-minute stall in the reports
// (2 minutes), so a real one fires well inside it. The round floor stays so the
// ladder has demonstrably run (a single slow round is not a stall), and the
// round count is the one actually spent at the height, not the constant. The
// watcher is polled every tick (50 ms), so the line lands within one tick of
// the threshold and cannot miss a multi-minute stall by sampling.
//
// A SYNCING NODE IS NOT STALLED (N-3). A node actively catching up has a
// certified head to fetch, so a height not advancing is expected there. The
// test is the one maybeCatchUp itself uses - a fresh, non-demoted peer
// announces a height above our committed head - so "the node would pull now"
// and "the node is not stalled" are the same condition. It cannot censor the
// line for long: a member that claims a height and then serves nothing is
// demoted for peerDemoteWaves, at which point it no longer counts and the line
// can fire.
//
// THE TALLIES ARE THE NEWEST RETAINED ROUND THAT HOLDS A VOTE, not necessarily
// the current one (see stallLine): a stalled engine sits at StepPropose in a
// round nobody else is in, and that round's empty tallies would be a constant
// that says nothing. The voted round is what separates "frames arrived, the
// committee agrees on nil and is merely out of step" from "frames are not
// arriving at all" - the distinction the CI `heights [0 0 0]` report could not
// make.
//
// PEERS ARE NAMED BY THEIR GENESIS SEAT, NOT BY THEIR SEAT AT THIS HEIGHT
// (testrun 2026-11-06, N-4). The committee a boundary derives is ordered by
// bonded stake (ties by public-key bytes), so a genesis seat's POSITION in it
// is a different permutation at every epoch: on the ten-seat fixture key 0 sits
// at index 4 and key 4 at index 8. Labelling peers with that index made seat 0
// print a list containing "seat0" and missing "seat4" - the index-to-key lookup
// was exact, the NUMBER was the wrong name, and the operator read it as the
// node listing itself. A peer is now named by the genesis seat its key holds
// ("seatN", the name `--index` and the transport's "vN" already use), or, for a
// key seated after genesis, by the key-derived name the transport gives it
// ("kN"). That name is stable across boundaries, so the list is comparable with
// the node names in every other line - which is the whole point of a
// diagnostic printed during an incident. A node's own seat is never in its own
// list.
//
// ONCE. The line is emitted once per height: the watcher re-arms when the
// committed height advances. A long stall therefore costs one line, not one per
// round, and a chain that is merely slow (a round or two at a height) says
// nothing.
//
// WHY THIS CANNOT CHANGE A DECISION. Everything here is a READ: the driver's
// own round, committed height and clock, the per-round snapshot Driver.Observe
// already keeps (diag.go), and the catch-up table the wave loop already
// maintains. No consensus path calls it, no branch is added to the engine, and
// the report starts no timer of its own: it reads Driver.NowMillis, the same
// clock the round ladder's deadlines use, so the watcher and the engine can
// never disagree about how long a height has been stuck. It runs on the tick
// goroutine after the tick's driver work, takes the same mutex (so it can never
// read a half-driven engine), and formats under that mutex so a blocked stderr
// cannot hold up consensus.

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/cti97/b10coincom/internal/consensus"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/transport"
)

// stallReportRounds is the fewest rounds a height must have spent undecided -
// every one of them with a reachable quorum - before it can be called a stall.
// It is the "the ladder has demonstrably run" floor, not the threshold: the
// time gate below is what decides. See the file comment.
const stallReportRounds = 8

// stallReportAfter is how long a height must have been undecided, on the
// driver's own clock, before the line is allowed to fire. 30 s is chosen
// against the measurements: the longest pause of the documented one-at-a-time
// restart was 8.4 s and restarting all ten at once took 23.1 s, while the
// stalls this line exists for hold for minutes (2 to 9). See the file comment
// for the arithmetic and for why the watcher cannot miss one.
const stallReportAfter = 30 * time.Second

// stallReportAfterMillis is stallReportAfter in the driver clock's unit
// (virtual milliseconds), which is what NowMillis reports.
const stallReportAfterMillis = int64(stallReportAfter / time.Millisecond)

// stallSeat is one seat of the committee that judges the stalled height.
//
// Index is the seat AT THAT HEIGHT - the position the tallies, the quorum and
// the proposer draw all use. Seat is the GENESIS seat: the name the operator's
// `--index` (and the transport's "vN") gives this key, stable for the life of
// the chain, or -1 for a key that joined the committee after genesis. Name is
// what the line prints (see stallSeatName).
type stallSeat struct {
	Seat  int
	Index int
	Name  string
	Power uint64
}

// stallPeer is one seat this node can currently hear from: the seat, the
// transport name its latest HELLO arrived on, and the height it announced
// there.
type stallPeer struct {
	stallSeat
	Via    transport.PeerID
	Height uint64
}

// stallBoard is everything one lookup of the committee at the stalled height
// says: the power this node can reach against the quorum, the seats it is
// missing, and the committee's own arithmetic. A non-nil error from
// stallQuorum means the committee cannot be resolved at all, in which case
// there is no board and the caller reports the derivation failure instead
// (audit B-4).
type stallBoard struct {
	power  uint64
	total  uint64
	quorum uint64
	// size is the committee's seat count at this height.
	size int
	// self is this node's seat in the committee at this height, or -1 when it
	// holds none there (rotated out, or not seated yet).
	self int
	// heard is the seats whose signed HELLO is fresh, and silent is the rest
	// (never including this node's own seat).
	heard  []stallPeer
	silent []stallSeat
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
//
// sinceRound and sinceMillis are the same idea for the TIME gate: when this
// node first saw the height (round 0 when it was seen below the threshold,
// because that is where it began; the round it was seen at after a restart,
// because the rounds before that were spent by an earlier process). A height
// first seen at or past the threshold therefore gets a full stallReportAfter
// from the moment this process could watch it - a restart cannot make the node
// print a stale verdict, and it cannot suppress one for long either.
//
// fired and firedReach are TWO latches because "no quorum this node can see
// exists" and "a quorum exists and is failing to commit" are two different
// diagnoses, and a height can pass from the first to the second: the operator
// starts a node behind a silent seat, the quorum becomes reachable, and what is
// left is the round divergence the ladder takes minutes to close. One latch
// would spend the height's only line on the first fact and leave the recovery
// - the part the operator is now waiting on - silent. The pair bounds a height
// at two lines, one per diagnosis.
type stallWatch struct {
	height      uint64
	fired       bool   // the "nothing this node can judge or reach can commit" line
	firedReach  bool   // the "quorum reachable, yet nothing commits" line
	observed    bool   // a round of this height has been observed
	round       uint32 // the round last observed
	reachable   bool   // the quorum was reachable at every observation since reachFrom
	reachFrom   uint32
	sinceRound  uint32
	sinceMillis int64
}

// elapsed reports whether this height has been undecided long enough, on the
// driver's clock, for the time half of the threshold. A clock reading BELOW the
// one recorded when the height was first seen (only reachable in a test that
// re-creates the driver) is not evidence of time passing, so it never fires.
func (w *stallWatch) elapsed(nowMillis int64) bool {
	return nowMillis-w.sinceMillis >= stallReportAfterMillis
}

// roundsAt is the number of rounds this node has watched at the height: the
// line's "no block for N rounds". It is at least stallReportRounds wherever a
// line is allowed, and it is the count actually spent - not the constant - so
// the line does not claim 8 when the threshold it crossed was 30 s of ladder.
func (w *stallWatch) roundsAt(round uint32) uint32 {
	if round < w.sinceRound {
		return stallReportRounds
	}
	return round - w.sinceRound
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
// healthy path: no stall, a stall below the round or time threshold, a stall
// this node is not a party to (no seat, or a catch-up in progress), or a height
// already reported.
//
// It takes the validator mutex itself, so callers run it after - not inside -
// a driver operation.
func (v *Validator) stallReportOnce() (string, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.drv == nil || v.closing.Load() {
		return "", false
	}
	head, round, now := v.drv.Height(), v.drv.Round(), v.drv.NowMillis()
	w := &v.stall
	first := w.height != head || !w.observed || round < w.sinceRound
	if first {
		// A height first seen below the threshold is counted from round 0,
		// which is where it began. One first seen AT or past it - a round
		// restored from the store after a restart - is counted from where it
		// was seen: the rounds before it were spent by an earlier process, or
		// unobserved, and are no evidence of a reachable quorum failing. The
		// clock is read the same way, for the same reason.
		*w = stallWatch{height: head, observed: true, round: round, reachable: true, sinceMillis: now}
		if round >= stallReportRounds {
			w.reachFrom, w.sinceRound = round, round
		}
	}
	if w.fired && w.firedReach {
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
	b, err := v.stallQuorum(head + 1)
	if err != nil {
		// THE QUORUM IS NOT COMPUTED, AND THAT IS THE POINT (audit B-4). There
		// used to be a fallback to the GENESIS committee here, so a chain whose
		// next epoch could not be derived printed a quorum measured against a
		// set that may hold no seat at that height at all - a number that is
		// wrong in the one case it is printed. A diagnostic that can lie is
		// worse than one that is silent, but silence would hide a height that
		// cannot advance at all, so the line says exactly what is known: the
		// committee for the next height cannot be derived, no quorum is
		// reported, and this node cannot judge another block at this height.
		w.reachable = false
		if w.fired {
			return "", false // this shape has already been reported at this height
		}
		if round < w.sinceRound+stallReportRounds || !w.elapsed(now) || v.stallSyncing(head) {
			return "", false
		}
		v.stall.fired = true
		v.drv.Observe()
		return v.stallUndeducibleLine(head, round, err), true
	}
	if b.power < b.quorum {
		// QUORUM OUT OF REACH (testrun 2026-11-06, S-1). This is the branch
		// that used to return in silence, and it is the shape of a permanent
		// halt: with the power this node can see below the quorum, nothing it
		// can do - waiting, restarting, or proposing - can commit a block, so
		// the round ladder cannot close it either. It gets its own line, and
		// it must be its own line: the reachable-quorum line below would be a
		// lie here (it asserts a quorum exists), while silence is what made
		// the halt undiagnosable for nine minutes.
		//
		// A node with no seat at this height does NOT report it (b.self < 0):
		// it cannot vote here, so its inability to see a quorum says nothing
		// about whether the committee can commit, and a rotated-out node would
		// otherwise cry halt on every healthy chain.
		w.reachable = false
		if b.self < 0 || w.fired {
			return "", false
		}
		if round < w.sinceRound+stallReportRounds || !w.elapsed(now) || v.stallSyncing(head) {
			return "", false
		}
		v.stall.fired = true
		v.drv.Observe()
		return v.stallUnreachableLine(head, round, b), true
	}
	if !w.reachable {
		w.reachable, w.reachFrom = true, round
	}
	if w.firedReach {
		return "", false // this shape has already been reported at this height
	}
	if round < w.reachFrom+stallReportRounds || !w.elapsed(now) || v.stallSyncing(head) {
		return "", false
	}
	w.firedReach = true
	// Fold the engine's current state into the ring before formatting the
	// line, exactly as DiagRounds does: a report must never name a round older
	// than the engine it is looking at. The fold is deliberately HERE and not
	// at the top of this function: every return above reports nothing, so on a
	// healthy tick this watcher costs one height/round read and a bool test,
	// and the one ring fold the tick path pays is the tickLoop's own (RT-4).
	// The harness poll needs no help - DiagRounds folds for itself.
	v.drv.Observe()
	return v.stallLine(head, round, b), true
}

// stallSyncing reports whether this node is actively CATCHING UP rather than
// stalled: a fresh, non-demoted peer announces a height above this node's
// committed head, which is exactly the condition maybeCatchUp pulls on (it
// reuses that selection, so "the node would pull now" and "the node is not
// stalled" cannot drift apart). A node with certified blocks still to fetch has
// a reason for its height not moving; the stall line is about a node that has
// nothing to fetch and still cannot commit (testrun 2026-11-06, N-3: the line
// fired on nodes that were only syncing).
//
// It is called under the validator mutex, which is the same order every other
// reader of the catch-up table uses (mu, then peerHMu); the table walk takes
// peerHMu and releases it before returning.
func (v *Validator) stallSyncing(head uint64) bool {
	who, _, peerHeight := v.tallestPeer()
	return who != "" && peerHeight > head
}

// stallQuorum measures the power this validator can reach at height: its own
// seat (when it holds one there) plus the seat of every member whose signed
// HELLO is fresh, the quorum that power is measured against, and the seats it
// hears nothing from. A non-nil error means the committee for that height
// cannot be resolved, and in that case there is nothing sound to report: the
// caller says so in one line instead of measuring a quorum against some other
// set (audit B-4; the genesis fallback that used to be here printed a quorum
// for seats that may hold no vote at that height).
//
// A rotated-out validator holds no seat at the height it is following: its own
// power is zero there and self is -1, so the reachable-quorum line reports only
// if the seats it can still hear from hold quorum by themselves - which is the
// honest reading, because such a node no longer votes and cannot be the reason
// a height fails to commit - and the unreachable-quorum line does not report at
// all (see stallReportOnce).
func (v *Validator) stallQuorum(height uint64) (stallBoard, error) {
	vals, err := v.cfgC.CommitteeAt(height)
	if err != nil {
		return stallBoard{}, fmt.Errorf("the committee for height %d cannot be derived: %w", height, err)
	}
	if len(vals) == 0 {
		return stallBoard{}, fmt.Errorf("the committee for height %d seats no validator", height)
	}
	c := consensus.Config{Committee: vals}
	b := stallBoard{total: c.TotalPower(), quorum: c.Quorum(), size: len(vals), self: -1}
	seen := make(map[string]bool, len(vals))
	heard := make([]bool, len(vals))
	if seat := genesis.SeatOfPubKey(vals, v.pub); seat >= 0 {
		b.power += vals[seat].Power
		b.self, heard[seat] = seat, true
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
		heard[seat] = true
		b.power += vals[seat].Power
		b.heard = append(b.heard, stallPeer{
			stallSeat: v.stallSeatOf(vals, seat),
			Via:       st.via,
			Height:    st.height,
		})
	}
	v.peerHMu.Unlock()
	for i := range vals {
		if heard[i] {
			continue
		}
		b.silent = append(b.silent, v.stallSeatOf(vals, i))
	}
	// Deterministic output: the table is a map, and a log line that reorders
	// itself run to run is not one you can diff. Genesis seats sort in the
	// operator's own order; a post-genesis key sorts after them, by its name.
	sort.Slice(b.heard, func(i, j int) bool { return stallSeatLess(b.heard[i].stallSeat, b.heard[j].stallSeat) })
	sort.Slice(b.silent, func(i, j int) bool { return stallSeatLess(b.silent[i], b.silent[j]) })
	return b, nil
}

// stallSeatOf labels one committee seat. The NAME is the genesis seat the key
// holds - the operator's `--index`, the transport's "vN", and the same name
// every other line in the run uses - not the key's position in THIS committee,
// which the stake-then-key derivation reorders at every boundary (testrun
// 2026-11-06, N-4; see the file comment). A key seated after genesis has no
// such position and is named the way the transport names it ("kN").
func (v *Validator) stallSeatOf(vals []genesis.Validator, index int) stallSeat {
	pub := vals[index].PubKey
	seat := -1
	if v.g != nil {
		seat = genesis.SeatOfPubKey(v.g.Validators, pub)
	}
	return stallSeat{Seat: seat, Index: index, Name: stallSeatName(seat, pub), Power: vals[index].Power}
}

// stallSeatName renders the stable name for a seat: "seatN" for a genesis seat,
// "kN" (the key's first six bytes, the transport's own form for a post-genesis
// key) otherwise. It never returns the committee index, because that number is
// not a name: it changes at every epoch boundary.
func stallSeatName(genesisSeat int, pub []byte) string {
	if genesisSeat >= 0 {
		return fmt.Sprintf("seat%d", genesisSeat)
	}
	n := len(pub)
	if n > 6 {
		n = 6
	}
	return fmt.Sprintf("k%x", pub[:n])
}

// stallSeatLess orders seats by their stable name: genesis seats in seat order
// first, then keys seated after genesis by name. Deterministic across runs.
func stallSeatLess(x, y stallSeat) bool {
	if (x.Seat >= 0) != (y.Seat >= 0) {
		return x.Seat >= 0
	}
	if x.Seat != y.Seat {
		return x.Seat < y.Seat
	}
	return x.Name < y.Name
}

// stallUndeducibleLine is the line a stalled validator emits when the committee
// for the next height cannot be derived at all (audit B-4). It deliberately
// prints NO power and NO quorum: the only set available would be the genesis
// committee, which may hold no seat at this height, so any number formed from it
// would be the lie this finding is about. What it prints instead is the fact that
// stops the height: which height, which round, and why the derivation failed.
// The engine has halted for the same reason (Driver.HaltError), and the last
// clause says so, because "no block" and "this node cannot judge a block" are
// different diagnoses.
//
// IT MUST NOT PROMISE A RECOVERY THAT DOES NOT EXIST (audit S-1). This line
// used to end "until the derivation succeeds", which for the cause S-1 found -
// a deciding state with no bonded candidate - could never happen: the state was
// already committed, so no retry, restart or waiting period could change the
// derivation, and the Bond that would seat a candidate could only arrive in a
// block this height refuses. The wording now states the terminal shape instead:
// the deciding state is committed, so nothing this node retries changes it, and
// no block at this height can be judged. That is true for every cause that
// reaches here - CommitteeAt only runs out of candidates on an already-committed
// state, and the remaining causes (no CommitteeSize, EpochBlocks 0, a genesis
// seating none) are equally fixed - so the line does not have to guess which one
// it is looking at.
func (v *Validator) stallUndeducibleLine(head uint64, round uint32, err error) string {
	return fmt.Sprintf("b10coin: no block for %d rounds at height %d (round %d, step %s): the committee for height %d cannot be derived (%v), so no quorum is reported - a power figure measured against any other set would be wrong, and this node cannot judge a block at this height. This does not clear on its own: the state that decides it is already committed, so no retry, restart or wait can change the derivation, and no block at this height can be judged - not even one carrying the Bond that would seat a candidate. The driver reports the same cause as its halt error (see Driver.HaltError). The stall line is silent about tallies for the same reason: nothing was judged here",
		v.stall.roundsAt(round), head, round, v.drv.DiagStep(), head+1, err)
}

// stallUnreachableLine is the line a stalled validator emits when the committee
// for the next height DERIVES and the power it can reach is still below the
// quorum (testrun 2026-11-06, S-1). It is the distinct sibling of the
// reachable-quorum line: that one says "a quorum exists and is failing to
// commit", this one says "no quorum this node can see exists at all", and the
// operator's action is different (start a node behind a silent seat, or wait
// for the seat to leave at a boundary - not "restart the committee together",
// because the ladder cannot close a gap in voting power).
//
// It names the arithmetic (reachable, total, quorum), the seats it hears
// nothing from WITH their power - the seats an operator has to go and start -
// and it states the cause it can rule out: the derivation succeeded, so this is
// not the B-4 shape (a height this node cannot judge). It does not say "unbond
// the silent seat": an Unbond is a transaction, and no block at this height can
// carry one.
func (v *Validator) stallUnreachableLine(head uint64, round uint32, b stallBoard) string {
	short := b.quorum - b.power
	return fmt.Sprintf("b10coin: no block for %d rounds at height %d (round %d, step %s) and the quorum is UNREACHABLE: this node can reach %d of %d power and the quorum is %d, so nothing at this height can commit - not even a block carrying the Unbond that would free a seat - and %d more power is needed; the committee for height %d DOES derive (%d seats), so the cause is not a missing derivation: it is seats with no node behind them (a bonded key whose validator is not running, or one this node cannot reach), and the %d seat(s) it hears nothing from are %s; peers=%s; this does not clear by waiting - the round ladder closes a gap in rounds, not a gap in voting power - so start a node behind one of those seats, or let the seat leave the committee at a boundary (README: nodeless seats and the 1/4 cap). Reported once per height",
		v.stall.roundsAt(round), head, round, v.drv.DiagStep(),
		b.power, b.total, b.quorum, short, head+1, b.size, len(b.silent),
		stallSilent(b.silent), stallPeers(b.heard))
}

// stallLine formats the one line a stalled validator emits when the quorum IS
// reachable and nothing commits. It is a function so the constructed-state test
// can assert every part of it without a socket, a clock or a race.
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
func (v *Validator) stallLine(head uint64, round uint32, b stallBoard) string {
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
	var bld strings.Builder
	fmt.Fprintf(&bld, "b10coin: no block for %d rounds at height %d (round %d, step %s): quorum reachable with %d of %d power (quorum %d), yet nothing commits; peers=%s; tallies %s: proposal=%s; %s; %s; selfprevote=%s; the round ladder is the only closer for a round divergence here, so a rolling restart can hold this for minutes - restart the committee together or expect the delay (README: rolling restart)",
		v.stall.roundsAt(round), head, round, v.drv.DiagStep(),
		b.power, b.total, b.quorum,
		stallPeers(b.heard), which, proposal,
		stallTally("prevote", r.Prevote, b.quorum), stallTally("precommit", r.Precommit, b.quorum),
		self)
	return bld.String()
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
		fmt.Fprintf(&b, "%s/%s h=%d", p.Name, p.Via, p.Height)
	}
	b.WriteString("]")
	return b.String()
}

// stallSilent renders the seats this node hears nothing from, with the power
// each holds: the seats an operator must go and start, and the arithmetic that
// makes them matter. Bounded by the committee size.
func stallSilent(seats []stallSeat) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d[", len(seats))
	for i, s := range seats {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%s power=%d", s.Name, s.Power)
	}
	b.WriteString("]")
	return b.String()
}
