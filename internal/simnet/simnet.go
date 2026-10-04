// Package simnet runs N consensus validators in one process over a deterministic
// simulated network. It is the harness the spec's section 9.1 scenarios drive: a
// failure here replays exactly from the seed, which is the only way consensus bugs
// become debuggable rather than merely observable.
//
// The package is production code, not test scaffolding: it imports the real
// crypto/ed25519 (the test aliases live only inside the consensus tests) and the
// real chain, genesis and transport packages. Task 10 drives it from the CLI.
package simnet

import (
	"crypto/ed25519"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/consensus"
	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/mempool"
	"github.com/cti97/b10coincom/internal/transport"
	"github.com/cti97/b10coincom/internal/transport/sim"
)

// The clock defaults a caller gets by leaving the fields zero. These are the
// values every scenario in the plan uses; a zero field is treated as unset
// because consensus.Config.Validate requires a positive TimeoutBase, and the
// brief's own Options{TempDir, Seed} construction must therefore still run.
const (
	defaultTimeoutBaseMS = int64(200)
	defaultTimeoutStepMS = int64(100)

	// RunBlocksStepMS is how much virtual time one step advances. Every online
	// driver ticks once per step and the network delivers once per step.
	runBlocksStepMS = int64(10)
	// runBlocksStepBudget is the HARD bound on one runUntil call (RunBlocks /
	// RunBlocksAmong run the same loop). It is rarely reached: a run whose
	// wait set stops making height progress errors at the stall limit instead
	// (runUntil / stallStepLimit), so only a run that keeps inching forward
	// forever can burn the whole budget.
	runBlocksStepBudget = 100_000
)

// Options configures a simulated network.
type Options struct {
	TempDir   string
	Seed      int64
	LatencyMS int64
	JitterMS  int64
	// DropPercent is the percentage of deliveries the network drops (0-100),
	// applied per delivery after the partition cut.
	//
	// MILESTONE LIMIT (M3): DropPercent cannot be used for any liveness
	// scenario. A validator whose quorum-committing proposal is lost never
	// holds the block bytes, so when the quorum's precommits arrive it cannot
	// APPEND - and the driver parks at that undecided height permanently,
	// because M3 has no catch-up, rejoin or block-sync path to adopt a peer's
	// block. Any "everyone reaches target" run with drops enabled therefore
	// parks the first time a commit-critical proposal is lost and stalls for
	// the rest of its budget. Until a milestone gives a node a way to adopt a
	// peer's block, run liveness scenarios at DropPercent 0 with only latency
	// and jitter; drops are honest only where liveness is not asserted.
	DropPercent int
	TimeoutBase int64 // virtual ms before a round expires; 0 takes the default
	TimeoutStep int64 // virtual ms added per further round; 0 takes the default
}

// Net is N validators plus the network and clock joining them.
type Net struct {
	opts Options
	sim  *sim.Net
	cfg  consensus.Config
	drv  []*consensus.Driver
	ch   []*chain.Chain
	keys []keyPair
	// syncs is each validator's BLOCK_SYNC syncer, built over the same tap
	// its driver is built over: requests and answers travel the validator's
	// own transport surface. Task 6's harness wiring: M4's catch-up made the
	// convergence scenarios possible, and the answering half plus the commit
	// witness (below) are what make a height PULLABLE by a peer.
	syncs []*consensus.Syncer
	// rts is each validator's frame router (consensus vs wire messages; the
	// two message unions share the 1-3 tag range, so the tap routes by
	// verified decode through it). Held on the Net so a reseat can re-bind
	// the syncer a restarted chain needs.
	rts []*consensus.MessageRouter
	// taps is each validator's recording wrapper, sitting between its driver
	// and the sim endpoint. Every scenario-injected driver (New, the restart
	// scenario's rebuild, MakeEquivocator) must route through it (use
	// transportFor), so a scenario can observe what a validator actually sent
	// and received - an offline validator's tap staying frozen is the direct
	// proof that "powered off" deafens as well as stills it.
	taps []*tap
	// g is the genesis every validator was opened with; genesis() hands it back
	// so a scenario can reopen a stopped validator's chain from disk.
	g *genesis.Genesis
	// offline marks validators that no longer tick AND no longer receive: the
	// sim endpoint's callback is swapped for a discarder. They stay in the
	// committee: TakeOffline models a powered-off machine, not a validator-set
	// change, and removing a member would lower the quorum and make committing
	// EASIER - the opposite of what an outage does.
	offline map[int]bool
	// now is the virtual clock in milliseconds. It lives on the Net rather than
	// in a RunBlocks local so repeated RunBlocks calls (as the plan's scenarios
	// make) continue one timeline instead of rewinding every driver's clock.
	now int64
	// equivs records the wrapper MakeEquivocator installed per validator, so a
	// scenario can inspect what its Byzantine validator actually sent.
	equivs map[int]*equivocating
}

type keyPair struct{ priv ed25519.PrivateKey }

// ValidatorKey derives validator i's key deterministically, so a failing run is
// reproducible: the same seed always produces the same committee and the same
// signatures. The index fits one byte, which caps n at 255 - enforced in New.
//
// Exported (Task 6) so the CLI's networked path and the in-process TCP
// integration test open EXACTLY the committee the harness drives: one shared
// fixture, one derivation, no second copy of the key schedule to drift.
// These are fixture keys, like genesis's devnet keys: derived, not secret,
// never used outside this committee.
func ValidatorKey(i int) ed25519.PrivateKey {
	h := crypto.HashParts([]byte("b10coin-simnet-validator"), []byte{byte(i)})
	return ed25519.NewKeyFromSeed(h[:])
}

// Committee builds a genesis with n equal-power validators over deterministic
// keys, so a failing run is reproducible. The production devnet has one validator
// because a single node needs no agreement; consensus needs a committee.
// Exported for the networked path (Task 6): a node given --peers opens THIS
// committee (chain ID "b10coin-simnet-<n>"), which is what lets four
// `b10coin node` processes derive the same committee - and the same seats -
// from one flag. Not secure: the seats are deterministic and so are the keys.
// Authenticated joins are a later milestone's work.
//
// The simnet genesis reuses the devnet's parameters as a fixture but must carry
// its OWN chain ID: chain.Open validates that Params.ChainID matches ChainID, and
// leaving the devnet's ID here would describe one chain as two different ones.
func Committee(n int) *genesis.Genesis {
	g := genesis.Devnet()
	g.ChainID = fmt.Sprintf("b10coin-simnet-%d", n)
	g.Params.ChainID = g.ChainID
	vals := make([]genesis.Validator, 0, n)
	for i := 0; i < n; i++ {
		priv := ValidatorKey(i)
		vals = append(vals, genesis.Validator{PubKey: priv.Public().(ed25519.PublicKey), Power: 1})
	}
	g.Validators = vals
	g.Params.CommitteeSize = n
	return g
}

// mempoolCapacity is the per-validator pool size the harness attaches to each
// driver. Nothing in the M3 scenarios submits a transaction, so every
// validator proposes empty blocks exactly as it did before consensus gained a
// transaction source; the pools exist so each validator's proposals run the
// real take-and-select path (Take returns nothing, block stays empty) rather
// than a nil-pool shortcut. M4's later wire tasks submit transactions through
// these same pools.
const mempoolCapacity = 1000

// New brings up n validators over one simulated network, each with its own chain
// in its own directory.
func New(n int, opts Options) (*Net, error) {
	if n < 1 || n > 255 {
		return nil, fmt.Errorf("simnet: committee size must be 1..255, got %d", n)
	}
	if opts.TimeoutBase <= 0 {
		opts.TimeoutBase = defaultTimeoutBaseMS
	}
	if opts.TimeoutStep <= 0 {
		opts.TimeoutStep = defaultTimeoutStepMS
	}
	out := &Net{opts: opts, offline: map[int]bool{}, equivs: map[int]*equivocating{}}
	out.sim = sim.New(sim.Options{
		Seed: opts.Seed, Latency: ms(opts.LatencyMS), Jitter: ms(opts.JitterMS),
		DropPercent: opts.DropPercent,
	})
	g := Committee(n)
	out.g = g
	// The spec's power cap is 1/4, and it is enforced as written for committees
	// of four or more. Below four validators a 1/4 cap is unsatisfiable - the
	// largest of n < 4 equal holders necessarily holds at least total/3, so
	// Config.Validate would reject EVERY such committee and no small fixture
	// could exist at all. Small fixtures therefore run under a 1/1 cap.
	capNum, capDen := uint64(1), uint64(4)
	if n < 4 {
		capNum, capDen = 1, 1
	}
	out.cfg = consensus.Config{
		Committee:   g.Validators,
		TimeoutBase: opts.TimeoutBase,
		TimeoutStep: opts.TimeoutStep,
		PowerCapNum: capNum, PowerCapDen: capDen,
	}
	if err := out.cfg.Validate(); err != nil {
		return nil, err
	}
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("v%d", i)
		out.sim.AddPeer(id)
		dir := filepath.Join(opts.TempDir, id)
		c, err := chain.Open(g, dir)
		if err != nil {
			// Do not leak the chains opened before the failure.
			for _, opened := range out.ch {
				_ = opened.Close()
			}
			return nil, err
		}
		out.ch = append(out.ch, c)
		priv := ValidatorKey(i)
		out.keys = append(out.keys, keyPair{priv: priv})
		// The driver sits over a tap, not over the raw endpoint: the tap is a
		// transparent recorder (see tap), so the run's rng draws, delivery
		// order and peer iteration are exactly the sim's own.
		tp := &tap{inner: out.sim.TransportFor(id)}
		out.taps = append(out.taps, tp)
		// The catch-up half: a syncer over the same surface, and the frame
		// router that splits consensus traffic from BLOCK_SYNC frames (the
		// two unions share the 1-3 tag range - Route decodes and VERIFIES).
		// The driver's commit witness archives each commit's certificate, so
		// the chain this harness drives is pullable by a catching-up peer
		// (Design Decision 8): without it Answer would refuse every range.
		sy := consensus.NewSyncer(c, tp, priv)
		rt := consensus.NewMessageRouter(sy)
		rt.SendReply = func(to transport.PeerID, frame []byte) error { return tp.Send(to, frame) }
		tp.router = rt
		out.syncs = append(out.syncs, sy)
		out.rts = append(out.rts, rt)
		out.drv = append(out.drv, out.newDriver(i, nil))
	}
	return out, nil
}

// newDriver builds validator i's driver over its own transport (or over a
// scenario-provided wrapper when tpOverride is non-nil) and wires the commit
// witness that archives certificates for catch-up. It is the harness's ONE
// driver-build path - New, reseat, CatchUp and the equivocator all build
// through it - so a rebuilt driver can never lose the witness or the sync
// routing the first build wired.
func (n *Net) newDriver(i int, tpOverride transport.Transport) *consensus.Driver {
	tp := n.transportFor(i)
	if tpOverride != nil {
		tp = tpOverride
	}
	d := consensus.NewDriver(n.cfg, n.ch[i], n.keys[i].priv, tp, mempool.New(mempoolCapacity))
	d.CommitWitness = n.syncs[i].RecordCommit
	return d
}

// genesis returns the genesis every validator in this network was opened with. The
// restart scenario needs it to reopen a stopped validator's chain from the same
// directory.
func (n *Net) genesis() *genesis.Genesis { return n.g }

// transportFor returns validator i's transport handle - the SAME transport the
// validator's driver was built over, tap included. Anything that rebuilds a
// driver (the restart scenario, MakeEquivocator) must route the new driver
// through this rather than through the raw sim endpoint, or the rebuild
// silently un-taps the validator and later observations miss its traffic.
func (n *Net) transportFor(i int) transport.Transport { return n.taps[i] }

// RunBlocks advances virtual time until every ONLINE validator (the wait set,
// recorded at call start) has committed target blocks, or the run stalls.
//
// Two limits end an unfinished run:
//
//   - The stall limit: if no validator in the wait set reaches a new height
//     for stallStepLimit() consecutive steps, the run is declared stalled and
//     errors EARLY, naming the steps taken, the waited validators' heights and
//     the seed - a run that cannot commit must not burn the whole budget (a
//     pre-fix two-offline stall spent 100,000 steps, minutes of wall time,
//     before erroring). The wait set, not the whole network, is watched: a
//     partitioned minority cut away from a progressing majority is NOT stall.
//   - The step budget (runBlocksStepBudget): the hard cap for a run that keeps
//     inching forward without ever reaching the target.
//
// It returns each validator's height by index either way, so a stalled run can
// be diagnosed from its final state instead of only its error. Success still
// means exactly what it always did: every online validator at or past target.
func (n *Net) RunBlocks(target uint64) (map[uint64]uint64, error) {
	wait := make([]int, 0, len(n.drv))
	for i := range n.drv {
		if !n.offline[i] {
			wait = append(wait, i)
		}
	}
	return n.runUntil(target, wait)
}

// RunBlocksAmong is RunBlocks with a NARROWED wait set: it advances virtual
// time until the NAMED validators have committed target blocks, ignoring the
// heights of everyone else. This is how a scenario expresses "wait for the
// validators that CAN progress": with a minority partitioned or otherwise cut
// off, RunBlocks would block on the cut validator forever while the majority
// commits on untouched.
//
// The wait set must name validators that exist and are ONLINE; an offline
// validator can never progress by construction, so waiting on one is a caller
// bug and is refused up front rather than after a stall window. The stall and
// budget limits of RunBlocks apply unchanged, with the watch and the success
// condition keyed to the named set: validators OUTSIDE it may sit at any
// height on a successful return (that is the point), so a caller that narrows
// the set asserts only what it names.
func (n *Net) RunBlocksAmong(target uint64, validators []int) (map[uint64]uint64, error) {
	if len(validators) == 0 {
		return n.Heights(), fmt.Errorf("simnet: RunBlocksAmong: empty wait set; there is no progress to wait for")
	}
	for _, i := range validators {
		if i < 0 || i >= len(n.drv) {
			return n.Heights(), fmt.Errorf("simnet: RunBlocksAmong: validator index %d out of range 0..%d", i, len(n.drv)-1)
		}
		if n.offline[i] {
			return n.Heights(), fmt.Errorf("simnet: RunBlocksAmong: validator %d is offline and can never progress; waiting on it would stall", i)
		}
	}
	return n.runUntil(target, validators)
}

// runUntil is the step loop both RunBlocks and RunBlocksAmong drive. The ticks,
// the sim advance and the delivery order are untouched by the wait set: only
// the success check and the stall watch are keyed to it.
func (n *Net) runUntil(target uint64, waited []int) (map[uint64]uint64, error) {
	if len(waited) == 0 {
		return n.Heights(), fmt.Errorf("simnet: no online validator can ever commit height %d; there is nothing to wait for", target)
	}
	isWaited := make([]bool, len(n.drv))
	last := make([]uint64, len(n.drv))
	for _, i := range waited {
		isWaited[i] = true
		last[i] = n.ch[i].Height()
	}
	limit := n.stallStepLimit()
	quiet := 0 // the step at which the wait set last made height progress
	for step := 0; step < runBlocksStepBudget; step++ {
		n.now += runBlocksStepMS
		for i, d := range n.drv {
			if n.offline[i] {
				continue // a powered-off machine ticks and receives nothing
			}
			d.Tick(n.now)
		}
		n.sim.Advance(ms(runBlocksStepMS))
		if n.waitedAtLeast(isWaited, target) {
			return n.Heights(), nil
		}
		for _, i := range waited {
			if h := n.ch[i].Height(); h > last[i] {
				last[i], quiet = h, step
			}
		}
		if step-quiet >= limit {
			stuck := make(map[uint64]uint64, len(waited))
			for _, i := range waited {
				stuck[uint64(i)] = n.ch[i].Height()
			}
			return n.Heights(), fmt.Errorf(
				"simnet: stalled below height %d after %d steps: nothing in the wait set progressed for %d consecutive steps (waited heights %v, seed %d)",
				target, step+1, limit, stuck, n.opts.Seed)
		}
	}
	return n.Heights(), fmt.Errorf("simnet: stalled below height %d after %d steps (heights %v, seed %d)", target, runBlocksStepBudget, n.Heights(), n.opts.Seed)
}

func (n *Net) waitedAtLeast(isWaited []bool, target uint64) bool {
	for i, c := range n.ch {
		if !isWaited[i] {
			continue
		}
		if c.Height() < target {
			return false
		}
	}
	return true
}

// stallStepLimit is how many consecutive steps a wait set may show no height
// progress before runUntil declares the run stalled. It is derived from the
// configured round timeouts rather than fixed: a healthy commit lands within
// one round (TimeoutBase, plus the escalated round's TimeoutStep for a
// re-proposal), so five such windows is generous grace, and the floor of 200
// steps (two virtual seconds, twenty base timeouts at the defaults) keeps
// fast-timeout configurations from flapping on start-up.
func (n *Net) stallStepLimit() int {
	limit := int((n.opts.TimeoutBase+n.opts.TimeoutStep)/runBlocksStepMS) * 5
	if limit < 200 {
		limit = 200
	}
	return limit
}

// Heights reports every validator's chain height by index.
func (n *Net) Heights() map[uint64]uint64 {
	out := make(map[uint64]uint64, len(n.ch))
	for i, c := range n.ch {
		out[uint64(i)] = c.Height()
	}
	return out
}

// AssertSameChain fails unless every ONLINE validator agrees on the chain's
// committed prefix. It compares the block at the LOWEST common height, not the
// head: validators may legitimately be at different heights - one was taken
// offline, one received a lost proposal - but they must agree on every height
// they all share. Two validators presenting different blocks at a shared height
// would be a broken two-thirds safety assumption, which is exactly what a
// scenario must be able to detect.
//
// With fewer than two validators online there is nothing to agree ABOUT, and a
// bare nil would be a vacuous pass: the call returns an error naming the online
// count instead. A committee of one, or a fully offline network, has no
// agreement claim to test.
func (n *Net) AssertSameChain() error {
	online := 0
	for i := range n.ch {
		if !n.offline[i] {
			online++
		}
	}
	if online < 2 {
		return fmt.Errorf("simnet: AssertSameChain compares %d online validator(s); fewer than two makes agreement vacuous and cannot be tested", online)
	}
	var ref [32]byte
	var refHeight uint64
	first := true
	for i, c := range n.ch {
		if n.offline[i] {
			continue
		}
		h := c.Height()
		if first || h < refHeight {
			b, err := c.BlockAt(h)
			if err != nil {
				return err
			}
			ref, refHeight, first = b.ID(), h, false
		}
	}
	for i, c := range n.ch {
		if n.offline[i] || c.Height() < refHeight {
			continue // a validator still catching up has nothing to say about refHeight yet
		}
		b, err := c.BlockAt(refHeight)
		if err != nil {
			return err
		}
		if b.ID() != ref {
			return fmt.Errorf("simnet: validator %d disagrees at height %d", i, refHeight)
		}
	}
	return nil
}

// AssertPrefix reports whether validator i's history is an exact prefix of the
// longest chain in the network: for every height i has committed, i's block must
// be the identical block the longest chain holds at that height, and i's head may
// not stand above the longest chain's head (a validator taller than everyone else
// holds blocks nobody else committed, which is a fork by definition).
//
// This is the honest safety assertion for a LAGGING validator under the M3
// milestone limits: with no block catch-up, a validator isolated behind the
// quorum cannot adopt the blocks it missed, so the strongest claim a scenario can
// make about it is "behind, never forked". Requiring it to reconverge would
// assert a mechanism M3 does not have.
//
// It lives in the non-test half of the package (moved out of the scenarios at
// review): the plan's interface list ships AssertPrefix, and a helper defined
// only in a _test file does not exist for any non-test caller - Task 10's
// devnet included.
func (n *Net) AssertPrefix(i int) error {
	if i < 0 || i >= len(n.ch) {
		return fmt.Errorf("simnet: AssertPrefix: validator index %d out of range 0..%d", i, len(n.ch)-1)
	}
	// The longest chain is the reference: the majority's chain, which the
	// scenarios keep advancing while i sits behind.
	refHeight := uint64(0)
	var ref *chain.Chain
	for _, c := range n.ch {
		if c.Height() > refHeight {
			refHeight, ref = c.Height(), c
		}
	}
	if ref == nil {
		return fmt.Errorf("simnet: AssertPrefix: no validator chain to compare against")
	}
	c := n.ch[i]
	if c.Height() > refHeight {
		return fmt.Errorf("simnet: validator %d stands at height %d, above the longest chain at %d: it committed blocks the network never agreed on",
			i, c.Height(), refHeight)
	}
	for h := uint64(0); h <= c.Height(); h++ {
		bi, err := c.BlockAt(h)
		if err != nil {
			return fmt.Errorf("simnet: reading validator %d at height %d: %w", i, h, err)
		}
		br, err := ref.BlockAt(h)
		if err != nil {
			return fmt.Errorf("simnet: reading the longest chain at height %d: %w", h, err)
		}
		if bi.ID() != br.ID() {
			id1, id2 := bi.ID(), br.ID()
			return fmt.Errorf("simnet: validator %d DIVERGED at height %d: %x vs the longest chain's %x - a fork, not a lag",
				i, h, id1[:8], id2[:8])
		}
	}
	return nil
}

// Partition cuts the network between two groups of validator indices. Messages
// within a group still flow; messages across the cut are dropped.
func (n *Net) Partition(a, b []int) {
	as, bs := ids(a), ids(b)
	n.sim.Partition(as, bs)
}

// Heal restores full connectivity.
func (n *Net) Heal() { n.sim.Heal() }

// TakeOffline stops validator i from ticking AND cuts its links in the
// simulated network, as if its machine were powered off: the machine is no
// longer running, so it neither sends nor receives. Skipping only the tick is
// NOT a power-off - the network would still deliver to the validator's
// endpoint, its driver would keep prevoting, precommitting and APPENDING on
// messages, and the one-offline liveness claim would pass while the
// two-offline stall happened for the wrong reason. The cut lives at the sim
// endpoint (its receive callback is swapped for a discarder) rather than in a
// partition group, because a powered-off machine is deaf to everyone INCLUDING
// other offline validators, and because the callback survives Heal and later
// Partition calls, which reassign partition groups wholesale. The swap is made
// on the raw endpoint, below the validator's tap, so while a validator is
// offline its tap stays frozen - that frozen log is the direct, observable
// definition of "this validator sends and receives nothing" (simnet_test.go
// asserts exactly that).
//
// It stays in the committee, so quorum does NOT become easier: the config's
// committee, total power and quorum threshold are all left untouched by design -
// silencing a validator must never be a way to lower the bar.
//
// The cut is one-way by design: M3 has no catch-up or rejoin, so a validator
// cannot merely be marked online again. Coming back means a restart - reopen
// the chain from disk and build a fresh driver over transportFor(i); the new
// driver's OnMessage registration restores the link.
func (n *Net) TakeOffline(i int) {
	if n.offline[i] {
		return
	}
	n.offline[i] = true
	// Cut the links: nothing delivered to this endpoint reaches the driver any
	// more, and with no Tick and no OnMessage the driver never flushes, so it
	// can emit nothing either. Messages already in flight towards the
	// validator are still delivered - into the discarder, where a real
	// power-off would drop them at the (stopped) NIC.
	n.sim.TransportFor(fmt.Sprintf("v%d", i)).OnMessage(func(transport.Message) {})
}

// MakeEquivocator replaces validator i's transport with one that duplicates every
// non-nil PREVOTE it sends as a prevote for a DIFFERENT block ID, signed with the
// key i genuinely owns.
//
// Signing with a REAL committee key is essential: a forged vote carrying a
// stranger's key would be rejected by the tally as a non-member, and the scenario
// would then pass without ever exercising the quorum arithmetic it exists to
// stress. The forger below puts validator i's own key in BOTH the signature and
// the Validator field, so peers see two equally valid, mutually conflicting
// prevotes from a committee member of good standing.
//
// The rebuild is also what puts the forgery on the wire: driver flushes reach
// the transport ONLY through Broadcast, so the forged vote is a second
// Broadcast through i's own wrapper into the live network - peers receive it
// like any other message (simnet_test.go asserts the forged bytes both on i's
// outgoing tap AND in another validator's received log; a forge that stayed
// local would leave both empty and the Byzantine scenario vacuous).
//
// Only OnMessage is a method the driver actually exercises - NewDriver
// re-registers its receive callback through it, so forwarding it is what keeps
// the rebuilt driver from going deaf. Peers and Close forward purely to
// satisfy the Transport interface: the driver never lists peers (its broadcasts
// reach the transport's whole peer set) and never closes its transport.
//
// The call errors when i is out of range, and on an OFFLINE validator: the
// rebuild re-registers a live receive callback, which would silently lift the
// power-off cut - a powered-off machine cannot be Byzantine.
func (n *Net) MakeEquivocator(i int) error { return n.installEquivocator(i, consensus.MsgPrevote) }

// MakePrecommitEquivocator installs the same equivocation seam over PRECOMMITS -
// design spec section 9.1's Byzantine scenario, verbatim: "a validator
// equivocates (sends conflicting precommits)". Every non-nil precommit
// validator i broadcasts is duplicated as a PRECOMMIT for a different block ID,
// signed with the key it genuinely owns, so peers see two equally valid,
// mutually conflicting precommits from one committee member at the same
// (height, round). The tally's one-vote-per-validator rule is type-agnostic -
// the dedup keys the VALIDATOR, not the vote - so a conflicting precommit must
// collapse exactly as a conflicting prevote does: no quorum anywhere for the
// forged ID, and no conflicting commit. The scenario that drives it (the
// precommit arm in scenarios_test.go) asserts that on the wire and on the
// committed chains. The range and offline errors are MakeEquivocator's
// verbatim: the rebuild is shared, and its contract is one contract.
func (n *Net) MakePrecommitEquivocator(i int) error {
	return n.installEquivocator(i, consensus.MsgPrecommit)
}

// installEquivocator is the rebuild both forged-vote seams share: it swaps
// validator i's transport for an equivocating wrapper that duplicates every
// non-nil vote of the given type as a vote for a DIFFERENT block ID, signed
// with i's own key, and rebuilds i's driver over the wrapper through
// transportFor (the tap stays wired - see its comment).
func (n *Net) installEquivocator(i int, typ consensus.MsgType) error {
	if i < 0 || i >= len(n.drv) {
		return fmt.Errorf("simnet: MakeEquivocator: validator index %d out of range 0..%d", i, len(n.drv)-1)
	}
	if n.offline[i] {
		return fmt.Errorf("simnet: MakeEquivocator: validator %d is offline; a powered-off machine cannot be Byzantine", i)
	}
	eq := &equivocating{
		inner:   n.transportFor(i),
		priv:    n.keys[i].priv,
		typ:     typ,
		forgeID: crypto.HashParts([]byte("b10coin-forged-block")),
	}
	n.equivs[i] = eq
	n.drv[i] = n.newDriver(i, eq)
	return nil
}

// tap is a transparent recording wrapper around one validator's transport. It
// exists so a scenario can assert what a validator actually put on the wire and
// what its driver actually consumed, without poking consensus internals: the
// offline validator whose tap stays frozen, the Byzantine validator whose
// forged bytes appear in both its own send log and its peers' receive logs.
// The wrapper records only; every call forwards unchanged to the sim endpoint,
// so the seeded rng, the (at, seq) delivery order and the sorted peer
// iteration are exactly the sim's own.
type tap struct {
	inner transport.Transport
	// mu guards the two recording logs below. Two writers can be live at the
	// same time on ONE validator: the catch-up pull runs Syncer.PullAndAdopt
	// on its own goroutine (its request goes out through tap.Send), and
	// CatchUp's own goroutine keeps advancing the sim while it waits, whose
	// deliveries drive the engine's broadcasts through tap.Broadcast (and
	// inbound frames through the OnMessage append). The two appends — and the
	// snapshots the scenarios read afterwards — must not run against each
	// other; unlocked slices appended from two goroutines are a latent data
	// race exactly hidden from scheduling (Task 6 review carry-forward, low).
	mu sync.Mutex
	// router splits consensus frames from wire (HELLO/BLOCK_SYNC) frames -
	// the two message unions share the numeric tag range 1-3, so routing
	// happens by what a frame VERIFIES as, through consensus.MessageRouter.
	// Nil until New installs it; deliveries only start after New, so it is
	// set before any frame can be routed.
	router *consensus.MessageRouter
	// sent holds a copy of every payload this validator broadcast, in send
	// order. A partition can stop a broadcast from being delivered; it is on
	// this validator's wire either way, which is the level this log reports.
	sent [][]byte
	// recv holds a copy of every payload DELIVERED TO THE DRIVER, in delivery
	// order. TakeOffline replaces the endpoint's callback below this wrapper,
	// so messages to a powered-off validator are dropped by the simulation and
	// never appear here: recv measures what the validator's engine acted on.
	// BLOCK_SYNC frames are NOT recorded here: the router consumes them for
	// the syncer, nothing in the engine acts on them (the convergence
	// scenarios assert engine behaviour, not sync plumbing).
	recv [][]byte
	// cons is the driver's OnMessage, set by NewDriver's registration.
	cons func(transport.Message)
}

func (t *tap) Broadcast(data []byte) error {
	t.keepSent(data)
	return t.inner.Broadcast(data)
}

// Send records the unicast and forwards it, mirroring Broadcast: a payload
// the validator put on the wire belongs in the send log whichever primitive
// carried it.
func (t *tap) Send(peer transport.PeerID, data []byte) error {
	t.keepSent(data)
	return t.inner.Send(peer, data)
}

// keepSent appends a copy of the payload to the send log under the log's
// mutex: Broadcast and Send can run on different goroutines (the pull and
// the delivery path), and an unsynchronised append there is a data race.
func (t *tap) keepSent(data []byte) {
	t.mu.Lock()
	t.sent = append(t.sent, append([]byte(nil), data...))
	t.mu.Unlock()
}

// OnMessage wraps the receive callback. Every consensus frame is counted as
// received (before the driver sees it) and passed to the driver; every
// HELLO/BLOCK_SYNC frame is routed to the syncer instead - it never reaches
// the driver, never enters the recv log, and a request is answered by the
// router through this validator's own Send.
func (t *tap) OnMessage(fn func(transport.Message)) {
	t.cons = fn
	t.inner.OnMessage(func(m transport.Message) {
		if t.router != nil {
			if !t.router.Route(m) {
				return // consumed by the router (sync answered/filed, hello observed, garbage counted)
			}
		}
		t.keepRecv(m.Data)
		if t.cons != nil {
			t.cons(m)
		}
	})
}

// keepRecv appends a copy of the delivered frame to the receive log under
// the same mutex as the send log — the OnMessage callback can run while the
// pull goroutine's Send records, so the logs share one lock.
func (t *tap) keepRecv(data []byte) {
	t.mu.Lock()
	t.recv = append(t.recv, append([]byte(nil), data...))
	t.mu.Unlock()
}

// sentCount, sentLog, recvCount and recvLog return LOCKED snapshots of the
// recording logs. The scenario assertions use them instead of reading the
// slice fields, so a read cannot race the append (the same guard the appends
// took) and a ranged assertion sees a consistent log even if it overlaps a
// pull.
func (t *tap) sentCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.sent)
}

func (t *tap) sentLog() [][]byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([][]byte(nil), t.sent...)
}

func (t *tap) recvCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.recv)
}

func (t *tap) recvLog() [][]byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([][]byte(nil), t.recv...)
}

func (t *tap) Peers() []transport.PeerID { return t.inner.Peers() }
func (t *tap) Close() error              { return t.inner.Close() }

// equivocating wraps a Transport and re-sends every vote of its kind
// (prevote or precommit, fixed by typ) as a conflicting one for the same
// (height, round), signed with the same key. The forged vote carries the
// wrapper's own VOTE TYPE, so the prevote seam manufactures conflicting
// prevotes and the precommit seam - the type design spec section 9.1 names -
// manufactures conflicting precommits.
type equivocating struct {
	inner   transport.Transport
	priv    ed25519.PrivateKey
	typ     consensus.MsgType
	forgeID [32]byte

	// forged records every conflicting vote this wrapper sent, in send order.
	// It is what a scenario (or a test) inspects to confirm the equivocation is
	// real: signed by a committee key, for a block nobody proposed.
	forged []*consensus.Vote
}

func (eq *equivocating) Broadcast(data []byte) error {
	if err := eq.inner.Broadcast(data); err != nil {
		return err
	}
	v, err := consensus.DecodeVote(data)
	if err != nil || v.Type != eq.typ || v.IsNil() {
		return nil
	}
	if v.BlockID == eq.forgeID {
		// No conflict to manufacture: re-broadcasting would be collapsed by the
		// recipients' one-vote-per-validator rule and is not an equivocation.
		return nil
	}
	f := &consensus.Vote{
		Type: v.Type, Height: v.Height, Round: v.Round,
		BlockID: eq.forgeID, Validator: v.Validator,
	}
	h := f.SigningHash()
	f.Sig = ed25519.Sign(eq.priv, h[:])
	eq.forged = append(eq.forged, f)
	return eq.inner.Broadcast(consensus.EncodeVote(f))
}

// OnMessage must forward to the wrapped transport, else the driver under the
// wrapper never receives anything and stalls for the wrong reason.
//
// Send forwards unchanged, like OnMessage: the equivocation machinery lives
// in the broadcast path, where a vote reaches every validator (each of which
// sees the conflict). A unicast vote would reach one validator only and fail
// to manufacture a visible conflict, so equivocating must NOT re-send it —
// forwarding keeps that property exactly.
func (eq *equivocating) OnMessage(fn func(transport.Message)) { eq.inner.OnMessage(fn) }
func (eq *equivocating) Send(p transport.PeerID, d []byte) error {
	return eq.inner.Send(p, d)
}
func (eq *equivocating) Peers() []transport.PeerID { return eq.inner.Peers() }
func (eq *equivocating) Close() error              { return eq.inner.Close() }

func ids(is []int) []string {
	out := make([]string, 0, len(is))
	for _, i := range is {
		out = append(out, fmt.Sprintf("v%d", i))
	}
	return out
}

// Close closes every validator's chain. A validator whose chain was already
// closed by a restart scenario stays closed: Close errors on it are suppressed.
func (n *Net) Close() {
	for _, c := range n.ch {
		_ = c.Close()
	}
}

// catchUpStepBudget bounds the network advance a CatchUp drives while its
// pull is in flight. A healthy window round-trips in a handful of steps
// (the sim delivers on the next Advance); the budget is a ceiling for a
// pull over many full windows, far past anything an honest committee needs.
const catchUpStepBudget = 200_000

// CatchUp drives validator i's BLOCK_SYNC pull from the tallest OTHER online
// validator, advancing the network until the pull settles. It is the harness
// half of the M3 carry-forward the scenarios now assert: a validator that
// misses blocks adopts them - certificate-gated, through the ordinary
// chain.Append - and its driver is rebuilt over the adopted head, so it
// rejoins the committee instead of parking forever at an undecided height.
//
// Without the rebuild the rejoin is a trap: the OLD engine keeps round-looping
// at its stale height (every one of its broadcasts matches nobody's current
// height any more), so pulling the chain up without re-arming the engine
// would converge the FILES and strand the validator. The rebuild is the
// same re-entry a restart takes: the engine begins at head+1 with the head
// as parent, and any lock it persisted for a still-undecided height is
// restored from the store.
//
// The pull runs on its own goroutine because Syncer.PullAndAdopt BLOCKS on
// its ReplyWait: deliveries must keep happening while it waits, which is why
// the sim's Advance moved under an internal lock (semantics unchanged - see
// sim's package comment). Everything here stays on the caller's goroutine
// otherwise, and the pull is fully SETTLED (its goroutine has returned)
// before CatchUp does. Offline validators are refused: a powered-off machine
// cannot pull, and letting one pass would put sync traffic on the wire of a
// validator whose scenarios assert frozen taps.
func (n *Net) CatchUp(i int) error {
	if i < 0 || i >= len(n.drv) {
		return fmt.Errorf("simnet: CatchUp: validator index %d out of range 0..%d", i, len(n.drv)-1)
	}
	if n.offline[i] {
		return fmt.Errorf("simnet: CatchUp: validator %d is offline; a powered-off machine cannot pull", i)
	}
	ref, refH := -1, uint64(0)
	for j, c := range n.ch {
		if j == i || n.offline[j] {
			continue
		}
		if c.Height() > refH {
			ref, refH = j, c.Height()
		}
	}
	if ref < 0 {
		return fmt.Errorf("simnet: CatchUp: no other online validator serves validator %d", i)
	}
	if refH <= n.ch[i].Height() {
		return nil // nothing taller: already caught up
	}
	start := n.ch[i].Height()
	n.syncs[i].Peer = transport.PeerID(fmt.Sprintf("v%d", ref))
	done := make(chan error, 1)
	go func() { done <- n.syncs[i].PullAndAdopt(start + 1) }()
	for step := 0; ; step++ {
		select {
		case err := <-done:
			// The pull's goroutine has RETURNED: no syncer or chain access
			// on it survives this point, so everything below is the
			// scenario's alone.
			if err != nil {
				return err
			}
			if n.ch[i].Height() > start {
				n.rebuildDriver(i)
			}
			return nil
		default:
		}
		if step >= catchUpStepBudget {
			// The pull is (or should be) settled by its own ReplyWait
			// deadline; wait for it to end rather than orphan a goroutine
			// that still owns the syncer, then report the stall.
			select {
			case err := <-done:
				if err != nil {
					return err
				}
				if n.ch[i].Height() > start {
					n.rebuildDriver(i)
				}
				return nil
			case <-time.After(replacePullWait):
				return fmt.Errorf("simnet: CatchUp: validator %d's pull did not settle within %d advanced steps (height %d, peers' head %d)",
					i, catchUpStepBudget, n.ch[i].Height(), refH)
			}
		}
		n.sim.Advance(ms(1))
	}
}

// replacePullWait is the wall-clock grace a wedged pull gets to return after
// the advance budget ran out before CatchUp reports it wedged.
const replacePullWait = 10 * time.Second

// reseat rebinds validator i to a reopened chain: the restart scenario closes
// the old chain and reopens the same directory from disk. The syncer's chain
// pointer and certificate archive both belonged to the OLD chain, and the
// driver's engine judges a head that no longer exists - so the syncer and
// the driver are rebuilt over the reopened one, exactly the wiring New did
// for the first build.
func (n *Net) reseat(i int, c *chain.Chain) {
	n.ch[i] = c
	n.syncs[i] = consensus.NewSyncer(c, n.transportFor(i), n.keys[i].priv)
	n.rts[i].Sync = n.syncs[i]
	n.rebuildDriver(i)
}

// rebuildDriver replaces validator i's driver with one judging the CURRENT
// head - the rejoin a successful CatchUp takes, and the same shape the
// restart scenario has always taken. The commit witness is re-wired so the
// rebuilt driver keeps archiving certificates for the heights it commits.
func (n *Net) rebuildDriver(i int) {
	n.drv[i] = consensus.NewDriver(n.cfg, n.ch[i], n.keys[i].priv, n.transportFor(i), mempool.New(mempoolCapacity))
	n.drv[i].CommitWitness = n.syncs[i].RecordCommit
}

func ms(n int64) time.Duration { return time.Duration(n) * time.Millisecond }
