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
	"time"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/consensus"
	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/genesis"
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
	// runBlocksStepBudget bounds a RunBlocks call: at 10 virtual ms per step
	// this is 1000 virtual seconds, far past anything a live network needs,
	// and the cap is what turns a liveness bug into an error instead of a
	// hung test.
	runBlocksStepBudget = 100_000
)

// Options configures a simulated network.
type Options struct {
	TempDir     string
	Seed        int64
	LatencyMS   int64
	JitterMS    int64
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
	// g is the genesis every validator was opened with; genesis() hands it back
	// so a scenario can reopen a stopped validator's chain from disk.
	g *genesis.Genesis
	// offline marks validators that no longer tick. They stay in the committee:
	// TakeOffline models a powered-off machine, not a validator-set change, and
	// removing a member would lower the quorum and make committing EASIER - the
	// opposite of what an outage does.
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

// simKey derives validator i's key deterministically, so a failing run is
// reproducible: the same seed always produces the same committee and the same
// signatures. The index fits one byte, which caps n at 255 - enforced in New.
func simKey(i int) ed25519.PrivateKey {
	h := crypto.HashParts([]byte("b10coin-simnet-validator"), []byte{byte(i)})
	return ed25519.NewKeyFromSeed(h[:])
}

// simGenesis builds a genesis with n equal-power validators over deterministic
// keys, so a failing run is reproducible. The production devnet has one validator
// because a single node needs no agreement; consensus needs a committee.
//
// The simnet genesis reuses the devnet's parameters as a fixture but must carry
// its OWN chain ID: chain.Open validates that Params.ChainID matches ChainID, and
// leaving the devnet's ID here would describe one chain as two different ones.
func simGenesis(n int) *genesis.Genesis {
	g := genesis.Devnet()
	g.ChainID = fmt.Sprintf("b10coin-simnet-%d", n)
	g.Params.ChainID = g.ChainID
	vals := make([]genesis.Validator, 0, n)
	for i := 0; i < n; i++ {
		priv := simKey(i)
		vals = append(vals, genesis.Validator{PubKey: priv.Public().(ed25519.PublicKey), Power: 1})
	}
	g.Validators = vals
	g.Params.CommitteeSize = n
	return g
}

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
	g := simGenesis(n)
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
		priv := simKey(i)
		out.keys = append(out.keys, keyPair{priv: priv})
		out.drv = append(out.drv, consensus.NewDriver(out.cfg, c, priv, out.sim.TransportFor(id)))
	}
	return out, nil
}

// genesis returns the genesis every validator in this network was opened with. The
// restart scenario needs it to reopen a stopped validator's chain from the same
// directory.
func (n *Net) genesis() *genesis.Genesis { return n.g }

// RunBlocks advances virtual time until every ONLINE validator has committed
// target blocks, or the step budget is exhausted. It returns each validator's
// height by index either way, so a stalled run can be diagnosed from its final
// state instead of only its error.
func (n *Net) RunBlocks(target uint64) (map[uint64]uint64, error) {
	for step := 0; step < runBlocksStepBudget; step++ {
		n.now += runBlocksStepMS
		for i, d := range n.drv {
			if n.offline[i] {
				continue // a powered-off machine ticks and receives nothing
			}
			d.Tick(n.now)
		}
		n.sim.Advance(ms(runBlocksStepMS))
		if n.allAtLeast(target) {
			return n.Heights(), nil
		}
	}
	return n.Heights(), fmt.Errorf("simnet: stalled below height %d after %d steps (heights %v, seed %d)", target, runBlocksStepBudget, n.Heights(), n.opts.Seed)
}

func (n *Net) allAtLeast(target uint64) bool {
	for i, c := range n.ch {
		if n.offline[i] {
			continue
		}
		if c.Height() < target {
			return false
		}
	}
	return true
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
func (n *Net) AssertSameChain() error {
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

// Partition cuts the network between two groups of validator indices. Messages
// within a group still flow; messages across the cut are dropped.
func (n *Net) Partition(a, b []int) {
	as, bs := ids(a), ids(b)
	n.sim.Partition(as, bs)
}

// Heal restores full connectivity.
func (n *Net) Heal() { n.sim.Heal() }

// TakeOffline stops a validator from ticking, as if its machine were powered off.
// It stays in the committee, so quorum does NOT become easier: the config's
// committee, total power and quorum threshold are all left untouched by design -
// silencing a validator must never be a way to lower the bar.
func (n *Net) TakeOffline(i int) { n.offline[i] = true }

// MakeEquivocator replaces validator i's transport with one that duplicates every
// prevote it sends as a prevote for a DIFFERENT block ID, signed with the key i
// genuinely owns.
//
// Signing with a REAL committee key is essential: a forged vote carrying a
// stranger's key would be rejected by the tally as a non-member, and the scenario
// would then pass without ever exercising the quorum arithmetic it exists to
// stress. The forger below puts validator i's own key in BOTH the signature and
// the Validator field, so peers see two equally valid, mutually conflicting
// prevotes from a committee member of good standing.
//
// OnMessage, Peers and Close forward to the wrapped transport: the driver that is
// rebuilt over this wrapper re-registers its callback and lists its peers through
// exactly these three methods, so dropping any of them would deafen or blind the
// driver and stall the scenario for the wrong reason.
func (n *Net) MakeEquivocator(i int) {
	inner := n.sim.TransportFor(fmt.Sprintf("v%d", i))
	eq := &equivocating{
		inner:   inner,
		priv:    n.keys[i].priv,
		forgeID: crypto.HashParts([]byte("b10coin-forged-block")),
	}
	n.equivs[i] = eq
	n.drv[i] = consensus.NewDriver(n.cfg, n.ch[i], n.keys[i].priv, eq)
}

// equivocating wraps a Transport and re-sends every prevote as a conflicting one.
type equivocating struct {
	inner   transport.Transport
	priv    ed25519.PrivateKey
	forgeID [32]byte

	// forged records every conflicting prevote this wrapper sent, in send order.
	// It is what a scenario (or a test) inspects to confirm the equivocation is
	// real: signed by a committee key, for a block nobody proposed.
	forged []*consensus.Vote
}

func (eq *equivocating) Broadcast(data []byte) error {
	if err := eq.inner.Broadcast(data); err != nil {
		return err
	}
	v, err := consensus.DecodeVote(data)
	if err != nil || v.Type != consensus.MsgPrevote || v.IsNil() {
		return nil
	}
	if v.BlockID == eq.forgeID {
		// No conflict to manufacture: re-broadcasting would be collapsed by the
		// recipients' one-vote-per-validator rule and is not an equivocation.
		return nil
	}
	f := &consensus.Vote{
		Type: consensus.MsgPrevote, Height: v.Height, Round: v.Round,
		BlockID: eq.forgeID, Validator: v.Validator,
	}
	h := f.SigningHash()
	f.Sig = ed25519.Sign(eq.priv, h[:])
	eq.forged = append(eq.forged, f)
	return eq.inner.Broadcast(consensus.EncodeVote(f))
}

// OnMessage must forward to the wrapped transport, else the driver under the
// wrapper never receives anything and stalls for the wrong reason.
func (eq *equivocating) OnMessage(fn func(transport.Message)) { eq.inner.OnMessage(fn) }
func (eq *equivocating) Peers() []transport.PeerID            { return eq.inner.Peers() }
func (eq *equivocating) Close() error                         { return eq.inner.Close() }

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
		if c == nil {
			continue
		}
		_ = c.Close()
	}
}

func ms(n int64) time.Duration { return time.Duration(n) * time.Millisecond }
