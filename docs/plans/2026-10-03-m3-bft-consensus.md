# M3: BFT Consensus — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the single node that "just produces blocks" with a committee of validators that must **agree** before a block is final — and prove, under injected network failures, that they never agree on two different blocks at the same height.

**Architecture:** Two new packages. `internal/transport` defines the one interface consensus is allowed to know about — `Broadcast`, `OnMessage`, `Peers` — with a **deterministic, virtual-time simulator** behind it that can inject latency, loss, reordering and partitions from a seed. `internal/consensus` is a **pure state machine**: it never reads a clock, never starts a goroutine, and never touches the network directly. A driver feeds it messages and timeout events and carries its outgoing messages away. That separation is the whole design: it is what makes a failing consensus run reproducible, and what keeps M4's real networking a drop-in replacement.

**Tech Stack:** Go 1.23+, standard library only (`math/big` for weighted selection, `math/rand` seeded for the simulator). No new dependencies.

**Spec:** `docs/2026-10-02-b10coin-design.md` — §6.3 (consensus) is the authority, and §9.1 (the deterministic simulation harness) defines how it must be verified.

**Prerequisites:** M0–M1 and M2 are complete and merged into `main`. The chain, state machine, crash-tolerant store, mempool, RPC, node loop, devnet driver and the faucet all work, and `go run ./cmd/b10coin devnet --blocks 100` prints `OK`.

## Global Constraints

- **Module path:** `github.com/cti97/b10coincom`
- **Go floor:** `go 1.23`. Two direct external modules (`lukechampine.com/blake3`, `golang.org/x/crypto`). **No others.**
- **Consensus must be deterministic.** The same sequence of (message, timeout) events must produce byte-identical outgoing messages and state on every run and every machine. No wall clock, no goroutines, no map iteration order reaching a decision, no `math/rand` global functions.
- **One clock, injected.** The engine never calls `time.Now`. The driver supplies virtual time.
- **The `Transport` interface is the only network knowledge consensus has.** The engine never imports a networking type.
- **Safety over liveness.** A validator must never precommit two different blocks at the same height, even if that means the chain stalls. Stalling is recoverable; a conflicting commit is not.
- **Never two conflicting commits at one height.** That is the property this milestone exists to establish.
- Commit prefixes: `feat:`, `test:`, `fix:`, `chore:`, `docs:`.
- **Every task ends with `go test -count=1 ./...` green and a commit.** Use `-count=1`: Go caches test results, and a cached green once hid a flaky test in this project.

## Design decisions

**1. The engine is a pure state machine, and the driver owns time and the network.** `Engine` exposes `OnMessage([]byte)`, `OnTimeout(TimeoutEvent)` and `Drain() []Outbound`. It holds no clock and does no I/O. This is the single most important decision in the milestone: a state machine that called `time.Now` or spawned a timer goroutine could not be replayed from a seed, and the spec's whole verification strategy (§9.1) depends on replay.

**2. The simulator uses virtual time and a seeded PRNG, single-threaded.** `sim.Net` keeps a priority queue of pending deliveries keyed by `(deliveryTime, sequence)`, and the driver advances the clock to the next event. No goroutines means no scheduler nondeterminism. `math/rand` is used only via an explicitly seeded `*rand.Rand` stored on the network.

**3. Quorum is two-thirds of TOTAL voting power, not of online power.** A validator that is offline does not reduce the threshold; it makes quorum harder to reach. That is the standard BFT assumption (`n > 3f`) and it is what makes safety hold when a third of the set is silent. (Contrast Nano's ORV, which uses online weight — a different design with different failure modes.)

**4. The locking rule is implemented literally, and tested adversarially.** A validator that precommits block `B` at round `r` locks `(r, B)`. In any later round it prevotes only for `B`, or for a proposal at a round strictly greater than `r`. Without this, two conflicting blocks can commit at the same height — the failure the spec calls safety-critical.

**5. Proposer selection is a pure function of `(height, round, parentHash, committee)`.** Weighted round-robin by power, with the choice derived from a hash so every validator computes the same proposer without communication. A proposer-selection divergence would not lose safety, but it would stall liveness on every round, so it is pinned by a test that checks agreement across all validators.

**6. Voting power is capped per validator at 1/4 of the total.** The spec requires it: a single operator holding more than 1/3 of power could commit conflicting blocks alone. The cap keeps every operator below the threshold, and `Config.Validate` rejects a committee where the cap cannot hold.

**7. A vote for `nil` is a first-class vote.** Validators must be able to advance past a round where no proposal arrived, so `Vote.BlockID` of all-zeros means "this round produced nothing I will accept". Treating nil votes as abstentions would deadlock the chain whenever a proposer is offline.

**8. Committing is the only place consensus mutates the chain.** The engine collects precommits and reports the quorum decision through `Committed()`; the DRIVER calls `chain.Append` exactly once on that decision, then advances to the next height. The engine never touches the chain at all - it holds no chain object, because a pure state machine that did I/O could not be replayed from a seed (Design Decision 1). Consensus never speculatively applies a block, so a stalled height leaves the chain untouched.

**9. The committee is the genesis validator set, fixed for the milestone.** Epoch-bound validator-set changes are M5 (staking). M3 builds the `height → committee` seam (a `CommitteeAt(height)` function) so M5 has somewhere to plug in, but returns the genesis set for every height.

**10. `--validators N` becomes real.** The spec's §9 named `devnet --validators 4 --blocks 100` as its proof; M0–M1 could not honour it because a single node needed no agreement. M3 makes a devnet of four validators finalizing blocks the milestone's acceptance check.

**11. A locked validator unlocks ONLY on evidence, not on a round number (the justification gate).**
The spec's §6.3 phrasing — *"in any later round it prevotes only for `B` or for a proposal at a round `> r`"* — implemented literally is **not safe**, and the M3 review demonstrated the counterexample: if `B` commits at round `r` then ≥2/3 prevoted `B` at `r`, so ≥1/3 honest validators are locked on `B`; a malicious proposer then offers a conflicting `B'` at round `r+1`, and the literal rule PERMITS every one of those locked validators to prevote `B'` merely because `r+1 > r`. `B'` reaches 2/3 prevotes, then 2/3 precommits, and commits. Two conflicting commits at one height, which is exactly what the rule was written to prevent.

What actually prevents it is Tendermint's **proof of lock change**. A proposal carries a `ValidRound` and a `Justification`: the set of prevotes proving that block reached a polka (2/3 prevotes) at `ValidRound`. A locked validator prevotes a DIFFERING block only when that block's polka came from a round **strictly greater than its own lock round**:

```go
// canPrevote reports whether id may be prevoted, given that the proposal carries a
// polka for id from validRound (-1 when it carries none).
func (l *lock) canPrevote(round uint32, id [32]byte, validRound int64) bool {
	if l.lockedRound < 0 {
		return true
	}
	if id == l.lockedBlock {
		return true
	}
	return validRound > l.lockedRound
}
```

Note what changed: the unlock condition is the **block's polka round**, not the round the proposal happens to be in. A validator locked at `r` does not unlock just because time passed — it unlocks when it is shown that a supermajority moved on without it.

The lemma this restores: *if `B` committed at round `r`, no conflicting block can have a polka at any round `≥ r`.* Proof: take the first such round `r*`; the ≥1/3 honest prevotes for the conflict at `r*` would each have required a polka from a round `> ` their lock round (≥ `r`), and `r*` is the first such round, so no such polka exists yet. Contradiction. Hence no conflicting polka, hence no conflicting commit.

**The justification must be VERIFIED, not trusted.** The engine decodes the carried prevotes, tallies them against the committee, and requires both that they reach quorum and that they are for the proposal's own block ID at exactly `ValidRound`. An unverified justification would be worse than none: it would let a proposer assert an unlock that never happened.

This is a change the spec does not name, adopted because the spec's stated GOAL ("never two conflicting commits at one height") requires it and its stated RULE does not achieve it. It is recorded here as a deliberate departure.

## File structure

| File | Responsibility |
|---|---|
| `internal/transport/transport.go` | The `Transport` interface, `PeerID`, `Message` — the only network knowledge consensus has |
| `internal/transport/sim/sim.go` | The deterministic virtual-time network: latency, jitter, loss, reordering, partitions |
| `internal/consensus/message.go` | `Vote`, `Proposal`, their canonical encoding and signing |
| `internal/consensus/committee.go` | Voting power, quorum thresholds, the power cap, proposer selection |
| `internal/consensus/tally.go` | Weighted vote accumulation and quorum detection |
| `internal/consensus/engine.go` | The round state machine: PROPOSE → PREVOTE → PRECOMMIT → COMMIT |
| `internal/consensus/lock.go` | The locking rule, kept separate because it is the safety-critical part |
| `internal/consensus/driver.go` | Wires an engine to a `Transport` and a clock; used by the node and the simulator |
| `internal/consensus/scenarios_test.go` | The six scenarios §9.1 requires |
| `internal/simnet/simnet.go` | Spins up N engines over one `sim.Net`; the harness the scenarios drive |
| `cmd/b10coin/main.go` | `devnet --validators N` |

## Interfaces this milestone adds

```
transport.Transport       Broadcast, OnMessage, Peers, Close
transport.PeerID, transport.Message

sim.Net, sim.Options      deterministic virtual-time network + its failure knobs
sim.Partition(a, b)       cut the link set between two groups of peers

consensus.Config          Committee, TimeoutBase, TimeoutStep, PowerCapNum/Den
consensus.Engine          OnMessage, OnTimeout, Drain, Height, Round, Step
consensus.Step            StepPropose, StepPrevote, StepPrecommit, StepCommit
consensus.Outbound        To, Data   (To == "" means broadcast)
consensus.TimeoutEvent    Height, Round, Step

consensus.Quorum          2/3 of total power, as an integer threshold
consensus.Proposer        (Config) Proposer(height, round, parent) []byte
consensus.NewVoteSet      weighted tally

simnet.Net                N engines + one sim.Net + a virtual clock, driven step by step
simnet.AssertPrefix(i)    validator i's history is a strict PREFIX of the longest chain,
                          never a fork of it - the honest safety assertion for a lagging
                          validator, since M3 has no catch-up for it to reconverge with
simnet.RunBlocksAmong(n, set)  advance until only the NAMED validators reach height n, so a
                          partitioned minority does not block the majority's progress

CLI: b10coin devnet --validators N --blocks M
```

---

## Task 0: Carry-forwards from the M2 final review

Three items the M2 review tracked or deferred. All are small and independent of consensus, but they touch the node the new engine will run inside, so they land first.

**Files:**
- Modify: `internal/mempool/mempool.go`, `internal/node/node.go`, `internal/rpc/server.go`, `internal/mempool/mempool_test.go`

**Interfaces:**
- Consumes: nothing
- Produces: `mempool.Mempool.TakeWeighted`-style bounded claim admission (see below); no signature changes to existing methods

- [ ] **Step 1: Write the failing test for bounded claim admission**

The M2 final review's one Important finding: `RunOnce` applies up to `MaxTxsPerBlock` (10,000) candidates per block, and `applyFaucetClaim` runs a **full Argon2id evaluation before it can reject**. `mempool.Add` checks only the signature, so anyone who can `POST /tx` parks 10,000 correctly-signed claims with garbage `PowNonce` at one Ed25519 each, and the node pays ~one Argon2id per claim per block while holding a read lock — at the testnet tuning (64 MiB × 3) that stalls block production for hours.

Add to `internal/mempool/mempool_test.go`:

```go
// A mempool full of signature-valid faucet claims must not force the node to
// evaluate an unbounded number of Argon2id puzzles per block. At the testnet
// tuning one claim costs ~3 s of CPU, so ten thousand of them would stall block
// production for hours; the pool must bound how many claims it will hand over.
func TestTakeBoundsFaucetClaimsPerBlock(t *testing.T) {
	m := New(1000)

	// Fill the pool with claims, which are validly signed but carry no evidence
	// that their puzzle was actually solved.
	var claims []types.Tx
	for i := 0; i < 50; i++ {
		claims = append(claims, mkClaim(t, uint64(i)))
	}
	for i, err := range m.Add(claims) {
		if err != nil {
			t.Fatalf("Add[%d]: %v", i, err)
		}
	}
	// Plus ordinary transfers, which are cheap to validate.
	var transfers []types.Tx
	for i := 0; i < 20; i++ {
		transfers = append(transfers, mkTx(t, uint64(i)))
	}
	for i, err := range m.Add(transfers) {
		if err != nil {
			t.Fatalf("Add[%d]: %v", i, err)
		}
	}

	got := m.Take(types.MaxTxsPerBlock)
	var claimsTaken, transfersTaken int
	for i := range got {
		if got[i].Type == types.TxFaucetClaim {
			claimsTaken++
		} else {
			transfersTaken++
		}
	}
	if claimsTaken > MaxFaucetClaimsPerBlock {
		t.Fatalf("handed over %d faucet claims in one block, want at most %d - each costs a full Argon2id evaluation",
			claimsTaken, MaxFaucetClaimsPerBlock)
	}
	if transfersTaken != len(transfers) {
		t.Fatalf("bounded %d cheap transfers out of %d - the bound must apply to claims only",
			len(transfers), len(transfers))
	}
}
```

`mkClaim` is a helper you add alongside `mkTx`:

```go
// mkClaim builds a faucet claim with a real signature but a garbage proof-of-work
// nonce. The mempool checks only signatures, so this is exactly what a spammer can
// produce for the cost of one Ed25519 signature - which is the asymmetry the bound
// in this task exists to neutralise.
func mkClaim(t *testing.T, nonce uint64) types.Tx {
	t.Helper()
	pub, priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	tx := &types.Tx{
		Type: types.TxFaucetClaim, From: types.AddressFromPub(pub), PubKey: pub,
		Nonce: nonce, Epoch: 1, PowNonce: 0,
	}
	h := tx.SigningHash()
	tx.Sig = crypto.Sign(priv, h[:])
	return *tx
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/mempool/ -run TestTakeBoundsFaucetClaimsPerBlock -v`
Expected: FAIL — `undefined: MaxFaucetClaimsPerBlock`

- [ ] **Step 3: Implement the bound**

In `internal/mempool/mempool.go`, add:

```go
// MaxFaucetClaimsPerBlock bounds how many faucet claims the pool will hand to a
// single block. A claim costs a full Argon2id evaluation to verify - ~3 s at the
// testnet tuning - while costing a submitter one Ed25519 signature, so without a
// bound a full pool of signature-valid claims with garbage proofs would stall
// block production for hours. Ordinary transactions are not bounded here: they
// are cheap to validate and the block size limits already cap them.
const MaxFaucetClaimsPerBlock = 8
```

Then split `Take` so the claim bound applies only to claims while the total still respects `max`. Keep `Take`'s existing contract for the non-claim case (every test in the package must still pass): it returns up to `max` transactions, claims first encountered beyond the bound are skipped and **left in the pool** rather than dropped, and the slice is drawn in insertion order.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -count=1 ./internal/mempool/ -v`
Expected: PASS, including every pre-existing test.

- [ ] **Step 5: Add HTTP server timeouts and document the probe contract**

`internal/rpc/server.go` already has a `Server`; give the `http.Server` construction in `cmd/b10coin/main.go` `ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout` and `IdleTimeout` if they are absent (check first — M0–M1's polish batch may have added them; if so, skip this step and say so in your report).

- [ ] **Step 6: Run the full suite and the acceptance check**

Run: `go test -count=1 ./... && go run ./cmd/b10coin devnet --blocks 100`
Expected: all packages PASS; the devnet prints `OK` and exits 0. The state root must be **unchanged** — this task adds no consensus behaviour.

- [ ] **Step 7: Commit**

```bash
git add internal/mempool internal/node internal/rpc cmd/b10coin
git commit -m "fix: bound faucet claims per block so a full pool cannot stall production

A claim costs a full Argon2id evaluation to verify while costing a submitter
one signature, so a pool of signature-valid claims with garbage proofs made
block production an Argon2id cost amplifier - hours per block at the testnet
tuning. Bounds the claim count handed to one block, leaving cheap
transactions unbounded. Carried forward from the M2 final review."
```

---

## Task 1: Consensus messages

**Files:**
- Create: `internal/consensus/message.go`, `internal/consensus/message_test.go`

**Interfaces:**
- Consumes: `types.Address`, `types.Encoder`/`Decoder`, `crypto.HashParts`, `crypto.Sign`/`Verify`
- Produces: `consensus.MsgType` with `MsgProposal`, `MsgPrevote`, `MsgPrecommit`; `consensus.Vote`, `consensus.Proposal`; `EncodeVote`/`DecodeVote`, `EncodeProposal`/`DecodeProposal`; `(*Vote).SigningHash`, `(*Vote).Verify`, and the same on `Proposal`

- [ ] **Step 1: Write the failing tests**

Create `internal/consensus/message_test.go`:

```go
package consensus

import (
	"errors"
	"testing"

	"github.com/cti97/b10coincom/internal/crypto"
)

func testKey(t *testing.T) ([]byte, []byte) {
	t.Helper()
	pub, priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func signedVote(t *testing.T, typ MsgType, height uint64, round uint32, blockID [32]byte) *Vote {
	t.Helper()
	pub, priv := testKey(t)
	v := &Vote{Type: typ, Height: height, Round: round, BlockID: blockID, Validator: pub}
	h := v.SigningHash()
	v.Sig = crypto.Sign(priv, h[:])
	return v
}

func TestVoteRoundTrips(t *testing.T) {
	var id [32]byte
	id[0] = 9
	v := signedVote(t, MsgPrecommit, 7, 3, id)

	got, err := DecodeVote(EncodeVote(v))
	if err != nil {
		t.Fatalf("DecodeVote: %v", err)
	}
	if got.Type != v.Type || got.Height != v.Height || got.Round != v.Round || got.BlockID != v.BlockID {
		t.Fatalf("round trip lost fields:\n got %+v\nwant %+v", got, v)
	}
	if string(got.Validator) != string(v.Validator) || string(got.Sig) != string(v.Sig) {
		t.Fatal("round trip lost key material")
	}
}

// The signature must cover every field that affects meaning: a validator that
// signed a prevote for block A at round 1 must not be quotable as having
// precommitted block B at round 9.
func TestVoteSignatureCoversEveryField(t *testing.T) {
	var id [32]byte
	id[0] = 9
	v := signedVote(t, MsgPrevote, 7, 3, id)
	base := v.SigningHash()

	cases := map[string]func(*Vote){
		"type":    func(x *Vote) { x.Type = MsgPrecommit },
		"height":  func(x *Vote) { x.Height = 8 },
		"round":   func(x *Vote) { x.Round = 4 },
		"blockID": func(x *Vote) { x.BlockID[0] = 10 },
	}
	for name, mutate := range cases {
		c := *v // a COPY, so every other byte of the signed body stays constant
		mutate(&c)
		if c.SigningHash() == base {
			t.Errorf("SigningHash ignored the %s field", name)
		}
	}
}

func TestVoteVerifyRejectsTampering(t *testing.T) {
	var id [32]byte
	v := signedVote(t, MsgPrevote, 7, 3, id)
	if err := v.Verify(); err != nil {
		t.Fatalf("valid vote rejected: %v", err)
	}
	v.Height = 8
	if err := v.Verify(); !errors.Is(err, ErrBadVoteSignature) {
		t.Fatalf("expected ErrBadVoteSignature, got %v", err)
	}
}

// A nil vote (all-zero BlockID) is a first-class vote: validators must be able to
// advance past a round in which no proposal arrived.
func TestNilVoteRoundTrips(t *testing.T) {
	v := signedVote(t, MsgPrevote, 5, 2, [32]byte{})
	if err := v.Verify(); err != nil {
		t.Fatalf("nil vote rejected: %v", err)
	}
	got, err := DecodeVote(EncodeVote(v))
	if err != nil {
		t.Fatal(err)
	}
	if got.BlockID != ([32]byte{}) {
		t.Fatal("nil vote did not round trip as nil")
	}
	if !got.IsNil() {
		t.Fatal("IsNil should be true for an all-zero BlockID")
	}
}

func TestDecodeVoteRejectsMalformed(t *testing.T) {
	v := signedVote(t, MsgPrevote, 7, 3, [32]byte{})
	enc := EncodeVote(v)
	if _, err := DecodeVote(append(enc, 0xFF)); err == nil {
		t.Fatal("trailing bytes must be rejected")
	}
	if _, err := DecodeVote(enc[:len(enc)-1]); err == nil {
		t.Fatal("a truncated encoding must be rejected")
	}
	if _, err := DecodeVote([]byte{0xFF}); err == nil {
		t.Fatal("an unknown message type must be rejected")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/consensus/ -v`
Expected: FAIL — `undefined: Vote`

- [ ] **Step 3: Write the implementation**

Create `internal/consensus/message.go`:

```go
// Package consensus implements b10coin's Byzantine-fault-tolerant agreement.
//
// The engine is a PURE STATE MACHINE. It never reads a clock, never starts a
// goroutine, and never touches the network: the driver feeds it messages and
// timeout events and carries its outgoing messages away. That is what makes a
// failing run reproducible from a seed, and it is what lets M4 swap the
// in-process simulator for real sockets without touching this package.
package consensus

import (
	"errors"
	"fmt"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/types"
)

// MsgType discriminates the consensus message union. It is a wire value: never
// renumber these.
type MsgType uint8

const (
	MsgProposal  MsgType = 1
	MsgPrevote   MsgType = 2
	MsgPrecommit MsgType = 3
)

var (
	ErrBadVoteSignature     = errors.New("consensus: bad vote signature")
	ErrBadProposalSignature = errors.New("consensus: bad proposal signature")
	ErrUnknownMsgType       = errors.New("consensus: unknown message type")
	ErrBadValidatorKey      = errors.New("consensus: validator key cannot derive its address")
)

// Vote is one validator's signed judgement about one (height, round).
//
// An all-zero BlockID is a NIL vote: "this round produced nothing I will accept".
// Nil votes are first-class, not abstentions - without them a round whose proposer
// is offline could never be left behind, and the chain would stall forever.
type Vote struct {
	Type      MsgType
	Height    uint64
	Round     uint32
	BlockID   [32]byte
	Validator []byte // Ed25519 public key
	Sig       []byte
}

// IsNil reports whether this is a nil vote.
func (v *Vote) IsNil() bool { return v.BlockID == ([32]byte{}) }

func (v *Vote) encodeBody() []byte {
	e := types.NewEncoder()
	e.U8(uint8(v.Type))
	e.U64(v.Height)
	e.U32(v.Round)
	e.Fixed32(v.BlockID)
	e.VarBytes(v.Validator)
	return e.Bytes()
}

// SigningHash covers every field that carries meaning, so a validator cannot be
// quoted as having said something it did not.
func (v *Vote) SigningHash() [32]byte {
	return crypto.HashParts([]byte("b10coin-vote"), v.encodeBody())
}

func EncodeVote(v *Vote) []byte {
	e := types.NewEncoder()
	e.Raw(v.encodeBody())
	e.VarBytes(v.Sig)
	return e.Bytes()
}

func DecodeVote(b []byte) (*Vote, error) {
	d := types.NewDecoder(b)
	rawType, err := d.U8()
	if err != nil {
		return nil, err
	}
	v := &Vote{Type: MsgType(rawType)}
	switch v.Type {
	case MsgPrevote, MsgPrecommit:
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnknownMsgType, rawType)
	}
	if v.Height, err = d.U64(); err != nil {
		return nil, err
	}
	if v.Round, err = d.U32(); err != nil {
		return nil, err
	}
	if v.BlockID, err = d.Fixed32(); err != nil {
		return nil, err
	}
	if v.Validator, err = d.VarBytes(); err != nil {
		return nil, err
	}
	if v.Sig, err = d.VarBytes(); err != nil {
		return nil, err
	}
	if err := d.Done(); err != nil {
		return nil, err
	}
	return v, nil
}

// Verify checks the signature against the validator key carried in the vote.
// Callers must separately check that the key is in the committee.
func (v *Vote) Verify() error {
	if len(v.Validator) == 0 {
		return fmt.Errorf("%w: missing validator key", ErrBadVoteSignature)
	}
	h := v.SigningHash()
	if !crypto.Verify(v.Validator, h[:], v.Sig) {
		return ErrBadVoteSignature
	}
	return nil
}

// Proposal is a block offered for a (height, round) together with its proposer's
// signature over the header.
type Proposal struct {
	Height    uint64
	Round     uint32
	Block     types.Block
	Validator []byte // the proposer's Ed25519 public key
	Sig       []byte // over Block.Header.SigningHash()
}

func (p *Proposal) SigningHash() [32]byte { return p.Block.Header.SigningHash() }

func (p *Proposal) Verify() error {
	if len(p.Validator) == 0 {
		return fmt.Errorf("%w: missing proposer key", ErrBadProposalSignature)
	}
	if string(p.Validator) != string(p.Block.Header.Proposer) {
		return fmt.Errorf("%w: key does not match the header's proposer", ErrBadProposalSignature)
	}
	h := p.SigningHash()
	if !crypto.Verify(p.Validator, h[:], p.Sig) {
		return ErrBadProposalSignature
	}
	return nil
}

// EncodeProposal renders a proposal canonically. The block is length-prefixed so
// the envelope frames it the same way DecodeProposal reads it back.
func EncodeProposal(p *Proposal) []byte {
	e := types.NewEncoder()
	e.U8(uint8(MsgProposal))
	e.U64(p.Height)
	e.U32(p.Round)
	e.VarBytes(p.Block.Encode())
	e.VarBytes(p.Validator)
	e.VarBytes(p.Sig)
	return e.Bytes()
}

func DecodeProposal(b []byte) (*Proposal, error) {
	d := types.NewDecoder(b)
	rawType, err := d.U8()
	if err != nil {
		return nil, err
	}
	if MsgType(rawType) != MsgProposal {
		return nil, fmt.Errorf("%w: %d", ErrUnknownMsgType, rawType)
	}
	p := &Proposal{}
	if p.Height, err = d.U64(); err != nil {
		return nil, err
	}
	if p.Round, err = d.U32(); err != nil {
		return nil, err
	}
	raw, err := d.VarBytes()
	if err != nil {
		return nil, err
	}
	blk, err := types.DecodeBlock(raw)
	if err != nil {
		return nil, err
	}
	p.Block = *blk
	if p.Validator, err = d.VarBytes(); err != nil {
		return nil, err
	}
	if p.Sig, err = d.VarBytes(); err != nil {
		return nil, err
	}
	if err := d.Done(); err != nil {
		return nil, err
	}
	return p, nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -count=1 ./internal/consensus/ -v`
Expected: PASS for all six tests.

- [ ] **Step 5: Commit**

```bash
git add internal/consensus
git commit -m "feat: add consensus messages with field-covering signatures"
```

---

## Task 2: The transport interface and the deterministic simulator

**Files:**
- Create: `internal/transport/transport.go`, `internal/transport/sim/sim.go`, `internal/transport/sim/sim_test.go`

**Interfaces:**
- Consumes: `crypto`
- Produces: `transport.Transport`, `transport.PeerID`, `transport.Message`; `sim.Options`, `sim.New`, `(*sim.Net).AddPeer`, `(*sim.Net).TransportFor`, `(*sim.Net).Advance`, `(*sim.Net).Now`, `(*sim.Net).Partition`

- [ ] **Step 1: Write the interface**

Create `internal/transport/transport.go`:

```go
// Package transport is the network boundary that consensus is allowed to know
// about, and nothing more. The engine never imports a networking type: it calls
// Broadcast, receives through OnMessage, and lists Peers. That boundary is what
// lets the deterministic simulator, the M4 outbound relay and a future libp2p
// stack be swapped without touching consensus code.
package transport

// PeerID identifies a connected peer.
type PeerID string

// Message is one received payload with its sender.
type Message struct {
	From PeerID
	Data []byte
}

// Transport moves opaque bytes between peers.
//
// Implementations MUST NOT deliver synchronously from within Broadcast: the
// sender's callback re-entering the engine mid-send would make the order of
// state transitions depend on the transport's internals. Queue instead.
type Transport interface {
	// Broadcast sends data to every connected peer except the sender.
	Broadcast(data []byte) error
	// OnMessage registers the callback invoked once per received message.
	OnMessage(fn func(Message))
	// Peers lists the currently connected peers.
	Peers() []PeerID
	// Close releases the transport's resources.
	Close() error
}
```

- [ ] **Step 2: Write the failing simulator tests**

Create `internal/transport/sim/sim_test.go`:

```go
package sim

import (
	"fmt"
	"testing"
	"time"
)

// collect returns a helper that records every message a peer receives.
func collect(n *Net, id string) *[]string {
	got := new([]string)
	n.TransportFor(id).OnMessage(func(m Message) {
		*got = append(*got, string(m.Data))
	})
	return got
}

// The whole point of the simulator: the same seed produces the same delivery
// order, so a failing consensus run can be replayed exactly.
func TestSameSeedReplaysIdentically(t *testing.T) {
	run := func() []string {
		n := New(Options{Seed: 42, Latency: 10 * time.Millisecond, Jitter: 5 * time.Millisecond})
		for _, id := range []string{"a", "b", "c", "d"} {
			n.AddPeer(id)
		}
		var seen []string
		n.TransportFor("a").OnMessage(func(m Message) { seen = append(seen, string(m.Data)) })
		n.TransportFor("b").Broadcast([]byte("x"))
		n.TransportFor("c").Broadcast([]byte("y"))
		n.TransportFor("d").Broadcast([]byte("z"))
		n.Advance(100 * time.Millisecond)
		return seen
	}
	first, second := run(), run()
	if fmt.Sprint(first) != fmt.Sprint(second) {
		t.Fatalf("same seed diverged:\n %v\n %v", first, second)
	}
	if len(first) == 0 {
		t.Fatal("no messages were delivered at all")
	}
}

func TestBroadcastSkipsTheSender(t *testing.T) {
	n := New(Options{Seed: 1, Latency: time.Millisecond})
	for _, id := range []string{"a", "b"} {
		n.AddPeer(id)
	}
	gotA := collect(n, "a")
	gotB := collect(n, "b")
	n.TransportFor("a").Broadcast([]byte("hello"))
	n.Advance(50 * time.Millisecond)

	if len(*gotA) != 0 {
		t.Fatalf("the sender received its own broadcast: %v", *gotA)
	}
	if len(*gotB) != 1 || (*gotB)[0] != "hello" {
		t.Fatalf("the peer did not receive the broadcast: %v", *gotB)
	}
}

// 100% loss must deliver nothing, which is how a scenario takes a validator
// fully offline without removing it from the peer set.
func TestFullPacketLossDeliversNothing(t *testing.T) {
	n := New(Options{Seed: 7, Latency: time.Millisecond, DropPercent: 100})
	for _, id := range []string{"a", "b"} {
		n.AddPeer(id)
	}
	got := collect(n, "b")
	for i := 0; i < 20; i++ {
		n.TransportFor("a").Broadcast([]byte("dropped"))
	}
	n.Advance(time.Second)
	if len(*got) != 0 {
		t.Fatalf("messages were delivered under 100%% loss: %v", *got)
	}
}

// A partition must cut the two groups apart, and healing it must restore delivery.
func TestPartitionCutsDeliveryAndHeals(t *testing.T) {
	n := New(Options{Seed: 3, Latency: time.Millisecond})
	for _, id := range []string{"a", "b", "c"} {
		n.AddPeer(id)
	}
	gotA := collect(n, "a")

	n.Partition([]string{"a"}, []string{"b", "c"})
	n.TransportFor("b").Broadcast([]byte("blocked"))
	n.Advance(50 * time.Millisecond)
	if len(*gotA) != 0 {
		t.Fatalf("a message crossed a partition: %v", *gotA)
	}

	n.Heal()
	n.TransportFor("b").Broadcast([]byte("through"))
	n.Advance(50 * time.Millisecond)
	if len(*gotA) != 1 || (*gotA)[0] != "through" {
		t.Fatalf("delivery did not resume after healing: %v", *gotA)
	}
}

// Broadcast must not deliver synchronously: a transport that re-entered the
// caller during Broadcast would make consensus's transition order depend on the
// transport's internals.
func TestBroadcastDoesNotDeliverSynchronously(t *testing.T) {
	n := New(Options{Seed: 5, Latency: 0})
	for _, id := range []string{"a", "b"} {
		n.AddPeer(id)
	}
	got := collect(n, "b")
	n.TransportFor("a").Broadcast([]byte("now"))
	if len(*got) != 0 {
		t.Fatal("Broadcast delivered synchronously; it must queue")
	}
	n.Advance(time.Millisecond)
	if len(*got) != 1 {
		t.Fatal("the queued message was never delivered")
	}
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `go test ./internal/transport/... -v`
Expected: FAIL — `undefined: New`

- [ ] **Step 4: Write the simulator**

Create `internal/transport/sim/sim.go`:

```go
// Package sim is a deterministic, virtual-time network. It is what makes the
// spec's verification strategy possible: N validators run in one process over an
// injected-latency, lossy, reordering, partitionable network, all driven by a
// seed, so any failure replays exactly.
//
// Two properties matter more than realism:
//
//   - SINGLE-THREADED. No goroutines, no channels, no sleeps. The driver advances
//     virtual time and the network delivers whatever is now due, in a fixed order.
//     Goroutine scheduling would make runs irreproducible.
//   - THE SEED IS THE ONLY RANDOMNESS. Every jitter, drop and reorder decision comes
//     from one explicitly seeded *rand.Rand stored on the Net.
package sim

import (
	"math/rand"
	"sort"
	"time"

	"github.com/cti97/b10coincom/internal/transport"
)

// Options configures the simulated network's failure behaviour.
type Options struct {
	Seed        int64         // the only source of randomness
	Latency     time.Duration // base one-way delay
	Jitter      time.Duration // uniform extra delay in [0, Jitter)
	DropPercent int           // 0..100, applied per delivery
	Reorder     bool          // if true, delivery order need not match send order
}

// pending is one message waiting for its delivery time.
type pending struct {
	at   time.Duration
	seq  uint64
	to   transport.PeerID
	from transport.PeerID
	data []byte
}

// Net is a deterministic network over virtual time.
type Net struct {
	opts  Options
	rng   *rand.Rand
	now   time.Duration
	seq   uint64
	peers map[transport.PeerID]*endpoint
	group map[transport.PeerID]int // partition group; equal groups can talk
	queue []pending
}

type endpoint struct {
	id  transport.PeerID
	net *Net
	fn  func(transport.Message)
}

// New creates a network. The seed fixes every subsequent decision.
func New(opts Options) *Net {
	return &Net{
		opts:  opts,
		rng:   rand.New(rand.NewSource(opts.Seed)),
		peers: make(map[transport.PeerID]*endpoint),
		group: make(map[transport.PeerID]int),
	}
}

// Now reports virtual time. It is the ONLY clock the simulator has.
func (n *Net) Now() time.Duration { return n.now }

// AddPeer registers a peer. All peers start in partition group 0.
func (n *Net) AddPeer(id string) {
	pid := transport.PeerID(id)
	n.peers[pid] = &endpoint{id: pid, net: n}
	n.group[pid] = 0
}

// TransportFor returns the transport handle for a peer.
func (n *Net) TransportFor(id string) *endpoint { return n.peers[transport.PeerID(id)] }

// Partition puts group A in one partition and group B in another. Messages
// between the groups are dropped; messages within a group still flow.
func (n *Net) Partition(a, b []string) {
	for _, id := range a {
		n.group[transport.PeerID(id)] = 1
	}
	for _, id := range b {
		n.group[transport.PeerID(id)] = 2
	}
}

// Heal puts every peer back in one partition.
func (n *Net) Heal() {
	for id := range n.group {
		n.group[id] = 0
	}
}

// Advance runs virtual time forward by d, delivering everything that becomes due.
// Deliveries happen in (at, seq) order, so the schedule is a total order and the
// run is reproducible.
func (n *Net) Advance(d time.Duration) {
	target := n.now + d
	for {
		next := -1
		for i := range n.queue {
			if n.queue[i].at > target {
				continue
			}
			if next < 0 || less(n.queue[i], n.queue[next]) {
				next = i
			}
		}
		if next < 0 {
			break
		}
		m := n.queue[next]
		n.queue = append(n.queue[:next], n.queue[next+1:]...)
		n.now = m.at
		if e := n.peers[m.to]; e != nil && e.fn != nil {
			e.fn(transport.Message{From: m.from, Data: m.data})
		}
	}
	n.now = target
}

// less orders deliveries by time, then by send sequence, so ties break the same
// way on every run.
func less(a, b pending) bool {
	if a.at != b.at {
		return a.at < b.at
	}
	return a.seq < b.seq
}

func (e *endpoint) Broadcast(data []byte) error {
	for id := range e.net.peers {
		if id == e.id {
			continue // a peer never receives its own broadcast
		}
		if e.net.group[id] != e.net.group[e.id] {
			continue // partitioned away
		}
		if e.net.opts.DropPercent > 0 && e.net.rng.Intn(100) < e.net.opts.DropPercent {
			continue
		}
		at := e.net.now + e.net.opts.Latency
		if e.net.opts.Jitter > 0 {
			at += time.Duration(e.net.rng.Int63n(int64(e.net.opts.Jitter)))
		}
		e.net.seq++
		e.net.queue = append(e.net.queue, pending{
			at: at, seq: e.net.seq, to: id, from: e.id, data: append([]byte(nil), data...),
		})
	}
	if e.net.opts.Reorder {
		// Shuffle the queue deterministically so delivery order need not match
		// send order; ordering is then pinned only by (at, seq) as usual.
		e.net.rng.Shuffle(len(e.net.queue), func(i, j int) {
			e.net.queue[i], e.net.queue[j] = e.net.queue[j], e.net.queue[i]
		})
	}
	return nil
}

func (e *endpoint) OnMessage(fn func(transport.Message)) { e.fn = fn }

func (e *endpoint) Peers() []transport.PeerID {
	out := make([]transport.PeerID, 0, len(e.net.peers))
	for id := range e.net.peers {
		if id != e.id {
			out = append(out, id)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] }) // deterministic order
	return out
}

func (e *endpoint) Close() error { return nil }
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test -count=1 ./internal/transport/... -v`
Expected: PASS for all five tests.

- [ ] **Step 6: Commit**

```bash
git add internal/transport
git commit -m "feat: add the transport interface and a deterministic virtual-time simulator"
```

---

## Task 3: Committee, power, quorum and proposer selection

**Files:**
- Create: `internal/consensus/committee.go`, `internal/consensus/committee_test.go`

**Interfaces:**
- Consumes: `genesis.Validator`, `crypto.HashParts`, `types.Encoder`
- Produces: `consensus.Committee`, `consensus.Config`; `(Config).Validate`, `(Config).TotalPower`, `(Config).Quorum`, `(Config).CommitteeAt(height)`, `(Config).IndexOf(pub)`, `(Config).Proposer(height, round, parent)`

- [ ] **Step 1: Write the failing tests**

Create `internal/consensus/committee_test.go`:

```go
package consensus

import (
	"testing"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/genesis"
)

// evenCommittee builds n validators of equal power, with deterministic keys so a
// failure is reproducible.
func evenCommittee(t *testing.T, n int, power uint64) Config {
	t.Helper()
	vals := make([]genesis.Validator, 0, n)
	for i := 0; i < n; i++ {
		h := crypto.HashParts([]byte("b10coin-test-validator"), []byte{byte(i)})
		priv := ed25519FromSeed(h)
		vals = append(vals, genesis.Validator{PubKey: priv.Public().(ed25519PublicKey), Power: power})
	}
	c := Config{Committee: vals, TimeoutBase: 1, TimeoutStep: 1, PowerCapNum: 1, PowerCapDen: 4}
	if err := c.Validate(); err != nil {
		t.Fatalf("even committee rejected: %v", err)
	}
	return c
}

func TestQuorumIsTwoThirdsPlusOne(t *testing.T) {
	cases := []struct {
		total    uint64
		want     uint64
	}{
		{4, 3},    // n=4 equal power: >2/3 means at least 3
		{21, 15},  // 21 validators: 2*21/3 + 1 = 15
		{100, 67}, // 2*100/3 + 1 = 67
		{3, 3},    // 2*3/3 + 1 = 3
	}
	for _, tc := range cases {
		if got := quorumFor(tc.total); got != tc.want {
			t.Errorf("quorumFor(%d) = %d, want %d", tc.total, got, tc.want)
		}
	}
}

// Two thirds of TOTAL power, not of online power: an offline validator must make
// quorum HARDER, not easier. If the threshold tracked online weight, taking a
// third of the set offline would lower the bar enough to commit alone.
func TestQuorumDoesNotShrinkWhenValidatorsGoOffline(t *testing.T) {
	c := evenCommittee(t, 4, 1)
	if got := c.Quorum(); got != 3 {
		t.Fatalf("quorum of a 4-validator committee = %d, want 3", got)
	}
}

func TestValidateRejectsAnOverPoweredValidator(t *testing.T) {
	c := evenCommittee(t, 4, 1)
	c.Committee[0].Power = 100 // far above a quarter of the total
	if err := c.Validate(); err == nil {
		t.Fatal("expected a committee with one validator above the power cap to be rejected")
	}
}

func TestValidateRejectsAnEmptyCommittee(t *testing.T) {
	c := Config{TimeoutBase: 1, TimeoutStep: 1, PowerCapNum: 1, PowerCapDen: 4}
	if err := c.Validate(); err == nil {
		t.Fatal("expected an empty committee to be rejected")
	}
}

// The property every validator must agree on without communicating: a proposer
// selection divergence would not lose safety but would stall liveness every round.
func TestProposerIsDeterministicAcrossValidators(t *testing.T) {
	c := evenCommittee(t, 4, 1)
	parent := crypto.HashParts([]byte("parent"))
	for h := uint64(0); h < 5; h++ {
		for r := uint32(0); r < 3; r++ {
			first := c.Proposer(h, r, parent)
			for i := 0; i < 10; i++ {
				if string(c.Proposer(h, r, parent)) != string(first) {
					t.Fatalf("proposer selection is not deterministic at (%d,%d)", h, r)
				}
			}
		}
	}
}

func TestProposerChangesWithHeightRoundAndParent(t *testing.T) {
	c := evenCommittee(t, 4, 1)
	p := crypto.HashParts([]byte("parent"))
	q := crypto.HashParts([]byte("other"))

	base := c.Proposer(1, 0, p)
	// Across enough heights and rounds the proposer must vary, or one validator
	// would propose every block and the others would never get their turn.
	distinct := map[string]bool{string(base): true}
	for h := uint64(0); h < 32; h++ {
		for r := uint32(0); r < 4; r++ {
			distinct[string(c.Proposer(h, r, p))] = true
		}
	}
	if len(distinct) < 3 {
		t.Fatalf("proposer selection used only %d of 4 validators across 128 rounds", len(distinct))
	}
	if string(c.Proposer(1, 0, p)) == string(c.Proposer(1, 0, q)) &&
		string(c.Proposer(1, 0, p)) == string(c.Proposer(2, 0, p)) {
		t.Fatal("proposer ignored height and parent entirely")
	}
}

// Weighted selection must favour the heavier validator, or power would be
// decorative.
func TestProposerFavoursHeavierValidators(t *testing.T) {
	c := evenCommittee(t, 2, 1)
	c.Committee[0].Power = 3 // 3:1 in favour of the first validator
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	parent := crypto.HashParts([]byte("parent"))
	counts := map[string]int{}
	for h := uint64(0); h < 400; h++ {
		counts[string(c.Proposer(h, 0, parent))]++
	}
	first := string(c.Committee[0].PubKey)
	if counts[first] <= 400/2 {
		t.Fatalf("a validator with 3 of 4 power proposed only %d of 400 times", counts[first])
	}
}
```

Add these two helpers at the top of `committee_test.go` (they exist only so the fixture reads cleanly):

```go
func ed25519FromSeed(seed [32]byte) ed25519PrivateKey { return ed25519NewKeyFromSeed(seed[:]) }
```

and a tiny `internal/consensus/testkeys_test.go` that aliases the standard library so the fixture above stays readable:

```go
package consensus

import "crypto/ed25519"

type (
	ed25519PrivateKey = ed25519.PrivateKey
	ed25519PublicKey  = ed25519.PublicKey
)

func ed25519NewKeyFromSeed(seed []byte) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(seed) }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/consensus/ -v`
Expected: FAIL — `undefined: Config`

- [ ] **Step 3: Write the implementation**

Create `internal/consensus/committee.go`:

```go
package consensus

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/types"
)

var (
	ErrEmptyCommittee = errors.New("consensus: committee must not be empty")
	ErrPowerCap       = errors.New("consensus: a validator holds more than the permitted share of voting power")
	ErrNotValidator   = errors.New("consensus: key is not in the committee")
)

// Config is the consensus parameters a validator needs. It is derived from the
// genesis of the chain it is validating.
type Config struct {
	Committee []genesis.Validator

	// TimeoutBase is the round-0 timeout and TimeoutStep the extra time added per
	// further round. Timeouts must grow, or a slow network would thrash through
	// rounds faster than messages can arrive.
	TimeoutBase int64 // in milliseconds; int64 so the engine stays clock-free
	TimeoutStep int64

	// PowerCapNum/PowerCapDen bound any one validator's share of total power. The
	// spec requires 1/4: a validator holding more than a third could commit
	// conflicting blocks alone, so the cap keeps every operator below it.
	PowerCapNum uint64
	PowerCapDen uint64
}

// Validate rejects a committee the engine could not run safely.
func (c Config) Validate() error {
	if len(c.Committee) == 0 {
		return ErrEmptyCommittee
	}
	total := c.TotalPower()
	if total == 0 {
		return ErrEmptyCommittee
	}
	if c.PowerCapDen == 0 {
		return fmt.Errorf("%w: zero power-cap denominator", ErrPowerCap)
	}
	// power * den > total * num  <=>  power/total > num/den
	for i, v := range c.Committee {
		if v.Power == 0 {
			return fmt.Errorf("%w: validator %d has zero power", ErrEmptyCommittee, i)
		}
		if v.Power*c.PowerCapDen > total*c.PowerCapNum {
			return fmt.Errorf("%w: validator %d holds %d of %d", ErrPowerCap, i, v.Power, total)
		}
	}
	return nil
}

// TotalPower is the sum of every validator's voting power.
func (c Config) TotalPower() uint64 {
	var t uint64
	for _, v := range c.Committee {
		t += v.Power
	}
	return t
}

// Quorum is the power required to commit: two thirds of TOTAL power, plus one so
// the boundary is strictly greater.
//
// It is deliberately NOT two thirds of ONLINE power. Taking validators offline
// must make quorum harder, not easier - otherwise an attacker who silences a
// third of the set would lower the bar far enough to commit alone.
func (c Config) Quorum() uint64 { return quorumFor(c.TotalPower()) }

func quorumFor(total uint64) uint64 { return 2*total/3 + 1 }

// CommitteeAt returns the committee that validates a height. Validator-set
// changes take effect at epoch boundaries in M5 (staking); until then this is the
// genesis set at every height, and the seam exists so M5 has somewhere to plug in
// without touching the engine.
func (c Config) CommitteeAt(height uint64) []genesis.Validator { return c.Committee }

// IndexOf returns the committee index of a public key, or -1.
func (c Config) IndexOf(pub []byte) int {
	for i := range c.Committee {
		if string(c.Committee[i].PubKey) == string(pub) {
			return i
		}
	}
	return -1
}

// Proposer returns the validator that proposes at (height, round), chosen by
// weighted round-robin over voting power.
//
// The choice is a pure function of the arguments, so every validator computes the
// same proposer with no communication. The parent hash seeds it so an adversary
// cannot predict or bias the order far ahead; height and round advance it.
//
// A divergence here would not break safety - the other validators would simply
// refuse to prevote - but it would stall liveness on every round, which is why it
// is pinned by a test.
func (c Config) Proposer(height uint64, round uint32, parent [32]byte) []byte {
	e := types.NewEncoder()
	e.U64(height)
	e.U32(round)
	e.Fixed32(parent)
	seed := crypto.HashParts([]byte("b10coin-proposer"), e.Bytes())

	total := c.TotalPower()
	pick := new(big.Int).Mod(new(big.Int).SetBytes(seed[:]), new(big.Int).SetUint64(total)).Uint64()

	var cum uint64
	for i := range c.Committee {
		cum += c.Committee[i].Power
		if pick < cum {
			return c.Committee[i].PubKey
		}
	}
	return c.Committee[len(c.Committee)-1].PubKey // unreachable: pick < total
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -count=1 ./internal/consensus/ -v`
Expected: PASS for all seven tests.

- [ ] **Step 5: Commit**

```bash
git add internal/consensus
git commit -m "feat: add committee power, quorum and deterministic proposer selection"
```

---

## Task 4: The weighted vote tally

**Files:**
- Create: `internal/consensus/tally.go`, `internal/consensus/tally_test.go`

**Interfaces:**
- Consumes: `Vote`, `Config`
- Produces: `consensus.VoteSet`; `NewVoteSet(cfg, height, round, typ)`; `(*VoteSet).Add(v *Vote) (added bool, err error)`; `(*VoteSet).PowerFor(blockID [32]byte) uint64`; `(*VoteSet).HasQuorum(blockID [32]byte) bool`; `(*VoteSet).NilPower() uint64`; `(*VoteSet).AnyQuorum() ([32]byte, bool)`

- [ ] **Step 1: Write the failing tests**

Create `internal/consensus/tally_test.go`:

```go
package consensus

import (
	"errors"
	"testing"
)

func voteFrom(t *testing.T, cfg Config, idx int, typ MsgType, height uint64, round uint32, id [32]byte) *Vote {
	t.Helper()
	// Re-sign with the committee member's own key so the tally's signature check
	// and committee check both pass for the validator we intend.
	pub := cfg.Committee[idx].PubKey
	v := &Vote{Type: typ, Height: height, Round: round, BlockID: id, Validator: pub}
	v.Sig = testSign(t, idx, v.SigningHash())
	return v
}

func TestTallyCountsWeightOncePerValidator(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	var id [32]byte
	id[0] = 1
	vs := NewVoteSet(cfg, 1, 0, MsgPrevote)

	for i := 0; i < 3; i++ {
		added, err := vs.Add(voteFrom(t, cfg, i, MsgPrevote, 1, 0, id))
		if err != nil || !added {
			t.Fatalf("validator %d: added=%v err=%v", i, added, err)
		}
	}
	if got := vs.PowerFor(id); got != 3 {
		t.Fatalf("power for the block = %d, want 3", got)
	}
	if !vs.HasQuorum(id) {
		t.Fatal("3 of 4 votes should meet the quorum of 3")
	}
}

// A validator that votes twice must not be counted twice. Double-counting would
// let two validators manufacture a quorum of four.
func TestTallyIgnoresAValidatorsSecondVote(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	var id [32]byte
	id[0] = 1
	vs := NewVoteSet(cfg, 1, 0, MsgPrevote)

	if _, err := vs.Add(voteFrom(t, cfg, 0, MsgPrevote, 1, 0, id)); err != nil {
		t.Fatal(err)
	}
	added, err := vs.Add(voteFrom(t, cfg, 0, MsgPrevote, 1, 0, id))
	if err != nil {
		t.Fatalf("a duplicate must be ignored, not rejected as an error: %v", err)
	}
	if added {
		t.Fatal("a validator's second vote was counted again")
	}
	if got := vs.PowerFor(id); got != 1 {
		t.Fatalf("power = %d after a duplicate, want 1", got)
	}
}

func TestTallyRejectsBadSignatureAndNonMembers(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	var id [32]byte
	id[0] = 1

	vs := NewVoteSet(cfg, 1, 0, MsgPrevote)
	bad := voteFrom(t, cfg, 0, MsgPrevote, 1, 0, id)
	bad.Height = 99 // invalidates the signature
	if _, err := vs.Add(bad); !errors.Is(err, ErrBadVoteSignature) {
		t.Fatalf("expected ErrBadVoteSignature, got %v", err)
	}

	stranger, priv := testKey(t)
	sv := &Vote{Type: MsgPrevote, Height: 1, Round: 0, BlockID: id, Validator: stranger}
	h := sv.SigningHash()
	sv.Sig = testSignRaw(t, priv, h)
	if _, err := vs.Add(sv); !errors.Is(err, ErrNotValidator) {
		t.Fatalf("expected ErrNotValidator, got %v", err)
	}
}

func TestTallyRejectsVotesForAnotherHeightOrRound(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	var id [32]byte
	id[0] = 1

	vs := NewVoteSet(cfg, 5, 2, MsgPrevote)
	if _, err := vs.Add(voteFrom(t, cfg, 0, MsgPrevote, 6, 2, id)); err == nil {
		t.Fatal("a vote for another height must be rejected")
	}
	if _, err := vs.Add(voteFrom(t, cfg, 0, MsgPrevote, 5, 3, id)); err == nil {
		t.Fatal("a vote for another round must be rejected")
	}
}

// Nil votes are tallied separately: they matter for advancing a round, but they
// must never be mistaken for a vote for a real block.
func TestTallySeparatesNilVotes(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	var id [32]byte
	id[0] = 1
	vs := NewVoteSet(cfg, 1, 0, MsgPrevote)

	if _, err := vs.Add(voteFrom(t, cfg, 0, MsgPrevote, 1, 0, id)); err != nil {
		t.Fatal(err)
	}
	if _, err := vs.Add(voteFrom(t, cfg, 1, MsgPrevote, 1, 0, [32]byte{})); err != nil {
		t.Fatal(err)
	}
	if got := vs.PowerFor(id); got != 1 {
		t.Fatalf("block power = %d, want 1", got)
	}
	if got := vs.NilPower(); got != 1 {
		t.Fatalf("nil power = %d, want 1", got)
	}
}

func TestAnyQuorumFindsTheBlockWithEnoughPower(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	var a, b [32]byte
	a[0], b[0] = 1, 2
	vs := NewVoteSet(cfg, 1, 0, MsgPrevote)

	for i := 0; i < 3; i++ {
		if _, err := vs.Add(voteFrom(t, cfg, i, MsgPrevote, 1, 0, a)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := vs.Add(voteFrom(t, cfg, 3, MsgPrevote, 1, 0, b)); err != nil {
		t.Fatal(err)
	}

	got, ok := vs.AnyQuorum()
	if !ok {
		t.Fatal("expected a quorum for block A")
	}
	if got != a {
		t.Fatalf("AnyQuorum returned the wrong block")
	}
}
```

Add the two signing helpers to `testkeys_test.go` alongside the aliases:

```go
func testSign(t *testing.T, idx int, h [32]byte) []byte {
	t.Helper()
	return testSignRaw(t, testCommitteeKey(idx), h)
}

func testSignRaw(t *testing.T, priv ed25519PrivateKey, h [32]byte) []byte {
	t.Helper()
	return ed25519Sign(priv, h[:])
}
```

**`testCommitteeKey` already exists** in `testkeys_test.go`, added by Task 3's review fix,
where it was made the single source of the validator-key derivation so that a later task
changing it would break a test. **Do NOT re-declare it** - that is a duplicate-declaration
compile error. It is:

```go
func testCommitteeKey(idx int) ed25519PrivateKey {
	h := crypto.HashParts([]byte("b10coin-test-validator"), []byte{byte(idx)})
	return ed25519.NewKeyFromSeed(h[:])
}
```

with `ed25519Sign = ed25519.Sign` added to the alias block. The fixture in Task 3 must use the same derivation, so `evenCommittee` and `testCommitteeKey` agree — **check that they do**, since a mismatch would make every tally test fail with a signature error rather than the behaviour under test.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/consensus/ -v`
Expected: FAIL — `undefined: NewVoteSet`

- [ ] **Step 3: Write the implementation**

Create `internal/consensus/tally.go`:

```go
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
func (vs *VoteSet) Add(v *Vote) (bool, error) {
	if v.Type != vs.typ {
		return false, fmt.Errorf("consensus: vote type %d in a set for %d", v.Type, vs.typ)
	}
	if v.Height != vs.height || v.Round != vs.round {
		return false, fmt.Errorf("consensus: vote for (%d,%d) in a set for (%d,%d)",
			v.Height, v.Round, vs.height, vs.round)
	}
	if err := v.Verify(); err != nil {
		return false, err
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
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -count=1 ./internal/consensus/ -v`
Expected: PASS for all six tests.

- [ ] **Step 5: Commit**

```bash
git add internal/consensus
git commit -m "feat: add the weighted vote tally with one-vote-per-validator counting"
```

---

## Task 5: The locking rule

The spec calls this the safety-critical part: *"a validator that precommits block `B` at round `r` is locked on `B`. In any later round it prevotes only for `B` or for a proposal at a round `> r`. Without this rule, two conflicting blocks can commit at the same height."*

It lives in its own file because it is the one piece of the engine a reviewer should read first.

**Files:**
- Create: `internal/consensus/lock.go`, `internal/consensus/lock_test.go`

**Interfaces:**
- Consumes: nothing (pure logic over heights, rounds and block IDs)
- Produces: `consensus.lock`; `(lock).lockOn(round uint32, id [32]byte)`; `(lock).canPrevote(round uint32, id [32]byte) bool`; `(lock).locked() bool`; `(lock).round() int64`; `(lock).blockID() [32]byte`

- [ ] **Step 1: Write the failing tests**

Create `internal/consensus/lock_test.go`:

```go
package consensus

import "testing"

func bid(n byte) [32]byte {
	var id [32]byte
	id[0] = n
	return id
}

func TestUnlockedValidatorMayPrevoteAnything(t *testing.T) {
	var l lock
	if l.locked() {
		t.Fatal("a zero lock must report unlocked")
	}
	for _, r := range []uint32{0, 1, 7} {
		if !l.canPrevote(r, bid(1)) {
			t.Fatalf("an unlocked validator refused to prevote at round %d", r)
		}
	}
}

// The rule the spec names: after locking (r, B), a later round may prevote B, or a
// proposal STRICTLY NEWER than r. Nothing else.
func TestLockedValidatorPrevotesOnlyItsBlockOrANewerRound(t *testing.T) {
	var l lock
	l.lockOn(3, bid(1))

	if !l.canPrevote(3, bid(1)) {
		t.Fatal("a locked validator must still prevote its own locked block at the same round")
	}
	if !l.canPrevote(4, bid(1)) {
		t.Fatal("a locked validator must prevote its own locked block in a later round")
	}
	if !l.canPrevote(4, bid(2)) {
		t.Fatal("a locked validator must prevote a DIFFERENT block proposed at a strictly newer round")
	}
	if l.canPrevote(2, bid(2)) {
		t.Fatal("a locked validator must not prevote an OLDER round's different block")
	}
	if l.canPrevote(3, bid(2)) {
		t.Fatal("a locked validator must not prevote a different block at the SAME round it is locked on")
	}
}

// Relocking must only ever move forward. A validator that could relock on an
// earlier round would be able to prevote two conflicting blocks at one height -
// exactly the failure the rule exists to prevent.
func TestRelockingNeverMovesBackwards(t *testing.T) {
	var l lock
	l.lockOn(5, bid(1))
	l.lockOn(3, bid(2)) // an attempt to go back
	if l.round() != 5 || l.blockID() != bid(1) {
		t.Fatalf("relock moved backwards: round=%d block=%v", l.round(), l.blockID()[0])
	}
	l.lockOn(6, bid(2)) // forward is allowed
	if l.round() != 6 || l.blockID() != bid(2) {
		t.Fatalf("relock forward failed: round=%d block=%v", l.round(), l.blockID()[0])
	}
}

// The adversarial property, stated as the safety condition it protects: once a
// validator has locked at round r, it is impossible for it to prevote two
// different blocks in any round <= r.
func TestLockedValidatorCannotPrevoteTwoBlocksInOneRound(t *testing.T) {
	for _, lockedRound := range []uint32{0, 1, 4} {
		var l lock
		l.lockOn(lockedRound, bid(1))

		// At every round up to and including the locked round, only the locked
		// block is prevotable.
		for r := uint32(0); r <= lockedRound; r++ {
			if l.canPrevote(r, bid(2)) {
				t.Fatalf("locked at round %d: prevoted a conflicting block at round %d", lockedRound, r)
			}
		}
		// At every round after it, a conflict is permitted - that is what lets an
		// honest validator follow a newer proposal and make progress.
		if !l.canPrevote(lockedRound+1, bid(2)) {
			t.Fatalf("locked at round %d: refused a conflicting block at round %d, which would stall the chain",
				lockedRound, lockedRound+1)
		}
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/consensus/ -v`
Expected: FAIL — `undefined: lock`

- [ ] **Step 3: Write the implementation**

Create `internal/consensus/lock.go`:

```go
package consensus

// lock is a validator's promise about a height: it has precommitted a block, and
// it will not help commit anything conflicting at that height unless the network
// moves to a strictly newer round.
//
// This is the safety-critical rule of the whole protocol. Without it two
// conflicting blocks can each collect two thirds of precommits at one height,
// because validators' precommits at different rounds are not mutually exclusive.
// With it, a quorum for two different blocks at one height would require more than
// a third of the power to have broken its promise.
//
// The zero value is "not locked": round() is -1, an int64 rather than a uint32
// precisely so "no lock" is representable without a separate bool.
type lock struct {
	lockedRound int64
	lockedBlock [32]byte
}

// lockOn records a precommit of id at round.
//
// It only ever moves FORWARD. Relocking backwards would let a validator prevote a
// conflicting block at a round it had already promised not to - which is the very
// failure this type exists to prevent - so a lower round is ignored rather than
// honoured.
func (l *lock) lockOn(round uint32, id [32]byte) {
	if int64(round) >= l.lockedRound {
		l.lockedRound = int64(round)
		l.lockedBlock = id
	}
}

// canPrevote reports whether the validator may prevote id at round while holding
// this lock. The rule, verbatim from the spec: a locked validator prevotes its
// locked block, or a block proposed at a round STRICTLY GREATER than the one it is
// locked on. Anything else is refused.
func (l *lock) canPrevote(round uint32, id [32]byte, validRound int64) bool {
	if l.lockedRound < 0 {
		return true // not locked: anything goes
	}
	if id == l.lockedBlock {
		return true // its own promise, at any round
	}
	// Unlock ONLY on evidence: the proposal must carry a polka for id from a round
	// strictly greater than this validator's lock. A round number alone is not
	// evidence - see Design Decision 11 for the counterexample that proves it.
	return validRound > l.lockedRound
}

func (l *lock) locked() bool            { return l.lockedRound >= 0 }
func (l *lock) round() int64            { return l.lockedRound }
func (l *lock) blockID() [32]byte       { return l.lockedBlock }
```

Note the zero value: `lockedRound` defaults to **0**, not -1, so every `Engine` must initialize it explicitly. Do that in the constructor in Task 6 and pin it with a test there, or a fresh validator would consider itself locked at round 0 on the zero block.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -count=1 ./internal/consensus/ -v`
Expected: PASS for all four tests.

- [ ] **Step 5: Commit**

```bash
git add internal/consensus
git commit -m "feat: add the locking rule, isolated because it is safety-critical"
```

---

## Task 6: The engine's round state machine

**Files:**
- Create: `internal/consensus/engine.go`, `internal/consensus/engine_test.go`

**Interfaces:**
- Consumes: `Config`, `Vote`, `Proposal`, `VoteSet`, `lock`, `types.Block`
- Produces: `consensus.Step` (`StepPropose`, `StepPrevote`, `StepPrecommit`, `StepCommit`); `consensus.Outbound`; `consensus.TimeoutEvent`; `consensus.Engine`; `NewEngine(cfg, height, parent, priv, propose func(...) (*types.Block, error)) *Engine`; `(*Engine).OnMessage([]byte) error`; `(*Engine).OnTimeout(TimeoutEvent)`; `(*Engine).Drain() []Outbound`; `(*Engine).Height/Round/Step/Locked/Committed`

- [ ] **Step 0: Carry the justification, and VERIFY it**

Design Decision 11 is the milestone's central safety mechanism: a locked validator
unlocks only when shown that a supermajority moved on without it. That evidence must
travel with the proposal and must be checked, not trusted.

`Proposal` gains two fields:

```go
	// ValidRound is the round at which this block reached a polka (2/3 prevotes), or
	// -1 when the proposer knows of none. Justification carries the prevotes proving
	// it. A locked validator prevotes a DIFFERING block only when ValidRound exceeds
	// its own lock round - see Design Decision 11 for why a bare round number is not
	// enough.
	ValidRound    int64
	Justification []byte
```

Both go in the envelope's signing hash, exactly like `Height` and `Round`. Encode the
justification as a length-prefixed sequence of encoded votes.

Then a verification helper on the engine, because an unverified justification would be
worse than none - it would let a proposer assert an unlock that never happened:

```go
// verifyJustification checks that the proposal's carried prevotes really do prove a
// polka for the proposal's own block at its own ValidRound. It returns the round to
// use for the lock comparison: ValidRound when the evidence checks out, and -1 when
// the proposal carries none, which is the honest case for a fresh block.
//
// Verification is not optional. Trusting the field would let a Byzantine proposer
// claim an unlock that no quorum ever granted, which is precisely the conflicting
// commit the gate exists to prevent.
func (e *Engine) verifyJustification(p *Proposal) (int64, error) {
	if p.ValidRound < 0 {
		if len(p.Justification) > 0 {
			return 0, ErrBadJustification // evidence for a round it does not claim
		}
		return -1, nil
	}
	vs := NewVoteSet(e.cfg, e.height, uint32(p.ValidRound), MsgPrevote)
	for _, raw := range decodeVotes(p.Justification) { // length-prefixed sequence
		v, err := DecodeVote(raw)
		if err != nil {
			return 0, ErrBadJustification
		}
		if _, err := vs.Add(v); err != nil {
			return 0, ErrBadJustification
		}
	}
	if !vs.HasQuorum(p.Block.ID()) {
		return 0, ErrBadJustification
	}
	return p.ValidRound, nil
}
```

`DecodeVote` already rejects a vote whose own height or round is wrong for the set it is
added to, so a justification cannot smuggle in votes from another height.

Then `maybePrevote` must use the verified round rather than the proposal's round:

```go
	validRound, err := e.verifyJustification(<the proposal>)
	if err != nil {
		return // an unjustified proposal is not prevoted at all
	}
	if !e.lk.canPrevote(e.round, id, validRound) {
		// The lock refuses this block. Prevote NIL rather than staying silent: a
		// validator that emits nothing leaves its weight out of the nil tally, so the
		// round can never end and the chain stalls on exactly the safety path this
		// gate protects.
		e.emitVote(MsgPrevote, [32]byte{})
		e.step = StepPrevote
		return
	}
```

**Note the second half of that snippet.** It closes a liveness bug the controller found
while auditing Task 5: when a validator HAS a proposal but the lock forbids prevoting it,
returning silently means it emits neither a prevote for the block nor a nil vote, so the
count never advances. The nil prevote is required.

Also update `Proposal`'s tests: the envelope's signing hash must now cover `ValidRound` and
`Justification`, and a test must fail if either is dropped.

- [ ] **Step 1: Write the failing tests**

Create `internal/consensus/engine_test.go`:

```go
package consensus

import (
	"testing"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/types"
)

// proposer returns a deterministic block for a height, signed by whoever the
// engine names as proposer. The engine under test never builds blocks itself: it
// is handed a proposer function, so this stays pure and testable.
func testProposer(t *testing.T, cfg Config, height uint64, round uint32, parent [32]byte) types.Block {
	t.Helper()
	pub := cfg.Proposer(height, round, parent)
	b := types.Block{Header: types.Header{
		Height:     height,
		ParentHash: parent,
		StateRoot:  crypto.HashParts([]byte("state"), []byte{byte(height)}),
		TxRoot:     types.ComputeTxRoot(nil),
		Timestamp:  int64(1_700_000_000 + height),
		Proposer:   pub,
	}}
	if err := b.ValidateStructure(); err != nil {
		t.Fatalf("test block is not structurally valid: %v", err)
	}
	return b
}

// newTestEngine builds an engine for committee index idx, starting at height 1
// with an all-zero parent and no lock.
func newTestEngine(t *testing.T, cfg Config, idx int, height uint64, parent [32]byte) *Engine {
	t.Helper()
	priv := testCommitteeKey(idx)
	e := NewEngine(cfg, height, parent, priv, func(h uint64, r uint32, p [32]byte) (types.Block, error) {
		return testProposer(t, cfg, h, r, p), nil
	})
	if e.Locked() {
		t.Fatal("a fresh engine must not be locked: the lock's zero value is round 0, which is a real round")
	}
	return e
}

func drainTypes(outs []Outbound) map[MsgType]int {
	m := map[MsgType]int{}
	for _, o := range outs {
		if v, err := DecodeVote(o.Data); err == nil {
			m[v.Type]++
		} else if p, err := DecodeProposal(o.Data); err == nil {
			_ = p
			m[MsgProposal]++
		}
	}
	return m
}

// The happy path, for one validator: as proposer it proposes, then as a validator
// it prevotes its own proposal once it has seen it.
func TestProposerProposesAndPrevotesItsOwnBlock(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	parent := crypto.HashParts([]byte("parent"))
	// Find the height/round at which validator 0 is the proposer.
	idx := 0
	var h uint64
	for h = 1; h < 100; h++ {
		if string(cfg.Proposer(h, 0, parent)) == string(cfg.Committee[idx].PubKey) {
			break
		}
	}
	e := newTestEngine(t, cfg, idx, h, parent)

	e.OnTimeout(TimeoutEvent{Height: h, Round: 0, Step: StepPropose})
	outs := e.Drain()

	var gotProposal bool
	for _, o := range outs {
		if p := tryProposal(o.Data); p != nil {
			gotProposal = true
		}
		if v, err := DecodeVote(o.Data); err == nil && v.Type == MsgPrevote && !v.IsNil() {
			// The proposer must have prevoted its own block, not nil: prevoting nil
			// would stall the very round it is trying to advance.
			if v.BlockID != e.proposal.ID() {
				t.Fatalf("the proposer prevoted %x, not its own block", v.BlockID[:4])
			}
		}
	}
	if !gotProposal {
		t.Fatal("the proposer produced no proposal")
	}
	if drainTypes(e.Drain())[MsgPrevote] == 0 {
		t.Fatal("the proposer never prevoted for its own proposal")
	}
}

// A non-proposer at round 0 must prevote NIL, not stall: without nil votes a round
// whose proposer is offline could never be left behind.
func TestNonProposerEmitsANilPrevoteWhenNoProposalArrives(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	parent := crypto.HashParts([]byte("parent"))
	var h uint64
	for h = 1; h < 100; h++ {
		if string(cfg.Proposer(h, 0, parent)) != string(cfg.Committee[1].PubKey) {
			break
		}
	}
	e := newTestEngine(t, cfg, 1, h, parent)

	e.OnTimeout(TimeoutEvent{Height: h, Round: 0, Step: StepPrevote})
	outs := e.Drain()

	found := false
	for _, o := range outs {
		if v, err := DecodeVote(o.Data); err == nil && v.Type == MsgPrevote && v.IsNil() {
			found = true
		}
	}
	if !found {
		t.Fatal("a validator with no proposal must emit a nil prevote, or the round can never advance")
	}
}

// Two thirds of prevotes for a block must move the validator to precommit it, and
// that precommit must lock it.
func TestQuorumOfPrevotesLeadsToPrecommitAndLock(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	parent := crypto.HashParts([]byte("parent"))
	var h uint64
	for h = 1; h < 100; h++ {
		if string(cfg.Proposer(h, 0, parent)) != string(cfg.Committee[1].PubKey) {
			break
		}
	}
	e := newTestEngine(t, cfg, 1, h, parent)
	blk := testProposer(t, cfg, h, 0, parent)
	id := blk.ID()

	// Deliver the proposal and three prevotes (the quorum).
	prop := &Proposal{Height: h, Round: 0, Block: blk, Validator: cfg.Proposer(h, 0, parent)}
	prop.Sig = signProposal(t, cfg, prop)
	if err := e.OnMessage(EncodeProposal(prop)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		v := voteFrom(t, cfg, i, MsgPrevote, h, 0, id)
		if err := e.OnMessage(EncodeVote(v)); err != nil {
			t.Fatal(err)
		}
	}
	outs := e.Drain()
	if drainTypes(outs)[MsgPrecommit] == 0 {
		t.Fatal("a quorum of prevotes produced no precommit")
	}
	if !e.Locked() {
		t.Fatal("precommitting must lock the validator on the block")
	}
	if e.locked.blockID() != id {
		t.Fatal("the lock names the wrong block")
	}
}

// Two thirds of precommits for the same block at the same round must commit it.
func TestQuorumOfPrecommitsCommits(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	parent := crypto.HashParts([]byte("parent"))
	var h uint64
	for h = 1; h < 100; h++ {
		if string(cfg.Proposer(h, 0, parent)) != string(cfg.Committee[2].PubKey) {
			break
		}
	}
	e := newTestEngine(t, cfg, 2, h, parent)
	blk := testProposer(t, cfg, h, 0, parent)
	id := blk.ID()

	prop := &Proposal{Height: h, Round: 0, Block: blk, Validator: cfg.Proposer(h, 0, parent)}
	prop.Sig = signProposal(t, cfg, prop)
	if err := e.OnMessage(EncodeProposal(prop)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := e.OnMessage(EncodeVote(voteFrom(t, cfg, i, MsgPrevote, h, 0, id))); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 3; i++ {
		if err := e.OnMessage(EncodeVote(voteFrom(t, cfg, i, MsgPrecommit, h, 0, id))); err != nil {
			t.Fatal(err)
		}
	}
	got, ok := e.Committed()
	if !ok {
		t.Fatal("a quorum of precommits did not commit")
	}
	if got != id {
		t.Fatal("the committed block is not the one that reached quorum")
	}
}

// A majority for one block must not be mistaken for a majority for another, and a
// sub-quorum must not commit. This is the boundary the whole protocol rests on.
func TestSubQuorumDoesNotCommit(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	parent := crypto.HashParts([]byte("parent"))
	var h uint64
	for h = 1; h < 100; h++ {
		if string(cfg.Proposer(h, 0, parent)) == string(cfg.Committee[3].PubKey) {
			break
		}
	}
	e := newTestEngine(t, cfg, 3, h, parent)
	blk := testProposer(t, cfg, h, 0, parent)
	id := blk.ID()

	prop := &Proposal{Height: h, Round: 0, Block: blk, Validator: cfg.Proposer(h, 0, parent)}
	prop.Sig = signProposal(t, cfg, prop)
	if err := e.OnMessage(EncodeProposal(prop)); err != nil {
		t.Fatal(err)
	}
	// Two of four is 50%: below the two-thirds bar.
	for i := 0; i < 2; i++ {
		if err := e.OnMessage(EncodeVote(voteFrom(t, cfg, i, MsgPrecommit, h, 0, id))); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := e.Committed(); ok {
		t.Fatal("a 50% precommit tally committed a block; the bar is two thirds")
	}
}
```

The three helpers referenced above belong in `testkeys_test.go`. Add them there:

```go
func signProposal(t *testing.T, cfg Config, p *Proposal) []byte {
	t.Helper()
	idx := cfg.IndexOf(p.Validator)
	if idx < 0 {
		t.Fatal("signProposal: proposer is not in the committee")
	}
	// SigningHash returns an array BY VALUE, which cannot be sliced in place; bind it first.
	h := p.SigningHash()
	return ed25519Sign(testCommitteeKey(idx), h[:])
}
```

For the proposal-or-nil decode used in the first test, replace `DecodePro proposalOrNil(o.Data)` with a small helper in `testkeys_test.go`:

```go
// tryProposal decodes a proposal, or returns nil if the message is not one.
func tryProposal(b []byte) *Proposal {
	p, err := DecodeProposal(b)
	if err != nil {
		return nil
	}
	return p
}
```

and in the test use `if p := tryProposal(o.Data); p != nil {`. **Do not invent a function named `DecodeProposalOrNil`.**

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/consensus/ -v`
Expected: FAIL — `undefined: NewEngine`

- [ ] **Step 3: Write the implementation**

Create `internal/consensus/engine.go`:

```go
package consensus

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/types"
)

// Step is where a validator is in a round's four-phase protocol.
type Step uint8

const (
	StepPropose Step = iota
	StepPrevote
	StepPrecommit
	StepCommit
)

func (s Step) String() string {
	switch s {
	case StepPropose:
		return "propose"
	case StepPrevote:
		return "prevote"
	case StepPrecommit:
		return "precommit"
	case StepCommit:
		return "commit"
	}
	return "unknown"
}

// Outbound is a message the engine wants sent. An empty To means broadcast.
type Outbound struct {
	To   string
	Data []byte
}

// TimeoutEvent tells the engine that its round has run out of time. The driver
// owns the clock; the engine never reads one.
type TimeoutEvent struct {
	Height uint64
	Round  uint32
	Step   Step
}

var (
	ErrStaleEvent  = errors.New("consensus: event is for a height or round already passed")
	ErrNoProposer  = errors.New("consensus: no proposer for this height and round")
	ErrProposeFn   = errors.New("consensus: the proposer function failed")
	ErrSelfNotInSet = errors.New("consensus: this validator's key is not in the committee")
)

// ProposeFn builds the block a validator should propose at (height, round). The
// engine does not build blocks: block construction belongs to the caller, which is
// what keeps this type free of chain and mempool concerns.
type ProposeFn func(height uint64, round uint32, parent [32]byte) (types.Block, error)

// Engine is a deterministic BFT state machine for one validator.
//
// It reads no clock, starts no goroutine and performs no I/O. The driver feeds it
// messages and timeout events and carries Drain's output to a Transport. That is
// what makes a failing run reproducible from a seed, and it is why the same type
// will run over real sockets in M4 unchanged.
type Engine struct {
	cfg    Config
	priv   ed25519.PrivateKey
	pub    ed25519.PublicKey
	idx    int
	parent [32]byte
	propose ProposeFn

	height uint64
	round  uint32
	step   Step

	lk        lock
	proposal  *types.Block
	prevotes  *VoteSet
	precommits *VoteSet

	committed    [32]byte
	hasCommitted bool
	out          []Outbound
}

// NewEngine creates an engine that will validate height, whose parent is parent,
// signing with priv.
func NewEngine(cfg Config, height uint64, parent [32]byte, priv ed25519.PrivateKey, propose ProposeFn) *Engine {
	pub := priv.Public().(ed25519.PublicKey)
	e := &Engine{
		cfg: cfg, priv: priv, pub: pub,
		idx: cfg.IndexOf(pub), parent: parent, propose: propose,
		height: height,
		// The lock's zero value is round 0, which is a REAL round, so "unlocked"
		// must be set explicitly. Forgetting this makes a fresh validator believe
		// it is locked on the zero block and prevote for nothing.
		lk:      lock{lockedRound: -1},
		step:    StepPropose,
		prevotes:   NewVoteSet(cfg, height, 0, MsgPrevote),
		precommits: NewVoteSet(cfg, height, 0, MsgPrecommit),
	}
	return e
}

func (e *Engine) Height() uint64          { return e.height }
func (e *Engine) Round() uint32           { return e.round }
func (e *Engine) Step() Step              { return e.step }
func (e *Engine) Locked() bool            { return e.lk.locked() }
func (e *Engine) Proposer() []byte        { return e.cfg.Proposer(e.height, e.round, e.parent) }
func (e *Engine) IsProposer() bool        { return string(e.Proposer()) == string(e.pub) }

// Committed reports the block this engine has committed, if any.
func (e *Engine) Committed() ([32]byte, bool) { return e.committed, e.hasCommitted }

// Drain returns and clears the messages the engine wants sent. The caller owns
// delivery, so the engine never performs I/O.
func (e *Engine) Drain() []Outbound {
	out := e.out
	e.out = nil
	return out
}

func (e *Engine) emit(data []byte) { e.out = append(e.out, Outbound{Data: data}) }

// OnTimeout advances the round. It is how a stalled round is left behind.
func (e *Engine) OnTimeout(ev TimeoutEvent) {
	if ev.Height < e.height || (ev.Height == e.height && ev.Round < e.round) {
		return // stale
	}
	if ev.Height > e.height {
		return // a future height we have not reached; the driver will re-fire
	}
	if ev.Round > e.round {
		e.enterRound(ev.Round)
	}
	if e.step == StepPropose {
		e.step = StepPrevote
	}
	// In StepPrevote with no proposal, the validator votes nil so the round can end.
	if e.step == StepPrevote && e.proposal == nil {
		e.emitVote(MsgPrevote, [32]byte{})
		e.step = StepPrecommit
	}
}

// enterRound moves to a later round, resetting the per-round tally. The lock
// deliberately SURVIVES the round change: that is the whole point of it.
func (e *Engine) enterRound(round uint32) {
	e.round = round
	e.step = StepPropose
	e.proposal = nil
	e.prevotes = NewVoteSet(e.cfg, e.height, round, MsgPrevote)
	e.precommits = NewVoteSet(e.cfg, e.height, round, MsgPrecommit)
}

func (e *Engine) emitVote(typ MsgType, id [32]byte) {
	v := &Vote{Type: typ, Height: e.height, Round: e.round, BlockID: id, Validator: e.pub}
	h := v.SigningHash()
	v.Sig = crypto.Sign(e.priv, h[:])
	e.emit(EncodeVote(v))
}

// OnMessage processes one wire message. An error means the message was malformed
// or unusable; the caller may drop it and carry on.
func (e *Engine) OnMessage(data []byte) error {
	if v, err := DecodeVote(data); err == nil {
		return e.onVote(v)
	}
	p, err := DecodeProposal(data)
	if err != nil {
		return fmt.Errorf("%w: not a vote or a proposal", ErrUnknownMsgType)
	}
	return e.onProposal(p)
}

func (e *Engine) onProposal(p *Proposal) error {
	if p.Height != e.height || p.Round != e.round {
		return nil // another height or round: not ours to judge here
	}
	if err := p.Verify(); err != nil {
		return err
	}
	if string(p.Validator) != string(e.Proposer()) {
		return nil // not the proposer for this round; ignore it
	}
	if e.proposal != nil {
		return nil // first proposal wins, so the choice is deterministic
	}
	e.proposal = &p.Block
	e.maybePrevote()
	return nil
}

func (e *Engine) onVote(v *Vote) error {
	if v.Height != e.height || v.Round != e.round {
		return nil // not this round
	}
	switch v.Type {
	case MsgPrevote:
		added, err := e.prevotes.Add(v)
		if err != nil {
			return err
		}
		if added {
			e.maybePrecommit()
		}
	case MsgPrecommit:
		added, err := e.precommits.Add(v)
		if err != nil {
			return err
		}
		if added {
			e.maybeCommit()
		}
	}
	return nil
}

// maybePrevote prevotes the current proposal if the lock permits it.
func (e *Engine) maybePrevote() {
	if e.step != StepPropose && e.step != StepPrevote {
		return
	}
	if e.proposal == nil {
		return
	}
	id := e.proposal.ID()
	if !e.lk.canPrevote(e.round, id) {
		return // locked on something else at an older or equal round
	}
	e.emitVote(MsgPrevote, id)
	e.step = StepPrevote
}

func (e *Engine) maybePrecommit() {
	if e.step == StepPrecommit || e.step == StepCommit {
		return
	}
	id, ok := e.prevotes.AnyQuorum()
	if !ok {
		return
	}
	e.emitVote(MsgPrecommit, id)
	e.step = StepPrecommit
	// Precommitting IS locking: this is the promise the lock records. Doing it
	// anywhere else, or only on commit, would leave the safety rule unenforced
	// for exactly the window it exists to cover.
	e.lk.lockOn(e.round, id)
}

func (e *Engine) maybeCommit() {
	if e.hasCommitted {
		return
	}
	id, ok := e.precommits.AnyQuorum()
	if !ok {
		return
	}
	e.committed, e.hasCommitted = id, true
	e.step = StepCommit
}

// StartProposing is called by the driver when this engine is the proposer for the
// current round: it builds and broadcasts a proposal.
func (e *Engine) StartProposing() error {
	if !e.IsProposer() {
		return ErrNoProposer
	}
	if e.proposal != nil {
		return nil
	}
	b, err := e.propose(e.height, e.round, e.parent)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProposeFn, err)
	}
	h := b.Header.SigningHash()
	p := &Proposal{
		Height: e.height, Round: e.round, Block: b,
		Validator: e.pub, Sig: crypto.Sign(e.priv, h[:]),
	}
	e.proposal = &b
	e.emit(EncodeProposal(p))
	// The proposer prevotes its own block once it has "received" it, which
	// maybePrevote does for us.
	e.maybePrevote()
	return nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -count=1 ./internal/consensus/ -v`
Expected: PASS for all six tests.

- [ ] **Step 5: Commit**

```bash
git add internal/consensus
git commit -m "feat: add the BFT round state machine, locking on precommit"
```

---

## Task 7: The driver, and committing to the chain

**Files:**
- Create: `internal/consensus/driver.go`, `internal/consensus/driver_test.go`

**Interfaces:**
- Consumes: `Engine`, `transport.Transport`, `chain.Chain`
- Produces: `consensus.Driver`; `NewDriver(cfg, ch *chain.Chain, priv, tp transport.Transport) *Driver`; `(*Driver).Tick(now int64)`; `(*Driver).OnMessage(transport.Message)`; `(*Driver).Height() uint64`

- [ ] **Step 1: Write the failing test**

Create `internal/consensus/driver_test.go`:

```go
package consensus

import (
	"testing"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/transport/sim"
)

// A single-validator committee has a quorum of 1, so it can drive itself all the
// way to a commit. That makes the whole append-on-commit path testable without the
// multi-node harness, and it is a POSITIVE test: the chain must actually advance.
func TestDriverAppendsOnCommit(t *testing.T) {
	// One validator: quorumFor(1) == 1, so its own prevote and precommit each reach
	// the threshold.
	pub, priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	g := genesis.Devnet()
	g.Validators = []genesis.Validator{{PubKey: pub, Power: 1}}
	g.Params.CommitteeSize = 1

	ch, err := chain.Open(g, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ch.Close()

		// A ONE-validator committee legitimately holds all the power, and the 1/4 cap is
	// UNSATISFIABLE below four validators (the largest holder is at least total/3):
	// Validate would reject this fixture before the test could run. The cap is a
	// meaningful constraint only from n >= 4, which is where the spec's committee lives.
	cfg := Config{Committee: g.Validators, TimeoutBase: 10, TimeoutStep: 10, PowerCapNum: 1, PowerCapDen: 1}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}

	net := sim.New(sim.Options{Seed: 1, Latency: 1})
	net.AddPeer("v0")
	d := NewDriver(cfg, ch, priv, net.TransportFor("v0"))

	before := ch.Height()
	if before != 0 {
		t.Fatalf("expected a fresh chain at height 0, got %d", before)
	}

	// Drive the loop until the chain advances, or give up loudly.
	for i := 0; i < 200 && ch.Height() == before; i++ {
		now := int64(i * 10)
		d.Tick(now)
		net.Advance(time.Millisecond)
		d.Tick(now + 5)
	}
	if ch.Height() != before+1 {
		t.Fatalf("the chain did not advance past height %d: the commit path never appended (height %d)",
			before, ch.Height())
	}
	// And it must not overshoot: committing appends EXACTLY one block.
	head, err := ch.BlockAt(ch.Height())
	if err != nil {
		t.Fatal(err)
	}
	if head.Header.Height != before+1 {
		t.Fatalf("appended a block at height %d, want %d", head.Header.Height, before+1)
	}
}
```
> **Implementer note:** this test needs `github.com/cti97/b10coincom/internal/transport/sim` in the test file's imports, plus `time`. It drives one validator to a real commit, so it fails if the driver never appends.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/consensus/ -v`
Expected: FAIL — `undefined: NewDriver`

- [ ] **Step 3: Write the implementation**

Create `internal/consensus/driver.go`:

```go
package consensus

import (
	"crypto/ed25519"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/transport"
	"github.com/cti97/b10coincom/internal/types"
)

// Driver connects one engine to a Transport and to chain persistence.
//
// It owns the clock (the engine does not) and the outgoing queue (the engine does
// not). Committing is the ONLY place consensus touches the chain: the engine never
// speculatively applies a block, so a stalled height leaves the chain untouched and
// a node that disagrees simply reports a lower height.
type Driver struct {
	cfg  Config
	ch   *chain.Chain
	priv ed25519.PrivateKey
	tp   transport.Transport
	eng  *Engine

	timeoutAt int64 // virtual milliseconds at which the current round expires
}

// NewDriver starts a driver that will extend ch from its current head.
func NewDriver(cfg Config, ch *chain.Chain, priv ed25519.PrivateKey, tp transport.Transport) *Driver {
	d := &Driver{cfg: cfg, ch: ch, priv: priv, tp: tp}
	d.eng = NewEngine(cfg, ch.Height()+1, ch.Head().ID(), priv, d.build)
	tp.OnMessage(d.OnMessage)
	return d
}

// build constructs the block this node would propose: the chain's own Build does
// the work, so proposal construction and block validation cannot disagree about
// what a valid block is.
func (d *Driver) build(height uint64, round uint32, parent [32]byte) (types.Block, error) {
	b, err := d.ch.Build(d.priv, nil, 0)
	if err != nil {
		return types.Block{}, err
	}
	return *b, nil
}

// Height reports the chain height this driver has committed to.
func (d *Driver) Height() uint64 { return d.ch.Height() }

// Tick advances virtual time. It drives two things: the engine's round timeout, and
// the commit-to-chain step when a quorum has been reached.
func (d *Driver) Tick(nowMillis int64) {
	if e := d.eng; e.IsProposer() && e.proposal == nil && e.step == StepPropose {
		_ = e.StartProposing()
	}
	if nowMillis >= d.timeoutAt {
		d.eng.OnTimeout(TimeoutEvent{Height: d.eng.Height(), Round: d.eng.Round(), Step: d.eng.Step()})
		d.timeoutAt = nowMillis + d.cfg.TimeoutBase + int64(d.eng.Round())*d.cfg.TimeoutStep
	}
	d.flush()
}

// OnMessage feeds a wire message into the engine and flushes whatever it produces.
func (d *Driver) OnMessage(m transport.Message) {
	_ = d.eng.OnMessage(m.Data)
	d.flush()
}

// flush delivers the engine's outbound messages and, if it has committed, appends
// the block to the chain exactly once.
func (d *Driver) flush() {
	for _, o := range d.eng.Drain() {
		if o.To == "" {
			_ = d.tp.Broadcast(o.Data)
		}
	}
	id, ok := d.eng.Committed()
	if !ok {
		return
	}
	// Re-read the committed block from the proposal we accepted and append it.
	// Append validates the block against the chain again, so a driver bug cannot
	// inject an invalid block.
	if d.eng.proposal == nil || d.eng.proposal.ID() != id {
		return
	}
	if err := d.ch.Append(d.eng.proposal); err != nil {
		return // the chain refused it: stay at this height rather than diverge
	}
	// Advance to the next height, keeping the lock: the lock is per-height, and a
	// new height starts unlocked.
	d.eng = NewEngine(d.cfg, d.ch.Height()+1, d.ch.Head().ID(), d.priv, d.build)
	d.timeoutAt = 0
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -count=1 ./internal/consensus/ -v`
Expected: PASS. If the Task 7 test passed trivially, strengthen it per the note.

- [ ] **Step 5: Commit**

```bash
git add internal/consensus
git commit -m "feat: add the consensus driver, appending to the chain only on commit"
```

---

## Task 8: The simulation harness

**Files:**
- Create: `internal/simnet/simnet.go`, `internal/simnet/simnet_test.go`

**Interfaces:**
- Consumes: `consensus.Driver`, `transport/sim`, `chain`, `genesis`
- Produces: `simnet.Options`, `simnet.Net`; `simnet.New(n int, opts Options) (*Net, error)`; `(*Net).RunBlocks(n uint64) (map[uint64]uint64, error)`; `(*Net).Heights() map[uint64]uint64`; `(*Net).Partition(a, b []int)`; `(*Net).Heal()`; `(*Net).TakeOffline(i int)`

- [ ] **Step 1: Write the failing test and the harness**

The harness is the milestone's centrepiece: N validators, one `sim.Net`, one virtual clock, and a loop that advances time until every online validator has committed the next height or a step budget runs out.

Create `internal/simnet/simnet_test.go`:

```go
package simnet

import (
	"testing"
)

// The happy path the spec requires: four validators finalise many blocks.
func TestFourValidatorsFinaliseBlocks(t *testing.T) {
	n, err := New(4, Options{TempDir: t.TempDir(), Seed: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()

	heights, err := n.RunBlocks(20)
	if err != nil {
		t.Fatalf("RunBlocks: %v", err)
	}
	for i := 0; i < 4; i++ {
		if heights[uint64(i)] < 20 {
			t.Fatalf("validator %d finalised only %d of 20 blocks", i, heights[uint64(i)])
		}
	}
	// Every validator must agree on the same chain, or they did not really agree.
	if err := n.AssertSameChain(); err != nil {
		t.Fatal(err)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/simnet/ -v`
Expected: FAIL — `undefined: New`

- [ ] **Step 3: Write the harness**

Create `internal/simnet/simnet.go`:

```go
// Package simnet runs N consensus validators in one process over a deterministic
// simulated network. It is the harness the spec's section 9.1 scenarios drive: a
// failure here replays exactly from the seed, which is the only way consensus bugs
// become debuggable rather than merely observable.
package simnet

import (
	"fmt"
	"path/filepath"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/consensus"
	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/transport/sim"
)

// Options configures a simulated network.
type Options struct {
	TempDir     string
	Seed        int64
	LatencyMS   int64
	JitterMS    int64
	DropPercent int
	TimeoutBase int64 // virtual ms before a round expires
	TimeoutStep int64
}

// Net is N validators plus the network and clock joining them.
type Net struct {
	opts  Options
	sim   *sim.Net
	cfg   consensus.Config
	drv   []*consensus.Driver
	ch    []*chain.Chain
	keys  []keyPair
	offline map[int]bool
}

type keyPair struct{ priv ed25519.PrivateKey }

// simGenesis builds a genesis with n equal-power validators over deterministic
// keys, so a failing run is reproducible. The production devnet has one validator
// because a single node needs no agreement; consensus needs a committee.
func simGenesis(n int) *genesis.Genesis {
	g := genesis.Devnet()
	g.ChainID = fmt.Sprintf("b10coin-simnet-%d", n)
	vals := make([]genesis.Validator, 0, n)
	for i := 0; i < n; i++ {
		h := crypto.HashParts([]byte("b10coin-simnet-validator"), []byte{byte(i)})
		priv := ed25519NewKeyFromSeed(h[:])
		vals = append(vals, genesis.Validator{PubKey: priv.Public().(ed25519PublicKey), Power: 1})
	}
	g.Validators = vals
	g.Params.CommitteeSize = n
	return g
}

// New brings up n validators over one simulated network, each with its own chain
// in its own directory.
func New(n int, opts Options) (*Net, error) {
	out := &Net{opts: opts, offline: map[int]bool{}}
	out.sim = sim.New(sim.Options{
		Seed: opts.Seed, Latency: ms(opts.LatencyMS), Jitter: ms(opts.JitterMS),
		DropPercent: opts.DropPercent,
	})
	g := simGenesis(n)
	out.cfg = consensus.Config{
		Committee:   g.Validators,
		TimeoutBase: opts.TimeoutBase,
		TimeoutStep: opts.TimeoutStep,
		PowerCapNum: 1, PowerCapDen: 4,
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
			return nil, err
		}
		out.ch = append(out.ch, c)
		h := crypto.HashParts([]byte("b10coin-simnet-validator"), []byte{byte(i)})
		priv := ed25519NewKeyFromSeed(h[:])
		out.keys = append(out.keys, keyPair{priv: priv})
		out.drv = append(out.drv, consensus.NewDriver(out.cfg, c, priv, out.sim.TransportFor(id)))
	}
	return out, nil
}

// RunBlocks advances virtual time until every ONLINE validator has committed
// target blocks, or the step budget is exhausted. It returns each validator's
// height by index.
func (n *Net) RunBlocks(target uint64) (map[uint64]uint64, error) {
	now := int64(0)
	for step := 0; step < 100_000; step++ {
		now += 10
		for i, d := range n.drv {
			if n.offline[i] {
				continue
			}
			d.Tick(now)
		}
		n.sim.Advance(ms(10))
		if n.allAtLeast(target) {
			return n.Heights(), nil
		}
	}
	return n.Heights(), fmt.Errorf("simnet: stalled below height %d after the step budget", target)
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

// AssertSameChain fails unless every validator's committed head is identical. Two
// validators at the same height with different head hashes would mean the
// two-thirds safety assumption had been violated.
func (n *Net) AssertSameChain() error {
	var ref [32]byte
	var refHeight uint64
	first := true
	for i, c := range n.ch {
		if n.offline[i] {
			continue
		}
		// Compare the block ID at the LOWEST common height, not the head: validators
		// may legitimately be at different heights, but they must agree on the
		// prefix they share.
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
			continue
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

// Partition cuts the network between two groups of validator indices.
func (n *Net) Partition(a, b []int) {
	as, bs := ids(a), ids(b)
	n.sim.Partition(as, bs)
}

// Heal restores full connectivity.
func (n *Net) Heal() { n.sim.Heal() }

// TakeOffline stops a validator from ticking, as if its machine were powered off.
// It stays in the committee, so quorum does NOT become easier.
func (n *Net) TakeOffline(i int) { n.offline[i] = true }

func ids(is []int) []string {
	out := make([]string, 0, len(is))
	for _, i := range is {
		out = append(out, fmt.Sprintf("v%d", i))
	}
	return out
}

func (n *Net) Close() {
	for _, c := range n.ch {
		_ = c.Close()
	}
}
```

Add the small clock helper to the package:

```go
func ms(n int64) time.Duration { return time.Duration(n) * time.Millisecond }
```

`simnet` is NOT a test package, so it imports the real library rather than aliasing
it: add `crypto/ed25519`, `time`, and `github.com/cti97/b10coincom/internal/transport`
to its imports, and use `ed25519.PrivateKey` / `ed25519.PublicKey` / `ed25519.NewKeyFromSeed`
directly wherever the code below writes the aliased spellings. The key store becomes:

```go
type keyPair struct{ priv ed25519.PrivateKey }
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test -count=1 ./internal/simnet/ -v`
Expected: PASS. If it stalls, the likely causes are a wrong proposer selection, a missing nil-vote path, or an engine that is not ticking — diagnose with the seed before changing the test.

- [ ] **Step 5: Commit**

```bash
git add internal/simnet
git commit -m "feat: add the multi-validator simulation harness"
```

---

## Task 9: The six scenarios the spec requires

**Files:**
- Create: `internal/simnet/scenarios_test.go`

**Interfaces:**
- Consumes: everything above
- Produces: no new API — this is the milestone's evidence

- [ ] **Step 1: Write all six scenarios**

Create `internal/simnet/scenarios_test.go`:

```go
package simnet

import "testing"

// 1. Happy path: four validators finalise 1,000 blocks.
func TestScenarioHappyPath(t *testing.T) {
	n, err := New(4, Options{TempDir: t.TempDir(), Seed: 1, LatencyMS: 5, TimeoutBase: 200, TimeoutStep: 100})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	if _, err := n.RunBlocks(1000); err != nil {
		t.Fatalf("happy path stalled: %v", err)
	}
	if err := n.AssertSameChain(); err != nil {
		t.Fatal(err)
	}
}

// 2. One validator offline: 3 of 4 is still more than two thirds, so the chain
// advances.
func TestScenarioOneOfflineStillAdvances(t *testing.T) {
	n, err := New(4, Options{TempDir: t.TempDir(), Seed: 2, LatencyMS: 5, TimeoutBase: 200, TimeoutStep: 100})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	n.TakeOffline(3)

	if _, err := n.RunBlocks(20); err != nil {
		t.Fatalf("the chain stalled with only one validator offline: %v", err)
	}
}

// 3. Two validators offline: 2 of 4 is below two thirds, so the chain MUST stall.
// It must also never commit two different blocks at one height.
func TestScenarioTwoOfflineStallsWithoutForks(t *testing.T) {
	n, err := New(4, Options{TempDir: t.TempDir(), Seed: 3, LatencyMS: 5, TimeoutBase: 200, TimeoutStep: 100})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()

	// Let them get somewhere first, then remove two.
	if _, err := n.RunBlocks(3); err != nil {
		t.Fatal(err)
	}
	n.TakeOffline(2)
	n.TakeOffline(3)

	before := n.Heights()
	if _, err := n.RunBlocks(6); err == nil {
		t.Fatal("the chain advanced with only half the voting power online; two thirds was not enforced")
	}
	if err := n.AssertSameChain(); err != nil {
		t.Fatal(err)
	}
	// The height must not have gone BACKWARDS, which is what a fork would look like.
	for i, h := range n.Heights() {
		if h < before[i] {
			t.Fatalf("validator %d lost height: %d -> %d", i, before[i], h)
		}
	}
}

// 4. Partition then heal: no safety violation while split, and the chain resumes
// afterwards. A minority partition must not commit on its own.
func TestScenarioPartitionThenHeal(t *testing.T) {
	n, err := New(4, Options{TempDir: t.TempDir(), Seed: 4, LatencyMS: 5, TimeoutBase: 200, TimeoutStep: 100})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()

	if _, err := n.RunBlocks(3); err != nil {
		t.Fatal(err)
	}
	// A 1-vs-3 split: the majority side can still commit, the minority cannot.
	n.Partition([]int{0}, []int{1, 2, 3})

	// The majority side must make progress ON ITS OWN. RunBlocksAmong waits only on
	// the majority, because the cut-off validator cannot advance and must not block
	// the call - that is the whole situation under test.
	if _, err := n.RunBlocksAmong(8, []int{1, 2, 3}); err != nil {
		t.Fatalf("the majority partition could not make progress: %v", err)
	}

	// WHAT THIS SCENARIO CAN HONESTLY ASSERT, and what it cannot.
	//
	// M3 has NO block catch-up: a validator that falls behind cannot adopt the blocks
	// it missed, because the Transport interface offers only Broadcast and no unicast
	// sync. So "the chain resumes" is asserted as: the majority never stopped, and the
	// lagging validator's history is a strict PREFIX of the majority's - it is behind,
	// never forked. Requiring the minority to RECONVERGE would need block sync, which
	// is M4's networking work. See the milestone's limits note.
	//
	// What must NEVER happen, and is asserted below, is a safety violation: two
	// validators with conflicting blocks at one height.
	if _, err := n.RunBlocksAmong(12, []int{1, 2, 3}); err != nil {
		t.Fatalf("the majority chain did not keep advancing: %v", err)
	}
	if err := n.AssertPrefix(0); err != nil {
		t.Fatalf("the partitioned validator diverged instead of merely lagging: %v", err)
	}
	if err := n.AssertSameChain(); err != nil {
		t.Fatalf("a safety violation after healing: %v", err)
	}
}

// 5. A Byzantine validator equivocates: it signs two conflicting prevotes for the
// same height and round. One Byzantine validator is below the one-third bar, so the
// chain must still advance, and no two honest validators may ever commit different
// blocks at the same height.
func TestScenarioByzantineEquivocatorDoesNotFork(t *testing.T) {
	n, err := New(4, Options{TempDir: t.TempDir(), Seed: 5, LatencyMS: 5, TimeoutBase: 200, TimeoutStep: 100})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()

	// Validator 3 turns Byzantine: every prevote it sends is duplicated as a prevote
	// for a DIFFERENT block ID, signed with the key it genuinely owns.
	n.MakeEquivocator(3)

	if _, err := n.RunBlocks(30); err != nil {
		t.Fatalf("one Byzantine validator stalled the chain: %v", err)
	}
	if err := n.AssertSameChain(); err != nil {
		t.Fatalf("a Byzantine equivocator produced a conflicting commit: %v", err)
	}
}

// 6. Restart mid-epoch: a validator stops, the others advance, and it reopens its
// chain from disk. Replay must re-derive the state root its peers computed, then
// it must rejoin rather than fork.
func TestScenarioRestartMidEpoch(t *testing.T) {
	n, err := New(4, Options{TempDir: t.TempDir(), Seed: 6, LatencyMS: 5, TimeoutBase: 200, TimeoutStep: 100})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()

	if _, err := n.RunBlocks(5); err != nil {
		t.Fatal(err)
	}
	// Stop validator 3: close its chain and stop ticking it. It stays in the
	// committee, so quorum does NOT become easier for the others.
	stopped := n.ch[3].Height()
	n.TakeOffline(3)
	if err := n.ch[3].Close(); err != nil {
		t.Fatal(err)
	}

	// The other three are more than two thirds, so they keep going.
	if _, err := n.RunBlocks(12); err != nil {
		t.Fatalf("the chain stalled with one validator stopped: %v", err)
	}

	// Reopen from the same directory. Open replays every stored block and re-derives
	// the state root, so a divergence would have failed Open itself.
	reopened, err := chain.Open(n.genesis(), filepath.Join(n.opts.TempDir, "v3"))
	if err != nil {
		t.Fatalf("reopening the stopped validator failed: %v", err)
	}
	if reopened.Height() != stopped {
		t.Fatalf("replay reached height %d, want the stored height %d", reopened.Height(), stopped)
	}
	// The assertion that matters: its replayed state root must equal a peer's at the
	// SAME height. Same chain means same state, or they are not validating one ledger.
	peer, err := n.ch[0].BlockAt(stopped)
	if err != nil {
		t.Fatal(err)
	}
	mine, err := reopened.BlockAt(stopped)
	if err != nil {
		t.Fatal(err)
	}
	if mine.Header.StateRoot != peer.Header.StateRoot {
		t.Fatalf("replayed state root diverged at height %d:\n mine %x\n peer %x",
			stopped, mine.Header.StateRoot[:8], peer.Header.StateRoot[:8])
	}

	// The restarted validator is now BEHIND its peers, and M3 has no block catch-up, so
	// it cannot adopt the blocks it missed - see the milestone's limits note. What the
	// spec requires of this scenario is the REPLAY assertion made above (the state root
	// matches), and what safety requires is that the restarted chain is a PREFIX of its
	// peers' rather than a fork of it.
	//
	// Re-wire it into the network anyway: a driver that is behind must remain harmless,
	// not disruptive. Rebuild it over `transportFor(3)` so the harness's recorder stays
	// wired to the new driver.
	n.ch[3] = reopened
	n.offline[3] = false
	n.drv[3] = consensus.NewDriver(n.cfg, reopened, n.keys[3].priv, n.transportFor(3))
	if err := n.AssertPrefix(3); err != nil {
		t.Fatalf("the restarted validator holds a conflicting history: %v", err)
	}
	// And the peers must be unaffected by its return.
	if _, err := n.RunBlocksAmong(20, []int{0, 1, 2}); err != nil {
		t.Fatalf("the restarted validator disrupted the running chain: %v", err)
	}
}

> **Implementer note:** scenarios 5 and 6 need harness support that Task 8 must provide: `(*Net).MakeEquivocator(i int)` and `(*Net).genesis() *genesis.Genesis`. Both are specified in Step 2 below. `TestScenarioRestartMidEpoch` also needs `path/filepath` and `chain` in that test file's imports.

- [ ] **Step 2: Add the harness seams scenarios 5 and 6 need**

Add to `internal/simnet/simnet.go` the genesis accessor the restart scenario reopens with, and the equivocator seam:

```
```go
// genesis returns the genesis every validator in this network was opened with. The
// restart scenario needs it to reopen a stopped validator's chain from the same
// directory.
func (n *Net) genesis() *genesis.Genesis { return n.g }
```

(store the genesis on `Net` as `g` in `New`), and:

```go
// MakeEquivocator replaces validator i's transport with one that duplicates every
// prevote it sends as a prevote for a DIFFERENT block ID, signed with the key i
// genuinely owns.
//
// Signing with a REAL committee key is essential: a forged vote carrying a
// stranger's key would be rejected by the tally as a non-member, and the scenario
// would then pass without ever exercising the quorum arithmetic it exists to
// stress.
func (n *Net) MakeEquivocator(i int) {
	inner := n.sim.TransportFor(fmt.Sprintf("v%d", i))
	n.drv[i] = consensus.NewDriver(n.cfg, n.ch[i], n.keys[i].priv, &equivocating{
		inner:   inner,
		priv:    n.keys[i].priv,
		forgeID: crypto.HashParts([]byte("b10coin-forged-block")),
	})
}

// equivocating wraps a Transport and re-sends every prevote as a conflicting one.
type equivocating struct {
	inner   transport.Transport
	priv    ed25519.PrivateKey
	forgeID [32]byte
}

func (eq *equivocating) Broadcast(data []byte) error {
	if err := eq.inner.Broadcast(data); err != nil {
		return err
	}
	v, err := consensus.DecodeVote(data)
	if err != nil || v.Type != consensus.MsgPrevote || v.IsNil() {
		return nil
	}
	f := &consensus.Vote{
		Type: consensus.MsgPrevote, Height: v.Height, Round: v.Round,
		BlockID: eq.forgeID, Validator: v.Validator,
	}
	h := f.SigningHash()
	f.Sig = ed25519.Sign(eq.priv, h[:])
	return eq.inner.Broadcast(consensus.EncodeVote(f))
}

// OnMessage must forward to the wrapped transport, or the driver under it would
// never receive anything and the scenario would stall for the wrong reason.
func (eq *equivocating) OnMessage(fn func(transport.Message)) { eq.inner.OnMessage(fn) }
func (eq *equivocating) Peers() []transport.PeerID              { return eq.inner.Peers() }
func (eq *equivocating) Close() error                           { return eq.inner.Close() }
```

`equivocating` needs `github.com/cti97/b10coincom/internal/transport` in the imports, and `ed25519` must be the real `crypto/ed25519` here, not the test alias.

- [ ] **Step 3: Run all six scenarios**

Run: `go test -count=1 ./internal/simnet/ -v`
Expected: PASS for all six, with **no skips remaining**. Then run `go test -count=20 ./internal/simnet/` — the same seeds must produce the same outcomes every time; a scenario that passes intermittently is a determinism bug in the simulator, not a flaky test.

- [ ] **Step 4: Commit**

```bash
git add internal/simnet
git commit -m "test: add the six consensus scenarios the spec requires"
```

---

## Task 10: A multi-validator devnet and the acceptance check

**Files:**
- Modify: `cmd/b10coin/main.go`, `internal/devnet/devnet.go`, `internal/devnet/devnet_test.go`, `.github/workflows/ci.yml`, `README.md`

**Interfaces:**
- Consumes: `simnet`
- Produces: CLI `devnet --validators N`

- [ ] **Step 1: Make `--validators` real**

The spec's §9 named `devnet --validators 4 --blocks 100` as its proof; M0–M1 could not honour it because a single node needed no agreement. Add the flag to `cmdDevnet`: when `--validators` is greater than 1, drive a `simnet.Net` of that size instead of the single-node loop, and report each validator's final height plus whether they agree.

- [ ] **Step 2: Write the failing test**

Add to `internal/devnet/devnet_test.go`:

```go
// The milestone's acceptance: four validators must AGREE, not merely each build
// blocks. A single node producing blocks proves nothing about consensus.
func TestDevnetWithFourValidatorsAgrees(t *testing.T) {
	s, err := RunMulti(Options{Dir: t.TempDir(), Blocks: 50, Validators: 4})
	if err != nil {
		t.Fatalf("RunMulti: %v", err)
	}
	if s.Validators != 4 {
		t.Fatalf("validators = %d, want 4", s.Validators)
	}
	for i, h := range s.ValidatorHeights {
		if h < 50 {
			t.Fatalf("validator %d finalised only %d of 50 blocks", i, h)
		}
	}
	if !s.Agreed {
		t.Fatal("the validators did not agree on a single chain")
	}
}
```

- [ ] **Step 3: Implement `RunMulti`**

Add a `Validators uint64` field to `Options` and `RunMulti` to `internal/devnet/devnet.go`, returning a `Summary` extended with `Validators`, `ValidatorHeights map[int]uint64` and `Agreed bool`, backed by `simnet`. Keep the existing single-node `Run` untouched so the M0–M1 acceptance command keeps working.

- [ ] **Step 4: Run the tests and both acceptance commands**

Run:
- `go test -count=1 ./...`
- `go run ./cmd/b10coin devnet --blocks 100`
- `go run ./cmd/b10coin devnet --validators 4 --blocks 100`

Expected: all PASS; the first prints `OK` as before, and the second reports four validators at height 100 that agree, then `OK`, exit 0. Paste both outputs into your report.

- [ ] **Step 5: Update CI and the README**

Add the multi-validator command to `.github/workflows/ci.yml` alongside the existing ones. In `README.md`, document that consensus now exists: the four-phase round, that two thirds of **total** power is required, that a validator that precommits is locked and will not help commit a conflicting block at the same height, and that the milestone was verified by the six scenarios in `internal/simnet` driven from a seed. Keep the valueless-testnet framing.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat: run a four-validator devnet, and make it the acceptance check"
```

---

## Self-Review

**Spec coverage.** §6.3's four phases are Task 6; the locking rule is Task 5, isolated and adversarial-tested; weighted proposer selection seeded by `(height, round, parent)` is Task 3; the round timeout is Task 7's `Tick`; the parameters table is Task 3's `Config` with the 1/4 power cap enforced by `Validate` and two thirds of **total** power as the quorum. §9.1's six scenarios are Task 9. §9.1's requirement that a failure replay from a seed is the reason for Task 2's single-threaded virtual-time network and Task 6's clock-free engine. The `Transport` boundary the spec's §6.6 asks for is Task 2, and M4's relay will implement it rather than replace it.

**Not in this plan, deliberately:** epoch-bound validator-set changes (M5 — `CommitteeAt` is the seam), timeout certificates / skip votes (the spec defers them: v1 uses a plain escalating timeout), slashing, and real networking (M4).

**The three things most likely to go wrong, and where they are guarded.** First, a validator committing two conflicting blocks at one height — guarded by the lock being applied at PRECOMMIT (Task 6) rather than at commit, by relocking never moving backwards (Task 5), and by `TestScenarioTwoOfflineStallsWithoutForks` and the Byzantine scenario (Task 9). Second, an engine that is not actually deterministic — guarded by the clock-free, goroutine-free design (Tasks 2 and 6) and by the `-count=20` run in Task 9. Third, a test that passes without testing anything — this project has shipped **ten** such tests across M0–M1 and M2, so every task in this plan names the one thing that must break for its test to fail, and Task 9 refuses to accept `t.Skip`.

**Honest limits of the MILESTONE (not of the plan).** Two mechanisms the spec's scenarios presuppose do not exist in M3 and are deliberately deferred:

1. **No block catch-up.** A validator that falls behind - partitioned away, or restarted - cannot adopt the blocks it missed, because `Transport` offers only `Broadcast` and no unicast sync. So the scenarios assert that a lagging validator's history is a strict PREFIX of the longest chain rather than demanding it reconverge. Reconvergence, and the block-sync mechanism it needs, belong with M4's real networking.
2. **Packet loss permanently parks a validator.** `sim.Options.DropPercent` is exposed but must not be used for any liveness scenario: a lost quorum-committing proposal parks that driver forever, because M3 has no recovery path. Loss is modelled and available, but a scenario that depends on it cannot complete.

Three further limits, named by the milestone's final review, are OBSERVED boundaries rather than deferred work - recorded here in the milestone-limits note, which is where Task 12's Step 6 asked them, so this note is the single place a reader finds the milestone's honest limits:

3. **No scenario injects message reordering.** Every scenario runs at zero jitter with fixed latency, so delivery is strictly send order. The harness models reordering and its storage-level tests exercise it, but no consensus scenario has yet run under it - the persisted-lock restart refusal is therefore validated with in-order delivery only.
4. **The justification gate's unlock path is unreachable from any shipped driver.** Every production `Proposal` is built with `ValidRound: -1` and `encodeJustification` has no non-test caller, so in production the gate is REFUSAL-ONLY: its safety half runs, and its unlock-on-evidence half is exercised by tests alone.
5. **Consensus blocks carry no transactions.** The per-block claim bound's motivating threat - a proposer stuffing a block with heavy faucet claims - never arises on the consensus path in M3; the bound is enforced and tested, but a committed consensus block never carries a claim.

None of the five are defects in what M3 built; all five are the boundary of what M3 set out to build, and all are recorded here so the milestone's claims are read no more broadly than they hold.

**Honest limits.** The simulator models latency, jitter, loss, reordering and partitions, but not clock skew, disk failure, or real network partitions — M4's real-hardware step is what tests those, and nothing here should be read as claiming otherwise. The liveness scenarios are seeded and finite; they demonstrate the protocol survives the failures injected, not that it survives every failure a real network can produce. And the Byzantine scenario models an equivocating validator, which is the most direct attack but not the only one: a validator that withholds votes selectively or delays them is not simulated, because those are liveness attacks the timeout path already covers.

---

## Task 11: Bound faucet claims per block, as a consensus rule

**Why this exists.** M3 Task 0 bounded claims in the LOCAL mempool, which stops a node burning CPU on its own pool. It does not stop a **proposer** packing a block with claims: `applyFaucetClaim` runs a full Argon2id evaluation before it can reject, `ApplyBlock` has no bound on how many it will attempt, and `types.MaxTxsPerBlock` is 10,000. So a single malicious proposer makes every validator pay ~10,000 Argon2id evaluations per block — at the committed testnet tuning (64 MiB × 3, ≈3 s each) that is **hours of work to validate one block**, on every validator, repeatedly. A block is attacker-chosen input, so this is the same amplifier Task 0 fixed, moved to a worse position: consensus now depends on it.

**Files:**
- Modify: `internal/state/apply.go`, `internal/state/apply_test.go`, `internal/genesis/genesis.go`, `internal/genesis/genesis_test.go`, `README.md`

**Interfaces:**
- Produces: `genesis.Params.MaxClaimsPerBlock uint64`, carried through `Encode`/`DecodeGenesis`; `state.ErrTooManyClaims`

- [ ] **Step 1: Write the failing tests**

```go
// A block is attacker-chosen input. Because validating one faucet claim costs a full
// Argon2id evaluation, a block carrying an unbounded number of them lets one proposer
// force every validator to spend hours on a single block. A block over the bound must
// therefore be INVALID, not merely slow.
func TestApplyBlockRejectsABlockWithTooManyClaims(t *testing.T) {
	// build a block whose transaction list carries MaxClaimsPerBlock+1 validly-signed
	// claims, and assert ApplyBlock returns ErrTooManyClaims without evaluating them:
	// the count must be checked BEFORE the first puzzle is verified, or the bound
	// protects nothing.
}

func TestApplyBlockAcceptsABlockAtTheClaimBound(t *testing.T) {
	// exactly MaxClaimsPerBlock claims: accepted. The bound is inclusive, so the
	// off-by-one is pinned in both directions.
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/state/ -run TestApplyBlockRejectsABlockWithTooManyClaims -v`
Expected: FAIL — `undefined: ErrTooManyClaims`

- [ ] **Step 3: Implement the bound**

Count the claims in the block's transaction list and reject the whole block if the count exceeds `MaxClaimsPerBlock`, **before verifying any puzzle**. The check must come first: a bound that is enforced after the expensive work bounds nothing.

Reuse the mempool's value so the two cannot drift, or pin both to the genesis parameter with a test asserting they agree — say which you chose and why.

- [ ] **Step 4: Re-derive the testnet Argon2 tuning**

The spec's ≈3 s target was chosen for the **claimer**, who pays it once. Validators pay it **per claim per block**, so `MaxClaimsPerBlock × verify-time` must fit inside the block interval. At 64 MiB × 3 the bound would need to be 0. Re-derive the testnet parameters (and the bound) so the worst-case block validates inside a small multiple of the 2 s block interval, and **state the arithmetic in the code comment** rather than asserting an unexplained pair of numbers. Keep the devnet's trivial tuning untouched.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test -count=1 ./... && go test -race -count=1 ./...`
Expected: PASS. The acceptance root must be **unchanged**: the devnet carries at most one claim per block, well under any sensible bound.

- [ ] **Step 6: Document the rule**

In `README.md`, state that a block may carry at most `MaxClaimsPerBlock` faucet claims and **why**: validation cost is per-claim, and a block is attacker-chosen. Remove or correct any claim that the mempool bound protects the chain — it protects the local node only.

- [ ] **Step 7: Commit**

```bash
git add internal/state internal/genesis README.md
git commit -m "feat: bound faucet claims per block as a consensus rule

Validating a claim costs a full Argon2id evaluation, and a block is
attacker-chosen input, so an unbounded claim count let one proposer force
every validator to spend hours validating a single block. A block over the
bound is now invalid, checked BEFORE any puzzle is evaluated. The testnet
tuning is re-derived so the worst case fits the block interval."
```

---

## Task 12: Persist the lock, so a restart cannot re-vote

**Why this exists.** The milestone's final review found the safety claim is stated unconditionally in the README while the code does not support it across a restart. `NewEngine` sets `lockedRound = -1`, and **neither `Driver`, `chain` nor `store` reads or writes lock state** - so a validator that precommitted `B` and then restarted re-enters **unlocked at the same height**, which is exactly the precondition Design Decision 11's counterexample needs. The reviewer demonstrated it: the locked engine emits only a nil prevote for a conflicting block, while a fresh engine at the same height prevotes it.

The counting argument that closes DD11 has a hidden premise: that the `f+1` locked honest validators **stay** locked. Nothing persists that. Persisting `lockedRound`/`lockedBlock` per height is the standard Tendermint requirement, and without it the milestone's headline sentence is false for any validator that restarts.

**Files:**
- Modify: `internal/store/store.go` (+ test), `internal/consensus/driver.go` (+ test), `internal/chain/chain.go` (+ test if the store is reached through it), `README.md`

**Interfaces:**
- Produces: `store.LockRecord{Height uint64; Round uint32; BlockID [32]byte}`, `(*Store).PutLock/PutLocked`, `(*Store).LockAt(height)`; `consensus.Driver` persisting on lock and restoring on engine creation

- [ ] **Step 1: Write the failing test**

```go
// The safety argument assumes a locked validator STAYS locked. Without persisting the
// lock, a validator that precommits and then restarts re-enters unlocked at the same
// height and will help commit a conflicting block - which is precisely the case the
// locking rule exists to prevent.
func TestRestartedValidatorRefusesToPrevoteAConflictingBlock(t *testing.T) {
	// 1. bring up a validator, let it precommit B at height h (so it locks)
	// 2. stop it, discarding the in-memory engine entirely
	// 3. restart it from the same directory
	// 4. hand the fresh engine a conflicting B' at height h with no justification
	// 5. assert it does NOT prevote B', and DOES prevote a properly justified B'
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/consensus/ -run TestRestartedValidatorRefusesToPrevoteAConflictingBlock -v`
Expected: FAIL - the fresh engine prevotes the conflicting block.

- [ ] **Step 3: Persist the lock**

Add a lock record to the crash-tolerant store, written **whenever the lock moves** (i.e. in the driver's commit/precommit path, after `lockOn`) and read when an engine is created for a height. Use the store's existing CRC framing so a torn write is detected rather than silently read as a lock.

Keep the record small and per-height, and make it survive replay: `Open` must reconstruct the lock for the chain's current height, not just the blocks.

- [ ] **Step 4: Restore it on engine creation**

`NewEngine` gains the persisted lock (or the driver sets it after construction). A restored lock must behave exactly like an in-memory one: it survives `enterRound`, and it refuses a differing block until a verified justification exceeds it.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test -count=1 ./... && go test -race -count=1 ./...`
Expected: PASS, including every pre-existing test.

- [ ] **Step 6: Correct the README, and record the remaining limits**

The README's safety sentence may now stand **unconditionally** - but only once the test above passes. Also add to the milestone-limits note the three omissions the final review found: no scenario injects reordering; the justification gate's unlock path is unreachable from any shipped driver (refusal-only in production); and consensus blocks carry no transactions, so the claim bound's motivating threat never arises on the consensus path.

- [ ] **Step 7: Commit**

```bash
git add internal/store internal/consensus internal/chain README.md
git commit -m "feat: persist the lock so a restart cannot re-vote a conflicting block

The locking rule's safety argument assumes a locked validator stays locked.
Nothing persisted it: a validator that precommitted and then restarted
re-entered unlocked at the same height and would help commit a conflicting
block - the exact case the rule exists to prevent. The lock is now written to
the crash-tolerant store whenever it moves and restored on engine creation."
```
