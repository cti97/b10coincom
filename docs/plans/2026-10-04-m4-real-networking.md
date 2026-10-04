# M4: Real Networking — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the in-process simulator with a real network. A `TcpTransport` and a dumb outbound relay let validators on **home Raspberry Pis behind NAT and CGNAT** reach each other, and `BLOCK_SYNC` lets one that fell behind rejoin. M4 is where the Pi thesis is proven or falsified.

**Architecture:** Four new pieces and one boundary change. A **framed wire format** (4-byte big-endian length + canonical payload) shared by every connection. A **`TcpTransport`** implementing the same `transport.Transport` the simulator already implements, so consensus is untouched. A **relay** — a ~300-line process that knows nothing about consensus and forwards signed frames between validators that all dial *outbound* to it, which is what makes home NAT and CGNAT irrelevant. And **`BLOCK_SYNC`**, the catch-up mechanism M3 deferred. The one boundary change: `Transport` gains a unicast `Send`, because catch-up is a request/response and broadcasting it would be wrong.

**Tech Stack:** Go 1.23+, standard library only (`net`, `encoding/binary`, `crypto/tls` if needed later). No new dependencies.

**Spec:** `docs/2026-10-02-b10coin-design.md` — **§6.6 (Networking)** is the authority, and **§10's M4 row** defines acceptance: *"Cross-compiled ARM64 binary; 3 validators on real Raspberry Pis across separate networks finalize blocks."*

**Prerequisites:** M0–M3 are complete and merged into `main`. The BFT engine, the simulator, the six scenarios and both acceptance commands all pass.

## Global Constraints

- **Module path:** `github.com/cti97/b10coincom`
- **Go floor:** `go 1.23`. Two direct external modules. **No others.** The networking layer must be stdlib.
- **The wire format is canonical and shared.** 4-byte big-endian length prefix + a canonical payload. Never JSON, never `gob`, never a map. A frame that does not parse is a protocol error, not something to salvage.
- **Consensus must not learn about sockets.** `internal/consensus` imports `internal/transport` and nothing below it. `TcpTransport` implements that interface; the engine cannot tell it apart from the simulator.
- **The relay is untrusted and must be treated as such.** Every consensus message is signed, so a malicious relay can censor or delay but **cannot forge a vote or a proposal**. Nothing may be moved *out* of a signature on the assumption that the relay checked it.
- **Safety over liveness, still.** A relay that partitions the validator set stalls consensus; that is an acceptable testnet trade, and it must be *written down*, never assumed away.
- Every task ends with `go test -count=1 ./...` green and a commit. Use `-count=1`: Go caches test results.

## Design decisions

**1. `Transport` gains `Send(peer, data)` — a unicast, and this is a deliberate boundary change.** `BLOCK_SYNC` is a request/response between two peers; broadcasting it would flood the network with answers every validator did not ask for. The spec's §6.6 interface lists only `broadcast`, and a star topology *could* carry sync over broadcast, but that is worse in every way and would have to be undone. The simulator implements `Send` as an immediate unicast, so it stays deterministic.

**2. The frame carries no type tag of its own beyond the payload's first byte.** The canonical encoding already discriminates: a `HELLO` and a consensus message start with different tags. Framing exists only to delimit, and a frame layer that also interpreted would be a second place for the wire semantics to live.

**3. Dedup lives in the transport-facing layer, keyed on `(validator_id, height, round, type)`.** A star topology has no loops, so this is not needed today — but it costs one map and it is the thing that must exist *before* the topology becomes a mesh, which is M5. Building it later means retrofitting it into a live protocol.

**4. `BLOCK_SYNC` is pull-based, and the requester verifies every block it adopts.** A lagging validator asks for blocks by height range and adopts what it receives only after the ordinary validation path accepts them. A push-based design would let any peer force work on a validator; a pull that trusted its source would be a remote code path that installs unvalidated state.

**5. Consensus blocks now carry transactions.** M3's driver proposed `nil` and the milestone's limits note records that this means the faucet path and the consensus path have never run together. That is the single largest untested integration in the project, and a real network makes it worse rather than better.

**6. Reconnection is exponential backoff with jitter, and the relay is stateless about it.** Every validator dials out; if the relay restarts, every validator redials. The relay keeps a connection registry and nothing else.

**7. The ARM64 build is a CI-checked artifact, not a local command.** A cross-compile that only works on one machine is not a deliverable. `GOOS=linux GOARCH=arm64 go build` must be in CI, so the Pi binary cannot rot.

## File structure

| File | Responsibility |
|---|---|
| `internal/wire/frame.go` | Length-prefixed framing over any `io.ReadWriteCloser`: `WriteFrame`, `ReadFrame` |
| `internal/wire/message.go` | `HELLO`, `BLOCK_SYNC` request/response, and the tag that discriminates them |
| `internal/transport/tcp/tcp.go` | `TcpTransport`: dial, accept, registry, `Broadcast`, `Send`, `OnMessage`, `Peers`, `Close` |
| `internal/transport/tcp/backoff.go` | Exponential backoff with jitter, seeded so it is testable |
| `internal/transport/dedup.go` | The per-height seen-set keyed on `(validator_id, height, round, type)` |
| `internal/consensus/sync.go` | `BLOCK_SYNC`: answering requests, and pulling + adopting missed blocks |
| `cmd/b10coin-relay/main.go` | The relay: accepts outbound connections, forwards frames, knows nothing |
| `cmd/b10coin/main.go` | `--peers` / `--relay` flags on `node` and `devnet` |
| `scripts/deploy/` | systemd units, a build script, and the three-Pi recipe |
| `.github/workflows/ci.yml` | The ARM64 cross-compile, and the loopback integration test |

## Interfaces this milestone adds

```
wire.WriteFrame(w io.Writer, payload []byte) error
wire.ReadFrame(r io.Reader, max int) ([]byte, error)

wire.MsgType        MsgHello, MsgBlockSyncReq, MsgBlockSyncResp
wire.Hello          { ChainID string; Validator []byte; Height uint64; Sig []byte }
wire.BlockSyncReq   { From, To uint64; Requester []byte; Sig []byte }
wire.BlockSyncResp  { Blocks [][]byte }

transport.Transport  gains  Send(peer PeerID, data []byte) error
tcp.Options          { DialTimeout, BackoffBase, BackoffMax, MaxFrameBytes, Seed }
tcp.New, (*TcpTransport).Dial, .Listen, .AddPeer

transport.Dedup      Seen(key VoteKey) bool,  Forget(below uint64)

consensus.Syncer     answers BLOCK_SYNC requests from local blocks, and pulls/adopts
                     missed blocks through the ordinary ApplyBlock path

CLI: b10coin node --peers ADDR,...  --relay ADDR
     b10coin-relay --listen ADDR

Artifacts: b10coin_linux_arm64, b10coin-relay_linux_arm64, scripts/deploy/*
```

---

## Task 0: Let consensus blocks carry transactions

The largest untested integration in the project: M3's driver proposes `nil` transactions, so "a chain that pays faucet claims" and "a committee that agrees" have never run together. M4's real network makes the gap worse, so it closes first.

**Files:**
- Modify: `internal/consensus/driver.go`, `internal/consensus/driver_test.go`, `internal/node/node.go`
- Test: `internal/consensus/driver_test.go`

**Interfaces:**
- Consumes: `chain.Chain.Build(proposer, txs, timestamp)`, `mempool.Mempool.Take`
- Produces: a driver that proposes the mempool's transactions, bounded by the claim rule

- [ ] **Step 1: Write the failing test**

```go
// A committed consensus block must carry the transactions the mempool held. Until M4
// the driver proposed an empty list, so the faucet path and the consensus path had
// never been exercised together - a block that pays claims had never been agreed on by
// a committee.
func TestAConsensusBlockCarriesMempoolTransactions(t *testing.T) {
	// put a transfer into the mempool, drive the driver to a commit, and assert the
	// committed block's transaction list is non-empty and contains that transfer.
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/consensus/ -run TestAConsensusBlockCarriesMempoolTransactions -v`
Expected: FAIL — the committed block carries no transactions.

- [ ] **Step 3: Propose the mempool's transactions**

The driver's `build` must take from the mempool the way `node.RunOnce` already does, so there is ONE policy for which transactions a block carries, not two. Pass the taken slice to `chain.Build`. The claim bound is enforced in `ApplyBlock` already; do not duplicate it here.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -count=1 ./... && go test -race -count=1 ./...`
Expected: PASS, including the six scenarios and both acceptance commands.

- [ ] **Step 5: Commit**

```bash
git add internal/consensus internal/node
git commit -m "feat: let consensus blocks carry mempool transactions

M3's driver proposed an empty transaction list, so the faucet path and the
consensus path had never run together - a block that pays claims had never been
agreed on by a committee. The driver now takes from the mempool exactly as the
node does, so one policy decides a block's contents."
```

---

## Task 1: The wire frame

**Files:**
- Create: `internal/wire/frame.go`, `internal/wire/message.go`, `internal/wire/frame_test.go`

**Interfaces:**
- Consumes: `types.Encoder`/`Decoder`
- Produces: `wire.WriteFrame`, `wire.ReadFrame`, `wire.MsgType` with `MsgHello`/`MsgBlockSyncReq`/`MsgBlockSyncResp`, `wire.Hello`, `wire.BlockSyncReq`, `wire.BlockSyncResp`, and their encode/decode

- [ ] **Step 1: Write the failing tests**

```go
func TestFrameRoundTrips(t *testing.T)          // write then read returns the payload
func TestReadFrameRejectsAnOversizedLength(t *testing.T)  // a 4-byte length of 4 GiB must be refused, not allocated
func TestReadFrameRejectsATruncatedPayload(t *testing.T)  // EOF mid-payload is an error, not a short read
func TestHelloRoundTrips(t *testing.T)
func TestBlockSyncReqRoundTrips(t *testing.T)
```

The oversized-length test is the one that matters: a length-prefixed protocol whose reader trusts the prefix will allocate 4 GiB on a hostile 4-byte input. `max` must be enforced **before** the allocation.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/wire/ -v`
Expected: FAIL — `undefined: WriteFrame`

- [ ] **Step 3: Write the implementation**

```go
// Package wire is the framing every real connection speaks: a 4-byte big-endian
// length prefix followed by a canonical payload.
//
// The frame layer only DELIMITS. It does not interpret: the canonical encoding's own
// tag byte already discriminates a HELLO from a vote from a block. A frame layer that
// also parsed would be a second place for the wire semantics to live, and the two
// would drift.
package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

var (
	ErrFrameTooLarge = errors.New("wire: frame exceeds the maximum size")
	ErrShortFrame    = errors.New("wire: frame ended before its declared length")
)

// WriteFrame writes one length-prefixed payload.
func WriteFrame(w io.Writer, payload []byte) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// ReadFrame reads one length-prefixed payload, refusing anything over max.
//
// The bound is checked BEFORE the allocation. A reader that trusts the prefix would
// allocate 4 GiB on four hostile bytes, which is a remote denial of service on any
// node that accepts an inbound connection.
func ReadFrame(r io.Reader, max int) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if int(n) > max {
		return nil, fmt.Errorf("%w: %d bytes, maximum %d", ErrFrameTooLarge, n, max)
	}
	if n == 0 {
		return nil, fmt.Errorf("%w: zero-length frame", ErrShortFrame)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrShortFrame, err)
	}
	return payload, nil
}
```

`message.go` defines `HELLO` and the two `BLOCK_SYNC` messages with the same canonical discipline the consensus messages use: fixed-width integers, varint-prefixed byte slices, a leading tag byte, and `Done()` on decode.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -count=1 ./internal/wire/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/wire
git commit -m "feat: add the length-prefixed wire frame and the HELLO/BLOCK_SYNC messages"
```

---

## Task 2: `TcpTransport`

**Files:**
- Create: `internal/transport/tcp/tcp.go`, `internal/transport/tcp/backoff.go`, `internal/transport/tcp/tcp_test.go`

**Interfaces:**
- Consumes: `wire`, `transport.Transport`
- Produces: `tcp.Options`, `tcp.New`, `(*TcpTransport).Dial`, `.Listen`, `.AddPeer`, and the `Transport` methods including the new `Send`

- [ ] **Step 1: Write the failing tests**

Test over **real TCP on loopback** — not a pipe. The point of this task is that the socket path works.

```go
func TestTwoTransportsExchangeAMessage(t *testing.T)   // listen, dial, broadcast, receive
func TestBroadcastSkipsTheSender(t *testing.T)
func TestSendDeliversToExactlyOnePeer(t *testing.T)    // the unicast the sync needs
func TestARejectedFrameDoesNotKillTheConnection(t *testing.T)
func TestReconnectUsesBackoff(t *testing.T)            // a dropped peer is redialled, with growing delay
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/transport/tcp/ -v`
Expected: FAIL — `undefined: New`

- [ ] **Step 3: Write the implementation**

The transport owns one goroutine per connection: a reader that frames and dispatches to `OnMessage`, and a writer with a bounded queue. `Broadcast` and `Send` enqueue; neither blocks on a slow peer beyond the queue bound, because a validator that stops reading must not be able to stall the consensus loop of the validator sending to it.

Reconnection lives in `backoff.go` and takes its jitter from an **explicitly seeded** `*rand.Rand`, so a test can assert the delays rather than hoping.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -race -count=1 ./internal/transport/tcp/ -v`
Expected: PASS, and `-race` clean — this is the first concurrent code in the project outside the node's block loop.

- [ ] **Step 5: Commit**

```bash
git add internal/transport/tcp
git commit -m "feat: add a TCP transport with framed reads and backoff reconnection"
```

---

## Task 3: The dedup seen-set

**Files:**
- Create: `internal/transport/dedup.go`, `internal/transport/dedup_test.go`

**Interfaces:**
- Produces: `transport.VoteKey{Validator string; Height uint64; Round uint32; Type uint8}`, `transport.Dedup` with `Seen(key) bool` and `Forget(below uint64)`

- [ ] **Step 1: Write the failing tests**

```go
func TestDedupReportsAKeySeenOnceAndOnlyOnce(t *testing.T)
func TestDedupForgetsBelowAHeight(t *testing.T)   // bounded memory, or the map grows forever
func TestDedupIsSafeUnderConcurrentUse(t *testing.T)  // frames arrive on many reader goroutines
```

The third matters: with one goroutine per connection, the seen-set is written concurrently. An unsynchronised map here is a crash, and Go's race detector will say so.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test -race ./internal/transport/ -run TestDedup -v`
Expected: FAIL — `undefined: Dedup`

- [ ] **Step 3: Write the implementation**

A `map[VoteKey]struct{}` behind a mutex, with `Forget(below)` called as the chain advances so memory is bounded by the live height window rather than by the length of the run.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -race -count=1 ./internal/transport/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/transport
git commit -m "feat: add the per-height vote dedup seen-set"
```

---

## Task 4: `BLOCK_SYNC` — catch-up

This is the M3 carry-forward the limits note names: *"a validator that falls behind cannot adopt the blocks it missed."* Without it a reconnecting validator can never rejoin, so a real network is unusable.

**Files:**
- Create: `internal/consensus/sync.go`, `internal/consensus/sync_test.go`
- Modify: `internal/transport/transport.go` (the `Send` addition), `internal/transport/sim/sim.go` (implement it)

**Interfaces:**
- Consumes: `wire`, `transport.Send`, `chain`
- Produces: `consensus.Syncer` with `Answer(req) ([][]byte, error)` and `PullAndAdopt(from uint64) error`

- [ ] **Step 1: Write the failing tests**

```go
// A validator that fell behind must be able to rejoin. Without catch-up the M3
// scenarios could only assert that a lagging validator was BEHIND rather than forked;
// with it they can assert it converges, which is what a real network needs.
func TestASyncerPullsAndAdoptsMissedBlocks(t *testing.T)
func TestSyncerRefusesBlocksThatDoNotValidate(t *testing.T)  // the whole point of pull-with-verify
func TestSyncerAdoptsNothingWhenAlreadyCurrent(t *testing.T)
```

The second is the one that matters: a peer that serves a block failing `ApplyBlock` must not get it into the chain. Catch-up that trusts its source is a remote path for installing unvalidated state.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/consensus/ -run TestSyncer -v`
Expected: FAIL — `undefined: Syncer`.

- [ ] **Step 3: Write the implementation**

`Answer` serves encoded blocks from the local chain by height range, refusing a range it does not hold. `PullAndAdopt` requests the range above its head, decodes each block, and appends it **through the ordinary `chain.Append` path**, so the same validation that guards a live block guards an adopted one. Any block that fails is dropped and the pull stops rather than skipping ahead.

`Send` goes on the `Transport` interface with a doc comment saying why it exists (a request/response is not a broadcast), and the simulator implements it as an immediate unicast so determinism is preserved.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -count=1 ./... && go test -race -count=1 ./...`
Expected: PASS.

- [ ] **Step 5: Add the recovery scenarios**

Now that recovery exists, M3's limits 2 and 3 stop being limits. Add scenarios:

- a validator that misses blocks **catches up and converges** (scenario 4 and 6 strengthened from "prefix" to "converges");
- a scenario that runs **with loss and reordering** (non-zero `DropPercent` and `JitterMS`) and still finalises.

The second is the one the milestone goal has claimed since M3 and never exercised.

- [ ] **Step 6: Commit**

```bash
git add internal/consensus internal/transport
git commit -m "feat: add BLOCK_SYNC catch-up, so a lagging validator can rejoin

M3's limits note recorded that a validator which fell behind could never adopt
the blocks it missed, because Transport offered only Broadcast. BLOCK_SYNC is a
pull: the lagging validator asks for a height range and adopts each block only
through the ordinary Append path, so a peer cannot install unvalidated state.
Transport gains Send for it - a request/response is not a broadcast."
```

---

## Task 5: The relay

**Files:**
- Create: `cmd/b10coin-relay/main.go`, `internal/relay/relay.go`, `internal/relay/relay_test.go`

**Interfaces:**
- Produces: a relay that accepts outbound connections, tracks a registry, and forwards frames between every other registered peer

- [ ] **Step 1: Write the failing test**

```go
// The relay exists because of one asymmetry: inbound to a home Pi is blocked, outbound
// is not. So every validator dials OUT to the relay, and the relay forwards. It must
// know nothing about consensus - if it did, it would become a place where consensus
// could be wrong.
func TestRelayForwardsBetweenTwoPeers(t *testing.T)
func TestRelayDoesNotForwardToTheSender(t *testing.T)
func TestRelaySurvivesAPeerDisappearing(t *testing.T)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/relay/ -v`
Expected: FAIL — `undefined: relay.New`

- [ ] **Step 3: Write the implementation**

The relay reads a frame, forwards it to every other registered connection, and does nothing else. It does not parse the payload beyond the frame length. That is the whole design: **a relay that understood consensus would be a relay that could be wrong about it**, and the trust property that makes this acceptable is that every consensus message is signed, so censorship and delay are the worst it can do — both liveness, never safety.

Document that trade in the command's own `--help` and in the README, not only in a comment.

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test -race -count=1 ./internal/relay/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/b10coin-relay internal/relay
git commit -m "feat: add the relay, a forwarder that knows nothing about consensus"
```

---

## Task 6: Validators over real TCP

**Files:**
- Create: `internal/simnet/tcp_test.go` (or `internal/devnet/tcp_test.go`)
- Modify: `cmd/b10coin/main.go` (the `--peers`/`--relay` flags)

**Interfaces:**
- Consumes: `tcp`, `consensus`, `chain`, `genesis`
- Produces: a test that runs four validators over loopback TCP and finalises blocks

- [ ] **Step 1: Write the failing test**

```go
// The simulator proves the PROTOCOL; this proves the WIRE. Four validators, four real
// TCP connections, one process - the same consensus code that the Pi run will execute,
// over sockets instead of a virtual network.
func TestFourValidatorsFinaliseOverRealTCP(t *testing.T) {
	// listen on four loopback ports, connect them in a star through one relay or a
	// full mesh, and drive until each chain reaches 20 blocks and agrees.
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/simnet/ -run TestFourValidatorsFinaliseOverRealTCP -v`
Expected: FAIL — the TCP path is not wired.

- [ ] **Step 3: Wire it**

The CLI gains `--peers` (a list of addresses to dial) and `--relay`. A node with peers dials them and runs consensus over the resulting transport; a node without them keeps the current single-node behaviour, so the M0–M3 acceptance commands are untouched.

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test -race -count=1 ./internal/simnet/ -run TestFourValidatorsFinaliseOverRealTCP -v`
Expected: PASS. Then re-run both acceptance commands and confirm the roots are unchanged.

- [ ] **Step 5: Commit**

```bash
git add internal cmd/b10coin
git commit -m "feat: run validators over real TCP, with --peers and --relay"
```

---

## Task 7: Cross-compile for the Pi, and the deployment recipe

**Files:**
- Create: `scripts/deploy/build.sh`, `scripts/deploy/b10coin.service`, `scripts/deploy/b10coin-relay.service`, `scripts/deploy/README.md`
- Modify: `.github/workflows/ci.yml`, `Makefile`, `README.md`

**Interfaces:**
- Produces: `b10coin-linux-arm64`, `b10coin-relay-linux-arm64`, and the recipe a person follows to run three Pis

- [ ] **Step 1: Add the cross-compile**

```make
# A cross-compile that only works on one machine is not a deliverable, so CI builds it.
arm64:
	GOOS=linux GOARCH=arm64 go build -o $(BIN)/b10coin-linux-arm64 ./cmd/b10coin
	GOOS=linux GOARCH=arm64 go build -o $(BIN)/b10coin-relay-linux-arm64 ./cmd/b10coin-relay
```

Add it to `ci.yml` so the Pi binary cannot rot silently.

- [ ] **Step 2: Write the deployment recipe**

`scripts/deploy/README.md` must let a person who has never seen this project go from three unopened Pis and a VPS to a running testnet. It states, in order: what to buy, how to build, how to copy the binary, the genesis each Pi uses (they must all share one — a chain ID mismatch is the most likely first failure), the relay's address, the systemd units, and **exactly what output means success**.

- [ ] **Step 3: Verify the artifacts exist and are for the right platform**

Run:
```bash
make arm64 && file bin/b10coin-linux-arm64 bin/b10coin-relay-linux-arm64
```
Expected: both report `ELF 64-bit LSB executable, ARM aarch64`.

- [ ] **Step 4: Commit**

```bash
git add scripts/deploy Makefile .github/workflows/ci.yml README.md
git commit -m "feat: cross-compile for ARM64 and document the three-Pi deployment"
```

---

## Task 8: The acceptance harness for the Pi run

**Files:**
- Create: `scripts/deploy/acceptance.sh`
- Modify: `README.md`

**Interfaces:**
- Produces: one command that queries every validator and reports whether the milestone's acceptance criterion holds

- [ ] **Step 1: Write the harness**

The milestone's acceptance is *"3 validators on real Raspberry Pis across separate networks finalize blocks."* Make it a single command that a person runs and pastes the output of:

```bash
scripts/deploy/acceptance.sh --pis pi-a.local,pi-b.example.net,pi-c.example.net --relay relay.example.net
```

It queries each node's RPC height, asserts all three are advancing and agree, and prints a verdict. **It must distinguish "all three agree" from "all three are reachable but stalled"** — a network that connects and never finalises looks identical to a healthy one if the check only tests reachability.

- [ ] **Step 2: Verify the harness against local instances**

Run it against four loopback nodes started from the ARM64... no: against the host build, since the Pis are the user's step. Confirm it prints a PASS verdict locally and a FAIL verdict when one node is stopped.

- [ ] **Step 3: Commit**

```bash
git add scripts/deploy README.md
git commit -m "feat: add the acceptance harness for the three-Pi run"
```

---

## Self-Review

**Spec coverage.** §6.6 asks for a swappable transport (Task 2), a frame format (Task 1), `HELLO` (Task 1), `BLOCK_SYNC` (Task 4), dedup (Task 3), backoff reconnection (Task 2), and an outbound relay on a cheap VPS (Task 5). §10's M4 row asks for a cross-compiled ARM64 binary (Task 7) and three Pis finalising (Tasks 7–8). The two M3 carry-forwards the limits note deferred — no catch-up, and no transactions in consensus blocks — are Tasks 4 and 0.

**Not in this plan, deliberately:** hole punching and libp2p (the spec says no NAT code beyond the relay until M5); `PEER_EXCHANGE` (M5); TLS on the relay (the payload is signed already, and a testnet relay that forwards to registered validators does not need it yet — but the recipe must say so plainly); staking and committee rotation (M5).

**The three things most likely to go wrong.** First, **a decoder that trusts its input** — the length prefix is the classic 4-GiB allocation bug, and Task 1 pins it before the allocation. Second, **catch-up that trusts its source**, which would be a remote path for installing unvalidated state; Task 4 routes every adopted block through the same `Append` that guards a live one. Third, **a test that passes without testing anything** — this project has shipped at least a dozen such tests across three milestones, so every task here names the one thing that must break for its test to fail, and the integration test runs over **sockets**, not a pipe, because the socket path is the deliverable.

**Honest limits, stated up front.** The relay is a single point of failure and a censorship point: a relay that partitions the validator set stalls consensus. Safety is not at risk — every message is signed, so the worst a malicious relay can do is delay or drop — but liveness is, and a testnet acceptance run that depends on one VPS is not a decentralisation claim. Multiple relays, direct connections where NAT permits, and hole punching are M5+. And the ARM64 binary is cross-compiled and tested over loopback, **not on a Pi**: nothing in this milestone establishes performance on the target hardware, and the Argon2 tuning in particular was derived from a published Pi-4 figure that has never been measured on the actual device.
