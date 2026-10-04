# b10coin security and quality audit

| | |
|---|---|
| Repository | `github.com/cti97/b10coincom`, branch `main`, commit `8224194` (clean tree) |
| Date | 2026-10-04 |
| Method | Static review of every Go source and test file (about 27,700 lines across 19 packages), the deploy scripts, the systemd units, CI, the README and the design/plan documents. No Go toolchain was available on the audit machine, so nothing was executed: no tests, no coverage profile, no `govulncheck`. Every finding cites the lines it rests on and was re-checked against the tree before inclusion. |
| Scope | Security (consensus safety and liveness, network exposure, denial of service, cryptography, storage integrity), test coverage, build and supply chain, operations, documentation accuracy. |
| Out of scope | Changing code. This document recommends; it does not patch. |

Line references are `path:line` against commit `8224194`.

---

## 1. Executive summary

**The low-level engineering is unusually careful for a project of this age.** The canonical codec rejects non-minimal varints, short buffers and trailing bytes and is fuzzed; every hash is domain-separated and length-prefixed; the frame reader bounds before it allocates; the quorum arithmetic is exact and overflow-free and checked against a big-integer reference; votes are counted once per validator; the precommit lock is written to a CRC-framed, crash-tolerant log before the precommit leaves the engine; the simnet scenarios assert on 32-byte block IDs rather than heights. **No Tendermint safety violation was found**: with less than one third of total power Byzantine, two conflicting blocks cannot both commit at one height.

**The serious problems sit one layer up**, in what the protocol does not yet do and in what the deployment exposes:

| Sev | ID | Finding | Area |
|---|---|---|---|
| **Critical** (deployed configuration) | A-1 | Every networked validator signs with a **publicly derivable fixture key**, and the deploy recipe opens the relay port to the internet. Anyone can be every validator. The README's "a malicious relay cannot forge a vote" claim is false today. | cmd, devnet, simnet, deploy |
| **High** | C-1 | Validators **prevote, lock on and commit a proposal without validating the block** (no structure, parent, height or state-root check). One Byzantine proposer gets a garbage block committed by the honest quorum; every node's `Append` then refuses it and the whole committee parks forever. | consensus |
| **High** | C-2 | A locked proposer **ignores its lock and proposes a fresh block**, then nil-prevotes its own proposal. No production code builds a justification. Once one third of power is locked on a round that did not commit, the height stalls with unbounded timeout growth. | consensus |
| **High** | N-1 | Through the relay, the transport's "ID handshake" reads **whatever frame arrives first** as the peer's identity. A stranger sending the bytes `v0`, `v1`, `v2` to the relay makes validators refuse their own relay link as a self-connection, after which the maintainer **never redials** until process restart. | transport/tcp, relay |
| **High** | N-2 | The relay's documented memory bound is wrong by the write-queue factor (16 GiB at defaults, not 256 MiB), slots and memory can be pinned **indefinitely** by a 5-byte keepalive frame, and a flooder can **censor honest votes** by keeping every receiver queue full. | relay |
| **High** | S-1 | The signed transaction body carries **no chain identifier**. A transfer signed on one b10coin chain is valid on any other with the same nonce and balance. | types |
| **High** | O-1 | **No single-writer lock on the data directory.** Two processes on one `--dir` (a systemd restart racing a slow shutdown) interleave appends and corrupt both the block log and the consensus lock log. | store, chain |
| **High** | R-1 | The mempool admits any signature-valid faucet claim and holds over-bound claims forever. 10,000 garbage claims **wedge the single-node pool for about 42 minutes**, refillable at 8 per block. | mempool, rpc |
| **High** | B-1 | **Go 1.23 is end-of-life** (no security fixes since Go 1.25 shipped), CI runs no `govulncheck`, no linter beyond `go vet`, actions are pinned by mutable tag, and there is **no LICENSE file** on a public repository. | build, governance |

Counts of enumerated findings: **Critical 1, High 9, Medium 28, Low 35, Info 4** (several Low and Info entries bundle closely related items). Sections 2 through 4 give every finding; section 5 covers tests; section 6 covers build, operations and documentation; section 7 is the prioritized remediation order.

A note on calibration. This is a valueless testnet, and many of these findings are acknowledged as "later milestone" work in code comments or plan documents. Severity here is rated against **what the README and deploy recipe tell an operator today**, because that is what a reader of the repository will believe. Where the code acknowledges a limitation, the finding says so.

---

## 2. Critical and High findings

### A-1 · Critical (deployed) · Validator keys are publicly derivable; the relay is open to the internet

**Where:** `internal/simnet/simnet.go:125-128` (`ValidatorKey`), `internal/devnet/tcpnode.go:219-220` (`StartValidator` derives its seat key from the index), `cmd/b10coin/main.go:446-480` (`runNetworkedNode`, no `--key` flag), `scripts/deploy/README.md:207` (`sudo ufw allow 7001/tcp`), `cmd/b10coin-relay/main.go:148` (`--addr` default `:7001`), `README.md:216-219` (the relay trust claim).

**What the code does.** The networked node derives its private key as `ed25519.NewKeyFromSeed(BLAKE3("b10coin-simnet-validator" ‖ byte(i)))`. The committee size is published in the chain ID (`b10coin-simnet-N`) that `/status` returns. There is no key file, no keystore, no `--key` flag. The relay authenticates nothing by design, and the deploy recipe opens its port to all sources while the relay's own help text says to run it behind an IP allowlist.

**Why it matters.** Anyone who reads the repository can sign proposals, prevotes and precommits for any seat, connect to the public relay, and fork, equivocate or halt the committee at will. The HELLO signature check in `observeHello` passes trivially. The README states that because every message is signed, "a malicious relay can censor or delay, but it cannot forge a vote or a proposal"; with fixture keys, forging requires no relay at all.

**Acknowledged?** In code comments (`tcpnode.go:87-93` "There is no secret anywhere in it", `simnet.go:130-133`) and the M4 plan. Not in the README node, relay or deployment sections, and contradicted by the relay trust paragraph.

**Fix.** Add `b10coin keygen` and a `--key PATH` flag; derive the committee from a genesis file that lists public keys rather than from `N`; until then, put a prominent warning in README, `usage()` and the deploy recipe, and make the recipe's firewall step an allowlist (`ufw allow from <ip> to any port 7001 proto tcp`).

### C-1 · High · Proposals are committed without block validation; one Byzantine proposer halts the network

**Where:** `internal/consensus/engine.go:267-284` (`onProposal`), `:312-346` (`maybePrevote`), `internal/consensus/driver.go:358-382` (`flush` and `appendRefused`), `engine.go:179-181` (`OnTimeout` returns at `StepCommit`).

**What the code does.** `onProposal` checks the envelope's height and round, the envelope signature, and that the signer is this round's proposer. `maybePrevote` then checks only the justification and the lock. Nothing checks `Block.Header.Height == p.Height`, `Block.Header.ParentHash == e.parent`, `Block.ValidateStructure()`, or the state root via `chain.Probe`. The chain's `Append` does all of that, but only after the engine has committed. On `Append` failure the driver sets `appendRefused`, the engine stays at `StepCommit`, `OnTimeout` returns early, and the node never proposes or advances again.

**Attack.** Validator X waits to be drawn as proposer, builds a normal block, overwrites `Header.StateRoot` with garbage, re-signs, and proposes with `ValidRound -1`. Every honest validator prevotes it (signature and proposer checks pass, justification is trivially valid, no lock yet), the polka forms, every validator **persists a lock on the garbage block** and precommits, the quorum commits. Every node's `Append` fails, every node parks. Catch-up cannot help because no node is ahead. Restart restores the lock on the garbage block. One validator of any power has permanently halted the chain.

**Acknowledged?** No. `TestDriverRejectedAppendStaysAtSameHeight` (`driver_test.go:373-434`) exercises the single-node path and treats parking as the desired outcome.

**Fix.** Add a `validate func(*types.Block) error` seam to the engine that the driver fills with structure, height, parent and `chain.Probe` state-root checks. Call it in `maybePrevote` before the lock check; on failure prevote nil (Tendermint's `valid(v)` rule). Reject `Block.Header.Height != p.Height` in `onProposal` as a protocol error. Add the 4-validator test that a bad-root proposal is nil-prevoted and the height still commits in a later round.

### C-2 · High (liveness) · No proof-of-lock; a locked proposer proposes a fresh block it then refuses

**Where:** `internal/consensus/engine.go:394-427` (`StartProposing` always emits `ValidRound: -1`), `:336-338` (locked proposer nil-prevotes its own block), `internal/consensus/message.go:251` (`encodeJustification` has no non-test caller), `internal/consensus/driver.go:197-242` (`build` always constructs a new block from the mempool), `driver.go:319` (`timeoutAt = now + base + round*step`, uncapped).

**What the code does.** The engine never re-proposes a locked block and never builds a justification. Tendermint's liveness relies on a locked proposer proposing its locked value with `validRound = lockedRound` and the polka as proof, and on every validator tracking `validValue`. Neither exists.

**Scenario.** Four validators, quorum 3, lossy network. Round 0: V3 proposes B, all prevote B, V0 and V1 see the polka and lock on B, V2's third prevote is lost, V3's precommit is delayed, nobody commits. Every later round's fresh proposal is nil-prevoted by V0 and V1, so no polka forms, so nobody unlocks. Recovery requires V3 to be redrawn **and** `build` to produce byte-identical bytes, which a single new mempool transaction prevents. Timeouts grow linearly with no cap.

**Acknowledged?** Partially. README says the unlock path is "unreachable from any shipped driver" as a coverage note, not as a stall.

**Fix.** Retain the prevotes that produced the lock; in `StartProposing`, if locked, propose the locked block with `ValidRound = lockedRound` and `Justification = encodeJustification(prevotes)`. Add `validValue/validRound` so an unlocked proposer re-proposes the last polka'd block. Cap round timeouts.

### N-1 · High · Relay handshake reads an arbitrary first frame as identity; a stranger induces permanent dormancy

**Where:** `internal/transport/tcp/tcp.go:571-604` (`adopt` writes `LocalID` then reads the first inbound frame as the peer ID), `:621-625` (`ErrSelfConnection` if it equals the local ID), `:528-535` (`maintain` **returns** on `ErrSelfConnection` or `ErrDuplicatePeer`, so the address is never redialled), `internal/relay/relay.go:435-452` (the relay forwards every frame to every other connection, never echoes), `internal/devnet/tcpnode.go:130-131` (admits "through a relay, the name is whatever frame first arrived"), `tcpnode.go:246` (IDs are `v0`, `v1`, ... and fully predictable).

**Attack.** A stranger connects to the relay and streams the frames `v0`, `v1`, `v2` every few hundred milliseconds. Whenever a validator connects or reconnects (boot, relay restart, any blip), its handshake read has a good chance of consuming its own name, `adopt` returns `ErrSelfConnection`, `maintain` goes dormant, and that validator is off the network until someone restarts the process. The effect outlives the attacker. The README's "validators reconnect to a restarted relay with exponential backoff" does not hold in this path.

**Related.** The same dormancy applies to `ErrDuplicatePeer`: with `--listen`, a squatter that dials first and announces `v1` becomes the incumbent, the real `v1`'s dial is refused and its maintainer exits for good (`tcp.go:626-637`, `newcomerWins` keeps same-direction incumbents). The first validator to reach a fresh relay also fails its handshake every 5 seconds until a second party speaks, which delays committee formation after a relay restart by up to 35 seconds (undocumented).

**Fix.** Make outbound maintainers never exit on self or duplicate errors: back off (the cap is 30 seconds) and retry; the registry's duplicate check already prevents churn when the incumbent is genuine. Separately, give the transport a relay-aware dial mode that registers the connection under a fixed name such as `relay:<addr>` and skips the ID read. Bound the handshake ID frame to a few hundred bytes (`tcp.go:589` reads it under the full 1 MiB frame bound).

### N-2 · High · Relay memory bound misstated; indefinite pinning; censorship by queue fill

**Where:** `internal/relay/relay.go:385` (read deadline armed per frame), `:458-473` (`writer` has no write deadline), `:444-451` (per-receiver queue shared by all senders, newest frame dropped when full), `:92-94` (acknowledges "64 MiB per wedged connection"), `README.md:236-238` and `cmd/b10coin-relay/main.go:68-70` (claim "at most max-conns × max-frame-bytes ... each for at most one read timeout, never forever").

**What the code does.** The read deadline is reset by any complete frame, so a 5-byte frame every 100 seconds keeps a slot forever while the client never reads. The writer blocks indefinitely on a non-reading peer and its 64-slot queue stays full. Payload slices are shared across targets, so the aggregate pin is `max-conns × write-queue × max-frame-bytes` = 256 × 64 × 1 MiB = 16 GiB, not 256 MiB.

**Attacks.** (a) One sender plus 16 non-reading sinks, each fed 64 distinct 1 MiB frames, exceeds a 1 GB VPS's memory after about 1 GiB of upload; systemd restarts the relay into the same attacker. (b) A flooder whose upload to the VPS exceeds a Pi's download keeps every Pi's queue full; honest votes arriving at a full queue are dropped. The README limits "a stranger can censor" to a malicious relay; any stranger who finds the port can. (c) No per-IP cap, so one host can hold all 256 slots and push honest validators into `RefusedConns` and 30-second backoff (`relay.go:342`).

**Fix.** Per-frame write deadline in `writer` that calls `finish` on expiry; byte-bounded queues instead of frame-bounded; per-sender fair share of each receiver's queue or a per-connection ingress rate limit; per-source-IP cap at accept; `MemoryMax=` in the unit; a much lower `--max-conns` default for a 3-validator star; correct the README and `--help` arithmetic.

### S-1 · High · Transactions are replayable across chains

**Where:** `internal/types/tx.go:59-81` (`encodeBody`, `SigningHash`), `internal/types/address.go:34-39` (`AddressFromPub` has no chain input).

**What the code does.** The signed body is `Type ‖ From ‖ PubKey ‖ Nonce ‖ (To, Amount | Epoch, PowNonce)`, hashed under the domain `b10coin-tx`. Neither the chain ID nor the genesis hash is included; `ChainID` is used only by the wire handshake and `/status`.

**Scenario.** Alice funds the same key on testnet and on a community fork with identical parameters, pays Bob on the fork; Bob re-submits the identical bytes to a testnet node and is paid again. The same applies to devnet versus testnet, and to any future chain reset that keeps keys. Faucet claims are not replayable only because puzzle parameters happen to differ per chain.

**Fix.** Add the genesis hash (or chain ID) as an extra `HashParts` part in `SigningHash`, thread it through `VerifySignature`, and add a test that a devnet-signed transaction is refused by a testnet-parameterised state. Consider the same for header and vote signing hashes (`message.go:59-73`, `:161-169` carry no chain ID; lower risk because block IDs will not collide across chains, but cheap to add).

### O-1 · High · No single-writer lock on the data directory

**Where:** `internal/store/store.go:108-128` (`Open` does `MkdirAll` and `OpenFile(O_CREATE|O_APPEND|O_WRONLY)`; nothing exclusive), `:250` (`Append` records an offset from its own `Seek`), `:199-201` (`scan` numbers heights by record count), `internal/chain/chain_lock_test.go` and `internal/store/lock_test.go` test the **consensus precommit lock**, not a file lock. A grep for `flock`, `LockFileEx`, `O_EXCL` finds nothing.

**Scenario.** Two `b10coin node --dir X` processes (the realistic case is a systemd restart racing a slow shutdown) both replay to height N and both append N+1 with different hashes. The next `Open` numbers the second N+1 as N+2 and `chain.Open` fails with `ErrGenesisReplay`. Worse, both processes share one `locks.log`, so a validator's safety promise can be interleaved by its twin, which is exactly what the lock log exists to prevent.

**Fix.** Take an exclusive advisory lock on a `LOCK` file for the store's lifetime (`flock` / `LockFileEx` via `x/sys`), fail `Open` with "data dir in use", and test that a second `Open` on the same directory fails.

### R-1 · High (Medium with the default loopback bind) · Garbage faucet claims wedge the mempool

**Where:** `internal/mempool/mempool.go:59` (`Add` checks only the signature), `:99-105, 111` (`Take` keeps over-bound claims in the pool), `cmd/b10coin/main.go:377` (`mempool.New(10_000)`), `internal/devnet/tcpnode.go:84` (1,000 for the networked node), `internal/state/apply.go:121` (Argon2id evaluated after the cheap checks pass).

**What the code does.** A claim with a fresh key, `Epoch: 1` and a random `PowNonce` costs the attacker one keygen and one signature. It is evicted only when `Take` hands it to `SelectApplicable`, which happens at most 8 claims per block. Transfers drain every block; claims are the one class the pool deliberately holds back, which turns capacity into a wedge.

**Impact.** 10,000 garbage claims over keep-alive HTTP (about one second of attacker CPU) fill the pool; every honest `POST /tx` gets `ErrFull` for 1,250 blocks (about 42 minutes), and the attacker tops up 8 per block indefinitely. Each taken garbage claim also costs the node a full Argon2id evaluation (8 MiB on testnet). The mempool test comment at `mempool_test.go:33-36` sees the asymmetry but believes the per-block bound neutralises it.

**Fix (layered).** At admission, run the cheap stateful checks against the head state (epoch is current or next, `ClaimedEpoch < epoch`, nonce matches); cap claims per pool separately from transfers; age out claims skipped by `Take` after N blocks; per-source limits on the RPC. The transfer path has the same signature-only admission and no per-sender bound (Medium, below).

### B-1 · High · End-of-life toolchain, no vulnerability scanning, mutable action pins, no licence

**Where:** `go.mod:3` (`go 1.23.0`, no `toolchain` directive), `.github/workflows/ci.yml:18, 59, 77` (`go-version: '1.23'`), `:15-16` (`actions/checkout@v4`, `actions/setup-go@v5` by tag, no `permissions:` block), repository root (no `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, `.github/CODEOWNERS`, `.github/dependabot.yml`).

**Why it matters.** Go 1.23 left the two-release support window when Go 1.25 shipped in August 2025; released binaries carry any `net/http`, `crypto/*` or runtime fixes since. CI runs `go vet` only: no `govulncheck`, `staticcheck`, `gofmt -l` gate (the README claims gofmt-clean but nothing enforces it) or `go mod tidy` diff. Tag-pinned actions run whatever the tag points at with the workflow's token. Without a licence, a public repository is all-rights-reserved: nobody may legally copy, run or redistribute the code, which defeats the stated multi-platform participation goal.

**Fix.** Bump to a supported Go line with a `toolchain` directive and `go-version-file: go.mod`; add a lint job (`gofmt -l`, `go mod tidy` diff, `staticcheck`, `govulncheck`, also on a schedule); pin actions to commit SHAs and add `permissions: contents: read`; add Dependabot for `gomod` and `github-actions`; add a LICENSE (MIT, Apache-2.0 or BSD-3), `SECURITY.md` with a disclosure contact, `CONTRIBUTING.md`, and `CODEOWNERS`.

---

## 3. Medium findings

### 3.1 Consensus (`internal/consensus`)

| ID | Finding | Where | Fix |
|---|---|---|---|
| C-3 | **No round synchronisation.** Messages for other rounds are dropped, not buffered; no `f+1`-round skip; no retransmission; round not persisted (restart re-enters round 0); `enterRound` discards the previous round's precommits so a late quorum cannot commit here. Validators desynchronise inside any long undecided height. | `engine.go:268, 287, 203-210`, `driver.go:110-130, 306-320` | Per-height multi-round vote sets with a small future window; jump on `f+1` power at a higher round; commit from a precommit quorum in any round; persist `(height, round)`; cap `TimeoutStep` growth. |
| C-4 | **BLOCK_SYNC requests are replayable and amplifying, served on the reader goroutine.** Signature covers `(From, To, Requester)` only, no nonce; each request costs up to 64 disk reads, a full certificate re-verification per height (quorum-many Ed25519 verifies), and a reply of up to 1 MiB; no rate limit despite the wire comment promising one; `Route` runs `Handle` inline, so on a relay star one sync request head-of-line blocks every consensus frame. | `sync.go:203-238, 321-336, 362-404`, `router.go:556-568`, `wire/message.go:102-103` | Nonce or timestamp plus responder key in the signed request; short-lived seen-set; per-requester and per-connection rate limit; cache the encoded certificate at `RecordCommit`; move `Handle` to a bounded worker. |
| C-5 | **Sync responses are uncorrelated with requests and the sender is ignored.** One-slot `reply`; `Receive` discards `from`; a pull consumes the first response filed after its request; an empty response reads as "caught up". Any connected peer (TCP identities are unauthenticated strings) can make every catch-up pull fail or appear complete. | `sync.go:156-163, 431-441, 563-573` | Request nonce echoed in the response; check `from == Peer`; accept only units in `[start, end]`; per-request reply channel. |
| C-6 | **One Byzantine member monopolises catch-up.** `recordHeight` keeps the maximum ever announced per peer and never decays it; `tallestPeer` always returns the global max; `maybeCatchUp` pulls only from it and discards errors. A HELLO with `Height = 2^62` makes every wave wait `ReplyWait` on that peer forever; vanished peers keep their entry. The comment considers only strangers inflating heights, not members. | `devnet/tcpnode.go:457-500` | Demote a peer whose attestation a pull cannot substantiate; expire entries not refreshed within a few waves; rotate to the next-tallest on silence; cap the announced height used for selection. |
| C-7 | **Certificate archive is unbounded in memory and lost on restart.** After a rolling restart of the committee, no validator can serve any history committed before the restarts, so a lagging or new validator can never catch up on those heights. Acknowledged as "in-memory"; the consequence is not stated. | `sync.go:169-182, 284-315, 338-404` | Persist the certificate with the block in the store; serve from disk; small LRU in memory. |
| C-8 | **Per-frame decode and signature verification before any membership check.** Every inbound frame costs `DecodeVote` + `Verify`, then `DecodeProposal` (up to 1 MiB, 10,000 txs) + `Verify`, before the key is checked against the committee. The router comment claiming an attacker "cannot pass" the consensus branch is wrong: a self-signed vote passes `Verify` and reaches the engine. CPU DoS on a Pi from unauthenticated connections. | `router.go:482-495, 550-554`, `engine.go:271-274`, `message.go:115-126` | Committee key set checked first; height window check for votes before verification; correct the comment. |

### 3.2 Networking (`internal/wire`, `internal/transport/tcp`, `internal/relay`)

| ID | Finding | Where | Fix |
|---|---|---|---|
| N-3 | **Unbounded inbound connections with `--listen`.** No `MaxConns`; read deadline cleared after the handshake ("may block forever"); no write deadline anywhere; every dialer with a distinct 1-byte ID is installed in `conns`, appears in `Peers()`, and receives a private copy of every broadcast with a 128-frame queue. A stranger sending a 1 MiB header and stalling pins 1 MiB per connection with no deadline. High if `--listen` is set; the deploy recipe leaves it off. | `tcp.go:376-418, 596, 759-773, 264` | `MaxConns` with accept-time check; idle read deadline; per-frame write deadline; do not admit to `Peers()` until a verified HELLO from a committee member arrives. |
| N-4 | **`DecodeBlockSyncResp` pre-allocates up to 56× the frame size on a hostile count** (`make([]BlockSyncUnit, 0, count)` where `count` is bounded only by remaining bytes; 56 bytes per unit in memory versus 6 on the wire; similarly 24× for votes). Reachable by any peer, since the router tries this decoder on every unrecognised frame. GC churn and transient pressure rather than a crash. | `wire/message.go:200-204, 217` | Cap the capacity hint to `remaining / minUnitBytes`, or append without a hint; add a MemStats assertion like the frame test. |
| N-5 | **Wire tags 1/2/3 collide with consensus tags 1/2/3.** The plan's Design Decision 2 says HELLO and consensus messages start with different tags; they do not. The verified-decode workaround is correct but costs every HELLO and sync frame a failed vote and proposal decode, and lets an attacker craft a frame that structurally decodes as a vote so each validator spends an Ed25519 verify first. Nothing is deployed yet. | `wire/message.go:32-36`, `router.go:6-13` | Renumber wire tags into a disjoint range now. |
| N-6 | **`dispatch` serialises all readers behind one user callback.** Over the relay every stranger frame reaches every Pi's reader and goes through `dispatchMu` → `Route` → up to two verifies before it is dropped; one flooder delays honest vote dispatch on every validator. | `tcp.go:749-755` | Rate limit at the transport; see C-8. |
| N-7 | **No authentication or chain-ID check at the transport.** Acknowledged in the package comment. Consequences not spelled out: strangers are peers for `Broadcast`; chain mismatch is detected only as silence; the dedup set, if ever wired before signature verification, would let a stranger pre-seed `(validator, height, round, type)` keys and have honest votes dropped. | `tcp.go:19-25`, `transport/dedup.go:24-26` | Signed HELLO before admission; call `Seen` strictly after `Verify`; bound dedup heights and shard by height so `Forget` is not an O(n) scan. |
| N-8 | **The only stated mitigation for the open relay, an IP allowlist, is contradicted by the deploy recipe and impractical for home validators behind CGNAT.** | `README.md:242-244`, `scripts/deploy/README.md:202-208` | Show the allowlist and how to keep it current, or add in-process access control (a pre-shared first frame compared by length and equality, keeping the "parses nothing" posture). |
| N-9 | **Relay `Stats()` is never surfaced.** `Dropped` and `RefusedConns` are exactly the counters that would reveal N-2; the deploy README says "a relay with no error and no output is healthy", which is also true when it is dropping. | `relay.go:304-315`, `cmd/b10coin-relay/main.go` | Log stats on a timer and on SIGUSR1. |
| N-10 | **Relay unit lacks `MemoryMax=`, `LimitNOFILE=` and most cheap sandboxing**; the node unit lacks `PrivateTmp`. Baseline (`User`, `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`) is good. | `scripts/deploy/b10coin-relay.service:38-41`, `b10coin.service:53-56` | Add `MemoryMax`, `PrivateDevices`, `ProtectKernel*`, `RestrictAddressFamilies=AF_INET AF_INET6`, `CapabilityBoundingSet=`, `SystemCallFilter=@system-service`, `UMask=0077`, and the rest of the standard set. |

### 3.3 Core (`internal/types`, `internal/state`, `internal/store`, `internal/genesis`, `internal/chain`, `internal/mempool`)

| ID | Finding | Where | Fix |
|---|---|---|---|
| S-2 | **CRC32C excludes the length prefix; a corrupt length byte in the final segment silently truncates committed blocks.** `scanSegment` tolerates a CRC mismatch in the final segment and advances by the stored length, so a flipped length bit misframes the next records as garbage until a garbage length runs past EOF, at which point `truncateTail` deletes everything from there to the end and `Open` succeeds. The lock log fixes exactly this with a fixed-width prefix; the block log does not. README's "a damaged record is reported, never silently dropped" holds only for payload damage. | `store.go:168-216, 266-281` | CRC over `uvarint(len) ‖ payload`; stop the scan at the first CRC failure in the final segment; distinguish torn tail from corruption with a checksummed fixed-width header; test "flip one length bit → Open fails loudly, file unchanged". |
| S-3 | **No transaction fee or any cost to transact.** One funded account can emit 10,000 one-spark transfers per block at zero cost: 10,000 verifies, a full state clone and re-hash, about 1 MiB of SD-card writes every 2 seconds, and unbounded dust accounts. README promises a "fees only" endgame the encoding has no field for; adding one later is a hard fork. | `tx.go:39-57`, `apply.go:47-77` | Add `Fee uint64` to the signed body now, enforce a minimum, debit `Amount + Fee` with overflow checks. |
| S-4 | **Rejected faucet claims still cost a full Argon2id evaluation.** The expensive check is the only one that can reject a claim whose signature, epoch and nonce are valid; the per-block bound protects validators from blocks, not the ingest path. See R-1. | `apply.go:82-124`, `chain.go:286-301` | Cheap outer puzzle (a BLAKE3 pre-target) before Argon2; mempool Argon2 budget. |
| S-5 | **`Genesis.Validate` leaves Argon2 cost and several parameters unchecked**: no upper bound on `MemoryKiB` (up to 4 TiB; every validator OOMs on the first claim), `Iterations == 0` or `Parallelism == 0` silently bricks the faucet, `ClaimAmountSparks == 0`, `MaxClaimsPerBlock` above `MaxTxsPerBlock`, duplicate validator keys (double power in sums and proposer draws), `CommitteeSize` and `Time` bounds. | `genesis.go:145-221`, `committee.go:344-389` | Add each bound with a negative test. |
| S-6 | **Chain `SelectApplicable` clones the full state per candidate**, O(candidates × accounts) per block; `RunOnce` hands it up to 10,000 candidates. Reachable by anyone who can post signature-valid transfers. | `chain.go:286-301`, `state.go:111-121`, `node.go:55` | Clone once, `ApplyTx` per candidate (it already promises no partial writes on error). |
| S-7 | **`Store.Read` and replay read the whole segment file per block.** Replay reads each segment about 1,000 times; `GET /block/{h}` for any non-head height allocates the entire segment (up to 1 GiB theoretical). A loop of `/block/1` on a LAN-exposed Pi is an OOM. | `store.go:171, 289-291`, `chain.go:130-131, 421` | Per-segment read handle with `ReadAt`; stream the scan. |
| S-8 | **Block timestamps are unvalidated beyond `> 0`.** No monotonicity, no future bound; `Build` takes the caller's value and consensus uses `parent+1`. No economic effect today (epochs are height-based), but it also makes proposer grinding free (C-14) and any future time rule inherits garbage. | `block.go:93-95`, `chain.go:363-401`, `node.go:48`, `driver.go:225` | Require `Timestamp > parent` and `<= now + drift` at `Append`, or pin `== parent+1` for the consensus path. |
| S-9 | **Signature-only mempool admission, no per-sender bound** for transfers; two same-nonce transactions from one sender are both admitted. | `mempool.go:59-73` | Stateful admission against head state; per-sender cap. |
| S-10 | **`Add` holds the mempool write lock across every signature in the batch**; `reAdd` can pass 10,000, blocking `/status` and `Take` for seconds on a Pi. | `mempool.go:54-75`, `node.go:84` | Verify outside the lock, insert under it. |

### 3.4 Test and build process

| ID | Finding | Where | Fix |
|---|---|---|---|
| T-1 | **Seed-replay determinism no longer holds once `CatchUp` is involved.** The pull runs on a second goroutine while the caller advances virtual time; the request is enqueued at whatever virtual `now` Go scheduling reaches, so RNG draws downstream depend on scheduling. The harness comments still claim exact replay. `TestSameSeedReproducesIdenticalBlocks` never exercises a pull. | `simnet.go:855-916`, `sim.go:14-22, 150-186` | Hand the pull request to the advance loop through a channel at a fixed step, or make `awaitReply` injectable; add an identical-blocks test through `CatchUp`. |
| T-2 | **Wall-clock deadlines inside the clock-free harness**: `DefaultReplyWait` 2 s and `replacePullWait` 10 s. Under `-race` on a loaded runner a legitimately answered pull can read as silence and fail "catch-up did not bring the committee to one height". | `simnet.go:909-920`, `sync.go:83, 463-474` | Virtual-time `ReplyWait` seam. |
| T-3 | **`internal/devnet` wall-clock test ceilings sum to about 940 s** against `go test`'s default 10-minute package timeout; CI passes no `-timeout`. A slow-but-progressing run dies with a goroutine dump. | `devnet/tcp_test.go`, `ci.yml:22-23` | `-timeout 20m`, or shorten `WaveEvery`/`TickEvery` in tests. |
| B-2 | **Release builds are not reproducible, unsigned and never published.** No `-trimpath`, `-buildvcs` left at `auto` (embeds the dirty flag), toolchain version not recorded, `SHA256SUMS` unsigned; the CI release job verifies the build but uploads nothing; the deploy recipe never copies or checks `SHA256SUMS` though README says to verify on the target. | `scripts/build-release.sh:83-85`, `ci.yml:73-85`, `scripts/deploy/README.md` §2 | `-trimpath -buildvcs=false`, record `go version`, sign with minisign, upload and attest artifacts, make the recipe `sha256sum -c`. |
| D-1 | **README is stale on M4.** "Status and roadmap" lists M4 as pending though PR 4 is merged; the `node` section lists only three flags though `--peers/--relay/--listen/--validators/--index` exist; "Sixteen Go packages" (there are 19; `relay`, `transport/tcp`, `wire` are missing from the table); the import-direction paragraph predates `tcpnode.go`; "a validator that falls behind cannot catch up yet" and "left strictly behind" contradict the convergence the tests now assert; the deploy README still says to clone branch `m4-real-networking`. | `README.md:164-180, 456, 655-665`, `scripts/deploy/README.md:48-53` | Refresh. |

---

## 4. Low and informational findings

### 4.1 Consensus

- **C-9 · Low** `ValidRound >= Round` is accepted (`engine.go:437-466`). Safety holds (a locked validator still needs a formed polka from a strictly later round), but it is non-standard and free to reject. No test on either side of the boundary.
- **C-10 · Low** Prevotes are not persisted (`driver.go:157-175`). A validator that prevotes, crashes and restarts can honestly double-prevote at the same round. Commit safety still holds given lock persistence; it does produce slashable evidence relevant to M5.
- **C-11 · Low** `emitVote` panics if the node's own key is not in the committee (`engine.go:243-252`); `NewDriver` never checks membership; `e.idx` is computed and never used. Return an error instead.
- **C-12 · Low** Nil prevotes have no protocol effect (`tally.go:113-114` `NilPower` has no non-test caller; no precommit-nil; rounds end only on timeout), while engine comments say nil weight is needed to leave the round. Implement nil-polka fast round change or fix the comments.
- **C-13 · Low** Lock log and `locks` map grow one record per height forever (`store.go` `PutLock`, `chain.go:435-449`). Prune below the committed height.
- **C-14 · Low (acknowledged bias, unacknowledged cost)** Proposer grinding via the parent hash is unbounded because timestamps are free inputs (`committee.go:473-480`, S-8).
- **C-15 · Low** `PullAndAdopt` does not check served unit count or heights against the window (`sync.go:575-620`); `Append` gates correctness.
- **C-16 · Low** Chain ID absent from vote and proposal signing hashes (`message.go:59-73, 161-169`).
- **C-17 · Info** `certVoteSet` builds an unvalidated `Config` whose `Quorum()` discards the overflow flag (`sync.go:245-247`); safe because the node validates the same committee at startup; reuse the validated config. `CommitteeAt(height)` seam exists but every reader uses `cfg.Committee` directly, so the M5 seam is not real. `TimeoutEvent.Step` is carried and never read. `Vote.Validator` and `Proposal.Validator` lengths are not checked at decode (`message.go:103, 231`), so a 1 MiB "key" is copied before `Verify` rejects it. `Engine.OnMessage` returns nil both for "not my round" and "accepted".

### 4.2 Networking and deploy

- **N-11 · Low** `WriteFrame` silently truncates lengths at or above 4 GiB and writes a zero-length frame that every reader treats as fatal (`wire/frame.go:49`); `Broadcast([]byte{})` from any caller tears down every link.
- **N-12 · Low** Hello and sync-request decoders impose no key-length bound (`wire/message.go`); callers check membership, so acceptable, but document it.
- **N-13 · Low** `skipOversized` uses `io.CopyN` with no deadline (`tcp.go:731`); a hostile configured peer can hold the reader indefinitely.
- **N-14 · Low** Relay `finish` is not atomic with the registry delete (`relay.go:225-233`), unlike the transport's fixed `finish`; only `Stats.Forwarded` accuracy is affected.
- **N-15 · Low** Relay flags `--max-conns 0` and `--write-queue 0` fall back to defaults rather than disabling; help text does not say so.
- **N-16 · Low** `acceptance.sh:253-254` passes operator-supplied hosts to `ssh` without `--`, so an entry beginning with `-` is parsed as an option; `RELAY_PORT` is not validated numeric; no `pipefail`; no shellcheck in CI.
- **N-17 · Low** `check-plan.sh:25, 29` hard-depends on a personal workstation path (`$HOME/.dsh/skills/...`) and reports the plan broken on any other machine; `plan_parity.py` has no argv check.
- **N-18 · Info** Dedup (`transport/dedup.go`) is built, tested and not wired; `Forget` is an O(n) scan; a key at `Height=MaxUint64` is immortal.
- **N-19 · Info** Verified correct: the "torn-down connection cannot serve sends" fix in commit `044ec13` (`tcp.go:246-256, 815-836`); `newcomerWins` converges identically at both ends; `MaxConns` accept-versus-count has no race (`relay.go:336-362`); keepalive sockopt is set and tested; the relay never echoes, duplicates or reorders per sender pair; `acceptLoop` tracks in-flight handshakes correctly; no double close.

### 4.3 Core, chain, node, RPC, CLI

- **S-11 · Low** Non-canonical address spellings accepted: 3 padding bits and mixed case give each address 2^39 × 8 accepted strings (`address.go:58-80`; the test comment at `address_test.go:57-66` notes it). Not a consensus risk; an interop hazard. Require `a.String() == s`.
- **S-12 · Low** `TxRoot` is safe from the odd-leaf duplication ambiguity (`[a,b,c]` and `[a,b,c,c]` share a root) only because `ValidateStructure` rejects duplicate transactions (`merkle.go:27-37`, `block.go:102-109`). Undocumented coupling; any future path that trusts `TxRoot` without `ValidateStructure` reopens it.
- **S-13 · Low** `Tx.ID()` covers the signature (`tx.go:84-86`); the signer can produce unlimited valid IDs for one body and fill the pool with copies.
- **S-14 · Low** Heights are assigned by record count and never checked against the segment file name; any `*.seg` is scanned (`store.go:102-104, 143-153`). A stray or renamed segment silently renumbers every later height.
- **S-15 · Low** No directory fsync after creating a segment or the lock log; files are 0644/0755 (`store.go:116, 120, 238-239`).
- **S-16 · Low** No "premine + emission ≤ cap" rule; the devnet fixture's 1,000,000 b10 plus the series exceeds the README's cap (fixture, but say so); `faucet.SeriesTotal` doc says `Validate` uses it, and it does not (`genesis.go:171-192, 371`, `emission.go:29-31`).
- **S-17 · Low** Varint overflow beyond 64 bits is reported as `ErrShortBuffer` (`codec.go:136-139`); `DecodeBlock` has no upfront `MaxBlockBytes` guard (`block.go:116-164`).
- **S-18 · Low** `PowDigest` preimage is an unprefixed concatenation with a variable-length key (`pow.go:34-47`); safe because callers force 32 bytes; enforce locally.
- **S-19 · Low** No transaction validity window; a signed transfer is spendable forever until its nonce is consumed.
- **S-20 · Low** `CommitteeSize int` is encoded via `uint64()` and decoded via `int()`; negatives wrap, 32-bit truncates (`genesis.go:119, 297`).
- **O-2 · Low (acknowledged)** Replay trusts stored bytes beyond position, link and root: `applyValidated` skips structure, proposer and signature checks (`chain.go:139-157, 335-352`). Local disk is the trust boundary; document it.
- **O-3 · Low** `Chain.State()` hands out the live committed state, and `state.State` exports `Set` and `SetHeight` (`chain.go:192-196`, `state.go:92-105`); `Head()` and `Genesis()` alias internals. In-process trust only.
- **O-4 · Low** Write lock held across `fsync` (`chain.go:364, 395`, `store.go:280`); every RPC read stalls for the SD-card sync.
- **O-5 · Low** Wrong genesis for a data dir is reported as "replay diverged" (`chain.go:152-156`); persist the genesis hash and compare first. A CRC-failing final record makes the node unopenable with no repair path (`store.go:195-201, 318-320`).
- **O-6 · Low** `Build(nil, ...)` panics inside `ed25519.PrivateKey.Public()`; the `ErrUnknownProposer` branch is unreachable (`chain.go:308-311`).
- **O-7 · Low** Any `RunOnce` error terminates the node loop and discards the in-memory mempool (`node.go:99-112`, `main.go:418-420`). Nonce-gap transactions are dropped after a 200 response with no `/tx/{id}` to learn it.
- **O-8 · Low** RPC returns `err.Error()` including filesystem paths on `BlockAt` failure (`server.go:102-105`, `store.go:289-292`); `/status` reads `Head()` and `Height()` under separate locks and can be internally inconsistent (`server.go:72, 77`); body limit of 1 MiB is 5,000× a transaction (`server.go:128`); `ErrFull` maps to 400 rather than 503. No logging anywhere in `rpc`, `node` or `chain`.
- **O-9 · Low** `Remove` is O(n) and recomputes `ID()` per element (`mempool.go:121-134`).
- **O-10 · Low** `claim` prints the ephemeral private key to stdout by default (`main.go:293-294`; documented), where shells, CI and `journalctl` capture it. `httpSrv.Close()` rather than `Shutdown` aborts in-flight requests though README says "cleanly" (`main.go:396-399, 504-507`); the "listening" banner prints before bind (`main.go:401-402`). `devnet --dir X` on a non-empty X fails with a confusing height error (`main.go:176-178`).
- **O-11 · Low** `TickEvery` below 1 ms truncates to zero and freezes consensus time (`tcpnode.go:380`); `tallestPeer` breaks ties by map iteration order (`tcpnode.go:466-477`); the `closing` gate protects the driver but not the router/chain path after `Close`, and the comment claims more (`tcpnode.go:140-149, 351-366`); `simnet.CatchUp` can orphan a pull goroutine on budget exhaustion despite its comment (`simnet.go:896-912`); `tap.cons` is written and read without `tap.mu` (`simnet.go:668, 699, 707`); `sim.Advance` reads `now` outside the lock (`sim.go:151`).
- **O-12 · Info** Verified correct: temp-dir handling deletes only the directory `cmdDevnet` created (`main.go:120-127`); `--dir` is never removed; signal handling uses `NotifyContext` for Interrupt and SIGTERM in both binaries; HTTP servers set header, read, write and idle timeouts (`main.go:388-395, 496-503`); the `claim` command does check the chain ID (`main.go:256-258`) and uses a 15-second HTTP client timeout; `/tx` body is bounded; `ParseUint` rejects negative, non-numeric and overflowing heights; `crypto.Verify` length-checks before `ed25519.Verify`; no panic reachable from HTTP or network input was found; `MaxFaucetClaimsPerBlock` is pinned equal to the genesis bound by test; no `TODO`, `unsafe`, `reflect`, `ioutil`, `//nolint` or `os.Setenv` anywhere; `math/rand` appears only in backoff jitter and the deterministic simulator, keys use `crypto/rand`; `time.Now()` is absent from consensus-critical code.

---

## 5. Test coverage

### 5.1 Assessment

There is no coverage number to report because no toolchain was available and CI produces none. By inspection, test density is high: 36 test files against 50 source files, roughly 15,000 of the 27,700 lines are tests, and the heavy packages (`consensus`, `tcp`, `relay`, `simnet`, `store`, `state`, `chain`) each have focused negative tests, positive controls and, where relevant, mutant-killing tests. The seven simnet scenarios assert on block IDs, not heights, and none can pass vacuously. Eight fuzz targets exist with adversarial seeds. CI runs the suite twice, plain and under `-race`, with `-count=1`.

The gaps are systematic rather than random: **adversarial consensus behaviour at the committee level, multi-round liveness, the relay and transport under a hostile stranger, and the operational failure modes** (two processes, corrupt length prefix, restart after rollover).

### 5.2 Process gaps

| Gap | Where | Recommendation |
|---|---|---|
| No coverage measurement | `ci.yml`, `Makefile` | `go test -race -count=1 -coverprofile=coverage.out ./...`, upload the profile, gate per-package floors for `consensus`, `state`, `types`, `wire`, `store`. |
| Fuzz targets run on seeds only; no committed corpus | `ci.yml`; no `testdata/fuzz/` tracked | Nightly job with `-fuzz=<Name> -fuzztime=60s` per target; commit found inputs as regression corpora. Add targets for `DecodeGenesis`, `ParseAddress`, `store.scanSegment`, `Engine.OnMessage`, `verifyJustification`. |
| No `-timeout` for the long devnet tests | `ci.yml:22-23` | See T-3. |
| Suite runs twice | `ci.yml:22-23` | Keep the `-race` run; spend the saved minutes on fuzzing and coverage. |
| `t.Skip` on a deterministic fixture | `consensus/driver_test.go:1521` | Either always runs or is permanently dead; pick the seat programmatically. |
| Several tests ignore `Open`'s error (`s, _ := Open(...)`) | `store_test.go:32, 50, 76, 87` | Fail clearly rather than nil-deref. |
| Stall detection parses error text with `Sscanf` | `simnet_test.go:318`, `scenarios_test.go:148-150` | Typed `*StallError`. |
| No shell test or shellcheck for `acceptance.sh`, `build.sh`, `build-release.sh` | `scripts/` | Add shellcheck to CI and a loopback smoke test for `acceptance.sh`. |
| Subprocess CLI tests need a Go toolchain and 60-90 s timeouts | `cmd/b10coin/main_test.go:135, 303` | Build tag so `go test ./...` on a Pi stays fast. |

### 5.3 Missing tests by package

**consensus** (highest value first)
1. A 4-validator committee receives a proposal with a wrong state root, wrong `Header.Height` or wrong `ParentHash`: today it commits and halts everyone (C-1). After the fix: nil-prevoted, height commits in a later round.
2. A validator locked on B is drawn as proposer: assert it re-proposes B with a justification (C-2); a committee with one third locked recovers within bounded rounds.
3. Precommit equivocation and proposer equivocation at the engine level (two valid proposals; first wins; no double lock).
4. Justification edge cases: duplicate signers (only the certificate path has the tripled-vote test), nil or precommit-typed votes inside a justification, `ValidRound == Round` and `> Round`, exactly-quorum power with unequal weights.
5. Weighted exactly-2/3 boundary in `VoteSet.HasQuorum` (e.g. powers 2, 2, 2, 3: total 9, quorum 7; 6 must fail, 7 must pass). `quorumFor` is exhaustively tested; `HasQuorum` only with equal weights.
6. Future-round and past-round messages dropped (documents C-3); buffered after the fix.
7. Restart mid-round at round > 0 rejoining a height in progress.
8. `persistLock` write failure panics; `NewDriver` with a non-member key.
9. Sync adversarial: response from a peer other than the one asked; empty response injected mid-pull; replayed signed request served twice; more units than the window; heights outside it; `MaxBlocksPerResponse` mismatch between peers (acknowledged untested at `sync.go:494-497`); certificate containing an equivocating precommit.
10. Any commit at round > 0 across a real committee (the blocked-quorum fixtures churn rounds but never commit).
11. Committee with duplicate keys.

**transport/tcp and relay**
- Relay-shaped handshake: two transports through a real `relay.Relay`, a third raw connection sends `a`, assert transport `a` returns `ErrSelfConnection` and never redials (N-1; should fail today).
- ID squatting on a listener: squatter claims `b`, real `b` is refused, squatter leaves, `b` never connects.
- 1,000 raw dials with distinct IDs all appear in `Peers()`; idle inbound peer never reaped; writer blocked on a non-reading peer never times out; 1 MiB handshake ID accepted.
- `Send` returning `ErrQueueFull`; `skipOversized` when the payload never arrives; `Broadcast([]byte{})` kills every link; `AddPeer`/`Dial`/`Listen` after `Close`; reconnect storm bounded by backoff; a `-race` stress of `finish` versus `Send` on real sockets (the current test constructs the pre-fix state by hand).
- Relay: a client sending a 5-byte frame every `ReadTimeout/2` and never reading is never reaped (falsifies the README claim); k sinks each holding 64 distinct 1 MiB frames; honest frame dropped behind a flooder; `MaxConns+1` simultaneous dials from a barrier; zero-length frame; `Close` while a writer is blocked in `Write`; `Stats.Forwarded` not over-counted (N-14).

**wire**
- `WriteFrame` with empty payload and with `len > MaxUint32`; `ReadFrame` over `iotest.OneByteReader` and `DataErrReader`; `DecodeBlockSyncResp` allocation bound with a MemStats assertion (N-4).

**types, crypto, state, store, faucet, genesis**
- Varint longer than 64 bits through `Decoder.Len`; `ValidateStructure` zero-timestamp test asserts only `err == nil` (should assert `ErrBadTimestamp`); negative timestamp; signing hash ignores the other type's fields; `VerifySignature` with a 31- or 33-byte key whose address matches; non-canonical address padding bits; a golden pubkey-to-address vector; fuzz `ParseAddress`.
- `MerkleRoot([a,b,c]) == MerkleRoot([a,b,c,c])` as a documented-limitation test; golden vectors for `HashParts` and small Merkle roots; `Verify` with nil inputs.
- Recipient balance overflow in `applyTransfer` (`apply.go:66-68`, the one guard with no test); claim with wrong nonce; two sequential nonces in one block; mixed transfers and claims; transfer to the faucet address; `ErrFaucetEmpty` exact boundary; supply conservation; `Clone` independence; `MaxClaimsPerBlock == 1`.
- Reopen after rollover and read from both segments (the rollover test only counts files); corrupt length prefix mid-file in the final segment (S-2); missing or renamed middle segment; stray `foo.seg`; empty final segment; non-final segment with a torn tail; append after a failed write; payload larger than 1 MiB; two `Open`s on one dir (O-1); fuzz `scanSegment`.
- `Reward` at halvings 63 and 64; `MeetsTarget` at `target - 1`; `Solve` returns the smallest nonce; `MemoryKiB` below Argon2's minimum (the library silently raises it, changing the digest).
- Negative `DecodeGenesis` tests and a fuzz target; tests for every absent validation in S-5, S-16, S-20; golden vectors for the fixture keys and faucet address strings.

**chain, node, rpc, mempool, cmd**
- `Append` with duplicate txs, over `MaxTxsPerBlock`, `TxRoot` mismatch, oversized block (only covered in `types`, never through `chain.Append`); replay state-root mismatch directly (tamper the last block's root and re-CRC); `Open` on a corrupt final record, truncated tail, wrong genesis, across a segment boundary; `Append` where `store.Append` fails leaves height and state unchanged; `BlockAt` of a corrupt record; `Close` twice; `Build(nil, ...)`.
- `Run`: cadence, cancel, error path; `RunOnce` with a failing `Append`; claims beyond 8 included in later blocks; mempool full at re-add.
- RPC: `/block/` overflow, negative, empty, trailing segments; non-head historical block from disk; 405 per endpoint; `/tx` over the limit, JSON-quoted, odd-length hex, unsupported type, duplicate, pool full status code; error-leak test for the 500 path; concurrent `POST /tx` with `Take` under `-race`; the R-1 regression (10,000 garbage claims then one honest transfer admitted).
- Mempool concurrency under `-race` (the doc promises it; nothing exercises it); `Remove` of an absent ID; `Take(n < Len)`; same tx twice in a batch; address mismatch; re-add after `Take`.
- `cmdNode` single-node: signal → exit 0, failed bind → exit 1 (asserted in comments at `main.go:403-408`, never tested); `cmdClaim` is entirely untested; `main()` dispatch and exit codes; `devnet --blocks 0`.

---

## 6. Other improvements

### 6.1 Documentation accuracy

| Claim | Where | Reality |
|---|---|---|
| "a malicious relay ... cannot forge a vote or a proposal" | `README.md:216-219` | Anyone can, with fixture keys (A-1). |
| Stranger pins "at most max-conns × max-frame-bytes ... never forever" | `README.md:236-238`, relay `--help` | 16 GiB at defaults; indefinitely (N-2). |
| "Validators reconnect to a restarted relay with exponential backoff" | `README.md:244-245` | Not after a self or duplicate handshake (N-1). |
| "run it behind the VPS firewall allowlisting the validator IPs" | `README.md:242-244` | Recipe opens the port to the world (N-8). |
| "a damaged record is reported, never silently dropped" | README architecture table, design decision 6 | Not for a damaged length prefix (S-2). |
| "the chain then runs on fees only" | README emission section | No fee field exists (S-3). |
| "Supply caps at 21,000,000 b10" | README | Devnet fixture exceeds it (S-16; fixture). |
| M4 pending; `node` has three flags; sixteen packages; laggard "left strictly behind"; "cannot catch up yet" | `README.md` several sections | M4 merged; five more flags; 19 packages; tests assert convergence (D-1). |
| "a HELLO and a consensus message start with different tags" | M4 plan Design Decision 2 | Both use 1/2/3 (N-5). |
| "Dedup lives in the transport-facing layer" | M4 plan | Built, not wired (N-18). |
| `git clone -b m4-real-networking`; "verify what you copied" with `SHA256SUMS` | deploy README | Branch merged; recipe never copies the checksum file (B-2). |
| "a relay with no error and no output is healthy" | deploy README | Also silent while dropping or refusing (N-9). |
| Router: an attacker frame "cannot pass" the consensus branch | `router.go:490-495` | Self-signed votes pass `Verify` (C-8). |
| Nil prevote weight "must leave the round or the round can never be left behind" | `engine.go:188-193, 326-330` | Nil votes are inert (C-12). |
| M3 plan Design Decision 4 versus 11 | M3 plan | DD4's rule is the one DD11 proves unsafe; mark DD4 superseded. |
| M4 plan Task 4 `Answer(req) ([][]byte, error)` | M4 plan | Returns `(*wire.BlockSyncResp, error)` with certificates. |
| `faucet.SeriesTotal` "used by the genesis-parameter check" | `emission.go:29-31` | `Validate` never calls it. |
| `pow.go` "ASICs confer no meaningful advantage" | package doc | README and `Testnet` already concede the 8 MiB trade-off. |
| `chain_lock_test.go` | file name | Tests the consensus lock, not a file lock; rename. |

### 6.2 Observability

Neither binary logs anything after its start-up banner. `tcp` keeps `dropped`, `droppedOversized`, `lastRedialDelay` in unexported fields; the relay's `Stats()` is never read; the router's `UnknownDropped`, `SyncRequestsServed`, `HellosSeen` are never surfaced; `Driver.OnMessage` and `Tick` discard every engine error; pull failures in `maybeCatchUp` are swallowed; `acceptLoop` retries every error every 100 ms silently; `persistLock` panics with no preceding log line. For a Pi operator, "stalled" is indistinguishable from "slow". Add a minimal `log/slog` logger with block-produced, tx-evicted, proposal-refused, pull-failed and rpc-error events; a periodic status line (height, round, peers, pulls, drops); the same fields on `/status` so `acceptance.sh` can read them; relay stats on a timer and SIGUSR1.

### 6.3 API and structure

- `State.SetHeight` is hidden execution context that `ApplyBlock` depends on; prefer `ApplyBlock(height, txs)`. Zero `Params` means "claims disabled" while `MaxClaimsPerBlock == 0` means "unbounded" in the same struct (`state.go:59-75`); make the unbounded case impossible.
- `Header` has no version field; any encoding change is a hard fork with no in-band signal. Add `Version uint8` while it is free. The same applies to `Fee` (S-3) and a chain identifier (S-1) in the transaction body.
- Route every committee read through `CommitteeAt(height)` so the M5 seam exists before M5 needs it.
- `ErrGenesisReplay` is overloaded for four distinct failures; distinct sentinels would make a future `b10coin repair` and operators' lives easier.
- `cmdDevnet` and `cmdNode` duplicate about 40 lines of HTTP plumbing (`main.go:388-430` versus `496-534`); `rebuildDriver` exists in both `tcpnode.go` and `simnet.go`; `assertAgreedOnEverySharedHeight` and `AssertPrefix` are duplicated across test packages. Factor.
- RPC gaps: no `/tx/{id}`, no `/account/{addr}` (a client cannot pick a nonce), no `/block/{hash}`; `blockResponse` omits `tx_root`, `proposer` and the transactions.
- `ValidateStructure` computes every tx ID twice and re-encodes the whole block to measure it (`block.go:99-112`); `State.Root()` re-hashes every account on every call and is called at least twice per block (`state.go:151-163`); each tx signature is verified four times on the producer. Not bugs; relevant to the Pi budget.
- `docs/plans/*` (about 11,300 lines) are process artefacts; a `docs/plans/README.md` stating they are historical would stop readers treating a plan's interface list as current.

---

## 7. Prioritized remediation

**Before any further public deployment**
1. **A-1** Warn in README, `usage()` and the deploy recipe that the committee's keys are public; make the firewall step an allowlist. Then: `keygen`, `--key`, genesis-listed public keys.
2. **B-1** LICENSE, SECURITY.md; supported Go with `toolchain`; `govulncheck`, `staticcheck`, `gofmt`, `tidy` gates; SHA-pinned actions with `permissions: contents: read`; Dependabot.

**Consensus liveness (the chain cannot be relied on to keep producing blocks until these land)**
3. **C-1** Validation seam before prevote; reject envelope/header height mismatch.
4. **C-2** Proof-of-lock and `validValue` re-proposal; cap timeouts.
5. **C-3** Multi-round vote sets, `f+1` round skip, persist round.

**Network exposure**
6. **N-1** Outbound maintainers never go permanently dormant; relay-aware naming; bound the handshake ID.
7. **N-2** Relay write deadline, byte-bounded queues, per-sender fairness, per-IP cap, `MemoryMax=`; correct the README arithmetic.
8. **C-4, C-5, C-6** Sync request nonce and correlation, sender check, rate limit, async `Handle`, peer rotation on lying HELLO.
9. **N-3** `MaxConns`, idle and write deadlines on the listener. **N-4** cap the pre-allocation. **N-5** renumber wire tags now.

**Storage and state integrity**
10. **O-1** Data-directory lock. **S-2** CRC over the length prefix; stop at first corruption. **C-7** persist certificates.
11. **S-1, S-3** Chain identifier and fee in the signed body (one hard-fork-shaped change, done once). **S-5** genesis bounds. **S-8** timestamp rule.

**Resource exhaustion**
12. **R-1, S-4, S-9** Stateful mempool admission, claim ageing, per-sender caps, cheap pre-puzzle. **S-6, S-7** Clone once; `ReadAt` per record.

**Tests and process**
13. Coverage in CI; nightly fuzzing with committed corpora; `-timeout`; the section 5.3 consensus items 1 through 5 and 9; the relay-handshake and indefinite-pin tests that falsify today's README claims.
14. **D-1** and the rest of section 6.1; observability per 6.2; **B-2** reproducible, signed, published releases.

---

## Appendix: verified-sound properties

Listed so the findings above are read in proportion. Each was traced through the cited code.

- Quorum is the smallest `q > 2·total/3`, computed without forming `2·total`, compared against a big-integer reference across the `uint64` range (`committee.go:435-444`); `HasQuorum` uses `>=` (`tally.go:120-122`); power sums are overflow-checked; cap comparisons use `big.Int`.
- One vote per validator per `(height, round, type)`; power is taken from the committee entry, never from the message; equivocation collapses to the first vote (`tally.go:73-105`).
- Vote, proposal, sync-request and HELLO signing hashes use disjoint domain tags and bind height, round, block ID or header hash, and validator key (`message.go:59-73, 161-169`; `sync.go:207-213`).
- Lock is forward-only; `canPrevote` requires a strictly later `validRound`, stronger than Tendermint's rule; justification is re-tallied through a fresh `VoteSet` with quorum demanded for the proposal's own block (`lock.go:674-704`, `engine.go:437-466`).
- Lock persisted with append and fsync before the precommit is queued; corrupt lock record fails `Open`; torn tail truncated only (`engine.go:365-377`, `store.go:329-399, 435-450`).
- Catch-up re-tallies carried precommits, requires quorum on the block's ID, refuses zero votes, stops at the first bad unit, and `Append` re-validates everything (`sync.go:258-278, 581-587`, `chain.go:363-401`).
- Proposer selection is a pure function of `(height, round, parent, committee)` with exact big-integer reduction (`committee.go:485-503`).
- `HashParts` length-prefixes each part; every hashed construction has a distinct domain label; Merkle leaves and nodes are domain-separated (`hash.go:15-26`, `merkle.go`).
- `Decoder.Len` enforces minimal LEB128 and bounds every length and count by the remaining buffer before allocation; `VarBytes`, `Fixed32`, `Fixed20` copy rather than alias; every top-level decoder calls `Done()`; fuzz targets assert canonical re-encoding (`codec.go:78-184`).
- `applyTransfer` and `applyFaucetClaim` run every validation before the first write, with overflow checks on credit before debit (`apply.go:47-77, 82-124`). The faucet address is `HashParts("b10coin-faucet", genesisHash)[:20]`, so no key can spend it.
- `Reward` returns 0 at or beyond 64 halvings; `SeriesTotal` saturates; `Validate` uses `bits.Mul64` (`emission.go`, `genesis.go`).
- Frame reader bounds through `int64` before `make`, refuses zero length, and the oversize path skips exactly the declared length (`wire/frame.go:67-84`).
- The duplicate-connection resolution converges identically at both ends; the torn-down-connection fix in `044ec13` is correct; `MaxConns` has no accept-versus-count race; keepalive is set; the relay never echoes, duplicates or reorders per sender pair.
- `cmdDevnet` removes only the temp directory it created; `--dir` is never deleted; both binaries handle Interrupt and SIGTERM through one context; HTTP servers carry all four timeouts; `/tx` body is bounded; `claim` checks the chain ID; `crypto.Verify` length-checks before `ed25519.Verify`.
- No `TODO`, `unsafe`, `reflect`, `ioutil`, `//nolint`, `os.Setenv`, `select {}` anywhere; `math/rand` only in backoff jitter and the deterministic simulator; `time.Now()` absent from consensus-critical code; no panic reachable from HTTP or network input.
