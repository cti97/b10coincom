# b10coin security review: `main` after M6

| | |
|---|---|
| Tree | `main` at `e64b1d5` (merge of PR 20), working tree clean |
| Date | 2026-11-06 |
| Scope | Whole tree: consensus, chain, state, mempool, genesis, transport, relay, wire, rpc, faucet, keystore, cmd, scripts, CI, documentation, git history |
| Method | Five independent source-only reviewers with no shared context (consensus/staking, transport/relay, wallet/RPC/web, crypto/storage/encoding, CI/scripts/process), then **controller verification of every finding below against the code at this commit**. Go was not executed by the reviewers; the controller ran the static gates and read each cited symbol directly. |
| Prior reports | `audit-2026-10-04.md`, `audit-2026-10-06-fix-verification.md`, `audit-2026-10-30-m5.md`, `audit-2026-10-31-main.md`, `fix-review-2026-10-31.md`, `audit-2026-11-01-m6.md`, the two Docker test-run reports |

**Citation rule for this document: symbols, not line numbers.** Across six prior reports the single most repeated defect was a line number that had drifted, which cost a fix round every time. Every finding below names a function or a constant; a reviewer re-checking it should grep the symbol, not seek the line.

**Verification labels.** `VERIFIED` means the controller read the cited code and confirmed the mechanism. `REPORTED` means a reviewer's analysis that the controller did not independently reproduce. Every `VERIFIED` item below was confirmed at `e64b1d5`; nothing is relayed unread.

---

## 1. Verdict

**Nothing found breaks BFT safety.** Five reviewers, reading independently, found no double commit, no lock bypass, no certificate-gate hole, no non-determinism, and **no peer-reachable panic** inside the consensus, chain, state, mempool, wire or transport packages. The certificate gate re-tallies every unit through `VoteSet.Add` at the block's own height; `quorumFor` is exact for every `uint64` total without forming `2·total`; the power cap converges within its proven pass bound and is order-independent; replay rebuilds the epoch committee identically from committed state; and `crypto.Verify` length-guards both key and signature at every wire-reachable call site. That half of the system is genuinely well built and this report does not touch it.

**What is broken is liveness, resource accounting, and contract gaps — and three of them are permanent.** Two are reachable with **no Byzantine actor at all**; one is a single CLI command. The current test suite cannot see any of the three, because each is a property that spans two packages and every existing test stays inside one.

| Sev | ID | Finding | Verified |
|---|---|---|---|
| **High** | S-1 | **Unbonding the last seated bond bricks the chain permanently and unrecoverably** | VERIFIED |
| **High** | S-2 | **The frame / block / window triangle has no invariant**: a legal block's proposal envelope, and a 64-block sync response, both exceed the transport frame bound; the receiver discards silently and the validator never catches up again | VERIFIED |
| **High** | S-3 | **A legal mempool makes the producer unable to build, and the process exits** | VERIFIED |
| **High** | S-4 | **Inbound slot double-release defeats `MaxConns`** — unauthenticated fd/goroutine exhaustion | VERIFIED |
| Medium | S-5 | Proposal frames are fully decoded before any height or membership check, on the single serialised dispatch goroutine | REPORTED |
| Medium | S-6 | `Genesis.MaxClaimsPerBlock` is not coordinated with the pool's per-block claim hand-out: a legal genesis can make the proposer permanently unable to propose | REPORTED |
| Medium | S-7 | `Genesis.Validate` accepts Argon2id tunings that make `argon2.IDKey` panic on every claim | REPORTED |
| Medium | S-8 | `/block/{height}` sits outside every bound that `/history` and `/explorer` obey | VERIFIED |
| Medium | S-9 | No `recover()` anywhere in non-test code; no fuzz target runs in CI | VERIFIED |
| Medium | S-10 | No artifact or binary carries a build identity, so a mixed-build committee is undetectable | VERIFIED |
| Medium | S-11 | Release integrity is self-attesting and unsigned end to end | VERIFIED |
| Medium | S-12 | `Open` reads the entire certificate log into memory, contradicting its own comment, and the log is never compacted | REPORTED |
| Low | S-13 | A hostile node's `txid` and error body are printed raw to the operator's terminal | VERIFIED |
| Low | S-14 | `?blocks` parses at 31 bits, so "clamped above 500" is false and the error text is untrue | VERIFIED |
| Low | S-15 | `SECURITY.md` pre-excuses printing the ephemeral claim key, which has been opt-in since `2122d06` | VERIFIED |
| Low | S-16 | The shipped relay unit is an unauthenticated listener on all interfaces | VERIFIED |
| Low | S-17 | A legal future-nonce transaction is silently destroyed by the block producer | REPORTED |
| Low | S-18 | `shellcheck` is the one unpinned tool in an otherwise exactly-pinned gate | VERIFIED |
| Low | S-19 | `check-plan.sh` reports `PLAN PARITY OK` while skipping brief extraction, and is not run in CI | VERIFIED |
| Low | S-20 | `everSeated` grows without bound for the life of the node | VERIFIED |

Counts: **Critical 0, High 4, Medium 8, Low 8.**

---

## 2. The four High findings

### S-1 · High · Unbonding the last seated bond bricks the chain, permanently

**Where.** `state.applyUnbond` permits a full exit and deletes the bond (a zero remainder is the documented carve-out); `state.Committee` returns `ErrNoCandidates` — an **error, by design**, not an empty slice — when no bond can be seated; `chain.memoCommitteeLocked` writes the memo only on success:

```go
if vals, err := st.Committee(); err == nil {   // the error is swallowed
    c.committees[epoch] = vals
}
```

so the epoch is **never memoised**; `chain.CommitteeAt` then returns `ErrNoCommittee`; `chain.validateLocked` finds `seatedAtLocked` false and returns `ErrNotValidator` for **every height in that epoch**; the driver records a halt error and `Tick` returns it forever.

**Sequence.** On the devnet or a one-seat chain — one seat, `Power` 1 — run `b10coin unstake` with no `--amount` (a full exit, and the documented default). Blocks continue to height `e·E − 1`. At that height the deciding state has no candidate, epoch `e` is never memoised, and every node refuses every block from `e·E` onward. **No block can be produced, so the `Bond` that would seat a candidate can never be applied.** A restart replays the same state and reproduces the halt. The only escape is a fresh `--dir`.

On an N-seat chain the same state needs every bond to exit, so it is an operator-action brick rather than a stranger attack — but the rotation workflow makes a full exit one ordinary command, and the M5 audit already listed "the driver halt path when every seat unbonds" as untested.

**Why tests miss it.** `state`'s committee test pins that `Committee()` returns `ErrNoCandidates`; nothing pins the **chain-level consequence**. There is no test that unbonds the last bond and crosses a boundary.

**Fix.** Refuse a transition that would leave zero bonded candidates when `CommitteeSize > 0`, in `applyUnbond` before the first write. It is a consensus-rule change, so it belongs with the next versioned fork. Keeping the memo alive with an empty set is worse: it makes `CommitteeAt` lie.

**The comment is also wrong.** The stall line says the node is stuck "until the derivation succeeds", which for this cause can never happen. Whatever the fix, that sentence must stop promising a recovery that does not exist.

### S-2 · High · The frame / block / window triangle, and a permanent catch-up failure

**Where.** `types.MaxBlockBytes` and `transport.DefaultMaxFrameBytes` are **both 1 MiB**; `types.ValidateStructure` enforces the former; `transport.skipOversized` **drains and discards** an oversized frame while keeping the connection; `consensus.EncodeProposal` adds ~124 bytes over the block; `consensus.DefaultMaxBlocksPerResponse` is 64 and `Answer` builds every unit unconditionally with **no byte budget**; a 21-seat committee needs ~15 precommits ≈ 2.2 KB of certificate per unit.

**Consequence A — a legal block that cannot be proposed.** A block of `1,048,452 < size ≤ 1,048,576` is legal by `ValidateStructure`, but its *proposal envelope* exceeds the frame bound. It is built, signed, and discarded by every receiver.

**Consequence B — a validator that can never catch up.** A node behind by G blocks requests a 64-height window; `Answer` encodes `G × block + G × certificate`. The response fits one frame only while `blockLen ≲ 14.2 KB` (~86 transfers). Beyond that the receiver drops it **silently**, `PullAndAdopt` reads silence as "caught up", the peer is demoted, and **every peer is the same**. The node is permanently ejected from consensus while it keeps re-pulling.

**Why tests miss it.** Sync tests use tiny fixture blocks and windows of 2–4; the block test checks `MaxBlockBytes` alone; transport tests use synthetic frames. **No test multiplies a legal block size by a sync window and compares it to the transport bound**, and no test encodes a `BlockSyncResp` and checks its length.

**Fix.** Accumulate units under a byte budget in `Answer` and serve the shorter range — `served < win` already ends a pull cleanly and the next wave resumes from the new head. Then add the invariant test: *a full window of max-size legal blocks must encode under the frame bound.* One test covers this finding and S-3.

### S-3 · High · A legal mempool crashes the producer

**Where.** `types.MaxTxsPerBlock = 10_000`; `types.MaxBlockBytes = 1 << 20`; each framed transfer is 165 bytes, so `10_000 × 165 + 212 = 1,650,212`, which **passes the count check and fails the byte check at 6,353 transactions**. `node.RunOnce` takes `MaxTxsPerBlock`, `SelectApplicable` keeps every applicable one (nothing bounds size), `chain.Build` runs the whole state transition and *then* calls `ValidateStructure`, which returns `ErrBlockTooLarge`; `RunOnce` returns it via `reAdd`, and `node.Run`:

```go
if _, err := n.RunOnce(0); err != nil {
    return err          // no log, no retry — the caller exits the process
}
```

**Sequence.** ~100 faucet-funded keys × 64 transfers each (the per-sender cap) ≈ 6,400 applicable transfers. The faucet pays 8 claims per block, so ~13 blocks of claiming; `/tx` admits a 256 burst at 64/s per source, so ~100 s of submitting. The next 2-second tick builds an oversized block and **every node holding those transactions exits.** Repeatable at the same cost.

**Why tests miss it.** `types`' block test proves an over-1 MiB block is *rejected*, constructing one directly. **No test drives `mempool → Take → SelectApplicable → Build`.** M1's acceptance runs use a handful of transactions.

**Fix.** Enforce the byte budget in the shared selection policy (`SelectApplicable`), accumulating encoded size and stopping before `MaxBlockBytes` — **not** truncating inside `Build`, because the caller's slice is the pool's bookkeeping and the dropped transactions would be lost. Add `MaxTxsPerBlock <= (MaxBlockBytes − overhead) / minTxSize` as an init assertion.

Separately, `node.Run` should not treat a build failure as fatal. A producer that cannot build should log and try the next tick; a crash turns a transient into an outage.

### S-4 · High · Inbound slot double-release defeats `MaxConns`

**Where.** `transport.acceptLoop` reserves a slot, then releases it when `adopt` fails:

```go
t.inboundSlots++
go func() {
    if _, err := t.adopt(nc, addr, false, true); err != nil {
        if t.inboundSlots > 0 { t.inboundSlots-- }   // release #2
    }
}()
```

but `adopt` **installs first** and, if the nonce exchange then fails, calls `finish`, which releases the same slot again because the conn is marked inbound:

```go
c, err := t.install(...)          // registers with inbound = true
if err := t.exchangeNonce(nc, c); err != nil {
    t.finish(c)                   // release #1
```

The comment above the release even asserts the opposite invariant: *"a successful adopt hands it to install, and finish releases it there."*

**Sequence.** Dial the P2P port, send a small ID frame with a fresh name, close before sending the nonce commitment. That socket costs the counter **2** and releases **1** real socket. Repeat: the counter decays faster than the socket count, so `MaxConns` (64) is bypassed and live connections accumulate. Each live connection costs two goroutines, a 128-slot channel, an fd and a registry entry, and one frame per two minutes keeps the idle deadline from reaping it. At EMFILE the node can no longer accept *or* dial, and **consensus liveness dies with the sockets**.

**Why tests miss it.** The only cap test completes two *successful* handshakes and refuses the third, so the second decrement never runs. Nothing reads `inboundSlots`.

**Fix.** Release the reservation only when `adopt` did **not** install — have `adopt` report whether it registered, or move the release into its pre-install error paths and delete it from `acceptLoop`. Two lines, plus a counter observable so a test can assert it.

---

## 3. Medium findings

- **S-5 · Proposal decode precedes every gate (REPORTED).** The vote branch checks a height window and membership **before** `Verify`; the proposal branch decodes the whole block first, because `Proposer` is the last field. Any connected peer — member or stranger — can force a 1 MiB decode per frame, and `transport.dispatch` holds one mutex across every `OnMessage`, so votes queue behind it. Fix: peek `Height` at its fixed wire offset before decoding and drop proposals outside the two-height window votes already use.
- **S-6 · `MaxClaimsPerBlock` not coordinated with the pool (REPORTED).** `Genesis.Validate` bounds the parameter above only; the pool caps claims at its own constant. A legal genesis with `MaxClaimsPerBlock = 1..7` makes `Take` hand out more claims than `ApplyBlock` accepts, so `Build` fails, the batch is re-added, and the proposer never proposes. Fix: have `Take` bound claims by the state's parameter.
- **S-7 · Argon2 tuning gap (REPORTED).** `Genesis.Validate` accepts `MemoryKiB ≥ 1` and `Parallelism ≥ 1` with no relation between them; `x/crypto`'s `argon2.IDKey` panics when memory < `8 × lanes`. A *validated* genesis then turns every claim into a node crash. Not reachable through the shipped loaders; it is a contract gap that turns an operator mistake into a crash instead of a refusal.
- **S-8 · `/block/{height}` outside every R-1 bound (VERIFIED).** `handleBlock` references `scanLimiter` **zero** times; `handleHistory` once. Same store read, serialised on the same mutex, allocating up to 1 MiB per request, with no per-source bucket and no in-flight cap. Two lines to fix.
- **S-9 · No panic containment, and the decoders were never fuzzed (VERIFIED).** `recover()` appears nowhere in non-test code; `-fuzz` appears in no CI job, Makefile or script; there are nine fuzz targets and **zero** committed corpora. The relay forwards every frame from every registered connection to every peer, so one unauthenticated dialer's bytes reach all validators, and a panic exits the process. The durable fix is `defer recover()` around each connection's read loop.
- **S-10 · No build identity (VERIFIED).** `version.Version` is a constant, the release builds with `-buildvcs=false`, and nothing reads `debug.ReadBuildInfo()`. An operator who upgrades one Pi across the C-1 hard fork and leaves two behind sees three nodes printing the same banner, the same chain ID and no warning — then the committee forks at the first unbond from a grant-plus-top-up bond.
- **S-11 · Release integrity is self-attesting (VERIFIED).** `ci.yml` contains **zero** `secrets.` references while instructing the reader to add one; the artifact upload has no ref gate; `deploy/README.md` verifies with `sha256sum -c --ignore-missing`, which **skips the Pi binaries**; `deploy/build.sh` regenerates `bin/SHA256SUMS` over whatever `bin/` holds, so a stale binary verifies cleanly.
- **S-12 · `Open` slurps the certificate log (REPORTED).** `scanCerts` uses `os.ReadFile` while its own comment promises records are read on demand. Certificates are written once per committed height and never compacted: at ~2.1 KB per height, a million heights is ~2.1 GB, which is an OOM kill on the Pi the README targets — after which the node cannot restart at all.

## 4. Low findings

- **S-13 · Terminal injection via a hostile node's reply (VERIFIED).** `postTxHex` checks only that the `txid` is non-empty, and every signing verb prints it with `%s` **after** the signature; the error body is echoed raw too. A node can therefore erase the lines just printed and substitute a forged receipt. This is the class `W-2` closed for `/history` rows, left open on the highest-trust string in the CLI.
- **S-14 · `?blocks` parses at 31 bits (VERIFIED)**, in `historyBlocks` and `unbondingWindow`. Values at or above 2³¹ return 400 "must be a positive integer" about a positive integer, while the help text promises clamping.
- **S-15 · `SECURITY.md` is stale (VERIFIED).** It still lists, as out of scope, *"the claim command printing its ephemeral key to stdout"*, although `--print-key` has been opt-in since `2122d06`. In a security policy that is worse than a stale README: it tells the next reviewer a risk was accepted that was actually fixed.
- **S-16 · The shipped relay is open (VERIFIED).** `B10COIN_RELAY_ADDR=:7001` with an empty token, protected only by a ufw rule the deploy README itself softens to *"if your provider's UI can"*. Ship the unit closed (`IPAddressDeny` plus explicit allows) and refuse a wildcard bind with neither token nor allowlist.
- **S-17 · A legal future-nonce transaction is silently destroyed (REPORTED).** The pool admits a future nonce as "will become applicable"; if both land in one `Take` batch, `SelectApplicable` evicts the gap and nothing puts it back, so it is gone with no error to anyone.
- **S-18 · `shellcheck` is unpinned (VERIFIED)** — the one tool in an otherwise exactly-pinned gate. A runner-image bump can redden the twice-weekly cron with no tree change and be filed as a code problem.
- **S-19 · The plan guard skips half its job (VERIFIED).** `check-plan.sh` prints `PLAN PARITY OK` and exits 0 when its brief-extraction helper is absent, and it is not run in CI. (It did extract briefs on this machine, so the M6 plan verdicts were real; the defect is that the same repository yields different verdicts on different machines.)
- **S-20 · `everSeated` grows without bound (VERIFIED).** Filled from every epoch's committee and only ever added to. Admission-forever is documented; unbounded growth is not. Small per entry, unbounded in principle, rate-limited by whoever can afford `MIN_STAKE`.

---

## 5. Checked and found sound

Recorded so the next reviewer does not re-derive it, and so these are not re-litigated without cause.

- **Signing envelope.** `types.Tx.SigningHash` covers every meaningful field and `VerifySignature` requires `AddressFromPub(PubKey) == From`. No unauthenticated field is signed.
- **Print equals sign.** The CLI builds once, prints from the decode, signs the decode and posts its canonical re-encode. The fee ceiling is enforced on the **decoded** fee, never on the node's claim.
- **Framing.** Every decoder bounds before `make`, calls `Done()`, and refuses non-minimal varints, truncation and trailing data. `wire.DecodeBlock` refuses an oversized input before parsing it.
- **Store framing order.** The length-prefix CRC is verified **before** the length is used, so a corrupt length can never be mistaken for a torn tail and truncated away.
- **Certificate gate.** Re-tallies through `VoteSet.Add` against `CommitteeAt(block height)`, checks `totalPower` overflow explicitly, and `PullAndAdopt` verifies every unit before its `Append`.
- **Quorum arithmetic.** `quorumFor` is exact for every `uint64` total without forming `2·total`; every power sum feeding it is overflow-checked.
- **Epoch committee.** Derived only from committed state, memoised at exactly `e·E − 1` by both `Append` and replay, keyed by epoch, returned as copies. `CommitteeAt`, `IsSeatedAt` and `seatedAtLocked` agree.
- **`EverSeated` widening.** Authorisation only: consensus still judges by `CommitteeAt(height)`, and an ever-seated but unseated key gets an inert engine.
- **C-1 and N-4.** Funded-first preserves `Unfunded ≤ Amount` and burns the grant exactly once; `pendingUnbonded` is clamped and adjusted exactly once per insert/remove.
- **Power cap.** Order-independent, converges within its proven pass bound, and the invariant `4·power ≤ T` holds, so a derived committee never fails `Config.Validate`.
- **Panics from peers.** None found inside the scoped packages: `crypto.Verify` length-guards both fields, membership precedes `Verify` where it matters, and every count is capped before allocation.
- **Pages.** `html/template` with a fixed FuncMap, CSP `default-src 'none'`, bounded `queryEcho`, a shell-safe `Host` sanitiser, and no script, form or external asset.
- **Keystore.** `O_EXCL`, 0600 plus explicit `Chmod`, 0700 parent, derived-pubkey cross-check, version pin, and a permission refusal.
- **Concurrency.** No data race found. The `helloBinding` publish is ordered by `start()`; `relayMode` is dial intent and never name-derived; the relay's accept-time reservation transfers under one lock and does **not** repeat S-4.

## 6. Disproved suspicions

Listed because each was a plausible lead that cost a reviewer time, and recording the answer saves the next one.

- *"`EverSeated` widens consensus admission."* No — consensus judges by `CommitteeAt(height)` at every point.
- *"Duplicate-before-`Verify` in the tally lets a forged frame poison an honest slot."* No — `seen` is written only after membership, `Verify` and placement.
- *"The cap can emit a zero-power seat or fail to converge."* No — the floor is ≥ 1 for four or more seats and the pass bound is proven.
- *"A single restarted validator can double-commit."* No — one validator at ≤ 1/4 cannot supply the > 1/3 intersection.
- *"A member's vote at `MaxUint64` fills the dedup set."* Does not reproduce on a chain-backed router: no epoch committee exists above head, so the frame is refused before dedup.
- *"Transport-name forgery redirects a catch-up pull."* No — `via` is a routing key and `Expect` pins the responder's key on the response.
- *"A peer wins the relay exemption by announcing `relay:`."* No — the prefix is refused on every direct connection.
- *"Non-minimal varints, trailing data, hash-part ambiguity, Merkle duplicate-last-leaf, overflow in the stake transitions."* All properly closed; see the reviewers' derivations.

## 7. Blindspots

These are the findings behind the findings. Each produced at least two of the items above.

1. **There is no invariant that spans two packages.** `MaxTxsPerBlock` lives in `types`, the per-sender cap and claim bound in `mempool`, the claim bound again in `state.ApplyBlock`, the frame bound in `transport`, the window in `consensus`, and the proposal envelope in `consensus` too. **Nothing asserts they compose.** S-2, S-3, S-6 and the 6,353-transaction crash are all that one gap. A single test — *a full sync window of max-size legal blocks must encode under the frame bound, and the producer must always be able to build what the pool hands it* — would have caught all four.
2. **Every DoS bound counts a quantity, not a cost.** Bytes, frames, connections, slots and names are bounded; Ed25519 verifications, chain-lock trips, log writes and disk reads are not. The two places where cost is the scarce resource — gated HELLO admission and BLOCK_SYNC answers — are limited in proxy units, so they amplify by ~1000×.
3. **Every containment is a single timer**, and each is defeated by a slow-drip peer that stays just inside it. Timers bound silence, not intent.
4. **`Genesis.Validate` validates ranges, not the relationships the node depends on** (Argon2 memory against lanes, the claim bound against the pool's hand-out). A genesis can validate and then be unrunnable.
5. **The tests cannot see a test that asserts the wrong thing.** A-2 shipped broken twice with a passing test and a commit message explaining why it was safe; `TestHistoryIsSafeDuringAppends` passes on a `/history` that always returns 500; the `inboundSlots` bug passes because the cap test only exercises successful handshakes. **Mutation testing over `internal/consensus`, `internal/transport` and `internal/rpc` would find more than a seventh audit.**
6. **Report prose is not gated.** The stale `SECURITY.md` clause, the `?blocks` "clamped" claim, `node.Run`'s documentation, and the recovery promised by the stall line all describe behaviour the code does not have. No CI check compares a documented claim to the code, which is why each survived the change that falsified it.

## 8. Prioritised remediation

**Before anything else — each permanent, each a one-function fix, none visible to the current suite**

1. **S-4** release the inbound slot exactly once (two lines; add a counter observable).
2. **S-3** bound `SelectApplicable` by encoded size, and stop `node.Run` treating a build failure as fatal.
3. **S-2** bound `Answer` by bytes and add the triangle invariant test.
4. **S-1** refuse an unbond that would leave zero candidates; correct the stall line's promise.

**Then**

5. **S-8** charge `/block` the limiter and slot it deserves (two lines).
6. **S-9** `defer recover()` around each connection read loop, then a scheduled fuzz job with committed corpora.
7. **S-5** peek the proposal height before decoding it.
8. **S-6, S-7** reconcile the claim bound; refuse Argon2 tunings the library cannot take.
9. **S-10, S-11** put the revision in the banner and the build; gate and sign the release; verify named files, not `--ignore-missing`.
10. **S-12** stream `scanCerts`.
11. **S-13 … S-20** the low set, plus the `SECURITY.md` and help-text corrections.

**Process, and this is the part that has now failed six times**

12. Every finding above becomes either an issue or an explicit *"won't fix, because X"*. **A carried-over list is not a tracker.** The nine process gaps that have survived six consecutive reports are the evidence.
13. Add mutation testing to CI over the three packages where a wrong test is invisible.

---

## 9. Corrections, and a scoreboard

Recorded because a report that does not correct itself is the defect this whole
document is about. Every item below was found by the round that *fixed* the
finding, not by the review that wrote it. **Fifteen corrections to a report of
twenty findings** is the honest measure of what a source-only review is worth:
the defects were real; the repairs were mine to get wrong and I did.

### Findings whose mechanism was wrong

| ID | What this report said | What the code does |
|---|---|---|
| **S-7** | `argon2.IDKey` **panics** when memory < 8×lanes, so a validated genesis crashes every claim | `deriveKey` **coerces**: memory/(4·lanes)·(4·lanes), then raised to 8·lanes. Only `time<1` and `lanes<1` panic, and `Validate` already refuses those. **A validated genesis never crashes the node.** The real defect is narrower: the declared cost is not the cost that runs. |
| **S-20** | the set is "rate-limited by whoever can afford `MIN_STAKE` bonds" | A bond is **necessary and not sufficient** — a key that bonds and loses the seat draw is never admitted. So `|everSeated| ≤ len(genesis.Validators) + CommitteeSize × epochs`, ≈ 91 keys/day on testnet, ≈ 3 MB/year. **The set is bounded**; the finding is real but its severity was overstated. |
| **S-5** | "any connected peer, member **or stranger**" | A stranger cannot reach `Route` on a direct socket — the HELLO gate stops it. The stranger case is real **only over the relay link**. |
| **S-17** | the transaction is destroyed "if both land in one `Take` batch" | It is destroyed **even when its predecessor is in a later batch**, and ordering alone does not save it; the selection must also return nonce-ahead candidates for retry. |
| **S-12** | incomplete: names only `Open` | `CertAt` had a comparable unbounded allocation — **67 MB requested from a 54-byte log** — and a swapped-record bug: two equal-width records exchanged in place keep every checksum valid, so `CertAt(1)` served height 2's certificate. |

### Remedies that would have failed, or made things worse

| ID | The prescription | Why it was wrong |
|---|---|---|
| **S-4** | "move the release into `adopt`'s pre-install error paths" | `adopt` is **also outbound**, which books no slot; releasing there decrements a slot never taken and makes `MaxConns` *more* permissive. |
| **S-3** | `MaxTxsPerBlock <= (MaxBlockBytes − overhead)/minTxSize` as an init assertion | Arithmetically **false**: `(1 MiB − 212)/165 = 6,353`, so `10,000 <= 6,353` **panics every node at startup**. |
| **S-10** | "drop `-buildvcs=false`" | `-buildvcs=auto` derives `vcs.modified` from `git status`, and `build-release.sh` builds inside its own untracked `.release-stage/` — **every clean release would have stamped "(modified)"**. |
| **S-11** | `grep … \| sha256sum -c -` | GNU `sha256sum -c` **exits 0 on empty input**, so the check silently passes when the entry is missing — the exact failure it was written to catch. |
| **S-14** | "parse at 64 bits then clamp" | `?offset` had **no clamp at all**; a 64-bit parse alone turns `2⁶⁴−1` into `−1` and indexes out of range. |
| **S-18** | "wire the signing secret" | `ubuntu-latest` ships **no `minisign`**, so wiring alone could not have signed anything. |

### Understatements

- **S-2's consequence A**: a **single** sync unit carrying a max-size block already exceeded the old frame bound — such a block could not be synced **at all**, not merely inside a 64-height window. The legal-band boundary is 1,048,455, not 1,048,452.
- **S-2 has a fourth triangle member**: `chain.Build` validates **before signing**, so it measures a block 65 bytes smaller than the wire form, while `DecodeBlock` bounds the **signed** bytes. A block at 1,048,555 validates and is then undecodable by every peer — unreachable from an honest producer, but admitted by the validity rule.
- **S-16** was under-specified: "refuse a wildcard bind with neither token nor allowlist" does not say how the binary can *know* about an allowlist. It now takes `--external-allowlist`, which the systemd unit passes.

### Two errors in this document's own production

- The heredoc terminator was consumed by its content, so **three lines of generator shell** were written into the file and the line count first reported (228) included them.
- The fixing brief labelled **S-20 as `REPORTED`**; the table here says `VERIFIED`, which is correct. The label was mine to get right.

### The rule worth keeping

Across twenty findings: **four Highs held exactly as described; of the sixteen Medium and Low items, seven had a component that was wrong** — a false mechanism, an overstated scope, or an incomplete statement. Every one of those seven was marked `REPORTED` except S-20 and S-12.

**A source-only review finds defects reliably and repairs them unreliably.** Write the finding; let the person reading the code choose the fix; and mark what you did not reproduce.
