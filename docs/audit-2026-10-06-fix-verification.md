# Fix verification for the 2026-10-04 audit

| | |
|---|---|
| Audited baseline | commit `8224194`, findings in [`audit-2026-10-04.md`](audit-2026-10-04.md) |
| Verified tree | `origin/main` at `1124241` (60 commits after the baseline, 113 files, about 22,300 insertions). The local working tree is `68892f9`, which is `1124241` plus three unpushed commits that only re-add a duplicate `docs/audit.md`; the code is identical. |
| Date | 2026-10-06 |
| Method | Static review of every fix commit (`git show`), the current source and tests, and the CI run history via `gh`. Go is still not installed on the review machine, so no test was executed here. CI results on GitHub are the only execution evidence and are cited where they apply. Every "Fixed" verdict names the code that closes the finding and the test that pins it. |

Line references are against `1124241`.

---

## 1. Verdict

**The fix campaign closed every Critical and High finding, and most Medium ones, with real tests behind them.** The headline items are genuinely gone: validators now sign with key files and a committee-listed genesis; proposals are validated before any prevote; a locked proposer re-proposes with proof; the relay link has a fixed name and a maintainer that never goes dormant; the relay's memory bound is derived and quoted correctly; transactions carry the genesis hash and a fee; the data directory is locked; the mempool admits claims against head state; the toolchain is current and CI has lint, vulnerability and shell gates.

**What remains falls into four groups**, none Critical or High:

1. **Fixes that are partial by design and say so**: proof-of-lock evidence is not persisted across restart (C-2), the claim sub-pool can still be kept full by an attacker with many keys (R-1), two attacker source prefixes can still fill a relay receiver queue (N-2), `claim` still prints its key by default (O-10).
2. **New issues introduced by the fixes** (section 3): the per-connection rate limit now throttles the shared relay link, so a flooder at the relay drops honest votes rather than merely delaying them; a node sends its relay access token unconditionally, so a relay started without a token forwards the secret to every peer; the tally verifies a signature before its duplicate check, so a Byzantine proposer can pack one vote thousands of times into a justification; the store format changed with no version marker, so a pre-fix data directory fails with a hint that tells the operator to delete their chain; the single-node producer can exit on a backwards clock step.
3. **Process gaps the audit asked for that were not done**: coverage measurement, a fuzz job with committed corpora, CONTRIBUTING and CODEOWNERS, release signing in practice, the `t.Skip` fixture, ignored `Open` errors in store tests, the Sscanf stall parsing, a build tag for the subprocess CLI tests.
4. **Two undiagnosed CI failures** on commits that changed no Go code, one under `-race`. A new relay test added by a direct-to-main push has a 150 ms wall-clock margin and is the most likely culprit.

Counts, from the tables in section 2: of the 74 code findings, **55 Fixed, 9 Partially fixed, 8 Accepted or documented as the audit recommended, 2 Not fixed** (S-13 and S-19). Of the 9 process gaps in section 2.4, 2 are fixed and 7 are not. Nine new issues were found: 4 Medium and 5 Low.

---

## 2. Finding-by-finding status

Status key: **Fixed** = code closes it and a test pins it. **Partial** = materially narrowed, residual stated. **Accepted** = not changed, with a recorded rationale the reviewers agree with. **Not fixed** = open. **Docs** = the audit recommended documentation only, and it was documented.

### 2.1 Critical and High

| ID | Finding | Status | Fix | Pinned by |
|---|---|---|---|---|
| A-1 | Publicly derivable validator keys; relay open to the internet | **Fixed** | `internal/keystore` (0600 files, `O_EXCL`, load refuses group/other-readable); `b10coin keygen`; `--genesis PATH --key PATH` mode in `cmd/b10coin/main.go:591-700`; committee file loader `internal/genesis/committee_file.go:84-150` (duplicate keys refused, 1 to 255 seats); `StartValidator` refuses a key not in the committee (`tcpnode.go:334-339`); deploy recipe generates keys per Pi, never copies them, and replaces `ufw allow 7001/tcp` with a per-validator allowlist plus a relay access token. README qualifies the relay-trust claim to key-file committees. | `keystore_test.go:26-126`, `main_test.go:601, 641, 673, 715`, `genesismode_test.go:68-126`, `committee_file_test.go:48-187` |
| C-1 | Proposals committed without block validation | **Fixed** | `Engine.validate` seam, default `refuseWithoutSeam`, `SetValidate(nil)` panics (`engine.go:154, 268, 279-284`); driver installs `chain.ValidateConsensusNext` (`driver.go:199`); `maybePrevote` runs justification, then validate, then nil-prevotes on failure, then the lock (`engine.go:934-981`); header/envelope height mismatch is a protocol error (`engine.go:799-802`). Every non-nil prevote path goes through `maybePrevote`. | `engine_test.go:894, 1114, 1159, 1200`; 4-validator `driver_test.go:1773` asserts the height still commits a non-attack block and no durable lock names the attack ID |
| C-2 | No proof-of-lock | **Partial** | Lock move retains `lockedBlock`, `lockedVotes`, `lockedVoteRound` (`engine.go:1033-1051`); `StartProposing` re-proposes with `ValidRound` and `Justification` (`engine.go:1207-1223`); round ladder capped at 16 (`driver.go:102`). **Residual:** `LockRecord` is still `(height, round, blockID)` (`store.go:134-138`), so after a restart the locked proposer has no bytes and falls through to a fresh build it then nil-prevotes (pinned as intended at `engine_test.go:1409`). No `validValue` for an unlocked proposer. A whole-committee restart inside a contested height can stall until a still-loaded locked proposer is drawn. | `engine_test.go:1300`, `driver_test.go:1936` (the audit's lossy scenario), `:2105` |
| N-1 | Relay handshake reads an arbitrary first frame; permanent dormancy | **Fixed** | `adoptRelay` writes and reads nothing, registers under `relay:<addr>` (`tcp.go:1012-1021`); accepted connections may not claim `relay:` names (`:1058-1069`); `maintain` never exits except on `quit`, all refusals back off (`:818-897`); handshake ID bounded to 512 bytes (`:133, 974`). | `tcp_test.go:1332, 1441, 1551, 1709, 1796` |
| N-2 | Relay memory bound misstated; indefinite pin; censorship by queue fill | **Partial** | `MaxPinnedBytes = MaxConns × (WriteQueueBytes + WriteQueueFrames×32 + 2×MaxFrameBytes)` = 132 MiB at the new defaults (`relay.go:407-409`), quoted identically in README, `--help` and the unit's `MemoryMax=256M`; write deadline (`:1312`); per-sender byte share (`:664-667`); per-/24 and per-/64 accept cap including handshaking sockets (`:964-1006`). **Residuals:** the share is bytes-only, so 1-byte frames fill the 4096-entry ring by count; the share floors at `MaxFrameBytes` (half the queue), so two attacker prefixes fill any receiver queue (acknowledged in README); a trickle-reading peer under continuous arrivals is never reaped, so "nothing is pinned forever" is overstated, though bounded per connection. Kernel socket buffers are outside the derivation. | `relay_test.go:1216, 1550, 1802, 1876, 1474, 2006` |
| S-1 | No chain identifier in signed transaction | **Fixed** | `SigningHash(genesisHash)` adds the genesis hash as a separate `HashParts` part (`tx.go:107-109`), threaded through `VerifySignature`, `state.Params.GenesisHash`, `chain.genesisState`, every `mempool.New` caller and the `claim` signer. | `apply_test.go:1078, 1133`, `tx_test.go:88` |
| O-1 | No data-directory lock | **Fixed** | `internal/store/dirlock.go`: pidfile created atomically with `os.Link`, PID plus random token, liveness via `kill(pid,0)` or `OpenProcess`, stale-lock breaking serialised through `LOCK.break`, a crashed breaker's marker is reported for operator removal rather than auto-deleted, second in-process `Open` refused, released on `Close`. | `dirlock_test.go:79` (real child process), `:152-377` incl. simultaneous acquisition |
| R-1 | Garbage faucet claims wedge the mempool | **Partial** | `admitClaim` (`mempool.go:306-352`): claim sub-pool cap 64, one pending claim per address, epoch in {head, next}, `ClaimedEpoch`, exact nonce, then a 16-bit BLAKE3 pre-puzzle; no Argon2 at admission; skipped claims age out after 32 `Take` calls; per-remote-host token bucket in RPC. The transfer wedge is closed. **Residual:** the 64-slot sub-pool refills at 8 per block; an attacker with fresh keys needs about 8 × 2^16 hashes per block to keep it full, so honest claims see 503 and must retry. The pre-puzzle is mempool policy, not consensus, so there is no hard fork and `claim` solves it transparently. | `mempool_test.go:301` (10,000-claim flood then an honest transfer), `:331-470`, `server_test.go:195-258` |
| B-1 | EOL toolchain, no scanning, mutable pins, no licence | **Partial** | `go 1.26.0` / `toolchain go1.27.1`, `go-version-file: go.mod`; lint job with `gofmt -l`, `go mod tidy` diff, `staticcheck`, `govulncheck`, shellcheck; twice-weekly schedule; actions SHA-pinned; `permissions: contents: read`; Dependabot for gomod and actions (PRs 7 to 10 prove it works); MIT `LICENSE`; `SECURITY.md`. **Not done:** `CONTRIBUTING.md`, `CODEOWNERS`. | `ci.yml` lint job; green runs on `1124241` |

### 2.2 Medium

| ID | Status | Evidence and residual |
|---|---|---|
| C-3 round sync | **Fixed** | Per-height multi-round vote sets with a 4-round window each way (`engine.go:21, 30, 128, 590-607`); jump on attested power at or above `TotalPower − Quorum + 1` (exactly f+1), stride capped at 16, only from `OnTimeout` (`engine.go:417-555`); commit from any buffered round (`:1084-1136`); `(height, round)` persisted before emission and restored with a floor at the lock round (`:628-661`, `driver.go:200-209`); round log pruned to head and head+1 on `Append`. Lock rules intact: a conflicting quorum still needs a strictly later verified polka. **Residual:** proposals for other rounds are still dropped, so a follower that jumps onto a buffered polka locks without bytes and relies on catch-up; no test pins the lock-round floor branch. Pinned by `round_test.go:26-274`, `late_round_commit_test.go`, `driver_test.go:2158-2433`, `store/round_test.go`. |
| C-4 sync replay and amplification | **Fixed** | Nonce in the signed request (`sync.go:427-434`); membership before verify; per-requester 128/s window; `(requester, nonce)` seen-set with 30 s TTL; router hands requests to a bounded async server (queue 16, 2 workers) (`router.go:270-285`, `tcpnode.go:880-907`). Pinned by `sync_test.go:1929-1968`, `router_test.go:334`, `rotation_test.go:254`. See new issue 3 for ordering. |
| C-5 uncorrelated sync responses | **Fixed** | Nonce echoed; responder signs over the correlation fields and every served byte; `Receive` checks in-flight request, nonce, membership, the pinned `Expect` key and the signature; per-request channel (`sync.go:470-492, 867-899`). Identity is the signature, not the transport name. Pinned by `sync_test.go:1567-1821`. |
| C-6 tallest-peer monopoly | **Fixed** | Table keyed by signed member key and bounded by committee size; 4-wave TTL; demotion on failed or empty pulls; unproven heights capped at one window above the substantiated high-water mark; deterministic tie-break (`tcpnode.go:676-866`). Pinned by `rotation_test.go:46-217`. |
| C-7 certificate archive | **Fixed** | `certs.log` with the same framing; offset-only index; served from disk and re-verified per serve (`store.go:916-1025`, `sync.go:691-738`). **Residual:** `certIndex` and the block index are in-memory maps that grow one entry per height forever (tens of bytes per height; hundreds of MB per year at 2 s blocks). Pinned by `sync_test.go:1988`, `store_test.go:526, 575`. |
| C-8 verify before membership | **Fixed** | Router: membership, then height window, then `Verify`, then dedup (`router.go:227-261`); tally and engine check `IndexOf` first; comment corrected. Proposal decode still precedes membership (acknowledged; bounded by the transport rate limit). Pinned by `c8_router_test.go`, `engine_test.go:989`, `tally_test.go:91`. |
| N-3 unbounded inbound with `--listen` | **Fixed** | `MaxConns` taken under `t.mu` before the handshake goroutine; idle read deadline and write deadline on every path; unadmitted sockets excluded from `Peers()` and `Broadcast`; admission requires a verified HELLO from a committee member (`tcp.go:660-692, 1182-1214, 1299, 1344, 1422`). **Residual:** the HELLO signature has no freshness, so a captured member HELLO replayed to a `--listen` node is admitted and can out-rank the honest dial. Deploy leaves `--listen` off. Pinned by `tcp_test.go:1857-2119`. |
| N-4 sync-response pre-allocation | **Fixed** | Hint capped at `Remaining()/6`; votes appended without a hint (`wire/message.go:383-439`). Pinned with a MemStats assertion at `frame_test.go:411`. |
| N-5 wire tag collision | **Fixed** | Tags moved to `0x80` to `0x82`, `WireTagFloor` (`message.go:165-176`). Pinned by `router_test.go:84`. |
| N-6 dispatch serialised behind one callback | **Fixed with regression** | Per-connection token bucket consulted before admission and dispatch (`tcp.go:368-406, 1201-1204`). See new issue 1. |
| N-7 transport authentication, dedup wiring | **Fixed** | Dedup consulted strictly after `Verify`, sharded by height, 64 buckets, `Forget` on every wave (`router.go:249-260`, `dedup.go:23, 85-153`, `tcpnode.go:639-641`). Residual documented: a member-signed proposal at an extreme height holds one bucket. |
| N-8 relay allowlist impractical | **Fixed with caveats** | Pre-shared first frame compared by length and `subtle.ConstantTimeCompare`, consumed and never forwarded, 5 s silence timeout, caps bind at accept (`relay.go:1040-1077`); node flag `--relay-access-token-file`; recipe writes a 0600 token. **Caveats:** the token travels in plaintext over TCP and is replayable by any passive observer (no document says so); no minimum length is enforced; a node with a wrong or missing token is closed by the relay and redials forever with no log line. See new issue 2. Pinned by `relay_test.go:1935-2006`, `relay_auth_test.go:125`. |
| N-9 relay stats | **Fixed** | 60 s timer and SIGUSR1, `unauthorized` included (`cmd/b10coin-relay/main.go:173-232`). |
| N-10 systemd hardening | **Fixed** | Both units carry the standard set, `MemoryMax=256M` on the relay, `UMask=0077`; `MemoryDenyWriteExecute` omitted with a correct Go-runtime justification. Unverified on a Linux target, stated in the unit. |
| S-2 CRC excludes length prefix | **Fixed, no migration** | New frame `u64be(len) ‖ crc32c(len) ‖ payload ‖ crc32c(len‖payload)`; header CRC checked before the length is used; scan stops at the first corruption in any segment; only a short header or an over-running valid header is a torn tail (`store.go:456-577, 645-663`). Pinned by `store_test.go:102-482`. See new issue 4 for the missing format marker. |
| S-3 no fee | **Fixed** | `Fee uint64` in the signed body for every type; `MinFeeSparks` genesis parameter (1 spark on both chains, JSON records updated and pinned); debit `Amount + Fee` with overflow check; fee burned; claims must carry zero fee (`apply.go:73-120`). Pinned by `apply_test.go:1157-1216`, `genesis_test.go:252`. Residual: `admitTransfer` does not pre-check the fee or balance (Info). |
| S-4 Argon2 on rejected claims | **Fixed** at the mempool layer (see R-1). Apply-side cost remains bounded by `MaxClaimsPerBlock` as before. |
| S-5 genesis bounds | **Fixed** | Argon2 memory 1 to 256 MiB, iterations and lanes at least 1, claim amount at least 1, claim bound at most `MaxTxsPerBlock`, duplicate keys, committee size 0 to 255, `Time > 0`, `MinFee > 0` (`genesis.go:241-325`). Each has a negative test. |
| S-6 clone per candidate | **Fixed** | One `Probe(nil)` then `ApplyTx` in place (`chain.go:362-377`). Allocation-ratio test `select_bench_test.go:93`. |
| S-7 whole-segment reads | **Fixed** | Per-segment read handles, LRU of 8, `ReadAt` per record, streaming scan (`store.go:525-577, 671-757`). Pinned by `read_alloc_test.go:34`. |
| S-8 timestamps | **Fixed** | Strict `> parent` at `Append`; consensus path pins `== parent + 1` (`chain.go:488-491, 572-583`). Pinned by `timestamp_test.go`. See new issue 5. |
| S-9 same-nonce admission | **Fixed** | `pendingNonces` per sender for transfers (`mempool.go:150-159`). Pinned by `same_nonce_test.go:121`. |
| S-10 verify under the pool lock | **Fixed** | Signatures verified in a first phase outside the lock (`mempool.go:224-232`). Pinned by `lock_test.go:19, 73`. See new issue 6 for the lock that was added. |
| T-1 CatchUp determinism | **Fixed** | The pull runs on the caller's goroutine and the reply wait advances the virtual clock (`simnet.go:286-293, 914-960`). Pinned by `simnet_test.go:146` with a non-vacuity assertion. |
| T-2 wall-clock reply wait | **Fixed** | `WaitReply` seam on the syncer (`sync.go:243-260, 908-924`). Pinned by `sync_test.go:2074`. |
| T-3 test timeout | **Fixed** | `-timeout 40m` on both test runs (`ci.yml:58-59`). |
| B-2 releases | **Partial** | `-trimpath -buildvcs=false`, `BUILD-INFO` with the toolchain, asserted in CI; `dist/` uploaded as an artifact; recipe copies and verifies `SHA256SUMS`. **Not done in practice:** minisign only when `B10COIN_RELEASE_SIGN_KEY` is set and CI has no secret, so every published checksum file is unsigned; no provenance attestation. |
| D-1 README staleness | **Fixed** | Twenty packages listed and matching; node flag table complete; M4 moved out of Pending; catch-up wording corrected; deploy README clones the default branch. |

### 2.3 Low and Info

| Area | Fixed | Partial or accepted | Not fixed |
|---|---|---|---|
| Consensus C-9 to C-17 | C-9 `ValidRound >= Round` refused; C-11 non-member returns an error; C-12 comments corrected; C-13 lock and round logs pruned; C-14 grinding cost closed via the `parent+1` pin; C-15 unit count and window checked; C-17 certificate overflow refused, `TimeoutEvent.Step` removed, key and signature lengths bounded at decode | C-10 prevotes not persisted (accepted, pinned as behaviour at `engine_test.go:1564`); C-16 chain ID absent from vote hashes (deferred to a versioned signing revision); `CommitteeAt` still unread | — |
| Networking N-11 to N-19 | N-11 `WriteFrame` refuses empty and oversize; N-12 key lengths bounded; N-13 skip deadline; N-14 relay `finish` atomic; N-15 help text; N-16 `ssh --`, port validation, `pipefail`, shellcheck gate; N-17 workstation path and argv | N-18 dedup `Forget` now O(buckets); extreme-height bucket bounded | — |
| Core S-11 to S-20 | S-11 canonical addresses; S-14 position authenticated at the chain layer; S-16 doc and pinned arithmetic; S-17 varint error class and `DecodeBlock` guard; S-20 committee size bounds | S-12, S-18 documented as recommended; S-15 directory fsync added, file modes unchanged | S-13 rejected with an incorrect rationale (see new issue 7); S-19 validity window (acknowledged in `tx.go:40-49`) |
| Chain, node, RPC, CLI O-2 to O-12 | O-5 genesis marker and repair hint; O-6 `Build(nil)` guarded; O-8 `HeadSnapshot`, no path leak on 500, 4096-byte body with 413, 503 on full; O-11 all six items | O-2, O-3, O-4, O-7 documented as accepted; O-9 ID cached per entry, scan still linear; O-10 `--print-key` opt-out added, default still prints | No logging added to `rpc`, `node` or `chain` |

### 2.4 Process gaps from section 5.2 of the audit

| Gap | Status |
|---|---|
| Coverage measurement in CI | **Not fixed.** No `-coverprofile` anywhere. |
| Fuzz job and committed corpora | **Not fixed.** No `-fuzz` in CI, no `testdata/fuzz/`, no new fuzz targets. |
| `-timeout` | Fixed. |
| Suite runs twice | Unchanged, deliberate. |
| `t.Skip` on a deterministic fixture | **Not fixed** (`driver_test.go:1618`). |
| `s, _ := Open(...)` in store tests | **Not fixed**, now 8 sites (`store_test.go:36-304`). |
| Sscanf stall parsing | **Not fixed** (`simnet_test.go:404`, `scenarios_test.go:148`). |
| shellcheck in CI | Fixed. |
| Build tag for subprocess CLI tests | **Not fixed.** |

### 2.5 Documentation table from section 6.1

Fixed: relay "cannot forge" qualified; memory bound derived; backoff claim now true; allowlist shown; damaged-record wording; fees wording; M4 status; dedup now wired; deploy clone and checksum steps; "no output is healthy" replaced; router and nil-prevote comments; `SeriesTotal` doc.

Not fixed: M4 plan Design Decision 2 still says the tags differ; M3 plan DD4 not marked superseded; M4 plan Task 4 signature stale; `pow.go` ASIC claim unchanged; `chain_lock_test.go` not renamed; no `docs/plans/README.md`. New: `README.md:714` "nothing parses the JSON at runtime" is now false for the committee file (the JSON bytes do not enter a hash, which is what matters, but the sentence should be reworded).

---

## 3. New issues introduced or exposed by the fixes

| # | Sev | Finding | Where | Fix |
|---|---|---|---|---|
| 1 | **Medium** | **The per-connection rate limit throttles the shared relay link.** Every honest peer's traffic arrives on one `relay:<addr>` connection, and the bucket drops whatever frame arrives once tokens are exhausted. Anyone who can put frames on the relay (anyone, without a token; any token holder, with one) sending above 2000 frames per second of 1-byte frames (about 10 KB/s) makes every validator drop honest votes and proposals indiscriminately. Before this fix a flood only delayed dispatch. | `tcp.go:368-406, 1201-1204`; the comment at `:359-361` notes the shared link but applies the same bucket | Exempt relay-mode connections, or make the node-side limit byte-based and push per-sender limiting to the relay, where the sender is known. |
| 2 | **Medium** | **A node sends its relay access token unconditionally, and a relay without a token forwards it to every peer.** `adoptRelay` writes the token as the first frame whenever it is configured; a relay started without `--access-token-file` skips the gate and treats that frame as ordinary payload. A misconfigured, rolled-back or older relay therefore leaks the secret to every registered connection, including strangers, and nothing on either side notices. Related: the token is plaintext over TCP and replayable by a passive observer, which no document states; no minimum length is enforced (a 1-byte token is brute-forced in 256 dials); a node whose token is refused redials forever with no log line, so the failure is visible only in the relay's `unauthorized` counter. | `tcp.go:1012-1021`, `relay.go:1048-1050, 1176` | Have the relay signal gating (a fixed first frame from the relay, or refuse to run without a token); enforce a minimum token length; log handshake deaths on the node; document the plaintext and replay limits. |
| 3 | **Medium** | **The tally verifies a signature before its per-validator duplicate check**, so a Byzantine proposer can pack one valid member vote thousands of times into a 1 MiB justification and force every validator to run thousands of Ed25519 verifications under the driver lock, once per round it proposes. The sync request path has the same ordering problem in reverse: the rate bucket is charged before the replay check, so a captured signed request replayed to every server drains that member's catch-up budget for free. | `tally.go:94-103`, `sync.go:772-775` | Move the `seen` check before `Verify` in `VoteSet.Add` (safe, since only verified votes are recorded); check replay before charging the bucket. |
| 4 | **Medium** (operational) | **The store format changed with no magic or version marker.** A data directory written before `4b1f36c` fails `Open` with a checksum-mismatch error whose repair hint says the record is bit rot and tells the operator to truncate at offset 0, which would delete the chain. Neither README mentions wiping `--dir` after upgrading. The same "add it while the format is free" argument the fee commit makes applies here. | `store.go:456-475, 494-510` | Add a segment header with magic and version; make the hint distinguish "unrecognised format" from corruption; document the reset. |
| 5 | Low | **The single-node producer can exit on a clock step.** `RunOnce` stamps `time.Now()` with no clamp, `Append` now requires `> parent`, and `Run` exits on the first error. A backwards NTP step or a `--block-time` under one second stops the node. | `node.go:46-48, 118-119`, `chain.go:488-491` | Stamp `max(now, parent+1)`. |
| 6 | Low | **The pool lock is now held while taking the chain's read lock.** `Add` snapshots `AdmissionHead` under `pool.mu`. Lock order is consistent and the chain never calls the pool, so there is no deadlock, but during `Append`'s fsync every `POST /tx` and `/status` now stalls behind the write lock. Widens the footprint of accepted finding O-4. | `mempool.go:239-242` | Snapshot the head before taking the pool lock, or release the chain lock before the per-item loop. |
| 7 | Low | **The new comment rejecting S-13 is wrong.** It argues that Ed25519 signing is deterministic so one key has exactly one signature per body. Determinism is a property of the honest signer; a key holder can choose any nonce and produce unlimited distinct valid signatures, each yielding a distinct transaction ID. Impact is contained by the per-sender pending-nonce set from S-9, which is therefore load-bearing and must not be removed on the strength of this comment. | `tx.go:111-124` | Correct the comment; keep `pendingNonces`. |
| 8 | Low | **Committee file loader gaps.** No `DisallowUnknownFields`, so a misspelled key is silently ignored; public keys are checked for length only, not as valid curve points, so a seat that can never sign still counts toward quorum; `scripts/deploy/committee.example.json` is parsed by no test. | `committee_file.go:84-150` | Add the three checks and a test over the example file. |
| 9 | Low | **Windows liveness check treats access-denied as dead.** `processAlive` returns false on any `OpenProcess` failure, so a live lock held by another Windows account is broken. Linux is the deployment target. | `process_windows.go` | Distinguish `ERROR_ACCESS_DENIED` as alive, or comment the limitation. |

Also noted, Info: `certIndex` and the block index grow one map entry per height forever (C-7 residual); `MaxClaimAgeBlocks` counts `Take` calls, which in the consensus driver is per round rather than per block; the RPC rate limiter evicts first-seen rather than least-recently-used and `ErrSenderLimit` maps to 400 rather than 429; `Add` runs Ed25519 before the cheaper BLAKE3 pre-puzzle; `persistRound` panics on a disk error for a liveness-only record; `StartValidator` does not length-check a programmatic `Key` before `.Public()`; the relay's token handshake reads under the 1 MiB frame bound rather than a small one; `awaitReplyVirtual` burns the full reply wait of virtual time per pull window.

---

## 4. CI history and process

**Runs since the audit.** Four `test`-job failures out of roughly 60 runs; `lint`, `cross` and `release` were green every time. Job logs are admin-only, so the failing test names could not be read from here.

| Run | Commit | Changed | Assessment |
|---|---|---|---|
| `37281329458` | `97a1921` relay memory bound | relay code | Real breakage, fixed by the next commit |
| `37303225525` | `72c61c1` superseded link self-heals | relay code | Real breakage, fixed by `b199422` |
| `37362892092` | `f54eb23` README wording | **no Go code** | **Flaky test**, plain run; not re-run, not diagnosed |
| `37440233423` | `8a45376` x/crypto bump merge | `go.mod`, `go.sum` | **Flaky under `-race`**; same tree passed on the PR branch 90 minutes earlier; not diagnosed |

**Most likely flake.** `TestTheReaperDoesNotBlameAReceiverForASendersBacklog` (`relay_test.go:2275-2345`, added by direct push `517f591` 45 minutes before the `-race` failure) uses `writeTimeout = 200ms`, records `lastPush` once, sleeps `writeTimeout/4`, and then needs the whole drain to finish inside the remaining 150 ms of wall clock or the reaper legitimately fires. Under `-race` with GC on a shared runner that margin is thin. The other new sleep-and-assert tests (`tcp_test.go:1667, 1767`) cannot fail spuriously but can pass vacuously.

**Review path.** 46 fix commits went through PR 6 with green CI at merge; the four Dependabot PRs had green runs. Two commits, `517f591` and `187f772` (about 1,200 test lines between them), were pushed directly to `main` with a passing push run but no PR review. The audit commit `95418ec` was also direct.

**Argon2 golden vector** is unchanged across the `golang.org/x/crypto` 0.41 to 0.57 bump and the test that pins it passed on every run after the merge.

**Repository state.** `origin/main` carries only `docs/audit-2026-10-04.md`. The local branch is three commits ahead and those commits re-add the original `docs/audit.md`, byte-identical apart from line endings. Pushing as-is publishes the duplicate; drop `docs/audit.md` first. There is no `.gitattributes`, so `*.sh` and `*.service` check out with CRLF on Windows.

---

## 5. Recommended next steps, in order

1. **New issue 1**: exempt or reshape the rate limit on relay-mode connections. This is the one regression that makes an honest deployment worse than before.
2. **New issue 2**: make the relay refuse to run without a token or signal gating before the node sends it; enforce a minimum length; log node-side handshake deaths; document plaintext and replay.
3. **New issue 3**: duplicate check before signature verification in `VoteSet.Add`; replay check before the rate bucket in `Answer`.
4. **New issue 4**: store magic and version; correct the repair hint; document the data-directory reset.
5. **C-2 residual**: persist the locked block bytes and polka with the lock record so a restarted locked proposer can still re-propose with proof.
6. Diagnose the two flaky CI failures by widening the relay test's margin or driving it with a constructed clock, then enable `-race` reruns to surface the test name.
7. Finish the process items: coverage in CI, a scheduled fuzz job with committed corpora, `CONTRIBUTING.md` and `CODEOWNERS`, a release signing key in CI, the `t.Skip` fixture, the ignored `Open` errors, the typed stall error, a build tag for the subprocess tests.
8. Low items 5 to 9, the stale plan-document rows, `pow.go`'s ASIC sentence, the `chain_lock_test.go` rename, and flipping `--print-key` to default off.
