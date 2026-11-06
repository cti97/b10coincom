# Test run report: main at 10 nodes, Docker only (2026-11-06)

**Commit under test:** `39a9363` (origin/main, "Merge pull request #22 from cti97/security-2026-11-06-followup"). It contains the M5 fixes, the 2026-10-31 audit fixes, M6 with the 2026-11-01 M6 audit fixes, the 2026-11-06 security review fixes S-5..S-20, and the rolling-restart work from the previous report: `5af2174` (the 3-seat stall fix), `af7a73e` (the stall-line false positives) and `1445c7b` (the resume line).
**Previous run:** [testrun-2026-10-30-m5-docker-rerun.md](testrun-2026-10-30-m5-docker-rerun.md)
**Scale:** every multi-node check used **10 validators** (the previous runs used 3 to 6).
**Environment:** Windows 11, Docker Desktop, 16 CPUs. Every check ran in containers: `golang:1.27.3-bookworm` (go1.27.3 linux/amd64) for builds and tests, and a `debian:bookworm-slim` runtime for nodes. Each container cloned the repo from a read-only mount and checked out `39a9363` explicitly. Every log prints `HEAD 39a93632dea0…`, and the binaries report `0.1.0 rev 39a93632dea0 (clean)`.
**Method:** five areas ran in parallel. An adversarial verifier then checked each area: it read the logs, tried to refute each claim, and re-ran anything doubtful on fresh containers. Everything below is the verified result.

> **Load caveat.** The five areas plus their verifiers ran up to about 57 containers on one host (load average up to 117 on 16 CPUs). Wall-clock timings are inflated. Two results in the original run (a race-suite failure, and a "7 of 10 crawl") were load artefacts that the verifiers refuted or reclassified. They are noted as such below.

## Summary

| Area | Result | Notes |
|---|---|---|
| Test suite + lint | **partial** | 1324/1324 pass without race, 0 data races. One race run on the overloaded host failed 5 timing/liveness tests. The second race run passed 22/22, and the verifier's re-run also passed 22/22 and 1324/1324. All five tests are flaky because of load. Lint, staticcheck, govulncheck, fuzz (9 targets), the cross build and the release job are all clean. |
| Acceptance + release + walkthrough | **pass** | Every README-quoted output matches exactly (state root `98e5cf46…`). Runs at 10 validators: 200 blocks pass, and the rotation demo passes (10 → 9 seats, k=4). 12/12 release artefacts are reproducible across warm and cold caches. The M6 walkthrough passes. |
| 10-validator network | **partial** | Relay star, fault tolerance (7 of 10 live, a stall at 6), the documented, fast and all-at-once restarts, 20 lock-window cycles, the mesh, and reconnect backoff all pass. **New high finding N-1:** several validators catching up at once over the relay halt the healthy quorum for minutes. |
| Staking at 10 seats | **partial** | All verbs, refusals, ST-3, C-1, pipelined unbonds and replay protection pass. **Found:** two nodeless bonds silently halt the fixture chain (S-1); transactions are not gossiped (S-2); the claim CLI is devnet-only, contrary to the README (S-3). Rotation-in of a newly bonded key was not reached. |
| M6 wallet, faucet, explorer | **pass** | Walkthrough, the bounded window, the trust boundaries, HTML escaping and the negative inputs all pass. A few low-severity doc and text mismatches. |

## Findings

### High

**N-1. Validators catching up over the relay can halt the healthy quorum for minutes.** *(Verifier: reproduced 2/2.)*
- **Setup:** 7 healthy validators committing about 6 blocks/s. 3 validators were stopped for 4.5 minutes, which left them about 1700 blocks behind, then restarted together.
- **Result:** the healthy 7 froze at height 5981 for **4 min 6 s** (14:41:29–14:45:35). They resumed only after two of the three laggards reached the head.
- **What the healthy nodes logged:** stall lines with `quorum reachable with 900000000000 … proposal=absent; prevote votes=1`. The healthy nodes stopped hearing each other's votes.
- **What the relay showed:** `dropped` rose 15 → 1530 over the window, and `conns` dipped from 10 to 8.
- **Second occurrence:** the same signature appeared with 8 healthy nodes and 2 syncing from height 0 (frozen at 1811).
- **Probable cause (not yet diagnosed):** bulk BLOCK_SYNC traffic crowds consensus frames out of the relay's per-connection queue (2 MiB / 4096 frames), by head-of-line blocking or by drops.
- **Not affected:** a single lagging node, which caught up without stalling the chain (check 3).
- **How this was missed:** the original run never had more than one validator far behind at once. Any operator who restarts several nodes after an outage will hit it.

### Medium

**S-1. Two nodeless MIN_STAKE bonds permanently and silently halt the 10-seat fixture chain.** *(Verifier: reproduced, deterministic.)*
- **Setup:** two keys bonded 10¹¹ each, with no node behind either key, before boundary 2000.
- **Result:** all 10 nodes froze at 1999 for more than 9 minutes.
- **Arithmetic:** the 1/4 cap gives the two bonded seats 4 + 4 of 16 against eight power-1 fixture seats, which leaves 8/16 live, below quorum.
- **No way out:** no Unbond can be included to free the seats.
- **No signal:** the nodes logged nothing after the halt, because with quorum unreachable the stall line does not fire.
- **Doc conflict:** the README's "two silent seats are tolerated from N ≥ 7" assumes equal seats.
- **Related, same run:** with one nodeless bond the chain runs at exactly quorum (`9 of 12 power (quorum 9)`).

**S-2. Transactions are not gossiped.** The wire carries only proposals, votes, HELLO, block sync and peer exchange (`internal/consensus/message.go:24-26`, `internal/wire/message.go:47-54`).
- **On a seated node:** a tx waits for that node's proposer turn, roughly 1 in 10 heights.
- **On an unseated node:** a tx is accepted with a txid and never included. This was observed live: an Unbond posted to the displaced seat f3 sat in its mempool for 400 blocks, and reposting the same bytes to f0 applied it in 12 s.
- **Where it's undocumented:** neither the README nor the CLI says this.

**S-3. The README says the shipped CLI can walk the 1,001-claim path; it cannot on committee-file or fixture chains.**
- **The code:** `claim` and `claim --key` refuse any chain that is not `b10coin-devnet-1` (`runs chain "…", not the devnet genesis "b10coin-devnet-1"`, rc=1).
- **Consequence:** on a chain built by the deploy recipe, no shipped command can fund an operator key to MIN_STAKE.
- **Same mismatch elsewhere:** the stake refusal text and the faucet page (W-1) still point users at it.

**N-2. The relay's default `--max-conns-per-ip 8` locks out validators that share a /24, and the node blames the token.** *(Verifier: reproduced.)*
- **What happened:** with default flags, 2 of 10 validators on one Docker bridge were refused at accept.
- **What they logged:** `the relay did not announce the access-token gate, so no proof was sent … EOF`, which sends the operator to the wrong problem.
- **Correction to the original run:** 8 of 10 connected still commit. The original's 5-minute height-0 stall was caused by outside container interference.
- **What's undocumented:** the README documents the cap, but not the consequence for validators behind one NAT, LAN or Docker bridge.
- **How the rest of the run worked around it:** with `--max-conns-per-ip` set to 16, 32 or 64.

**T-1. Rotation and RT-3 devnet tests fail on liveness under heavy CPU contention (`-race`).**
- **The tests:** `TestARotatedInValidatorStartsAndIsCounted`, `TestAStrangerIsStillRefusedAfterABoundary` and `TestARotatedOutValidatorResyncsReannouncesAndIsCountedAgain`.
- **The failure:** `heights [0 0 0 0 0]` at the 60 s wait, with about 53 other containers loading the host.
- **Under moderate load:** all three pass 10/10, and the full suite under race is 22/22 twice.
- **Classification:** flaky because of load, not deterministic. The fixed 60 s and 120 s waits are what make them brittle on slow shared CI runners.

**S-4. A claim flood slowed chain G about tenfold.** *(Plausible but unisolated.)*
- **Measured:** about 0.1 blocks/s while claims were posted, and about 1.15 blocks/s once they paused.
- **Why unisolated:** the host was heavily loaded, and the verifier did not re-run it.

### Low

- **N-3. The stall line is still noisy at 10 seats.**
  - It fires on hiccups of seconds: about 40 lines in 4 bursts during normal 10/10 running, and 20 lines during the documented one-at-a-time restart, whose longest gap was 8.4 s.
  - It also fires on nodes that are only syncing.
  - Eight rounds pass in a few seconds at low rounds. The README promises the line marks a stall that "can hold for minutes".
- **N-4. The stall-line peer list mislabels seats.** *(Verifier: reproduced on a fresh chain.)*
  - Seat 0 logs `peers=9[seat0, seat1, seat2, seat3, seat5, …]`: it includes itself and omits seat4.
  - Seat 4 includes itself and omits seat8.
  - Probably an index-to-seat mapping bug in the diagnostic.
- **N-5. Several catch-ups at once advance in bursts with 60–150 s pauses.** This is the syncing side of N-1.
  - **One node alone (light load):** about 1250 blocks in 45 s.
  - **One node alone (original run, heavy load):** about 550 blocks in 96 s, mostly load.
- **T-2. Two timing-threshold tests flake under `-race` on a loaded host.**
  - `TestRelayAKeepaliveSinkCannotPinASlotOrMemory` hit its 30 s wait at `relay_test.go:1471`.
  - `TestASlowReaderDoesNotBlockTheSender` took 2.595 s against a 2 s bound.
  - Both pass 10/10 in isolation.
- **W-1. On a non-devnet chain, the faucet page tells users to run a `claim` command that the CLI refuses.** The page states no devnet-only condition (`internal/rpc/templates/faucet.html`, "What to run").
- **W-2. The usage text says the node clamps `--blocks` above 500, but the CLI refuses it.**
  - The stale text is at `cmd/b10coin/main.go:172`.
  - `history --blocks 501` exits 1 since W-5.
  - The flag help was updated; this paragraph was not.
- **S-5. A fresh-directory re-seat from the deploy README cannot work for a post-genesis key.** This comes from reading the code, with only a partial live check.
- **A-1. CI timing comments are stale.**
  - The rotation demo is "about 8 s" in `ci.yml:137`; it measured 65–91 s wall here, against 14 s of user CPU, so it is bound by timers and load.
  - The devnet package is "104 s alone, 177 s in the full suite" in the comment; it measured 189–227 s here.
  - To confirm or refute these, re-run on an idle host.
- **A-2. The Nakamoto "top share" truncates instead of rounding.** For example, 1/6 prints as 16% and 1/9 as 11%. It is consistent with the README.

### Info

- **The wallet CLI does not retry a 503.** With 20 parallel mixed requests to one node, 4 of 5 `b10coin history` runs exited 1 with `503 … busy scanning`. The 4-slot semaphore works as designed (R-1/S-8).
- **R-7 is still open.** The faucet page says it is "bound to the node's loopback address" even on a node serving `0.0.0.0` (`faucet.html:71`).
- **Devnet at `--block-time 1s` hit same-second timestamp collisions during a 230-claim burst.** It logged 4 `block timestamp … is not after parent timestamp` lines. It recovered by itself, and all claims were paid.
- **No committed fuzz corpus.** `git ls-files` has no `testdata/fuzz` entries.
- **`check-plan.sh` in full mode needs python3.** The golang image lacks it, and the script correctly refuses (S-19).
- **`scripts/deploy/build.sh` replaces a full release `dist/`.** The script header documents this. Copy `dist/` first.
- **A 10-node fixture chain started one container at a time sits at height 0 for about 53 s (rounds 16–34) before the ladder converges.** This is consistent with the documented rolling-start behaviour.

## Status of earlier findings

| Item | Source | Status at `39a9363` | Evidence |
|---|---|---|---|
| 3-seat rolling-restart stall | previous report, fixed by `5af2174` | **Holds at 10 seats** | Step 4b, a fast rolling restart of all 10 with about 10 s outages and no waiting: the chain advanced 2 s after the last start, the longest window was 3.5 s, and all 10 were level within 15 s. Step 4c, all 10 restarted together: longest window 23.1 s. 20 lock-window stop/start cycles (every 4th was a `docker kill`): 0 stalls, `advance=2s` after each, longest window 5.5 s. |
| Stall-line false positives | `af7a73e` | **Partly** | No line fired in step 4c. At 10 seats, though, the 8-round threshold is still reached on hiccups of seconds (N-3). |
| Resume line | `1445c7b` | **Works** | Restarted nodes printed `consensus    resuming height H at round R …` (4 of the 10 in step 4c are quoted in the log). |
| M-1 reconnect backoff | M5 re-run | **Fixed** | Wrong-token node: 14 refusals over about 2 minutes, with growing gaps capped below 30 s. |
| M-2 `--peers` chain does not mesh | M5 re-run | **As documented** | A `--peers` chain and a `--peers` star both stay at height 0. The README documents the chain case. The star case follows from the same rule but is not named. |
| H-1 / H-2 | M5 run | **Still fixed** | A single node 550 blocks behind caught up with no chain stall (check 3), and every restart pattern recovered. |
| S-16 relay open-bind refusal | 11-06 security review | **Works** | `b10coin-relay --addr :7001` with no token: `refusing to listen … with no access token … (audit S-16)`, exit 2. |
| S-10 release VCS identity | 11-06 security review | **Works** | BUILD-INFO has `vcs.revision 39a9363…` and `vcs.modified false`. The release is marked UNSIGNED because no key was supplied. |
| R-1 / S-8 / S-14 bounded window | M6 audit, 11-06 review | **Works** | Server clamp: `blocks=501..2^64-1` returns `blocks:500`. Concurrent scans are limited to 4 slots (503 beyond). |
| W-1..W-3, S-13, R-3, T-2 trust boundaries | M6 audit | **Works** | Fee ceiling, redirect refusal, foreign-chain refusal and no-echo of key-shaped inputs were checked against a fake node. |
| ST-3, C-1, pipelined unbonds | M5 / 10-31 audit | **Works** | Live on the 10-seat fixture. |

## Checks run

### Test suite + lint (`b10-suite-`)

| Check | Result |
|---|---|
| `go vet ./...`, `go build ./...` | pass |
| `go test -count=1 -v ./...` | **pass**: 22/22 packages, 1324 RUN / 1324 PASS / 0 FAIL / 0 SKIP (357 subtests), 491 s. The previous run had 1016. |
| `go test -race ./...`, run 1 (about 53 containers on the host) | **fail**: 19/22; 5 load-flaky tests (T-1, T-2); 0 data races |
| `go test -race ./...`, run 2, plus the verifier re-run | **pass**: 22/22, 1324/1324, 0 data races |
| Cross build + vet for 6 targets | pass (cross-compiled from linux; CI builds darwin and windows natively) |
| CI release job | pass: 12 artefacts, `RELEASE_ASSERTIONS_OK`, statically linked linux ELFs |
| CI fuzz job, 9 targets × 60 s | pass, no crashers |
| gofmt, `go mod tidy`, staticcheck, govulncheck | clean |
| shellcheck v0.11.0 (CI pin) at `--severity=warning` | clean. 7 info/style notes at default severity. |
| `check-strays.sh`; `check-plan.sh` parity-only and full | pass. Full mode refuses without python3, as S-19 intends. |
| Benchmarks | 0 allocs/op on the observer and `IsSeatedAt` paths |

Slowest tests in the plain run: `TestScenarioHappyPath` 331.7 s, `TestThreeValidatorsAgreeOnABlockThatCarriesATransferAndAClaim` 82.3 s, and `TestThePlotShowsAStepAtTheBoundary` 70.4 s.

### Acceptance + release + walkthrough (`b10-accept-`)

| Check | Result |
|---|---|
| `devnet --blocks 100`, run twice plus a verifier run | pass: byte-identical, height 102, root `98e5cf468ecf…1cdd11cc` |
| `devnet --claims 1`, `--validators 4` | pass, matches the README |
| 6-validator rotation + Nakamoto | pass: the table matches the README |
| **10 validators, 200 blocks** | pass: all ten at 200, agreed. Run once (191 s). |
| **10-validator rotation + Nakamoto** | pass, twice, with identical tables: 10 → 9 seats at h40, k=4, top share 10% → 11% |
| Negative CLI cases | pass: usage errors exit 2, validation errors exit 1, and keygen refuses to overwrite |
| `scripts/acceptance-walkthrough.sh` | pass, 3/3 runs |
| Release reproducibility | pass: identical SHA256SUMS across 3 builds (warm, warm after moving `dist/`, cold cache). The deploy build matches. |

### 10-validator network (`b10-net-`)

| Check | Result |
|---|---|
| Relay refuses an open wildcard bind (S-16) | pass |
| Relay star, 10 validators, `acceptance.sh --mode http` | pass. The verifier re-ran it: block 4101 identical on all 10. |
| Stop 3 of 10: the 7 survivors keep committing | pass. Clean re-run: about 6 blocks/s for 4 min, no stall. The original's crawl was host load. |
| Stop a 4th: STALLED with 6 live | pass (the expected stall) |
| Restart the 4 → all 10 agree | pass, but these nodes were 0 blocks behind (see N-1) |
| Restart 3 validators about 1700 blocks behind | **fail**: N-1 |
| Catch-up after 90 s down, twice | pass: 96 s each, no chain stall |
| Documented one-at-a-time restart of all 10 | pass: longest window 8.4 s |
| Fast rolling restart of all 10, no waiting | pass: longest window 3.5 s |
| Restart all 10 together | pass: longest window 23.1 s |
| 20 lock-window cycles | pass: 0 stalls |
| Direct full mesh, no relay | pass |
| `--peers` chain and star | stays at height 0, as documented |
| Reconnect backoff with a wrong token | pass: growing gaps, capped below 30 s |

### Staking at 10 seats (`b10-stake-`)

| Check | Result |
|---|---|
| `stake --amount 1000` → Bond | pass (verifier reproduced it) |
| Refusal matrix: below MIN_STAKE, above balance, unstake above bonded, remainder below MIN, early withdraw | pass |
| Boundary with one nodeless bond | pass at exactly quorum, 9 of 12 (verifier reproduced it) |
| Boundary with two nodeless bonds | **fail**: S-1 |
| Rotation-in of a newly bonded key with its own node | **not run**: no shipped path funds a key on a committee chain (S-3) |
| Unstake → withdraw at maturity → second withdraw refused | pass |
| ST-3: a genesis seat's unfunded power is destroyed, not released | pass |
| C-1: funded-first proceeds | pass |
| Pipelined unbonds, same-epoch merge | pass |
| Cross-chain replay | pass: `types: bad signature` |
| `claim` on non-devnet chains | refused: S-3 |

Not exercised: the cross-epoch bound of at most 4 unbond records, and the refusal of an out-of-seat restart for a post-genesis key (B-2).

### M6 wallet, faucet, explorer (`b10-wallet-`)

| Check | Result |
|---|---|
| Unit tests for `internal/rpc` and `cmd/b10coin` | pass |
| Walkthrough by hand: keygen, claim, balance, history, send both ways | pass. The verifier re-ran it with correct exit-code capture: refusals exit 1. |
| Wallet verbs against the 10-validator chain | balance and history pass. Claim is refused as devnet-only (S-3), so send could not be shown succeeding there. |
| Faucet and explorer pages: content, CSP, nosniff, no-store | pass |
| HTML escaping of node-supplied and user-supplied content | pass |
| Bounded window past height 2000 | pass |
| Trust boundaries: fee ceiling, redirect, foreign chain, key-shaped input | pass |
| 20 parallel balance/history/explorer requests | pass. The 503s come from the 4-slot semaphore, as designed. |
| Negative inputs: addresses, amounts, key files, permissions, URLs | pass |

Gaps: the 230-claim truncation test ran on the devnet, not on the 10-node chain, and no successful send was shown on the 10-node chain.

## Harness notes

These are bugs in the test scripts, not in the product.
- The suite agent's `step()` helper recorded grep's exit code for piped steps.
- The wallet agent's `run()` echoed `rc=$?` after a `$(ts)` substitution had already reset it.

The verifiers re-checked every affected result against its output lines or with correct exit-code capture. None was a false pass.

## Suggested next steps

1. **N-1 (high):** diagnose the relay starvation when several nodes catch up at once. First step: reproduce with relay queue and drop counters per frame type, so we can see whether BLOCK_SYNC frames crowd out votes.
2. **S-1, S-2, S-3:** decide between product and docs.
   - **S-1:** make a halt with quorum unreachable visible in the logs, and correct the README's "N ≥ 7" claim for capped seats.
   - **S-2:** document that transactions are not gossiped, or add tx gossip.
   - **S-3:** let `claim` follow the node's genesis, or correct the README and the faucet page.
3. **Lows:**
   - **N-2:** make the relay refusal message name the per-prefix cap.
   - **N-3:** raise the stall-line threshold in seconds, not rounds.
   - **N-4:** fix the peer-list seat labels.
   - **W-2:** fix the usage text.
   - **T-1:** make the devnet test waits proportional to load, or longer in CI.
