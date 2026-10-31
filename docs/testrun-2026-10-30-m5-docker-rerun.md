# Test run report: M5 branch, Docker-only re-run (2026-10-30)

> **Correction, 2026-10-31.** This is a snapshot of `dcd2ede`; its status rows
> are left exactly as written. Three rows were fixed later on `m5-plan`: **M-1**
> by `88e70a8` (default the reconnect ceiling), **M-3** by `b531c08` (correct
> the four-seat displacement text), and **L-3** by `f566f79` (correct the CI
> timeout and its comment). Read those rows as history, not as the branch's
> current state.

**Commit under test:** `dcd2ede` on `m5-plan` (it contains the H-1/H-2 fix `235d33e` and the upstream staking commits `063cc60`, `4972883` and `34e6d86`)
**Previous run:** [testrun-2026-10-30-m5-docker.md](testrun-2026-10-30-m5-docker.md), on `9ea1cb8`
**Environment:** Windows 11, Docker Desktop 29.9.2. Every check ran in containers: `golang:1.27.3-bookworm` (go1.27.3 linux/amd64), `koalaman/shellcheck-alpine:v0.10.0`, and a `debian:bookworm-slim` runtime image built from statically linked binaries. Each container cloned the repo from a read-only mount, so it worked from LF sources. Keys and committee files lived in named volumes.
**Method:** five test areas ran in parallel. An independent verifier then checked each area against its logs and re-ran anything that was doubtful or missing. Everything below is the verified result. Because the areas shared one host, wall-clock timings are inflated and noisy.

## Summary

| Area | Result | Notes |
|---|---|---|
| Test suite | **partial** | 1016/1016 pass without race. The race suite failed once on a timing-flaky relay test, then passed 22/22 on re-run. 0 data races. |
| Acceptance + release | **pass** | Deterministic state root `98e5cf46…`. 12/12 release artefacts reproducible from a warm and a cold build cache. |
| Lint | **pass** | gofmt, tidy, shellcheck, staticcheck (with the toolchain pin) and govulncheck are clean. |
| Multi-container network | **partial** | **H-1 and H-2 are fixed on live nodes.** M-1 is still open. The M-2 re-check was not run. |
| Staking end to end | **partial** | All verbs and the new ST-1/ST-3/ST-4 rules behave as documented. M-3 is still open. A rolling-restart stall was found; it is consensus behaviour, not specific to staking. |

> **Update:** upstream commits that landed while this run was in progress address several of the open items below. None of them were tested in this run:
> `88e70a8` (M-1: default the reconnect ceiling; `internal/transport/tcp` passes in Docker at `9d4e750`, including `TestDefaultOptionsBackOffGrows`), `4d1b7dd` (M-2: expose the local peer-hint exception), `b531c08` (M-3 doc), `40c43bc` (L-2), `f566f79` (L-1 line endings, L-3 CI comment).

## Status of the findings from the previous report

| ID | Previous finding | Status at `dcd2ede` | Evidence |
|---|---|---|---|
| H-1 | A validator more than 64 blocks behind never catches up | **Fixed** | Regression test 8/8 pass. Live 4-node chain: the victim restarted 260 and then about 300 blocks behind, and was level with its peers within 10 to 12 s both times. |
| H-2 | Relay-only 3-validator chain halts after stop/restart | **Fixed** | 8 cycles (6 `docker stop`, 2 `docker kill`), rotating the victim: 0 halts, acceptance PASS in 7 of them. Cycle 6 reproduced the exact pre-fix trigger (victim at 7370, peers at 7371) and recovered. |
| M-1 | Reconnect backoff pinned at ~100 ms | **Open** | `internal/transport/tcp/tcp.go:347-354` still never defaults `BackoffMax` to `DefaultBackoffMax`. A wrong-token node redialled 566 to 691 times per minute (mean gap 79 to 87 ms) with no growth. |
| M-2 | A `--peers` chain doesn't form a mesh | **Not re-tested** | Neither run agent nor verifier got to it. The "private-subnet hints are refused by design" reading (`errHintLocal`, no CLI flag for `AllowLocalPeerHints`) comes from the code only. |
| M-3 | Deploy README says an unbacked spare seat halts the chain | **Open (doc)** | `scripts/deploy/README.md:534-535` still says the chain halts. `internal/state/stake.go:580-595` caps every seat at 1/4 once there are 4 or more seats, so 3 live seats keep quorum. The live chain kept committing across boundaries 4000 and 7000. The halt is real only below 4 seats (observed: frozen at 999). |
| L-1 | No `.gitattributes`, so CRLF working trees break scripts | **Open** | The committed blobs are LF. A copy of a Windows working tree still breaks in Linux. Not re-tested, because every build used a clone. |
| L-2 | `acceptance.sh` refuses 2 validators and dedupes on raw strings | **Open** | Unchanged: `--pis` with 2 names gives exit 64, and `v0,v1,v0:8645` is accepted as 3 validators. |
| L-3 | The devnet duration in the CI comment (~24 s) is stale | **Open** | `internal/devnet` took 189 s alone, 117 s in the full suite and 166 to 472 s under race. The comment is at `.github/workflows/ci.yml:56`. |
| L-4 | `/tx` admits an unfunded account's future-nonce tx (HTTP 200) | Not re-tested | Consistent with README O-7; noted only. |

## New findings

| Sev | Finding | Detail |
|---|---|---|
| Medium | **Rolling restart stalls the chain for minutes, silently** | Restarting the seated validators one by one with 15 s outages left a 4-seat chain (one seat without a node) at the same head for more than 4 to 6.5 min. It recovered only after all nodes were restarted together, and it happened again (more than 3 min at 5774). The verifier reproduced the mechanism without staking: recovery took 17 to 63 s on 3-of-3 and 32 to 48 s on 4 seats with one nodeless. The size grows with the length of the halt. This matches the linear round-timeout trade-off documented in `internal/consensus/driver.go:600-614`. The gaps: it is easy to trigger with an ordinary rolling restart, node logs say nothing, and neither README mentions it. |
| Medium | **Flaky test: `TestRelayAKeepaliveSinkCannotPinASlotOrMemory`** | It failed once in `go test -race ./...` (565 s run on a heavily loaded host), at `relay_test.go:1438`: the `Dropped > 0` wait hit `waitFor`'s hard-coded 10 s deadline. It then passed the full race re-run and 71 isolated runs. Not a product defect, but CI on a slow runner can go red. A deadline that scales with load, or a longer one, would fix it. |
| Low | **4-seat committee with a seat missing is slow to start** | With `--validators 4` and seat 3 never started (no staking), two chains sat at height 0 for 1.6 to 3 min, logging nothing. A 3-of-3 chain started the same way reached height 40 within 20 s. Once running, the 4-seat chain produced blocks at about 1/3 of the 3-of-3 rate. This is relevant to the deploy recipe (3 keys, `committee_size 4`). |
| Low | **README says CI runs four acceptance commands; it runs three** | `README.md:1160` against `.github/workflows/ci.yml:69-71`. The M5 rotation command isn't in CI (same as audit CI-3). The command passes when run by hand. |
| Low | **README `devnet` flag table omits the M5 flags** | `--epoch-blocks`, `--rotate-demo` and `--plot-nakamoto` are in the usage text and in the README's own acceptance command, but not in the table at `README.md:243-246`. |
| Low | **Misleading stake refusal hint** | Refusing a stake for a 2-spark fee shortfall adds "no shipped genesis gives an operator's key MIN_STAKE in spendable funds…", even though the account held about 1000× MIN_STAKE. Cosmetic. |

## Area detail

### Test suite
- `go vet`, `go build` and the 6-target cross build and vet (darwin, linux and windows, each on amd64 and arm64) all pass.
- `go test -count=1 -v ./...`: 22/22 packages, 1016 RUN / 1016 PASS / 0 FAIL / 0 SKIP, including 262 subtests. The previous run had 962. Only `TestScenarioHappyPath` took over 60 s (122 s).
- `go test -race ./...`: the first run gave rc=1 (the flaky relay test above) with 0 data races. The verifier's re-run gave 22/22 ok in 254 s.
- The H-1 regression test `TestALaggingValidatorAboveOneWindowStillPulls` passed 8/8 runs, at 0.95 to 2.1 s each.

### Acceptance and release
- `devnet --blocks 100` printed state root `98e5cf468ecf…cdd11cc` in 6 runs across 3 containers, and its stdout matches `README.md` exactly. The root changed from `3c1dae9c…` because of audit ST-3 (`34e6d86`), as `README.md:77` says. The previous report's `3c1dae9c…` was correct for `9ea1cb8`.
- The `--claims 1`, `--validators 4` and M5 rotation commands (`--validators 6 --epoch-blocks 40 --blocks 105 --rotate-demo --plot-nakamoto`) all pass, with output matching the README exactly. All 4 flag-combination refusals, the no-subcommand and unknown-subcommand cases, and `version` (0.1.0) behave as documented.
- Release: 12 artefacts for 6 targets, all 12 pass `sha256sum -c`, and `file(1)` matches all 12. A second build through `make` and a cold-GOCACHE build in a separate container produced byte-identical `SHA256SUMS`. The module cache was shared between them. The deploy build for linux/amd64 produced the same hashes as the release.

### Lint
- gofmt: 0 files. `go mod tidy`: no diff. shellcheck `--severity=warning` over all 6 tracked scripts: clean. At default severity it gives the same 5 notes as before: SC2086 ×2 and SC2012 in `build-release.sh`, SC2001 ×2 in `check-strays.sh`.
- staticcheck v0.8.1 with `GOTOOLCHAIN=go1.26.9` passes with no findings. Without the pin it still fails on export data v5, so the pin in CI is still needed.
- govulncheck: the code is affected by 0 vulnerabilities. GO-2026-5932 (x/crypto openpgp, no fix available) is required but never called; unchanged.
- `check-plan.sh`: the parity check passes on all 5 plans. Brief extraction was skipped because the external SDD scripts aren't in the image (an environment gap).

### Multi-container network
- Keygen writes keys with mode 0600 and refuses to overwrite. A committee file with power 1 is now refused (below MIN_STAKE). A key not in the committee refuses to start. The token is never sent to a relay that doesn't announce the gate. A wrong token makes the relay refuse the connection, and the node logs it.
- Healthy 3-validator relay chain: `acceptance.sh --mode http` gives PASS. Throughput was 15 to 25 blocks/s (not paced by block time, which the README documents).
- Stopping 1 of 3 validators: the chain STALLs and acceptance exits 2. After a restart it passes. Stopping the relay: STALLED, with the relay named as unreachable. After the relay restarts, the chain recovers in 28 to 41 s.
- The H-1 and H-2 re-checks are in the status table above. The run agent's own H-2 log claimed 2 cycles. In fact its cleanup removed the image during cycle 2, so the verifier's 8-cycle run is the evidence used here.

### Staking end to end
- Chains: F, the fixture chain with `--validators 4` and a funded fixture account; G, a committee-file chain whose operator account holds balance 0; T, a 3-seat chain used for the displacement check.
- Bond: `stake --amount 1000` moved exactly 10¹¹ plus a 1-spark fee from the balance into the bond. Refusals checked before submission: unstaking more than is bonded, leaving a remainder below MIN_STAKE (ST-1), and a short fee.
- Unbond and withdraw: the release height is rounded up to the epoch boundary (9000). Withdrawing early is refused with the remaining block count. Withdrawing at maturity restores the balance exactly. A second withdraw is refused.
- ST-3: unstaking a genesis bond releases nothing and creates no record. Withdraw and a second unstake are both refused.
- ST-4: unbonding records stay bounded (at most 4 observed) and the amounts are conserved.
- Committee-file loader: refuses power below MIN_STAKE and `committee_size` below the number of validators.
- Cross-chain signatures: a transaction signed for another chain is rejected with `bad signature` (HTTP 400). Replaying a nonce is rejected.
- A seat that bonds without running a node: with 4 or more seats it is capped to an equal share, and the chain stays live (M-3). With 3 seats it freezes the chain (height 999), as the README warns.

## Recommended next steps
1. **M-1:** default `BackoffMax` to `DefaultBackoffMax` in the TCP transport's option normaliser. It is a one-line fix plus a test.
2. **Rolling-restart stall:** log the round and timeout escalation at INFO, and document the restart procedure (restart all nodes together, or wait between restarts) in the deploy README.
3. **Flaky relay test:** make the `waitFor` deadline scale, or raise it for the `-race` build.
4. **M-3 doc fix:** correct `scripts/deploy/README.md:534-535` so it describes degraded liveness, not a halt, for 4 or more seats.
5. **M-2:** do a dedicated Docker re-run of the 4-validator `--peers` mesh with no relay.
6. Doc items: README CI command count, the devnet flag table, and the L-3 CI comment.

Raw logs from this run stayed on the test host and are not committed.

## Network re-run at `6d54215` (after the upstream fixes)

The network area was run again on its own at `6d54215`, which includes `88e70a8`, `4d1b7dd`, `40c43bc` and `f566f79`. As before, an independent verifier checked the results against the logs and re-ran the doubtful steps. **Overall result: fail.** Two liveness problems remain, described below. Everything else passed.

| Item | Result | Evidence |
|---|---|---|
| M-1 reconnect backoff | **Fixed** | A node with the wrong token was refused 14 times in 125 s (previously about 690 per minute). The gaps grew 0.07 → 0.18 → 0.28 → 0.69 → 1.2 → 1.8 → 6.4 → 8.4 s, then stayed at 15–23 s, below the 30 s cap. After a 64 s relay outage the chain resumed about 20 s after the relay came back. |
| M-2 `--peers` topologies | **Matches the README now** | Chain without `--allow-local-peer-hints`: stuck at height 0. The same chain with the flag: still stuck at 0, with the same 3 links, as the README now states. Star with the flag: stuck at 0 (no leaf-to-leaf link). Full `--peers` mesh with the flag: acceptance PASS. The no-progress windows observed were about 36–38 s, not the 90 s claimed. |
| L-2 acceptance harness | **Fixed** | 2 survivors give "PARTIAL reading" with STALLED exit 2. `v0,v0:8645` is refused as one validator, exit 64. |
| H-1 catch-up | **Fixed** (confirmed again) | On a 4-seat chain, a validator 250–260 blocks behind caught up in 11–14 s, twice. |
| Relay down/up, foreign key, ungated relay, wrong token | Pass | Same behaviour as the previous run. |
| Rolling restart, 3 seats | Pass | Recovered within 4–23 s of the last start. Restarting all together recovered within 8 s. |
| **Rolling restart, 4 seats with 3 live** | **Fail, reproducible** | The chain froze for more than 9 min (first run) and more than 6 min (verifier, fresh chain). Node logs show only the startup banner. Starting the 4th seat recovered it in about 1 min, and so did restarting all four. This is the shape `internal/consensus/driver.go` describes as one the jump rule cannot close. |
| **Stop/restart cycles, 3 seats (H-2 procedure)** | **Fail, intermittent** | 3 of 12 cycles froze all three validators at the same head, once for more than 6.7 min. Each time the victim restarted *at* the survivors' height, not one block behind as in the H-2 trigger. Each stall cleared only after another node was restarted. The verifier ran 18 cycles of the same procedure on a fresh chain and saw no stalls (0/18; at the observed 3/12 stall rate, the chance of that is about 0.6%). |

### What the two failures mean
- **The 3-seat stall is not the catch-up bug that was fixed in `235d33e`.** The victim was already level with the survivors, so the catch-up code had nothing to pull. The likely cause is a consensus *round* that differs between the nodes after the restart. With 3 of 3 signers required, this is the same family as the rolling-restart stall. It only appeared on a chain that had already been through relay outages, a node with a bad token and several restarts, so it seems to depend on the chain's history or on host load. It is not proven: nodes expose no round or step information, so the stall can't be inspected from outside.
- **The 4-seat rolling-restart stall is deterministic and undocumented.** `scripts/deploy/README.md` §6 tells operators to restart each machine in turn, with no warning that this can freeze a chain that has exactly the quorum's power live.

### Next steps (updated)
1. Log the consensus round and step (and the timeout escalation) at INFO, or expose them on `/status`. Neither stall can be diagnosed without this.
2. Investigate the 3-seat stall, using that visibility, on a long-lived chain with mixed faults.
3. Document the restart procedure in the deploy README: restart all nodes together, or wait for the chain to advance between restarts.
4. Log PEER_EXCHANGE and relay reconnect events. Right now they are visible only through `ss`.

## Follow-up: why a rolling restart stalls a 4-seat chain

This was diagnosed with a debug build in Docker: 4 seats, 3 nodes, a chain warmed to height 1000, then a one-at-a-time restart with 15 s outages.
- A restarted node resumes at **the round it had saved before it stopped**. The rest of the committee kept moving through rounds while it was down, so it comes back behind. In the reproduction, q1 came back at round 20 while q0 was at 26.
- To catch up, it has to jump forward, and the jump rule needs 2 of the 4 seats to be ahead. In a fast rolling restart the next node is already stopping, so only one node is ahead, and the gap stays. After all three were back the nodes sat at rounds 33, 28 and 27, and each round's tally held only the node's own vote. Only the timeout ladder could close the gap, and it shrank from 5–6 rounds to 2 over 4 minutes.
- Ruled out, with evidence: clock drift (every node's consensus clock ran at 1.0000× wall time); locks losing their evidence on restart (a deterministic simulation recovered within 10 ms, because the original proposer rebuilds the identical block); and the pure engine logic (an in-process rolling restart recovered within 1.6–15 s, because an in-process restart is instant and the node hears both peers before the next one stops).
- Whether a no-wait restart stalls depends on timing: a second trial with the same procedure recovered within seconds.

What changed:
- Upstream's `0ccfce9` and `b213aad` added the stall line and the "restart together" advice.
- This follow-up adds a startup line that names the restored round (`consensus    resuming height H at round R …`) and documents a safe one-at-a-time procedure: wait for the chain to advance after each restart before stopping the next node. Verified in Docker over 3 trials (9 restarts): the chain advanced 6–33 s after every restart and never stalled afterwards.

Stall line false positives, fixed afterwards:
- Startup: the line fires at height 0 on a fresh chain. On inspection this is **not** a false positive. Containers started a few seconds apart sat at height 0 for 13–43 s in all 4 trials, with diverged rounds: the same mechanism, and the slow start the verifier reported. It stays reported.
- The restart burst **was** a false positive. A node that climbed rounds while it could not reach a quorum reported a stall the moment a peer came back, because the round number was already past 8. Its `peers=` even listed the node that had just been stopped, which still counted until its HELLO expired. Now only rounds spent with a reachable quorum count: a height first seen below round 8 is counted from round 0, and any round without a reachable quorum disarms the count until it returns. Two new tests pin this, and both fail on the old code. A Docker no-wait rolling restart that recovered in seconds now logs no stall lines, down from 2–3 per restart before.

## Follow-up: the 3-seat stall, root cause and fix

This was captured twice in Docker with a debug build, on two 3-seat relay chains running repeated 15 s stop/restart cycles. The plain chain stalled in cycle 10 (`docker stop`); the chain with a history of outages and restarts stalled in cycle 8 (`docker kill`).
- **The stop lands in the lock window.** All three nodes prevote block B, the two survivors lock on B (keeping its bytes and its polka in memory), and the victim stops before its precommit gets out. In the first capture the victim was unlocked; in the second it was locked on B by ID only, with the bytes and votes lost.
- **The restarted victim never sees a proposal.** It joins every round by a timeout jump, so it always enters a round after the survivors. Each round's proposal is broadcast once, when its proposer enters the round, so it reached the victim while it was still in the previous round. `onProposal` dropped every proposal not for the current round (`foreignprop=20` in both captures).
- **So nothing could commit.** The survivors' re-proposals of B never reached the victim, and the victim's own fresh proposals were refused by the survivors' lock. A 3-of-3 committee then has no round with three prevotes, until the victim is restarted again and lands with different timing.

**Fix (`5af2174`, `internal/consensus/engine.go`):** a proposal for a round ahead of the engine's own is now kept until the engine enters that round. It must be inside the existing 4-round window, and it is checked on arrival: the header's height, the signer against the drawn proposer of the round it names, then the signature. Only the first per round is kept, and duplicates are dropped before any signature check. `enterRound` adopts the kept proposal and judges it there: justification, block validation and the lock all apply in that round, before the buffered votes are counted, so a buffered polka locks with the block's bytes. `committedBlock` can also serve the bytes of a kept proposal to a commit that lands in a round ahead of the engine. Kept proposals are pruned with the round's tallies, so at most 8 are held. A new `EarlyProposals` diagnostic counter tracks them.

**Verification:**
- 10 new engine tests, including the exact restored-lock capture; the three behaviour tests fail without the fix.
- An adversarial review from three angles (safety, liveness and DoS, test adequacy) found no correctness issue. Its 4 surviving mutants are now killed by added tests, and its low items (dropping duplicates before verify, the diagnostic counter, the bound comment) are applied.
- The full suite passes from a clean clone of `5af2174`, and so do the race runs.
- Docker: **0 stalls in 50 cycles** across two chains (12 of them `docker kill`), against 2 in 18 cycles before the fix on the same procedure (3 in 12 in the original run).
