# Test run report: M5 branch, Docker-only (2026-10-30)

> **Correction, 2026-10-31.** This is a snapshot of `9ea1cb8`; its status rows
> are left exactly as written. Three rows were fixed later on `m5-plan`: **M-1**
> by `88e70a8` (default the reconnect ceiling), **M-3** by `b531c08` (correct
> the four-seat displacement text), and **L-3** by `f566f79` (correct the CI
> timeout and its comment). Read those rows as history, not as the branch's
> current state.

| | |
|---|---|
| Branch / commit | `m5-plan` @ `9ea1cb8` ("audit 2026-10-30"), version `0.1.0` |
| Host | Windows 11, Docker Desktop 29.9.2, 16 CPUs |
| Toolchain | `golang:1.27.3-bookworm` (go1.27.3 linux/amd64, `GOTOOLCHAIN=local`) |
| Other images | `koalaman/shellcheck-alpine:v0.10.0`, `debian:bookworm-slim` (runtime image for nodes) |
| Method | Repo mounted read-only into containers and built from a copy (authoritative runs use an LF clone of HEAD). Five areas ran in parallel. An independent verifier then re-checked each area's evidence and re-ran its most load-bearing checks. |

## Verdict

**The build, the test suite, lint, the documented acceptance commands and the release pipeline are all green. The live multi-container network was not.** Two liveness defects reproduced across independent chains: a validator that falls behind never catches up, and a relay-only 3-seat chain can halt for good after one validator restarts. Neither the unit tests nor the in-process `devnet` acceptance runs catch either one. Both show up only with real nodes in separate processes.

**Update, same day:** H-1 and H-2 had one root cause, and it is fixed in `235d33e` on `m5-plan`. See [Follow-up](#follow-up-h-1-and-h-2-root-cause-and-fix). M-1, M-2, M-3 and the low findings are still open.

| Area | Result |
|---|---|
| Test suite (vet, test, race, build, 6-target cross build + vet) | PASS |
| Acceptance commands + release build | PASS (the release scripts fail from a CRLF Windows checkout, see L-1) |
| Lint gate (gofmt, mod tidy, shellcheck, staticcheck, govulncheck) | PASS |
| Multi-container network (relay, faults, peer exchange) | FAIL (H-2, M-1, M-2); H-2 since fixed |
| Staking end-to-end on live nodes | PARTIAL (the verbs work; H-1 and M-3 found); H-1 since fixed |

## Findings

### High

**H-1. A validator that falls behind never catches up, with or without staking.** *Fixed in `235d33e`.* Reproduced on three separate chains. On a fresh 4-seat `simnet-4` chain with no staking and no intervention, seat `w2` froze at height 278 within about 30 s while its peers went on to 1171. It stayed at 278 after `docker restart`: its log prints `listening ... (height 278)` and nothing more. A seat displaced by a stake (chain V) froze at 1001 and another (chain B) at 1999, and neither recovered. The README says a lagging validator "still catches up through BLOCK_SYNC". That never happened in this run. The defect also hurts liveness: on chain W, one silently frozen seat plus one stopped seat halted the whole chain at height 389. Root cause: see Follow-up.

**H-2. A relay-only 3-validator chain can halt permanently after one validator is stopped and restarted.** *Same root cause as H-1; fixed in `235d33e`.* This happened in 4 of 9 stop/restart cycles across two independent networks. In those cycles the survivors froze, which is correct because 2 of 3 is below quorum. After the restart, all three stayed at the same height for 1.5 to 11+ minutes, even though the relay showed 3 connections and kept forwarding frames. The other 5 cycles recovered within about 20 s. One control trial on a peer-exchange mesh recovered, but a single trial cannot show the problem is specific to relay-only setups. Confirmed afterwards as the same root cause as H-1. Impact before the fix: every Pi reboot in the 3-seat deployment recipe risks a halt that the README gives no recovery procedure for.

### Medium

**M-1. Reconnect backoff is stuck at 100 ms. The 30 s ceiling is never applied.** In `internal/transport/tcp/tcp.go:347-353`, the options normaliser sets a default for `BackoffBase` but not for `BackoffMax`. When the options are zero-valued, as `devnet/tcpnode.go` passes them, `BackoffMax` is raised to the base value, so every redial waits 50 to 100 ms. `DefaultBackoffMax` (`tcp.go:129`) is referenced nowhere outside its declaration. Observed: a node holding a wrong token redialled the gated relay 792 times in 60 s, with no growth in the gaps between attempts. This contradicts the comment at `tcp.go:125-127` ("never a busy redial loop against a dead address") and the README's "reconnects with backoff". It affects every outbound maintainer, both peers and relays. (Code path checked during this report.)

**M-2. `PEER_EXCHANGE` cannot turn a `--peers` chain into a mesh in any of the configurations tested.** 4 validators wired as a chain (`m1->m0`, `m2->m1`, `m3->m2`) with no relay stalled at height 0 in all three variants tested:
- With `0.0.0.0` listeners, nodes advertise nothing. This is documented.
- With private-range listeners, peer hints are refused (`errHintLocal`, `peerexchange.go:97`). `AllowLocalPeerHints` has no CLI flag.
- With public-range listeners, hints were exchanged only between direct neighbours, so no mesh formed.

What does work: listeners learned through the relay form a full mesh, and that mesh keeps finalising after the relay is killed (acceptance `PASS` without `--relay`).

**M-3. The README's displacement warning is right for 3 seats but wrong for 4 or more.** On a 3-seat chain, a `MIN_STAKE` bond that takes a power-1 seat with no node behind it stalls the chain at the boundary (999), as documented. On 4-seat chains (two runs) the chain keeps committing on 3 of 4 power, and only the displaced seat's node freezes (see H-1). The README says the chain stops.

### Low

- **L-1. Shell scripts break on a Windows checkout.** The repo has no `.gitattributes`. With Git for Windows' `core.autocrlf=true`, `build-release.sh`, `deploy/build.sh` and `acceptance.sh` get `\r` shebangs and fail in Linux with exit 127. A copy of that working tree also makes `gofmt -l` flag nearly every file. The committed blobs are LF, so CI is unaffected. Fix: add `*.sh text eol=lf`, or `* text=auto eol=lf`.
- **L-2. `acceptance.sh` refuses fewer than 3 `--pis` (exit 64).** So "the two survivors are STALLED" cannot be judged directly. Its de-duplication also compares raw strings, so `host` and `host:8645` count as two validators.
- **L-3. The CI comment calls `internal/devnet`'s healthy pass "~24 s".** It measured 104 s alone, 177 s in the full suite and 201 s under race. The 40 m timeout is still far away.
- **L-4. `/tx` admits a transaction from an unfunded account with a future nonce (HTTP 200).** This is consistent with README O-7 (held, not applied). Noted only.

### Info

- `govulncheck` reports one module-level advisory that the code never calls: GO-2026-5932, `x/crypto/openpgp`, no fix available. The gate passes.
- shellcheck reports 5 notes at default severity (SC2086 x2 and SC2012 in `build-release.sh`; SC2001 x2 in `check-strays.sh`) and nothing at warning level or above.
- The staticcheck pin `GOTOOLCHAIN=go1.26.9` is necessary: under go1.27.3, staticcheck v0.8.1 fails with "export data version 5". This matches the CI comment.
- On committee-file chains the devnet fixture account is not funded, as the README scopes it. So the staking end-to-end ran on the fixture committee (`--validators N`) for the funded path, and on a committee-file chain for the genesis-bond path.
- `TestScenarioHappyPath` is the only test over 60 s: 195 s in the full suite and about 100 s alone. It passed every time it ran.

## Results by area

### 1. Test suite: PASS

| Check | Result | Time |
|---|---|---|
| `go vet ./...` | rc 0 | 32 s |
| `go test -timeout 40m -count=1 -v ./...` | 22/22 packages ok; 962 RUN / 962 PASS / 0 FAIL / 0 SKIP | 271 s |
| `go test -race -timeout 40m -count=1 ./...` | 22/22 ok, no DATA RACE | 418 s |
| `go build ./...` | rc 0 | 1 s |
| build + vet for darwin, linux and windows on amd64 and arm64 | all 6 targets rc 0 | about 2 to 32 s each |

Slowest packages: simnet 255 s (314 s under race), devnet 177 s, consensus 115 s, store 101 s.

### 2. Acceptance commands and release: PASS

| Command | Result |
|---|---|
| `devnet --blocks 100` | height 102, root `3c1dae9c...e93d`, OK. Byte-identical to the README across 5 runs in 3 containers |
| `devnet --blocks 100 --claims 1` | identical output, OK |
| `devnet --validators 4 --blocks 100` | v0-v3 = 100, agreed yes, OK |
| `devnet --validators 6 --epoch-blocks 40 --blocks 105 --rotate-demo --plot-nakamoto` | Nakamoto table byte-identical to the README (6 seats, k=3, then 5 seats, k=2 from height 40), OK |
| Flag refusals (`--claims` + `--validators`, `--rotate-demo` / `--plot-nakamoto` without `--validators`, `--rotate-demo` with 4 validators) | all refused, rc 1 |
| No subcommand / unknown subcommand | usage text, rc 2 |
| `b10coin version` | `0.1.0`, matches `internal/version` |
| `scripts/build-release.sh` (LF clone) | 12 artifacts, `sha256sum -c` 12/12 OK, `file(1)` matches every target, BUILD-INFO present, unsigned |
| Release reproducibility | Two builds produced identical SHA256SUMS. The second build used a warm cache; a cold-cache cross-check matched 2 of 12 artifacts |
| `scripts/deploy/build.sh linux/amd64` | OK, `bin/SHA256SUMS` matches the release hashes |

Not exercised: release signing (no minisign key available).

### 3. Lint gate: PASS

`gofmt -l cmd internal` printed nothing. `go mod tidy` left no diff. `shellcheck --severity=warning` over all 6 tracked scripts was clean. staticcheck 2026.2.1 under go1.26.9 found nothing. `govulncheck` v1.8.0: "Your code is affected by 0 vulnerabilities". `check-strays.sh` OK. `check-plan.sh` reported fence parity OK on all 5 plans; its brief-extraction half was skipped because it needs external SDD tooling.

### 4. Multi-container network: FAIL

Setup: static linux/amd64 binaries in a `debian:bookworm-slim` image, one relay with an access token, three validators with `keygen` keys and a committee file, all on a Docker bridge network. Measured cadence is 21 to 23 blocks/s on a quiet host and 8.5 blocks/s under load.

| Scenario | Result |
|---|---|
| `keygen` x3 (0600, refuses to overwrite) | pass |
| Healthy network, `acceptance.sh --mode http` | **PASS** exit 0, one block hash at height 1390 on all 3 |
| Stop 1 of 3 validators | the survivors freeze, STALLED exit 2 (correct) |
| Restart it | **FAIL**: 4 of 9 cycles halted permanently (H-2) |
| Stop the relay | STALLED exit 2, and the harness names the relay as unreachable (correct) |
| Restart the relay | reconnect, PASS (fast because of M-1, not because of backoff) |
| Key not in committee | refuses to start, rc 1 |
| Key file mode 0644 | refused, rc 1 |
| Token sent to an ungated relay | token NOT sent (a packet capture saw 0 bytes), refusal logged |
| Wrong token | relay refuses, node logs it, then redials about 13 times per second (M-1) |
| 8-byte token | refused at startup |
| Chain `--peers` topology with no relay (3 variants) | **FAIL**: stalled at height 0 (M-2) |
| Peer exchange learned via the relay, then the relay killed | **PASS** without `--relay`; full mesh keeps finalising |

### 5. Staking end-to-end: PARTIAL

Run against real node containers using the fixture key (written by a throwaway helper inside the container copy, as the README describes; nothing was added to the repo).

| Step | Result |
|---|---|
| `stake --amount 1000` | Bond included. Balance down by 10^11 + 1 spark fee, bonded 10^11, nonce 1 |
| Refusals: below `MIN_STAKE`, more than the balance (by 2 sparks), unstake more than bonded, withdraw before maturity (names the release height and blocks to go), unfunded key | all refused before submission with the documented messages, rc 1 |
| `unstake` | fee 0. Release height = applied height + 2 x 1000 (2398 -> 4398). Coins are neither spendable nor bonded |
| `withdraw` at maturity | fee 0, balance restored. A second withdraw is refused |
| Genesis-bond seat top-up below the floor | accepted when the resulting bond is at least `MIN_STAKE` |
| Bond signed for another chain's genesis hash | `types: bad signature`, HTTP 400. A replay is refused on nonce |
| Bond displacing a power-1 seat | 3 seats: the chain stops at 999 (README correct). 4 seats: the chain continues (M-3) |
| First Bond submitted at height 7 on one chain | not included for more than 1200 blocks. **Not reproduced**: the identical tx on a fresh chain was included within 15 blocks. Possibly H-1 interference. Unconfirmed |

## Follow-up: H-1 and H-2 root cause and fix

**Root cause.** `tallestPeer` (`internal/devnet/tcpnode.go`) caps how far it trusts a peer's announced height. The cap was measured from zero, not from our own head:

- For a member never pulled from, the cap was one window, height **64**.
- For a member pulled from earlier, the cap was `substantiated + 64`, where `substantiated` is the highest height a pull from it reached.

Once a validator's head passed that cap, every peer looked no taller than itself. `maybeCatchUp` then returned without sending a request, so nothing was ever pulled and no peer was ever proven, and nothing was logged. The peer table lives in memory, so after a restart every peer counted as never pulled from, which is why restarting never helped. Every catch-up test ran below height 64. The cap was introduced in `0ada8bb` (2026-10-05).

H-2 is the same bug. When the stopped node had already precommitted height *h* but had not appended it, it restarted one block behind. It could not pull that one block, and the other two could not reach quorum without it. Whether the node got the last block written before stopping is what made H-2 happen only some of the time.

**Fix (`235d33e`).** A member's trusted height is now capped at one window above the higher of our head and `substantiated`. A member announcing a height it cannot serve is still capped, picked, demoted and rotated away from, as `TestALyingHeightIsRotatedAwayFrom` still checks. The field `proven` was only ever written after the change, so it was removed. `TestALaggingValidatorAboveOneWindowStillPulls` pins the fix: it fails on the old code (`head 100, member announces 150: pulls []`).

**Verification.**

| Check | Before | After |
|---|---|---|
| New unit test | FAIL | PASS |
| 4-node direct mesh, stop the victim for 20 s, restart (2 cycles) | victim stuck at 1298 while peers passed 2900 | victim caught up within one 10 s sample, both cycles |
| 3-node relay, stop the victim for 15 s, restart (4 cycles) | cycle 3: victim restarted at 3137, peers at 3138. All three frozen for both remaining cycles | recovered in 4 of 4 cycles, chain reached 5023 |
| gofmt, vet, staticcheck, `go test ./...` (22/22), acceptance runs | - | all pass on the rebased `235d33e` |
| `go test -race ./...` | - | 22/22 pass before the rebase onto upstream `063cc60..34e6d86`; not re-run after the rebase |

The rest of this report describes `9ea1cb8`. Upstream commits `063cc60`, `4972883` and `34e6d86`, which landed after the run, change staking, peer exchange and the transport. Only the gates above have been re-run against them. M-1 (backoff) and M-3 (displacement on a committee of 4) may be affected and should be re-checked.

## Evidence

Raw logs, scripts and verifier re-runs were written to the session scratchpad, which is temporary. Copy it if you want to keep it:
`C:\Users\catalin.istratoiu\AppData\Local\Temp\claude\C--Users-catalin-istratoiu-git-b10coincom\3109c60d-490a-4140-8cdf-217df2607ac0\scratchpad\testrun\` (subfolders `suite`, `acceptance`, `lint`, `network`, `network-verify`, `staking`, and `diag` for the follow-up).

All `b10-*` containers, networks and volumes created by the run were removed. The Go cache volumes `b10-gomod` and `b10-gocache` were kept. During the run itself the host repository was not modified; the only repository changes are the follow-up fix and this report.
