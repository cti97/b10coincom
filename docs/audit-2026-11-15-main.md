# b10coin security audit — main @ M7/M8 (bounded history + rotation-aware checkpoints)

| | |
|---|---|
| Date | 2026-11-15 |
| Commit | `73f3544` (origin/main, merge of PR #31) |
| Scope | the M7 (bounded history: pruning, cert segments, retention) and M8 (rotation-aware checkpoints, trust downgrade) work merged since the last main audit (`6f34e6c`): ~5,600 lines across `internal/{chain,consensus,store,retention,state}` and `cmd/b10coin` |
| Method | three focused code reviews (M8 trust, M7 pruning safety, M7/M8 regressions) run in parallel, then **every** High-candidate and the one Low re-verified by hand against the cited symbol; spec read in full (`plan-2026-11-15-m7-bounded-history.md`, `plan-2026-11-15-m8-rotation-checkpoints.md`); mandated security tests confirmed present. No code changed. |
| Citation rule | every claim cites a **symbol** (function/type/const/flag), never a line number, and each was re-read against the code as written. |

## Headline

**No Critical, High, or Medium findings.** The M7/M8 work is the strongest-tested and most carefully reasoned milestone in this series. The two properties that could have been safety breaks — pruning the double-vote records, and a checkpoint that authenticates itself — are both closed by construction, and each has a test that is the security argument in executable form. One **Low** (a degraded-until-restart window on a rare I/O error path) and three **Informational** notes follow.

The central M8 claim holds on my own read, not merely the reviewer's: **a checkpoint is a trust anchor, not a consensus key.** A fresh node trusts only the genesis committee by default; a rotated or fabricated self-consistent checkpoint is *refused* unless the operator passes `--checkpoint-trust`, and even then only within a hard age bound. Self-consistency is not authenticity, and the code refuses to pretend otherwise.

## Findings

| # | Severity | Finding | Status |
|---|---|---|---|
| L-1 | **Low** | `Chain.PruneHistory` leaves in-memory `baseHeight` stale if `PruneCerts` errors after `PruneBlocks` has already advanced the on-disk base, degrading the running process until the next restart. | Verified by hand |
| I-1 | Informational | `certIndex` is guarded by the chain's `c.mu` across the serve-path disk read, not by `indexMu` like the block index (R-2). The two parallel index maps have different locking contracts; a future change could turn `certIndex` into an unguarded concurrent map. | Verified by hand |
| I-2 | Informational | `Store.PruneCerts` can reach an `os.Remove` of the *open* active cert segment — dead code in normal operation, a Windows open-handle hazard if ever reached. | Reviewer-identified |
| I-3 | Informational | Spec §3 names `rounds.log` as "double-vote protection"; in the code the double-vote *safety* record is `locks.log`, and `rounds.log` is liveness (restart position). Both are PERMANENT and untouched by the pruner, so the invariant holds under either reading — but a reviewer checking the literal record could mis-locate the real safety edge. | Verified by hand |

### L-1 (Low) — a `PruneCerts` error leaves the chain half-pruned until restart

In `Chain.PruneHistory` the order is `store.PruneBlocks(upTo)` → `store.PruneCerts(upTo)` → assign `c.baseHeight/baseState/baseHead`. `PruneBlocks` persists the base marker (`blockFirst = upTo+1`) and deletes the sub-horizon block segments; only if `PruneCerts` then *also* succeeds does `c.baseHeight` advance. If `PruneCerts` returns an I/O error, the function returns with the on-disk block base advanced but the in-memory `baseHeight` still at the old (lower) value.

**Failure scenario.** A disk error during `PruneCerts` (segment unlink / recreate) on a validator mid-prune. Afterwards, `StateAt(h)` for `h` in `(oldBase, upTo]` passes its `h < base` guard against the stale in-memory base, then calls `c.store.Read(height)` on a block that `PruneBlocks` already deleted → `ErrNotFound`. So `StateAt`, `BaseSnapshot` and any checkpoint re-export over that range fail for the life of the process.

**Not a safety break.** No bad state is adopted; the pre-staged checkpoint makes the next `OpenResume` recover the correct base; `Validator.maybePrune` only logs the error. It is a degraded running process, self-healing on restart.

**Fix.** Advance `c.baseHeight/baseState/baseHead` immediately after `PruneBlocks` succeeds, and treat a subsequent `PruneCerts` failure as reclaimable surplus (the next pass reclaims it — this is already `PruneCerts`'s own idempotence design). That keeps the in-memory base in step with the on-disk block base on every path.

### I-1 (Informational) — the two index maps have different locking contracts

`Store.PruneCerts` writes `certIndex` under `indexMu`, but the serve path (`Store.CertAt` → `readCertAt`) reads `certIndex` with no `indexMu`; it is race-free today only because `Chain.CertAt` holds `c.mu.RLock()` across the whole call including the disk read, while `Chain.PruneHistory`/`PutCert` hold `c.mu.Lock()`, so the chain RWMutex serializes them. This is deliberate and correct — but it is *asymmetric* with the block index, which (per audit R-2) releases `c.mu.RLock()` before `store.Read` and therefore needs `indexMu` to guard `s.index`. Two consequences worth recording: serving a historical certificate to a lagging peer blocks the commit path for the read's duration (serving a block does not); and a future change that moved `CertAt`'s `RUnlock` ahead of the store read, to match `BlockAt`, would silently turn `certIndex` into an unguarded concurrent map and produce a fatal "concurrent map read and map write". A one-line comment on `certIndex`'s locking contract would prevent that.

### I-2 (Informational) — `PruneCerts` active-segment delete path

`PruneCerts` does not skip the active cert segment the way `PruneBlocks` skips the active block segment (inode compare in `fileIsActiveSegment`); it deletes any segment whose `certSegMax < first`, then recreates the active one via `recreateCertSegmentLocked`. In normal operation the active (highest) segment always holds `cert(head)` whose height ≫ horizon, so its max is never `< first` and the delete/recreate branch is unreachable. If it were reached, `os.Remove` on the still-open `certFile` handle is a portability hazard on Windows. Harmless today; flagged because the block path avoids it by construction and the asymmetry could bite a future change to segment sizing.

### I-3 (Informational) — which record is the double-vote anchor

The M7 spec §3 calls `rounds.log` the double-vote record. In the code the double-vote *safety promise* is `locks.log` (`LockRecord`, with `scanLocks`' strict error policy); `rounds.log` (`RoundRecord`) is the restart position (liveness). Both are `Prunable:false` in `retention.table` and neither is enumerated by any deletion loop, so the "never prune the safety record" invariant holds regardless. Recorded only so that a future reviewer guards `locks.log` hardest — it is the one that must never be lost — and it is.

## What holds — the invariants that matter, each verified against the code

These are the substance of the audit: the properties that *could* have been breaks, confirmed closed.

**M8 — checkpoint trust (the whole milestone).**
- **Default refuses a rotated or fabricated checkpoint.** `verifyCheckpoint` in `checkpointAnchored` mode runs `committeeDiff(g.Validators, vals)` and returns `rotatedRefusal` on any difference — before any tally. An attacker who instead copies the *real* (public) genesis keys into `CommitteeHex` to pass the diff is then caught by `VerifyCommitCertificate`, which requires precommit signatures from those keys — which the attacker does not hold. Both sub-cases are closed, and the test `TestAFabricatedSelfConsistentCheckpointIsAdmittedOnlyByTrust` exercises exactly this.
- **The trust downgrade is hard-bounded.** `checkCheckpointAge` (reached only in `checkpointTrusted` mode) refuses a zero `MaxAgeEpochs`, a missing or future-dated `IssuedAt`, and any file older than the bound; the comparison direction is correct and `checkpointMaxAge` refuses each overflow rather than wrapping. The CLI (`cmdNode`) independently refuses `--checkpoint-trust` without `--checkpoint`, `--checkpoint-max-age` without the trust flag, and `--checkpoint-max-age 0`, so the verifier can never be reached with a zero bound.
- **The committee is derived and asserted at export, never trusted from the file.** `exportCheckpointAt` reads the signer committee from `chain.CommitteeAt(at)` and asserts it via `VerifyCommitCertificate` before writing; `CommitteeHex` is `encodeCommittee(committee)` of that derived set.
- **Format is version-gated both directions** (`CheckpointVersion == 2`), and `decodeCommittee` bounds the committee (≤255 seats, exact key width, positive power, **no duplicate keys** — so the quorum sum cannot be inflated by repeating a key).
- **Restart after a trusted import does not re-upgrade or break.** The first boot uses the verified `ResumeState` directly in `OpenResume` (which calls `AdoptBase(resume.Height+1)`), so `base > 1` thereafter; a later flag-less restart goes through `VerifyAdoptedCheckpoint` (internal-consistency, no age bound by design, gated on the directory's *own* adopted anchor). No silent re-trust, no liveness break.

**M7 — bounded history.**
- **The safety-critical records are never pruned, by construction.** The only deletion loops (`Store.PruneBlocks`, `Store.PruneCerts`) enumerate only `.seg`/`.cseg`/legacy `certs.log` files; `rounds.log`, `locks.log` and `genesis.hash` are never named by any loop, and `retention.table` marks them `Prunable:false` with `Deletable` refusing any *unclassified* record (fail-safe). Tested by `TestPruneBlocksDoesNotTouchRoundsLocksOrGenesis` and `TestThePrunableAndPermanentListsPartitionTheTable`.
- **The head and its certificate always survive.** `PruneBlocks` refuses `upTo >= s.last` and skips the active segment; `PruneHistory` refuses `upTo >= head`; `PruneCerts` keeps every cert at height ≥ `upTo` (including the horizon's, for re-export).
- **Pruning only at epoch boundaries**, enforced twice (`Pruner.MaybePrune` computes `k*blocks − 1`; `PruneHistory` independently refuses `(upTo+1)%blocks != 0`), so the horizon state exactly reproduces the first retained epoch's committee.
- **Retention floor and keep-everything default**: `ValidateRetain` refuses anything below `MinRetainEpochs (4) * epochBlocks`; `--retain-blocks` defaults to 0 and constructs no pruner.
- **No silent partial recovery**: three independent state-root checks (`checkResume`, `verifyCheckpoint`, and `StateAt`'s per-block `ErrRuleChange`), and `PruneHistory` re-verifies the supplied root against the stored header *before* deleting anything.

**Regressions — the pre-M7/M8 safety properties survived.**
- `validateLocked` still seats the proposer at the block's **own** height via `seatedAtLocked(b.Header.Height, b.Header.Proposer)` (the A-1 property) — the M7 refactor only split `BlockAt` into a lock-free `blockAt` and routed `advanceLocked` through the shared `transition`; the seat check is byte-unchanged.
- The live commit gate and the checkpoint verifier share one body (`verifyCertificateVotes`), which refuses a power-overflow committee (C-17) before tallying and re-proves every vote's signature, membership, placement and uniqueness.
- Lock discipline on the new `StateAt`/`PruneHistory` is correct: both take `pruneMu`, so the base cannot shift under a running replay, and the replay reads only immutable historical heights.
- No new ingress adopts a block without the certificate gate: `OpenResume` refuses every mismatch shape (`ErrHistoryPruned`, `ErrCheckpointMismatch`), and `Answer` adds only a refusal (`ErrRangePruned`) for ranges below the horizon.

## Test coverage

Strong, and targeted at the security arguments rather than the happy path. Every plan-mandated test exists:

| Plan requirement | Test |
|---|---|
| M8 §5(a): fabricated self-consistent checkpoint imports only under trust | `TestAFabricatedSelfConsistentCheckpointIsAdmittedOnlyByTrust` |
| M8 §5(b): expired trusted checkpoint refused | `TestATrustedCheckpointOlderThanTheBoundIsRefused` |
| M8 §5(c): trusted import reaches the replay root | `TestARotatedCheckpointNeedsTrustAndThenReachesTheReplayRoot` |
| M7/M8 acceptance: wiped node recovers to the same head and root | `TestAWipedNodeRecoversFromACheckpointToTheSameHeadAndRoot` |
| M7 §3: pruner never touches the safety records | `TestPruneBlocksDoesNotTouchRoundsLocksOrGenesis` |
| M7: horizon is an epoch boundary / head never pruned | `TestPruneHistoryOnlyAtAnEpochBoundary`, `TestPruneHistoryRefusesTheHead` |
| M7 §8: crash between marker and deletion recovers | `TestACrashBetweenTheMarkerAndTheDeletionIsRecovered` |
| M7: replay reproduces every stored root | `TestStateAtReproducesEveryStoredRoot` |

No coverage gap of a security-critical path was found. A possible addition: a test that drives `PruneHistory` to a `PruneCerts` error (fault injection) and asserts the running chain is still consistent — this is the L-1 path, currently unexercised.

## Execution evidence

The new packages' suites were run in Docker (`golang:1.27.3-bookworm`, `GOTOOLCHAIN=local`), and **all pass**:

```
ok  internal/consensus   113.187s
ok  internal/chain        14.679s
ok  internal/store        84.170s
ok  internal/retention     0.007s
ok  internal/state         0.070s
```

So the mandated security tests above are not merely present — they are green at `73f3544`. None of the findings in this report depends on that run; the Low and the Informationals are static-analysis results about paths the tests do not yet exercise (notably the L-1 `PruneCerts`-error path).

## Recommendations

1. **Fix L-1**: advance the in-memory base right after `PruneBlocks` succeeds, so a `PruneCerts` error cannot desynchronize the running chain from its on-disk base. Add the fault-injection test above.
2. **Document the `certIndex` locking contract** (I-1) with a one-line comment: it is serialized by the chain lock, *not* by `indexMu`, and must not adopt `BlockAt`'s lock-release pattern without first guarding the map.
3. **Make `PruneCerts` skip the active segment by construction** (I-2), matching `PruneBlocks`, so the open-handle delete path cannot exist even under a future segment-sizing change.
4. **Align the spec's §3 wording with the code** (I-3): name `locks.log` as the double-vote safety record and `rounds.log` as the restart position, so the sharpest edge is labelled where a reviewer looks.

## Closing note

No finding here changes the security posture established by the prior audits: consensus safety is intact, and the new recovery machinery is honest about the one place it trades authentication for availability (`--checkpoint-trust`), guarding that trade with a flag, a hard age bound, a file-level `Note`, and an import-time warning. This is a milestone that made the attack surface *smaller* relative to its ambition, which is the rare and correct direction.
