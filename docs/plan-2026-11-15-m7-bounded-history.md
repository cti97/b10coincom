# M7 — Bounded history with verifiable recovery

| | |
|---|---|
| Status | **plan, not started** |
| Depends on | nothing open; uses `internal/store`, `internal/chain` |
| Provenance | the 18-hour three-host run: `docs/testrun-2026-11-14-three-host-live.md` §11 |
| Goal | a node's disk reaches a **steady state** instead of growing without bound, and a node that has lost history can still rejoin |

---

## 1. Why this is a milestone and not a cleanup

Today a running validator's data directory grows forever. Measured at height
824,350 after ~18 hours:

```
558 MB total      =  710 bytes/block
  381 MB  certs.log   = 485 B/block   ← 68%, a single append-only file
  178 MB  825 × .seg  = 226 B/block   ← rotated, but never deleted
```

At the observed ~15 blocks/s that is **~1.7 GB/day**, and `certs.log` is the
dominant term. A 32 GB Pi card fills in under three weeks.

The fix is not "delete old files". A validator that deletes history loses the
ability to do two things that are load-bearing:

1. **Recover after being down longer than the retained window.** Today recovery
   is replay-from-genesis; if the blocks are gone, there is nothing to replay.
2. **Serve a peer that is behind.** If every node prunes, a node that falls
   further back than the window can never catch up from the network.

So bounded history requires an **answer to recovery**, and that answer is the
actual work.

## 2. The numbers, so the target is honest

| Retention | Blocks (at 15/s) | Disk (at 710 B/block) |
|---|---|---|
| 24 h | 1,296,000 | **~0.86 GB** |
| 24 h at a 2 s block time | 43,200 | ~29 MB |
| 72 h | 3,888,000 | ~2.6 GB |

**24 hours is ~0.86 GB at the observed rate.** That fits a Pi card comfortably and
is a real steady state. Note what this does *not* do: at 15 blocks/s the chain
only accumulates 0.86 GB per day, so a 24 h window on an 18-hour-old chain
prunes **nothing today**. The milestone is about the *bound*, which only starts
mattering after the window is exceeded — and about being able to recover, which
matters immediately.

## 3. What must never be pruned

Pruning a live validator is where a well-meaning "clean up disk" turns into a
safety bug. These are load-bearing and must survive every pruning pass:

| Record | Why |
|---|---|
| `genesis.hash` | chain identity; a mismatch must be fatal, not a silent re-sync |
| the lock record (`locks.log`) | **double-vote protection** — a validator that precommits two different blocks at one height has broken safety, and `locks.log` is the promise it made, surviving the restart that would otherwise forget it. Its scan policy is strict (a corrupt lock log fails Open) because it is the record that must never be lost |
| the durable round record (`rounds.log`) | **restart position (liveness)** — a validator that loses the highest round it entered re-runs the round ladder from round 0 for a height it already advanced past. That is a liveness regression, not a safety one: `locks.log` still refuses a conflicting vote, so no double-vote follows from losing it. It is permanent anyway, because re-running the ladder is exactly the multi-minute stall the restart tests exist to prevent |
| the head block and its certificate | the node must know what it last committed |
| the committee/validator set at the pruning horizon | without it, a replayed state cannot be checked |

**The lock record is the sharp edge, and the round record is not.** M7 must
assert, in a test, that pruning never removes or truncates `locks.log`; and
`rounds.log` is permanent too, for the liveness reason above. A pruner that
"cleans the data directory" and takes `locks.log` with it is a consensus-safety
bug that presents as a disk fix; one that takes `rounds.log` is a liveness bug
in the same costume. Audit I-3 (2026-11-15) found this table naming `rounds.log`
as the double-vote record — the code has always had it the other way round
(`retention.LockLog` is "the double-vote promise", `retention.RoundLog` the
restart position), and both were permanent under either reading. Corrected
here so a reviewer checks the sharpest edge in the right file.

## 4. The recovery design

Three tiers, by how far behind a node is:

**Tier 1 — within the window (≤24 h down).** Replay from its own log. Works
today; measured at ~91 MB/s, so 0.86 GB replays in about 10 s.

**Tier 2 — beyond the window (24 h – weeks down).** Needs a **checkpoint**: a
state at some height H, plus proof the committee agreed on it.

The key observation is that **the chain already produces that proof**. Every
height carries a quorum certificate in `certs.log`. A checkpoint is therefore
*(height H, state root R, the certificate for H)* — and a node that trusts the
committee can verify a quorum certificate without replaying anything.

**This is tractable now and gets harder later, which is why the milestone is
worth doing before rotation.** The committee is genesis-fixed: no stake has
bonded, unbonded or rotated, so the committee at *any* height is the genesis
committee, and a certificate at any height can be checked against it directly.
Once rotation exists, a checkpoint must additionally carry the committee at H,
and verifying it requires a light-client proof of the rotation — a materially
harder problem. **Doing retention while the committee is static avoids that
entire class of work.**

**Tier 3 — fresh node, no history at all.** Same as tier 2: start at a
checkpoint and sync forward. This is what lets a new Pi join without replaying a
million blocks.

### Trust

A checkpoint fetched from a peer is *not* trusted on its own. The node verifies:

1. the certificate for H is a valid quorum certificate under the committee it
   knows (genesis committee, while static);
2. the state root in the checkpoint equals the root the certificate commits to;
3. blocks after H chain forward and verify normally.

A peer that lies about a checkpoint cannot produce a valid quorum certificate for
a root the committee did not sign. **The trust anchor stays genesis** — which is
the property that matters, and the reason this is a checkpoint design and not a
"trust the operator" design.

## 5. Steps

**Step 1 — segment `certs.log`.** It is the 68% term and a single append-only
file, so nothing can be pruned until it is split. Mirror the `.seg` rotation
already used for blocks: fixed-size cert segments with an index, and a reader
that can start at a segment boundary. This is a prerequisite for everything
else and is worth landing on its own.

**Step 2 — separate the prunable from the permanent.** One place that answers
"what may be deleted", with the §3 table encoded as code and a test that asserts
`rounds.log`, `locks.log` and `genesis.hash` are never in the prunable set. No pruning logic
yet.

**Step 3 — the pruner.** `--retain-blocks N` (heights, not hours: a height is
exact and a duration is not, and the operator can convert). Default **keep
everything**, so behaviour is unchanged unless asked for. Prune only at
**epoch boundaries** (`epoch_blocks`, 1000 today) so the state at the horizon is
exactly reproducible, and refuse a retention shorter than a few epochs.

**Step 4 — checkpoint export/import.** `b10coin checkpoint export --at H` writes
*(height, root, certificate)*; `--checkpoint <file>` starts a node from one. The
verification in §4 is the whole feature.

**Step 5 — prove recovery.** The test that must exist: build a chain, prune it,
**wipe a second node**, give it only the checkpoint, and assert it reaches the
same head with the same state root as an unpruned node. Not "it starts" —
the roots must agree.

**Step 6 — docs and a Docker scenario.** The 10-node Docker run exists for
exactly this kind of scenario; extend it with a pruned node plus a fresh joiner.

## 6. Acceptance criteria

- [ ] Disk reaches a **steady state** under `--retain-blocks`: 48 hours of
      continuous running at a fixed retention does not grow the data directory
      beyond one window's worth plus a small margin.
- [ ] A node **wiped entirely** and given only a checkpoint reaches the same head
      **and the same state root** as a node that never lost history.
- [ ] A node **down beyond the retention window** rejoins via a checkpoint and
      agrees on the head.
- [ ] **No safety regression**: `locks.log`, `rounds.log` and `genesis.hash`
      survive every pruning pass, asserted by test; and a pruned validator does not double-vote
      across a restart (the existing round-record tests must still pass with
      pruning enabled).
- [ ] A pruned node either **serves** peers behind the horizon or **says plainly
      that it cannot** — silence here would be the same class of defect as the
      relay gate's silent refusal.
- [ ] Default behaviour is unchanged: no pruning unless asked for.

## 7. What I would not do

- **Do not prune block bodies while keeping headers, hoping the header chain
  stays verifiable.** At this block rate a header chain still grows ~0.4 GB/day
  and the milestone would not bound anything. Checkpoints bound it; headers
  only postpone it.
- **Do not make retention the primary mechanism for recovery.** Retention is the
  bound; checkpoints are the recovery. Shipping the pruner without checkpoints
  would produce nodes that look healthy and cannot recover, which is worse than
  a full disk because a full disk is visible.
- **Do not implement rotation-aware checkpoints as part of this.** That is the
  next milestone's problem; M7's design should state the assumption explicitly
  (§4) so that the moment rotation lands, whoever lands it knows the checkpoint
  format must grow.

## 8. Risk

The failure mode to guard against is **silent partial recovery**: a node that
starts from a checkpoint whose root is wrong, or which prunes while its round
record is stale, and then participates in consensus with bad state. The design
answers it by making every checkpoint verification a *certificate* check
(§4) — a root no committee signed cannot be adopted — and by excluding the
safety-critical records from pruning by construction rather than by care.
