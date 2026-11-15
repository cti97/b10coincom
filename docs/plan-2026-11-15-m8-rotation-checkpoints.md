# M8 — Rotation-aware checkpoints: the trust decision

| | |
|---|---|
| Status | **plan, not started** |
| Depends on | M7 (merged, `675c2b2`) |
| Provenance | M7's deferral, recorded in `checkpointNote` and PR #30 |
| Question | A checkpoint can currently be verified only against the **genesis** committee. How do we verify it after the committee has rotated? |

---

## 1. What M7 shipped, so this does not re-derive it

`internal/consensus/checkpoint.go`'s `Checkpoint` already carries:

```
Height, Round, BlockHex, StateHex, VotesHex, ChainID, GenesisHash
```

and its own `Note` says, in the file:

> "verifiable against the GENESIS committee only … Rotation-aware checkpoints
> (carrying the committee at height and a rotation proof) are explicitly out of
> scope for M7; an exporter refuses to produce one where the committee has
> rotated."

**The committee is therefore already *present*** — `CommitteeAt(H)` derives it from
`StateHex`, deterministically. What is missing is not data. It is **trust**.

## 2. The actual problem, stated precisely

Verification today is: *the votes for block H form a quorum under the committee I
trust*, and the only committee a fresh node trusts is genesis, because genesis is
the anchor it was started with.

After rotation, the committee at H is **not** the genesis committee, so a node
that only trusts genesis cannot check H's votes.

And here is the trap that makes this a design decision rather than a task:

> **A checkpoint carrying its own committee verifies against itself.**
>
> The votes form a quorum under the committee derived from `StateHex`. But an
> attacker who fabricates a whole state — a committee of keys they hold, a
> consistent state, votes signed by those keys — produces a checkpoint that
> passes that check trivially. **Self-consistency is not authenticity.**

So there is no purely-local way to authenticate a rotated checkpoint. Every real
chain resolves this one of two ways.

## 3. The two honest options

### Option A — weak subjectivity (what Ethereum does)

The checkpoint is an **explicitly trusted anchor**, supplied by the operator or
socially agreed, valid for a bounded window.

- Verification: internal consistency only — votes form a quorum under
  `CommitteeAt(H)` derived from the carried state, and the state hashes to the
  root the votes commit to.
- Trust: **the operator trusts the checkpoint's provenance**. A malicious peer or
  a compromised source can hand you a valid-looking fork.
- Mitigation: a **weak-subjectivity period** — the checkpoint must be no older
  than N epochs, so a node cannot be silently pinned to a long-dead fork, and the
  window is small enough that social consensus on "the chain you see" is
  meaningful.
- **This is the only option that works for a node that has been wiped or down
  longer than retention**, which is the case M7 exists to serve.

### Option B — authenticated rotation proof

Carry the evidence that the committee changed lawfully, so `CommitteeAt(H)` is
proven from an anchor the node already trusts.

- What it needs: every block between the anchor and H that carried a `TxBond` or
  `TxUnbond`, **plus enough header chain to bind them**, plus their certificates.
- What it costs: the header chain is the problem. Binding a state root at H to a
  state root at an anchor T requires the headers T..H, which at ~1.1M blocks/day
  is exactly the growth M7 removed.
- **It is tractable only when the anchor is near H** — i.e. when the node still
  has history within the retention window. A node that does is *not* the case M7
  exists for; it can already replay.

**Both are real, and they serve different nodes.** A only serves the wiped node.
B only serves a node that barely needs it. That asymmetry is the finding.

## 4. Recommendation

**Ship Option A, and keep Option B's refusal.**

- **Default stays exactly as M7 is today**: genesis-anchored, exporter refuses on
  rotation. No change for anyone who does not ask.
- **`--checkpoint-trust` (opt-in) enables Option A**, and the checkpoint file
  states in its own `Note`, and on **stderr at import**, what it does and does
  not prove. A security property this weak must be impossible to acquire by
  accident or to forget.
- **The weak-subjectivity period becomes a hard check**: an Option-A checkpoint
  older than `--checkpoint-max-age` (default a small number of epochs) is
  refused. Without a bound, Option A is a way to pin a node to an arbitrary past
  fork forever.
- **Option B is not built.** Building it would be a light client, which is a
  milestone of its own, and shipping a partial version would be worse than the
  refusal.

## 5. Steps

1. **Export the committee.** Add `CommitteeHex` to the checkpoint (derived, not
   supplied — it must equal `CommitteeAt(H)` from the carried state, asserted at
   export). Add a format `Version` bump; refuse to import an old-format file
   under the new trust and vice versa.
2. **Internal-consistency verification.** Votes form a quorum under the carried
   committee; state hashes to the root the votes commit to; the block commits to
   that root. Reuse `VerifyCommitCertificate(vals, …)` — it already takes the set
   as a parameter, so no new consensus code.
3. **The trust flag and the age bound.** `--checkpoint-trust` +
   `--checkpoint-max-age`. Absent the flag, behaviour is M7's. Present, verification
   is internal-consistency **and** the age check.
4. **Say it loudly.** The file's `Note`, an import-time stderr warning naming the
   trade (a trusted checkpoint cannot be authenticated against the real chain),
   and `docs/` + `README` rows. A silent trust downgrade is the failure mode
   worth guarding hardest.
5. **Tests that must exist**: (a) a fabricated self-consistent checkpoint —
   attacker's own keys — **imports under Option A and is refused without it**,
   because that test is the whole security argument in executable form; (b) an
   expired checkpoint is refused; (c) an Option-A import reproduces the same
   state root as replay, which proves it did not silently change the chain.

## 6. Acceptance criteria

- [ ] Default behaviour **unchanged**: no flag, no new trust, M7's refusal intact.
- [ ] `--checkpoint-trust` admits a rotated checkpoint and reaches the **same
      state root** as a node that replayed.
- [ ] **Without** the flag, the same checkpoint is refused, and the error says
      why and what the flag would cost.
- [ ] A **fabricated** checkpoint (attacker-held keys, self-consistent) is
      admitted under the flag — the test proves the weakness exists rather than
      hiding it — and refused without it.
- [ ] An expired checkpoint is refused.
- [ ] The trust level in force is visible at import, not merely documented.

## 7. What I would not do

- **Do not make Option A the default.** It converts an authenticated restore into
  a trusted one, and every existing operator's expectation of the checkpoint
  would quietly weaken.
- **Do not claim Option A "fixes" rotation-aware checkpoints.** It makes a rotated
  restore *possible* at the cost of a trust assumption. The honest statement is
  that full verification of a rotated checkpoint by a wiped node is a light
  client, and this milestone does not build one.
- **Do not add an age bound later.** An unbounded weak-subjectivity checkpoint is
  a permanent fork-pin, and the bound is cheap now and a migration later.

## 8. Risk

The failure mode is a **silent trust downgrade**: a node that believes it
verified a checkpoint when it only checked that the checkpoint agreed with
itself. The design answers it with four separate signals — a separate flag, a
`Note` in the file, an import-time warning, and the fabricated-checkpoint test —
because one of them will be skipped by a reader under time pressure.
