# Implementation plans

These are the plans this repository was built from, one per milestone. They are
**historical records**, not a specification of the shipped code: where a plan
and the code disagree, the code is the source of truth, and the disagreement is
named here or in the plan.

| Plan | Milestone | Status |
|---|---|---|
| [`2026-10-02-m0-m1-foundation-single-node.md`](2026-10-02-m0-m1-foundation-single-node.md) | M0–M1: chain, store, state, RPC, single-node devnet | Shipped |
| [`2026-10-02-m2-faucet.md`](2026-10-02-m2-faucet.md) | M2: Argon2id claim puzzle, emission, claim transaction | Shipped |
| [`2026-10-03-m3-bft-consensus.md`](2026-10-03-m3-bft-consensus.md) | M3: engine, driver, round/lock protocol | Shipped. **Design Decision 4 is SUPERSEDED by Decision 11** (the justification gate); do not implement the literal unlock branch |
| [`2026-10-04-m4-real-networking.md`](2026-10-04-m4-real-networking.md) | M4: TCP transport, relay, HELLO, BLOCK_SYNC | Shipped. Decision 2's tag claim was false at M4 and is now true only because `wire` renumbered its tags (correction in the plan); Task 4's `Answer` signature is corrected to the shipped one |
| [`2026-10-11-m5-staking-rotation.md`](2026-10-11-m5-staking-rotation.md) | M5: bonds, unbonding, stake-derived committee, PEER_EXCHANGE, Nakamoto | Shipped |

Review and audit records live one level up in [`docs/`](../): the milestone
audits (`audit-2026-*.md`), the fix verifications, and the Docker test runs.
The honest account of how the work was reviewed and merged is
[`docs/process-2026-10-31.md`](../process-2026-10-31.md).

**Reading a plan cold.** Each plan states its acceptance commands and the
decisions taken at the time. Decisions that were later reversed carry a
**Correction** or **SUPERSEDED** note beside them; if one does not, and the code
contradicts it, treat the plan as stale and fix it rather than the code.
