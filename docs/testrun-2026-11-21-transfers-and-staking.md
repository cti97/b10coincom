# Test run report: transfers and staking on the live three-seat testnet (2026-11-21)

| | |
|---|---|
| Chain | `b10coin-simnet-3` — fixture committee, three seats, keys from the public seed |
| Validators | 2 × Raspberry Pi (separate home networks) + 1 × macOS (third network), all behind NAT |
| Transport | one public relay, `93.115.53.244:7001`, token-gated |
| Artefact | release `v0.1.8`, `rev 44afa62554e4 (clean)` on all three seats |
| Account under test | `b10n6bx7wjzbjlw4xd5aqbo5jp27uq5yxhcziim7dy` — the fixture dev account, 1,000,000 b10 at genesis |
| Date | 2026-11-21, plus a confirmation run on 2026-11-22 |

**This is the first time the user-facing money paths — `send`, `stake`, `unstake`,
`withdraw` — have been driven against the live committee over the public relay,
rather than against a local devnet.** Every transaction below was signed by the
CLI, posted to a node's `/tx`, and committed by a block the three seats agreed
on. Nothing was written into state directly.

---

## 1. Result

Two full staking cycles and six transfers, with the refusals exercised
alongside the happy paths. Every rule the chain promises held, including the
ones that are easy to get wrong: the cooldown rounding, the merge of unbonding
records at one release height, and "a refusal moves nothing, not even the nonce".

The account finished the runs at **999,997.74999989 b10, nonce 18, bonded 0,
unbonding empty** — every spark accounted for by transfers plus 1-spark fees.

## 2. Transfers

| Case | Observed |
|---|---|
| 1 b10 to a fresh key (first run) | recipient `0 → 100,000,000` sparks; sender nonce 0 → 1 |
| 0.5 b10 to a fresh key | recipient `+50,000,000`; sender paid amount + 1 spark |
| 1 spark ("dust", 0.00000001 b10) | recipient `+1` spark exactly |
| drain an account to zero (`balance − 1`) | balance `0`, nonce `1`, recipient got the full drained amount |
| transfer to self | refused **before signing**: `state.applyTransfer refuses a transfer to self (ErrSelfTransfer)` |
| transfer larger than the balance | refused **before signing**: `holds 0 b10 … short 10000000001 sparks` |
| replay / same nonce while pending | refused by the node: `nonce N is already pending from <txid>` |

## 3. Staking

Two cycles, each timed to start just after an epoch boundary so the bond could
be placed and fully removed inside one 1000-block epoch.

| Case | Observed |
|---|---|
| bond 500 b10 (below `MIN_STAKE`) | refused: `--amount 500 b10 would leave the bond at 500 b10`; bonded stayed `0` |
| bond 1000 b10 | `bonded = 100,000,000,000` sparks |
| top-up 100 b10 (below the floor, legal because the result clears it) | `bonded = 110,000,000,000` |
| partial unbond 50 b10 | `bonded = 105,000,000,000`; one unbonding record of 50 b10 |
| unbond 5000 b10 (more than bonded) | refused: `more than the bonded 1050 b10` |
| withdraw before the release height | refused: `no unbonding record has matured at head …: the next releases at height <R>`; nonce unchanged |
| unbond the remaining 1050 b10 | `bonded = 0`; the 50 b10 and 1050 b10 records **merged into one** of 1100 b10 |
| withdraw at the release height | 1100 b10 returned; `unbonding` empty, `bonded` 0 |

Release heights confirmed the rule rather than an assumption: unbond at
`h = 6704581` → `release_height 6707000`, i.e. `h + 2 × 1000` rounded **up** to
the next epoch boundary (`state.releaseHeightFor`). The second cycle produced
the same shape at `6710000`.

## 4. Invariants checked arithmetically

- **Fees are exactly 1 spark** on `send`/`stake`; `unbond` and `withdraw` carry
  **0**. Run 1 moved the nonce by 7 (seven state-changing transactions) and the
  balance by exactly `−50,000,005` sparks: 0.5 b10 transferred plus five
  1-spark fees.
- **Supply is not conserved across a transfer** and is not supposed to be: every
  committed block mints its 0.5 b10 reward to the proposer, so `TotalBalance`
  grows while a test waits. The transfer-local sheet (`sender loss − recipient
  gain = fee`) is the invariant, and it held in every run.
- **A refusal changes nothing.** Nonce, bonded amount and unbonding records were
  re-read after each refused command and were unchanged.
- **The chain crossed two epoch boundaries with no bond outstanding** (unbonded
  at 6704581 and 6707717; boundaries at 6705000 and 6708000) and kept
  committing — the safe way to stake on this fixture, because a standing
  1000 b10 bond would put a key with no process behind it at the top of the
  derived committee.

## 5. What tripped the harness (not the chain)

Recorded because each one produced a red line in the first batch run and cost
time to explain:

1. **One pending transaction per nonce.** A second command signed from a nonce
   the pool still held was refused with `nonce N is already pending`. Wait for
   `/account`'s nonce to reach the expected value after each verb, not for the
   balance to move.
2. **`/account` can answer one block behind.** Two consecutive reads may
   disagree; read until two samples are equal before asserting.
3. **`unbonding_total` is the number of records, not sparks.** The amounts are
   in `unbonding[].amount`; summing the wrong field reported "want
   110000000000, got 1".
4. **Most refusals happen in the CLI, before signing** — self-transfer,
   insufficient balance, bond below `MIN_STAKE`, unbond above the bond, withdraw
   before release. That is the intended behaviour (nothing irreversible is
   signed for a transaction the chain would reject), but it means a test of the
   *chain's* refusal path needs a crafted transaction, not the CLI.

Each was re-run with settling waits and passed: a separate confirmation run of
transfer → exact-zero drain → self-transfer refusal scored 9/9.

## 6. Chain state after 43 hours on v0.1.8

Measured 2026-11-22 09:35 EET, node started 2026-11-20 14:06 EET:

```
height     5,414,047 → 7,498,019        2,083,972 blocks over 43.4 h
average    ~13.3 blocks/s               (healthy stretches run 15–16/s)
relay      conns=3 live=3  forwarded=110,339,893  dropped=3,073  refused=0
site       /live/chain.json 3 s old
```

The stall log recorded **20 episodes** in that window — two at the restart
(one closing the pre-restart ladder, one while both Pis were down) and **18
during steady state**, roughly one per two hours. Each is the documented round
divergence: a ladder of 11–97 rounds, `quorum reachable … yet nothing commits`,
which closes on its own and the chain catches up. At 2 s + 100 ms per round the
ladder for 70 rounds costs about six minutes, which is consistent with the
observed average being ~2 blocks/s below the healthy rate.

No deadlock shape occurred: the deaf-link watchdog did not cycle, and
`peers=2` with both seats at the same height appears only in the pre-restart
lines.

## 7. What this does not prove

- The committee's keys derive from a public seed, and the premine is fixture
  spendable. **Nothing here is evidence about value, security or a real
  committee**; it is the plumbing working end to end.
- Three seats with 3-of-3 quorum has no liveness margin: the transient stalls in
  §6 are a known residual, not a closed issue. Closing it is a consensus
  question (quorum shape and the round ladder's tail), not a client one.
- The exercises ran from one host (this Mac) against one node's RPC. They say
  nothing about many wallets, mempool pressure or reorg behaviour.
