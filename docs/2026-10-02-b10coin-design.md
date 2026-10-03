# b10coin — Design Specification

**Date:** 2026-10-02
**Status:** Approved for planning (M0–M3 in scope)
**Codename:** b10coin (working name; rename freely)
**Read with zero context:** yes — this document is self-contained.

---

## 1. Purpose

Build a proof-of-stake-style cryptocurrency "from zero" whose **validators run on
small computers** (Raspberry Pi class), with **no proof-of-work consensus** and
**no premine**, delivered first as a **testnet** whose goal is deep understanding
rather than market launch.

This document is the contract. It records what we are building, what we are
explicitly *not* building, and how each claim will be verified.

---

## 2. The premise this project corrects

The original motivation was: *"I don't want PoW because I want it to run on a
Raspberry Pi."* That conflates two different jobs.

| Job | Cost | Pi-viable? |
|---|---|---|
| Validate transactions, store the chain (a **node**) | disk + bandwidth | **Yes** — including Bitcoin and Litecoin today |
| Produce blocks and earn new coins (**mining**) | energy (PoW) or capital (PoS) | A Pi can **stake**; it can never **mine** competitively |
| Vote in consensus (**validator**) | network + signing | Yes, comfortably |

So the real objection is not "PoW won't run on a Pi" — a Pi runs a Bitcoin full
node fine. The real objection is **distributional**: on a PoW chain a Pi owner
can never *earn* the coin; only industrial ASIC farms can.

**Therefore this project's difficulty lives in issuance and distribution, not in
consensus.** Consensus is treated as a solved problem to be selected, not
invented.

---

## 3. The constraint we accept

PoW is the only mechanism that is simultaneously (a) permissionless,
(b) Sybil-resistant, (c) roughly fair in distribution, and (d) self-bootstrapping.
Every non-PoW design substitutes something and breaks one property.

**Accepted trilemma: permissionless + fairly-distributed + no-PoW — pick two.**
b10coin sacrifices *permissionless validation at genesis* (it begins federated)
and compensates with a measurable, explicit path to decentralisation.

---

## 4. Non-goals (YAGNI)

Explicitly **out of scope**, each a separate project if ever wanted:

- Smart contracts, EVM, or any VM
- Zero-knowledge proofs, privacy features
- Light clients / SPV proofs
- Sharding, rollups, or any scaling layer
- On-chain governance / DAO
- Token sale, ICO, or any fundraise (**also a legal decision — see §13**)
- Mainnet launch, exchange listings, market making
- Hole-punching NAT traversal (deferred to M5+, see §10)
- Mobile/desktop GUI wallets (CLI only through M6)

---

## 5. Architecture overview

```
        ┌───────────────────────────────────────────────┐
        │  cmd/b10coin  (CLI: node, devnet, wallet,     │
        │              faucet)                          │
        └───────────────────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────────────┐
        │                   │                           │
   ┌────▼─────┐      ┌──────▼──────┐             ┌──────▼──────┐
   │consensus │      │   state     │             │  transport  │
   │ BFT      │◄────►│ apply(),    │             │  Transport  │
   │ rounds   │      │ accounts,   │             │  interface  │
   │ locking  │      │ Merkle root │             │  sim|tcp|   │
   └────┬─────┘      └──────┬──────┘             │  relay      │
        │                   │                    └──────┬──────┘
        │            ┌──────▼──────┐                    │
        └───────────►│    store    │              ┌─────▼──────┐
                     │  segments + │              │    sim     │
                     │  snapshots  │              │ deterministic│
                     └─────────────┘              │  network   │
                                                  └────────────┘
```

**Design rule:** `consensus` depends only on the `Transport` *interface*. It must
never know whether it is talking to an in-process simulator, a TCP peer, or a
relay. This single boundary is what keeps NAT work deferrable and cheap.

**Proposed repository layout:**

```
b10coin/
  cmd/b10coin/           CLI entrypoint (node, devnet, wallet, faucet)
  internal/
    crypto/             Ed25519, BLAKE3, Argon2id wrappers
    types/              Block, Header, Tx, Address, canonical encoding
    state/              account state, apply(), Merkle commitment
    consensus/          BFT round logic, locking, vote tallying
    transport/          Transport interface + sim, tcp, relay impls
    faucet/             claim verification, emission schedule
    store/              block segments, snapshots, replay
    sim/                deterministic network + scheduler
  genesis/              genesis files (devnet, testnet)
  docs/
```

---

## 6. Component specifications

### 6.1 Ledger model — account-based

State is a map `Address -> Account`:

```
Account {
    balance:      u64   // spendable, in sparks
    nonce:        u64   // replay protection
    bonded:       u64   // stake locked for validation
    unbonding:    u64   // stake in cooldown
    unbond_at:    u64   // block height when unbonding completes
    pubkey:       [32]u8
}
```

Account-based (not UTXO) because it is substantially easier to reason about, and
because staking integrates naturally. At testnet scale (< 1M accounts) state fits
in memory; the Merkle root is committed per block and state is rebuilt by replay
on restart. **No key-value database until replay time actually hurts.**

### 6.2 Transaction types

| Type | Fields | Effect |
|---|---|---|
| `Transfer` | `to, amount, nonce, sig` | Move balance; requires `nonce == account.nonce` |
| `FaucetClaim` | `pow_nonce, epoch, pubkey, sig` | Verify Argon2id PoW; credit `CLAIM_AMOUNT`; mark key claimed for epoch |
| `Bond` | `amount, validator_pubkey, nonce, sig` | Move balance → bonded; registers validator candidate |
| `Unbond` | `amount, nonce, sig` | Move bonded → unbonding; set `unbond_at = height + UNBONDING_BLOCKS` |
| `Withdraw` | `nonce, sig` | After `unbond_at`, move unbonding → balance |

**Validity rule — a self-transfer (`from == to`) is rejected** (`ErrSelfTransfer`,
`internal/state/apply.go`): a transfer debits and credits the same account, which
would alias the two writes and corrupt the balance. Implemented since M1 and
pinned there by `TestApplyTransferRejectsSelfTransfer`; recorded here so the M3
consensus work cannot diverge on it.

### 6.3 Consensus — Tendermint-style BFT, stake-weighted

Chosen over HotStuff deliberately: the lock/unlock rule is subtle, but reference
material is far more abundant, and the project's goal is deep understanding.
HotStuff is the v2 upgrade path.

**Rounds within a height:**

1. **PROPOSE** — proposer for `(height, round)` broadcasts a signed block.
2. **PREVOTE** — validators validate and broadcast prevote for the proposal.
3. **PRECOMMIT** — on ≥2/3 voting power of prevotes, broadcast precommit.
4. **COMMIT** — on ≥2/3 voting power of precommits for the same block at the
   same round, commit; execute; persist; advance to `height + 1`.

**Locking rule (the safety-critical part):** a validator that precommits block
`B` at round `r` is *locked* on `B`. In any later round it prevotes only for `B`
or for a proposal at a round `> r`. Without this rule, two conflicting blocks can
commit at the same height.

**Proposer selection:** weighted round-robin by voting power, deterministically
seeded from `(height, round, parent_block_hash)` so all validators agree.

**Round timeout:** base timeout, increasing each round if no progress. v1 uses a
plain timeout to advance rounds (no timeout certificates); a skip certificate is
a later refinement.

**Parameters:**

| Parameter | Devnet | Testnet | Rationale |
|---|---|---|---|
| Target block time | 2 s | 2 s | Fast finality; emission math in §6.4 assumes this |
| Committee size | 4 | 21 | Pi-realistic; 21 keeps O(n²) gossip bounded |
| Fault tolerance | < 1/3 voting power | < 1/3 | Standard BFT assumption |
| Max power per validator | 1/4 of total | 1/4 | Keeps one operator below the 1/3 threshold |
| Epoch length | 1,000 blocks | 10,000 blocks | Validator set changes only at epoch boundaries |
| `UNBONDING_BLOCKS` | 2 epochs | 2 epochs | Weak-subjectivity / long-range mitigation |

**Properties to verify (see §12):**
- *Safety:* never two conflicting commits at the same height.
- *Liveness:* with < 1/3 Byzantine and partial synchrony, height advances.

### 6.4 Issuance — capped emission into a protocol-controlled faucet

**The "no premine" rule, made concrete:** the genesis block mints to a **faucet
account that no private key can spend from.** Coins leave it only through the
protocol's claim rule. There is no human key, no insider allocation, and no sale.

| Parameter | Value | Notes |
|---|---|---|
| Base unit | **spark** (1 b10 = 10⁸ sparks) | Mirrors satoshi; `u64` throughout |
| Total supply cap | **21,000,000 b10** | Terminal; emission reaches zero |
| Initial block reward | 0.5 b10 = 50,000,000 sparks | Paid into the faucet account |
| Halving interval | every 21,000,000 blocks | ≈1.33 years at 2 s blocks |
| Emission endpoint | ~20 halvings | Sum = `0.5 × 21,000,000 × 2` = 21,000,000 b10 ✓ |
| `CLAIM_AMOUNT` | 100 b10 per key per epoch | Genesis-configurable |
| Faucet puzzle | Argon2id, tuned to ≈3 s on a Pi 4 | Memory-hard; ASICs do not help |
| Claims allowed | one per key per epoch | The actual anti-farming rule |
| After emission ends | **fees only** | No perpetual inflation |

Emission arithmetic check: `R0 × HALVING_INTERVAL × 2 = 50,000,000 sparks ×
21,000,000 × 2 = 2.1 × 10¹⁵ sparks = 21,000,000 b10`. Fits in `u64`
(max ≈1.8 × 10¹⁹). ✓

**Invariant:** a `FaucetClaim` is valid only if the faucet balance covers
`CLAIM_AMOUNT`. If the faucet is empty, claims fail until more emission accrues.

**Demotion of PoW.** PoW is not used for consensus. It is used *only* as a
faucet rate-limiter, which is legitimate and Pi-friendly: the difficulty is
calibrated so a Pi completes a puzzle in seconds, and at that difficulty ASICs
confer no meaningful advantage.

### 6.5 Validator admission — the decentralisation ramp

**v1 (federated, M0–M4):** the genesis file hardcodes the validator public keys.
No stake required. This is an honest starting condition, not something to hide —
Bitcoin's equivalent was one person mining alone.

**v2 (staking, M5):** `Bond` ≥ `MIN_STAKE` (1,000 b10) registers a candidate.
The committee is the top 21 candidates by bonded stake. Exiting requires
`Unbond` and a `UNBONDING_BLOCKS` cooldown before `Withdraw`.

**The thesis becomes measurable:** because stake can only be acquired through
faucet claims, the stake distribution — and therefore the Nakamoto coefficient of
the validator set — is a function of how far distribution has progressed. This is
a claim b10coin can graph over time rather than merely assert.

### 6.6 Networking — swappable transport, staged NAT strategy

**Core asymmetry driving every decision:**

| Direction | Status |
|---|---|
| Inbound (a stranger connects to a home Pi) | Blocked by default (NAT/firewall) |
| Outbound (a home Pi connects out) | Almost never blocked |

Consequence: any node can reach a public node, but **two private nodes cannot
reach each other directly**. Additionally, many ISPs use **CGNAT**, where no
public IP exists at all and port forwarding is impossible.

**The interface consensus depends on:**

```
Transport:
  broadcast(bytes)            # send to all connected peers
  on_message(callback)        # receive a validated frame
  peers() -> []PeerId
```

**Staged NAT strategy — no NAT code is written until M5.**

| Stage | Topology | NAT code written |
|---|---|---|
| M3 — 4 validators in one process | `SimTransport` (in-process, deterministic) | None |
| M4 — real Pis across real homes | **Outbound relay on a cheap VPS** | ~300 lines (dumb forwarder) |
| M5+ — strangers permitted | Relay + hole punching, or adopt libp2p | Significant |

**M4 relay design.** A ~€4/month VPS runs `b10coin-relay`, which knows nothing
about consensus and simply forwards signed frames between registered validators.
Every Pi dials **outbound** to it, so no port forwarding is needed and CGNAT is
irrelevant. Bandwidth is kilobytes per second — a trivial load.

**Trust property that makes this acceptable:** every consensus message is signed
with the sender's Ed25519 key. **A malicious relay can censor or delay, but it
cannot forge a vote or a proposal.** Safety is never at risk from the relay;
liveness is (a relay that partitions the validator set stalls consensus). For a
testnet this is an acceptable trade. Mitigations when it matters: multiple
relays, direct connections where possible, an over-provisioned mesh.

**Frame format:** 4-byte big-endian length prefix + canonical payload.

**Message types:** `HELLO`, `PROPOSAL`, `PREVOTE`, `PRECOMMIT`, `TX_GOSSIP`,
`BLOCK_SYNC` (catch-up), `PEER_EXCHANGE` (M5).

**Dedup:** every consensus message carries `(validator_id, height, round, type)`;
each node keeps a seen-set per height. A star topology has no loops, but this is
required the moment the topology becomes a mesh.

**Reconnection:** exponential backoff with jitter; the relay keeps a connection
registry; if the relay restarts every validator redials.

### 6.7 Cryptography

All primitives from the standard library of the implementation language; **no
exotic dependencies**.

| Purpose | Algorithm |
|---|---|
| Signatures | Ed25519 |
| Hashing / Merkle tree | BLAKE3 |
| Faucet puzzle | Argon2id (memory-hard) |
| Addresses | `"b10" + base32(payload ‖ checksum)`, where `payload = BLAKE3("b10coin-address" ‖ pubkey)[0..20]` and `checksum = BLAKE3("b10coin-checksum" ‖ payload)[0..4]`, base32 is RFC4648 lowercase unpadded, and `‖` denotes domain-separated framing via `HashParts` (each part length-prefixed), NOT bare concatenation |
| Node identity | same keypair as the validator key |

### 6.8 Storage

- **Blocks:** append-only segment files, 1,000 blocks per segment, each record
  length-prefixed and checksummed. Immutable once written.
- **State:** in memory; Merkle root committed in each block header.
- **Snapshots:** every 10,000 blocks, so restart does not require full replay.
- **On restart:** load newest valid snapshot, replay remaining blocks, verify the
  resulting root matches the last committed header.

---

## 7. Implementation language

**Recommendation: Go.**

The original preference was Zig. It is a legitimate choice — excellent ARM64
cross-compilation, a complete `std.crypto`, and TigerBeetle as a best-in-class
Zig consensus reference. It was set aside for one specific reason: **an AI agent
writes this code, and Zig is pre-1.0 with breaking changes every release.**
Zig 0.16 introduced a new `std.Io` interface (announced December 2025), so
model-generated Zig is likely to be stale in ways that do not compile. Go's
stability, error messages, race detector, and available libp2p escape hatch make
the agent's self-correction loop far tighter.

| Factor | Go | Zig |
|---|---|---|
| Accuracy of AI-authored code | High (stable, large corpus) | Risk of stale pre-1.0 APIs |
| ARM64 cross-compile | `GOOS=linux GOARCH=arm64` | Marginally better |
| Pi runtime footprint | ~20–50 MB RSS (fine on 4–8 GB) | Smaller, no GC |
| P2P escape hatch | libp2p available | Young bindings |
| Debugging | Delve, pprof, race detector | Weaker tooling |

The architecture is language-independent; only §12's tooling commands change.

---

## 8. Genesis parameters

Stored in `genesis/devnet.json` and `genesis/testnet.json`:

```json
{
  "chain_id": "b10coin-devnet-1",
  "genesis_time": "<RFC3339>",
  "validators": [ { "pubkey": "...", "power": 1 } ],
  "faucet_pubkey": null,
  "params": {
    "block_time_ms": 2000,
    "committee_size": 4,
    "epoch_blocks": 1000,
    "max_power_fraction_num": 1,
    "max_power_fraction_den": 4,
    "unbonding_epochs": 2,
    "total_supply_sparks": 2100000000000000,
    "initial_reward_sparks": 50000000,
    "halving_interval_blocks": 21000000,
    "claim_amount_sparks": 10000000000,
    "min_stake_sparks": 100000000000,
    "faucet_pow_argon2": { "m_kib": 65536, "t": 3, "p": 1 }
  }
}
```

`faucet_pubkey` is `null` by design: the faucet account is derived
deterministically from the genesis hash and has no corresponding private key.

---

## 9. Verification plan

Per this workspace's principle *"a project isn't real until one command proves it
works."* **Two commands must exist and be green at every milestone:**

```
go test ./...                                   # unit + property + simulation tests
go run ./cmd/b10coin devnet --blocks N [--dir D]  # end-to-end: a fresh devnet, N blocks appended and verified
```

### 9.1 Deterministic simulation harness (the centrepiece)

Run N virtual validators in a single process over a simulated network with
injected latency, packet loss, reordering, and partitions — all driven by a seed,
so any failure replays exactly. This is the TigerBeetle VOPR model and it is the
highest-leverage investment available for consensus code.

Scenarios that must pass:
- Happy path: 4 validators finalize 1,000 blocks.
- One validator offline: chain still advances (3 of 4 > 2/3).
- Two validators offline: chain **stalls** and does not commit conflicting blocks.
- Network partition then heal: **no safety violation**, chain resumes.
- Byzantine validator equivocates (sends conflicting precommits): detected, no
  conflicting commit.
- Node restart mid-epoch: state root matches after replay.

### 9.2 Other layers

- **Unit tests:** every state transition, including negative cases (bad nonce,
  insufficient balance, double claim, invalid PoW, early withdraw).
- **Property tests:** signature verification rejects tampering; serialisation
  round-trips; supply never exceeds the cap; sum of accounts is conserved.
- **Fuzzing:** the wire decoder and the block decoder, both of which consume
  untrusted input.
- **Replay test:** rebuild state from genesis and compare Merkle roots.

### 9.3 Honest limits

The simulator cannot catch real-network bugs, clock skew, or genuine hardware
failure. **M4 (real Pis over a real network) is the only test that validates the
transport.** Until M4 passes, the Pi thesis is unproven — say so rather than
implying otherwise.

---

## 10. Milestones and acceptance criteria

| | Deliverable | Acceptance criterion |
|---|---|---|
| **M0** | Repo skeleton, canonical encoding, crypto wrappers, CI | `go test ./...` green |
| **M1** | Single-node chain: state machine, block production, persistence, RPC | `b10coin node --dir D [--http ADDR] [--block-time DUR]` produces and persists blocks; restart replays to the same root (the one-command end-to-end proof is `b10coin devnet --blocks 100`) |
| **M2** | Faucet: Argon2id claim, emission schedule | Coins claimed on devnet; **replayed double-claim and insufficient-PoW claims both fail** |
| **M3** | **BFT consensus** over `SimTransport` | All §9.1 scenarios pass deterministically; safety property holds under partition |
| **M4** | Real networking: `TcpTransport` + relay | Cross-compiled ARM64 binary; **3 validators on real Raspberry Pis across separate networks finalize blocks** |
| **M5** | Staking, committee rotation, admission, `PEER_EXCHANGE` | Nakamoto coefficient plotted across a devnet run; validator set rotates at an epoch boundary |
| **M6** | Wallet CLI, minimal explorer, faucet web UI | A person unfamiliar with the project can claim coins and send a transfer using only the docs |

**M0–M3 yields a chain that is fully understood.** M4 is where the Pi thesis is
proven or falsified.

---

## 11. Risks and open uncertainties

| Risk | Severity | Mitigation / status |
|---|---|---|
| **Faucet PoW farming.** Nano's captcha faucet was farmed; this is the weakest link by historical precedent | High | One claim per key per epoch; memory-hard puzzle; **accepted as a testnet lesson** rather than solved at M2 |
| Simulator misses real-network bugs | Medium | M4 is a hard gate; do not claim Pi viability before it passes |
| Relay is a liveness single point of failure | Medium | Signed messages protect safety; add a second relay before any real use |
| **The "fees only" endgame is unproven.** With no inflation, validator income depends entirely on fee volume that a testnet will not generate | Medium | Accept for testnet; model fee revenue before ever considering mainnet |
| Long-range / weak-subjectivity attacks on staking | Medium | `UNBONDING_BLOCKS` cooldown; document the weak-subjectivity assumption rather than pretending it is solved |
| Concentration despite a "fair" launch. Research on three fair-launch models found concentration occurs in **all** of them, driven by tradability itself | High | Out of scope for a testnet with valueless coins; **revisit before any mainnet** |
| Zig pre-1.0 churn (only if Zig is chosen over Go) | Medium | Pin the exact compiler version |
| AI-authored code silently wrong | High | Deterministic simulation + replay tests; prefer checks that catch *silent* wrongness over checks that catch crashes |

---

## 12. Legal note

b10coin is a **testnet with valueless coins and no sale**, which keeps it almost
entirely outside financial regulation: nothing is offered to the public and
nothing is sold.

If a future mainnet were ever considered, note that under the EU's **MiCA**
regulation an offer of a crypto-asset to the public generally requires a notified
crypto-asset white paper with mandated content (Art. 6). **Art. 4 exempts**
crypto-assets offered for free, via airdrop, or as a reward for validation —
which points the same direction as this design: a coin that is *given away*
rather than *sold* is dramatically simpler than one that is sold. In Romania the
competent authority is the ASF.

Nothing here is legal advice; a mainnet decision requires a lawyer. This is
recorded so the constraint is known at design time rather than discovered later.

---

## 13. References

- Nano, Open Representative Voting — https://docs.nano.org/protocol-design/orv-consensus/
- Chia PoST critique — https://chainscorelabs.com/blog/comparison-of-consensus-mechanisms/alternative-proofs/why-chias-proof-of-space-and-time-is-a-flawed-masterpiece
- Chia farming requirements — https://docs.chia.net/chia-blockchain/consensus/proof-of-space-2.0/new-proof-farming-requirements/
- Fair-launch concentration study (arXiv 2208.10271) — https://ar5iv.labs.arxiv.org/html/2208.10271
- Proof-of-Stake Is a Defective Mechanism — https://eprint.iacr.org/2022/409
- Ethereum slot centralization — https://eprint.iacr.org/2025/219
- CometBFT validators — https://docs.cosmos.network/cometbft/latest/docs/core/Validators
- BFT consensus survey (ACM) — https://dl.acm.org/doi/10.1145/3636553
- BFT consensus survey (MDPI) — https://www.mdpi.com/2079-9292/12/18/3801
- Proof of Useful Work — https://arxiv.org/html/2405.19027v3
- Avalanche node requirements — https://docs.avax.network/docs/nodes/system-requirements
- Avalanche staking on Raspberry Pi — https://medium.com/@nita_bx/avalanche-staking-on-raspberry-pi-4-c4b51ee28974
- Spacemesh PoST — https://docs.spacemesh.io/docs/learn/post
- Kaspa / PHANTOM GHOSTDAG — https://eprint.iacr.org/2018/104.pdf
- Raspberry Pi 5 Bitcoin full node — https://runabitcoinnode.com/why-the-raspberry-pi-5-is-the-best-option-to-run-a-bitcoin-full-node-in-2025/
- Ethereum Pi node tutorial — https://github.com/ethereum/ethereum-org-website/blob/dev/public/content/developers/tutorials/run-node-raspberry-pi/index.md
- TigerBeetle VOPR (deterministic simulation testing) — https://github.com/tigerbeetle/tigerbeetle/blob/main/docs/internals/vopr.md
- Zig new async I/O plan — https://lwn.net/Articles/1046084/
- Zig std.crypto — https://github.com/ziglang/zig/blob/master/lib/std/crypto.zig
- ZigCoin (existence proof of a Zig L1) — https://zeicoin.com/
- btcd: should I use it for a new coin? — https://github.com/btcsuite/btcd/issues/1388
- MiCA Art. 4 (exemptions) — https://www.mica.info/article/4/
- MiCA Art. 6 (white paper content) — https://www.esma.europa.eu/publications-and-data/interactive-single-rulebook/mica/article-6-content-and-form-crypto-asset
- SEC crypto-asset interpretation (Mar 2026) — https://www.sec.gov/files/rules/interp/2026/33-11412.pdf
