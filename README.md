# b10coin

b10coin is a from-scratch, proof-of-stake-style cryptocurrency built for small
computers: the stated target is a validator node on Raspberry Pi class
hardware. There is **no proof-of-work consensus** and **there is no premine**.

Above all: **this is a testnet project. Coins on it are valueless test
currency. There is no sale, no token offering, and there is no mainnet.** The
goal is a chain that is deeply understood, not a market launch — the design
specification is the contract for what b10coin is and what it deliberately is
not (`docs/2026-10-02-b10coin-design.md`: no smart contracts, no privacy
features, no scaling layers, no governance, no token sale, no mainnet launch).

## Why no proof of work?

The design document's own argument (`docs/2026-10-02-b10coin-design.md` §2):
"no PoW because it must run on a Pi" conflates two different jobs. Validating
transactions and storing the chain costs disk and bandwidth, and a Pi does that
fine — a Pi runs a Bitcoin full node today. Producing blocks under
proof-of-work requires ASIC farms, so on a PoW chain a Pi owner could run the
node but could never *earn* the coin. The real objection to PoW is therefore
distributional, and the project puts its difficulty in **issuance and
distribution** rather than in consensus: a capped emission schedule and a
keyless claim faucet, with consensus treated as a solved problem instead of an
invention (Tendermint-style BFT; implemented in M3 — see
[Consensus](#consensus)). The accepted trade-off is the
design's, stated honestly in §3: *permissionless + fairly distributed + no-PoW
— pick two*. b10coin begins federated (genesis validators are hardcoded) with
staking-based admission on the roadmap. Where PoW does survive, in the M2
faucet, it is only a rate limiter on coin claims — tuned so a Pi completes a
claim in seconds — never a consensus mechanism.

## Quick start

Requires Go 1.23+. Two direct external dependencies:
`lukechampine.com/blake3` (v1.4.1) and `golang.org/x/crypto` (v0.41.0, for
Argon2id). From the repository root:

```sh
make build                                # go build -o bin/b10coin ./cmd/b10coin
make test                                 # go test -count=1 ./...
go run ./cmd/b10coin devnet --blocks 100  # the single-node acceptance check
go run ./cmd/b10coin devnet --validators 4 --blocks 100  # the consensus acceptance check
```

`devnet --blocks 100` builds a fresh local chain in a temporary directory,
signs and appends 100 blocks, includes one real transfer transaction, persists
everything to append-only segment files, and reports a reproducible state root
(verified as stable across repeated runs). Since M2 the default run also
exercises the faucet: it solves the Argon2id puzzle for an ephemeral claimant
key and pays one claim from protocol emission, then immediately attempts a
second claim from the same key in the same epoch, which is refused — the
anti-farming rule, proven. Those two extra blocks put the chain at height 102.
It prints:

```text
chain        b10coin-devnet-1
height       102
state root   be1c9e90914d23292d47873727e512a6dd76f6ccb7117b03bae189e9e51837ea
txs included 2
claims paid  1 of 1 attempts, 100000000 sparks each
double claims refused 1 (one claim per key per epoch)
claimant bal 100000000 sparks
faucet bal   5050000000 sparks (emitted 5150000000 sparks in total)
OK
```

and exits 0.

The multi-validator acceptance command runs the same idea as a consensus
committee: four validators, each with its own chain, driven to height 100 over
a deterministic simulated network, and a report of each validator's final
height plus whether the validators hold one history. A single node producing
blocks proves nothing about consensus, so the run fails (no `OK`, exit 1)
unless the validators agree:

```text
$ go run ./cmd/b10coin devnet --validators 4 --blocks 100
chain        b10coin-simnet-4
validators   4
heights      v0=100 v1=100 v2=100 v3=100
agreed       yes
OK
```

## The CLI

`cmd/b10coin` implements five subcommands. With no subcommand, or with an
unknown one, it prints the usage text and exits with code 2.

### `b10coin devnet`

Builds and verifies a self-contained local chain — the milestone acceptance
check (M0–M2), shared by the CLI and the test suite. Since M3 it is also the
consensus acceptance check: `--validators N` swaps the single-node fixture for
a committee of `N` consensus validators driven through the simulated network,
reported per validator, and failing unless the validators hold one history.
The faucet-claim scenario is the single-node path's proof — a committee
accepts no transactions — so `--claims` alongside an explicit `--validators`
is refused rather than silently dropped.

| Flag | Default | Meaning |
|---|---|---|
| `--blocks N` | `100` | number of blocks to produce (must be > 0) |
| `--claims N` | `1` | faucet-claim attempts after the block loop (single-node run only); each paid claim is followed by the same key's same-epoch double claim, which must be refused (a run that sees the double claim applied fails) |
| `--validators N` | *unset (single node)* | committee size; omitting the flag keeps the M0–M2 single-node run as it shipped, and any explicit value — `1` included — runs the consensus committee of that size |
| `--dir PATH` | *fresh temporary directory* | data directory; a temporary one is deleted afterwards, an explicit path is kept (multi-validator runs lay out one chain per validator under `PATH/v0`, `PATH/v1`, …) |

### `b10coin node`

Runs a single-node chain serving HTTP RPC. In M1 a node produced blocks
unilaterally, one block per tick, because a single node needs no agreement;
the consensus engine exists since M3 and is exercised through the
`devnet --validators` runs above, while `node` itself still runs the
single-validator devnet fixture — a real committee of separate processes
needs real networking, which is M4. Nodes currently run the
**devnet** genesis and sign
with a deterministic, public test key that is safe only because devnet coins
are valueless; the testnet genesis has no validator keys yet.

| Flag | Default | Meaning |
|---|---|---|
| `--dir PATH` | `./b10coin-data` | data directory |
| `--http ADDR` | `127.0.0.1:8645` | HTTP RPC listen address |
| `--block-time DURATION` | `2s` | target block interval |

Ctrl-C (or SIGTERM) stops block production and the HTTP server cleanly.

### `b10coin claim`

Solves the faucet puzzle locally and submits one claim to a running node (the
`node` command's default HTTP address is the claim command's default target).
The puzzle's parameters are genesis state, not carried on the wire: the claim
command solves with the compiled-in devnet parameters an M2 node runs, and it
bails out if the node it is talking to runs a different chain.

| Flag | Default | Meaning |
|---|---|---|
| `--node URL` | `http://127.0.0.1:8645` | HTTP RPC of the node to submit the claim to |
| `--dir PATH` | `./b10coin-data` | accepted for uniformity with the other commands, and deliberately **never read**: the claim command reads nothing from disk and writes nothing |

There is **no key file and no keystore**: `claim` signs with an ephemeral
fresh key, and prints that key once — copy it out immediately if you plan a
follow-up transfer, because it cannot be recovered later. The claim is only
queued by this command; the node pays it when its next block applies it.

### `b10coin-relay`

A separate binary (`cmd/b10coin-relay`) — the one component of the network a
stranger can reach. It runs on a cheap public VPS; every home validator dials
**outbound** to it, which is what makes the topology work with no port
forwarding and nothing to do about CGNAT (inbound to a home Pi is blocked,
outbound almost never is). The relay keeps a registry of connected peers and
forwards every frame it receives to every **other** peer. It parses nothing
beyond the frame's 4-byte length prefix — it does not know what a vote is,
and that is the design, not a shortcut.

The trust trade it rests on: every consensus message is signed with the
sender's Ed25519 key, so **a malicious relay can censor or delay, but it
cannot forge a vote or a proposal**. Consensus safety is never at risk from
the relay; only liveness is (a relay that partitions the validator set stalls
consensus, which the round protocol's rebroadcasts and the reconnection
backoff pay for). If that ever stops being acceptable the answer is multiple
relays and direct connections — never a smarter relay, because a relay that
understood consensus would be a relay that could be wrong about it.

Because it authenticates nothing, it binds everything a stranger controls: a
frame whose declared length exceeds the bound is refused before any
allocation and its connection is ended; dials past the connection bound are
closed at accept; every connection buffers at most a bounded write queue, so
a peer that stops reading cannot stall the relay for the others (dropped
frames, never a blocked forwarder); and two socket-level timers bound how
long a connection may *hold* what it has taken — nothing is parsed to enforce
them. The per-frame read timeout (`--read-timeout`, default 120 seconds) is
armed before each frame's 4-byte header and refreshed at every completed
frame, so an actively sending peer is never cut off; when it expires — a
connection that delivered no complete frame for the whole period — the
connection is closed and its registry slot is released the same instant. So a
stranger can pin at most `max-conns × max-frame-bytes` of memory and
`max-conns` of slots, each for at most one read timeout, never forever. TCP
keepalive (`--keepalive`, default 15 seconds) reaps a half-open connection —
a peer that vanished without closing, e.g. a power cut — after the kernel's
unanswered probes, again without the relay looking at any byte. In production
the access policy does not
live in the relay at all — run it behind the VPS firewall allowlisting the
validator IPs. Validators reconnect to a restarted relay with exponential
backoff. Bandwidth is kilobytes per second.

| Flag | Default | Meaning |
|---|---|---|
| `--addr ADDR` | `:7001` | listen address (all interfaces — validators must reach this one) |
| `--max-frame-bytes N` | `1048576` | largest frame any connection may send; a larger declared length ends that connection (keep at or above the validators' own frame bound, or the relay severs mid-sized honest traffic) |
| `--max-conns N` | `256` | maximum simultaneous connections; excess dials are closed at accept and the validator's backoff redials |
| `--write-queue N` | `64` | per-connection buffered frames; a full queue drops new frames for that peer instead of blocking the relay |
| `--read-timeout SECONDS` | `120` | per-frame read deadline: armed before each frame's header, refreshed at every completed frame (an actively sending peer is never cut off); expiry ends the connection and releases its registry slot |
| `--keepalive SECONDS` | `15` | TCP keepalive probe period for every accepted connection; a half-open connection is reaped by the kernel after unanswered probes |

Ctrl-C (or SIGTERM) stops the listener, closes every connection and joins
every goroutine before the process exits.

### `b10coin version` and `b10coin help`

`version` prints the software version (`0.1.0`). `help`, `-h` and `--help`
print the usage text.

## The faucet

M2 adds the faucet — a distribution mechanism — and keeps the promise about
what that mechanism is worth. **This is still a valueless testnet: every coin
the faucet pays is worthless test currency, and there is no sale and no
mainnet.** The faucet itself is governed by the design's no-premine rule: it
is an account derived from the genesis hash, so no private key can spend from
it. Coins enter circulation only through the protocol's claim rule, paid out
of protocol emission.

### The puzzle

A claim transaction carries `(pubkey, epoch, pow_nonce)` and is valid only if
its proof-of-work digest — `Argon2id(pubkey ‖ epoch ‖ pow_nonce)` under the
salt `"b10coin-faucet-pow"`, read big-endian — is strictly below the chain's
32-byte difficulty target. Argon2id is memory-hard, so GPUs and ASICs buy
almost nothing over commodity hardware; the difficulty is chosen so a
Raspberry Pi 4 completes a puzzle in seconds rather than minutes.

**PoW here is a rate limiter, not consensus.** No block is ever produced by
mining: validators (a consensus committee since M3 — one signer in the devnet
fixture, with staked rotation from M5) produce blocks without solving
anything. The puzzle's only job is to throttle how fast one key can drain the
faucet.

The parameters are per-chain genesis parameters, recorded in
`genesis/devnet.json` and `genesis/testnet.json`:

| | Argon2id tuning | Difficulty target |
|---|---|---|
| devnet (fixture) | 64 KiB × 1 iteration × 1 lane | `0x7f` followed by 31 `0xff` bytes — a handful of attempts, so tests and CI stay fast |
| testnet (re-derived) | 8 MiB × 1 iteration × 1 lane | `0x0f` followed by 31 `0xff` bytes — ~16 expected attempts per solve |

The testnet tuning is **derived, not asserted**: the spec's original 64 MiB × 3
pairing was sized for the *claimer*, but validators pay *per claim per block*,
and a block may carry `max_claims_per_block` claims (below), so the worst-case
block costs `8 × per-eval` time. On the spec's Raspberry Pi 4 reference
(≈3 s for 64 MiB × 3 ≈ 15.6 ms per MiB·pass), 8 MiB × 1 lands at ≈0.125 s per
eval: a claimer solves in ≈2.0 s and the worst-case block verifies in ≈1.0 s —
half the 2,000 ms block interval. The trade-off is stated rather than hidden:
8 MiB buys less GPU asymmetry than the spec's 64 MiB would have, but the
puzzle's job here is a per-key rate limit (with the per-epoch marker and the
per-block bound behind it), not mining resistance. The full arithmetic is
recorded in the
`Testnet` constructor's comment, and the tuning, target and bound must be
re-measured together on real hardware before any public testnet opens.

### The emission schedule

- The base unit is the **spark**; `1 b10 = 10⁸ sparks`.
- The reward starts at **0.5 b10 per block** (50,000,000 sparks), paid into
  the faucet account — height 0's genesis mint comes from the same formula.
- It **halves every 21,000,000 blocks** (≈1.33 years at 2 s blocks) and
  reaches zero at halving 26 — emission ends after ≈34.6 years of 2 s blocks,
  and the chain then runs on fees only.
- The **supply cap is 21,000,000 b10** (2.1 × 10¹⁵ sparks).
- The **realized series lands at 20,999,997.48 b10** (2,099,999,748,000,000
  sparks): each halving's shift truncates, losing 252,000,000 sparks (2.52 b10)
  in total. The series therefore falls **2.52 b10 short of the cap** — and it
  can **never exceed the cap**. The cap is a maximum, never a target; the
  shortfall is integer truncation by design, not a bug, and no code path mints
  the difference.

### The anti-farming rule

**One claim per key per epoch.** A paid claim commits an epoch marker
(`ClaimedEpoch`) into the claimant's account as consensus state — it is part
of the state root — and the rule refuses any claim whose marker is not
strictly older than the claim's epoch. A second claim from the same key in the
same epoch is refused even when it is solved and signed exactly like the
first (the default `devnet` run proves this live; see the acceptance output
above). Epochs are 1-based and last 1,000 blocks on devnet and 10,000 on
testnet.

The claim amount is a genesis parameter: the devnet fixture claims **1 b10**
so a short devnet run can fund a claim from emission, and testnet keeps the
spec's **100 b10** (see [Genesis configurations](#genesis-configurations)).
The honest trade-off stands: a determined attacker with many keys is
rate-limited by the puzzle, not prevented — that is what the spec accepted
when it chose a faucet over a premine.

### The per-block claim bound

**A block may carry at most `max_claims_per_block` faucet claims (8 on both
shipped chains). Carrying more makes the block invalid — not merely slow.**
This is a consensus rule, enforced by `state.ApplyBlock` **before any puzzle
is verified**, because of two facts it cannot escape:

- **Validating a claim is expensive per claim.** Every claim in a block costs
  every validator one full Argon2id evaluation — the puzzle's worst case is
  what a validator pays for every block it checks.
- **A block is attacker-chosen input.** `types.MaxTxsPerBlock` allows 10,000
  transactions in a block, and each claim's puzzle must be evaluated before
  that claim can be accepted *or rejected*, so without a bound one malicious
  proposer could pack a block with claims and set every validator's cost by
  the claim count alone — ~10,000 full Argon2id evaluations, about 21 minutes
  of Argon2id work at the testnet tuning, to decide one block. That block
  cannot exist: carrying more than 8 claims makes it invalid, and
  `state.ApplyBlock` rejects it on the count before the first puzzle is
  evaluated, so every validator pays at most 8 evaluations for any block,
  whatever a proposer packs into its bytes.

The bound and the testnet puzzle tuning are derived together so the
worst-case block fits inside a small multiple of the 2,000 ms block interval
(see the table above and the `Testnet` constructor's comment). One scope
note so the two layers are never confused: the mempool's own
`MaxFaucetClaimsPerBlock` — equal to the genesis bound by a pinning test —
protects **the local node only**. It stops this node's pool from assembling
a block the chain would have to reject; it does not protect the chain,
because the pool is local policy. The genesis parameter is what makes the
count a rule every validator enforces, identically.

## Consensus

M3 ships the consensus the design picked from the start: a Tendermint-style
BFT round, run by every validator for every height over the real chain
machinery — proposals, prevotes and precommits are signed, verified and
tallied messages, and a block is committed exactly when the tally says so.
**This is still a valueless testnet: consensus makes the toy chain correct,
not valuable, and there is no sale and no mainnet.**

A round has four phases — **propose → prevote → precommit → commit**. The
proposer for each (height, round) is drawn weighted by voting power and seeded
by `(height, round, parent hash)`, so every validator computes the same
proposer without communication; a round that produces no decision times out
into the next round, with slightly longer timeouts.

Three rules carry the safety, and all three are about the arithmetic of
distrust:

- **A quorum is two thirds of TOTAL voting power — not of online power.**
  Committing (and every unlock, below) needs strictly more than two thirds of
  the power the committee held at genesis. Taking validators offline therefore
  makes committing *harder*, never easier: with four equal validators, three
  must agree, and two cannot. An attacker who silences a third of the set
  lowers nothing — the bar stays pinned to the full committee, offline
  members included.
- **A validator that precommits is locked — and the lock survives a restart.**
  Precommitting block B at height h is a promise: from then on the validator
  prevotes only B (or nothing) at that height. It will not — cannot, within
  the protocol — help commit a conflicting block at the same height, which is
  why two conflicting blocks cannot each collect a quorum unless more than a
  third of the power breaks its promise. The promise is not just memory: it is
  written to the crash-tolerant store the moment the lock moves (before the
  precommit that records it is signed or shipped), and a validator that
  crashes mid-height and restarts re-enters that height still locked, refusing
  a conflicting block exactly as before. A corrupt lock record fails the node
  loudly at startup rather than degrading to "unlocked" — silently re-entering
  unlocked is precisely the unsafe direction. This is what makes the promise
  unconditional: a locked validator stays locked whether or not it restarts.
- **A locked validator unlocks only on evidence.** The one way out is a
  proposal for a conflicting block at a strictly later round that CARRIES its
  proof: a justification of quorum prevotes — verified signatures, counted
  once per validator — showing that block in fact reached two thirds at an
  earlier round. A bare claim that "we moved on" is not evidence; a proposal
  whose claimed justification has no prevotes behind it is refused outright,
  not even nil-prevoted.

The committee in this milestone is the genesis set: equal test validators with
a fixed cap of one quarter of total power each — enforced, for committees of
four or more, by configuration validation, while any smaller committee runs
under a 1/1 cap, because below four equal holders no one-quarter share is
satisfiable. Validator-set changes by stake arrive with M5.

**How this is verified.** The `devnet --validators 4 --blocks 100` acceptance
command above is the milestone's own check — four validators, one history, or
the run fails. Behind it sit the six failure scenarios of the design's
verification plan (`internal/simnet`), every one driven from a fixed seed over
a clock-free simulated network, so a failure replays exactly: the 1,000-block
happy path; one validator powered off while the chain advances at exactly the
two-thirds bar; two offline — below two thirds — so the chain stalls without
forking; a partition healed with the isolated validator left strictly behind,
never forked; a Byzantine validator equivocating on the wire while the
committee still agrees; and a mid-epoch restart whose replayed state root
matches its peers'. M3's honest limits are recorded with the scenarios: a
validator that falls behind cannot catch up yet (block sync is M4's
networking work), and a lost proposal parks a validator permanently, so
liveness scenarios run drop-free. The persisted lock has its own limits,
recorded here rather than hidden: no scenario injects message reordering, so
the restart-time refusal is exercised with in-order delivery only; the
justification gate's unlock path is unreachable from any shipped driver —
honest proposals never carry a polka for a conflicting block, so in
production the gate is refusal-only and the unlock-on-evidence half is
exercised by tests alone; and consensus blocks carry no transactions, so the
claim bound's motivating threat (a proposer stuffing a block with heavy
faucet claims) never arises on the consensus path in M3. None of these are
defects in what M3 built; all three are the boundary of what it claims.

## Architecture

Sixteen Go packages under `internal/` (the simulated transport is one of them,
at `internal/transport/sim`), and the CLI in `cmd/b10coin`. Import direction is
`cmd → devnet → {chain, node, simnet}` — the RPC layer is brought in by `cmd`
alone, not by `devnet` — and
`chain → {store, state, genesis, types, crypto, faucet}`; `types` never imports
`state`, `state` never imports `chain`, `chain` never imports `rpc`, and
`internal/faucet` (the puzzle and emission arithmetic) sits under `state` and
`chain` — it is imported by them and by `devnet` and `cmd`, never the reverse.

| Package | Responsibility |
|---|---|
| `internal/crypto` | BLAKE3 over length-prefixed, domain-separated parts (`HashParts`); order-sensitive binary Merkle root; Ed25519 key generation, signing, verification |
| `internal/types` | Consensus structures (`Address`, `Tx`, `Header`, `Block`) and the canonical binary codec; the decoder rejects short buffers, trailing bytes, and non-minimal varints |
| `internal/state` | Address → account state map; the transfer transition (signature, nonce, balance rules) applied atomically per block on a clone; sorted-leaf Merkle state root; zero-value accounts pruned |
| `internal/genesis` | Protocol parameters, genesis hash and validation, the devnet and testnet configurations, deterministic public dev fixtures, and the keyless faucet address |
| `internal/faucet` | The M2 faucet machinery: the Argon2id claim puzzle (`Solve`, digest construction, target comparison) and the emission schedule (`Reward`, `SeriesTotal`) |
| `internal/store` | Append-only block segment files (1,000 blocks per segment), each record CRC32C-checksummed; a partial trailing record from a crash is truncated on open and a damaged record is reported, never silently dropped |
| `internal/chain` | Owns the canonical chain: validates and appends blocks, replays them on startup — requiring each stored block to claim its stored position and link its predecessor — and verifies the recomputed state root against each committed header; internal state is mutex-guarded for RPC concurrency |
| `internal/mempool` | Bounded, deduplicated set of pending signed transactions, safe for concurrent use, one validation error per transaction |
| `internal/node` | Wires chain and mempool into block production; in M1 one node appends exactly one block per tick, evicting only unapplicable transactions |
| `internal/rpc` | HTTP JSON API: `GET /status` (chain ID, height, head hash, state root, mempool size), `GET /block/{height}`, and `POST /tx` (hex-encoded canonical transaction bytes) |
| `internal/consensus` | The M3 BFT engine: the four-phase round (propose, prevote, precommit, commit), signed vote tallies with one vote per validator, the two-thirds-of-TOTAL-power quorum, precommit locking unlockable only by a verified justification, and the power-cap, proposer-selection and escalation-timeout parameters |
| `internal/transport` | The Transport boundary (Broadcast/OnMessage/Peers) the engine speaks over, so the simulated network and M4's real one are interchangeable |
| `internal/transport/sim` | The deterministic simulated network: seeded latency, jitter, loss, reordering and partitions over a virtual clock |
| `internal/simnet` | N validators over one simulated network, with recording taps, offline and equivocation helpers, and prefix-agreement assertions — the harness the six seeded scenarios drive, and the multi-validator devnet with it |
| `internal/devnet` | The in-process devnet driver used by both the CLI acceptance commands and the tests: the single-node transfer, claim and double-claim-refusal scenario with replay verification, and — since M3 — the multi-validator committee run reporting per-validator heights and agreement |
| `internal/version` | The semantic version constant (`0.1.0`) |
| `cmd/b10coin` | CLI entrypoint: `devnet`, `node`, `claim`, `version`, `help` |

## Key design decisions

1. **Canonical binary encoding, everywhere that gets hashed.** All fixed-width
   integers are big-endian; lengths are minimally-encoded LEB128 varints;
   byte slices are varint-length-prefixed. The decoder rejects short buffers,
   trailing bytes, and padded (non-minimal) varints, so every value has
   exactly one encoding. Nothing hashed or signed ever uses JSON or `gob`,
   and no Go map is ever encoded directly: state leaves are emitted from
   byte-sorted addresses. This is the anti-fork rule from the design's §6.
2. **A block's identity is the hash of its header.** The header commits to
   parent hash, state root, ordered transaction root, timestamp and proposer,
   and the body travels separately — so re-sending a body can never change a
   block's ID (a property pinned by a test).
3. **Ed25519 signatures, BLAKE3 hashing.** Every hashed construction goes
   through `crypto.HashParts`, which length-prefixes each part before hashing
   so different part boundaries can never collide, with separate domain labels
   for transactions, tx IDs, headers, blocks, accounts, genesis and the
   faucet. There are two direct external dependencies: BLAKE3
   (`lukechampine.com/blake3`) and Argon2id (`golang.org/x/crypto`).
4. **A protocol faucet that has no private key.** The faucet address is
   derived as `BLAKE3("b10coin-faucet" ‖ genesis hash)[:20]`: its preimage is
   a chain-wide constant, not a public key, so no Ed25519 signature can ever
   be produced for it. Coins leave it only through the protocol's claim rule
   (M2). A test asserts it is not the address of any nameable public key —
   including the genesis hash reinterpreted as one.
5. **Capped emission whose realized total can never exceed the cap.** The
   base unit is the spark; `1 b10 = 10^8 sparks`. Supply caps at
   21,000,000 b10; the block reward starts at 0.5 b10 and halves every
   21,000,000 blocks, after which the chain runs on fees only.
   `Genesis.Validate` requires the idealized identity
   `InitialRewardSparks × HalvingIntervalBlocks × 2 == TotalSupplySparks`
   (2.1 × 10¹⁵ sparks, comfortably inside `uint64`); the realized series —
   what the shift-truncated rewards actually sum to — totals
   20,999,997.48 b10, 2.52 b10 below the cap, and
   `TestEmissionNeverExceedsTheCap` keeps the cap a maximum, never a target.
6. **Crash-tolerant, append-only block storage.** Blocks are written to
   segment files as length-prefixed, CRC32C-checksummed records. Opening the
   store truncates a partial trailing record — the crash-mid-write case — and
   flags a structurally complete record whose checksum fails as corrupt on
   read rather than silently dropping it. On restart the chain replays all
   blocks from genesis and fails loudly if the recomputed state root diverges
   from a committed header; a replay test closes this loop.

## Genesis configurations

Two configurations ship in `genesis/`, mirroring the design's devnet and
testnet chains. The Go constructors in `internal/genesis` (`genesis.Devnet`,
`genesis.Testnet`) are the source of truth the node runs from — nothing parses
the JSON at runtime, so JSON never enters a hashed path. The JSON files are
**checked records**: `TestGenesisJSONRecordsMatchTheGoConstructors` unmarshals
each one and requires it to agree field-for-field with the corresponding
constructor (`chain_id`, validator and dev-account counts, every `params`
value including the faucet puzzle parameters and difficulty target), so either
copy drifting from the other fails the suite. Both chains share the same
monetary protocol constants: 2,000 ms block time, 21,000,000 b10 supply cap,
50,000,000 sparks (0.5 b10) initial reward, 21,000,000-block halving interval,
1,000 b10 minimum stake, and 2 unbonding epochs. They also share the
**per-block faucet-claim bound of 8 claims** (`max_claims_per_block`), the
consensus rule from [the per-block claim bound](#the-per-block-claim-bound).
The chains differ in these
parameters: epoch length is **1,000-block epochs on devnet, 10,000-block
epochs on testnet**, per the design's §6.3; the faucet claim amount is
deliberately **1 b10 on devnet** (a fixture claim a short devnet run can fund)
and **the spec's 100 b10 on testnet**; and the faucet puzzle is tuned per
chain (trivial on devnet, the re-derived 8 MiB × 1 on testnet — its
derivation is recorded in the `Testnet` constructor's comment). The other
differences are in the table below.

| | `genesis/devnet.json` | `genesis/testnet.json` |
|---|---|---|
| `chain_id` | `b10coin-devnet-1` | `b10coin-testnet-1` |
| Validators | 1, from a deterministic public test key | 0 (validator keys arrive with real networking, M4) |
| Dev accounts | 1 funded account plus 1 zero-balance recipient, for transfers before the M2 faucet exists | **none** |
| Committee size | 1 | 21 |
| Faucet claim amount | 1 b10 (100,000,000 sparks) | 100 b10 (10,000,000,000 sparks) |
| Max claims per block | 8 | 8 |
| Faucet puzzle | Argon2id 64 KiB × 1 iteration × 1 lane, target `0x7f` + 31 × `0xff` | Argon2id 8 MiB × 1 iteration × 1 lane, target `0x0f` + 31 × `0xff` (re-derived with the claim bound; arithmetic in `Testnet`) |

The devnet fixture exists to exercise transfers and the CLI; the testnet
configuration is where the no-premine promise lives:

| Promise | How the code enforces it |
|---|---|
| No premine on testnet | `TestTestnetGenesisHasNoPremine` rejects any funded account in the `genesis.Testnet` constructor — the Go source of truth the node runs from — and `TestGenesisJSONRecordsMatchTheGoConstructors` requires `genesis/testnet.json` to agree field-for-field with it, so a funded entry in the JSON record fails the suite too |
| No key can spend from the faucet | the faucet address is hash-of-genesis, not hash-of-pubkey; the derivation is pinned by a test |
| Emission never exceeds the cap (it lands 2.52 b10 short of it) | `Genesis.Validate` enforces the idealized identity `InitialRewardSparks × HalvingIntervalBlocks × 2 == TotalSupplySparks`, which pins the parameters; the realized truncated series — 20,999,997.48 b10 — is kept under the cap by `TestEmissionNeverExceedsTheCap`, and `TestSupplyCapIsPinned` pins the absolute monetary values, so a proportional "renegotiation" cannot pass |

## Checks

`go test -count=1 ./...` and `go test -race ./...` are green across the test
suite, and `go vet ./...` and `gofmt` are clean on this repository as
committed. CI (`.github/workflows/ci.yml`) runs all three acceptance commands
on every push and pull request as well, on Go 1.23:

| Check | Command |
|---|---|
| Static analysis | `go vet ./...` |
| Test suite | `go test ./...` |
| Build | `go build ./...` |
| Acceptance check, default run | `go run ./cmd/b10coin devnet --blocks 100` |
| Acceptance check, claim variant | `go run ./cmd/b10coin devnet --blocks 100 --claims 1` |
| Acceptance check, consensus committee | `go run ./cmd/b10coin devnet --validators 4 --blocks 100` |

Makefile targets: `make test`, `make build` (produces `bin/b10coin`), `make
vet`, `make fmt`, and `make devnet` (build followed by the acceptance check).

## Status and roadmap

Implemented — modules M0, M1, M2 and M3:

- **M0** — repository skeleton, canonical encoding, crypto wrappers, CI.
- **M1** — single-node chain: account state machine, block production,
  durable persistence and replay, HTTP RPC, and the devnet acceptance check.
- **M2** — faucet: claimable coins from the keyless protocol faucet, paid
  from the capped emission schedule and rate-limited by the Argon2id puzzle
  (one claim per key per epoch). At M2 the consensus path was untouched; M3
  closed the last gap by making the per-block claim count a consensus rule.
- **M3** — Tendermint-style BFT consensus: the four-phase round,
  two-thirds-of-total-power quorum, weighted proposer selection and precommit
  locking unlockable only on evidence, over a deterministic in-process
  simulated network; a block over `max_claims_per_block` faucet claims is
  invalid before any puzzle is verified (the per-block claim bound, derived
  together with the testnet tuning); verified by the six seeded failure scenarios in
  `internal/simnet` — safety under partition, outage and equivocation,
  liveness at and above the two-thirds bar — and by the four-validator
  `devnet --validators 4 --blocks 100` acceptance command.

Pending:

- **M4** — real networking (TCP transport plus a small outbound relay so home
  validators need no port forwarding), cross-compiled ARM64 binaries, and
  validators on actual Raspberry Pis. Block catch-up — letting a validator
  that fell behind adopt its peers' blocks — arrives with real networking
  too.

The design's milestone table defines further stages beyond M4 — staking and
committee rotation (M5), and a wallet CLI with a minimal explorer and faucet
web UI (M6). One honest limitation carries over from the design: until M4
passes, the Raspberry Pi thesis is unproven; the deterministic simulator
cannot catch real-network failures, and only real hardware validates the
transport.

## Documentation

- `docs/2026-10-02-b10coin-design.md` — the full specification: ledger model,
  consensus design, issuance, networking strategy, verification plan,
  non-goals, risks and the legal note.
- `docs/plans/2026-10-02-m0-m1-foundation-single-node.md` — the M0–M1
  implementation plan: tasks, exact interfaces and the acceptance gate.
- `docs/plans/2026-10-02-m2-faucet.md` — the M2 faucet implementation plan:
  the puzzle, the emission schedule, the claim rule and this milestone's
  acceptance gate.
- `docs/plans/2026-10-03-m3-bft-consensus.md` — the M3 consensus
  implementation plan: the engine and its locking rule, the simulated network,
  the six verification scenarios and this milestone's acceptance gate.