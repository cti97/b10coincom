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
invention (Tendermint-style BFT, arriving in M3). The accepted trade-off is the
design's, stated honestly in §3: *permissionless + fairly distributed + no-PoW
— pick two*. b10coin begins federated (genesis validators are hardcoded) with
staking-based admission on the roadmap. Where PoW does survive, in the M2
faucet, it is only a rate limiter on coin claims — tuned so a Pi completes a
claim in seconds — never a consensus mechanism.

## Quick start

Requires Go 1.23+. The only direct external dependency is
`lukechampine.com/blake3` (v1.4.1). From the repository root:

```sh
make build                                # go build -o bin/b10coin ./cmd/b10coin
make test                                 # go test ./...
go run ./cmd/b10coin devnet --blocks 100  # the acceptance check
```

`devnet --blocks 100` builds a fresh local chain in a temporary directory,
signs and appends 100 blocks, includes one real transfer transaction, persists
everything to append-only segment files, and reports a reproducible state root
(verified as stable across repeated runs). It prints:

```text
chain        b10coin-devnet-1
height       100
state root   a86409159fd1afaa312e1e59dcb02edeaf44cbebf55f20b59fad01ed738b9c3e
txs included 1
OK
```

and exits 0.

## The CLI

`cmd/b10coin` implements four subcommands. With no subcommand, or with an
unknown one, it prints the usage text and exits with code 2.

### `b10coin devnet`

Builds and verifies a self-contained local chain — the single M0–M1 acceptance
check, shared by the CLI and the test suite.

| Flag | Default | Meaning |
|---|---|---|
| `--blocks N` | `100` | number of blocks to produce (must be > 0) |
| `--dir PATH` | *fresh temporary directory* | data directory; a temporary one is deleted afterwards, an explicit path is kept |

### `b10coin node`

Runs a single-node chain serving HTTP RPC. In M1 a node produces blocks
unilaterally, one block per tick — there is no consensus yet; agreement between
validators arrives in M3. Nodes currently run the **devnet** genesis and sign
with a deterministic, public test key that is safe only because devnet coins
are valueless; the testnet genesis has no validator keys yet.

| Flag | Default | Meaning |
|---|---|---|
| `--dir PATH` | `./b10coin-data` | data directory |
| `--http ADDR` | `127.0.0.1:8645` | HTTP RPC listen address |
| `--block-time DURATION` | `2s` | target block interval |

Ctrl-C (or SIGTERM) stops block production and the HTTP server cleanly.

### `b10coin version` and `b10coin help`

`version` prints the software version (`0.1.0`). `help`, `-h` and `--help`
print the usage text.

## Architecture

Eleven Go packages under `internal/`, plus the CLI in `cmd/b10coin`.
Import direction is `cmd → devnet → {chain, rpc, node}` and
`chain → {store, state, genesis, types, crypto}`; `types` never imports
`state`, `state` never imports `chain`, `chain` never imports `rpc`.

| Package | Responsibility |
|---|---|
| `internal/crypto` | BLAKE3 over length-prefixed, domain-separated parts (`HashParts`); order-sensitive binary Merkle root; Ed25519 key generation, signing, verification |
| `internal/types` | Consensus structures (`Address`, `Tx`, `Header`, `Block`) and the canonical binary codec; the decoder rejects short buffers, trailing bytes, and non-minimal varints |
| `internal/state` | Address → account state map; the transfer transition (signature, nonce, balance rules) applied atomically per block on a clone; sorted-leaf Merkle state root; zero-value accounts pruned |
| `internal/genesis` | Protocol parameters, genesis hash and validation, the devnet and testnet configurations, deterministic public dev fixtures, and the keyless faucet address |
| `internal/store` | Append-only block segment files (1,000 blocks per segment), each record CRC32C-checksummed; a partial trailing record from a crash is truncated on open and a damaged record is reported, never silently dropped |
| `internal/chain` | Owns the canonical chain: validates and appends blocks, replays them on startup — requiring each stored block to claim its stored position and link its predecessor — and verifies the recomputed state root against each committed header; internal state is mutex-guarded for RPC concurrency |
| `internal/mempool` | Bounded, deduplicated set of pending signed transactions, safe for concurrent use, one validation error per transaction |
| `internal/node` | Wires chain and mempool into block production; in M1 one node appends exactly one block per tick, evicting only unapplicable transactions |
| `internal/rpc` | HTTP JSON API: `GET /status` (chain ID, height, head hash, state root, mempool size), `GET /block/{height}`, and `POST /tx` (hex-encoded canonical transaction bytes) |
| `internal/devnet` | The in-process devnet driver used by both the CLI acceptance command and the tests, including replay verification |
| `internal/version` | The semantic version constant (`0.1.0`) |
| `cmd/b10coin` | CLI entrypoint: `devnet`, `node`, `version`, `help` |

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
   faucet. BLAKE3 is the repository's single direct dependency.
4. **A protocol faucet that has no private key.** The faucet address is
   derived as `BLAKE3("b10coin-faucet" ‖ genesis hash)[:20]`: its preimage is
   a chain-wide constant, not a public key, so no Ed25519 signature can ever
   be produced for it. Coins leave it only through the protocol's claim rule
   (M2). A test asserts it is not the address of any nameable public key —
   including the genesis hash reinterpreted as one.
5. **Capped emission with arithmetic that closes exactly.** The base unit is
   the spark; `1 b10 = 10^8 sparks`. Supply caps at 21,000,000 b10; the block
   reward starts at 0.5 b10 and halves every 21,000,000 blocks, after which
   the chain runs on fees only. `Genesis.Validate` requires
   `InitialRewardSparks × HalvingIntervalBlocks × 2 == TotalSupplySparks`,
   so the schedule sums exactly to the cap (2.1 × 10¹⁵ sparks, comfortably
   inside `uint64`).
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
value), so either copy drifting from the other fails the suite. Both chains
share the same monetary protocol constants: 2,000 ms
block time, 21,000,000 b10 supply cap, 50,000,000 sparks (0.5 b10) initial
reward, 21,000,000-block halving interval, 100 b10 per faucet claim, 1,000 b10
minimum stake, and 2 unbonding epochs. The chains differ in these parameters:
epoch length is **1,000-block epochs on devnet, 10,000-block epochs on
testnet**, per the design's §6.3; the other differences are in the table
below.

| | `genesis/devnet.json` | `genesis/testnet.json` |
|---|---|---|
| `chain_id` | `b10coin-devnet-1` | `b10coin-testnet-1` |
| Validators | 1, from a deterministic public test key | 0 (validator keys arrive with real networking, M4) |
| Dev accounts | 1 funded account plus 1 zero-balance recipient, for transfers before the M2 faucet exists | **none** |
| Committee size | 1 | 21 |

The devnet fixture exists to exercise transfers and the CLI; the testnet
configuration is where the no-premine promise lives:

| Promise | How the code enforces it |
|---|---|
| No premine on testnet | `TestTestnetGenesisHasNoPremine` rejects any funded account in the `genesis.Testnet` constructor — the Go source of truth the node runs from — and `TestGenesisJSONRecordsMatchTheGoConstructors` requires `genesis/testnet.json` to agree field-for-field with it, so a funded entry in the JSON record fails the suite too |
| No key can spend from the faucet | the faucet address is hash-of-genesis, not hash-of-pubkey; the derivation is pinned by a test |
| Emission closes exactly at the cap | `Genesis.Validate` enforces `InitialRewardSparks × HalvingIntervalBlocks × 2 == TotalSupplySparks`; `TestSupplyCapIsPinned` pins the absolute monetary values, so a proportional "renegotiation" cannot pass |

## Checks

`go test -count=1 ./...` and `go test -race ./...` are green across all eleven
test packages, and `go vet ./...` and `gofmt` are clean on this repository as
committed. CI (`.github/workflows/ci.yml`) runs the same core three on every
push and pull request, on Go 1.23:

| Check | Command |
|---|---|
| Static analysis | `go vet ./...` |
| Test suite | `go test ./...` |
| Build | `go build ./...` |

Makefile targets: `make test`, `make build` (produces `bin/b10coin`), `make
vet`, `make fmt`, and `make devnet` (build followed by the acceptance check).

## Status and roadmap

Implemented — modules M0 and M1:

- **M0** — repository skeleton, canonical encoding, crypto wrappers, CI.
- **M1** — single-node chain: account state machine, block production,
  durable persistence and replay, HTTP RPC, and the devnet acceptance check.

Pending:

- **M2** — faucet: coins claimable from the protocol faucet at the fixed
  claim amount, rate-limited by an Argon2id proof-of-work puzzle (memory-hard,
  tuned to the order of seconds on a Pi; consensus is unaffected).
- **M3** — Tendermint-style BFT consensus over a deterministic in-process
  simulated network, with safety verified under partitions and equivocation.
- **M4** — real networking (TCP transport plus a small outbound relay so home
  validators need no port forwarding), cross-compiled ARM64 binaries, and
  validators on actual Raspberry Pis.

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