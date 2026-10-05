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

Requires a supported Go — the `go` directive in `go.mod` sets the language
floor (currently **1.26**), and the `toolchain` line names a toolchain
(currently **1.27.1**) which is the **minimum toolchain version the go
command switches to**, not an exact pin: an install older than it downloads
and uses that toolchain automatically (GOTOOLCHAIN=auto, the default); an
installed newer toolchain is kept. Two direct external
dependencies: `lukechampine.com/blake3` (v1.4.1) and `golang.org/x/crypto`
(v0.41.0, for Argon2id). From the repository root:

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
state root   12a643be48c13ffb35d1339e07f2e174346ec110c6c347e206d043a049b3cf54
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

## Platforms and releases

b10coin builds for **six targets, and its test suite compiles for all of
them**: darwin/amd64, darwin/arm64, linux/amd64, linux/arm64, windows/amd64
and windows/arm64. The Raspberry Pi is M4's *acceptance* target (three Pis
across separate networks finalize blocks — the deployment recipe below), not
the only platform the software runs on: a contributor on a laptop builds and
runs the same binaries, on macOS or Windows just as on Linux.

```sh
make release
```

builds **both binaries for every target** into `dist/` — no flags to get
right, no per-platform incantations:

```text
dist/b10coin-0.1.0-darwin-amd64            dist/b10coin-relay-0.1.0-darwin-amd64
dist/b10coin-0.1.0-darwin-arm64            dist/b10coin-relay-0.1.0-darwin-arm64
dist/b10coin-0.1.0-linux-amd64             dist/b10coin-relay-0.1.0-linux-amd64
dist/b10coin-0.1.0-linux-arm64             dist/b10coin-relay-0.1.0-linux-arm64
dist/b10coin-0.1.0-windows-amd64.exe       dist/b10coin-relay-0.1.0-windows-amd64.exe
dist/b10coin-0.1.0-windows-arm64.exe       dist/b10coin-relay-0.1.0-windows-arm64.exe
dist/SHA256SUMS
```

Guarantees a release keeps (all enforced by `scripts/build-release.sh`, the
one build story the Makefile, CI and the deployment wrapper share): the
version comes from `internal/version` — the binary prints it, so file names
cannot disagree with what a binary says; `dist/` starts empty every run and
is swapped in only after everything succeeds — the builds, the architecture
assertions AND the checksums — so a failure at any of those steps leaves no
`dist/` at all to be mistaken for a release; the artifact count must equal
the target count, so a build that silently produced only the host platform
fails instead of shipping a hole; and every artifact is `file(1)`-checked to
report its own architecture — its format and architecture tokens (`Mach-O`,
`ELF` or `PE32+`, plus `x86_64`, `arm64`, `x86-64` or `aarch64`) must appear
wherever they sit in `file`'s output, so the check holds for Apple's `file`
word order ("Mach-O 64-bit executable arm64") and upstream libmagic's ("Mach-O
64-bit arm64 executable", which the Linux CI runners emit) alike, and `Mach-O`
/ `PE32+` names never appear except where they belong. On the target machine,
verify what you copied:

```sh
( cd dist && sha256sum -c SHA256SUMS )    # or: shasum -a 256 -c SHA256SUMS
```

CI (`.github/workflows/ci.yml`) runs a matrix over all six targets on every
push: each one is cross-compiled with `go build ./...` **and** `go vet
./...` — vet, not the build, is what caught this milestone's one
cross-platform defect (a Unix-only syscall in the relay's test code, which
made `GOOS=windows go vet` fail while every build stayed green) — plus a
release job that builds and asserts all twelve artifacts, so no platform can
rot silently and none ships unverified.

## The CLI

`cmd/b10coin` implements six subcommands. With no subcommand, or with an
unknown one, it prints the usage text and exits with code 2.

### `b10coin devnet`

Builds and verifies a self-contained local chain — the milestone acceptance
check (M0–M2), shared by the CLI and the test suite. Since M3 it is also the
consensus acceptance check: `--validators N` swaps the single-node fixture for
a committee of `N` consensus validators driven through the simulated network,
reported per validator, and failing unless the validators hold one history.
The faucet-claim scenario is the single-node path's proof — a committee
accepts no transactions — so `--claims` alongside an explicit `--validators`
is refused rather than silently dropped. The `--validators` committee is the
**fixture committee** (below): every seat's key is derivable from public
seeds, which is exactly what makes these runs deterministic and reproducible
— and what makes it development-only.

| Flag | Default | Meaning |
|---|---|---|
| `--blocks N` | `100` | number of blocks to produce (must be > 0) |
| `--claims N` | `1` | faucet-claim attempts after the block loop (single-node run only); each paid claim is followed by the same key's same-epoch double claim, which must be refused (a run that sees the double claim applied fails) |
| `--validators N` | *unset (single node)* | committee size; omitting the flag keeps the M0–M2 single-node run as it shipped, and any explicit value — `1` included — runs the consensus committee of that size |
| `--dir PATH` | *fresh temporary directory* | data directory; a temporary one is deleted afterwards, an explicit path is kept (multi-validator runs lay out one chain per validator under `PATH/v0`, `PATH/v1`, …) |

### `b10coin keygen`

Generates one real validator key and writes it to a key file with owner-only
permissions (`0600`). The command refuses to overwrite an existing key file —
a careless rerun derives a *different* key, which would orphan the seat the
committee file lists — and prints the **public** key (the value you paste into
the committee file every validator shares) and the key's seat address.

```text
$ go run ./cmd/b10coin keygen --out /var/lib/b10coin/b10coin.key
key file     /var/lib/b10coin/b10coin.key (owner-only 0600; regenerate elsewhere, never over this one)
public key   a4198cc4f3ee076a810f62c3fa58502c3d13a1d5b54ca99a257ba9686c27853c
seat address b10tleywhxwbe7uw54ty57hit34rf2pbjstmhk4j7i
```

| Flag | Default | Meaning |
|---|---|---|
| `--out PATH` | `./b10coin.key` | key file to create; written with owner-only permissions and **never overwritten** (a second run on an existing path fails with `refusing to overwrite`) |

The file is versioned JSON (`private_key`, `public_key`, creation time as
hex key material in owner-readable form). Loading re-derives the public key
and refuses a file whose two halves disagree, and refuses a file readable by
group or others (`chmod 600` fixes it) — a key that leaks its permissions
leaks its votes.

### `b10coin node`

Runs a chain serving HTTP RPC. Without any networking flag it is the M1
single-node producer: the devnet fixture chain, unilateral blocks, the
fixture devnet key — safe only because devnet coins are valueless.

With networking flags (`--peers`, `--relay`, `--listen`), a node joins the
M4 consensus committee over real TCP. **How the committee is named decides
whose keys sign, and that is the security boundary:**

- **`--genesis PATH --key PATH` — the committee of held keys.** `--genesis`
  names a small JSON committee file every validator shares, listing the
  members' **public keys** and powers and the operators' chosen chain ID;
  `--key` names this machine's key file (`b10coin keygen`). A node's seat is
  the position of its public key in that list, and **a node whose key is not
  in the committee refuses to start** with a message naming the problem —
  it never silently signs as a seat it does not hold. Nothing about this
  committee is derivable from the repository, and the chain ID comes from
  the operators: no committee-size is published through it. The committee
  file deliberately carries ONLY the committee section: the rest of the
  genesis is the compiled-in fixture (trivial puzzle, 1 b10 claims), so a
  shared chain remains valueless test currency and its economy cannot be
  rewritten by whoever writes the file. This is the mode the
  [deployment recipe](scripts/deploy/README.md) uses.
- **`--validators N --index I` — the fixture committee, development only.**
  This is the pre-A-1 path kept for local development: every seat's private
  key is derived from the public seed `b10coin-simnet-validator` plus the
  seat number, so **anyone with this repository can sign proposals, prevotes
  and precommits for ANY seat of `b10coin-simnet-N`** — and the chain ID,
  which `/status` reports, publishes the committee size. A node running this
  mode prints a loud warning on stderr; `usage()` says the same; the deploy
  recipe forbids it on any reachable network. It exists so the M3/M4
  acceptance commands keep running unchanged with their legitimate,
  deliberately-public fixture keys.

| Flag | Default | Meaning |
|---|---|---|
| `--dir PATH` | `./b10coin-data` | data directory |
| `--http ADDR` | `127.0.0.1:8645` | HTTP RPC listen address (loopback-only by default; keep it that way) |
| `--block-time DURATION` | `2s` | target block interval (single-node producer only; refused with networking) |
| `--genesis PATH` | *unset* | shared committee file listing the validators' public keys; giving it runs the consensus committee that file names |
| `--key PATH` | *unset* | this validator's key file (`b10coin keygen`); **required with `--genesis`**, refused elsewhere — a key that is not in the committee refuses to start |
| `--peers ADDR,...` | *unset* | comma-separated peer addresses to dial (committee mode) |
| `--relay ADDR` | *unset* | the dumb forwarder relay to dial (committee mode), through the transport's relay mode: the connection announces its own ID and reads nothing back, is registered under the fixed name `relay:<addr>`, and reconnects with backoff — no frame the relay forwards can name, duplicate, or silence it (audit N-1) |
| `--listen ADDR` | *unset* | P2P listen address for direct connections (committee mode) |
| `--validators N` | *unset* | fixture committee size — development only, see the security note above |
| `--index I` | *unset* | fixture seat number — development only |

Ctrl-C (or, on Unix, SIGTERM) stops block production and the HTTP server
cleanly. The graceful stop listens for both through one cancellation
channel, so on Windows — where SIGTERM is a POSIX signal that is never
delivered — Ctrl-C still reaches the same clean path.

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

The trust trade it rests on: every consensus message is signed with a key
its sender actually holds, so **a malicious relay can censor or delay, but
it cannot forge a vote or a proposal**. Consensus safety is never at risk from
the relay; only liveness is (a relay that partitions the validator set stalls
consensus, which the round protocol's rebroadcasts and the reconnection
backoff pay for).

**That trade holds only for committees of held keys** — validators started
with `--genesis` (the shared committee file of public keys) and `--key`
(`b10coin keygen`), above. It does **not** hold for the development fixture
committee (`--validators/--index`), whose keys are derived from public seeds
anyone with this repository can reproduce: with a fixture committee, anyone
can be every validator, and no property of the relay matters because forging
needs no relay at all. That is why the deployment recipe's firewall step
allowlists the validators' IPs and why the fixture committee must never reach
a publicly reachable relay. If relay-only trust ever stops being acceptable
the answer is multiple relays and direct connections — never a smarter relay,
because a relay that understood consensus would be a relay that could be
wrong about it.

Because it authenticates nothing, it binds everything a stranger controls,
with **structural bounds only** (byte budgets, socket deadlines, endpoint
counts — the relay parses the frame length and nothing beyond it): a frame
whose declared length exceeds the bound is refused before any allocation and
its connection is ended; dials past the connection bound are closed at
accept, in total (`--max-conns`) and per source **prefix**
(`--max-conns-per-ip` — IPv6 `/64`, IPv4 `/24`, so one routed prefix cannot
rotate addresses past the cap); every connection buffers at most a bounded
**byte** queue (`--write-queue-bytes`) **and** a bounded frame count
(`--write-queue-frames`, because a byte budget cannot bound the queue's
per-frame entry memory when the smallest legal frame is one byte), so a peer
that stops reading cannot stall the relay for the others (dropped frames,
never a blocked forwarder) and cannot occupy more than its allowance of
another connection's queue — the allowance is the sender's equal share of the
**receiver's own queue capacity** (`limit/senders`, over the sender accounts
registered for it) once another account is actually holding bytes, and the
**whole budget** while none is. A lone sender — even among registered peers
that are not sending — therefore uses the whole queue and loses nothing while
the receiver has room; a sender that is actually sharing the queue is held to
its equal share, and its allowance is never below `limit/senders`, so a host
that queues frames cannot crowd another account below that share, nor displace
bytes that account already holds (queued bytes are only removed by that
receiver's writer). The share is keyed on the
**sender's source group**, not the connection, so two connections from one host
share one account and cannot split a receiver's budget between them. The
residual is stated rather than glossed: a flooder that fills the queue
*before* another sender has queued anything can still occupy all of it, and
that late sender's frames drop until the backlog drains; a receiver too slow
to drain it is ended by the write timeout below, which is what bounds the pin.
And two socket-level timers
bound how long a connection may *hold* what it has taken — nothing is parsed to
enforce them. The per-frame read timeout (`--read-timeout`, default 120
seconds) is armed before each frame's 4-byte header and refreshed at every
completed frame, so an actively sending peer is never cut off. The write
timeout (`--write-timeout`, default 30 seconds) is anchored to the instant a
connection's queue became **non-empty**: the backlog must drain back to empty
inside it, so a sink that never reads is ended — **keepalive frames refresh
only the read deadline, so the write deadline is what bounds a sink's pin** —
and so is a sink that merely reads too slowly for the backlog to clear, which
a per-write deadline alone never caught because each individual write
"succeeded". A peer that drains as it goes empties its queue constantly and
is never cut off.

**The memory arithmetic, derived rather than asserted.** One connection can
hold, at one instant, at most: its write-queue **payload** budget
(`write-queue-bytes`); its write-queue **entry ring**, at most
`write-queue-frames` entries of 32 bytes each; the single frame in its
writer's hand (≤ `max-frame-bytes`); and the single frame in its reader's
hand (≤ `max-frame-bytes`); the aggregate over the registry is therefore
`max-conns × (write-queue-bytes + write-queue-frames × 32 + 2 × max-frame-bytes)`.
At the defaults:
**32 × (2 MiB + 4096 × 32 B + 2 × 1 MiB) = 32 × 4.125 MiB = 132 MiB**. (Two
earlier claims on this spot were wrong. The first omitted the write-queue
factor entirely: 256 conns could each queue 64 *frames* × 1 MiB = 64 MiB —
**16 GiB**, not the 256 MiB documented — and hold it *indefinitely*, a sink
that never reads having no write deadline to end it. The second omitted the
queue's **per-frame entry cost**, so a 2 MiB byte budget admitted ~2 million
one-byte entries: 8 connections from one source IP measured **231.6 MiB** of
heap and the full registry over **1 GiB**, against a documented 128 MiB, and
`MemoryMax=256M` was 4× too small. This derivation has all three terms, the
frame cap is what bounds the entries structurally, and
`relay.Options.MaxPinnedBytes` computes exactly it from the option fields.)
`--max-conns-per-ip` additionally bounds slots per source prefix, and TCP
keepalive (`--keepalive`, default 15 seconds) reaps a half-open connection —
a peer that vanished without closing, e.g. a power cut — after the kernel's
unanswered probes, again without the relay looking at any byte. In production
the access policy does not live in the relay at all — run it behind the VPS
firewall allowlisting the validator IPs. Validators reconnect to a restarted
relay with exponential backoff. Bandwidth is kilobytes per second.

| Flag | Default | Meaning |
|---|---|---|
| `--addr ADDR` | `:7001` | listen address (all interfaces — validators must reach this one) |
| `--max-frame-bytes N` | `1048576` | largest frame any connection may send; a larger declared length ends that connection (keep at or above the validators' own frame bound, or the relay severs mid-sized honest traffic) |
| `--max-conns N` | `32` | maximum simultaneous connections; excess dials are closed at accept and the validator's backoff redials |
| `--max-conns-per-ip N` | `8` | how many of those slots one source **prefix** may hold — the IPv6 `/64` or IPv4 `/24`, IPv4-mapped IPv6 unmapped, masked — so a routed prefix cannot bypass the cap by rotating addresses; a dial from a prefix at its cap is closed at accept |
| `--write-queue-bytes N` | `2097152` | per-connection write-queue budget in **payload bytes** (floored at `--max-frame-bytes`); a full queue drops new frames for that peer instead of blocking the relay, and no single **sender source group** may occupy more than its contention-relative allowance — its equal share of the queue budget (`limit/senders`) once another account holds bytes there, and the whole budget while none does, so a lone sender uses the whole budget, a sharing sender is held to its share, and two connections from one host share one account. Residual: a flooder that fills the queue before another sender queues anything can occupy all of it until the write timeout reaps a slow receiver |
| `--write-queue-frames N` | `4096` | per-connection write-queue bound in **frames**: the entry ring, so the queue's per-frame memory is structural (a byte budget alone admits ~2 million one-byte entries). Counted into `relay.Options.MaxPinnedBytes` at 32 bytes each |
| `--write-timeout SECONDS` | `30` | per-connection write deadline, anchored to when the queue became non-empty: the backlog must drain to empty within it, so a never-reading sink **and** a slow-reading one are ended and their queued bytes and entry ring released |
| `--read-timeout SECONDS` | `120` | per-frame read deadline: armed before each frame's header, refreshed at every completed frame (an actively sending peer is never cut off); expiry ends the connection and releases its registry slot |
| `--keepalive SECONDS` | `15` | TCP keepalive probe period for every accepted connection; a half-open connection is reaped by the kernel after unanswered probes |

Ctrl-C (or, on Unix, SIGTERM) stops the listener, closes every connection and
joins every goroutine before the process exits. Same as the node command: one
cancellation channel serves both signals, so Windows' Ctrl-C reaches the same
graceful drain.

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
  reaches zero at halving 26 — emission ends after ≈34.6 years of 2 s blocks.
  A transfer must then pay the chain's minimum **fee**, a signed field of the
  transaction body (`params.min_fee_sparks`, 1 spark on both shipped chains);
  the fee is **burned** today, because the protocol has no proposer-reward
  rule yet, so "runs on fees only" describes the schedule, not a distribution
  rule the code already implements.
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
| `internal/types` | Consensus structures (`Address`, `Tx`, `Header`, `Block`) and the canonical binary codec; the decoder rejects short buffers, trailing bytes, and non-minimal varints. A transaction's signed body carries its **fee** and is bound to a **chain identifier** (the genesis hash), so one transaction is not valid on two chains |
| `internal/state` | Address → account state map; the transfer transition (chain-binding signature, nonce, minimum fee, balance rules, amount+fee overflow) applied atomically per block on a clone; the fee is burned; sorted-leaf Merkle state root; zero-value accounts pruned |
| `internal/genesis` | Protocol parameters, genesis hash and validation, the devnet and testnet configurations, deterministic public dev fixtures, and the keyless faucet address |
| `internal/faucet` | The M2 faucet machinery: the Argon2id claim puzzle (`Solve`, digest construction, target comparison) and the emission schedule (`Reward`, `SeriesTotal`) |
| `internal/store` | Append-only block segment files (1,000 blocks per segment), each record framed by a **checksummed fixed-width header** (length plus its CRC32C) and a trailing CRC32C over the length and payload, with the lock log and the commit-certificate log framed the same way; a torn trailing record is truncated on open, and a complete record whose checksum fails stops the scan and fails open, never silently dropped |
| `internal/chain` | Owns the canonical chain: validates and appends blocks, replays them on startup — requiring each stored block to claim its stored position and link its predecessor — and verifies the recomputed state root against each committed header; internal state is mutex-guarded for RPC concurrency |
| `internal/mempool` | Bounded, deduplicated set of pending signed transactions, safe for concurrent use, one validation error per transaction |
| `internal/node` | Wires chain and mempool into block production; in M1 one node appends exactly one block per tick, evicting only unapplicable transactions |
| `internal/rpc` | HTTP JSON API: `GET /status` (chain ID, height, head hash, state root, mempool size), `GET /block/{height}`, and `POST /tx` (hex-encoded canonical transaction bytes) |
| `internal/consensus` | The M3 BFT engine: the four-phase round (propose, prevote, precommit, commit), signed vote tallies with one vote per validator, the two-thirds-of-TOTAL-power quorum, precommit locking unlockable only by a verified justification, and the power-cap, proposer-selection and escalation-timeout parameters. M4 adds BLOCK_SYNC catch-up and a certificate log: a commit certificate is persisted to the data directory, so a restarted validator still serves the evidence for blocks it adopted before it restarted |
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
   21,000,000 blocks, after which the chain's income is transaction fees — a
   signed field of the transaction body, floored by `params.min_fee_sparks`
   and burned for now, because no proposer-reward rule exists yet.
   `Genesis.Validate` requires the idealized identity
   `InitialRewardSparks × HalvingIntervalBlocks × 2 == TotalSupplySparks`
   (2.1 × 10¹⁵ sparks, comfortably inside `uint64`); the realized series —
   what the shift-truncated rewards actually sum to — totals
   20,999,997.48 b10, 2.52 b10 below the cap, and
   `TestEmissionNeverExceedsTheCap` keeps the cap a maximum, never a target.
6. **Crash-tolerant, append-only block storage.** Blocks are written to
   segment files as records with a fixed-width, checksummed header — the
   payload length and the CRC32C of that length — followed by the payload and
   a CRC32C over both. The length's own checksum is what lets the scanner
   trust a length *before* using it to find the record's end; without it a
   single flipped bit in a length prefix was indistinguishable from a crash,
   and "repairing" the file truncated committed blocks. Opening the store
   truncates only what a crash can leave (the file ending inside a record) and
   otherwise stops at the first damaged record and fails loudly, never
   dropping it silently. On restart the chain replays all blocks from genesis
   and fails loudly if the recomputed state root diverges from a committed
   header; a replay test closes this loop. The lock log and the
   commit-certificate log use the same framing, so a lock promise and a
   certificate survive a restart the same way a block does.

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
consensus rule from [the per-block claim bound](#the-per-block-claim-bound),
and the **minimum transfer fee of 1 spark** (`min_fee_sparks`), which makes a
zero-fee transfer invalid on both chains.
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
| Min fee per transfer | 1 spark | 1 spark |
| Faucet puzzle | Argon2id 64 KiB × 1 iteration × 1 lane, target `0x7f` + 31 × `0xff` | Argon2id 8 MiB × 1 iteration × 1 lane, target `0x0f` + 31 × `0xff` (re-derived with the claim bound; arithmetic in `Testnet`) |

The devnet fixture exists to exercise transfers and the CLI; the testnet
configuration is where the no-premine promise lives:

| Promise | How the code enforces it |
|---|---|
| No premine on testnet | `TestTestnetGenesisHasNoPremine` rejects any funded account in the `genesis.Testnet` constructor — the Go source of truth the node runs from — and `TestGenesisJSONRecordsMatchTheGoConstructors` requires `genesis/testnet.json` to agree field-for-field with it, so a funded entry in the JSON record fails the suite too |
| No key can spend from the faucet | the faucet address is hash-of-genesis, not hash-of-pubkey; the derivation is pinned by a test |
| Emission never exceeds the cap (it lands 2.52 b10 short of it) | `Genesis.Validate` enforces the idealized identity `InitialRewardSparks × HalvingIntervalBlocks × 2 == TotalSupplySparks`, which pins the parameters; the realized truncated series — 20,999,997.48 b10 — is kept under the cap by `TestEmissionNeverExceedsTheCap`, and `TestSupplyCapIsPinned` pins the absolute monetary values, so a proportional "renegotiation" cannot pass |

## Deploying to Raspberry Pis

M4's acceptance is real hardware, and the linux/arm64 release is where the
full matrix meets it: `make release` produces the six targets above, of which
`b10coin-*-linux-arm64` is the pair a 64-bit Raspberry Pi OS runs — and
`scripts/deploy/build.sh` is the deployment-facing wrapper for exactly that
pair: it runs the same release script with `--only linux/arm64` and copies
the result into `bin/` under the names the recipe's scp lines use, so a
version bump never breaks the recipe (and
`scripts/deploy/build.sh linux/amd64` produces the relay an amd64 VPS wants —
see its §2). CI (`.github/workflows/ci.yml`) runs the release build for every
target and asserts every artifact on every push, so the Pi binary cannot rot
silently. The version the binaries print comes from `internal/version`; no
build-flag override adds a second source of truth. The Pi is the *acceptance*
target of this milestone — the other five targets build, vet and release
alongside it, per [Platforms and releases](#platforms-and-releases).

The full recipe — three Pis on separate home networks plus one relay VPS,
build → copy → shared genesis → first contact → systemd units → what output
means success, then the three likeliest failures and how to tell them apart —
lives in [`scripts/deploy/README.md`](scripts/deploy/README.md).

After the Pis are running, the acceptance run itself becomes one command:

```sh
scripts/deploy/acceptance.sh --pis pi-a.local,pi-b.example.net,pi-c.example.net --relay relay.example.net
```

It reads each validator's loopback RPC over SSH, takes two `/status` readings
15 s apart, and prints one pastable verdict with exit code. It fails — for a
different, named reason and a different exit code — when a validator is
**UNREACHABLE** (exit 1), when all are reachable but no height moved
(**STALLED**, exit 2: relay down or no quorum), when they are advancing on
**different chains or different blocks** (**DISAGREE**, exit 3: the chain-ID
or shared-`--index` failures, never reported as a pass), or when the relay's
TCP port alone is unreachable (**RELAY**, exit 4 — named as its own failure,
with the caveat that the probe runs from the machine invoking the script).
The rule it enforces: agreeing-by-hash while stalled proves nothing, so a
PASS requires every height to have *increased* **and** all validators to name
the identical block at one height. See `scripts/deploy/README.md` §7.

## License

MIT — see [LICENSE](LICENSE). **This license is a decision still open for
review**: it was chosen as the most permissive reasonable option among the
audit's suggestions (MIT, Apache-2.0, BSD-3) so the multi-platform
participation goal — anyone may legally run, copy and redistribute a node —
holds by default, and because a from-scratch educational codebase gains
little from Apache-2.0's patent-grant machinery at this stage. If the
maintainers want the explicit patent grant for a public crypto codebase,
switching to Apache-2.0 is a one-file change; the point is that it is a
decision to make deliberately, not a default to be buried in a commit.

## Reporting a vulnerability

See [SECURITY.md](SECURITY.md): GitHub private security advisories, scope and
non-goals. In particular: the fixture keys are public by design, and this is
a valueless testnet.

## Checks

`go test -count=1 ./...` and `go test -race ./...` are green across the test
suite, and `go vet ./...`, `gofmt`, `staticcheck` and `govulncheck` are clean
on this repository as committed. CI (`.github/workflows/ci.yml`) runs all
three acceptance commands on every push and pull request as well, on the
toolchain go.mod pins: currently Go 1.27.1 over language version 1.26.

| Check | Command |
|---|---|
| Static analysis | `go vet ./...` |
| Lint gate (the `lint` job) | `gofmt -l cmd internal` (must print nothing); `go mod tidy` (must leave no diff); `staticcheck` pinned to module version v0.8.1 (release 2026.2.1); `govulncheck` pinned to v1.8.0 — both run via `go run tool@version` so they never enter go.mod |
| Test suite | `go test ./...` |
| Build | `go build ./...` |
| Cross-platform, per target | `GOOS=<os> GOARCH=<arch> go build ./...` and `go vet ./...` for each of the six targets (the matrix job) |
| Release, all six targets | `make release` (12 artifacts + `SHA256SUMS`, all asserted) |
| Acceptance check, default run | `go run ./cmd/b10coin devnet --blocks 100` |
| Acceptance check, claim variant | `go run ./cmd/b10coin devnet --blocks 100 --claims 1` |
| Acceptance check, consensus committee | `go run ./cmd/b10coin devnet --validators 4 --blocks 100` |

Actions in CI are pinned to commit SHAs, not mutable tags, and the whole
workflow's token is scoped to `contents: read`
(`.github/workflows/ci.yml`); Dependabot watches Go modules and GitHub
Actions weekly (`.github/dependabot.yml`).

Makefile targets: `make test`, `make race`, `make build` (produces
`bin/b10coin`), `make release` (both binaries for all six targets into
`dist/` with `SHA256SUMS` — [platforms](#platforms-and-releases)), `make
vet`, `make fmt`, and `make devnet` (build followed by the acceptance
check).

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
  validators need no port forwarding), release builds for all six OS/arch
  targets (macOS, Linux and Windows — see
  [Platforms and releases](#platforms-and-releases)), and validators on
  actual Raspberry Pis. Block catch-up — letting a validator that fell behind
  adopt its peers' blocks — arrives with real networking too.

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
