# b10coin adversary analysis: what a relay access token buys an attacker

| | |
|---|---|
| Date | 2026-11-14 |
| Commit | `6f34e6c` (origin/main) |
| Question | Given a valid relay access token and the bootstrap script, can an attacker take over the network? |
| Method | **Local Docker devnet only, loopback only.** A 4-seat committee was stood up through a token-gated relay inside one container, every address `127.0.0.1`, and attacked by a stdlib-only tool that holds the token and does exactly what the token permits at the relay. No third-party host was contacted; no live token was used; the token here was generated for the experiment. |
| Harness | `data/adversary/run.sh` and `data/adversary/attacker/` (gitignored under `/data/`, local-only; the attacker refuses any non-loopback relay). The generated keys, token and chain data were deleted after the run. |

## Scope note

The request as originally phrased was to run the pasted `curl … | sudo … sh` bootstrap against a real public relay at `93.115.53.244:7001` with a live token. That was declined: it executes root-level code aimed at a routable third-party host on the strength of a credential and an authorization claim made in chat, which is indistinguishable from a real attack regardless of intent. This analysis answers the same security question on a devnet where every node is ours, which is both safe and a stronger basis for a finding because every variable is controlled and the result is reproducible.

## Answer, in one line

**The token is relay admission and nothing more. It cannot take over consensus — safety held absolutely under attack — but it hands the holder full control over the network's liveness: a token holder can stall or fully halt the committee at will.** This matches the design's own stated boundary (`docs/2026-10-02-b10coin-design.md` §6.6; `README.md`; `internal/relay/relay.go` package comment): "a malicious relay can censor or delay, but it cannot forge a vote or a proposal. Safety is never at risk from the relay; only liveness is." The experiment confirms both halves empirically.

## Threat model

A holder of the relay access token is an **admitted relay-position actor**. The HMAC challenge-response gate (`internal/wire/relaygate.go`, audits N-8/PX-3/D-1) means the token is the one credential needed to connect to a gated relay; once past it, the holder is a peer in the relay's frame fan-out. The holder does **not** have any committee Ed25519 key: every vote and proposal is signed (`internal/consensus/message.go` `Vote.SigningHash`/`Verify`, keyed by the validator's committee key), and the attacker tool contains no consensus code at all. So the attacker can send and receive frames through the relay, but cannot produce a frame any validator will count.

## What was run and measured

### Baseline — the committee commits through the token-gated relay

Four validators on a committee file, each dialing the relay with the token, no `--listen` (the pure relay-star, home-Pi topology). They committed immediately and in agreement: heights climbed 35 → 324 across all four in 14 s. Relay: `conns=4 forwarded=9159 dropped=0 refused=0 unauthorized=0`. The token gate admitted every honest node (`unauthorized=0`).

### Phase 1 — SAFETY under a token-holder frame flood

The attacker, holding the token, opened 6 connections and flooded 512 KiB frames. The token admitted all of them: the tool reported `opened=6 gated=6 failed=0`, and the relay never counted one as `unauthorized`.

| t (s) | relay `dropped` | committee heights |
|---|---|---|
| before | 0 | 345 / 345 / 345 / 346 |
| +10 | 794,662 | all stuck at 347 |
| +20 | 1,717,013 | all stuck at 347 |
| +30 | 2,123,533 (steady) | 377 / 377 / 377 / **347** |
| +40 | 2,123,533 | 467 / 467 / 467 / **347** |

Two things happened, both important:

- **The flood caused a real liveness stall.** The whole committee froze at height 347 for about 26 seconds while the relay dropped 2.1 million frames: the garbage crowded the consensus frames out of the relay's per-connection write queues. This is the mechanism audit N-1 already recorded from the 10-node run, reproduced here deliberately rather than by accident.
- **The relay's own defense ended it, mostly.** At about t+28 the relay's 30-second per-connection write deadline (`internal/relay/relay.go` `DefaultWriteTimeout`) reaped the wedged flood connections — relay `conns` fell from 10 back to 4 and `dropped` stopped climbing — and three of the four validators resumed on the same chain. The fourth (v3) had fallen too far behind to catch up over the still-busy relay within the window, the laggard dynamic of N-1.
- **Safety was never touched.** Over every sample from all four nodes, the fork check found **no height that ever carried two different block hashes**. The attacker, with the token but no committee key, could stall the chain and drop two million frames but could not forge a block or split the chain. One history throughout.

### Phase 2 — LIVENESS: the token holder fills the relay's connection slots

A fresh relay was started with `--max-conns 5`. The attacker opened 5 hold connections first, filling it (`conns=5`, token accepted). The four honest validators were then started into the full relay:

| Window | heights | relay |
|---|---|---|
| denial (12 s observed) | all **0** | `conns=5 refused=32` |
| attacker stopped → recovery | 0 → 457 in ~30 s | `conns=4` |

While the attacker held the slots, every validator was refused at accept and the chain never started (height 0, relay `refused` climbing to 32 as the validators retried). The node logs name the refusal exactly (the "refused at accept before the gate is announced" path). The instant the attacker disconnected, the slots freed, the committee reconnected on its backoff, and the chain climbed from 0 to 457 in about 30 seconds. **Deterministic, total denial for as long as the token holder chooses to hold the slots.**

## Findings

| # | Severity | Finding |
|---|---|---|
| A-1 | **Informational (by design, confirmed)** | A token holder cannot take over consensus. No forged vote or proposal is possible without a committee key; safety held under a 2.1-million-frame flood with zero forks. This is the design's central claim and it stands. |
| A-2 | **High (liveness)** | A token holder can halt the entire committee by exhausting the relay's connection slots (`--max-conns`). The one credential in the bootstrap command is sufficient; no committee key, no code, no forgery. Recovery requires the attacker to leave or the operator to intervene. |
| A-3 | **High (liveness)** | A token holder can stall the committee and strand validators by flooding frames, until the relay's 30 s write deadline reaps the flood connections. Sustained or reconnecting floods (the attacker reopens as fast as the deadline closes) would make the stall continuous. The relay's defenses blunt it but do not stop a determined, reconnecting flooder. |
| A-4 | **Medium (credential hygiene)** | The deployment uses **one shared token across the whole fleet**, embedded in the bootstrap command (`B10_RELAY_TOKEN=…` in the pasted `sudo sh` line). Any copy of that command — a shell history, a CI log, a screenshot, a chat message — is full relay-access compromise and therefore the A-2/A-3 liveness attack. The token is the single point of compromise for network liveness. |

A-2 and A-3 are the same class the prior audits already flagged at the relay (N-1 bulk-traffic crowd-out, N-2 the `--max-conns`/`--max-conns-per-ip` levers). This experiment confirms they are reachable by an ordinary token holder, not only by the relay operator, and quantifies them.

## Why this is not a "takeover"

Taking over the network would mean deciding what commits: forging votes, committing attacker blocks, forking the chain, or stealing funds. None is reachable from the token:

- **Votes and proposals are signed by committee keys** the attacker does not hold (`internal/consensus/message.go`). An unsigned or wrong-key frame is dropped by every validator's tally before it counts.
- **The relay parses nothing** (`internal/relay/relay.go`): it forwards length-delimited frames and cannot be made to inject consensus state.
- **The fork check proved it:** under the worst flood the chain stayed one history.

So the honest framing of the result: the token is a **liveness kill-switch, not a consensus key.** That is a serious finding for an operator — anyone who leaks the token can take the chain down — but it is categorically weaker than control of consensus, and it is exactly the boundary the design drew.

## Recommendations

1. **Treat the token as a liveness-critical secret and stop embedding it in a shared bootstrap command.** A per-node token (the relay accepts a set of tokens, one per validator, each revocable) turns a single leak into a single revocation instead of a fleet-wide compromise, and lets the operator tell which credential leaked. At minimum, rotate the token on any exposure and keep it out of command lines and logs.
2. **Bound one source's share of `--max-conns`** so a single token holder (or prefix) cannot occupy every slot and lock the committee out (A-2). `--max-conns-per-ip` already does this per prefix; a per-credential or reserved-headroom bound would close the single-token case the gate currently permits.
3. **Rate-limit or evict a connection by drop rate, not only by the 30 s write deadline** (A-3): a flooder that reopens every 30 s keeps the stall continuous. Charging a connection for the frames it causes to be dropped, and refusing a credential that keeps doing it, would make the flood self-limiting rather than self-healing-then-repeating.
4. **Run multiple relays or add direct links** (the design's own M5+ note): a single relay, token-gated or not, is a liveness single point of failure, which is what A-2 and A-3 exploit.
5. **Document the token as a liveness credential**, not only an access control: the current flag help frames it as "who may connect," but the security property it actually guards is "who can halt the chain."

## Reproducibility and cleanup

The harness is `data/adversary/run.sh` and `data/adversary/attacker/main.go`, under the gitignored `/data/` path so it never enters the repo or its history. The attacker is stdlib-only and refuses any relay address that is not loopback. After the run, the generated validator keys, the token file, the built binaries and the chain data directories were deleted; only the two source files remain, locally. Nothing in this analysis touched a host outside the container, and no credential from the original request was used.
