# Security policy

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report through GitHub's private vulnerability reporting on this repository:
`https://github.com/cti97/b10coincom/security/advisories/new`. There is no
separate email channel at this time; the advisory form reaches the maintainers
directly and privately.

Include what you can of: the affected component/package, the commit or release
you tested against, a minimum reproduction (ideally a failing test), and your
judgement of impact. A crash is a finding too if it is reachable from network
or RPC input.

You will get an acknowledgement as fast as the maintainer is online, and a
fix or a written assessment before anything is published. Credit in the
advisory is yours unless you prefer otherwise.

## What is in scope

- **Consensus safety and liveness** (`internal/consensus`): quorum arithmetic,
  locking and justification rules, proposer selection, certificate/sync
  verification — anything by which a stranger or a minority of validators can
  fork the chain, halt the committee, or break the persisted-lock promise.
- **Transaction and state rules** (`internal/types`, `internal/state`,
  `internal/chain`, `internal/mempool`): signature checks, replay and
  chain-identity handling, replay-on-startup integrity, storage integrity
  (`internal/store`), the mempool and RPC as untrusted input paths
  (`internal/rpc`).
- **Network exposure** (`internal/transport/tcp`, `internal/relay`,
  `internal/wire`, `internal/devnet`): frame decoding as untrusted input,
  resource-exhaustion bounds beyond the documented ones, and anything that
  lets a stranger impersonate a validator or corrupt a node's state.
- **Key handling** (`internal/keystore`, the `--key`/`--genesis` node paths):
  key-file permissions and consistency checks, committee membership refusal,
  anything that would let a non-member sign as a member.

## What is out of scope (by design, and documented)

- **Fixture keys are not secret.** The devnet, simnet and the `--validators`
  committee mode derive their private keys from public seeds in this
  repository on purpose; that is how the acceptance runs are reproducible.
  Reports of the form "I derived a fixture key" describe documented behavior,
  not a vulnerability. A node on the fixture path prints a loud warning and
  must never be pointed at a network beyond the operator's own machines.
- **This is a valueless testnet.** There is no sale, no token offering and no
  mainnet; coins cannot be transferred to real value. Reports asking for a bug
  bounty valuation of test coins will be declined.
- **The relay's documented trust trade.** A relay can censor or delay frames;
  the README and `b10coin-relay --help` state the bounds it does put on
  strangers. Reports that the documented bounds are *wrong or bypassable* (a
  pinned slot that is never reaped, memory beyond the stated ceiling) are in
  scope and are exactly the class worth reporting.
- **The relay gate authenticates a ROLE, not an owner.** A node with
  `--relay-access-token-file` reads the relay's greeting, answers an HMAC over
  the relay's per-connection challenge, and expects the accepted frame before
  it registers the link. That defends against a relay started **without** a
  token, and it never puts the token on the wire (a replay of the answer is
  worthless on another connection). It does **not** defend against an attacker
  who controls the endpoint `--relay` names: the node reads frames, not
  provenance, so that endpoint can play the greeting, a challenge of its own and
  the accepted frame, and then keep a link that was never gated. "The relay is
  gated" describes this node's configuration, not who owns the address. The
  gate answer is read under a fixed 32-byte bound (`wire.RelayGateMACBytes`),
  never the 1 MiB frame bound, and the relay still decodes nothing on that path.
  (Audit PX-9: the *frame bound* item is fixed; the endpoint-trust boundary is
  the documented residual.)
- **HELLO admission is a union, and a rotated-out genesis seat keeps it.** A
  transport connection becomes a peer when a signed committee HELLO arrives on
  it; membership is checked against the **union** of genesis, the committee at
  the announced height and the committee at this node's head. The union is what
  lets a rotated-in key reach a node that is still behind the boundary, and a
  peer one boundary behind reach this node; the price is that a **genesis** seat
  that rotation removed keeps *admission* for the life of the node — it can open
  a connection and send bounded traffic forever. It cannot change state: every
  frame still faces the router's per-height membership, and every block is
  adopted only through the certificate gate for its own height. Reports asking
  for a penalty or for "the evicted seat should be disconnected" describe a
  policy this branch documents rather than implements (audit PX-9, RT-3).
- **No slashing, by design.** No code path confiscates or reduces a bond: a
  validator that equivocates, double-signs, or goes offline loses no stake. The
  certificate gate and the tally are what stop a faulty node from contributing.
  For the same fixed-boundary reason, an `Unbond` submitted mid-epoch does not
  remove the seat or its voting duty until the next epoch boundary — the epoch's
  committee is derived from the state at `epoch_blocks·e − 1` and memoised — so a
  leaving validator serves the rest of the epoch with nothing bonded behind it.
  Reports asking for a penalty, a forfeiture, or "the validator should lose its
  stake" describe a protocol change the plan deliberately leaves out of scope;
  the README's Staking section says so.
- The claim command printing its ephemeral key to stdout: documented,
  operator-visible, intentionally.

## Supported versions

Only the default branch's HEAD is supported. This project has no long-term
release branches; a fix lands on the default branch and ships in the next
release build.
## A scheduled govulncheck failure is usually a Go patch release

`go.mod` pins an exact `toolchain` line on purpose (audit finding B-1), so the
version a binary reports and the version CI scans are one source of truth.
Dependabot does not manage the `toolchain` directive, so **every Go patch
release re-creates the failure until someone edits that line**.

Any other failed job on a `schedule` run now files its own issue naming the job
(`test`, `release`, `cross`), so a red cron is never silent; this section is the
govulncheck procedure specifically. Before CI-1, only a govulncheck failure was
reported, and `main` failed its scheduled release for days unnoticed.

If the scheduled `lint` run fails and the findings are all in the **standard
library** (`net/http`, `crypto/...`, `net/url`, ...) with no third-party module
named, the fix is one line:

    toolchain go1.27.3      # was go1.27.2

Then verify locally - **all four** must pass. These are the same four commands
the scheduled-failure issue body lists; keep the two in step:

    go mod tidy && git diff --exit-code go.mod go.sum
    go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...
    GOTOOLCHAIN=go1.26.9 go run honnef.co/go/tools/cmd/staticcheck@v0.8.1 ./...
    go test -count=1 ./...

The staticcheck step is not optional and is pinned on purpose. `staticcheck`
(2026.2.1, module `honnef.co/go/tools` v0.8.1) is the newest release that
exists and its `golang.org/x/tools` reads compiler export data up to version 4,
so a toolchain bump can break it with "export data version 5 is greater than
maximum supported version 4" - an upstream limitation, not a finding about this
code. `GOTOOLCHAIN=go1.26.9` judges the source against the module's language
floor and keeps both gates green; when a staticcheck release reads version 5,
that pin can go.

Push on a branch so the `pull_request` run exercises the full matrix and the
release job's `BUILD-INFO` toolchain assertion.
