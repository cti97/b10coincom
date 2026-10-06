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
- The claim command printing its ephemeral key to stdout: documented,
  operator-visible, intentionally.

## Supported versions

Only the default branch's HEAD is supported. This project has no long-term
release branches; a fix lands on the default branch and ships in the next
release build.