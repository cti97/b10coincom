# Decisions: S-2 (no transaction gossip) and S-3 (claim's devnet gate)

**Starting commit:** `b668768c81ff1aa210c02b3194a54e3577f3cb70` ("test: make the
N-1 reserved-lane loss pin deterministic"), branch `testrun-2026-11-06-fixes`.
**Findings:** `docs/testrun-2026-11-06-main-10nodes-docker.md`, S-2 and S-3 (and
the small items W-1, W-2, N-2 that point at the same surfaces).
**Nature:** both are product decisions, not defects in an isolated line. This
file records what was verified, what was decided, and what was deliberately not
done, before the code changed.

---

## S-2 · Transactions are not gossiped

### Verified, and the report is right

- **The wire carries no transaction.** `internal/wire/message.go` defines
  `MsgHello`, `MsgBlockSyncReq`, `MsgBlockSyncResp` and `MsgPeerExchange`; the
  consensus union beside it is `MsgProposal`, `MsgPrevote` and `MsgPrecommit`
  (`internal/consensus/message.go`). A transaction has no message type at all.
- **A block is built from the LOCAL pool only.** `consensus.Driver.build` calls
  `d.pool.Take(types.MaxTxsPerBlock)` and hands the batch to
  `chain.SelectApplicable`; nothing else feeds a proposal. So a transaction
  reaches a block only through the node that holds it, and only in a round where
  that node is the proposer.
- **A seated node therefore waits for its own proposer turn** (one height in the
  committee size, so roughly one in ten at ten seats).
- **An unseated node's pool never feeds a block**, because the driver is never
  asked to propose: the committee at each height decides who proposes, and a key
  that is not in it is never that node. The transaction is admitted with a txid
  and stays in that node's pool. That is exactly the observed 400-block `Unbond`.

The mechanism is as reported: no gossip, so transaction locality is a property
of the design, not a bug in it. **This is not a defect to patch silently.**

### Considered

1. **Document it.** Say that a transaction reaches the chain only through the
   node it was posted to, that an unseated node's pool is a dead end, and that
   an operator must post to a seated validator. No protocol change.
2. **Add gossip.** A new wire message, with a version story (this branch has
   already taken two coordinated signed-body forks), a cross-peer dedup story,
   an amplification bound, and a decision about how much a received transaction
   is trusted before its signature is checked.
3. **Make the failure loud.** No gossip, but `POST /tx` tells the client when
   the node it is talking to holds no seat.

### Decided: (1) + (3). Not (2).

**Why not (2).** A gossip layer is a protocol change on a branch whose protocol
story is already two signed-body forks deep, and every one of its four costs is
a way to introduce a liveness bug: a peer receiving a transaction it did not
sign for has to re-run the whole admission policy against its own head (nonce,
fee, bond arithmetic, the claim pool's per-epoch rule), the amplification bound
is the pool size times the peer count in the worst case, and the answer to
"trusted before the signature is checked" is "never" - which means the receiving
node's `mempool.Add` is the only gate and the forwarder adds nothing but
latency. None of that is needed to fix the reported harm, which is *silence*:
an operator posted an `Unbond`, read a txid, and waited 400 blocks.

**What (3) reports.** `POST /tx` still answers **200** for an admitted
transaction - it was admitted, and the reply must not lie about that - and adds:

- `"seated": false` -
- `"warning": "..."` naming the height it judged and what the pool now means.

Nothing is emitted when the server has no signing key to check (a test or an
embedded server); a real node always supplies one. The CLI (`send`, `stake`,
`unstake`, `withdraw`, `claim`) prints the node's warning and keeps the txid, so
"accepted" is no longer read as "will be included".

The check is `chain.IsSeatedAt(head+1, key)`: the chain's own read lock, the
same memoised epoch set consensus uses, no new lock and no copy (it is the
method the router calls per vote, audit RT-6). Asking about **head+1** rather
than head is the honest question - the pool can only reach a block at a height
that has not been decided yet, and at an epoch boundary the seat that matters is
the *next* epoch's. The answer cannot be a stale read: an epoch's set is a pure
function of the state at `epoch*E - 1`, which is committed by the time that
epoch can be asked about, and it never changes afterwards, so a commit racing
the reply can only make it newer than the height it names, never wrong for that
height. When the chain cannot derive a committee at all, the reply says that
instead of blaming the key: `CommitteeAt` distinguishes the two, and
`IsSeatedAt` deliberately does not.

**The residual, stated rather than fixed.** A seated node still waits for its
proposer turn; that is consensus, not a bug. And the pool of an unseated node
still accepts (and holds) what is posted to it. (3) makes the dead end audible,
it does not route around it.

---

## S-3 · `claim` refuses every chain that is not the devnet

### Verified

Both paths refuse:

- `cmdClaim` (ephemeral) compares `status.ChainID` with `genesis.Devnet().ChainID`;
- `claimWithKey` compares the chain ID **and** the node's `genesis_hash`.

The report's reproduction (rc=1, `runs chain "…", not the devnet genesis
"b10coin-devnet-1"`) is right.

### What the gate was protecting

Three things, and only the second is a real protection:

1. **The puzzle's tuning is genesis state.** A claim is solved with
   `FaucetPowArgon2` (memory / iterations / parallelism) and `FaucetPowTarget`,
   and the chain re-derives the digest with ITS parameters
   (`state.applyFaucetClaim`). Solving against the wrong tuning produces a claim
   the chain refuses.
2. **The signature binds a genesis hash.** `types.Tx.SigningHash` is taken over
   the genesis hash, and `mempool.Add` verifies it against the chain's own. A
   claim signed over a hash the node does not run is a dud on that node - and,
   worse, a *valid* claim on whichever chain that hash belongs to. "Never sign
   for a genesis you did not read" is the same rule audit W-1 established.
3. **The epoch is derived from `EpochBlocks`.** `cmdClaim` used the compiled-in
   devnet value while `claimWithKey` used the node's.

### The fact that decides it

**Every chain a shipped node can open carries `genesis.Devnet()`'s parameters.**
The three ways to make a chain are:

- `genesis.Devnet()` - the fixture, and the single-node producer;
- `simnet.Committee(n)` - which starts from `genesis.Devnet()` and overrides
  only the chain ID, the validator list and the committee size;
- `genesis.ParseCommitteeJSON` - which starts from `Devnet()` and overrides only
  the chain ID, the validator list and the seat count, deliberately keeping the
  monetary and puzzle parameters (`DevAccounts` is nil: no premine).

The only parameter that can differ is `EpochBlocks` (`--epoch-blocks`), and
`/status` already reports it. `genesis.Testnet()` - the one genesis with a
different Argon2id tuning - has **no CLI entry point**: nothing outside its own
definition and its tests constructs it.

So the gate's stated reason ("the puzzle parameters are genesis state, and this
command holds only the devnet's") is true of the tuning but does **not** apply
to any chain the CLI can reach: the tuning it holds is the tuning those chains
run. What the gate actually did was refuse on the *chain ID string*, which
differs from the devnet's on every committee-file and simnet chain while the
parameters behind it are identical.

### Decided: (1) - `claim` follows the node's genesis

- **Both paths drop the chain-ID equality check** and sign the transaction over
  the **node-reported** `genesis_hash` (as `claim --key` already did through
  `walletTx.submit`; the ephemeral path used to sign over the compiled-in
  devnet hash and now reads the same field).
- **Both derive the epoch from the node's `epoch_blocks`** (the ephemeral path
  used the compiled-in value) and refuse a node reporting zero.
- **The puzzle is still solved with the fixture tuning**, which is stated in the
  code comment as the fact above rather than as an assumption, and the node is
  the verifier: `state.applyFaucetClaim` re-derives the digest with ITS
  parameters, so a claim solved against a different tuning fails the transition
  and is dropped by the proposer's applicability filter (`chain.SelectApplicable`)
  instead of riding a block. It cannot succeed silently; it can only be parked
  and dropped, which is the same fate an inapplicable transaction already has.

**Why this is not a weakening.** The protection worth keeping is "sign for the
genesis this node actually runs", and the new code keeps it more tightly than
the old one did: the ephemeral path used to sign over a *compiled-in* hash and
merely assert that the node's chain ID matched; both paths now read the hash
from the node and bind the signature to it. Refusing on a chain-ID string was a
proxy for reading the hash, and the proxy is what made the path unreachable on a
committee chain. Nothing about a claim can harm the claimant either way: it
carries no fee, no funds of theirs, and the coins land on the key they hold.

### What S-3 does NOT claim

The 1,001-claim arithmetic is **still long** (1,001 keys, 1,001 claims, 1,001
transfers, ~2,002 blocks of emission). S-3 was that the shipped command cannot
walk it at all off the devnet; it was not that the path is short. An operator
who can edit the committee file still has the cheaper route: seat the key there
(a genesis bond), which is what the deploy recipe does.

---

## Small items decided with them

- **W-1.** The faucet page's "What to run" command is now correct on every chain
  this build runs, because `claim` follows the node's genesis. The page states
  what the claim pays and that the amount is the chain's parameter, and drops
  the implied devnet-only condition that the CLI used to enforce.
- **W-2.** The usage paragraph claimed the node *clamps* `--blocks` above 500;
  the CLI refuses it (exit 1) since W-5. The paragraph now says which end does
  which: the CLI refuses above 500, a hand-written client that asks the node for
  more gets it clamped to 500.
- **N-2.** The relay closes a dial at accept against `--max-conns` or
  `--max-conns-per-ip` **before** any access-token greeting, so a node waiting
  for the greeting sees EOF and blamed the token. The message now names both
  caps, the per-prefix one included, and the README and the relay's help state
  the consequence: validators behind one IPv4 `/24` (a Docker bridge, a LAN, one
  NAT) share the per-prefix budget of 8, and the default is not raised silently
  - the operator raises it, or reads the relay's `RefusedConns` counter.

## State root

Unchanged, and expected to be: nothing that enters the genesis hash changed, no
state transition changed, and no parameter changed. `devnet --blocks 100` still
ends at `98e5cf468ecf0b6ca9c148a4ef7e5056c14254dead11efaa1f2890631cdd11cc`.
S-3 does not move it: the claim's *signing hash* is a client-side input, and the
genesis parameters it signs over are the same ones (S-3 changed which chain the
client will talk to, not what a claim is).

---

## What was verified after the change

- **S-2, constructed states (unit):** an unseated node's `POST /tx` answers
  `{"txid":"…","seated":false,"warning":"this node's key holds no committee seat
  at height 1, …"}`, a seated node answers `{"txid":"…","seated":true}`, a chain
  that seats no committee says so instead of blaming the key, and a server with
  no signing key answers the M5 shape. Five compile-confirmed mutants (no seat
  fields, a forced `seated: true`, a forced warning, the diagnostic branch
  dropped, `head` instead of `head+1`) each fail a named test.
- **S-2, live:** a claim posted to a running single-node devnet producer prints
  no warning (the producer's key holds the chain's only seat), and the CLI's
  warning path itself is covered by three compile-confirmed mutants (not printed,
  printed without the `seated: false` verdict, printed unsanitised).
- **S-3, live:** a one-seat committee-file chain (`chain_id
  committee-s3-verify-1`, genesis `6c9cac69…`) built and run on this machine:
  `b10coin claim --key … --yes` posted a claim that **applied** (balance 0 → 1
  b10, nonce 0 → 1) — the path the report says cannot be walked off the devnet.
  Before the change the same command exited 1 with `runs chain "…", not the
  devnet genesis "b10coin-devnet-1"`.
- **S-3, constructed states (unit):** both claim paths sign over the node's
  genesis hash and not the devnet's; the ephemeral path uses the node's epoch
  length (a chain at height 100 with 40-block epochs gets epoch 3, not 1); a
  node reporting `epoch_blocks 0` is refused on both paths; and a claim signed
  for one chain does not verify on another. Four compile-confirmed mutants
  (ephemeral signed over the devnet hash, ephemeral epoch from the compiled-in
  length, `submit` signed over the devnet hash, the zero-epoch guard removed)
  each fail a named test.
- **State root:** `devnet --blocks 100` still reports
  `98e5cf468ecf0b6ca9c148a4ef7e5056c14254dead11efaa1f2890631cdd11cc`, and
  `devnet --validators 4 --blocks 100` still passes.
