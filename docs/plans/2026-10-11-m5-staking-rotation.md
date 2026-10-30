# M5 — Staking, committee rotation, admission, `PEER_EXCHANGE`

| | |
|---|---|
| Spec | `docs/2026-10-02-b10coin-design.md` §6.3 (stake-weighted consensus), §6.5 (validator admission — the decentralisation ramp) |
| Predecessor | M4 (`docs/plans/2026-10-04-m4-real-networking.md`), merged as PR 6 |
| Acceptance | **The Nakamoto coefficient is plotted across a devnet run; the validator set rotates at an epoch boundary.** |

M4 delivered validators that agree over real TCP. M5 is where the committee stops
being a constant: stake becomes the thing that buys a seat, the seat set changes
only at an epoch boundary, and the distribution — which is the whole thesis — becomes
a number this project can graph instead of assert.

---

## Global Constraints

- **`spark` is the unit.** 1 b10 = 10^8 sparks. `MIN_STAKE` is 1,000 b10 = 10^11 sparks.
  Nothing in this milestone may use a float where money is involved.
- **Canonical encoding only** in hashed paths: fixed-width big-endian ints, minimal
  LEB128, varint-prefixed slices; never a map, never JSON, never gob.
- **The acceptance root moves once, and deliberately.** `Bond`/`Unbond`/`Withdraw`
  are new signed transaction types, so the transaction encoding and every state root
  change. This is the second hard fork on this branch (the first was S-1/S-3's chain
  identifier). Record the old and new root and name this milestone as the cause.
- **Commit safety is not negotiable.** A committee change at an epoch boundary must
  never let two different blocks commit at one height. The lock and the certificate
  gate keep working across a rotation; that is the point of doing rotation at
  boundaries rather than continuously.
- **Determinism.** Committee selection, tie-breaks and the Nakamoto coefficient must
  be pure functions of committed state. No map iteration order, no wall clock.
- **One parameter, two periods.** `EpochBlocks` already governs the faucet claim
  epoch, which is `h/EpochBlocks + 1` and 1-based (0 means "never claimed"). M5 gives
  it a second job: the committee epoch, which is `h/EpochBlocks` and 0-based. The two
  numbers are not interchangeable and must never be derived from one another. If the
  periods must ever diverge that is a new genesis parameter and a third fork, so M5
  keeps them equal on purpose.
- **No new dependencies.**

## Design decisions

1. **Stake is locked state, not a balance.** A bond is a record `(validator, amount,
   height)` in committed state, separate from the spendable balance. `Unbond` moves
   the amount to an unbonding record with `releaseHeight` = the epoch boundary at or
   after `height + UNBONDING_BLOCKS`, and the coins are **neither spendable nor counted
   in the committee** in between — that is what makes the cooldown a real economic delay
   rather than a formality. The rounding is audit ST-4's record bound: an epoch's
   unbonds share a release height (at most `UnbondingEpochs+1` unmatured records), and
   already-matured records collapse on the next unbond, so an address holds at most
   `UnbondingEpochs+2` records for the life of the chain instead of one per block. A
   release can be later than `height + UNBONDING_BLOCKS` by at most one epoch minus a
   block, never earlier.
2. **The committee is the top 21 by bonded stake, ties broken by public key bytes.**
   Deterministic, and the tie-break is by bytes rather than by address string so it
   cannot depend on formatting. §6.3 also caps any one validator at 1/4 of total
   power; the cap is applied after selecting, not instead of it. Because clamping
   changes the total it is measured against, it is applied in passes to a fixed
   point, so the cap holds over the powers the derivation actually emits.
3. **Rotation happens at the epoch boundary and nowhere else.** `EpochBlocks` already
   exists in `genesis.Params` (and is copied into `state.Params`), and
   `consensus.Config.CommitteeAt(height)` already exists
   as a seam returning a constant. M5 is what makes that seam real. Consensus for
   height `h` uses the committee of epoch `h / EpochBlocks`, derived from the state
   committed by height `e*EpochBlocks - 1`; a height mid-epoch must never see a
   different set than its first block did.
4. **`Bond` is a transaction, so joining costs a fee and is ordered.** Admission is
   not a separate channel: it is a signed `Bond`, validated like any other transaction
   against head state, and it takes effect at the next boundary. That keeps one
   admission path and lets the fee market do its job.
5. **`PEER_EXCHANGE` carries no consensus meaning.** It advertises *listening
   addresses*, nothing about height or identity, and the relay still parses nothing.
   Peers learned this way are dialled through the same maintainer, with the same
   backoff, and are still refused unless they complete a signed committee HELLO.
6. **The Nakamoto coefficient is computed from committed state, not from `Peers()`.**
   It is the smallest number of validators whose combined power exceeds one third —
   the BFT threshold, not an arbitrary fraction — and it is reported per height so a
   run can be plotted.

## File structure

- `internal/types/tx.go` — three new transaction types and their canonical encoding
- `internal/state/stake.go` (new) — bonds, unbonding records, cooldowns, committee derivation
- `internal/state/apply.go` — the `Bond`/`Unbond`/`Withdraw` arms
- `internal/state/state.go` — params, `Root()`, `Clone()`
- `internal/mempool/mempool.go` — the three types' admission and nonce bookkeeping
- `internal/chain/chain.go` — genesis bonds, and the per-epoch committee memo behind `CommitteeAt`
- `internal/consensus/committee.go` — `CommitteeAt` returns the epoch's committee
- `internal/consensus/engine.go`, `internal/consensus/driver.go` — read the committee per height, never cache across a boundary
- `internal/consensus/router.go`, `internal/consensus/sync.go` — membership and certificate gates by height
- `internal/wire/peerexchange.go` (new) — the `PEER_EXCHANGE` message
- `internal/devnet`, `internal/node` — wiring, and the rotation at boundaries
- `internal/devnet/nakamoto.go` (new) — the coefficient per height (no `internal/metrics` package: one pure function does not justify one)
- `internal/rpc/server.go` — `/status` params + genesis hash, and `/account/{address}`
- `cmd/b10coin` — `devnet --plot-nakamoto`, and `stake`/`unstake` CLI verbs

## Interfaces this milestone adds

```
types.Tx        Bond/Unbond carry Amount(8); Withdraw carries nothing new
state.State     Bonded, UnbondingOf, TotalBonded, TotalUnbonding, Committee
state.Bond      { Validator []byte; Amount, Height uint64 }
state.Unbonding { Amount, ReleaseHeight uint64 }

chain.Chain.CommitteeAt(h uint64) ([]genesis.Validator, error)

consensus.Config.CommitteeFor func(h uint64) ([]genesis.Validator, error)
consensus.Config.CommitteeAt(h uint64) ([]genesis.Validator, error)   // was: []genesis.Validator
consensus.PowerCapFor(n int) (num, den uint64)

wire.MsgPeerExchange = 0x83
wire.PeerExchange    { Addrs []string }
wire.MaxPeerExchangeAddrs, wire.MaxListenAddrBytes

devnet.Nakamoto(committee []genesis.Validator) int
devnet.Options       + EpochBlocks, RotateDemo, PlotNakamoto
simnet.Net.Unbond(i int) error
simnet.Net.CommitteeAt(i int, h uint64) ([]genesis.Validator, error)

genesis.ParseB10(s string) (sparks uint64, err error)
rpc: GET /status gains genesis_hash + stake params; GET /account/{address}
CLI: b10coin stake --node URL --key PATH --amount 1000
     b10coin unstake --node URL --key PATH [--amount 1000]
     b10coin devnet --validators 6 --epoch-blocks 40 --rotate-demo --plot-nakamoto
```

---

### Task 0: The staking transaction types

**Goal.** Make `Bond`, `Unbond` and `Withdraw` real signed, canonically encoded
transactions instead of reserved tag values, so every later task can put one in a
block. No state changes here: a `Bond` that reaches `state.ApplyTx` still fails with
`ErrUnsupportedTxType`, and nothing in this task may submit one.

**The interface.** The type is `types.Tx` — there is no `types.Transaction`. The tags
already exist at `internal/types/tx.go:26-31`; this task fills in their bodies.

```go
// internal/types/tx.go — the common prefix stays byte-identical:
//   Type(1) | From(20) | len PubKey | Nonce(8) | Fee(8) | <body> | len Sig
// encodeBody appends, per type, exactly these fields after the prefix:
//   TxBond      Amount(8)
//   TxUnbond    Amount(8)
//   TxWithdraw  (nothing)
func (tx *Tx) encodeBody() []byte          // extend the two `if` branches to a switch
func DecodeTx(b []byte) (*Tx, error)       // accept 1..5; keep rejecting 0 and 6+
func (tx *Tx) SigningHash(genesisHash [32]byte) [32]byte  // unchanged; covers the new bodies
```

**Invariants and constraints.**

- Tag values 3, 4 and 5 are frozen: the comment at `tx.go:21` promises a stable
  encoding, and a reserved value nobody has ever used is the cheapest thing this
  project will ever get to freeze.
- `Amount` is the only new field. `Epoch` and `PowNonce` belong to the faucet claim —
  `Epoch` is the 1-based claim epoch `h/EpochBlocks + 1` and is *unrelated* to the
  0-based committee epoch M5 introduces. A `Bond` must not carry either field; a
  signed stake transition that embedded a claim epoch would couple two rules that
  are only accidentally equal in period today.
- `DecodeTx` runs `Done()`, so a trailing byte is a protocol error. Every new field is
  fixed-width (no varint, no length prefix): the amount is 8 bytes, always.
- The chain binding is inherited, not re-implemented: `SigningHash` already folds
  `genesisHash` in as a domain-separated part, and `VerifySignature` is type-agnostic.
- No float, no `Amount` in b10: sparks only.

**What must NOT change.**

- A transfer's and a claim's encoded bytes must be *identical* to today's. Every block
  on disk is decoded on `chain.Open`, and every stored signature covers these bytes;
  an accidental prefix change invalidates every chain in every data directory.
- `DecodeTx`'s refusal of 0 and 6+ (`ErrUnsupportedTxType`), and `VerifySignature`'s
  `ErrAddressMismatch` / `ErrBadSignature` paths.
- `ID()` hashing the signature (audit S-13): do not "simplify" it to the body now that
  the body is richer.
- The fuzz corpus. `internal/types/fuzz_test.go` gains one valid encoding per new
  type; without seeds the new decode branches are unreachable, and that corpus is the
  project's only untrusted-input test for this decoder.

**Tests.**

- `TestBondRoundTrips` (and the same for `Unbond`/`Withdraw`): encode, decode, re-encode
  is byte-identical, every field equal, and `len(enc)` equals the common length plus
  exactly 8 for Bond/Unbond and 0 for Withdraw. The length assertion is what makes it
  non-vacuous: encode and decode can share a misordering and still round-trip, but
  they cannot fake the offset.
- `TestATransferAndAClaimEncodeToTheSameGoldenBytesAsM2`: two hard-coded hex strings.
  Both sides of a round-trip move together; only a golden notices a renumbering.
- `TestASignatureForABondDoesNotVerifyForAnotherTypeOrAmount`: sign `Bond{1000}`, then
  verify that signature against `Unbond{1000}`, `Bond{1001}` and a foreign genesis
  hash. All three must fail, which exercises `encodeBody` rather than only the decoder.
- `TestDecodeRejectsReservedAndTrailingBytes`: type 0, type 6, and a valid `Bond` with
  one extra byte.
- Fuzz: seeds for all three types, with the property "decode then re-encode either
  fails or reproduces the input bytes" — canonicality, not merely "no panic".

**The mutants.**

- `Amount` written for `Withdraw`, or omitted for `Bond`: the length/offset assertion
  and the golden both die.
- `DecodeTx` reads `Amount` but `encodeBody` does not write it: `Sig` is consumed as the
  amount and `Done()` fails, so the round-trip dies.
- The signature covers only the common prefix: the cross-type signature test accepts a
  `Bond` signature for an `Unbond`.
- Tags renumbered (`TxBond = 6`): the golden dies.
- `Done()` dropped: the trailing-byte test dies.

Each must die on a *named* test. A survivor is a hole in the suite, not a pass.

---

### Task 1: Stake state and the cooldown

**Goal.** Make stake a first-class locked part of committed state. A `Bond` moves
sparks out of a spendable balance into a bond record; an `Unbond` moves them into an
unbonding record that is worth nothing — not spendable, not counted — until its
release height; a `Withdraw` returns matured sparks to the balance. After this task a
validator's bond is consensus state, committed in the root, and no transaction can
create or destroy a spark.

**The interface.**

```go
// internal/state/stake.go (new)
type Bond struct {
	Validator []byte // ed25519 public key: the identity the committee seats
	Amount    uint64 // sparks, locked
	Unfunded  uint64 // sparks in Amount that genesis created; destroyed on Unbond (ST-3)
	Height    uint64 // the height at which it was recorded
}
type Unbonding struct {
	Amount        uint64
	ReleaseHeight uint64 // the epoch boundary at or after height + UnbondingEpochs*EpochBlocks
}

func (s *State) Bonded(a types.Address) uint64
func (s *State) UnbondingOf(a types.Address) []Unbonding // sorted by ReleaseHeight, a copy
func (s *State) TotalBonded() uint64
func (s *State) TotalUnbonding() uint64

// internal/state/apply.go — three new arms in ApplyTx
// internal/state/state.go — Params gains MinStake, UnbondingEpochs, CommitteeSize;
// Root and Clone cover the new maps
// internal/chain/chain.go — genesisState seeds one bond per genesis.Validator: Amount = Power, Height = 0
// internal/mempool/mempool.go — the three types take the transfer's nonce admission
```

**Invariants and constraints.**

- **Money is conserved by every stake transaction, exactly.** `spendable + bonded +
  unbonding` is unchanged by `Bond`, `Unbond` and `Withdraw`; a transfer lowers it by
  exactly its fee (the fee is burned, as it is today); emission and claims are chain
  level and outside this sum's per-transaction invariance. Genesis is the initial
  condition: genesis seats are bonded by the genesis hash, not bought, so height 0 has
  bonded stake that no balance funded. Say that in the code, because it is the first
  place a reviewer will look for a double count.
- `Bond`: requires `Fee >= MinFee`; `Amount > 0`; the *resulting* bond is at least
  `MinStake`; `balance >= Amount+Fee` with the sum overflow-checked; accumulation
  overflow-checked. A second `Bond` from the same address adds to the same record and
  keeps the first-recorded public key (a different key cannot reach the same address).
- `Unbond`: requires `Fee == 0`. This is deliberate and load-bearing: a validator may
  hold nothing spendable, and an exit that needs a coin is an exit an operator with a
  zero balance can never make, which would let a seat that must leave be
  un-rotatable. `Amount > 0`, `Amount <= bonded`; the record's release height is the
  epoch boundary at or after `s.height + UnbondingEpochs*EpochBlocks`, the product, the
  sum and the rounding all overflow-checked; a record at the same release height merges,
  already-matured records collapse into one, and the resulting bound is
  `UnbondingEpochs+2` records per address (audit ST-4); a zero remainder deletes the
  bond. The bond carries an `Unfunded` amount (audit ST-3): the genesis grant is
  destroyed on unbond, not recorded, so no genesis spark is ever withdrawable.
- `Withdraw`: requires `Fee == 0`; releases **every** unbonding record with
  `ReleaseHeight <= s.height` to the balance, in one transaction, and errors with
  `ErrNothingToWithdraw` if none is mature. `<=` is the rule: a record is releasable at
  exactly its release height.
- `Params` zero values stay legal: `MinStake == 0` or `EpochBlocks == 0` makes a stake
  transaction fail with `ErrStakeUnconfigured`, never panic and never divide.
- `Root()` commits to all three kinds of record under three disjoint leaf domains
  (`b10coin-account`, `b10coin-bond`, `b10coin-unbonding`), each sorted by address
  bytes, concatenated accounts-then-bonds-then-unbonding, zero-amount records pruned.
  A bond the root does not commit is a bond a node can lie about.
- `Clone()` deep-copies both maps and the slices inside the unbonding values.

**What must NOT change.**

- `applyTransfer` and `applyFaucetClaim`, byte for byte: the fee burn, the fee floor
  order, the claim's epoch rule, the claim bound.
- `ApplyBlock`'s clone-then-apply contract. A failed second transaction must leave the
  receiver untouched; a shallow clone of the new maps silently breaks that, and it is
  the most likely regression in this task.
- `Root()` for a state with no bonds must equal today's root (empty maps contribute no
  leaves), so every existing root test stays green. If it does not, the change is
  wrong — not the tests.
- `state.Params`'s existing fields and the `chain.genesisState` mapping of them; the
  mempool's per-sender caps, claim courtesy bound and `SelectApplicable` filter.
- The mempool must refuse two stake transactions at one nonce. `insert`/`forget`
  currently track `pendingNonces` for `TxTransfer` only; extend that to every
  non-claim type, or a proposer can be handed two transactions that cannot both apply
  and the whole block fails on the second.

**Tests.**

- `TestBondMovesSparksFromSpendableToLocked`: balance down by `Amount+Fee`, bonded up
  by `Amount`, the three-way sum unchanged.
- `TestBondBelowMinStakeIsRefused` and `TestBondAccumulatesToTheFloor`: 600 alone is
  refused; 600 then 500 is accepted because the *resulting* 1100 clears the floor.
- `TestUnbondingCoinsAreNeitherSpendableNorCounted`: after `Unbond`, bonded down,
  unbonding up, and a transfer of the unbonded amount fails `ErrInsufficientFunds`.
  Three assertions on one constructed state; the third is what a "move but keep
  spendable" mutant dies on.
- `TestWithdrawReleasesOnlyMatured`: two unbonds at different heights; one withdraw
  between them returns only the first and leaves the second in place.
- `TestWithdrawAtExactlyTheReleaseHeight`: fails at R−1, succeeds at R.
- `TestAStakeTransactionNeverChangesTheSupplySum`: a scripted sequence — bond, transfer,
  unbond, withdraw — asserting the sum moves by exactly the burned fees and by nothing
  else. This is the invariant test; it fails on any double credit or leak.
- `TestTheStateRootCommitsToBondsAndUnbonding`: two states differing only in one bond
  amount, and two differing only in one release height, have different roots; a state
  with no bonds has the pre-M5 root. The negative half is what stops it passing on a
  root function that hashes something unrelated.
- `TestApplyBlockRollsBackAStakeFailure`: `[valid bond, invalid unbond]` leaves the
  receiver's root and bonded total byte-identical.
- `TestMempoolRefusesTwoStakeTransactionsAtOneNonce`: pool-level, not block-level.

Every one of these constructs its state directly: no driver, no clock, no network.
There is nothing to provoke and nothing that can pass by scheduling.

**The mutants.**

- `Unbond` credits the balance *and* keeps the unbonding record: the supply-sum test.
- `Unbond` leaves the amount in the bond map: the unbonding/uncounted test, and Task
  2's selection.
- `Withdraw` ignores `ReleaseHeight`: the matured-only test.
- The release height uses one `EpochBlocks` instead of `UnbondingEpochs` of them: the
  exact-height test (R is computed from two epochs).
- `Root()` skips the unbonding leaves: the root test's release-height half.
- `Clone()` shallow-copies: the rollback test.
- `Unbond` charges a fee: the fixture has no spendable balance, so the unbond fails.
- `Bond` admits below `MinStake`: the floor test.

---

### Task 2: Committee derivation from stake

**Goal.** Turn committed bonds into the committee that will validate an epoch: the top
`CommitteeSize` candidates by bonded stake, ties broken by public-key bytes, each
seat's power capped at a quarter of the seated total. The cap is applied in passes to a
fixed point, because a single pre-cap division is not safe: a holder of 99% of the
stake would end at 96% of the clamped total and could commit alone. The result is a
pure function of state — no clock, no map order, no address strings.

**The interface.**

```go
// internal/state/stake.go
// Committee returns the seats derived from THIS state: the top CommitteeSize
// candidates by bonded stake (ties by public-key bytes, ascending), each power
// capped at a quarter of the seated total. Which height this state is decides
// which epoch's committee it is; the function itself knows nothing of heights.
func (s *State) Committee() ([]genesis.Validator, error)

// applyPowerCap is the fixed-point clamp, unexported and separately tested:
// each pass takes T once and clamps every member against that same T.
func applyPowerCap(powers []uint64) ([]uint64, error)

var ErrNoCandidates  = errors.New("state: no bonded candidate can be seated")
var ErrZeroCommittee = errors.New("state: CommitteeSize is zero")
```

**Invariants and constraints.**

- Candidate means a bond record with `Amount > 0`. Unbonding coins are not candidates
  and are not in the bond map at all; a withdrawn seat is gone.
- Seats: `min(CommitteeSize, len(candidates))`, in stake-descending order, ties broken
  by `bytes.Compare` on the public key. Sorting by `types.Address` is wrong: the
  address is a hash, so its byte order is unrelated, and §6.3's tie-break is on the key.
- The cap: `p_i = min(stake_i, T/4)` with `T` the seated total, applied in passes; each
  pass computes `T` once and clamps everyone against it, repeating until a pass changes
  nothing. Passes are capped at 64 and a non-converged result is an error, never an
  approximation. The pass structure is what makes the result independent of the order
  the validators are visited in.
- After the fixed point the largest share is at most 1/4 — equality is allowed, because
  `consensus.Config.Validate` rejects only `> 1/4` — and therefore strictly below 1/3,
  which is the property the cap exists to buy.
- **The cap's other face (audit ST-2), documented and not changed.** That bullet
  describes the whale side. A fixed point over the seated total does more than cap a
  dominant seat at 1/4: it drags it DOWN — to the others' power on a four-seat
  committee, to a quarter of the seated total on a larger one (the floor seats then
  share the other three quarters). Four seats at 10,000 / 1,000 / 1,000 / 1,000 b10
  all converge to a quarter of the committee each, so the three `MIN_STAKE` seats hold
  3/4 and can commit alone, and a seat costs `MIN_STAKE` flat.
  The Nakamoto coefficient is computed on these capped powers, so it reports the
  committee's composition — how many keys must collude — and OVERSTATES how
  distributed the stake is (it prints k=2 for that four-seat state while one party
  holds ~77% of the stake). This is §6.3's rule implemented exactly; the README states
  the consequence next to the Nakamoto claim.
- **Proposal, not implemented:** either cap against the UNCAPPED total stake
  (`p_i = min(stake_i, sum(stake)/4)`, one pass, no fixed point) so extra stake above
  the cap still dilutes a dominant seat, or require a minimum power-per-seat ratio
  (`power_i >= MIN_STAKE` and `power_i` no more than, say, 10x the smallest seated
  power) so a floor seat cannot be worth the same as a whale's quarter. Both are
  protocol changes with their own review; neither is in this milestone.
- Below four seats the cap does not apply: 1/4 is unsatisfiable there (the largest of
  fewer than four holders is at least a third), and `consensus.Config.Validate` already
  encodes exactly that escape. Use `1/1` for those committees rather than inventing a
  second rule.
- No zero-power seat: with four or more seats and every bond at least one spark,
  `T >= 4` so `T/4 >= 1`. If the arithmetic ever disagrees, return an error — a
  zero-power member is a `Validate` failure one layer later, with a worse message.
- `T` is summed with checked adds; a wrapped total would make every share wrong.
- Two derivations from states built in different insertion orders must be identical,
  element for element.

**What must NOT change.**

- `consensus.Config.Validate` and its pinned `ErrPowerCap`. The derivation must *pass*
  it, never rely on it to reject: a committee that only fails at construction halts a
  running chain instead of seating a safe one.
- `Config.Quorum`'s two-thirds-of-total rule and `Config.Proposer`'s weighted draw. They
  consume the powers the committee carries; a capped committee is a valid committee to
  them, and no second cap may appear inside consensus.
- `genesis.Validator.Power` keeps its name and type. For a genesis seat it is also its
  bond (`Height = 0`); the derivation must not rescale it.
- `simnet.Committee(n)` and `genesis.Devnet()` keep `Power: 1` per seat. Raising it to
  `MIN_STAKE` to make the fixture look realistic would change every M3/M4 quorum,
  proposer draw and acceptance output for no milestone reason.
- The genesis committee must still be a valid committee for `Validate` at construction,
  so a node can start before any state has been derived.

**Tests.**

- `TestCommitteeIsTheTopNByStake`: stakes 5,4,3,2,1 with `CommitteeSize 3`; assert the
  *ordered public keys* are the top three. Powers are asserted separately, because the
  cap legitimately rewrites them.
- `TestTheTieBreakIsThePublicKeyBytes`: two equal-stake keys whose address bytes order
  opposite to their key bytes (find the pair once and hard-code it); the key-order
  winner is seated. An address-string or address-bytes sort fails.
- `TestCommitteeIsIndependentOfInsertionOrder`: the same five bonds inserted forwards
  and backwards, derived 100 times each; identical results. One call is a weak test
  because Go randomises map order per iteration; 100 calls over a five-entry map has no
  realistic false-pass.
- `TestTheCapHoldsAfterClamping`: one holder at 10^12 against three at 1 spark. Every
  power must be at most a quarter of the total and — the sharp part — the dominant
  holder ends at the small holders' power, because the fixed point of
  `p <- (p+3)/4` is 1. A single pre-cap pass leaves it at 96% and fails loudly.
- `TestEveryDerivedCommitteePassesConsensusValidate`: a table of distributions (flat 4,
  flat 6, flat 21, skewed, and a three-seat committee with the 1/1 rule) run through
  `consensus.Config{...}.Validate()`; nil error for four or more seats. This is the
  cross-package agreement pin between the two implementations of one rule.
- `TestAWithdrawnValidatorIsNotACandidate`: bond, unbond all, withdraw, derive — gone.
- `TestCommitteeSizeZeroIsRefused` and `TestNoCandidatesIsRefused`: errors, not empty
  slices. An empty committee reaching `NewEngine` fails later with a worse message.

**The mutants.**

- One pre-cap clamp pass: the cap test.
- Sort by address bytes: the ordering and tie-break tests.
- Range over the bond map without sorting: the insertion-order test.
- Treat unbonding records as candidates: the withdrawn-seat test.
- Cap against all candidates' total instead of the seated total: the cap test's share
  arithmetic, and `Validate` in the table test.
- `CommitteeSize` from a constant 21 rather than the chain's params: the simnet-6
  fixture seats a committee the harness never built.
- A 1/4 cap below four seats: the table test's three-seat row.

---

### Task 3: Rotation at the epoch boundary

**Goal.** Make the M4 seam real. Consensus for height `h` uses the committee derived
from the committed state at the last block of the preceding epoch, and nothing else: a
seat that ends ends exactly at the boundary, a seat that begins begins there, and the
driver, the vote router, the certificate gate and the HELLO admission all read the same
per-height source. Nothing caches a committee across a boundary.

**The interface.**

```go
// internal/chain/chain.go
// CommitteeAt returns the committee that validates h: derived from the state
// committed at h/EpochBlocks*EpochBlocks - 1 (epoch 0: the genesis state) and
// memoised per epoch. Rebuilt by replay, never persisted. Returns a copy.
func (c *Chain) CommitteeAt(h uint64) ([]genesis.Validator, error)

// internal/consensus/committee.go
type Config struct {
	Committee    []genesis.Validator
	CommitteeFor func(h uint64) ([]genesis.Validator, error) // nil = static Committee
	...
}
func (c Config) CommitteeAt(h uint64) ([]genesis.Validator, error) // signature change; no readers today (C-17)

func PowerCapFor(n int) (num, den uint64) // 1/4 at n >= 4, 1/1 below

// internal/consensus/driver.go
func (d *Driver) configFor(h uint64) (Config, error) // CommitteeAt + PowerCapFor + Validate
func (d *Driver) newEngine(h uint64, parent [32]byte) (*Engine, error)
```

**Invariants and constraints.**

- Epoch `e`'s committee is a function of the state at height `e*E - 1`; epoch 0's is a
  function of the genesis state. The last block of an epoch decides the next epoch and
  is itself committed by the old set, so nothing inside epoch `e` can change epoch
  `e`'s seats — the set that committed the boundary's parent is the set that must judge
  the boundary.
- `h/E` is the committee epoch; `h/E + 1` is the faucet claim epoch (1-based, 0 = never
  claimed). Keep them separate and never derive one from the other.
- The memo is derived state: `chain.Open` replays every block through
  `applyValidatedLocked`, so a restart rebuilds every epoch's committee and derives the
  same answer. It is never written to the store.
- `configFor` returns a Config whose `Committee` is the height's set and whose cap is
  `PowerCapFor(len(set))`, then runs `Validate` on it. A failure is a refusal to act at
  that height, never a fallback to the previous committee.
- A driver whose own key is not seated at that height builds an *inert* engine: it
  tallies inbound frames and emits nothing, because `emitVote` and `CheckMembership`
  already refuse to sign without a seat. That is how a rotated-out validator stops
  without a flag, an error path or a panic.
- Every reader varies by height: the driver (per height), the router's membership check
  (per frame height), the certificate re-tally (per block height), HELLO admission (per
  the frame's height within the existing head/head+1 window), and BLOCK_SYNC
  membership (the asker's head is `From-1`; the responder's is its highest unit).
- Safety across a boundary is structural: the tallies at height `H` are built from
  exactly one committee, so the other epoch's votes fail the membership check before
  their power is counted. Two blocks cannot commit at one height.

**What must NOT change.**

- The persisted lock and its restore (`store.LockRecord`, `d.persistLock`, `newEngine`'s
  restore-on-construction). A lock belongs to a height, not to an epoch: a rotation
  must neither clear it nor skip the restore.
- `chain.Append`'s one-commit-per-height rule, `ValidateConsensusNext`'s timestamp pin
  and `committedBlock`'s "append only bytes this engine holds" contract.
- The claim epoch rule and the 1-based `ClaimedEpoch`; the existing double-claim tests
  must stay green.
- `consensus.Config.Validate`'s semantics — the derivation passes it, it is not excused
  from it.
- `driver.build`'s mempool take and `SelectApplicable`: a boundary must not change what
  a block may carry.
- `MessageRouter.Route`'s audit C-8 order: the membership check stays before `Verify`.
  Only the *set* becomes height-dependent.

**Tests.**

- `TestTheCommitteeChangesExactlyAtTheBoundary`: `E = 4`, a seat unbonds at height 1;
  `CommitteeAt(2)` and `CommitteeAt(3)` are the old set (keys, powers, quorum 5 of 6),
  `CommitteeAt(4)` and `CommitteeAt(5)` the new (4 of 5). Fails on `h/E+1`, on
  `(h+1)/E`, and on anything derived from head state.
- `TestTheBoundaryCommitteeSurvivesReplay`: derive at `E` on a live chain, then reopen
  the same directory (`chain.Open`) and derive at `E`; identical keys and powers. Fails
  if the memo is not rebuilt by replay — that is a node that forks at the boundary after
  a restart.
- `TestAnUnbondMidEpochDoesNotChangeThatEpoch`: the bond is already zero at height 2,
  yet the seats and the quorum for 2..3 are unchanged. Fails on "recompute when a bond
  changes".
- `TestVotesAcrossTheBoundaryDoNotCombine`: at `H = E`, build the `VoteSet` from
  `CommitteeAt(H)`, add precommits from the *old* set worth more than two thirds of the
  old total, assert each is refused and `HasQuorum` is false; then add the new set's
  quorum and assert it passes. Constructed, no engine and no clock: the failure a
  genesis-wide membership check produces is exactly this.
- `TestTheCertificateGateUsesTheBlocksEpoch`: a certificate signed by epoch 1's seats
  for a height in epoch 1 verifies; the same votes relabelled to an epoch-0 height are
  refused. `syncer.verifyCertificate` reads `Genesis().Validators` today, so this test
  is what forces that change.
- `TestAValidatorWhoseSeatEndsStopsActingAtTheBoundary`: the departing validator's
  height is the boundary minus one after the others commit past it, its history is a
  prefix of theirs, and it emits no vote for the boundary. Fails if the driver caches
  its Config.
- `TestAnUnseatedEngineEmitsNothing`: `NewEngine` with a key outside the committee
  tallies a valid vote and emits none, with no panic.

**The mutants.**

- `h/E + 1` for the committee epoch: the boundary test.
- Derive from head state: the mid-epoch test.
- Keep `d.cfg` instead of `configFor`: the departed-seat tests.
- Leave `verifyCertificate` on the genesis set: the certificate-gate test.
- Leave the router's membership on the genesis set: the cross-boundary vote test.
- Keep 1/4 for a three-seat derived committee: `Validate` refuses and a fixture stalls.
- Rebuild the memo on replay but not on commit (or the reverse): the replay test.

---

### Task 4: `PEER_EXCHANGE`

**Goal.** Let a validator learn its peers' listening addresses from the peers
themselves, so a mesh forms without an operator-supplied `--peers` list on every node.
The message advertises addresses and nothing else — no height, no identity, no
consensus meaning. Every address learned this way is dialled through the existing
maintainer and is still refused at the door unless it completes a signed committee
HELLO, so a lie buys a wasted dial, never a vote.

**The interface.**

```go
// internal/wire/peerexchange.go (new)
const MsgPeerExchange MsgType = 0x83 // next free tag above WireTagFloor (0x80)

type PeerExchange struct {
	Addrs []string // host:port, at most MaxPeerExchangeAddrs
}
func EncodePeerExchange(p *PeerExchange) []byte
func DecodePeerExchange(b []byte) (*PeerExchange, error)

const (
	MaxPeerExchangeAddrs = 8
	MaxListenAddrBytes   = 255
)

// internal/consensus/router.go
type MessageRouter struct {
	...
	OnPeerExchange func(from transport.PeerID, p *wire.PeerExchange)
}

// internal/devnet/tcpnode.go
func (v *Validator) observePeerExchange(from transport.PeerID, p *wire.PeerExchange)
```

The frame is **not signed**. Its authority is the connection it arrived on, which is
already an admitted committee member's; a signature over a list of addresses would add
nothing a member could not already claim by dialling, and would drag a non-consensus
message into the signature domain the rest of the wire keeps separate.

**Invariants and constraints.**

- The payload carries no height, no validator key, no chain id and no vote. No
  `consensus` code may read it as evidence about the chain.
- A hint can cause a dial, never a peer. The only admission path is still
  `admitHello`: chain id, committee seat at that height, signature over the HELLO hash.
- Bounded before allocation: at most 8 addresses, each at most 255 bytes, the count
  checked against the remaining frame bytes before any slice is grown (the N-12
  discipline the HELLO decoder already applies).
- A hint is not operator intent. Accept only `IP:port` — no hostnames, no empty host,
  port 1..65535, no duplicates, and never the node's own listen address. Refuse
  loopback, private, link-local and unspecified addresses learned from a hint, even
  though `--peers` may name them: an operator may aim the node at its own network, a
  peer may not.
- Dialling goes through `TcpTransport.AddPeer`, which owns the one-maintainer-per-
  address, backoff and dedupe rules. A direct dial would create a second connection
  policy.
- Nothing enters `transport.Dedup`: these are not votes, and recording their keys would
  let repeated advertisements evict real votes under the bucket ceiling.
- The relay still parses nothing: `internal/relay` and `cmd/b10coin-relay` gain no
  decoder import and no branch on the tag, and forward the frame byte-identically.

**What must NOT change.**

- `admitHello`'s checks and their order (audit N-3/N-7). Its membership *lookup* becomes
  the frame's-height committee (Task 3); nothing else about it moves.
- The relay's parse-nothing property and the access-token gate (`wire/relaygate.go`).
- `AddPeer`'s semantics: one maintainer per address, backoff with jitter, supersede by
  rank. PEER_EXCHANGE must not add a second dial path.
- The simulator's topology: `simnet` has no dedup set and no relay, and stays a star.
  Every mesh test lives over real TCP in `internal/devnet` or
  `internal/transport/tcp`.
- Tag disjointness (audit N-5): 0x83 must fail every consensus decoder on its first
  byte, and 0x01..0x03 must fail `DecodePeerExchange`.

**Tests.**

- `TestPeerExchangeRoundTripsAndRefusesTooManyAddresses`: 8 addresses round-trip; 9 are
  refused before allocation; an empty list is refused (a message that says nothing is a
  bug, not a no-op).
- `TestTheConsensusDecodersRejectAPeerExchangeFrame`: `DecodeVote`, `DecodeProposal` and
  `DecodeHello` all refuse a 0x83 frame.
- `TestALearnedAddressIsNotAPeerUntilItSaysHello`: over loopback, A advertises B to C;
  C dials B, but B is absent from `C.Peers()` and none of its frames reach the router
  until it sends a signed HELLO with C's chain id and a committee key. Fails if the
  handler creates a peer instead of calling `AddPeer`.
- `TestAPeerExchangeCannotAimTheNodeAtItsOwnNetwork`: `127.0.0.1:1`, `[::1]:1`,
  `10.0.0.5:9`, `169.254.1.1:9` and `example.com:9` produce no dials; a public
  `IP:port` produces exactly one.
- `TestTheRelayForwardsAPeerExchangeFrameUnchanged`: a 0x83 frame through the relay
  arrives byte-identical. The relay already has a "forwards what it cannot parse" test;
  this one pins that the new message is not special-cased.
- `TestAMeshedVoteIsCountedOnce`: A↔B↔C plus A↔C; one broadcast from A reaches C twice,
  the router's duplicate counter moves and the tally counts the power once. Fails if the
  mesh wiring loses the dedup set.
- `TestAPeerExchangeMovesNoConsensusState`: after delivering a frame, the node's height,
  round and tallies are unchanged.

**The mutants.**

- The handler creates a peer directly: the learnt-address test.
- Unbounded `Addrs`: the too-many test.
- Hostnames or private addresses accepted: the own-network test.
- The relay special-cases 0x83, or drops unknown tags: the forward test.
- Dedup removed for the mesh: the counted-once test.
- 0x83 placed inside the consensus tag range: the decoder-disjointness test.

---

### Task 5: The Nakamoto coefficient, plotted

**Goal.** Turn the thesis into a number the project can graph: from committed state at
each height, the smallest number of validators whose combined power exceeds one third
of the committee, with the seat count and the largest share, printed as a series across
a devnet run in which the set actually rotates. The skeleton's
`--validators 4 --epoch-blocks 100` cannot do this: a rotation needs a stake change, and
four seats losing one drops into the below-four cap regime. The fixture below is the
smallest run that shows a visible step.

**The interface.**

```go
// internal/devnet/nakamoto.go (new)
// Nakamoto is the smallest k whose k largest powers sum to MORE than a third of
// the total — the BFT threshold. Equality is not enough: four equal seats give 2.
func Nakamoto(committee []genesis.Validator) int

// internal/devnet/devnet.go
type Options struct {
	...
	EpochBlocks  uint64 // 0 = the genesis value
	RotateDemo   bool   // fixture: one seat unbonds mid-epoch and leaves at the boundary
	PlotNakamoto bool
}
type NakamotoRow struct {
	Epoch, Height        uint64
	Seats, Nakamoto      int
	TopPower, TotalPower uint64
}

// internal/simnet/simnet.go
func (n *Net) Unbond(i int) error                                  // the fixture's own Unbond, fee 0
func (n *Net) CommitteeAt(i int, h uint64) ([]genesis.Validator, error)

// cmd/b10coin/main.go
//   --epoch-blocks N   mutates the compiled-in devnet genesis BEFORE it is hashed
//   --plot-nakamoto    one row per epoch boundary, plus the head
//   --rotate-demo      drives a rotation; requires --validators >= 5
```

**Invariants and constraints.**

- Computed from committed state: a row for height `h` uses `CommitteeAt(h)` — the
  committee that validated that height — never `Peers()`, never the genesis set and
  never the head's committee for a historical row.
- The threshold is strict: `cum > total/3` (integer division, exactly equivalent to
  `3*cum > total` without forming the product). A three-seat equal committee is 2, not
  1; a single seat is 1.
- No float in the computation or the printed numbers: powers and totals in sparks, and
  a share printed as `100*power/total` truncated to an integer percent. A percentage of
  voting power is not money, but the project does not print a number it computed in a
  float.
- Rows are monotone in height, one per epoch boundary plus the head. The series is a
  report: it reads a clone, takes no lock and changes no state.
- The fixture rotates through the ordinary `Unbond` transaction (Decision 4's path).
  After the boundary it waits only on the seated validators: a rotated-out validator's
  height is *expected* to stop, and the run's agreement check must read its history as a
  prefix rather than calling it a fork.
- The fixture's stakes are the simnet genesis's `Power`, one spark per seat. Shares are
  what the coefficient measures; the report must not present a spark as money.
- `--epoch-blocks` changes the genesis hash, so it defines a different chain: a `--dir`
  built at another epoch length is refused by `store.CheckGenesis`, not silently reused.
  The chain *id* string stays as it is (it is pinned), so two epoch lengths share an id
  and differ in hash — say so in the flag's help.

**What must NOT change.**

- Both acceptance commands still print `OK` and exit 0: `devnet --blocks 100` and
  `devnet --validators 4 --blocks 100`. The single-node path must not acquire a
  rotation requirement.
- `RunMulti`'s guards: the fresh-directory refusal, `ErrNoValidators`, the
  driven-versus-requested count, and `Agreed` computed through `AssertPrefix`.
- `committeeChainID`'s `b10coin-simnet-N` format.
- `Summary`'s faucet fields and their arithmetic; a multi-validator run still takes no
  claims.
- The claim epoch rule. `--epoch-blocks` moves both periods because they are one
  genesis parameter — that is the parameter's property, not something to decouple here.

**Tests.**

- `TestNakamotoCountsTheSmallestShareAboveOneThird`: 4 equal → 2, 5 equal → 2, 6 equal →
  3, 21 equal → 8, one 30% seat plus four at 17.5% → 2, a single seat → 1, an empty
  committee → 0 without a panic. The 21-seat figure is the known one, and 4 equal → 2
  (not 1) is exactly the strictness the definition turns on.
- `TestNakamotoIsComputedFromTheHeightsCommittee`: after the run has passed a boundary,
  the row for an earlier height still reports the earlier coefficient. Fails if every
  row is read from the head.
- `TestThePlotShowsAStepAtTheBoundary`: the acceptance fixture — 6 seats, `E = 40`,
  rotation at height ~10 — prints `0: 6 seats, k=3` and `40: 5 seats, k=2`. Asserts the
  rows, not the formatting. Fails if the fixture does not actually rotate.
- `TestTheRotatedOutValidatorStopsAtTheBoundary`: its height is 39 while the rest reach
  105, and its history is a prefix. This is the cross-check that the plotted step and
  the rotation are the same event.
- `TestTheReportChangesNoState`: the head and state root before and after building the
  rows are identical.
- `TestNakamotoOverAnEmptyCommitteeRefuses`: a chain with no validators reports an
  error, not `0/0`.

**The mutants.**

- `>=` instead of `>`: four equal seats print 1.
- The coefficient from `Peers()` or the online set: a stopped validator changes the
  number with no boundary.
- The head committee for every row: the historical-row test.
- One row only: the step test.
- A float percentage: the integer rows, and the diff itself.
- The fixture unbonds but keeps waiting on the whole committee: the step test hangs,
  which is a failure, not a pass.

---

### Task 6: CLI, recipe and README

**Goal.** Make staking usable by a person and make the milestone legible to the next
reader: `stake`/`unstake` verbs that build, sign and submit ordinary transactions with
money parsed exactly; a node read that tells a client the nonce, the balance, the bond
and the chain it is talking to; the deploy recipe's stake section; and the README's
status list, CLI table and validator paragraphs updated with the *new* root, re-derived
by running the command and attributed to M5.

**The interface.**

```go
// internal/genesis/amount.go (new) — exact decimal b10, integer arithmetic only
func ParseB10(s string) (sparks uint64, err error) // "1000" -> 1e11, "0.00000001" -> 1

// cmd/b10coin/main.go
func cmdStake(args []string) error   // stake   --node URL --key PATH --amount 1000
func cmdUnstake(args []string) error // unstake --node URL --key PATH [--amount 1000]

// internal/rpc/server.go
//   GET /status  gains genesis_hash, min_fee_sparks, min_stake_sparks,
//                epoch_blocks, unbonding_epochs, committee_size
//   GET /account/{address} -> {"address","balance","nonce","bonded",
//                              "unbonding":[{"amount","release_height"}]}
func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request)
```

**Invariants and constraints.**

- Money never touches a float. `ParseB10` splits on the decimal point, parses the
  integer part, right-pads or rejects the fraction at 8 digits, refuses signs, empty
  parts, exponents and more than 8 decimals, and checks the multiply by 10^8 for
  overflow before it happens.
- The verb never opens the node's data directory: it reads `/status` for the chain
  identity and the stake parameters, `/account` for the nonce, balance and bond, signs
  with the key file, and POSTs to `/tx`. Two processes appending to one store is not a
  client design.
- The signature is bound to the hash the node reports (`genesis_hash`), not to a
  compiled-in devnet assumption: a verb pointed at another chain then produces a
  transaction that chain can verify, and one pointed at a doctored node produces a
  useless transaction rather than a dangerous one.
- `stake --amount` is in b10 and converted once; the transaction carries sparks. A bond
  must clear the node's `min_stake_sparks`, and the verb says so before submitting
  rather than letting the node refuse it.
- `unstake` without `--amount` unbonds the whole bond read from `/account`; with
  `--amount` it unbonds that much and refuses more than is bonded.
- Both verbs submit and report the transaction id; neither waits for inclusion, because
  a bond takes effect at the next boundary and "nothing happened yet" is correct for up
  to an epoch.

**What must NOT change.**

- `claim`'s flags, output and ephemeral-key behaviour, and the `--print-key` default.
- `handleStatus`'s existing `chain_id` and `height` fields and their meaning: add
  fields, rename none. A client that ignores unknown fields must keep working.
- The `/tx` path: per-source limit, body bound, decode, mempool admission. No bypass and
  no direct append.
- `devnet --blocks 100`'s printed root: it must be the *new* M5 root, and the README's
  old `12a643be…` must remain visible as the M4 figure with a one-line note that M5's
  transaction encoding moved it.
- The single-node path's output lines that the README documents verbatim, and
  `internal/version` as the one version source.
- The README line that says "a committee accepts no transactions" is already false
  since M4 and becomes actively misleading once the rotation fixture submits an
  `Unbond` through a committee's mempool. Correct it.

**Tests.**

- `TestParseB10IsExact`: `"1"` → 1e8; `"0.1"` → 10,000,000 (a float64 gives 9,999,999);
  `"1000"` → 1e11; `"1000.00000001"` → 1e11+1; reject `""`, `"1."`, `".5"`, `"-1"`,
  `"1.000000001"`, `"1e9"`, `" 1"`, and a value that overflows when scaled.
- `TestStakeVerbSubmitsABondWithTheRightFields`: a stub HTTP server captures the POSTed
  bytes; the test decodes them, asserts type, sender, nonce, fee, amount in sparks, and
  verifies the signature against the genesis hash the stub reported. This is the verb's
  whole job, tested without a chain.
- `TestUnstakeWithNoAmountUnbondsTheWholeBond`: the stub's `/account` reports a bond; the
  posted transaction's amount equals it.
- `TestTheVerbRefusesAKeyThatDoesNotOwnTheAccount`: the key's address differs from the
  account's; the verb refuses before submitting.
- `TestStatusReportsTheGenesisHashAndTheStakeParams`: every new field present and equal
  to `genesis.Devnet()`'s values, alongside the unchanged ones.
- `TestAccountReportsBondAndUnbonding`: a node with a constructed bond and one matured
  unbonding record reports both, and the release height as a height, not a duration.

**The mutants.**

- `ParseB10` through `strconv.ParseFloat`: the `"0.1"` row.
- b10 passed straight through without the 10^8 scale: the decoded-amount assertion.
- The verb signs with the compiled-in devnet hash instead of the reported one: the
  different-genesis case.
- `unstake` always sends the whole bond (or zero): the amount assertion.
- `/status` renames rather than adds a field: the existing status test.
- The README root typed by hand: Task 6's own verification step re-runs
  `devnet --blocks 100` and pastes the output.

---

## Acceptance

- `b10coin devnet --validators 6 --epoch-blocks 40 --blocks 105 --rotate-demo
  --plot-nakamoto` prints a series whose seat count and coefficient step at height 40
  (6 seats / k=3 → 5 seats / k=2) and exits 0.
- Two blocks cannot commit at one height across a rotation (constructed test, no
  timing): votes from the other epoch's set are refused and cannot combine to quorum.
- Unbonding coins are unspendable and uncounted until exactly `releaseHeight`.
- The relay still makes zero decoder calls, and forwards a `PEER_EXCHANGE` frame
  unchanged.
- Both existing acceptance commands still print `OK`, with the new state root recorded
  and attributed to this milestone.

## Self-Review

**Spec coverage.** §6.3's stake weighting, 1/4 cap and 1,000-block epoch are Tasks 1–3;
§6.5's admission ramp (Bond ≥ MIN_STAKE, top 21, Unbond + cooldown + Withdraw) is Tasks
0–2; §6.6's peer discovery is Task 4; §9.2's "supply never exceeds the cap, sum of
accounts is conserved" is Task 1's property test; §10's M5 row — the coefficient plotted
and the set rotating at a boundary — is Tasks 3 and 5, wired to the CLI in Task 6.

**Not in this plan, deliberately:** slashing, delegation and a bond marketplace; a
second relay or hole punching; persisting per-epoch committees; a version field in the
header for the new transaction tags (S-19's expiry has the same prerequisite); and any
`internal/metrics` package.

**The three things most likely to go wrong.** First, **a cached committee**, which looks
correct for a whole epoch and forks at the boundary — the driver's per-height Config and
the replay test are the guards. Second, **a certificate gate still reading the genesis
set**, which passes every single-epoch test and fails the first catch-up across a
boundary. Third, **a clamp that is applied once**, which leaves the largest holder with
most of the power while every small test stays green.

**Honest limits, stated up front.** The genesis seats are bonded by the genesis hash,
not bought, so height 0 carries stake no balance funded; that is the federated v1 set
and the first *bond-driven* seat change is what M5 adds. The compiled-in testnet names
no validators at all, so a real testnet committee still has to come from a genesis
file, exactly as in M4. The 1/4 cap makes an over-concentrated distribution *capped*
rather than refused, which means a whale cannot buy more than a quarter of the vote —
but its excess stays locked until it unbonds, so the cap is a cost, not a rebate. And
the CLI's `stake` is exercised against a stub RPC and against state-level tests, not
end to end on a shipped chain: no shipped genesis funds a key with `MIN_STAKE`, since
the devnet faucet pays 1 b10 per key per epoch and a bond needs 1,000.
