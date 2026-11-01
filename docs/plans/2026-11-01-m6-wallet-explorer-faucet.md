# M6 — Wallet CLI, minimal explorer, faucet web UI

| | |
|---|---|
| Spec | `docs/2026-10-02-b10coin-design.md` M6: *"A person unfamiliar with the project can claim coins and send a transfer using only the docs."* |
| Predecessor | M5 (PR 17) plus its audit remediation (PR 19), merged at `9bd6745` |
| Acceptance | **An unfamiliar person, with only the repository's own documentation, claims coins and sends a transfer — and the walkthrough that proves it is a script, not a narrative.** |

M5 made coins buy consensus power. M6 makes them usable by someone who has
never seen the code. The distinguishing constraint is the acceptance sentence:
it is about a **person**, not a feature list, so a walkthrough a developer
performs once does not satisfy it and a walkthrough the suite performs every
run does.

---

## Global Constraints

- **`spark` is the unit.** 1 b10 = 10^8 sparks, money is `uint64`. No float in
  any balance, fee or amount, in the CLI or on a page.
- **The wallet signs; a node never holds a key.** The verbs build and sign
  locally against the node-reported genesis hash, exactly as `stake` does
  after CL-1. A verb that asks a node to sign is a defect.
- **The node is untrusted.** CL-1's rules bind M6: a fee ceiling with
  `--max-fee`, a printed transaction that **is** the signed bytes, `--yes`/TTY
  confirmation and `--dry-run`. A `send` that weakens any of them regresses a
  fixed finding.
- **Canonical encoding only** in any hashed path. Nothing M6 adds is hashed —
  if that stops being true, say so and follow the encoding rules.
- **The explorer and the faucet page are read-mostly and unauthenticated.**
  They run on the same loopback-bound RPC server. Do not add a second listener
  without saying why, and do not expose a key or a signing operation over HTTP.
- **No new dependencies.** The Go standard library has `html/template`; use it.
- **The acceptance root must not move.** `98e5cf468ecf0b6ca9c148a4ef7e5056c14254dead11efaa1f2890631cdd11cc`.
  M6 is CLI, HTTP pages and documentation; if it moves, STOP and report.

## Design decisions

1. **The walkthrough is an executable acceptance script.** The criterion names
   a person using only the docs, so the proof must be a script that reads the
   same commands the docs give, runs them against a fresh node, and asserts
   the outcome. A doc that is correct today and wrong next month is the failure
   mode; the script is what makes the doc testable.
   - Consequence: the script must **extract** the commands from the walkthrough
     document at run time and fail if the document has zero or more than one
     shell fence. A script that repeats the commands proves the script, not the
     doc, and is the mutant Task 5 exists to kill.
   - Consequence: it runs in CI on every push (`.github/workflows/ci.yml`), in a
     temporary directory against a fresh chain, with a bounded wait — otherwise
     "every run" is "the runs someone remembered".
2. **Wallet reads come from `GET /account` and a new history read**, not from a
   wallet-side chain. The CLI must not download blocks to show a balance.
   - Consequence: `balance` is one `/status` read plus one `/account` read and
     nothing else; it never opens a data directory and never scans a block. A
     verb that grew a `--dir` would be the beginning of a second node.
   - Consequence: the history read is a **server-side backward scan over
     blocks**, so it is bounded, and it reports the window it scanned. There is
     no index and M6 does not add one; `truncated` and `from`/`to` are the
     honest answer to "how far back does this go".
3. **The faucet page is a form over the existing puzzle.** The Argon2id
   pre-puzzle stays server-side; the page's job is to make the claim reachable
   by someone who does not know what a nonce is.
   - Consequence: the page performs **no solve and no signature**. Solving
     Argon2id for anonymous requests would make the node's CPU the faucet's
     cost centre, and signing over HTTP would put a key on the wire. The page
     answers eligibility from committed state and hands back the exact command
     line, which the claimant runs locally.
   - Consequence: the puzzle's parameters and the claim rule stay in
     `internal/faucet` and the state machine. The page displays the claim
     amount and the epoch; it does not re-derive either.
4. **The explorer is one page, server-rendered, no JavaScript.** A single
   `html/template` page listing recent blocks and transactions is enough for
   the acceptance sentence; anything interactive is M7 or later.
   - Consequence: no `<script>`, no inline event handler, no external asset —
     the page is a `default-src 'none'` document with an inline stylesheet, and
     a test asserts it. A page that needs a CDN is a page that needs a second
     dependency.
   - Consequence: the page reads a bounded number of blocks per request (the
     HTTP write timeout is 10 s), and does not hold the chain's lock across
     rendering.
5. **Every page states what it cannot do.** The explorer has no search, the
   faucet is rate-limited, the wallet cannot recover a lost key. A page that
   silently omits a limit teaches the operator the wrong thing.
   - Consequence: each page carries a fixed "what this page cannot do" list,
     and `history` prints the block window it scanned. The wording is a
     deliverable, not decoration: the tests assert the sentences exist.

## File structure

- `internal/rpc/wallet.go` (new) — the history read the wallet needs
- `internal/rpc/web.go`, `internal/rpc/templates/*.html` (new) — the explorer and faucet pages
- `internal/rpc/server.go` — three routes (`/history`, `/faucet`, `/explorer`), and one additive `/status` field
- `cmd/b10coin/main.go` — `balance`, `history`, `send` verbs; `claim --key`
- `cmd/b10coin/wallet*.go` (new) — signing, fee handling, the printed transaction
- `scripts/acceptance-walkthrough.sh` (new) — the executable proof
- `.github/workflows/ci.yml` — the step that runs the walkthrough on every push
- `docs/2026-11-01-m6-walkthrough.md` (new) — the walkthrough the script follows
- `docs/` — the README's M6 row, its CLI/RPC rows, and the corrected funding text
- `cmd/b10coin/main_test.go`, `internal/rpc/server_test.go` — the tests below

## Interfaces this milestone adds

```go
// ---- internal/rpc: the read surface (Task 0) --------------------------------
// GET /history?address=ADDR&blocks=N    (address optional: the explorer's feed)
type historyEntry struct {
	TxID   string `json:"txid"`
	Height uint64 `json:"height"`
	Type   string `json:"type"` // "transfer" | "faucet claim" | "bond" | "unbond" | "withdraw"
	From   string `json:"from"`
	To     string `json:"to,omitempty"`
	Amount uint64 `json:"amount"` // sparks; 0 where the type carries none
	Fee    uint64 `json:"fee"`    // sparks
}
type historyResponse struct {
	Address   string         `json:"address,omitempty"`
	Head      uint64         `json:"head"`
	From      uint64         `json:"from"`     // lowest height scanned
	To        uint64         `json:"to"`       // == Head
	Blocks    int            `json:"blocks"`   // blocks actually scanned
	Truncated bool           `json:"truncated"`
	Txs       []historyEntry `json:"txs"`      // newest first, never null
}
func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request)
func historyBlocks(q url.Values) (blocks int, err error) // default 100, range 1..500
func historyWindow(head uint64, blocks int) (from, to uint64)
func historyEntryOf(h uint64, tx *types.Tx) historyEntry
const (
	defaultHistoryBlocks = 100
	maxHistoryBlocks     = 500
	maxHistoryEntries    = 200
)

// statusResponse GAINS ONE FIELD (additive, per its existing contract):
//   ClaimAmountSparks uint64 `json:"claim_amount_sparks"`

// ---- internal/rpc: the two pages (Tasks 2 and 3) ---------------------------
func (s *Server) handleFaucet(w http.ResponseWriter, r *http.Request)   // GET /faucet[?address=ADDR]
func (s *Server) handleExplorer(w http.ResponseWriter, r *http.Request) // GET /explorer
func (s *Server) recentBlocks(head uint64, n int) ([]explorerBlock, error)
func pageHeader(w http.ResponseWriter) // Content-Type, X-Content-Type-Options, CSP
type faucetView struct { /* Task 2 */ }
type explorerView struct { /* Task 3 */ }

// ---- cmd/b10coin (Tasks 0 and 1) ------------------------------------------
func cmdBalance(args []string) error // balance --node URL (--key PATH | --address ADDR)
func cmdHistory(args []string) error // history --node URL (--key PATH | --address ADDR) [--blocks N]
func cmdSend(args []string) error    // send --node URL --key PATH --to ADDRESS --amount B10 [--max-fee SPARKS] [--yes|--dry-run]
// claim gains ONE optional flag, its ephemeral default unchanged:
//   --key PATH   sign the claim with this key file instead of an ephemeral key

// wallet.go, after Task 1's move: the ONE signing envelope every verb shares.
type walletTarget struct { /* was stakingTarget */ }
func connectWalletNode(nodeURL, keyPath string) (*walletTarget, error) // was connectStakingNode
type txOptions struct { /* was stakingTxOptions */ }
func (t *walletTarget) submit(tx *types.Tx, o txOptions, prov txProvenance) (txid string, posted bool, err error)
func buildTx(tx *types.Tx) (*builtTx, error)
func (b *builtTx) print(w io.Writer, genesisHash [32]byte, node string, prov txProvenance, maxFee uint64)
func confirmTransaction(yes bool) error
func addTxConfirmationFlags(fs *flag.FlagSet) (yes, dryRun *bool)

// ---- the CLI surface after M6 ---------------------------------------------
//   b10coin keygen  --out PATH
//   b10coin node    --dir PATH --http ADDR --block-time DUR
//   b10coin claim   --node URL [--key PATH] [--print-key=false]
//   b10coin balance --node URL (--key PATH | --address ADDR)
//   b10coin history --node URL (--key PATH | --address ADDR) [--blocks N]
//   b10coin send    --node URL --key PATH --to ADDRESS --amount 0.5 [--max-fee 1] [--yes|--dry-run]
//   b10coin stake | unstake | withdraw   (unchanged)
//   GET /explorer, GET /faucet, GET /history, GET /status, GET /block/{h},
//       GET /account/{address}, POST /tx   (the full route table after M6)
```

---

### Task 0: Wallet reads — `balance` and `history`

**Goal.** Make the node's read surface enough to answer "what do I have?" and
"what happened to it?" without downloading a chain. This task adds one JSON
route, one additive `/status` field, and two read-only CLI verbs. It signs
nothing, posts nothing, and adds no state: the state root cannot move in it.

**The interface.** The routes live in `internal/rpc/server.go:278-286` (the
one routing table) and the handler in a new `internal/rpc/wallet.go`. The two
JSON shapes in `internal/rpc/server.go:60-86` are the pattern to follow:
numbers are JSON numbers, sparks only, lists are `[]` and never `null`.

```go
// internal/rpc/wallet.go (new) — the handler and its window/entry helpers,
// exactly as declared in "Interfaces this milestone adds" above.

// internal/rpc/server.go
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/status", s.handleStatus)
	mux.HandleFunc("/block/", s.handleBlock)
	mux.HandleFunc("/account/", s.handleAccount)
	mux.HandleFunc("/history", s.handleHistory) // NEW
	mux.HandleFunc("/tx", s.handleTx)
	return mux
}
// statusResponse gains: ClaimAmountSparks uint64 `json:"claim_amount_sparks"`
// handleStatus fills it from g.Params.ClaimAmountSparks.

// cmd/b10coin/wallet.go (new) — the reads every verb needs. This file starts
// here and Task 1 moves the signing envelope into it.
func readStatus(base string) (stakingStatus, [32]byte, error)  // GET /status, parse the 32-byte genesis hash
func readAccount(base string, addr types.Address) (stakingAccount, error) // GET /account/{addr}; the echoed address must match
func walletAddress(keyPath, addrFlag string) (types.Address, error) // --key loads the keystore; --address parses canonically
func cmdBalance(args []string) error
func cmdHistory(args []string) error
```

`balance` output, pinned because the walkthrough greps it (Task 4/5):

```text
address     b10n6bx7wjzbjlw4xd5aqbo5jp27uq5yxhcziim7dy
balance     100000000 sparks (1 b10)
nonce       1
bonded      0 sparks (0 b10)
unbonding   0 records
chain       b10coin-devnet-1
height      7
```

`history` output, pinned the same way:

```text
history for b10n6bx7... (blocks 1..7, scanned 7, newest first)
     7  transfer      49999999 sparks (0.49999999 b10)  fee 1  to   b10n4m...
     1  faucet claim 100000000 sparks (1 b10)            fee 0  from -
```

**Invariants and constraints.**

- `/history` is a GET route like every other read: anything else is 405, with
  the same shape `handleStatus` returns (`internal/rpc/server.go:288-292`).
- `balance` is two reads: `/status` (chain id, height, min fee, min stake,
  claim amount) and `/account/{address}` (balance, nonce, bonded). It must not
  accept a data directory, must not open a store, and must not scan a block.
- The address the node echoes back must equal the one asked for, or the verb
  refuses. `/account` already echoes it for exactly this reason
  (`internal/rpc/server.go:316-323`), and a client that ignores the echo lets a
  node answer for somebody else.
- `--key` and `--address` are alternatives: exactly one must be given. With
  `--key` the address is `types.AddressFromPub` of the key file's public half;
  with `--address` it is `types.ParseAddress`, which is canonical and
  checksummed.
- `history` is a **backward scan over at most `blocks` blocks** starting at the
  head the request read once. `from`/`to`/`blocks` echo the window actually
  scanned, and `truncated` is true when the entry cap (`maxHistoryEntries`)
  dropped matches. An honest client can therefore tell "no more history" from
  "I stopped looking".
- The scan matches a transaction when `addr` equals its `From` **or** its `To`
  (`types.Tx.To` is `TxTransfer` only, so a bond or a claim carries the zero
  address). A zero address in `To` must never match a query.
- `blocks` is bounded: absent → 100, non-numeric → 400, `0` → 400, above 500 →
  clamped to 500 (the same "you asked for as much as allowed" rule
  `unbondingWindow` already applies at `internal/rpc/server.go:103`). The bound
  is what keeps an unauthenticated request from reading the whole store: the
  HTTP server's write timeout is 10 s and every block is a disk read.
- `BlockAt` takes and releases the chain's read lock per call
  (`internal/chain/chain.go:1005-1024`), so the handler must call it in a loop
  and must not try to hold a lock across the loop; it also must not call
  `State()` or `Head()` once per block.
- A block that cannot be read is a 500 with a generic body, never a silently
  short list and never a filesystem path (audit O-8's rule for `/block`).
- Both verbs exit 0 on success and 1 with a one-line reason on refusal; `history`
  prints the "no index, this is a window" sentence every time, not only when
  truncated (design decision 5).

**What must NOT change.**

- The four existing routes and their bodies. `/status` gains one field and
  renames none; `/account`'s fields, its `unbonding` window and its
  zeroes-not-404 behaviour stay exactly as they are. A client that ignores
  unknown fields must keep working (the comment at `internal/rpc/server.go:22`).
- `POST /tx`'s per-source limiter, body bound, decode and admission path: the
  history handler must not touch the limiter, and the pages must not add a
  bypass.
- `getJSON` and the redirect-refusing `claimHTTP` client
  (`cmd/b10coin/main.go:357-362`, audit CL-4): the new reads use them rather
  than a fresh `http.Get`.
- The certificate gate, the persisted commit lock, ST-1..ST-10's staking rules
  and CL-1's envelope: this task is read-only and must not reach any of them.
  If a diff here touches `internal/consensus`, `internal/state` or `internal/types`,
  it is wrong.
- The acceptance root `98e5cf468ecf0b6ca9c148a4ef7e5056c14254dead11efaa1f2890631cdd11cc`.
  A read cannot move it; a state or transaction change smuggled in would, and
  that is the check that catches it.

**Tests.**

- `TestStatusReportsTheClaimAmount`: `/status` carries `claim_amount_sparks`
  equal to `genesis.Devnet().Params.ClaimAmountSparks`, alongside every field
  the existing status test already asserts. Fails if the field is dropped or
  misnamed.
- `TestHistoryReportsATransferToBothParties`: a chain with a transfer
  alice→bob; querying `address=alice` and `address=bob` both return it, with
  `from` and `to` intact. Fails if the scan matches only one side, or if the
  entry swaps the two (which would tell a reader the money moved the wrong way).
- `TestHistoryWindowIsBoundedAndSaysWhatItScanned`: `blocks=10000` clamps to
  500 and `blocks` reports 500; a 3-block chain reports `from`/`to` and
  `blocks=3`; the entry cap sets `truncated`. Fails if the window is ignored and
  the whole chain is walked, or if `truncated` is always false.
- `TestHistoryRefusesAZeroOrGarbageWindow`: `blocks=0`, `blocks=x` → 400;
  a non-canonical address → 400 with the address not echoed raw.
- `TestHistoryIsSafeDuringAppends`: the handler runs while blocks are appended
  (the pattern of `TestRPCReadsAreSafeDuringAppends`); every reply is a
  well-formed window whose `to == head` and whose entries are a subset of that
  window. Fails on a torn read or a half-written response.
- `TestBalanceVerbPrintsSparksAndB10Exactly`: an account holding
  `10_000_000` sparks prints `10000000 sparks (0.1 b10)`. A float64 conversion
  prints `9999999` for a tenth of a b10, so this row kills it.
- `TestBalanceOutputFormatIsStable`: the label column is the one the walkthrough
  greps (`address`, `balance`, `nonce`, `bonded`, `unbonding`, `chain`,
  `height`). Fails if a label is renamed, which would break Task 4's commands.
- `TestBalanceRefusesANodeNamingAnotherAccount`: the stub reports a different
  address; the verb refuses before printing a balance.
- `TestHistoryVerbPrintsTheWindowAndItsLimit`: the output names the block range
  and says there is no index. Fails if decision 5 is dropped from the verb.

**The mutants.**

- The handler ignores `blocks` and walks to height 0: the window test's
  `blocks=500` assertion and the timing of `TestHistoryIsSafeDuringAppends` die.
- `truncated` is hard-coded false: the entry-cap row dies.
- The scan matches `From` only: bob's query returns nothing.
- A faucet claim is reported as a transfer to the zero address: the
  both-parties test's entry list gains a phantom.
- `balance` divides sparks by a float: the 0.1-b10 row prints 9,999,999.
- The handler calls `s.chain.State()` per block: the append-during-read test
  finds a reply whose entries are outside its own window.
- `/status` renames `min_fee_sparks` instead of adding `claim_amount_sparks`:
  the existing status test dies.

Each must die on a *named* test. A survivor is a hole in the suite, not a pass.

---

### Task 1: `send` — the transfer verb

**Goal.** Let a person who holds a key pay another person, with the same safety
envelope that CL-1 put on `stake` — and let a claim fund *that* key, because
today it cannot. This is the task the acceptance sentence actually needs: a
stranger cannot send anything if the only claim path throws its key away.

Two gaps make this task larger than "one more verb", and both are the plan's,
not an implementer's choice:

- `claim` signs with an ephemeral key it prints and never stores
  (`cmd/b10coin/main.go:370-457`), and nothing in the tree turns a printed key
  into a key file — `keystore` has `Generate` and `Load` only. So the shipped
  claim path funds an address that no verb can sign for. `claim --key PATH`
  closes that: the claim funds a key the operator holds.
- `send` must not become a second signing path. The envelope already exists;
  this task **moves** it into `cmd/b10coin/wallet.go` and renames its type so a
  transfer is not called "staking", and adds nothing to it.

**The move, stated exactly.** `stakingTarget` → `walletTarget`,
`connectStakingNode` → `connectWalletNode`, `stakingTxOptions` → `txOptions`.
Everything else moves verbatim: `builtTx`, `buildTx`, `print`, `submit`,
`confirmTransaction`, `askConfirmation`, `stdinIsTerminal`, `errNoAnswer`,
`feeCeilingReason`, `defaultMaxFeeSparks`, `maxFeeHelp`, `txProvenance`,
`addTxConfirmationFlags`, `stakingStatus`, `stakingAccount`,
`stakingUnbondingRec`. The two JSON structs keep their names: the test suite
references them 37 times and a rename would churn it for no behaviour. If the move
forces any change to a CL-1 test beyond a symbol name, **stop** — that is the
signal the move changed behaviour.

**The interface.**

```go
// cmd/b10coin/wallet.go — moved, then extended by exactly three things.

// (1) the preview learns the transfer type. These two lines are wrong for a
// transfer today and must branch correctly:
//   print's fee line has THREE cases after this task, and each is a true
//     statement to the signer: bond/transfer -> the node's claim, with the
//     ceiling; unbond/withdraw -> "fixed at 0 by consensus: an exit is free";
//     faucet claim -> "fixed at 0 by consensus: a claim may not carry a fee";
//   print's amount line: a transfer prints its amount AND its recipient;
//   print's claim line: a faucet claim prints its epoch and pow nonce,
//     labelled as the NODE's claim (the epoch is the transaction's only
//     time binding, and it is signed).
func (b *builtTx) print(w io.Writer, genesisHash [32]byte, node string, prov txProvenance, maxFee uint64)

// (2) the cover check, split so a transfer's refusal stays honest. A bond
// that is short may be fixed by funding to MIN_STAKE; a transfer that is short
// is never fixed that way, so the transfer must not inherit the bond's lecture
// (the M5 Docker re-run, 2026-10-30, was exactly this mistake in the other
// direction). Same arithmetic, same "short %d sparks" tail.
func checkCover(balance, amount, fee uint64) error                        // NEW: no hint
func checkSpendable(balance, amount, fee, minStake uint64) error          // bond: checkCover + fundingNote

// (3) the verb.
func cmdSend(args []string) error
//   --node URL        default http://127.0.0.1:8645
//   --key PATH        required; the key that pays
//   --to ADDRESS      required; types.ParseAddress
//   --amount B10      required; genesis.ParseB10, exact decimal, sparks only
//   --max-fee SPARKS  default defaultMaxFeeSparks (1)
//   --yes | --dry-run shared with stake/unstake/withdraw

// cmd/b10coin/main.go — cmdClaim gains one optional flag.
//   --key PATH        sign the claim with this key file; absent = today's
//                     ephemeral path, byte-identical in output and behaviour.
```

`send` builds one `types.Tx{Type: types.TxTransfer, From, PubKey, To, Nonce,
Fee, Amount}` and hands it to `submit`. The nonce and the fee come from the
node's `/status` and `/account` reads (`t.status.MinFeeSparks`,
`t.account.Nonce`), exactly as `cmdStake` does at `cmd/b10coin/main.go:1050-1057`;
`--amount` and `--to` are the operator's own and are the only two values the
verb can vouch for. The `effect` line says the recipient is credited when a
block includes the transaction, that the fee is burned, and that the signature
cannot be withdrawn.

`claim --key` builds `types.Tx{Type: types.TxFaucetClaim, From, PubKey, Nonce:
t.account.Nonce, Fee: 0, Epoch: (height+1)/EpochBlocks + 1, PowNonce}` and also
goes through `submit`. Its fee is 0 by consensus (`state.ErrClaimCarriesFee`),
so the ceiling is inert but still enforced; its epoch is the node's claim and
the preview prints it and the pow nonce, labelled as the node's claim (the
claim's binding is a time window, so the epoch is the one field a reader must
be able to see).

**Invariants and constraints.**

- **One envelope, one signing path.** `submit` remains the only function that
  calls `crypto.Sign` for a CLI verb: it builds the transaction once, prints
  those bytes, checks the fee ceiling **on the fee decoded back from them**,
  honours `--dry-run` before the confirmation, and asks for confirmation before
  the signature. `send` and `claim --key` must not sign anywhere else.
- The fee is the node's claim and is floored by the chain: a node reporting
  `min_fee_sparks` 0 is refused before signing (the same guard `cmdStake` has
  at `cmd/b10coin/main.go:1028`), because `state.applyTransfer` refuses a fee
  under the minimum and a zero-fee transfer could never apply.
- `--amount` is parsed by `genesis.ParseB10` and must be positive; zero is a
  refusal before any network call (`state.ErrZeroAmount`), and so is a
  self-transfer (`state.ErrSelfTransfer`) and a malformed `--to`. These are
  cheap local checks; letting the node be the first to notice teaches nothing.
- The account must cover `amount + fee` with the overflow check
  (`checkCover`), before signing. The refusal says how short it is and nothing
  else: `send` does not append the MIN_STAKE funding hint, because a transfer
  short by a hundred sparks is not a bond short by a thousand b10, and telling
  a sender about `stake` is the same class of misleading hint the M5 Docker
  re-run found in the bond path (`fundingNote`, `cmd/b10coin/main.go:867`, stays
  bond-only).
- The signature is bound to the genesis hash the node reports, never to a
  compiled-in devnet assumption.
- `claim --key` requires the key file to own the account the node reports
  (`connectWalletNode` already refuses otherwise), reads the nonce instead of
  assuming 0, and still refuses to run against a chain whose ID is not the
  compiled-in devnet (`cmd/b10coin/main.go:409-411`) — the puzzle parameters are
  compiled in, so any other chain would reject the proof anyway.
- No amount, fee or balance touches a float anywhere in either path.

**What must NOT change.**

- **CL-1's envelope, field by field**: the ceiling default (`1`, derived at
  `cmd/b10coin/main.go:546-566`), the printed-then-signed order, `--dry-run`
  beating `--yes`, the no-TTY refusal, the redirect refusal, and the
  post-signature note that the transaction cannot be withdrawn.
- `claim`'s default path: ephemeral key, printed once, `--print-key=false`
  withholding it, nonce 0, no preview, no confirmation. `--key` is an addition;
  an operator who does not pass it sees byte-identical output.
- `stake`/`unstake`/`withdraw` behaviour and their refusals, including the
  ST-1 floor on a partial exit, the ST-3 funded-first split (`splitUnbondExit`)
  and the ST-4 release forecast (`releaseForecast`, `ceilToEpoch`).
- `POST /tx`'s limiter, body bound and admission; the mempool's per-key and
  per-block claim caps; the certificate gate and the persisted commit lock —
  none of which this task may touch.
- The acceptance root `98e5cf468ecf0b6ca9c148a4ef7e5056c14254dead11efaa1f2890631cdd11cc`.
  A new verb cannot move it. If it moves, something changed a signed encoding or
  a state leaf, and the commit is wrong.

**Tests.**

- `TestSendVerbSubmitsATransferWithTheRightFields`: the stub captures the POST;
  the decoded transaction has `Type == types.TxTransfer`, the key file's
  address, the stub's nonce, the stub's `min_fee_sparks`, the amount in sparks,
  and the expected recipient; its signature verifies against the stub's genesis
  hash. This is the verb's whole job, tested without a chain.
- `TestSendPostsExactlyThePrintedBytesPlusASignature`: reuse the `printedTx`
  helper the staking tests already have — the posted encoding minus `Sig` is
  byte-identical to the printed hex, and the printed transaction carries no
  signature. Fails if the preview is rendered from a second source.
- `TestSendPreviewNamesTheRecipientAndTheAmount`: the preview contains the
  recipient address, `50000000 sparks (0.5 b10)`, and a fee line that names the
  node's claim and the ceiling. Fails if the transfer path inherits the "an exit
  is free" line, which would be a false statement to the signer.
- `TestSendRefusesAHostileFee`: the stub reports a fee equal to
  `balance - amount`; the verb refuses, nothing is signed, nothing posted. The
  same attack `TestHostileNodeFeeIsRefused` runs against `stake`.
- `TestSendRefusesMoreThanTheAccountCanCover`: a 0.5 b10 send from a balance of
  0.4 b10 is refused with the shortfall, before signing.
- `TestASendRefusalDoesNotLectureAboutStake`: the same refusal contains
  "short" and does **not** contain "no shipped genesis". Fails the moment
  `send` is wired to `checkSpendable` instead of `checkCover` — and a sender
  told to go and fund a bond would be told something true about the wrong
  transaction.
- `TestSendRefusesZeroAmountSelfTransferAndABadAddress`: three table rows; each
  refuses before any HTTP request (the stub records no reads and no posts).
- `TestSendDryRunSignsAndPostsNothing`: `--dry-run` prints and stops; the stub
  sees no POST.
- `TestSendRefusesAZeroReportedMinFee`: the stub reports `min_fee_sparks: 0`;
  the verb refuses.
- `TestClaimWithKeySignsForTheKeyFileAndUsesTheAccountsNonce`: the stub reports
  nonce 1; the posted claim has `From` = the key file's address, nonce 1,
  `Fee == 0`, the epoch derived from the stub's height, and a signature that
  verifies. Fails if `--key` silently keeps signing with an ephemeral key.
- `TestClaimWithKeyGoesThroughTheEnvelope`: `--dry-run` posts nothing, and no
  `--yes` with a non-TTY stdin refuses. `--yes` posts.
- `TestClaimPreviewPrintsTheEpochAndThePowNonce`: the preview for a claim names
  the epoch and the nonce and labels them the node's claim. Fails if the claim
  preview is the bond/exit preview with a different type line.
- `TestClaimWithoutKeyIsUnchanged`: no `--key` → the ephemeral path still
  prints a key, still has no preview, and still posts a claim whose `From` is
  not any key file.

**The mutants.**

- `send` builds its own transaction and signs it directly: the printed-bytes
  test and the hostile-fee test both die.
- The ceiling is checked against the *flag* instead of the decoded fee: the
  hostile-fee test passes a fee the verb never sees and the attacker's
  `balance - amount` is signed.
- The transfer preview reuses the exit's "fixed at 0 by consensus" line: the
  preview test dies. The claim preview reusing it is the same defect wearing a
  different type — "a claim may not carry a fee" and "an exit is free" are
  different facts and both tests pin one.
- `send` posts with `Fee: 0`: the min-fee guard test dies (and the chain would
  refuse the transaction at execution).
- `send` calls `checkSpendable` with the chain's `min_stake_sparks`: the
  no-lecture test dies, and every short transfer carries advice about staking.
- `send` signs against `genesis.Devnet().Hash()` instead of the reported hash:
  the different-genesis case in `TestSendVerbSubmitsATransferWithTheRightFields`
  dies.
- `claim --key` still generates an ephemeral key: the claim-nonce/`From`
  assertions die.
- `claim --key` writes the key to disk "for convenience": the file-system
  assertion in `TestClaimWithKeyGoesThroughTheEnvelope` (no new files in the
  key's directory) dies.

---

### Task 2: The faucet web UI

**Goal.** Give a stranger a page that answers, without a terminal: how much is
in the faucet, what one claim pays, whether *their* address can claim now, and
exactly what to run. It is a page over the existing puzzle — it solves nothing,
signs nothing and submits nothing.

**The interface.**

```go
// internal/rpc/web.go (new) — shared by Tasks 2 and 3
//go:embed templates/*.html
var templateFS embed.FS
var pageTemplates = template.Must(template.ParseFS(templateFS, "templates/*.html"))

func pageHeader(w http.ResponseWriter) // "text/html; charset=utf-8",
//   X-Content-Type-Options: nosniff, and
//   Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'

type faucetView struct {
	ChainID        string
	Height         uint64
	EpochBlocks    uint64
	Epoch          uint64 // (height+1)/EpochBlocks + 1: the 1-BASED epoch of the block that will apply the claim
	ClaimAmount    uint64 // sparks, from state.Params().ClaimAmount
	ClaimAmountB10 string // genesis.FormatB10
	FaucetAddress  string
	FaucetBalance  uint64 // state.Get(genesis.FaucetAddress()).Balance
	FaucetBalB10   string
	NodeURL        string // from the request's Host, so the command is copy-pasteable

	Queried      string // the raw query, echoed only after validation
	QueriedAddr  string // canonical form, "" when absent
	QueriedErr   string // why the query was refused
	CanClaim     bool
	ClaimedEpoch uint64
	Reason       string // the sentence rendered next to CanClaim
	Command      string // "b10coin claim --node <NodeURL> --key <path>"
}

func (s *Server) handleFaucet(w http.ResponseWriter, r *http.Request) // GET only
func (s *Server) faucetView(nodeURL, rawAddr string) (faucetView, error)
```

The template is `internal/rpc/templates/faucet.html`: a `<form method="get"
action="/faucet">` with one `<input name="address">`, a table of the numbers
above, the command in a `<pre>`, and a fixed "what this page cannot do" list.
A GET form is deliberate — a POST would need a body bound, a CSRF story and a
reason to exist, and this page has no state to change.

Server-side numbers come from state the server already holds:
`s.chain.State().Params()` gives `ClaimAmount`, `EpochBlocks` and
`FaucetAddress`; `s.chain.Height()` gives the head; `st.Get(addr).ClaimedEpoch`
gives eligibility. Nothing is added to the RPC contract for this page except
the one `/status` field Task 0 added (which the CLI's claim preview uses).

**Invariants and constraints.**

- **No signing, no solving, no submission.** The handler must not call
  `faucet.Solve`, `faucet.SolveClaim`, `crypto.Sign` or `mempool.Add`. The
  rendered page must contain no `<form method="post">` and no path to `/tx`.
  This is the constraint that makes an unauthenticated page safe to run on a
  node: every request costs a few state reads.
- A private key pasted into the address field is refused **by name**: 128 hex
  characters (or 64) is not an address, and the refusal says never to paste a
  key into a page. A form that silently accepts a secret over plain HTTP is a
  trap, and the page is served over plain HTTP.
- The address is validated with `types.ParseAddress` before it is echoed. The
  canonical form is what the page renders; the raw query is rendered only
  inside the refusal sentence and only through `html/template`'s escaping.
- The epoch is `(height+1)/EpochBlocks + 1` and 1-based, because the claim is
  applied by the next block and `state.applyFaucetClaim` compares against THAT
  block's epoch. `claim` already derives it this way
  (`cmd/b10coin/main.go:414`); the page must agree with the verb, and must not
  read `state.height` (the next block's execution context) for it.
  `ClaimedEpoch >= epoch` means "already claimed in this epoch" — the same
  comparison the state machine makes.
- The claim amount is printed in both units from one integer: `1 b10` is
  `100000000 sparks`. A page that formats `1.0` is the float mutant.
- The command line names `claim --key`, not the bare `claim`: the page's whole
  point is that the coins land on a key the person keeps.
- **No second listener.** The page is a handler on the existing `Server`; the
  node's `--http` address stays `127.0.0.1:8645` by default and both node modes
  already share one `http.Server` shape (`cmd/b10coin/main.go:1398-1406` and
  `1623-1631`).

**What must NOT change.**

- `/status`, `/account`, `/block` and `/tx` behaviour, and the routing table's
  existing patterns.
- The claim rule and the puzzle: no parameter, target, or bound is touched, and
  the page must not become a place where a second, "web" faucet could grow.
- The certificate gate, the persisted commit lock, ST-1..ST-10's staking rules
  and CL-1's envelope: this task adds a handler and a template and nothing else.
- The acceptance root `98e5cf468ecf0b6ca9c148a4ef7e5056c14254dead11efaa1f2890631cdd11cc`.
  A page reads state; if the root moves, a write was smuggled into a read.

**Tests.**

- `TestFaucetPageStatesItsLimitsAndTheClaimAmount`: the body contains the claim
  amount in both units, the epoch and epoch length, the one-claim-per-key rule,
  and the "cannot sign / cannot hold your key / cannot pay you" sentences.
  Fails if decision 5 is dropped.
- `TestFaucetPageReportsEligibility`: a chain where `alice` claimed this epoch
  and `bob` did not — `?address=<alice>` renders "already claimed in epoch N",
  `?address=<bob>` renders the command line. Fails if eligibility is inverted
  (the `>=` vs `>` mutant) or computed from the wrong height.
- `TestFaucetPageRefusesAPrivateKeyInTheAddressField`: a 128-hex query is
  refused with the never-paste-a-key sentence, and the rendered page does not
  echo the secret.
- `TestFaucetPageIsReadOnly`: `POST /faucet` is 405 and the rendered body has no
  `method="post"` and no `/tx` reference. Fails if the page grows a submit path.
- `TestThePagesEscapeEveryValueTheyRender`: an address query containing
  `"><script>` reaches the handler and the body contains neither `<script` nor
  the unescaped bytes. Fails the moment a template uses `template.HTML`.
- `TestFaucetPageIsSafeDuringAppends`: renders while blocks are appended; every
  response is 200 or a clean error, never a partially written page.

**The mutants.**

- The handler solves the puzzle for the queried key (the "helpful" version):
  the page then costs an Argon2id evaluation per request; the review item is the
  missing call, and the read-only test catches the submit half of the same
  mistake.
- The page posts a claim on the operator's behalf: the 405/no-POST-form test.
- Eligibility uses `ClaimedEpoch > epoch`: the claimed address is told it can
  claim.
- The page formats b10 through a float: the exact `100000000 sparks` assertion.
- The query is written into the template through `template.HTML` "so the
  command renders": the escaping test.
- The page serves at a new address on a second listener: not a test — a review
  rejection, named in the brief so it is not a surprise.

---

### Task 3: The minimal explorer

**Goal.** One page that shows the chain is alive and what it is carrying:
the head, the last blocks, the last transactions, and what the page cannot do.
Server-rendered, no JavaScript, no external asset, no search.

**The interface.**

```go
// internal/rpc/web.go
type explorerBlock struct {
	Height uint64
	Hash   string // hex
	Time   int64  // unix seconds, as the header carries it
	Txs    int
	Root   string // hex, the block's state root
}
type explorerView struct {
	ChainID   string
	Height    uint64
	HeadHash  string
	StateRoot string
	Blocks    []explorerBlock // newest first
	Txs       []historyEntry  // newest first; the Task 0 entry type, reused
	CannotDo  []string        // the fixed limit list, rendered as a <ul>
}
func (s *Server) handleExplorer(w http.ResponseWriter, r *http.Request) // GET only
func (s *Server) recentBlocks(head uint64, n int) ([]explorerBlock, error)
const (
	explorerBlocks = 20 // blocks rendered per request
	explorerTxs    = 20 // transactions rendered per request
)
```

The template is `internal/rpc/templates/explorer.html`: a header table
(chain id, height, head hash, state root), a blocks table, a transactions
table, and the "what this page cannot do" list. `CannotDo` is fixed text, and
its content is a deliverable: **no search; no address lookup (use `b10coin
history`); no pagination; at most 20 of each; times are unix seconds; a
transaction appears only once a block includes it; this is one node's view of
one chain, not a network view.**

**Invariants and constraints.**

- Blocks are read newest-first from the head the handler read once. Pin the
  loop so a `uint64` cannot wrap at height 0:

  ```go
  lo := uint64(0)
  if head >= uint64(n) { lo = head - uint64(n) + 1 }
  for h := head + 1; h > lo; {
      h--
      // BlockAt(h) -> explorerBlock
  }
  ```

  `head` is captured once and passed in, so the page's numbers agree with each
  other; a second `Height()` call mid-render is the torn-read mutant, and a
  `for h := head; h >= 0; h--` is the wrap that never terminates.
- `BlockAt` under the hood (`internal/chain/chain.go:1005`): the genesis block
  at height 0 comes from `genesisState`/`genesisBlock`, not from the store, so a
  fresh chain renders one block and does not 404.
- The transaction list is the Task 0 scan with no address filter, capped at
  `explorerTxs`; the explorer must **reuse** `handleHistory`'s helpers rather
  than grow a second scan. One scan path, one set of bounds.
- A block that cannot be read is a 500 page with a generic message — never a
  silently short table and never a filesystem path (audit O-8). The test that
  proves it removes a segment file, the way
  `TestBlockEndpointDoesNotLeakFilesystemPaths` does.
- Total work per request is bounded by `explorerBlocks` disk reads plus the
  history window; the HTTP server's write timeout is 10 s, and the page must
  render well inside it on a real data directory.
- The page carries the same `pageHeader` as the faucet: `html/template`
  escaping, `nosniff`, and `default-src 'none'` with an inline stylesheet. No
  `<script>`, no `on…=` attribute, no `<link rel=stylesheet href=…>`.

**What must NOT change.**

- `/block/{height}`'s response shape and its no-path-leak behaviour: the
  explorer renders the same facts in HTML and must not change the JSON route.
- The history handler's bounds and `truncated` semantics from Task 0.
- The certificate gate, the persisted commit lock, ST-1..ST-10's staking rules
  and CL-1's envelope — a page cannot reach them, and a diff that does is wrong.
- The acceptance root `98e5cf468ecf0b6ca9c148a4ef7e5056c14254dead11efaa1f2890631cdd11cc`.

**Tests.**

- `TestExplorerListsRecentBlocksNewestFirst`: a 3-block chain; the page contains
  heights 2, 1, 0 in that order (assert the index positions, not just presence —
  presence passes even when the order is reversed).
- `TestExplorerShowsATransferFromARecentBlock`: a chain with a transfer; the
  page contains the transaction id's first 16 hex characters, `transfer`, and
  the amount in sparks.
- `TestExplorerOnAGenesisOnlyChain`: height 0 renders one block, one empty
  transaction table, and returns 200. Fails if the loop reads height -1 or
  `BlockAt` is asked for a height that does not exist.
- `TestExplorerIsSafeDuringAppends`: renders while appending; every page's
  height, head hash and block table agree with one snapshot, and no request
  fails with a partially written body.
- `TestThePageHasNoScriptAndNoExternalResource`: the body contains no
  `<script`, no `onload=`, no `http://` or `https://` asset reference, and the
  `Content-Security-Policy` header is present.
- `TestExplorerReportsAnUnreadableBlockAsAPageError`: remove a segment file,
  then `GET /explorer` returns 500 and the body contains neither the data
  directory nor the segment name.

**The mutants.**

- The block loop runs forward (`0..head`): the newest-first position assertions
  die.
- `Head()` is called again inside the loop: the during-appends test finds a page
  whose header disagrees with its own first block.
- The explorer writes its own scan instead of reusing Task 0's: the window and
  `truncated` tests cover only one of the two paths, which is the point — the
  duplicate is caught in review as a second source of truth.
- The template gains a `<script>` for "just a refresh": the no-script test.
- `BlockAt`'s error is swallowed and the block is skipped: the missing-segment
  test renders a 200 with a gap.

---

### Task 4: The walkthrough the script follows

**Goal.** Write the document a stranger actually reads. It must be complete
enough that the person needs nothing else, and shaped so that a script can run
it: **exactly one** fenced `sh` block, whose lines are the commands, with the
setup expressed as environment variables at the top.

The file is `docs/2026-11-01-m6-walkthrough.md`. Its sections, in order:

1. **What you will do**, in three sentences: make two keys, claim 1 b10 from
   the faucet, send 0.5 b10 to the other key, watch it land.
2. **What you need**: this repository, a Go toolchain (the go.mod
   `toolchain` line is what the `go` command uses), a terminal, and nothing
   else. No accounts, no node, no coins.
3. **The commands** — the one `sh` fence. Everything before it explains what
   it will do; nothing after it re-states a command.
4. **What you should see** — the exact output lines, quoted, with the numbers
   this plan verified (Task 5 asserts them, so they must match).
5. **What this cannot do** — the limit list: one claim per key per epoch; 1 b10
   per claim on the devnet; `MIN_STAKE` is 1,000 b10, so this walkthrough does
   *not* make you a validator (1,001 keys and 1,001 transfers, ~2,002 blocks of
   faucet emission, is what it would take); `claim` is devnet-only as shipped;
   a lost key is a lost balance; the node is untrusted and the printed
   transaction is the thing that gets signed; the explorer and faucet pages are
   read-only views of the same node.
6. **Where to read more** — `README.md`'s CLI, Staking and RPC sections, and
   the plan this came from.

**The fence, exactly.** It must start from the repository root and be safe to
paste. The variables `B10`, `WORK` and `PORT` are overridable so the acceptance
script can point them at a temporary directory and a free port without editing
the doc; the defaults are what a reader gets.

```sh
export B10=${B10:-bin/b10coin}
export WORK=${WORK:-./walkthrough}
export PORT=${PORT:-18645}
export NODE=http://127.0.0.1:$PORT
mkdir -p "$WORK"
$B10 keygen --out "$WORK/alice.key"
BOB=$($B10 keygen --out "$WORK/bob.key" | sed -n 's/^seat address //p')
$B10 node --dir "$WORK/data" --http "127.0.0.1:$PORT" --block-time 500ms >"$WORK/node.log" 2>&1 &
echo $! >"$WORK/node.pid"
for i in $(seq 1 50); do $B10 balance --node "$NODE" --key "$WORK/alice.key" >/dev/null 2>&1 && break; sleep 0.2; done
$B10 claim --node "$NODE" --key "$WORK/alice.key" --yes
$B10 balance --node "$NODE" --key "$WORK/alice.key"
$B10 send --node "$NODE" --key "$WORK/alice.key" --to "$BOB" --amount 0.5 --yes
for i in $(seq 1 40); do $B10 balance --node "$NODE" --address "$BOB" | grep -q '50000000 sparks' && break; sleep 0.5; done
$B10 history --node "$NODE" --key "$WORK/alice.key"
$B10 balance --node "$NODE" --address "$BOB"
kill "$(cat "$WORK/node.pid")"
```

Two things about that block are load-bearing and must not be "tidied":

- `BOB` is parsed from `keygen`'s own output (`seat address <addr>`), because
  the address is not known until the key exists. A hard-coded address would be
  a second source of truth, and the doc would break on the next keygen change.
- The two wait loops are commands a human needs too: a node takes a moment to
  bind, and a transfer appears only when a block includes it. They are bounded
  so a stuck run fails instead of hanging.

**Invariants and constraints.**

- **Exactly one ```sh fence** in the file. The acceptance script asserts the
  count and extracts that block; a second fence, or a ```` ```bash ```` fence
  the extractor does not expect, silently changes what is tested.
- Every command in the fence must be a command this milestone ships, with flags
  that exist. The doc may not document an aspiration.
- Every number in the prose matches the chain's parameters, verified against
  `internal/genesis/genesis.go:523-556`: claim 1 b10 = 100,000,000 sparks;
  `min_fee_sparks` 1; `epoch_blocks` 1000; `min_stake_sparks` 10^11; the send is
  50,000,000 sparks, leaving the sender 49,999,999 and the recipient exactly
  50,000,000.
- The doc names the *output* it expects, so a reader can tell success from a
  hang: `claimant`/`txid` from `claim`, the `transfer to` line from `send`'s
  preview, the `balance` line's exact sparks, and the `history` window line.
- No "as discussed", no "see the commit", no session context. The doc is the
  only document a stranger reads.
- The doc must state the funding limit as a limit, not bury it: one claim pays
  1 b10, `MIN_STAKE` is 1,000 b10, and the walkthrough does not reach it.

**What must NOT change.**

- The CLI's flags, defaults and output formats as Tasks 0 and 1 pinned them.
  If a command in the fence needs a flag that does not exist, the fix is the
  verb (Task 1), not a different command in the doc.
- `claim`'s ephemeral behaviour in its default form, and `keygen`'s
  "refuses to overwrite" rule: the doc must not tell a reader to rerun `keygen`
  over an existing file.
- The acceptance root `98e5cf468ecf0b6ca9c148a4ef7e5056c14254dead11efaa1f2890631cdd11cc`:
  the walkthrough prints chain output, and the doc quotes none of it as a fixed
  root — but a reader running `devnet --blocks 100` must still see that number,
  so the doc's "where to read more" points at the README figure rather than
  inventing one.

**Tests.**

- There is no Go test for prose. The test is Task 5's script: it fails if a
  command in the fence does not run, if an output line the doc promises does not
  appear, or if the fence count is not exactly one.
- A reviewer check the script cannot make: read the doc cold and confirm every
  claim is either a command in the fence or a number that matches
  `internal/genesis/genesis.go`. Anything else is prose that will be stale
  before M7.

**The mutants.**

- A second ```sh fence (a "quick version" of the commands): the script's fence
  count fails, which is the point of counting.
- The doc quotes a `send --amount 1` that the balance cannot cover: the
  script's balance assertion fails.
- The doc drops the "this does not reach MIN_STAKE" paragraph: no automated
  test kills this one, so it is called out here as the review item — decision 5
  is a deliverable, and the honest limit is the paragraph a stranger most needs.
- The doc tells the reader to reuse the ephemeral key that `claim` printed:
  `claim --key` exists, so the instruction would be obsolete and the script's
  key-file assertions would fail.

---

### Task 5: The acceptance script

**Goal.** Make the doc executable on every push: extract its one fence, run it
against a fresh chain in a temporary directory, and assert the outcome the doc
promises. This is the milestone's acceptance artefact — `PLAN OK` is not the
acceptance, this script passing is.

**The interface.**

```sh
# scripts/acceptance-walkthrough.sh [--doc PATH] [--keep]
#   exit 0  the doc's commands ran and produced the promised outcome
#   exit 1  a command failed, a promised line is missing, or the doc's shape is wrong
#   exit 2  bad invocation / the tree cannot build
#
# Environment: B10COIN_DOC (default docs/2026-11-01-m6-walkthrough.md),
#              B10COIN_TIMEOUT (default 120, seconds for the whole run).
```

Behaviour, in order:

1. Locate the repository root from the script's own path, so it runs from any
   cwd (`cd "$(dirname "$0")/.."`).
2. Build the binary into the temporary directory:
   `go build -o "$tmp/b10coin" ./cmd/b10coin`. Building into `$tmp` rather than
   `bin/` means the script can never test a stale binary and never writes into
   the repository.
3. Count the doc's ```sh fences. Anything other than exactly 1 is a failure
   with the count printed.
4. Extract the block (awk between the fence lines) into `$tmp/commands.sh`.
5. Run it with `B10="$tmp/b10coin"`, `WORK="$tmp/work"` and `PORT` exported,
   from `$tmp`, with stdout+stderr into `$tmp/run.log`. `PORT` is
   `$((20000 + RANDOM % 20000))`, and a readiness that never succeeds is
   reported as "the port may be busy, or the node did not start — see
   $tmp/work/node.log". No `set -e` inside the extracted block: the script
   judges the exit code.
6. Assert on `$tmp/run.log`, each with its own message:
   - the claim printed a `txid        <64 hex>` line;
   - the send's preview names `$BOB` on its `to` line and prints
     `50000000 sparks`;
   - the sender's `balance` line shows `49999999 sparks (0.49999999 b10)`;
   - the recipient's `balance` line shows `50000000 sparks (0.5 b10)`;
   - `history` printed a `transfer` line for the recipient and the
     `blocks A..B, scanned` window line.
7. Print `OK` and exit 0, or print the failing assertion plus the log tail and
   exit 1. Always remove `$tmp` (`--keep` keeps it and prints the path), and
   always kill the node: the script reads `$tmp/work/node.pid` in its EXIT trap,
   because the extracted block may die before its own `kill`.

**Invariants and constraints.**

- **The commands come from the doc, never from the script.** The script must
  contain no `b10coin claim`/`send`/`balance` invocation of its own except as
  assertions over the log. A script that hardcodes the commands proves nothing
  about the doc, which is the failure decision 1 exists to prevent.
- Every wait is bounded and every failure names the assertion that failed. A
  hanging CI step is an outage, not a test result.
- Cleanup is unconditional: `trap` on EXIT/INT/TERM, kill the node by pid file,
  remove `$tmp` unless `--keep` (which exists so a human can debug a failure).
- No new runtime dependency: bash, coreutils, `sed`, `awk`, `grep`, and the
  built binary. No `curl`, no `jq`, no Python. (The walkthrough's readiness wait
  uses the CLI itself for the same reason.)
- **`shellcheck --severity=warning` must be clean.** CI runs it over every
  tracked `*.sh` (`.github/workflows/ci.yml:180-187`), and a script that lands
  with warnings fails the whole pipeline for an unrelated reason.
- The script is added to the CI acceptance job as one more step beside the four
  `devnet` commands (`.github/workflows/ci.yml:141-144`), so "the suite performs
  it every run" is literally true. It must finish well inside CI's job timeouts;
  the walkthrough is a handful of blocks at 500 ms, so the whole run is tens of
  seconds, and `B10COIN_TIMEOUT` bounds it.
- The script must not run under `set -e` for the extracted block, and must not
  inherit a caller's `CDPATH`, `IFS` or `B10`/`WORK`/`PORT` — it exports them
  explicitly.

**What must NOT change.**

- `scripts/check-plan.sh`, `scripts/check-strays.sh` and the other scripts: this
  task adds a script and a CI step, and touches neither.
- The four `devnet` acceptance commands in CI and their expected outputs.
- The certificate gate, the persisted commit lock, ST-1..ST-10's staking rules,
  CL-1's envelope: the script exercises the CLI, not consensus internally, and
  must not need a second node or a committee.
- The acceptance root `98e5cf468ecf0b6ca9c148a4ef7e5056c14254dead11efaa1f2890631cdd11cc`:
  the walkthrough runs on a fresh chain that never reaches `--blocks 100`, so it
  cannot re-derive that figure. The README's figure stays the one the `devnet`
  command prints, and this script must not assert it.

**Tests.**

- The script is its own test. Three ways a reviewer proves it is real:
  delete one command from the doc's fence and watch the script fail; change
  `--amount 0.5` to `--amount 2` and watch the balance assertion fail; add a
  second fence and watch the count assertion fail.
- `bash -n scripts/acceptance-walkthrough.sh` and
  `shellcheck --severity=warning scripts/acceptance-walkthrough.sh` are part of
  the task's own verification, not the reviewer's.
- A green CI run on the branch is the evidence that it runs on every push.

**The mutants.**

- The script repeats the commands instead of extracting them: change the doc's
  `--block-time` and the script still passes — the mutant a reviewer kills by
  editing the doc.
- The script greps only for `OK`/`txid`: with `--amount 0.5` replaced by
  `--amount 0`, the transaction is refused and the `txid` assertion is what
  catches it; with the recipient's balance unchecked, a transfer to the wrong
  key passes.
- The node is never killed: the second run fails on a bound port, which is why
  the pid-file kill and the trap are both required.
- `set -e` added around the extracted block: a command that legitimately
  returns non-zero inside a wait loop aborts the run and the log looks like a
  product failure.

---

### Task 6: README, and the M6 row

**Goal.** Make the repository's own front page true again, and make the
milestone legible to the next reader: the status row, the CLI and RPC tables,
the documentation list, and — the part that matters — the paragraphs M6
*falsifies*.

**The interface.** Documentation only; no code path changes except one user-facing
string.

The README sections that must change, each verified against the tree:

1. **Status and roadmap** (`README.md:1425`): add the M6 bullet under
   "Implemented — modules M0 through M5" and retitle it "M0 through M6"; remove
   the `- **M6** — …` item from "Pending" (`README.md:1474`) and leave the M4/M5
   hardware item. The bullet states what shipped: `balance`, `history`, `send`,
   `claim --key`, the `GET /history` read, the explorer and faucet pages, and the
   walkthrough script — and it states that the root did **not** move.
2. **The CLI section**: `claim`'s flag table gains `--key PATH` and its prose
   stops saying the claim command "has no key file and no keystore"
   (`README.md:400-419`) without qualification — it now has both, optionally.
   New subsections for `balance`, `history` and `send`, with the flags, an
   example of the printed transaction, and the sentence that `send` is the same
   envelope as `stake`.
3. **The command summary** near the top (`README.md:46-52`): add the walkthrough
   to the acceptance commands list.
4. **`internal/rpc`'s package row** (`README.md:1189`): add `/history`,
   `/explorer` and `/faucet`, and the new `/status` field, in the row's existing
   style (fields are added, never renamed).
5. **The acceptance table** (`README.md:1406`) gains a row for
   `scripts/acceptance-walkthrough.sh` with its one-line purpose.
6. **The documentation list** (`README.md:1476-1500`): the walkthrough doc and
   the M6 plan.
7. ***The funding paragraphs that M6 changes.*** Three places currently say the
   shipped CLI cannot reach `MIN_STAKE` and that no command turns the devnet
   fixture account into a key file:
   - `README.md:518-527` ("Where the stake comes from is a real limitation");
   - the claim arithmetic block at `README.md:1050-1085`, whose own correction
     note says the 1,000-key path is not walkable;
   - `stakingFundingNote` (`cmd/b10coin/main.go:852-872`), the string appended to
     `stake`'s refusals.

   After M6 the *walkability* changes and the arithmetic does not. Keep the
   first clause — "no shipped genesis gives an operator's key `MIN_STAKE` in
   spendable funds" — which stays true and is pinned by
   `TestTheFundingHintAppearsOnlyWhenTheBalanceCannotReachMinStake`. Correct the
   second: with `claim --key` and `send`, 1,001 keys × 1 claim and 1,001
   transfers into one address do reach 10^11 sparks — **1,001 and not 1,000,
   because each transfer burns its 1-spark fee**
   (1,001 × 10^8 − 1,001 = 100,099,998,999 ≥ 10^11) — and the faucet needs
   ~2,002 blocks of 0.5 b10/block emission to pay for them, about 67 minutes at
   2 s blocks. The honest sentence is: *the path exists and is ~2,000 commands
   long; the walkthrough does not take it, and M6 does not shorten it.*

**Invariants and constraints.**

- Every number written into the README is copied from a command's output or
  from `internal/genesis/genesis.go`, not from memory. The claim/fee/stake
  figures this plan verified: 1 b10 per devnet claim, 1 spark minimum fee,
  1000-block epochs, 10^11 sparks for `MIN_STAKE`, 1,001 keys for the sweep.
- No README line may describe a flag or route that does not exist. Each new
  table row is checked against `b10coin help` and against
  `internal/rpc/server.go`'s routing table.
- The M4/M5 figures stay visible as history, with their attribution intact:
  `98e5cf46…` is M5's root and M6 does not repeat or replace it.
- `usage()` (`cmd/b10coin/main.go:75-158`) gains the three verbs and the
  `claim --key` line, in the existing column style. The help text is the
  documentation a reader sees first; it must not be the last thing updated.
- The stale-claim sweep is part of the task: grep the tree for
  `no transfer`, `ephemeral key it never saves`, `cannot be accumulated`,
  `has no key file`, and every README sentence that says a verb does not exist.
  `README.md:1089` ("there is no `transfer` verb") is the known instance and
  will not be the only one.

**What must NOT change.**

- The M0–M5 bullets, the M5 root figure and its attribution, and the "correction
  (audit RT-2)" note: M6 corrects *walkability*, not the arithmetic, so the
  correction note stays and gains one clause if it still claims the CLI cannot
  walk the path at all.
- The certificate gate, the persisted commit lock, ST-1..ST-10's staking rules
  and CL-1's envelope, as *documented facts*: the README's statements about them
  stay true, and no M6 paragraph may weaken one ("a transfer is free" is false;
  "an exit is free" is true and stays scoped to exits).
- The acceptance root `98e5cf468ecf0b6ca9c148a4ef7e5056c14254dead11efaa1f2890631cdd11cc`:
  it appears in the README as M5's figure and must keep that wording. M6 adds a
  sentence saying it did not move; it does not add a second number.

**Tests.**

- `TestUsageListsEveryVerb`: `usage()`'s text contains a line for every verb in
  `main`'s switch, including the new three. Fails when a verb is added and the
  help is not — the drift this task exists to prevent.
- `TestTheFundingHintAppearsOnlyWhenTheBalanceCannotReachMinStake` (already in
  the tree, `cmd/b10coin/main_test.go:1093`) must keep passing after the string
  edit: it pins the "no shipped genesis" clause and the "only when the balance
  is below MIN_STAKE" rule, and it is the only automated guard on the refusal
  text. A rewording that drops the clause is a test failure, not a judgement
  call.
- The rest is a review checklist with a grep as evidence: every changed line
  quotes a command's output or a genesis parameter, and the sweep's results are
  in the commit message.

**The mutants.**

- The README claims `b10coin send` waits for inclusion (it does not — no
  `/tx/{id}` exists, and the walkthrough's wait loop exists for this reason):
  caught by reading Task 1's output instead of the skeleton's summary.
- The funding paragraph keeps "there is no `transfer` verb": a reader with the
  binary in hand disproves the README in ten seconds.
- The M6 bullet claims the state root moved: the README then contradicts the
  `devnet --blocks 100` output CI prints on every push.
- `usage()` is left at seven verbs: `TestUsageListsEveryVerb` dies.
- The claim table says `--key` is required: it is optional, and the default
  path is the documented ephemeral one.

---

## Acceptance

- `./scripts/acceptance-walkthrough.sh` exits 0, having extracted the
  walkthrough doc's single fence and run it against a fresh node in a temporary
  directory: two keys, one claim of 100,000,000 sparks, one `send` of 50,000,000
  sparks, the recipient's balance reaching exactly 50,000,000, a `history`
  window containing the transfer.
- The same step runs in CI on every push, beside the four `devnet` commands, so
  the walkthrough is performed by the suite and not by a developer once.
- `go run ./cmd/b10coin devnet --blocks 100` still prints
  `state root   98e5cf468ecf0b6ca9c148a4ef7e5056c14254dead11efaa1f2890631cdd11cc`
  and exits 0 (verified at `9bd6745` while this plan was written).
- `./scripts/check-plan.sh docs/plans/2026-11-01-m6-wallet-explorer-faucet.md`
  prints `PLAN OK`.
- These do not move, in any commit of this milestone: the certificate gate and
  the persisted commit lock (no M6 task touches `internal/consensus`),
  CL-1's fee ceiling and printed-bytes signing (Task 1 moves them and adds no
  second path), ST-1..ST-10's staking rules (Tasks 1 and 6 change wording only),
  and the acceptance root above.

## Self-Review

**Spec coverage.** The M6 row (`docs/2026-10-02-b10coin-design.md:451`) asks for
a wallet CLI, a minimal explorer and a faucet web UI, gated on a stranger
claiming and sending. The wallet is Tasks 0 and 1; the pages are Tasks 2 and 3;
the "using only the docs" half is Tasks 4 and 5, which is where the acceptance
sentence actually lives. Decision 1's executable proof is Task 5, decision 2's
read-only wallet is Task 0, decision 3's page over the puzzle is Task 2,
decision 4's one server-rendered page is Task 3, and decision 5's stated limits
appear in Tasks 0, 2, 3, 4 and 6.

**Not in this plan, deliberately:** a transaction index (history is a bounded
scan and says so), address search on the explorer, pagination, JavaScript, a
second HTTP listener, key recovery or an import verb (`claim --key` obviates
one), a testnet faucet page (`claim` is compiled against the devnet genesis),
`--wait` on `send` (there is no `/tx/{id}` to wait on), and any change to
`internal/state`, `internal/types` or `internal/consensus`.

**The three things most likely to go wrong.** First, **a second signing path**:
a `send` that builds and signs its own bytes passes every functional test and
skips the fee ceiling, which is the fixed finding CL-1 closed — the
printed-bytes and hostile-fee tests are the guards, and the envelope move is
the structural one. Second, **a script that repeats the doc instead of reading
it**: it passes forever while the doc rots, and nothing in CI can tell — the
fence-count assertion and the extraction are the only defence. Third, **a page
that becomes a signing or solving surface** because "it would be more
convenient": the read-only tests and the no-POST-form assertion cover the first
half; the second half is a review item, named here so it is not discovered by
an incident.

**Honest limits, stated up front.** The walkthrough is **devnet-only**: `claim`
refuses any chain whose ID is not `b10coin-devnet-1`
(`cmd/b10coin/main.go:409-411`) and the testnet genesis names no validators, so
no chain runs on the 100-b10 claim. The faucet page cannot pay anyone — it can
only tell a person what to run, because paying would require a signature over
HTTP. `history` is a backward scan, not a history: it shows a window and prints
which window, and an address with no activity in that window looks empty even on
a chain that has years behind it. The walkthrough does **not** reach `MIN_STAKE`
and does not try: one claim pays 1 b10, `MIN_STAKE` is 1,000 b10, and the honest
path to it is 1,001 claims from 1,001 keys plus 1,001 transfers, ~2,002 blocks
of faucet emission and roughly 67 minutes at 2 s blocks — a documented
limitation, not a milestone. And the pages bind the node's existing loopback
`--http` address; exposing that address to the internet exposes an
unauthenticated explorer, faucet page and `/tx` together, which is stated on
both pages rather than implied.
