# Claim and send b10 — the walkthrough

This is the smallest thing b10coin does that is still the whole thing: make two
keys, claim coins from the faucet into the first, send half of them to the
second, and read back a balance that proves both happened. It runs on the
**devnet** — the single-node chain this repository builds — talks to nothing but
`127.0.0.1`, and needs no account, no coins and no existing node.

The unit is the **spark**: 1 b10 = 100,000,000 sparks, and sparks are the integer
the chain stores. Every balance below is printed in both, and no step depends on
a fraction of a spark.

## What you will do

You will make two key files with `b10coin keygen`, claim 1 b10 from the faucet
into the first, send 0.5 b10 from the first to the second, and watch the second
key's balance reach exactly 0.5 b10 while the first keeps what the 1-spark fee
left of the other half. You will start one node and stop it at the end. The
coins are devnet coins: they are worth nothing, and the chain is a directory you
delete when you are done.

## What you need

- This repository, at the commit that ships this document.
- A Go toolchain. The `toolchain` line in `go.mod` is the version the `go`
  command uses; if your installed Go is older, the `go` command downloads that
  one for you (the default `GOTOOLCHAIN=auto`).
- A terminal.
- Nothing else: no account, no coins, no node, no second machine.

From the repository root, build the binary once:

```
go build -o bin/b10coin ./cmd/b10coin
```

(`make build` runs exactly that command.) The block below expects the binary at
`bin/b10coin`. If you build it somewhere else, set `B10` to its path.

## The commands

Run the block below from the repository root, in a directory where you can
create files. It takes a few seconds.

Its first four lines are settings, not steps: `B10` is the binary, `WORK` is the
directory the run writes to (`./walkthrough`), `PORT` is the loopback port the
node listens on, and `NODE` is that address as a URL. They are written as
`${VAR:-default}` so you can override any of them — for example
`PORT=19000 bash -c '...'` — without editing the block. Everything after them
is the walkthrough itself:

1. `keygen` writes two key files and prints each key's address. The second
   key's address is captured in `BOB`, because it does not exist until the key
   does.
2. `node` starts the devnet producer in the background on `127.0.0.1:$PORT`,
   with a **1-second** block interval, writing its log to `$WORK/node.log`. Its
   process id goes to `$WORK/node.pid` so the last line can stop it.
3. A bounded loop waits until the node answers a `balance` read.
4. `claim` solves the faucet's puzzle and submits the claim **signed by
   alice's key** — this is what makes the coins spendable — then waits, in a
   bounded loop, for the claim to be applied.
5. `send` builds a transfer from alice to `BOB`, prints it, signs it, submits
   it, and then waits, in a bounded loop, for the recipient's balance to move.
6. `history` and two `balance` reads show what the chain recorded.
7. `kill` stops the node.

```sh
export B10=${B10:-bin/b10coin}
export WORK=${WORK:-./walkthrough}
export PORT=${PORT:-18645}
export NODE=http://127.0.0.1:$PORT
mkdir -p "$WORK"
$B10 keygen --out "$WORK/alice.key"
BOB=$($B10 keygen --out "$WORK/bob.key" | sed -n 's/^seat address //p')
$B10 node --dir "$WORK/data" --http "127.0.0.1:$PORT" --block-time 1s >"$WORK/node.log" 2>&1 &
echo $! >"$WORK/node.pid"
for i in $(seq 1 50); do $B10 balance --node "$NODE" --key "$WORK/alice.key" >/dev/null 2>&1 && break; sleep 0.2; done
$B10 claim --node "$NODE" --key "$WORK/alice.key" --yes
$B10 balance --node "$NODE" --key "$WORK/alice.key"
for i in $(seq 1 40); do $B10 balance --node "$NODE" --key "$WORK/alice.key" | grep -q '100000000 sparks' && break; sleep 0.5; done
$B10 balance --node "$NODE" --key "$WORK/alice.key"
$B10 send --node "$NODE" --key "$WORK/alice.key" --to "$BOB" --amount 0.5 --yes
for i in $(seq 1 40); do $B10 balance --node "$NODE" --address "$BOB" | grep -q '50000000 sparks' && break; sleep 0.5; done
$B10 balance --node "$NODE" --key "$WORK/alice.key"
$B10 history --node "$NODE" --key "$WORK/alice.key"
$B10 balance --node "$NODE" --address "$BOB"
kill "$(cat "$WORK/node.pid")"
```

Two flags are worth naming before you run it, because they are the difference
between the walkthrough working and not:

- **`claim --key PATH`** signs the claim with a key file you hold. Without
  `--key`, `claim` generates an **ephemeral** key that is printed and **never
  saved**, and there is no command in this tool that turns that printed value
  into a key file — the coins would land on an address nothing here can spend
  from. `--key` is how the claim reaches a key you own.
- **`--yes`** is the confirmation for the two verbs that sign a transaction.
  Both print the transaction and, in a terminal, ask you to type `yes`;
  `--yes` supplies that answer for a non-interactive run. Without it, run with
  no terminal, both refuse and sign nothing, with a message beginning
  `refusing to sign: nothing was signed because this run cannot confirm the transaction`.

## What you should see

The outputs below are copied from a real run. Your keys, addresses, txids and
pow nonces will differ — every run generates fresh ones — but the shapes and
the numbers on the `balance` and `history` lines will match exactly. Where a
block quotes a few lines of a longer output, the lines are verbatim and the
lines between them are elided.

### 1. Two keys

`keygen` prints three lines and then some advice for validators. The third line
is the address of the key, and it is the only line this walkthrough parses:

```text
key file     ./walkthrough/alice.key (owner-only 0600; regenerate elsewhere, never over this one)
public key   28753682c06229b3bdb3fe58de905d36c5ba0c6ae77288451c5b37632ca76d2a
seat address b10iwvk7nvjvewzqtcx2i5r35p2fs2vksfslf7aera
```

The lines after those (`Add the public key line above to the committee file your
validators share` …) matter only to a validator sharing a genesis; this
walkthrough uses the same key file only as a wallet. The second key is generated
the same way, silently, and its `seat address` line becomes `$BOB`.

### 2. The node

`node` prints nothing to your terminal: its log goes to `$WORK/node.log`, and
the background job keeps running. The readiness loop is silent and finishes as
soon as a `balance` read succeeds (a few hundred milliseconds). If the node
never answers, the loop gives up after about 10 seconds and the next command
fails with `cannot read the node's status at http://127.0.0.1:18645/status` —
then read `$WORK/node.log`.

The interval is `1s`, and it is a **floor rather than a preference**. The
producer stamps every block with the wall clock in whole seconds, and the chain
requires each block's timestamp to be strictly greater than its parent's, so two
blocks inside one second would stop the node. Ask for less and `node` refuses
before it starts:

```text
error: --block-time 500ms is below the 1s floor: the producer stamps each block with the wall clock in whole seconds (time.Now().Unix()) and the chain requires every block's timestamp to be strictly greater than its parent's, so two blocks inside one second stop the node with "chain: block timestamp is not valid for its parent". Use --block-time 1s or longer
```

### 3. The claim is queued, not paid

`claim` solves the puzzle locally, prints the transaction it is about to sign,
signs it, and posts it. The preview names the epoch the claim is bound to:

```text
transaction to sign (built, not yet signed):
  type        faucet claim (2)
  from        b10iwvk7nvjvewzqtcx2i5r35p2fs2vksfslf7aera
  nonce       0  (the node's claim)
  fee         0 spark  (fixed at 0 by consensus: a claim may not carry a fee)
  epoch       1  (the node's claim: the block at its head+1 decides it; it is signed)
```

and the receipt after the node accepts it:

```text
claimant    45aaafb6a9a92d984c57d23b1df5fa2cb55548b2
claim epoch 1
txid        ce142df1d2e5cc4cf08f41fe694f8a4314a7b54d62265b5665fedf464c33fad9
the claim is queued on the node; it is paid when the node's next block applies it.
```

**That last sentence is the important one.** `claim` does not put coins in your
account; it puts a transaction in the node's mempool. The coins move when a
later block includes it. (The `claimant` line above is the same account as
`address`, shown as the raw 20 bytes the transaction commits to; the `b10…`
spelling adds the prefix and checksum.) The next command reads the balance in
that window, and this is what it usually shows:

```text
address     b10iwvk7nvjvewzqtcx2i5r35p2fs2vksfslf7aera
balance     0 sparks (0 b10)
nonce       0
chain       b10coin-devnet-1
height      0
```

`height 0` is the node's head: the chain has committed its genesis block and no
block with the claim in it yet. A `send` run now would be refused for lack of
funds, and that refusal is not a broken faucet — it is the queue. The wait loop
after it polls the balance every half second until it reads
`100000000 sparks`, and is bounded so a stuck run fails instead of hanging. If a
block happened to land before this read, you will see the paid balance at
`height 1` instead; the loop then finishes immediately.

### 4. The claim is paid

Within a second or so the same read prints:

```text
address     b10iwvk7nvjvewzqtcx2i5r35p2fs2vksfslf7aera
balance     100000000 sparks (1 b10)
nonce       1
chain       b10coin-devnet-1
height      1
```

Three facts moved at once. The balance is 1 b10 = 100,000,000 sparks, the
devnet's claim amount. The nonce went from 0 to 1: a claim spends the account's
replay counter like any other transaction. And the height is 1: block 1 included
the claim, credited the claimant and debited the faucet.

**The faucet is epoch-bound.** It pays one claim per key per epoch, and an epoch
on this chain is 1,000 blocks. The claim carried `epoch 1`, the number of the
epoch of the block at the node's head+1, and only a block in that same epoch can
apply it — a claim built for one epoch is not payable in another. That is why
this walkthrough makes one claim on a fresh node and waits, instead of claiming
in a loop: a second claim from the same key in the same epoch is refused:

```text
error: 400 Bad Request: state: this key has already claimed in this epoch: last claimed in epoch 1, claim is for epoch 1
```

### 5. The transfer

`send` prints the transaction before it signs it, because the bytes it prints are
the bytes the signature covers — the node is not trusted to describe them for
you:

```text
transaction to sign (built, not yet signed):
  type        transfer (1)
  from        b10iwvk7nvjvewzqtcx2i5r35p2fs2vksfslf7aera
  nonce       1  (the node's claim)
  fee         1 spark  (the node's claim; ceiling 1)
  amount      50000000 sparks (0.5 b10)  (from --amount)
  to          b10gsmtxpsxbrt2s4hdkx3pmj5eubtq7jvbcmvrjly  (the operator's --to; the address this transfer credits)
```

`--amount 0.5` means 50,000,000 sparks and is parsed as an exact decimal, never
as a float. `--to` and `--amount` are yours; the `nonce` and the 1-spark `fee`
are the node's claim and are bounded by the printed ceiling, so a node cannot
slip a larger fee past you. The fee is burned — it pays no one — and 1 spark is
the chain's minimum. Then the receipt:

```text
txid        645b20deea6dd118ad4ee4d0e85037bb80212c0a55dac5c0c27e763c3b83bc5e
send does not wait for a block: the recipient's balance changes only when a block includes the transaction. Poll `b10coin balance --address` (there is no /tx/{id} route to wait on).
```

There is no `/tx/{id}` endpoint to wait on, so the block's wait loop does what
the sentence says: it polls `balance --address "$BOB"` until the recipient's
balance is exactly 50,000,000 sparks.

### 6. The transfer is applied

```text
address     b10iwvk7nvjvewzqtcx2i5r35p2fs2vksfslf7aera
balance     49999999 sparks (0.49999999 b10)
nonce       2
height      2
```

and the recipient:

```text
address     b10gsmtxpsxbrt2s4hdkx3pmj5eubtq7jvbcmvrjly
balance     50000000 sparks (0.5 b10)
nonce       0
height      2
```

The sender started with 100,000,000 sparks, sent 50,000,000 and paid 1 spark of
fee: 100,000,000 − 50,000,000 − 1 = 49,999,999. The recipient's nonce is 0
because receiving is not transacting — only the sender's nonce advanced.

### 7. The history

```text
history for b10iwvk7nvjvewzqtcx2i5r35p2fs2vksfslf7aera (blocks 1..2, scanned 2, newest first)
     2  transfer        50000000 sparks (0.5 b10)  fee 1  to   b10gsmtxpsxbrt2s4hdkx3pmj5eubtq7jvbcmvrjly
     1  faucet claim           0 sparks (0 b10)  fee 0  from -
no transaction index: this is a backward scan over the 2 block(s) above, not a complete account history - older activity is not shown. Raise --blocks to look further back (at most 500 per run).
```

The first line is the **window**: in this run the node scanned blocks 1
through 2 (if it produced another block while you were reading, the second
number is one higher — the window follows the head), and it says so because
there is no transaction index — a history read is a bounded walk back from the
head, not a query of everything an address ever did. The default window is 100
blocks and the maximum is 500 per run; anything older than the window is simply
not shown, even though the chain still has it. On a chain with years behind it,
an empty history means "nothing in this window", not "nothing ever". The
transfer row's party column names the **other** side: here it is the recipient,
`$BOB`, because this is alice's history. The claim's row shows `0 sparks`
because a claim transaction carries no amount field at all: the amount it pays
is the chain's claim rule (1 b10 on the devnet), which is why the money is
visible in the balance and not in that row.

### 8. The node stops

`kill` sends the node a termination signal and the block ends. The run leaves
`$WORK` (`./walkthrough`) behind, holding `alice.key`, `bob.key`, the chain in
`data/`, `node.log` and `node.pid`. `keygen` refuses to overwrite an existing
key file — a second run derives a *different* key, so it fails with a message
beginning `error: keystore: refusing to overwrite an existing key file` rather
than replacing one. To run the walkthrough again, remove the directory first:
`rm -rf ./walkthrough`. The keys and chain data are the only thing to keep, and
on the devnet there is no reason to.

## What this cannot do

- **One claim per key per epoch.** The devnet epoch is 1,000 blocks; a key that
  has claimed in the current epoch is refused until the next one.
- **One claim is 1 b10.** That is the devnet's claim amount, not the 100 b10 the
  testnet configuration names. `claim` as shipped is **devnet-only**: it refuses
  a node whose chain ID is not the compiled-in `b10coin-devnet-1`.
- **This does not make you a validator.** `MIN_STAKE` is 1,000 b10 =
  100,000,000,000 sparks. One claim pays 1 b10 and the 1-spark transfer fee means
  a claimer can forward at most 99,999,999 sparks, so reaching the floor from
  faucet claims alone takes **1,001 keys, 1,001 claims and 1,001 transfers** —
  about 2,002 blocks of faucet emission, or roughly 67 minutes at the default
  2-second block time. That is a documented limitation, not a step this
  walkthrough skips for convenience.
- **A lost key is a lost balance.** There is no recovery, no import verb and no
  customer support. The key file is the account.
- **The node is untrusted.** It reports your nonce, the fee and the genesis hash
  the transaction is bound to; the printed transaction is what gets signed, so
  read it. The signature cannot be withdrawn once the node accepts the bytes.
- **`history` is a scan, not an index.** It is bounded (100 blocks by default,
  500 maximum) and prints the window it looked at.
- **The explorer and faucet pages are read-only views** of the same node on the
  same address. They cannot claim, sign or spend for you.
- **No privacy.** The devnet is a single node on loopback; nothing here is a
  private payment system.

## Where to read more

- `README.md`: **Quick start** (building, the acceptance commands and the
  reproducible state root), **The CLI** (`keygen`, `node`, `claim` and the rest,
  flag by flag), **Staking** (`MIN_STAKE`, bonds and the epoch rules) and
  **Architecture**, whose `internal/rpc` row lists the HTTP reads this
  walkthrough's `balance` and `history` verbs use.
- `docs/plans/2026-11-01-m6-wallet-explorer-faucet.md`: the plan this
  walkthrough comes from, including the limits above stated as design decisions.
- While a node is running, `http://127.0.0.1:18645/faucet` and
  `http://127.0.0.1:18645/explorer` are the two pages of this milestone. They
  are views of committed state and state their own limits; neither can move
  coins.
