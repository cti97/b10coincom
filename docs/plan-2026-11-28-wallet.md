# Wallet: plan and first increment

| | |
|---|---|
| Status | increment 1 done (signer + parity tests); extension shell next |
| Scope | a wallet that signs with the repository's own code, in a browser |
| Explicitly out | running a validator, a light client, any key the operator cannot back up |

## What a wallet is here

A wallet holds a seed, derives an address, reads state from a node, builds and
signs transactions, and submits them. It is a client. It never votes, never
relays, never verifies a chain: that is what a node is for, and the design
document excludes light clients by name.

Five operations cover the chain's whole user surface — `transfer`, `bond`,
`unbond`, `withdraw`, and the faucet `claim`. Everything else a wallet shows
(balance, unbonding records, history) is a read of the node's RPC.

## The decision that shapes it: one encoder, two clients

A JavaScript wallet that built transactions itself would be a **second
definition of the wire format**. The failure is not cosmetic: a wrong field
order or width produces a signature over a hash the node never computes, and
the only symptom is a rejected transaction.

So the wallet does not encode anything. `internal/wallet` builds and signs, and
`cmd/b10coin-wasm` compiles *that same package* to WebAssembly for the browser.

The CLI still constructs its envelope inline (it predates the package). Until it
is moved onto `internal/wallet` — a small refactor, deliberately not mixed into
this change — the two are held together by
`TestTransferIsByteIdenticalToTheCliConstruction`, which builds the same
transfer both ways and fails if the encodings differ by a byte. The wasm build
cannot diverge from the package by construction: it is the same source.

## Shape of the client

**A Manifest V3 browser extension**, not a page:

- **It can reach the node.** The RPC sends no `Access-Control-Allow-Origin`, so
  a website cannot call `http://127.0.0.1:8645`; an extension with
  `host_permissions` can. That is the difference between "possible in theory"
  and "works in ten minutes".
- **It has a background context.** Keys and the wasm module live in the service
  worker, not in a tab that can be closed.
- **Site JavaScript cannot reach its storage.** A key in extension storage is
  exposed to far less than a key in a page.

It is deliberately **not** a validator host: browsers have no raw TCP, the
service worker is killed when idle, and the machine sleeps. A seat belongs on a
Pi or a Mac under a supervisor (`docs/2026-11-20-public-site.md` and the README
describe that side).

## First increment (this change)

`internal/wallet`:

| | |
|---|---|
| `NewKey` / `KeyFromSeed` / `KeyFromPrivate` | one identity type; 32-byte seed is the storage form, 64-byte key interoperates with the CLI's key file |
| `Transfer` / `Bond` / `Unbond` / `Withdraw` / `Claim` | build + sign in one call; refusals that the chain would make are made here first (self-transfer, zero amount, a fee on an exit) |
| `Hex` / `ID` | the wire form `POST /tx` wants, and the txid it returns |

`cmd/b10coin-wasm` exposes them to JavaScript as one JSON-in/JSON-out call:

```js
const out = JSON.parse(b10coin.request(JSON.stringify({
  op: "transfer", seed, genesis_hash, to, amount: sparks, fee, nonce
})));
// { ok: true, tx_hex, tx_id, address }   or   { ok: false, error }
```

Verified end to end: a key generated in wasm signed a transfer that a live node
accepted on `POST /tx` (`200 {"txid": …}`), and the self-transfer refusal fires
inside wasm before any network call.

## Next increments

1. **Extension shell** — `manifest.json`, service worker holding the wasm module
   and the seed (`chrome.storage.local`), popup with create/import, balance,
   send, receive. Reads `genesis_hash`, `min_fee_sparks` and the nonce from
   `/status` and `/account/{address}`.
2. **Faucet claim** — the Argon2id puzzle is already Go; exposing it through the
   same wasm bridge keeps the claim rule in one place. Today the only way to get
   coins onto a fresh key is `b10coin claim`.
3. **History and unbonding** — `/history` and the `unbonding[]` records, so a
   staker can see what is locked and when it matures.
4. **Key handling worth trusting** — export/import, a passphrase-wrapped seed,
   and an explicit "this key is on a testnet with no value" banner.

## Honest limits

- The fixture committee's keys derive from a public seed: on this chain *anyone*
  can sign as any seat. A wallet here proves the plumbing and nothing about
  custody.
- An extension protects a key from web pages, not from a compromised profile,
  a malicious update, or a user who pastes the seed into a chat.
- Nothing in this plan makes the chain valuable. It makes it usable, which is
  the point of a wallet.
