# Bug: the relay gate rejects every node — the first frame disagrees

**Status: FIXED 2026-11-14 (commit `fix:` on `fix-relay-gate`). Root cause was
neither H1 nor H2 — see §7. Loopback DID reproduce it, with one flag omitted.**
Found 2026-11-14 during the three-Pi deployment, with two Pis on separate home
networks and a relay on a public VPS.

---

## 1. Symptom

Every node that dials the relay with a **correct** token is refused:

```
b10coin-relay: gate refused 79.115.164.15:36674: err=<nil> frameLen=2 wantLen=32 frame="v1"
b10coin-relay: gate refused 188.26.8.179:44562: err=<nil> frameLen=2 wantLen=32 frame="v0"
```

`"v1"`/`"v0"` are the nodes' **transport IDs**, 2 bytes each. The relay expects
the **32-byte HMAC** proof.

The node stays healthy and at height 0 forever:

```
$ curl -s 127.0.0.1:8645/status
{"chain_id":"b10coin-simnet-3","height":0, …,"committee_size":3, …}
consensus  committee of 3, seat 0 (derived fixture key), listening for inbound connections
… no block for 23 rounds … quorum is UNREACHABLE: this node can reach 1 of 3 power …
  peers=0[]
```

The relay shows `conns=0` and `unauthorized` climbing (~1,200 per 40 s), and
hundreds of TIME-WAIT sockets — a redial loop, because the relay closes each
connection immediately after the challenge.

## 2. Evidence, in the order it was gathered

**(a) A packet capture** (`tcpdump` on the VPS, one socket) shows the relay
writing greeting + challenge and then **FIN on the same socket**, without
waiting for a proof:

```
93.115.53.244.7001 > 79.115.164.15.56690  [P.] seq 26:80  length 54
    … b10coin-relay-gate-v1 … 93.115.53.244:7001
93.115.53.244.7001 > 79.115.164.15.56690  [F.] seq 80
```

**(b) A log line in the relay's refusal path** gave the reason the FIN happens:
`frameLen=2 wantLen=32`, `frame="v1"`.

**(c) The token is not the cause.** Both sides are byte-identical (44 bytes, one
trailing newline, effective 43 after the relay trims it). Verified with `wc -c`
and `od -c` on both hosts.

**(d) The node's own relay path is internally consistent.** With diagnostics in
`adoptRelay`:

```
DIAG adoptRelay 93.115.53.244:7001
DIAG challenge=50 bytes token=43 proof=32 bytes
```

50 = 32 random bytes + the 18-character address `93.115.53.244:7001`; the
54-byte frame in the capture is that payload plus its 4-byte header. So the
challenge is read correctly, the token is 43 bytes, and the proof is 32.

**(e) `adopt()`, the direct-peer path, never ran.** It is instrumented and it
would log `DIAG adopt …`. It does not appear. `writeHello` — the only code that
writes an ID frame — is called from exactly one place, `adopt()`.

> **WRONG, and this is the sentence the whole investigation turned on.**
> `writeHello` has a SECOND caller: the `else` branch of `adoptRelay`, taken when
> the transport holds no access token. That branch is inside `adoptRelay`, so it
> does not log `DIAG adopt` — which is exactly why the absence of that line
> looked like proof that no ID was written. Verified at HEAD by grep and by the
> reproduction in §7.

**(f) The routing is correct.** `--relay` → `Validator.ConnectRelay` →
`ttp.AddRelay` → `registerOutbound(addr, relay=true, …)` → `ob.relay` true →
`adoptRelay`. Verified by reading each step.

## 3. The contradiction

The relay receives an ID frame. The node's relay path writes a 32-byte proof and
never takes the path that writes an ID. **Both halves are individually verified.**

Two possibilities remain, and they need different fixes:

- **H1 — the relay reads one frame behind.** It consumes the node's proof as
  something else (or discards a frame) and then reads the *next* frame, which
  would be an ID if the node sends one. This would be entirely relay-side.
- **H2 — a second dial exists.** Something dials the relay address as a plain
  peer, taking `adopt()` → `writeHello` → ID. The `DIAG adopt` line is missing,
  which argues against this — but the instrumentation could be in a function
  that is skipped, or the process was killed before flushing.

## 4. What is *not* wrong (verified, do not re-check)

- The token, its newline handling, and `MinRelayAccessTokenBytes`.
- The challenge construction and `RelayGateProof`/`RelayGateConfirmation`.
- `wire.WriteFrame`/`wire.ReadFrame` framing (both 4-byte BE length + payload).
- The `--relay` → `AddRelay` → `adoptRelay` routing.
- The relay's gate code path itself: it writes greeting, writes challenge, sets
  a read deadline of `AccessTimeout`, reads a fixed 32 bytes, compares in
  constant time. Read at `internal/relay/relay.go`.
- The consensus, transport framing, and the fixture committee: three seats on
  one host commit normally (1,004 blocks, 42,992 frames forwarded).

> **That run proves nothing about the gate.** It was run against a relay with NO
> access token (the token-less path, §7), so it exercised the *ungated* relay and
> never touched `handshake`'s gate at all. It is not evidence that the gate
> admitted anyone.

## 5. Plan to fix

**Step 1 — separate H1 from H2 (one command, ~5 minutes).**
In `adoptRelay`, log immediately after each write:

```go
log.Printf("DIAG adoptRelay wrote proof=%d", len(proof))
```

Interpretation:
- node logs `wrote proof=32` **and** the relay reads an ID → **H1**: relay-side
  read offset. Fix in `internal/relay/relay.go`'s `handshake` — it must read
  exactly one frame and it is reading past or before it.
- node never logs the write → **H2**: `adoptRelay` bails before it, and a second
  dial is emitting the ID. Find it by logging at the top of `adopt()` with the
  address and comparing.

**Step 2 — fix whichever it is.** Both are small: H1 is an ordering bug in one
function; H2 means either stopping the second dial or making the relay accept the
ID frame before the proof (whichever the protocol intends — the relay's own
header comment documents greeting → challenge → proof, so the ID should not be
first).

**Step 3 — pin it.** A test in `internal/relay` that runs the real gate against a
real node transport (there is already `relay_gate_test.go`; it uses an
in-process relay, so extend it to the dial path that `--relay` uses) asserting
the relay admits on the first attempt. A regression here is invisible until
deployed, which is how this survived: every existing gate test passes.

**Step 4 — revert the debug relay on the VPS** and re-run the three-host
deployment.

## 6. Process notes, honestly

Seven diagnoses were wrong before this one: the token (twice), a handshake
stall, the challenge encoding, "the three-seat demo proves it works", the arch
check, and the `/etc` permission. Each cost an install cycle.

**The tool that worked — a packet capture plus one log line — was available at
the first `unauthorized` increment.** It should have been the first step, not
the eighth. A counter that cannot say *why* it incremented is not a diagnostic;
the refusal path should have logged its reason from the day the gate landed.
That logging is the durable fix regardless of which hypothesis is true.

## 7. Resolution (2026-11-14)

**Neither H1 nor H2. The node took `adoptRelay`'s token-less branch**, so it
wrote its transport ID (`"v0"`/`"v1"`, i.e. `fmt.Sprintf("v%d", index)`) as the
first frame, exactly as the relay's refusal said. Nothing was one frame behind,
and there was no second dial: the relay read the only frame the node sent.

The two halves of §3 were individually true because **they came from two
different invocations**. The `challenge=50 token=43 proof=32` lines (§2 d) came
from a hand-run node that DID have the token, where the gate works; the failing
service ran without one, where `adoptRelay` skips that whole branch and logs
`DIAG adoptRelay` only. That is the contradiction, and §6's own lesson applies:
the log line was read from one run and the packet capture from another.

**Why the node had no token.** `scripts/deploy/README.md` §4 starts the relay
with `--access-token-file` and tells the operator to give each node
`--relay-access-token-file` "§5, §6" — but §5's copy-paste command did not
contain it, and the shipped unit's `B10COIN_RELAY_TOKEN=` defaults to EMPTY, and
an empty value is passed as an empty flag, which the node reads as "no token".
Following the recipe literally produced a token-less node against a gated relay.

**Why it was silent on both machines.** The relay only incremented
`unauthorized`. The node installs a relay link without reading any frame (a relay
link reads no ID), so it believed it was connected and never saw an error; the
maintainer's `report(err)` only hands the FIRST failure to a registration
channel, so every later redial failed silently. The relay closes each refused
socket at once, and the maintainer resets its backoff on any non-superseded
death, so the loop ran at ~25 dials/s (the ~1,200 `unauthorized` per 40 s and the
TIME_WAIT pile).

**Fix.**
1. `internal/transport/tcp` — a relay-mode connection announces NO identity in
   either mode (`adoptRelay` no longer calls `writeHello`). A relay never reads an
   ID on that link (it names it `relay:<addr>`), so the frame was consumed by
   nobody, refused by every gated relay, and forwarded to peers by every ungated
   one. The `writeHello` and `devnet.ConnectRelay` comments that claimed the
   opposite are corrected — that disagreement is what hid the branch.
2. `internal/relay` — the gate's refusal now LOGS ITS REASON, rate-limited to one
   line per second with a suppressed count so it cannot be used to flood a log.
   It names the short-frame shape (a 2-byte opening frame is a transport ID, so
   the dialer has no token) and the wrong-MAC shape separately.
3. `cmd/b10coin` — a node dialling a relay with no token prints a startup warning
   naming both flags.
4. `scripts/deploy/README.md` §5 and `b10coin.service` now carry the flag and
   state that an empty token is fatal against a gated relay.

**Pinned by** `TestTheRelayDialPathIsAdmittedOnTheFirstAttempt` (real dial path,
real relay, first attempt: `conns==1`, zero `unauthorized`),
`TestATokenlessRelayDialSendsNoIdentityFrame` (fails on the pre-fix branch with
the literal `"v0"` frame) and
`TestTheGateRefusalNamesItsReasonAndCannotFloodTheLog`.

**Reproduced on loopback, one flag.** `--relay` WITH the token file admits on loopback
(`conns=1 unauthorized=0`); the same binary with the token file omitted
reproduces `frameLen=2 wantLen=32 frame="v0"`, `conns=0` and a climbing
`unauthorized` in under a second. The VPS was never needed.

**Still open, and deliberately not fixed here:** the maintainer resets its
backoff on ANY non-superseded connection death, so a relay that accepts and
closes instantly still produces a hot redial loop (~10/s at the 100 ms default
base, which is the TIME_WAIT pile and the ~1,200 `unauthorized` per 40 s). This
fix does not change that rate: a token-less link now writes a consensus frame
first instead of a transport ID, and the gate refuses either one immediately.
Fixing it means changing the reset rule, which is a pinned liveness contract
(`TestBackoffClimbs…`: "a live connection resets the counter"), so it needs its
own lifetime threshold and its own test rather than a passenger change here.
