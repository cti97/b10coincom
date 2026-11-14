# Bug: the relay gate rejects every node — the first frame disagrees

**Status: open. Diagnosed to a first-frame ordering disagreement; not fixed.**
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
