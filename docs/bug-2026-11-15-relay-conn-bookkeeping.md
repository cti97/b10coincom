# The relay's `conns` count, and the sockets it was read as

Date: 2026-11-15. Scope: `internal/relay` connection accounting and the
`b10coin-relay` stats line. Status: **the leak did not reproduce; the metric
that made it look real is fixed.** Read §5 first if you only read one section.

## 1. The report

A relay up 23 hours, carrying 12.4 million frames, with

```
b10coin-relay stats: conns=3 forwarded=12386468 dropped=0 refused=0 unauthorized=140541
```

while `ss -tn state established '( sport = :7001 )'` on the same host showed
**no established sockets**. Three validators were admitted as peers
(`peers=2` on every node — their HELLOs had gone through) but no consensus
vote ever arrived; each node tallied `prevote votes=1 power=1 quorum=3`, its
own vote only. `systemctl restart b10coin-relay` restored service instantly.

The tempting reading is a connection-bookkeeping leak: three slots held after
their sockets were gone, so the relay's fan-out set named three corpses and
every frame was queued for a writer that no longer existed.

## 2. What I did to reproduce it, before changing anything

The production shape is rare per event (three leaks over ~12 million frames and
23 hours of reconnects) and systematic over many, so the test is a LOOP of
connect/disconnect cycles that asserts, after every cycle, the property that
matters:

> after every client has disconnected, `Stats().Conns == 0` and the per-prefix
> group accounting (`perGroup`, the `--max-conns-per-ip` counter) is empty.

Exit paths driven, each in its own loop (`internal/relay/conn_leak_test.go`):

| path | how it is driven |
| --- | --- |
| clean close | dial, wait for registration, close |
| abrupt reset | dial, one frame, `SO_LINGER 0` + close (RST) |
| half-close | dial, one frame, `CloseWrite` (FIN, no RST) |
| mid-handshake | gated relay, read the greeting, RST |
| gate refusal (short first frame) | send a 2-byte `v0` transport ID: the 2026-11-14 shape, and the source of `unauthorized=140541` |
| gate refusal (wrong proof) | read challenge, answer with 32 zero-ish bytes |
| gate timeout | gated relay, read greeting + challenge, answer nothing |
| gate write failure | gated relay, dial and close without reading the greeting |
| read-deadline expiry | stalled header, `--read-timeout` shrunk |
| write-deadline expiry (wedged receiver) | a sink that never reads, 4 MiB of bulk into an 8 KiB queue, then silence |
| accept refusal at the global cap | 40 concurrent dials, `--max-conns 3` |
| accept refusal at the per-prefix cap | 10 cycles of two concurrent dials, `--max-conns-per-ip 1` |
| `Close` with sockets mid-handshake | 16 silent gated dials, then `Close` |

Plus a concurrent churn (all of the above from 8 goroutines) with a watchdog
asserting `sum(perGroup) == conns + handshaking` continuously, and an opt-in
soak (`RELAY_SOAK=1`) of 4,000 cycles per run.

**Every one of them passes on `origin/main` (71e4f4a), including 40,000 churn
cycles under `-race`.** No cycle, and no concurrent run, left a slot behind.
A test that does not fail first is not evidence, so this is not claimed as a
reproduction.

## 3. What the accounting actually does

The relay's socket lifecycle is a single transfer:

- `acceptLoop` takes a socket, applies both caps under `r.mu`, and reserves it
  as `r.handshaking[nc] = group` + `r.perGroup[group]++`;
- `admit` converts that reservation into a registration in one critical
  section: the handshaking entry is deleted and the conn joins `r.conns`
  (the per-group slot is untouched — the reservation becomes the
  registration);
- `finish` (once, from reader, writer or `Close`) deletes the registration and
  returns the per-group slot;
- `releaseHandshake` returns the reservation for the socket that never got
  admitted.

Every one of `handshake`'s nine exits calls exactly one of those two: the
eight gate exits call `releaseHandshake`, and the ninth is `admit`, which
either converts the reservation or (on shutdown) releases it. `finish` and
`releaseHandshake` both decrement through `decGroupLocked`, and `finish` is
idempotent through `sync.Once`. There is no path where a socket is in both
populations, so no path can release twice either.

The code is self-consistent, and the invariant tests prove it on a real
socket, not just by reading:

- removing `releaseHandshake` from the gate-refusal exit → the cycle test
  fails with `conns=0 handshaking=1 perGroup=map[127.0.0.0/24:1]`;
- removing `decGroupLocked` from `finish` → the cycle test fails with
  `conns=0 perGroup=map[127.0.0.0/24:2]` on every registered-connection path;
- adding a second `decGroupLocked` in `admit` (the double-release direction)
  → the churn watchdog fails with `sum(perGroup)=0 but conns+handshaking=1`,
  and the per-prefix cap test fails because the second dial from a prefix
  holding its one slot is ADMITTED.

All three mutants were compile-confirmed before the test was run against them.

## 4. Why the reported state cannot be produced by this source

The reader arms a per-frame deadline of `--read-timeout` (default 120 s)
BEFORE every frame, covering the header and the payload. A connection that
delivers no complete frame inside that window is ended by its own reader, which
runs `finish` and releases the slot. So:

> `conns > 0` means every registered connection delivered a complete frame
> within the last `--read-timeout`.

That is the whole finding. A `conns=3` that stood for hours means either

1. those three connections were delivering frames — in which case the relay
   was forwarding, `forwarded` was climbing and every peer was receiving, and
   the missing votes are a problem ABOVE the relay (the relay parses nothing;
   it cannot drop a signed vote it received without incrementing `dropped`); or
2. the number was not a socket count at all.

`conns=3` with `dropped=0` is not compatible with three writers that had
stopped draining: a queue that nobody drains fills to its byte budget in
seconds at that frame rate and `dropped` rises with it. And a slot that leaked
does NOT show up in `conns` at all unless the connection was registered first —
a leaked *handshake* slot shows up only in `handshaking`, which the stats line
did not print.

What the line COULD not do is contradict itself. It printed the registry's
length and called it `conns`; nothing on the line came from the socket
lifecycle or from observed traffic, so no reading of it could distinguish
"three live connections" from "three registry entries". That is the actual
defect this incident cost two days to: **a metric that reports a desired state,
with nothing observed beside it.** `ss` was the only observation available,
and it contradicted the line with no way to tell which was right.

## 5. What changed

1. `Stats` now carries the socket lifecycle and an observation, and the stats
   line prints them (see `cmd/b10coin-relay --help`):

   ```
   b10coin-relay stats: conns=3 handshaking=0 live=3 forwarded=... dropped=... refused=... unauthorized=...
   ```

   - `conns` — registry length (unchanged meaning; now documented as
     bookkeeping, not sockets);
   - `handshaking` — accepted sockets still presenting the access token, which
     both caps count but the registry does not;
   - `live` — `accepted - closed`: the sockets this process has NOT closed,
     counted at the socket's own lifecycle (`closeSocket` counts only the call
     that actually closed a socket, so `Close`'s sweep and a handshake
     goroutine's own close cannot double-count one socket).

2. `Relay.ConnBookkeepingIssue` compares, and the stats tick logs a second line
   when it fires:

   ```
   b10coin-relay: CONNECTION BOOKKEEPING DISAGREES: the caps count 3 slots ... but the socket lifecycle counts 0 live ...
   ```

   Two comparisons: `conns+handshaking` against `live` (a leaked slot, a
   double release, or a connection whose socket is already closed all land
   here, and the message names the direction), and the oldest registered
   connection's silence against twice `--read-timeout` (a reader that is no
   longer reading — the incident's shape in the only form this source can
   produce it). A disagreement that a re-read 2 ms later no longer sees is not
   reported; the normal tick costs one `Stats` read.

3. `conn.lastFrame` is the one hot-path addition: one atomic store per complete
   frame, per connection, read once per stats tick. No new goroutine, no timer,
   no busy loop, no new dependency.

`--max-conns`, `--max-conns-per-ip`, the queue bounds, the frame cap, the
read/write deadlines and the gate's security properties are untouched; the
acceptance state root does not move.

## 6. What remains undetermined, stated plainly

- **No connection-slot leak exists in this source, so there was nothing to
  fix in the accounting.** The tests above are detectors, not a reproduction;
  they fail on the three mutants and pass on `origin/main`.
- **The incident's relay-side state could not be reconstructed.** If the run
  was this source, then per §4 the relay was forwarding at the time, and the
  consensus stall was above it. If the binary was older, the difference is not
  in this tree. A future incident of this shape should now be decidable from
  one stats line: `live` against `conns+handshaking`, and the disagreement
  line.
- **The node side was not investigated**, because the task's scope was the
  relay's bookkeeping. `conns=3` with HELLOs delivered and no votes arriving,
  plus an instant fix from restarting the RELAY, is also consistent with each
  node's relay link being wedged at the application layer while its socket
  stayed open; restarting the relay would then "fix" it by forcing a redial.
  Nothing in this tree rules that in or out — it is the next thing to look at,
  and node-side link liveness (last frame received per relay link) is the
  metric that would settle it.
