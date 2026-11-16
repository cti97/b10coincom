# Post-mortem: the 2026-11-16 three-seat chain stall

| | |
|---|---|
| **Incident** | The live three-seat testnet (`b10coin-simnet-3`: two Raspberry Pis + one macOS, one relay at `93.115.53.244:7001`) stopped advancing and could not be recovered by restarting nodes |
| **Detected** | 2026-11-16 ~16:56 EET (height frozen at 5797; noticed at 16:56–17:00) |
| **Duration** | ~1 h 30 min to root cause; ~2 h to a working mitigation release; the deadlock itself is **not yet fixed** |
| **Impact** | Fixture testnet only: no funds, no user data, no fork, no divergence of committed state. All three nodes agreed on the same head hash throughout. The live experiment (and the v0.1.7 validation) was blocked |
| **Status** | Root cause identified (transport/dispatch deadlock). Mitigation shipped in **v0.1.7** (round-timeout widening, PR #38). Deadlock fix **outstanding** (§7) |

## 1. Executive summary

The chain froze at a fixed tip (5797, later 5798, later 5799 — one block per
coordinated restart). Every node reported the same head and state root, the relay
reported all connections live with zero drops, and every node's own frame
counters said consensus frames were **sent but never received**.

The initial hypothesis — a consensus liveness problem caused by a too-tight
round timeout — was **partly right but secondary**. It produced a shipped
mitigation (v0.1.7: round-0 timeout 200 ms → 2 s, both values operator-tunable),
which is a genuine improvement. But the v0.1.7 live run reproduced the stop in
under two minutes, and a `SIGQUIT` goroutine dump showed the real fault:

> **The node's transport deadlocks.** Its single dispatch mutex is held across a
> callback that blocks on the validator mutex; every socket reader parks behind
> it; the consensus clock parks behind the same mutex; and each relay-link
> watchdog redial leaves another reader behind, so the process accumulates
> zombie readers until no frame can be read from any socket.

The relay was never at fault. The consensus rules were never at fault. The nodes'
own recovery machinery (the 64 s silence watchdog) made the situation worse by
dialling a fresh connection while the previous reader was still parked.

## 2. Timeline (EET, 2026-11-16)

| Time | Event |
|---|---|
| ~16:45–16:53 | Two Pis (seats 0/1) and this Mac (seat 2) are up. The chain produces ~5,797 blocks in about three minutes |
| 16:50:11 | Relay restarted to deploy v0.1.6 (binary swap). **Every validator link drops at once** and each node redials |
| ~16:56:20 | Chain stops at 5797. All three nodes report the same head hash |
| 17:00–17:15 | Single-node restarts, `rounds.log` resets, watchdog redials. Each attempt buys zero or one block |
| 17:07:20 / 17:08:07 | Coordinated restart (Mac, then Pi seat 0). **Exactly one block commits** (5798 at 17:08:41), then silence |
| 17:20–17:27 | Local reproduction: three nodes + the real relay on localhost, same v0.1.6 binaries — healthy at ~22 blocks/s past 13,700 blocks |
| 17:26–17:30 | Local fault-injection: relay bounce and a 2-minute seat outage both recover within seconds |
| 17:30–17:40 | Code analysis of the round ladder; mitigation designed, implemented, tested |
| 18:07 | PR #38 green (the only red was a cancelled CI job, re-run to pass) |
| 18:15 | **v0.1.7 released** (round-0 timeout 2 s, `--timeout-base`/`--timeout-step` flags) |
| 18:19 | Pis upgraded to v0.1.7; Mac seat started on v0.1.7 with a fresh `rounds.log` |
| 18:19:58 | First stall line on v0.1.7: frames **are** crossing (`proposal 7/3`, `prevote 11/10`), 2 of 3 prevotes for the same block, `early=1` |
| 18:20:50 | Block 5799 commits — then silence again |
| 18:24:58 | Relay bounced (documented recovery) — **no effect this time** |
| 18:27 | `SIGQUIT` goroutine dump: **dispatch deadlock identified** (§5) |

## 3. What operators saw

```
b10coin-relay stats: conns=3 handshaking=0 live=3 forwarded=… dropped=0
                     dropped_share=0 dropped_bytes=0 dropped_frames=0
                     dropped_lane=0 … refused=0 unauthorized=0
```

```
b10coin: no block for 24 rounds at height 5797 (round 24, step propose):
quorum reachable with 3 of 3 power (quorum 3), yet nothing commits;
peers=2[seat0 h=5797, seat1 h=5797];
tallies r23: proposal=absent; prevote votes=1 nil=1 ids=[00000000:1];
frames sent/recv[hello 64/130 proposal 15/0 prevote 24/0 …];
routed=0 refused=0 dup=0 unknown=0
```

And, every ~65 seconds, on every node:

```
b10coin: relay …: no frame received for 1m4.8s (relay-link silence bound 1m0s),
so the relay link is presumed wedged … being closed so the maintainer dials a fresh one
```

The three signals that misled the investigation:

1. **The relay's health line was clean.** Zero drops at every stage, connections
   live, bytes flowing on both ends (`ss -tin`). It looked like the one system
   that was working — and it was.
2. **The watchdog message said the socket was open and only the application was
   silent.** That is true, but it invited a network explanation when the actual
   cause was in-process.
3. **`sent` > 0, `recv` = 0** is the fingerprint the frame counters were built
   for (v0.1.5/PR #36). It correctly said "nothing was read off the socket", but
   until the goroutine dump there was no way to see *why* the reads were not
   happening.

## 4. What was ruled out, and how

| Hypothesis | Verdict | Evidence |
|---|---|---|
| Fork / divergent state | Ruled out | identical head hash and state root on all three nodes at every freeze |
| State-machine bug at that height | Ruled out | `devnet --validators 3 --blocks 6000` completes; local 3-node TCP committee sailed past the stall height (13,700+ blocks, ~22 blocks/s) |
| Relay queue loss | Ruled out | every per-reason `dropped_*` counter zero; v0.1.6 accounting makes an admitted-then-abandoned frame a counted drop |
| Relay connection registry leak | Ruled out (not the cause here) | relay held 3 live sockets matching `conns=3`; byte counters showed traffic both ways |
| TCP blackhole / NAT | Ruled out | `ss -tin` on both ends: bytes sent and ACKed, retransmits present but small, `Recv-Q`/`Send-Q` near zero |
| Reader parked in a *network* read | Ruled out | the reader was in `wire.ReadFrame` on an **idle** socket — consistent with data never being dispatched, not with a dead link |
| Connection churn (kill/rejoin) | Ruled out as a sufficient cause | local kill/rejoin recovers in ~12 s; relay bounce recovers immediately **on a clean network** |
| Too-tight round timeout | **Real, but secondary** | fixed and shipped in v0.1.7; the live v0.1.7 run still stalled, so it was not sufficient |

## 5. Root cause

### RC-1 (primary): transport dispatch deadlock

The `SIGQUIT` dump of the live Mac node at 18:27:

```
goroutine 19  [sync.Mutex.Lock, 6 minutes]
  transport/tcp.(*TcpTransport).dispatch          tcp.go:2544   ← holds dispatchMu
  transport/tcp.(*TcpTransport).reader
  consensus.(*Driver).OnMessage → flush → maybePrune
  devnet.(*Validator).maybePrune                  tcpnode.go:1765 ← wants v.mu

goroutine 52  [sync.Mutex.Lock, 6 minutes]
  devnet.(*Validator).tickLoop                    tcpnode.go:1180 ← wants v.mu

goroutine 114, 30, 12, 149, 123, 126, 183  [sync.Mutex.Lock]
  transport/tcp.(*TcpTransport).dispatch → dispatchMu ← every reader parked
```

`dispatch` deliberately holds one mutex across the whole callback:

> "At most one callback runs at a time (the lock is held across the call): the
> engine is single-threaded, and concurrent delivery from two readers would
> corrupt it." — `internal/transport/tcp/tcp.go`

That is fine only if the callback never blocks on anything else. It does: the
consensus flush path reaches `maybePrune`, which takes the validator mutex
`v.mu`, which the tick loop also needs for the same height. One callback stuck on
`v.mu` therefore parks **every reader of every connection**, which is exactly
the observed "no frame received for 64 s" while the relay keeps forwarding.

**Zombie accumulation.** The dump shows **eight reader goroutines but one
writer**. Each 64 s watchdog teardown closes a socket whose reader is parked in
`dispatch` (a closed socket does not unblock a goroutine waiting on a mutex), the
maintainer dials a fresh connection, and the old reader stays parked forever.
After a handful of reconnects the process can no longer make progress at all.

**What the dump does not show:** the goroutine that holds `v.mu`. The visible
goroutines are all waiting on it, so either the holder exited without releasing
it (leak) or it is blocked outside the captured set. The fix must therefore
remove the nested lock acquisition (RC-1) *and* add a dump-time debug endpoint
that names the lock holder; both are in §7.

### RC-2 (amplifier): 3-of-3 quorum with an unbounded timeout ladder

The committee is three seats, so quorum is **3 of 3**: every block needs all
three votes *in one round*. The round deadline is

```
T(r) = TimeoutBase + r × TimeoutStep        (was 200 ms + 100 ms × r)
```

The ladder is deliberately uncapped so that a node holding a lower round fires
sooner and catches up. Its catch-up rate is `1/T(r) − 1/T(r+k)`, which collapses
as the rounds grow:

| Round | T(r) | Gap-closing rate |
|---|---|---|
| 0 | 0.2 s | tens of rounds/s (recoverable) |
| 100 | 10.2 s | ~0.01 rounds/s (minutes per round) |
| 300 | 30.2 s | ~0.001 rounds/s (hours per round) |

So a link that goes deaf for one round's worth of time is survivable, but a link
that goes deaf for 64 s (the watchdog bound) drives all three nodes far up the
ladder, and the ladder can never close the gap again in practical time. This is
why the symptom looked like "one block per restart": a coordinated restart
resets the rounds to 0, one alignment commits, then the deadlock re-arms.

### RC-3 (trigger): reconnect churn from relay restarts and watchdog redials

The 16:50 relay restart dropped every link at once. Every node redialled, and
each redial is the step in which a parked reader can be left behind (RC-1). The
watchdog then creates a self-sustaining loop: silence → redial → another zombie
reader → more silence. This is why the local clean-network reproduction (no
reconnects at all) never triggered it in ~15 minutes of running.

## 6. Why it took 1.5 hours to find

- The failure is **silent at every layer**: no panic, no error log, no counter
  movement. The only visible symptom was the absence of blocks.
- The relay, the network, and the state machine were each independently healthy,
  and each was ruled out with experiments — correctly, but that left the fault
  hiding in the least observable place: goroutine state inside the node.
- The `sent/recv` counters (v0.1.5) proved *nothing was read off the socket*,
  which pointed at the network. The missing step was a **goroutine dump**, which
  should have been the first tool once "socket open, no frames" was established.
  It was found at 18:27; it should have been at 17:10.
- The 64 s watchdog message reads like a diagnosis ("presumed wedged") and sent
  the investigation toward the relay link rather than the reader.

## 7. Fixes

### Shipped: v0.1.7 (PR #38, tag `v0.1.7`, commit `060e37e`)

- Round-0 timeout **200 ms → 2 s**; step unchanged at 100 ms (it dominates the
  deadline at high rounds, so the ladder's slope is untouched).
- `--timeout-base` / `--timeout-step` per-node flags (refused on the
  single-node producer, negatives refused) so an operator can widen further on a
  slow path.
- Tests: defaulting rule + a 1 s floor on the base; stall-log tests pinned to the
  historical ladder deliberately.
- Verified locally: ~21–26 blocks/s, no throughput cost (the base is a wait
  ceiling, not a block interval).

This removes RC-2's *common trigger* (a single retransmit no longer starts the
ladder) but **cannot save a link that is deaf for 64 s**. It is necessary, not
sufficient.

### Required: the deadlock fix (RC-1/RC-3, not yet written)

1. **No validator lock from the dispatch path.** `maybePrune` (and any other
   `v.mu` work) must be handed to the tick/prune goroutine, never run on a
   reader's stack.
2. **No transport lock held across a callback.** Either drop `dispatchMu` before
   `onMessage` (serialise at the engine, which is single-threaded by design) or
   make the callback non-blocking by queueing to the engine's own goroutine.
3. **A reader must exit when its connection closes**, even if it is parked
   waiting to dispatch: check the connection's `dead` channel immediately before
   dispatch and return if closed, and give each connection a generation so a
   stale reader can never deliver into the current engine.
4. **Bound connections per peer.** The registry must refuse a second live
   connection from the same peer identity (or close the older one), so a redial
   loop cannot accumulate readers. The dump's 8-readers/1-writer ratio must not
   be reachable.
5. **Instrument the lock.** A debug endpoint that dumps per-connection state
   (address, frames in/out, parked readers) and the current holder of `dispatchMu`
   and `v.mu` turns the next occurrence into a one-command diagnosis instead of a
   SIGQUIT and 30 minutes of stack reading. Also log connection accept/close on
   both ends.
6. **Regression test.** Drive N reconnects while frames flow, then assert: one
   reader per live connection, no goroutine growth across cycles, and that the
   committee height still advances. This is the test that would have caught it.

## 8. Action items

| # | Item | Area | Status |
|---|---|---|---|
| 1 | Round-0 timeout 2 s + tunable flags | consensus | **Shipped v0.1.7** |
| 2 | Move `maybePrune` off the dispatch path | transport/devnet | Open |
| 3 | Stop holding `dispatchMu` across `onMessage` | transport | Open |
| 4 | Reader exit-on-close + connection generation | transport | Open |
| 5 | Bound live connections per peer | transport | Open |
| 6 | Debug endpoint: connection state + lock holder | transport/devnet | Open |
| 7 | Reconnect-storm regression test | tests | Open |
| 8 | Document the coordinated-restart rule in the deploy README | docs | Open (in bug doc §7) |

## 9. Lessons

- **A healthy relay line does not mean a healthy link.** Counters at the relay
  measure enqueue/write, not decode. The node's own read counters are the truth,
  and `sent > 0 / recv = 0` means "nothing was read", not "nothing arrived".
- **When a socket is open and the application sees nothing, dump the goroutines
  before theorising about the network.** `kill -QUIT` is one command and answers
  the question the logs cannot.
- **Single-lock fan-in across subsystems is a liability.** The transport's
  dispatch mutex exists for a good reason (one engine), but it must not be held
  across code that can block on another subsystem's lock.
- **Watchdogs that redial can amplify a fault.** A redial loop that leaves the
  old reader behind turns a transient stall into a permanent one. Recovery
  machinery needs the same lock/ownership rigour as the fault it recovers from.
- **A 3-of-3 committee has no liveness margin.** Any single missed round is a
  full stall; the ladder only helps at low rounds. Either the deadlock is fixed
  or the committee needs a fourth seat before any long run.

## 10. References

- `docs/bug-2026-11-16-round-divergence-ratchet.md` — the evidence trail, the
  ladder arithmetic, and the local reproduction steps.
- PR #38 / tag `v0.1.7` — the round-timeout mitigation.
- `internal/transport/tcp/tcp.go` — `dispatch` (the lock), `reader`, `writer`,
  `relayWatchdog`.
- `internal/devnet/tcpnode.go` — `tickLoop`, `maybePrune`, `waveLoop`.
- `internal/consensus/driver.go` — `Tick`, `OnMessage`, `flush`.
