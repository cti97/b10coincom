# The round-divergence ratchet: why the live three-seat chain stops, and why it does not restart

Date: 2026-11-16. Scope: `internal/consensus` liveness on a live three-seat
fixture committee (three hosts, one WAN, one token-gated relay). Status: **cause
of the permanent stop identified as a design ratchet; trigger not fully proven;
a mitigation ships in this change.** Read §4 for the mechanism and §6 for the
mitigation.

## 1. The symptom

Three seats (two Raspberry Pis at home, one macOS), one relay at
`93.115.53.244:7001`, all on v0.1.6. The chain advanced from genesis to height
5797 in about three minutes (~20-30 blocks/s), then stopped at 5797 and stayed
there for hours:

- All three nodes reported the **same head hash** at the same height — no fork,
  no divergent state.
- The relay reported `conns=3 live=3`, `dropped=0`, every per-reason drop counter
  at zero, and `forwarded` advancing at ~12 frames/s — the HELLO rate.
- Each node's stall line showed **frame counters that name the fault**:

```
no block for 24 rounds at height 5798 (round 24, step propose):
quorum reachable with 3 of 3 power (quorum 3), yet nothing commits;
peers=2[seat0/... h=5798, seat1/... h=5798];
tallies r23 (last round with a vote): proposal=absent;
prevote votes=1 power=1 quorum=3 nil=1 ids=[00000000:1];
frames sent/recv[hello 64/130 proposal 15/0 prevote 24/0 precommit 0/0 ...];
routed=0 refused=0 dup=0 unknown=0
```

That line says: this node **sent** 15 proposals and 24 prevotes and **received
zero of either**, while it received 130 HELLOs (enough to learn both peers were
at the same height). The peers were alive, connected, and at the same height —
and no consensus frame crossed the wire.

- Restarting a single node did not help. Restarting all three together (with
  `rounds.log` deleted, which is liveness-only state) produced exactly **one
  block** (5798) and then the same silence.

## 2. What is NOT the cause

| Candidate | Verdict | Evidence |
| --- | --- | --- |
| Deterministic chain/state bug at height ~5798 | **Ruled out** | `devnet --validators 3 --blocks 6000` completes (`OK`, all three at 6000). A local three-node TCP committee (same v0.1.6 binaries, same genesis, real relay) ran from genesis past 13,700 blocks at ~22 blocks/s. |
| Fork / divergent state | **Ruled out** | identical head hash and state root on all three nodes |
| Relay dropping frames silently | **Ruled out for the queue** | every `dropped_*` counter at zero; the v0.1.6 accounting makes an admitted-and-abandoned frame a counted drop |
| Relay unreachable / TCP blackhole | **Ruled out** | `ss -tin` on both ends showed bytes flowing in both directions (≈5 KB/20 s per socket, 0 Recv-Q), with retransmits and RTTs of 8–35 ms |
| Node reader parked in the dispatch callback | **Ruled out** | a SIGQUIT goroutine dump showed the reader blocked inside `wire.ReadFrame` waiting for the next frame header — an idle socket, not a held lock |
| Connection churn (a node dropping and rejoining) | **Ruled out locally** | killing one of the three local nodes for 2 minutes and restarting it: the committee re-converged within ~12 s and resumed at 22 blocks/s |
| A relay bounce mid-run | **Ruled out locally** | killing and restarting the local relay under a running committee: it recovered immediately |

So the software is healthy on a clean network, and every mechanism that can be
tested locally recovers. The live failure needs the live conditions.

## 3. What the live conditions add

- RTT to the relay: 8–35 ms, with jitter up to ~25 ms and TCP retransmissions
  (`retrans: 0/23` on one socket, RTO ≈ 210–236 ms).
- The consensus round timeout at round 0 is **200 ms**
  (`internal/devnet/tcpnode.go`: `consensusTimeoutBaseMS = 200`,
  `consensusTimeoutStepMS = 100`). A vote whose packet is lost on the WAN is
  redelivered no sooner than one RTO — **≈210 ms, past the round-0 deadline.**
- Every node runs its own wall clock and its own ladder; a single late vote is
  enough to move one node to round 1 while the others are still in round 0.

## 4. The mechanism: a ratchet, not a bug in one line

The committee is three seats, and `consensus.Config.Quorum()` makes a 3-seat
committee's quorum **3 of 3**. A quorum needs all three votes *in the same
round*. The engine only votes in the round it is in.

Once one node is a round ahead, the timeout ladder is supposed to close the gap:
`Driver.Tick` arms each round at `TimeoutBase + round × TimeoutStep` — strictly
increasing in the round, so the node holding the **lower** round fires sooner and
gains a round at a time ("job 2" in the Tick comment). The catch-up rate is
proportional to `1/T(r) − 1/T(r+k)`:

```
T(r) = 0.2 s + 0.1 s × r

r = 0    : T = 0.2 s     gap closes at ~tens of rounds/s   (recoverable)
r = 100  : T = 10.2 s    gap closes at ~0.01 rounds/s      (minutes per round)
r = 300  : T = 30.2 s    gap closes at ~0.001 rounds/s     (hours per round)
```

The ratchet is the combination:

1. A transient (one lost vote, one slow read on a Pi, one reconnect) buys one
   timeout at 200 ms. That is all it takes to start the ladder.
2. The ladder climbs fast at low rounds (0.2 s, 0.3 s … per round), so a node
   that stays out of step for a minute is already at round ~30; after ten
   minutes it is at round ~100, where the catch-up rate has collapsed.
3. Because quorum is 3 of 3, the two in-step nodes cannot commit without the
   third; they keep timing out too, so **all three** climb the ladder at
   different offsets. This is why the height freezes at the same value on all
   three: the chain can only stall at its tip.
4. From there, every mechanism that could resync needs the very votes that are
   the rarest thing on the wire — one nil prevote per node per round, at
   intervals now measured in tens of seconds — and the relay-link watchdog
   (below) can throw those away by redialling.

`jumpTarget` (the +16-rounds-per-timeout resync on attested-round evidence)
cannot break the tie quickly here: at round 100 each jump costs one 10-second
timeout, and a 3-seat committee's `quorum == total` is exactly the shape the
engine's own comments call out as the one with "full stall power" in a single
member.

## 5. The open sub-mystery: no consensus frames at all

The counters in §1 say *zero* proposals and prevotes were read off the socket,
while HELLOs were read. The receive counter is incremented immediately after
`wire.ReadFrame`, before pacing, admission or routing, so this is not a filtering
artefact — the bytes really were not there. Yet the relay's kernel reported
bytes flowing to the same peer, and the node's reader was found parked in
`ReadFrame` on an idle socket.

Two candidates remain, and they need one instrumented live run to separate:

- **A replaced connection.** Nodes redial on the 64 s relay-link watchdog
  (`DefaultRelaySilenceTimeout = 4 × the relay's 15 s keepalive`). If the relay's
  fan-out ever names a connection the peer is no longer reading (or the peer
  reads a socket the relay no longer forwards to), frames are written into a
  hole and counted as forwarded. The relay's registry is keyed per connection;
  `newcomerWins` decides which of two dials keeps the slot.
- **A partial frame.** `wire.WriteFrame` writes the 4-byte header and the payload
  as two separate `Write` calls. A write deadline expiring between them leaves
  the peer's parser waiting for a payload that will never come; `ReadFrame`
  blocks until the socket is closed, which is the 64 s watchdog. Every live
  reconnect would then repeat the cycle.

Neither is proven. What is needed: one log line per accepted/closed connection
and per forward (peer address, frames in/out, queue bytes) on the relay, plus a
per-connection read counter on the node. That is a follow-up, not part of this
mitigation.

## 6. The mitigation

**Raise the round-0 tolerance by an order of magnitude, keep the ladder's slope,
and make both operator-tunable.** The base timeout is a *ceiling on waiting*, not
a polling interval: a healthy round commits as soon as its votes arrive, so a
larger base costs nothing in throughput. It only buys immunity to the transient
that starts the ratchet.

- `consensusTimeoutBaseMS`: 200 → **2000** (10 × the observed RTT p99 including
  one retransmit).
- `consensusTimeoutStepMS`: 100 (unchanged) — so at round 100 the deadline is
  2 s + 10 s = 12 s, essentially the same as before (10.2 s); the ladder still
  closes gaps at high rounds at the same rate, but far fewer gaps start at all.
- New `--timeout-base` / `--timeout-step` flags on `b10coin node` thread the
  values through `devnet.ValidatorConfig`, so an operator on a worse path can
  slow the committee further without a rebuild. Zero keeps the shipped defaults.

This is the trade the mitigation makes, stated plainly: **it does not fix the
ratchet's tail; it makes the ratchet start ~10× less often.** A chain on a
pathological network that still manages to fall 100 rounds out of step will
still take a very long time to recover — that is the protocol's design, and
changing it (round-resync messages, a bounded ladder with a resync floor, or a
fourth seat so quorum is 3 of 4) is a consensus change that needs its own plan
and audit.

## 7. Operating the three-seat fixture

- Restart the committee **together**; a rolling restart of one node leaves the
  other two climbing the ladder alone.
- Do not restart the relay while the committee is running. The relay's restart
  drops every link at once, which is exactly the transient that starts the
  ratchet. (In this incident the relay was bounced at 16:50 to deploy v0.1.6;
  the chain ran for another six minutes and then stopped.)
- If the height is flat, check `curl -s 127.0.0.1:8645/status` on all three:
  identical head hash means no fork (wait or restart together); different heads
  mean a real partition (stop and investigate).

## 8. What is proven, and what is not

Proven:

- The live stop is a liveness failure of a 3-of-3 committee, not a fork, not a
  relay drop, not a state-machine bug at that height.
- The timeout ladder's catch-up rate collapses as `1/T²`; at round 100+ a
  divergence is effectively permanent.
- Every mechanically reproducible transient (relay bounce, node kill/rejoin) is
  survivable on a clean network, and none of them is survivable on a network
  where a single round-0 deadline can be missed.

Not proven:

- Which side of the relay link stopped delivering consensus frames in §5.
- Whether the same stall recurs with the new base on the live path — that is the
  test this mitigation exists to run.

## 9. Reproducing the local half

```sh
# three nodes + one relay on localhost, same binaries and genesis
b10coin-relay --addr 127.0.0.1:7102 --access-token-file token &
b10coin node --dir seat0 --http 127.0.0.1:8651 --validators 3 --index 0 \
  --relay 127.0.0.1:7102 --relay-access-token-file token &
# ... seat1/8652, seat2/8653
```

Healthy: ~22 blocks/s, all three within one height of each other. Killing one
seat for two minutes and restarting it re-converges in ~12 s; bouncing the relay
under a live committee recovers immediately. The live failure is not reproducible
this way, which is why the mitigation targets the transient rather than the
local path.
