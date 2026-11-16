# The 2026-11-15 vote stall: what the counters prove, and what is still open

**Status: cause NOT proven. No consensus change was made.** This file records the
instrumentation that was missing, the measurements it produced on one host, one
measurement that was an artifact and is rejected below, and the ranked candidates
that survive — each with the exact number that would confirm or kill it on the
live three-host topology.

The incident (three validators on three home networks through one token-gated
relay) is still undiagnosed. Read this as "here is the instrument and the first
readings", not as a diagnosis.

---

## 1. Why the incident was unanswerable

The stall line said, on every node:

```
tallies r23: proposal=absent; prevote votes=1 power=1 quorum=3 nil=1;
             ids=[00000000:1]; selfprevote=nil
```

`votes=1` with a fresh HELLO from both peers is consistent with **four different
faults**, and they need four different fixes:

| # | Fault | What a run would show |
|---|---|---|
| 1 | The node never **sent** the vote | sent = 0 |
| 2 | It sent it and the far end never **received** it | sent > 0, received = 0 |
| 3 | It received it and its **router refused** it (non-member key, height outside the live window, duplicate) | received > 0, routed = 0, refused/dup rising |
| 4 | It routed it and the **engine dropped** it (another height, a round now behind or ahead, a wrong proposer) | routed > 0, tallies still 1, engine foreign/early/late rising |

The relay could not help: it parses nothing by design, and that property is
preserved. The node now publishes the numbers itself.

---

## 2. The instrumentation (landed on `investigate-vote-propagation`)

`internal/transport/tcp/framecounts.go` counts, **per connection and per
direction**, frames by kind: `hello`, `proposal`, `prevote`, `precommit`,
`exchange` (PEER_EXCHANGE), `sync` (BLOCK_SYNC), `other`.

- **SENT** is incremented when a frame is accepted into the connection's write
  queue. A queue-full refusal goes to the existing `dropped` counter instead, so
  every frame the node offered a link is in exactly one counter.
- **WRITTEN** is incremented after `wire.WriteFrame` returns nil. `written <=
  sent` always; the gap is the link's own backlog.
- **RECEIVED** is incremented the instant a complete frame is read off the
  socket — **before** pacing, admission or dispatch can drop it. That placement
  is deliberate: a vote that arrives and is then refused is still "received",
  and the router's counters say why.

Classification reads **one tag byte** and decides nothing: no control flow,
admission, routing or framing depends on it. The router keeps its verified-decode
discipline; the relay is untouched. A test pins the tag mapping against the
`consensus` and `wire` unions, so a renumbering cannot drift the buckets.

`internal/devnet` renders the totals and a verdict on the once-per-height stall
line (and its quorum-unreachable sibling), which is the one output a stalled run
already produces:

```
... selfprevote=nil;
frames sent/recv[hello 62/58 proposal 4/10 prevote 21/27 precommit 0/0
  exchange 0/0 sync 0/0 other 0/0] queued=1 qdrop=0 gated=0 paced=0
  links=1[relay:…];
routed=3 refused=0 dup=0 unknown=0
engine[otherheight=0 early=0 late=29 foreignprop=14 wrongprop=0 …];
...
```

One line now answers all four rows of §1. `links=N[...]` names the connection(s)
the counters are about; a relay star has exactly one, and `queued` is that link's
sent-minus-written backlog.

Tests: `framecounts_test.go` (classification against the real tag unions; both
directions counted on a real socket; a live three-seat committee puts consensus
frames in both directions) and `framesummary_test.go` (the summary and the
verdict appear on the line a stalled run prints).

---

## 3. Measurements on one host

All runs are three or four real `Validator` processes on one machine, a real
in-process `internal/relay`, real TCP, real token gate, and a frame-aware proxy
that adds **propagation** delay per direction (each frame is stamped when read
and written when due, so a burst arrives together — see §4 for why that detail
matters).

| Topology | Result |
|---|---|
| 3 seats, local relay, no added delay | ~13 blocks/s (5 heights in 0.4 s) |
| 3 seats, asym 10/60/120 ms + 0 jitter | **59 heights in 90 s**, longest gap 2.6 s |
| 4 seats (3 nodes), asym 10/60/120 ms + 0 jitter | 55 heights in 90 s |
| 3 seats, asym 10/150/300 ms + 50 ms jitter | **17 heights in 120 s**, gaps of a few seconds |

A valid 30 s sample at 10/150/300 ms + 50 ms jitter, after committing height 6:

```
seat0 h=6 r=3 frames sent/recv[hello 60/116 proposal 27/28 prevote 54/103
      precommit 8/25 exchange 0/0 sync 0/0 other 0/0]
      queued=0 qdrop=0 gated=0 paced=0 links=1[relay:…]
      routed=156 refused=0 dup=0 unknown=0
      engine[otherheight=1 early=0 late=0 foreignprop=2 …]
```

Both directions of every consensus bucket move, `qdrop=0`, `refused=0`,
`unknown=0`, and the chain is committing.

In every one of these runs the counters showed the same thing:

- `sent` and `recv` move in all consensus buckets; each node's `recv` is roughly
  twice its `sent` (two peers), as it must be on a 3-seat star;
- `qdrop=0`, `gated=0`, `paced=0`, `queued≈0` — **no frame was dropped or even
  queued for long on the node side**;
- rounds per height rose to 3–10, and the engine diagnosis (same pipelined
  proxy) showed the reason for the slowdown: prevote sets **split**
  (`v=3 power=3 n=2`: two votes for the block, one nil) or a precommit tally of
  **1–2 of 3**, never a same-round quorum; `foreignprop` rose and `late`/`early`
  stayed near zero. That is round-phase fragmentation under asymmetric RTT, not
  loss.

So on one host, with a correct propagation model, **real RTT degrades throughput
by two orders of magnitude but does not stop the chain**. It does not reproduce
"cannot commit one block".

---

## 4. A rejected measurement (recorded so it is not repeated)

An earlier proxy version forwarded frames **one at a time with a `sleep(delay)`
between them**. That does not model propagation delay; it imposes a `1/delay`
frame *rate*. Under it, three seats at 10/150/300 ms + 50 ms jitter made **zero
progress for 300 s** at height 0, rounds reached 75, and each node printed
exactly the incident's tallies — while the counters showed
`hello 600/1195, proposal 31/43, prevote 76/147` and `qdrop=0`.

That run is the clearest illustration of the instrumentation's value and of the
trap: **the incident's line is not evidence of missing frames.** It is also
exactly what a round-phase split produces. But the stop itself was an artifact of
serializing bursts, and it disappeared when the proxy was made pipelined. The
two mutant comparisons run before that fix (no round jump; four seats instead of
three) are therefore **void** and are not used below.

---

## 5. What is proven

1. **The one-host node/transport/relay path loses no frames**, with real TCP, a
   real relay, real gate and WAN-shaped delay up to 600 ms pair RTT: sent,
   written and received all advance, `qdrop=0`.
2. **Real RTT alone does not reproduce the incident.** Under a correct delay
   model the three-seat committee commits continuously (slower), and the engine
   diagnosis names the slowdown as round-phase splitting, not propagation.
3. **`proposal=absent; votes=1 nil=1` does not discriminate** between "frames
   missing" and "frames arriving for other rounds". The stale tallies look
   identical. Only the counters separate them.

What is **not** proven: the live incident's cause. I could not reach the three
hosts, and no one-host topology I can build reproduces the 13-minute halt.

### What the relay's own rate implies

The relay forwarded **~14 frames/s** during the stall. With three seats and a
HELLO every 500 ms (`devnet.WaveEvery`), HELLOs alone are 3 senders x 1 frame x
2 receivers per 0.5 s = **12 forwarded frames/s**. (`PEER_EXCHANGE` adds 3/s only
if a node advertises a listener; the shipped unit passes no `--listen`, so the
expected value is 12/s.) The remaining ~2/s is about one originated consensus
frame per 0.5 s — the rate of three nodes each casting one nil prevote per
~2.6 s round, forwarded to two peers each, is ~2.3/s.

That arithmetic is rough, but it points one way: **the relay was probably
carrying the nil votes and the nodes were mostly in different rounds, not losing
frames.** If so the tallies are the round-phase shape, and the engine's
`late`/`early`/`foreignprop` counters are where the votes went. This is inference
from a sampled rate, not proof, and the new line settles it.

---

## 6. Ranked candidates, with the number that decides each

**A. Received but dropped after the socket: router (membership, two-height
window, dedup) or engine (another height, a round ahead or behind).** The
incident's `peers=2` with fresh HELLOs proves the reader was alive and reading;
the relay's ~14 frames/s suggests consensus frames were also flowing (see §5).
If they were read, they were dropped by the node's own decision after the socket,
or the node was in another round when they arrived. *Decided by*: `recv>0` with
`routed=0` and `refused`/`dup` rising (router), or `routed>0` with
`late`/`early`/`otherheight` rising (engine). **These are the first numbers to
read on the next stall**, and they were invisible until this branch.

**B. Round-phase fragmentation under latency, jitter and per-host tick-rate
differences.** The three-seat committee needs all three seats in the *same*
round; a phase split makes every vote foreign to someone, while HELLOs (a 500 ms
cadence, no quorum) keep arriving. My one-host model reproduces the split and the
throughput collapse (15/s to 0.1-0.7/s) but not a 13-minute halt, so this
candidate needs a harsher or longer-lived network than I could build.
*Decided by*: rounds climbing across the 13 minutes, and `late`/`early`/
`foreignprop` rising while `recv>0` and `routed>0`. The single sampled line
cannot tell a parked round from one instant of a climbing ladder — that is the
measurement to make next.

**C. The relay tears a link down and discards its queued frames silently.**
`internal/relay`'s `finish` drops the queue without incrementing `dropped` and
without a log line; `forwarded` was already counted at enqueue. A link that dies
under the relay's 30 s write timeout therefore loses frames that every relay
counter calls forwarded. *Decided by*: the relay's `Accepted`/`Closed` counters
moving during the stall while `conns` samples look like 3, the node's `links`
changing, or a sender's `written` advancing while the peer's `recv` for that kind
stays flat. Weaker against `peers=2` unless the teardown is brief — and the
~14 frames/s argues the relay was carrying traffic.

**D. Something outside this process** (MTU/PMTU blackhole, a one-way firewall
rule, DNS flapping). *Decided by*: `sent>0, written>0` on the sender with the
peer's `recv=0` for every kind. A blackhole that passes HELLOs should also pass
votes (both are small), so this is ranked last — but an MTU-limited *proposal*
alone would not explain `votes=1`.

---

## 7. The next live measurement

Build the node binary from `investigate-vote-propagation` and redeploy the three
seats (the relay binary is unchanged — it still parses nothing). On a stall, one
line now contains all four numbers:

```
frames sent/recv[...] qdrop=… gated=… paced=… links=…
routed=… refused=… dup=… unknown=…
engine[otherheight=… early=… late=… foreignprop=…]
```

- `precommit 0/0` + `proposal 0/0` sent = 0 → the engine never emitted (row 1).
- sent > 0, peer `recv` = 0 → relay/network (row 2, candidate C/D).
- peer `recv` > 0, `routed` = 0 → router (row 3, candidate A).
- `routed` > 0, tallies still 1 → engine round handling (row 4, candidate A/B).

The relay's `Accepted`/`Closed`/`Handshaking` should be sampled beside `conns`
during the stall; `conns` alone cannot show a redial between samples.

---

## 8. Candidate fixes and why none was made

- **Relay: count and log frames discarded by `finish`.** Low risk, instrumentation
  only, but it changes a production process and would not have fixed anything by
  itself; left as a recommendation because it closes the only silent-loss path
  in the relay.
- **Node: measure the round phase directly** (per-node round-entry timestamps in
  the diag ring) to make candidate C measurable rather than inferred.
- **Consensus timing / jump bar / a fourth seat.** These are consensus or
  deployment changes. A wrong one is far worse than a documented cause: the jump
  bar, the linear ladder and the three-seat limitation are each load-bearing and
  audited elsewhere. Do not touch them on this evidence.

---

## 9. What could not be determined

- Whether the live nodes sent the votes at all. The counters answer this; no
  counter existed during the incident.
- Whether any relay link was torn down and redialled during the 13 minutes. The
  relay does not log teardowns and the operator sampled `conns` periodically.
- The real pairwise RTTs and their asymmetry during the stall.
- Whether the round ladder was climbing. A single sampled line cannot tell a
  parked round from one instant of a ladder.

---

## 10. 2026-11-16: the relay's silent discard at teardown (found and fixed)

The relay's per-connection `sendQ` was instrumented with one counter per refusal
reason (per-sender share, byte budget, frame-count ring, the N-1 reservation).
That DISPROVED the hypothesis this round started from: `sendQ.push` never
returned false without `forward` counting a dropped frame, and no consensus-sized
frame was preferentially refused. Measured at the bulk ceiling (queue 1,966,080
of 2,097,152 bytes; bulk limit 2,031,616): 12 of 12 HELLOs and 12 of 12
consensus frames were admitted, and the only refusals were bulk frames.

The counters did expose the real silent path, in `finish`: a frame ADMITTED to a
queue was counted `Forwarded` at enqueue and then discarded when its connection
was torn down (`Forwarded` counts enqueued frames); nothing counted those
frames as lost. Reproduced end-to-end: 1,500 consensus-sized frames offered, the
receiver paused past the write bound, 368 delivered, 1,132 discarded - and
`dropped=0` while `forwarded` read 1,500.

The fix counts them: `finish` drains the queue through `sendQ.abandon`, and every
discarded frame (plus the frame in the writer's hand when its write fails) is a
`Dropped` frame, logged with the byte count. The invariant is now `Forwarded =
delivered + Dropped` for the frames the relay admitted, which is what makes a
"forwarded climbing, dropped=0" line mean something.

Two teardown paths abandon frames, and both are counted. The ordinary close
(peer gone, read deadline, shutdown) attributes to `DroppedOnClose`. The
write-deadline REAP - the writer ending a receiver that stayed stalled past
`WriteTimeout`, which is the path the live stall exercised (queues of 60-66 KB
against a 30 s timeout in 572 of 1,019 samples) - attributes to `DroppedReap`
and logs once per reap. The frame the writer had already popped when the
deadline expired, or when the deadline could not be armed, is invisible to
`abandon`; the writer charges that frame itself as `rejectReap` /
`rejectConnClosed`, so the one frame in hand cannot slip out uncounted. The
stats line publishes every per-reason counter, including `dropped_reap`.
Tests fail on `origin/main`: `TestRelayFinishCountsTheFramesItDiscards`,
`TestRelayAReceiverPauseLeavesNoUncountedFrame` and the constructed exit pins
(`TestTheWriteDeadlineReapCountsTheBacklogItDiscards`,
`TestTheWriterCountsThePoppedFrameWhenTheDeadlineCannotBeArmed`,
`TestTheWriterCountsThePoppedFrameWhenTheWriteDeadlineExpires`).

What is still NOT claimed: this is not proof that the live three-host stall was
a teardown. It is proof that the relay could report a frame forwarded and never
deliver or count it, which is exactly the shape the incident's counters showed.
