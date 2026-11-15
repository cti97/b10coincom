# Test run report: three validators on three hosts, live (2026-11-14)

| | |
|---|---|
| Chain | `b10coin-simnet-3` — the fixture committee, three seats, keys from public seed |
| Validators | 2 × Raspberry Pi (separate home networks) + 1 × macOS (separate network), all behind NAT |
| Transport | one public relay, `93.115.53.244:7001`, token-gated |
| Artefact | release `v0.1.1`, built from tag `0a09562`, `rev 0a095628f8f4 (clean)` |
| Date | 2026-11-14, 17:00–17:10 EET |

**This is the first time b10coin finalised blocks on more than one machine.** Every
earlier run — devnet, simnet, the Docker runs — was either one process or several
containers on one host.

---

## 1. Result

```
height  2483 → 2959 in 30 s          ~15 blocks/s sustained
head    b57b0d94c0f7 → 75de878b2b24
relay   conns=3  forwarded=35,575  dropped=0  refused=0
        unauthorized=140,522  (frozen since v0.1.1 — see §4)
```

Three seats, three hosts, three home networks, one public relay. Blocks commit,
the head advances, and the relay carries every frame with **zero drops and zero
refusals**.

For scale: 15 blocks/s is faster than the 2 s block time the single-node
producer uses, because a three-seat committee commits as fast as its rounds
complete rather than on a ticker. Nothing in the design caps that.

## 2. What this proves

- **The transport works across NAT and the open internet.** Both Pis dial out
  through their home routers; the node this Mac runs on dials out likewise; none
  needs an inbound port.
- **The relay gate admits honest nodes and only honest nodes.** With a correct
  token: admitted on the first attempt, `conns=3`. Without one, refused — see §4.
- **Peer admission completes over the relay.** Each node names the others as
  peers (`seat0/relay:…`, `seat1/relay:…`) and votes are exchanged through a
  dumb forwarder that parses nothing.
- **Consensus commits with a real WAN round trip in the path.** The BFT path was
  previously only ever exercised with sub-millisecond latency.

## 3. What this does *not* prove

- **Not three Raspberry Pis.** Two Pis and a Mac. The Pi-class hardware claim
  needs a third Pi.
- **Not a secure committee.** The fixture committee derives every seat's key from
  a public seed; any reader of the repository can sign as any seat. The nodes say
  so in a startup banner. This proves the *plumbing*, not the *security model*.
- **Not a long run.** Ten minutes, ~3,000 blocks. No soak, no restart-under-load,
  no network partition.
- **No staking.** The committee is genesis-defined; nothing bonded, rotated or
  unbonded during the run.

## 4. The one code defect this run found

The deployment could not start at all until `0a09562`:

```
b10coin-relay: gate refused 79.115.164.15:36674: frameLen=2 wantLen=32 frame="v1"
```

A relay link sent its **2-byte transport ID** where the relay expects the
**32-byte gate MAC**, so every gated relay refused it, the node redialled in
silence, and `conns` never left 0. The node took that path because its transport
had no access token: the shipped systemd unit's `B10COIN_RELAY_TOKEN` defaulted
to empty, so `--relay-access-token-file` was never passed, and `adoptRelay`'s
token-less branch wrote the identity frame.

Full investigation: [`bug-2026-11-14-relay-gate.md`](bug-2026-11-14-relay-gate.md).

**`unauthorized=140,522` is frozen** — every one of those was counted before
`v0.1.1`. Not one has been added since, which is the gate fix working.

## 5. Why the test suite did not catch it

`relay_gate_test.go` passes on both the broken and the fixed tree. It drives an
**in-process relay** and never takes the `--relay` dial path, so the frame the
node actually sends on that path was never on a wire any test could see.

Two tests now close it:

- `TestATokenlessRelayDialSendsNoIdentityFrame` — fails pre-fix with the literal
  `"v0"` forwarded by a real relay
- `TestTheRelayDialPathIsAdmittedOnTheFirstAttempt` — real `net.Dial`, real
  relay, a one-hour backoff so no retry can mask it: `conns==1`,
  `unauthorized==0`

**The general lesson**: a suite of 1,324 tests could not see this because every
gate test exercised one side of the socket boundary and not the other. A defect
that lives *between* two components needs a test that spans both, and this
project's tests are otherwise almost entirely within-package.

## 6. Operational failures during the deployment

None were software defects; all were in the deployment path, and each is now
fixed:

| Symptom | Cause |
|---|---|
| `226/NAMESPACE`, crash loop, restart counter 29 | the unit used `ProtectSystem=full` + `ReadWritePaths=/var/lib/b10coin`, which **requires the path to already exist** — deleting the data dir made it unmountable. Now `StateDirectory=b10coin`, which creates, owns and recreates it. |
| Nodes resumed at **round 429**, 43 s per round | the durable round record persisted from earlier timeouts. A node that has been idle resumes far ahead of the committee, where the uncapped ladder makes progress take minutes per round. |
| Pis at different rounds never converging | consequence of the above: one at round 0, two at round 429. Clearing the data dir on all three made them start level. |
| A stale `nohup` node held port 8645 | the harness kills background processes when a tool call ends, so the same port was re-bound by a dead socket's owner. Now a managed background job. |

**The round-429 resume is a genuine open issue**, not just an operational one: a
validator down for a while comes back at a round ahead of everyone, and there is
no way to clear it except deleting the data directory. It is the same class as
the rolling-restart stall the Docker run found, and it deserves either a bound
relative to peers observed or a documented reset.

## 7. Reproducing

```bash
# on each host, identically — the seat is assigned and remembered
curl -fsSL https://github.com/cti97/b10coincom/releases/download/v0.1.1/pi.sh \
  | sudo B10_RELAY_TOKEN=<token> sh
```

The seat coordinator on the relay host (`:8646`) assigns 0/1/2 and records the
machine id, so a re-run keeps its seat and two machines never share one.

Watch it: `journalctl -u b10coin -f`, and `curl -s 127.0.0.1:8645/status`.

---

## 9. Five-hour soak (added after the fact, same run)

The run in §1 was still going when this report was written. Five hours and fifteen
minutes later, without a restart of any node or of the relay:

```
node       height 280,427 -> 280,521 while watched   (10 blocks/s live)
           sustained 14.8 blocks/s over 5h15m  =  280,169 blocks
relay      conns=3   forwarded=4,195,263   dropped=0   refused=0
           unauthorized 140,522 -> 140,526   (+4 in five hours)
           5.6 MiB RSS   ·   0 restarts   ·   0 OOM
```

**These are stronger figures than §1 and they supersede them.**

- **280,169 blocks across three hosts on three networks, continuously, with no
  halt, no fork and no stalled round.** The consensus ran for five hours.
- **4,195,263 frames carried at ~222 frames/s with `dropped=0 refused=0`.** The
  relay's queue bounds - the PX-4 byte bucket, the N-1 reserved lane, the
  32-connection caps - held under sustained load.
- **5.6 MiB resident after 4.2 million frames.** This is the most useful number
  here: the relay's memory story is not "bounded by design" but *measured*, so the
  `MaxPinnedBytes` arithmetic is confirmed rather than asserted. No leak.
- **`unauthorized` moved by four in five hours.** On the broken build (§4) the same
  counter climbed ~1,200 every 40 seconds. This is the gate fix, measured over
  hours rather than minutes.

### What the soak did not exercise

**No node was restarted during the run.** That matters, because the one known
liveness defect - a restarted node resuming at its persisted round, where the
uncapped ladder costs ~43 s per round (§6) - is exactly what a soak with a restart
would hit, and this run never did. A 24-hour soak that restarts one validator and
confirms it rejoins is the missing evidence.

The live rate also drifted: ~15 blocks/s at the start of the run, 10 in the final
sample, 14.8 sustained. Nothing in the project measures block cadence over hours,
so whether that drift is load, peer churn or something structural is unmeasured.

## 8. Next

- **A third Raspberry Pi**, to make the hardware claim complete.
- **A soak**: 24 hours, restarting one validator, and confirm the round-resume
  does not strand it.
- **Held-key committee** (`--genesis` + `--key`) — this run used fixture keys, so
  it proves the transport but says nothing about admission, staking or rotation
  on real hardware.
- **Record the numbers**: 15 blocks/s across a WAN relay with three Pi-class
  nodes is a figure the README's Pi section should carry, and nothing measures it
  in CI.

---

## 10. Restart test (2026-11-15, same chain at height 824,350)

The soak never restarted a node, which §9 recorded as its main gap. It was then
restarted deliberately.

### The clean restart

```
stopped    height 820,083   data 557 MB across 821 segments
restarted  08:04:32
loaded     08:04:41        height 820,131   <- 9 s to replay 820k blocks
now        height 820,205 -> 820,513 in 20 s = 15 blocks/s

relay      conns=3  forwarded=12,256,721  dropped=0  refused=0
           unauthorized=140,539  (unchanged - the restart cost zero refusals)
```

**Recovery was nine seconds**, the node rejoined at the same height, and it was
voting at full rate within twenty more. `conns=3` throughout and `unauthorized`
unmoved means the other two seats never noticed the gap.

Two numbers worth recording: **557 MB of log replays in ~9 s** (about 91 MB/s,
~91,000 blocks/s of replay throughput, so the on-disk format is not a restart
bottleneck), and **zero refusals on reconnect** - the gate re-admits a returning
node on the first attempt, not just a first-time one.

### The round-resume defect did NOT reproduce, and it is narrower than recorded

**No `resuming height N at round R` line appeared.** The node came back at round 0
of the current height.

The Pis had shown `resuming height 1 at round 429`, and the difference is what
matters: **they had been stalling**, accumulating rounds by timeout; this node was
**committing** when stopped, so its persisted round was small and the resume was
cheap.

So the defect from §6 is not "a restart strands a node". It is:

> **A node that was stalled when it stopped resumes at its accumulated round. A
> node that was healthy resumes cheaply. The durable round record persists
> STALLS, not only state.**

That is worse than the earlier note suggests, because the trigger is not
"restart" - it is **"restart a node that had already been failing"**, which is
exactly the situation in which an operator would most want a restart to help.
Clearing the data directory is still the only way out.

### What this test did not cover

**The restart was clean** - `SIGTERM`, so the node flushed and closed its log
properly. A `kill -9` or a power cut is the harder case and is what a Pi actually
experiences; it would exercise log-truncation recovery across the `.seg` files.
**Untested.** Do not read this section as evidence that an unclean stop is safe.

## 11. `certs.log` is the dominant disk cost, and it is unbounded

Measured at height 824,350:

```
558 MB  total data directory
381 MB  certs.log       <- 68%, more than twice the block log
178 MB  825 x .seg      <- the block log, segmented and rotated
547 B   rounds.log
7.7 K   locks.log
```

**The certificate log is larger than the block log**, and unlike the block log it
is a single append-only file with **no rotation and no compaction**. At roughly
465 bytes per height that is about **1.6 GB per million blocks** from
`certs.log` alone.

At this run's rate (824,350 blocks in about 18 hours, ~1.1M blocks/day) that is
**~1.8 GB per day of certificates**. A Raspberry Pi on a 32 GB card would fill it
in under three weeks, and the file that fills it is not the one anyone thinks to
watch.

`du -sh /var/lib/b10coin/certs.log` is the number an operator should actually
monitor. Bounding it the way the block log is already bounded is bounded work.
