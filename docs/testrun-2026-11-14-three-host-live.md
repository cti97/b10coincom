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
