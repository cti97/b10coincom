# Open: consensus votes do not reach peers, on a healthy relay

**Status: OPEN. Cause not identified. The chain has not committed since height 5,794.**
2026-11-15, three validators (two Raspberry Pis, one macOS) across three networks
through one token-gated relay.

---

## 1. The observation

Every seat at the **same height**, the **same round**, every peer **admitted** — and
each tallying only **its own** vote:

```
my node:  height 5794, round 24
          peers=2[seat0/relay:93.115.53.244:7001 h=5794,
                  seat1/relay:93.115.53.244:7001 h=5794]
          tallies r23: proposal=absent;
                       prevote votes=1 power=1 quorum=3 nil=1;
                       ids=[00000000:1]; selfprevote=nil

relay:    conns=3  forwarded=190315  dropped=61  refused=0  unauthorized=0
ss:       3 established sockets
```

`votes=1 power=1 quorum=3` is one vote — the node's own. It never counts a second.
**HELLOs arrive (peer admission works); consensus messages do not.**

## 2. What was ruled out, and how — do not repeat these

| Hypothesis | Verdict | Evidence |
|---|---|---|
| A code regression in M7/M8/the audit fixes | **No** | `v0.1.1` — the binary that ran 824,350 blocks the day before — stalls at height 1 on the same topology |
| `--retain-blocks` interference | **No** | bisected: reproduced without the flag |
| The relay mis-reporting `conns` | **No** | my `ss` command printed `$5` of a **4-column** output, so the blank lines I read as "0 sockets" were my own off-by-one. `conns=3` was correct throughout |
| The relay leaking connection slots | **No** | nine handshake exits each release exactly once; 40,000 churn cycles under `-race`; three compile-confirmed mutants prove the detectors bite (see `bug-2026-11-15-relay-conn-bookkeeping.md`) |
| A silent relay link (wedged socket) | **No, and now instrumented** | the link watchdog (`66978db`) tears down and logs a link silent for 60 s; no such line has fired, while ~190,000 frames were forwarded |
| Round divergence | **Real, but not this** | it was a genuine failure mode; `/var/lib/b10coin/rounds.log` persists the round a node reached, so a restarted node resumes ahead of its peers (`resuming height 2 at round 249`). Deleting `rounds.log` fixes it (it is liveness, not safety — `locks.log` is the double-vote record per audit I-3) |
| The catch-up path | **No** | catch-up covers a one-height gap in every shape the harness can build (direct TCP, relay star, live timing); its defect is that a **failed pull logs nothing** (`bug-2026-11-15-catch-up-gap.md`) |
| A version mismatch between nodes | **No** | reproduced with all three on the same binary |

## 3. What is actually known

- **The relay forwards.** ~190,000 frames, three live sockets, honest counters.
- **Peer admission works.** Every node lists every other seat at the same height.
- **Heights and rounds agree.** This is not divergence.
- **Votes still do not arrive.** Each node counts one prevote out of three.

So the gap is between *the node deciding to send a vote* and *that vote being counted by
a peer* — and it is upstream of the relay (which forwards) and downstream of peer
admission (which works).

## 4. The next instrumentation, and why it is the right one

**Count frames by kind on both the send and the receive path.**

If the ~190,000 forwarded frames are HELLOs and heartbeats rather than proposals and
votes, the node is sending consensus traffic nowhere — or not sending it at all. The
relay cannot say (it parses nothing by design). The node can.

Concretely, two counters per link:

- **sent**, by message kind (hello, proposal, prevote, precommit)
- **received**, by message kind

Then one stalled run answers it: either the votes are not being sent, or they are
sent and not received, or they are received and not counted. Each has a different
fix, and today all three are equally consistent with the evidence.

This is the fifth silent failure in this project. The pattern is now established, and
the fix shape is the same every time: **publish what the component observed, not what
it intended.**

## 5. What not to do

- **Do not restart the nodes to "try again".** Heights and rounds already agree;
  restarting changes the round position (see §2) and adds a variable.
- **Do not restart the relay.** It is measurably healthy. Its apparent earlier "fix"
  was a fresh socket, and with three honest sockets the failure persists.
- **Do not change consensus to make the tally more forgiving.** A node that counts
  votes it should not is a safety break; the goal is to find where the votes went.

## 6. Operational note

`rounds.log` can be deleted safely (liveness). `locks.log` must not be (double-vote
safety). There is **no supported way to reset the round position** and the deploy
README's advice — "restart the committee together" — makes the position worse, because
each restart resumes at a higher round. That lack is a real gap, recorded here because
it will bite the next operator.
