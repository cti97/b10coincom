# Bug: a node one block behind did not catch up — evidence and the recommended path

| | |
|---|---|
| Date | 2026-11-15 |
| Status | **OPEN — documented, not fixed.** No behaviour changed. |
| Area | `internal/consensus/sync.go` (BLOCK_SYNC), `internal/devnet/tcpnode.go` (`maybeCatchUp`, peer table), `internal/devnet/stall.go` (the line) |
| Verdict | Catch-up **is** supposed to cover this case and does cover it in every shape this repo can build. The live node's own diagnostic proves its pull attempts were failing — and **no code path records why**. The fix is a diagnosability fix first; a consensus change now would be a guess. |

## 1. The observation

Three validators on real hardware, quorum **3 of 3**. One was wiped and restarted
at height 0 while the other two stood at height 1 (so they could not advance:
the quorum is exactly the three seats). The wiped node printed:

```
peers=2[seat0/relay:... h=1, seat1/relay:... h=1]
b10coin: no block for 25 rounds at height 0 (round 25, step propose): quorum
reachable with 3 of 3 power (quorum 3), yet nothing commits; tallies r24:
proposal=absent; prevote votes=1 power=1 quorum=3 nil=1; selfprevote=nil;
the round ladder is the only closer for a round divergence here, so a rolling
restart can hold this for minutes - restart the committee together or expect
the delay (README: rolling restart)
```

It knew both peers were at height 1, stayed at round 25 of height 0, and never
obtained block 1. The line's closing advice ("a rolling restart can hold this
for minutes") was also wrong: this shape does not clear with time, because the
peers' height never comes back down to it.

## 2. What the diagnostic actually proves — the clue that reclassifies the bug

`stallSyncing` (in `stall.go`) suppresses the stall line while this node is
*catching up*, and it is deliberately the **same selection `maybeCatchUp` pulls
on** — `tallestPeer()` returning a member above our committed head:

```go
func (v *Validator) stallSyncing(head uint64) bool {
	who, _, peerHeight := v.tallestPeer()
	return who != "" && peerHeight > head
}
```

`tallestPeer()` skips a member whose **every socket is demoted**, and a socket
is demoted only by `maybeCatchUp` after a pull that adopted nothing
(`demotePeer`, `peerDemoteWaves = 4` waves at `WaveEvery = 500 ms`). But the
`peers=` field in the line is built from fresh signed HELLOs **without** the
demotion filter (`stallQuorum`), which is why the line can print
`peers=2[… h=1, … h=1]` and still fire.

So the printed line is itself the proof that:

1. both members were fresh and above us (they are listed at h=1), and
2. **both members' paths were demoted at that moment** — i.e. `maybeCatchUp`
   had been pulling, and every pull within the last ≥ 4 waves had adopted
   nothing, repeatedly, long enough for a demotion to be in force on the one
   path each member had (the relay).

In other words the node was not sitting in a round ladder with no catch-up
route: it was **pulling and getting silence**, and the line then told the
operator a story about round divergence, which is a different fault with a
different fix. The "peer height is permanently one ahead" observation in the
report is not by itself causal either: the gap size is 1, the pull is not
gap-sensitive, and §4 shows a 1-height gap closing in seconds when the pull
works.

## 3. What `sync.go` is supposed to do (and does)

Catch-up is meant to cover this case, and says so in three places: the file
header ("A validator that fell behind could watch rounds happen but never adopt
the blocks it missed"), the M4 plan's design decision 8, and the README
("a validator that has fallen behind in *height* rather than in round still
catches up through BLOCK_SYNC"). The shipped path is:

- `broadcastHello` puts this node's signed height on every connection each
  wave; `recordHeight` keeps a member's **high-water** height, its `via` socket
  and every socket it was heard on, and expires entries after `peerHeightTTL`.
- `tallestPeer` picks the tallest fresh, **non-demoted** member, capped at one
  response window above the higher of our head and what a pull from it ever
  substantiated.
- `maybeCatchUp` (each wave) pulls `PullAndAdopt(head+1)` from that member, and
  on adoption rebuilds the driver over the new head.
- `PullAndAdopt` asks for `[head+1, head+win]` with a fresh nonce, registers the
  one request in flight, and files only a response from that peer whose nonce
  matches **and** whose envelope `verifySyncResp` re-signs to the selected
  member (needed on a relay, where every member shares `relay:<addr>`).
- Every unit must pass `verifyCertificate` (re-tally the carried precommits
  through the ordinary `VoteSet`, require quorum for **that** block at **that**
  height) before `chain.Append` sees it; `RecordCommit` files the certificate
  so the caught-up node can serve it onward.
- `Answer` refuses rather than truncating: bad auth, rate limit, replay,
  oversized range, range ahead of its head, a range below its pruning horizon,
  or — the one that matters here — **a height it holds no quorum-proving
  certificate for** (`ErrBadSyncCommit`).

Nothing in that path is height-gap-specific, and every refusal on both sides is
a **silent** drop on the wire by design ("Refusal has no negative wire shape").

## 4. Reproduction attempts, and their result

Three new tests (`internal/devnet/catchup_height_gap_test.go`) build the live
shape exactly — 3 seats, quorum 3 of 3 (so no block commits without all three),
one seat closed and restarted on a **fresh** directory at height 0 with both
peers parked at height 1 — and assert both halves the report asks for: block 1
is **adopted** from a peer (same block ID, same state root as the committee)
and the committee then **commits again** (height 2 needs all three seats, so a
passenger that syncs while voting at a stale height cannot pass).

| Test | Topology | Result |
|---|---|---|
| `TestAWipedValidatorOneHeightBehindCatchesUp` | direct full mesh over real TCP | PASS, 4.4 s |
| `TestAWipedValidatorOneHeightBehindThroughARelay` | every seat dials out to one relay (the live topology, `relay:` names, member-pinned answers) | PASS, 1.2 s |
| `TestAWipedValidatorCatchesUpAfterItsPeersRanTheLadder` | live **timing**: the wiped seat returns after its peers spent 30 s climbing the timeout ladder at height 2 (round ~21 at 200 ms base + 100 ms step, the same order as the live node's round 25) | PASS, 35.6 s (30 s is the deliberate wait) |

So in every shape a single-process harness can build, a node one height behind
adopts the committed block within one or two waves and re-enters consensus. The
harness cannot reproduce: SD-card stalls on a Pi, a relay on another continent,
a paced relay link (`RelayBytesPerSec`) carrying HELLO + pull + answer together,
or — the one that matters most — **an answer-side refusal, because its reason is
never logged** (see §5).

## 5. Where the silence is (the actionable finding)

For a pull that comes back empty, the requester can tell the operator nothing,
and the responder usually tells nobody either:

| Site | What happens on failure |
|---|---|
| `Syncer.Handle` | `Answer`'s error is swallowed: `if err != nil { return nil, false }` — no log, no negative frame |
| `Syncer.Receive` | a response that fails decode, sender, nonce, envelope or member pin is dropped silently |
| `Validator.maybeCatchUp` | on `err != nil` (transport refused) and on silence it only `demotePeer`s — **no log at all**, and on success it logs nothing either |
| `Syncer.sayPrunedRequest` | the **only** answer-side refusal that says anything, throttled to once per 10 min |
| `stallSyncing` | as §2 shows, the stall line's own suppression turns off exactly when pulls are failing, so the operator gets a line that describes the wrong fault |

The consequence is the one the plan itself calls unacceptable (§6: "a pruned
node either **serves** peers behind the horizon or **says plainly** that it
cannot — silence here would be the same class of defect as the relay gate's
silent refusal" — see `docs/bug-2026-11-14-relay-gate.md`). From the outside,
"the request never arrived", "the peer refused", and "the answer failed our
gate" are one observation: nothing.

## 6. Candidate designs and their risks

**A. Say what the pull did (recommended first).** One line per episode from
`maybeCatchUp`: the member, the range, and the outcome — adopted N blocks /
`PullAndAdopt`'s error / silence (no answer inside `ReplyWait`) — plus, on the
answer side (C), the refusal reason. Risk: log volume (bounded by an
episode latch, as `rebuildFailLogged` already does). It changes no decision and
is testable through the **existing** `Validator.pull` seam, which a test can set
to return an error or nil without touching consensus. This is the change that
would have named the live cause, and until it exists a second occurrence will be
just as blind.

**B. Retry the driver rebuild when the engine is behind the chain.** Found while
reading `maybeCatchUp`, and independent of the live cause: after a **successful**
adoption the node calls `rebuildDriver()`; if that fails it logs once and
returns. The next wave evaluates `peerH <= mine` — which is now TRUE, because
the adoption just reached the peer's attested height — and returns before any
retry. The comment's claim that "the next pull re-enters this branch" holds only
while a peer stays further ahead. A stuck engine then judges an already-committed
height forever, and with quorum == all seats that is a permanent halt. Risk:
small and node-local (`if v.drv.Height() < v.ch.Height() { rebuild }` in the
wave loop), but it is **not** the observed fault (that node's chain height was
0) and testing it needs a way to fail the rebuild, which does not exist yet.
Fix it on its own merits, not as this bug's remedy.

**C. Log answer-side refusals.** One throttled line in `Handle`/`Answer` for
`ErrBadSyncCommit`, `ErrRangeAhead`, `ErrRangePruned` (already), auth and rate
limits. Risk: an unauthenticated flood could spam the responder's log, so it
must be throttled per requester and emitted **after** the auth gate. Cheapest
way to separate "refused" from "lost", and it is the peer's log — which is the
only place the reason exists.

**D. A height-gap-specific consensus/liveness change** — peers re-proposing
their committed block for a lagging node, a HELLO-triggered block push, a pull
that starts from the *attested* height instead of `head+1`. **Do not.** Each
touches the live protocol, none is justified by evidence yet, and the observed
node's failure is consistent with a pull that was attempted and answered with
silence — which a protocol change would not fix. This is the class of change the
project has repeatedly learned to refuse without a reproduction.

## 7. What was done, and what should happen next

**Done:** no code change. The three tests above are committed as the pins for
this shape (the repo had no test with quorum == all seats and a wiped member),
and they pass, so the invariant "a node one height behind catches up" is now
executable rather than implied.

**Next:** implement A and C, then re-run the three-host scenario. The next
occurrence will then print the member, the range and the outcome, which decides
between the remaining candidates (peer has no certificate for that height /
authorisation or rate refusal / transport loss / answer failing our gate) and
only then justifies a protocol-adjacent fix. Until that evidence exists, the
honest status of this bug is *"the catch-up path is intended to cover it, works
in every reproduced shape, and failed silently in the field."*
