# Decisions: A-2 and the 2026-11-06 Info items

**Starting commit:** `48648b29cea8b4bbc4525e9251282b577022f952` ("test: pin the relay
refusal message to the per-prefix cap (testrun N-2)"), branch
`testrun-2026-11-06-fixes`.
**Findings:** Low **A-1** and **A-2**, and the whole **Info** section of
`docs/testrun-2026-11-06-main-10nodes-docker.md`.
**Nature:** most of these are verifications, not defects. This file records what
was checked and what was deliberately left alone, so the next reader does not
re-litigate it. The fixes themselves are in the code and in the README/ci.yml
diffs.

---

## A-2 · The Nakamoto "top share" truncates on purpose — left unchanged

`sharePercent` (`internal/devnet/nakamoto.go`) computes `100*power/total` with
`bits.Mul64`/`bits.Div64` and returns the quotient. Its comment says "truncated
to an integer", and a float is explicitly excluded because it would introduce
rounding into a power sum. The README's acceptance table is the same artefact:

- `1 of 6 (16%)` — 16.67 truncated;
- `1 of 9 (11%)` — 11.11 truncated;
- the ten-seat run prints `10%` then `11%`.

Rounding would print `17%` for 1/6 and would disagree with the README, with the
2026-11-06 acceptance table, and with every recorded run. **The report is right
that it is consistent with the README; it is wrong to imply it is a defect.**
Decision: no change. The truncation is the documented representation, and the
denominator is printed beside it (`1 of 6`) so a reader can see the fraction.

## Info · No committed fuzz corpus — the empty state is correct

`git ls-files` has no `testdata/fuzz` entry, and none should exist yet:

- **All nine targets already start from a valid frame.** Each calls `f.Add`
  in code with at least one well-formed encoding (plus truncated, empty,
  non-canonical and wrong-tag neighbours): `FuzzReadFrame`, `FuzzDecodeHello`,
  `FuzzDecodeBlockSyncReq`, `FuzzDecodeBlockSyncResp`,
  `FuzzDecodePeerExchange`, `FuzzDecodeVote`, `FuzzDecodeProposal`,
  `FuzzDecodeBlock`, `FuzzDecodeTx`. The Info item's premise — that a seed
  corpus is what stops them starting from random bytes — does not hold here.
- **The committed corpus is a REGRESSION record, not a starter.** A file under
  `testdata/fuzz/<Target>/<hash>` is how a run that found something keeps it;
  S-9's job says to commit a crasher's corpus. No target has crashed, so there
  is nothing to record.

Decision: commit no corpus. If a target ever finds an input, its `testdata`
entry is committed by that run (the fuzz step already prints where it lands).

## Info · `check-plan.sh` needs python3 — CI cannot be bitten; the *message* was wrong

Verified:

- **CI calls it one way only:** `.github/workflows/ci.yml` runs
  `./scripts/check-plan.sh --parity-only "$p"` for `docs/plans/*.md`, in the
  `lint` job on `ubuntu-latest`, which ships `python3`.
- **`--parity-only` does not remove the python3 dependency.** The fence half is
  `scripts/plan_parity.py` and runs in both modes; the flag only skips the SDD
  skill's brief extraction (which is not in this repository). The report's
  "full mode needs python3" is therefore imprecise: *both* modes do.
- **The old failure was not a correct refusal.** In the golang image, `python3`
  is missing, the parity call failed, and the script printed **"PLAN IS
  BROKEN"** and exited 1: a verdict about the plan produced by a missing tool —
  the exact false verdict S-19 exists to stop. It now names the interpreter and
  exits 2 ("cannot run"), verified with a `PATH` that has no `python3`.

## Info · The wallet CLI did not retry a 503 — fixed

`getJSON` (the one function every read path uses: `/status`, `/account`,
`/history`) now retries a 503 three times with a 50/100/200 ms backoff, then
reports the node's own sentence. Only GETs go through it — the signing verbs'
POST has `postTxHex` — and a GET is idempotent, so a spurious retry costs a
delay and nothing else. A non-503 status is still reported on the first answer
(no retry of a 404, and none of a 429, which a retry would make worse). The
semaphore itself is unchanged: R-1/S-8's thrift is the server's, the client's
job is to wait the node's own "retry shortly".

## Info · R-7 — the faucet page no longer claims a binding it does not own

The page said it was "bound to the node's loopback address". That is the
`--http` default, not a property of the handler; the node serves it from
whatever address the operator chose. The sentence now says the default is
`127.0.0.1`, that the choice is the operator's, and that `--http 0.0.0.0:8645`
serves the page (and `/tx`) to every network that can reach that port.

## Info · `scripts/deploy/build.sh` replaces `dist/` — documented both places

The wrapper's header already says "It wipes `dist/`, builds the pair …", and
`scripts/build-release.sh` says the same. The README's Pi section pointed at
the wrapper but not at that consequence; it now says a wrapper run replaces
`dist/` and that a full six-target release must be copied out first.

## Info · A ten-node chain started one at a time sits at height 0 for ~53 s — now documented

The observation is consistent with the documented rolling-start mechanism
(each member climbs rounds alone; when the last arrives the rounds are apart
and only the timeout ladder closes them), but the README carried no number for
a *first* start — only the 4–6.5 min rolling-*restart* figure. It now records
the measured ~53 s (rounds 16–34, 2026-11-06 run) with the advice to start the
members together or wait for the chain to advance.

## A-1 · The CI timing comments — the numbers were host-dependent, not stale

Re-measured on the 2026-11-06 fix host (12-CPU Apple Silicon, go1.27.3,
`GOMAXPROCS=2`, load ~3.9 during the measurements):

- the rotation demo: **8.3–8.4 s wall, 3.0–3.5 s user CPU** over three runs of
  the prebuilt binary; 9.2 s including `go run`'s link. The comment's "about
  8 s" is therefore **correct on a quiet host** — what was missing was the
  condition, since the same command measured 65–91 s on the loaded host at
  load 117.
- `go test -count=1 ./internal/devnet`: **60.8 s alone, 68.9 s in the full
  suite, 85.8 s in the full suite under `-race`** on this host, against the
  comment's 104 / 177 / 201 s on the 16-CPU Windows + Docker host. Again
  host-dependent, not stale.

Both comments now give the figure with its conditions and say the number
tracks the host, not the work.
