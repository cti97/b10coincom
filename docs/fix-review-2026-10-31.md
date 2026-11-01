# Fix review for the 2026-10-31 audit

| | |
|---|---|
| Branch | `audit-2026-10-31` at `be68d77`, six commits past `d4ec076` (the audit commit on `main`): `1d425ac`, `f18f456`, `1bf9074`, `a13578e`, `7aa53f1`, `be68d77`. 50 files, about 3,560 insertions. |
| Date | 2026-10-31 |
| Method | Static review of every changed file at this commit, by symbol. Go is not installed on the review machine; the only execution evidence is GitHub CI, which passed every job on every commit of the branch and on the PR run. Every claim below was re-read against the function as it exists at `be68d77`; the High and Medium verdicts were checked by hand before inclusion. |
| Audit under review | [`audit-2026-10-31-main.md`](audit-2026-10-31-main.md) |

---

## 1. Verdict

**The High is fixed. Two of the three Mediums are fixed. One Medium, A-2, is not: the new HELLO binding does not close the attack it was written to close, and its pinning test models the wrong attacker.** Of the 15 Low and 10 Info items, 20 are fixed or documented as recommended, and the remaining items are either accepted with a correct record or partial. The nine process gaps are untouched for a fifth report, and nothing in the new process note is enforced by repository configuration.

| ID | Audit severity | Status | One-line reason |
|---|---|---|---|
| A-1 | High | **Fixed** | `Chain.validateLocked` now checks the proposer through `seatedAtLocked` for the block's own height; `isValidator` is deleted; a block proposed by a post-genesis seat is appended by every validator in a new test. |
| A-2 | Medium | **Not fixed** | The HELLO now signs both socket challenges, but `exchangeNonce` reveals the local challenge before reading the peer's, so a member on both sockets can sequence the handshakes and still present one node's HELLO to another. |
| A-3 | Medium | **Fixed** | `Validator.recordHeight` is a high-water mark within the attestation TTL. |
| A-4 | Medium (accepted) | **Partial** | The capture cost is now stated beside the example file; the file itself still ships three seats at exactly the floor, and the tie-break is unchanged. |

**New issues introduced by the fixes:** one Low that matters operationally. The funded-first unbond order (C-1) changes the state transition for any bond that holds both a genesis grant and a top-up, so a chain that ran the previous order with such a bond diverges on replay with the corrupt-log message rather than a version message; no document names it as a fork. Everything else new is Low or Info.

---

## 2. The High: A-1

**Status: Fixed.**

`internal/chain/chain.go` `validateLocked` now runs, after the parent link, height and structure checks, `seatedAtLocked(b.Header.Height, b.Header.Proposer)`, which reads the memoised committee for the block's epoch under the lock already held. `isValidator` no longer exists. `Chain.Open` records the epoch-0 committee from the genesis state and additionally calls `memoCommitteeLocked` for height 0, which covers the one-block-epoch edge where epoch 1 is decided by the genesis state itself. Replay through `applyValidatedLocked` applies no proposer rule, as before and as documented (the local disk is the trust boundary); what matters is that it calls the same `memoCommitteeLocked` at every deciding height, so after `Open` every epoch up to head+1 is memoised before a new `Append` asks. `Build` is unchanged and still checks nothing; it only runs when `Engine.IsProposer` drew the key from the epoch committee, and every block it produces still passes `validateLocked` in `Append` and `ValidateNext`.

Pinned by `internal/chain/postgenesis_proposer_test.go`: `TestAPostGenesisSeatProposesAndEveryValidatorAppends` (uses the production `Config.Proposer` draw), `TestACommitteeWithNoGenesisSeatsStillAppends`, `TestTheGenesisCommitteeIsTheEpochZeroCommittee`, `TestAOneBlockEpochChainAppendsItsFirstBlock`, `TestAProposerFromAnotherEpochIsRefused`; and by `internal/devnet/rotation_in_test.go` `TestARotatedInValidatorStartsAndIsCounted`, which now waits for a committed block whose header names the joiner, the observable the old test lacked.

Safety: `validateLocked` refuses strictly more than before at post-genesis heights and exactly the same set at epoch 0. No path lets a non-member's block be appended.

Still missing: a chain-level test that appends a post-genesis-proposed block, closes and reopens the directory, and appends again; and a test that a failing epoch-0 derivation (for example a power sum overflowing) is reported rather than silently refusing every block, which is the one new edge: with the old scan such a genesis still accepted blocks on the single-node path, and now it does not.

---

## 3. The Mediums

### A-2 · Not fixed · HELLO identity misbinding by a member

**What changed.** `wire.Hello.Nonce` now carries `HelloBinding(sender's challenge, receiver's challenge)`, 64 bytes. `tcp.exchangeNonce` generates a local 32-byte challenge, writes it, then reads the peer's under the handshake timeout, and stores `conn.helloBinding`. `tcp.PeerChallenges` emits the binding the node must sign for each connection; `tcp.reader` demands it on admission; `Validator.observeHello` recomputes it from `ConnNonces`. `helloHash` signs chain ID, key, height and this binding.

**Why it does not close the attack.** The binding ties a HELLO to the two challenges of a socket, but nothing ties it to the identities at either end, and `exchangeNonce` writes the local challenge before reading the remote one. A counterparty on both sockets can therefore order the handshakes:

1. Member M opens a socket to honest A. A writes its challenge `aL` and waits up to the handshake timeout for M's.
2. M opens a socket to honest B. B writes `bL`. M replies with `aL` as its own challenge. B's expected binding is now `HelloBinding(aL, bL)`.
3. M sends `bL` to A as its challenge. A's binding for that socket is `HelloBinding(aL, bL)`.
4. A's `broadcastHello` signs over `aL ‖ bL`. M forwards the frame to B. B's `admitHello` sees a matching binding, a member key and a valid signature, admits M's socket as A, and `observeHello` records A's `via` as M's socket. B's catch-up pulls for A go to M, which answers nothing, and A is repeatedly demoted at B.

The new test `internal/devnet/hello_binding_test.go` `TestAMemberCannotBindAnotherMembersHelloToItsOwnSocket` passes only because its attacker commits a constant challenge to B (`dialRawPeer` with the fixed `0x5a` bytes) before it has seen A's challenge (`acceptRawPeer` runs second). Reversing those two steps reproduces the attack against the current code. The doc comments on `wire.HelloBinding`, `tcp.exchangeNonce` and the `admitHello` closure now assert a property the code does not have.

On the relay link the situation is unchanged and documented: `ConnNonces` returns nothing, the binding is empty, and any party can present any member's genuine HELLO; `recordHeight` only limits that to "cannot lower".

**Fix.** Commit-then-reveal in `exchangeNonce`: each side sends a hash of its challenge first and reveals only after receiving the peer's commitment, so the attacker must commit `aL` to B before learning it and `bL` to A before learning it, which is circular. Stronger: a key-authenticated handshake where each side signs both challenges and both validator keys before any HELLO is accepted. The audit's original suggestion, one admitted connection per validator key, would also stop the pull redirection; the commit message rejected it, and that decision should be revisited together with the handshake fix. Test: the attacker order above, which fails today.

### A-3 · Fixed · Relay replay lowering a recorded height

`Validator.recordHeight` creates a new entry on first sight and otherwise updates height and `via` only when the new height is at least the stored one; `seen` is refreshed either way; the entry is pruned after `peerHeightTTL` waves of silence from that key. A member that legitimately resyncs from scratch can lower its height only after that silence, and if an attacker keeps replaying its old high HELLO over the relay the cost is a periodic wasted pull window followed by a demotion, bounded and not a freeze.

Residual, documented in `recordHeight`: an equal height from the relay moves `via` to the relay, so a replay of a member's current HELLO still steals the catch-up source. A direct nonce-bound attestation does not yet outrank a relay one.

Pinned by `internal/devnet/hello_height_test.go` `TestAReplayedLowHelloOverTheRelayCannotLowerTheRecordedHeight` and `TestAHighWaterHeightCannotCaptureTheCatchUpSource`.

### A-4 · Partial · Capture cost on the shipped recipe

`scripts/deploy/README.md` section 3.2 now carries a callout under the sample file stating what that file costs to capture and recommending genesis powers ten times the floor. `scripts/deploy/committee.example.json` still ships three seats at exactly `MinStakeSparks` with `committee_size` 4, its `note` does not mention the cost, and `TestTheShippedExampleCommitteeFileIsLoadable` does not enforce the README's own advice. `compareCandidates` is unchanged; its comment argues the address alternative is equally grindable and that a bond-height tie-break would be a protocol change. Accepted risk, correctly labelled, but the file operators copy is still the capturable shape.

---

## 4. Low and Info items

### 4.1 Consensus and rotation

| ID | Status | Symbol | Test |
|---|---|---|---|
| B-1 stale driver on a rotated-out post-genesis node | **Fixed** | `consensus.NewDriver` admits a key that is seated, in the genesis list, or `Chain.EverSeated`; `Validator.maybeCatchUp` counts adoption before the rebuild and no longer demotes the peer on a rebuild failure | `rotation_out_driver_test.go` `TestARotatedOutPostGenesisNodeRebuildsItsDriver` |
| B-2 out-of-seat restart | Accepted, documented | `StartValidator` still refuses a key neither in genesis nor seated at head+1; the docs commit states this is deliberate and distinct from B-1 | none; the refusal of an ever-seated-but-unseated key has no pinning test |
| B-3 proposer draw before dedup | **Fixed** | `Engine.bufferProposal` checks `pending` before `cfg.Proposer` | `TestADuplicateEarlyProposalCostsNoProposerDraw` |
| B-4 stall quorum genesis fallback | **Fixed** | `Validator.stallQuorum` returns an error; `stallUndeducibleLine` prints no quorum | `TestAStallOnAnUnderivableCommitteeDoesNotPrintAQuorum` |
| B-5 4-seat 3-live divergence | Coverage added | `internal/simnet/round_divergence_test.go` `TestARoundDivergenceAmongExactlyQuorumLiveSeatsCloses` for 4, 5 and 6 seats; no code change needed | constructed state (one live seat written ahead through `Chain.PutRound`, drivers rebuilt), not a reproduction of the Docker rolling restart; it does not observe that the jump rule stayed silent |

An inert engine admitted through `EverSeated` cannot sign (`Engine.emitVote` runs `CheckMembership` first) and cannot be drawn (`Engine.IsProposer` draws from the epoch committee only). It can still persist a lock on a foreign polka, as a rotated-out genesis seat already could; `Chain.Append` prunes it on commit. The remaining rebuild-failure case (committee at head+1 underivable) keeps the stale engine ticking and emitting nil prevotes for an old height until the next successful rebuild, silently; harmless, but unlogged.

### 4.2 Staking, CLI, RPC

| ID | Status | Symbol | Test |
|---|---|---|---|
| C-1 unfunded-first burn | **Fixed, with a new issue** | `applyUnbond`: `fundedOut = min(tx.Amount, Amount − Unfunded)`, `unfundedOut` is the rest; records receive only `fundedOut`; `Unfunded ≤ Amount` preserved; CLI `splitUnbondExit`, `unbondEffect`, `releaseForecast` | `TestAFundedTopUpOnAGenesisSeatStaysWithdrawable` (rewritten, expectation flipped), `TestAUnbondForecastFollowsTheFundedFirstSplit` |
| C-2 no upgrade path for `Unfunded` | **Fixed** (message and docs) | `Chain.Open`'s height-1 parent-link branch now names a different build, ST-3 and `Bond.Unfunded` and tells the operator to start a fresh directory; deploy README section 6 callout | `TestAPreFixDataDirectoryFailsWithAVersionMessage` |
| C-3 immature withdraw, sub-floor unbond at admission | **Fixed** | `mempool.admitStake`: unbond remainder mirror; withdraw requires `state.HasMatureUnbonding(from, headHeight+1)`, with state and height from one `AdmissionHead` snapshot | `TestAnUnmaturedRecordCannotParkAFeeFreeWithdrawFlood`, `TestAnUnbondThatWouldLeaveASubFloorRemainderIsRefusedAtAdmission` |
| C-4 derivation has no floor | Decision documented | `Committee` doc block states the floor lives in the writers | `TestTheDerivationSeatsAnyPositiveBondAndTheWritersRefuseASubFloorOne` |
| C-5 caveats | Docs | `nakamoto.go` header, `rpc.unbondingResponse` doc, `TotalBonded` doc | — |
| E-1 terminal detection | **Fixed** | `stdinIsTerminal` is a pure `os.ModeCharDevice` test; the `SameFile` comparison is gone; `askConfirmation` refuses an empty read | `TestStdinIsTerminalUsesThePortableCharDeviceTest`, `TestRealAskConfirmationRefusesEveryNonTerminal`; the positive console path is untested |
| E-2 refusal quotes the hostile fee as a flag | **Fixed** | `stakingTarget.submit` quotes the operator's own `--max-fee` and says not to copy the node's number | `TestHostileNodeFeeIsRefused` |
| E-3 two-validator pass | **Fixed** | `acceptance.sh` `--partial`; fewer than three hosts without it exits 64 before probing; a two-validator pass is exit 6 `PARTIAL PASS`; exit 0 only with three or more; STALLED, DISAGREE, RELAY, UNREACHABLE, INCONCLUSIVE unchanged | none (shellcheck only) |
| E-4 misc | **Fixed** | `--yes --dry-run` documented; README `claim` table lists `--print-key`; recipe examples drop `--yes`; `ParseCommitteeJSON` uses `DisallowUnknownFields` | `TestCommitteeFileRefusesAMisspelledField`; the example file still loads |

### 4.3 Networking

| ID | Status | Symbol | Test |
|---|---|---|---|
| D-1 gate-trio spoof | **Fixed** | `wire.RelayGateConfirmation`: the relay answers with an HMAC over challenge and proof; `adoptRelay` recomputes it before `install` | `TestATokenlessRelayForwardsNoProofOfTheToken` now also asserts no peer is installed; `TestTheNodeGateHandshakeCompletesAgainstAGatingRelay` |
| D-2 stale gate docs | **Fixed** | both binaries' help and flag strings, `relay.Options.AccessToken`, `ValidatorConfig.RelayAccessToken`, deploy README section 4.1 | — |
| D-3 expire/re-learn race | **Fixed** | `expireUnprovenHints` deletes and calls `peerRemove` under `hints.mu` | `TestTheEvictionAndTheLearnPathShareOneLock` |
| D-4 proven slots never released | **Fixed** | `hintProvenLifetimeWaves`, `learnedHint.lastProven`, `markHintProven`, `peerConnectedAt` | `TestAProvenAddressIsRetiredOnceItsPeerIsGone`, `TestALiveProvenPeerIsNotRetiredEvenWhenItsHelloStops` |
| D-5 bundle | Partial | failed gate write no longer counted as unauthorised; the handshake hold time was re-measured and documented; hint replay is unchanged in code and not stated in the README | `TestAFailedGateWriteIsNotCountedAsUnauthorized` |

### 4.4 CI, tests, docs, process

| ID | Status | Artifact |
|---|---|---|
| F-1 timeout arithmetic | **Fixed** | `ci.yml` job `test`: `-timeout 120m` on both steps; the comment's three figures (6,527 s of multiplied literals, 6,707 s with the three bare `time.Minute` arguments, 5,927 s seconds-only) match an independent recount at this commit |
| F-2 reporter never fired | Partial | `workflow_dispatch` input `simulate_failure` and a matching step and `report` condition were added; the rehearsal has never been run, and no scheduled run has happened since the release fix |
| F-3 flakes and reaper margin | Partial | `TestAGateProofIsNotReplayableOnAnotherConnection` now waits for the relay's connection count before judging, a plausible diagnosis of one `-race` flake that cannot be confirmed without logs; `TestTheReaperDoesNotBlameAReceiverForASendersBacklog` is byte-identical, its 150 ms margin unchanged |
| F-4 reproducibility, signing, benchmarks | Honestly recorded | README now says CI builds once and compares nothing and every checksum file is unsigned; the two benchmarks run in CI with `-benchtime=100x` but gate nothing; signing has still never been executed |
| F-5 review path | Recorded only | `docs/process-2026-10-31.md` documents the self-merged PRs and the mislabeled commit; it commits to nothing going forward; `main` has no branch protection, no rulesets, no required checks, no `CODEOWNERS` |
| F-6 stale docs | **Fixed, all eight** | M4 plan correction for the tag renumbering; M3 plan DD4 marked superseded by DD11; M4 plan Task 4 signature; `pow.go` package doc; `chain_lock_test.go` renamed to `chain_precommit_lock_test.go`; `docs/plans/README.md` created; `MessageRouter.OnPeerExchange` doc; `peerexchange_sign_test.go` header |
| Process gaps (nine) | **Not fixed** | no coverage in CI; no fuzz step or corpora; `t.Skip` still in `TestARebuiltDriverDoesNotBurnRoundZeroOnARunningClock`; eight ignored `Open` errors in `store_test.go`; `Sscanf` stall parsing; no build tag on the subprocess CLI tests; no `CONTRIBUTING.md`; no `CODEOWNERS`; no signing step in the release job |

---

## 5. New issues introduced by the fixes

| Sev | ID | Finding | Fix |
|---|---|---|---|
| Low (Medium if any chain ran the old order with a topped-up seat) | N-1 | **C-1 is a consensus-rule change with no fork marker.** `applyUnbond` now yields a different post-state for any exit from a bond holding both a grant and a top-up. A chain that ran `d4ec076` with such a bond diverges on replay at that block with `ErrGenesisReplay`'s "replay diverged from stored state root", the corrupt-log message, not the C-2 version message, which fires only at height 1. A mixed-build committee forks at the first such unbond. README says "only the order changed"; the hard-fork callout names ST-3 only; the process note does not mention it. The fixtures cannot see it because their genesis seats are pure grants. | Add C-1 to the ST-3 hard-fork callout, or state that no chain with a topped-up seat ran the old order. |
| Low | N-2 | **The A-2 fix leaves false comments and a mis-ordered test** (section 3). The confidence regression matters more than the code: `wire.HelloBinding`, `tcp.exchangeNonce`, the `admitHello` closure and `broadcastHello` now claim a property the handshake does not provide. | Commit-then-reveal or a key-authenticated handshake; rewrite the test with the real attacker order. |
| Low | N-3 | **Silent vintage split on the HELLO binding width.** The old 32-byte binding never equals the new 64-byte one, so a node on either side of `f18f456` never admits the other on a gated socket and never records it as a catch-up source. The only observable is `TcpTransport.GatedFrames`; no log line, no version field in `wire.Hello`. Same for the relay gate: an old node and a new relay fail closed and loud, which the README states, but the HELLO split is silent. | Log a gated HELLO with a mismatched binding length once per connection; consider a version byte in `Hello`. |
| Low | N-4 | **`admitStake`'s unbond mirror refuses a legitimate pipelined exit.** The remainder is judged against the head bond, so two unbonds submitted back to back where the second is a full exit after the first are refused at admission although legal once the first applies. The CLI cannot produce this; a hand-built pipeline can. Resubmitting next block works. | Judge the remainder against bonded minus pending unbonds for the sender, or document the one-per-block limit. |
| Low | N-5 | **Epoch-0 derivation failure now refuses every block.** A genesis with four or more validators whose powers overflow the sum makes `applyPowerCap` fail, `committees[0]` is absent, and `validateLocked` refuses every block at epoch 0 where the old scan accepted. Consensus already could not run on such a genesis; only the single-node producer is newly affected. | Bound the power sum in `genesis.Validate`. |
| Info | N-6 | **D-4 retires a live peer whose own inbound dial won.** `markHintProven` and `peerConnectedAt` match on the connection's address, which is the ephemeral remote address when the peer's dial won `newcomerWins`, so the learned entry is retired after `hintProvenLifetimeWaves` and re-learned on the next advertisement. Benign churn; contradicts "cannot evict a live peer" and inflates `PeerHintsEvicted`. | Match on the peer's admitted key rather than the address. |
| Info | N-7 | **One documented flag does not exist.** Deploy README section 4.1 says a silent dialer is closed after `--access-timeout` seconds; `cmd/b10coin-relay` defines no such flag (`relay.Options.AccessTimeout` defaults to the constant and is not operator-settable). | Drop the flag reference or add the flag. |
| Info | N-8 | **Unverifiable measurements stated as fact** in the deploy README ("measured at 5.0 s on the audit host") and the CI comment ("1.4 s"); no artifact in the tree backs them. The remaining rebuild-failure path in `maybeCatchUp` keeps a stale engine ticking with no log line. `TestATokenlessRelayForwardsNoProofOfTheToken` has one synchronous negative assertion that can pass trivially before its real poll. | — |

No new unauthenticated path, unbounded table, verify-before-membership regression, goroutine leak, lock-order inversion or malformed-frame panic was found. `seatedAtLocked` was split from `IsSeatedAt` precisely to avoid re-entering the chain's read lock under `Append`'s write lock, and the callers are consistent. `NewDriver`'s key assertion now uses the two-value form and no longer panics on a malformed key.

---

## 6. Tests that would fail today

1. The real A-2 attacker: M learns A's challenge first, dials B presenting it, then sends B's challenge to A, and forwards A's HELLO to B; B must not admit M's socket as A or record A `via` it.
2. A replayed current-height member HELLO over the relay must not move `via` off a nonce-bound direct connection (A-3 residual).
3. A chain that applied an unbond under the old burn order and is reopened under the new one yields a readable fork message, not the corrupt-log message (N-1).
4. A pipelined exit of two unbonds where the second is a full exit is admitted (N-4), or the limit is pinned.
5. A genesis whose epoch-0 derivation fails is reported at `Open` rather than refusing every block (N-5).
6. Mixed C-1 exit where both `unfundedOut` and the remainder are positive, asserting `Unfunded ≤ Amount` afterwards and total recorded equals the funded total.
7. The C-3 withdraw boundary at exactly `ReleaseHeight == headHeight + 1`.
8. A post-genesis-proposed block survives close, reopen and a further append (A-1 replay path).
9. An ever-seated-but-unseated key is refused at `StartValidator` (B-2 is documented but unpinned).
10. The HELLO binding vintage mismatch is observable (N-3).

---

## 7. What to do next, in order

1. **A-2**: commit-then-reveal in `exchangeNonce` or a key-authenticated handshake; rewrite `TestAMemberCannotBindAnotherMembersHelloToItsOwnSocket` with the attacker order in section 3; revisit one-admitted-connection-per-key. Until then the Medium stays open and the comments claiming otherwise should be softened.
2. **N-1**: name the C-1 fork in the ST-3 callout and the process note.
3. **A-4**: change the example file's powers to the recommended multiple of the floor, or make `TestTheShippedExampleCommitteeFileIsLoadable` enforce the README's advice.
4. **N-3, N-7**: a log line for the HELLO vintage split; remove the nonexistent flag from the deploy README.
5. Run the `workflow_dispatch` rehearsal of the `report` job before the next cron, and confirm the 2026-11-03 scheduled run passes `release` on `main`.
6. The nine process gaps and, at minimum, branch protection with required checks on `main`, which the process note records as absent.
