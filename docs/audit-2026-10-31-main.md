# b10coin audit: `main` after the M5 fixes

| | |
|---|---|
| Tree | branch `main`, HEAD `35f7d47` (merge of PR 18). 35 commits past the M5 audit tree `614d3c4`; 75 files, about 12,000 insertions. About 67,500 lines of Go. |
| Date | 2026-10-31 |
| Method | Static review of every file the 35 commits touched plus the surrounding packages, the plan, README, deploy recipe, CI configuration, CI run history via `gh`, and the two Docker test-run reports. Go is not installed on the review machine; nothing was executed here. Execution evidence is GitHub CI at HEAD and the Docker reports at earlier commits, both cited where they apply. |
| Citation rule | Findings cite the file and the function, type, constant, flag or test by name, never a line number. Every claim was re-read against the function as it exists at this commit. Where this report contradicts a previous one, it says so. |
| Prior reports | [`audit-2026-10-04.md`](audit-2026-10-04.md), [`audit-2026-10-06-fix-verification.md`](audit-2026-10-06-fix-verification.md), [`ci-fix-2026-10-09-govulncheck.md`](ci-fix-2026-10-09-govulncheck.md), [`audit-2026-10-30-m5.md`](audit-2026-10-30-m5.md). |

---

## 1. Verdict

**The M5 fix campaign closed all five High findings and nearly every Medium and Low from the 2026-10-30 report, with tests behind them.** The unbond floor, the unfunded genesis bonds, the committee-file power floor with spare seats, rotation-in at the node entry point, signed peer hints, the HMAC relay gate, dedup before verification, gated learned dials with nonce-bound HELLOs, the sync authorisation union, epoch-aligned unbonding records, the bounded `/account` reply, the staking fee ceiling with preview and confirmation, the release-script fix on `main`, and the scheduled-failure reporter for every job are all present and pinned. Commit safety is intact: nothing in the fixes lets two blocks commit at one height or bypasses a lock.

**One High remains, and it is a correction to the previous report.** The M5 audit's appendix said every reader takes the committee for the block's own height from the memoised source. That was wrong for one reader: `Chain.validateLocked` still checks a block's proposer against the genesis list through `Chain.isValidator`. Now that a post-genesis validator can start a node (RT-1 fixed), it is drawn as proposer from the epoch committee, builds a block, and every validator including itself nil-prevotes it, while `Chain.Append` refuses it. Every round such a validator is drawn is burned; a committee whose genesis seats have all exited can never append another block, and catch-up cannot repair it because `Syncer.PullAndAdopt` ends in the same `Append`. The rotation-in test only checks that the joiner's precommit appears in a certificate, which passes while all of its proposals are refused.

| Sev | ID | Finding |
|---|---|---|
| **High** | A-1 | Block validation checks the proposer against the genesis list, not the epoch committee; a post-genesis seat's proposals are refused by everyone. |
| Medium | A-2 | A committee member can misbind a HELLO: the HELLO signature covers a nonce the peer chose but not the socket or announced identity, so a member can present another member's nonce-bound HELLO on its own socket and be recorded as that member. |
| Medium | A-3 | Over the relay, HELLOs carry no nonce and `Validator.recordHeight` overwrites rather than keeps a high-water mark, so a replayed low-height HELLO keeps a lagging node from ever selecting a catch-up source. |
| Medium | A-4 | On the shipped three-seat recipe, committee capture costs three `MIN_STAKE` bonds plus a few key-generation attempts; the README states the general consequence but not this number for the file it tells operators to copy. |

Counts of enumerated findings: **Critical 0, High 1, Medium 3, Low 15, Info 10.** Of the 45 items from the M5 report, 35 are fixed, 7 accepted with documentation, 3 partial, none unaddressed. The older residuals and the nine process gaps that have now appeared in four reports are all still open.

---

## 2. High finding

### A-1 · High (liveness) · Proposer membership is checked against genesis, not the epoch committee

**Where.** `internal/chain/chain.go`: `validateLocked` calls `isValidator`, which scans `c.gen.Validators`. `Build` performs no membership check. `internal/consensus/committee.go` `Config.Proposer` draws from the per-height committee that `Driver.configFor` obtains through `Chain.CommitteeAt`. `internal/consensus/engine.go` `maybePrevote` nil-prevotes when the `validate` seam fails. `Chain.ValidateConsensusNext` and `Chain.Append` both go through `validateLocked`.

**What happens.** A key that bonds after genesis and is seated at the next boundary now starts (`devnet.StartValidator` admits it through `Chain.CommitteeAt`, RT-1 fixed). When the draw lands on it, `Driver.build` produces a block, the engine broadcasts the proposal, and every validator's pre-vote seam refuses the block with `ErrNotValidator` before any lock or justification check. That round times out. If every genesis seat has exited, which `applyUnbond` permits in full, no block can ever be appended again, and a pull cannot repair it.

**Why the tests pass.** `internal/devnet/rotation_in_test.go` `TestARotatedInValidatorStartsAndIsCounted` asserts the joiner's precommit appears in a certificate; it never asserts a block the joiner proposed was committed. `internal/chain/chain_test.go` pins `ErrNotValidator` for a stranger proposer but has no test for a post-genesis seated proposer being accepted.

**Fix.** `validateLocked` should check `b.Header.Proposer` against the committee for `b.Header.Height` through the existing non-copying `Chain.IsSeatedAt`, falling back to genesis only for epoch 0. Add a test that commits a block proposed by a post-genesis seat, and one in which every genesis seat has exited and the chain still advances.

**Correction.** The M5 report's appendix claim about "every reader" was wrong for `validateLocked`; the function was never changed in M5 and the earlier report did not re-read it.

---

## 3. Medium findings

### A-2 · Medium · HELLO identity misbinding by a committee member

**Where.** `internal/devnet/tcpnode.go` `helloHash` covers chain ID, validator key, height and nonce. `internal/transport/tcp/tcp.go` `exchangeNonce` sends the local nonce in the clear. `StartValidator`'s `admitHello` closure and `Validator.observeHello` check nonce equality, membership and signature, but nothing binds the signed frame to the socket's announced transport ID or to the key the receiver handshook with.

**Scenario.** Member M dials honest B and receives B's nonce. M then opens a link to honest A and, as its own nonce on that link, sends B's nonce. A's `Validator.broadcastHello` signs a HELLO over that nonce every wave; M forwards it to B. B admits M's socket as a peer carrying A's identity and `recordHeight` sets A's `via` to M's socket. B's catch-up pulls for A now go to M, which answers nothing, so A is repeatedly demoted and is never a usable sync source at B. If M announced A's transport name first, `install`'s incumbent rule holds A's own dial off that name. Safety is unaffected: the router and certificate gate re-check per height. It requires a seated key, so it is a malicious-member liveness and mesh attack.

**Fix.** One admitted connection per validator key: `admitHello` refuses a HELLO whose key already owns an admitted, nonce-bound connection, and `observeHello` does not move `via` away from such a connection. That also removes the broadcast amplification a single member gets by admitting many sockets under its own key. Test: a forwarded member HELLO on a third node's inbound socket.

### A-3 · Medium · Relay HELLO replay lowers a member's recorded height

**Where.** `internal/transport/tcp/tcp.go` `ConnNonces` returns nothing for relay links, so HELLOs over the relay carry an empty nonce. `internal/devnet/tcpnode.go` `observeHello` accepts them, and `recordHeight` assigns `st.height = height` rather than taking the maximum. `Validator.tallestPeer` selects a pull source by that height.

**Scenario.** A stranger on a token-less relay, or any token holder, replays each member's old low-height HELLO at the relay byte budget. Every member's recorded height stays at or below the lagging node's own head, `tallestPeer` never selects anyone, and the node never catches up, even if it also holds direct links, because the entry is keyed by member and the relay replay overwrites it. The comment on `TcpTransport.PeerChallenges` says a relay replay "changes no decision except refreshing its height"; it changes catch-up selection.

**Fix.** Keep the per-member height as a high-water mark within `peerHeightTTL`, or prefer a nonce-bound direct attestation over a relay one. Test: a replayed low-height HELLO over the relay must not displace a higher attestation.

### A-4 · Medium (accepted risk, made concrete) · Capture cost on the shipped recipe

**Where.** `scripts/deploy/committee.example.json` seats three keys at exactly `MinStakeSparks` with `committee_size` 4. `internal/state/stake.go` `compareCandidates` orders equal stakes by raw key bytes. `applyPowerCap` gives four seats a quarter each.

**Scenario.** An attacker bonds exactly `MIN_STAKE` on three keys, grinding each key a few times so it sorts ahead of the genesis keys. `Committee` seats the three attacker keys plus one genesis seat; the attacker holds three quarters and commits alone. README's own funding arithmetic puts one `MIN_STAKE` at about 71 minutes of faucet farming with a custom client, so about 3,000 b10 and a few hours end to end. README states "a handful of floor seats is the cheapest route to a supermajority" and the plan accepts the tie-break grind. Neither states this number against the example file.

**Fix.** State it next to the example file, and recommend genesis powers well above the floor so a floor bond cannot tie. A tie-break on something the attacker cannot grind for free, such as bond height, would remove the grind.

---

## 4. Low and informational findings

### 4.1 Consensus and rotation

- **B-1 · Low** A rotated-out post-genesis node keeps a stale driver. `internal/devnet/tcpnode.go` `Validator.maybeCatchUp` calls `rebuildDriver`, `consensus.NewDriver` refuses the unseated key, and the branch commented as unreachable runs: it demotes the honest peer and leaves `v.drv` judging the pre-pull head. The header of `rotation_out_rt3_test.go` describes a halted driver; the code path is repeated failed rebuilds until re-seated. Let `NewDriver` admit an ever-seated key with an inert engine, or skip the rebuild when unseated at head+1.
- **B-2 · Low** A rotated-out post-genesis node cannot be restarted until re-seated: `StartValidator` checks genesis then `CommitteeAt(head+1)` only. Documented as deliberate; the operational consequence is that a crash during out-of-seat epochs is a permanent exit until re-seating plus a resync.
- **B-3 · Info** `Engine.bufferProposal` computes `Config.Proposer` per early frame before engine-level dedup; bounded by the router's existing `Dedup.Has`.
- **B-4 · Info** `internal/devnet/stall.go` `stallQuorum` falls back to the genesis committee when `CommitteeAt` errors, so on a chain whose next epoch cannot be derived the stall line reports quorum against the wrong set while `Driver.HaltError` is the real signal.
- **B-5 · Info** The 4-seat, 3-live rolling-restart stall is a different mechanism from the 3-seat one that `5af2174` fixed: round divergence among exactly-quorum live seats, closed only by the `Driver.Tick` ladder. The Docker re-run report says so; no networked test covers 4 to 6 seats with one restarted seat.

### 4.2 Staking

- **C-1 · Low** `applyUnbond` burns the unfunded genesis portion first (`unfundedOut = min(tx.Amount, bond.Unfunded)`), so a genesis operator who topped up with its own coins cannot recover any of them without burning the grant; `TestAFundedTopUpOnAGenesisSeatStaysWithdrawable` pins that ordering. README's "released like any other after one cooldown" is untrue for a partial exit, and the CLI `unstake` effect text says the seat is gone even when the remainder keeps it. Flip to funded-first, or document the order and make the effect text conditional.
- **C-2 · Low** No upgrade path for the `Unfunded` leaf: `bondLeaf` now commits it, so the genesis root changed while `Genesis.Hash` did not; opening a pre-fix data directory passes `store.CheckGenesis` and then fails at height 1 with `ErrGenesisReplay`'s "does not link its predecessor", the message for a corrupt log. Deliberate hard fork; name it in the deploy README.
- **C-3 · Low** `mempool.admitStake` admits a `Withdraw` on any unbonding record, mature or not, and an `Unbond` that would leave a sub-floor remainder; with future nonces admitted up to the per-sender cap, one address holding an unmatured record can park 64 fee-free withdraws that all fail in `SelectApplicable`. The flood now costs `MIN_STAKE` per address instead of nothing; two single lookups close it.
- **C-4 · Info** `Committee` still seats every bond with positive amount; the floor rests on `applyBond`, `applyUnbond` and `ParseCommitteeJSON`, not on the derivation. `Genesis.Validate` accepts any positive power; only the loader enforces the floor. Fixture committees (`genesis.Devnet`, `simnet.Committee`) still seat one-spark seats by design.
- **C-5 · Info** `mergeUnbonding` rewrites matured records to the earliest release height, so `/account.unbonding` no longer shows per-epoch history; `TotalBonded` and `TotalUnbonding` use unchecked adds (test-only consumers). ST-2's count-weighting caveat sits in README's staking section but not beside the quick-start Nakamoto table or in `nakamoto.go`'s header.

### 4.3 Networking

- **D-1 · Low** Gate-trio spoof on an ungated relay: `TcpTransport.adoptRelay` reads greeting, challenge and accepted as bytes, so a stranger on a token-less relay looping the three frames makes a token-configured node install the link as gated. No secret leaves (the answer is an HMAC), but the operator's "only a gated relay" intent is silently defeated. Acknowledged in `adoptRelay`'s comment; not in the deploy README.
- **D-2 · Low** Operator-facing text contradicts the HMAC gate: `cmd/b10coin-relay/main.go` `helpText` and the `--access-token-file` flag string say "send exactly the token bytes" and "PLAINTEXT, REPLAYABLE"; `cmd/b10coin/main.go` `--relay-access-token-file` says "plaintext over TCP and replayable"; `relay.Options.AccessToken` and `devnet.ValidatorConfig.RelayAccessToken` docs and deploy README section 4.1 describe the old three-frame scheme. `wire.RelayGateProof` and the root README are correct.
- **D-3 · Low** `Validator.expireUnprovenHints` deletes the learned entry, releases the lock, then calls `peerRemove`; a concurrent re-learn of the same address between the two finds the old registration and is then removed with it, leaving an entry with no maintainer until the next grace expiry. Self-healing; reorder the two steps.
- **D-4 · Low** `markHintProven` sets `proven` forever and `expireUnprovenHints` skips proven entries, so a member that rotates out, moves or dies keeps one of the 32 learned slots and a maintainer redialling at the backoff ceiling for the process life.
- **D-5 · Info** Peer-hint replay is unbounded (the signature covers chain ID, height and addresses, not a nonce or wave); impact is one redial of a stale address per grace period. `Relay.handshake` now holds a non-reading dialer's slot for about 95 seconds before release. A failed greeting write is counted as `Unauthorized`. `observePeerExchange` runs one Ed25519 verify per frame from any ever-seated key before the per-wave window; a gated inbound socket costs one verify per HELLO-shaped frame since the dialer knows the nonce.

### 4.4 CLI, RPC and node

- **E-1 · Low (not executed)** `cmd/b10coin/main.go` `stdinIsTerminal` returns false when `os.SameFile` matches `os.DevNull`. Reading Go's Windows `os` implementation, a console handle and `NUL` both stat with zero volume and index, so on Windows every `stake`, `unstake` and `withdraw` without `--yes` is likely refused as non-interactive. Fails closed. No test exercises the real `askConfirmation`; both confirmation tests stub it.
- **E-2 · Low** The fee-ceiling refusal in `stakingTarget.submit` ends with "Re-run with --max-fee N", where N is the fee the node reported. A hostile node's `balance − amount` becomes a copy-pasteable flag.
- **E-3 · Low** `scripts/deploy/acceptance.sh` now passes with two reachable validators (floor lowered in `40c43bc`) and exit 0 is indistinguishable from the three-validator pass. STALLED, DISAGREE, RELAY and UNREACHABLE semantics are unchanged, so a stalled pair cannot pass; what it allows is naming two healthy hosts on a larger committee with a frozen third. A distinct exit code or a required `--partial` flag would keep CI honest.
- **E-4 · Info** `--yes --dry-run` together is accepted silently (dry-run wins). Piped consent is refused by design. README's `claim` flag table omits `--print-key`. The deploy recipe's primary staking examples use `--yes`, removing the confirmation step from the place operators copy from. `ParseCommitteeJSON` still lacks `DisallowUnknownFields`; with `committee_size` now a field, a misspelled key silently drops the spare seat and a newcomer evicts a genesis seat instead.

### 4.5 CI, tests and docs

- **F-1 · Low** The CI timeout comment's arithmetic is wrong again. `.github/workflows/ci.yml` job `test` runs with `-timeout 60m` and the comment says the devnet ceilings total about 3,030 seconds. Summing the `time.Second` and `time.Minute` literals in `internal/devnet/*_test.go` at this commit gives 6,357 seconds, about 106 minutes, with `rotation_out_rt3_test.go` alone at 1,800. Healthy runs take two to three minutes, so this is latent, but it is the second time the stated figure has not matched the tree.
- **F-2 · Low** CI-1 is fixed on `main` but unproven: the release-script fix merged through PR 17 after the last scheduled run, and the scheduled runs of 2026-10-27 and 2026-10-30 both failed `release`. The next cron (Tuesday 2026-11-03) is the first real test, and the `report` job has never run except as skipped. No issue has ever been filed.
- **F-3 · Low** Two unexplained flaky failures on `m5-plan` after the M5 audit: the `-race` step on a commit that added only `nonce_test.go`, and the plain step on a docs-only commit. Neither was diagnosed; the next push passed. The relay reaper margin in `TestTheReaperDoesNotBlameAReceiverForASendersBacklog` is unchanged.
- **F-4 · Info** Reproducibility evidence contradicts itself: the first Docker report says a cold-cache cross-check matched 2 of 12 artifacts, the re-run says a cold `GOCACHE` build was byte-identical. CI builds once and compares nothing, so README's reproducibility claim rests on two disagreeing runs. Signing has never been executed anywhere. The two new benchmarks that back the "allocates nothing" claims in `diag.go` and `IsSeatedAt` are never run by CI.
- **F-5 · Info** Review path: PR 17 (42 commits, about 19,500 insertions) and PR 18 (5 commits) were both self-merged with zero reviews; all feature commits went directly to `m5-plan`. Commit `9653248` is titled as a test change but carries the PX-2, PX-3 and PX-4 feature fixes, as `0a655ba`'s message admits.
- **F-6 · Info** Still-stale documents, unchanged across four reports: M4 plan design decision 2 (tags), M3 plan design decision 4 (not marked superseded), M4 plan Task 4's `Answer` signature, `internal/faucet/pow.go` package doc's ASIC claim, the name `chain_lock_test.go`, and the absent `docs/plans/README.md`. `MessageRouter.OnPeerExchange`'s doc still says the frame is unsigned; `peerexchange_sign_test.go`'s header still says a replayed member HELLO is admitted on a learned dial.

---

## 5. Status of the M5 report's findings

| ID | Status | Implementing symbol | Pinning test |
|---|---|---|---|
| ST-1 unbond floor | **Fixed** | `state.applyUnbond` (remainder zero or at least `MinStake`); mirrored in `cmdUnstake` | `TestUnbondBelowTheFloorIsRefused`, `TestASubMinimumGenesisSeatCanOnlyExitInFull`, `TestOneSparkSeatsCannotBeBuiltByUnbonding` |
| ST-2 count-weighting | Accepted, documented | README "Staking"; plan "The cap's other face" | `TestTheCapHoldsAfterClamping` |
| ST-3 genesis premine | **Fixed** | `Bond.Unfunded`, set in `chain.genesisState`, destroyed in `applyUnbond`, committed by `state.bondLeaf` | `TestAGenesisBondIsUnfundedAndUnbondingItReleasesNothing`; Docker re-run |
| ST-4 unbounded records | **Fixed** | `releaseHeightFor` rounds up to an epoch multiple; `mergeUnbonding` collapses matured records; at most `UnbondingEpochs + 2` per address | `TestUnbondRecordsPerAddressAreBoundedByEpochBuckets` |
| ST-5 stake admission | Fixed with residual C-3 | `mempool.admitStake`, `state.HasUnbonding` | `TestMempoolRefusesStakeTransactionsThatCannotApply` |
| ST-6 genesis zero params | **Fixed** | `genesis.Validate` | `TestStakingParametersArePinnedPerChainAndZeroIsRefused` |
| ST-7 no slashing | Accepted, documented | README "Staking", `SECURITY.md` | — |
| ST-8 leaf goldens | **Fixed** | `state.bondLeaf`, `state.unbondingLeaf` | `TestBondAndUnbondingLeafGoldenVectors` |
| ST-9 failure-path pins | **Fixed** | — | staking rows in `TestApplyTxLeavesNoPartialWriteOnEveryFailurePath`, `TestMergeUnbondingRefusesAnOverflow` |
| ST-10 `/account` bound | **Fixed** | `rpc.handleAccount`, `unbondingWindow`, `maxUnbondingLimit` | `TestAccountUnbondingWindow`, `TestTheUnbondingWindowIsBoundedByTheLimit` |
| ST-11 plan drift | Closed | plan corrected | — |
| RT-1 rotation-in | **Fixed, exposes A-1** | `devnet.StartValidator` checks genesis, then `Chain.CommitteeAt(head+1)` after `chain.Open`; `consensus.NewDriver` admits a seated non-genesis key | `TestARotatedInValidatorStartsAndIsCounted`, `TestAStrangerIsStillRefusedAfterABoundary` |
| RT-2 capture on recipe | **Fixed** | `genesis.ParseCommitteeJSON` refuses power below `MinStakeSparks` and `committee_size` below the list; example file updated | `TestCommitteeFileRefusesAPowerBelowMinStake`, `TestSpareSeatsAdmitWithoutEvicting`, `TestTheShippedExampleCommitteeFileIsLoadable` |
| RT-3 rotated-out frozen | **Fixed** | `Chain.everSeated` filled in `Open` and `memoCommitteeLocked`; `Syncer.syncSeated` and `devnet.committeeMemberAt` add it as a fourth term | `TestARotatedOutValidatorResyncsReannouncesAndIsCountedAgain`, `TestASyncPullIsAdmittedForARotatedOutPostGenesisSeat` |
| RT-4 diag hot path | Accepted, comment corrected | `diag.go` header, `Driver.Observe` doc; `Engine.diagFillRound` caches the block ID | `BenchmarkHotPathObservers` (not run by CI) |
| RT-5 replay-set flood | **Fixed** | `Syncer.Answer`: `checkReplay`, `allowRequest`, `recordRequest` | `TestARefusedSyncRequestIsNotRecordedInTheReplaySet` |
| RT-6 per-frame copies | **Fixed** | `Chain.IsSeatedAt`; `MessageRouter.isMemberAt` | benchmark only |
| RT-7, RT-8 | Accepted, documented | `Syncer.syncSeated`, `Chain.memoCommitteeLocked` docs | — |
| RT-9 committee size bound | **Fixed** | `genesis.Validate` | genesis tests |
| RT-10, RT-11 | Accepted, comments corrected | `Engine.OnTimeout`, `Driver.Tick` docs | `TestAnUnseatedEngineWithAProposalEntersRoundOneAndLocks` |
| PX-1 unsigned hints | **Fixed** | `wire.PeerExchange{Height, Validator, Addrs, Sig}`, `devnet.peerExchangeHash`, `Validator.hintAuthority`; window keyed by signer; eviction via `expireUnprovenHints` and `TcpTransport.RemovePeer` | `TestARelayStrangerCannotAdvertise` (real token-less relay), `TestAHintMustBeSignedByASeat`, `TestALearnedAddressThatNeverCompletesIsEvicted` |
| PX-2 hint dials admitted | **Fixed** on direct links | `tcp.Options.Admit` takes the local nonce; `exchangeNonce`; `install` gates learned dials; `helloHash` covers the nonce | `TestACapturedMemberHelloDoesNotAdmitAHintDialledStranger`, `TestALearnedAddressIsNotAPeerUntilItSaysHello` |
| PX-3 constant greeting | **Fixed** | `Relay.handshake` sends a random challenge; `wire.RelayGateProof` is HMAC-SHA-256; constant-time compare; `wire.MinRelayAccessTokenBytes` | `TestATokenlessRelayForwardsNoProofOfTheToken`, `TestAGateProofIsNotReplayableOnAnotherConnection`; Docker re-run |
| PX-4 verify flood | **Fixed** | `MessageRouter.Route` checks `Dedup.Has` before `Verify`; `tcp.paceRelay` delays rather than drops | `TestAReplayedVoteCostsNoSecondVerification`, `TestARelayFloodIsPacedNotShed` |
| PX-5 to PX-8 | **Fixed** | `install` duplicate rule for learned links; `Validator.reserveRelayAddr`; `isLocalHintAddr`, `canonicalHintAddr`; `ValidatorConfig.Advertise` and `--advertise` | `TestAHintedSquatterCannotHoldAnHonestPeersName`, `TestAPeerHintMayNotNameTheRelayThisNodeDials`, `TestAPeerExchangeCannotAimTheNodeAtItsOwnNetwork`, `TestAnAdvertiseOverrideMakesAForwardedListenerDialable` |
| PX-9 | Partial, accepted | token read bounded at `RelayGateMACBytes`; genesis permanence widened by RT-3 | — |
| CL-1 fee oracle | **Fixed** | `defaultMaxFeeSparks`, `--max-fee`, `buildTx`, `builtTx.print`, `stakingTarget.submit`, `confirmTransaction`, `--yes`, `--dry-run` | `TestHostileNodeFeeIsRefused`, `TestPrintedTransactionIsTheSignedBytes`, `TestNonInteractiveRunRefusesWithoutYes` |
| CL-2, CL-3, CL-4 | **Fixed** (CL-4 except `--epoch-blocks 1`) | `txProvenance.effect`; `--amount` help; `claimHTTP.CheckRedirect`; `rpc.Server.genesisHash`; `releaseForecast` | `TestBondPreviewNamesItsEffectBeforeTheSignature`, `TestGetJSONRefusesARedirect`, `TestReleaseForecastRefusesAHostileOverflow` |
| CI-1 release on main | Fixed, unproven until the next cron | `scripts/build-release.sh`; `ci.yml` job `report` | — |
| CI-2 reporter exits | **Fixed** | `scripts/ci/file-toolchain-issue.sh` wraps every `gh` call | — |
| CI-3 fourth command | Fixed in CI; no CLI-level test | `ci.yml` job `test` | in-process only via `RunMulti` |
| CI-4 timeout rationale | Partial; see F-1 | `ci.yml` job `test` | — |
| CI-5, TS-1, TS-2, TS-3, DOC-1, DOC-2 | **Fixed** | README and plan corrections; `TestStallReportIsRaceSafeWhileDriversTick` polls; `TestPeerExchangeSendRateIsBounded` counts waves; `TestStallReportWouldHaveAnsweredTheCIShape` asserts | — |
| C-3 future-round proposals | **Fixed** | `Engine.onProposal`, `bufferProposal`, `roundSets.pending`, adopted in `enterRound`, served by `committedBlock`; bounded by `withinWindow` and `pruneRounds` to at most eight retained proposals; drawn-proposer check before `Verify` | ten tests in `future_proposal_test.go` |
| C-2 lock bytes across restart | Partial, mitigated | `LockRecord` unchanged; a restarted lock-by-ID victim now prevotes the survivors' justified re-proposal on entering its round | `TestARestartedValidatorPrevotesTheSurvivorsJustifiedReProposalOnEntry` |
| N-2 relay queue residuals | Not fixed, accepted | `relay.sendQ.push`, `shareFor`, `receiverStalled` unchanged | — |
| N-3 HELLO freshness | Partial | direct links nonce-bound; relay links not (A-3) | — |
| C-10, C-16 | Accepted, unchanged | — | — |
| Long-open items: producer clock clamp (`node.RunOnce`), pool lock over chain lock (`mempool.Add`), `DisallowUnknownFields` and curve-point check in `ParseCommitteeJSON`, `claim --print-key` default, no logging in `rpc`/`node`/`chain`, RPC limiter FIFO eviction, `ErrSenderLimit` to 400 | Not fixed | — | — |

**Process gaps, fourth report unchanged:** no coverage in CI, no fuzz job or corpora, `t.Skip` on a deterministic fixture in `TestARebuiltDriverDoesNotBurnRoundZeroOnARunningClock` (the Docker reports' zero skips confirm the guard is dead), eight ignored `Open` errors in `store_test.go`, `Sscanf` stall parsing in simnet tests, no build tag on the subprocess CLI tests, no `CONTRIBUTING.md` or `CODEOWNERS`, no signing step in the release job, the relay reaper margin.

---

## 6. Tests that would fail today

1. A block proposed by a post-genesis seated key is prevoted and appended (A-1).
2. A committee with no genesis seats remaining still commits (A-1).
3. A member forwards another member's nonce-bound HELLO onto its own inbound socket at a third node; the third node must not record the victim `via` that socket (A-2).
4. A replayed low-height member HELLO over the relay must not lower `peerAttestation.height` or displace a direct attestation (A-3).
5. A rotated-out post-genesis node's `rebuildDriver` succeeds or is skipped and `adopted` counts (B-1).
6. `Committee` on a state holding a sub-floor bond beside four floor bonds: decide and pin whether it is seated (C-4).
7. A genesis seat with a funded top-up, partial unbond no larger than `Unfunded`: nothing withdrawable, seat retained (C-1).
8. Opening a data directory written before the `Unfunded` leaf yields a readable error (C-2).
9. Concurrent `expireUnprovenHints` and re-learn leave either a maintainer or no entry (D-3); a proven address with no HELLO for N waves is released (D-4).
10. `stdinIsTerminal` against a pipe, `/dev/null` and a pseudo-terminal, on Windows as well (E-1).
11. `cmdDevnet` with `--rotate-demo --plot-nakamoto` asserting the printed table (CI-3).

---

## 7. Prioritised remediation

1. **A-1**: per-height proposer membership in `validateLocked` through `IsSeatedAt`, plus tests 1 and 2 above. This blocks any run that seats a non-genesis key.
2. **A-2, A-3**: one admitted connection per validator key; high-water mark in `recordHeight`; tests 3 and 4.
3. **A-4**: state the capture cost beside the example file; recommend genesis powers above the floor; consider a non-grindable tie-break.
4. **D-2**: correct the relay-gate help and docs in both binaries, the two option docs, and deploy README section 4.1. Operators read `--help`.
5. **C-1, C-3, D-3, D-4, E-1, E-2, E-3**: the Low items, each a small change.
6. **F-1**: measure the ceilings before writing the number into the comment. **F-2**: watch the 2026-11-03 cron and confirm the `report` job files an issue when something fails.
7. The nine process gaps and six stale documents, now four reports old.

---

## Appendix: verified-sound properties

Each property names the symbol it was read in.

- Candidacy floor as a state invariant: `applyBond` (result), `applyUnbond` (remainder), `ParseCommitteeJSON` (genesis power).
- Genesis grants never become money: `Bond.Unfunded` set in `genesisState`, destroyed before any record is written in `applyUnbond`; `applyWithdraw` credits records only; `Unfunded` is at most `Amount` through both transitions.
- Every validation precedes the first write in `applyBond`, `applyUnbond` (including `mergeUnbonding`), `applyWithdraw`; `Clone` deep-copies `Unfunded` and record slices; release heights are epoch multiples and overflow-checked in `releaseHeightFor`.
- `Committee` is a pure, totally ordered function of `s.bonds` and `s.params` (`compareCandidates`), with the cap fixed point bounded by `committeeMaxCapPasses` and overflow refused by `sumPowers`.
- Epoch committees memoised once in `Chain.memoCommitteeLocked`, rebuilt by `Chain.Open`, read without copying by `Chain.IsSeatedAt`; a miss is `ErrNoCommittee`; `Driver.configFor` validates and `Driver.flush` halts rather than falling back.
- Lock rules unchanged: `lock.lockOn` forward-only; `lock.canPrevote` unlocks only on a verified polka from a strictly later round; `Engine.verifyJustification` re-tallies through `VoteSet.Add` with membership, duplicate and signature in that order.
- Early proposals judged only inside their round: `Engine.enterRound` adopts `pending` after `persistRound` and before `maybePrevote`; `bufferProposal` checks the drawn proposer before `Proposal.Verify`; retained proposals bounded by `withinWindow` and `pruneRounds`.
- Certificate gate: `Syncer.verifyCertificate` uses the committee for the block's height on serve, record and adopt; `Syncer.Answer` orders `checkReplay`, `allowRequest`, `recordRequest`; `Receive` correlates peer, nonce and signed responder.
- Membership before verification on every router path: `MessageRouter.Route` runs `Dedup.Has`, `isMemberAt`, `voteHeightInWindow`, `Verify`, `Dedup.Seen` in that order; forged frames record nothing.
- Hint authority is the signature: `hintAuthority` checks membership through `committeeMemberAt` before `crypto.Verify`; `DecodePeerExchange` bounds count and widths before allocation; one dial path through `AddLearnedPeer`, gated in `install` and `reader`; `RemovePeer` ends a maintainer and nothing a peer sends can.
- Direct-link HELLOs bound to the socket: `exchangeNonce` (crypto/rand, 32 bytes), `helloHash` includes the nonce, equality checked in `admitHello` and `observeHello` before membership and verification; own key refused.
- Relay gate never sends the token: `Relay.handshake` issues a fresh challenge, `wire.RelayGateProof` answers with HMAC-SHA-256, compare is constant-time, read is fixed-width; the relay still decodes nothing (`TestTheRelayCallsNoDecoder`).
- Backoff grows from zero options: `tcp.Options.withDefaults` sets `BackoffMax`; `Backoff.Next` doubles, clamps and jitters.
- Staking CLI: `stakingTarget.submit` is the only path to `crypto.Sign`, ordered print, ceiling, dry-run, confirm, sign; `buildTx` encodes once and decodes once so display and signature cannot diverge; `confirmTransaction` treats EOF, empty input and non-terminal stdin as refusal; `claimHTTP.CheckRedirect` refuses every redirect; `keystore.Load` re-derives the public half and refuses group-readable files.
- RPC: `handleAccount` bounded by `maxUnbondingLimit`, `handleStatus` takes one `HeadSnapshot` and a cached `genesisHash`, `handleTx` rate-limits before reading and bounds the body.
- Store logs unchanged since the previous audit and self-identifying (`SegmentMagic`, `SegmentFormatVersion`); the data-directory lock in `dirlock.go` unchanged.
- `.gitattributes` pins LF; `go.mod` adds no dependency; the Argon2 golden vector is unchanged across the x/crypto bumps; no new `panic` reachable from the network; no `time.Now()` in consensus, state or chain outside `Syncer.nonceSeed` and `Syncer.now`.
