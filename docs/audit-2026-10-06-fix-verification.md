# Fix verification for the 2026-10-04 audit

| | |
|---|---|
| Audited baseline | commit `8224194`, findings in [`audit-2026-10-04.md`](audit-2026-10-04.md) |
| Verified tree | `origin/main` at `1124241` (60 commits after the baseline, 113 files, about 22,300 insertions). The local working tree is `68892f9`, which is `1124241` plus three unpushed commits that only re-add a duplicate `docs/audit.md`; the code is identical. |
| Date | 2026-10-06 |
| Method | Static review of every fix commit (`git show`), the current source and tests, and the CI run history via `gh`. Go is still not installed on the review machine, so no test was executed here. CI results on GitHub are the only execution evidence and are cited where they apply. Every "Fixed" verdict names the code that closes the finding and the test that pins it. |

Line references are against `1124241`.

---

## 1. Verdict

**The fix campaign closed every Critical and High finding, and most Medium ones, with real tests behind them.** The headline items are genuinely gone: validators now sign with key files and a committee-listed genesis; proposals are validated before any prevote; a locked proposer re-proposes with proof; the relay link has a fixed name and a maintainer that never goes dormant; the relay's memory bound is derived and quoted correctly; transactions carry the genesis hash and a fee; the data directory is locked; the mempool admits claims against head state; the toolchain is current and CI has lint, vulnerability and shell gates.

**What remains falls into four groups**, none Critical or High:

1. **Fixes that are partial by design and say so**: proof-of-lock evidence is not persisted across restart (C-2), the claim sub-pool can still be kept full by an attacker with many keys (R-1), two attacker source prefixes can still fill a relay receiver queue (N-2), `claim` still prints its key by default (O-10).
2. **New issues introduced by the fixes** (section 3): the per-connection rate limit now throttles the shared relay link, so a flooder at the relay drops honest votes rather than merely delaying them; a node sends its relay access token unconditionally, so a relay started without a token forwards the secret to every peer; the tally verifies a signature before its duplicate check, so a Byzantine proposer can pack one vote thousands of times into a justification; the store format changed with no version marker, so a pre-fix data directory fails with a hint that tells the operator to delete their chain; the single-node producer can exit on a backwards clock step.
3. **Process gaps the audit asked for that were not done**: coverage measurement, a fuzz job with committed corpora, CONTRIBUTING and CODEOWNERS, release signing in practice, the `t.Skip` fixture, ignored `Open` errors in store tests, the Sscanf stall parsing, a build tag for the subprocess CLI tests.
4. **Two undiagnosed CI failures** on commits that changed no Go code, one under `-race`. A new relay test added by a direct-to-main push has a 150 ms wall-clock margin and is the most likely culprit.

Counts, from the tables in section 2: of the 74 code findings, **55 Fixed, 9 Partially fixed, 8 Accepted or documented as the audit recommended, 2 Not fixed** (S-13 and S-19). Of the 9 process gaps in section 2.4, 2 are fixed and 7 are not. Nine new issues were found: 4 Medium and 5 Low.

---

## 2. Finding-by-finding status

Status key: **Fixed** = code closes it and a test pins it. **Partial** = materially narrowed, residual stated. **Accepted** = not changed, with a recorded rationale the reviewers agree with. **Not fixed** = open. **Docs** = the audit recommended documentation only, and it was documented.

### 2.1 Critical and High

| ID | Finding | Status | Fix | Pinned by |
|---|---|---|---|---|
| A-1 | Publicly derivable validator keys; relay open to the internet | **Fixed** | `internal/keystore` (0600 files, `O_EXCL`, load refuses group/other-readable); `b10coin keygen`; `--genesis PATH --key PATH` mode in `cmd/b10coin/main.go:591-700`; committee file loader `internal/genesis/committee_file.go:84-150` (duplicate keys refused, 1 to 255 seats); `StartValidator` refuses a key not in the committee (`tcpnode.go:334-339`); deploy recipe generates keys per Pi, never copies them, and replaces `ufw allow 7001/tcp` with a per-validator allowlist plus a relay access token. README qualifies the relay-trust claim to key-file committees. | `keystore_test.go:26-126`, `main_test.go:601, 641, 673, 715`, `genesismode_test.go:68-126`, `committee_file_test.go:48-187` |
