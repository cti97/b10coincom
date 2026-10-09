# CI failure: scheduled lint run 82, govulncheck step

| | |
|---|---|
| Run | [actions/runs/37927052462](https://github.com/cti97/b10coincom/actions/runs/37927052462), job `lint`, 2026-10-09 11:58 UTC |
| Trigger | `schedule` (the twice-weekly cron added for audit finding B-1), not a push |
| Commit | `db083f2` (Merge pull request 11, `review-fixes-4`) |
| Failed step | `go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...` |
| Other jobs | `test`, all six `build + vet` targets and `release` passed on the same commit |
| Verdict | **Not a code regression.** The Go team published a batch of standard-library advisories on 2026-10-08 with fixes in Go 1.27.2. The repository pins `toolchain go1.27.1` in `go.mod`, so the scheduled scan found the vulnerable standard library on the next run. The gate did exactly what it was added to do. |

## What govulncheck reported

The job produced 10 annotations, two for each of five call chains that reach the standard library's bundled HTTP/2 code from `cmd/b10coin`:

| Call chain reported | Entry point in this repo | Matching advisory |
|---|---|---|
| `getJSON` → `http.Client.Get` → `http2.Transport.AddConn` | `cmd/b10coin/main.go:372` (`claim` command) | GO-2026-6610 / CVE-2026-78660, HTTP/2 transport accepts malformed framing-related headers |
| `getJSON` → `http.Client.Get` → `http2.NetHTTPClientConn.RoundTrip` | same | GO-2026-6611 / CVE-2026-78669, excessive CPU from repeated initial window changes (client and server) |
| `getJSON` → `http.Client.Get` → `http2.NetHTTPClientConn.Close` | same | GO-2026-6603 / CVE-2026-78659, HTTP/2 server memory exhaustion via Trailer headers; GO-2026-6617 / CVE-2026-97032, HTTP/2 server crash from an HPACK encoder race |
| `runProducerNode` → `http.Server.Serve` → `http2.Server.ServeConn` | `cmd/b10coin/main.go:499` (node RPC server) | GO-2026-6612 / CVE-2026-78663, double flow-control refund on HTTP/2 server streams; also 6603, 6611, 6617 |
| `shutdownHTTP` → `http.Server.Shutdown` → `http2.Server.GracefulShutdown` | `cmd/b10coin/main.go:493` | 6603, 6611, 6617 |

All five advisories are in `net/http` (via `net/http/internal/http2`), published 2026-10-08, and fixed in **Go 1.26.9 and Go 1.27.2**. Three further advisories in the same batch (GO-2026-6605, 6609, 6613: HTTP/1 CONNECT desynchronisation and Range-header parsing) were not reported because the repository does not reach their symbols.

The full job log is restricted to repository admins, so the mapping above was reconstructed from the job annotations and the advisory records at `vuln.go.dev`. Go 1.27.2 was confirmed current at `go.dev/dl`.

## Actual exposure

Low. Every reported chain goes through HTTP/2, and this repository never enables it:

- The node's RPC server is plaintext. `runProducerNode` and `runNetworkedNode` call `net.Listen` and `http.Server.Serve` with no TLS configuration and no h2c handler, and Go's `net/http` only negotiates HTTP/2 over TLS. `http2.Server.ServeConn` is unreachable for a plaintext listener, so the three server-side advisories do not apply to a running node.
- The `claim` command's client (`claimHTTP`, `main.go:275`) defaults to `http://127.0.0.1:8645`. HTTP/2 is only attempted for `https://` URLs, so the client-side advisories apply only if an operator points `--node` at a TLS endpoint, which the CLI permits but nothing in the repository or recipe sets up.

govulncheck reports on the static call graph, not on runtime configuration, so it cannot see either of those facts. The report is correct that the vulnerable code is linked into the binaries, and the fix below is still the right thing to ship: it costs one line and removes the question entirely.

## Fix

**Bump the pinned toolchain.** In `go.mod`, change

```text
toolchain go1.27.1
```

to

```text
toolchain go1.27.2
```

Leave `go 1.26.0` as the language floor. Nothing else needs to change: every CI job uses `go-version-file: go.mod`, so `setup-go` will install 1.27.2; the release job records the toolchain in `dist/BUILD-INFO` and asserts it, so the artifacts will carry the new version automatically. Run `go mod tidy` afterwards to confirm no diff (the lint job checks this).

Verification before merging:

```bash
go mod tidy && git diff --exit-code go.mod go.sum
```

```bash
go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...
```

The second command must print no findings. Push on a branch so the `pull_request` run exercises the full matrix and the release job's `BUILD-INFO` assertion on the new version.

## Why the cron, not a push, caught it

The advisories were modified in the database on 2026-10-08 at 22:31 UTC. The last push to `main` (`db083f2`) ran before that and passed. The scheduled run on 2026-10-09 was the first scan after publication. This is the scenario the schedule was added for in the B-1 fix: a vulnerability that appears while the code is unchanged still fails a build within days rather than waiting for the next commit.

## Keeping this from recurring silently

The pinned `toolchain` line means every new Go patch release will re-create this failure until someone edits `go.mod`. Dependabot's `gomod` ecosystem does not manage the `toolchain` directive. Two options:

1. **Keep the pin and accept the chore** (recommended). It matches the repository's one-source-of-truth rule for the version a binary reports, and the scheduled run turns each Go patch release into a visible failure with a one-line fix. Add a note to `SECURITY.md` or `CONTRIBUTING.md` that a scheduled govulncheck failure with only standard-library findings means "bump `toolchain`".
2. **Float the patch level in CI** by giving `setup-go` `go-version: '1.27'` with `check-latest: true` instead of `go-version-file`. CI would then always test and release on the newest 1.27.x, but local builds and the `BUILD-INFO` record would no longer be pinned by `go.mod`, which weakens the reproducibility story from audit finding B-2.

Either way, the scheduled job should also run on the release matrix only if that cost is wanted; today the cron runs all four jobs, including the six-target cross build and the release upload, when only `lint` needs to run on a schedule. Splitting the schedule onto the lint job alone would make these runs cheaper without losing the gate.

## Repository note

The local checkout used for this report is 10 commits behind `origin/main` and 3 ahead with the unpushed duplicate `docs/audit.md`. The fix above should be made on a fresh branch from `origin/main`.
