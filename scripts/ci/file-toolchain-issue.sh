#!/usr/bin/env bash
#
# File a failed scheduled run where work is tracked.
#
# WHY THIS EXISTS
#   go.mod pins an exact `toolchain` line on purpose (audit B-1), so the version a
#   binary reports and the version CI scans are one source of truth. The cost is
#   that every Go patch release fixing a standard-library advisory turns into a red
#   `schedule` run while the code stands still. That is the gate doing its job - but
#   it is a chore nobody sees until they look at Actions, and it has already rotated
#   twice: the 2026-10-08 net/http batch (-> go1.27.2), then GO-2026-6809 (-> go1.27.3).
#   SECURITY.md documents the procedure; nothing pointed at it at the moment it was
#   needed. This script does.
#
#   CI-1 is the second half of the reason. `main` failed its scheduled release
#   on every run from 2026-10-27 and nobody was told, because this reporter fired
#   only on a govulncheck failure. It now fires on ANY failed job of a `schedule`
#   run - see the generic class below - so the next red cron is visible even when
#   govulncheck is green.
#
# USAGE
#   file-toolchain-issue.sh [govulncheck-output-file]
#   Defaults to "$RUNNER_TEMP/govulncheck.out". Needs `gh` (GH_TOKEN) for the API
#   and GITHUB_SERVER_URL / GITHUB_REPOSITORY / GITHUB_RUN_ID for the run link.
#   REPORT_JOB overrides GITHUB_JOB with the id of the job that FAILED (the
#   workflow's report job passes it; inside a job, GITHUB_JOB is already it).
#
# WHAT IT FILES
#   standard library only      -> an issue naming the exact `toolchain` line, taken
#                                 from govulncheck's own "Fixed in:", plus the four
#                                 commands to verify it
#   any call-reachable non-stdlib finding -> a differently titled issue that says
#                                 plainly it needs a human, with the full output
#   a scheduled job that failed for any other reason -> an issue naming the job
#                                 (`test`, `lint`, `release`, `cross`), so a red
#                                 cron is not silent (audit CI-1/CI-2)
#   an issue is already open    -> a comment, never a second issue
#
# It exits 0 in every case. It is a reporter: the gate that failed has already
# failed the job, and a reporter that fails too would bury the real error. Every
# `gh` call is therefore wrapped, and the one failure that would be worse than
# silence is handled deliberately: if the DEDUP LOOKUP fails, the script files
# nothing, because a missed comment beats a new issue on every run.
set -euo pipefail

out="${1:-${RUNNER_TEMP:-/tmp}/govulncheck.out}"
job="${REPORT_JOB:-${GITHUB_JOB:-unknown}}"
job=$(printf '%s' "$job" | tr -cd 'A-Za-z0-9_-')
: "${job:=unknown}"
: "${GITHUB_SERVER_URL:=https://github.com}"
: "${GITHUB_REPOSITORY:=cti97/b10coincom}"
: "${GITHUB_RUN_ID:=unknown}"
run_url="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"

kind=job
if [ -s "$out" ] && grep -q 'GO-[0-9]\{4\}-' "$out"; then
  # A module-level advisory the code never calls does not fail the gate, so what
  # is here is a call-reachable finding: either the standard library or a module
  # we actually call. "Standard library" with no "Module:" line is the bump case.
  stdlib=$(grep -c 'Standard library' "$out" || true)
  modules=$(grep -cE '^[[:space:]]+Module:' "$out" || true)
  if [ "${stdlib:-0}" -gt 0 ] && [ "${modules:-0}" -eq 0 ]; then
    kind=stdlib
  else
    kind=triage
  fi
elif [ "${GITHUB_ACTIONS:-}" != "true" ]; then
  # Run by hand with no advisory output: there is no failed job to report, so
  # keep the historical "nothing to do" behaviour instead of filing an issue
  # about a run that does not exist.
  echo "no scheduled job failure to report (no advisory IDs, not running in Actions). Nothing to file."
  exit 0
fi

# The version to bump to, from govulncheck's own "Fixed in:" lines. `sort -V` is
# coreutils, present on the ubuntu-latest runner.
fixed=$(grep -oE 'Fixed in: [^ ]+@go[0-9]+\.[0-9]+\.[0-9]+' "$out" 2>/dev/null \
          | grep -oE 'go[0-9]+\.[0-9]+\.[0-9]+' | sort -V | tail -1 || true)

findings=$(grep -E 'Vulnerability #[0-9]+: GO-' "$out" 2>/dev/null | sed 's/^ *//' || true)
summary=$(grep -E 'Your code is affected by' "$out" 2>/dev/null | tail -1 || true)

if [ "$kind" = stdlib ]; then
  title='ci: Go toolchain bump needed (scheduled govulncheck, standard library only)'
  target="${fixed:-the newest Go patch release}"
  body="$(cat <<EOF
The scheduled \`lint\` run failed \`govulncheck\` with **call-reachable findings in the standard library only**. By the procedure in \`SECURITY.md\`, that means one line changed in \`go.mod\`:

\`\`\`text
toolchain ${target}
\`\`\`

Then verify locally - all four must pass:

\`\`\`bash
go mod tidy && git diff --exit-code go.mod go.sum
go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...
GOTOOLCHAIN=go1.26.9 go run honnef.co/go/tools/cmd/staticcheck@v0.8.1 ./...
go test -count=1 ./...
\`\`\`

Check the staticcheck line specifically. \`staticcheck@v0.8.1\` is the newest release that exists and its \`golang.org/x/tools\` reads compiler export data up to version 4, so a toolchain bump can break it. That is why the CI step pins \`GOTOOLCHAIN=go1.26.9\`; when a staticcheck release reads version 5, that pin can go.

${summary}

Findings:
\`\`\`text
${findings}
\`\`\`

Run: ${run_url}
EOF
)"
elif [ "$kind" = triage ]; then
  title='ci: scheduled govulncheck failure needs triage (not standard library only)'
  body="$(cat <<EOF
The scheduled \`lint\` run failed \`govulncheck\` with a call-reachable finding that is **not** explained by a Go toolchain bump. This needs a human: a dependency upgrade or a code change.

${summary}

Findings:
\`\`\`text
${findings}
\`\`\`

Full output:
\`\`\`text
$(cat "$out")
\`\`\`

Run: ${run_url}
EOF
)"
else
  title="ci: scheduled ${job} job failed"
  if [ "$job" = lint ]; then
    detail='`govulncheck` produced no advisory IDs, so a different lint gate failed (gofmt, shellcheck, `go mod tidy`, or staticcheck).'
  else
    detail="The \`${job}\` job failed. This report does not name the step: the job log is the evidence."
  fi
  body="$(cat <<EOF
A scheduled run failed the \`${job}\` job. This reporter now fires on **any** failed job of a \`schedule\` run, not only on a govulncheck failure, because a red cron that nobody hears about is the CI-1 defect.

${detail}

Open the run and read the failing step:

${run_url}
EOF
)"
fi

# One issue per kind, updated in place: a twice-weekly cron must not open a new
# issue on every run. The title is matched exactly, not by substring, so the
# stdlib, triage and per-job issues stay distinct.
#
# A failed LOOKUP files nothing. If `gh` cannot answer "is one already open?",
# creating an issue could duplicate one on every run - the noise this dedup
# exists to prevent - so silence is the safer error.
if ! existing=$(gh issue list --state open --search "in:title ${title}" \
                  --json number,title \
                  --jq "[.[] | select(.title == \"${title}\") | .number] | first // empty" 2>/dev/null); then
  echo "::warning::could not look up an open issue; not filing (a missed report beats a duplicate every run)" >&2
  exit 0
fi

# The `dependencies` label is optional: a deleted label must not turn a report
# into silence, and `gh issue create --label` fails when the label is absent.
# The check itself is wrapped, so a gh failure here just omits the label.
label_args=()
if gh label list --search dependencies --json name --jq '.[].name' 2>/dev/null \
     | grep -qx 'dependencies'; then
  label_args=(--label dependencies)
fi

if [ -n "${existing:-}" ]; then
  if printf '%s\n\n---\n\n_Re-detected by run %s on %s._\n' \
       "$body" "$run_url" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
       | gh issue comment "$existing" --body-file -; then
    echo "commented on the existing issue #${existing}"
  else
    echo "::warning::could not comment on issue #${existing}; the run log still holds the failure" >&2
  fi
elif gh issue create --title "$title" --body "$body" ${label_args[@]+"${label_args[@]}"}; then
  echo "filed: ${title}"
else
  echo "::warning::could not file '${title}'; the run log still holds the failure" >&2
fi
exit 0
