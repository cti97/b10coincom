#!/usr/bin/env bash
#
# File the "the pinned toolchain needs a bump" chore where work is tracked.
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
# USAGE
#   file-toolchain-issue.sh [govulncheck-output-file]
#   Defaults to "$RUNNER_TEMP/govulncheck.out". Needs `gh` (GH_TOKEN) for the API
#   and GITHUB_SERVER_URL / GITHUB_REPOSITORY / GITHUB_RUN_ID for the run link.
#
# WHAT IT FILES
#   standard library only      -> an issue naming the exact `toolchain` line, taken
#                                 from govulncheck's own "Fixed in:", plus the four
#                                 commands to verify it
#   any call-reachable non-stdlib finding -> a differently titled issue that says
#                                 plainly it needs a human, with the full output
#   no advisory IDs in the output -> nothing (a different lint gate failed)
#   an issue is already open    -> a comment, never a second issue
#
# It exits 0 in every case. It is a reporter: the gate that failed has already
# failed the job, and a reporter that fails too would bury the real error.
set -euo pipefail

out="${1:-${RUNNER_TEMP:-/tmp}/govulncheck.out}"
: "${GITHUB_SERVER_URL:=https://github.com}"
: "${GITHUB_REPOSITORY:=cti97/b10coincom}"
: "${GITHUB_RUN_ID:=unknown}"
run_url="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"

if [ ! -s "$out" ] || ! grep -q 'GO-[0-9]\{4\}-' "$out"; then
  echo "govulncheck produced no advisory findings; a different lint gate failed. Nothing to file."
  exit 0
fi

# A module-level advisory the code never calls does not fail the gate, so what is
# here is a call-reachable finding: either the standard library or a module we
# actually call. "Standard library" with no "Module:" line is the bump case.
stdlib=$(grep -c 'Standard library' "$out" || true)
modules=$(grep -cE '^[[:space:]]+Module:' "$out" || true)
if [ "${stdlib:-0}" -gt 0 ] && [ "${modules:-0}" -eq 0 ]; then
  kind=stdlib
else
  kind=triage
fi

# The version to bump to, from govulncheck's own "Fixed in:" lines. `sort -V` is
# coreutils, present on the ubuntu-latest runner.
fixed=$(grep -oE 'Fixed in: [^ ]+@go[0-9]+\.[0-9]+\.[0-9]+' "$out" \
          | grep -oE 'go[0-9]+\.[0-9]+\.[0-9]+' | sort -V | tail -1 || true)

findings=$(grep -E 'Vulnerability #[0-9]+: GO-' "$out" | sed 's/^ *//' || true)
summary=$(grep -E 'Your code is affected by' "$out" | tail -1 || true)

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
else
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
fi

# One issue per kind, updated in place: a twice-weekly cron must not open a new
# issue on every run. The title is matched exactly, not by substring, so the
# stdlib and triage issues stay distinct.
existing=$(gh issue list --state open --search "in:title ${title}" \
             --json number,title \
             --jq "[.[] | select(.title == \"${title}\") | .number] | first // empty")

if [ -n "${existing:-}" ]; then
  printf '%s\n\n---\n\n_Re-detected by run %s on %s._\n' \
    "$body" "$run_url" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    | gh issue comment "$existing" --body-file -
  echo "commented on the existing issue #${existing}"
else
  gh issue create --title "$title" --body "$body" --label dependencies
fi
