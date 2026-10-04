#!/usr/bin/env bash
# Guard for the failure mode that has now cost this project three rounds: an edit
# to a plan file can leave its Markdown code fences unbalanced, which inverts fence
# parity for every later section. The task-brief extractor toggles on each fence
# line, so a section whose heading lands "inside" a fence is never found and its
# brief silently comes out EMPTY - or bleeds into the next task.
#
# Run this after ANY edit to a file under docs/plans/, before dispatching anything.
#
# Usage: scripts/check-plan.sh docs/plans/<plan>.md
set -uo pipefail

plan=${1:?usage: check-plan.sh <plan.md>}
[ -f "$plan" ] || { echo "no such plan: $plan" >&2; exit 2; }

fail=0

# 1. Fence parity, per task section. A section with an odd count is a defect even
#    when the file-wide total is even, because the sections after it stay inverted.
if ! python3 scripts/plan_parity.py "$plan"; then
  fail=1
fi

# 2. Every task's brief must extract, be non-trivial, and not bleed into the next.
dir=$("$HOME/.dsh/skills/subagent-driven-development/scripts/sdd-workspace" "$plan")
tasks=$(grep -oE '^#+[[:space:]]+Task[[:space:]]+[0-9]+' "$plan" | grep -oE '[0-9]+$' | sort -n | uniq)
echo "  tasks found: $(echo "$tasks" | tr '\n' ' ')"
for n in $tasks; do
  if ! "$HOME/.dsh/skills/subagent-driven-development/scripts/task-brief" "$plan" "$n" >/dev/null 2>&1; then
    echo "  Task $n: EXTRACTION FAILED"; fail=1; continue
  fi
  b="$dir/task-$n-brief.md"
  lines_n=$(wc -l < "$b" | tr -d ' ')
  bleeds=$(grep -c "^## Task $((n+1))" "$b" || true)
  if [ "$lines_n" -lt 20 ]; then echo "  Task $n: SUSPICIOUSLY SHORT ($lines_n lines)"; fail=1; fi
  if [ "$bleeds" -ne 0 ]; then echo "  Task $n: BLEEDS into Task $((n+1))"; fail=1; fi
done
[ $fail -eq 0 ] && echo "  briefs: OK" || echo "  briefs: FAIL"

if [ $fail -ne 0 ]; then
  echo
  echo "PLAN IS BROKEN - fix the fences before dispatching anything." >&2
  exit 1
fi
echo "PLAN OK"
