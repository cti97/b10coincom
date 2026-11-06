#!/usr/bin/env bash
# Guard for the failure mode that has now cost this project three rounds: an edit
# to a plan file can leave its Markdown code fences unbalanced, which inverts fence
# parity for every later section. The task-brief extractor toggles on each fence
# line, so a section whose heading lands "inside" a fence is never found and its
# brief silently comes out EMPTY - or bleeds into the next task.
#
# Run this after ANY edit to a file under docs/plans/, before dispatching anything.
#
# TWO HALVES, AND AN ABSENT TOOL IS NOT A PASS (audit S-19). The fence-parity half
# is self-contained (scripts/plan_parity.py). The brief-extraction half drives the
# SDD skill's own scripts, which live in the operator's skill directory and are not
# in this repository. When they are absent the old behaviour printed
# "PLAN PARITY OK" and exited 0, so the same repository produced a weaker verdict
# on a different machine. Now absence is a FAILURE unless the caller states, with
# --parity-only, that they accept the parity half alone - which is what CI does,
# because CI cannot have the operator's skill directory and CAN enforce fences.
#
# Usage: scripts/check-plan.sh [--parity-only] docs/plans/<plan>.md
#   exit 0  the requested halves passed
#   exit 1  a fence is unbalanced, a brief is broken, or the brief tool is absent
#           and --parity-only was not given
#   exit 2  bad invocation, unreadable plan, or the parity half's interpreter is
#           absent. A missing TOOL is not a broken plan: the golang image has no
#           python3, and this used to report "PLAN IS BROKEN" (testrun
#           2026-11-06). --parity-only does NOT remove the dependency - the fence
#           half IS scripts/plan_parity.py; what the flag skips is the SDD
#           skill's brief extraction, which is not in this repository.
set -uo pipefail

parity_only=no
plan=""
for arg in "$@"; do
  case "$arg" in
    --parity-only) parity_only=yes ;;
    -h|--help)
      echo "usage: scripts/check-plan.sh [--parity-only] docs/plans/<plan>.md"
      echo "  --parity-only  skip brief extraction; enforce fence parity only (the CI half)"
      exit 0
      ;;
    --*)
      echo "check-plan.sh: unknown option $arg" >&2
      echo "usage: scripts/check-plan.sh [--parity-only] docs/plans/<plan>.md" >&2
      exit 2
      ;;
    *)
      if [ -n "$plan" ]; then
        echo "check-plan.sh: more than one plan given ($plan, $arg)" >&2
        exit 2
      fi
      plan=$arg
      ;;
  esac
done

if [ -z "$plan" ]; then
  echo "usage: check-plan.sh [--parity-only] docs/plans/<plan>.md" >&2
  exit 2
fi
[ -f "$plan" ] || { echo "no such plan: $plan" >&2; exit 2; }

fail=0

# 0. The fence half runs through scripts/plan_parity.py. On a machine without
#    python3 (the golang image, for one) the old path called the interpreter,
#    caught its failure, and printed "PLAN IS BROKEN" - a verdict about the PLAN
#    produced by a missing TOOL. Name the absence instead (testrun 2026-11-06).
if ! command -v python3 >/dev/null 2>&1; then
  echo "check-plan.sh: python3 is required for the fence-parity half (scripts/plan_parity.py) and is not on PATH." >&2
  echo "               This is a missing interpreter, not a broken plan; install python3 (or run this guard where it exists)." >&2
  exit 2
fi

# 1. Fence parity, per task section. A section with an odd count is a defect even
#    when the file-wide total is even, because the sections after it stay inverted.
if ! python3 scripts/plan_parity.py "$plan"; then
  fail=1
fi

# 2. Every task's brief must extract, be non-trivial, and not bleed into the next.
#    This half drives the SDD skill's OWN scripts (sdd-workspace / task-brief).
#    They live in the operator's skill directory, NOT in this repository, so on a
#    machine without them the old hard-coded $HOME/.dsh path made every task read
#    "EXTRACTION FAILED" and then "PLAN IS BROKEN" - a false failure caused by a
#    missing tool, not by the plan (audit N-17). The directory is located through
#    SDD_SKILL_DIR (default: the standard install path). Absence is now an
#    explicit, caller-acknowledged skip (audit S-19), never a silent pass.
skill_dir=${SDD_SKILL_DIR:-$HOME/.dsh/skills/subagent-driven-development}
scripts_dir=$skill_dir/scripts
workspace=$scripts_dir/sdd-workspace
brief_tool=$scripts_dir/task-brief

briefs_ran=no
if [ "$parity_only" = yes ]; then
  # The caller asked for the CI half explicitly; do not run, or report, the
  # half whose tools may or may not exist on this machine.
  echo "  briefs: SKIPPED - --parity-only (SDD skill scripts not run)"
elif [ -x "$workspace" ] && [ -x "$brief_tool" ]; then
  briefs_ran=yes
  dir=$("$workspace" "$plan")
  tasks=$(grep -oE '^#+[[:space:]]+Task[[:space:]]+[0-9]+' "$plan" | grep -oE '[0-9]+$' | sort -n | uniq)
  echo "  tasks found: $(echo "$tasks" | tr '\n' ' ')"
  for n in $tasks; do
    if ! "$brief_tool" "$plan" "$n" >/dev/null 2>&1; then
      echo "  Task $n: EXTRACTION FAILED"; fail=1; continue
    fi
    b="$dir/task-$n-brief.md"
    lines_n=$(wc -l < "$b" | tr -d ' ')
    bleeds=$(grep -c "^## Task $((n+1))" "$b" || true)
    if [ "$lines_n" -lt 20 ]; then echo "  Task $n: SUSPICIOUSLY SHORT ($lines_n lines)"; fail=1; fi
    if [ "$bleeds" -ne 0 ]; then echo "  Task $n: BLEEDS into Task $((n+1))"; fail=1; fi
  done
  [ $fail -eq 0 ] && echo "  briefs: OK" || echo "  briefs: FAIL"
else
  echo "  briefs: NOT RUN - the SDD skill's task-brief scripts are absent:"
  echo "           $workspace"
  echo "           $brief_tool"
  echo "           Refusing to print the weaker verdict this guard used to print on"
  echo "           such a machine (audit S-19). Install the skill, set SDD_SKILL_DIR"
  echo "           to its directory, or pass --parity-only to enforce fences alone."
fi

if [ $fail -ne 0 ]; then
  echo
  echo "PLAN IS BROKEN - fix the fences before dispatching anything." >&2
  exit 1
fi
if [ "$briefs_ran" = yes ]; then
  echo "PLAN OK"
elif [ "$parity_only" = yes ]; then
  echo "PLAN PARITY OK - brief extraction SKIPPED (--parity-only)"
else
  echo
  echo "PLAN PARITY OK, but the brief half did not run: refusing to report a pass (audit S-19)." >&2
  exit 1
fi
