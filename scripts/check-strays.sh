#!/usr/bin/env bash
# This repository lives under ~/Documents, which macOS syncs to iCloud. When a sync
# races a git checkout, iCloud leaves conflict copies named "<name> 2.<ext>". A copy
# ending in .go inside a package directory is COMPILED BY GO, so it redeclares live
# symbols and the build fails with errors that look like real defects.
#
# That has now happened twice - once at the start of M3 and again at the start of M4 -
# and each time it was diagnosed from scratch. This check makes it a one-line answer.
#
# Run before building, or in CI, or whenever the build fails inexplicably.
set -uo pipefail
root=${1:-.}
found=$(find "$root" -path "$root/.git" -prune -o -type f \( -name '* 2' -o -name '* 2.*' \) -print 2>/dev/null)
if [ -n "$found" ]; then
  echo "STRAY iCLOUD CONFLICT COPIES - these break the Go build:" >&2
  echo "$found" | sed 's/^/  /' >&2
  echo >&2
  echo "They are byte-identical duplicates. MOVE them out of the repository; do not just" >&2
  echo "ignore them, because Go compiles every .go file in a package directory:" >&2
  echo "  mkdir -p ../.icloud-duplicates-b10coin && while read -r f; do" >&2
  echo "    mkdir -p \"../.icloud-duplicates-b10coin/\$(dirname \"\$f\")\" && mv \"\$f\" \"../.icloud-duplicates-b10coin/\$f\"; done" >&2
  exit 1
fi
echo "no stray conflict copies"
