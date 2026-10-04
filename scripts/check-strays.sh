#!/usr/bin/env bash
# This repository lives under ~/Documents, which macOS syncs to iCloud. When a sync
# races a git checkout, iCloud leaves conflict copies named "<name> 2.<ext>", and a
# copy ending in .go inside a package directory is COMPILED BY GO - so it redeclares
# live symbols and the build fails with errors that look like real defects.
#
# That has now happened twice, once at the start of M3 and again at the start of M4,
# and each time it was diagnosed from scratch. This makes it a one-line answer.
#
# Go ignores directories whose names begin with "." or "_", so a copy under
# .superpowers/ cannot break the build; those are reported as clutter, not as danger.
set -uo pipefail
root=${1:-.}

# Same rule Go itself uses: skip dotted and underscored directories.
# -mindepth 1 is essential: without it the START path itself matches the '.'
# basename rule below and the whole tree is pruned, so the guard reports "no
# strays" while strays exist. That bug shipped once and was caught by a reviewer,
# not by the guard - which is the worst kind of guard.
all=$(find "$root" -mindepth 1 \
  \( -name '.*' -o -name '_*' \) -type d -prune -o \
  -type f \( -name '* 2' -o -name '* 2.*' \) -print 2>/dev/null)

[ -z "$all" ] && { echo "no stray conflict copies"; exit 0; }

breaking=$(echo "$all" | grep '\.go$' || true)
clutter=$(echo "$all" | grep -v '\.go$' || true)
status=0

if [ -n "$breaking" ]; then
  echo "STRAY .go COPIES THAT BREAK THE BUILD (Go compiles every .go in a package dir):" >&2
  echo "$breaking" | sed 's/^/  /' >&2
  status=1
fi
if [ -n "$clutter" ]; then
  echo "stray non-Go conflict copies (clutter, cannot break the build):" >&2
  echo "$clutter" | sed 's/^/  /' >&2
fi

cat >&2 <<'HOWTO'

They are byte-identical duplicates. MOVE them out of the repository rather than
deleting or ignoring them:
  Q=../.icloud-duplicates-b10coin
  while IFS= read -r f; do
    mkdir -p "$Q/$(dirname "$f")" && mv "$f" "$Q/$f"
  done < <(find "$root" -mindepth 1 \( -name '.*' -o -name '_*' \) -type d -prune -o -type f \( -name '* 2' -o -name '* 2.*' \) -print)
HOWTO
exit $status
