#!/bin/sh
# The deployment-facing wrapper the Pi recipe (scripts/deploy/README.md) runs:
# it builds BOTH binaries for ONE target through the ONE build story —
# scripts/build-release.sh — and then copies the pair into bin/ under the
# STABLE, unversioned names the recipe's scp lines copy forever:
#
#     scripts/deploy/build.sh                 → bin/b10coin-linux-arm64       (+ relay)  — the Pis
#     scripts/deploy/build.sh linux/amd64     → bin/b10coin-relay-linux-amd64            — the e.g. amd64 VPS
#
# The release script owns the build flags, the .exe suffix, the version (from
# internal/version — no flags), and every artifact assertion (count ==
# target count, each artifact file(1)-checked to really report its own
# architecture); this wrapper adds only the stable-name interface and a
# belt-and-braces re-listing in `file`, so a recipe reader sees the check the
# recipe quotes. Task 9 note: the single-target `make arm64` line this
# replaces was a special case of the release script — nothing here builds
# with different flags than a full `make release` would.
#
# Usage: scripts/deploy/build.sh [os/arch]
set -eu

cd "$(dirname "$0")/../.."

osarch=${1:-linux/arm64}
os=${osarch%/*}
arch=${osarch#*/}
ext=""
[ "$os" = "windows" ] && ext=".exe"

# The build itself: the release script, restricted to this one target. It
# wipes dist/, builds the pair, asserts the count and each file's
# architecture and writes dist/SHA256SUMS; any failure exits loudly and
# leaves no partial dist/ behind.
scripts/build-release.sh --only "$osarch"

# Stable names for the recipe: copy the freshly built pair out of dist/. The
# globs must match exactly one file each — a mismatch here IS the stale
# or missing-artifact failure, named instead of shipped.
node_src=$(ls dist/b10coin-[0-9]*-"$os-$arch$ext" 2>/dev/null) || true
relay_src=$(ls dist/b10coin-relay-[0-9]*-"$os-$arch$ext" 2>/dev/null) || true
if [ "$node_src" = "" ] || [ "$relay_src" = "" ]; then
    echo "FAIL: the release build for $osarch did not produce both artifacts (node: '$node_src', relay: '$relay_src')" >&2
    exit 1
fi
mkdir -p bin
cp "$node_src" "bin/b10coin-$os-$arch$ext"
cp "$relay_src" "bin/b10coin-relay-$os-$arch$ext"

# Belt: the copies must report the same architecture the release script just
# asserted for the originals (same bytes — but here is the check a reader can
# see without opening dist/). Same TOKEN-BASED assertion as build-release.sh
# (format + architecture token, any word order): Apple's file prints
# "Mach-O 64-bit executable x86_64", upstream libmagic on Linux prints
# "Mach-O 64-bit x86_64 executable", and one exact sentence would pin this
# check to one vendor. Arch tokens match case-insensitively (arm64 vs
# Aarch64/AArch64 differ between implementations).
for f in "bin/b10coin-$os-$arch$ext" "bin/b10coin-relay-$os-$arch$ext"; do
    case "$os/$arch" in
        darwin/amd64)  fmt="Mach-O" tok="x86_64"  ;;
        darwin/arm64)  fmt="Mach-O" tok="arm64"   ;;
        linux/amd64)   fmt="ELF"    tok="x86-64"  ;;
        linux/arm64)   fmt="ELF"    tok="aarch64" ;;
        windows/amd64) fmt="PE32+"  tok="x86-64"  ;;
        windows/arm64) fmt="PE32+"  tok="aarch64" ;;
    esac
    got=$(file "$f" 2>&1)
    if ! printf '%s\n' "$got" | grep -q -- "$fmt" ||
       ! printf '%s\n' "$got" | grep -iq -- "$tok"; then
        echo "FAIL: $f is not the $osarch artifact it is named for (wanted: $fmt + $tok):" >&2
        echo "$got" >&2
        exit 1
    fi
done

file "bin/b10coin-$os-$arch$ext" "bin/b10coin-relay-$os-$arch$ext"

# bin/SHA256SUMS over the STABLE names, so the recipe can copy a checksum file
# to each machine and verify what it copied ON THE TARGET (audit B-2; the
# README told operators to verify and gave them nothing to verify against).
# Regenerated over every b10coin-* file present, so a later invocation for a
# second target (e.g. the amd64 relay for an amd64 VPS) ADDS its pair instead
# of replacing the file. dist/SHA256SUMS still covers the versioned artifacts.
if command -v sha256sum >/dev/null 2>&1; then
    sum="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
    sum="shasum -a 256"
else
    echo "FAIL: neither sha256sum nor shasum is available to write bin/SHA256SUMS" >&2
    exit 1
fi
( cd bin && $sum b10coin-* > SHA256SUMS ) || {
    echo "FAIL: writing bin/SHA256SUMS failed" >&2
    exit 1
}
echo "checksums  bin/SHA256SUMS covers $(wc -l < bin/SHA256SUMS | tr -d ' ') stable-name artifact(s); verify on each target with: sha256sum -c --ignore-missing SHA256SUMS"
echo "OK: $osarch pair in bin/ under stable names (built via scripts/build-release.sh; dist/ also holds the versioned copies and their SHA256SUMS)"
