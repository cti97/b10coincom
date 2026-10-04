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
# see without opening dist/).
for f in "bin/b10coin-$os-$arch$ext" "bin/b10coin-relay-$os-$arch$ext"; do
    case "$os/$arch" in
        darwin/amd64)  want="Mach-O 64-bit executable x86_64" ;;
        darwin/arm64)  want="Mach-O 64-bit executable arm64" ;;
        linux/amd64)   want="ELF 64-bit LSB.*x86-64" ;;
        linux/arm64)   want="ELF 64-bit LSB.*ARM aarch64" ;;
        windows/amd64) want="PE32+ executable.*x86-64" ;;
        windows/arm64) want="PE32+ executable.*Aarch64" ;;
    esac
    if ! file "$f" | grep -q "$want"; then
        echo "FAIL: $f is not the $osarch artifact it is named for:" >&2
        file "$f" >&2 || true
        exit 1
    fi
done

file bin/b10coin-"$os"-"$arch$ext" bin/b10coin-relay-"$os"-"$arch$ext"
echo "OK: $osarch pair in bin/ under stable names (built via scripts/build-release.sh; dist/ also holds the versioned copies and their SHA256SUMS)"
