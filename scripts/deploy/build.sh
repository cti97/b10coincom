#!/bin/sh
# The deployment-facing wrapper the Pi recipe (scripts/deploy/README.md) runs:
# it builds BOTH binaries for ONE target through the ONE build story —
# scripts/build-release.sh — and then copies the pair into bin/ under the
# STABLE, unversioned names the recipe's scp lines copy forever:
#
#     scripts/deploy/build.sh                 → bin/b10coin-linux-arm64       (+ relay)  — the Pis
#     scripts/deploy/build.sh linux/amd64     → bin/b10coin-relay-linux-amd64            — the e.g. amd64 VPS
#
# Each run also writes bin/SHA256SUMS-<os>-<arch> covering EXACTLY the two files
# that run built (never a glob over bin/, which is what let a stale binary pick
# up a fresh checksum — audit S-11), and signs it when B10COIN_RELEASE_SIGN_KEY
# is set, so the recipe can verify both identity and provenance on the target.
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

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

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

# A checksum file over the STABLE names, so the recipe can copy one to each
# machine and verify what it copied ON THE TARGET (audit B-2; the README told
# operators to verify and gave them nothing to verify against).
#
# It covers EXACTLY the two files this run just built, named explicitly — never
# `b10coin-*` (audit S-11). That glob was the defect, not a shortcut: bin/
# survives between runs, so a week-old leftover binary in it got a fresh, valid
# checksum, and "verified on the target" then proved only that the bytes had
# not rotted — not that any build had produced them. A checksum file must
# describe a BUILD, not a directory listing.
#
# PER TARGET rather than one shared bin/SHA256SUMS: two invocations (the Pi
# pair, then the amd64 relay for a VPS) would otherwise either overwrite each
# other's evidence or merge pairs from different builds into one file that
# vouches for both. `SHA256SUMS-<os>-<arch>` is written by the run that
# produced those bytes and by nothing else.
sums="SHA256SUMS-$os-$arch"
# Remove this target's PREVIOUS file first, so a run that fails below cannot
# leave an older checksum file describing binaries this run has overwritten.
rm -f "bin/$sums" "bin/$sums.minisig"

if command -v sha256sum >/dev/null 2>&1; then
    sum="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
    sum="shasum -a 256"
else
    fail "neither sha256sum nor shasum is available to write bin/$sums"
fi
( cd bin && $sum "b10coin-$os-$arch$ext" "b10coin-relay-$os-$arch$ext" > "$sums" ) ||
    fail "writing bin/$sums failed"
lines=$(wc -l < "bin/$sums" | tr -d ' ')
[ "$lines" -eq 2 ] ||
    fail "bin/$sums covers $lines artifact(s), want 2 (exactly the $osarch pair this run built)"
# The file must hold for these bytes before it is offered as evidence.
( cd bin && $sum -c "$sums" >/dev/null ) ||
    fail "bin/$sums does not verify against the artifacts it names"

# SIGNING (audit S-11): sign the checksum file when the operator supplies a
# key, with the same discipline as scripts/build-release.sh — no key, no
# signature, stated loudly at the end; key set and no .minisig is a FAILURE,
# not a quiet downgrade. The signature is what turns "these bytes did not rot
# in transit" into "these bytes came from the holder of this key", which is the
# only claim that survives the build machine itself being untrusted.
signing="UNSIGNED"
if [ -n "${B10COIN_RELEASE_SIGN_KEY:-}" ]; then
    [ -f "$B10COIN_RELEASE_SIGN_KEY" ] ||
        fail "B10COIN_RELEASE_SIGN_KEY is set but '$B10COIN_RELEASE_SIGN_KEY' is not a file"
    command -v minisign >/dev/null 2>&1 ||
        fail "B10COIN_RELEASE_SIGN_KEY is set but minisign is not installed (see https://jedisct1.github.io/minisign/)"
    minisign -Sm "bin/$sums" -s "$B10COIN_RELEASE_SIGN_KEY" -t "b10coin deploy artifacts $osarch" >/dev/null ||
        fail "minisign failed to sign bin/$sums"
    [ -f "bin/$sums.minisig" ] ||
        fail "minisign reported success but wrote no bin/$sums.minisig"
    signing="signed (bin/$sums.minisig)"
fi

printf 'checksums  bin/%s covers exactly the pair this run built: %s %s\n' \
    "$sums" "b10coin-$os-$arch$ext" "b10coin-relay-$os-$arch$ext"
echo "verify on the target BEFORE installing, naming the file you copied: the block form is"
echo "in scripts/deploy/README.md section 2, and it is the single source for that command."
echo "Do NOT use --ignore-missing, and do NOT pipe grep straight into 'sha256sum -c': GNU's"
echo "-c exits 0 on EMPTY input, so either would PASS when the entry is missing."
if [ "$signing" = "UNSIGNED" ]; then
    echo "NOTE: bin/$sums is UNSIGNED (no B10COIN_RELEASE_SIGN_KEY); export it, as for make release, to sign this file too." >&2
fi
echo "OK: $osarch pair in bin/ under stable names (built via scripts/build-release.sh; dist/ also holds the versioned copies and their SHA256SUMS); release $signing"
