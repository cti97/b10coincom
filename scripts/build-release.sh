#!/bin/sh
# Build BOTH binaries for EVERY supported target into dist/ and checksum what
# was built. This is the ONE build story (Makefile's `release`, ci.yml's
# release job, and scripts/deploy/build.sh all go through it — the Pi recipe's
# `make arm64` line this replaces was a special case of it).
#
# Output layout (per artifact, version from internal/version — the binary
# itself prints it, so the names cannot disagree with what the binaries say):
#
#   dist/b10coin-<version>-<os>-<arch>[.exe]
#   dist/b10coin-relay-<version>-<os>-<arch>[.exe]
#   dist/SHA256SUMS
#
# Rules a usable release keeps:
#   - Windows artifacts end in .exe.
#   - dist/ starts EMPTY every run and is swapped in only after EVERYTHING
#     succeeds, so a failing run cannot leave a partial dist/ behind.
#   - The artifact count must equal the target count — a build that silently
#     produced only the host platform fails here with a named target.
#   - Every artifact is asserted with file(1) to report its own architecture,
#     so "compiled" cannot mean "host build renamed". The assertion demands a
#     FORMAT token and an ARCHITECTURE token in ANY ORDER, because file(1)
#     implementations word the same binary differently: Apple's file prints
#     "Mach-O 64-bit executable x86_64" while upstream libmagic (every Linux,
#     i.e. the CI release job) prints "Mach-O 64-bit x86_64 executable".
#   - REPRODUCIBLE: every artifact is built with `-trimpath` (no checkout path
#     baked into the binary) and `-buildvcs=false` (no VCS revision or dirty
#     flag embedded), so two builds from the same clean tree on the same
#     toolchain produce byte-identical files. dist/BUILD-INFO records the
#     toolchain that actually ran and the exact flags, because go.mod's `go`
#     and `toolchain` lines are a MINIMUM the go command may upgrade past.
#   - SIGNING BOUNDARY: SHA256SUMS is signed only when the operator supplies a
#     minisign secret key (B10COIN_RELEASE_SIGN_KEY); the repository never
#     contains one and the script never generates one. With no key the release
#     is completed and dist/SHA256SUMS is UNSIGNED, stated loudly at the end.
set -eu

cd "$(dirname "$0")/.."

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

# The six supported targets. Each pair (os/arch) is what `go build` names;
# nothing here is inferred from the host, so the list is the matrix.
targets_all="darwin/amd64 darwin/arm64 linux/amd64 linux/arm64 windows/amd64 windows/arm64"

# The reproducible-build flags every artifact is built with (audit B-2):
# -trimpath records no checkout path, and -buildvcs=false records no VCS
# revision or dirty flag, so the toolchain has no host-specific input left to
# embed. They are one variable so the build line and dist/BUILD-INFO cannot
# disagree about what was actually passed.
goflags="-trimpath -buildvcs=false"

# Optional subset: `--only <os>/<arch>` for recipes that want exactly one
# target (the Pi deployment build). The argument must name a DECLARED target,
# or the script refuses: a typo must fail loudly, not silently build nothing
# that the caller then mistakes for a release.
only=""
if [ $# -gt 0 ]; then
    [ $# -eq 2 ] || fail "usage: $0 [--only <os>/<arch>]"
    [ "$1" = "--only" ] || fail "usage: $0 [--only <os>/<arch>]"
    only="$2"
    printf '%s\n' "$targets_all" | tr ' ' '\n' | grep -Fxq "$only" ||
        fail "--only '$only' is not a declared target (one of: $targets_all)"
    targets="$only"
else
    targets="$targets_all"
fi

ntargets=$(printf '%s\n' $targets | wc -l | tr -d ' ')
expected=$((ntargets * 2))

# The version comes from internal/version, read the only way that guarantees
# it: ask the binary that `go build` produces from the same package. No
# ldflags, no second constant, no parsing the source.
version=$(go run ./cmd/b10coin version) || fail "cannot read the version from internal/version (go run ./cmd/b10coin version failed)"
printf '%s' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' ||
    fail "internal/version reported '$version', which is not semver x.y.z"

# Fresh start: no stale dist/ and no stale staging. If any step below fails,
# the leftover staging directory is removed and dist/ DOES NOT EXIST — a
# person seeing dist/ after a failed run must be seeing a complete one.
start=$(pwd)
stage="$start/.release-stage"
rm -rf dist "$stage"
trap 'rm -rf "$stage"' EXIT HUP INT TERM
mkdir -p "$stage"

for t in $targets; do
    os=${t%/*}
    arch=${t#*/}
    suffix=""
    [ "$os" = "windows" ] && suffix=".exe"
    for pair in "b10coin ./cmd/b10coin" "b10coin-relay ./cmd/b10coin-relay"; do
        name=${pair%% *}
        main=${pair#* }
        echo "build $name $os/$arch"
        env CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
            go build $goflags -o "$stage/$name-$version-$os-$arch$suffix" "$main" ||
            fail "building $name for $os/$arch"
    done
done

# Count: every target must yield exactly both binaries. THE assertion a
# silently-shrinking matrix cannot pass.
built=$(ls "$stage" | wc -l | tr -d ' ')
if [ "$built" -ne "$expected" ]; then
    ls "$stage" >&2 || true
    fail "built $built artifacts for $ntargets target(s), want $expected (2 per target) - a target failed to produce its pair"
fi

# Names: each target's pair must exist under its declared name (count alone
# cannot catch a target built under another target's name).
for t in $targets; do
    for name in b10coin b10coin-relay; do
        arch=${t#*/}
        os=${t%/*}
        suffix=""
        [ "$os" = "windows" ] && suffix=".exe"
        [ -f "$stage/$name-$version-$os-$arch$suffix" ] ||
            fail "missing artifact $name-$version-$os-$arch$suffix in dist/"
    done
done

# Architecture: every artifact must really be what its name claims, per
# file(1) — the same per-file discipline scripts/deploy/build.sh keeps. If
# file(1) is unavailable the script fails: an unasserted release is not a
# release.
#
# The assertion is TOKEN-BASED, not sentence-based. file(1) implementations
# disagree on where the CPU goes (see the header note), so demanding a fixed
# sentence only pins the check to one vendor's wording. Instead each target
# requires a format token (Mach-O / ELF / PE32+) AND its architecture token
# (x86_64, arm64, x86-64, aarch64), wherever they sit in the output. The
# tokens are what varies per TARGET; the order is what varies per file(1)
# IMPLEMENTATION — so this stays a real assertion (an x86_64 binary never
# reports arm64, an ELF never reports Mach-O) while being portable across
# vendors. Arch tokens are matched case-insensitively because implementations
# capitalize the 64-bit ARM name differently (arm64/Aarch64/AArch64).
command -v file >/dev/null 2>&1 ||
    fail "file(1) is required to assert the artifacts really match their targets"
for t in $targets; do
    os=${t%/*}
    arch=${t#*/}
    suffix=""
    [ "$os" = "windows" ] && suffix=".exe"
    case "$os/$arch" in
        darwin/amd64)  fmt="Mach-O" tok="x86_64"  ;;
        darwin/arm64)  fmt="Mach-O" tok="arm64"   ;;
        linux/amd64)   fmt="ELF"    tok="x86-64"  ;;
        linux/arm64)   fmt="ELF"    tok="aarch64" ;;
        windows/amd64) fmt="PE32+"  tok="x86-64"  ;;
        windows/arm64) fmt="PE32+"  tok="aarch64" ;;
        *)             fail "no arch assertion for $os/$arch" ;;
    esac
    for name in b10coin b10coin-relay; do
        f="$stage/$name-$version-$os-$arch$suffix"
        got=$(file "$f" 2>&1)
        if ! printf '%s\n' "$got" | grep -q -- "$fmt"; then
            echo "FAIL: $f does not report the $fmt format its $os/$arch name claims:" >&2
            echo "$got" >&2
            exit 1
        fi
        if ! printf '%s\n' "$got" | grep -iq -- "$tok"; then
            echo "FAIL: $f does not report the $tok architecture its $os/$arch name claims:" >&2
            echo "$got" >&2
            exit 1
        fi
    done
done

# Record HOW the artifacts were built (audit B-2). go.mod's `go` and
# `toolchain` lines are a MINIMUM the go command may upgrade past, so the only
# honest record of the toolchain that produced these bytes is what the go
# command reports here; the flags are the variable the build line used, so the
# record cannot drift from the build. BUILD-INFO is metadata, not an artifact:
# SHA256SUMS below covers the binaries only, exactly the set `sha256sum -c`
# verifies in dist/ and in the deployment recipe.
toolchain=$(go version) || fail "go version failed; cannot record the toolchain that built the release"
goversion=$(go env GOVERSION) || fail "go env GOVERSION failed; cannot record the toolchain version"
{
    printf 'toolchain %s\n' "$toolchain"
    printf 'go-env-goversion %s\n' "$goversion"
    printf 'flags %s\n' "$goflags"
    printf 'version %s\n' "$version"
} > "$stage/BUILD-INFO" || fail "recording BUILD-INFO failed"

# Checksums over EVERY artifact, relative to dist/ so `shasum -a 256 -c`
# (or `sha256sum -c`) verifies inside the directory with no flag gymnastics.
# They are generated AND verified while everything still sits in the staging
# directory: dist/ is installed only after the sums WRITE and VERIFY, so a
# checksum failure leaves no dist/ at all (the swap-in-last rule above applies
# to this step too, not only to the builds).
if command -v sha256sum >/dev/null 2>&1; then
    sum="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
    sum="shasum -a 256"
else
    fail "neither sha256sum nor shasum is available to write SHA256SUMS"
fi
( cd "$stage" && $sum b10coin-* > SHA256SUMS ) || fail "writing SHA256SUMS failed"

lines=$(wc -l < "$stage/SHA256SUMS" | tr -d ' ')
if [ "$lines" -ne "$expected" ]; then
    fail "SHA256SUMS covers $lines artifacts, want $expected"
fi

# Every line must VERIFY against the artifact it names — the sums file is the
# release's contract with `sha256sum -c`, so it must actually hold for these
# bytes before the directory is installed. (Still in staging; dist/ appears
# only below.)
( cd "$stage" && $sum -c SHA256SUMS >/dev/null ) ||
    fail "SHA256SUMS does not verify against the artifacts it names"

# THE SIGNING BOUNDARY (audit B-2). SHA256SUMS is signed with minisign ONLY
# when the operator supplies a secret key in B10COIN_RELEASE_SIGN_KEY. This
# repository contains no key and this script never generates, stores or guesses
# one: a committed signing key would be no better than no signature. What the
# user must supply, once, OUT OF BAND:
#   1. install minisign (https://jedisct1.github.io/minisign/), an external
#      tool deliberately not a Go dependency of this module;
#   2. `minisign -G -p b10coin.pub -s b10coin.key` (or use an existing key) and
#      publish b10coin.pub where verifiers can find it;
#   3. export B10COIN_RELEASE_SIGN_KEY=/abs/path/to/b10coin.key and run
#      `make release`, or hand the same variable to CI from a repository secret
#      (see .github/workflows/ci.yml). A passphrase-protected key prompts on
#      stdin, so CI needs an unencrypted key or an interactive runner; that
#      trade-off is the operator's to make.
# With no key the release still completes and dist/SHA256SUMS is UNSIGNED. The
# note below states loudly which of the two happened.
signing="UNSIGNED"
if [ -n "${B10COIN_RELEASE_SIGN_KEY:-}" ]; then
    [ -f "$B10COIN_RELEASE_SIGN_KEY" ] ||
        fail "B10COIN_RELEASE_SIGN_KEY is set but '$B10COIN_RELEASE_SIGN_KEY' is not a file"
    command -v minisign >/dev/null 2>&1 ||
        fail "B10COIN_RELEASE_SIGN_KEY is set but minisign is not installed (see https://jedisct1.github.io/minisign/)"
    minisign -Sm "$stage/SHA256SUMS" -s "$B10COIN_RELEASE_SIGN_KEY" -t "b10coin $version release" >/dev/null ||
        fail "minisign failed to sign SHA256SUMS"
    [ -f "$stage/SHA256SUMS.minisig" ] ||
        fail "minisign reported success but wrote no SHA256SUMS.minisig"
    signing="signed (SHA256SUMS.minisig)"
fi

# Last step: install the staging directory as dist/. Nothing after this can fail.
mv "$stage" dist

echo "OK: $expected release artifacts for $ntargets target(s) in dist/ (version $version from internal/version), SHA256SUMS covers all; release $signing"
if [ "$signing" = "UNSIGNED" ]; then
    echo "NOTE: dist/SHA256SUMS is UNSIGNED. Install minisign and set B10COIN_RELEASE_SIGN_KEY to sign it (see this script's header); never commit the key." >&2
fi
