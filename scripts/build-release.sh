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
#     so "compiled" cannot mean "host build renamed".
set -eu

cd "$(dirname "$0")/.."

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

# The six supported targets. Each pair (os/arch) is what `go build` names;
# nothing here is inferred from the host, so the list is the matrix.
targets_all="darwin/amd64 darwin/arm64 linux/amd64 linux/arm64 windows/amd64 windows/arm64"

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
            go build -o "$stage/$name-$version-$os-$arch$suffix" "$main" ||
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
command -v file >/dev/null 2>&1 ||
    fail "file(1) is required to assert the artifacts really match their targets"
for t in $targets; do
    os=${t%/*}
    arch=${t#*/}
    suffix=""
    [ "$os" = "windows" ] && suffix=".exe"
    case "$os/$arch" in
        darwin/amd64)  want="Mach-O 64-bit executable x86_64" ;;
        darwin/arm64)  want="Mach-O 64-bit executable arm64" ;;
        linux/amd64)   want="ELF 64-bit LSB.*x86-64" ;;
        linux/arm64)   want="ELF 64-bit LSB.*ARM aarch64" ;;
        windows/amd64) want="PE32+ executable.*x86-64" ;;
        windows/arm64) want="PE32+ executable.*Aarch64" ;;
        *)             fail "no arch assertion for $os/$arch" ;;
    esac
    for name in b10coin b10coin-relay; do
        f="$stage/$name-$version-$os-$arch$suffix"
        if ! file "$f" | grep -q "$want"; then
            echo "FAIL: $f does not report $os/$arch (wanted: $want):" >&2
            file "$f" >&2 || true
            exit 1
        fi
    done
done

# Checksums over EVERY artifact, relative to dist/ so `shasum -a 256 -c`
# (or `sha256sum -c`) verifies inside the directory with no flag gymnastics.
if command -v sha256sum >/dev/null 2>&1; then
    sum="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
    sum="shasum -a 256"
else
    fail "neither sha256sum nor shasum is available to write SHA256SUMS"
fi
mv "$stage" dist
( cd dist && $sum b10coin-* > SHA256SUMS )

lines=$(wc -l < dist/SHA256SUMS | tr -d ' ')
if [ "$lines" -ne "$expected" ]; then
    fail "SHA256SUMS covers $lines artifacts, want $expected"
fi

echo "OK: $expected release artifacts for $ntargets target(s) in dist/ (version $version from internal/version), SHA256SUMS covers all"
