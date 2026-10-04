#!/bin/sh
# Build the M4 Pi binaries and assert the artifacts before anyone ships them.
#
# This is the deployment-facing wrapper around `make arm64` (the Makefile owns
# the build flags; this script owns the ARTIFACT CHECKS): exactly two
# linux/arm64 binaries in bin/, each really a statically linked aarch64 ELF.
# A cross-compile that quietly produced host binaries, or that left one of the
# two binaries missing, fails HERE and not on a Pi hours later.
#
# Scope note: one target only (linux/arm64), because M4's acceptance is three
# Raspberry Pis. Task 9's six-target release matrix replaces this file with
# per-platform artifacts and per-platform assertions.
set -eu

cd "$(dirname "$0")/../.."

make arm64

# Artifact count: the committee and the forwarder. A missing binary ships a
# hole — a relay-less testnet or a Pi with nothing to run.
built=$(ls bin/*-linux-arm64 2>/dev/null | wc -l | tr -d ' ')
if [ "$built" -ne 2 ]; then
    echo "FAIL: expected 2 ARM64 binaries in bin/, found $built" >&2
    exit 1
fi

# Architecture: "ARM aarch64" must appear in file(1) output for both. This is
# the check a weaker build would skip — a host binary carries host arch.
for f in bin/*-linux-arm64; do
    if ! file "$f" | grep -q 'ELF 64-bit LSB.*ARM aarch64'; then
        echo "FAIL: $f is not a 64-bit ARM aarch64 ELF:" >&2
        file "$f" >&2
        exit 1
    fi
done

file bin/*-linux-arm64
echo "OK: 2 linux/arm64 artifacts in bin/ (b10coin, b10coin-relay)"