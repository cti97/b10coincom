#!/bin/sh
# Build the wallet's WebAssembly signer.
#
# The wallet signs with the repository's own transaction builder (internal/wallet)
# compiled to wasm, not with a JavaScript re-implementation of the envelope: a
# second encoder is a second definition of the wire format, and its failure mode
# - a signature over a hash the node never computes - is invisible until a
# transaction is rejected on the wire.
#
# Outputs into dist/:
#   b10coin-wasm.wasm   the signer (loaded by the wallet page/extension)
#   wasm_exec.js        Go's runtime shim for the browser, copied from GOROOT so
#                       the pair can never drift apart
#
# Usage: scripts/build-wasm.sh [outdir]
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-"$root/bin/wasm"}
mkdir -p "$out"

GOOS=js GOARCH=wasm go build -o "$out/b10coin-wasm.wasm" ./cmd/b10coin-wasm

shim="$(go env GOROOT)/lib/wasm/wasm_exec.js"
[ -f "$shim" ] || shim="$(go env GOROOT)/misc/wasm/wasm_exec.js"
[ -f "$shim" ] || { echo "build-wasm: no wasm_exec.js under $(go env GOROOT)" >&2; exit 1; }
cp "$shim" "$out/wasm_exec.js"

printf '%s\n' "built $out/b10coin-wasm.wasm and wasm_exec.js"
ls -lh "$out/b10coin-wasm.wasm" "$out/wasm_exec.js"
