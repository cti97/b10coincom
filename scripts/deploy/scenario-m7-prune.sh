#!/usr/bin/env bash
#
# M7 scenario: a PRUNED validator plus a FRESH JOINER, end to end.
#
# What it runs (all on loopback, four fixture-committee validators):
#
#   1. four validators reach a height well past one retention window;
#   2. validator 3 is STOPPED and its data directory is WIPED;
#   3. validator 0 is restarted with --retain-blocks, so it prunes at the first
#      epoch boundary below its window and writes a checkpoint;
#   4. the chain keeps producing while validator 0 is stopped, so 0 is now
#      behind as well as pruned;
#   5. a checkpoint is exported from validator 0's directory (an OFFLINE verb),
#      and validator 3 - an empty directory holding ONLY that checkpoint - is
#      started against the same committee;
#   6. the script waits until the joiner and the pruned node report the SAME
#      height, and compares the state roots character for character.
#
# The assertions are the M7 acceptance criteria, not "it started":
#
#   * the joiner's state root equals the pruned node's at the same height;
#   * the pruned node reported a prune and can be restarted from its own
#     checkpoint;
#   * the data directory's size after pruning is recorded before and after, so
#     the steady-state claim has numbers attached.
#
# FIXTURE KEYS. It uses --validators/--index, whose private keys are derived
# from public seeds. That is development-only and the binary prints the warning;
# never point this at a network beyond your own machine.
#
# Usage:
#   scripts/deploy/scenario-m7-prune.sh                 # on the host, with the checkout
#   scripts/deploy/scenario-m7-prune.sh --docker        # same scenario inside golang:1.27.4-bookworm
#   B10COIN=/path/to/b10coin TARGET_HEIGHT=200 scripts/deploy/scenario-m7-prune.sh
#
set -euo pipefail

# ---------------------------------------------------------------- docker mode
# The Docker harness path: one container, the checkout mounted read-write (the
# build cache is inside it), and the same script re-entered with M7_INNER set so
# it does not recurse. The Go toolchain comes from the image.
if [ "${1:-}" = "--docker" ] && [ "${M7_INNER:-}" = "" ]; then
    if ! command -v docker >/dev/null 2>&1; then
        echo "scenario-m7-prune: --docker asked for, but no docker on PATH" >&2
        exit 2
    fi
    repo=$(cd "$(dirname "$0")/../.." && pwd)
    echo "scenario-m7-prune: running inside golang:1.27.4-bookworm"
    exec docker run --rm \
        -v "$repo":/src -w /src \
        -e M7_INNER=1 -e TARGET_HEIGHT="${TARGET_HEIGHT:-}" \
        -e GOFLAGS=-buildvcs=false \
        golang:1.27.4-bookworm bash scripts/deploy/scenario-m7-prune.sh --inner
fi
if [ "${M7_INNER:-}" = "1" ] && [ "${1:-}" = "--inner" ]; then
    shift
fi

# ---------------------------------------------------------------- parameters
N=${N:-4}
# A SHORT fixture epoch. The shipped fixture epoch is 1000 blocks, so the first
# prune could not happen before ~5000 blocks - over an hour at the fixture
# committee's pace (~1 block/s on loopback). --epoch-blocks is the fixture-only
# override the node grew for exactly this scenario; on a real chain the epoch is
# the shared committee document's.
EPOCH=${EPOCH:-20}
RETAIN=${RETAIN:-$((4 * EPOCH))}          # the pruner's floor: four epochs
# The first prune needs head - retain >= one epoch, so a head above
# retain + epoch = 100 blocks here. 400 leaves room for several passes.
TARGET_HEIGHT=${TARGET_HEIGHT:-400}
BASE_HTTP=${BASE_HTTP:-18600}
BASE_P2P=${BASE_P2P:-17600}
WAIT=${WAIT:-600}                         # seconds any single wait may take

ROOT=$(mktemp -d "${TMPDIR:-/tmp}/m7-prune-XXXXXX")
BIN=${B10COIN:-}
PIDS=()
cleanup() {
    local p
    for p in "${PIDS[@]:-}"; do
        [ -n "$p" ] && kill "$p" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    echo "scenario-m7-prune: logs and data kept in $ROOT"
}
trap cleanup EXIT

die() { echo "scenario-m7-prune: FAIL: $*" >&2; exit 1; }
say() { echo "== $*"; }

if [ -z "$BIN" ]; then
    say "building b10coin"
    ( cd "$(dirname "$0")/../.." && go build -o "$ROOT/b10coin" ./cmd/b10coin )
    BIN=$ROOT/b10coin
fi
[ -x "$BIN" ] || die "$BIN is not executable"
"$BIN" version --short >/dev/null || die "$BIN does not run"

# ---------------------------------------------------------------- helpers
# status_field PORT FIELD: one /status value, or empty when the node is not up.
# It ALWAYS returns 0: a node that is not answering is an empty value, not an
# error, and `set -e` would otherwise abort the script the moment a node is
# stopped - which is every restart in this scenario.
status_field() {
    local port=$1 field=$2
    curl -fsS --max-time 2 "http://127.0.0.1:${port}/status" 2>/dev/null \
        | grep -o "\"${field}\":[[:space:]]*\"\?[A-Za-z0-9_-]*\"\?" \
        | head -1 | sed 's/.*:[[:space:]]*//; s/"//g' || true
    return 0
}

# node_peers INDEX: every other validator's P2P address.
node_peers() {
    local self=$1 i out=""
    for ((i = 0; i < N; i++)); do
        [ "$i" -eq "$self" ] && continue
        out="${out}${out:+,}127.0.0.1:$((BASE_P2P + i))"
    done
    printf '%s' "$out"
}

# start_node INDEX LOGFILE [extra args...]
start_node() {
    local idx=$1 log=$2
    shift 2
    "$BIN" node \
        --dir "$ROOT/v$idx" \
        --http "127.0.0.1:$((BASE_HTTP + idx))" \
        --listen "127.0.0.1:$((BASE_P2P + idx))" \
        --peers "$(node_peers "$idx")" \
        --allow-local-peer-hints \
        --validators "$N" --index "$idx" --epoch-blocks "$EPOCH" \
        "$@" >>"$log" 2>&1 &
    PIDS+=("$!")
    echo "$!" >"$ROOT/v$idx.pid"
}

# stop_node INDEX: stop the process started for that validator.
#
# "Did it stop" is asked by REAPING it, not by polling kill -0: a child bash has
# not waited for yet is a zombie, and kill -0 succeeds for a zombie. A consensus
# node also drains an in-flight BLOCK_SYNC pull before it exits, so the grace is
# generous and a hard kill is the last resort (the store is crash-safe, but a
# killed writer costs a torn-tail repair on the next start for no reason).
stop_node() {
    local idx=$1 pidfile="$ROOT/v$1.pid" pid watcher
    [ -f "$pidfile" ] || return 0
    pid=$(cat "$pidfile")
    kill "$pid" 2>/dev/null || true
    # A watcher that hard-kills after 30 s, and that is told to STAND DOWN by a
    # flag file once the node has exited - so it is never killed itself, and
    # bash prints no job-control noise over the scenario's output.
    local flag="$ROOT/stop.$pid.flag"
    rm -f "$flag"
    ( for _ in $(seq 1 300); do
        [ -f "$flag" ] && exit 0
        sleep 0.1
      done
      kill -9 "$pid" 2>/dev/null ) &
    watcher=$!
    wait "$pid" 2>/dev/null || true
    : >"$flag"
    wait "$watcher" 2>/dev/null || true
    rm -f "$pidfile" "$flag"
}

# wait_height INDEX MIN: wait until that validator reports height >= MIN.
wait_height() {
    local idx=$1 want=$2 port=$((BASE_HTTP + $1)) h deadline=$((SECONDS + WAIT))
    while [ "$SECONDS" -lt "$deadline" ]; do
        h=$(status_field "$port" height)
        if [ -n "$h" ] && [ "$h" -ge "$want" ]; then
            echo "$h"
            return 0
        fi
        sleep 0.5
    done
    die "validator $idx did not reach height $want in ${WAIT}s (last: ${h:-unreachable})"
}

dir_bytes() { du -sk "$1" | awk '{print $1 * 1024}'; }

# ---------------------------------------------------------------- the scenario
say "fixture committee: $N validators, epoch $EPOCH, retention $RETAIN blocks, target height $TARGET_HEIGHT"
mkdir -p "$ROOT"
for ((i = 0; i < N; i++)); do
    start_node "$i" "$ROOT/v$i.log"
done

h=$(wait_height 0 "$TARGET_HEIGHT")
say "chain reached height $h on all four validators"

# The future joiner is stopped and WIPED: everything it had is gone, which is
# the "disk died" case M7 must survive.
say "wiping validator 3 (the joiner) so it has NO history"
stop_node 3
rm -rf "$ROOT/v3"

# Restart validator 0 with retention. It prunes on the first commit it makes,
# after writing the checkpoint for its horizon.
say "restarting validator 0 with --retain-blocks $RETAIN"
before_bytes=$(dir_bytes "$ROOT/v0")
stop_node 0
start_node 0 "$ROOT/v0.prune.log" --retain-blocks "$RETAIN"

# The prune line appears at most once per epoch; wait for it rather than guess.
prune_deadline=$((SECONDS + WAIT))
while [ "$SECONDS" -lt "$prune_deadline" ]; do
    if grep -q "pruned history below height" "$ROOT/v0.prune.log" 2>/dev/null; then
        break
    fi
    sleep 0.5
done
grep -q "pruned history below height" "$ROOT/v0.prune.log" \
    || die "validator 0 never pruned; log: $(tail -3 "$ROOT/v0.prune.log" 2>/dev/null)"
prune_line=$(grep "pruned history below height" "$ROOT/v0.prune.log" | head -1)
say "validator 0: $prune_line"

# The horizon's certificate was recorded BEFORE the prune could run (the
# exporter refuses without it), so nothing more has to arrive first.
horizon=$(echo "$prune_line" | sed 's/.*checkpoint at height //; s/[^0-9].*//')
[ -n "$horizon" ] || die "could not parse the checkpoint height from: $prune_line"

# The export is OFFLINE: stop validator 0 first, or the directory lock refuses.
say "exporting a checkpoint at height $horizon from validator 0"
stop_node 0
"$BIN" checkpoint export --dir "$ROOT/v0" --at "$horizon" \
    --validators "$N" --epoch-blocks "$EPOCH" --out "$ROOT/cp.json" 2>"$ROOT/export.log" \
    || die "checkpoint export failed: $(cat "$ROOT/export.log")"
[ -s "$ROOT/cp.json" ] || die "checkpoint export wrote nothing"
v0_bytes=$(dir_bytes "$ROOT/v0")
say "validator 0 data directory: $before_bytes bytes before pruning, $v0_bytes after (checkpoint height $horizon)"

# Restart validator 0 (it must resume from its own checkpoint) and start the
# joiner from the checkpoint ALONE.
say "restarting validator 0 (resumes from its own checkpoint) and starting the joiner from cp.json alone"
start_node 0 "$ROOT/v0.after.log"
start_node 3 "$ROOT/v3.log" --checkpoint "$ROOT/cp.json"

# The joiner starts at the checkpoint's height and pulls everything above it.
target=$((horizon + 1))
wait_height 3 "$target" >/dev/null
say "joiner resumed at height >= $horizon and is pulling"

# Wait for agreement AT A SINGLE HEIGHT. Production continues while the joiner
# catches up, so sampling both heights once can catch them one block apart; the
# loop asks until one sample holds both at the same height with a root.
deadline=$((SECONDS + WAIT))
while [ "$SECONDS" -lt "$deadline" ]; do
    h0=$(status_field "$((BASE_HTTP + 0))" height)
    h3=$(status_field "$((BASE_HTTP + 3))" height)
    if [ -n "$h0" ] && [ -n "$h3" ] && [ "$h0" = "$h3" ]; then
        break
    fi
    sleep 0.5
done
[ -n "${h0:-}" ] && [ -n "${h3:-}" ] || die "validators stopped answering /status"
r0=$(status_field "$((BASE_HTTP + 0))" state_root)
r3=$(status_field "$((BASE_HTTP + 3))" state_root)
[ -n "$r0" ] && [ -n "$r3" ] || die "missing state roots ($r0 / $r3)"

say "pruned node    height $h0  state root $r0"
say "fresh joiner   height $h3  state root $r3"
if [ "$h0" != "$h3" ]; then
    die "heights differ: pruned node $h0, joiner $h3"
fi
if [ "$r0" != "$r3" ]; then
    die "STATE ROOTS DIFFER at height $h0: pruned node $r0, joiner $r3"
fi
say "OK: the fresh joiner recovered from a checkpoint alone and holds the same state root at the same height"
say "disk: $before_bytes bytes before any pruning, $v0_bytes after the prune, $TARGET_HEIGHT blocks in (retention $RETAIN)"
