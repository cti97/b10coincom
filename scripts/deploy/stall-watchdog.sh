#!/bin/sh
# stall-watchdog.sh - restart this validator when it is wedged at one height.
#
# Why this exists
# ---------------
# A round divergence (seats sitting in different rounds at the same height)
# cannot commit, and the round ladder's tail is minutes to effectively never
# (catching up from round r needs ~r*base + step*r^2/2). The documented
# recovery is: stop the seat, delete `rounds.log` (liveness state ONLY), start
# it again - the seat re-enters at round 0 and the committee converges in
# seconds. On 2026-11-27 that had to be done by hand on three machines, after
# a laptop restart removed a seat for two hours and the chain stopped.
#
# This script makes that recovery automatic and local: each host watches its
# own node and heals itself. No cross-host coordination is needed because a
# restart at round 0 is exactly the state the committee converges from.
#
# Safety
# ------
# * `locks.log` is NEVER touched - it is the double-vote safety record.
# * `rounds.log` is moved aside, not deleted, so the evidence survives.
# * A cooldown stops it from thrashing a chain that is merely slow.
# * If the RPC is unreachable the node is left alone: a dead RPC is a dead
#   process (or a starting one), and the supervisor's job is to restart that,
#   not this script's.
#
# Usage
#   stall-watchdog.sh [--dry-run] [--max-stall N] [--cooldown N] [--rpc URL] [--dir DIR]
#
#   --max-stall N   seconds at one height before acting   (default 900 = 15 min)
#   --cooldown N    minimum seconds between restarts      (default 1800 = 30 min)
#   --rpc URL       node RPC                              (default http://127.0.0.1:8645)
#   --dir DIR       node data dir                         (default /var/lib/b10coin, or
#                                                          ~/b10coin-node on macOS)
#   --dry-run       report what it would do, change nothing
#
# Exit codes: 0 nothing to do, 10 the node was restarted, 1 usage/IO error.

set -u

MAX_STALL=900
COOLDOWN=1800
RPC="http://127.0.0.1:8645"
DRY_RUN=0
case "$(uname -s)" in
  Darwin) DIR="$HOME/b10coin-node"; SUPERVISOR="launchd"; LABEL="com.b10coin.node" ;;
  *)      DIR="/var/lib/b10coin";  SUPERVISOR="systemd"; UNIT="b10coin" ;;
esac

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run)   DRY_RUN=1 ;;
    --max-stall) MAX_STALL="$2"; shift ;;
    --cooldown)  COOLDOWN="$2"; shift ;;
    --rpc)       RPC="$2"; shift ;;
    --dir)       DIR="$2"; shift ;;
    *) echo "stall-watchdog: unknown argument $1" >&2; exit 1 ;;
  esac
  shift
done

STATE="$DIR/stall-watchdog.state"
LOG="$DIR/stall-watchdog.log"

log() { printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >>"$LOG"; }

status_height() {
  # /status is JSON; height is the first numeric field we need. No jq on a
  # default Pi, so parse with sed, and fail cleanly when the RPC is down.
  body=$(curl -s -m 5 "$RPC/status" 2>/dev/null) || return 1
  [ -n "$body" ] || return 1
  printf '%s' "$body" | sed -n 's/.*"height"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -1
}

now=$(date +%s)
h=$(status_height) || { log "rpc unreachable at $RPC; leaving the node to its supervisor"; exit 0; }
[ -n "${h:-}" ] || { log "rpc answered without a height; leaving the node alone"; exit 0; }

prev_h=""; prev_since="$now"; last_restart=0
if [ -f "$STATE" ]; then
  prev_h=$(sed -n '1p' "$STATE")
  prev_since=$(sed -n '2p' "$STATE")
  last_restart=$(sed -n '3p' "$STATE")
fi
case "$prev_h" in ''|*[!0-9]*) prev_h=$h ;; esac
case "$prev_since" in ''|*[!0-9]*) prev_since=$now ;; esac
case "$last_restart" in ''|*[!0-9]*) last_restart=0 ;; esac

if [ "$h" != "$prev_h" ]; then
  # The chain moved: reset the stall clock and say so if we were timing one.
  if [ "$prev_h" != "" ] && [ "$((now - prev_since))" -ge 120 ]; then
    log "height moved $prev_h -> $h after $((now - prev_since))s"
  fi
  [ "$DRY_RUN" -eq 1 ] || printf '%s\n%s\n%s\n' "$h" "$now" "$last_restart" >"$STATE"
  exit 0
fi

stalled=$((now - prev_since))
if [ "$stalled" -lt "$MAX_STALL" ]; then
  [ "$DRY_RUN" -eq 1 ] || printf '%s\n%s\n%s\n' "$h" "$prev_since" "$last_restart" >"$STATE"
  exit 0
fi

if [ "$last_restart" -ne 0 ] && [ "$((now - last_restart))" -lt "$COOLDOWN" ]; then
  log "stalled ${stalled}s at height $h, but the last restart was $((now - last_restart))s ago (cooldown ${COOLDOWN}s); waiting"
  exit 0
fi

log "stalled ${stalled}s at height $h; restarting with rounds.log set aside"
if [ "$DRY_RUN" -eq 1 ]; then
  log "dry-run: would stop the node, move $DIR/rounds.log aside and start it again"
  exit 10
fi

stamp=$(date +%s)
if [ -f "$DIR/rounds.log" ]; then
  mv "$DIR/rounds.log" "$DIR/rounds.log.stall-$stamp" && log "rounds.log -> rounds.log.stall-$stamp"
fi

if [ "$SUPERVISOR" = "launchd" ]; then
  # bootout stops it without KeepAlive fighting back; bootstrap starts it again.
  launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null
  sleep 2
  launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/$LABEL.plist" || { log "bootstrap failed"; exit 1; }
else
  systemctl stop "$UNIT" || { log "systemctl stop failed"; exit 1; }
  sleep 2
  systemctl start "$UNIT" || { log "systemctl start failed"; exit 1; }
fi

printf '%s\n%s\n%s\n' "$h" "$now" "$now" >"$STATE"
log "restarted; next check will see whether the committee converges"
exit 10
