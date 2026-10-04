#!/usr/bin/env bash
#
# b10coin M4 acceptance harness — the one command a person runs after the
# three-Pi deployment (scripts/deploy/README.md) to turn their run into
# evidence, and pastes the output of:
#
#     scripts/deploy/acceptance.sh --pis pi-a.local,pi-b.example.net,pi-c.example.net \
#                                  --relay relay.example.net
#
# What it checks, in order:
#
#   1. REACHABILITY  every validator answers RPC GET /status. The RPC binds
#      loopback only (--http default 127.0.0.1:8645), so by default the
#      harness reaches it the way deploy README §7 does: over SSH, curl on
#      the Pi itself. --mode http queries http://host:port directly instead
#      (direct-peer and loopback runs; this is the mode it was verified in).
#   2. ADVANCING    two /status readings --advance-wait seconds apart; a PASS
#      requires EVERY validator's height to have INCREASED. A network that
#      connects but never finalises fails here — height only moves when the
#      committee commits, so reachability alone can never look healthy.
#   3. AGREEMENT    same chain_id everywhere, and ONE block identity: if every
#      second-reading head sits at the same height, those head hashes are
#      compared (the manual bar of README §7.3); otherwise the block at the
#      common height H = min(heights) is read from each node via
#      /block/<H> and the hashes compared. Equal hashes mean the committee
#      finalised one shared chain.
#   4. RELAY        --relay host[:port] (default port 7001) gets a bounded TCP
#      connect probe, FROM THE MACHINE RUNNING THIS SCRIPT (the Pis are what
#      really dial the relay, so a local firewall can mislead — the output
#      says so). Probe failure is its own distinct failure, never folded into
#      the consensus verdict.
#
# The failure modes it separates (fix recipes in deploy README §8), each with
# its own verdict label and exit code:
#
#   UNREACHABLE (exit 1)  a validator gave no parseable /status — wrong
#                         address, node not running, SSH blocked.
#   DISAGREE    (exit 3)  reachable and advancing but NOT one chain: differing
#                         chain IDs (§8 failure 1) or differing block identity
#                         at one height (a fork, or §8 failure 3 — two
#                         machines claiming one seat).
#   STALLED     (exit 2)  all reachable, one chain, but no height moved in the
#                         wait: relay down or no quorum (§8 failures 2/3); a
#                         failed relay probe is named here explicitly.
#   RELAY       (exit 4)  only the relay failed its probe. Not a consensus
#                         problem: if the validators nevertheless advanced and
#                         agreed, the verdict says exactly that.
#   INCONCLUSIVE(exit 5)  agreement could not be READ: a /block/<H> fetch
#                         failed after both status readings succeeded.
#
# Dependencies: bash (/dev/tcp and arrays — present on macOS and Raspberry Pi
# OS; the recipe's §8 already assumes bash) and curl, with wget as the
# automatic fallback when curl is absent (curl preferred and the choice
# printed; B10COIN_FETCH=curl|wget forces one). No other tools: the node's
# /status and /block bodies are flat JSON with known keys, so fields are read
# with sed — no JSON parser, no jq, no python.
#
# Exit codes: 0 PASS, 1 UNREACHABLE, 2 STALLED, 3 DISAGREE, 4 RELAY,
# 5 INCONCLUSIVE, 64 bad usage.

set -u

PROG=$(basename "$0")
HTTP_PORT=8645          # the node's default --http port (deploy README §5)
MODE=ssh                # ssh | http
SSH_USER=pi             # deploy README §2 works as pi@<pi>
ADVANCE_WAIT=15         # seconds between the two readings
PROBE_TIMEOUT=5         # relay TCP probe bound, seconds
RELAY_GIVEN=""
PIS_ARG=""
FETCH_TIMEOUT=8         # per-HTTP-request bound, seconds

usage() {
    cat <<EOF
$PROG — the b10coin M4 acceptance harness (three Pis finalising one chain).

Usage:
  $PROG --pis HOST[,HOST...] [--relay RELAYHOST[:PORT]] [options]

  --pis LIST        comma-separated validators. In ssh mode (default) each
                    entry is [user@]host and its RPC is read over SSH at
                    http://127.0.0.1:<http-port>/status (the RPC is
                    loopback-only). In http mode each entry is host[:port],
                    queried directly — for direct-peer and loopback runs.
  --relay ADDR      the VPS relay from deploy README §4, host[:7001]. Probed
                    with a plain bounded TCP connect from THIS machine. Omit
                    for runs with no relay (direct --peers setups).
Options:
  --mode ssh|http   how to reach each validator's RPC (default: ssh)
  --http-port N     validator RPC port (default $HTTP_PORT)
  --ssh-user NAME   SSH user for validator hosts (default $SSH_USER; a
                    user@host entry in --pis overrides it)
  --advance-wait S  seconds between the two /status readings (default $ADVANCE_WAIT)
  --relay-timeout S bound for the relay TCP probe (default $PROBE_TIMEOUT)
  --help            this text

Environment: B10COIN_FETCH curl|wget forces the HTTP client (default: first
of curl, wget found in PATH). Exit codes: 0 PASS, 1 UNREACHABLE, 2 STALLED,
3 DISAGREE, 4 RELAY, 5 INCONCLUSIVE, 64 usage.
EOF
}

# ---- argument parsing -------------------------------------------------------

die_usage() { echo "$PROG: $1" >&2; echo "Run '$PROG --help' for usage." >&2; exit 64; }

while [ $# -gt 0 ]; do
    case $1 in
        --help|-h) usage; exit 0 ;;
        --pis)   [ $# -ge 2 ] || die_usage "--pis needs a value";           PIS_ARG=$2;      shift 2 ;;
        --pis=*) PIS_ARG=${1#*=};                                                            shift ;;
        --relay) [ $# -ge 2 ] || die_usage "--relay needs a value";         RELAY_GIVEN=$2;  shift 2 ;;
        --relay=*) RELAY_GIVEN=${1#*=};                                                      shift ;;
        --mode)  [ $# -ge 2 ] || die_usage "--mode needs a value";          MODE=$2;         shift 2 ;;
        --mode=*) MODE=${1#*=};                                                              shift ;;
        --http-port) [ $# -ge 2 ] || die_usage "--http-port needs a value"; HTTP_PORT=$2;    shift 2 ;;
        --http-port=*) HTTP_PORT=${1#*=};                                                    shift ;;
        --ssh-user) [ $# -ge 2 ] || die_usage "--ssh-user needs a value";   SSH_USER=$2;     shift 2 ;;
        --ssh-user=*) SSH_USER=${1#*=};                                                      shift ;;
        --advance-wait) [ $# -ge 2 ] || die_usage "--advance-wait needs a value"; ADVANCE_WAIT=$2; shift 2 ;;
        --advance-wait=*) ADVANCE_WAIT=${1#*=};                                              shift ;;
        --relay-timeout) [ $# -ge 2 ] || die_usage "--relay-timeout needs a value"; PROBE_TIMEOUT=$2; shift 2 ;;
        --relay-timeout=*) PROBE_TIMEOUT=${1#*=};                                            shift ;;
        *) die_usage "unknown argument: $1" ;;
    esac
done

case $MODE in ssh|http) ;; *) die_usage "--mode must be ssh or http (got '$MODE')" ;; esac
case $HTTP_PORT in *[!0-9]*|"") die_usage "--http-port must be a number (got '$HTTP_PORT')" ;; esac
[ "$HTTP_PORT" -ge 1 ] && [ "$HTTP_PORT" -le 65535 ] || die_usage "--http-port must be 1..65535"
case $ADVANCE_WAIT in *[!0-9]*|"") die_usage "--advance-wait must be seconds (got '$ADVANCE_WAIT')" ;; esac
[ "$ADVANCE_WAIT" -ge 2 ] || die_usage "--advance-wait must be at least 2 s"
case $PROBE_TIMEOUT in *[!0-9]*|"") die_usage "--relay-timeout must be seconds (got '$PROBE_TIMEOUT')" ;; esac
[ "$PROBE_TIMEOUT" -ge 1 ] || die_usage "--relay-timeout must be at least 1 s"
[ -n "$PIS_ARG" ] || die_usage "--pis is required (comma-separated validator hosts)"

# split --pis on commas into PIS, trimming, dropping empties, rejecting dups
PIS=()
_seen=","
OLDIFS=$IFS; IFS=,
for raw in $PIS_ARG; do
    t=${raw#"${raw%%[![:space:]]*}"}; t=${t%"${t##*[![:space:]]}"}
    [ -n "$t" ] || continue
    case $_seen in *",$t,"*) die_usage "duplicate validator '$t' in --pis" ;; esac
    PIS+=("$t"); _seen="$_seen$t,"
done
IFS=$OLDIFS
[ ${#PIS[@]} -ge 1 ] || die_usage "--pis named no validators"

# ---- helpers ----------------------------------------------------------------

have() { command -v "$1" >/dev/null 2>&1; }

case ${B10COIN_FETCH:-} in
    ""|curl|wget) ;;
    *) die_usage "B10COIN_FETCH must be curl or wget (got '$B10COIN_FETCH')" ;;
esac
if [ -n "${B10COIN_FETCH:-}" ]; then
    FETCH_BIN=$B10COIN_FETCH
    FETCH_NOTE="(forced by B10COIN_FETCH)"
elif have curl; then
    FETCH_BIN=curl; FETCH_NOTE="(wget is the fallback when curl is absent)"
elif have wget; then
    FETCH_BIN=wget; FETCH_NOTE="(curl not found)"
else
    echo "$PROG: need curl or wget to query the validators' RPC; neither is in PATH" >&2
    exit 64
fi

WORK=$(mktemp -d "${TMPDIR:-/tmp}/b10coin-accept.XXXXXX") || { echo "$PROG: cannot create a temp dir" >&2; exit 70; }
trap 'rm -rf "$WORK"' EXIT

LAST_ERR=""; OUT_BODY=""

# clean_err — one-line, whitespace-squeezed text from an error dump file.
# NOTE: '\+' is a GNU sed extension absent from BSD sed; use [x][x]* forms.
clean_err() { tr -d '\n' <"$1" | sed 's/[[:space:]][[:space:]]*/ /g;s/^ //;s/ $//'; }

# jstr BODY KEY / jnum BODY KEY — extract one flat-JSON field with sed only.
# The node's /status and /block schemas are flat and known, so values cannot
# contain quotes or escapes; anything unexpected fails the parse checks in
# read_status instead of being silently misread.
jstr() { printf '%s' "$1" | tr -d '\r' | sed -n 's/.*"'"$2"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1; }
jnum() { printf '%s' "$1" | tr -d '\r' | sed -n 's/.*"'"$2"'"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -n 1; }

# local_fetch URL — sets OUT_BODY; non-zero and LAST_ERR on failure.
local_fetch() {
    local out rc
    if [ "$FETCH_BIN" = curl ]; then
        out=$(curl -sfS -m "$FETCH_TIMEOUT" "$1" 2>"$WORK/fetch.err"); rc=$?
    else
        out=$(wget -q -T "$FETCH_TIMEOUT" -O - "$1" 2>"$WORK/fetch.err"); rc=$?
    fi
    if [ "$rc" -ne 0 ]; then
        LAST_ERR=$(clean_err "$WORK/fetch.err")
        [ -n "$LAST_ERR" ] || LAST_ERR="$FETCH_BIN exited $rc"
        return 1
    fi
    OUT_BODY=$out
    return 0
}

# get_rpc TARGET PATH — one RPC request in the configured mode; sets OUT_BODY.
# ssh mode: [user@]host, and the request runs ON the validator against its
# loopback RPC — exactly the manual check in deploy README §7 step 3.
get_rpc() {
    local target=$1 path=$2 body rc user host tgt url remote
    LAST_ERR=""; OUT_BODY=""
    if [ "$MODE" = http ]; then
        case $target in
            *:*) url="http://$target$path" ;;
            *)   url="http://$target:$HTTP_PORT$path" ;;
        esac
        local_fetch "$url"
        return $?
    fi
    case $target in
        *@*) user=${target%%@*}; host=${target#*@} ;;
        *)   user=""; host=$target ;;
    esac
    tgt=$host
    [ -n "$user" ] && tgt="$user@$host"
    # curl first, wget second, on the Pi itself; accept-new avoids re-typing
    # host keys on first contact but still pins a CHANGED key (OpenSSH >= 7.6,
    # which every supported OS here ships).
    remote="if command -v curl >/dev/null 2>&1; then
    curl -sfS -m $FETCH_TIMEOUT http://127.0.0.1:$HTTP_PORT$path
elif command -v wget >/dev/null 2>&1; then
    wget -q -T $FETCH_TIMEOUT -O - http://127.0.0.1:$HTTP_PORT$path
else
    echo 'neither curl nor wget is installed on the validator' >&2; exit 127
fi"
    body=$(ssh -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new \
        "$tgt" "$remote" 2>"$WORK/ssh.err")
    rc=$?
    if [ "$rc" -ne 0 ]; then
        LAST_ERR=$(clean_err "$WORK/ssh.err")
        [ -n "$LAST_ERR" ] || LAST_ERR="ssh exited $rc"
        return 1
    fi
    OUT_BODY=$body
    return 0
}

# try_rpc TARGET PATH — up to 3 attempts 2 s apart: a node a second behind its
# systemd restart, or one Wi-Fi hiccup, must not read as UNREACHABLE. Sets
# OUT_BODY/LAST_ERR globals (never called in a command substitution).
try_rpc() {
    local attempt=0
    while :; do
        if get_rpc "$1" "$2"; then return 0; fi
        attempt=$((attempt + 1))
        [ "$attempt" -ge 3 ] && return 1
        sleep 2
    done
}

# tcp_probe HOST PORT SECONDS — bounded connect via bash /dev/tcp (no nc, no
# timeout(1): neither is guaranteed on Raspberry Pi OS Lite or macOS). The
# connect runs in a background subshell; a silently filtered host is killed
# after the bound instead of hanging for the kernel's ~75 s TCP give-up.
tcp_probe() {
    local host=$1 port=$2 bound=$3 i=0 pid
    ( : < "/dev/tcp/$host/$port" ) >/dev/null 2>&1 &
    pid=$!
    while kill -0 "$pid" 2>/dev/null && [ "$i" -lt "$bound" ]; do
        sleep 1; i=$((i + 1))
    done
    if kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null
        wait "$pid" 2>/dev/null
        return 1
    fi
    wait "$pid"
}

trunc() { printf '%s' "$1" | head -c 12; }

# ---- per-validator state (parallel arrays) ----------------------------------

N=${#PIS[@]}
CH=(); H1=(); H2=(); B1=(); B2=(); OK1=(); OK2=(); ERR=()
i=0
while [ $i -lt $N ]; do
    CH+=("?"); H1+=(""); H2+=(""); B1+=(""); B2+=(""); OK1+=("no"); OK2+=("no"); ERR+=("")
    i=$((i + 1))
done

# read_status INDEX first|second — GET /status into the arrays.
read_status() {
    local idx=$1 which=$2 cid h hh
    if ! try_rpc "${PIS[$idx]}" /status; then
        ERR[$idx]="no parseable /status after 3 attempts (last: ${LAST_ERR:-unknown})"
        return 1
    fi
    cid=$(jstr "$OUT_BODY" chain_id)
    h=$(jnum "$OUT_BODY" height)
    hh=$(jstr "$OUT_BODY" head_hash)
    if [ -z "$cid" ] || [ -z "$h" ] || [ -z "$hh" ]; then
        ERR[$idx]="reply is not a b10coin /status (missing chain_id/height/head_hash)"
        return 1
    fi
    CH[$idx]=$cid
    if [ "$which" = first ]; then
        H1[$idx]=$h; B1[$idx]=$hh; OK1[$idx]=yes
    else
        H2[$idx]=$h; B2[$idx]=$hh; OK2[$idx]=yes
    fi
    return 0
}

# ---- run --------------------------------------------------------------------

SECOND_RUN=no
echo "=== b10coin M4 acceptance check ==="
echo "time        $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "validators  $N: ${PIS[*]}"
[ "$N" -ge 2 ] || echo "            NOTE: a single validator cannot demonstrate agreement across networks"
if [ "$MODE" = ssh ]; then
    echo "mode        ssh — each validator's RPC is read on its own loopback (port $HTTP_PORT), as in deploy README §7"
else
    echo "mode        http — validators queried directly at http://<host>:$HTTP_PORT"
fi
echo "fetch       $FETCH_BIN $FETCH_NOTE"
echo "advancing   two /status readings ${ADVANCE_WAIT}s apart; a PASS requires every height to INCREASE"

# relay probe — from THIS machine; the Pis dial the relay themselves, so a
# local firewall can produce a false 'unreachable' while the Pis still agree.
RELAY_HOST=""; RELAY_PORT=""; RELAY_STATE=""; RELAY_TXT=""
if [ -n "$RELAY_GIVEN" ]; then
    case $RELAY_GIVEN in
        *:*) RELAY_HOST=${RELAY_GIVEN%:*}; RELAY_PORT=${RELAY_GIVEN##*:} ;;
        *)   RELAY_HOST=$RELAY_GIVEN;      RELAY_PORT=7001 ;;
    esac
    if tcp_probe "$RELAY_HOST" "$RELAY_PORT" "$PROBE_TIMEOUT"; then
        RELAY_STATE=reachable
        RELAY_TXT="TCP connect ok (from THIS machine)"
    else
        RELAY_STATE=UNREACHABLE
        RELAY_TXT="TCP connect to $RELAY_HOST:$RELAY_PORT failed or was filtered within ${PROBE_TIMEOUT}s — probed from THIS machine, not from a Pi"
    fi
else
    RELAY_STATE="not given (no --relay: direct-peer run, relay unchecked)"
fi
echo "relay       ${RELAY_HOST:+$RELAY_HOST:$RELAY_PORT }$RELAY_STATE${RELAY_TXT:+ — $RELAY_TXT}"

echo
echo "-- reading 1 --"
i=0
while [ $i -lt $N ]; do
    if read_status "$i" first; then
        echo "${PIS[$i]}  chain ${CH[$i]}  height ${H1[$i]}  head $(trunc "${B1[$i]}")..."
    else
        echo "${PIS[$i]}  UNREACHABLE — ${ERR[$i]}"
    fi
    i=$((i + 1))
done

ANY_UNREACH=no
i=0
while [ $i -lt $N ]; do
    if [ "${OK1[$i]}" != yes ]; then ANY_UNREACH=yes; fi
    i=$((i + 1))
done

if [ "$ANY_UNREACH" = yes ]; then
    echo
    echo "-- second reading skipped: with a validator unreachable, advancing and agreement cannot be judged --"
else
    SECOND_RUN=yes
    echo "waiting ${ADVANCE_WAIT}s ..."
    sleep "$ADVANCE_WAIT"
    echo "-- reading 2 --"
    i=0
    while [ $i -lt $N ]; do
        if read_status "$i" second; then
            echo "${PIS[$i]}  chain ${CH[$i]}  height ${H1[$i]} -> ${H2[$i]} (+$(( ${H2[$i]} - ${H1[$i]} )))  head $(trunc "${B2[$i]}")..."
        else
            ANY_UNREACH=yes
            echo "${PIS[$i]}  UNREACHABLE at reading 2 — ${ERR[$i]}"
        fi
        i=$((i + 1))
    done
fi

# a validator counts as UNREACHABLE when its first read failed, or when the
# second reading actually ran and its second read failed (readings skipped,
# OK2 stays "no" for healthy validators — that must not count against them).
failed_validator() {
    if [ "${OK1[$1]}" != yes ]; then return 0; fi
    if [ "${SECOND_RUN:-no}" = yes ] && [ "${OK2[$1]}" != yes ]; then return 0; fi
    return 1
}

# ---- judgement ---------------------------------------------------------------

# reached both readings? advanced?
REACHED_BOTH=yes
NOT_ADVANCING=""
i=0
while [ $i -lt $N ]; do
    if [ "${OK1[$i]}" != yes ] || [ "${OK2[$i]}" != yes ]; then
        REACHED_BOTH=no
    elif [ "${H2[$i]}" -le "${H1[$i]}" ]; then
        if [ "${H2[$i]}" -eq "${H1[$i]}" ]; then
            NOT_ADVANCING="$NOT_ADVANCING ${PIS[$i]} (${H1[$i]} -> ${H2[$i]}, +0)"
        else
            NOT_ADVANCING="$NOT_ADVANCING ${PIS[$i]} (height went BACKWARDS: ${H1[$i]} -> ${H2[$i]})"
        fi
    fi
    i=$((i + 1))
done

# agreement: same chain_id everywhere, and one block identity at a common
# height. Sequential reads can straddle a commit, so equality is judged at
# H = min(second-reading heights): if every head sits at H the heads ARE the
# blocks at H (no extra fetch); otherwise /block/<H> is read per validator —
# the RPC surface provides block identity at a height, so this needs nothing
# new from the node. A validator whose height straddled H between its own two
# readings still answers /block/<H> from disk.
AGREE_STATE="not judged"; AGREE_DETAIL=""; COMMON_H=""
BH=()
if [ "$REACHED_BOTH" = yes ]; then
    UNIQUE_CHAINS=$(printf '%s\n' "${CH[@]}" | sort -u)
    if [ "$(printf '%s\n' "$UNIQUE_CHAINS" | grep -c .)" -ne 1 ]; then
        AGREE_STATE="CHAIN-ID MISMATCH"
        i=0
        while [ $i -lt $N ]; do
            [ "$i" -gt 0 ] && AGREE_DETAIL="$AGREE_DETAIL; "
            AGREE_DETAIL="$AGREE_DETAIL${PIS[$i]}=${CH[$i]}"
            i=$((i + 1))
        done
    else
        COMMON_H=""
        i=0
        while [ $i -lt $N ]; do
            if [ -z "$COMMON_H" ] || [ "${H2[$i]}" -lt "$COMMON_H" ]; then COMMON_H=${H2[$i]}; fi
            i=$((i + 1))
        done
        BH_MISSING=0
        i=0
        while [ $i -lt $N ]; do
            bh=""
            if [ "${H2[$i]}" -eq "$COMMON_H" ]; then
                bh=${B2[$i]}        # reading-2 head IS the block at height H
            elif try_rpc "${PIS[$i]}" "/block/$COMMON_H"; then
                bh=$(jstr "$OUT_BODY" hash)
            fi
            if [ -z "$bh" ]; then
                BH_MISSING=$((BH_MISSING + 1))
                AGREE_DETAIL="$AGREE_DETAIL (could not read block $COMMON_H from ${PIS[$i]}${LAST_ERR:+: $LAST_ERR})"
                BH+=("?")
            else
                BH+=("$bh")
            fi
            i=$((i + 1))
        done
        if [ "$BH_MISSING" -gt 0 ]; then
            AGREE_STATE=INCONCLUSIVE
        else
            UNIQUE_HASHES=$(printf '%s\n' "${BH[@]}" | sort -u)
            if [ "$(printf '%s\n' "$UNIQUE_HASHES" | grep -c .)" -eq 1 ]; then
                AGREE_STATE=AGREE
                AGREE_DETAIL="chain ${CH[0]}, block $COMMON_H = $(printf '%s' "${BH[0]}" | head -c 16)... identical on all $N validators"
            else
                AGREE_STATE="BLOCK MISMATCH"
                i=0
                while [ $i -lt $N ]; do
                    [ "$i" -gt 0 ] && AGREE_DETAIL="$AGREE_DETAIL; "
                    AGREE_DETAIL="$AGREE_DETAIL${PIS[$i]}=$(printf '%s' "${BH[$i]}" | head -c 16)..."
                    i=$((i + 1))
                done
                AGREE_DETAIL="$AGREE_DETAIL at height $COMMON_H"
            fi
        fi
    fi
fi

# ---- verdict ----------------------------------------------------------------

CODE=0
echo
if [ "$REACHED_BOTH" != yes ]; then
    CODE=1
    echo "agreement   not judged: at least one validator was unreachable"
    echo
    echo "VERDICT: FAIL — UNREACHABLE (exit 1): these validators gave no /status:$(i=0; while [ $i -lt $N ]; do if failed_validator "$i"; then printf ' %s' "${PIS[$i]}"; fi; i=$((i + 1)); done)"
    i=0
    while [ $i -lt $N ]; do
        if failed_validator "$i"; then
            ctx=""
            [ "${OK1[$i]}" = yes ] && ctx=" (was reachable at reading 1, height ${H1[$i]}, then vanished)"
            echo "  ${PIS[$i]}: ${ERR[$i]}$ctx"
        fi
        i=$((i + 1))
    done
    [ "$RELAY_STATE" = UNREACHABLE ] && echo "  (relay $RELAY_HOST:$RELAY_PORT also UNREACHABLE — deploy README §8, failure 2)"
    echo "  wrong address, node not running, or (ssh mode) SSH blocked — deploy README §8"
elif [ "$AGREE_STATE" = "CHAIN-ID MISMATCH" ]; then
    CODE=3
    echo "agreement   CHAIN-ID MISMATCH — $AGREE_DETAIL"
    echo
    echo "VERDICT: FAIL — DISAGREE (exit 3): validators are on DIFFERENT CHAINS: $AGREE_DETAIL."
    echo "  Same binary build and same --validators value on every node — deploy README §8, failure 1."
elif [ -n "$NOT_ADVANCING" ]; then
    CODE=2
    echo "agreement   $AGREE_STATE — $AGREE_DETAIL"
    echo
    echo "VERDICT: FAIL — STALLED (exit 2): all validators reachable on chain ${CH[0]}, but these heights did NOT increase in ${ADVANCE_WAIT}s:$NOT_ADVANCING"
    if [ "$RELAY_STATE" = UNREACHABLE ]; then
        echo "  relay $RELAY_HOST:$RELAY_PORT is UNREACHABLE from this machine — deploy README §8, failure 2."
        echo "  Re-probe from a validator: ssh <pi> 'bash -c \"exec 3<>/dev/tcp/$RELAY_HOST/$RELAY_PORT\" && echo open'"
    else
        echo "  Reachable-but-frozen: the relay can be down in a way this machine cannot see, or the committee"
        echo "  cannot reach quorum — e.g. two machines on one --index seat (deploy README §8, failures 2 and 3)."
    fi
elif [ "$AGREE_STATE" = "BLOCK MISMATCH" ]; then
    CODE=3
    echo "agreement   BLOCK MISMATCH — $AGREE_DETAIL"
    echo
    echo "VERDICT: FAIL — DISAGREE (exit 3): every validator advanced on chain ${CH[0]}, but they did NOT finalise"
    echo "  the same blocks: $AGREE_DETAIL. A fork, or two validators on one --index seat (same key) — deploy README §8, failure 3."
elif [ "$AGREE_STATE" = INCONCLUSIVE ]; then
    CODE=5
    echo "agreement   could not be read:$AGREE_DETAIL"
    echo
    echo "VERDICT: FAIL — INCONCLUSIVE (exit 5): every validator advanced on chain ${CH[0]}, but the common-block reads failed:$AGREE_DETAIL"
elif [ "$RELAY_STATE" = UNREACHABLE ]; then
    CODE=4
    echo "agreement   $AGREE_DETAIL"
    echo
    echo "VERDICT: FAIL — RELAY (exit 4): $RELAY_HOST:$RELAY_PORT $RELAY_STATE."
    echo "  This is NOT a consensus problem: the validators DID advance and DID agree ($AGREE_DETAIL)."
    echo "  The probe ran from THIS machine (a laptop-side firewall can cause exactly this); from a validator:"
    echo "  ssh <pi> 'bash -c \"exec 3<>/dev/tcp/$RELAY_HOST/$RELAY_PORT\" && echo open'  (deploy README §8, failure 2)."
else
    CODE=0
    echo "agreement   $AGREE_DETAIL"
    echo
    echo "VERDICT: PASS — $N validators on chain ${CH[0]}, every height increased during the ${ADVANCE_WAIT}s wait, and all"
    echo "  report the identical block at height $COMMON_H: the committee finalises ONE shared chain. M4's criterion —"
    echo "  validators finalising blocks — holds for the machines named above; paste this entire output."
fi

exit $CODE