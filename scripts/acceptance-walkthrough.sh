#!/usr/bin/env bash
#
# acceptance-walkthrough.sh — make docs/2026-11-01-m6-walkthrough.md executable.
#
# The M6 acceptance sentence is about a person who has only the repository's
# documentation. A narrative walkthrough cannot prove that sentence, because a
# document that is correct today and wrong next month still reads correctly.
# This script is the proof (design decision 1): it EXTRACTS the walkthrough's
# one ```sh fence at run time, runs it against a fresh chain in a temporary
# directory, and asserts the outcome the document promises. It carries no copy
# of the commands on purpose — if it did, the document could rot while the
# script kept passing.
#
# What it extracts
# ----------------
# Exactly one fence whose info string is `sh`. It counts shell fences
# (`sh`, `bash`, `shell`, `zsh`, `console`) and refuses anything other than
# exactly one, so a second "quick version" block — or a ```bash block an
# extractor that only looked for ```sh would silently ignore — fails the run.
# The build is deliberately NOT extracted: the walkthrough builds `bin/b10coin`
# in prose (the fence never does), and this script runs the fence from a
# temporary directory that is not a Go module, so it builds the binary itself
# and points the fence's `B10` variable at it.
#
# What it waits on
# ----------------
# Conditions, never a sleep that happens to be long enough:
#   * the node's port accepts a TCP connection before the fence's own
#     readiness loop can give up (the fence still does its own wait; this one
#     exists to fail fast with a node-specific message if it never binds);
#   * the extracted commands finish, bounded by B10COIN_TIMEOUT seconds;
#   * cleanup waits for the node process to disappear and for the port to stop
#     accepting connections.
# The assertions then read the log the fence produced. In particular the
# transfer preview must appear AFTER the sender's balance read the claim's
# 100,000,000 sparks, which is the observable difference between waiting for
# the balance and proceeding on the POST (a claim is queued, not paid).
#
# Ports
# -----
# 20000..29999. The test suite's real listeners all bind 127.0.0.1:0, so the
# OS hands them ports from its ephemeral range (32768..60999 on Linux,
# 49152..65535 on macOS); a port below both floors cannot be one of them.
# The range also excludes the suite's fixed ports (7001, 7005, 8645) and the
# walkthrough's documented default (18645). A candidate that already accepts a
# connection is skipped, so two concurrent local runs also stay apart.
#
# Cleanup
# -------
# The extracted fence's own last command kills the node. The trap is still
# mandatory: a timeout, an interrupt, or a fence that dies before its `kill`
# would otherwise leak a node and a bound port. The trap kills the pid in
# $tmp/work/node.pid, waits for it to exit, waits for the port to close, and
# removes $tmp unless --keep.
#
# usage: scripts/acceptance-walkthrough.sh [--doc PATH] [--keep]
#   exit 0  the doc's commands ran and produced the promised outcome
#   exit 1  a command failed, a promised line is missing, or the doc's shape
#           is wrong (fence count, fence language)
#   exit 2  bad invocation, the document is unreadable, or the tree cannot
#           build
#
# Environment: B10COIN_DOC (default docs/2026-11-01-m6-walkthrough.md),
#              B10COIN_TIMEOUT (default 120, seconds for the extracted block).
#
# No new runtime dependency: bash, coreutils, sed, awk, grep, tail, the Go
# toolchain (to build) and the built binary. No curl, no jq, no Python.

set -u -o pipefail

# A caller's CDPATH makes `cd` print a path, and a caller's IFS changes how the
# extracted block splits words. Neither is part of the contract: the block gets
# default values, and B10/WORK/PORT are set explicitly when it is started.
unset CDPATH
unset IFS

EXIT_OK=0
EXIT_FAIL=1
EXIT_USAGE=2

ROOT=$(cd "$(dirname "$0")/.." && pwd)
DOC=${B10COIN_DOC:-$ROOT/docs/2026-11-01-m6-walkthrough.md}
TIMEOUT=${B10COIN_TIMEOUT:-120}
KEEP=0

TMP=
PORT=
PIDFILE=
RUNLOG=
NODELOG=
BLOCK_PID=

usage() {
	cat <<EOF
usage: $0 [--doc PATH] [--keep]

Extract the walkthrough's one sh fence, run it against a fresh node in a
temporary directory, and assert the outcome the document promises.

  --doc PATH   the walkthrough document (default: $DOC,
               or B10COIN_DOC)
  --keep       keep the temporary directory and print its path (the node is
               still killed and the port still checked)
  --help       this text

exit 0: the document's commands ran and the promised outcome is present
exit 1: a command failed, a promised line is missing, or the document's shape
        is wrong (not exactly one sh fence)
exit 2: bad invocation, the document is unreadable, or the tree cannot build

B10COIN_TIMEOUT bounds the extracted block in seconds (default 120).
EOF
}

die_usage() {
	printf 'error: %s\n' "$*" >&2
	printf 'run %s --help for usage\n' "$0" >&2
	exit "$EXIT_USAGE"
}

# port_open returns success when something accepts a TCP connection on
# 127.0.0.1:$1. Bash's /dev/tcp is a builtin, not an external command.
port_open() {
	(exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null
}

# pick_port sets PORT to a candidate in 20000..29999 that nothing is listening
# on. If /dev/tcp is unavailable the first candidate is kept; the readiness
# wait and the cleanup check then report what they can.
pick_port() {
	local tries candidate
	tries=0
	while [ "$tries" -lt 20 ]; do
		candidate=$((20000 + (RANDOM % 10000)))
		if ! port_open "$candidate"; then
			PORT=$candidate
			return 0
		fi
		tries=$((tries + 1))
	done
	return 1
}

dump_failure() {
	if [ -n "$RUNLOG" ] && [ -f "$RUNLOG" ]; then
		printf '\n--- %s (last 40 lines) ---\n' "$RUNLOG" >&2
		tail -n 40 "$RUNLOG" >&2 || true
	fi
	if [ -n "$NODELOG" ] && [ -f "$NODELOG" ]; then
		printf '\n--- %s (last 20 lines) ---\n' "$NODELOG" >&2
		tail -n 20 "$NODELOG" >&2 || true
	fi
	printf '\nRe-run with --keep to keep the temporary directory for inspection.\n' >&2
}

fail() {
	printf 'FAIL: %s\n' "$*" >&2
	dump_failure
	exit "$EXIT_FAIL"
}

# require MESSAGE COMMAND... runs COMMAND and fails the whole script (with the
# log tail) when it returns non-zero.
require() {
	local msg
	msg=$1
	shift
	if ! "$@"; then
		fail "$msg"
	fi
}

cleanup() {
	# Capture $? in the SAME command that declares it: a bare `local rc`
	# resets $? to 0 and would mask every failure the trap is exiting on.
	local rc=$?
	if [ -n "$TMP" ] && [ -d "$TMP" ]; then
		if [ -n "$PIDFILE" ] && [ -f "$PIDFILE" ]; then
			local pid
			pid=$(cat "$PIDFILE" 2>/dev/null) || pid=
			case "$pid" in
			'' | *[!0-9]*) pid= ;;
			esac
			if [ -n "$pid" ]; then
				if kill -0 "$pid" 2>/dev/null; then
					kill "$pid" 2>/dev/null
					local i
					i=0
					while kill -0 "$pid" 2>/dev/null && [ "$i" -lt 50 ]; do
						sleep 0.1
						i=$((i + 1))
					done
					if kill -0 "$pid" 2>/dev/null; then
						kill -9 "$pid" 2>/dev/null
					fi
				fi
				printf 'cleanup: node %s stopped\n' "$pid" >&2
			fi
		fi
		if [ -n "$PORT" ]; then
			local n
			n=0
			while port_open "$PORT" && [ "$n" -lt 50 ]; do
				sleep 0.1
				n=$((n + 1))
			done
			if port_open "$PORT"; then
				printf 'cleanup: 127.0.0.1:%s is STILL listening after the node was stopped\n' "$PORT" >&2
				if [ "$rc" -eq 0 ]; then
					rc=$EXIT_FAIL
				fi
			else
				printf 'cleanup: 127.0.0.1:%s is free\n' "$PORT" >&2
			fi
		fi
		if [ "$KEEP" -eq 1 ]; then
			printf 'cleanup: kept %s\n' "$TMP" >&2
		else
			rm -rf "${TMP:?}"
			printf 'cleanup: removed %s\n' "$TMP" >&2
		fi
	fi
	exit "$rc"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

while [ "$#" -gt 0 ]; do
	case "$1" in
	--doc)
		[ "$#" -ge 2 ] || die_usage "--doc needs a path"
		DOC=$2
		shift 2
		;;
	--doc=*)
		DOC=${1#*=}
		shift
		;;
	--keep)
		KEEP=1
		shift
		;;
	--help | -h)
		usage
		exit "$EXIT_OK"
		;;
	*)
		die_usage "unknown argument: $1"
		;;
	esac
done

case "$TIMEOUT" in
'' | *[!0-9]*) die_usage "B10COIN_TIMEOUT must be a positive whole number of seconds (got '$TIMEOUT')" ;;
esac
[ "$TIMEOUT" -gt 0 ] || die_usage "B10COIN_TIMEOUT must be a positive whole number of seconds (got '$TIMEOUT')"

[ -f "$DOC" ] || die_usage "the walkthrough document is not readable: $DOC"
[ -r "$DOC" ] || die_usage "the walkthrough document is not readable: $DOC"

TMP=$(mktemp -d "${TMPDIR:-/tmp}/b10coin-acceptance.XXXXXX") || die_usage "cannot create a temporary directory"
PIDFILE=$TMP/work/node.pid
RUNLOG=$TMP/run.log
NODELOG=$TMP/work/node.log

# ---------------------------------------------------------------------------
# 1. The document's shape: exactly one ```sh fence, and it is terminated.
# ---------------------------------------------------------------------------

shell_fences() {
	awk '
		/^```/ {
			info = $0
			sub(/^```[[:space:]]*/, "", info)
			sub(/[[:space:]]+$/, "", info)
			if (info ~ /^(sh|bash|shell|zsh|console)$/)
				printf "%d\t%s\n", NR, info
		}
	' "$DOC"
}

fences=$(shell_fences)
n=0
if [ -n "$fences" ]; then
	n=$(printf '%s\n' "$fences" | wc -l | tr -d ' ')
fi
if [ "$n" -ne 1 ]; then
	printf 'FAIL: the walkthrough must contain exactly one shell fence (```sh); found %s:\n' "$n" >&2
	if [ -n "$fences" ]; then
		printf '%s\n' "$fences" | sed 's/^/  line /' >&2
	fi
	exit "$EXIT_FAIL"
fi
lang=$(printf '%s\n' "$fences" | cut -f2)
if [ "$lang" != "sh" ]; then
	fail "the walkthrough's one shell fence is \`\`\`$lang, not \`\`\`sh; the extractor only runs the \`\`\`sh block"
fi

awk '
	/^```sh[[:space:]]*$/ { inblock = 1; next }
	inblock && /^```[[:space:]]*$/ { inblock = 0; closed = 1; next }
	inblock { print }
	END { if (inblock || !closed) exit 3 }
' "$DOC" >"$TMP/commands.sh"
extract_rc=$?
if [ "$extract_rc" -ne 0 ]; then
	exit "$EXIT_FAIL"
fi
require "the walkthrough's shell fence is empty" test -s "$TMP/commands.sh"

# ---------------------------------------------------------------------------
# 2. The tree must build. The binary goes to $TMP, never bin/, so the script
#    cannot test a stale binary and never writes into the repository.
# ---------------------------------------------------------------------------

command -v go >/dev/null 2>&1 || die_usage "the go command is not on PATH; the tree cannot be built"
if ! (cd "$ROOT" && go build -o "$TMP/b10coin" ./cmd/b10coin); then
	printf 'error: go build -o %s/b10coin ./cmd/b10coin failed in %s\n' "$TMP" "$ROOT" >&2
	exit "$EXIT_USAGE"
fi

# ---------------------------------------------------------------------------
# 3. Run the extracted commands from $TMP (which has no go.mod), with B10,
#    WORK and PORT set explicitly so a caller's values cannot leak in. No
#    set -e for the block: its own loops legitimately see failed reads while
#    the node starts, and the assertions below judge the outcome.
# ---------------------------------------------------------------------------

pick_port || die_usage "cannot find a free port in 20000..29999"
printf 'doc:  %s\n' "$DOC"
printf 'port: %s\n' "$PORT"

(
	cd "$TMP" &&
		env B10="$TMP/b10coin" WORK="$TMP/work" PORT="$PORT" bash "$TMP/commands.sh"
) </dev/null >"$RUNLOG" 2>&1 &
BLOCK_PID=$!

ready=0
waited=0
while [ "$waited" -lt 100 ]; do
	if port_open "$PORT"; then
		ready=1
		break
	fi
	if ! kill -0 "$BLOCK_PID" 2>/dev/null; then
		break
	fi
	sleep 0.1
	waited=$((waited + 1))
done
if [ "$ready" -ne 1 ]; then
	if kill -0 "$BLOCK_PID" 2>/dev/null; then
		kill "$BLOCK_PID" 2>/dev/null
	fi
	fail "the node never bound 127.0.0.1:$PORT within 10 s (the port may be busy, or the node did not start) - see $NODELOG"
fi

started=$SECONDS
timed_out=0
while kill -0 "$BLOCK_PID" 2>/dev/null; do
	if [ $((SECONDS - started)) -ge "$TIMEOUT" ]; then
		timed_out=1
		kill "$BLOCK_PID" 2>/dev/null
		break
	fi
	sleep 0.2
done
wait "$BLOCK_PID" 2>/dev/null
block_rc=$?
if [ "$timed_out" -eq 1 ]; then
	fail "the extracted commands did not finish within ${TIMEOUT}s (B10COIN_TIMEOUT)"
fi
if [ "$block_rc" -ne 0 ]; then
	fail "the extracted commands exited $block_rc; the document's last command failed"
fi

# The document's last line is `kill`: a block that returns with the node still
# running is a wrong document even when the balances look right. The EXIT trap
# is the safety net for a block that dies early, not a substitute for the
# command. Wait a short, bounded grace for SIGTERM to take effect.
if [ -f "$PIDFILE" ]; then
	node_pid=$(cat "$PIDFILE" 2>/dev/null) || node_pid=
	case "$node_pid" in
	'' | *[!0-9]*) node_pid= ;;
	esac
	if [ -n "$node_pid" ]; then
		n=0
		while kill -0 "$node_pid" 2>/dev/null && [ "$n" -lt 50 ]; do
			sleep 0.1
			n=$((n + 1))
		done
		if kill -0 "$node_pid" 2>/dev/null; then
			fail "the extracted commands returned while node $node_pid was still running; the walkthrough's last line must stop it"
		fi
	fi
fi

# ---------------------------------------------------------------------------
# 4. Assert the outcome the document promises, from the log alone.
# ---------------------------------------------------------------------------

alice=$(awk '/^seat address / { print $3; exit }' "$RUNLOG")
if ! printf '%s' "$alice" | grep -Eq '^b10[0-9a-z]+$'; then
	fail "the walkthrough printed no usable 'seat address' line for the first key (got '$alice')"
fi

# The claim's receipt: a txid tied to the claim, not a stray txid from the
# send. The queued sentence is the fact the wait loops exist for.
claim_txid=$(awk '
	/^claimant[[:space:]]/ { inclaim = 1 }
	inclaim && /^txid[[:space:]]/ { print $2; exit }
' "$RUNLOG")
if ! printf '%s' "$claim_txid" | grep -Eq '^[0-9a-f]{64}$'; then
	fail "the claim receipt has no 'txid <64 hex>' line (got '$claim_txid'); the doc promises the claim is posted"
fi
require "the claim receipt has no 'claim epoch N' line" grep -Eq '^claim epoch [0-9]+$' "$RUNLOG"
require "the claim receipt does not say the claim is queued" grep -Fq 'the claim is queued on the node; it is paid when the node' "$RUNLOG"

# The balance must reach 100000000 with nonce 1 BEFORE the transfer preview.
paid_line=$(awk -v a="$alice" '
	/^address[[:space:]]/ { addr = $2 }
	/^balance[[:space:]]/ { if (addr == a && $2 == "100000000") { print NR; exit } }
' "$RUNLOG")
if [ -z "$paid_line" ]; then
	fail "the sender's balance never read '100000000 sparks (1 b10)'; the claim was never observed as paid"
fi
paid_nonce=$(awk -v a="$alice" '
	/^address[[:space:]]/ { addr = $2; bal = "" }
	/^balance[[:space:]]/ { bal = $2 }
	/^nonce[[:space:]]/ { if (addr == a && bal == "100000000" && $2 == "1") { print "yes"; exit } }
' "$RUNLOG")
if [ "$paid_nonce" != "yes" ]; then
	fail "the paid balance did not show nonce 1; the claim's replay counter did not move as the doc says"
fi
send_preview_line=$(grep -nE '^transaction to sign \(built, not yet signed\):' "$RUNLOG" | sed -n '2p' | cut -d: -f1)
if [ -z "$send_preview_line" ]; then
	fail "the walkthrough printed no transfer preview (the second 'transaction to sign' block)"
fi
if [ "$paid_line" -ge "$send_preview_line" ]; then
	fail "the send ran before the claim's 100000000 sparks were observed; it must wait for the balance, not the POST"
fi

preview_to=$(awk '
	/^transaction to sign \(built, not yet signed\):/ { block++ }
	block == 2 && /^  to[[:space:]]/ { print $2; exit }
' "$RUNLOG")
if ! printf '%s' "$preview_to" | grep -Eq '^b10[0-9a-z]+$'; then
	fail "the transfer preview has no 'to' address (got '$preview_to')"
fi
preview_amount=$(awk '
	/^transaction to sign \(built, not yet signed\):/ { block++ }
	block == 2 && /^  amount[[:space:]]/ { print $2 " " $3 " " $4 " " $5; exit }
' "$RUNLOG")
if [ "$preview_amount" != "50000000 sparks (0.5 b10)" ]; then
	fail "the transfer preview's amount is '$preview_amount', not '50000000 sparks (0.5 b10)'; the doc's --amount is what must run"
fi

send_txid=$(awk '
	/^transaction to sign \(built, not yet signed\):/ { block++ }
	block == 2 && /^txid[[:space:]]/ { print $2; exit }
' "$RUNLOG")
if ! printf '%s' "$send_txid" | grep -Eq '^[0-9a-f]{64}$'; then
	fail "the send receipt has no 'txid <64 hex>' line (got '$send_txid'); the transfer was not posted"
fi

# The recipient is the only balance read whose address is not the sender's.
# The doc does not print $BOB, so the script identifies it from the read the
# doc promises and cross-checks it against the preview and the history row.
bob=$(awk -v a="$alice" '
	/^address[[:space:]]/ { addr = $2 }
	/^balance[[:space:]]/ { if (addr != "" && addr != a) seen[addr] = 1 }
	END { n = 0; for (k in seen) { n++; last = k } if (n == 1) print last }
' "$RUNLOG")
if [ -z "$bob" ]; then
	fail "the walkthrough printed no balance read for an address other than the sender's; the recipient's balance is promised"
fi
if [ "$bob" != "$preview_to" ]; then
	fail "the send preview credits '$preview_to' but the recipient balance read names '$bob'; the transfer went elsewhere"
fi

sender_bal=$(awk -v a="$alice" '
	/^address[[:space:]]/ { addr = $2 }
	/^balance[[:space:]]/ { if (addr == a) last = $2 " " $3 " " $4 " " $5 }
	END { print last }
' "$RUNLOG")
if [ "$sender_bal" != "49999999 sparks (0.49999999 b10)" ]; then
	fail "the sender's last balance is '$sender_bal', not '49999999 sparks (0.49999999 b10)'; 100000000 - 50000000 - 1 fee is not what the doc promises"
fi

bob_bal=$(awk -v b="$bob" '
	/^address[[:space:]]/ { addr = $2 }
	/^balance[[:space:]]/ { if (addr == b) bal = $2 " " $3 " " $4 " " $5 }
	END { print bal }
' "$RUNLOG")
if [ "$bob_bal" != "50000000 sparks (0.5 b10)" ]; then
	fail "the recipient's balance is '$bob_bal', not '50000000 sparks (0.5 b10)'"
fi

# history is the SENDER's view: its header names alice and its transfer row
# names the recipient ($BOB) on the party line.
hist_addr=$(awk '/^history for / { print $3; exit }' "$RUNLOG")
if [ "$hist_addr" != "$alice" ]; then
	fail "the history read is not the sender's: header names '$hist_addr', sender is '$alice'"
fi
require "the history header does not print its scanned window ('blocks A..B, scanned N, newest first')" \
	grep -Eq '^history for [^ ]+ [(]blocks [0-9]+[.][.][0-9]+, scanned [0-9]+, newest first[)]$' "$RUNLOG"
# The window must be coherent, not pinned to the heights of one run: the doc
# itself says the head can advance while it is being read. The node's contract
# is scanned == to - from + 1, from >= 1, and a window that reaches the
# transfer (height >= 2).
window_ok=$(awk '
	/^history for / {
		split($5, ab, /\.\./)
		from = ab[1] + 0
		to = ab[2] + 0
		scanned = $7
		sub(/,/, "", scanned)
		scanned = scanned + 0
		if (from >= 1 && to >= 2 && scanned == to - from + 1) print "yes"
		exit
	}
' "$RUNLOG")
if [ "$window_ok" != "yes" ]; then
	fail "the history window line is not coherent: expected from>=1, to>=2 and scanned == to-from+1"
fi

if ! awk -v b="$bob" '
	$1 ~ /^[0-9]+$/ && $2 == "transfer" && $3 == "50000000" && $4 == "sparks" &&
	$5 == "(0.5" && $6 == "b10)" && $7 == "fee" && $8 == "1" &&
	$9 == "to" && $10 == b { found = 1 }
	END { exit !found }
' "$RUNLOG"; then
	fail "the sender's history has no 'transfer 50000000 sparks ... to <recipient>' row; the history is the sender's view and must name $bob"
fi

printf 'OK: the walkthrough ran and produced the outcome it promises\n'
exit "$EXIT_OK"
