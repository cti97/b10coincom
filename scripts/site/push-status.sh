#!/bin/sh
# Push a live chain snapshot to the public page on the VPS.
# Run by launchd (com.b10coin.push) every 15 s. Silent on failure: a page with a
# stale "updated" age is the correct display for a node that is down, and a
# crash-looping pusher would be worse than a missing update.
#
# The snapshot carries a measured block rate. The page used to compute one in
# the browser from successive polls, which meant every reload showed "—" until
# it had seen two different heights, and a reader could not tell "not measured
# yet" from "chain stopped". The pusher already knows the previous height and
# when it was taken, so it measures the rate over that window (15 s by default)
# and the page shows a number on the first render. A null rate is a statement:
# the chain has not moved for more than a minute.
set -eu
API=http://127.0.0.1:8645
DEST=b17g0d@93.115.53.244
DIR=/usr/share/nginx/b10coin.com/html/live
STATE="$HOME/b10coin-node/push-rate.state"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

curl -fsS -m 4 "$API/status" -o "$work/status.json" || exit 0

python3 - "$work/status.json" "$STATE" > "$work/chain.json" <<'PY'
import json, os, sys, time, urllib.request

st = json.load(open(sys.argv[1]))
state_path = sys.argv[2]
api = "http://127.0.0.1:8645"
blocks = []
head = int(st.get("height", 0))
for h in range(max(0, head - 7), head + 1):
    try:
        with urllib.request.urlopen(f"{api}/block/{h}", timeout=3) as r:
            b = json.load(r)
        blocks.append({
            "height": b.get("height", h),
            "hash": b.get("hash", ""),
            "parent": b.get("parent", ""),
            "tx_count": b.get("tx_count", 0),
            "timestamp": b.get("timestamp", 0),
        })
    except Exception:
        pass
blocks.sort(key=lambda b: b["height"], reverse=True)

now = int(time.time())
rate = None
try:
    with open(state_path) as f:
        prev = json.load(f)
except Exception:
    prev = None

if prev and isinstance(prev.get("height"), int) and isinstance(prev.get("ts"), int):
    dh = head - prev["height"]
    dt = now - prev["ts"]
    if dh > 0 and dt >= 3:
        inst = dh / dt
        prior = prev.get("rate")
        # The window is one push long, so a raw number is noisy; a light EMA
        # keeps the display from flickering between renders.
        rate = inst if not isinstance(prior, (int, float)) or prior <= 0 else 0.6 * prior + 0.4 * inst
    elif dt < 60 and isinstance(prev.get("rate"), (int, float)):
        # No new measurement to take - a quiet window, or two runs closer
        # together than the window needs - so keep the last rate rather than
        # blanking a number that is still a minute-fresh observation.
        rate = prev["rate"]
    # dh == 0 for longer than a minute, or dh < 0 (replay/reorg): null.

out = dict(st)
out["updated"] = now
out["blocks"] = blocks
out["rate"] = round(rate, 1) if isinstance(rate, (int, float)) and rate > 0 else None
json.dump(out, sys.stdout)

tmp = state_path + ".new"
with open(tmp, "w") as f:
    json.dump({"height": head, "ts": now, "rate": rate}, f)
os.replace(tmp, state_path)
PY

# One round trip, atomic on the far side: a reader never sees a half file.
ssh -o BatchMode=yes -o ConnectTimeout=6 "$DEST" \
  "cat > $DIR/chain.json.new && mv $DIR/chain.json.new $DIR/chain.json" < "$work/chain.json"
