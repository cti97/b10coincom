#!/bin/sh
# install-watchdog.sh - install the stall watchdog on this host.
#
# Idempotent. Detects the platform:
#   macOS  -> ~/b10coin-node/stall-watchdog.sh + LaunchAgent com.b10coin.watchdog
#             (every 60 s, no sudo)
#   Linux  -> /usr/local/lib/b10coin/stall-watchdog.sh + systemd timer
#             b10coin-watchdog.timer (every 60 s, run as root for systemctl)
#
# Run it from a repository checkout:
#   sudo sh scripts/deploy/install-watchdog.sh          # Linux / Pi
#   sh scripts/deploy/install-watchdog.sh               # macOS
#
# Verify afterwards:
#   macOS: launchctl print gui/$(id -u)/com.b10coin.watchdog
#   Linux: systemctl list-timers b10coin-watchdog.timer

set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
SRC="$HERE/stall-watchdog.sh"
[ -f "$SRC" ] || { echo "install-watchdog: $SRC not found (run from a checkout)" >&2; exit 1; }

case "$(uname -s)" in
Darwin)
  DEST_DIR="$HOME/b10coin-node"
  DEST="$DEST_DIR/stall-watchdog.sh"
  PLIST="$HOME/Library/LaunchAgents/com.b10coin.watchdog.plist"
  mkdir -p "$DEST_DIR" "$HOME/Library/LaunchAgents"
  install -m 0755 "$SRC" "$DEST"
  cat >"$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!--
  Runs the b10coin stall watchdog every 60 s. See scripts/deploy/stall-watchdog.sh
  for why: a round divergence cannot commit and the ladder's tail is effectively
  unbounded, while a restart at round 0 converges in seconds. Keeping this on
  the same host as the seat means no cross-host coordination is required.
-->
<plist version="1.0">
<dict>
  <key>Label</key><string>com.b10coin.watchdog</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/sh</string>
    <string>$DEST</string>
  </array>
  <key>StartInterval</key><integer>60</integer>
  <key>RunAtLoad</key><true/>
  <key>StandardOutPath</key><string>$DEST_DIR/stall-watchdog.log</string>
  <key>StandardErrorPath</key><string>$DEST_DIR/stall-watchdog.log</string>
</dict>
</plist>
EOF
  launchctl bootout "gui/$(id -u)/com.b10coin.watchdog" 2>/dev/null || true
  launchctl bootstrap "gui/$(id -u)" "$PLIST"
  echo "installed: $DEST"
  echo "installed: $PLIST (every 60 s)"
  launchctl print "gui/$(id -u)/com.b10coin.watchdog" | sed -n 's/^[[:space:]]*\(state = .*\)/  \1/p' | head -1
  ;;
Linux)
  DEST_DIR=/usr/local/lib/b10coin
  install -d -m 0755 "$DEST_DIR"
  install -m 0755 "$SRC" "$DEST_DIR/stall-watchdog.sh"
  cat >/etc/systemd/system/b10coin-watchdog.service <<EOF
[Unit]
Description=b10coin stall watchdog (restarts a seat wedged at one height)
After=b10coin.service
Wants=b10coin.service

[Service]
Type=oneshot
ExecStart=$DEST_DIR/stall-watchdog.sh
# 10 is "restarted the node": a successful heal must not look like a failure.
SuccessExitStatus=10
Nice=10
EOF
  cat >/etc/systemd/system/b10coin-watchdog.timer <<EOF
[Unit]
Description=Run the b10coin stall watchdog every minute

[Timer]
OnBootSec=3min
OnUnitActiveSec=60s
AccuracySec=10s

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable --now b10coin-watchdog.timer
  echo "installed: $DEST_DIR/stall-watchdog.sh"
  echo "installed: b10coin-watchdog.service + .timer (every 60 s)"
  systemctl list-timers b10coin-watchdog.timer --no-pager | sed -n '1,2p'
  ;;
*)
  echo "install-watchdog: unsupported platform $(uname -s)" >&2
  exit 1
  ;;
esac
