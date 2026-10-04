# Three Raspberry Pis + one VPS: the b10coin testnet deployment recipe

This file takes a person who has never seen b10coin from three unopened
Raspberry Pis and one cheap VPS to a running three-validator testnet whose
members sit on separate home networks. It is M4's acceptance path in
`docs/2026-10-02-b10coin-design.md`: *"3 validators on real Raspberry Pis
across separate networks finalize blocks."*

```
        each Pi dials OUTBOUND (no port forwarding, CGNAT-proof)
Pi 0 (home A) ──┐
Pi 1 (home B) ──┼──► b10coin-relay on the VPS (TCP 7001)
Pi 2 (home C) ──┘            │
                             └── forwards every frame it gets to every
                                 OTHER peer, parsing nothing beyond the
                                 length prefix
```

Scope note: this recipe and `make arm64` cover **one platform — Linux/ARM64**
— because that is what a Pi runs. A later task generalizes the build into a
multi-platform release matrix and will replace `make arm64` and
`scripts/deploy/build.sh`; until then, treat this as the single supported
target.

---

## 1. What to buy and prepare

| Item | What | Notes |
|---|---|---|
| 3× Raspberry Pi | Pi 4 or Pi 5, 2 GB or more | the validators. Different homes/networks are the point: the milestone is "across separate networks" |
| 3× microSD + PSU | 16 GB+, official PSU recommended | flash **64-bit Raspberry Pi OS Lite** — the standard 32-bit install **cannot** run the binary. Verify with `uname -m`: it must print `aarch64` |
| 1× VPS | any Linux box, 1 core / 1 GB is plenty | runs the relay. ~€4/month tier from any provider is enough; bandwidth is kilobytes per second |
| 1× build machine | laptop/desktop with Go 1.23+ | builds the binaries. Any OS works; it does not run the chain |
| SSH access | to all four machines | everything below happens over SSH |

Why the VPS: a validator running at home sits behind NAT — or behind CGNAT,
where there is no public IP to forward a port to at all. The VPS has one,
so **every Pi connects outbound to the relay and no Pi ever needs an inbound
rule**. Outbound is almost never blocked; inbound is almost never possible.
The relay itself is deliberately dumb: it forwards signed frames between
connected peers and understands nothing. Because every consensus message is
signed with the sender's key, a malicious relay can censor or delay, but
cannot forge a vote — liveness is what depends on it, never safety. (`b10coin-relay --help` after install prints this trade in full.)

## 2. Build the binaries and copy them over

On the build machine, from a checkout of `github.com/cti97/b10coincom`:

```sh
make arm64                       # or: scripts/deploy/build.sh — builds AND asserts
```

This produces exactly two Linux/ARM64 binaries in `bin/` (versions come from
the source tree — `internal/version`, currently `0.1.0` — not from build
flags):

- `bin/b10coin-linux-arm64` — the node/validator binary (the Pis)
- `bin/b10coin-relay-linux-arm64` — the relay (the VPS)

Confirm on the build machine that both really are ARM (a build that quietly
produced host binaries is the failure mode this check exists for):

```sh
file bin/*-linux-arm64
# bin/b10coin-linux-arm64:        ELF 64-bit LSB executable, ARM aarch64, ... statically linked
# bin/b10coin-relay-linux-arm64:  ELF 64-bit LSB executable, ARM aarch64, ... statically linked
```

Copy each binary to the machine that runs it, then install it on each (the
static binaries need no runtime packages; current 64-bit Raspberry Pi OS and
any current Debian/Ubuntu VPS run them as-is):

```sh
# from the build machine — replace pi@ and vps@ with your real SSH targets
scp bin/b10coin-relay-linux-arm64 vps@example.com:/tmp/
for p in 192.0.2.11 192.0.2.12 192.0.2.13; do
    scp bin/b10coin-linux-arm64 pi@$p:/tmp/
done
```

On the VPS:

```sh
sudo useradd --system --home-dir /var/lib/b10coin --shell /usr/sbin/nologin b10coin || true
sudo mkdir -p /opt/b10coin
sudo install -m 0755 /tmp/b10coin-relay-linux-arm64 /opt/b10coin/b10coin-relay
```

The same commands on **each** Pi (`useradd` reports the user exists on the
second and later Pis — that is what the `|| true` absorbs locally; ignore its
message). The last line pre-creates the data directory §3 and the node unit
write into — root-owned `/var/lib` is not writable by the `b10coin` user, and
systemd's `StateDirectory` only guarantees the directory once the unit first
starts:

```sh
sudo useradd --system --home-dir /var/lib/b10coin --shell /usr/sbin/nologin b10coin || true
sudo mkdir -p /opt/b10coin
sudo install -m 0755 /tmp/b10coin-linux-arm64 /opt/b10coin/b10coin
sudo install -d -o b10coin -g b10coin -m 0750 /var/lib/b10coin
```

## 3. The genesis all three Pis must share — read this first

> **⚠️ The most likely first failure of this entire deployment.** All three
> validators must run the SAME chain — same chain ID, same genesis. Two
> validators on different chains do **not** print an error: they silently
> ignore each other's messages and every node sits at height 0 forever.

There is **no genesis file to copy between the Pis**. The testnet's committee
genesis is derived deterministically inside the binary from one number — the
committee size. `--validators 3` produces the chain `b10coin-simnet-3` and
its three fixed validator keys, and `--index` selects which of those keys
this machine claims. So sharing the chain takes exactly two conditions:

1. **the same binary** on all three Pis (copy all three from one `make arm64`), and
2. **the same `--validators` value on all three** — here `3`.

Nothing you could misconfigure as a "genesis file" exists; the failure mode
instead is a **flag mismatch** — one Pi launched with `--validators 4` (or an
older binary) derives a different chain and goes quiet.

Give every validator this exact command (run it on each Pi in the foreground
the first time, before systemd — §6), each SSH session a different index:

```sh
# Pi 0 — and --index 1 for Pi 1, --index 2 for Pi 2
sudo -u b10coin /opt/b10coin/b10coin node \
    --dir /var/lib/b10coin \
    --relay example.com:7001 \
    --validators 3 \
    --index 0
```

Every node's first output line names its chain — **all three must print the
identical chain ID**:

```
b10coin 0.1.0 listening on http://127.0.0.1:8645 (chain b10coin-simnet-3, height 0)
```

A node printing `chain b10coin-simnet-4`, `b10coin-devnet-1`, or anything
else is on a different chain — stop and fix that before anything else, using
the checklist in §8, failure 1.

## 4. The relay: address and how to run it

On the VPS, in the foreground first:

```sh
sudo -u b10coin /opt/b10coin/b10coin-relay --addr :7001
```

`--addr` is the relay's listen address (`:7001`, all interfaces, is the
default and what the rest of this recipe assumes). One line, then silence —
**a relay with no error and no output is healthy**; every validator message
that arrives is forwarded onward untouched and unlogged:

```
b10coin-relay forwarding on :7001 (max frame 1048576, max conns 256, queue 64, read timeout 2m0s, keepalive 15s)
```

The address the Pis dial is `<VPS public IP or DNS name>:7001`. The VPS must
allow inbound TCP 7001 — both the cloud security group and, if enabled, the
host firewall:

```sh
sudo ufw allow 7001/tcp     # only needed where ufw is active
```

The relay binds everything a stranger controls (frame size, connection
count, per-connection buffers, stalled-read timeout) and authenticates
nothing: anyone who finds the port may connect, so its abuse ceiling is
fixed by those flags — see `b10coin-relay --help` for the full trust trade
and knobs.

## 5. Each validator's command

The command each Pi runs (systemd runs exactly this per §6; §3 shows the same
thing with `sudo -u b10coin` for first contact):

```sh
# Pi 0 (then --index 1 on Pi 1, --index 2 on Pi 2)
/opt/b10coin/b10coin node \
    --dir /var/lib/b10coin \
    --relay example.com:7001 \
    --validators 3 \
    --index 0
```

| Flag | Meaning |
|---|---|
| `--dir` | this node's data directory — its chain database lives here. Each Pi keeps its own |
| `--relay` | the VPS's `<host>:7001` from §4. All consensus traffic flows through it; this is the only address a home Pi needs to reach |
| `--validators 3` | committee size. **Same value on every node — it derives the shared chain and genesis (§3)** |
| `--index 0` | **which validator this machine claims — see below; getting it wrong is failure 3 in §8** |
| `--http` (default `127.0.0.1:8645`) | RPC status endpoint, loopback-only by default. Read it via SSH (§7) rather than opening it to your LAN |
| `--listen`, `--peers` | optional **direct** peer connections (same-LAN or port-forwarded setups). With the relay star they stay off; a dial list is already complete via `--relay`. Home NAT/CGNAT is why these exist at all: direct inbound to a Pi is normally impossible |

**`--index` — the one flag that is different per Pi.** The committee
derives validator `i`'s signing key deterministically from `i`. `--index N`
makes THIS machine claim seat `N` and its key: it is the machine's identity
inside the committee. Two Pis started with the same `--index` therefore
derive and use the **same** private key — two machines acting as one
validator, double-signing under one identity. The committee will not
finalize; nothing prints a warning. The three seats must be exactly
`0, 1, 2`, one per machine — §7's success check and §8's failure 3 both
include a way to verify this from the logs.

## 6. The systemd units (what runs after the first contact test)

This directory ships two units. They go on **different machines**:

| Unit | Machine | Role |
|---|---|---|
| `b10coin-relay.service` | the **VPS** | the public forwarder |
| `b10coin.service` | each **Pi** | one validator node |

Both units assume what §2 installed: the binary under `/opt/b10coin/` and a
system user/group `b10coin`; the node unit additionally assumes outbound TCP
to the relay and manages `/var/lib/b10coin` itself via `StateDirectory`;
the relay unit assumes inbound TCP 7001 and writes nothing to disk. Copy,
edit, start:

```sh
# VPS
scp scripts/deploy/b10coin-relay.service vps@example.com:/tmp/
sudo install -m 0644 /tmp/b10coin-relay.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now b10coin-relay
```

On each Pi — **edit the unit before enabling**: the file you copied in
declares everything configurable as `Environment=` lines, and exactly two
need a decision per deployment: `B10COIN_RELAY` (the VPS address, same on
every Pi) and `B10COIN_INDEX` (this Pi's seat, unique: 0, 1 or 2 — §5).

```sh
scp scripts/deploy/b10coin.service pi@192.0.2.11:/tmp/
sudo install -m 0644 /tmp/b10coin.service /etc/systemd/system/
sudo nano /etc/systemd/system/b10coin.service   # set B10COIN_RELAY and B10COIN_INDEX
sudo systemctl daemon-reload
sudo systemctl enable --now b10coin
```

Both units carry `After=network-online.target` (+`Wants=`), so the network is
up before the first dial; `Restart=always` with a 5-second `RestartSec`, so
a crashed process is back in the committee without anyone logging in; an
explicit `User`/`Group`; a `WorkingDirectory`; and `NoNewPrivileges` /
`ProtectSystem` hardening around the key-holding node. Logs:

```sh
journalctl -u b10coin -f        # (VPS: journalctl -u b10coin-relay -f)
```

To update a binary: overwrite `/opt/b10coin/b10coin` (§2's `install`) and
`sudo systemctl restart b10coin` on each machine — **all machines from the
same build**, for the §3 reason.

## 7. Exactly what output means success

Success is **agreement — the same finalized history on all three Pis** — not
reachability. Machines can be perfectly connected and still be on different
chains (§8, failure 1 judges from reachability alone; do not).

1. **The banner.** Each Pi's log (`journalctl -u b10coin`) shows, exactly:

   ```
   b10coin 0.1.0 listening on http://127.0.0.1:8645 (chain b10coin-simnet-3, height 0)
   consensus    committee of 3, seat 0, dialled example.com:7001
   ```

   Same chain ID on all three; and seats 0, 1 and 2, no repeats.

2. **The chain advances.** The node prints nothing more to the terminal
   while it runs — progress is read from its RPC. On each Pi:

   ```sh
   curl -s http://127.0.0.1:8645/status
   {"chain_id":"b10coin-simnet-3","height":57,"head_hash":"9e0f…","state_root":"…","mempool":0}
   ```

   `height` rising on all three, checked a minute apart, means blocks are
   being produced and finalized (height only moves when the committee
   commits).

3. **The bar: one history.** At one moment, all three Pis must report the
   **same `head_hash` at the same `height`** — that hash names the identical
   block, so equal hashes mean the committee finalized one shared chain.
   From your laptop, over SSH in one loop:

   ```sh
   for p in 192.0.2.11 192.0.2.12 192.0.2.13; do
       ssh pi@$p curl -s http://127.0.0.1:8645/status
   done
   ```

   Identical `chain_id`, `height` and `head_hash` across all three: **the
   testnet works** — that is M4's acceptance criterion met on real hardware
   across separate networks.

## 8. When it does not work: the three failures

All three look alike from the outside — a quiet node at height 0 — so judge
them by these signatures, in this order.

| # | Failure | Signature (how you tell) | Fix |
|---|---|---|---|
| 1 | **Chain-ID / genesis mismatch** — one node runs a different `--validators` (or an older binary) and derives a different chain | `journalctl -u b10coin \| grep listening` — the `chain …` part of the banner **differs** between Pis (e.g. `b10coin-simnet-3` vs `b10coin-simnet-4`). Nodes on different chains never object; they just ignore each other forever | Stop the odd node; start it from the **same binary build** with the same `--validators 3` as the others (§3). No other remedy exists |
| 2 | **Relay unreachable** — relay not running, VPS address wrong, port 7001 closed in the cloud firewall or ufw | All chain IDs **match**, but from a Pi: `timeout 3 bash -c '</dev/tcp/example.com/7001' && echo open` prints nothing. On the VPS: `systemctl status b10coin-relay` and `ss -tlnp | grep 7001` tell you whether it listens at all | Start the relay (`systemctl enable --now b10coin-relay`), open TCP 7001 in the security group and `sudo ufw allow 7001/tcp`. Nodes redial with backoff; nothing to restart on the Pis |
| 3 | **Wrong `--index`** — two Pis share a seat, i.e. one validator key used by two machines | Chain IDs all match, relay reachable, yet heights stall. `journalctl -u b10coin \| grep committee` shows **the same `seat N` on two Pis** (the three must read `seat 0`, `seat 1`, `seat 2` in some order) | Set a unique `B10COIN_INDEX` on one of the two duplicates (`/etc/systemd/system/b10coin.service`), then `sudo systemctl daemon-reload && sudo systemctl restart b10coin` |

Quick disambiguation: chain IDs differ → 1; chain IDs match and the relay
port test fails → 2; chain IDs match, relay reachable, a `seat` repeats → 3.
If the table and logs genuinely cannot place the fault, reproduce the
committee locally on one machine (`make devnet`) to confirm the build
consensus-works, and treat the difference as network.

---

One repeated rule, because it costs hours when ignored: **one binary build,
one `--validators` value, and one `B10COIN_INDEX` per machine — from one
`make arm64`.** Everything else in this recipe is plumbing around that.