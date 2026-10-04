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

Scope note: the project builds for **six targets** — darwin/amd64, darwin/arm64, linux/amd64, linux/arm64, windows/amd64 and windows/arm64 — through the one release mechanism (`make release` → `scripts/build-release.sh`). This recipe uses it for the **Linux/ARM64 pair, because that is what a Pi runs**, and `scripts/deploy/build.sh linux/amd64` (or the machine's own architecture) for the **relay, which runs on the VPS, not on a Pi** — §2 asks the machine (`uname -m`) before choosing. The full six-target release is built and artifact-asserted by the same script; nothing here is a second build story.

---

## 1. What to buy and prepare

| Item | What | Notes |
|---|---|---|
| 3× Raspberry Pi | Pi 4 or Pi 5, 2 GB or more | the validators. Different homes/networks are the point: the milestone is "across separate networks" |
| 3× microSD + PSU | 16 GB+, official PSU recommended | flash **64-bit Raspberry Pi OS Lite** — the standard 32-bit install **cannot** run the binary. Verify with `uname -m`: it must print `aarch64` |
| 1× VPS | any Linux box, 1 core / 1 GB is plenty | runs the relay. ~€4/month tier from any provider is enough; bandwidth is kilobytes per second. **Its CPU architecture is whatever the provider sold you** — §2 asks the machine (`uname -m`) and builds the relay for it |
| 1× build machine | laptop/desktop with Go 1.23+ and `git` | builds the binaries. Any OS works; it does not run the chain |
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

On the build machine (any OS with Go 1.23+ and `git` installed), get the
source and build inside it:

```sh
git clone -b m4-real-networking https://github.com/cti97/b10coincom
cd b10coincom
```

(`-b` checks out the branch this recipe ships on — the deployment files are
not on `main` until the milestone merges.)

Build the two Linux/ARM64 **Pi** binaries:

```sh
scripts/deploy/build.sh          # builds AND asserts: runs scripts/build-release.sh --only linux/arm64 and copies the pair into bin/ under stable names
```

These two land in `bin/` (versions come from the source tree —
`internal/version`, currently `0.1.0` — not from build flags):

- `bin/b10coin-linux-arm64` — the node/validator binary (the Pis)
- `bin/b10coin-relay-linux-arm64` — the relay (runs **on the VPS**; whether
  this ARM64 copy is the right one for YOUR VPS is settled just below)

Confirm on the build machine that both really are ARM (a build that quietly
produced host binaries is the failure mode this check exists for):

```sh
file bin/*-linux-arm64
# bin/b10coin-linux-arm64:        ELF 64-bit LSB executable, ARM aarch64, ... statically linked
# bin/b10coin-relay-linux-arm64:  ELF 64-bit LSB executable, ARM aarch64, ... statically linked
```

The node binaries above are for the Pis. **The relay runs on the VPS, not on
a Pi, so it must match the VPS's own architecture** — the Pi pair cannot
know what that is. Ask the VPS before copying anything:

```sh
ssh vps@example.com uname -m
```

Two answers are likely:

- **`x86_64`** — the standard amd64 VPS almost every provider hands you by
  default. The ARM64 relay would fail here with `Exec format error` (§8,
  failure 4), so build the relay for the VPS — one line, on the build
  machine:

  ```sh
  scripts/deploy/build.sh linux/amd64
  file bin/b10coin-relay-linux-amd64
  # bin/b10coin-relay-linux-amd64:  ELF 64-bit LSB executable, x86-64, ... statically linked
  ```

  (`x86_64` and Go's `amd64` name the same architecture; the version and the
  artifact assertions come from the same release script as the Pi pair.) Copy
  **that** file to the VPS below, not the `-arm64` one.

- **`aarch64`** — an ARM64 VPS (some providers sell ARM tiers). The relay
  pair the Pi build already produced is the right one; nothing more to
  build. Copy `bin/b10coin-relay-linux-arm64` below.

Copy the binaries to the machine that runs each, then install (the static
binaries need no runtime packages; current 64-bit Raspberry Pi OS and any
current Debian/Ubuntu VPS run them as-is — the relay "as-is" only once it is
the architecture-matched file from the branch above):

```sh
# from the build machine — replace pi@ and vps@ with your real SSH targets
scp bin/b10coin-relay-linux-amd64 vps@example.com:/tmp/    # x86_64 VPS (uname -m above)
# scp bin/b10coin-relay-linux-arm64 vps@example.com:/tmp/  # aarch64 VPS: that line instead
for p in 192.0.2.11 192.0.2.12 192.0.2.13; do
    scp bin/b10coin-linux-arm64 pi@$p:/tmp/
done
```

On the VPS:

```sh
sudo useradd --system --home-dir /var/lib/b10coin --shell /usr/sbin/nologin b10coin || true
sudo mkdir -p /opt/b10coin
sudo install -m 0755 /tmp/b10coin-relay-linux-amd64 /opt/b10coin/b10coin-relay   # -arm64 on an aarch64 VPS
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

1. **the same binary** on all three Pis (copy all three from one `scripts/deploy/build.sh` run), and
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
the relay unit assumes inbound TCP 7001 and writes nothing to disk. From the
**build machine** (the only place with the checkout) — copy, edit, start:

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
chains (§8, failure 1: every node answers RPC and looks fine while the
committee never finalizes anything — judge it from the chain IDs and block
hashes below, never from reachability).

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

3. **The bar: one history.** All three Pis must name the **same block at
   the same height** — equal hashes at one height mean the committee
   finalized one shared chain. Do **not** compare the instantaneous
   `height` from a loop of SSH visits: blocks commit fast (on the order of
   a per second), and three sequential round trips usually land on
   different heights **even on a perfectly healthy committee**. The
   reliable manual check is the one `acceptance.sh` performs: pick one
   **fixed height `H` that all three Pis have passed** — any height you
   saw on every Pi, so after a few minutes any small number works — and
   compare what each node reports for block `H`:

   ```sh
   H=50   # must be behind every Pi: any height from the /status calls above
   for p in 192.0.2.11 192.0.2.12 192.0.2.13; do
       ssh pi@$p curl -s http://127.0.0.1:8645/block/$H
   done
   ```

   Three replies with the **identical `"hash":"…"`** (their `height` fields
   all read `H` — a node asked before the committee reached `H` answers
   `404 height not found`; wait a moment and retry): **the testnet
   works** — that is M4's acceptance criterion met on real hardware across
   separate networks. One more judgement rule, and it matters: a `height`
   or `head_hash` that differs between Pis is **not a fault** as long as
   the block at the fixed height hashes identically everywhere — only the
   fixed-height hash is the verdict. Chain identity comes from the same
   `/status` calls as in step 2: `chain_id` must be identical on all three
   (§8, failure 1).

   **This whole check is one command:** `scripts/deploy/acceptance.sh`
   runs §7 for you — two `/status` readings per Pi (reachability, then an
   *increased-height* requirement, so a stalled network that still agrees
   cannot look healthy), then agreement as the fixed-height block-hash
   comparison above (at the committee's common height), plus a relay
   probe. Verdict labels map to §8's failures 1–3 (failure 4 is an
   install fault no running network can exhibit); `--help` lists them
   with their exit codes:

   ```sh
   scripts/deploy/acceptance.sh --pis 192.0.2.11,192.0.2.12,192.0.2.13 --relay example.com
   ```

## 8. When it does not work: the four failures

Failures 1–3 all look alike from the outside — a quiet node at height 0 —
so judge them by these signatures, in this order. Failure 4 never gets that
far: the binary itself refuses to run, so it announces itself the moment
you start it.

| # | Failure | Signature (how you tell) | Fix |
|---|---|---|---|
| 1 | **Chain-ID / genesis mismatch** — one node runs a different `--validators` (or an older binary) and derives a different chain | `journalctl -u b10coin \| grep listening` — the `chain …` part of the banner **differs** between Pis (e.g. `b10coin-simnet-3` vs `b10coin-simnet-4`). Nodes on different chains never object; they just ignore each other forever | Stop the odd node; start it from the **same binary build** with the same `--validators 3` as the others (§3). No other remedy exists |
| 2 | **Relay unreachable** — relay not running, VPS address wrong, port 7001 closed in the cloud firewall or ufw | All chain IDs **match**, but from a Pi: `timeout 3 bash -c '</dev/tcp/example.com/7001' && echo open` prints nothing. On the VPS: `systemctl status b10coin-relay` and `ss -tlnp | grep 7001` tell you whether it listens at all | Start the relay (`systemctl enable --now b10coin-relay`), open TCP 7001 in the security group and `sudo ufw allow 7001/tcp`. Nodes redial with backoff; nothing to restart on the Pis |
| 3 | **Wrong `--index`** — two Pis share a seat, i.e. one validator key used by two machines | Chain IDs all match, relay reachable, yet heights stall. `journalctl -u b10coin \| grep committee` shows **the same `seat N` on two Pis** (the three must read `seat 0`, `seat 1`, `seat 2` in some order) | Set a unique `B10COIN_INDEX` on one of the two duplicates (`/etc/systemd/system/b10coin.service`), then `sudo systemctl daemon-reload && sudo systemctl restart b10coin` |
| 4 | **Wrong-architecture binary** — e.g. the ARM64 relay copied onto a standard amd64 (x86_64) VPS, or either binary onto a 32-bit OS | The binary refuses to start at all: running it directly prints `Exec format error` / `cannot execute binary file`, and systemd's log (`journalctl -u b10coin-relay`) shows the same with exit `status=203/EXEC`. Confirm with `file /opt/b10coin/b10coin-relay` — the architecture it names must match what `uname -m` prints on that machine | Rebuild for the machine's own architecture (§2's `uname -m` step: the VPS almost always wants `b10coin-relay-linux-amd64`, from `scripts/deploy/build.sh linux/amd64`), reinstall with `install -m 0755`, and nothing on the Pis changes |

Quick disambiguation: the binary will not start (`Exec format error`) → 4;
chain IDs differ → 1; chain IDs match and the relay port test fails → 2;
chain IDs match, relay reachable, a `seat` repeats → 3. And a non-fault: Pis
at slightly different heights whose fixed-height block hashes agree (§7.3)
are healthy — do not chase it.
If the table and logs genuinely cannot place the fault, reproduce the
committee locally on one machine (`make devnet`) to confirm the build
consensus-works, and treat the difference as network.

---

One repeated rule, because it costs hours when ignored: **one build for the
three Pis (all three from one `scripts/deploy/build.sh` run), one `--validators` value on
all, and one `B10COIN_INDEX` per machine; the VPS relay only has to match
the VPS's own architecture (§2), not the Pis'.** Everything else in this
recipe is plumbing around that.
