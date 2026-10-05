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
| 1× build machine | laptop/desktop with Go 1.26+ and `git` | builds the binaries. Any OS works; it does not run the chain. It also assembles the committee file (§3.2) from the public keys the Pis' `keygen` runs printed |
| SSH access | to all four machines | everything below happens over SSH |

Why the VPS: a validator running at home sits behind NAT — or behind CGNAT,
where there is no public IP to forward a port to at all. The VPS has one,
so **every Pi connects outbound to the relay and no Pi ever needs an inbound
rule**. Outbound is almost never blocked; inbound is almost never possible.
The relay itself is deliberately dumb: it forwards signed frames between
connected peers and understands nothing. Because every consensus message is
signed with the sender's key, a malicious relay can censor or delay, but
cannot forge a **vote or a proposal** — safety is never at risk from the
relay, only liveness. That trade holds only for committees of **held keys**:
validators started with `--genesis` (the shared committee file of public
keys) and `--key` (`b10coin keygen`). The development fixture committee
(`--validators/--index`) derives every member's private key from public
seeds, so with it anyone can sign as any seat, and no property of the relay
matters — never point a fixture committee at a relay reachable beyond your
own machines. (`b10coin-relay --help` after install prints this trade in full.)

## 2. Build the binaries and copy them over

On the build machine (any OS with Go 1.26+ and `git` installed), get the
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

## 3. The committee file and the keys — read this first

> **⚠️ Fixtures are public; this deployment is not one.** b10coin can also
> run a committee derived from public seeds (`--validators N --index I`, and
> `devnet --validators N`). That committee's private keys are **public
> knowledge** — anyone with this repository can sign proposals, prevotes and
> precommits for any of its seats, and the chain ID (`b10coin-simnet-N`)
> publishes the committee size. It exists for development and acceptance
> runs only; a node started that way prints a loud warning. The recipe below
> therefore uses **real generated keys and a committee file** — precisely so
> that no seat's key can be derived by a stranger and none of the trust
> claims elsewhere in this file are built on fixture keys.

> **⚠️ The most likely first failure of this entire deployment.** All three
> validators must run the SAME chain: one shared **committee file**
> (identical bytes on every Pi) plus each machine's own **key file**. Two
> validators on different committee files do not print an error at consensus
> time: they silently ignore each other's messages and every node sits at
> height 0 forever. The loud path is the refusal you WANT to see: a node
> whose `--key` is not listed in the committee file **refuses to start**.

### 3.1 Generate one key per Pi (on the Pi, so the private key never leaves it)

On each Pi, after the binary is installed (§2):

```sh
# on Pi 0, Pi 1 and Pi 2 alike — one key file per machine, never copied
sudo -u b10coin /opt/b10coin/b10coin keygen --out /var/lib/b10coin/b10coin.key
```

It prints:

```text
key file     /var/lib/b10coin/b10coin.key (owner-only 0600; regenerate elsewhere, never over this one)
public key   a4198cc4f3ee076a810f62c3fa58502c3d13a1d5b54ca99a257ba9686c27853c
seat address b10tleywhxwbe7uw54ty57hit34rf2pbjstmhk4j7i
```

Copy the three `public key …` lines somewhere safe now. The key file itself
refuses to be overwritten (`refusing to overwrite an existing key file`), so
a rerun cannot replace a key under you; if you lose a printed line, read the
`public_key` field back from the file (`sudo -u b10coin sed -n 4p
/var/lib/b10coin/b10coin.key` — the file is not secret to its own machine,
only to group/others).

**Never copy the key file between machines.** Two Pis holding one file are
two machines acting as ONE validator (same seat, same signatures) and the
committee stops finalizing — that failure and how to spot it are §8's
failure 3.

### 3.2 Write the committee file (on the build machine) and share it verbatim

```json
{
  "chain_id": "example-testnet-1",
  "note": "optional human annotation — never enters the genesis hash",
  "validators": [
    { "name": "pi-0", "pubkey": "<Pi 0's public key hex>", "power": 1 },
    { "name": "pi-1", "pubkey": "<Pi 1's public key hex>", "power": 1 },
    { "name": "pi-2", "pubkey": "<Pi 2's public key hex>", "power": 1 }
  ]
}
```

A checked example lives at `scripts/deploy/committee.example.json`. The
binary enforces (refusing the file otherwise): `chain_id` non-empty — chosen
by you, and unlike the fixture's `b10coin-simnet-N` it must not be made to
encode the committee size; every `pubkey` a 64-hex-character Ed25519 public
key, with **duplicates refused** (one key holds one seat); `power` ≥ 1; and
**order matters** — a validator's seat is its entry's position. The file
carries the committee and nothing else: monetary and protocol parameters
stay the compiled-in devnet fixture values (trivial puzzle, 1 b10 claims,
2 s blocks), so a shared chain stays valueless test currency and no member
can rewrite its economy hand-edited. **Treat the file as final once the
chain starts** — editing it changes the genesis hash, i.e. it starts a
different chain.

Then copy the SAME file to every Pi:

```sh
# build machine; replace 192.0.2.x with the Pis' addresses
for p in 192.0.2.11 192.0.2.12 192.0.2.13; do scp committee.json pi@$p:/tmp/; done
# then on each Pi:
sudo install -o b10coin -g b10coin -m 0644 /tmp/committee.json /var/lib/b10coin/committee.json
```

### 3.3 The command each Pi must start on

Give every validator this exact command (run it on each Pi in the foreground
the first time, before systemd — §6):

```sh
# Pi 0 — Pi 1 and Pi 2 differ ONLY in their own key file
sudo -u b10coin /opt/b10coin/b10coin node \
    --dir /var/lib/b10coin \
    --relay example.com:7001 \
    --genesis /var/lib/b10coin/committee.json \
    --key /var/lib/b10coin/b10coin.key
```

Every node's first output lines name its chain — **all three must print the
identical chain ID** (the file's), and each its own seat:

```
b10coin 0.1.0 listening on http://127.0.0.1:8645 (chain example-testnet-1, height 0)
consensus    committee of 3, seat 0, key file /var/lib/b10coin/b10coin.key, dialled example.com:7001
```

A node that exits immediately with `refusing to start: this validator's
public key … is not listed in the committee's genesis` — fix its `--key` (or
the file it was handed); it will never sign for a seat it does not hold (§8,
failure 3). A node printing a different chain ID is on a different chain —
stop and fix that before anything else, using the checklist in §8, failure 1.

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
b10coin-relay forwarding on :7001 (max frame 1048576, max conns 32 (8 per prefix), queue 2097152 bytes / 4096 frames, read timeout 2m0s, write timeout 30s, keepalive 15s)
```

At the relay's defaults the memory a stranger can pin is
`max-conns × (write-queue-bytes + write-queue-frames × 32 + 2 × max-frame-bytes)`
= 32 × (2 MiB payload + 4096 × 32 B entry ring + 2 × 1 MiB hands) =
**32 × 4.125 MiB = 132 MiB** (one write-queue payload budget, the queue's
per-frame entry ring, and the one frame in each of the writer's and reader's
hands, per connection), held at most one read- or write-timeout — the unit's
`MemoryMax=256M` sits above that plus the runtime. The per-prefix cap (`8`
slots from any one source prefix — an IPv6 `/64` or IPv4 `/24`) keeps a
single host, or a whole routed prefix, from holding the registry.

The address the Pis dial is `<VPS public IP or DNS name>:7001`. The VPS must
allow inbound TCP 7001 **from the validators only** — both the cloud security
group (restrict the source, or scope it to the validators' IPs if your
provider's UI can) and, if enabled, the host firewall. The host-firewall step
is an ALLOWLIST, one line per validator — its outbound source IP — and never
a bare `ufw allow 7001/tcp` (the audit's A-1 found exactly that open rule in
the previous revision of this recipe):

```sh
# one ALLOWLIST line per validator — the Pi's outbound source IP
for p in 192.0.2.11 192.0.2.12 192.0.2.13; do
    sudo ufw allow from $p to any port 7001 proto tcp comment "b10 validator $p"
done
# verify: 7001 must appear ONLY as restricted rules, and any older open rule
# must be removed
sudo ufw status numbered
sudo ufw delete allow 7001/tcp   # only where this pre-allowlist rule exists
```

Two cautions on keeping the allowlist current: a home Pi's outbound IP can
change (ISP DHCP, CGNAT pools) — re-check each Pi's address whenever the
allowlist seems stale (`curl -s ifconfig.me` from the Pi) and refresh the
line; and the security group counts too, not only ufw. The relay
authenticates nothing by design, so whatever can reach 7001 can flood, pin
connection slots and censor honest votes (its `--help` records the bound it
puts on that) — allowlisting the validators is what keeps strangers off.

The relay binds everything a stranger controls (frame size, connection
count, per-connection buffers, stalled-read timeout) and authenticates
nothing: anyone who finds the port may connect, so its abuse ceiling is
fixed by those flags — see `b10coin-relay --help` for the full trust trade
and knobs.

## 5. Each validator's command

The command each Pi runs (systemd runs exactly this per §6; §3 shows the same
thing with `sudo -u b10coin` for first contact):

```sh
# Pi 0 — Pi 1 and Pi 2 differ ONLY in B10COIN_KEY (their own key file)
/opt/b10coin/b10coin node \
    --dir /var/lib/b10coin \
    --relay example.com:7001 \
    --genesis /var/lib/b10coin/committee.json \
    --key /var/lib/b10coin/b10coin.key
```

| Flag | Meaning |
|---|---|
| `--dir` | this node's data directory — its chain database lives here. Each Pi keeps its own |
| `--relay` | the VPS's `<host>:7001` from §4. All consensus traffic flows through it; this is the only address a home Pi needs to reach |
| `--genesis` | the shared committee file (§3.2) — the committee's public keys, the chain ID. **Byte-identical on all three Pis; final once the chain starts** |
| `--key` | THIS machine's key file (§3.1) — unique per Pi; a key not listed in the committee file **refuses to start** rather than signing as a foreign seat |
| `--http` (default `127.0.0.1:8645`) | RPC status endpoint, loopback-only by default. Read it via SSH (§7) rather than opening it to your LAN |
| `--listen`, `--peers` | optional **direct** peer connections (same-LAN or port-forwarded setups). With the relay star they stay off; a dial list is already complete via `--relay` |

**The seat is derived, not configured.** A node's seat is the position of its
public key inside the shared committee file, so there is no `--index` here
any more: the machine that presents key `k` acts as the seat `k`'s entry
occupies, and cannot claim any other. The `--validators`/`--index` pair is a
DEVELOPMENT-ONLY fixture (derived public keys — §3's warning); it is refused
alongside `--genesis` so the two ways to name a committee cannot be mixed by
accident or by mistake.

If you lose track of which Pi holds which seat: the banners name it
(`seat N, key file /var/lib/b10coin/b10coin.key`), and
`sudo -u b10coin /opt/b10coin/b10coin keygen --out /tmp/probe.key` on a Pi
prints a NEW key's public half — never load such a probe key as a member;
generate, read, delete.

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
declares everything configurable as `Environment=` lines. Two name shared
facts and one names a per-machine fact: `B10COIN_RELAY` and
`B10COIN_GENESIS` are the same on every Pi (the VPS's address; the shared
committee file), while `B10COIN_KEY` — this Pi's key file from §3.1 — MUST
be different (a duplicated key file is §8's failure 3), and the key file
itself must be owned by `b10coin` and mode 0600, which `keygen` wrote it as.

```sh
scp scripts/deploy/b10coin.service pi@192.0.2.11:/tmp/
sudo install -m 0644 /tmp/b10coin.service /etc/systemd/system/
sudo nano /etc/systemd/system/b10coin.service   # set B10COIN_RELAY; GENESIS/KEY already match §3's paths
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
   b10coin 0.1.0 listening on http://127.0.0.1:8645 (chain example-testnet-1, height 0)
   consensus    committee of 3, seat 0, key file /var/lib/b10coin/b10coin.key, dialled example.com:7001
   ```

   Same chain ID on all three (it comes from the shared committee file §3.2);
   seats 0, 1 and 2, each derived from a DIFFERENT key file — no repeats, and
   no `FIXTURE COMMITTEE` warning (that one belongs to the development path,
   and its presence here means the wrong node mode is running).

2. **The chain advances.** The node prints nothing more to the terminal
   while it runs — progress is read from its RPC. On each Pi:

   ```sh
   curl -s http://127.0.0.1:8645/status
   {"chain_id":"example-testnet-1","height":57,"head_hash":"9e0f…","state_root":"…","mempool":0}
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
| 1 | **Committee-file / binary mismatch** — one node runs a different (or hand-edited) `committee.json`, or an older binary | `journalctl -u b10coin \| grep listening` — the `chain …` part of the banner **differs** between Pis (the chain ID comes from the shared file §3.2; an older binary that cannot read `--genesis` exits before any banner). Nodes on different chains never object; they just ignore each other forever | Stop the odd node; start it from the **same binary build** with the same **committee.json bytes** the others run (§3.2). No other remedy exists — a changed committee file is a different chain |
| 2 | **Relay unreachable** — relay not running, VPS address wrong, port 7001 closed in the cloud firewall, or this Pi's source IP missing from the ufw allowlist | All chain IDs **match**, but from a Pi: `timeout 3 bash -c '</dev/tcp/example.com/7001' && echo open` prints nothing. On the VPS: `systemctl status b10coin-relay` and `ss -tlnp \| grep 7001` tell you whether it listens at all; `sudo ufw status numbered` tells you whose access was refused | Start the relay (`systemctl enable --now b10coin-relay`), open TCP 7001 in the security group, and add the **allowlist line for this Pi's current IP** (§4 — a bare open port is the audit finding, never the remedy). Nodes redial with backoff; nothing to restart on the Pis |
| 3 | **One identity, two machines** — the same key file on two Pis, so both act as the same seat | Chain IDs all match, relay reachable, yet heights stall. `journalctl -u b10coin \| grep consensus` shows **the same `seat N` on two Pis** — with genesis-file mode the seat is derived from the key, so two machines sharing `b10coin.key` share every signature they make. A related loud case: a node whose key is NOT in the committee file **exits at startup** with `refusing to start … not listed` | `b10coin keygen` on the offending Pi (its old key file must be renamed away first — keygen refuses to overwrite), add the NEW public key to the committee file and redistribute it — remembering a committee-file edit changes the chain identity, so this is for bring-up, not for a chain history that already exists |
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
three Pis (all three from one `scripts/deploy/build.sh` run), one committee
file shared byte-identically on all (§3.2, final once the chain starts), one
key file per machine — generated on that machine (§3.1) and never copied —
and the VPS relay reachable only through the validators' allowlist (§4).**
The VPS relay only has to match the VPS's own architecture (§2), not the
Pis'. Everything else in this recipe is plumbing around that.
