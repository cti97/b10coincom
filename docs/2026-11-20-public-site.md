# The public site: b10coin.com (landing + live chain)

Date: 2026-11-20. Scope: how the public web presence is built, deployed and
operated. Audience: whoever has to change, debug or rebuild it. Everything here
is reproducible from the repository plus the two hosts it names (this Mac and
the relay VPS at `93.115.53.244`).

## 1. What exists

| URL | What it is | Source |
| --- | --- | --- |
| `https://b10coin.com/` | landing / presentation page | `docs/site/index.html` in this repo → `/usr/share/nginx/b10coin.com/html/index.html` |
| `https://b10coin.com/live/` | live chain page (explorer) | `docs/site/live.html` → `…/html/live/index.html` |
| `https://b10coin.com/live/chain.json` | chain snapshot (height, head, params, last 8 blocks) | pushed from this Mac every 15 s |
| `https://b10coin.com/live/relay.json` | relay counters (conns, forwarded, drops by reason) | VPS cron, once a minute |
| `https://bitgod.xyz/b10coin/` | the same two pages under an existing site | **symlink** to the same root — never a copy |

The pages are static: no server-side code, no database, no secrets. All liveness
comes from two JSON files that something else writes.

## 2. Why a pusher, and not a proxy

The validator seat (and therefore the chain's HTTP RPC) runs on this Mac, behind
NAT, with no public address. The VPS cannot reach `127.0.0.1:8645`, and exposing
that RPC publicly would expose `/tx` and `/faucet` too — write-capable endpoints
that must stay private.

So the direction is reversed: the Mac **pushes** a read-only snapshot to the VPS.
The public site never talks to a node.

```
  Mac (seat 2, behind NAT)                     VPS 93.115.53.244
  ┌──────────────────────────┐                ┌──────────────────────────────┐
  │ b10coin node RPC :8645   │                │ nginx :80                    │
  │  /status   /block/<h>    │  ssh, every    │  /            landing        │
  │        │                 │  15 s, atomic  │  /live/       chain page     │
  │        ▼                 │  rename        │  /live/*.json snapshots      │
  │ launchd com.b10coin.push │ ─────────────► │                              │
  │  push-status.sh          │                │ cron (1 min): relay-json.sh  │
  └──────────────────────────┘                │  └─ journalctl → relay.json  │
                                              └──────────────────────────────┘
```

## 3. Host layout

```
/usr/share/nginx/b10coin.com/html/          # site root, owner b17g0d:b17g0d
├── index.html                              # landing page
└── live/
    ├── index.html                          # chain page
    ├── chain.json                          # written by the Mac pusher
    └── relay.json                          # written by the VPS cron

/etc/nginx/sites-available/b10coin.com      # vhost (symlinked into sites-enabled)
/usr/share/nginx/bitgod.xyz/html/b10coin -> /usr/share/nginx/b10coin.com/html
/home/b17g0d/relay-json.sh                  # relay.json generator (cron)
~/b10coin-node/push-status.sh               # chain.json pusher (Mac)
~/Library/LaunchAgents/com.b10coin.push.plist
```

The directory is owned by `b17g0d` on purpose: both producers write without
`sudo`, and nothing in the deploy path needs root except nginx itself.

The `bitgod.xyz` entry is a **symlink to the root**, so `/b10coin/` there serves
the landing page and `/b10coin/live/` the chain page. Do not copy files into
`bitgod.xyz`; replace the symlink target only.

## 4. nginx

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name b10coin.com www.b10coin.com;

    root /usr/share/nginx/b10coin.com/html;
    index index.html;
    charset utf-8;

    location / { try_files $uri $uri/ =404; }
    location = /live { return 301 /live/; }
    location /live/ {
        try_files $uri $uri/ =404;
        add_header Cache-Control "no-cache";   # snapshots must not be cached
    }
    location ~ /\.ht { deny all; }
}
```

Facts worth remembering:

- There is exactly **one** server block for the name (`nginx -T | grep -c
  "server_name b10coin.com"` → 1). A duplicate would silently shadow this one.
- The origin listens on **:80 only**. TLS is Cloudflare's job (§6); there is no
  `:443` listener and no Let's Encrypt certificate on this host.
- The origin must **not** redirect http→https while Cloudflare runs in
  *Flexible* mode, or every request loops.
- `nginx -t && systemctl reload nginx` after any edit; a full `restart` is only
  needed when the user asks for one or when listeners changed.

## 5. Data producers

### 5.1 `chain.json` — the Mac pusher

`~/b10coin-node/push-status.sh`, run by launchd (`com.b10coin.push`) every 15 s:

1. `curl http://127.0.0.1:8645/status` (height, head hash, state root, mempool,
   chain parameters). Exits silently if the RPC is down — a stale page is the
   correct display for a dead node.
2. Fetches the last 8 `/block/<h>` for the recent-blocks table.
3. Emits JSON with `updated` (unix seconds) and `blocks[]`.
4. Pushes it in **one** ssh round trip, writing `chain.json.new` then `mv` — a
   reader never sees a half file.

Operate it with:

```sh
launchctl print gui/$(id -u)/com.b10coin.push | head -20   # state
launchctl bootout  gui/$(id -u)/com.b10coin.push            # stop
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.b10coin.push.plist
sh ~/b10coin-node/push-status.sh                            # one manual run
tail -f ~/b10coin-node/push.log                             # errors only
```

The pusher reads no credentials: the relay token is irrelevant to it and the RPC
is loopback-only.

### 5.2 `relay.json` — the VPS cron

`/home/b17g0d/relay-json.sh`, from `crontab -l`:

```
* * * * * /home/b17g0d/relay-json.sh >/dev/null 2>&1
```

It reads the relay's last `stats:` journal line (`sudo -n journalctl`), turns the
`key=value` pairs into integers, adds `updated`, and writes atomically. This is
where the v0.1.6 drop accounting becomes visible: `dropped` is the sum, and
`dropped_on_close` / `dropped_reap` say whether frames were abandoned at an
ordinary teardown or by the write-deadline reap.

## 6. DNS and TLS (Cloudflare)

The domain is fronted by Cloudflare, which terminates TLS. Requirements:

1. **Proxied records.** `b10coin.com` must be an **A record → 93.115.53.244,
   Proxied (orange cloud)**; `www` must be a proxied CNAME to `b10coin.com`
   (plus an optional Redirect Rule `www → apex`). A grey-clouded A record
   bypasses Cloudflare entirely: HTTPS then fails because the origin has no
   certificate, and that is exactly the state this site was in before 2026-11-20.
2. **SSL/TLS mode.** *Flexible* works with this origin as-is (Cloudflare →
   origin over HTTP :80). *Full (strict)* additionally needs a certificate on
   the origin: generate a Cloudflare Origin Certificate for `b10coin.com` and
   `*.b10coin.com`, install it, add a `:443` server block, and only then add the
   `:80 → https` redirect. Never add that redirect while the mode is Flexible.
3. **What Cloudflare does not do for you:** it does not proxy a record you left
   grey, and it does not fix a `www` record pointing at somebody else's service
   (this domain's `www` pointed at an `onrender.com` chain from the registrar).

Verification from anywhere:

```sh
dig +short b10coin.com            # Cloudflare anycast IPs when proxied
curl -sI https://b10coin.com/     # 200, server: cloudflare
curl -s  https://b10coin.com/live/chain.json | head -c 200
```

## 7. The pages

Both are single self-contained HTML files, no external assets, no trackers, no
fonts to fetch. Dark theme, responsive, and they degrade honestly:

- They poll (`chain.json` every 8 s on the chain page, 10 s on the landing) with
  a cache-busting query.
- A `live` / `stale` / `no data` pill is derived from `updated`: under 45 s is
  live, under 5 min is stale, beyond that is no data. A dead node looks dead,
  not frozen at old numbers.
- **Block rate is measured between height changes, not between polls.** The
  snapshot is pushed every 15 s, so a per-poll delta reads 0 most of the time;
  the rate is smoothed over changes and shown as `—` once the last change is
  older than two minutes.
- The landing page carries the project's own honesty: fixture committee (keys
  derive from a public seed), no sale, no mainnet, and the known consensus
  residual (a round divergence can pause production for minutes).

Fixture-chain block timestamps are synthetic (`genesis time + height`), so the
times in the recent-blocks table are chain time, not wall clock.

## 8. Runbook

**The page says stale / no data.**
1. `pgrep -f b10coin-0.1.8` on the Mac — is the seat running?
2. `curl -s 127.0.0.1:8645/status` — is the RPC answering?
3. `tail -20 ~/b10coin-node/push.log` — is the pusher erroring (usually ssh)?
4. `ssh b17g0d@93.115.53.244 'crontab -l; ls -l /usr/share/nginx/b10coin.com/html/live'`
   — is `relay.json` fresh?

**Changing the pages.** Edit `docs/site/index.html` / `docs/site/live.html` in
this repo, then:

```sh
scp docs/site/index.html b17g0d@93.115.53.244:/home/b17g0d/landing.html
scp docs/site/live.html  b17g0d@93.115.53.244:/home/b17g0d/live.html
ssh b17g0d@93.115.53.244 '
  install -m 0644 /home/b17g0d/landing.html /usr/share/nginx/b10coin.com/html/index.html
  install -m 0644 /home/b17g0d/live.html    /usr/share/nginx/b10coin.com/html/live/index.html'
```

**Changing the vhost.** Edit `sites-available/b10coin.com`, then
`nginx -t && systemctl reload nginx`; verify with
`curl -H 'Host: b10coin.com' http://127.0.0.1/` and the four paths in §9.

## 9. Acceptance checks

```sh
# origin, by name
for p in / /live/ /live/chain.json /live/relay.json /nope; do
  printf '%-18s -> ' "$p"
  curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: b10coin.com' "http://127.0.0.1$p"
done
# expect 200 200 200 200 404

# the alias serves the same bytes
curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: bitgod.xyz' http://127.0.0.1/b10coin/live/

# public
curl -s https://b10coin.com/ | grep -o '<title>[^<]*</title>'
curl -s https://b10coin.com/live/chain.json | python3 -c \
  'import json,sys,time; d=json.load(sys.stdin); print(d["height"], int(time.time())-d["updated"], "s old")'
```

## 10. Known issues

- **Single pusher host.** If this Mac is off, the page says stale within a
  minute. That is by design (honest staleness), but it means the site's
  liveness is the seat's liveness.
- **15 s granularity.** The landing strip and the chain page are at most one
  push interval behind; the rate needs two pushes to appear.
- **Origin is HTTP-only.** TLS is Cloudflare's; `Full (strict)` needs the origin
  certificate described in §6.
- **Cosmetic log noise.** `/favicon.ico` 404s (no icon is shipped), and the
  `bitgod.xyz` vhost tries `index.php` before `index.html` under the symlinked
  path before falling through to the HTML. Neither affects responses.
- **Fixture chain.** The numbers on the page are a plumbing testnet — the
  committee's keys are public, and the chain carries no value.
