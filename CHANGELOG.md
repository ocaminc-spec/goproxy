# Changelog

## v2.8.2 — 2026-10-29
Stability, device insight and a phone-first dashboard. First public release by Ocam.
### Added
- **Devices**: per-device lookups, top sites, blocked/failed counts, average answer time and a 24 h hourly sparkline. Searchable and sortable in Pro; *Top devices* card in Simple. Aggregated counts only, stored locally (`goproxy-devstats.json`), capped at 256 devices and 60 sites each on disk.
- **Automatic `.home` names** learned from the router's reverse lookups (read-only, `-ptr-server`); manual names in Settings › Local names always win.
- **Health & stability card**: status, saved answers restored after restart, last backup and watchdog (from `goproxy-ops.json`, written by the optional host scripts).
- **Customize layout**: drag or ↑/↓ cards, hide/show, saved per browser, *Reset layout*.
- Phone layout: bottom tab bar, single-column cards, 44 px touch targets, no horizontal scroll.
- Skeleton loaders, friendly empty states, plain-English tooltips, visible keyboard focus, crossfades that respect reduced motion.
- Panic recovery on the DNS query path and new API handlers (a bad lookup returns SERVFAIL instead of crashing).
- Container HEALTHCHECK uses the built-in self-test name (no internet dependency).
### Changed
- Simple mode: live graph moved to Pro; *What's happening* merged into *Health & stability*.
- `-ptr-server` now defaults to `off` (set it to your router's IP).
- `-version` prints `GoProxy DNS <version> by Ocam`.

## v2.8.1 — 2026-10-29
Fixes the Version tab and adds a Simple/Pro dashboard, an Update impact card and faster cold lookups.
### Fixed
- Version tab froze the browser: the pane-animation observer re-added the class it was watching (endless loop). Panes now fade in with the Web Animations API, only when they become visible.
- No more `/favicon.ico` 404 on every load (inline icon).
- In a container (online updates off) the "Update from file…" and SHA-256 row is hidden; the update-status poll backs off on errors instead of retrying every 0.7 s forever.
- Count-up animation never touches version text.
### Simple and Pro
- **Simple** (default): health ring, average speed, cache share, blocked count, one live graph, top 5 sites and plain-language alerts. Technical knobs hidden.
- **Pro** (remembered): query log with search and filters (5,000 kept in memory), per-upstream latency histograms and race details, cache inspector (search, remove a record or a whole name), raw metrics (Prometheus text), settings export/import, ⌘K / Ctrl K command palette, shortcuts (`/` `p` `g d` `g v` `r`), denser layout.
### Update impact
- Every version is recorded with its install time (`goproxy-versions.json`, kept across restarts and in backups). 2.8.0's install time is estimated from the oldest history minute.
- New 30-day minute file `goproxy-impact.bin` (fixed 6 MB): cold and cached latency histograms, CPU and memory.
- Version tab card compares 24 h before vs after each update: cold median/p95/average, cached median/p95, cache hit, failures, CPU, memory, with green/red changes.
- Version markers on the Speed history chart; `/api/version` lists them (no other data) for other home dashboards.
### Faster upstreams (each can be switched off in Smart settings)
- Warm connections: idle encrypted upstreams get a tiny query every 15 s so the TLS/HTTP/2 connection is never cold (on).
- Serve stale at once (RFC 8767): an expired answer is returned immediately with TTL 30 s and refreshed in the background, for up to 1 day (on).
- Nearest anycast address: a provider's sibling address is used when it connects ≥20% (and ≥2 ms) faster, with the certificate still checked against the original name; skipped when the sibling is already one of your upstreams, so the race keeps its diversity (on).
- HTTP/3 (QUIC) for DoH, falling back to HTTP/2 per server for 10 min after a failure (off, experimental).
- Already in place: HTTP/2 multiplexing, TLS session resumption, keep-alive pings, large UDP buffers and one listener per core.

## v2.8.0 — 2026-10-29
A smarter server, plus an Apple-style polish for the whole dashboard: frosted-glass header and section bar, spring motion, numbers that count up, charts that draw in, skeletons while loading, and a light/dark/auto switch. Motion is turned off when the system asks for reduced motion.
### Smart server (all on by default unless noted)
- **Smart upstreams**: every upstream is probed once a minute. Lookups race only the best 3 (by speed × success). Every 20th lookup tries one of the others. Slow or failing upstreams are benched for 5 minutes, and at least 3 healthy ones always stay in the race.
- **Prefetch limit**: popular answers are refreshed before they expire, at most 20 per second.
- **Habits**: learns which names are busy at each hour of the week and pre-warms them a few minutes before (totals only, at most 40 names at 5 per second).
- **Self-healing**: if lookups slow down, fail or the cache share drops, it races everyone for 10 minutes, benches the worst upstream or re-warms the cache. Alerts go through your existing webhook.
- **Weekly report card**: grade, cache, speed and reliability rings, a daily chart, top domains and anything unusual.
- **Suspicious domains**: random-looking (DGA) names and DNS tunneling are reported. Alert only; blocking is optional.
- **Threat feeds** (off by default): URLhaus and Phishing Army sinkholes.
- **DNSSEC strict** (off by default): your encrypted upstreams already validate. Strict turns off the CD=1 retry.
- **Adaptive TTL**: stable answers are kept up to 2× longer (max 1 h). Answers that keep changing are kept shorter, but never under the 60 s floor.
- **History on disk**: 30 days at one-minute resolution in a fixed 5.5 MB file. Pick 1h, 24h, 7d or 30d.

## v2.7.0 — 2026-10-29
All new views share the Live graph's look: monotone curves, soft gradient fills, thin gridlines, big eased numbers, rounded cards, one accent colour per metric.
### Live insights (collected only while the dashboard is open; memory only)
- **Top domains**, rolling 1 or 5 minutes, with gradient bars.
- **Blocked & failed feed** (last 200), newest first. Device addresses only with *Devices by volume* on.
- **24 h response-time heat grid** (10-minute columns × 11 latency bands), from a new per-bucket latency histogram in the health history.
- **Upstream race**: per-upstream win share and average answer time, per second, last 2 minutes.
- **Live graph** gains a CPU strip (GoProxy process % of the machine, dashed host CPU %; memory under the number) and an **Active clients** strip (distinct client IPs in the last 60 s). Count only; addresses only with *Devices by volume* on.
### Protection, alerts, sync & backup (new settings card)
- **Ad & tracker blocking**: subscriptions (default StevenBlack hosts + OISD small), allow and block lists, blocked-lookup counter. **Off by default**; nothing is downloaded while off. Can be switched on from the dashboard (no restart).
- **Alerts engine**: slow (p95 over 5 min > 300 ms) and failing (> 20 % of lookups over 5 min), thresholds editable. Optional **webhook** (ntfy / Pushover / generic JSON), **off by default with no address**; URL and token stored encrypted, masked in the API, never logged; at most one message per alert per 30 min; "Send test".
- **Peer sync** of blocking settings, local names, ads settings and alert thresholds over the token-authenticated peer API (`GET /api/peer/sync`, pull only). Newest change wins; after the upgrade nothing is overridden until a setting is changed or **Sync now** is pressed. Secrets and device rules never travel.
- **Peer watch**: a peer that misses 3 checks in a row (~90 s) raises an alert (and the webhook, if on).
- **Nightly backup** (after 03:00) of settings, history, secret key, auth, kiosk and groups files into `<data>/backups/YYYY-MM-DD_HHMMSS/` (folders 0700, files 0600), 7 kept, "Back up now". Contents are never logged.
- **Per-device** live view, blocking and bedtime schedules, **only** with the *Devices by volume* approval switch on.
### API (login required)
`/api/v27/insights`, `/api/v27/config`, `/api/v27/sync`, `/api/v27/backup`, `/api/v27/webhook/test`, `/api/v27/devices/live`; `/api/health/live` points gain `cpu_proc`, `cpu_host`, `mem_mb`, `host_mem_pct`, `clients`.

## v2.6.1 — 2026-10-29
### New: 1-minute and 5-minute Health views
- The Health Score card has a **1 min / 5 min / 24 h** selector. 1 min shows 12 buckets of 5 s (refreshes every 5 s), 5 min shows 20 buckets of 15 s (every 15 s); scores, bars, scrubber and the query / cache / latency / error stats all follow the chosen window. The choice is remembered in the browser.
- Backed by an in-memory ring of 5-second buckets (last 5 minutes, not persisted). Health is now sampled every 5 s (was 10 s); the 24 h history and its file are unchanged.
- **Live** option (Live / 1 min / 5 min / 24 h): a real-time scrolling graph of the last 2 minutes, one point per second: queries/sec, average and p95 response time (estimated from the latency histogram), cache hit % and failures/sec. Switch back to any other range to see the Health Score again.
  - UniFi-style look: smooth monotone curves (no overshoot), soft gradient fill under each line, thin dashed gridlines, large eased current values on top, a colour per metric, continuous right-to-left scrolling (requestAnimationFrame, ~30 fps, paused when the tab is hidden, crisp on high-DPI screens).
  - Backed by a 1-second in-memory ring (120 points) that only samples while someone has the Live view open (idle 30 s after the last poll), so it costs nothing otherwise. Login required: `/api/health/live`. The browser polls once a second and pauses while the tab is hidden.
- API: `/api/health?window=1m|5m` (default / `window=24h` unchanged, now also returns `"window"`).

## v2.6.0 — 2026-10-29
### New: Parallel upstream ("parallel syncing")
- Every cache miss is sent to **all** raced upstreams at once (every encrypted server in the list; plain UDP servers below the top stay fallback-only for privacy); the **first valid answer (NOERROR/NXDOMAIN) wins** and the rest are cancelled. A SERVFAIL/REFUSED or error from one server never wins while another succeeds.
- Setting **Parallel upstream** (Advanced tab, default **on**, `-parallel-all=false` turns it off and restores the v2.5.1 race-first + hedge behaviour). Used from the next start.
- Dashboard shows the mode and the **last winning upstream**; per-server wins as before (`/api/stats`: `parallel_all`, `last_winner`).
### New: cache size in MB, 60 s TTL floor
- `-cache-mb` / *Cache size (MB)* in Advanced (64–65536; overrides `-cache-gb`; entries = budget/512 B, e.g. 500 MB ≈ 1.02 M entries).
- `-min-ttl` (*Minimum TTL*) now defaults to **60 s** (pinned names keep 300 s, `-min-ttl-exempt` CDN names and HTTPS/SVCB keep their real TTL). Set 0 for the v2.5 behaviour.
### Changed: encrypted defaults, Cloudflare + Google over DoH **and** DoT
- Default DNS Servers: `https://1.1.1.1/dns-query`, `https://dns.google/dns-query` (bootstrapped by IP), `tls://1.1.1.1:853`, `tls://8.8.8.8:853`, all raced in parallel over pooled keep-alive connections (HTTP/2 for DoH, reused TLS sessions for DoT). UltraDNS is no longer in the defaults (still a preset). New presets: Google (dns.google), Cloudflare DoT (1.1.1.1), Google DoT (8.8.8.8).
- **Fall back to plain DNS** (`-plain-fallback`, Advanced > Upstreams, default **on**): only when every encrypted server fails, the plain fallbacks `8.8.8.8:53, 1.1.1.1:53` are asked. Off = encrypted only.
- The dashboard shows the winning server **with its transport** (e.g. `Cloudflare DoT (1.1.1.1) (DoT)`).
### New: performance profiles (`-profile max|balanced`, default max)
- max: one SO_REUSEPORT UDP socket per core, 4 MB socket buffers, keep-hot 1000, prefetch after 2 hits at 25 % TTL left, preload 2000 names at 200/s. balanced: ≤4 sockets, 1 MB, 200, 3 hits/20 %, 500 at 50/s. Explicit flags and Advanced-tab values still win.
### New: startup preload
- At start the most-used names from history plus the **Preload names** list (Advanced > Prefetch) are resolved in the background, rate-limited (`-warmup-rate`, `-warmup-list`). DNS is served immediately.
### New: Servers & Health panel (one dashboard for all servers)
- Status and stats of this server and its **peers** (e.g. primary server 192.168.1.108, NAS 192.168.1.75) with **Flush cache** and **Filter on/off** per peer. Peers talk over the LAN only (private IPs), authenticated with a shared **peer token** (16+ characters, constant-time check, stored encrypted, never shown). A peer that is down shows "not answering" after 2.5 s; everything else keeps working.
- **Uptime Kuma** monitors (up/down, latency, 24 h uptime) from Kuma's public status-page JSON (Advanced > Health monitoring: URL + slug, default `dns`). LAN URLs only, 3 s timeout, cached 20 s.
- **Devices by volume** (feature switch `device_volume`, **off by default**): per-device queries/min, last hour, 24 h and blocked counts for every server, names from PTR/client names, spikes (≥60 q/min and ≥5× the hourly average) highlighted. Aggregate atomic counters only; no per-query log.
### New: `/health`
- Unauthenticated `GET /health`: `ok` (200) or `degraded` (503). No other data. For Uptime Kuma / Docker.
### Stability
- DNSSEC pass-through: if every upstream answers SERVFAIL (often a validation failure), GoProxy retries once with CD=1 and passes a valid answer through uncached instead of failing (`-dnssec-passthrough`, default on).
### Security
- Notification and peer tokens are now **encrypted at rest** (AES-256-GCM, key `goproxy-secret.key`, mode 0600, next to the settings file), also in Config history; never in the audit log or backups. The devices file is written 0600.
### Fixed
- Pausing/resuming the ad filter from the dashboard **wiped every other saved setting** (it saved an empty settings object). It now changes only that field.
- Start-up log showed `dashboard http://localhost127.0.0.1:…` when the dashboard listened on an IP.
### Not done (container note)
- Remote/peer self-update is disabled in Docker (container mode, as in v2.5.0); update by loading the new image and recreating the container.

## v2.5.1 — 2026-10-18
### New: DNS Servers (Advanced tab)
- **Add, remove, enable/disable and reorder** the internet DNS servers GoProxy asks (▲/▼ buttons or drag). Each entry has a name, an address, a protocol (**DoH**, **DoT** or **UDP**), an on/off switch and its place in the list. Known servers can be picked from a menu (Cloudflare, Quad9, Quad9 ECS, Google, AdGuard, Cloudflare/Quad9/Google DoT, UltraDNS Public); your own can be added and **tested** first.
- **Priority now decides the race:** the top N enabled servers (*Upstreams raced first*, default 2) are asked at once; encrypted servers further down join after the hedge delay (as before); **unencrypted servers further down are fallbacks only**, asked only when every server above failed. A server that keeps failing is still skipped for a while by the circuit breaker. (With `-upstreams` on the command line the old fastest-first order stays and the list is saved but not used.)
- **Applied live, no restart** (the resolver list is swapped in place; servers that stay keep their stats and connections). Saved in `goproxy-settings.json` (`dns_servers`) in the data folder, recorded in Config history (Revert undoes it) and the audit log, included in the settings backup/restore. Input is validated (IP-address servers or a name with bootstrap IPs, no duplicates, at most 16, GoProxy can't be pointed at itself) and **at least one server must stay enabled**; if the saved list is ever empty or unusable, GoProxy uses the defaults and says so.
- Upstream presets, Quad9 ECS and the extra upstream now apply **immediately** too; applying a preset replaces the DNS Servers list. Changes go through the CSRF-protected API (`/api/dns-servers`, `/reset`, `/test`).
- New: **DNS-over-TLS** upstreams (RFC 7858, reused TLS connections, certificate checked).
### New: UltraDNS Public (64.6.64.6, 64.6.65.6)
- Added to the defaults **enabled at the lowest priority**, so it is visible in the list, and to the DNS benchmark.
- **Unencrypted (plain UDP/TCP):** UltraDNS Public (formerly Verisign Public DNS) has no DoH or DoT service: port 853 is closed, there is no DNS-over-HTTPS on 443 and `dns.ultradns.com` does not exist (checked 2026-10-18; independent audits agree). It is labelled *unencrypted* everywhere. Because it is at the bottom it only sees a lookup when Cloudflare and Quad9 both fail; move it to the top to make it a main server.

## v2.5.0 — 2026-10-17
Review fixes (outside review, checked against the real code; items that were already in place are listed too).
### Changed: TTLs follow the site again (GP-01)
- **The global 300 s minimum TTL is gone.** `-min-ttl` now defaults to **0**: every answer keeps the TTL the site asked for, so short-TTL failover (AWS Route 53, dynamic DNS, CDNs) works. A 5 s floor still stops TTL-0 answers from being fetched on every query. Raising `-min-ttl` (or *Minimum TTL* in the Advanced tab) still works if you want the old behaviour.
- **Pinned names keep a 300 s floor** (`-pinned-min-ttl`, default 300 s): YouTube, Netflix and the connectivity-check names, which keep-hot refreshes anyway. CDN names in `-min-ttl-exempt` and HTTPS/SVCB records always keep their real TTL.
- **Negative caching per RFC 2308:** NXDOMAIN and NODATA are cached for min(SOA TTL, SOA MINIMUM), clamped to **5–300 s** (`-neg-min-ttl`, `-neg-max-ttl`; was clamped to the 300 s minimum … 1 h). Without an SOA: 30 s.
- If your start command or Advanced tab sets `-min-ttl 300s` / *Minimum TTL 300*, that setting still wins; clear it to get the new default.
### New: container mode (GP-03)
- In Docker (`GOPROXY_CONTAINER=true`, or `/.dockerenv` / `/run/.containerenv` present) the self-updater, update folder, update check, rollback and in-app restart are disabled. The update APIs answer **409** with how to update (new image + `docker compose up -d`) and restart (Container Manager or `docker restart goproxy`). The Version tab says so. Set `GOPROXY_CONTAINER=false` to override.
### Security: dashboard CSRF token (GP-06)
- Every state-changing dashboard request (POST/PUT/PATCH/DELETE) with a login session must now carry the `X-GoProxy-CSRF` header. The token is derived from the session (HMAC, no server state), handed to the page in the `goproxy_csrf` cookie (SameSite=Strict) and added automatically by the dashboard. This is on top of the existing Origin check and the HttpOnly, SameSite=Strict session cookie. A request without `Origin` but with `Sec-Fetch-Site: cross-site` is now refused too.
- A dashboard tab left open from before the update: **reload it once** (buttons that change something answer "reload the dashboard page" until you do). Logins made before the update keep working; the token cookie is issued on the next page load.
### Already in place (checked, regression tests added)
- One upstream lookup per question for simultaneous misses (singleflight) and a fast SERVFAIL/REFUSED never ends the race while another upstream can still answer (GP-02).
- Blocked HTTPS/SVCB (type 65/64) queries answer NOERROR with no records (GP-05).

## v2.4.3 — 2026-10-17
### Fixed: "Update from file" on Windows still failed with "being used by another process"
- **Cause:** v2.4.1 correctly moved the running goproxy.exe aside, but the step after it, renaming the freshly written and just test-run (`-version`) goproxy.new.exe into place, was done once with no retry. Right after a new .exe is written and run, the antivirus (Windows Defender) holds it open for a short scan without allowing rename/delete, so the rename failed (`install: rename …goproxy.new.exe …goproxy.exe: The process cannot access the file because it is being used by another process`). The original exe was put back and v2.4.1 kept serving.
- **Fix:** the new file is first renamed to goproxy.ready.exe, retrying while another program holds it (up to 45 s); the running exe is not touched until that works. Then the running exe is moved aside and the new one renamed into place, each retried briefly; if it is still locked, its bytes are copied into place instead (a scan blocks renaming, not reading). The dashboard log says when it is waiting. Leftover goproxy.ready*.exe files are cleaned up after the next start.
- Tests simulate Windows locking (running exe locked, antivirus handle on the new exe) and drive the dashboard upload handler end to end through the same install code.

## v2.4.2 — 2026-10-17
### New: Ads & Tracking filter (OFF by default)
- A small, curated, built-in list of Google ad / ad-statistics names (doubleclick.net, googleads.g.doubleclick.net, ad. / static. / stats.g.doubleclick.net, pagead2.googlesyndication.com, googlesyndication.com, googleadservices.com, adservice.google.com …) and common trackers (app-measurement.com, Criteo, Taboola, Outbrain, Amazon ads, The Trade Desk …). Blocked names get 0.0.0.0 / ::.
- **It cannot block the ads inside YouTube videos**: YouTube sends them from the same servers as the videos. The **?** next to the switch explains this and what does work.
- **imasdk.googleapis.com is never blocked** (it breaks video players). YouTube, Netflix, googlevideo and the connectivity-check names are pinned and **always win** over the filter, even if added to the extra list (which refuses them).
- Optional **Also Google Analytics** sub-switch (google-analytics.com, analytics.google.com, Tag Manager), off by default.
- Optional **extra domains** list (Advanced · Ads & Tracking filter).
- **Per device**: Devices tab, each device *Default* (follows its group, then the global switch) / *On* / *Off*; **per group** too. Devices are identified by IP address (explained in the **?**).
- Optional **schedules**: e.g. the Kids group *On* 21:00–07:00 (windows may cross midnight; optional days).
- **Blocked per day** card on the dashboard (14 days), kept across restarts.
- Every switch, per-device and per-group change is recorded in **Config history** (Revert undoes it) and the **audit log**. Applied live, no restart.
### New: Updates
- **Auto-rollback** (Advanced · Updates, off by default): for 5 minutes after an update from the dashboard, the new version checks itself every 20 s; if DNS/the dashboard fail 3 times in a row, or the self-test fails while the internet is up, it goes back to the previous version (same seamless handover). Rollbacks and restarts are never watched (no loops).
- **Signed releases**: release zips now contain `goproxy.exe.sig` (ed25519). A signature that does not match is always refused. **Require signed updates** (off by default) also refuses unsigned files, with a clear message. Rollback is not checked.
### New: tools
- **Why was this answered?** (Advanced): enter a domain (and optionally a device IP) to see local name, blocklist, Ads & Tracking decision and why, pinned status, cache state per record type and the last upstream. Read-only.
- **This week** card on the dashboard: lookups, cache share, blocked (and by the filter), failures, health per day and its trend, top domains, outages.
- **Backup & restore** (Advanced): download settings (optionally device names & groups) as a file; never contains the password hash, sessions, kiosk password or ntfy token. Import only from the home network, validated, recorded in Config history.

## v2.4.1 — 2026-10-16
### Fixed: updating on Windows failed with "file is being used by another process"
- Installing a new version no longer tries to overwrite the running goproxy.exe. The running file is renamed to goproxy.old.exe (Windows allows that), the new one is moved into place, and on any failure the original is put back. goproxy.prev.exe (for Rollback) is now a plain copy, so it can always be replaced. Leftover goproxy.old.exe files are deleted after the next start (retried while still in use). Applies to the tray app handover, the Windows service restart and Rollback.

## v2.4.0 — 2026-10-16
### Fixed: GoProxy could stop answering (the "Start with Windows" hang)
- **What happened:** after clicking *Start with Windows*, v2.3.1 stopped answering DNS and the dashboard while Windows still showed it as *Responding*. Several ways this could happen were found and fixed:
  - All DNS listeners share one UDP socket. One unusual network error (for example a reset reported by Windows) made the DNS library **close that shared socket**, which silently stopped *all* UDP DNS while the process kept running. The socket can no longer be closed by a listener; only a real stop closes it, and a listener that dies is now noticed and re-opened.
  - If the dashboard server stopped, nothing noticed. It is now detected and re-opened too.
  - An error popup could block the stop/restart path forever (no one to click OK). It is now limited to 2 seconds (the error is still in goproxy.log).
  - *Start with Windows* could save an internal handover flag (`-takeover`) into the startup entry. Internal flags are now never saved, and old entries are cleaned.
  - Writing the log to a console that no longer exists could block. The log file is now written directly and the console copy can never block.
  - The *Start with Windows* registry write now runs in the background, so the tray menu can't freeze.
- **New watchdog:** every 15 s GoProxy asks itself a DNS question (UDP and TCP) and checks the dashboard. After 3 failures it saves a diagnostic file (`goproxy-hang-*.txt`, what every part of the program was doing), re-opens the ports and, if that does not help, restarts itself. Status: Health card and Advanced tab.
### Windows service mode (optional)
- `goproxy.exe -install-service` (or **install-service.cmd**) runs GoProxy as the **GoProxyDNS** Windows service: starts at boot before sign-in, survives sign-out, restarted by Windows after a crash or a watchdog restart.
- The **tray icon becomes UI only** (status, Open Dashboard, Stop DNS service…) and talks to the service; it shows a balloon for alerts and when DNS is not responding.
- Migration keeps your flags and data folder, health-checks the service and rolls back to the tray app if it doesn't answer. `-uninstall-service` puts everything back as it was.
- **Updates under the service** restart it through a helper (1–3 s gap, not shown as a crash); a version that does not answer DNS is rolled back automatically. The portable tray app keeps the zero-downtime handover.
### Alerts
- **PC address changed:** if this PC's LAN address is no longer the one the router hands out as DNS, a banner on the dashboard, a tray balloon and (optional) a phone alert say so, with what to change. *Accept new IP* if it was intentional. Also warns when the PC has no network at all.
- **Quiet devices:** mark cameras, doorbells, feeders as *watched* in the Devices tab; if one makes no lookups for 60 minutes (adjustable), you are warned.
- **Phone alerts via ntfy:** OFF by default. Nothing is sent until you switch it on, choose a topic and pick which alerts (IP change, quiet devices, outages). Test button, at most one push per alert per 30 minutes.
### Health
- **Self-test:** every 5 minutes GoProxy looks up YouTube, Netflix, the phone/PC/console *"is there internet?"* names, a local name and a name that must not exist, through itself. Its result is a separate *Self-test* score; a failing self-test saves a flight recording.
- **Outage log:** every internet outage (all upstreams failing) and network loss, with start, end and length, on the dashboard; **Download CSV** per month for ISP credit requests.
- **Flight recorder:** the last 10 minutes of lookups are kept in memory and saved to `flight\` when the health score drops, the self-test fails or the watchdog acts. Never uploaded.
- **Streaming drift alert:** an informational note when the record types or CNAME chain of YouTube / Netflix change (a hint if streaming acts up after a provider change).
- The connectivity-check names (Android, Apple, Windows, Firefox) are **always kept hot** and never blocked.
### New tabs
- **Devices:** every device by IP address with queries, cache hits, failures, last seen and its top domains; names (aliases), groups with totals, watch + quiet minutes; an **IPv6 coverage** score that flags signs of devices asking another DNS server over IPv6 (read-only, nothing is changed on the router).
- **Advanced:** every setting in one place with a **?** on each: upstreams (incl. **Quad9 with ECS**, off by default, and an optional extra DoH upstream with IP bootstrap), cache & TTL, prefetch & warm-up, serve-stale, alerts, feature switches, local names, retention, kiosk password, **config history with one-click Revert**, **audit log**, password reset help. Save validates; each section has *Reset to defaults*. Engine settings apply after **Restart** (no DNS drop on the tray app).
- **Kiosk:** read-only `/kiosk` page for a tablet: health, who's online, outages. No IPs, domains or buttons; its own optional view-only password. Off by default.
### DNS benchmark and presets (Advanced tab)
- **Run benchmark** measures, from this PC, Cloudflare, Quad9, Quad9 with ECS, Google, AdGuard (unfiltered), optionally NextDNS, and your current upstreams, over encrypted DoH and plain UDP: time for a new (uncached) name and a popular (cached) name (median and p95), answered / SERVFAIL rate, and whether the server checks DNSSEC. It uses its own connections, paced, one run at a time with a 3-minute cooldown, so live DNS is not affected. Unreachable servers are skipped quickly.
- A ranked table and a plain-language recommendation (including a warning if plain DNS looks intercepted). The last 20 results are saved (`goproxy-bench.json`) and can be reopened.
- **Presets** with one tap (confirm first, recorded in Config history so Revert undoes it, applied on Restart): **Fastest** (benchmark's top 2, from different providers), **Privacy** (Cloudflare + Quad9, DoH only, no ECS), **Streaming** (Quad9 with ECS + Cloudflare, YouTube/Netflix stay pinned), **Reliability** (Cloudflare + Quad9 + Google), **Default**.
- New **Upstream list** setting (IP-address DoH URLs, or the known names with built-in bootstrap IPs).
### Other
- **Local names** (e.g. `nas.home` → 192.168.1.123), answered by GoProxy itself.
- **Audit log** of logins, failed logins, password and settings changes, updates and restarts (`goproxy-audit.jsonl`, 90 days).
- **Per-feature switches:** each new feature can be turned off on its own.
- Cache lifetimes use the monotonic clock, so a Windows clock change (time sync, daylight saving) can't make answers expire early or live too long (tested).
- New tests: hang/listener recovery, watchdog, YouTube/Netflix replay scenarios, self-test, large answers over TCP, clock jumps, settings history, ntfy (off by default sends nothing), kiosk access.

## v2.3.1 — 2026-10-16
### Fewer upstream errors, smarter race
- **Errors are now split by type** on each upstream: timeout, http (with the last status, e.g. 429 = rate limited), conn (reset / GOAWAY / TLS), servfail, refused, and **cancelled**. Cancelled = a race loser stopped because another upstream already answered: it is **not an error** and no longer shows in red. The red "err" count is only real failures (timeout + http + conn + bad reply).
- **Why Quad9 showed thousands of errors:** a SERVFAIL/REFUSED reply was only counted when it arrived *before* the winner. Quad9 answers fastest (28 ms vs 43 ms), so its error replies were almost always counted while Cloudflare's arrived after the race was over and were never counted. SERVFAIL is usually a problem with that one name (DNSSEC failure, dead authoritative server), not with Quad9. Every reply is now counted the same way for every upstream, and SERVFAIL is shown separately.
- **Smarter race:** instead of asking all 4 every time, GoProxy asks the **2 best** upstreams (lowest p95 latency and error rate) and brings in the others only if those haven't answered after a short delay (about their p95, 20–200 ms) or have both failed. Half the upstream traffic, same speed. `-race-first` (default 2) and `-hedge` (default adaptive) tune it.
- **Circuit breaker:** an upstream that fails 3 times in a row is skipped for 2 s, then 4 s, 8 s… up to 60 s, and is tried again automatically. If every upstream is backing off, they are all still tried.
- **Healthier encrypted connections:** a lookup that hits a connection the server just closed (GOAWAY / reset) is retried once on a fresh connection instead of failing. Idle connections are closed after 90 s (before servers drop them), TLS sessions are resumed, and dead connections are detected by pings.
- SERVFAIL/REFUSED still never win; they are used only as a last resort after the UDP fallback.
### Cache survives updates, restarts and crashes
- The cache, prefetch / keep-hot / warm-up counters and top-domains history are saved on every stop (Quit, `-stop`, update handover) **and every 10 minutes** (`-autosave`), so a crash or power cut loses little.
- Files are written to a temp file, flushed to disk, then renamed, so a half-written snapshot can never replace a good one.
- On start, answers keep their **real remaining TTL** (time spent stopped is subtracted). Expired answers are kept for serve-stale for up to 1 hour, then dropped. A corrupt or truncated snapshot is skipped safely (the good part is kept) and the log says so. The log and dashboard show **restored N entries**.
### Dashboard login
- **First run:** the dashboard asks you to create a username and password. There is no default login. Setup is only offered to this PC and the home network.
- The password is stored only as a **bcrypt hash** in `goproxy-auth.json` (readable only by you), never in plain text.
- Every page, API, the live WebSocket and **Update / Roll back** need a login. Sessions use an HttpOnly, SameSite=Strict cookie (Secure on HTTPS) and last 30 days, including across updates. Cross-site requests are blocked.
- **5 wrong passwords** lock that device out for 1 minute, then 2, 4… up to 30 minutes.
- **Log out** button at the top, and **Settings · Dashboard login** in the Version tab to change the password (this signs out every other device).
- **Forgot the password?** On the GoProxy PC run `goproxy.exe -reset-password`, then open the dashboard there to create a new one.
- DNS on port 53 is not affected. `goproxy.exe -stop` and the updater keep working without a login from this PC.

## v2.3.0 — 2026-10-16
### Updates without dropping DNS
- New **Update** section in the Version tab, with a (?) beside every part:
  - **Update from file:** pick a new `goproxy.exe` or the release `.zip` in the dashboard. You can paste an optional **SHA-256**, and the file is only installed if it matches.
  - **Update folder:** copy an exe or zip into `C:\GoProxyDNS\updates` and it installs within a few seconds. A `<file>.sha256` beside it is checked first, and handled files move to `processed\` (`-update-dir`).
  - **Online updates:** optional `-update-url` pointing at a JSON manifest (`version`, `url`, `sha256`). It is checked every 6 hours, and a newer version is offered with an Install button. Nothing installs on its own.
- **Seamless handover:** the new version starts with `-takeover` and loads the cache snapshot the old one saved a moment earlier. The old version then releases port 53, the new one binds it (retrying every 20 ms) and must answer a test lookup over UDP and TCP (`-health-name`) before the old one exits. Measured gap: **1.4–2.3 ms**.
- **Automatic rollback:** if the new version fails to start or fails its test lookup, it is stopped, the files are put back, and the current version takes port 53 back and keeps running.
- **One-click Roll back:** the replaced version is kept as `goproxy.prev.exe`. Going back to a version older than v2.3.0 works too, with about a second of downtime.
- Updates are accepted only from this PC or the home network.
### Graceful stop
- `goproxy.exe -stop` stops the running GoProxy cleanly, saving the cache, and waits until it has exited. Other ways to stop it: `POST /api/shutdown` (from this PC only) or the Windows named event `Local\GoProxyDNS-Stop`.
### Fixed: a start right after a kill could fail silently
- **Cause:** when the previous GoProxy was force-killed, Windows can hold port 53 for a moment while the process is torn down. The new one failed to bind and exited, and because the exe has no console window, the error went nowhere.
- GoProxy now **retries binding port 53 and the dashboard port for up to 10 s** (`-bind-retry`).
- Every start, stop and error is written to **`goproxy.log`** beside the exe, which rolls over at 5 MB.
- If it still cannot start, a **Windows error popup** explains why.
- `goproxy.exe -version` prints the version.

## v2.2.0 — 2026-10-16
### Ad blocking is off by default
- Nothing is blocked and **no blocklist is downloaded** unless GoProxy is started with `-blocking=true`. The dashboard toggle is greyed out with a hint while blocking is off.
- The **pause toggle is remembered across restarts** (`goproxy-settings.json` next to the cache file).
### Fixes for a whole house (TVs, phones, consoles)
- **SERVFAIL / REFUSED can no longer win the upstream race.** They used to be returned as the "winner" when no valid answer came in, and counted as a win. They now count as an upstream error and are used only as a last resort after the UDP fallback.
- **Upstream race data race fixed:** the same query was packed by every upstream at once, which could corrupt the EDNS0 record that went out. Each upstream now gets its own copy.
- **EDNS0 done properly:** replies always carry an OPT record when the device sent one, and cached and stale answers now carry one too. The advertised UDP size is 1232 bytes (DNS Flag Day 2020) to avoid fragmented packets over Wi-Fi. Larger answers are truncated with TC=1 so the device retries over TCP, which returns the full answer. EDNS versions other than 0 get BADVERS.
- **DNSSEC passthrough:** upstreams are always asked with DO=1. Devices that set DO get RRSIGs and the AD bit, and other devices get neither (RFC 6840). The CD bit is passed through.
- **Case-preserving answers:** the question and the matching answer names are returned exactly as the device spelled them (DNS 0x20), even when served from the cache.
- **HTTPS/SVCB (type 65/64) keep their real TTL.** The 300 s minimum no longer applies to them, so ECH keys and alternative endpoints stay current. They are passed through unchanged, and NODATA (no HTTPS record) stays NOERROR with no answer instead of turning into an error.
- **CDN failover:** short-TTL CDN hosts keep their real TTL instead of the 300 s minimum (`-min-ttl-exempt`, default googlevideo.com, nflxvideo.net, nflxso.net, akamaiedge.net, akamaized.net, cloudfront.net, fastly.net, edgekey.net; 5 s floor).
- **Duplicate lookups collapsed:** when several devices ask for the same uncached name at once, one upstream lookup is made and all of them get its answer.
- The AAAA/HTTPS sibling prefetch is skipped when the A lookup was NXDOMAIN.
- **Wi-Fi drops:** when every upstream fails, GoProxy treats the internet as down for 30 s and serves stale answers **immediately** instead of making each device wait 3 s (RFC 8767 failure recheck). Idle DoH connections are dropped so the next lookup redials, and HTTP/2 health pings detect dead connections within about 13 s.
### Health Score
- New **Health Score** card in the style of the router: an overall 0–100 score plus Upstream, Cache, Latency and Errors scores. Each has a 24-hour timeline in 10-minute segments colored green, yellow or red.
- Drag the round handle (touch-friendly; arrow keys work too) to scrub back in time. The header shows the selected window, and the scores and metrics update to match. A (?) beside each score explains it.
- History is saved to `goproxy-health.json` every 10 minutes and on quit. New API: `GET /api/health`.
### Tested
- 5,000 queries/s from 50 simulated devices: p99 1.07 ms with every answer cached, and p99 13 ms with 2% never-seen names. No failures and no truncation.

## v2.1.0 — 2026-10-15
### Stricter serve-stale (RFC 8767)
- Expired answers now try upstream first. The stale answer is served only if the internet hasn't answered within the **stale answer timeout** of 3 s (`-stale-timeout`). New `refreshed` result in the log.
- Max stale age cut from 24 h to **1 h** (`-stale`). Both are shown in Expert Mode.
### More aggressive caching
- Default minimum TTL raised to **300 s** (`-min-ttl`).
- Prefetch any name queried **≥ 1 time** once **20 %** of its TTL is left (`-prefetch-hits`, `-prefetch-at`).
- When an A record is fetched, AAAA and HTTPS (type 65) are prefetched in the background (`-prefetch-siblings`).
- **Popular never expire:** the top 200 names are kept refreshed continuously (`-keep-hot`, `-keep-hot-every`).
- **Warm-up at start:** the top 500 domains from saved history are resolved in the background, 4 at a time (`-warmup`, `-warmup-workers`).
- **Pinned domains**, always cached and refreshed and grouped by service in the UI (`-pinned`):
  - YouTube: youtube.com, www/m.youtube.com, i.ytimg.com, yt3.ggpht.com, youtubei.googleapis.com, plus every `*.googlevideo.com` host seen (auto-pinned).
  - Netflix: netflix.com, www.netflix.com, api-global.netflix.com, assets.nflxext.com, plus every `*.nflxso.net` (occ-0-*) and `*.nflxvideo.net` host seen (`-auto-pin`).
- googlevideo.com, nflxvideo.net, nflxso.net and nflxext.com are **never blocked** (`-never-block`).
- **Warm start:** the cache, query history and stats are saved to disk on quit and loaded in the background at start (`-cache-file`, default `goproxy-cache.bin` next to the program).
### Dashboard redesign
- New clean card layout inspired by NAS DSM 7, Apple, Pi-hole v6, AdGuard Home and Linear/Vercel. Light and dark mode follow the system, the layout works on phones, and it no longer loads anything from the internet.
- NAS-style **(?) help** beside every metric, panel, toggle and setting, explaining what it means and what a good value is (hover, or tap on a phone).
- Live **CPU line chart** with queries/sec overlaid and red markers where CPU spikes line up with lookup bursts. Per-core CPU in Expert Mode.
- New panels: latency histogram, cache gauge (size and entries) with **Flush cache** (asks first), query-type breakdown, devices with names from the router (reverse lookup to 192.168.1.1, `-ptr-server`), blocklist **Update now** with last-updated time, upstream health dots (up/slow/down), smart-caching counters, and a caching settings panel in Expert Mode.
- New API: `POST /api/flush`, `POST /api/blocklist/update`.
- All new background work stays off the query path. Cache hits are as fast as in v2.0.0.
## v2.0.0 — 2026-10-15
### GoProxy becomes a DNS server (Pi-hole replacement)
- Ultra-fast DNS server on UDP + TCP port 53 (all interfaces), one UDP listener per CPU thread.
- Sharded RAM cache with a 4–64 GB budget, TTL-honouring with a configurable minimum TTL, and negative caching.
- Serve-stale (RFC 8767) with background refresh, plus prefetch of popular names before they expire.
- Encrypted upstreams over DNS-over-HTTPS (Cloudflare 1.1.1.1 / 1.0.0.1, Quad9 9.9.9.9 / 149.112.112.112) with HTTP/2 keepalive.
- **Parallel upstream racing:** every miss asks all upstreams at once, the first valid answer wins and the rest are cancelled (`-parallel` to tune). Plain UDP fallback.
- Ad blocking from blocklists (StevenBlack hosts by default) with allow/deny lists, refreshed daily; blocked names answer `0.0.0.0` / `::`.
- Dashboard: queries/sec, cache hit %, blocked %, p50/p99 latency, per-upstream win rate and latency, top domains, top blocked, top clients, live query log, ad-blocking pause toggle.
- New **Version** tab with this changelog; version shown in the tray tooltip.
- The HTTP caching proxy was removed.

## v1.1.0
- Site icons (favicons) in the live log.
- New Top Sites panel.

## v1.0.0
- HTTP caching proxy with a 4–64 GB RAM cache.
- Live Apple-style dashboard with Expert Mode and WebSocket stats.
- Windows tray app (Open Dashboard, Start with Windows, Quit).
