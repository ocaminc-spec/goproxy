// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
// goproxy: ultra-fast caching, ad-blocking DNS server (Pi-hole replacement) with a live dashboard.
package main

import (
	"context"
	"net"
	"net/url"

	"flag"
	"fmt"
	"github.com/miekg/dns"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

const gb = int64(1) << 30

const defaultDoH = "https://1.1.1.1/dns-query,https://dns.google/dns-query" // v2.6.0: + DoT 1.1.1.1:853 / 8.8.8.8:853 in the default DNS Servers list

func splitList(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' }) {
		out = append(out, strings.TrimSpace(f))
	}
	return out
}

func readListFile(path string) []string {
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		log.Printf("list %s: %v", path, err)
		return nil
	}
	m := map[string]struct{}{}
	ParseList(strings.NewReader(string(b)), m)
	var out []string
	for d := range m {
		out = append(out, d)
	}
	return out
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	dnsAddr := flag.String("dns-addr", ":53", "DNS listen address (UDP+TCP, all interfaces)")
	httpAddr := flag.String("http-addr", ":8080", "dashboard listen address")
	cacheGB := flag.Int64("cache-gb", 4, "cache RAM budget in GB (clamped 4..64)")
	cacheMB := flag.Int64("cache-mb", 0, "cache RAM budget in MB, 64..65536 (overrides -cache-gb when > 0; entries = budget/512 bytes)")
	maxEntries := flag.Int64("max-entries", 0, "max cached entries (0 = budget/512 bytes)")
	minTTL := flag.Duration("min-ttl", 60*time.Second, "minimum cache TTL (TTL floor) for every answer (v2.6.0 default 60s; 0 = honour the upstream TTL, a 5 s floor still applies to TTL-0 answers)")
	pinnedMinTTL := flag.Duration("pinned-min-ttl", defaultPinnedFloor, "minimum cache TTL for pinned names only (YouTube, Netflix, connectivity checks; 0 = honour upstream)")
	negMinTTL := flag.Duration("neg-min-ttl", defaultNegMinTTL, "RFC 2308 negative caching: lower clamp for NXDOMAIN/NODATA lifetimes")
	negMaxTTL := flag.Duration("neg-max-ttl", defaultNegMaxTTL, "RFC 2308 negative caching: upper clamp for NXDOMAIN/NODATA lifetimes")
	maxTTL := flag.Duration("max-ttl", 24*time.Hour, "maximum cache TTL")
	staleFor := flag.Duration("stale", time.Hour, "max stale age: how long an expired answer may still be served (RFC 8767)")
	staleTimeout := flag.Duration("stale-timeout", 3*time.Second, "RFC 8767 client response timeout: wait this long for a fresh answer before serving stale (0 = serve stale immediately)")
	prefetchHits := flag.Int64("prefetch-hits", 1, "prefetch names queried at least this many times")
	prefetchAt := flag.Float64("prefetch-at", 0.2, "prefetch when this fraction of the TTL remains (0.2 = 20%)")
	siblings := flag.Bool("prefetch-siblings", true, "when an A record is fetched, also prefetch AAAA and HTTPS (type 65)")
	keepHot := flag.Int("keep-hot", 200, "'popular never expire': keep the top N names refreshed continuously (0 = off)")
	keepHotEvery := flag.Duration("keep-hot-every", 30*time.Second, "how often the keep-hot sweep runs")
	warmup := flag.Int("warmup", 500, "at start, resolve the top N domains from saved history (0 = off)")
	warmupWorkers := flag.Int("warmup-workers", 4, "warm-up concurrency (kept low)")
	pinnedF := flag.String("pinned", defaultPinned+","+strings.Join(connectivityNames, ","), "pinned domains: always kept cached and refreshed (includes the phone/PC/TV connectivity-check names)")
	autoPin := flag.String("auto-pin", "googlevideo.com,nflxso.net,nflxvideo.net", "auto-pin every observed host under these domains")
	neverBlock := flag.String("never-block", "googlevideo.com,nflxvideo.net,nflxso.net,nflxext.com,"+strings.Join(connectivityNames, ","), "domains (and subdomains) that are never blocked")
	cacheFile := flag.String("cache-file", "", "cache snapshot path (default: goproxy-cache.bin next to the program; 'off' disables)")
	ptrServer := flag.String("ptr-server", "off", "router (e.g. 192.168.1.1) used for reverse lookups of client device names ('off' disables)")
	upstreams := flag.String("upstreams", defaultDoH, "comma-separated DoH URLs, raced in parallel")
	parallel := flag.Int("parallel", 0, "max DoH upstreams used per miss (0 = all)")
	raceFirst := flag.Int("race-first", 2, "best-scored DoH upstreams (by p95 and error rate) raced immediately; the rest join after -hedge")
	parallelAll := flag.Bool("parallel-all", true, "parallel upstream: send every cache miss to ALL upstreams at once, first valid answer wins (false = race the top -race-first, hedge to the rest)")
	hedge := flag.Duration("hedge", 0, "delay before the other upstreams join the race (0 = adaptive: p95 of the best, 20-200 ms)")
	fallback := flag.String("fallback", "8.8.8.8:53,1.1.1.1:53", "plain UDP fallback resolvers")
	blocking := flag.Bool("blocking", false, "enable ad blocking (downloads the blocklists); off by default")
	minTTLExempt := flag.String("min-ttl-exempt", "googlevideo.com,nflxvideo.net,nflxso.net,akamaiedge.net,akamaized.net,cloudfront.net,fastly.net,edgekey.net", "names (and subdomains) that keep their real TTL instead of -min-ttl (HTTPS/SVCB records always do)")
	blocklists := flag.String("blocklists", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", "comma-separated blocklist URLs (hosts or domain format)")
	blockFiles := flag.String("blocklist-files", "", "comma-separated local blocklist files")
	allow := flag.String("allow", "", "comma-separated allowed domains (never blocked)")
	deny := flag.String("deny", "", "comma-separated extra blocked domains")
	allowFile := flag.String("allow-file", "", "file of allowed domains")
	denyFile := flag.String("deny-file", "", "file of extra blocked domains")
	refresh := flag.Duration("blocklist-refresh", 24*time.Hour, "blocklist refresh interval")
	listeners := flag.Int("udp-listeners", runtime.NumCPU(), "UDP listener goroutines/sockets")
	profileF := flag.String("profile", "max", "performance profile: max (all cores, big buffers, aggressive prefetch/preload) or balanced; only changes flags you did not set")
	udpBuf := flag.Int("udp-buf", 0, "UDP socket receive/send buffer in bytes (0 = from -profile)")
	plainFallback := flag.Bool("plain-fallback", true, "if every encrypted (DoH/DoT) upstream fails, ask the plain UDP fallbacks so sites keep working (false = encrypted only)")
	warmupRate := flag.Float64("warmup-rate", 0, "startup preload rate limit in names/second (0 = from -profile)")
	warmupList := flag.String("warmup-list", "", "comma-separated names always preloaded at start (plus Advanced > Preload names)")
	dnssecPass := flag.Bool("dnssec-passthrough", true, "if every upstream answers SERVFAIL, retry once with DNSSEC checking disabled (CD) so a broken DNSSEC signature does not blank a site")
	takeover := flag.Bool("takeover", false, "internal: take over from a running GoProxy (zero-downtime update)")
	stopCmd := flag.Bool("stop", false, "gracefully stop the running GoProxy (saves the cache) and wait until it has exited")
	autosaveEvery := flag.Duration("autosave", 10*time.Minute, "save the cache snapshot, stats and history this often (0 = only on stop)")
	dataDirF := flag.String("data-dir", "", `folder for cache, settings, history, login and log (default: %ProgramData%\GoProxyDNS when installed, else the program's folder)`)
	authFile := flag.String("auth-file", "", "dashboard login file (default: goproxy-auth.json next to the program)")
	resetPw := flag.Bool("reset-password", false, "remove the dashboard login (run on this PC); the dashboard then asks for a new username and password")
	showVer := flag.Bool("version", false, "print the version and exit")
	updateDir := flag.String("update-dir", defaultUpdateDir, "folder watched for new goproxy.exe / .zip files ('off' disables)")
	updateURL := flag.String("update-url", "", "optional update manifest URL (JSON: version, url, sha256)")
	healthName := flag.String("health-name", "www.google.com", "name resolved by the new process before an update is accepted")
	bindRetry := flag.Duration("bind-retry", 10*time.Second, "keep retrying to bind port 53 / dashboard port for this long at start")
	// v2.4
	serviceF := flag.Bool("service", false, "internal: run as the GoProxyDNS Windows service (set by -install-service)")
	trayF := flag.Bool("tray", false, "show only the tray icon (status and menu) for the GoProxyDNS service")
	installSvc := flag.Bool("install-service", false, "install GoProxy as a Windows service (Administrator): keeps the data folder and flags, the tray becomes status-only")
	uninstallSvc := flag.Bool("uninstall-service", false, "remove the Windows service (Administrator) and go back to the normal tray program")
	svcRestart := flag.Bool("service-restart", false, "internal: restart the service after an update")
	restartOnly := flag.Bool("restart-only", false, "internal: with -service-restart, do not roll back")
	portable := flag.Bool("portable", false, "run the DNS engine in this process even when the GoProxyDNS service is installed")
	wdOn := flag.Bool("watchdog", true, "self-check the DNS listener and dashboard and recover if they stop answering")
	wdEvery := flag.Duration("watchdog-every", 15*time.Second, "watchdog check interval")
	wdFails := flag.Int("watchdog-fails", 3, "failed checks in a row before the watchdog acts")
	flag.Parse()
	if *showVer {
		attachConsole()
		fmt.Println(VersionString())
		return
	}
	serviceMode = *serviceF || isWindowsService()
	initDataDir(*dataDirF)
	setupLog()
	switch {
	case *svcRestart:
		os.Exit(serviceRestartHelper(*dnsAddr, *healthName, *restartOnly))
	case *installSvc:
		attachConsole()
		os.Exit(installService(filterArgs(os.Args[1:])))
	case *uninstallSvc:
		attachConsole()
		os.Exit(uninstallService())
	}
	if *stopCmd {
		attachConsole()
		os.Exit(runStopCmd(*httpAddr))
	}
	if *resetPw {
		p := *authFile
		if p == "" {
			dir := dataDir
			if *cacheFile != "" && *cacheFile != "off" {
				dir = filepath.Dir(*cacheFile)
			}
			p = filepath.Join(dir, "goproxy-auth.json")
		}
		os.Exit(resetPassword(p))
	}
	if *trayF {
		os.Exit(runTray(*httpAddr))
	}
	if !serviceMode && !*portable && !*takeover && serviceInstalled() {
		// the service runs the engine; an old "Start with Windows" entry just shows the tray
		log.Print("the GoProxyDNS service is installed: starting the tray only (use -portable to override)")
		os.Exit(runTray(*httpAddr))
	}
	ready, done := make(chan struct{}), make(chan struct{})
	waitSvc := func() {}
	if serviceMode {
		waitSvc = beginService(ready, done, func() {
			if theApp != nil {
				theApp.Stop(true)
			} else {
				os.Exit(0)
			}
		})
		log.Printf("running as the %s Windows service", serviceName)
	}

	// settings first: the Advanced tab can override engine flags (explicit flags win)
	if *cacheFile == "" {
		*cacheFile = filepath.Join(dataDir, "goproxy-cache.bin")
	}
	settingsDir := dataDir
	if *cacheFile != "off" {
		settingsDir = filepath.Dir(*cacheFile)
	}
	settings := &settingsStore{path: filepath.Join(settingsDir, "goproxy-settings.json")}
	st, _ := settings.Load()
	explicit := setFlags()
	prof, perr := profileFor(*profileF)
	if perr != nil {
		log.Fatal(perr)
	}
	for name, val := range map[string]string{"udp-listeners": fmt.Sprint(prof.UDPListeners), "keep-hot": fmt.Sprint(prof.KeepHot),
		"prefetch-hits": fmt.Sprint(prof.PrefetchHits), "prefetch-at": fmt.Sprint(prof.PrefetchAt), "warmup": fmt.Sprint(prof.Warmup),
		"warmup-workers": fmt.Sprint(prof.WarmupWorkers)} {
		if !explicit[name] {
			_ = flag.Set(name, val)
		}
	}
	if applied := applyTuneOverrides(st, explicit); len(applied) > 0 {
		log.Printf("settings: Advanced overrides applied: %s", strings.Join(applied, " "))
	}
	if e := strings.TrimSpace(st.ExtraUpstream); e != "" && st.ExtraBoot != "" {
		if u, err := url.Parse(e); err == nil {
			setBootstrap(u.Hostname(), splitList(st.ExtraBoot))
		}
	}

	*cacheGB = min(max(*cacheGB, 4), 64)
	budget := *cacheGB * gb
	if *cacheMB > 0 {
		budget = min(max(*cacheMB, 64), 65536) << 20
	}
	if *maxEntries <= 0 {
		*maxEntries = budget / 512
	}
	cache := NewDNSCache(budget, *maxEntries, 256)
	cache.minTTL, cache.maxTTL, cache.staleFor = *minTTL, *maxTTL, *staleFor
	cache.pinnedFloor, cache.negMinTTL, cache.negMaxTTL = *pinnedMinTTL, *negMinTTL, *negMaxTTL
	for _, d := range splitList(*minTTLExempt) {
		if d = normName(d); d != "" {
			cache.minTTLExempt = append(cache.minTTLExempt, d)
		}
	}

	tr := newDoHTransport()
	res := &Resolver{Parallel: *parallel, First: *raceFirst, Hedge: *hedge, Tr: tr}
	res.ParallelAll.Store(*parallelAll)
	res.NoPlainFallback.Store(!*plainFallback)
	res.DNSSECPass = *dnssecPass
	udpSockBuf = prof.SockBuf
	if *udpBuf > 0 {
		udpSockBuf = *udpBuf
	}
	if *warmupRate <= 0 {
		*warmupRate = prof.WarmupRate
	}
	if _, p, err := net.SplitHostPort(*dnsAddr); err == nil {
		selfDNSPort = p
	}
	// v2.5.1: the DNS Servers list (or the defaults); the v24 API rebuilds it live on changes
	servers, srvSrc, srvWarn := effectiveServers(*upstreams, st, explicit["upstreams"])
	if srvWarn != "" {
		log.Printf("dns servers: %s", srvWarn)
	}
	res.DoH, _ = buildUpstreams(servers, tr, nil)
	res.Priority.Store(srvSrc != "flag")
	{
		var names []string
		for _, u := range res.DoH {
			names = append(names, u.Label()+" "+u.Proto()+" "+u.URL)
		}
		log.Printf("dns servers (%s, priority order): %s", srvSrc, strings.Join(names, " · "))
	}
	for _, u := range splitList(*fallback) {
		res.Fallback = append(res.Fallback, NewUpstream(u, nil))
	}

	bl := NewBlocklist(splitList(*blocklists), append(append(splitList(*allow), splitList(*neverBlock)...), readListFile(*allowFile)...), append(splitList(*deny), readListFile(*denyFile)...))
	bl.Files = splitList(*blockFiles)
	bl.Enabled = *blocking
	ctx, cancel := context.WithCancel(context.Background())

	s := NewDNSServer(ctx, cache, res, bl)
	s.tune = Tuning{StaleTimeout: *staleTimeout, PrefetchHits: max(*prefetchHits, 1), PrefetchAt: min(max(*prefetchAt, 0), 1), Siblings: *siblings,
		KeepHotN: *keepHot, KeepHotEvery: max(*keepHotEvery, time.Second), WarmupN: *warmup, WarmupWorkers: max(*warmupWorkers, 1),
		WarmupRate: *warmupRate, WarmupList: append(splitList(*warmupList), splitList(st.WarmupList)...)}
	s.profile = *profileF
	s.pinned = NewPinned(splitList(*pinnedF), splitList(*autoPin))
	cache.isPinned = s.pinned.Has
	s.neverBlock = splitList(*neverBlock)
	if *ptrServer != "off" && *ptrServer != "" {
		s.names = NewClientNames(*ptrServer)
		s.ptrServer = *ptrServer
	}
	stateFile := ""
	if *cacheFile != "off" {
		s.cacheFile = *cacheFile
		stateFile = *cacheFile + ".history.json"
	}
	s.settings = settings
	s.health = NewHealth(filepath.Join(settingsDir, "goproxy-health.json"))
	_ = s.health.Load()
	go s.RunHealth(ctx)
	s.live = NewLive()
	go s.RunLive(ctx)
	bl.paused.Store(st.BlockingPaused)

	// v2.4 features
	theAudit = NewAudit(filepath.Join(settingsDir, "goproxy-audit.jsonl"), func() int { return settings.Get().AuditDays })
	settings.audit = theAudit.Add
	ntfy := NewNtfy(dialViaServer(s))
	s.alerts = NewAlerts(settings, ntfy)
	s.flight = NewFlight(65536, time.Duration(orInt(st.FlightMinutes, 10))*time.Minute, filepath.Join(settingsDir, "flight"))
	s.flight.rec.Store(st.Feature("flight_rec"))
	s.devvol = NewDeviceVolume()
	s.devvol.On.Store(st.Feature("device_volume"))
	s.flight.on = func() bool { return settings.Get().Feature("flight_rec") }
	s.devices = NewDevices(filepath.Join(settingsDir, "goproxy-groups.json"), settings, s.alerts)
	s.devices.names, s.devices.flight = s.names, s.flight
	s.canary = NewCanary(s, filepath.Join(settingsDir, "goproxy-drift.json"))
	s.canary.onFail = func(reason string) { s.flight.Dump("canary: "+reason, false) }
	outages := NewOutages(filepath.Join(settingsDir, "goproxy-outages.json"), settings, s.alerts)
	ipw := NewIPWatch(settings, s.alerts, outages)
	weekly := NewWeekly(filepath.Join(settingsDir, "goproxy-weekly.json"), s, outages)
	go weekly.Run(ctx)
	s.ads.Apply(st)
	if st.AdsFilter {
		log.Print("ads & tracking filter: on (global)")
	}
	if err := s.applyLocalNames(st); err != nil {
		log.Printf("local names: %v", err)
	}
	go s.devices.Run(ctx)
	go s.canary.Run(ctx)
	go outages.Watch(ctx, res)
	go ipw.Run(ctx)
	go watchHealthDrop(ctx, s)
	if bl.Enabled {
		log.Printf("ad blocking: on (paused=%v), %d blocklist(s)", bl.paused.Load(), len(bl.URLs))
	} else {
		log.Print("ad blocking: off unless switched on in the dashboard (Blocking card) or with -blocking=true")
	}
	go bl.Run(ctx, *refresh) // v2.7.0: downloads only while blocking is on
	app := &App{s: s, cache: cache, dnsAddr: *dnsAddr, httpAddr: *httpAddr, listeners: *listeners, stateFile: stateFile, cancel: cancel, stop: make(chan struct{}), died: make(chan string, 8)}
	theApp = app
	mux := http.NewServeMux()
	mux.HandleFunc("/ws/stats", s.serveWS)
	mux.HandleFunc("/api/stats", s.serveStatsJSON)
	mux.HandleFunc("/api/blocking", s.serveBlocking)
	mux.HandleFunc("/api/version", serveVersion)
	mux.HandleFunc("/api/flush", s.serveFlush)
	mux.HandleFunc("/health", s.serveHealthz)
	mux.HandleFunc("/api/peer/", s.servePeerAPI)
	mux.HandleFunc("/api/peers", s.servePeers)
	mux.HandleFunc("/api/peers/config", s.servePeerConfig)
	mux.HandleFunc("/api/kuma", s.serveKuma)
	mux.HandleFunc("/api/devices/volume", s.serveDeviceVolume)
	mux.HandleFunc("/api/health", s.serveHealth)
	mux.HandleFunc("/api/health/live", s.serveHealthLive)
	mux.HandleFunc("/api/blocklist/update", s.serveBlocklistUpdate)
	mux.HandleFunc("/api/shutdown", app.serveShutdown)
	app.upd = NewUpdater(app, *updateDir, *updateURL, *healthName)
	go func() {
		// wait so a takeover/rollback in progress can still use goproxy.old.exe
		time.Sleep(90 * time.Second)
		cur, prev, _ := exePaths()
		cleanupOldExes(cur, prev)
	}()
	app.upd.Register(mux)
	mux.Handle("/favicon", NewIconCache(2048, 24*time.Hour, 3*time.Second))
	mux.Handle("/", dashboardHandler())
	if *authFile == "" {
		*authFile = filepath.Join(settingsDir, "goproxy-auth.json")
	}
	auth := NewAuth(*authFile)
	auth.Register(mux)
	wd := NewWatchdog()
	wd.Every, wd.Fails = max(*wdEvery, 2*time.Second), max(*wdFails, 1)
	wd.Check = func() error { return selfCheck(app.dnsAddr, app.httpAddr) }
	wd.Paused = func() bool {
		select {
		case <-app.stop:
			return true
		default:
		}
		return app.upd.busy.Load() || !settings.Get().Feature("watchdog")
	}
	wd.Recover = app.recoverListeners
	wd.Escalate = app.restartProcess
	wd.Dump = func(reason string) { dumpGoroutines(reason); s.flight.Dump("watchdog: "+reason, true) }
	v24 := &V24{app: app, s: s, ipw: ipw, out: outages, wd: wd, audit: theAudit, ntfy: ntfy, auth: auth, explicit: explicit, started: st.clone(), upFlag: *upstreams, manageUpstreams: true}
	v24.upSig, v24.upWarn = serversSig(servers, srvSrc), srvWarn
	v24.kiosk = NewKiosk(filepath.Join(settingsDir, "goproxy-kiosk.json"), auth)
	v24.kiosk.v = v24
	v24.Register(mux)
	// v2.7.0
	s.insights = NewInsights()
	go s.RunInsights(ctx.Done())
	mux.HandleFunc("/api/v27/insights", s.serveInsights)
	v27 := NewV27(v24)
	s.v27 = v27
	s.alerts.hook = v27.pushWebhook
	v27.Register(mux)
	go v27.Run(ctx)
	mux.HandleFunc("/api/weekly", weekly.serve)
	// v2.8.0 smart server
	v28 := NewV28(s, settingsDir, weekly)
	v28.Register(mux)
	go v28.Run(ctx)
	v282 := NewV282(s, settingsDir)
	v282.Register(mux)
	go v282.Run(ctx)
	bench := NewBench(filepath.Join(settingsDir, "goproxy-bench.json"), func() []string {
		var out []string
		for _, u := range res.Ups() {
			out = append(out, u.URL)
		}
		return out
	})
	v24.registerBench(mux, bench)
	mux.HandleFunc("/api/ntfy/topic", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, map[string]string{"topic": randomTopic()}) })
	if !auth.Configured() {
		log.Printf("auth: no dashboard login yet; open the dashboard to create one")
	}
	app.mux = auth.Middleware(mux)

	var ho *handoffChild
	if *takeover {
		// zero-downtime handoff: load the snapshot the old process just saved, then ask it to let go of the ports.
		ho = newHandoffChild()
		if s.cacheFile != "" {
			t0 := time.Now()
			n, err := cache.LoadFile(s.cacheFile)
			s.restored.Store(int64(n))
			log.Printf("takeover: restored %d entries in %v (%v)", n, time.Since(t0).Round(time.Millisecond), err)
		}
		if err := ho.ready(); err != nil {
			fatal("takeover: old process did not answer: " + err.Error())
		}
	} else {
		go app.warmStart(ctx, true)
	}
	go s.KeepHot(ctx)
	go app.autosave(ctx, *autosaveEvery)
	if err := app.bindAll(*bindRetry); err != nil {
		if ho != nil {
			ho.fail(err.Error())
		}
		fatal(fmt.Sprintf("GoProxy DNS could not start: %v\n\nIs another DNS server (or an old GoProxy) still using port 53 / %s?\nDetails: %s", err, *httpAddr, logPath))
	}
	if ho != nil {
		if err := healthCheck(*dnsAddr, *healthName); err != nil {
			ho.fail("health check: " + err.Error())
			fatal("takeover health check failed: " + err.Error())
		}
		ho.ok()
		log.Print("takeover: health check passed, now serving")
		go app.warmStart(ctx, false)
	}
	close(ready)
	if *wdOn {
		go wd.Run(ctx)
		go func() {
			for r := range app.died {
				wd.Wake(r)
			}
		}()
	}
	log.Printf("data folder: %s", dataDir)
	log.Printf("goproxy v%s DNS on %s (udp x%d + tcp) | threads=%d cache=%dMB | upstreams=%d parallel-all=%v plain-fallback=%v profile=%s | dashboard %s",
		Version, *dnsAddr, udpListeners, runtime.NumCPU(), budget>>20, len(res.Ups()), res.ParallelAll.Load(), !res.NoPlainFallback.Load(), s.profile, dashURL(*httpAddr))

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		app.Stop(true)
	}()
	watchStopEvent(func() { log.Print("stop event received"); app.Stop(true) })
	go app.upd.Run(ctx)
	go app.upd.WatchAfterUpdate(ctx, rollbackProbe{
		enabled: func() bool { return settings.Get().AutoRollback },
		check:   func() error { return selfCheck(app.dnsAddr, app.httpAddr) },
		selfTest: func() bool {
			if !settings.Get().Feature("canary") {
				return true
			}
			return s.canary.RunOnce()
		},
		offline: res.Offline,
		every:   20 * time.Second,
		now:     time.Now,
	})
	go func() {
		<-app.stop
		app.shutdown()
		close(done)
	}()
	if serviceMode {
		<-done
		waitSvc()
		return
	}
	runPlatform(*httpAddr, app.stop, done)
}

// dialViaServer resolves names through GoProxy itself (used for ntfy), so alerts work even
// when this PC's own DNS settings point at an address that no longer works.
func dialViaServer(s *DNSServer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 5 * time.Second}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil || net.ParseIP(host) != nil {
			return d.DialContext(ctx, network, addr)
		}
		q := new(dns.Msg)
		q.SetQuestion(dns.Fqdn(host), dns.TypeA)
		if r, _, _ := s.Handle(q); r != nil {
			for _, rr := range r.Answer {
				if a, ok := rr.(*dns.A); ok {
					if c, err := d.DialContext(ctx, network, net.JoinHostPort(a.A.String(), port)); err == nil {
						return c, nil
					}
				}
			}
		}
		return d.DialContext(ctx, network, addr)
	}
}

// watchHealthDrop saves the flight recorder when the health score falls sharply.
func watchHealthDrop(ctx context.Context, s *DNSServer) {
	prev := -1
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		v := s.health.View()
		cur := v[len(v)-1].Scores.Overall
		if cur >= 0 && cur < 50 && prev >= 70 {
			s.flight.Dump(fmt.Sprintf("health score dropped from %d to %d", prev, cur), false)
		}
		if cur >= 0 {
			prev = cur
		}
	}
}

var stopOnce sync.Once

func closeOnce(c chan struct{}) { stopOnce.Do(func() { close(c) }) }

// dashURL turns a listen address (":8080", "127.0.0.1:8053") into a clickable URL.
func dashURL(addr string) string {
	if strings.HasPrefix(addr, ":") {
		return "http://localhost" + addr + "/"
	}
	return "http://" + addr + "/"
}
