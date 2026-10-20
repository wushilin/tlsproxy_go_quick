package main

// Connection handling: accept, read ClientHello, route, relay, log.
//
// One goroutine per connection does the handshake and the client->server
// copy; a second does server->client. Goroutines are multiplexed over
// kqueue/epoll by the Go runtime, so this is plain blocking-style code.

import (
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/acme"
)

// TLS alert record: fatal (2), access_denied (49).
var alertAccessDenied = []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 49}

// Runtime is everything derived from one version of the config file. It is
// swapped atomically on reload: new connections use the new one, existing
// connections keep the one they started with. A new Runtime has empty caches.
type Runtime struct {
	cfg              *Config
	pool             *BufferPool
	cache            *RouteCache
	upstreamSessions map[*Rule]tls.ClientSessionCache
	limits           map[*Rule]*ruleLimits  // max_aggregated_speed buckets
	limitsBySource   map[string]*ruleLimits // the same, for the next reload to keep
	// Per listener: the configuration its connections run with, and its
	// max_aggregated_speed buckets.
	byListener     map[string]*Config
	listenerLimits map[string]*ruleLimits
	serve          *serveState // what rules with service_rule keys serve with
}

func newRuntime(cfg *Config, prev *Runtime) *Runtime {
	rt := &Runtime{cfg: cfg, cache: NewRouteCache(cfg.AllowCacheSize, cfg.DenyCacheSize), upstreamSessions: make(map[*Rule]tls.ClientSessionCache)}
	for i := range cfg.Rules {
		if cfg.Rules[i].Terminates() && cfg.Rules[i].UpstreamTLS {
			rt.upstreamSessions[&cfg.Rules[i]] = tls.NewLRUClientSessionCache(64)
		}
	}
	var prevLimits map[string]*ruleLimits
	if prev != nil {
		prevLimits = prev.limitsBySource
	}
	rt.limits, rt.limitsBySource = newRuleLimits(cfg, prevLimits)
	rt.byListener, rt.listenerLimits = map[string]*Config{}, map[string]*ruleLimits{}
	for _, l := range cfg.PortListeners() {
		rt.byListener[l.Name] = cfg.ForListener(l)
		if l.MaxAggregatedSpeed == 0 {
			continue
		}
		var keep *ruleLimits
		if prev != nil {
			keep = prev.listenerLimits[l.Name]
		}
		if keep == nil || keep.rate != l.MaxAggregatedSpeed {
			keep = &ruleLimits{rate: l.MaxAggregatedSpeed}
			for d := range keep.dir {
				keep.dir[d] = newLimiter(l.MaxAggregatedSpeed, cfg.BufferSize)
			}
		}
		rt.listenerLimits[l.Name] = keep
	}
	if prev != nil && prev.cfg.BufferSize == cfg.BufferSize && prev.cfg.BufferPoolMaxIdle == cfg.BufferPoolMaxIdle {
		rt.pool = prev.pool
	} else {
		// A replaced pool is simply dropped: its parked buffers are garbage
		// collected, and buffers still in use are freed when returned.
		if prev != nil {
			prev.pool.Stop()
		}
		rt.pool = NewBufferPool(cfg.BufferSize, cfg.BufferPoolMaxIdle)
	}
	return rt
}

type Server struct {
	runtime atomic.Pointer[Runtime]
	stats   *Stats
	certs   *CertManager
	nextID  atomic.Uint64

	configPath string               // "" when the config did not come from a file
	reloadNow  chan chan<- []string // poked by the console after a save; the reply says what failed
	console    *Console

	// console.toml (--console): its path, and the last version of it that
	// parsed, which every load of config.toml merges in (see loadConfig).
	consolePath string
	consoleCfg  atomic.Pointer[ConsoleConfig]
	consoleHash string // what was last read from consolePath, good or not (reload only)

	// Rules stopped from the console, by Rule.Key: routed as if absent. Kept
	// in memory only, across reloads; a restart starts them all again.
	stoppedMu sync.Mutex
	stopped   atomic.Pointer[map[string]bool]

	// The ports, by listener name (see listeners.go).
	listenersMu      sync.Mutex
	listeners        map[string]*liveListener
	stoppedListeners map[string]bool // stopped from the console, in memory only
	serving          bool            // start-up is over: log each listener that opens

	// Connections served here (rules with service_rule keys), by their TLS
	// connection, for the web server to find (see serve.go).
	served sync.Map // *tls.Conn -> *servedConn
	auth   *authChecker

	dialer *targetDialer // resolves targets (cached) and connects

	// Connections per source address that have not sent their ClientHello yet.
	handshakes *sourceCounts // per source, still sending a ClientHello

	rejectLog, handshakeLog rateLimitedLog

	tickets atomic.Pointer[ticketKeys] // replaced whole when rotated

	nonces *nonceCache // ClientHello randoms forwarded lately (remember_nonce)
}

// sessionTicketKeys returns a stable current key and yesterday's key.  TLS
// configs are deliberately built per connection (ALPN differs), so without
// this shared server state every ticket would be unusable on the next one.
// stoppedRules is the current set of stopped rule keys (never modified).
func (s *Server) stoppedRules() map[string]bool {
	if m := s.stopped.Load(); m != nil {
		return *m
	}
	return nil
}

// setRuleStopped stops or starts a rule. Stopping closes its connections.
// Either way the route cache starts empty, so no decision made under the
// old set survives.
func (s *Server) setRuleStopped(key string, stop bool) {
	s.stoppedMu.Lock()
	next := map[string]bool{}
	for k := range s.stoppedRules() {
		next[k] = true
	}
	if stop {
		next[key] = true
	} else {
		delete(next, key)
	}
	s.stopped.Store(&next)
	s.stoppedMu.Unlock()
	for {
		rt := s.runtime.Load()
		fresh := *rt
		fresh.cache = NewRouteCache(rt.cfg.AllowCacheSize, rt.cfg.DenyCacheSize)
		if s.runtime.CompareAndSwap(rt, &fresh) {
			break // else a reload just swapped in a runtime (with empty caches); redo on that one
		}
	}
	if !stop {
		return
	}
	var victims []*ConnState
	s.stats.conns.Range(func(c *ConnState) bool {
		c.mu.Lock()
		if c.RuleKey == key {
			victims = append(victims, c)
		}
		c.mu.Unlock()
		return true
	})
	for _, c := range victims {
		c.stop("rule stopped from the console; closed by proxy")
	}
}

// ticketKeys are the TLS session ticket keys, newest first: never changed
// once published, so handshakes read them without a lock.
type ticketKeys struct {
	keys    [][32]byte
	rotated time.Time
}

func (s *Server) sessionTicketKeys() [][32]byte {
	for {
		old := s.tickets.Load()
		if old != nil && time.Since(old.rotated) < 24*time.Hour {
			return old.keys
		}
		var key [32]byte
		if _, err := rand.Read(key[:]); err != nil {
			panic(fmt.Sprintf("TLS ticket key randomness: %v", err))
		}
		next := &ticketKeys{keys: [][32]byte{key}, rotated: time.Now()}
		if old != nil {
			next.keys = append(next.keys, old.keys[0]) // the previous key still decrypts
		}
		if s.tickets.CompareAndSwap(old, next) {
			return next.keys
		}
		// Another handshake rotated first: use its keys.
	}
}

// NewServer fails if a CA a rule names cannot be opened.
func NewServer(cfg *Config) (*Server, error) {
	s := &Server{stats: NewStats(), certs: NewCertManager(), reloadNow: make(chan chan<- []string, 1), dialer: newTargetDialer(), handshakes: newSourceCounts(), nonces: newNonceCache(), auth: newAuthChecker()}
	if err := s.certs.Apply(cfg); err != nil {
		return nil, err
	}
	s.stats.prepare(cfg)
	rt := newRuntime(cfg, nil)
	rt.serve = s.newServeState(cfg)
	s.runtime.Store(rt)
	s.consoleCfg.Store(cfg.Console)
	if cfg.Console != nil {
		s.consoleHash = cfg.Console.sourceHash
	}
	return s, nil
}

// startConsoleOnce starts the console, if the configuration has one and it
// is not running yet. The plaintext password goes first, so the console
// never starts with a hash that is not on disk.
func (s *Server) startConsoleOnce() error {
	con := s.runtime.Load().cfg.Console
	if con == nil || s.console != nil {
		return nil
	}
	s.securePassword(con)
	if err := s.startConsole(con); err != nil {
		return fmt.Errorf("console: %w", err)
	}
	return nil
}

// loadConfig reads a version of config.toml as the proxy runs it: with
// console.toml merged in. Every load goes through here (start-up, reloads,
// and each check or save from the console), so a version that passes a
// check is one a reload accepts.
func (s *Server) loadConfig(text string) (*Config, error) {
	return LoadConfig(text, s.consoleCfg.Load())
}

// rateLimitedLog writes at most one line a second and says how many it left
// out, so a flood cannot fill the log or slow down whoever is logging.
type rateLimitedLog struct {
	last       atomic.Int64 // unix nanoseconds of the last line written
	suppressed atomic.Int64
}

func (r *rateLimitedLog) logf(format string, args ...any) {
	now := time.Now().UnixNano()
	last := r.last.Load()
	if now-last < int64(time.Second) || !r.last.CompareAndSwap(last, now) {
		r.suppressed.Add(1) // within the second, or another caller just took it
		return
	}
	n := r.suppressed.Swap(0)
	if n > 0 {
		format += fmt.Sprintf(" (and %d more like this in the last second, not logged)", n)
	}
	logf(format, args...)
}

// sourceKey is what per-source limits count by: the IPv4 address, or the /64
// of an IPv6 address (one host typically owns a whole /64).
func sourceKey(addr net.Addr) netip.Addr {
	tcp, ok := addr.(*net.TCPAddr)
	if !ok {
		return netip.Addr{}
	}
	ip, _ := netip.AddrFromSlice(tcp.IP)
	if ip = ip.Unmap(); ip.Is6() {
		p, _ := ip.Prefix(64)
		return p.Addr()
	}
	return ip
}

// beginHandshake counts a connection that is about to send its ClientHello. It
// reports false when its source already has max_handshakes_per_ip of them:
// slots cost a client nothing to hold for handshake_timeout, so without this
// one address could occupy all of max_connections with idle sockets.
//
// It takes no lock: the count is an atomic per source (see sourceCounts). It
// returns the counter to hand to endHandshake, nil when refused.
func (s *Server) beginHandshake(key netip.Addr, limit int) *atomic.Int32 {
	n := s.handshakes.counter(key)
	if v := n.Add(1); limit > 0 && int(v) > limit {
		n.Add(-1)
		return nil
	}
	return n
}

func (s *Server) endHandshake(n *atomic.Int32) { n.Add(-1) }

// Run binds to the configured address and serves forever. consolePath is
// the console.toml cfg was loaded with, "" for none.
func Run(cfg *Config, path, consolePath string) error {
	srv, err := NewServer(cfg) // before binding: a bad certificate is a startup error
	if err != nil {
		return err
	}
	srv.consolePath, srv.configPath = consolePath, path
	if err := srv.startConsoleOnce(); err != nil { // before any listener: its rule may be the console's
		return err
	}
	// A listener whose port cannot be opened is reported (and shown in the
	// console, where Start retries it); the proxy refuses to start only when
	// none can open.
	if failed := srv.syncListeners(cfg); !srv.anyOpen(cfg.Listeners) {
		return errors.New(strings.Join(failed, "; "))
	}
	// From here on the streams go to their log files, if configured.
	if err := ConfigureLogging(cfg.Log); err != nil {
		return err
	}
	StartAsyncLogging() // from here on nobody waits for the log to be written
	defer FlushLogs()
	return srv.Serve(nil, path)
}

// Serve runs the proxy on the listeners Run opened, or, when l is given, on
// l (and more) as the first configured listener, whatever its bind and port
// say (tests listen on a free port). If path is non-empty the config file is
// watched and reloaded when it changes. With l, it returns when l is closed.
func (s *Server) Serve(l net.Listener, path string, more ...net.Listener) error {
	rt := s.runtime.Load()
	s.configPath = path // before the console starts: its handlers read it
	if err := s.startConsoleOnce(); err != nil {
		return err
	}
	if l != nil {
		first := &rt.cfg.Listeners[0]
		live := newLiveListener(first.Name, nil)
		live.lns, live.adopted = append([]net.Listener{l}, more...), true
		for _, ln := range live.lns {
			live.addrs = append(live.addrs, ln.Addr().String())
		}
		s.listenersMu.Lock()
		s.listeners = map[string]*liveListener{first.Name: live}
		s.listenersMu.Unlock()
		if len(rt.cfg.Listeners) > 1 || rt.cfg.Redirect != nil {
			if failed := s.syncListeners(rt.cfg); failed != nil {
				return errors.New(failed[0])
			}
		}
	}
	s.listenersMu.Lock()
	var addrs, closed []string
	for _, lc := range rt.cfg.PortListeners() {
		if live := s.listeners[lc.Name]; live != nil && live.open() {
			addrs = append(addrs, lc.Name+" "+strings.Join(live.addrs, ", "))
		} else {
			closed = append(closed, lc.Name)
		}
	}
	s.serving = true
	s.listenersMu.Unlock()
	notOpen := ""
	if closed != nil {
		notOpen = " (not open: " + strings.Join(closed, ", ") + ")"
	}
	logf("listening on %s%s with %s", strings.Join(addrs, "; "), notOpen, rt.cfg.Describe())
	for _, w := range rt.cfg.Warnings {
		errorf("config: %s", w)
	}
	if n := len(rt.cfg.AutoDomains()); n > 0 {
		logf("cert: managing %d automatic certificate(s) in %s via %s", n, rt.cfg.CertPath, rt.cfg.AcmeDirectory)
	}
	s.certs.Start()
	for _, k := range rt.cfg.Ignored {
		logf("config: %q is not used by this version and was ignored", k)
	}
	if path != "" {
		go s.watchConfig(path)
	}
	go s.reportStats()
	go func() {
		for range time.Tick(time.Second) {
			s.stats.sample()
		}
	}()
	watchSignals(s)
	if l == nil {
		select {} // the listeners' accept loops do the work
	}
	s.listenersMu.Lock()
	live := s.listeners[rt.cfg.Listeners[0].Name]
	s.listenersMu.Unlock()
	for _, extra := range more {
		go s.acceptLoop(extra, live)
	}
	return s.acceptLoop(l, live)
}

// acceptLoop serves one socket of a listener until it is closed.
func (s *Server) acceptLoop(l net.Listener, live *liveListener) error {
	for {
		sock, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			errorf("accept error: %v", err) // typically EMFILE; back off
			time.Sleep(200 * time.Millisecond)
			continue
		}
		rt := s.runtime.Load()
		name := *live.name.Load()
		cfg := rt.byListener[name]
		if cfg == nil {
			sock.Close() // removed by a reload an instant ago; its socket is closing
			continue
		}
		ls := s.stats.listener(name)
		id := s.nextID.Add(1)
		active := s.stats.Active.Add(1)
		mine := ls.Active.Add(1)
		reject := ""
		switch lim := cfg.listener.MaxConnections; {
		case int(active) > rt.cfg.MaxConnections:
			reject = fmt.Sprintf("too many connections (%d > %d)", active, rt.cfg.MaxConnections)
		case lim > 0 && int(mine) > lim:
			reject = fmt.Sprintf("too many connections on listener %s (%d > %d)", name, mine, lim)
		}
		if reject != "" {
			s.rejectLog.logf("[#%d] rejected %s: %s", id, sock.RemoteAddr(), reject)
			s.stats.flows.refused(id, name, time.Now(), sock.RemoteAddr(), sock.LocalAddr(), reject)
			s.stats.Active.Add(-1)
			ls.Active.Add(-1)
			s.stats.Rejected.Add(1)
			ls.Rejected.Add(1)
			sock.Close()
			continue
		}
		ls.Accepted.Add(1)
		s.stats.GoroutinesStarted.Add(1)
		go func() {
			defer s.stats.GoroutinesFinished.Add(1)
			defer s.stats.Active.Add(-1)
			defer ls.Active.Add(-1)
			if cfg.listener.IsRedirect {
				s.handleRedirect(id, sock, int(active), cfg)
				return
			}
			s.handle(id, sock, int(active), rt, cfg)
		}()
	}
}

func (s *Server) reportStats() {
	for {
		every := s.runtime.Load().cfg.StatsInterval
		if every == 0 {
			time.Sleep(5 * time.Second) // may be enabled by a reload
			continue
		}
		time.Sleep(every)
		logf("%s", s.stats.Summary(s.runtime.Load()))
	}
}

// watchConfig re-reads the config file every reload_interval and swaps in a
// new Runtime when its content changes. Comparing content (not mtime) means
// the newest version always wins and reloads happen at most once per interval.
func (s *Server) watchConfig(path string) {
	lastHash := s.runtime.Load().cfg.sourceHash
	haveLast := lastHash != ""
	for {
		// Wake up every reload_interval, or at once when the console saved.
		// With reload_interval = 0 only the console triggers reloads.
		var tick <-chan time.Time
		if interval := s.runtime.Load().cfg.ReloadInterval; interval > 0 {
			tick = time.After(interval)
		}
		var reply chan<- []string
		select {
		case <-tick:
		case reply = <-s.reloadNow:
		}
		problems := s.reload(path, &lastHash, &haveLast)
		if reply != nil {
			reply <- problems
		}
	}
}

// reload applies the config file if its content (hash) changed since
// lastHash. It returns what went wrong: why the file was not applied, or the
// listeners that could not open their ports.
func (s *Server) reload(path string, lastHash *string, haveLast *bool) []string {
	text, err := os.ReadFile(path)
	if err != nil {
		if *haveLast {
			errorf("config reload: cannot read %s: %v; keeping current config", path, err)
			*haveLast = false
		}
		return []string{fmt.Sprintf("cannot read %s: %v; the running configuration is unchanged", path, err)}
	}
	hash := fileHash(text)
	consoleChanged, problems := s.rereadConsole()
	if *haveLast && hash == *lastHash && !consoleChanged {
		return problems
	}
	*lastHash, *haveLast = hash, true
	cfg, err := s.loadConfig(string(text))
	if err != nil {
		errorf("config reload: %s is invalid, keeping current config: %v", path, err)
		return append(problems, fmt.Sprintf("the file is invalid, so the running configuration is unchanged: %v", err))
	}
	old := s.runtime.Load()
	if err := s.certs.Apply(cfg); err != nil {
		errorf("config reload: %s rejected, keeping current config: %v", path, err)
		return []string{fmt.Sprintf("the file was not applied, the running configuration is unchanged: %v", err)}
	}
	s.securePassword(cfg.Console)
	if s.console != nil && cfg.Console != nil {
		s.console.update(cfg.Console)
		if consoleServed(cfg.Console) != s.console.served {
			msg := fmt.Sprintf("console.toml: the console's plain HTTP address or its cert changed (from %s to %s); that part needs a restart", s.console.served, consoleServed(cfg.Console))
			errorf("config reload: %s", msg)
			problems = append(problems, msg)
		}
	}
	for _, w := range cfg.Warnings {
		errorf("config: %s", w)
	}
	if err := ConfigureLogging(cfg.Log); err != nil {
		errorf("config reload: %v; logging is unchanged", err)
	}
	rt := newRuntime(cfg, old)
	rt.serve = s.newServeState(cfg)
	s.stats.prepare(cfg) // before it goes live: connections only read these counters
	s.runtime.Store(rt)
	old.serve.retire()
	problems = append(problems, s.syncListeners(cfg)...) // after the store: a new listener's connections need its config
	extra := ""
	if rt.pool != old.pool {
		extra = ", buffer pool replaced (old buffers freed)"
	}
	logf("config reloaded from %s: %s; route caches cleared%s; existing connections keep their settings",
		path, cfg.Describe(), extra)
	return problems
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// addrOf is a TCP address's IP, the zero Addr for anything else.
func addrOf(a net.Addr) netip.Addr {
	if tcp, ok := a.(*net.TCPAddr); ok {
		if ip, ok := netip.AddrFromSlice(tcp.IP); ok {
			return ip.Unmap()
		}
	}
	return netip.Addr{}
}

// readHello reads until the ClientHello is complete. It returns the SNI/ALPN
// and every byte read (forwarded verbatim, or replayed into our own TLS
// server when terminating). buf is a pooled buffer; a hello
// that doesn't fit spills into a heap slice, which is returned instead.
func readHello(client net.Conn, buf []byte) (info helloInfo, data []byte, err error) {
	data = buf[:0]
	// Keep framing state across reads. Calling parseHello after every Read would
	// rebuild all preceding handshake fragments each time; a peer could exploit
	// that by trickling the final record one byte at a time. We only invoke the
	// full parser once the record framing proves that the complete ClientHello
	// is present.
	scanAt, records, handshakeBytes := 0, 0, 0
	headerBytes, helloBytes := 0, -1
	var header [4]byte
	for {
		if len(data) == cap(data) {
			if cap(data) > maxClientHello+16 {
				return info, data, errors.New("ClientHello too large")
			}
			bigger := make([]byte, len(data), 2*cap(data)+4096)
			copy(bigger, data)
			data = bigger
		}
		n, rerr := client.Read(data[len(data):cap(data)])
		data = data[:len(data)+n]
		if n > 0 {
			for {
				if len(data)-scanAt < 5 {
					if len(data) > scanAt && data[scanAt] != 0x16 {
						return info, data, fmt.Errorf("not a TLS handshake record (content type 0x%02x)", data[scanAt])
					}
					break
				}
				if data[scanAt] != 0x16 {
					return info, data, fmt.Errorf("not a TLS handshake record (content type 0x%02x)", data[scanAt])
				}
				if records >= maxClientHelloRecords {
					return info, data, fmt.Errorf("ClientHello spans more than %d TLS records", maxClientHelloRecords)
				}
				if data[scanAt+1] != 0x03 {
					return info, data, fmt.Errorf("unsupported TLS record version %02x%02x", data[scanAt+1], data[scanAt+2])
				}
				recordBytes := int(data[scanAt+3])<<8 | int(data[scanAt+4])
				if recordBytes == 0 {
					return info, data, errors.New("empty TLS record")
				}
				recordEnd := scanAt + 5 + recordBytes
				if recordEnd > maxClientHello {
					return info, data, errors.New("ClientHello too large")
				}
				if len(data) < recordEnd {
					break
				}
				payload := data[scanAt+5 : recordEnd]
				if headerBytes < len(header) {
					headerBytes += copy(header[headerBytes:], payload)
					if headerBytes == len(header) {
						if header[0] != 0x01 {
							return info, data, fmt.Errorf("first handshake message is not ClientHello (type %d)", header[0])
						}
						helloBytes = 4 + int(header[1])<<16 + int(header[2])<<8 + int(header[3])
						if helloBytes > maxClientHello {
							return info, data, errors.New("ClientHello too large")
						}
					}
				}
				handshakeBytes += recordBytes
				if helloBytes >= 0 && handshakeBytes >= helloBytes {
					info, perr := parseHello(data)
					return info, data, perr
				}
				scanAt = recordEnd
				records++
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				rerr = errors.New("closed before ClientHello was complete")
			}
			return info, data, rerr
		}
	}
}

// handle serves one accepted connection with cfg, its listener's
// configuration.
func (s *Server) handle(id uint64, sock net.Conn, active int, rt *Runtime, cfg *Config) {
	defer sock.Close()
	start := time.Now()
	physicalKey := sourceKey(sock.RemoteAddr())
	physicalSlot := s.beginHandshake(physicalKey, cfg.MaxHandshakesPerIP)
	if physicalSlot == nil {
		s.handshakeLog.logf("[#%d] rejected %s: %d connections from this source are still sending their ClientHello (max_handshakes_per_ip)", id, sock.RemoteAddr(), cfg.MaxHandshakesPerIP)
		s.stats.Rejected.Add(1)
		s.stats.flows.refused(id, cfg.listener.Name, start, sock.RemoteAddr(), sock.LocalAddr(), "too many handshakes from this source (max_handshakes_per_ip)")
		return
	}
	s.stats.Accepted.Add(1)
	slot := physicalSlot // the handshake count this connection holds; nil once released
	defer func() {
		if slot != nil {
			s.endHandshake(slot)
		}
	}()

	// A PROXY protocol header is only looked for when the peer is listed in
	// proxy_trust_source: whoever may send one chooses the address that is
	// logged, counted by max_handshakes_per_ip and passed on to the target, so
	// it must not be any client that happens to connect. For everybody else
	// the stream is TLS from its first byte (a header would simply be a bad
	// ClientHello). Header detection shares the ClientHello deadline.
	sock.SetReadDeadline(start.Add(cfg.HandshakeTimeout))
	client, err := &proxyConn{Conn: sock}, error(nil)
	if cfg.trustsProxySource(sock.RemoteAddr()) {
		client, err = detectProxyProtocol(sock)
	}
	if err != nil {
		s.stats.Failed.Add(1)
		logf("[#%d] closed src=%s: bad PROXY protocol header: %v after %s", id, sock.RemoteAddr(), err, humanDuration(time.Since(start)))
		s.stats.flows.refused(id, cfg.listener.Name, start, sock.RemoteAddr(), sock.LocalAddr(), "bad PROXY protocol header: "+err.Error())
		return
	}
	proxiedKey := sourceKey(client.RemoteAddr())
	if proxiedKey != physicalKey {
		proxiedSlot := s.beginHandshake(proxiedKey, cfg.MaxHandshakesPerIP)
		if proxiedSlot == nil {
			s.handshakeLog.logf("[#%d] rejected %s: %d connections from this source are still sending their ClientHello (max_handshakes_per_ip)", id, client.RemoteAddr(), cfg.MaxHandshakesPerIP)
			s.stats.Accepted.Add(-1) // source admission happens after header detection
			s.stats.Rejected.Add(1)
			s.stats.flows.refused(id, cfg.listener.Name, start, client.RemoteAddr(), client.LocalAddr(), "too many handshakes from this source (max_handshakes_per_ip)")
			return
		}
		s.endHandshake(physicalSlot)
		slot = proxiedSlot
	}
	src := client.RemoteAddr().String()
	logf("[#%d] accepted from %s (active=%d)", id, src, active)

	c := &ConnState{ID: id, Src: src, Local: client.LocalAddr().String(), Start: start, Listener: cfg.listener.Name, lstats: s.stats.listener(cfg.listener.Name)}
	c.lastActivityUnixNano.Store(start.UnixNano())
	if client.version > 0 { // a load balancer in front stated the client's address
		c.how.Via, c.how.ViaVersion = sock.RemoteAddr().String(), client.version
	}
	s.stats.register(c)
	defer s.stats.unregister(c)

	// One overall deadline: a slow trickle can't extend it.
	helloBuf := rt.pool.Get()
	info, hello, err := readHello(client, helloBuf)
	s.endHandshake(slot)
	slot = nil
	sni := info.SNI
	if err != nil {
		rt.pool.Put(helloBuf)
		s.stats.Failed.Add(1)
		if isTimeout(err) {
			c.setEnd(flowFailed, fmt.Sprintf("no ClientHello within %s", humanDuration(cfg.HandshakeTimeout)))
			logf("[#%d] closed src=%s: no ClientHello within %s", id, src, humanDuration(cfg.HandshakeTimeout))
		} else {
			c.setEnd(flowFailed, fmt.Sprintf("bad ClientHello: %v", err))
			logf("[#%d] closed src=%s: bad ClientHello: %v after %s", id, src, err, humanDuration(time.Since(start)))
		}
		return
	}
	client.SetReadDeadline(time.Time{})
	sniDisp := sni
	if sni == "" {
		sniDisp = "<none>"
		if info.SNIIP.IsValid() {
			sniDisp = "<ip " + info.SNIIP.String() + ">" // routed as no SNI
		}
	}
	if cfg.RememberNonce && s.nonces.seen(info.Digest, time.Now()) {
		rt.pool.Put(helloBuf)
		s.stats.Denied.Add(1)
		c.mu.Lock()
		c.SNI, c.routed = sni, true
		c.mu.Unlock()
		c.setEnd(flowDenied, "connection loop: this proxy forwarded this ClientHello itself moments ago (remember_nonce)")
		logf("[#%d] route sni=%s src=%s -> DENY (connection loop: this proxy forwarded this ClientHello itself moments ago)", id, sniDisp, src)
		client.Write(alertAccessDenied)
		return
	}

	// One cache for every listener: the key says whose rules decided.
	d, hit := rt.cache.GetOrRoute(cfg.listener.Name+"\x00"+sni, func() Decision { return cfg.RouteExcept(sni, s.stoppedRules()) })
	cached := ""
	if hit {
		cached = ", cached"
		s.stats.CacheHits.Add(1)
	} else {
		s.stats.CacheMisses.Add(1)
	}
	// The CA validating a TLS-ALPN-01 challenge for one of our names: only
	// answered here when the rule that routes the name terminates TLS here.
	// A passed-through name's challenges reach its target untouched, like
	// any other connection (its backend runs its own ACME client), and so
	// do a terminated name's when no challenge of ours is pending.
	if info.offers(acme.ALPNProto) && d.Allow && d.Rule != nil && d.Rule.Terminates() {
		if answer := s.certs.Challenge(sni); answer != nil {
			tc := tls.Server(&prefixConn{Conn: client, prefix: hello}, &tls.Config{
				Certificates: []tls.Certificate{*answer},
				NextProtos:   []string{acme.ALPNProto},
			})
			tc.SetDeadline(time.Now().Add(cfg.HandshakeTimeout))
			err := tc.Handshake()
			tc.Close()
			rt.pool.Put(helloBuf)
			c.mu.Lock()
			c.SNI, c.routed = sni, true
			c.mu.Unlock()
			if err != nil {
				s.stats.Failed.Add(1)
				c.setEnd(flowFailed, fmt.Sprintf("TLS-ALPN-01 challenge failed: %v", err))
				errorf("[#%d] cert: TLS-ALPN-01 challenge for %s from %s failed: %v", id, sni, src, err)
			} else {
				s.stats.Completed.Add(1)
				c.setEnd(flowACME, "answered the TLS-ALPN-01 challenge")
				logf("[#%d] cert: answered the TLS-ALPN-01 challenge for %s from %s", id, sni, src)
			}
			return
		}
	}
	if !d.Allow {
		rt.pool.Put(helloBuf)
		s.stats.Denied.Add(1)
		c.mu.Lock()
		c.SNI, c.routed = sni, true
		if d.Rule != nil {
			c.RuleKey, c.rulePattern = d.Rule.Key(), d.Rule.Source
		}
		c.mu.Unlock()
		switch {
		case d.Err != "":
			c.setEnd(flowDenied, "error: "+d.Err)
			logf("[#%d] route sni=%s src=%s -> DENY (error: %s%s)", id, sniDisp, src, d.Err, cached)
		case d.RuleLine == 0:
			c.setEnd(flowDenied, "no rule matched")
			logf("[#%d] route sni=%s src=%s -> DENY (no rule matched%s)", id, sniDisp, src, cached)
		default:
			c.setEnd(flowDenied, fmt.Sprintf("deny rule at line %d", d.RuleLine))
			logf("[#%d] route sni=%s src=%s -> DENY (rule line %d%s)", id, sniDisp, src, d.RuleLine, cached)
		}
		client.Write(alertAccessDenied)
		return
	}
	dest := net.JoinHostPort(d.Host, strconv.Itoa(d.Port))
	destDisp := dest // [2001:db8::1]:443 for an IPv6 target
	if d.Rule.Serves() {
		destDisp = "served here"
	}
	logf("[#%d] route sni=%s -> %s (ALLOW, rule line %d%s)", id, sniDisp, destDisp, d.RuleLine, cached)
	ruleKey := d.Rule.Key()
	l := cfg.listener
	c.mu.Lock()
	c.how.Cached = hit
	if d.Rule.Proxy {
		c.how.ProxyOut = d.Rule.ProxyVersion
	}
	c.how.ConnLimit = minLimit(d.Rule.MaxSingleConnectionSpeed, l.MaxSingleConnectionSpeed)
	c.how.ShareLimit = minLimit(d.Rule.MaxAggregatedSpeed, l.MaxAggregatedSpeed)
	c.SNI, c.Dst, c.routed = sni, destDisp, true
	c.host = s.stats.host(sniDisp)
	c.RuleKey, c.rulePattern, c.rule = ruleKey, d.Rule.Source, s.stats.rule(ruleKey)
	c.mu.Unlock()
	c.host.Active.Add(1)
	c.host.Total.Add(1)
	defer c.host.Active.Add(-1)
	c.rule.Active.Add(1)
	c.rule.Total.Add(1)
	defer c.rule.Active.Add(-1)
	s.stats.flows.emit("route", c)

	// A local CA only issues for the names its rule allows: refuse the others
	// before connecting anywhere.
	if caID := d.Rule.LocalCA(); caID != "" {
		if _, err := d.Rule.LocalCAName(sni, info.SNIIP, addrOf(client.LocalAddr())); err != nil {
			rt.pool.Put(helloBuf)
			s.stats.Failed.Add(1)
			reason := fmt.Sprintf("CA %s: %v", caID, err)
			c.setEnd(flowFailed, reason)
			logf("[#%d] closed src=%s sni=%s: %s", id, src, sniDisp, reason)
			client.Write(alertAccessDenied)
			return
		}
	}
	if d.Rule.Serves() {
		s.serveHere(c, client, hello, helloBuf, info, d, cfg, rt)
		return
	}

	t0 := time.Now()
	up, err := s.dialer.Dial(d.Host, d.Port, cfg.ConnectTimeout)
	if err != nil {
		rt.pool.Put(helloBuf)
		s.stats.Failed.Add(1)
		c.setEnd(flowFailed, fmt.Sprintf("connect failed: %v", err))
		logf("[#%d] closed src=%s sni=%s dst=%s: connect failed: %v after %s", id, src, sniDisp, destDisp, err, humanDuration(time.Since(t0)))
		return
	}
	defer up.Close()
	peer := up.RemoteAddr().String()
	c.mu.Lock()
	c.Peer, c.UpLocal = peer, up.LocalAddr().String()
	c.mu.Unlock()

	var clientSide, serverSide duplex = client, up.(*net.TCPConn)
	mode := ""
	terminateHere := d.Rule != nil && d.Rule.Terminates()
	if terminateHere && info.offers(acme.ALPNProto) {
		// A TLS-ALPN-01 validation that is not ours (ours was answered above):
		// the upstream is running its own ACME client for this name. Only it
		// can answer, so hand the connection over untouched instead of
		// terminating it. That needs an upstream that speaks TLS.
		if !d.Rule.UpstreamTLS {
			rt.pool.Put(helloBuf)
			s.stats.Failed.Add(1)
			c.setEnd(flowFailed, "TLS-ALPN-01 challenge for a plaintext upstream")
			logf("[#%d] closed src=%s sni=%s dst=%s: TLS-ALPN-01 challenge that this proxy did not start, and the upstream is plaintext so it cannot answer either", id, src, sniDisp, destDisp)
			return
		}
		terminateHere = false
		mode = "TLS-ALPN-01 challenge not started here: passed through untouched to the TLS upstream"
	}
	if terminateHere {
		// Terminate TLS here. The upstream is contacted first so the client is
		// offered exactly the application protocol (h2, http/1.1) the upstream
		// agreed to; the ClientHello we already read is replayed into our TLS
		// server instead of being forwarded.
		tlsClient, tlsServer, how, err := s.terminate(client, up, hello, info, d, cfg, rt)
		rt.pool.Put(helloBuf)
		if err != nil {
			s.stats.Failed.Add(1)
			c.setEnd(flowFailed, err.Error())
			logf("[#%d] closed src=%s sni=%s dst=%s (%s): %v", id, src, sniDisp, destDisp, peer, err)
			return
		}
		clientSide, mode = tlsClient, how
		c.host.Terminated.Add(1)
		st := tlsClient.ConnectionState()
		c.mu.Lock()
		c.Mode = how
		c.how.TLS, c.how.ClientTLS, c.how.ALPN, c.how.Resumed = "terminated", tls.VersionName(st.Version), st.NegotiatedProtocol, st.DidResume
		switch {
		case !d.Rule.UpstreamTLS:
			c.how.Upstream = "plain"
		case !d.Rule.UpstreamTLSVerify:
			c.how.Upstream = "tls-unverified"
		default:
			c.how.Upstream = "tls"
		}
		c.mu.Unlock()
		if tlsServer != nil {
			serverSide = tlsServer
		}
		logf("[#%d] connected %s -> %s (%s) in %s (%s)", id, src, destDisp, peer, humanDuration(time.Since(t0)), withLimits(mode, d.Rule))
	} else {
		c.mu.Lock()
		c.how.TLS, c.how.ALPN = "passthrough", strings.Join(info.ALPN, ",") // what the client offered
		c.mu.Unlock()
		if cfg.RememberNonce {
			// Before any byte goes out: a hop back to this proxy could
			// otherwise read the hello before it is remembered.
			s.nonces.remember(info.Digest, time.Now())
		}
		// A foreign TLS-ALPN-01 challenge bypasses normal termination, but a
		// backend configured for PROXY protocol still needs its header before
		// the untouched ClientHello.
		if d.Rule != nil && d.Rule.Proxy {
			up.SetWriteDeadline(time.Now().Add(cfg.ConnectTimeout))
			if err := writeProxyProtocol(up, d.Rule.ProxyVersion, client.RemoteAddr(), client.LocalAddr()); err != nil {
				rt.pool.Put(helloBuf)
				s.stats.Failed.Add(1)
				c.setEnd(flowFailed, fmt.Sprintf("upstream PROXY protocol header failed: %v", err))
				logf("[#%d] closed src=%s sni=%s dst=%s: upstream PROXY protocol v%d header failed: %v", id, src, sniDisp, destDisp, d.Rule.ProxyVersion, err)
				return
			}
			up.SetWriteDeadline(time.Time{})
			if mode != "" {
				mode += ", "
			}
			mode += fmt.Sprintf("PROXY v%d header sent", d.Rule.ProxyVersion)
		}
		if mode = withLimits(mode, d.Rule); mode != "" {
			logf("[#%d] connected %s -> %s (%s) in %s (%s)", id, src, destDisp, peer, humanDuration(time.Since(t0)), mode)
		} else {
			logf("[#%d] connected %s -> %s (%s) in %s", id, src, destDisp, peer, humanDuration(time.Since(t0)))
		}
		if cfg.IdleTimeout > 0 {
			up.SetWriteDeadline(time.Now().Add(cfg.IdleTimeout))
		}
		written, writeErr := up.Write(hello)
		c.BytesUp.Add(int64(written))
		c.host.BytesUp.Add(int64(written))
		c.rule.BytesUp.Add(int64(written))
		c.lstats.BytesUp.Add(int64(written))
		s.stats.BytesUp.Add(int64(written))
		err = writeErr
		if err == nil && written != len(hello) {
			err = io.ErrShortWrite
		}
		rt.pool.Put(helloBuf) // back to the pool before the (possibly long) relay
		if err != nil {
			s.stats.Failed.Add(1)
			c.setEnd(flowFailed, fmt.Sprintf("upstream write error: %v", err))
			logf("[#%d] closed src=%s sni=%s dst=%s: upstream write error: %v", id, src, sniDisp, destDisp, err)
			return
		}
	}
	c.touch()
	s.stats.flows.emit("route", c) // connected: the peer and TLS mode are known

	r := &relay{c: c, stats: s.stats, cfg: cfg, pool: rt.pool, client: clientSide, server: serverSide, done: make(chan struct{})}
	for dir := range r.limits {
		r.limits[dir][0] = newLimiter(d.Rule.MaxSingleConnectionSpeed, cfg.BufferSize)
		if agg := rt.limits[d.Rule]; agg != nil {
			r.limits[dir][1] = agg.dir[dir]
		}
		r.limits[dir][2] = newLimiter(l.MaxSingleConnectionSpeed, cfg.BufferSize)
		if agg := rt.listenerLimits[l.Name]; agg != nil {
			r.limits[dir][3] = agg.dir[dir]
		}
	}
	var wg sync.WaitGroup
	// A stop from the console (the connection, or its rule since routing)
	// ends the relay; one asked for earlier is applied right here.
	c.setKill(r.closeAll)
	if s.stoppedRules()[ruleKey] {
		r.closeAll("rule stopped from the console; closed by proxy")
	}
	wg.Add(1)
	s.stats.GoroutinesStarted.Add(1)
	go func() {
		defer s.stats.GoroutinesFinished.Add(1)
		defer wg.Done()
		r.pump(sToC)
	}()
	r.pump(cToS)
	wg.Wait()
	r.finish()
	s.stats.Completed.Add(1)
	c.setEnd(flowClosed, r.reason())
	logf("[#%d] closed src=%s sni=%s dst=%s (%s) up=%s down=%s duration=%s reason=%s",
		id, src, sniDisp, destDisp, peer, humanBytes(c.BytesUp.Load()), humanBytes(c.BytesDown.Load()),
		humanDuration(time.Since(start)), r.reason())
}

// minLimit is the tighter of two speed limits, 0 meaning none.
func minLimit(a, b float64) float64 {
	if a == 0 || (b != 0 && b < a) {
		return b
	}
	return a
}

// withLimits adds the rule's speed limits, if any, to the connected line's note.
func withLimits(mode string, r *Rule) string {
	l := ""
	if r != nil {
		l = describeLimits(r)
	}
	switch {
	case l == "":
		return mode
	case mode == "":
		return l
	}
	return mode + "; " + l
}

// duplex is a connection whose write side can be closed on its own
// (*net.TCPConn: FIN; *tls.Conn: close_notify).
type duplex interface {
	net.Conn
	CloseWrite() error
}

// prefixConn replays bytes that were already read from the socket (the
// ClientHello) before continuing with the socket itself.
type prefixConn struct {
	net.Conn
	prefix []byte
}

func (p *prefixConn) Read(b []byte) (int, error) {
	if len(p.prefix) > 0 {
		n := copy(b, p.prefix)
		p.prefix = p.prefix[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}

// terminate completes TLS with the client (and with the upstream, if the rule
// says so). It returns the two sides to relay between (upstream is nil when it
// stays plaintext) and a short description for the log.
func (s *Server) terminate(client, up net.Conn, hello []byte, info helloInfo, d Decision, cfg *Config, rt *Runtime) (*tls.Conn, *tls.Conn, string, error) {
	rule := d.Rule
	var offer []string // what the client asked for, minus ACME's pseudo protocol
	for _, p := range info.ALPN {
		if p != acme.ALPNProto {
			offer = append(offer, p)
		}
	}
	if rule.Proxy {
		up.SetWriteDeadline(time.Now().Add(cfg.ConnectTimeout))
		if err := writeProxyProtocol(up, rule.ProxyVersion, client.RemoteAddr(), client.LocalAddr()); err != nil {
			return nil, nil, "", fmt.Errorf("upstream PROXY protocol v%d header failed: %v", rule.ProxyVersion, err)
		}
		up.SetWriteDeadline(time.Time{})
	}
	var tlsUp *tls.Conn
	var protos []string
	how := "tls terminated, plaintext"
	if rule.Proxy {
		how += fmt.Sprintf(" with PROXY v%d", rule.ProxyVersion)
	}
	if rule.UpstreamTLS {
		// Like any reverse proxy, present the name the client asked for, so an
		// upstream that itself routes or picks certificates by SNI works (and
		// its certificate is verified against that name). An IP address is
		// never sent as SNI, so the target host alone would not do.
		serverName := rule.UpstreamSNI
		if serverName == "" {
			serverName = info.SNI
		}
		if serverName == "" {
			serverName = d.Host
		}
		tlsUp = tls.Client(up, &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: !rule.UpstreamTLSVerify,
			NextProtos:         offer,
			MinVersion:         tls.VersionTLS12,
			ClientSessionCache: rt.upstreamSessions[rule],
		})
		tlsUp.SetDeadline(time.Now().Add(cfg.ConnectTimeout))
		if err := tlsUp.Handshake(); err != nil {
			return nil, nil, "", fmt.Errorf("upstream TLS handshake failed: %v", err)
		}
		tlsUp.SetDeadline(time.Time{})
		how = "tls terminated, tls sni=" + serverName
		if rule.Proxy {
			how += fmt.Sprintf(" with PROXY v%d", rule.ProxyVersion)
		}
		if !rule.UpstreamTLSVerify {
			how += " (certificate not verified)"
		}
		if p := tlsUp.ConnectionState().NegotiatedProtocol; p != "" {
			protos = []string{p}
			how += " alpn=" + p
		}
	} else if info.offers("http/1.1") {
		protos = []string{"http/1.1"} // a plaintext upstream can't do h2 over TLS ALPN
	}
	var served *tls.Certificate
	clientConfig := &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			c, err := s.certs.CertificateForClient(rule, info, addrOf(client.LocalAddr()))
			served = c
			return c, err
		},
		NextProtos: protos,
		MinVersion: tls.VersionTLS12,
	}
	clientConfig.SetSessionTicketKeys(s.sessionTicketKeys())
	tlsClient := tls.Server(&prefixConn{Conn: client, prefix: hello}, clientConfig)
	tlsClient.SetDeadline(time.Now().Add(cfg.HandshakeTimeout))
	if err := tlsClient.Handshake(); err != nil {
		return nil, nil, "", fmt.Errorf("client TLS handshake failed: %v", err)
	}
	tlsClient.SetDeadline(time.Time{})
	st := tlsClient.ConnectionState()
	alpn := st.NegotiatedProtocol
	if alpn == "" {
		alpn = "none"
	}
	how = fmt.Sprintf("TLS terminated here: client %s alpn=%s, %s; upstream %s",
		tls.VersionName(st.Version), alpn, describeCert(rule, served, st.DidResume), strings.TrimPrefix(how, "tls terminated, "))
	return tlsClient, tlsUp, how, nil
}

// describeCert says which certificate a terminated connection was given.
func describeCert(rule *Rule, c *tls.Certificate, resumed bool) string {
	if resumed && c == nil {
		// A resumed session skips the certificate: the client verified it when
		// the session was first set up.
		return "cert=" + rule.Cert + " (TLS session resumed, no certificate sent)"
	}
	if c == nil || c.Leaf == nil {
		return "cert=?"
	}
	source := "cert=" + rule.Cert
	if len(c.Leaf.Subject.Organization) > 0 && c.Leaf.Subject.Organization[0] == "tlsproxy placeholder" {
		return source + " (self-signed PLACEHOLDER, no real certificate yet)"
	}
	return fmt.Sprintf("%s (issuer %q, expires %s)", source, c.Leaf.Issuer.CommonName, c.Leaf.NotAfter.UTC().Format("2006-01-02"))
}

func (c *ConnState) touch() { c.lastActivityUnixNano.Store(time.Now().UnixNano()) }

type direction int

const (
	cToS direction = iota
	sToC
)

var (
	dirName        = [2]string{"client->upstream", "upstream->client"}
	closedLabel    = [2]string{"client closed", "upstream closed"}
	stoppedReading = [2]string{"upstream stopped reading", "client stopped reading"}
)

// relay is the pair of copy directions of one connection.
type relay struct {
	c              *ConnState
	stats          *Stats
	cfg            *Config
	pool           *BufferPool
	client, server duplex
	// Speed limits per direction: [0] this connection's and [1] the rule's
	// shared one, [2] and [3] the same from the listener. nil = none.
	limits    [2][4]*limiter
	done      chan struct{} // closed by closeAll: wakes a pump waiting on a limit
	closeOnce sync.Once
}

func (r *relay) dirState(d direction) *atomic.Int32 {
	if d == cToS {
		return &r.c.CToS
	}
	return &r.c.SToC
}

// mover moves one direction a chunk at a time: read waits for data and takes
// up to chunk() bytes of it, write delivers all n of them and says how many
// it did deliver (fewer only with an error).
type mover interface {
	read() (int, error)
	write(n int) (int, error)
	chunk() int
	close()
}

// errNoSplice: the kernel refused to splice this socket before anything was
// moved, so the direction can still switch to a buffer.
var errNoSplice = errors.New("splice not supported")

// bufferMover copies through a pooled buffer held for the life of the
// connection. Stale bytes in a reused buffer are never looked at: only
// buf[:n] from the latest read is used.
type bufferMover struct {
	from, to duplex
	pool     *BufferPool
	buf      []byte
}

func (m *bufferMover) read() (int, error) { return m.from.Read(m.buf) }

func (m *bufferMover) write(n int) (int, error) { return m.to.Write(m.buf[:n]) }
func (m *bufferMover) chunk() int               { return len(m.buf) }
func (m *bufferMover) close()                   { m.pool.Put(m.buf) }

// pump copies one direction: spliced in the kernel when both sides are plain
// TCP on Linux (passthrough), through a buffer otherwise (terminated TLS).
func (r *relay) pump(d direction) {
	from, to := r.client, r.server
	bytes, total, perHost, perRule, perListener := &r.c.BytesUp, &r.stats.BytesUp, &r.c.host.BytesUp, &r.c.rule.BytesUp, &r.c.lstats.BytesUp
	if d == sToC {
		from, to = r.server, r.client
		bytes, total, perHost, perRule, perListener = &r.c.BytesDown, &r.stats.BytesDown, &r.c.host.BytesDown, &r.c.rule.BytesDown, &r.c.lstats.BytesDown
	}
	// A limited direction moves smaller chunks, about 20 a second, so the
	// rate stays smooth.
	chunk := r.cfg.BufferSize
	limits := r.limits[d][:]
	for _, l := range limits {
		if l != nil {
			chunk = min(chunk, limitedChunk(l.rate, r.cfg.BufferSize))
		}
	}
	var m mover
	if r.cfg.Splice {
		m = newSpliceMover(from, to, chunk)
	}
	if m == nil {
		m = &bufferMover{from: from, to: to, pool: r.pool, buf: r.pool.Get()[:chunk]}
	} else {
		r.c.spliced.Add(1)
	}
	if r.c.relaying.Add(1) == 2 { // both directions chose: the flow log can say how
		r.stats.flows.emit("route", r.c)
	}
	defer func() { m.close() }()
	idle := r.cfg.IdleTimeout
	for {
		if idle > 0 {
			// Idle means no traffic in EITHER direction, so the deadline
			// follows the shared last-activity time.
			from.SetReadDeadline(time.Unix(0, r.c.lastActivityUnixNano.Load()).Add(idle))
		}
		n, err := m.read()
		if err == errNoSplice {
			m.close()
			m = &bufferMover{from: from, to: to, pool: r.pool, buf: r.pool.Get()[:chunk]}
			r.c.spliced.Add(-1)
			continue
		}
		if n > 0 {
			if limits[0] != nil || limits[1] != nil || limits[2] != nil || limits[3] != nil {
				if !waitAll(int64(n), r.done, limits...) {
					return // closeAll woke us; the reason is already recorded
				}
				r.c.touch() // waiting for the limit is not idleness
			}
			if idle > 0 {
				to.SetWriteDeadline(time.Now().Add(idle))
			}
			written, werr := m.write(n)
			if written > 0 {
				bytes.Add(int64(written))
				perHost.Add(int64(written))
				perRule.Add(int64(written))
				perListener.Add(int64(written))
				total.Add(int64(written))
				r.c.touch()
			}
			if werr == nil && written != n {
				werr = io.ErrShortWrite
			}
			if werr != nil {
				if isTimeout(werr) {
					// Blocked for a whole idle period: nothing is moving.
					r.closeAll(fmt.Sprintf("%s error: write timed out", dirName[d]))
				} else {
					// The receiver won't take more. Only this direction is
					// over; data may still flow the other way.
					r.endDirection(d, stoppedReading[d], false)
				}
				return
			}
			// Optional coalescing: after a short read the socket is drained;
			// pausing lets more data queue, so the next read is bigger (fewer
			// syscalls and goroutine wake-ups per byte).
			if n < m.chunk() && r.cfg.ShortReadDelay > 0 && err == nil {
				time.Sleep(r.cfg.ShortReadDelay)
			}
		}
		if err == nil {
			continue
		}
		switch {
		case err == io.EOF:
			r.endDirection(d, closedLabel[d], true)
		case r.isClosed():
			// Woken up by closeAll; the reason is already recorded.
		case isTimeout(err):
			last := time.Unix(0, r.c.lastActivityUnixNano.Load())
			if time.Since(last) < idle {
				continue // the other direction was active; keep waiting
			}
			r.closeAll(r.idleReason())
		case errors.Is(err, io.ErrUnexpectedEOF):
			// Only a terminated (TLS) side reports this: the TCP connection
			// ended in the middle of a TLS record. (One that ends between
			// records without a close_notify, as many HTTP peers do, reads as a
			// normal close.) The data is incomplete, so it is not forwarded as
			// a clean end of stream; say what happened rather than "error".
			r.closeAll(fmt.Sprintf("%s in the middle of a TLS record, without close_notify; closed by proxy", closedLabel[d]))
		default:
			r.closeAll(fmt.Sprintf("%s error: %v", dirName[d], err))
		}
		return
	}
}

func (r *relay) isClosed() bool {
	r.c.mu.Lock()
	defer r.c.mu.Unlock()
	return r.c.closed
}

func (r *relay) reason() string {
	r.c.mu.Lock()
	defer r.c.mu.Unlock()
	return r.c.closeReason
}

func (r *relay) idleReason() string {
	r.c.mu.Lock()
	first := r.c.firstClosed
	r.c.mu.Unlock()
	if first != "" {
		first += ", then "
	}
	return fmt.Sprintf("%sidle timeout (%s); closed by proxy", first, humanDuration(r.cfg.IdleTimeout))
}

// endDirection: direction d is over, because its source reached EOF (forward
// the half-close) or its destination refused data. The other direction may
// continue until it ends or half_close_timeout fires.
func (r *relay) endDirection(d direction, how string, forward bool) {
	if forward {
		to := r.server
		if d == sToC {
			to = r.client
		}
		// Sent once this end is on record (every return below unlocks first):
		// the peer may answer the FIN with its own close at once, and that
		// must not be logged as the first.
		defer to.CloseWrite()
	}
	r.dirState(d).Store(dirHalfClosed)
	c := r.c
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	if r.dirState(1-d).Load() == dirHalfClosed {
		// The other side had already ended: a normal, mutual close.
		c.closed = true
		if c.firstClosed != "" {
			c.closeReason = fmt.Sprintf("%s, then %s %s later", c.firstClosed, how, humanDuration(time.Since(c.firstClosedAt)))
		} else {
			c.closeReason = how + ", both directions ended"
		}
		c.mu.Unlock()
		return
	}
	c.firstClosed, c.firstClosedAt = how, time.Now()
	if limit := r.cfg.HalfCloseTimeout; limit > 0 {
		c.halfCloseTimer = time.AfterFunc(limit, func() {
			r.closeAll(fmt.Sprintf("%s, other direction still open after half_close_timeout (%s); closed by proxy", how, humanDuration(limit)))
		})
	}
	c.mu.Unlock()
}

// closeAll ends the connection (the first reason wins) and unblocks both pumps.
func (r *relay) closeAll(reason string) {
	c := r.c
	c.mu.Lock()
	if !c.closed {
		c.closed, c.closeReason = true, reason
	}
	c.mu.Unlock()
	r.closeOnce.Do(func() { close(r.done) })
	r.client.Close()
	r.server.Close()
}

func (r *relay) finish() {
	r.c.mu.Lock()
	if r.c.halfCloseTimer != nil {
		r.c.halfCloseTimer.Stop()
	}
	r.c.closed = true
	r.c.mu.Unlock()
}

// rereadConsole reads console.toml again if it changed since it was last
// read. A version that parses becomes the one every load merges in; one
// that does not is reported, and the last good one stays.
func (s *Server) rereadConsole() (changed bool, problems []string) {
	if s.consolePath == "" {
		return false, nil
	}
	text, err := os.ReadFile(s.consolePath)
	if err != nil {
		return false, []string{fmt.Sprintf("cannot read %s: %v; the console keeps its settings", s.consolePath, err)}
	}
	hash := fileHash(text)
	if hash == s.consoleHash {
		return false, nil
	}
	s.consoleHash = hash
	con, err := ParseConsole(string(text))
	if err != nil {
		errorf("config reload: %s is invalid, the console keeps its settings: %v", s.consolePath, err)
		return false, []string{fmt.Sprintf("%s is invalid, so the console keeps its settings: %v", s.consolePath, err)}
	}
	s.consoleCfg.Store(con)
	logf("config reload: %s changed", s.consolePath)
	return true, nil
}

// securePassword replaces a plaintext password in console.toml with its
// hash, so the secret sits on disk only until the proxy first sees it.
// Only that one line is rewritten. It reports whether the file changed.
func (s *Server) securePassword(c *ConsoleConfig) bool {
	if c == nil || c.Password == "" || s.consolePath == "" {
		return false
	}
	path := s.consolePath
	hash, err := hashPassword(c.Password)
	if err != nil {
		errorf("console: cannot hash the password: %v", err)
		return false
	}
	c.PasswordHash, c.Password = hash, ""
	configFileMu.Lock() // no other writer of ours may slip between this read and write
	defer configFileMu.Unlock()
	data, err := os.ReadFile(path)
	if err != nil {
		errorf("console: cannot read %s to remove the plaintext password: %v", path, err)
		return false
	}
	if c.sourceHash == "" || fileHash(data) != c.sourceHash {
		logf("console: %s changed since it was parsed; leaving the newer file intact for the next reload", path)
		return false
	}
	lines := strings.Split(string(data), "\n")
	done := false
	for i, line := range lines {
		key, _, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "password":
			lines[i] = "password_hash = \"" + hash + "\""
			done = true
		case "password_hash":
			lines[i] = "" // superseded by the new password
		}
	}
	if !done {
		return false
	}
	rewritten := []byte(strings.Join(lines, "\n"))
	if err := writeFileAtomic(path, rewritten); err != nil {
		errorf("console: cannot rewrite %s, THE PLAINTEXT PASSWORD IS STILL IN THE FILE: %v", path, err)
		return false
	}
	c.sourceHash = fileHash(rewritten)
	if s.consoleHash != "" {
		s.consoleHash = c.sourceHash // our own rewrite: nothing for the next reload to pick up
	}
	logf("console: replaced the plaintext password in %s with its hash", path)
	return true
}
