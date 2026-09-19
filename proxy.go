package main

// Connection handling: accept, read ClientHello, route, relay, log.
//
// One goroutine per connection does the handshake and the client->server
// copy; a second does server->client. Goroutines are multiplexed over
// kqueue/epoll by the Go runtime, so this is plain blocking-style code.

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
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
	cfg   *Config
	pool  *BufferPool
	cache *RouteCache
}

func newRuntime(cfg *Config, prev *Runtime) *Runtime {
	rt := &Runtime{cfg: cfg, cache: NewRouteCache(cfg.AllowCacheSize, cfg.DenyCacheSize)}
	if prev != nil && prev.cfg.BufferSize == cfg.BufferSize && prev.cfg.BufferPoolMaxIdle == cfg.BufferPoolMaxIdle {
		rt.pool = prev.pool
	} else {
		// A replaced pool is simply dropped: its parked buffers are garbage
		// collected, and buffers still in use are freed when returned.
		rt.pool = NewBufferPool(cfg.BufferSize, cfg.BufferPoolMaxIdle)
	}
	return rt
}

type Server struct {
	runtime atomic.Pointer[Runtime]
	stats   *Stats
	certs   *CertManager
	nextID  atomic.Uint64

	configPath string        // "" when the config did not come from a file
	reloadNow  chan struct{} // poked by the console after a save
	console    *Console
}

// NewServer fails if a rule's cert = <dir> certificate cannot be loaded.
func NewServer(cfg *Config) (*Server, error) {
	s := &Server{stats: NewStats(), certs: NewCertManager(), reloadNow: make(chan struct{}, 1)}
	if err := s.certs.Apply(cfg); err != nil {
		return nil, err
	}
	s.runtime.Store(newRuntime(cfg, nil))
	return s, nil
}

// Run binds to the configured address and serves forever.
func Run(cfg *Config, path string) error {
	srv, err := NewServer(cfg) // before binding: a bad certificate is a startup error
	if err != nil {
		return err
	}
	l, err := net.Listen(listenNetwork(cfg.Bind), net.JoinHostPort(cfg.Bind, strconv.Itoa(cfg.Port)))
	if err != nil {
		return err
	}
	// From here on the streams go to their log files, if configured.
	if err := ConfigureLogging(cfg.Log); err != nil {
		return err
	}
	return srv.Serve(l, path)
}

// Serve accepts connections on l. If path is non-empty the config file is
// watched and reloaded when it changes.
func (s *Server) Serve(l net.Listener, path string) error {
	rt := s.runtime.Load()
	logf("listening on %s with %s", l.Addr(), rt.cfg.Describe())
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
	s.configPath = path
	if path != "" {
		s.securePassword(path, rt.cfg) // before anything reads the file again
		go s.watchConfig(path)
	}
	go s.reportStats()
	go func() {
		for range time.Tick(time.Second) {
			s.stats.sample()
		}
	}()
	if rt.cfg.Console != nil {
		if err := s.startConsole(rt.cfg.Console); err != nil {
			return fmt.Errorf("[console]: %w", err)
		}
	}
	watchSignals(s)
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
		id := s.nextID.Add(1)
		active := s.stats.Active.Add(1)
		if int(active) > rt.cfg.MaxConnections {
			logf("[#%d] rejected %s: too many connections (%d > %d)", id, sock.RemoteAddr(), active, rt.cfg.MaxConnections)
			s.stats.Active.Add(-1)
			s.stats.Rejected.Add(1)
			sock.Close()
			continue
		}
		s.stats.Accepted.Add(1)
		s.stats.GoroutinesStarted.Add(1)
		go func() {
			defer s.stats.GoroutinesFinished.Add(1)
			defer s.stats.Active.Add(-1)
			s.handle(id, sock.(*net.TCPConn), int(active), rt)
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
	last, _ := os.ReadFile(path)
	haveLast := last != nil
	for {
		// Wake up every reload_interval, or at once when the console saved.
		// With reload_interval = 0 only the console triggers reloads.
		var tick <-chan time.Time
		if interval := s.runtime.Load().cfg.ReloadInterval; interval > 0 {
			tick = time.After(interval)
		}
		select {
		case <-tick:
		case <-s.reloadNow:
		}
		text, err := os.ReadFile(path)
		if err != nil {
			if haveLast {
				errorf("config reload: cannot read %s: %v; keeping current config", path, err)
				haveLast = false
			}
			continue
		}
		if haveLast && string(text) == string(last) {
			continue
		}
		last, haveLast = text, true
		cfg, err := ParseConfig(string(text))
		if err != nil {
			errorf("config reload: %s is invalid, keeping current config: %v", path, err)
			continue
		}
		old := s.runtime.Load()
		if cfg.Bind != old.cfg.Bind || cfg.Port != old.cfg.Port {
			errorf("config reload: bind/port change to %s:%d needs a restart; still listening on %s:%d",
				cfg.Bind, cfg.Port, old.cfg.Bind, old.cfg.Port)
		}
		if err := s.certs.Apply(cfg); err != nil {
			errorf("config reload: %s rejected, keeping current config: %v", path, err)
			continue
		}
		if s.securePassword(path, cfg) {
			last, _ = os.ReadFile(path) // our own rewrite is not a change to reload
		}
		if s.console != nil {
			s.console.update(cfg.Console)
		}
		for _, w := range cfg.Warnings {
			errorf("config: %s", w)
		}
		if err := ConfigureLogging(cfg.Log); err != nil {
			errorf("config reload: %v; logging is unchanged", err)
		}
		rt := newRuntime(cfg, old)
		s.runtime.Store(rt)
		extra := ""
		if rt.pool != old.pool {
			extra = ", buffer pool replaced (old buffers freed)"
		}
		logf("config reloaded from %s: %s; route caches cleared%s; existing connections keep their settings",
			path, cfg.Describe(), extra)
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// readHello reads until the ClientHello is complete. It returns the SNI/ALPN
// and every byte read (forwarded verbatim, or replayed into our own TLS
// server when terminating). buf is a pooled buffer; a hello
// that doesn't fit spills into a heap slice, which is returned instead.
func readHello(client net.Conn, buf []byte) (info helloInfo, data []byte, err error) {
	data = buf[:0]
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
			info, perr := parseHello(data)
			if perr == nil {
				return info, data, nil
			}
			if perr != errNeedMore {
				return info, data, perr
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

func (s *Server) handle(id uint64, client *net.TCPConn, active int, rt *Runtime) {
	defer client.Close()
	cfg := rt.cfg
	start := time.Now()
	src := client.RemoteAddr().String()
	logf("[#%d] accepted from %s (active=%d)", id, src, active)

	c := &ConnState{ID: id, Src: src, Start: start}
	c.lastActivityUnixNano.Store(start.UnixNano())
	s.stats.register(c)
	defer s.stats.unregister(c)

	// One overall deadline: a slow trickle can't extend it.
	client.SetReadDeadline(start.Add(cfg.HandshakeTimeout))
	helloBuf := rt.pool.Get()
	info, hello, err := readHello(client, helloBuf)
	sni := info.SNI
	if err != nil {
		rt.pool.Put(helloBuf)
		s.stats.Failed.Add(1)
		if isTimeout(err) {
			logf("[#%d] closed src=%s: no ClientHello within %s", id, src, humanDuration(cfg.HandshakeTimeout))
		} else {
			logf("[#%d] closed src=%s: bad ClientHello: %v after %s", id, src, err, humanDuration(time.Since(start)))
		}
		return
	}
	client.SetReadDeadline(time.Time{})
	sniDisp := sni

	// The CA validating a TLS-ALPN-01 challenge for one of our names. If no
	// challenge is pending, routing continues: a passed-through backend may
	// be running its own ACME client.
	if info.offers(acme.ALPNProto) {
		if answer := s.certs.Challenge(sni); answer != nil {
			tc := tls.Server(&prefixConn{Conn: client, prefix: hello}, &tls.Config{
				Certificates: []tls.Certificate{*answer},
				NextProtos:   []string{acme.ALPNProto},
			})
			tc.SetDeadline(time.Now().Add(cfg.HandshakeTimeout))
			err := tc.Handshake()
			tc.Close()
			rt.pool.Put(helloBuf)
			if err != nil {
				errorf("[#%d] cert: TLS-ALPN-01 challenge for %s from %s failed: %v", id, sni, src, err)
			} else {
				logf("[#%d] cert: answered the TLS-ALPN-01 challenge for %s from %s", id, sni, src)
			}
			return
		}
	}
	if sni == "" {
		sniDisp = "<none>"
	}

	d, hit := rt.cache.GetOrRoute(sni, func() Decision { return cfg.Route(sni) })
	cached := ""
	if hit {
		cached = ", cached"
		s.stats.CacheHits.Add(1)
	} else {
		s.stats.CacheMisses.Add(1)
	}
	if !d.Allow {
		rt.pool.Put(helloBuf)
		s.stats.Denied.Add(1)
		switch {
		case d.Err != "":
			logf("[#%d] route sni=%s src=%s -> DENY (error: %s%s)", id, sniDisp, src, d.Err, cached)
		case d.RuleLine == 0:
			logf("[#%d] route sni=%s src=%s -> DENY (no rule matched%s)", id, sniDisp, src, cached)
		default:
			logf("[#%d] route sni=%s src=%s -> DENY (rule line %d%s)", id, sniDisp, src, d.RuleLine, cached)
		}
		client.Write(alertAccessDenied)
		return
	}
	dest := net.JoinHostPort(d.Host, strconv.Itoa(d.Port))
	destDisp := dest // [2001:db8::1]:443 for an IPv6 target
	logf("[#%d] route sni=%s -> %s (ALLOW, rule line %d%s)", id, sniDisp, destDisp, d.RuleLine, cached)
	c.mu.Lock()
	c.SNI, c.Dst = sni, destDisp
	c.host = s.stats.host(sniDisp)
	c.mu.Unlock()
	c.host.Active.Add(1)
	c.host.Total.Add(1)
	defer c.host.Active.Add(-1)

	t0 := time.Now()
	dialer := net.Dialer{Timeout: cfg.ConnectTimeout}
	up, err := dialer.Dial("tcp", dest)
	if err != nil {
		rt.pool.Put(helloBuf)
		s.stats.Failed.Add(1)
		logf("[#%d] closed src=%s sni=%s dst=%s: connect failed: %v after %s", id, src, sniDisp, destDisp, err, humanDuration(time.Since(t0)))
		return
	}
	defer up.Close()
	peer := up.RemoteAddr().String()
	c.mu.Lock()
	c.Peer = peer
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
		tlsClient, tlsServer, how, err := s.terminate(client, up, hello, info, d, cfg)
		rt.pool.Put(helloBuf)
		if err != nil {
			s.stats.Failed.Add(1)
			logf("[#%d] closed src=%s sni=%s dst=%s (%s): %v", id, src, sniDisp, destDisp, peer, err)
			return
		}
		clientSide, mode = tlsClient, how
		c.host.Terminated.Add(1)
		c.mu.Lock()
		c.Mode = how
		c.mu.Unlock()
		if tlsServer != nil {
			serverSide = tlsServer
		}
		logf("[#%d] connected %s -> %s (%s) in %s (%s)", id, src, destDisp, peer, humanDuration(time.Since(t0)), mode)
	} else {
		if mode != "" {
			logf("[#%d] connected %s -> %s (%s) in %s (%s)", id, src, destDisp, peer, humanDuration(time.Since(t0)), mode)
		} else {
			logf("[#%d] connected %s -> %s (%s) in %s", id, src, destDisp, peer, humanDuration(time.Since(t0)))
		}
		if cfg.IdleTimeout > 0 {
			up.SetWriteDeadline(time.Now().Add(cfg.IdleTimeout))
		}
		_, err = up.Write(hello)
		rt.pool.Put(helloBuf) // back to the pool before the (possibly long) relay
		if err != nil {
			s.stats.Failed.Add(1)
			logf("[#%d] closed src=%s sni=%s dst=%s: upstream write error: %v", id, src, sniDisp, destDisp, err)
			return
		}
		c.BytesUp.Add(int64(len(hello)))
		c.host.BytesUp.Add(int64(len(hello)))
		s.stats.BytesUp.Add(int64(len(hello)))
	}
	c.touch()

	r := &relay{c: c, stats: s.stats, cfg: cfg, pool: rt.pool, client: clientSide, server: serverSide}
	var wg sync.WaitGroup
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
	logf("[#%d] closed src=%s sni=%s dst=%s (%s) up=%s down=%s duration=%s reason=%s",
		id, src, sniDisp, destDisp, peer, humanBytes(c.BytesUp.Load()), humanBytes(c.BytesDown.Load()),
		humanDuration(time.Since(start)), r.reason())
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
func (s *Server) terminate(client, up net.Conn, hello []byte, info helloInfo, d Decision, cfg *Config) (*tls.Conn, *tls.Conn, string, error) {
	rule := d.Rule
	var offer []string // what the client asked for, minus ACME's pseudo protocol
	for _, p := range info.ALPN {
		if p != acme.ALPNProto {
			offer = append(offer, p)
		}
	}
	var tlsUp *tls.Conn
	var protos []string
	how := "tls terminated, plaintext"
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
		})
		tlsUp.SetDeadline(time.Now().Add(cfg.ConnectTimeout))
		if err := tlsUp.Handshake(); err != nil {
			return nil, nil, "", fmt.Errorf("upstream TLS handshake failed: %v", err)
		}
		tlsUp.SetDeadline(time.Time{})
		how = "tls terminated, tls sni=" + serverName
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
	tlsClient := tls.Server(&prefixConn{Conn: client, prefix: hello}, &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			c, err := s.certs.CertificateFor(rule, info.SNI)
			served = c
			return c, err
		},
		NextProtos: protos,
		MinVersion: tls.VersionTLS12,
	})
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
		tls.VersionName(st.Version), alpn, describeCert(rule, served), strings.TrimPrefix(how, "tls terminated, "))
	return tlsClient, tlsUp, how, nil
}

// describeCert says which certificate a terminated connection was given.
func describeCert(rule *Rule, c *tls.Certificate) string {
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
}

func (r *relay) dirState(d direction) *atomic.Int32 {
	if d == cToS {
		return &r.c.CToS
	}
	return &r.c.SToC
}

// pump copies one direction with a pooled buffer held for the life of the
// connection. Stale bytes in a reused buffer are never looked at: only
// buf[:n] from the latest read is used.
func (r *relay) pump(d direction) {
	from, to := r.client, r.server
	bytes, total, perHost := &r.c.BytesUp, &r.stats.BytesUp, &r.c.host.BytesUp
	if d == sToC {
		from, to = r.server, r.client
		bytes, total, perHost = &r.c.BytesDown, &r.stats.BytesDown, &r.c.host.BytesDown
	}
	buf := r.pool.Get()
	defer r.pool.Put(buf)
	idle := r.cfg.IdleTimeout
	for {
		if idle > 0 {
			// Idle means no traffic in EITHER direction, so the deadline
			// follows the shared last-activity time.
			from.SetReadDeadline(time.Unix(0, r.c.lastActivityUnixNano.Load()).Add(idle))
		}
		n, err := from.Read(buf)
		if n > 0 {
			if idle > 0 {
				to.SetWriteDeadline(time.Now().Add(idle))
			}
			if _, werr := to.Write(buf[:n]); werr != nil {
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
			bytes.Add(int64(n))
			perHost.Add(int64(n))
			total.Add(int64(n))
			r.c.touch()
			// Optional coalescing: after a short read the socket is drained;
			// pausing lets more data queue, so the next read is bigger (fewer
			// syscalls and goroutine wake-ups per byte).
			if n < len(buf) && r.cfg.ShortReadDelay > 0 && err == nil {
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
		to.CloseWrite()
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

// securePassword replaces a plaintext [console] password in the config file
// with its hash, so the secret sits on disk only until the proxy first sees
// it. Only that one line is rewritten. It reports whether the file changed.
func (s *Server) securePassword(path string, cfg *Config) bool {
	c := cfg.Console
	if c == nil || c.Password == "" {
		return false
	}
	hash, err := hashPassword(c.Password)
	if err != nil {
		errorf("console: cannot hash the password: %v", err)
		return false
	}
	c.PasswordHash, c.Password = hash, ""
	configFileMu.Lock() // no console save may slip between this read and write
	defer configFileMu.Unlock()
	data, err := os.ReadFile(path)
	if err != nil {
		errorf("console: cannot read %s to remove the plaintext password: %v", path, err)
		return false
	}
	lines := strings.Split(string(data), "\n")
	section, done := "", false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			section = strings.Trim(trimmed, "[] \t")
			continue
		}
		key, _, ok := strings.Cut(trimmed, "=")
		if !ok || section != "console" {
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
	if err := writeFileAtomic(path, []byte(strings.Join(lines, "\n"))); err != nil {
		errorf("console: cannot rewrite %s, THE PLAINTEXT PASSWORD IS STILL IN THE FILE: %v", path, err)
		return false
	}
	logf("console: replaced the plaintext password in %s with its hash", path)
	return true
}
