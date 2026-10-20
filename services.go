package main

// Local services at run time (see services_config.go for the sections):
// their ports, opened and closed to match the configuration as it is
// reloaded like the listeners', a PROXY protocol header read before HTTP,
// static files for http_server and proxy_pass_rules for reverse_proxy.
//
// The client's address is what a trusted PROXY header says, else the TCP
// peer's. It is what each request is logged with and what goes upstream as
// X-Forwarded-For. Headers the client sent are never trusted for it: behind
// one of this proxy's terminating rules, the client's own X-Forwarded-For
// arrives byte for byte from a trusted peer, so it is replaced, not kept.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// maxServiceHeader caps a request's line and headers.
const maxServiceHeader = 64 << 10

// liveService is one configured service's port in this process.
type liveService struct {
	name   string
	key    string // what the port was opened with: addresses, type, timeouts
	lns    []*serviceListener
	srv    *http.Server
	state  atomic.Pointer[serviceState] // replaced whole on reload
	active atomic.Int64                 // connections accepted and not closed
	err    string                       // why the last attempt to open failed
}

// serviceState is what one version of the configuration serves with.
type serviceState struct {
	svc       *LocalService
	cfg       *Config
	root      *os.Root     // http_server: doc_root; nil if it could not be opened
	rootErr   error        // why
	files     http.Handler // http_server
	transport *http.Transport
	proxies   map[*ProxyPassRule]*httputil.ReverseProxy
}

// openKey is what a service's port depends on: a change reopens it.
func openKey(svc *LocalService, cfg *Config) string {
	return fmt.Sprintf("%s|%s|%d|%d|%d", strings.Join(svc.Addrs(), ","), svc.Type, cfg.HandshakeTimeout, cfg.IdleTimeout, cfg.ConnectTimeout)
}

// syncServices makes the services' ports match cfg, as syncListeners does
// for the listeners. Connections already accepted carry on with the
// settings they started with. A port or doc_root that cannot be opened is
// logged and returned; the other services carry on.
func (s *Server) syncServices(cfg *Config) (failed []string) {
	s.servicesMu.Lock()
	defer s.servicesMu.Unlock()
	if s.services == nil {
		s.services = map[string]*liveService{}
	}
	want := map[string]bool{}
	for i := range cfg.Services {
		svc := &cfg.Services[i]
		want[svc.Name] = true
		st, err := s.newServiceState(svc, cfg)
		if err != nil {
			msg := fmt.Sprintf("service %s: %v", svc.Name, err)
			errorf("%s", msg)
			failed = append(failed, msg)
		}
		live := s.services[svc.Name]
		if live != nil && live.key == openKey(svc, cfg) && len(live.lns) > 0 {
			live.swap(st)
			continue
		}
		if live != nil {
			live.close()
			logf("service %s: reopening on %s", svc.Name, strings.Join(svc.Addrs(), ", "))
		}
		live = &liveService{name: svc.Name, key: openKey(svc, cfg)}
		live.swap(st)
		s.services[svc.Name] = live
		if err := s.openService(live, svc, cfg); err != nil {
			live.err = err.Error()
			msg := fmt.Sprintf("service %s: cannot listen on %s: %v", svc.Name, strings.Join(svc.Addrs(), ", "), err)
			errorf("%s", msg)
			failed = append(failed, msg)
			continue
		}
		logf("service %s (%s): listening on %s, proxy_version = %s", svc.Name, svc.Type, strings.Join(svc.Addrs(), ", "), svc.ProxyVersion)
	}
	for name, live := range s.services {
		if !want[name] {
			live.close()
			live.swap(nil)
			delete(s.services, name)
			logf("service %s: removed from the configuration; its port is closed (its open connections continue)", name)
		}
	}
	return failed
}

// newServiceState builds what svc serves with under cfg. The error is a
// doc_root that cannot be opened: the service answers 503 until it can.
func (s *Server) newServiceState(svc *LocalService, cfg *Config) (*serviceState, error) {
	st := &serviceState{svc: svc, cfg: cfg}
	switch svc.Type {
	case serviceHTTP:
		if st.root, st.rootErr = os.OpenRoot(svc.DocRoot); st.rootErr != nil {
			return st, fmt.Errorf("doc_root: %v; every request is answered 503 until it is fixed and the configuration reloaded", st.rootErr)
		}
		st.files = http.FileServer(rootDir{st.root})
	case serviceProxy:
		st.transport = &http.Transport{
			Proxy: nil, // never an HTTP_PROXY from the environment
			DialContext: func(_ context.Context, _, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				p, _ := strconv.Atoi(port)
				return s.dialer.Dial(host, p, cfg.ConnectTimeout)
			},
			MaxIdleConnsPerHost: 32,
			IdleConnTimeout:     90 * time.Second,
		}
		st.proxies = map[*ProxyPassRule]*httputil.ReverseProxy{}
		for _, r := range svc.PassRules {
			st.proxies[r] = st.reverseProxy(r)
		}
	}
	return st, nil
}

// swap makes st current and lets go of the previous state once requests
// still using it have had a minute to finish.
func (l *liveService) swap(st *serviceState) {
	old := l.state.Swap(st)
	if old == nil {
		return
	}
	time.AfterFunc(time.Minute, func() {
		if old.root != nil {
			old.root.Close()
		}
		if old.transport != nil {
			old.transport.CloseIdleConnections()
		}
	})
}

func (l *liveService) close() {
	for _, ln := range l.lns {
		ln.Close()
	}
	l.lns = nil
}

// openService binds every address of svc, or none, and serves them.
func (s *Server) openService(live *liveService, svc *LocalService, cfg *Config) error {
	lns, err := bindListener(&Listener{Binds: svc.Binds, Port: svc.Port})
	if err != nil {
		return err
	}
	live.srv = &http.Server{
		Handler:           live,
		ReadHeaderTimeout: cfg.HandshakeTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		MaxHeaderBytes:    maxServiceHeader,
		ErrorLog:          log.New(serviceErrorLog{svc.Name}, "", 0),
	}
	for _, ln := range lns {
		sl := &serviceListener{Listener: ln, live: live, s: s, conns: make(chan net.Conn), done: make(chan struct{})}
		live.lns = append(live.lns, sl)
		s.stats.GoroutinesStarted.Add(2)
		go func() {
			defer s.stats.GoroutinesFinished.Add(1)
			sl.acceptLoop()
		}()
		go func() {
			defer s.stats.GoroutinesFinished.Add(1)
			live.srv.Serve(sl) // returns once sl is closed
		}()
	}
	return nil
}

// serviceErrorLog sends net/http's own messages to the error log.
type serviceErrorLog struct{ name string }

func (e serviceErrorLog) Write(p []byte) (int, error) {
	errorf("service %s: %s", e.name, strings.TrimSpace(string(p)))
	return len(p), nil
}

// serviceListener hands http.Server connections whose PROXY header, if
// any, has been read: each is admitted in its own goroutine, so one slow
// client can't hold up the others.
type serviceListener struct {
	net.Listener
	live  *liveService
	s     *Server
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func (l *serviceListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *serviceListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return l.Listener.Close()
}

func (l *serviceListener) acceptLoop() {
	for {
		sock, err := l.Listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				l.Close()
				return
			}
			errorf("service %s: accept error: %v", l.live.name, err) // typically EMFILE; back off
			time.Sleep(200 * time.Millisecond)
			continue
		}
		st := l.live.state.Load()
		if st == nil {
			sock.Close() // removed an instant ago
			continue
		}
		if n := l.live.active.Add(1); int(n) > st.cfg.MaxConnections {
			l.live.active.Add(-1)
			l.s.rejectLog.logf("service %s: rejected %s: too many connections (%d > %d)", l.live.name, sock.RemoteAddr(), n, st.cfg.MaxConnections)
			sock.Close()
			continue
		}
		go l.admit(sock, st)
	}
}

// admit reads the PROXY header the service expects and queues the
// connection for http.Server.
func (l *serviceListener) admit(sock net.Conn, st *serviceState) {
	c, err := readServiceProxy(sock, st.svc, st.cfg.HandshakeTimeout)
	if err != nil {
		logf("service %s: closed src=%s: %v", l.live.name, sock.RemoteAddr(), err)
		sock.Close()
		l.live.active.Add(-1)
		return
	}
	sc := &serviceConn{proxyConn: c, done: func() { l.live.active.Add(-1) }}
	select {
	case l.conns <- sc:
	case <-l.done:
		sc.Close()
	}
}

// readServiceProxy reads the PROXY protocol header svc expects from a
// connection: with proxy_version = auto, one is used if the peer is trusted
// and sends it; with v1 or v2, the peer must be trusted and send that one.
func readServiceProxy(sock net.Conn, svc *LocalService, timeout time.Duration) (*proxyConn, error) {
	peer := addrOf(sock.RemoteAddr())
	trusted := svc.trusts(peer)
	switch {
	case svc.ProxyVersion == "none", svc.ProxyVersion == "auto" && !trusted:
		return &proxyConn{Conn: sock}, nil
	case !trusted:
		return nil, fmt.Errorf("proxy_version = %s requires a PROXY header, and %s is not in proxy_trust_source", svc.ProxyVersion, peer)
	}
	sock.SetReadDeadline(time.Now().Add(timeout))
	c, err := detectProxyProtocol(sock)
	sock.SetReadDeadline(time.Time{})
	switch {
	case err != nil:
		return nil, fmt.Errorf("bad PROXY protocol header: %v", err)
	case svc.ProxyVersion != "auto" && "v"+strconv.Itoa(c.version) != svc.ProxyVersion:
		if c.version == 0 {
			return nil, fmt.Errorf("proxy_version = %s, and the connection has no PROXY header", svc.ProxyVersion)
		}
		return nil, fmt.Errorf("proxy_version = %s, and the connection has a PROXY v%d header", svc.ProxyVersion, c.version)
	}
	return c, nil
}

// serviceConn counts down the service's connections once, when closed.
type serviceConn struct {
	*proxyConn
	once sync.Once
	done func()
}

func (c *serviceConn) Close() error {
	c.once.Do(c.done)
	return c.proxyConn.Close()
}

// ReadFrom reaches the TCP connection's own, which sends a file with
// sendfile(2). Only reads go through the PROXY header's leftovers, so
// writing straight to the connection is safe.
func (c *serviceConn) ReadFrom(r io.Reader) (int64, error) {
	if rf, ok := c.proxyConn.Conn.(io.ReaderFrom); ok {
		return rf.ReadFrom(r)
	}
	return io.Copy(struct{ io.Writer }{c.proxyConn.Conn}, r)
}

// statusWriter remembers the status of a response, for the log line.
type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}

// ReadFrom keeps the response's own, which the file server's copy uses to
// reach sendfile(2).
func (w *statusWriter) ReadFrom(r io.Reader) (int64, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	var n int64
	var err error
	if rf, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		n, err = rf.ReadFrom(r)
	} else {
		n, err = io.Copy(struct{ io.Writer }{w.ResponseWriter}, r)
	}
	w.bytes += n
	return n, err
}

// Unwrap lets http.ResponseController reach Flush and Hijack (WebSocket).
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (l *liveService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	st := l.state.Load()
	if st == nil {
		http.Error(w, "service removed", http.StatusServiceUnavailable)
		return
	}
	sw := &statusWriter{ResponseWriter: w}
	start := time.Now()
	via := ""
	switch st.svc.Type {
	case serviceHTTP:
		st.serveFile(sw, r)
	case serviceProxy:
		via = st.serveProxy(sw, r)
	}
	if sw.status == 0 {
		sw.status = http.StatusOK
	}
	logf("service %s: %s %s %s -> %d%s, %d bytes, %s", l.name, r.RemoteAddr, r.Method, r.URL.RequestURI(), sw.status, via, sw.bytes, humanDuration(time.Since(start)))
}

// serveFile answers from doc_root: GET and HEAD only, no directory
// listings, no hidden files (a path part starting with "."), except
// /.well-known/.
func (st *serviceState) serveFile(w http.ResponseWriter, r *http.Request) {
	switch {
	case st.files == nil:
		http.Error(w, "doc_root is not available", http.StatusServiceUnavailable)
		return
	case r.Method != http.MethodGet && r.Method != http.MethodHead:
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	for i, part := range strings.Split(path.Clean("/"+r.URL.Path), "/") {
		if strings.HasPrefix(part, ".") && !(i == 1 && part == ".well-known") {
			http.NotFound(w, r)
			return
		}
	}
	st.files.ServeHTTP(w, r)
}

// rootDir serves doc_root through os.Root, so nothing outside it is
// reached (a symlink that leads out is refused). It hands the file server
// the *os.File itself, which http.FileServerFS would wrap: a plain
// *os.File is what lets Linux send it with sendfile(2). It hides
// directories that have no index.html, so the file server never lists one.
type rootDir struct{ root *os.Root }

func (d rootDir) Open(name string) (http.File, error) {
	name = strings.TrimPrefix(path.Clean("/"+name), "/")
	if name == "" {
		name = "."
	}
	f, err := d.root.Open(name)
	if err != nil {
		if !errors.Is(err, fs.ErrPermission) {
			err = fs.ErrNotExist // a symlink out of doc_root, too: as if it weren't there
		}
		return nil, err
	}
	if info, err := f.Stat(); err == nil && info.IsDir() {
		if _, err := d.root.Stat(path.Join(name, "index.html")); err != nil {
			f.Close()
			return nil, fs.ErrNotExist
		}
	}
	return f, nil
}

// serveProxy passes a request to the longest matching proxy_pass_rule. It
// returns what to add to the log line.
func (st *serviceState) serveProxy(w http.ResponseWriter, r *http.Request) string {
	// /asdf for prefix /asdf/: the client is sent to the folder, as nginx does.
	for _, rule := range st.svc.PassRules {
		if len(rule.Prefix) > 1 && strings.HasSuffix(rule.Prefix, "/") && r.URL.Path == strings.TrimSuffix(rule.Prefix, "/") {
			to := (&url.URL{Path: rule.Prefix, RawQuery: r.URL.RawQuery}).String()
			http.Redirect(w, r, to, http.StatusMovedPermanently)
			return ""
		}
	}
	rule := st.svc.Route(r.URL.Path)
	if rule == nil {
		http.NotFound(w, r)
		return " (no proxy_pass_rules prefix matches)"
	}
	st.proxies[rule].ServeHTTP(w, r)
	return fmt.Sprintf(" via %s (prefix %s, line %d)", net.JoinHostPort(rule.TargetHost, strconv.Itoa(rule.TargetPort)), rule.Prefix, rule.Line)
}

// reverseProxy is the proxy for one pass rule.
func (st *serviceState) reverseProxy(rule *ProxyPassRule) *httputil.ReverseProxy {
	target := net.JoinHostPort(rule.TargetHost, strconv.Itoa(rule.TargetPort))
	name := st.svc.Name
	proto := st.svc.ForwardedProto
	return &httputil.ReverseProxy{
		Transport:     st.transport,
		FlushInterval: -1, // stream: server-sent events and long polls arrive as they are written
		// The X-Forwarded-* headers the client sent are already removed.
		Rewrite: func(pr *httputil.ProxyRequest) {
			out := pr.Out
			out.URL.Scheme, out.URL.Host = "http", target
			if rule.StripPrefix {
				escaped := pr.In.URL.EscapedPath()
				rest, ok := strings.CutPrefix(escaped, rule.Prefix)
				if !ok {
					rest = strings.TrimPrefix(pr.In.URL.Path, rule.Prefix)
				}
				if !strings.HasPrefix(rest, "/") {
					rest = "/" + rest
				}
				if p, err := url.PathUnescape(rest); err == nil {
					out.URL.Path, out.URL.RawPath = p, rest
				}
			}
			out.Host = pr.In.Host
			if rule.ForceHost != "" {
				out.Host = rule.ForceHost
			}
			client, _, err := net.SplitHostPort(pr.In.RemoteAddr)
			if err != nil {
				client = pr.In.RemoteAddr
			}
			out.Header.Del("Forwarded") // RFC 7239: the client's own would be believed upstream
			out.Header.Set("X-Forwarded-For", client)
			out.Header.Set("X-Real-IP", client)
			out.Header.Set("X-Forwarded-Proto", proto)
			if pr.In.Host != "" {
				out.Header.Set("X-Forwarded-Host", pr.In.Host)
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			errorf("service %s: %s %s: upstream %s (line %d): %v", name, r.Method, r.URL.RequestURI(), target, rule.Line, err)
			w.WriteHeader(http.StatusBadGateway)
		},
		ErrorLog: log.New(serviceErrorLog{name}, "", 0),
	}
}

// serviceStatus is what the console shows about one service's port.
func (s *Server) serviceStatus(name string) (addrs []string, open bool, err string) {
	s.servicesMu.Lock()
	defer s.servicesMu.Unlock()
	live := s.services[name]
	if live == nil {
		return nil, false, ""
	}
	for _, ln := range live.lns {
		addrs = append(addrs, ln.Addr().String())
	}
	if err = live.err; err == "" {
		if st := live.state.Load(); st != nil && st.rootErr != nil {
			err = "doc_root: " + st.rootErr.Error()
		}
	}
	return addrs, len(live.lns) > 0, err
}
