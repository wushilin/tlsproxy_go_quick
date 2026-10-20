package main

// Rules with service_rule keys (see serve_config.go) serve HTTP themselves:
// the TLS connection the proxy terminates goes straight to a net/http
// server in this process, with no target and no extra hop. The client's
// address is the connection's own (or what a trusted PROXY header in front
// of the listener said), so X-Forwarded-For needs no second PROXY header.
//
// Each request is routed again with the configuration running at that
// moment: a reload applies to the next request even on an open connection.
// A request whose Host belongs to another rule (a browser reusing an HTTP/2
// connection for a second name its certificate covers) is answered 421, so
// the client opens a connection of its own for it.

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
)

// maxServeHeader caps a request's line and headers.
const maxServeHeader = 64 << 10

// webServer is a net/http server fed with connections the proxy has
// terminated: one per listener with serving rules, per configuration.
type webServer struct {
	srv   *http.Server
	conns chan net.Conn
	done  chan struct{}
	start sync.Once
	stop  sync.Once
}

func (w *webServer) Accept() (net.Conn, error) {
	select {
	case c := <-w.conns:
		return c, nil
	case <-w.done:
		return nil, net.ErrClosed
	}
}

// Close stops taking connections; those it has keep being served.
func (w *webServer) Close() error {
	w.stop.Do(func() { close(w.done) })
	return nil
}

func (w *webServer) Addr() net.Addr { return &net.TCPAddr{} }

// push hands a connection over, false once the server is closed.
func (w *webServer) push(s *Server, c net.Conn) bool {
	w.start.Do(func() {
		s.stats.GoroutinesStarted.Add(1)
		go func() {
			defer s.stats.GoroutinesFinished.Add(1)
			w.srv.Serve(w)
		}()
	})
	select {
	case w.conns <- c:
		return true
	case <-w.done:
		return false
	}
}

// serveState is what one configuration serves with: per listener its web
// server, per static route its folder, per proxy route its reverse proxy.
type serveState struct {
	web        map[string]*webServer
	roots      map[*ServiceRoute]*os.Root
	rootErrs   map[*ServiceRoute]error
	files      map[*ServiceRoute]http.Handler
	proxies    map[*ServiceRoute]*httputil.ReverseProxy
	transports []*http.Transport
}

// newServeState opens what cfg's serving rules need. A base_dir that cannot
// be opened is logged; its route answers 503 until a reload fixes it.
func (s *Server) newServeState(cfg *Config) *serveState {
	st := &serveState{web: map[string]*webServer{}, roots: map[*ServiceRoute]*os.Root{}, rootErrs: map[*ServiceRoute]error{},
		files: map[*ServiceRoute]http.Handler{}, proxies: map[*ServiceRoute]*httputil.ReverseProxy{}}
	transports := map[bool]*http.Transport{} // by tls_verify
	transport := func(verify bool) *http.Transport {
		if t := transports[verify]; t != nil {
			return t
		}
		t := &http.Transport{
			Proxy: nil, // never an HTTP_PROXY from the environment
			DialContext: func(_ context.Context, _, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				p, _ := strconv.Atoi(port)
				return s.dialer.Dial(host, p, cfg.ConnectTimeout)
			},
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: !verify, MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2:   true,
			MaxIdleConnsPerHost: 32,
			IdleConnTimeout:     90 * time.Second,
		}
		transports[verify] = t
		st.transports = append(st.transports, t)
		return t
	}
	for i := range cfg.Rules {
		r := &cfg.Rules[i]
		if !r.Serves() {
			continue
		}
		if st.web[r.Listener] == nil {
			lc := cfg.ForListener(cfg.Listener(r.Listener))
			st.web[r.Listener] = &webServer{conns: make(chan net.Conn), done: make(chan struct{}), srv: &http.Server{
				Handler:           webHandler{s},
				ReadHeaderTimeout: lc.HandshakeTimeout,
				IdleTimeout:       lc.IdleTimeout,
				MaxHeaderBytes:    maxServeHeader,
				ConnContext:       s.servedContext,
				ErrorLog:          log.New(webErrorLog{}, "", 0),
			}}
		}
		for _, route := range r.Routes {
			switch route.Type {
			case routeStatic:
				root, err := os.OpenRoot(route.BaseDir)
				if err != nil {
					st.rootErrs[route] = err
					errorf("[[host]] at line %d: %s: base_dir: %v; its requests are answered 503 until it is fixed and the configuration reloaded", r.Line, route.Key, err)
					continue
				}
				st.roots[route] = root
				st.files[route] = http.FileServer(rootDir{root})
			case routeProxy:
				st.proxies[route] = reverseProxy(r, route, transport(route.TLSVerify))
			}
		}
	}
	return st
}

// retire lets go of a state the configuration no longer uses: its web
// servers take no new connections at once, its folders and idle upstream
// connections are closed once requests still using them have had a minute.
func (st *serveState) retire() {
	if st == nil {
		return
	}
	for _, w := range st.web {
		w.Close()
	}
	time.AfterFunc(time.Minute, func() {
		for _, root := range st.roots {
			root.Close()
		}
		for _, t := range st.transports {
			t.CloseIdleConnections()
		}
	})
}

// webErrorLog sends net/http's own messages to the error log.
type webErrorLog struct{}

func (webErrorLog) Write(p []byte) (int, error) {
	errorf("serve: %s", strings.TrimSpace(string(p)))
	return len(p), nil
}

// servedConn is the client's side of a served connection, under TLS: it
// counts the bytes, applies the speed limits, and says when it is closed.
type servedConn struct {
	net.Conn
	c        *ConnState
	stats    *Stats
	limits   [2][4]*limiter
	done     chan struct{}
	once     sync.Once
	mu       sync.Mutex
	reason   string // why the proxy closed it; "" = the client or the web server did
	ruleKey  string // the rule that routed it
	listener string
	sni      string
}

func (sc *servedConn) Read(b []byte) (int, error) {
	n, err := sc.Conn.Read(b)
	if n > 0 {
		if !waitAll(int64(n), sc.done, sc.limits[cToS][:]...) {
			return 0, net.ErrClosed
		}
		sc.count(cToS, n)
	}
	return n, err
}

func (sc *servedConn) Write(b []byte) (int, error) {
	if !waitAll(int64(len(b)), sc.done, sc.limits[sToC][:]...) {
		return 0, net.ErrClosed
	}
	n, err := sc.Conn.Write(b)
	if n > 0 {
		sc.count(sToC, n)
	}
	return n, err
}

func (sc *servedConn) count(d direction, n int) {
	c := sc.c
	if d == cToS {
		c.BytesUp.Add(int64(n))
		c.host.BytesUp.Add(int64(n))
		c.rule.BytesUp.Add(int64(n))
		c.lstats.BytesUp.Add(int64(n))
		sc.stats.BytesUp.Add(int64(n))
	} else {
		c.BytesDown.Add(int64(n))
		c.host.BytesDown.Add(int64(n))
		c.rule.BytesDown.Add(int64(n))
		c.lstats.BytesDown.Add(int64(n))
		sc.stats.BytesDown.Add(int64(n))
	}
	c.touch()
}

func (sc *servedConn) Close() error {
	sc.once.Do(func() { close(sc.done) })
	return sc.Conn.Close()
}

// kill closes it from the proxy's side (the console, a stopped rule).
func (sc *servedConn) kill(reason string) {
	sc.mu.Lock()
	if sc.reason == "" {
		sc.reason = reason
	}
	sc.mu.Unlock()
	sc.Close()
}

type servedKey struct{}

// servedContext gives each request the connection it came on.
func (s *Server) servedContext(ctx context.Context, c net.Conn) context.Context {
	if tc, ok := c.(*tls.Conn); ok {
		if sc, ok := s.served.Load(tc); ok {
			return context.WithValue(ctx, servedKey{}, sc)
		}
	}
	return ctx
}

// serveHere completes TLS with the client and hands the connection to the
// web server of its listener, then waits until it is closed. helloBuf goes
// back to the pool once the handshake has read the ClientHello.
func (s *Server) serveHere(c *ConnState, client net.Conn, hello, helloBuf []byte, info helloInfo, d Decision, cfg *Config, rt *Runtime) {
	rule := d.Rule
	var protos []string
	for _, p := range []string{"h2", "http/1.1"} {
		if info.offers(p) {
			protos = append(protos, p)
		}
	}
	sc := &servedConn{Conn: &prefixConn{Conn: client, prefix: hello}, c: c, stats: s.stats, done: make(chan struct{}),
		ruleKey: rule.Key(), listener: cfg.listener.Name, sni: info.SNI}
	l := cfg.listener
	for dir := range sc.limits {
		sc.limits[dir][0] = newLimiter(rule.MaxSingleConnectionSpeed, cfg.BufferSize)
		if agg := rt.limits[rule]; agg != nil {
			sc.limits[dir][1] = agg.dir[dir]
		}
		sc.limits[dir][2] = newLimiter(l.MaxSingleConnectionSpeed, cfg.BufferSize)
		if agg := rt.listenerLimits[l.Name]; agg != nil {
			sc.limits[dir][3] = agg.dir[dir]
		}
	}
	var served *tls.Certificate
	tc := tls.Server(sc, &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert, err := s.certs.CertificateForClient(rule, info, addrOf(client.LocalAddr()))
			served = cert
			return cert, err
		},
		NextProtos: protos,
		MinVersion: tls.VersionTLS12,
	})
	tc.SetDeadline(time.Now().Add(cfg.HandshakeTimeout))
	err := tc.Handshake()
	rt.pool.Put(helloBuf) // the handshake has read the ClientHello
	src, sniDisp := c.Src, c.SNI
	if sniDisp == "" {
		sniDisp = "<none>"
	}
	if err != nil {
		s.stats.Failed.Add(1)
		c.setEnd(flowFailed, fmt.Sprintf("client TLS handshake failed: %v", err))
		logf("[#%d] closed src=%s sni=%s: client TLS handshake failed: %v", c.ID, src, sniDisp, err)
		return
	}
	tc.SetDeadline(time.Time{})
	st := tc.ConnectionState()
	alpn := st.NegotiatedProtocol
	if alpn == "" {
		alpn = "none"
	}
	how := fmt.Sprintf("TLS terminated here: client %s alpn=%s, %s; served here", tls.VersionName(st.Version), alpn, describeCert(rule, served, st.DidResume))
	c.host.Terminated.Add(1)
	c.mu.Lock()
	c.Mode = how
	c.how.TLS, c.how.ClientTLS, c.how.ALPN, c.how.Resumed, c.how.Upstream = "terminated", tls.VersionName(st.Version), st.NegotiatedProtocol, st.DidResume, "served"
	c.mu.Unlock()
	c.touch()
	logf("[#%d] connected %s -> served here (%s)", c.ID, src, withLimits(how, rule))
	s.stats.flows.emit("route", c)

	s.served.Store(tc, sc)
	defer s.served.Delete(tc)
	c.setKill(sc.kill)
	if s.stoppedRules()[sc.ruleKey] {
		sc.kill("rule stopped from the console; closed by proxy")
	}
	for !s.webFor(rt, sc.listener).push(s, tc) {
		rt = s.runtime.Load() // a reload retired that server an instant ago: the current one serves it
		if s.webFor(rt, sc.listener) == nil {
			sc.kill("its rule no longer serves after a reload; closed by proxy")
			break
		}
	}
	<-sc.done
	sc.mu.Lock()
	reason := sc.reason
	sc.mu.Unlock()
	if reason == "" {
		reason = "closed (HTTP connection ended)"
	}
	s.stats.Completed.Add(1)
	c.setEnd(flowClosed, reason)
	logf("[#%d] closed src=%s sni=%s dst=served here up=%s down=%s duration=%s reason=%s",
		c.ID, src, sniDisp, humanBytes(c.BytesUp.Load()), humanBytes(c.BytesDown.Load()), humanDuration(time.Since(c.Start)), reason)
}

// webFor is the web server of a listener in rt, nil if it serves nothing.
func (s *Server) webFor(rt *Runtime, listener string) *webServer {
	if rt.serve == nil {
		return nil
	}
	return rt.serve.web[listener]
}

// webHandler serves the requests of every served connection.
type webHandler struct{ s *Server }

func (h webHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sc, _ := r.Context().Value(servedKey{}).(*servedConn)
	if sc == nil {
		http.Error(w, "not a served connection", http.StatusInternalServerError)
		return
	}
	sw := &statusWriter{ResponseWriter: w}
	start := time.Now()
	note := h.s.serveRequest(sw, r, sc)
	if sw.status == 0 {
		sw.status = http.StatusOK
	}
	logf("[#%d] %s %s %s%s -> %d%s, %d bytes, %s", sc.c.ID, r.Proto, r.Method, r.Host, r.URL.RequestURI(), sw.status, note, sw.bytes, humanDuration(time.Since(start)))
}

// requestName is the name a request's Host routes as: "" for an IP
// address, as for a client that sent no SNI.
func requestName(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(strings.Trim(host, "[]"))
	if _, err := netip.ParseAddr(host); err == nil {
		return ""
	}
	return host
}

// serveRequest answers one request with the rule that routes its Host
// now. It returns what to add to the log line.
func (s *Server) serveRequest(w http.ResponseWriter, r *http.Request, sc *servedConn) string {
	rt := s.runtime.Load()
	cfg := rt.byListener[sc.listener]
	var d Decision
	if cfg != nil {
		d = cfg.RouteExcept(requestName(r.Host), s.stoppedRules())
	}
	if d.Rule == nil || d.Rule.Key() != sc.ruleKey || !d.Rule.Serves() {
		w.Header().Set("Connection", "close")
		http.Error(w, "misdirected request: this connection is not for "+r.Host, http.StatusMisdirectedRequest)
		return " (Host is not this connection's rule)"
	}
	rule := d.Rule
	route := rule.RouteFor(r.URL.Path)
	// /docs for the prefix /docs/: send the client to the folder, as nginx
	// does, unless a prefix at least as long as /docs takes it as it is.
	for _, x := range rule.Routes {
		if folder := strings.TrimSuffix(x.Prefix, "/"); len(x.Prefix) > 1 && folder != x.Prefix && r.URL.Path == folder && (route == nil || len(route.Prefix) < len(folder)) {
			http.Redirect(w, r, (&url.URL{Path: x.Prefix, RawQuery: r.URL.RawQuery}).String(), http.StatusMovedPermanently)
			return " (to the folder " + x.Prefix + ")"
		}
	}
	if route == nil {
		http.NotFound(w, r)
		return " (no service_rule prefix matches)"
	}
	note := fmt.Sprintf(" via %s", route.Key)
	if route.auth != nil {
		user, password, ok := r.BasicAuth()
		if !ok || !s.auth.check(route.auth, user, password) {
			w.Header().Set("WWW-Authenticate", `Basic realm="`+strings.ReplaceAll(rule.Source, `"`, "")+`", charset="UTF-8"`)
			http.Error(w, "authentication required", http.StatusUnauthorized)
			if !ok {
				return note + " (basic_auth: no credentials)"
			}
			return note + fmt.Sprintf(" (basic_auth: wrong password, or no user %q)", user)
		}
		r.Header.Del("Authorization") // the password stays here: it is not the backend's
		note += " user=" + user
	}
	switch route.Type {
	case routeStatic:
		files := rt.serve.files[route]
		if files == nil {
			http.Error(w, "base_dir is not available", http.StatusServiceUnavailable)
			return note + fmt.Sprintf(" (base_dir: %v)", rt.serve.rootErrs[route])
		}
		serveFile(w, r, route, files)
	case routeProxy:
		rt.serve.proxies[route].ServeHTTP(w, r)
		note += " -> " + route.Target.Scheme + "://" + route.TargetAddr()
	}
	return note
}

// serveFile answers from a route's base_dir, the prefix standing for it:
// GET and HEAD only, no directory listings, no hidden files (a path part
// starting with "."), except .well-known at its top.
func serveFile(w http.ResponseWriter, r *http.Request, route *ServiceRoute, files http.Handler) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rest := "/" + strings.TrimPrefix(r.URL.Path, route.Prefix)
	for i, part := range strings.Split(path.Clean(rest), "/") {
		if strings.HasPrefix(part, ".") && !(i == 1 && part == ".well-known") {
			http.NotFound(w, r)
			return
		}
	}
	// The file server sees the path below the prefix, and redirects (a folder
	// without its /, index.html to its folder) relative to it, so the
	// redirects still point under the prefix.
	r2 := new(http.Request)
	*r2 = *r
	r2.URL = new(url.URL)
	*r2.URL = *r.URL
	r2.URL.Path, r2.URL.RawPath = rest, ""
	files.ServeHTTP(w, r2)
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

// Unwrap lets http.ResponseController reach Flush and Hijack (WebSocket).
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// rootDir serves a base_dir through os.Root, so nothing outside it is
// reached (a symlink that leads out is refused). It hides directories that
// have no index.html, so the file server never lists one.
type rootDir struct{ root *os.Root }

func (d rootDir) Open(name string) (http.File, error) {
	name = strings.TrimPrefix(path.Clean("/"+name), "/")
	if name == "" {
		name = "."
	}
	f, err := d.root.Open(name)
	if err != nil {
		if !errors.Is(err, fs.ErrPermission) {
			err = fs.ErrNotExist // a symlink out of base_dir, too: as if it weren't there
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

// reverseProxy is the proxy for one reverse_proxy route. The client's
// address comes from the connection; the X-Forwarded-* headers and Forwarded
// it sent itself are replaced or removed, never passed on.
func reverseProxy(rule *Rule, route *ServiceRoute, transport *http.Transport) *httputil.ReverseProxy {
	target := route.TargetAddr()
	return &httputil.ReverseProxy{
		Transport:     transport,
		FlushInterval: -1, // stream: server-sent events and long polls arrive as they are written
		Rewrite: func(pr *httputil.ProxyRequest) {
			out := pr.Out
			out.URL.Scheme, out.URL.Host = route.Target.Scheme, target
			if route.StripPrefix {
				escaped := pr.In.URL.EscapedPath()
				rest, ok := strings.CutPrefix(escaped, route.Prefix)
				if !ok {
					rest = strings.TrimPrefix(pr.In.URL.Path, route.Prefix)
				}
				if !strings.HasPrefix(rest, "/") {
					rest = "/" + rest
				}
				if p, err := url.PathUnescape(rest); err == nil {
					out.URL.Path, out.URL.RawPath = p, rest
				}
			}
			out.Host = pr.In.Host
			if route.ForceHost != "" {
				out.Host = route.ForceHost
			}
			client, _, err := net.SplitHostPort(pr.In.RemoteAddr)
			if err != nil {
				client = pr.In.RemoteAddr
			}
			out.Header.Del("Forwarded") // RFC 7239: the client's own would be believed upstream
			out.Header.Set("X-Forwarded-For", client)
			out.Header.Set("X-Real-IP", client)
			out.Header.Set("X-Forwarded-Proto", "https")
			if pr.In.Host != "" {
				out.Header.Set("X-Forwarded-Host", pr.In.Host)
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			errorf("[[host]] at line %d: %s: %s %s: upstream %s: %v", rule.Line, route.Key, r.Method, r.URL.RequestURI(), route.Target, err)
			w.WriteHeader(http.StatusBadGateway)
		},
		ErrorLog: log.New(webErrorLog{}, "", 0),
	}
}

// authChecker checks [[basic_auth]] passwords. A browser sends the password
// with every request and a hash takes a good part of a second, so a
// password that matched is remembered for a few minutes; and only a few
// hashes are computed at once, so a flood of wrong ones cannot use up the
// memory argon2id takes for each.
type authChecker struct {
	mu   sync.Mutex
	good map[[32]byte]time.Time // sha256(hash, user, password) -> until when
	sem  chan struct{}
}

const (
	authRemember    = 5 * time.Minute
	authRememberMax = 4096
)

func newAuthChecker() *authChecker {
	return &authChecker{good: map[[32]byte]time.Time{}, sem: make(chan struct{}, 2)}
}

func (a *authChecker) check(ba *BasicAuth, user, password string) bool {
	cred, ok := ba.Users[user]
	if !ok {
		return false
	}
	if cred.hash == "" {
		return subtle.ConstantTimeCompare([]byte(cred.plain), []byte(password)) == 1
	}
	key := sha256.Sum256([]byte(cred.hash + "\x00" + user + "\x00" + password))
	now := time.Now()
	a.mu.Lock()
	until, hit := a.good[key]
	a.mu.Unlock()
	if hit && now.Before(until) {
		return true
	}
	a.sem <- struct{}{}
	good := checkPassword(cred.hash, password)
	<-a.sem
	if good {
		a.mu.Lock()
		if len(a.good) >= authRememberMax {
			clear(a.good)
		}
		a.good[key] = now.Add(authRemember)
		a.mu.Unlock()
	}
	return good
}
