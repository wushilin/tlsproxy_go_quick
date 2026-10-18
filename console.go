package main

// Web console on its own port: dashboard, connections, certificates, log and
// a config editor. Plain HTTP by design (see ConsoleConfig). Defences:
//
//   - a password is always required; sessions are random, in memory, 12 h
//   - login attempts are rate limited globally (through the proxy every
//     client looks like 127.0.0.1, so per-address limits would be useless)
//   - every POST needs the session's CSRF token and a JSON content type
//   - the Host header must be an IP literal, "localhost" or a configured
//     name, which defeats DNS rebinding
//   - the [console] section itself cannot be seen or changed from here

import (
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed console
var consoleFiles embed.FS

const (
	sessionCookie   = "tlsproxy_session"
	consolePath     = "/tlsproxy_quick" // every page and API lives under it; / redirects there
	sessionLifetime = 12 * time.Hour
	maxBackups      = 10
	consoleHidden   = "# [console] is managed outside this editor (hidden here, kept as it is on save)"
)

// configFileMu serialises every read-check-write of a config file by this
// process (console saves and the password-hash rewrite), so two writers can
// never interleave and a save always acts on the state it just checked.
var configFileMu sync.Mutex

// fileVersion identifies what is on disk: modification time plus content hash.
// A save must present the version the editor loaded; if anything else wrote
// the file in between (another editor, another console session, the proxy
// itself), the versions differ and that save is refused.
type fileVersion struct{ Mtime, Hash string }

func versionOf(path string, data []byte) (fileVersion, error) {
	st, err := os.Stat(path)
	if err != nil {
		return fileVersion{}, err
	}
	return fileVersion{strconv.FormatInt(st.ModTime().UnixNano(), 10), fileHash(data)}, nil
}

type session struct {
	csrf    string
	expires time.Time
}

type Console struct {
	srv  *Server
	addr string // actual listen address

	mu           sync.Mutex
	verifyMu     sync.Mutex // serialises deliberately expensive password checks
	hash         string
	secureCookie bool
	hostnames    map[string]bool
	sessions     map[string]*session
	failures     int
	lockedUntil  time.Time

	rules *ruleState // live state pushed to the rules page
}

func (s *Server) startConsole(cfg *ConsoleConfig) error {
	ln, err := net.Listen(listenNetwork(cfg.Listen), net.JoinHostPort(cfg.Listen, strconv.Itoa(cfg.Port)))
	if err != nil {
		return err
	}
	c := &Console{srv: s, addr: ln.Addr().String(), sessions: map[string]*session{}, rules: newRuleState()}
	c.update(cfg)
	s.console = c
	mux := http.NewServeMux()
	static, _ := fs.Sub(consoleFiles, "console")
	files := http.FileServerFS(static)
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache") // a new build is picked up at once
		files.ServeHTTP(w, r)
	})
	mux.HandleFunc("POST /api/login", c.login)
	mux.HandleFunc("POST /api/logout", c.authed(c.logout))
	mux.HandleFunc("GET /api/session", c.authed(c.sessionInfo))
	mux.HandleFunc("GET /api/status", c.authed(c.status))
	mux.HandleFunc("GET /api/connections", c.authed(c.connections))
	mux.HandleFunc("GET /api/certs", c.authed(c.certs))
	mux.HandleFunc("POST /api/certs/retry", c.authed(c.certRetry))
	mux.HandleFunc("POST /api/certs/remove", c.authed(c.certRemove))
	mux.HandleFunc("GET /api/cas", c.authed(c.caList))
	mux.HandleFunc("GET /api/cas/cert", c.authed(c.caCert))
	mux.HandleFunc("POST /api/cas/generate", c.authed(c.caGenerate))
	mux.HandleFunc("POST /api/cas/import", c.authed(c.caImport))
	mux.HandleFunc("POST /api/cas/delete", c.authed(c.caDelete))
	mux.HandleFunc("GET /api/cas/config", c.authed(c.caConfigGet))
	mux.HandleFunc("POST /api/cas/config", c.authed(c.caConfigSave))
	mux.HandleFunc("GET /api/log", c.authed(c.recentLog))
	mux.HandleFunc("GET /api/config", c.authed(c.configGet))
	mux.HandleFunc("POST /api/config/validate", c.authed(c.configValidate))
	mux.HandleFunc("POST /api/config/test", c.authed(c.configTest))
	mux.HandleFunc("POST /api/config/save", c.authed(c.configSave))
	mux.HandleFunc("GET /api/config/backups", c.authed(c.backups))
	mux.HandleFunc("GET /api/config/backup", c.authed(c.backupGet))
	mux.HandleFunc("GET /api/state", c.authed(c.stateGet))
	mux.HandleFunc("GET /api/ws", c.authed(c.stateSocket))
	mux.HandleFunc("GET /api/flows", c.authed(c.flowSocket))
	mux.HandleFunc("POST /api/rules/validate", c.authed(c.ruleValidate))
	mux.HandleFunc("POST /api/rules/save", c.authed(c.ruleSave))
	mux.HandleFunc("POST /api/rules/delete", c.authed(c.ruleDelete))
	mux.HandleFunc("POST /api/rules/stop", c.authed(c.ruleStopStart(true)))
	mux.HandleFunc("POST /api/rules/start", c.authed(c.ruleStopStart(false)))
	mux.HandleFunc("POST /api/connections/stop", c.authed(c.connStop))
	mux.HandleFunc("POST /api/listeners/validate", c.authed(c.listenerValidate))
	mux.HandleFunc("POST /api/listeners/save", c.authed(c.listenerSave))
	mux.HandleFunc("POST /api/listeners/delete", c.authed(c.listenerDelete))
	mux.HandleFunc("POST /api/listeners/stop", c.authed(c.listenerStopStart(true)))
	mux.HandleFunc("POST /api/listeners/start", c.authed(c.listenerStopStart(false)))
	go c.broadcast()
	root := http.NewServeMux()
	root.Handle(consolePath+"/", http.StripPrefix(consolePath, mux))
	root.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, consolePath+"/", http.StatusFound)
	})
	server := &http.Server{Handler: c.guard(root), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 2 * time.Minute}
	logf("console: listening on http://%s%s/ (plain HTTP; password required)", c.addr, consolePath)
	go func() {
		if err := server.Serve(ln); err != nil {
			errorf("console: stopped: %v", err)
		}
	}()
	return nil
}

// update applies the reloadable console settings. listen and port are not:
// they need a restart.
func (c *Console) update(cfg *ConsoleConfig) {
	if cfg == nil {
		return
	}
	// A password change must also wait for any login using the old hash.
	c.verifyMu.Lock()
	defer c.verifyMu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if cfg.PasswordHash != "" && cfg.PasswordHash != c.hash {
		if c.hash != "" {
			logf("console: password changed; all sessions signed out")
		}
		c.hash = cfg.PasswordHash
		c.sessions = map[string]*session{}
	}
	if c.secureCookie != cfg.SecureCookie {
		// Existing browsers must sign in again to receive the new cookie policy.
		c.sessions = map[string]*session{}
	}
	c.secureCookie = cfg.SecureCookie
	c.hostnames = map[string]bool{"localhost": true}
	for _, h := range cfg.Hostnames {
		c.hostnames[h] = true
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, status int, format string, a ...any) {
	writeJSON(w, status, map[string]any{"ok": false, "error": fmt.Sprintf(format, a...)})
}

// guard runs for every request: Host check, security headers, POST hygiene.
func (c *Console) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.ToLower(strings.Trim(host, "[]"))
		c.mu.Lock()
		known := c.hostnames[host]
		c.mu.Unlock()
		if !known && net.ParseIP(host) == nil {
			// A DNS name we were not told about: possibly DNS rebinding.
			http.Error(w, "unknown host name; add it to [console] hostnames", http.StatusForbidden)
			return
		}
		h := w.Header()
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		// connect-src names the WebSocket explicitly: older browsers don't
		// count ws:// to the same host as 'self'. Only the checked name and a
		// numeric port go into the header.
		connect, origin := "'self'", ""
		if name, port, err := net.SplitHostPort(r.Host); err != nil {
			origin = r.Host // no port: the name alone, as checked above
		} else if port != "" && strings.Trim(port, "0123456789") == "" {
			if strings.Contains(name, ":") {
				name = "[" + name + "]"
			}
			origin = name + ":" + port
		}
		if origin != "" {
			connect += " ws://" + origin + " wss://" + origin
		}
		h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src "+
			connect+"; frame-ancestors 'none'")
		if r.Method == http.MethodPost {
			if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
				fail(w, http.StatusUnsupportedMediaType, "POST bodies must be application/json")
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
		}
		next.ServeHTTP(w, r)
	})
}

func (c *Console) session(r *http.Request) *session {
	ck, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.sessions[ck.Value]
	if s == nil || time.Now().After(s.expires) {
		delete(c.sessions, ck.Value)
		return nil
	}
	return s
}

// authed requires a session, and for POSTs its CSRF token.
func (c *Console) authed(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s := c.session(r)
		if s == nil {
			fail(w, http.StatusUnauthorized, "not signed in")
			return
		}
		if r.Method == http.MethodPost && r.Header.Get("X-CSRF-Token") != s.csrf {
			fail(w, http.StatusForbidden, "missing or wrong CSRF token")
			return
		}
		h(w, r)
	}
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (c *Console) login(w http.ResponseWriter, r *http.Request) {
	var req struct{ Password string }
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	// Queue verifications as well as recording failures.  Checking the
	// lockout before PBKDF2 alone lets a parallel burst all start hashing.
	c.verifyMu.Lock()
	defer c.verifyMu.Unlock()
	c.mu.Lock()
	if wait := time.Until(c.lockedUntil); wait > 0 {
		c.mu.Unlock()
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		fail(w, http.StatusTooManyRequests, "too many failed sign-ins; try again in %s", humanDuration(wait.Round(time.Second)))
		return
	}
	hash := c.hash
	c.mu.Unlock()

	ok := checkPassword(hash, req.Password) // slow on purpose; outside the lock

	c.mu.Lock()
	defer c.mu.Unlock()
	if !ok {
		c.failures++
		if c.failures >= 5 { // 30 s, doubling, capped at 15 min
			lock := 30 * time.Second << min(c.failures-5, 5)
			c.lockedUntil = time.Now().Add(min(lock, 15*time.Minute))
		}
		errorf("console: failed sign-in from %s (%d in a row)", r.RemoteAddr, c.failures)
		fail(w, http.StatusUnauthorized, "wrong password")
		return
	}
	c.failures = 0
	for id, s := range c.sessions { // drop expired ones while we are here
		if time.Now().After(s.expires) {
			delete(c.sessions, id)
		}
	}
	id, err := randomToken()
	if err != nil {
		errorf("console: cannot generate session token: %v", err)
		fail(w, http.StatusInternalServerError, "cannot create session")
		return
	}
	csrf, err := randomToken()
	if err != nil {
		errorf("console: cannot generate CSRF token: %v", err)
		fail(w, http.StatusInternalServerError, "cannot create session")
		return
	}
	s := &session{csrf: csrf, expires: time.Now().Add(sessionLifetime)}
	c.sessions[id] = s
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: id, Path: consolePath, HttpOnly: true, Secure: c.secureCookie || r.TLS != nil,
		SameSite: http.SameSiteStrictMode, MaxAge: int(sessionLifetime.Seconds())})
	logf("console: sign-in from %s", r.RemoteAddr)
	writeJSON(w, 200, map[string]any{"ok": true, "csrf": s.csrf})
}

func (c *Console) logout(w http.ResponseWriter, r *http.Request) {
	if ck, err := r.Cookie(sessionCookie); err == nil {
		c.mu.Lock()
		delete(c.sessions, ck.Value)
		c.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: consolePath, MaxAge: -1})
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (c *Console) sessionInfo(w http.ResponseWriter, r *http.Request) {
	s := c.session(r)
	if s == nil { // password reload or logout may revoke it after authed checked
		fail(w, http.StatusUnauthorized, "not signed in")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "csrf": s.csrf})
}

// ---------------------------------------------------------------- read-only pages

func (c *Console) status(w http.ResponseWriter, r *http.Request) {
	st, rt := c.srv.stats, c.srv.runtime.Load()
	up, down, conns := st.Rates()
	type hostRow struct {
		Host                                          string
		Active, Total, Terminated, BytesUp, BytesDown int64
	}
	hosts := make([]hostRow, 0, st.hosts.Len())
	st.hosts.Range(func(name string, h *HostStats) bool {
		hosts = append(hosts, hostRow{name, h.Active.Load(), h.Total.Load(), h.Terminated.Load(), h.BytesUp.Load(), h.BytesDown.Load()})
		return true
	})
	sort.Slice(hosts, func(i, j int) bool {
		if hosts[i].Active != hosts[j].Active {
			return hosts[i].Active > hosts[j].Active
		}
		if hosts[i].Total != hosts[j].Total {
			return hosts[i].Total > hosts[j].Total
		}
		return hosts[i].Host < hosts[j].Host
	})
	allow, deny := rt.cache.Len()
	writeJSON(w, 200, map[string]any{
		"uptimeSeconds": int(time.Since(st.Started).Seconds()),
		"listen":        listenAddrs(rt.cfg),
		"rules":         len(rt.cfg.Rules),
		"active":        st.Active.Load(), "accepted": st.Accepted.Load(), "completed": st.Completed.Load(),
		"denied": st.Denied.Load(), "failed": st.Failed.Load(), "rejected": st.Rejected.Load(),
		"maxConnections": rt.cfg.MaxConnections,
		"bytesUp":        st.BytesUp.Load(), "bytesDown": st.BytesDown.Load(),
		"rateUp": up, "rateDown": down, "rateConnections": conns, "rateWindowSeconds": rateWindow,
		"goroutines": st.OpenGoroutines(), "goroutinesRuntime": runtime.NumGoroutine(),
		"cacheAllow": allow, "cacheDeny": deny, "cacheHits": st.CacheHits.Load(), "cacheMisses": st.CacheMisses.Load(),
		"poolIdle": rt.pool.Idle(), "bufferSize": rt.cfg.BufferSize,
		"hosts": hosts,
	})
}

func (c *Console) connections(w http.ResponseWriter, r *http.Request) {
	st := c.srv.stats
	conns, _ := st.connList(0)
	sort.Slice(conns, func(i, j int) bool { return conns[i].ID > conns[j].ID })
	state := func(v int32) string {
		if v == dirOpen {
			return "open"
		}
		return "half-closed"
	}
	rows := make([]map[string]any, 0, len(conns))
	for _, cs := range conns {
		cs.mu.Lock()
		sni, dst, peer, mode := cs.SNI, cs.Dst, cs.Peer, cs.Mode
		cs.mu.Unlock()
		if len(rows) == 1000 {
			break
		}
		rows = append(rows, map[string]any{"id": cs.ID, "src": cs.Src, "sni": sni, "dst": dst, "peer": peer,
			"terminated": mode != "", "mode": mode,
			"bytesUp": cs.BytesUp.Load(), "bytesDown": cs.BytesDown.Load(),
			"ageSeconds":  int(time.Since(cs.Start).Seconds()),
			"idleSeconds": int(time.Since(time.Unix(0, cs.lastActivityUnixNano.Load())).Seconds()),
			"cToS":        state(cs.CToS.Load()), "sToC": state(cs.SToC.Load())})
	}
	writeJSON(w, 200, map[string]any{"total": len(conns), "connections": rows})
}

func (c *Console) certs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"certs": c.srv.certs.Snapshot(), "certPath": c.srv.runtime.Load().cfg.CertPath,
		"acmeDirectory": c.srv.runtime.Load().cfg.AcmeDirectory})
}

func (c *Console) certRetry(w http.ResponseWriter, r *http.Request) {
	var req struct{ Domain string }
	if json.NewDecoder(r.Body).Decode(&req) != nil || !c.srv.certs.RetryNow(req.Domain) {
		fail(w, http.StatusBadRequest, "not an automatic certificate name")
		return
	}
	logf("console: retry requested for certificate %s", req.Domain)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (c *Console) certRemove(w http.ResponseWriter, r *http.Request) {
	var req struct{ Source, CA, Name string }
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	if err := c.srv.certs.RemoveCertificate(req.Source, req.CA, req.Name); err != nil {
		fail(w, http.StatusBadRequest, "%s", err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (c *Console) recentLog(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.URL.Query().Get("n"))
	if n <= 0 || n > recentLogSize {
		n = 500
	}
	writeJSON(w, 200, map[string]any{"lines": RecentLog(n, r.URL.Query().Get("filter"))})
}

// ---------------------------------------------------------------- config editor

var (
	consoleHeader = regexp.MustCompile(`(?i)^\s*\[\s*console\s*\]`)
	anyHeader     = regexp.MustCompile(`^\s*\[`)
	lineRef       = regexp.MustCompile(`\bline (\d+)`)
)

// hideConsole replaces the [console] section with a one-line placeholder. It
// returns the editor text, the hidden lines, and the placeholder's index
// (-1 if there is no such section).
func hideConsole(text string) (visible string, block []string, at int) {
	lines := strings.Split(text, "\n")
	start, end := -1, len(lines)
	for i, l := range lines {
		if start < 0 && consoleHeader.MatchString(l) {
			start = i
		} else if start >= 0 && anyHeader.MatchString(l) {
			end = i
			break
		}
	}
	if start < 0 {
		return text, nil, -1
	}
	for end > start+1 && strings.TrimSpace(lines[end-1]) == "" {
		end-- // blank lines before the next section stay visible
	}
	block = append(block, lines[start:end]...)
	out := append(append(append([]string{}, lines[:start]...), consoleHidden), lines[end:]...)
	return strings.Join(out, "\n"), block, start
}

// showConsole puts the hidden section back. It returns the full text and a
// function translating line numbers of the full text to editor lines.
func showConsole(visible string, block []string) (string, func(int) int, error) {
	lines := strings.Split(visible, "\n")
	at := -1
	for i, l := range lines {
		if consoleHeader.MatchString(l) {
			return "", nil, fmt.Errorf("line %d: the [console] section cannot be edited here; change it in the file itself", i+1)
		}
		if at < 0 && strings.TrimSpace(l) == consoleHidden {
			at = i
		}
	}
	if len(block) == 0 {
		return visible, func(n int) int { return n }, nil
	}
	if at < 0 { // placeholder deleted: keep the section anyway, at the end
		full := strings.TrimRight(visible, "\n") + "\n\n" + strings.Join(block, "\n") + "\n"
		return full, func(n int) int { return min(n, len(lines)) }, nil
	}
	out := append(append(append([]string{}, lines[:at]...), block...), lines[at+1:]...)
	toEditor := func(n int) int {
		switch {
		case n <= at:
			return n
		case n <= at+len(block):
			return at + 1
		default:
			return n - len(block) + 1
		}
	}
	return strings.Join(out, "\n"), toEditor, nil
}

func fileHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// check validates editor text as the proxy would load it. Errors refer to
// editor line numbers.
// toEditor maps a line of the full file to the line the editor shows; the
// warnings in cfg already use editor lines.
func (c *Console) check(visible string, block []string) (full string, cfg *Config, toEditor func(int) int, err error) {
	full, toEditor, err = showConsole(visible, block)
	if err != nil {
		return "", nil, nil, err
	}
	translate := func(err error) error {
		return fmt.Errorf("%s", lineRef.ReplaceAllStringFunc(err.Error(), func(m string) string {
			n, _ := strconv.Atoi(m[5:])
			return "line " + strconv.Itoa(toEditor(n))
		}))
	}
	if cfg, err = ParseConfig(full); err != nil {
		return "", nil, nil, translate(err)
	}
	if err = c.srv.certs.Check(cfg); err != nil {
		return "", nil, nil, translate(err)
	}
	for i, w := range cfg.Warnings {
		cfg.Warnings[i] = translate(errors.New(w)).Error()
	}
	return full, cfg, toEditor, nil
}

// readConfig reads the file and its version. Callers that go on to write
// must hold configFileMu across both.
func (c *Console) readConfig() (data []byte, visible string, block []string, ver fileVersion, err error) {
	if c.srv.configPath == "" {
		return nil, "", nil, ver, fmt.Errorf("this proxy was not started from a config file")
	}
	if data, err = os.ReadFile(c.srv.configPath); err != nil {
		return nil, "", nil, ver, err
	}
	if ver, err = versionOf(c.srv.configPath, data); err != nil {
		return nil, "", nil, ver, err
	}
	visible, block, _ = hideConsole(string(data))
	return data, visible, block, ver, nil
}

func (c *Console) configGet(w http.ResponseWriter, r *http.Request) {
	configFileMu.Lock()
	_, visible, _, ver, err := c.readConfig()
	configFileMu.Unlock()
	if err != nil {
		fail(w, 500, "%v", err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "text": visible, "hash": ver.Hash, "mtime": ver.Mtime, "path": c.srv.configPath})
}

type configRequest struct {
	Text      string
	BaseHash  string
	BaseMtime string
	SNIs      []string
}

func (c *Console) configValidate(w http.ResponseWriter, r *http.Request) {
	var req configRequest
	_, _, block, _, err := c.readConfig()
	if err == nil && json.NewDecoder(r.Body).Decode(&req) != nil {
		err = fmt.Errorf("bad request")
	}
	var cfg *Config
	if err == nil {
		var toEditor func(int) int
		var full string
		full, cfg, toEditor, err = c.check(req.Text, block)
		if err == nil {
			writeJSON(w, 200, map[string]any{"ok": true, "warnings": cfg.Warnings, "problems": problemsOf(cfg.Warnings), "summary": cfg.Describe(),
				"autoDomains": cfg.AutoDomains(), "tree": configTree(cfg, full, toEditor)})
			return
		}
	}
	writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error(), "line": lineOf(err.Error())})
}

// configTest routes SNIs through the text in the editor, saved or not.
func (c *Console) configTest(w http.ResponseWriter, r *http.Request) {
	var req configRequest
	_, _, block, _, err := c.readConfig()
	if err == nil && json.NewDecoder(r.Body).Decode(&req) != nil {
		err = fmt.Errorf("bad request")
	}
	var cfg *Config
	if err == nil {
		_, cfg, _, err = c.check(req.Text, block)
	}
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	var results []map[string]any
	for _, sni := range req.SNIs {
		name := strings.ToLower(strings.TrimSpace(sni))
		if name == "<none>" || name == "none" {
			name = ""
		}
		for i := range cfg.Listeners {
			d := cfg.ForListener(&cfg.Listeners[i]).Route(name)
			label := sni
			if len(cfg.Listeners) > 1 {
				label = cfg.Listeners[i].Name + ": " + sni // each listener has its own rules
			}
			row := map[string]any{"sni": label, "listener": cfg.Listeners[i].Name, "allow": d.Allow, "ruleLine": d.RuleLine, "error": d.Err}
			if d.Rule != nil { // which rule won, and why it outranks the others
				row["kind"], row["pattern"] = d.Rule.Kind.String(), d.Rule.Source
			}
			if d.Allow {
				row["target"] = net.JoinHostPort(d.Host, strconv.Itoa(d.Port))
				row["terminated"] = d.Rule.Terminates()
			}
			results = append(results, row)
		}
	}
	// Rule lines refer to the full file; say so rather than mistranslate silently.
	writeJSON(w, 200, map[string]any{"ok": true, "results": results})
}

func (c *Console) configSave(w http.ResponseWriter, r *http.Request) {
	var req configRequest
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		fail(w, 400, "bad request")
		return
	}
	// Everything from "what is on disk now?" to the rename happens under the
	// lock, so the check and the write cannot be separated by another writer
	// in this process.
	configFileMu.Lock()
	defer configFileMu.Unlock()
	onDisk, _, block, ver, err := c.readConfig()
	if err != nil {
		fail(w, 500, "%v", err)
		return
	}
	if req.BaseMtime != ver.Mtime || req.BaseHash != ver.Hash {
		errorf("console: save from %s refused: %s was modified after the editor loaded it", r.RemoteAddr, c.srv.configPath)
		fail(w, http.StatusConflict, "not saved: the config file was changed by someone else after you opened it. Copy your text if you need it, then use Discard & reload from disk")
		return
	}
	full, cfg, _, err := c.check(req.Text, block)
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	c.commit(w, r, onDisk, full, cfg, "config saved")
}

func backupFiles(path string) []string {
	matches, _ := filepath.Glob(path + ".*.bak")
	sort.Strings(matches) // timestamped names: oldest first
	return matches
}

func pruneBackups(path string) {
	files := backupFiles(path)
	for len(files) > maxBackups {
		os.Remove(files[0])
		files = files[1:]
	}
}

func (c *Console) backups(w http.ResponseWriter, r *http.Request) {
	var names []string
	for _, f := range backupFiles(c.srv.configPath) {
		names = append([]string{filepath.Base(f)}, names...) // newest first
	}
	writeJSON(w, 200, map[string]any{"backups": names})
}

// backupGet returns a backup's text for the editor (nothing is restored until
// the user saves it).
func (c *Console) backupGet(w http.ResponseWriter, r *http.Request) {
	want := r.URL.Query().Get("name")
	for _, f := range backupFiles(c.srv.configPath) { // only names we listed: no path tricks
		if filepath.Base(f) == want {
			data, err := os.ReadFile(f)
			if err != nil {
				fail(w, 500, "%v", err)
				return
			}
			visible, _, _ := hideConsole(string(data))
			writeJSON(w, 200, map[string]any{"ok": true, "text": visible})
			return
		}
	}
	fail(w, 404, "no such backup")
}
