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
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
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

//go:embed console.html
var consoleHTML []byte

const (
	sessionCookie   = "tlsproxy_session"
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

	mu          sync.Mutex
	hash        string
	hostnames   map[string]bool
	sessions    map[string]*session
	failures    int
	lockedUntil time.Time
}

func (s *Server) startConsole(cfg *ConsoleConfig) error {
	ln, err := net.Listen(listenNetwork(cfg.Listen), net.JoinHostPort(cfg.Listen, strconv.Itoa(cfg.Port)))
	if err != nil {
		return err
	}
	c := &Console{srv: s, addr: ln.Addr().String(), sessions: map[string]*session{}}
	c.update(cfg)
	s.console = c
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(consoleHTML)
	})
	mux.HandleFunc("POST /api/login", c.login)
	mux.HandleFunc("POST /api/logout", c.authed(c.logout))
	mux.HandleFunc("GET /api/session", c.authed(c.sessionInfo))
	mux.HandleFunc("GET /api/status", c.authed(c.status))
	mux.HandleFunc("GET /api/connections", c.authed(c.connections))
	mux.HandleFunc("GET /api/certs", c.authed(c.certs))
	mux.HandleFunc("POST /api/certs/retry", c.authed(c.certRetry))
	mux.HandleFunc("GET /api/log", c.authed(c.recentLog))
	mux.HandleFunc("GET /api/config", c.authed(c.configGet))
	mux.HandleFunc("POST /api/config/validate", c.authed(c.configValidate))
	mux.HandleFunc("POST /api/config/test", c.authed(c.configTest))
	mux.HandleFunc("POST /api/config/save", c.authed(c.configSave))
	mux.HandleFunc("GET /api/config/backups", c.authed(c.backups))
	mux.HandleFunc("GET /api/config/backup", c.authed(c.backupGet))
	server := &http.Server{Handler: c.guard(mux), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
	logf("console: listening on http://%s (plain HTTP; password required)", c.addr)
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
	c.mu.Lock()
	defer c.mu.Unlock()
	if cfg.PasswordHash != "" && cfg.PasswordHash != c.hash {
		if c.hash != "" {
			logf("console: password changed; all sessions signed out")
		}
		c.hash = cfg.PasswordHash
		c.sessions = map[string]*session{}
	}
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
		h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
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

func randomToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (c *Console) login(w http.ResponseWriter, r *http.Request) {
	var req struct{ Password string }
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
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
	id, s := randomToken(), &session{csrf: randomToken(), expires: time.Now().Add(sessionLifetime)}
	c.sessions[id] = s
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: id, Path: "/", HttpOnly: true,
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
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: "/", MaxAge: -1})
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (c *Console) sessionInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"ok": true, "csrf": c.session(r).csrf})
}

// ---------------------------------------------------------------- read-only pages

func (c *Console) status(w http.ResponseWriter, r *http.Request) {
	st, rt := c.srv.stats, c.srv.runtime.Load()
	up, down, conns := st.Rates()
	type hostRow struct {
		Host                                          string
		Active, Total, Terminated, BytesUp, BytesDown int64
	}
	st.mu.Lock()
	hosts := make([]hostRow, 0, len(st.hosts))
	for name, h := range st.hosts {
		hosts = append(hosts, hostRow{name, h.Active.Load(), h.Total.Load(), h.Terminated.Load(), h.BytesUp.Load(), h.BytesDown.Load()})
	}
	st.mu.Unlock()
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
		"listen":        net.JoinHostPort(rt.cfg.Bind, strconv.Itoa(rt.cfg.Port)),
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
	st.mu.Lock()
	conns := make([]*ConnState, 0, len(st.conns))
	for _, cs := range st.conns {
		conns = append(conns, cs)
	}
	st.mu.Unlock()
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
func (c *Console) check(visible string, block []string) (full string, cfg *Config, err error) {
	full, toEditor, err := showConsole(visible, block)
	if err != nil {
		return "", nil, err
	}
	translate := func(err error) error {
		return fmt.Errorf("%s", lineRef.ReplaceAllStringFunc(err.Error(), func(m string) string {
			n, _ := strconv.Atoi(m[5:])
			return "line " + strconv.Itoa(toEditor(n))
		}))
	}
	if cfg, err = ParseConfig(full); err != nil {
		return "", nil, translate(err)
	}
	if err = c.srv.certs.Check(cfg); err != nil {
		return "", nil, translate(err)
	}
	return full, cfg, nil
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
		_, cfg, err = c.check(req.Text, block)
	}
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "warnings": cfg.Warnings, "summary": cfg.Describe(), "autoDomains": cfg.AutoDomains()})
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
		_, cfg, err = c.check(req.Text, block)
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
		d := cfg.Route(name)
		row := map[string]any{"sni": sni, "allow": d.Allow, "ruleLine": d.RuleLine, "error": d.Err}
		if d.Rule != nil { // which rule won, and why it outranks the others
			row["kind"], row["pattern"] = d.Rule.Kind.String(), d.Rule.Source
		}
		if d.Allow {
			row["target"] = net.JoinHostPort(d.Host, strconv.Itoa(d.Port))
			row["terminated"] = d.Rule.Terminates()
		}
		results = append(results, row)
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
	full, cfg, err := c.check(req.Text, block)
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if full == string(onDisk) {
		writeJSON(w, 200, map[string]any{"ok": true, "unchanged": true, "hash": ver.Hash, "mtime": ver.Mtime})
		return
	}
	path := c.srv.configPath
	backup := fmt.Sprintf("%s.%s.bak", path, time.Now().UTC().Format("20060102T150405.000Z"))
	if err := writeFileAtomic(backup, onDisk); err != nil {
		fail(w, 500, "cannot write the backup: %v", err)
		return
	}
	if err := writeFileAtomic(path, []byte(full)); err != nil {
		fail(w, 500, "cannot write %s: %v", path, err)
		return
	}
	pruneBackups(path)
	now, err := versionOf(path, []byte(full))
	if err != nil {
		fail(w, 500, "saved, but cannot stat %s: %v", path, err)
		return
	}
	logf("console: config saved from %s (previous version kept as %s)", r.RemoteAddr, filepath.Base(backup))
	select {
	case c.srv.reloadNow <- struct{}{}: // apply now instead of at the next poll
	default:
	}
	running := c.srv.runtime.Load().cfg
	writeJSON(w, 200, map[string]any{"ok": true, "hash": now.Hash, "mtime": now.Mtime, "backup": filepath.Base(backup),
		"warnings": cfg.Warnings, "restartNeeded": cfg.Bind != running.Bind || cfg.Port != running.Port})
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
