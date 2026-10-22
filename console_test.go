package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// consoleClient is a browser-like client: cookie jar plus the CSRF token.
type consoleClient struct {
	t    *testing.T
	base string
	http *http.Client
	csrf string
	host string                   // overrides the Host header when set
	dial func() (net.Conn, error) // a TLS connection to the console, for WebSockets
}

// hostPort is the console's address, as in a Host header.
func (c *consoleClient) hostPort() string {
	return strings.TrimPrefix(strings.TrimSuffix(c.base, consolePath), "https://")
}

func (c *consoleClient) do(method, path string, body any, contentType string) (int, map[string]any) {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		rd = bytes.NewReader(data)
	}
	req, _ := http.NewRequest(method, c.base+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", contentType)
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	if c.host != "" {
		// Go keys its cookie jar by the Host header, so carry the session over
		// by hand, as a browser signed in under that name would have it.
		req.Host = c.host
		base, _ := url.Parse(c.base)
		for _, ck := range c.http.Jar.Cookies(base) {
			req.AddCookie(ck)
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (c *consoleClient) get(path string) (int, map[string]any) { return c.do("GET", path, nil, "") }
func (c *consoleClient) post(path string, body any) (int, map[string]any) {
	return c.do("POST", path, body, "application/json")
}

func (c *consoleClient) login(password string) int {
	code, out := c.post("/api/login", map[string]string{"password": password})
	if code == 200 {
		c.csrf = out["csrf"].(string)
	}
	return code
}

// consoleCA signs every test console's certificate.
var consoleCA struct {
	once sync.Once
	ca   *testCA
}

// testConsole is a console on 127.0.0.1:port for console.test, with a
// certificate from the tests' CA.
func testConsole(t *testing.T, port int, password string) *ConsoleConfig {
	t.Helper()
	consoleCA.once.Do(func() { consoleCA.ca = newTestCA(t) })
	hash, err := hashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM := consoleCA.ca.issue(t, 12*time.Hour, "console.test")
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return &ConsoleConfig{Bind: "127.0.0.1", Binds: []string{"127.0.0.1"}, Port: port, Domain: "console.test",
		Cert: "local-ca", PasswordHash: hash, certificate: &cert}
}

// consoleClientFor is a browser on con: it dials con's address for
// console.test and trusts the tests' CA.
func consoleClientFor(t *testing.T, con *ConsoleConfig) (*consoleClient, *http.Transport) {
	addr := con.Addrs()[0]
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		},
		TLSClientConfig:   &tls.Config{RootCAs: consoleCA.ca.pool},
		ForceAttemptHTTP2: true,
	}
	jar, _ := cookiejar.New(nil)
	c := &consoleClient{t: t, base: fmt.Sprintf("https://%s:%d%s", con.Domain, con.Port, consolePath), http: &http.Client{Jar: jar, Timeout: T, Transport: tr}}
	c.dial = func() (net.Conn, error) {
		cfg := tr.TLSClientConfig.Clone()
		cfg.ServerName, cfg.NextProtos = con.Domain, []string{"http/1.1"}
		return tls.DialWithDialer(&net.Dialer{Timeout: T}, "tcp", addr, cfg)
	}
	return c, tr
}

// consolePassword is what password = in the old console lines said.
var consolePassword = regexp.MustCompile(`(?m)^\s*password\s*=\s*"?([^"#\n]*?)"?\s*(#.*)?$`)

// startConsoleProxy writes a config file and starts the proxy with a
// console (see testConsole) whose password is the one in consoleLines
// ("password = ..."). It returns the config file's path.
func startConsoleProxy(t *testing.T, consoleLines, rules string) (*proxyUnderTest, *consoleClient, string) {
	t.Helper()
	return startConsoleProxyGlobal(t, "", consoleLines, rules)
}

// startConsoleProxyGlobal is startConsoleProxy with extra [global] lines.
func startConsoleProxyGlobal(t *testing.T, globalLines, consoleLines, rules string) (*proxyUnderTest, *consoleClient, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	text := fmt.Sprintf("# top comment\n[[listener]]\nname=default\nport=1\n[global]\nstats_interval=0\nreload_interval=0\n%s\n\n%s", globalLines, rules)
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	password := "pw"
	if m := consolePassword.FindStringSubmatch(consoleLines); m != nil {
		password = m[1]
	}
	con := testConsole(t, freePort(t), password)
	p := startProxyConsole(t, text, path, con)
	waitForPort(t, con.Addrs()[0])
	c, _ := consoleClientFor(t, con)
	return p, c, path
}

func TestConsoleAuthAndRequestGuards(t *testing.T) {
	t.Parallel()
	p, c, _ := startConsoleProxy(t, "password = correct horse\nhostnames = console.example.com", "[[host]]\nlistener=default\npattern=.*\naction=deny\n")
	if code, _ := c.get("/api/status"); code != 401 {
		t.Fatalf("unauthenticated API: %d", code)
	}
	if code, _ := c.get("/"); code != 200 {
		t.Fatalf("the page itself must load: %d", code)
	}
	for i := 0; i < 5; i++ {
		if code := c.login("wrong"); code != 401 {
			t.Fatalf("wrong password #%d: %d", i, code)
		}
	}
	if code := c.login("correct horse"); code != 429 { // locked out, even with the right password
		t.Fatalf("after 5 failures: %d", code)
	}
	con := p.srv.console
	con.mu.Lock()
	con.lockedUntil = time.Time{}
	con.mu.Unlock()
	if code := c.login("correct horse"); code != 200 {
		t.Fatalf("sign-in: %d", code)
	}
	if code, out := c.get("/api/status"); code != 200 || out["rules"].(float64) != 2 { // and the console's
		t.Fatalf("status: %d %v", code, out)
	}

	// CSRF: the cookie alone is not enough for a POST.
	token := c.csrf
	c.csrf = "stolen-or-missing"
	if code, _ := c.post("/api/config/validate", map[string]string{"text": ""}); code != 403 {
		t.Fatalf("POST without the CSRF token: %d", code)
	}
	c.csrf = token
	if code, _ := c.do("POST", "/api/config/validate", map[string]string{"text": ""}, "text/plain"); code != 415 {
		t.Fatalf("POST that a plain HTML form could send: %d", code)
	}

	// DNS rebinding: only the console's domain reaches it; any other Host
	// on its connection is not its rule's (421).
	for host, want := range map[string]int{"evil.example.net": 421, c.hostPort(): 200, "console.test": 200, "localhost:1234": 421, "10.1.2.3": 421, "[::1]:99": 421} {
		c.host = host
		if code, _ := c.get("/api/status"); code != want {
			t.Errorf("Host %q: %d, want %d", host, code, want)
		}
	}
	c.host = ""
	if code, _ := c.post("/api/logout", map[string]string{}); code != 200 {
		t.Fatal(code)
	}
	if code, _ := c.get("/api/status"); code != 401 {
		t.Fatalf("after sign-out: %d", code)
	}
}

// The console's settings come from flags and the environment, a flag
// winning; the password is required, the domain is not.
func TestConsoleSettings(t *testing.T) {
	for _, k := range []string{"CONSOLE_DOMAIN", "CONSOLE_PASSWORD", "CONSOLE_BIND", "CONSOLE_PORT", "CONSOLE_CERT"} {
		t.Setenv(k, "")
	}
	for flags, want := range map[string]string{
		"":                        "needs a password: set $CONSOLE_PASSWORD",
		"console_domain=a.test":   "needs a password: set $CONSOLE_PASSWORD",
		"console_domain=*.test":   "needs a password",
		"console_domain=10.0.0.1": "needs a password",
		"console_domain=none":     "needs a password",
	} {
		f := map[string]string{}
		if k, v, ok := strings.Cut(flags, "="); ok {
			f[k] = v
		}
		if _, err := ConsoleFromSettings(f); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", flags, err, want)
		}
	}
	t.Setenv("CONSOLE_PASSWORD", "s3cret pass")
	// No domain, none or $no_sni: clients without SNI, with a local CA's
	// certificate. An IP address: the same, for that address.
	for domain, want := range map[string]string{"": "", "none": "", "NONE": "", "$no_sni": "", "10.0.0.1": "10.0.0.1",
		"[2001:DB8::1]": "2001:db8::1", "::ffff:10.0.0.2": "10.0.0.2"} {
		c, err := ConsoleFromSettings(map[string]string{"console_domain": domain})
		if err != nil || c.Domain != want || !c.NoSNI() || c.Cert != "local-ca" {
			t.Errorf("%q: %+v %v", domain, c, err)
		}
	}
	if c, err := ConsoleFromSettings(map[string]string{"console_domain": "none", "console_cert": "local-ca:ca002"}); err != nil || c.Cert != "local-ca:ca002" {
		t.Errorf("none with another CA: %+v %v", c, err)
	}
	for domain, want := range map[string]string{"none": "ACME can't issue for $no_sni", "10.0.0.1": "ACME can't issue for 10.0.0.1"} {
		if _, err := ConsoleFromSettings(map[string]string{"console_domain": domain, "console_cert": "auto"}); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s with cert auto: %v", domain, err)
		}
	}
	if _, err := ConsoleFromSettings(map[string]string{"console_domain": "*.test"}); err == nil || !strings.Contains(err.Error(), "not a host name") {
		t.Errorf("a glob: %v", err)
	}
	t.Setenv("CONSOLE_DOMAIN", "Admin.Example.com")
	c, err := ConsoleFromSettings(nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Domain != "admin.example.com" || c.Port != 443 || c.Bind != "0.0.0.0" || c.Cert != "auto" || c.ListenerName() != "$console" ||
		!checkPassword(c.PasswordHash, "s3cret pass") || checkPassword(c.PasswordHash, "other") {
		t.Fatalf("defaults: %+v", c)
	}
	t.Setenv("CONSOLE_PORT", "8443")
	t.Setenv("CONSOLE_CERT", "local-ca:ca002")
	c, err = ConsoleFromSettings(map[string]string{"console_domain": "flag.example.com", "console_bind": "127.0.0.1; ::1"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Domain != "flag.example.com" || c.Port != 8443 || c.ListenerName() != "$console" || c.Cert != "local-ca:ca002" || c.Bind != "127.0.0.1; ::1" {
		t.Fatalf("flags and environment: %+v", c)
	}
	hash := mustHash(t, "pw")
	t.Setenv("CONSOLE_PASSWORD", hash)
	if c, err = ConsoleFromSettings(nil); err != nil || c.PasswordHash != hash {
		t.Fatalf("a hash is used as it is: %v %v", c, err)
	}
	t.Setenv("CONSOLE_PASSWORD", "$argon2id$v=19$broken")
	if _, err = ConsoleFromSettings(nil); err == nil || !strings.Contains(err.Error(), "looks like a hash") {
		t.Fatalf("a broken hash: %v", err)
	}
	for k, v := range map[string]string{"console_port": "0", "console_cert": "/etc/x", "console_bind": ""} {
		t.Setenv("CONSOLE_PASSWORD", "pw")
		if k == "console_bind" {
			continue
		}
		if _, err := ConsoleFromSettings(map[string]string{k: v}); err == nil {
			t.Errorf("%s=%s accepted", k, v)
		}
	}
}

func mustHash(t *testing.T, pw string) string {
	h, err := hashPassword(pw)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestConsoleConfigEditing(t *testing.T) {
	t.Parallel()
	a, b := echoBackend(t, "A"), echoBackend(t, "B")
	p, c, path := startConsoleProxy(t, "password = pw", allowAll(a))
	c.login("pw")
	roundtrip(t, p, "x.test", "A")

	_, cfg := c.get("/api/config")
	text := cfg["text"].(string)
	if strings.Contains(text, "password") || strings.Contains(text, "console") || !strings.Contains(text, "routes:") {
		t.Fatalf("the editor shows config.yaml, which has no console in it:\n%s", text)
	}
	save := func(text string, base map[string]any) (int, map[string]any) {
		return c.post("/api/config/save", map[string]any{"text": text, "baseHash": base["hash"], "baseMtime": base["mtime"]})
	}

	// Invalid text is refused, and the error names the EDITOR's line.
	broken := text + "basic_auth:\n  - name: \"bad/name\"\n"
	wantLine := fmt.Sprintf("line %d", strings.Count(text, "\n")+2)
	if _, out := c.post("/api/config/validate", map[string]string{"text": broken}); out["ok"] == true || !strings.Contains(out["error"].(string), wantLine) {
		t.Fatalf("want an error at %s: %v", wantLine, out)
	}
	if _, out := c.post("/api/config/validate", map[string]string{"text": broken}); out["line"] != float64(strings.Count(text, "\n")+2) {
		t.Fatalf("want the error's line as a number: %v", out["line"])
	}
	// Valid text: a tree of the settings, rule lines in the editor's numbering.
	_, valid := c.post("/api/config/validate", map[string]string{"text": text})
	if valid["ok"] != true {
		t.Fatal(valid)
	}
	editorLines := strings.Split(text, "\n")
	rulesSeen := 0
	for _, n := range valid["tree"].([]any) {
		if n.(map[string]any)["title"] != "Listeners" {
			continue
		}
		for _, l := range n.(map[string]any)["children"].([]any) {
			for _, r := range l.(map[string]any)["children"].([]any) {
				if r.(map[string]any)["tag"] == "console" {
					continue // the console's rule is not in the file
				}
				line := int(r.(map[string]any)["line"].(float64))
				if !strings.HasPrefix(strings.TrimSpace(editorLines[line-1]), "- domain:") {
					t.Errorf("rule %v: editor line %d is %q", r.(map[string]any)["title"], line, editorLines[line-1])
				}
				rulesSeen++
			}
		}
	}
	if rulesSeen == 0 {
		t.Fatalf("no rules in the tree: %v", valid["tree"])
	}
	before, _ := os.ReadFile(path)
	if _, out := save(broken, cfg); out["ok"] == true {
		t.Fatal("an invalid config must not be saved")
	}
	if _, out := save(text+"console:\n  password: hacked\n", cfg); out["ok"] == true || !strings.Contains(out["error"].(string), "the console is not configured in this file") {
		t.Fatalf("[console] must not be settable from the editor: %v", out)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Fatal("refused saves must leave the file untouched")
	}

	// Routing can be tried against unsaved text.
	edited := strings.Replace(text, fmt.Sprintf("127.0.0.1:%d\"", a), fmt.Sprintf("127.0.0.1:%d\"", b), 1)
	_, out := c.post("/api/config/test", map[string]any{"text": edited, "snis": []string{"x.test", "<none>"}})
	// One row per name and listener; the console's listener has no rule for x.test.
	if res := out["results"].([]any); res[0].(map[string]any)["target"] != fmt.Sprintf("127.0.0.1:%d", b) || res[0].(map[string]any)["listener"] != "default" || len(res) != 4 {
		t.Fatalf("%v", out)
	}
	roundtrip(t, p, "x.test", "A") // ...without touching the running config

	// A valid save: written, backed up, applied at once.
	_, out = save(edited, cfg)
	if out["ok"] != true || out["backup"] == nil {
		t.Fatalf("save: %v", out)
	}
	saved, _ := os.ReadFile(path)
	st := string(saved)
	if st != edited {
		t.Fatalf("saved file:\n%s", st)
	}
	if backup, _ := os.ReadFile(filepath.Join(filepath.Dir(path), out["backup"].(string))); !bytes.Equal(backup, before) {
		t.Fatal("the backup must be the previous file")
	}
	deadline := time.Now().Add(3 * time.Second) // reload_interval=0: only the console's poke applies it
	for p.srv.runtime.Load().cfg.Rules[0].TargetPort != b {
		if time.Now().After(deadline) {
			t.Fatal("the saved config was not applied")
		}
		time.Sleep(20 * time.Millisecond)
	}
	roundtrip(t, p, "x.test", "B")
	if c.login("pw") != 200 {
		t.Fatal("the console password must survive a save")
	}

	// The editor's version is now stale: saving again with it must fail.
	if code, out := save(text, cfg); code != 409 || out["ok"] == true {
		t.Fatalf("stale save: %d %v", code, out)
	}
	// An external edit (vim, another session) makes the pending save fail...
	_, fresh := c.get("/api/config")
	external := st + "# edited by hand\n"
	os.WriteFile(path, []byte(external), 0o600)
	if code, _ := save(fresh["text"].(string)+"\n# from the console\n", fresh); code != 409 {
		t.Fatalf("save over an external change: %d", code)
	}
	// ...and so does a bare change of the modification time, content unchanged.
	_, fresh = c.get("/api/config")
	os.Chtimes(path, time.Now(), time.Now().Add(3*time.Second))
	if code, _ := save(fresh["text"].(string)+"\n# from the console\n", fresh); code != 409 {
		t.Fatalf("save after the mtime moved: %d", code)
	}
	if now, _ := os.ReadFile(path); string(now) != external {
		t.Fatal("refused saves must not write")
	}

	// Two sessions saving from the same version: exactly one wins.
	_, fresh = c.get("/api/config")
	var wg sync.WaitGroup
	var mu sync.Mutex
	codes := map[int]int{}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			code, _ := save(fresh["text"].(string)+fmt.Sprintf("\n# writer %d\n", i), fresh)
			mu.Lock()
			codes[code]++
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	if codes[200] != 1 || codes[409] != 7 {
		t.Fatalf("concurrent saves: %v", codes)
	}
	if _, err := parseFixture(string(mustRead(t, path))); err != nil {
		t.Fatalf("file corrupted by concurrent saves: %v", err)
	}
	_, list := c.get("/api/config/backups")
	names := list["backups"].([]any)
	if len(names) != 2 {
		t.Fatalf("backups: %v", names)
	}
	if _, old := c.get("/api/config/backup?name=" + names[len(names)-1].(string)); !strings.Contains(old["text"].(string), fmt.Sprintf("127.0.0.1:%d\"", a)) || strings.Contains(old["text"].(string), "password") {
		t.Fatal("the oldest backup should be the original")
	}
	if code, _ := c.get("/api/config/backup?name=../../etc/passwd"); code != 404 {
		t.Fatalf("path tricks: %d", code)
	}
}

func mustRead(t *testing.T, path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestConsoleDashboardConnectionsCertsAndLog(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	l, dead := listen(t)
	l.Close()
	certPath := t.TempDir()
	rules := fmt.Sprintf("[[host]]\nlistener=default\npattern=term\\.test\ncert=%s\nupstream_tls=false\ntarget_host=127.0.0.1\ntarget_port=%d\n"+
		"[[host]]\nlistener=default\npattern=auto\\.test\ncert=auto\nupstream_tls=false\ntarget_host=127.0.0.1\ntarget_port=%d\n"+
		"[[host]]\nlistener=default\npattern=pass\\.test\ntarget_host=127.0.0.1\ntarget_port=%d\n",
		ca.localCA(t), echoBackend(t, ""), echoBackend(t, ""), echoBackend(t, ""))
	path := filepath.Join(t.TempDir(), "config.yaml")
	text := fmt.Sprintf("[[listener]]\nname=default\nport=1\n[global]\nstats_interval=0\ncert_path=%s\nacme_agree_tos=true\nacme_directory=https://127.0.0.1:%d/dir\n%s", certPath, dead, rules)
	os.WriteFile(path, []byte(text), 0o600)
	con := testConsole(t, freePort(t), "pw")
	p := startProxyConsole(t, text, path, con)
	waitForPort(t, con.Addrs()[0])
	c, _ := consoleClientFor(t, con)
	c.login("pw")

	// Traffic: two passed-through connections (one stays open) and one terminated.
	hello := clientHello("pass.test")
	open := dial(t, p)
	open.Write(hello)
	open.Write(make([]byte, 5000))
	readN(t, open, len(hello)+5000)
	roundtrip(t, p, "pass.test", "")
	tc, err := tlsDial(t, p, &tls.Config{RootCAs: ca.pool, ServerName: "term.test"})
	if err != nil {
		t.Fatal(err)
	}
	tc.Write([]byte("hello"))
	readN(t, tc, 5)
	// The recent log holds 2,000 lines for the whole process, and other tests
	// run in parallel: look for the line now, not at the end of this test.
	for deadline := time.Now().Add(T); ; time.Sleep(20 * time.Millisecond) {
		_, lg := c.get("/api/log?filter=TLS+terminated+here")
		lines := lg["lines"].([]any)
		// Lines of other tests' proxies are in there too (one process, one log):
		// ours is the one terminated with this test's CA.
		if strings.Contains(fmt.Sprint(lines), "cert="+ca.localCA(t)+" ") && !strings.Contains(fmt.Sprint(lines), "pass.test") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("filtered log: %v", lines)
		}
	}
	// Rates come from one sample per second: move data between two samples.
	time.Sleep(1200 * time.Millisecond)
	open.Write(make([]byte, 20000))
	readN(t, open, 20000)
	time.Sleep(1200 * time.Millisecond)

	_, st := c.get("/api/status")
	hosts := map[string]map[string]any{}
	for _, h := range st["hosts"].([]any) {
		hosts[h.(map[string]any)["Host"].(string)] = h.(map[string]any)
	}
	pass, term := hosts["pass.test"], hosts["term.test"]
	if pass == nil || term == nil || pass["Active"].(float64) != 1 || pass["Total"].(float64) != 2 || pass["Terminated"].(float64) != 0 ||
		term["Active"].(float64) != 1 || term["Terminated"].(float64) != 1 || term["BytesUp"].(float64) != 5 ||
		pass["BytesUp"].(float64) != float64(2*len(hello)+25000+4) {
		t.Fatalf("per-host numbers: %v", hosts)
	}
	// The console's own connections count too: this test's client, and the
	// probe that waited for its port.
	own := hosts["console.test"]
	if own == nil || st["active"].(float64) != 2+own["Active"].(float64) || st["accepted"].(float64) != 4+own["Total"].(float64) || st["bytesDown"].(float64) < 25000 || st["rateDown"].(float64) < 1000 || st["rateUp"].(float64) < 1000 || st["rateWindowSeconds"].(float64) != 5 {
		t.Fatalf("totals and rates: %v", st)
	}

	_, cs := c.get("/api/connections")
	var rows []any
	for _, r := range cs["connections"].([]any) {
		if r.(map[string]any)["sni"] != "console.test" { // this test's own, to the console
			rows = append(rows, r)
		}
	}
	if len(rows) != 2 || rows[0].(map[string]any)["terminated"] != true || rows[1].(map[string]any)["terminated"] != false ||
		rows[1].(map[string]any)["sni"] != "pass.test" || rows[1].(map[string]any)["cToS"] != "open" {
		t.Fatalf("connections: %v", rows)
	}

	// Certificates: the one the local CA issued and the automatic one (failing: the CA is unreachable).
	var local, auto map[string]any
	for deadline := time.Now().Add(T); ; time.Sleep(100 * time.Millisecond) {
		_, out := c.get("/api/certs")
		local, auto = nil, nil
		for _, row := range out["certs"].([]any) {
			switch r := row.(map[string]any); r["Source"] {
			case "local-ca":
				local = r
			case "auto":
				auto = r
			}
		}
		if local != nil && auto != nil && auto["Status"] == "failing" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("certs: %v", out["certs"])
		}
	}
	if local["Status"] != "ok" || local["Issuer"] != "test CA" || local["Name"] != "term.test" ||
		auto["Name"] != "auto.test" || auto["LastError"] == "" || auto["NextAttempt"] == "" {
		t.Fatalf("local=%v\nauto=%v", local, auto)
	}
	if code, _ := c.post("/api/certs/retry", map[string]string{"domain": "auto.test"}); code != 200 {
		t.Fatal(code)
	}
	if code, _ := c.post("/api/certs/retry", map[string]string{"domain": "not-managed.test"}); code != 400 {
		t.Fatal(code)
	}

	// A filter that matches nothing is an empty list, not null.
	if _, lg := c.get("/api/log?filter=no-such-line-anywhere-7f3a"); len(lg["lines"].([]any)) != 0 {
		t.Fatalf("%v", lg)
	}
}

// The console owns a listener, $console, on any port. Its name, bind,
// port and rule are fixed; config.yaml may give it options and
// rules.
func TestConsoleListener(t *testing.T) {
	t.Parallel()
	con := &ConsoleConfig{Bind: "0.0.0.0", Binds: []string{"0.0.0.0"}, Port: 443, Domain: "admin.example.com", Cert: "auto"}
	load := func(text string, c *ConsoleConfig) (*Config, error) {
		return LoadConfig("global:\n  acme_agree_tos: true\n"+text, c)
	}
	cfg, err := load(`listeners:
  - name: $console
    max_connections: 7
    proxy_trust_source: [10.0.0.0/8]
  - name: lan
    bind: [192.168.1.1]
    port: 443
routes:
  - listener: $console
    rules:
      - domain: "*.example.com"
        action: deny
`, con)
	if err != nil {
		t.Fatal(err)
	}
	l := cfg.Listener("$console")
	if l == nil || !l.Console || l.Port != 443 || l.Bind != "0.0.0.0" || l.MaxConnections != 7 || l.ProxyTrustSource == nil {
		t.Fatalf("the console's listener, with config.yaml's options: %+v", l)
	}
	r := cfg.ConsoleRule()
	if r == nil || r.Listener != "$console" || r.Source != "admin.example.com" || !r.Serves() || r.Line != 0 {
		t.Fatalf("its rule: %+v", r)
	}
	if d := cfg.ForListener(l).Route("admin.example.com"); d.Rule != r {
		t.Fatal("its domain beats the wildcard")
	}
	if !slices.Contains(cfg.AutoDomains(), "admin.example.com") {
		t.Fatal("cert: auto issues for its domain")
	}
	// Without config.yaml listing it, it is there anyway, on any port.
	other := *con
	other.Port = 8443
	cfg, err = load("listeners:\n  - {name: lan, port: 9000}\n", &other)
	if err != nil {
		t.Fatal(err)
	}
	if l := cfg.Listener("$console"); l == nil || !l.Console || l.Port != 8443 || l.Line != 0 {
		t.Fatalf("$console: %+v", cfg.Listeners)
	}
	for text, want := range map[string]string{
		"listeners:\n  - {name: $console, port: 443}\n":                                                    "listener $console is the web console's",
		"listeners:\n  - {name: $console, bind: [0.0.0.0]}\n":                                              "listener $console is the web console's",
		"listeners:\n  - {name: $console}\n  - {name: $console}\n":                                         "listed twice",
		"listeners:\n  - {name: https, bind: [0.0.0.0], port: 443}\n":                                      "is the web console's listener $console, reserved",
		"routes:\n  - listener: $console\n    rules:\n      - {domain: admin.example.com, action: deny}\n": "is the web console's domain",
	} {
		if _, err := load(text, con); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", text, err, want)
		}
	}
	// https is a name like any other: only the console's bind and port are its own.
	if _, err := load("listeners:\n  - {name: https, port: 8443}\nroutes:\n  - listener: https\n    rules:\n      - {domain: a.test, action: deny}\n", con); err != nil {
		t.Errorf("a listener named https next to the console: %v", err)
	}
	if _, err := LoadConfig("listeners:\n  - {name: lan, port: 9}\n", con); err == nil || !strings.Contains(err.Error(), "acme_agree_tos") {
		t.Errorf("cert: auto without acme_agree_tos: %v", err)
	}
	// No console: https is a name like any other, and must say where it listens.
	if _, err := LoadConfig("listeners:\n  - {name: https}\n", nil); err == nil || !strings.Contains(err.Error(), "port is required") {
		t.Errorf("no console: %v", err)
	}
	if _, err := LoadConfig("listeners:\n  - {name: https, port: 443}\n", nil); err != nil {
		t.Errorf("no console, https defined by hand: %v", err)
	}
}

// No code but the loader parses config.toml: a check that skipped the
// console would pass versions a reload then refuses.
func TestEveryLoadMergesTheConsole(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") || f == "config.go" {
			continue
		}
		src := string(mustRead(t, f))
		if strings.Contains(src, "parseFixture(") {
			t.Errorf("%s calls ParseConfig: load through Server.loadConfig (or LoadConfig with the console) instead", f)
		}
		if strings.Contains(src, "loadFixture(") && f != "main.go" && f != "proxy.go" {
			t.Errorf("%s calls LoadConfig: load through Server.loadConfig instead", f)
		}
	}
}

// The console over TLS, on its listener: signed in, and nothing in it can
// cut it off.
func TestConsoleOverTLS(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "config.yaml")
	text := "[[listener]]\nname=default\nport=1\n[global]\nstats_interval=0\nreload_interval=0\n[[host]]\nlistener=default\npattern=ANY\naction=deny\n"
	os.WriteFile(path, []byte(text), 0o600)
	con := testConsole(t, freePort(t), "pw")
	p := startProxyConsole(t, text, path, con)
	waitForPort(t, con.Addrs()[0])
	c, tr := consoleClientFor(t, con)
	if code := c.login("pw"); code != 200 {
		t.Fatalf("sign-in over TLS: %d", code)
	}
	_, st := c.get("/api/state")
	if st["version"] != version || version == "" {
		t.Errorf("the state's version: %v, want %s", st["version"], version)
	}
	var consoleRule map[string]any
	for _, l := range st["listeners"].([]any) {
		lv := l.(map[string]any)
		for _, r := range lv["rules"].([]any) {
			if r.(map[string]any)["console"] == true {
				consoleRule = r.(map[string]any)
				if lv["name"] != "$console" || lv["console"] != true {
					t.Errorf("the console's listener: %v", lv["name"])
				}
			}
		}
	}
	if consoleRule == nil || consoleRule["pattern"] != "console.test" || consoleRule["target"] != "the console" {
		t.Fatalf("the console's rule in the state: %v", consoleRule)
	}
	if code, _ := c.post("/api/rules/stop", map[string]string{"key": consoleRule["key"].(string)}); code != 409 {
		t.Errorf("stopping the console's rule: %d", code)
	}
	if code, _ := c.post("/api/listeners/stop", map[string]string{"name": "$console"}); code != 409 {
		t.Errorf("stopping the console's listener: %d", code)
	}
	_, cfg := c.get("/api/config")
	edit := cfg["text"].(string) + "  - listener: $console\n    rules:\n      - {domain: console.test, action: deny}\n"
	if _, out := c.post("/api/config/validate", map[string]string{"text": edit}); out["ok"] == true || !strings.Contains(out["error"].(string), "is the web console's domain") {
		t.Errorf("a rule for the console's domain: %v", out)
	}
	// A rule for another name on the console's listener is fine.
	edit = cfg["text"].(string) + "  - listener: $console\n    rules:\n      - {domain: other.test, action: deny}\n"
	if _, out := c.post("/api/config/save", map[string]any{"text": edit, "baseHash": cfg["hash"], "baseMtime": cfg["mtime"]}); out["ok"] != true {
		t.Fatalf("a rule on the console's listener: %v", out)
	}
	tr.CloseIdleConnections()
	if code, _ := c.get("/api/status"); code != 200 {
		t.Fatalf("after the save: %d", code)
	}

	// Its options: not in the file yet (line 0), so saving them adds an
	// entry with its name and the options, never bind or port.
	_, cfg = c.get("/api/config")
	vals := map[string]any{"name": "$console", "max_connections": "77"}
	if _, out := c.post("/api/listeners/save", map[string]any{"line": 0, "baseHash": cfg["hash"], "baseMtime": cfg["mtime"], "values": vals}); out["ok"] != true {
		t.Fatalf("its options: %v", out)
	}
	written, _ := os.ReadFile(path)
	if !strings.Contains(string(written), "- name: $console\n    max_connections: 77\n") {
		t.Fatalf("written as:\n%s", written)
	}
	if l := p.srv.runtime.Load().cfg.Listener("$console"); l == nil || l.MaxConnections != 77 || !l.Console {
		t.Fatalf("applied: %+v", l)
	}
	_, st = c.get("/api/state")
	var line float64
	for _, l := range st["listeners"].([]any) {
		if l := l.(map[string]any); l["name"] == "$console" {
			line = l["line"].(float64)
		}
	}
	_, cfg = c.get("/api/config")
	if _, out := c.post("/api/listeners/delete", map[string]any{"line": line, "baseHash": cfg["hash"], "baseMtime": cfg["mtime"]}); out["ok"] == true ||
		!strings.Contains(out["error"].(string), "can't be deleted") {
		t.Fatalf("deleting the console's listener: %v", out)
	}
}

// $console is the console's listener, whatever its port: moving the
// console doesn't break the file.
func TestConsoleAlias(t *testing.T) {
	t.Parallel()
	text := "global:\n  acme_agree_tos: true\nlisteners:\n  - {name: $console, max_connections: 9}\nroutes:\n  - listener: $console\n    rules:\n      - {domain: www.test, action: deny}\n"
	for _, port := range []int{443, 8443} {
		con := &ConsoleConfig{Bind: "0.0.0.0", Binds: []string{"0.0.0.0"}, Port: port, Domain: "admin.test", Cert: "auto"}
		c, err := LoadConfig(text, con)
		if err != nil {
			t.Fatal(err)
		}
		if l := c.Listener("$console"); l == nil || !l.Console || l.Port != port || l.MaxConnections != 9 || c.Rules[0].Listener != "$console" {
			t.Fatalf("port %d: %+v", port, c.Listeners)
		}
	}
	if _, err := LoadConfig(text, nil); err == nil || !strings.Contains(err.Error(), "no console") {
		t.Fatalf("without a console: %v", err)
	}
}

// A listener without $anything_else shows its implicit deny as a locked
// rule, with the connections no rule took.
func TestConsoleImplicitDeny(t *testing.T) {
	t.Parallel()
	p, c, _ := startConsoleProxy(t, "password = pw", "[[host]]\nlistener=default\npattern=a.test\naction=deny\n")
	c.login("pw")
	expectDenied(t, p, clientHello("nobody.test"))
	var implicit map[string]any
	for deadline := time.Now().Add(T); implicit == nil || implicit["total"].(float64) < 1; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("implicit deny: %v", implicit)
		}
		_, st := c.get("/api/state")
		implicit = nil
		for _, l := range st["listeners"].([]any) {
			if l.(map[string]any)["name"] != "default" {
				continue
			}
			for _, r := range l.(map[string]any)["rules"].([]any) {
				if r.(map[string]any)["implicit"] == true {
					implicit = r.(map[string]any)
				}
			}
		}
	}
	if implicit["pattern"] != "$anything_else" || implicit["target"] != "deny (implicit)" || implicit["line"].(float64) != 0 {
		t.Fatalf("implicit deny: %v", implicit)
	}
	cfg, err := LoadConfig(yamlFixture("[[listener]]\nname=x\nport=1\n[[host]]\nlistener=x\npattern=ANY\naction=deny\n"), nil)
	if err != nil || cfg.Rules[0].Key() != implicitDenyKey("x") {
		t.Fatalf("an explicit $anything_else has the implicit one's key, so its counts carry on: %v", err)
	}
}

// The console lists a listener's rules in the order they are tried, not
// file order.
func TestRulesInEvaluationOrder(t *testing.T) {
	t.Parallel()
	c, err := LoadConfig(`listeners:
  - {name: lan, port: 1}
routes:
  - listener: lan
    rules:
      - {domain: $anything_else, action: deny}
      - {domain: "*.example.com", action: deny}
      - {domain: "*.api.example.com", action: deny}
      - {domain: www.example.com, action: deny}
      - {domain: $no_sni, action: deny}
      - {domain: a.test, action: deny}
`, nil)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range evaluationOrder(c.Rules) {
		got = append(got, r.Source)
	}
	want := []string{"$no_sni", "www.example.com", "a.test", "*.api.example.com", "*.example.com", "$anything_else"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// A console without a domain (none) is its listener's $no_sni rule: config.yaml
// can't have one there, and with an IP address as its domain its
// certificate is for that address.
func TestConsoleNoSNIConfig(t *testing.T) {
	t.Parallel()
	con := &ConsoleConfig{Bind: "0.0.0.0", Binds: []string{"0.0.0.0"}, Port: 8443, Cert: "local-ca"}
	text := "global:\n  cert_root: " + strconv.Quote(testCARoot()) + "\nlisteners:\n  - {name: lan, port: 9000}\n"
	cfg, err := LoadConfig(text+"routes:\n  - listener: lan\n    rules:\n      - {domain: $no_sni, action: deny}\n"+
		"  - listener: $console\n    rules:\n      - {domain: www.test, action: deny}\n", con)
	if err != nil {
		t.Fatal(err)
	}
	r := cfg.ConsoleRule()
	if r == nil || r.Kind != kindNone || r.Listener != "$console" || !r.Console || !r.Serves() {
		t.Fatalf("its rule: %+v", r)
	}
	if d := cfg.ForListener(cfg.Listener("$console")).Route(""); d.Rule != r {
		t.Fatal("no SNI on its listener is the console")
	}
	if d := cfg.ForListener(cfg.Listener("$console")).Route("www.test"); d.Rule == nil || d.Rule.Console {
		t.Fatal("a name on its listener is the file's rule")
	}
	if _, err := LoadConfig(text+"routes:\n  - listener: $console\n    rules:\n      - {domain: $no_sni, action: deny}\n", con); err == nil ||
		!strings.Contains(err.Error(), "answers clients without SNI") {
		t.Fatalf("a $no_sni rule of the file's on its listener: %v", err)
	}
	ip := *con
	ip.Domain = "10.9.8.7"
	if cfg, err = LoadConfig(text, &ip); err != nil {
		t.Fatal(err)
	}
	if r := cfg.ConsoleRule(); r.Kind != kindNone || len(r.certIPs) != 1 || r.certIPs[0].String() != "10.9.8.7" {
		t.Fatalf("an IP address: %+v", r)
	}
	// A host name is what it was: a literal rule, and $no_sni stays the file's.
	named := *con
	named.Domain = "admin.test"
	if cfg, err = LoadConfig(text+"routes:\n  - listener: $console\n    rules:\n      - {domain: $no_sni, action: deny}\n", &named); err != nil || cfg.ConsoleRule().Kind != kindLiteral {
		t.Fatalf("a host name: %v", err)
	}
}

// The console over TLS without SNI: a client by IP address gets a
// certificate from the default CA for that address, signs in, and the
// editor can't add a $no_sni rule to the console's listener. A host name in
// the Host header is refused (DNS rebinding).
func TestConsoleNoSNIOverTLS(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "config.yaml")
	text := "[[listener]]\nname=default\nport=1\n[global]\nstats_interval=0\nreload_interval=0\n[[host]]\nlistener=default\npattern=ANY\naction=deny\n"
	os.WriteFile(path, []byte(text), 0o600)
	for _, domain := range []string{"", "127.0.0.1"} {
		con := &ConsoleConfig{Bind: "127.0.0.1", Binds: []string{"127.0.0.1"}, Port: freePort(t), Domain: domain, Cert: "local-ca", PasswordHash: mustHash(t, "pw")}
		p := startProxyConsole(t, text, path, con)
		waitForPort(t, con.Addrs()[0])
		caPEM, err := os.ReadFile(filepath.Join(testCARoot(), defaultCAID, "ca_cert.pem"))
		if err != nil {
			t.Fatal(err)
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(caPEM)
		tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}} // by IP: Go sends no SNI and checks the IP
		t.Cleanup(tr.CloseIdleConnections)
		jar, _ := cookiejar.New(nil)
		c := &consoleClient{t: t, base: fmt.Sprintf("https://127.0.0.1:%d%s", con.Port, consolePath), http: &http.Client{Jar: jar, Timeout: T, Transport: tr}}
		if code := c.login("pw"); code != 200 {
			t.Fatalf("domain %q: sign-in by IP: %d", domain, code)
		}
		if code, _ := c.get("/api/status"); code != 200 {
			t.Fatalf("domain %q: signed in: %d", domain, code)
		}
		c.host = "rebind.example"
		if code, _ := c.get("/api/status"); code != 403 && code != http.StatusMisdirectedRequest { // routed elsewhere: 421
			t.Errorf("domain %q: a host name in Host: %d", domain, code)
		}
		c.host = "127.0.0.2"
		if code, _ := c.get("/api/status"); (domain == "") != (code == 200) {
			t.Errorf("domain %q: Host 127.0.0.2: %d", domain, code)
		}
		c.host = ""
		_, f := c.get("/api/config")
		vals := map[string]any{"listener": "$console", "domain": "$no_sni", "action": "deny"}
		if _, out := c.post("/api/rules/save", map[string]any{"line": 0, "baseHash": f["hash"], "baseMtime": f["mtime"], "values": vals}); out["ok"] == true ||
			!strings.Contains(fmt.Sprint(out["error"]), "answers clients without SNI") {
			t.Errorf("domain %q: a $no_sni rule on the console's listener: %v", domain, out)
		}
		_ = p
	}
}
