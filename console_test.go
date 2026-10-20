package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"slices"
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
	host string // overrides the Host header when set
}

// hostPort is the console's address, as in a Host header.
func (c *consoleClient) hostPort() string {
	return strings.TrimPrefix(strings.TrimSuffix(c.base, consolePath), "http://")
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

// startConsoleProxy writes a config file and a console.toml with
// consoleLines (plain HTTP on a free loopback port), and starts the proxy
// with both. It returns the config file's path; the console file is
// p.consolePath.
func startConsoleProxy(t *testing.T, consoleLines, rules string) (*proxyUnderTest, *consoleClient, string) {
	t.Helper()
	return startConsoleProxyGlobal(t, "", consoleLines, rules)
}

// startConsoleProxyGlobal is startConsoleProxy with extra [global] lines.
func startConsoleProxyGlobal(t *testing.T, globalLines, consoleLines, rules string) (*proxyUnderTest, *consoleClient, string) {
	t.Helper()
	dir := t.TempDir()
	path, conPath := filepath.Join(dir, "config.toml"), filepath.Join(dir, "console.toml")
	port := freePort(t)
	text := fmt.Sprintf("# top comment\n[[listener]]\nname=default\nport=1\n[global]\nstats_interval=0\nreload_interval=0\n%s\n\n%s", globalLines, rules)
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(conPath, []byte(fmt.Sprintf("# console comment\n[console]\nport = %d\n%s\n", port, consoleLines)), 0o600); err != nil {
		t.Fatal(err)
	}
	p := startProxyConsole(t, text, path, conPath)
	waitForPort(t, fmt.Sprintf("127.0.0.1:%d", port))
	jar, _ := cookiejar.New(nil)
	return p, &consoleClient{t: t, base: fmt.Sprintf("http://127.0.0.1:%d%s", port, consolePath), http: &http.Client{Jar: jar, Timeout: T}}, path
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
	if code, out := c.get("/api/status"); code != 200 || out["rules"].(float64) != 1 {
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

	// DNS rebinding: an unknown DNS name in Host is refused; IPs and configured names are fine.
	for host, want := range map[string]int{"evil.example.net": 403, "console.example.com": 200, "localhost:1234": 200, "10.1.2.3": 200, "[::1]:99": 200} {
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

func TestConsolePlaintextPasswordIsReplacedByItsHash(t *testing.T) {
	t.Parallel()
	p, c, _ := startConsoleProxy(t, "password = \"s3cret pass\"  # typed by hand", "[[host]]\nlistener=default\npattern=.*\naction=deny\n")
	data, _ := os.ReadFile(p.consolePath)
	text := string(data)
	if strings.Contains(text, "s3cret") || !strings.Contains(text, "password_hash = \"$argon2id$") {
		t.Fatalf("plaintext still on disk, or no hash:\n%s", text)
	}
	if !strings.Contains(text, "# console comment\n[console]\nport = ") {
		t.Fatalf("only the password line may change:\n%s", text)
	}
	if _, err := ParseConsole(text); err != nil {
		t.Fatalf("rewritten file must still load: %v", err)
	}
	if c.login("s3cret pass") != 200 || c.login("other") == 200 {
		t.Fatal("the hash must accept exactly the original password")
	}
	if !checkPassword(mustHash(t, "pw"), "pw") || checkPassword(mustHash(t, "pw"), "pW") || checkPassword("garbage", "pw") {
		t.Fatal("hash verification")
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
	if strings.Contains(text, "password") || strings.Contains(text, "[console]") || strings.Contains(text, "console comment") || !strings.Contains(text, "# top comment") {
		t.Fatalf("the editor shows config.toml, which has no console in it:\n%s", text)
	}
	consoleBefore, _ := os.ReadFile(p.consolePath)
	save := func(text string, base map[string]any) (int, map[string]any) {
		return c.post("/api/config/save", map[string]any{"text": text, "baseHash": base["hash"], "baseMtime": base["mtime"]})
	}

	// Invalid text is refused, and the error names the EDITOR's line.
	broken := text + "\n[[host]]\nlistener=default\npattern=(\ntarget_host=x.lan\ntarget_port=443\n"
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
				line := int(r.(map[string]any)["line"].(float64))
				if strings.TrimSpace(editorLines[line-1]) != "[[host]]" {
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
	if _, out := save(text+"\n[console]\nport=1\npassword=hacked\n", cfg); out["ok"] == true || !strings.Contains(out["error"].(string), "[console] has a file of its own") {
		t.Fatalf("[console] must not be settable from the editor: %v", out)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Fatal("refused saves must leave the file untouched")
	}

	// Routing can be tried against unsaved text.
	edited := strings.Replace(text, fmt.Sprintf("target_port=%d", a), fmt.Sprintf("target_port=%d", b), 1)
	_, out := c.post("/api/config/test", map[string]any{"text": edited, "snis": []string{"x.test", "<none>"}})
	if res := out["results"].([]any); res[0].(map[string]any)["target"] != fmt.Sprintf("127.0.0.1:%d", b) || len(res) != 2 {
		t.Fatalf("%v", out)
	}
	roundtrip(t, p, "x.test", "A") // ...without touching the running config

	// A valid save: written, backed up, console.toml untouched, applied at once.
	_, out = save(edited, cfg)
	if out["ok"] != true || out["backup"] == nil {
		t.Fatalf("save: %v", out)
	}
	saved, _ := os.ReadFile(path)
	st := string(saved)
	if st != edited {
		t.Fatalf("saved file:\n%s", st)
	}
	if after, _ := os.ReadFile(p.consolePath); !bytes.Equal(after, consoleBefore) {
		t.Fatal("console.toml is never written by a save")
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
	external := strings.Replace(st, "# top comment", "# edited by hand", 1)
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
	if _, err := ParseConfig(string(mustRead(t, path))); err != nil {
		t.Fatalf("file corrupted by concurrent saves: %v", err)
	}
	_, list := c.get("/api/config/backups")
	names := list["backups"].([]any)
	if len(names) != 2 {
		t.Fatalf("backups: %v", names)
	}
	if _, old := c.get("/api/config/backup?name=" + names[len(names)-1].(string)); !strings.Contains(old["text"].(string), fmt.Sprintf("target_port=%d", a)) || strings.Contains(old["text"].(string), "password") {
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
	dir := t.TempDir()
	path, conPath := filepath.Join(dir, "config.toml"), filepath.Join(dir, "console.toml")
	port := freePort(t)
	text := fmt.Sprintf("[[listener]]\nname=default\nport=1\n[global]\nstats_interval=0\ncert_path=%s\nacme_agree_tos=true\nacme_directory=https://127.0.0.1:%d/dir\n%s", certPath, dead, rules)
	os.WriteFile(path, []byte(text), 0o600)
	os.WriteFile(conPath, []byte(fmt.Sprintf("[console]\nport=%d\npassword=pw\n", port)), 0o600)
	p := startProxyConsole(t, text, path, conPath)
	waitForPort(t, fmt.Sprintf("127.0.0.1:%d", port))
	jar, _ := cookiejar.New(nil)
	c := &consoleClient{t: t, base: fmt.Sprintf("http://127.0.0.1:%d%s", port, consolePath), http: &http.Client{Jar: jar, Timeout: T}}
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
	if st["active"].(float64) != 2 || st["accepted"].(float64) != 3 || st["bytesDown"].(float64) < 25000 || st["rateDown"].(float64) < 1000 || st["rateUp"].(float64) < 1000 || st["rateWindowSeconds"].(float64) != 5 {
		t.Fatalf("totals and rates: %v", st)
	}

	_, cs := c.get("/api/connections")
	rows := cs["connections"].([]any)
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

func TestConsoleFile(t *testing.T) {
	t.Parallel()
	mustConsole := func(text string) *ConsoleConfig {
		t.Helper()
		c, err := ParseConsole(text)
		if err != nil {
			t.Fatalf("%s: %v", text, err)
		}
		return c
	}
	plain := mustConsole("# mine\n[console]\nbind=192.168.1.1\nport=9000\npassword=x\nhostnames=a.example.com; B.example.com\n")
	if plain.TLS() || plain.Bind != "192.168.1.1" || fmt.Sprint(plain.Hostnames) != "[a.example.com b.example.com]" || len(plain.Warnings) != 1 {
		t.Fatalf("%+v", plain) // plain HTTP off loopback is allowed, with a warning
	}
	if c := mustConsole("[console]\nport=9000\npassword=x\n"); c.Bind != "127.0.0.1" || len(c.Warnings) != 0 {
		t.Fatalf("defaults: %+v", c)
	}
	tlsCon := mustConsole("[console]\nbind=::\nport=443\nhostname=Admin.Example.com\ncert=AUTO\npassword=x\n")
	if !tlsCon.TLS() || tlsCon.Hostname != "admin.example.com" || tlsCon.Cert != "auto" || len(tlsCon.Warnings) != 0 {
		t.Fatalf("TLS: %+v", tlsCon)
	}
	for text, want := range map[string]string{
		"[console]\nport=9000\n":                                                    "needs a password",
		"[console]\npassword=x\n":                                                   "port is required",
		"[console]\nport=9000\npassword_hash=md5$abc\n":                             "password_hash",
		"[console]\nport=9000\npassword=x\ntls=true\n":                              `unknown key "tls"`,
		"[console]\nport=9000\npassword=x\nlisten=127.0.0.1\n":                      "listen is now called bind",
		"[console]\nport=443\npassword=x\ncert=auto\n":                              "needs hostname",
		"[console]\nport=443\npassword=x\ncert=/etc/certs\nhostname=a.b":            "cert must be auto or local-ca",
		"[console]\nport=443\npassword=x\ncert=auto\nhostname=*.b.c\n":              "hostname must be a host name",
		"[console]\nport=443\npassword=x\ncert=auto\nhostname=a.b\nhostnames=c.d\n": "hostnames only applies without cert",
		"[global]\nport=1\n":                                                        "holds only the [console] section",
		"[[host]]\n":                                                                "holds only the [console] section",
		"port=1\n":                                                                  "key outside of [console]",
		"# nothing\n":                                                               "no [console] section",
	} {
		if _, err := ParseConsole(text); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", text, err, want)
		}
	}
	// [console] in config.toml says where it went.
	if _, err := ParseConfig("[[listener]]\nname=default\nport=1\n[console]\nport=9000\npassword=x\n"); err == nil || !strings.Contains(err.Error(), "--console") {
		t.Fatalf("[console] in config.toml: %v", err)
	}
}

// The console's address decides where it goes: on the listener with exactly
// its address and port, on a listener of its own, or an error.
func TestConsoleMerge(t *testing.T) {
	t.Parallel()
	head := "[[listener]]\nname=https\nbind=::\nport=443\n[global]\nacme_agree_tos=true\n"
	con := func(lines string) *ConsoleConfig {
		c, err := ParseConsole("[console]\npassword=x\nhostname=admin.example.com\ncert=auto\n" + lines)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	merged, err := LoadConfig(head+"[[host]]\nlistener=https\npattern=*.example.com\naction=deny\n", con("bind=::\nport=443\n"))
	if err != nil {
		t.Fatal(err)
	}
	r := merged.ConsoleRule()
	if r == nil || r.Listener != "https" || !r.Serves() || r.Line != 0 || r.Cert != "auto" || len(merged.Listeners) != 1 || !merged.Listeners[0].Console {
		t.Fatalf("merged: %+v %+v", r, merged.Listeners)
	}
	if d := merged.ForListener(&merged.Listeners[0]).Route("admin.example.com"); !d.Allow || d.Rule != r {
		t.Fatalf("its name beats the wildcard: %+v", d)
	}
	if !slices.Contains(merged.AutoDomains(), "admin.example.com") {
		t.Fatal("cert = auto: the console's name gets a certificate")
	}
	own, err := LoadConfig(head, con("bind=127.0.0.1\nport=8443\n"))
	if err != nil {
		t.Fatal(err)
	}
	if l := own.Listener(consoleListener); l == nil || !l.Console || l.Line != 0 || l.Port != 8443 || own.ConsoleRule().Listener != consoleListener {
		t.Fatalf("own listener: %+v", own.Listeners)
	}
	for text, want := range map[string]string{
		head + "[[host]]\nlistener=https\npattern=admin.example.com\naction=deny\n":         "is the console's hostname",
		"[[listener]]\nname=https\nbind=0.0.0.0\nport=443\n[global]\nacme_agree_tos=true\n": "exactly the same addresses: bind = 0.0.0.0",
		"[[listener]]\nname=https\nbind=::\nport=443\n":                                     "acme_agree_tos",
		"[[listener]]\nname=(console)\nport=5\n[global]\nacme_agree_tos=true\n":             "reserved for the console",
		head + "http_to_https_redirect=true\n":                                              "",
	} {
		c := con("bind=::\nport=443\n")
		if strings.Contains(text, "http_to_https_redirect") {
			c = con("bind=::\nport=80\n")
			want = "http_to_https_redirect listener"
		}
		if _, err := LoadConfig(text, c); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", text, err, want)
		}
	}
	plain, err := ParseConsole("[console]\npassword=x\nbind=::\nport=443\n")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(head, plain); err == nil || !strings.Contains(err.Error(), "set cert and hostname") {
		t.Errorf("plain HTTP on a listener's port: %v", err)
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
		if strings.Contains(src, "ParseConfig(") {
			t.Errorf("%s calls ParseConfig: load through Server.loadConfig (or LoadConfig with the console) instead", f)
		}
		if strings.Contains(src, "LoadConfig(") && f != "main.go" && f != "proxy.go" {
			t.Errorf("%s calls LoadConfig: load through Server.loadConfig instead", f)
		}
	}
}

// The console over TLS: a rule of the listener with its address, locked
// against stopping, and moving to a listener of its own (and back) without
// its port ever closing.
func TestConsoleOverTLS(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	dir := t.TempDir()
	path, conPath := filepath.Join(dir, "config.toml"), filepath.Join(dir, "console.toml")
	port := freePort(t)
	head := fmt.Sprintf("[[listener]]\nname=default\nport=1\n[global]\nstats_interval=0\nreload_interval=0\nca_root=%s\n", testCARoot())
	web := fmt.Sprintf("[[listener]]\nname=web\nbind=127.0.0.1\nport=%d\n", port)
	rules := "[[host]]\nlistener=default\npattern=ANY\naction=deny\n"
	os.WriteFile(path, []byte(head+web+rules), 0o600)
	os.WriteFile(conPath, []byte(fmt.Sprintf("[console]\nbind=127.0.0.1\nport=%d\nhostname=console.test\ncert=%s\npassword=pw\n", port, ca.localCA(t))), 0o600)
	p := startProxyConsole(t, head+web+rules, path, conPath)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	waitForPort(t, addr)
	jar, _ := cookiejar.New(nil)
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		},
		TLSClientConfig:   &tls.Config{RootCAs: ca.pool},
		ForceAttemptHTTP2: true,
	}
	c := &consoleClient{t: t, base: fmt.Sprintf("https://console.test:%d%s", port, consolePath), http: &http.Client{Jar: jar, Timeout: T, Transport: tr}}
	if code := c.login("pw"); code != 200 {
		t.Fatalf("sign-in over TLS: %d", code)
	}
	_, st := c.get("/api/state")
	var consoleRule map[string]any
	for _, l := range st["listeners"].([]any) {
		lv := l.(map[string]any)
		for _, r := range lv["rules"].([]any) {
			if r.(map[string]any)["console"] == true {
				consoleRule = r.(map[string]any)
				if lv["name"] != "web" || lv["console"] != true {
					t.Errorf("the console's listener: %v", lv["name"])
				}
			}
		}
	}
	if consoleRule == nil || consoleRule["pattern"] != "console.test" || consoleRule["target"] != "the console" {
		t.Fatalf("the console's rule in the state: %v", consoleRule)
	}
	// Nothing in the console can cut it off.
	if code, _ := c.post("/api/rules/stop", map[string]string{"key": consoleRule["key"].(string)}); code != 409 {
		t.Errorf("stopping the console's rule: %d", code)
	}
	if code, _ := c.post("/api/listeners/stop", map[string]string{"name": "web"}); code != 409 {
		t.Errorf("stopping the console's listener: %d", code)
	}
	_, cfg := c.get("/api/config")
	text := cfg["text"].(string)
	if _, out := c.post("/api/config/validate", map[string]string{"text": text + "[[host]]\nlistener=web\npattern=console.test\naction=deny\n"}); out["ok"] == true ||
		!strings.Contains(out["error"].(string), "is the console's hostname") {
		t.Errorf("a rule for the console's name: %v", out)
	}
	// Another Host on the console's connection: not the console's.
	if code, _ := c.do("GET", "/api/status", nil, ""); code != 200 {
		t.Fatalf("status: %d", code)
	}

	save := func(text string) {
		t.Helper()
		_, now := c.get("/api/config")
		if _, out := c.post("/api/config/save", map[string]any{"text": text, "baseHash": now["hash"], "baseMtime": now["mtime"]}); out["ok"] != true {
			t.Fatalf("save: %v", out)
		}
	}
	// Delete the listener: the console moves to one of its own, and the
	// socket is handed over, so the signed-in session's next request works.
	save(head + rules)
	if l := p.srv.runtime.Load().cfg.Listener(consoleListener); l == nil || p.srv.runtime.Load().cfg.ConsoleRule().Listener != consoleListener {
		t.Fatal("the console has a listener of its own")
	}
	if code, _ := c.get("/api/status"); code != 200 {
		t.Fatalf("after its listener was deleted: %d", code)
	}
	tr.CloseIdleConnections() // a new connection, too
	if code, _ := c.get("/api/status"); code != 200 {
		t.Fatalf("new connection after the move: %d", code)
	}
	// And back.
	save(head + web + rules)
	if p.srv.runtime.Load().cfg.ConsoleRule().Listener != "web" {
		t.Fatal("back on web")
	}
	tr.CloseIdleConnections()
	if code, _ := c.get("/api/status"); code != 200 {
		t.Fatalf("back on web: %d", code)
	}
	if !strings.Contains(testLog.String(), "listener (console): takes over "+addr+" from web") || !strings.Contains(testLog.String(), "listener web: takes over "+addr+" from (console)") {
		t.Error("the port was handed over both ways, never reopened")
	}
}
