package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
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

// startConsoleProxy writes a config file with a [console] section placed
// between [global] and the rules, and starts the proxy from it.
func startConsoleProxy(t *testing.T, consoleLines, rules string) (*proxyUnderTest, *consoleClient, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	port := freePort(t)
	text := fmt.Sprintf("# top comment\n[global]\nport=1\nstats_interval=0\nreload_interval=0\n\n[console]\n# console comment\nport = %d\n%s\n\n%s", port, consoleLines, rules)
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	p := startProxyText(t, text, path)
	waitForPort(t, fmt.Sprintf("127.0.0.1:%d", port))
	jar, _ := cookiejar.New(nil)
	return p, &consoleClient{t: t, base: fmt.Sprintf("http://127.0.0.1:%d", port), http: &http.Client{Jar: jar, Timeout: T}}, path
}

func TestConsoleAuthAndRequestGuards(t *testing.T) {
	t.Parallel()
	p, c, _ := startConsoleProxy(t, "password = correct horse\nhostnames = console.example.com", "[[host]]\npattern=.*\naction=deny\n")
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
	_, c, path := startConsoleProxy(t, "password = \"s3cret pass\"  # typed by hand", "[[host]]\npattern=.*\naction=deny\n")
	data, _ := os.ReadFile(path)
	text := string(data)
	if strings.Contains(text, "s3cret") || !strings.Contains(text, "password_hash = \"pbkdf2-sha256$") {
		t.Fatalf("plaintext still on disk, or no hash:\n%s", text)
	}
	if !strings.Contains(text, "# top comment") || !strings.Contains(text, "# console comment") || !strings.Contains(text, "pattern=.*") {
		t.Fatalf("only the password line may change:\n%s", text)
	}
	if _, err := ParseConfig(text); err != nil {
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
	if strings.Contains(text, "password") || strings.Contains(text, "pbkdf2") || strings.Contains(text, "\n[console]") || strings.Contains(text, "console comment") || !strings.Contains(text, consoleHidden) {
		t.Fatalf("the [console] section must be hidden:\n%s", text)
	}
	save := func(text string, base map[string]any) (int, map[string]any) {
		return c.post("/api/config/save", map[string]any{"text": text, "baseHash": base["hash"], "baseMtime": base["mtime"]})
	}

	// Invalid text is refused, and the error names the EDITOR's line.
	broken := text + "\n[[host]]\npattern=(\ntarget_host=x.lan\n"
	wantLine := fmt.Sprintf("line %d", strings.Count(text, "\n")+2)
	if _, out := c.post("/api/config/validate", map[string]string{"text": broken}); out["ok"] == true || !strings.Contains(out["error"].(string), wantLine) {
		t.Fatalf("want an error at %s: %v", wantLine, out)
	}
	before, _ := os.ReadFile(path)
	if _, out := save(broken, cfg); out["ok"] == true {
		t.Fatal("an invalid config must not be saved")
	}
	if _, out := save(text+"\n[console]\nport=1\npassword=hacked\n", cfg); out["ok"] == true || !strings.Contains(out["error"].(string), "cannot be edited here") {
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

	// A valid save: written, backed up, [console] block kept where it was, applied at once.
	_, out = save(edited, cfg)
	if out["ok"] != true || out["backup"] == nil {
		t.Fatalf("save: %v", out)
	}
	saved, _ := os.ReadFile(path)
	st := string(saved)
	if !strings.Contains(st, "# console comment\nport = ") || !strings.Contains(st, "password_hash") || strings.Contains(st, consoleHidden) ||
		strings.Index(st, "[console]") > strings.Index(st, "[[host]]") || !strings.Contains(st, fmt.Sprintf("target_port=%d", b)) {
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
		t.Fatal("the oldest backup should be the original, with [console] hidden")
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
	rules := fmt.Sprintf("[[host]]\npattern=term\\.test\ncert=%s\nupstream_tls=false\ntarget_host=127.0.0.1\ntarget_port=%d\n"+
		"[[host]]\npattern=auto\\.test\ncert=auto\nupstream_tls=false\ntarget_host=127.0.0.1\ntarget_port=%d\n"+
		"[[host]]\npattern=pass\\.test\ntarget_host=127.0.0.1\ntarget_port=%d\n",
		ca.certDir(t, "term.test"), echoBackend(t, ""), echoBackend(t, ""), echoBackend(t, ""))
	path := filepath.Join(t.TempDir(), "config.toml")
	port := freePort(t)
	text := fmt.Sprintf("[global]\nport=1\nstats_interval=0\ncert_path=%s\nacme_agree_tos=true\nacme_directory=https://127.0.0.1:%d/dir\n[console]\nport=%d\npassword=pw\n%s", certPath, dead, port, rules)
	os.WriteFile(path, []byte(text), 0o600)
	p := startProxyText(t, text, path)
	waitForPort(t, fmt.Sprintf("127.0.0.1:%d", port))
	jar, _ := cookiejar.New(nil)
	c := &consoleClient{t: t, base: fmt.Sprintf("http://127.0.0.1:%d", port), http: &http.Client{Jar: jar, Timeout: T}}
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

	// Certificates: the directory one (managed by you) and the automatic one (failing: the CA is unreachable).
	var certs []any
	for deadline := time.Now().Add(T); ; time.Sleep(100 * time.Millisecond) {
		_, out := c.get("/api/certs")
		certs = out["certs"].([]any)
		if len(certs) == 2 && certs[1].(map[string]any)["Status"] == "failing" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("certs: %v", certs)
		}
	}
	dir, auto := certs[0].(map[string]any), certs[1].(map[string]any)
	if dir["Source"] != "directory" || dir["Status"] != "ok" || dir["Issuer"] != "test CA" || dir["Name"] != "term.test" || dir["DaysLeft"].(float64) != 0 ||
		auto["Source"] != "auto" || auto["Name"] != "auto.test" || auto["LastError"] == "" || auto["NextAttempt"] == "" {
		t.Fatalf("dir=%v\nauto=%v", dir, auto)
	}
	if code, _ := c.post("/api/certs/retry", map[string]string{"domain": "auto.test"}); code != 200 {
		t.Fatal(code)
	}
	if code, _ := c.post("/api/certs/retry", map[string]string{"domain": "not-managed.test"}); code != 400 {
		t.Fatal(code)
	}

	_, lg := c.get("/api/log?filter=TLS+terminated+here")
	lines := lg["lines"].([]any)
	if len(lines) == 0 || !strings.Contains(fmt.Sprint(lines), "TLS terminated here") || strings.Contains(fmt.Sprint(lines), "pass.test") {
		t.Fatalf("filtered log: %v", lines)
	}
}

func TestConsoleConfigValidation(t *testing.T) {
	ok := mustParse(t, "[global]\nport=1\n[console]\nlisten=192.168.1.1\nport=9000\npassword=x\nhostnames=a.example.com; B.example.com\n")
	if ok.Console.Listen != "192.168.1.1" || fmt.Sprint(ok.Console.Hostnames) != "[a.example.com b.example.com]" || len(ok.Warnings) != 1 {
		t.Fatalf("%+v %v", ok.Console, ok.Warnings) // plain HTTP off loopback is allowed, with a warning
	}
	if c := mustParse(t, "[global]\nport=1\n[console]\nport=9000\npassword=x\n"); c.Console.Listen != "127.0.0.1" || len(c.Warnings) != 0 {
		t.Fatalf("%+v %v", c.Console, c.Warnings)
	}
	if mustParse(t, "[global]\nport=1\n").Console != nil {
		t.Fatal("no [console] section = no console")
	}
	for name, text := range map[string]string{
		"no password": "[global]\nport=1\n[console]\nport=9000\n",
		"no port":     "[global]\nport=1\n[console]\npassword=x\n",
		"bad hash":    "[global]\nport=1\n[console]\nport=9000\npassword_hash=md5$abc\n",
		"unknown key": "[global]\nport=1\n[console]\nport=9000\npassword=x\ntls=true\n",
	} {
		if _, err := ParseConfig(text); err == nil {
			t.Errorf("%s: should be rejected", name)
		}
	}
	// Hiding and restoring the section is exact, wherever it sits.
	for _, text := range []string{
		"[global]\nport=1\n\n[console]\nport=2\npassword=x\n\n[[host]]\npattern=.*\naction=deny\n",
		"[global]\nport=1\n[[host]]\npattern=.*\naction=deny\n[console]\nport=2\npassword=x",
		"[global]\nport=1\n",
	} {
		visible, block, _ := hideConsole(text)
		full, _, err := showConsole(visible, block)
		if err != nil || full != text || strings.Contains(visible, "password") {
			t.Errorf("round trip failed for %q: %q (%v)", text, full, err)
		}
	}
}
