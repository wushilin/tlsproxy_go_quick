package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

// wsFrames connects to the console's state WebSocket and returns a reader of text frames.
func wsFrames(t *testing.T, c *consoleClient) func() map[string]any {
	t.Helper()
	return wsFramesAt(t, c, "/api/ws")
}

func wsFramesAt(t *testing.T, c *consoleClient, path string) func() map[string]any {
	t.Helper()
	conn, err := c.dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	key := make([]byte, 16)
	rand.Read(key)
	var cookies []string
	for _, ck := range c.http.Jar.Cookies(mustURL(c.base)) {
		cookies = append(cookies, ck.Name+"="+ck.Value)
	}
	io.WriteString(conn, "GET "+consolePath+path+" HTTP/1.1\r\nHost: "+c.hostPort()+"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: "+base64.StdEncoding.EncodeToString(key)+"\r\nCookie: "+strings.Join(cookies, "; ")+"\r\n\r\n")
	rd := bufio.NewReader(conn)
	status, _ := rd.ReadString('\n')
	if !strings.Contains(status, "101") {
		t.Fatalf("upgrade: %q", status)
	}
	for l, _ := rd.ReadString('\n'); l != "\r\n"; l, _ = rd.ReadString('\n') {
	}
	return func() map[string]any {
		t.Helper()
		for {
			conn.SetReadDeadline(time.Now().Add(T))
			var hdr [2]byte
			if _, err := io.ReadFull(rd, hdr[:]); err != nil {
				t.Fatal(err)
			}
			n := int(hdr[1] & 0x7f)
			switch n {
			case 126:
				var b [2]byte
				io.ReadFull(rd, b[:])
				n = int(b[0])<<8 | int(b[1])
			case 127:
				var b [8]byte
				io.ReadFull(rd, b[:])
				n = 0
				for _, x := range b {
					n = n<<8 | int(x)
				}
			}
			payload := make([]byte, n)
			io.ReadFull(rd, payload)
			if hdr[0]&0x0f != wsOpText {
				continue
			}
			var m map[string]any
			if err := json.Unmarshal(payload, &m); err != nil {
				t.Fatal(err)
			}
			return m
		}
	}
}

// ruleOf finds a rule in a state frame by pattern.
func ruleOf(t *testing.T, state map[string]any, pattern string) map[string]any {
	t.Helper()
	for _, l := range state["listeners"].([]any) {
		for _, r := range l.(map[string]any)["rules"].([]any) {
			if r := r.(map[string]any); r["pattern"] == pattern {
				return r
			}
		}
	}
	t.Fatalf("no rule %s in %v", pattern, state["listeners"])
	return nil
}

// The whole loop: live frames over the WebSocket, stop/start falling through
// to the next rule, stopping one connection, and add/edit/delete through the
// file with conflict detection.
func TestConsoleRuleManager(t *testing.T) {
	t.Parallel()
	a, b := echoBackend(t, "A:"), echoBackend(t, "B:")
	rules := "[[host]]\nlistener = default\npattern = svc.rulemgr.test\ntarget_host = 127.0.0.1\ntarget_port = " + strconv.Itoa(a) +
		"\n\n[[host]]\nlistener = default\npattern = *.rulemgr.test\ntarget_host = 127.0.0.1\ntarget_port = " + strconv.Itoa(b) + "\n"
	p, c, path := startConsoleProxy(t, "password = pw", rules)
	if c.login("pw") != 200 {
		t.Fatal("login")
	}
	next := wsFrames(t, c)
	first := next()
	if f := first["file"].(map[string]any); f["editable"] != true || f["hash"] == "" {
		t.Fatalf("file: %v", f)
	}

	// A live connection shows up under its rule.
	conn := dial(t, p)
	conn.Write(clientHello("svc.rulemgr.test"))
	readN(t, conn, len("A:"))
	var r map[string]any
	for deadline := time.Now().Add(T); ; {
		if r = ruleOf(t, next(), "svc.rulemgr.test"); r["connCount"].(float64) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("connection never appeared")
		}
	}
	id := r["connections"].([]any)[0].(map[string]any)["id"].(float64)

	// Stopping the connection closes it.
	if code, out := c.post("/api/connections/stop", map[string]any{"id": id}); code != 200 {
		t.Fatal(code, out)
	}
	readToEnd(t, conn)
	if reason := closeReason(t, "svc.rulemgr.test"); reason != "stopped from the console; closed by proxy" {
		t.Fatal(reason)
	}

	// Stopping the rule: svc.rulemgr.test falls through to *.rulemgr.test; an open connection is closed.
	conn = dial(t, p)
	conn.Write(clientHello("svc.rulemgr.test"))
	readN(t, conn, len("A:"))
	key := r["key"].(string)
	if code, out := c.post("/api/rules/stop", map[string]any{"key": key}); code != 200 {
		t.Fatal(code, out)
	}
	readToEnd(t, conn)
	roundtrip(t, p, "svc.rulemgr.test", "B:")
	for deadline := time.Now().Add(T); ; { // frames queued before the stop come first
		r := ruleOf(t, next(), "svc.rulemgr.test")
		if r["stopped"] == true {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(r)
		}
	}
	c.post("/api/rules/start", map[string]any{"key": key})
	roundtrip(t, p, "svc.rulemgr.test", "A:")

	// Edit through the file: point svc.rulemgr.test at B. A stale version is refused.
	f := first["file"].(map[string]any)
	line := r["line"].(float64)
	vals := map[string]any{"target": "127.0.0.1:" + strconv.Itoa(b)}
	if code, _ := c.post("/api/rules/save", map[string]any{"line": line, "baseHash": "x", "baseMtime": f["mtime"], "values": vals}); code != 409 {
		t.Fatal("stale save accepted", code)
	}
	if _, out := c.post("/api/rules/validate", map[string]any{"line": line, "values": map[string]any{"target": "127.0.0.1:70000"}}); out["ok"] != false || out["error"] == "" {
		t.Fatal("bad port validated", out)
	}
	_, out := c.post("/api/rules/validate", map[string]any{"line": line, "values": vals, "snis": []string{"svc.rulemgr.test", "x.rulemgr.test"}})
	if out["ok"] != true || !strings.Contains(out["block"].(string), "target: 127.0.0.1:"+strconv.Itoa(b)) {
		t.Fatal(out)
	}
	if routes := out["routes"].([]any); routes[0].(map[string]any)["thisRule"] != true || routes[1].(map[string]any)["thisRule"] != false {
		t.Fatal(routes)
	}
	if code, out := c.post("/api/rules/save", map[string]any{"line": line, "baseHash": f["hash"], "baseMtime": f["mtime"], "values": vals}); code != 200 || out["ok"] != true {
		t.Fatal(code, out)
	}
	for deadline := time.Now().Add(T); ; time.Sleep(50 * time.Millisecond) {
		cn := dial(t, p)
		cn.Write(clientHello("svc.rulemgr.test"))
		if string(readN(t, cn, 2)) == "B:" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("edit never applied")
		}
	}
	text, _ := os.ReadFile(path)
	if !strings.Contains(string(text), "# top comment\n") || len(backupFiles(path)) != 1 {
		t.Fatalf("file:\n%s", text)
	}

	// Delete it: svc.rulemgr.test goes to *.rulemgr.test for good.
	st := next()
	for ruleOf(t, st, "svc.rulemgr.test")["values"].(map[string]any)["target"] != "127.0.0.1:"+strconv.Itoa(b) {
		st = next()
	}
	f = st["file"].(map[string]any)
	if code, out := c.post("/api/rules/delete", map[string]any{"line": line, "baseHash": f["hash"], "baseMtime": f["mtime"]}); code != 200 || out["ok"] != true {
		t.Fatal(code, out)
	}
	text, _ = os.ReadFile(path)
	if strings.Contains(string(text), "svc.rulemgr.test") {
		t.Fatalf("not deleted:\n%s", text)
	}
}

// The page and everything it references are served, without signing in.
func TestConsolePageAssets(t *testing.T) {
	t.Parallel()
	_, c, _ := startConsoleProxy(t, "password = pw", "[[host]]\nlistener=default\npattern=ANY\naction=deny\n")
	page, err := c.http.Get(c.base + "/")
	if err != nil || page.StatusCode != 200 {
		t.Fatal(err, page.Status)
	}
	html, _ := io.ReadAll(page.Body)
	page.Body.Close()
	if csp := page.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "connect-src 'self' ws://"+c.hostPort()) {
		t.Fatal(csp)
	}
	refs := regexp.MustCompile(`(?:src|href)="([^"#:]+)"`).FindAllStringSubmatch(string(html), -1)
	if len(refs) < 3 {
		t.Fatalf("only %d assets referenced", len(refs))
	}
	for _, m := range refs {
		resp, err := c.http.Get(c.base + "/" + m[1])
		if err != nil || resp.StatusCode != 200 {
			t.Errorf("%s: %v %v", m[1], err, resp.Status)
		}
		resp.Body.Close()
	}

	// Everything lives under consolePath: / and the bare path redirect there,
	// nothing else is served.
	noFollow := &http.Client{Transport: c.http.Transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Timeout: T}
	for path, want := range map[string]string{"/": consolePath + "/", consolePath: consolePath + "/", "/api/state": "", "/app.js": ""} {
		resp, err := noFollow.Get("https://" + c.hostPort() + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if loc := resp.Header.Get("Location"); want != "" && (resp.StatusCode/100 != 3 || loc != want) {
			t.Errorf("%s: %s -> %q, want a redirect to %s", path, resp.Status, loc, want)
		} else if want == "" && resp.StatusCode != 404 {
			t.Errorf("%s: %s, want 404", path, resp.Status)
		}
	}
}
