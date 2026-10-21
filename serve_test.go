package main

import (
	"bufio"
	"context"
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const serveHead = "[[listener]]\nname=default\nport=1\n[global]\nacme_agree_tos=true\n"

func TestServeConfig(t *testing.T) {
	t.Parallel()
	head := "global:\n  acme_agree_tos: true\nlisteners:\n  - {name: default, port: 1}\n"
	cfg := mustParse(t, head+`routes:
  - listener: default
    rules:
      - domain: www.test
        cert: auto
        serve:
          - {type: reverse_proxy, prefix: /, target: "http://127.0.0.1:8080"}
          - type: reverse_proxy
            prefix: /api/
            target: https://api.lan
            strip_prefix: true
            force_host: x.lan
            tls_verify: false
            basic_auth: team
          - {type: static_content, prefix: /static/, base_dir: /opt/www/static}
basic_auth:
  - name: team
    users:
      - {username: jack, password_plain: secret}
      - {username: jill, password_hash: "`+mustHash(t, "pw")+`"}
`)
	r := &cfg.Rules[0]
	if !r.Serves() || r.UpstreamTLS || len(r.Routes) != 3 {
		t.Fatalf("rule: serves=%v upstream_tls=%v routes=%d", r.Serves(), r.UpstreamTLS, len(r.Routes))
	}
	if got := r.RouteFor("/api/x"); got == nil || got.Key != "serve 2" || !got.StripPrefix || got.ForceHost != "x.lan" || got.TLSVerify || got.TargetAddr() != "api.lan:443" || got.auth == nil {
		t.Fatalf("the longest prefix wins, with its options: %+v", got)
	}
	if got := r.RouteFor("/static/a.css"); got == nil || got.BaseDir != "/opt/www/static" {
		t.Fatalf("static: %+v", got)
	}
	if got := r.RouteFor("/other"); got == nil || got.TargetAddr() != "127.0.0.1:8080" {
		t.Fatalf("/ catches the rest: %+v", got)
	}
	team := cfg.BasicAuth["team"]
	if team.Users["jack"].plain != "secret" || team.Users["jill"].hash == "" {
		t.Fatalf("users: %+v", team.Users)
	}
	if d := cfg.Route("www.test"); !d.Allow || d.Rule != r || d.Host != "" {
		t.Fatalf("a serving rule routes without a target: %+v", d)
	}

	rule := "routes:\n  - listener: default\n    rules:\n      - domain: www.test\n        cert: auto\n"
	serve := func(entries ...string) string { return rule + "        serve: [" + strings.Join(entries, ", ") + "]\n" }
	auth := func(users string) string { return "basic_auth:\n  - name: a\n    users: [" + users + "]\n" }
	for text, want := range map[string]string{
		serve("{type: ftp, prefix: /}"):                                                                             "type must be",
		serve("{prefix: /}"):                                                                                        "type is required",
		serve("{type: reverse_proxy, target: \"http://h\"}"):                                                        "prefix is required",
		serve("{type: reverse_proxy, prefix: /}"):                                                                   "needs target: http://host:port",
		serve("{type: reverse_proxy, prefix: /, target: \"ftp://h\"}"):                                              "http:// or https://",
		serve("{type: reverse_proxy, prefix: /, target: \"http://h/base\"}"):                                        "scheme://host:port only",
		serve("{type: reverse_proxy, prefix: /, target: \"http://h\", tls_verify: false}"):                          "only applies to an https:// target",
		serve("{type: reverse_proxy, prefix: /, target: \"http://h\", base_dir: /x}"):                               "base_dir only applies to type: static_content",
		serve("{type: static_content, prefix: /}"):                                                                  "needs base_dir",
		serve("{type: static_content, prefix: /x, base_dir: /x}"):                                                   "ends with /",
		serve("{type: static_content, prefix: /, base_dir: /x, strip_prefix: true}"):                                "strip_prefix only applies to type: reverse_proxy",
		serve("{type: static_content, prefix: /, base_dir: /x, colour: red}"):                                       `unknown key "colour" in a serve entry`,
		serve("{type: static_content, prefix: x, base_dir: /x}"):                                                    "starting with /",
		serve("{type: static_content, prefix: /, base_dir: /x, basic_auth: nope}"):                                  "no basic_auth named nope",
		serve("{type: static_content, prefix: /, base_dir: /x}", "{type: static_content, prefix: /, base_dir: /y}"): "already served by serve 1",
		serve("{type: static_content, prefix: /, base_dir: /x}") + "        target: \"h:1\"\n":                      "target does not apply",
		serve("{type: static_content, prefix: /, base_dir: /x}") + "        upstream_tls: false\n":                  "upstream_tls does not apply",
		serve("{type: static_content, prefix: /, base_dir: /x}") + "        proxy: v2\n":                            "proxy does not apply",
		serve("{type: static_content, prefix: /, base_dir: /x}") + "        action: deny\n":                         "action: allow",
		strings.Replace(serve("{type: static_content, prefix: /, base_dir: /x}"), "        cert: auto\n", "", 1):    "serve needs cert: auto or cert: local-ca",
		serve("x"): "a serve entry must be a mapping",
		"basic_auth:\n  - users: [{username: a, password_plain: b}]\n":             "name is required",
		"basic_auth:\n  - name: a\n":                                               "no users",
		auth("{password_plain: b}"):                                                "username is required",
		auth("{username: a}"):                                                      "password_plain or password_hash is required",
		auth("{username: a, password_plain: b, password_hash: c}"):                 "not both",
		auth("{username: a, password_hash: nope}"):                                 "not an argon2id",
		auth("{username: \"a:b\", password_plain: x}"):                             "without a colon",
		auth("{username: a, password_plain: x}, {username: a, password_plain: y}"): "listed twice",
		auth("{username: a, password: x}"):                                         `unknown key "password" in a user`,
		"basic_auth:\n  - {name: a, users: [{username: a, password_plain: x}]}\n  - {name: a, users: [{username: b, password_plain: x}]}\n": "already used",
	} {
		if _, err := ParseConfig(head + text); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s:\n  %v, want %q", text, err, want)
		}
	}
}

func TestPasswordHashes(t *testing.T) {
	t.Parallel()
	h, err := hashPassword("pw")
	if err != nil || !strings.HasPrefix(h, "$argon2id$v=19$m=64,t=1,p=1$") || validHash(h) != nil {
		t.Fatalf("new hashes are argon2id: %q %v", h, err)
	}
	if !checkPassword(h, "pw") || checkPassword(h, "pW") {
		t.Fatal("argon2id check")
	}
	// A published argon2id vector (password "password", salt "somesalt",
	// t=1, m=64, p=1) as a PHC string, the way other tools write them.
	vector := "$argon2id$v=19$m=64,t=1,p=1$c29tZXNhbHQ$ZVrRXqxlLcWfcXCnMyv0m4Rpvh/bnCi7"
	if !checkPassword(vector, "password") || checkPassword(vector, "Password") {
		t.Fatal("a hash written elsewhere")
	}
	salt := []byte("0123456789abcdef")
	key, err := pbkdf2.Key(sha256.New, "pw", salt, pbkdf2Iterations, 32)
	if err != nil {
		t.Fatal(err)
	}
	old := fmt.Sprintf("%s$%d$%s$%s", hashPrefix, pbkdf2Iterations, b64(salt), b64(key))
	if validHash(old) != nil || !checkPassword(old, "pw") || checkPassword(old, "x") {
		t.Fatal("pbkdf2-sha256 hashes still work")
	}
	for hash, want := range map[string]string{
		"$argon2id$v=19$m=4194304,t=1,p=1$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG": "m (memory in KiB)",
		"$argon2id$v=16$m=64,t=1,p=1$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG":      "only v=19",
		"$argon2i$v=19$m=64,t=1,p=1$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG":       "not an argon2id",
		"$argon2id$v=19$m=64,t=1$c29tZXNhbHQ":                                           "wrong number",
	} {
		if err := validHash(hash); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", hash, err, want)
		}
	}
}

func b64(b []byte) string { return base64.RawStdEncoding.EncodeToString(b) }

// httpEcho answers with what it received.
func httpEcho(t *testing.T) int {
	l, port := listen(t)
	go http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "path=%s host=%s xff=%s proto=%s fwd=%s auth=%s", r.URL.RequestURI(), r.Host, r.Header.Get("X-Forwarded-For"),
			r.Header.Get("X-Forwarded-Proto"), r.Header.Get("Forwarded"), r.Header.Get("Authorization"))
	}))
	return port
}

// serveClient is an HTTPS client that connects every name to the proxy and
// trusts the test CA; h2 says whether it offers HTTP/2.
func serveClient(p *proxyUnderTest, ca *testCA, h2 bool) *http.Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: T}).DialContext(ctx, "tcp", p.addr)
		},
		TLSClientConfig:   &tls.Config{RootCAs: ca.pool},
		ForceAttemptHTTP2: h2,
	}
	if !h2 {
		tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	return &http.Client{Transport: tr, Timeout: T, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func httpsGet(t *testing.T, c *http.Client, url string, header ...string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	for i := 0; i+1 < len(header); i += 2 {
		if header[i] == "Host" {
			req.Host = header[i+1]
		} else {
			req.Header.Set(header[i], header[i+1])
		}
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

func TestServeRules(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "index.html"), []byte("home"), 0o644)
	os.WriteFile(filepath.Join(root, "a.txt"), []byte("A"), 0o644)
	os.WriteFile(filepath.Join(root, ".env"), []byte("secret"), 0o644)
	os.MkdirAll(filepath.Join(root, "empty"), 0o755)
	os.MkdirAll(filepath.Join(root, "sub"), 0o755)
	os.WriteFile(filepath.Join(root, "sub", "index.html"), []byte("sub"), 0o644)
	os.MkdirAll(filepath.Join(root, ".well-known"), 0o755)
	os.WriteFile(filepath.Join(root, ".well-known", "security.txt"), []byte("sec"), 0o644)
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "x"), []byte("outside"), 0o644)
	os.Symlink(filepath.Join(outside, "x"), filepath.Join(root, "escape"))
	a, dead := httpEcho(t), freePort(t)
	p := startProxy(t, "", fmt.Sprintf(`[[host]]
listener=default
pattern=www.test
cert=%[1]s
service_rule1 = type=reverse_proxy; prefix=/; target=http://127.0.0.1:%[2]d
service_rule2 = type=reverse_proxy; prefix=/api/; target=http://127.0.0.1:%[2]d; strip_prefix=true; force_host=backend.lan
service_rule3 = type=static_content; prefix=/files/; base_dir=%[3]s
service_rule4 = type=reverse_proxy; prefix=/private/; target=http://127.0.0.1:%[2]d; basic_auth=team
service_rule5 = type=reverse_proxy; prefix=/dead/; target=http://127.0.0.1:%[4]d
service_rule6 = type=static_content; prefix=/missing/; base_dir=%[3]s/nothing-here
[[host]]
listener=default
pattern=other.test
cert=%[1]s
target_host=127.0.0.1
target_port=%[2]d
upstream_tls=false
[[basic_auth]]
name=team
user1=username=jack;password_hash=%[5]s
user2=username=jill;password_plain=open sesame
`, ca.localCA(t), a, root, dead, mustHash(t, "pw")))

	for _, h2 := range []bool{false, true} {
		c := serveClient(p, ca, h2)
		proto := map[bool]string{false: "HTTP/1.1", true: "HTTP/2.0"}[h2]
		check := func(path, want string, header ...string) {
			t.Helper()
			resp, body := httpsGet(t, c, "https://www.test"+path, header...)
			if resp.Proto != proto {
				t.Errorf("%s: %s, want %s", path, resp.Proto, proto)
			}
			got := fmt.Sprint(resp.StatusCode)
			if resp.StatusCode == 200 {
				got += " " + body
			} else if loc := resp.Header.Get("Location"); loc != "" {
				got += " " + loc
			}
			if got != want {
				t.Errorf("%s %s:\n  %s\nwant %s", proto, path, got, want)
			}
		}
		// The client's address is the connection's; what it claims is replaced.
		check("/x?q=1", "200 path=/x?q=1 host=www.test xff=127.0.0.1 proto=https fwd=for=127.0.0.1;host=www.test;proto=https auth=", "X-Forwarded-For", "6.6.6.6", "Forwarded", "for=6.6.6.6")
		check("/api/v1/y", "200 path=/v1/y host=backend.lan xff=127.0.0.1 proto=https fwd=for=127.0.0.1;host=www.test;proto=https auth=")
		check("/api", "301 /api/")
		check("/files/", "200 home")
		check("/files/a.txt", "200 A")
		check("/files/sub/", "200 sub")
		check("/files/sub", "301 /files/sub/")
		check("/files/.well-known/security.txt", "200 sec")
		check("/files/.env", "404")
		check("/files/empty/", "403") // no index, no directory_listing
		check("/files/escape", "404")
		check("/files/nope", "404")
		check("/missing/a", "503")
		check("/dead/", "502")
		check("/private/z", "401")
		check("/private/z", "401", "Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("jack:wrong")))
		check("/private/z", "200 path=/private/z host=www.test xff=127.0.0.1 proto=https fwd=for=127.0.0.1;host=www.test;proto=https auth=", "Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("jack:pw")))
		check("/private/z", "200 path=/private/z host=www.test xff=127.0.0.1 proto=https fwd=for=127.0.0.1;host=www.test;proto=https auth=", "Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("jill:open sesame")))
		// A Host that another rule serves, on this connection: 421, so the
		// client asks on a connection of its own.
		check("/x", "421", "Host", "other.test")
	}
	if resp, _ := httpsGet(t, serveClient(p, ca, false), "https://www.test/private/"); resp.Header.Get("WWW-Authenticate") != `Basic realm="www.test", charset="UTF-8"` {
		t.Errorf("realm: %q", resp.Header.Get("WWW-Authenticate"))
	}
	// POST to static files is refused; to the proxy it goes through.
	c := serveClient(p, ca, false)
	if resp, err := c.Post("https://www.test/files/a.txt", "text/plain", strings.NewReader("x")); err != nil || resp.StatusCode != 405 {
		t.Errorf("POST to files: %v %v", resp, err)
	}
	if resp, err := c.Post("https://www.test/api/p", "text/plain", strings.NewReader("x")); err != nil || resp.StatusCode != 200 {
		t.Errorf("POST through the proxy: %v %v", resp, err)
	}
	if !strings.Contains(testLog.String(), "GET www.test/files/a.txt -> 200 via serve 3") {
		t.Error("each request is logged with the service rule that served it")
	}
}

// A reload applies to the next request on a connection already open.
func TestServeRulesReloadOnOpenConnection(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	a, b := httpEcho(t), httpEcho(t)
	rules := "[[host]]\nlistener=default\npattern=www.test\ncert=%s\nservice_rule1 = type=reverse_proxy; prefix=/; target=http://127.0.0.1:%d; force_host=%s\n"
	head := "[[listener]]\nname=default\nport=1\n[global]\nstats_interval=0\nca_root=" + testCARoot() + "\n"
	path := filepath.Join(t.TempDir(), "config.toml")
	text := head + fmt.Sprintf(rules, ca.localCA(t), a, "first")
	os.WriteFile(path, []byte(text), 0o600)
	p := startProxyText(t, text, path)
	c := serveClient(p, ca, false)
	if _, body := httpsGet(t, c, "https://www.test/"); !strings.Contains(body, "host=first") {
		t.Fatal(body)
	}
	os.WriteFile(path, []byte(yamlFixture(head+fmt.Sprintf(rules, ca.localCA(t), b, "second"))), 0o600)
	var hash string
	have := false
	if problems := p.srv.reload(path, &hash, &have); problems != nil {
		t.Fatal(problems)
	}
	if _, body := httpsGet(t, c, "https://www.test/"); !strings.Contains(body, "host=second") {
		t.Fatal("the same connection uses the new rule:", body)
	}
	if n := p.srv.stats.Accepted.Load(); n != 1 {
		t.Errorf("both requests on one connection: %d connections terminated", n)
	}
}

// A base_dir made after the configuration was loaded is served without a
// reload: a request tries to open it again.
func TestServeBaseDirMadeLater(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	dir := filepath.Join(t.TempDir(), "site")
	text := "[[listener]]\nname=default\nport=1\n[global]\nstats_interval=0\nca_root=" + testCARoot() + "\n" +
		"[[host]]\nlistener=default\npattern=www.test\ncert=" + ca.localCA(t) + "\nservice_rule1 = type=static_content; prefix=/; base_dir=" + dir + "\n"
	p := startProxyText(t, text, "")
	c := serveClient(p, ca, false)
	if resp, _ := httpsGet(t, c, "https://www.test/index.html"); resp.StatusCode != 503 {
		t.Fatalf("no folder yet: %d", resp.StatusCode)
	}
	os.Mkdir(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "index.html"), []byte("hello"), 0o644)
	time.Sleep(1100 * time.Millisecond) // tried again at most once a second
	if resp, body := httpsGet(t, c, "https://www.test/"); resp.StatusCode != 200 || body != "hello" {
		t.Fatalf("folder made: %d %q", resp.StatusCode, body)
	}
}

// A folder: its index.html, else its index.htm, else a listing where
// directory_listing allows one, else 403.
func TestServeFolders(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	dir := t.TempDir()
	for name, body := range map[string]string{
		"html/index.html": "from html", "html/index.htm": "not this", "htm/index.htm": "from htm",
		"list/a b.txt": "x", "list/a&b.png": "y", "list/.secret": "z", "list/sub/f": "", "none/f": "",
	} {
		os.MkdirAll(filepath.Join(dir, filepath.Dir(name)), 0o755)
		os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644)
	}
	text := "[[listener]]\nname=default\nport=1\n[global]\nstats_interval=0\nca_root=" + testCARoot() + "\n" +
		"[[host]]\nlistener=default\npattern=www.test\ncert=" + ca.localCA(t) +
		"\nservice_rule1 = type=static_content; prefix=/; base_dir=" + dir +
		"\nservice_rule2 = type=static_content; prefix=/list/; base_dir=" + filepath.Join(dir, "list") + "; directory_listing=true\n"
	p := startProxyText(t, text, "")
	c := serveClient(p, ca, false)
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for url, want := range map[string]string{
		"https://www.test/html/": "200 from html",
		"https://www.test/htm/":  "200 from htm",
		"https://www.test/none/": "403",
		"https://www.test/":      "403", // the top too
		"https://www.test/htm":   "301",
		"https://www.test/list/": "200 listing",
	} {
		resp, body := httpsGet(t, c, url)
		got := fmt.Sprint(resp.StatusCode)
		if strings.HasPrefix(want, "200 from") {
			got += " " + body
		} else if want == "200 listing" && strings.Contains(body, "Index of") {
			got += " listing"
		}
		if got != want {
			t.Errorf("%s: %s, want %s", url, got, want)
		}
		if sv := resp.Header.Get("Server"); sv != serverName {
			t.Errorf("%s: Server %q", url, sv)
		}
		if want == "200 listing" {
			for _, in := range []string{`href="a%20b.txt"`, ">a&amp;b.png<", `href="sub/"`, `data-kind="image"`} {
				if !strings.Contains(body, in) {
					t.Errorf("listing lacks %s", in)
				}
			}
			if strings.Contains(body, "secret") || strings.Contains(body, ">a&b.png<") {
				t.Error("listing shows a hidden file or an unescaped name")
			}
			if !strings.Contains(resp.Header.Get("Content-Security-Policy"), "default-src 'none'") {
				t.Error("listing without its CSP")
			}
			if !strings.Contains(body, `href="`+repoURL+`"`) {
				t.Error("listing without the link to the repository")
			}
		}
	}
}

// The whole path without SNI: a client connects from 127.0.0.2 and checks
// the certificate against the IP it dialed; the NONE rule serves itself,
// and the upstream sees the client's own address.
func TestNoSNIServeEndToEnd(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	a := httpEcho(t)
	p := startProxy(t, "", fmt.Sprintf("[[host]]\nlistener=default\npattern=NONE\ncert=%s\nservice_rule1 = type=reverse_proxy; prefix=/; target=http://127.0.0.1:%d\n", ca.localCA(t), a))
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}, Timeout: T}
	raw, err := d.Dial("tcp", p.addr)
	if err != nil {
		t.Skip("cannot connect from 127.0.0.2 here:", err)
	}
	defer raw.Close()
	// ServerName is an IP: Go sends no SNI and verifies the IP address SAN.
	tc := tls.Client(raw, &tls.Config{RootCAs: ca.pool, ServerName: "127.0.0.1"})
	tc.SetDeadline(time.Now().Add(T))
	if err := tc.Handshake(); err != nil {
		t.Fatal("the IP certificate verifies:", err)
	}
	fmt.Fprint(tc, "GET /hello HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Forwarded-For: 6.6.6.6\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if want := "path=/hello host=127.0.0.1 xff=127.0.0.2 proto=https fwd=for=127.0.0.2;host=127.0.0.1;proto=https auth="; string(body) != want {
		t.Fatalf("%s\nwant %s", body, want)
	}
}

// The console's Basic auth page: a password set there is the one a served
// page asks for, at once.
func TestConsoleBasicAuthPage(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	a := httpEcho(t)
	p, c, _ := startConsoleProxy(t, "password = pw", fmt.Sprintf("[[host]]\nlistener=default\npattern=www.test\ncert=%s\n"+
		"service_rule1 = type=reverse_proxy; prefix=/; target=http://127.0.0.1:%d; basic_auth=team\n"+
		"[[basic_auth]]\nname=team\nuser1=username=jack; password_plain=old\n", ca.localCA(t), a))
	if c.login("pw") != 200 {
		t.Fatal("sign-in")
	}
	_, list := c.get("/api/auth")
	g := list["groups"].([]any)[0].(map[string]any)
	if g["name"] != "team" || g["users"].([]any)[0].(map[string]any)["plain"] != true || len(g["usedBy"].([]any)) != 1 {
		t.Fatalf("groups: %v", list)
	}
	if strings.Contains(fmt.Sprint(list), "old") {
		t.Fatal("no password is sent to the page")
	}
	f := list["file"].(map[string]any)
	if _, out := c.post("/api/auth/save", map[string]any{"op": "set_password", "group": "team", "user": "jack", "password": "n3w pass", "baseHash": f["hash"], "baseMtime": f["mtime"]}); out["ok"] != true {
		t.Fatalf("set_password: %v", out)
	}
	if code, _ := c.post("/api/auth/save", map[string]any{"op": "add_user", "group": "team", "user": "x", "password": "p", "baseHash": f["hash"], "baseMtime": f["mtime"]}); code != 409 {
		t.Fatalf("a stale version is refused: %d", code)
	}
	web := serveClient(p, ca, false)
	try := func(pw string) int {
		for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(50 * time.Millisecond) {
			resp, _ := httpsGet(t, web, "https://www.test/", "Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("jack:"+pw)))
			if resp.StatusCode == 200 || time.Now().After(deadline) {
				return resp.StatusCode
			}
		}
	}
	if code := try("n3w pass"); code != 200 {
		t.Fatalf("the new password: %d", code)
	}
	if resp, _ := httpsGet(t, web, "https://www.test/", "Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("jack:old"))); resp.StatusCode != 401 {
		t.Fatalf("the old password: %d", resp.StatusCode)
	}
	_, list = c.get("/api/auth")
	if list["groups"].([]any)[0].(map[string]any)["users"].([]any)[0].(map[string]any)["plain"] != false {
		t.Fatal("now a hash")
	}
	_, st := c.get("/api/state")
	if fmt.Sprint(st["authGroups"]) != "[team]" {
		t.Fatalf("the rule editor's groups: %v", st["authGroups"])
	}
}

// Static files take byte ranges (one, several, If-Range, out of range), and
// conditional requests, over HTTP/1.1 and HTTP/2; index.html too.
func TestServeRanges(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "f.txt"), []byte("0123456789"), 0o644)
	os.WriteFile(filepath.Join(dir, "index.html"), []byte("<p>home</p>"), 0o644)
	text := "[[listener]]\nname=default\nport=1\n[global]\nstats_interval=0\nca_root=" + testCARoot() + "\n" +
		"[[host]]\nlistener=default\npattern=www.test\ncert=" + ca.localCA(t) + "\nservice_rule1 = type=static_content; prefix=/; base_dir=" + dir + "\n"
	p := startProxyText(t, text, "")
	for _, h2 := range []bool{false, true} {
		c := serveClient(p, ca, h2)
		resp, body := httpsGet(t, c, "https://www.test/f.txt", "Range", "bytes=2-4")
		if resp.StatusCode != 206 || body != "234" || resp.Header.Get("Content-Range") != "bytes 2-4/10" || resp.ProtoMajor != map[bool]int{false: 1, true: 2}[h2] {
			t.Errorf("h2=%v one range: %d %s %q %q", h2, resp.StatusCode, resp.Proto, body, resp.Header.Get("Content-Range"))
		}
		if resp, body := httpsGet(t, c, "https://www.test/f.txt", "Range", "bytes=-3"); resp.StatusCode != 206 || body != "789" {
			t.Errorf("h2=%v suffix range: %d %q", h2, resp.StatusCode, body)
		}
		if resp, body := httpsGet(t, c, "https://www.test/f.txt", "Range", "bytes=0-1,8-9"); resp.StatusCode != 206 ||
			!strings.HasPrefix(resp.Header.Get("Content-Type"), "multipart/byteranges") || !strings.Contains(body, "01") || !strings.Contains(body, "89") {
			t.Errorf("h2=%v two ranges: %d %s", h2, resp.StatusCode, resp.Header.Get("Content-Type"))
		}
		if resp, _ := httpsGet(t, c, "https://www.test/f.txt", "Range", "bytes=20-30"); resp.StatusCode != 416 {
			t.Errorf("h2=%v out of range: %d", h2, resp.StatusCode)
		}
		last := resp.Header.Get("Last-Modified")
		if resp, _ := httpsGet(t, c, "https://www.test/f.txt", "If-Modified-Since", last); resp.StatusCode != 304 {
			t.Errorf("h2=%v If-Modified-Since: %d", h2, resp.StatusCode)
		}
		if resp, body := httpsGet(t, c, "https://www.test/f.txt", "Range", "bytes=0-0", "If-Range", "Mon, 01 Jan 2001 00:00:00 GMT"); resp.StatusCode != 200 || body != "0123456789" {
			t.Errorf("h2=%v stale If-Range sends it all: %d %q", h2, resp.StatusCode, body)
		}
		if resp, body := httpsGet(t, c, "https://www.test/", "Range", "bytes=3-6"); resp.StatusCode != 206 || body != "home" {
			t.Errorf("h2=%v index.html range: %d %q", h2, resp.StatusCode, body)
		}
	}
}

// What a reverse_proxy tells its backend: the client, the name and port it
// asked for, the prefix strip_prefix took, and who forwarded it. What the
// client claimed in the same headers is replaced.
func TestServeForwardingHeaders(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	l, port := listen(t)
	names := []string{"X-Forwarded-For", "X-Real-IP", "X-Forwarded-Proto", "X-Forwarded-Host", "X-Forwarded-Port",
		"X-Forwarded-Prefix", "Forwarded", "X-Forwarded-By", "Via"}
	go http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, n := range names {
			fmt.Fprintf(w, "%s: %s\n", n, strings.Join(r.Header.Values(n), ", "))
		}
	}))
	text := "[[listener]]\nname=default\nport=1\n[global]\nstats_interval=0\nca_root=" + testCARoot() + "\n" +
		"[[host]]\nlistener=default\npattern=www.test\ncert=" + ca.localCA(t) +
		fmt.Sprintf("\nservice_rule1 = type=reverse_proxy; prefix=/; target=http://127.0.0.1:%d\nservice_rule2 = type=reverse_proxy; prefix=/api/; target=http://127.0.0.1:%d; strip_prefix=true\n", port, port)
	p := startProxyText(t, text, "")
	_, proxyPort, _ := net.SplitHostPort(p.addr)
	by := "tlsproxy_go_quick/" + strings.TrimPrefix(version, "v")
	for _, h2 := range []bool{false, true} {
		via := map[bool]string{false: "1.1", true: "2.0"}[h2] + " tlsproxy_go_quick"
		c := serveClient(p, ca, h2)
		spoof := []string{"X-Forwarded-For", "6.6.6.6", "X-Forwarded-Host", "evil", "X-Forwarded-Port", "1", "X-Forwarded-Prefix", "/evil", "Forwarded", "for=6.6.6.6", "X-Forwarded-By", "evil"}
		for path, prefix := range map[string]string{"/x": "", "/api/x": "/api"} {
			_, body := httpsGet(t, c, "https://www.test"+path, spoof...)
			want := "X-Forwarded-For: 127.0.0.1\nX-Real-IP: 127.0.0.1\nX-Forwarded-Proto: https\nX-Forwarded-Host: www.test\n" +
				"X-Forwarded-Port: " + proxyPort + "\nX-Forwarded-Prefix: " + prefix + "\nForwarded: for=127.0.0.1;host=www.test;proto=https\n" +
				"X-Forwarded-By: " + by + "\nVia: " + via + "\n"
			if body != want {
				t.Errorf("h2=%v %s:\n%s\nwant\n%s", h2, path, body, want)
			}
		}
	}
	for client, host := range map[string]string{"2001:db8::1": "www.test:8443", "192.0.2.1": "a.test"} {
		got := forwardedHeader(client, host)
		want := map[string]string{"2001:db8::1": `for="[2001:db8::1]";host="www.test:8443";proto=https`, "192.0.2.1": "for=192.0.2.1;host=a.test;proto=https"}[client]
		if got != want {
			t.Errorf("Forwarded %s %s: %s, want %s", client, host, got, want)
		}
	}
}
