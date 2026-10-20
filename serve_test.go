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

func TestServiceRuleConfig(t *testing.T) {
	t.Parallel()
	cfg := mustParse(t, serveHead+`
[[host]]
listener = default
pattern = www.test
cert = auto
service_rule1 = type=reverse_proxy; prefix=/; target=http://127.0.0.1:8080
service_rule_api = type=reverse_proxy;prefix=/api/;target=https://api.lan;strip_prefix=true;force_host=x.lan;tls_verify=false;basic_auth=team;
service_rule3 = type=static_content; prefix=/assets/; base_dir=/opt/www/assets
service_rule3 = type=static_content; prefix=/static/; base_dir=/opt/www/static

[[basic_auth]]
name = team
user1 = username=jack; password_plain=secret
user2 = username=jill; password_hash=`+mustHash(t, "pw")+`
user1 = username=joe; password_plain=other
`)
	r := &cfg.Rules[0]
	if !r.Serves() || r.UpstreamTLS || len(r.Routes) != 3 {
		t.Fatalf("rule: serves=%v upstream_tls=%v routes=%d", r.Serves(), r.UpstreamTLS, len(r.Routes))
	}
	if got := r.RouteFor("/api/x"); got == nil || got.Key != "service_rule_api" || !got.StripPrefix || got.ForceHost != "x.lan" || got.TLSVerify || got.TargetAddr() != "api.lan:443" || got.auth == nil {
		t.Fatalf("the longest prefix wins, with its options: %+v", got)
	}
	if got := r.RouteFor("/static/a.css"); got == nil || got.BaseDir != "/opt/www/static" {
		t.Fatalf("a repeated key keeps its last value: %+v", got)
	}
	if r.RouteFor("/assets/a.css").Prefix != "/" {
		t.Fatal("the replaced service_rule3 is gone")
	}
	if got := r.RouteFor("/other"); got == nil || got.TargetAddr() != "127.0.0.1:8080" {
		t.Fatalf("/ catches the rest: %+v", got)
	}
	if !strings.Contains(strings.Join(cfg.Warnings, "\n"), "service_rule3 is also set") {
		t.Errorf("a repeated key is a warning: %v", cfg.Warnings)
	}
	team := cfg.BasicAuth["team"]
	if _, ok := team.Users["jack"]; ok || team.Users["joe"].plain != "other" || team.Users["jill"].hash == "" {
		t.Fatalf("user keys, the last value of user1 winning: %+v", team.Users)
	}
	if d := cfg.Route("www.test"); !d.Allow || d.Rule != r || d.Host != "" {
		t.Fatalf("a serving rule routes without a target: %+v", d)
	}

	rule := "[[host]]\nlistener=default\npattern=www.test\ncert=auto\n"
	for text, want := range map[string]string{
		rule + "service_rule1=type=ftp;prefix=/":                                                                                "type must be",
		rule + "service_rule1=prefix=/":                                                                                         "type is required",
		rule + "service_rule1=type=reverse_proxy;target=http://h":                                                               "prefix is required",
		rule + "service_rule1=type=reverse_proxy;prefix=/":                                                                      "needs target=",
		rule + "service_rule1=type=reverse_proxy;prefix=/;target=ftp://h":                                                       "http:// or https://",
		rule + "service_rule1=type=reverse_proxy;prefix=/;target=http://h/base":                                                 "scheme://host:port only",
		rule + "service_rule1=type=reverse_proxy;prefix=/;target=http://h;tls_verify=false":                                     "only applies to an https:// target",
		rule + "service_rule1=type=reverse_proxy;prefix=/;target=http://h;base_dir=/x":                                          "base_dir only applies to type=static_content",
		rule + "service_rule1=type=static_content;prefix=/":                                                                     "needs base_dir",
		rule + "service_rule1=type=static_content;prefix=/x;base_dir=/x":                                                        "ends with /",
		rule + "service_rule1=type=static_content;prefix=/;base_dir=/x;strip_prefix=true":                                       "strip_prefix only applies to type=reverse_proxy",
		rule + "service_rule1=type=static_content;prefix=/;base_dir=/x;colour=red":                                              `unknown option "colour"`,
		rule + "service_rule1=type=static_content;prefix=/;prefix=/a/;base_dir=/x":                                              "prefix is given twice",
		rule + "service_rule1=type=static_content;prefix=x;base_dir=/x":                                                         "starting with /",
		rule + "service_rule1=type=static_content;prefix=/;base_dir=/x;basic_auth=nope":                                         "no [[basic_auth]] named nope",
		rule + "service_rule1=type=static_content;prefix=/;base_dir=/x\nservice_rule2=type=static_content;prefix=/;base_dir=/y": "already served by service_rule1",
		rule + "service_rule1=type=static_content;prefix=/;base_dir=/x\ntarget_host=h":                                          "target_host does not apply",
		rule + "service_rule1=type=static_content;prefix=/;base_dir=/x\nupstream_tls=false":                                     "upstream_tls does not apply",
		rule + "service_rule1=type=static_content;prefix=/;base_dir=/x\nproxy=true":                                             "proxy does not apply",
		rule + "service_rule1=type=static_content;prefix=/;base_dir=/x\naction=deny":                                            "action = allow",
		"[[host]]\nlistener=default\npattern=www.test\nservice_rule1=type=static_content;prefix=/;base_dir=/x":                  "need cert = auto or cert = local-ca",
		"[[basic_auth]]\nuser1=username=a;password_plain=b":                                                                     "name is required",
		"[[basic_auth]]\nname=a":                                                                       "no users",
		"[[basic_auth]]\nname=a\nuser1=password_plain=b":                                               "username= is required",
		"[[basic_auth]]\nname=a\nuser1=username=a":                                                     "password_plain= or password_hash= is required",
		"[[basic_auth]]\nname=a\nuser1=username=a;password_plain=b;password_hash=c":                    "not both",
		"[[basic_auth]]\nname=a\nuser1=username=a;password_hash=nope":                                  "not an argon2id",
		"[[basic_auth]]\nname=a\nuser1=username=a:b;password_plain=x":                                  "without a colon",
		"[[basic_auth]]\nname=a\nuser1=username=a;password_plain=x\nuser2=username=a;password_plain=y": "already listed",
		"[[basic_auth]]\nname=a\npassword=x":                                                           `unknown key "password"`,
	} {
		if _, err := ParseConfig(serveHead + text + "\n"); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s:\n  %v, want %q", text, err, want)
		}
	}
	// The old sections are gone.
	if _, err := ParseConfig(serveHead + "[[local_services]]\nname=a\n"); err == nil || !strings.Contains(err.Error(), "unknown section [[local_services]]") {
		t.Errorf("[[local_services]]: %v", err)
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
		check("/x?q=1", "200 path=/x?q=1 host=www.test xff=127.0.0.1 proto=https fwd= auth=", "X-Forwarded-For", "6.6.6.6", "Forwarded", "for=6.6.6.6")
		check("/api/v1/y", "200 path=/v1/y host=backend.lan xff=127.0.0.1 proto=https fwd= auth=")
		check("/api", "301 /api/")
		check("/files/", "200 home")
		check("/files/a.txt", "200 A")
		check("/files/sub/", "200 sub")
		check("/files/sub", "301 sub/")
		check("/files/.well-known/security.txt", "200 sec")
		check("/files/.env", "404")
		check("/files/empty/", "404")
		check("/files/escape", "404")
		check("/files/nope", "404")
		check("/missing/a", "503")
		check("/dead/", "502")
		check("/private/z", "401")
		check("/private/z", "401", "Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("jack:wrong")))
		check("/private/z", "200 path=/private/z host=www.test xff=127.0.0.1 proto=https fwd= auth=", "Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("jack:pw")))
		check("/private/z", "200 path=/private/z host=www.test xff=127.0.0.1 proto=https fwd= auth=", "Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("jill:open sesame")))
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
	if !strings.Contains(testLog.String(), "GET www.test/files/a.txt -> 200 via service_rule3") {
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
	os.WriteFile(path, []byte(head+fmt.Sprintf(rules, ca.localCA(t), b, "second")), 0o600)
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
	if want := "path=/hello host=127.0.0.1 xff=127.0.0.2 proto=https fwd= auth="; string(body) != want {
		t.Fatalf("%s\nwant %s", body, want)
	}
}

// The rule editor's one text box becomes service_rule1, 2, ... and back.
func TestEditServiceRules(t *testing.T) {
	t.Parallel()
	text := serveHead + "[[host]]\nlistener = default\npattern = www.test\ncert = auto\nservice_rule_a = type=static_content; prefix=/; base_dir=/x  # old\n# keep me\nmax_aggregated_speed = 1MB\n"
	out, err := editRules(text, 6, map[string]string{serviceRulesValue: "type=reverse_proxy; prefix=/api/; target=http://h:1\n\n# a note\ntype=static_content; prefix=/; base_dir=/srv/www\n"}, false)
	if err != nil {
		t.Fatal(err)
	}
	want := serveHead + "[[host]]\nlistener = default\npattern = www.test\ncert = auto\n" +
		`service_rule1 = "type=reverse_proxy; prefix=/api/; target=http://h:1"` + "\n" +
		`service_rule2 = "type=static_content; prefix=/; base_dir=/srv/www"` + "\n# keep me\nmax_aggregated_speed = 1MB\n"
	if out != want {
		t.Fatalf("got\n%s\nwant\n%s", out, want)
	}
	cfg := mustParse(t, out)
	if len(cfg.Rules[0].Routes) != 2 {
		t.Fatal("the written rules load")
	}
	lines := strings.Split(out, "\n")
	if v := hostValues(lines, hostBlocks(lines)[0])[serviceRulesValue]; v != "type=reverse_proxy; prefix=/api/; target=http://h:1\ntype=static_content; prefix=/; base_dir=/srv/www" {
		t.Fatalf("read back for the editor: %q", v)
	}
	if _, err := editRules(text, 6, map[string]string{serviceRulesValue: "type=static_content; prefix=/"}, false); err == nil || !strings.Contains(err.Error(), "service rule on line 1: type=static_content needs base_dir") {
		t.Fatalf("checked as typed: %v", err)
	}
	out, err = editRules(text, 6, map[string]string{serviceRulesValue: "", "target_host": "h", "target_port": "1"}, false)
	if err != nil || strings.Contains(out, "service_rule") || !strings.Contains(out, "target_host = h") {
		t.Fatalf("emptied: %v\n%s", err, out)
	}
	out, err = editRules(serveHead, 0, map[string]string{"listener": "default", "pattern": "new.test", "cert": "auto", serviceRulesValue: "type=static_content; prefix=/; base_dir=/srv"}, false)
	if err != nil || !strings.HasSuffix(strings.TrimSpace(out), `cert = auto`+"\n"+`service_rule1 = "type=static_content; prefix=/; base_dir=/srv"`) {
		t.Fatalf("a new rule: %v\n%s", err, out)
	}
}
