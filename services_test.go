package main

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const serviceHead = "[[listener]]\nname=default\nport=1\n"

func TestLocalServicesConfig(t *testing.T) {
	t.Parallel()
	cfg := mustParse(t, serviceHead+`
[[local_services]]
name = api
type = reverse_proxy
port = 1081

[[proxy_pass_rules]]
server = api
prefix = /
target_host = 127.0.0.1
target_port = 8080

[[proxy_pass_rules]]
server = api
prefix = /asdf/
target_host = 127.0.0.1
target_port = 8888
strip_prefix = true
force_host = localhost002
`)
	svc := cfg.Services[0]
	if svc.Bind != "127.0.0.1" || svc.ProxyVersion != "auto" || svc.ForwardedProto != "https" || len(svc.ProxyTrustSource) != 2 {
		t.Fatalf("defaults: %+v", svc)
	}
	if r := svc.Route("/asdf/x"); r == nil || r.TargetPort != 8888 || !r.StripPrefix || r.ForceHost != "localhost002" {
		t.Fatalf("longest prefix wins: %+v", r)
	}
	if r := svc.Route("/other"); r == nil || r.TargetPort != 8080 {
		t.Fatalf("/ catches the rest: %+v", r)
	}
	for _, peer := range []string{"127.0.0.1", "127.9.9.9", "::1", "::ffff:127.0.0.1"} {
		if !svc.trusts(addrOf(&net.TCPAddr{IP: net.ParseIP(peer)})) {
			t.Errorf("loopback %s is trusted by default", peer)
		}
	}
	for _, peer := range []string{"10.0.0.1", "fe80::1", "192.168.1.1"} {
		if svc.trusts(addrOf(&net.TCPAddr{IP: net.ParseIP(peer)})) {
			t.Errorf("%s is not trusted by default", peer)
		}
	}

	for text, want := range map[string]string{
		"[[local_services]]\nname=a\ntype=http_server\nport=2":                                                                                                                                                   "needs doc_root",
		"[[local_services]]\nname=a\ntype=reverse_proxy\nport=2\ndoc_root=/x":                                                                                                                                    "only applies to type = http_server",
		"[[local_services]]\nname=a\ntype=ftp\nport=2":                                                                                                                                                           "type must be",
		"[[local_services]]\nname=a\nport=2":                                                                                                                                                                     "type is required",
		"[[local_services]]\nname=a\ntype=reverse_proxy\nport=1\nbind=0.0.0.0":                                                                                                                                   "overlaps [[listener]] default",
		"[[local_services]]\nname=a\ntype=reverse_proxy\nport=2\n[[local_services]]\nname=A\ntype=reverse_proxy\nport=3":                                                                                         "already used",
		"[[local_services]]\nname=a\ntype=reverse_proxy\nport=2\n[[local_services]]\nname=b\ntype=reverse_proxy\nport=2":                                                                                         "overlaps [[local_services]] a",
		"[[local_services]]\nname=a\ntype=reverse_proxy\nport=2\nproxy_version=v3":                                                                                                                               "auto, none, v1 or v2",
		"[[local_services]]\nname=a\ntype=reverse_proxy\nport=2\nproxy_protocol_from=10.0.0.1":                                                                                                                   "now called proxy_trust_source",
		"[[proxy_pass_rules]]\nserver=nope\nprefix=/\ntarget_host=h\ntarget_port=1":                                                                                                                              "no [[local_services]] named nope",
		"[[local_services]]\nname=w\ntype=http_server\nport=2\ndoc_root=/x\n[[proxy_pass_rules]]\nserver=w\nprefix=/\ntarget_host=h\ntarget_port=1":                                                              "proxy_pass_rules belong to a reverse_proxy",
		"[[local_services]]\nname=a\ntype=reverse_proxy\nport=2\n[[proxy_pass_rules]]\nserver=a\nprefix=x\ntarget_host=h\ntarget_port=1":                                                                         "starting with /",
		"[[local_services]]\nname=a\ntype=reverse_proxy\nport=2\n[[proxy_pass_rules]]\nserver=a\nprefix=/\ntarget_host=h:1\ntarget_port=1":                                                                       "must not contain a port",
		"[[local_services]]\nname=a\ntype=reverse_proxy\nport=2\n[[proxy_pass_rules]]\nserver=a\nprefix=/\ntarget_host=h\ntarget_port=1\n[[proxy_pass_rules]]\nserver=a\nprefix=/\ntarget_host=h\ntarget_port=2": "already has a rule",
		"[console]\nport=2\npassword=x\n[[local_services]]\nname=a\ntype=reverse_proxy\nport=2":                                                                                                                  "overlaps [console]",
	} {
		if _, err := ParseConfig(serviceHead + text + "\n"); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s:\n  %v, want %q", text, err, want)
		}
	}
	// proxy_protocol_from is renamed everywhere.
	for _, text := range []string{"[global]\nproxy_protocol_from=10.0.0.1", "[[listener]]\nname=x\nport=5\nproxy_protocol_from=10.0.0.1"} {
		if _, err := ParseConfig(serviceHead + text + "\n"); err == nil || !strings.Contains(err.Error(), "proxy_trust_source = 10.0.0.1") {
			t.Errorf("%s: %v", text, err)
		}
	}
	// A rule that sends a PROXY header to a service that takes none.
	c := mustParse(t, serviceHead+"[[local_services]]\nname=a\ntype=reverse_proxy\nport=2\nproxy_version=none\n[[host]]\nlistener=default\npattern=x.test\ntarget_host=127.0.0.1\ntarget_port=2\nproxy=true\n")
	if !strings.Contains(strings.Join(c.Warnings, "\n"), "proxy_version = none") {
		t.Fatalf("warnings: %v", c.Warnings)
	}
}

// startServices runs a proxy whose configuration has these services, on
// free ports given as %d in order.
func startServices(t *testing.T, sections string, ports ...any) *proxyUnderTest {
	t.Helper()
	return startProxy(t, "", fmt.Sprintf(sections, ports...))
}

func svcGet(t *testing.T, addr, path string, header ...string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", "http://"+addr+path, nil)
	for i := 0; i+1 < len(header); i += 2 {
		if header[i] == "Host" {
			req.Host = header[i+1]
		} else {
			req.Header.Set(header[i], header[i+1])
		}
	}
	client := &http.Client{Timeout: T, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

func TestLocalHTTPServer(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "index.html"), []byte("home"), 0o644)
	os.WriteFile(filepath.Join(root, "a.txt"), []byte("A"), 0o644)
	os.WriteFile(filepath.Join(root, ".env"), []byte("secret"), 0o644)
	os.MkdirAll(filepath.Join(root, "empty"), 0o755)
	os.MkdirAll(filepath.Join(root, ".well-known"), 0o755)
	os.WriteFile(filepath.Join(root, ".well-known", "security.txt"), []byte("sec"), 0o644)
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "x"), []byte("outside"), 0o644)
	os.Symlink(filepath.Join(outside, "x"), filepath.Join(root, "escape"))

	port := freePort(t)
	startServices(t, "[[local_services]]\nname=web\ntype=http_server\nport=%d\ndoc_root=%s\n", port, root)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	waitForPort(t, addr)
	for path, want := range map[string]string{"/": "200 home", "/a.txt": "200 A", "/.well-known/security.txt": "200 sec",
		"/.env": "404", "/empty/": "404", "/escape": "404", "/missing": "404"} {
		resp, body := svcGet(t, addr, path)
		got := fmt.Sprint(resp.StatusCode)
		if resp.StatusCode == 200 {
			got += " " + body
		}
		if got != want {
			t.Errorf("%s: %s, want %s", path, got, want)
		}
	}
	resp, err := http.Post("http://"+addr+"/a.txt", "text/plain", strings.NewReader("x"))
	if err != nil || resp.StatusCode != 405 {
		t.Fatalf("POST: %v %v", resp, err)
	}
}

// httpEcho answers with what it received: path, host and headers.
func httpEcho(t *testing.T) int {
	l, port := listen(t)
	go http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "path=%s host=%s xff=%s proto=%s fwd=%s", r.URL.RequestURI(), r.Host, r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Forwarded-Proto"), r.Header.Get("Forwarded"))
	}))
	return port
}

func TestLocalReverseProxy(t *testing.T) {
	t.Parallel()
	a, b, svc := httpEcho(t), httpEcho(t), freePort(t)
	dead := freePort(t)
	startServices(t, `[[local_services]]
name=api
type=reverse_proxy
port=%d
proxy_version=none
[[proxy_pass_rules]]
server=api
prefix=/
target_host=127.0.0.1
target_port=%d
[[proxy_pass_rules]]
server=api
prefix=/asdf/
target_host=127.0.0.1
target_port=%d
strip_prefix=true
force_host=localhost002
[[proxy_pass_rules]]
server=api
prefix=/keep/
target_host=127.0.0.1
target_port=%d
[[proxy_pass_rules]]
server=api
prefix=/dead/
target_host=127.0.0.1
target_port=%d
`, svc, a, b, b, dead)
	addr := fmt.Sprintf("127.0.0.1:%d", svc)
	waitForPort(t, addr)

	_, body := svcGet(t, addr, "/asdf/x?q=1", "Host", "orig.test", "X-Forwarded-For", "6.6.6.6", "Forwarded", "for=6.6.6.6")
	if want := "path=/x?q=1 host=localhost002 xff=127.0.0.1 proto=https fwd="; body != want {
		t.Errorf("strip + force_host, client's forwarding headers replaced:\n  %s\nwant %s", body, want)
	}
	if _, body = svcGet(t, addr, "/keep/y", "Host", "orig.test"); body != "path=/keep/y host=orig.test xff=127.0.0.1 proto=https fwd=" {
		t.Errorf("kept prefix and Host: %s", body)
	}
	if _, body = svcGet(t, addr, "/elsewhere"); !strings.HasPrefix(body, "path=/elsewhere ") {
		t.Errorf("/ catches the rest: %s", body)
	}
	if resp, _ := svcGet(t, addr, "/asdf?z=2"); resp.StatusCode != 301 || resp.Header.Get("Location") != "/asdf/?z=2" {
		t.Errorf("folder redirect: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp, _ := svcGet(t, addr, "/dead/"); resp.StatusCode != 502 {
		t.Errorf("unreachable upstream: %d", resp.StatusCode)
	}
}

func TestLocalReverseProxyNoMatch(t *testing.T) {
	t.Parallel()
	svc, a := freePort(t), httpEcho(t)
	startServices(t, "[[local_services]]\nname=api\ntype=reverse_proxy\nport=%d\n[[proxy_pass_rules]]\nserver=api\nprefix=/only/\ntarget_host=127.0.0.1\ntarget_port=%d\n", svc, a)
	addr := fmt.Sprintf("127.0.0.1:%d", svc)
	waitForPort(t, addr)
	if resp, _ := svcGet(t, addr, "/other"); resp.StatusCode != 404 {
		t.Fatalf("no matching prefix: %d", resp.StatusCode)
	}
}

// rawRequest sends a PROXY header (if any) and one request, and returns
// the status line and body ("" if the connection was dropped).
func rawRequest(t *testing.T, addr string, header []byte) string {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, T)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(T))
	c.Write(append(header, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"...))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return ""
	}
	body, _ := io.ReadAll(resp.Body)
	return fmt.Sprintf("%d %s", resp.StatusCode, body)
}

func TestLocalServiceProxyProtocol(t *testing.T) {
	t.Parallel()
	a := httpEcho(t)
	auto, v2, none, untrusted := freePort(t), freePort(t), freePort(t), freePort(t)
	section := "[[local_services]]\nname=%s\ntype=reverse_proxy\nport=%d\n%s\n[[proxy_pass_rules]]\nserver=%s\nprefix=/\ntarget_host=127.0.0.1\ntarget_port=%d\n"
	startServices(t, section+section+section+section,
		"auto", auto, "", "auto", a,
		"v2", v2, "proxy_version=v2", "v2", a,
		"none", none, "proxy_version=none", "none", a,
		"untrusted", untrusted, "proxy_trust_source=10.0.0.0/8", "untrusted", a)
	v1Header := []byte("PROXY TCP4 203.0.113.9 127.0.0.1 5555 80\r\n")
	v2Header := func() []byte {
		srv, cli := net.Pipe()
		go func() {
			writeProxyProtocol(cli, 2, &net.TCPAddr{IP: net.ParseIP("198.51.100.4"), Port: 1}, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2})
			cli.Close()
		}()
		b, _ := io.ReadAll(srv)
		return b
	}()
	at := func(p int) string { addr := fmt.Sprintf("127.0.0.1:%d", p); waitForPort(t, addr); return addr }
	for _, tc := range []struct {
		name   string
		addr   string
		header []byte
		want   string // the X-Forwarded-For upstream saw, or "dropped" / a status
	}{
		{"auto, v1", at(auto), v1Header, "xff=203.0.113.9"},
		{"auto, v2", at(auto), v2Header, "xff=198.51.100.4"},
		{"auto, none", at(auto), nil, "xff=127.0.0.1"},
		{"v2 required, v2", at(v2), v2Header, "xff=198.51.100.4"},
		{"v2 required, none", at(v2), nil, "dropped"},
		{"v2 required, v1", at(v2), v1Header, "dropped"},
		{"none: a header is just bytes", at(none), v1Header, "400"},
		{"untrusted peer: header not read", at(untrusted), v1Header, "400"},
		{"untrusted peer, plain", at(untrusted), nil, "xff=127.0.0.1"},
	} {
		got := rawRequest(t, tc.addr, tc.header)
		switch {
		case tc.want == "dropped" && got == "":
		case strings.HasPrefix(got, tc.want):
		case strings.HasPrefix(tc.want, "xff=") && strings.Contains(got, " "+tc.want+" "):
		default:
			t.Errorf("%s: %q, want %s", tc.name, got, tc.want)
		}
	}
}

// Reloading moves, adds and removes services; a doc_root change applies
// without reopening the port.
func TestLocalServicesReload(t *testing.T) {
	t.Parallel()
	one, two := t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(one, "index.html"), []byte("one"), 0o644)
	os.WriteFile(filepath.Join(two, "index.html"), []byte("two"), 0o644)
	port, moved := freePort(t), freePort(t)
	p := startServices(t, "[[local_services]]\nname=web\ntype=http_server\nport=%d\ndoc_root=%s\n", port, one)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	waitForPort(t, addr)
	reload := func(text string) {
		cfg, err := ParseConfig(serviceHead + text)
		if err != nil {
			t.Fatal(err)
		}
		if failed := p.srv.syncServices(cfg); failed != nil {
			t.Fatal(failed)
		}
	}
	reload(fmt.Sprintf("[[local_services]]\nname=web\ntype=http_server\nport=%d\ndoc_root=%s\n", port, two))
	if _, body := svcGet(t, addr, "/"); body != "two" {
		t.Fatalf("doc_root change: %q", body)
	}
	reload(fmt.Sprintf("[[local_services]]\nname=web\ntype=http_server\nport=%d\ndoc_root=%s\n", moved, two))
	waitForPort(t, fmt.Sprintf("127.0.0.1:%d", moved))
	if c, err := net.Dial("tcp", addr); err == nil {
		c.Close()
		t.Fatal("the old port is closed after a move")
	}
	reload("")
	if c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", moved)); err == nil {
		c.Close()
		t.Fatal("a removed service's port is closed")
	}
}

// The whole path: a client without SNI connects from 127.0.0.2 and checks
// the certificate against the IP it dialed; the NONE rule terminates with
// the local CA and passes the connection with PROXY v2 to a reverse_proxy
// service, whose upstream sees the client's own address.
func TestNoSNIToLocalServiceEndToEnd(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	a, svc := httpEcho(t), freePort(t)
	p := startProxy(t, "", fmt.Sprintf(`[[host]]
listener=default
pattern=NONE
cert=%s
upstream_tls=false
proxy=true
proxy_version=2
target_host=127.0.0.1
target_port=%d
[[local_services]]
name=api
type=reverse_proxy
port=%d
[[proxy_pass_rules]]
server=api
prefix=/
target_host=127.0.0.1
target_port=%d
`, ca.localCA(t), svc, svc, a))
	waitForPort(t, fmt.Sprintf("127.0.0.1:%d", svc))
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
	if want := "path=/hello host=127.0.0.1 xff=127.0.0.2 proto=https fwd="; string(body) != want {
		t.Fatalf("%s\nwant %s", body, want)
	}
}

// The file server must reach the TCP connection's ReadFrom with a plain
// *os.File, or Linux copies files through user space instead of sendfile(2).
func TestServiceFilesKeepSendfile(t *testing.T) {
	var _ io.ReaderFrom = (*serviceConn)(nil)
	var _ io.ReaderFrom = (*statusWriter)(nil)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	f, err := rootDir{root}.Open("/a.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, ok := f.(*os.File); !ok {
		t.Fatalf("rootDir hands the file server a %T, not an *os.File", f)
	}
	if _, err := (rootDir{root}).Open("/missing"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a missing file: %v, want fs.ErrNotExist", err)
	}
}
