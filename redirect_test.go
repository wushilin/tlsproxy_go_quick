package main

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestRedirectConfig(t *testing.T) {
	c := mustParse(t, "[[listener]]\nname=default\nbind=127.0.0.1\nport=443\n[[host]]\nlistener=default\npattern=ANY\ntarget_host=x\ntarget_port=443\n")
	if c.Redirect != nil || len(c.PortListeners()) != 1 {
		t.Fatal("off by default")
	}
	c = mustParse(t, "[[listener]]\nname=default\nbind=127.0.0.1\nport=443\n[global]\nhttp_to_https_redirect=true\n[[host]]\nlistener=default\npattern=ANY\ntarget_host=x\ntarget_port=443\n")
	if r := c.Redirect; r == nil || r.Name != RedirectListenerName || r.Port != 80 || !slices.Equal(r.Binds, []string{"127.0.0.1"}) || len(c.Listeners) != 1 {
		t.Fatalf("%+v", c.Redirect)
	}
	if c.Rules[0].Listener != "default" || c.PortListener(RedirectListenerName) != c.Redirect || c.Listener(RedirectListenerName) != nil {
		t.Fatal("the redirect listener is not one rules can use")
	}

	// Every address of every listener, a wildcard standing for its family.
	c = mustParse(t, "[global]\nhttp_to_https_redirect=true\n"+
		"[[listener]]\nname=a\nbind=0.0.0.0; 2001:db8::1\nport=443\n"+
		"[[listener]]\nname=b\nbind=10.0.0.1; 2001:db8::2\nport=8443\n"+
		"[[host]]\nlistener=a\npattern=ANY\ntarget_host=x\ntarget_port=443\n")
	if want := []string{"0.0.0.0", "2001:db8::1", "2001:db8::2"}; !slices.Equal(c.Redirect.Binds, want) {
		t.Fatalf("%v, want %v", c.Redirect.Binds, want)
	}

	for text, want := range map[string]string{
		"[[listener]]\nname=default\nport=80\n[global]\nhttp_to_https_redirect=true\n":                                                                                    "port 80, which [[listener]] default at line 1 also uses",
		"[global]\nhttp_to_https_redirect=true\n[[listener]]\nname=a\nport=443\n[[listener]]\nname=b\nbind=10.0.0.1\nport=80\n":                                           "port 80, which [[listener]] b at line 6 also uses",
		"[[listener]]\nname=HTTP-to-HTTPS-redirect\nport=1\n":                                                                                                             "reserved for http_to_https_redirect",
		"[[listener]]\nname=default\nport=443\n[global]\nhttp_to_https_redirect=maybe\n":                                                                                  "http_to_https_redirect",
		"[global]\nhttp_to_https_redirect=true\n[[listener]]\nname=a\nport=443\n[[host]]\nlistener=http-to-https-redirect\npattern=ANY\ntarget_host=x\ntarget_port=443\n": "there is no [[listener]] named http-to-https-redirect",
	} {
		_, err := ParseConfig(text)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", text, err, want)
		}
	}
	// A listener on port 80 at an address the redirect also binds.
	if _, err := ParseConfig("[global]\nhttp_to_https_redirect=true\n[[listener]]\nname=a\nbind=10.0.0.1\nport=443\n[[listener]]\nname=b\nbind=10.0.0.2\nport=80\n"); err == nil {
		t.Error("a listener on port 80 at an address the redirect binds must be refused")
	}
}

func TestRedirectHost(t *testing.T) {
	for in, want := range map[string]string{
		"Example.COM": "example.com", "example.com:80": "example.com", "10.0.0.1:8080": "10.0.0.1",
		"[2001:DB8::1]:80": "[2001:db8::1]", "[::1]": "[::1]",
		"": "", ":80": "", "a b": "", "a\r\nX: y": "", "[::1": "", "[10.0.0.1]": "", "a:x": "", "a:80:80": "", "a/b": "",
	} {
		got, ok := redirectHost(in)
		if got != want || ok != (want != "") {
			t.Errorf("%q: %q %v, want %q", in, got, ok, want)
		}
	}
}

// startRedirect serves the redirect listener of cfg on a free loopback port.
func startRedirect(t *testing.T, extra string) (*Server, string) {
	t.Helper()
	cfg := mustParse(t, "[[listener]]\nname=default\nbind=127.0.0.1\nport=443\n[global]\nhttp_to_https_redirect=true\nhandshake_timeout=2\n"+extra+"[[host]]\nlistener=default\npattern=ANY\ntarget_host=x\ntarget_port=443\n")
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go srv.acceptLoop(ln, RedirectListenerName)
	return srv, ln.Addr().String()
}

func readResponse(t *testing.T, br *bufio.Reader) *http.Response {
	t.Helper()
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp
}

func waitClosedFlow(t *testing.T, srv *Server) flowView {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if fl := srv.stats.flows.closedSince(0); len(fl) > 0 {
			return fl[len(fl)-1]
		}
	}
	t.Fatal("no closed flow")
	return flowView{}
}

func TestRedirectKeepAlive(t *testing.T) {
	srv, addr := startRedirect(t, "")
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(conn)

	// Two requests on one connection, the second with a body: 301, then 308
	// and close.
	io.WriteString(conn, "GET /a/b?c=1&d=%20 HTTP/1.1\r\nHost: WWW.Example.com:80\r\n\r\n")
	resp := readResponse(t, br)
	if resp.StatusCode != 301 || resp.Header.Get("Location") != "https://www.example.com/a/b?c=1&d=%20" || resp.Close {
		t.Fatalf("%d %q close=%v", resp.StatusCode, resp.Header.Get("Location"), resp.Close)
	}
	io.WriteString(conn, "POST /form HTTP/1.1\r\nHost: other.test\r\nContent-Length: 5\r\n\r\nhello")
	resp = readResponse(t, br)
	if resp.StatusCode != 308 || resp.Header.Get("Location") != "https://other.test/form" || !resp.Close {
		t.Fatalf("%d %q close=%v", resp.StatusCode, resp.Header.Get("Location"), resp.Close)
	}
	if _, err := br.ReadByte(); err != io.EOF {
		t.Fatalf("want EOF after Connection: close, got %v", err)
	}
	f := waitClosedFlow(t, srv)
	if f.Listener != RedirectListenerName || f.Result != flowClosed || f.SNI != "other.test" || f.Reason != "redirected 2 request(s)" || f.TLS != "http" || f.BytesUp == 0 || f.BytesDown == 0 {
		t.Fatalf("%+v", f)
	}
	if rs := srv.stats.ruleSnapshot(redirectKey); rs == nil || rs.Total.Load() != 1 || rs.Active.Load() != 0 {
		t.Fatal("pseudo-rule counters")
	}
}

func TestRedirectHugeBody(t *testing.T) {
	// The body is never read: the 308 comes back right after the headers.
	_, addr := startRedirect(t, "")
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(conn, "PUT /upload HTTP/1.1\r\nHost: up.test\r\nContent-Length: 10737418240\r\n\r\n")
	go conn.Write(make([]byte, 64<<10)) // some of it, still arriving (less than the server drains: no reset)
	resp := readResponse(t, bufio.NewReader(conn))
	if resp.StatusCode != 308 || resp.Header.Get("Location") != "https://up.test/upload" {
		t.Fatalf("%d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestRedirectBadRequests(t *testing.T) {
	for req, want := range map[string]int{
		"GET / HTTP/1.1\r\n\r\n":                            400, // no Host
		"GET / HTTP/1.1\r\nHost: a b\r\n\r\n":               400,
		"OPTIONS * HTTP/1.1\r\nHost: a.test\r\n\r\n":        400,
		"nonsense\r\n\r\n":                                  400,
		"GET / HTTP/1.1\r\nX: " + strings.Repeat("a", 9000): 431,
	} {
		_, addr := startRedirect(t, "")
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		io.WriteString(conn, req)
		resp := readResponse(t, bufio.NewReader(conn))
		conn.Close()
		if resp.StatusCode != want {
			t.Errorf("%.40q: %d, want %d", req, resp.StatusCode, want)
		}
	}
}

func TestRedirectStopFromConsole(t *testing.T) {
	srv, addr := startRedirect(t, "")
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(conn)
	io.WriteString(conn, "GET / HTTP/1.1\r\nHost: a.test\r\n\r\n")
	readResponse(t, br) // kept alive
	srv.stats.conns.Range(func(c *ConnState) bool {
		c.stop("stopped from the console; closed by proxy")
		return true
	})
	if _, err := br.ReadByte(); err == nil {
		t.Fatal("still open")
	}
	if f := waitClosedFlow(t, srv); f.Reason != "stopped from the console; closed by proxy" {
		t.Fatalf("%+v", f)
	}
}
