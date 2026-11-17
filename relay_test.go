package main

// Relay targets (relay.go): the exchanges and endpoints sections' checks, and every kind of
// rule through a real pf-simple hub.
//
// The hub is pf-simple's own binary, of the version go.mod pins, built with
// `go install` (the hub is pf-simple's package main, which cannot be
// imported) and run with its QUIC listener on and a self-signed CA. The
// serving side of each tunnel is pf-simple's SDK in this process, over QUIC
// and over WebSockets, since the hub joins either with this proxy's QUIC.
//
// Building the hub needs the module proxy, or the module in the cache. A
// hub that cannot be built or does not start skips these tests, unless
// TLSPROXY_LIVE is set (as in CI's Linux job), when they fail.
// PF_SIMPLE_BIN names a pf-simple binary to use instead of building one.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wushilin/pf-simple/pfrelay"
	"github.com/wushilin/pf-simple/pfrelayquic"
)

// ---------------------------------------------------------------- the exchanges and endpoints sections

const relayListener = "listeners:\n  - {name: a, port: 1}\n"

func TestRelayConfig(t *testing.T) {
	cfg := mustLoadYAML(t, relayListener+`routes:
  - listener: a
    rules:
      - {domain: office.test, target: relay://office}
      - {domain: wiki.test, target: "RELAY://wiki", cert: local-ca, upstream_tls: false, proxy: v2}
exchanges:
  - {name: home, hub: "https://relay.example.com/"}
  - {name: work, hub: "https://relay.example.com:18222/pf/"}
endpoints:
  - {name: office, exchange: home, word: K3F9-X2MQ-7HPA}
  - {name: wiki, exchange: work, word: h7cq-m2xe-9tka, client_token: correct-horse-battery}
  - {name: same-word, exchange: work, word: h7cq-m2xe-9tka}
`)
	for sni, want := range map[string]string{"office.test": "relay://office", "wiki.test": "relay://wiki", "other.test": "DENY"} {
		if got := route(t, cfg, sni); got != want {
			t.Errorf("%s -> %s, want %s", sni, got, want)
		}
	}
	office, wiki := cfg.Endpoints["office"], cfg.Endpoints["wiki"]
	if office.Word != "k3f9-x2mq-7hpa" || office.WordLabel() != "k3f9-…" {
		t.Errorf("word %q label %q: words are normalized, and shown by their first group only", office.Word, office.WordLabel())
	}
	if office.Exchange() != cfg.Exchanges["home"] || wiki.Exchange() != cfg.Exchanges["work"] {
		t.Error("endpoints are not on their exchanges")
	}
	if d := office.Describe(); strings.Contains(d, "x2mq") || !strings.Contains(d, "exchange home (https://relay.example.com/)") {
		t.Errorf("Describe: %s", d)
	}
	if d := wiki.Describe(); !strings.Contains(d, "client token") || strings.Contains(d, "correct-horse") {
		t.Errorf("Describe: %s", d)
	}
	if r := cfg.Route("wiki.test").Rule; r.endpoint != wiki || !r.Terminates() || r.UpstreamTLS || !r.Proxy {
		t.Errorf("the rule's other settings: %+v", r)
	}
	if office.key == wiki.key || wiki.key == cfg.Endpoints["same-word"].key {
		t.Error("two tunnels share a client key")
	}
}

func TestRelayConfigErrors(t *testing.T) {
	missingCA := filepath.Join(t.TempDir(), "none.pem")
	notPEM := filepath.Join(t.TempDir(), "x.pem")
	os.WriteFile(notPEM, []byte("not a certificate"), 0o600)
	rule := func(target string) string {
		return "routes:\n  - listener: a\n    rules:\n      - {domain: x.test, target: \"" + target + "\"}\n"
	}
	exchange := func(fields string) string { return "exchanges:\n  - {" + fields + "}\n" }
	endpoint := func(fields string) string { return "endpoints:\n  - {" + fields + "}\n" }
	hub := exchange("name: h, hub: \"https://h.example/\"")
	ok := hub + endpoint("name: r, exchange: h, word: k3f9-x2mq-7hpa")
	for _, tc := range []struct{ text, want string }{
		{rule("relay://nope") + ok, "there is no endpoint named nope (endpoints: r)"},
		{rule("relay://nope"), "there is no endpoint named nope (endpoints: none)"},
		{rule("relay://") + ok, "relay:// needs the name of an endpoint"},
		{exchange("hub: \"https://h.example/\""), "an exchanges item needs name: <name>"},
		{exchange("name: h"), "exchange h: hub is required"},
		{exchange("name: h, hub: \"http://h.example/\""), "exchange h: hub:"},
		{exchange("name: h, hub: \"https://h.example/a%20b/\""), "exchange h: hub:"},
		{exchange("name: h, hub: \"https://h.example/../\""), "exchange h: hub:"},
		{exchange("name: h, hub: \"https://h.example/\", ca_file: " + missingCA), "exchange h: ca_file:"},
		{exchange("name: h, hub: \"https://h.example/\", ca_file: " + notPEM), "holds no PEM certificate"},
		{exchange("name: h, hub: \"https://h.example/\", serve_token: x"), `unknown key "serve_token" in an exchanges item (name, hub, ca_file)`},
		{hub + "  - {name: h, hub: \"https://other.example/\"}\n", "exchange h is already defined at line"},
		{hub + endpoint("exchange: h, word: k3f9-x2mq-7hpa"), "an endpoints item needs name: <name>"},
		{hub + endpoint("name: r, word: k3f9-x2mq-7hpa"), "endpoint r: exchange is required: the name of an exchanges item (h)"},
		{hub + endpoint("name: r, exchange: x, word: k3f9-x2mq-7hpa"), "endpoint r: exchange x: there is no exchanges item of that name (h)"},
		{endpoint("name: r, exchange: x, word: k3f9-x2mq-7hpa"), "there is no exchanges item of that name (there are none)"},
		{hub + endpoint("name: r, exchange: h"), "endpoint r: word is required"},
		{hub + endpoint("name: r, exchange: h, word: hello"), "endpoint r: word:"},
		{hub + endpoint("name: r, exchange: h, word: k3f9-x2mq-7hpa, client_token: short"), "endpoint r: client_token:"},
		{hub + endpoint("name: r, exchange: h, word: k3f9-x2mq-7hpa, hub: x"), `unknown key "hub" in an endpoints item (name, exchange, word, client_token)`},
		{ok + "  - {name: r, exchange: h, word: h7cq-m2xe-9tka}\n", "endpoint r is already defined at line"},
	} {
		text := relayListener + tc.text
		_, err := ParseConfig(text)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s\ngot %v\nwant %q", text, err, tc.want)
		}
	}
}

func mustLoadYAML(t *testing.T, text string) *Config {
	t.Helper()
	cfg, err := ParseConfig(text)
	if err != nil {
		t.Fatalf("%v\n%s", err, text)
	}
	return cfg
}

// ---------------------------------------------------------------- a real hub

// pfHub is a running pf-simple hub with its QUIC listener on.
type pfHub struct {
	url    string // https://127.0.0.1:<port>/
	caFile string // its self-signed CA, which clients trust
	tls    *tls.Config
}

var (
	pfBinOnce sync.Once
	pfBin     string
	pfBinErr  error
)

// pfSimpleBinary builds the pf-simple go.mod pins (once per test run).
func pfSimpleBinary() (string, error) {
	pfBinOnce.Do(func() {
		if bin := os.Getenv("PF_SIMPLE_BIN"); bin != "" {
			pfBin = bin
			return
		}
		mod, err := os.ReadFile("go.mod")
		if err != nil {
			pfBinErr = err
			return
		}
		m := regexp.MustCompile(`github\.com/wushilin/pf-simple (v\S+)`).FindSubmatch(mod)
		if m == nil {
			pfBinErr = fmt.Errorf("go.mod does not require pf-simple")
			return
		}
		dir := filepath.Join(testCARoot(), "pf-simple-bin") // removed with it by TestMain
		cmd := exec.Command("go", "install", "github.com/wushilin/pf-simple@"+string(m[1]))
		cmd.Dir = testCARoot() // outside this module: its vendor/ does not hold pf-simple's main
		cmd.Env = append(os.Environ(), "GOBIN="+dir, "GOFLAGS=", "GOWORK=off", "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			pfBinErr = fmt.Errorf("go install pf-simple %s: %v\n%s", m[1], err, out)
			return
		}
		pfBin = filepath.Join(dir, "pf-simple")
		if runtime.GOOS == "windows" {
			pfBin += ".exe"
		}
	})
	return pfBin, pfBinErr
}

// freeUDPPort is a UDP port nothing listens on.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// syncBuffer collects a process's output for the test's log.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// startHub runs a pf-simple hub for the test: https with its own CA, the
// relay hub on with anonymous serving, and QUIC on 127.0.0.1.
func startHub(t *testing.T) *pfHub {
	t.Helper()
	return startHubAt(t, "")
}

// startHubAt is startHub with the hub at path ([console] path), or at its
// default /pf when path is empty; the hub's url has the path in it.
func startHubAt(t *testing.T, path string) *pfHub {
	t.Helper()
	bin, err := pfSimpleBinary()
	if err != nil {
		if os.Getenv("TLSPROXY_LIVE") != "" {
			t.Fatalf("no pf-simple hub: %v", err)
		}
		t.Skipf("no pf-simple hub (set TLSPROXY_LIVE to make this fail): %v", err)
	}
	dir := t.TempDir()
	httpsPort, quicPort := freePort(t), freeUDPPort(t)
	conf := fmt.Sprintf(`[console]
listen = "127.0.0.1:%d"
password = "test"
tls = "self_signed"
%s
[tunnel]
enabled = true
anonymous_serve = true

[tunnel.quic]
enabled = true
listen = "127.0.0.1:%d"
advertise_host = "127.0.0.1"
`, httpsPort, pathLine(path), quicPort)
	if err := os.WriteFile(filepath.Join(dir, "pf-simple.toml"), []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	out := &syncBuffer{}
	cmd := exec.Command(bin, "-c", "pf-simple.toml")
	cmd.Dir, cmd.Stdout, cmd.Stderr = dir, out, out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		if t.Failed() {
			t.Logf("pf-simple hub's log:\n%s", out.String())
		}
	})
	hub := &pfHub{url: fmt.Sprintf("https://127.0.0.1:%d%s/", httpsPort, path), caFile: filepath.Join(dir, "certs", "ca.pem")}
	deadline := time.Now().Add(T)
	for {
		if pem, err := os.ReadFile(hub.caFile); err == nil && strings.Contains(out.String(), "QUIC listener on") {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(pem) {
				hub.tls = &tls.Config{RootCAs: pool}
				if c, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", httpsPort), hub.tls); err == nil {
					c.Close()
					return hub
				}
			}
		}
		if time.Now().After(deadline) {
			if os.Getenv("TLSPROXY_LIVE") != "" {
				t.Fatalf("the pf-simple hub did not start:\n%s", out.String())
			}
			t.Skipf("the pf-simple hub did not start (set TLSPROXY_LIVE to make this fail):\n%s", out.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func pathLine(path string) string {
	if path == "" {
		return ""
	}
	return fmt.Sprintf("path = %q\n", path)
}

// serve serves a new tunnel to target from this process, over QUIC or
// WebSockets, asking for clientToken if it is not empty. It returns the
// tunnel's word once a connecting client can see it.
func (h *pfHub) serve(t *testing.T, overQUIC bool, target, clientToken string) string {
	t.Helper()
	word, err := pfrelay.NewWord()
	if err != nil {
		t.Fatal(err)
	}
	newClient := pfrelay.NewClient
	if overQUIC {
		newClient = pfrelayquic.NewClient
	}
	server, err := newClient(h.url, word, h.tls)
	if err != nil {
		t.Fatal(err)
	}
	server.Name, server.ClientToken, server.Logf = "tlsproxy test", clientToken, func(string, ...any) {}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); server.Serve(ctx, target) }()
	t.Cleanup(func() { cancel(); <-done; server.Close() })

	check, err := pfrelayquic.NewClient(h.url, word, h.tls)
	if err != nil {
		t.Fatal(err)
	}
	defer check.Close()
	check.ClientToken = clientToken
	deadline := time.Now().Add(T)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		err := check.Check(ctx)
		cancel()
		if err == nil {
			return word
		}
		if time.Now().After(deadline) {
			t.Fatalf("the tunnel to %s is not served: %v", target, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// exchange is the exchanges section with h as its one item, hub.
func (h *pfHub) exchange() string {
	return fmt.Sprintf("exchanges:\n  - name: hub\n    hub: %q\n    ca_file: %q\n", h.url, h.caFile)
}

// endpoint is an endpoints item for word on h.
func endpointItem(name, word, clientToken string) string {
	s := fmt.Sprintf("  - name: %s\n    exchange: hub\n    word: %s\n", name, word)
	if clientToken != "" {
		s += fmt.Sprintf("    client_token: %q\n", clientToken)
	}
	return s
}

// relayLogLine waits for the proxy's log line that has every one of parts.
func relayLogLine(t *testing.T, parts ...string) string {
	t.Helper()
	deadline := time.Now().Add(T)
	for {
		sc := bufio.NewScanner(strings.NewReader(testLog.String()))
		sc.Buffer(make([]byte, 64<<10), 1<<20)
	lines:
		for sc.Scan() {
			for _, p := range parts {
				if !strings.Contains(sc.Text(), p) {
					continue lines
				}
			}
			return sc.Text()
		}
		if time.Now().After(deadline) {
			t.Fatalf("no log line with %q", parts)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// tlsEchoBackend is a TLS server for names that writes tag and its ALPN,
// then echoes. With proxied, it first reads a PROXY protocol header and
// reports the source it states.
func (ca *testCA) tlsEchoBackend(t *testing.T, tag string, proxied chan<- string, names ...string) int {
	t.Helper()
	certPEM, keyPEM := ca.issue(t, 12*time.Hour, names...)
	cert, _ := tls.X509KeyPair(certPEM, keyPEM)
	return backend(t, func(raw *net.TCPConn) {
		var c net.Conn = raw
		if proxied != nil {
			pc, err := detectProxyProtocol(raw)
			if err != nil {
				proxied <- "error: " + err.Error()
				return
			}
			proxied <- pc.RemoteAddr().String()
			c = pc
		}
		tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}})
		if tc.Handshake() != nil {
			return
		}
		fmt.Fprintf(tc, "%s[%s]", tag, tc.ConnectionState().NegotiatedProtocol)
		io.Copy(tc, tc)
		tc.CloseWrite()
	})
}

// plainBackend reads until EOF and answers with what it got. With proxied,
// it first reads a PROXY protocol header and reports the source it states.
func plainBackend(t *testing.T, proxied chan<- string) int {
	return backend(t, func(raw *net.TCPConn) {
		var c net.Conn = raw
		if proxied != nil {
			pc, err := detectProxyProtocol(raw)
			if err != nil {
				proxied <- "error: " + err.Error()
				return
			}
			proxied <- pc.RemoteAddr().String()
			c = pc
		}
		data, _ := io.ReadAll(c)
		fmt.Fprintf(c, "backend got %q", data)
	})
}

// Every kind of rule through a tunnel, with the serving side over QUIC and
// over WebSockets: passthrough, terminated with a plaintext and a TLS
// upstream, PROXY v1 and v2, client tokens, and the failures.
func TestRelayThroughPFSimpleHub(t *testing.T) {
	hub := startHub(t)
	ca := newTestCA(t)
	local := ca.localCA(t)
	for _, overQUIC := range []bool{true, false} {
		via := map[bool]string{true: "quic", false: "ws"}[overQUIC]
		t.Run("served over "+via, func(t *testing.T) {
			name := func(kind string) string { return kind + "-" + via + ".relay.test" }
			const token = "correct-horse-battery"
			proxied1, proxied2 := make(chan string, 1), make(chan string, 1)
			echo := backend(t, func(c *net.TCPConn) { io.Copy(c, c); c.CloseWrite() })
			closedPort := freePort(t)

			words := map[string]string{
				"pass":   hub.serve(t, overQUIC, fmt.Sprintf("127.0.0.1:%d", ca.tlsEchoBackend(t, "P", nil, name("pass"))), ""),
				"plain":  hub.serve(t, overQUIC, fmt.Sprintf("127.0.0.1:%d", plainBackend(t, nil)), ""),
				"tls":    hub.serve(t, overQUIC, fmt.Sprintf("127.0.0.1:%d", ca.tlsEchoBackend(t, "B", nil, "backend.internal")), ""),
				"proxy2": hub.serve(t, overQUIC, fmt.Sprintf("127.0.0.1:%d", ca.tlsEchoBackend(t, "X", proxied2, name("proxy2"))), ""),
				"proxy1": hub.serve(t, overQUIC, fmt.Sprintf("127.0.0.1:%d", plainBackend(t, proxied1)), ""),
				"token":  hub.serve(t, overQUIC, fmt.Sprintf("127.0.0.1:%d", plainBackend(t, nil)), token),
				"echo":   hub.serve(t, overQUIC, fmt.Sprintf("127.0.0.1:%d", echo), ""),
				"down":   hub.serve(t, overQUIC, fmt.Sprintf("127.0.0.1:%d", closedPort), ""),
			}
			unserved, _ := pfrelay.NewWord()
			relays := hub.exchange() + "endpoints:\n" +
				endpointItem("pass", words["pass"], "") +
				endpointItem("plain", words["plain"], "") +
				endpointItem("tls", words["tls"], "") +
				endpointItem("proxy2", words["proxy2"], "") +
				endpointItem("proxy1", words["proxy1"], "") +
				endpointItem("token", words["token"], token) +
				endpointItem("badtoken", words["token"], "wrong-horse-battery") +
				endpointItem("notoken", words["token"], "") +
				endpointItem("echo", words["echo"], "") +
				endpointItem("down", words["down"], "") +
				endpointItem("unserved", unserved, "")
			rule := func(kind, relay, extra string) string {
				return fmt.Sprintf("      - domain: %s\n        target: relay://%s\n%s", name(kind), relay, extra)
			}
			term := "        cert: " + local + "\n"
			plain := term + "        upstream_tls: false\n"
			config := "global:\n  stats_interval: 0\n  max_handshakes_per_ip: 0\n  connect_timeout: 5\n" +
				"listeners:\n  - name: default\n    port: 1\n" +
				"routes:\n  - listener: default\n    rules:\n" +
				rule("pass", "pass", "") +
				rule("plain", "plain", plain) +
				rule("tls", "tls", term+"        upstream_tls_verify: false\n") +
				rule("verify", "tls", term) +
				rule("proxy2", "proxy2", "        proxy: v2\n") +
				rule("proxy1", "proxy1", plain+"        proxy: v1\n") +
				rule("token", "token", plain) +
				rule("badtoken", "badtoken", plain) +
				rule("notoken", "notoken", plain) +
				rule("big", "echo", plain+"        max_single_connection_speed: 64MiB/s\n") +
				rule("down", "down", plain) +
				rule("unserved", "unserved", plain) +
				relays
			p := startProxyText(t, config, "")
			t.Cleanup(func() {
				if t.Failed() {
					var mine []string
					for _, line := range strings.Split(testLog.String(), "\n") {
						if strings.Contains(line, "-"+via+".relay.test") || strings.Contains(line, "relay://") {
							mine = append(mine, line)
						}
					}
					t.Logf("the proxy's log:\n%s", strings.Join(mine, "\n"))
				}
			})

			// clientTLS dials the proxy for kind's name, trusting the test CA
			// (the backend's certificate when passed through, else the proxy's).
			clientTLS := func(t *testing.T, kind string, protos ...string) (*tls.Conn, string, error) {
				raw := dial(t, p)
				tc := tls.Client(raw, &tls.Config{RootCAs: ca.pool, ServerName: name(kind), NextProtos: protos})
				tc.SetDeadline(time.Now().Add(T))
				return tc, raw.LocalAddr().String(), tc.Handshake()
			}
			mustTLS := func(t *testing.T, kind string, protos ...string) (*tls.Conn, string) {
				t.Helper()
				tc, src, err := clientTLS(t, kind, protos...)
				if err != nil {
					t.Fatalf("handshake: %v", err)
				}
				return tc, src
			}
			// plainExchange sends msg, half-closes, and expects the plain
			// backend's answer: half-close crosses the tunnel both ways.
			plainExchange := func(t *testing.T, tc *tls.Conn, msg string) {
				t.Helper()
				tc.Write([]byte(msg))
				tc.CloseWrite()
				if got, want := string(readToEnd(t, tc)), fmt.Sprintf("backend got %q", msg); got != want {
					t.Fatalf("got %q, want %q", got, want)
				}
			}

			t.Run("passthrough", func(t *testing.T) {
				tc, _ := mustTLS(t, "pass", "h2", "http/1.1")
				if st := tc.ConnectionState(); st.PeerCertificates[0].DNSNames[0] != name("pass") || st.NegotiatedProtocol != "h2" {
					t.Fatalf("not the backend's own TLS: cert %v alpn %q", st.PeerCertificates[0].DNSNames, st.NegotiatedProtocol)
				}
				tc.Write([]byte("ping"))
				tc.CloseWrite()
				if got := string(readToEnd(t, tc)); got != "P[h2]ping" {
					t.Fatalf("%q", got)
				}
				// Passed through, close_notify is only bytes to the proxy, and
				// the client's Read ends at the backend's close_notify, which
				// may be before the proxy sees the backend's FIN: either side
				// may be the first to close, cleanly.
				tc.Close()
				line := relayLogLine(t, "connected", "-> relay://pass (")
				if !strings.Contains(line, " conn ") {
					t.Errorf("the peer should name the hub's connection id: %s", line)
				}
				if r := closeReason(t, name("pass")); !strings.HasPrefix(r, "upstream closed, then client closed") && !strings.HasPrefix(r, "client closed, then upstream closed") {
					t.Errorf("reason %q", r)
				}
			})

			t.Run("terminated, plaintext upstream", func(t *testing.T) {
				tc, _ := mustTLS(t, "plain", "h2", "http/1.1")
				if tc.ConnectionState().NegotiatedProtocol != "http/1.1" {
					t.Errorf("alpn %q: a plaintext upstream can't do h2", tc.ConnectionState().NegotiatedProtocol)
				}
				plainExchange(t, tc, "hello through the tunnel")
			})

			t.Run("terminated, TLS upstream", func(t *testing.T) {
				for _, offer := range []string{"h2", "http/1.1"} {
					tc, _ := mustTLS(t, "tls", offer)
					if got := tc.ConnectionState().NegotiatedProtocol; got != offer {
						t.Fatalf("client got %q, want %q (the upstream's choice)", got, offer)
					}
					tc.Write([]byte("ping"))
					want := "B[" + offer + "]ping"
					if got := string(readN(t, tc, len(want))); got != want {
						t.Fatalf("%q", got)
					}
					tc.Close()
				}
			})

			t.Run("terminated, TLS upstream not trusted", func(t *testing.T) {
				// upstream_tls_verify defaults to true and the system roots don't
				// know the backend's CA: nothing may be relayed.
				tc, _, err := clientTLS(t, "verify")
				if err == nil {
					if n, _ := tc.Read(make([]byte, 1)); n > 0 {
						t.Fatal("relayed to an unverified upstream")
					}
				}
				relayLogLine(t, "sni="+name("verify")+" ", "upstream TLS handshake failed")
			})

			t.Run("PROXY v2, passthrough", func(t *testing.T) {
				tc, src := mustTLS(t, "proxy2")
				tc.Write([]byte("ping"))
				if got := string(readN(t, tc, len("X[]ping"))); got != "X[]ping" {
					t.Fatalf("%q", got)
				}
				if got := <-proxied2; got != src {
					t.Fatalf("PROXY source %q, want the client's %q", got, src)
				}
				tc.Close()
			})

			t.Run("PROXY v1, terminated", func(t *testing.T) {
				tc, src := mustTLS(t, "proxy1")
				plainExchange(t, tc, "with a v1 header")
				if got := <-proxied1; got != src {
					t.Fatalf("PROXY source %q, want the client's %q", got, src)
				}
			})

			t.Run("client token", func(t *testing.T) {
				tc, _ := mustTLS(t, "token")
				plainExchange(t, tc, "with the right token")
				for _, kind := range []string{"badtoken", "notoken"} {
					if tc, _, err := clientTLS(t, kind); err == nil {
						if n, _ := tc.Read(make([]byte, 1)); n > 0 {
							t.Fatalf("%s: relayed", kind)
						}
					}
					relayLogLine(t, "sni="+name(kind)+" ", "connect failed: endpoint "+kind+": access denied")
				}
			})

			t.Run("tunnel not served", func(t *testing.T) {
				if tc, _, err := clientTLS(t, "unserved"); err == nil {
					if n, _ := tc.Read(make([]byte, 1)); n > 0 {
						t.Fatal("relayed")
					}
				}
				relayLogLine(t, "sni="+name("unserved")+" ", "connect failed: endpoint unserved: ")
			})

			t.Run("serving side cannot reach its target", func(t *testing.T) {
				tc, _ := mustTLS(t, "down")
				tc.Write([]byte("anyone there?"))
				tc.CloseWrite()
				if got := readToEnd(t, tc); len(got) > 0 {
					t.Fatalf("got %q from nowhere", got)
				}
				if r := closeReason(t, name("down")); !strings.Contains(r, "the serving side could not reach its target") {
					t.Errorf("the far side's failure should be the reason, got %q", r)
				}
			})

			t.Run("8 MiB each way, speed limited", func(t *testing.T) {
				tc, _ := mustTLS(t, "big")
				tc.SetDeadline(time.Now().Add(3 * T))
				data := make([]byte, 8<<20)
				rand.Read(data)
				go func() { tc.Write(data); tc.CloseWrite() }()
				got, err := io.ReadAll(tc)
				if err != nil {
					t.Fatalf("after %d bytes: %v", len(got), err)
				}
				if sha256.Sum256(got) != sha256.Sum256(data) {
					t.Fatalf("got %d bytes, not what was sent", len(got))
				}
			})

			// Many connections at once share the one QUIC connection.
			t.Run("concurrent", func(t *testing.T) {
				var wg sync.WaitGroup
				errs := make(chan error, 20)
				for i := 0; i < 20; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						tc, _, err := clientTLS(t, "plain")
						if err != nil {
							errs <- err
							return
						}
						msg := fmt.Sprintf("connection %d", i)
						tc.Write([]byte(msg))
						tc.CloseWrite()
						got, _ := io.ReadAll(tc)
						if want := fmt.Sprintf("backend got %q", msg); string(got) != want {
							errs <- fmt.Errorf("got %q, want %q", got, want)
						}
					}()
				}
				wg.Wait()
				close(errs)
				for err := range errs {
					t.Error(err)
				}
				p.srv.relays.mu.Lock()
				n := len(p.srv.relays.clients)
				p.srv.relays.mu.Unlock()
				if n > len(words)+3 {
					t.Errorf("%d clients for %d tunnels", n, len(words)+3)
				}
			})
		})
	}
}

// A reload that drops a tunnel keeps its open connections; its client is
// closed once the last one ends, and made again when a tunnel needs it.
func TestRelayReloadKeepsOpenConnections(t *testing.T) {
	hub := startHub(t)
	echo := backend(t, func(c *net.TCPConn) { io.Copy(c, c); c.CloseWrite() })
	word := hub.serve(t, true, fmt.Sprintf("127.0.0.1:%d", echo), "")
	cfg := mustLoadYAML(t, relayListener+hub.exchange()+"endpoints:\n"+endpointItem("echo", word, ""))
	pool := newRelayPool()
	defer pool.closeAll()
	r := cfg.Endpoints["echo"]

	conn, err := pool.dial(r, T)
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(T))
	pool.sync(&Config{}) // the reload: no relays any more
	conn.Write([]byte("still here"))
	if got := string(readN(t, conn, len("still here"))); got != "still here" {
		t.Fatalf("%q", got)
	}
	if n := len(pool.clients); n != 1 {
		t.Fatalf("%d clients while a connection is open, want 1", n)
	}
	conn.Close()
	if n := len(pool.clients); n != 0 {
		t.Fatalf("%d clients after the last connection, want 0", n)
	}

	// Back in a configuration: a new client.
	conn, err = pool.dial(r, T)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(T))
	conn.Write([]byte("again"))
	if got := string(readN(t, conn, len("again"))); got != "again" {
		t.Fatalf("%q", got)
	}
}
