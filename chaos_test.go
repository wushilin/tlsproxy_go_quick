package main

// The combination test: every way a connection can be handled, at once, on
// one proxy, each checked end to end.
//
// Each case has its own rule (one name), its own backend and a random
// payload, and checks: the certificate the client is given, that it reached
// its own backend, what that backend received (the PROXY header and the
// client address it states, the name the backend's TLS saw), that the payload
// arrived intact both ways, and what the proxy logged and put in the flow
// log. The cases cross:
//
//	TLS        passed through, or terminated with a local CA
//	backend    TCP echo, TLS echo, HTTP, HTTPS (where the pairing makes sense)
//	PROXY out  none, v1, v2 (to the backend)
//	PROXY in   none, v1, v2 (from a load balancer in front of the proxy)
//	relay      splice on and off (two proxies)
//	listener   the first or a second one; with or without a speed limit
//
// and refused ones: a deny rule, a name no rule matches, a name the local CA
// doesn't issue for, a backend that is down, an upstream certificate that
// fails verification. The seed is logged; TLSPROXY_CHAOS_SEED repeats a run.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------- what a backend sees

// seen is what a backend found out about one connection.
type seen struct {
	proxyVersion int    // 0: no PROXY header
	src          string // the client address the header stated ("" without one)
	sni          string // the name its TLS saw ("" for plain backends)
	alpn         string // the ALPN protocols it was offered, comma-separated
	chose        string // the one it agreed to
	version      uint16 // the TLS version it spoke
}

func (s seen) String() string {
	return fmt.Sprintf("proxy=v%d src=%s sni=%s alpn=%s chose=%s ver=%x", s.proxyVersion, s.src, s.sni, s.alpn, s.chose, s.version)
}

// learn records what a TLS backend's ClientHello offered.
func (s *seen) learn(h *tls.ClientHelloInfo) {
	s.sni, s.alpn = h.ServerName, strings.Join(h.SupportedProtos, ",")
}

// readProxyHeader consumes a PROXY v1 or v2 header if the stream starts with
// one. It is written here from the specification, not borrowed from the
// proxy, so the two check each other.
func readProxyHeader(br *bufio.Reader) (version int, src string, err error) {
	peek, _ := br.Peek(12)
	switch {
	case bytes.HasPrefix(peek, []byte("PROXY ")):
		line, err := br.ReadString('\n')
		if err != nil {
			return 0, "", err
		}
		f := strings.Fields(strings.TrimSpace(line)) // PROXY TCP4 src dst sport dport
		if len(f) != 6 {
			return 0, "", fmt.Errorf("bad v1 line %q", line)
		}
		return 1, net.JoinHostPort(f[2], f[4]), nil
	case bytes.Equal(peek, []byte("\r\n\r\n\x00\r\nQUIT\n")):
		hdr := make([]byte, 16)
		if _, err := io.ReadFull(br, hdr); err != nil {
			return 0, "", err
		}
		body := make([]byte, binary.BigEndian.Uint16(hdr[14:16]))
		if _, err := io.ReadFull(br, body); err != nil {
			return 0, "", err
		}
		switch hdr[13] >> 4 { // address family
		case 1: // IPv4: src(4) dst(4) sport(2) dport(2)
			return 2, net.JoinHostPort(net.IP(body[0:4]).String(), strconv.Itoa(int(binary.BigEndian.Uint16(body[8:10])))), nil
		case 2: // IPv6: src(16) dst(16) sport(2) dport(2)
			return 2, net.JoinHostPort(net.IP(body[0:16]).String(), strconv.Itoa(int(binary.BigEndian.Uint16(body[32:34])))), nil
		}
		return 2, "", nil
	}
	return 0, "", nil
}

// bufConn is a connection whose first bytes were already read into br.
type bufConn struct {
	net.Conn
	br *bufio.Reader
}

func (c *bufConn) Read(p []byte) (int, error) { return c.br.Read(p) }

// echoKind backends write one line saying what they saw, then echo.
func chaosEchoBackend(t *testing.T, tag string, tlsCfg *tls.Config) int {
	return backend(t, func(raw *net.TCPConn) {
		br := bufio.NewReader(raw)
		var s seen
		var err error
		if s.proxyVersion, s.src, err = readProxyHeader(br); err != nil {
			return
		}
		var c net.Conn = &bufConn{raw, br}
		if tlsCfg != nil {
			cfg := tlsCfg.Clone()
			cfg.GetConfigForClient = func(h *tls.ClientHelloInfo) (*tls.Config, error) { s.learn(h); return nil, nil }
			tc := tls.Server(c, cfg)
			if tc.Handshake() != nil {
				return
			}
			st := tc.ConnectionState()
			s.chose, s.version = st.NegotiatedProtocol, st.Version
			c = tc
		}
		fmt.Fprintf(c, "%s %s\n", tag, s)
		io.Copy(c, c)
		if tc, ok := c.(*tls.Conn); ok {
			tc.CloseWrite()
		} else {
			raw.CloseWrite()
		}
	})
}

// headerListener reads the PROXY header (if any) of every connection it
// accepts, for an HTTP server; the header's facts go to the handler.
type headerListener struct {
	net.Listener
	tlsCfg *tls.Config
}

type seenConn struct {
	net.Conn
	s *seen
}

func (l headerListener) Accept() (net.Conn, error) {
	for {
		c, err := l.accept()
		if c != nil || err != nil {
			return c, err
		}
	}
}

// accept reads one connection's PROXY header and, for HTTPS, does its TLS
// handshake (recording what was agreed); nil, nil drops a broken one.
func (l headerListener) accept() (net.Conn, error) {
	raw, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	br := bufio.NewReader(raw)
	s := &seen{}
	raw.SetReadDeadline(time.Now().Add(T))
	s.proxyVersion, s.src, _ = readProxyHeader(br)
	raw.SetReadDeadline(time.Time{})
	var c net.Conn = &bufConn{raw, br}
	if l.tlsCfg != nil {
		cfg := l.tlsCfg.Clone()
		cfg.GetConfigForClient = func(h *tls.ClientHelloInfo) (*tls.Config, error) { s.learn(h); return nil, nil }
		tc := tls.Server(c, cfg)
		tc.SetDeadline(time.Now().Add(T))
		if tc.Handshake() != nil {
			raw.Close()
			return nil, nil
		}
		tc.SetDeadline(time.Time{})
		st := tc.ConnectionState()
		s.chose, s.version = st.NegotiatedProtocol, st.Version
		c = tc
	}
	return seenConn{c, s}, nil
}

type seenKey struct{}

// chaosHTTPBackend answers every request with what it saw and the SHA-256 of
// the request body.
func chaosHTTPBackend(t *testing.T, tag string, tlsCfg *tls.Config) int {
	l, port := listen(t)
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s := r.Context().Value(seenKey{}).(*seen)
			sum := sha256.New()
			io.Copy(sum, r.Body)
			fmt.Fprintf(w, "%s %s host=%s body=%s\n", tag, *s, r.Host, hex.EncodeToString(sum.Sum(nil)))
		}),
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, seenKey{}, c.(seenConn).s)
		},
	}
	go srv.Serve(headerListener{l, tlsCfg})
	t.Cleanup(func() { srv.Close() })
	return port
}

// ---------------------------------------------------------------- the cases

type chaosCase struct {
	name     string // the SNI, unique per case
	pass     bool   // passed through (else terminated: with the local CA, or auto)
	auto     bool   // terminated with cert = auto (Pebble)
	backend  string // tcp, tls, http, https
	proxyOut int    // PROXY version the rule sends; 0 = none
	proxyIn  int    // PROXY version a load balancer in front sends; 0 = none
	second   bool   // on the second listener
	limit    bool   // with a per-connection speed limit
	payload  []byte
	port     int // its backend

	lbSrc string // the client address the load balancer states
}

func (c *chaosCase) upstreamTLS() bool { return c.backend == "tls" || c.backend == "https" }
func (c *chaosCase) http() bool        { return c.backend == "http" || c.backend == "https" }

func (c *chaosCase) rule() string {
	var b strings.Builder
	fmt.Fprintf(&b, "[[host]]\nlistener = %s\npattern = %s\ntarget_host = 127.0.0.1\ntarget_port = %d\n",
		map[bool]string{true: "second", false: "first"}[c.second], c.name, c.port)
	if !c.pass {
		if c.auto {
			b.WriteString("cert = auto\n")
		} else {
			b.WriteString("cert = " + chaosLocalCA + "\n")
		}
		if c.upstreamTLS() {
			b.WriteString("upstream_tls_verify = false\n") // the backend's CA is not a public one
		} else {
			b.WriteString("upstream_tls = false\n")
		}
	}
	if c.proxyOut > 0 {
		fmt.Fprintf(&b, "proxy = true\nproxy_version = %d\n", c.proxyOut)
	}
	if c.limit {
		b.WriteString("max_single_connection_speed = 64MiB/s\n")
	}
	return b.String()
}

var chaosLocalCA string // set by the test: local-ca:caNNN

// newChaosCase makes case n, with a random payload and its own backend.
func newChaosCase(t *testing.T, rnd *rand.Rand, n int, mode, be string, out, in int, backendTLS *tls.Config) *chaosCase {
	c := &chaosCase{
		name:    fmt.Sprintf("c%d-%s-%s-out%d-in%d.chaos.test", n, mode, be, out, in),
		backend: be, proxyOut: out, proxyIn: in, limit: rnd.Intn(3) == 0,
		payload: make([]byte, rnd.Intn(200<<10)),
		lbSrc:   fmt.Sprintf("203.0.113.%d:%d", 1+rnd.Intn(250), 1024+rnd.Intn(60000)),
	}
	rnd.Read(c.payload)
	tag := "B" + strconv.Itoa(n)
	var tlsCfg *tls.Config
	if c.upstreamTLS() {
		tlsCfg = backendTLS
	}
	if c.http() {
		c.port = chaosHTTPBackend(t, tag, tlsCfg)
	} else {
		c.port = chaosEchoBackend(t, tag, tlsCfg)
	}
	return c
}

// runChaosCases runs every case at once and checks each.
func runChaosCases(t *testing.T, p *proxyUnderTest, cases []*chaosCase, secondAddr string, termTrust, passTrust *x509.CertPool, splice bool) {
	var wg sync.WaitGroup
	for _, c := range cases {
		wg.Add(1)
		go func() {
			defer wg.Done()
			addr := p.addr
			if c.second {
				addr = secondAddr
			}
			trust := termTrust
			if c.pass {
				trust = passTrust // passed through: the backend's own certificate
			}
			line, _, leaf, st, err := c.runState(t, addr, trust)
			if err != nil {
				t.Errorf("%s: %v", c.name, err)
				return
			}
			checkChaosCase(t, p, c, line, leaf, splice)
			checkChaosTLS(t, c, line, st)
		}()
	}
	wg.Wait()
}

// chaosBackendTLS is the backends' own TLS: a certificate for *.chaos.test
// from a CA of their own.
func chaosBackendTLS(t *testing.T) (*tls.Config, *testCA) {
	backendCA := newTestCA(t)
	certPEM, keyPEM := backendCA.issue(t, time.Hour, "*.chaos.test")
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	// The echo backends choose x-chaos (their first choice) when offered;
	// nothing else would pick that, so seeing it proves where the choice came from.
	return &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"x-chaos", "http/1.1"}}, backendCA
}

// ---------------------------------------------------------------- the client side

// dialChaos connects to the proxy and, when the case has a load balancer in
// front, sends its PROXY header first.
func dialChaos(t *testing.T, addr string, c *chaosCase) (net.Conn, error) {
	raw, err := net.DialTimeout("tcp", addr, T)
	if err != nil {
		return nil, err
	}
	raw.SetDeadline(time.Now().Add(3 * T))
	if c.proxyIn > 0 {
		host, port, _ := net.SplitHostPort(c.lbSrc)
		src, dst := &net.TCPAddr{IP: net.ParseIP(host), Port: atoi(port)}, raw.RemoteAddr().(*net.TCPAddr)
		hdr, err := proxyProtocolHeader(c.proxyIn, src, dst)
		if err != nil {
			t.Fatal(err)
		}
		raw.Write(hdr)
	}
	return raw, nil
}

func atoi(s string) int { n, _ := strconv.Atoi(s); return n }

// run sends the payload and returns the backend's line and what came back.
// clientALPN is what the client offers: for raw TLS, a protocol only the echo
// backends choose (x-chaos), so a match proves the choice came from them.
func (c *chaosCase) clientALPN() []string {
	if c.http() {
		return []string{"http/1.1"}
	}
	return []string{"h2", "x-chaos"}
}

func (c *chaosCase) run(t *testing.T, addr string, trust *x509.CertPool) (line string, echoed []byte, leaf *x509.Certificate, err error) {
	line, echoed, leaf, _, err = c.runState(t, addr, trust)
	return
}

// runState is run, also giving the client's own view of its TLS.
func (c *chaosCase) runState(t *testing.T, addr string, trust *x509.CertPool) (line string, echoed []byte, leaf *x509.Certificate, st tls.ConnectionState, err error) {
	raw, err := dialChaos(t, addr, c)
	if err != nil {
		return "", nil, nil, st, err
	}
	defer raw.Close()
	if c.http() {
		// HTTP(S) end to end (passed through) or to the proxy (terminated).
		tc := tls.Client(raw, &tls.Config{RootCAs: trust, ServerName: c.name, NextProtos: c.clientALPN()})
		if err := tc.Handshake(); err != nil {
			return "", nil, nil, st, err
		}
		st = tc.ConnectionState()
		leaf = st.PeerCertificates[0]
		req, _ := http.NewRequest("POST", "https://"+c.name+"/upload", bytes.NewReader(c.payload))
		req.Write(tc)
		resp, err := http.ReadResponse(bufio.NewReader(tc), req)
		if err != nil {
			return "", nil, leaf, st, err
		}
		body, err := io.ReadAll(resp.Body)
		return strings.TrimSpace(string(body)), nil, leaf, st, err
	}
	var conn net.Conn = raw
	var sent []byte
	if c.pass && c.backend == "tcp" {
		// A plain backend behind a passed-through rule just gets the bytes:
		// the ClientHello the proxy read, then the payload.
		sent = append(clientHello(c.name), c.payload...)
		go func() { raw.Write(sent); raw.(*net.TCPConn).CloseWrite() }()
	} else {
		tc := tls.Client(raw, &tls.Config{RootCAs: trust, ServerName: c.name, NextProtos: c.clientALPN()})
		if err := tc.Handshake(); err != nil {
			return "", nil, nil, st, err
		}
		st = tc.ConnectionState()
		leaf = st.PeerCertificates[0]
		conn, sent = tc, c.payload
		go func() { tc.Write(sent); tc.CloseWrite() }()
	}
	br := bufio.NewReader(conn)
	line, err = br.ReadString('\n')
	if err != nil {
		return "", nil, leaf, st, fmt.Errorf("no line from the backend: %w", err)
	}
	echoed, err = io.ReadAll(br)
	if err != nil && !bytes.Equal(echoed, sent) {
		return line, echoed, leaf, st, err
	}
	if !bytes.Equal(echoed, sent) {
		return line, echoed, leaf, st, fmt.Errorf("echo: sent %d bytes, got %d back (or different ones)", len(sent), len(echoed))
	}
	return strings.TrimSpace(line), echoed, leaf, st, nil
}

// ---------------------------------------------------------------- the test

func chaosSeed(t *testing.T) int64 {
	seed := time.Now().UnixNano()
	if s := os.Getenv("TLSPROXY_CHAOS_SEED"); s != "" {
		seed, _ = strconv.ParseInt(s, 10, 64)
	}
	t.Logf("seed %d (TLSPROXY_CHAOS_SEED=%d repeats this run)", seed, seed)
	return seed
}

func TestChaosCombinations(t *testing.T) {
	t.Parallel()
	seed := chaosSeed(t)
	ourCA := newTestCA(t)
	chaosLocalCA = ourCA.localCA(t)
	backendTLS, backendCA := chaosBackendTLS(t)

	for _, splice := range []bool{true, false} {
		t.Run(fmt.Sprintf("splice=%v", splice), func(t *testing.T) {
			t.Parallel()
			rnd := rand.New(rand.NewSource(seed + map[bool]int64{true: 1, false: 2}[splice]))
			var cases []*chaosCase
			n := 0
			for _, mode := range []struct {
				pass     bool
				backends []string
			}{{true, []string{"tcp", "tls", "https"}}, {false, []string{"tcp", "tls", "http", "https"}}} {
				for _, be := range mode.backends {
					for _, out := range []int{0, 1, 2} {
						for _, in := range []int{0, 1, 2} {
							n++
							c := newChaosCase(t, rnd, n, map[bool]string{true: "pass", false: "term"}[mode.pass], be, out, in, backendTLS)
							c.pass, c.second = mode.pass, rnd.Intn(2) == 0
							cases = append(cases, c)
						}
					}
				}
			}
			rnd.Shuffle(len(cases), func(i, j int) { cases[i], cases[j] = cases[j], cases[i] })

			// Refused ones, on the first listener.
			// Refused, always: a port from freePort could be taken by a parallel
			// test before it is used, and then the connection would succeed.
			down := 1
			verifyFails := chaosEchoBackend(t, "never", backendTLS)
			second := freePort(t)
			var rules strings.Builder
			for _, c := range cases {
				rules.WriteString(c.rule())
			}
			fmt.Fprintf(&rules, "[[host]]\nlistener = first\npattern = denied.chaos.test\naction = deny\n")
			fmt.Fprintf(&rules, "[[host]]\nlistener = first\npattern = *.refuse.chaos.test\ncert = %s\ncert_domains = ok.refuse.chaos.test\nupstream_tls = false\ntarget_host = 127.0.0.1\ntarget_port = %d\n", chaosLocalCA, down)
			fmt.Fprintf(&rules, "[[host]]\nlistener = first\npattern = down.chaos.test\ntarget_host = 127.0.0.1\ntarget_port = %d\n", down)
			fmt.Fprintf(&rules, "[[host]]\nlistener = first\npattern = verify.chaos.test\ncert = %s\ntarget_host = 127.0.0.1\ntarget_port = %d\n", chaosLocalCA, verifyFails)
			text := fmt.Sprintf("[global]\nstats_interval = 0\nmax_handshakes_per_ip = 0\nsplice = %v\nproxy_protocol_from = 127.0.0.1\n"+
				"[[listener]]\nname = first\nport = 1\n[[listener]]\nname = second\nbind = 127.0.0.1\nport = %d\n%s", splice, second, rules.String())
			p := startProxyText(t, text, "")
			secondAddr := fmt.Sprintf("127.0.0.1:%d", second)
			waitForPort(t, secondAddr)

			runChaosCases(t, p, cases, secondAddr, ourCA.pool, backendCA.pool, splice)
			checkRefused(t, p, ourCA)
		})
	}
}

// checkChaosCase checks one finished case: what the client saw, what its
// backend saw, and what the proxy logged.
func checkChaosCase(t *testing.T, p *proxyUnderTest, c *chaosCase, line string, leaf *x509.Certificate, splice bool) {
	t.Helper()
	fail := func(format string, a ...any) { t.Errorf("%s: %s", c.name, fmt.Sprintf(format, a...)) }

	// The certificate: the backend's own when passed through, ours (issued for
	// exactly this name) when terminated.
	if leaf != nil {
		switch {
		case c.pass && (len(leaf.DNSNames) == 0 || leaf.DNSNames[0] != "*.chaos.test"):
			fail("passed through, but the client got a certificate for %v, not the backend's own", leaf.DNSNames)
		case !c.pass && (len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != c.name):
			fail("terminated: certificate for %v, want exactly %s", leaf.DNSNames, c.name)
		case !c.pass && !c.auto && leaf.Issuer.CommonName != "test CA":
			fail("terminated with the local CA, but issued by %q", leaf.Issuer.CommonName)
		case c.auto && !strings.Contains(leaf.Issuer.CommonName, "Pebble"):
			fail("cert = auto, but issued by %q, not the ACME CA", leaf.Issuer.CommonName)
		}
	}

	// Its own backend, and what that backend saw.
	f := strings.Fields(line)
	if len(f) < 4 || f[0] != "B"+strings.Split(strings.TrimPrefix(c.name, "c"), "-")[0] {
		fail("reached the wrong backend: %q", line)
		return
	}
	got := parseSeen(line)
	if got.proxyVersion != c.proxyOut {
		fail("backend got a PROXY v%d header, want v%d", got.proxyVersion, c.proxyOut)
	}
	if c.proxyOut > 0 && c.proxyIn > 0 && got.src != c.lbSrc {
		fail("backend was told the client is %s, but the load balancer said %s", got.src, c.lbSrc)
	}
	if c.proxyOut > 0 && c.proxyIn == 0 && !strings.HasPrefix(got.src, "127.0.0.1:") {
		fail("backend was told the client is %s, want the client's own address", got.src)
	}
	if c.upstreamTLS() && got.sni != c.name {
		fail("backend's TLS saw the name %q, want %q", got.sni, c.name)
	}
	if c.http() {
		sum := sha256.Sum256(c.payload)
		if !strings.Contains(line, "body="+hex.EncodeToString(sum[:])) || !strings.Contains(line, "host="+c.name) {
			fail("HTTP request did not arrive intact: %q", line)
		}
	}

	// The flow log and the log lines.
	fl := clientFlow(t, p, c.name)
	wantTLS := map[bool]string{true: "passthrough", false: "terminated"}[c.pass]
	wantRelay := "copy"
	if c.pass && splice && runtime.GOOS == "linux" {
		wantRelay = "splice"
	}
	switch {
	case fl.Result != flowClosed:
		fail("flow result %q (%s)", fl.Result, fl.Reason)
	case fl.TLS != wantTLS:
		fail("flow says tls=%q, want %q", fl.TLS, wantTLS)
	case fl.ProxyOut != c.proxyOut:
		fail("flow says PROXY v%d, want v%d", fl.ProxyOut, c.proxyOut)
	case (fl.Via != "") != (c.proxyIn > 0) || (c.proxyIn > 0 && fl.ViaVersion != c.proxyIn):
		fail("flow says via %q (v%d), want a load balancer: %v", fl.Via, fl.ViaVersion, c.proxyIn > 0)
	case fl.Relay != wantRelay:
		fail("flow says relay=%q, want %q", fl.Relay, wantRelay)
	case fl.Listener != map[bool]string{true: "second", false: "first"}[c.second]:
		fail("flow says listener %q", fl.Listener)
	case fl.BytesUp < int64(len(c.payload)) || fl.BytesDown == 0 || (!c.http() && fl.BytesDown < int64(len(c.payload))):
		fail("flow counted %d up, %d down for a %d-byte payload", fl.BytesUp, fl.BytesDown, len(c.payload)) // HTTP: only the request carries it
	}
	wantSrc := "127.0.0.1:"
	if c.proxyIn > 0 {
		wantSrc = c.lbSrc
	}
	if fl.Src != wantSrc && !(c.proxyIn == 0 && strings.HasPrefix(fl.Src, wantSrc)) {
		fail("flow says the client is %s, want %s", fl.Src, wantSrc)
	}
	dst := fmt.Sprintf("127.0.0.1:%d", c.port)
	log := testLog.String()
	if !strings.Contains(log, "route sni="+c.name+" -> "+dst+" (ALLOW, rule line ") {
		fail("no route line to %s in the log", dst)
	}
	if !strings.Contains(log, "closed src="+fl.Src+" sni="+c.name+" dst="+dst) {
		fail("no closed line for src=%s dst=%s in the log", fl.Src, dst)
	}
}

// checkRefused tries the cases that must not get through, and what the
// client, the flow log and the log say about each.
func checkRefused(t *testing.T, p *proxyUnderTest, ourCA *testCA) {
	t.Helper()
	tryTLS := func(name string) error {
		tc, err := tlsDial(t, p, &tls.Config{RootCAs: ourCA.pool, ServerName: name})
		if err == nil {
			tc.Write([]byte("x"))
			_, err = tc.Read(make([]byte, 1))
			tc.Close()
		}
		return err
	}
	for _, tc := range []struct {
		name, result, reason, log string
	}{
		{"denied.chaos.test", flowDenied, "deny rule at line", "route sni=denied.chaos.test src="},
		{"nomatch.chaos.test", flowDenied, "no rule matched", "-> DENY (no rule matched"},
		{"bad.refuse.chaos.test", flowFailed, "does not issue for bad.refuse.chaos.test", "sni=bad.refuse.chaos.test: CA "},
		{"down.chaos.test", flowFailed, "connect failed", "sni=down.chaos.test dst="},
		{"verify.chaos.test", flowFailed, "certificate", "sni=verify.chaos.test dst="},
	} {
		if err := tryTLS(tc.name); err == nil {
			t.Errorf("%s: got through", tc.name)
			continue
		}
		f := flowFor(t, p, tc.name)
		if f.Result != tc.result || !strings.Contains(f.Reason, tc.reason) {
			t.Errorf("%s: flow %s %q, want %s with %q", tc.name, f.Result, f.Reason, tc.result, tc.reason)
		}
		if !strings.Contains(testLog.String(), tc.log) {
			t.Errorf("%s: the log lacks %q", tc.name, tc.log)
		}
	}
}

// The same, terminated with cert = auto: certificates from Pebble (Let's
// Encrypt's test CA, in this process), which validates over TLS-ALPN-01
// through the proxy as Let's Encrypt would. Every backend, PROXY out and
// PROXY in.
func TestChaosAutoCertificates(t *testing.T) {
	t.Parallel()
	pb := newPebble(t, nil)
	seed := chaosSeed(t)
	rnd := rand.New(rand.NewSource(seed))
	backendTLS, _ := chaosBackendTLS(t)
	var cases []*chaosCase
	n := 0
	for _, be := range []string{"tcp", "tls", "http", "https"} {
		for _, out := range []int{0, 1, 2} {
			for _, in := range []int{0, 1, 2} {
				n++
				c := newChaosCase(t, rnd, n, "auto", be, out, in, backendTLS)
				c.auto = true
				cases = append(cases, c)
			}
		}
	}
	var rules strings.Builder
	for _, c := range cases {
		rules.WriteString(c.rule())
	}
	text := fmt.Sprintf("[global]\nstats_interval = 0\nmax_handshakes_per_ip = 0\nproxy_protocol_from = 127.0.0.1\n%s\n"+
		"[[listener]]\nname = first\nport = 1\n[[listener]]\nname = second\nbind = 127.0.0.1\nport = %d\n%s",
		pb.global(t.TempDir()), freePort(t), rules.String())
	p := startProxyText(t, text, "")
	_, proxyPort, _ := net.SplitHostPort(p.addr)
	pb.start(t, proxyPort)
	retryCertificatesNow(p.srv.certs)

	// Every name gets its certificate from the CA.
	m := p.srv.certs
	for deadline := time.Now().Add(120 * time.Second); ; time.Sleep(200 * time.Millisecond) {
		missing := 0
		m.mu.RLock()
		for _, c := range cases {
			if m.auto[c.name] == nil {
				missing++
			}
		}
		m.mu.RUnlock()
		if missing == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d of %d names have no certificate after 120s", missing, len(cases))
		}
	}
	runChaosCases(t, p, cases, "", pb.roots(t), nil, true)
}

// clientFlow is the closed flow of the case's client connection: not the
// CA's TLS-ALPN-01 validation, which comes to the same name.
func clientFlow(t *testing.T, p *proxyUnderTest, sni string) flowView {
	t.Helper()
	for deadline := time.Now().Add(T); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		for _, f := range p.srv.stats.flows.closedSince(0) {
			if f.SNI == sni && f.Result != flowACME {
				return f
			}
		}
	}
	t.Fatalf("no closed client flow for %s", sni)
	return flowView{}
}

// parseSeen reads a backend's line: "B<n> proxy=v2 src=... sni=... alpn=... chose=... ver=304 ...".
func parseSeen(line string) seen {
	var s seen
	for _, f := range strings.Fields(line) {
		k, v, _ := strings.Cut(f, "=")
		switch k {
		case "proxy":
			fmt.Sscanf(v, "v%d", &s.proxyVersion)
		case "src":
			s.src = v
		case "sni":
			s.sni = v
		case "alpn":
			s.alpn = v
		case "chose":
			s.chose = v
		case "ver":
			n, _ := strconv.ParseUint(v, 16, 16)
			s.version = uint16(n)
		}
	}
	return s
}

// checkChaosTLS: TLS and ALPN. Passed through, the backend is the client's
// TLS peer: it sees exactly the client's ALPN offer, and the client ends up
// with the backend's choice and version. Terminated in front of a TLS
// backend, the proxy hands the client's offer on, and gives the client the
// protocol the backend chose.
func checkChaosTLS(t *testing.T, c *chaosCase, line string, st tls.ConnectionState) {
	t.Helper()
	if !c.upstreamTLS() {
		return
	}
	got := parseSeen(line)
	offer := strings.Join(c.clientALPN(), ",")
	if got.alpn != offer {
		t.Errorf("%s: the backend was offered ALPN %q, the client offered %q", c.name, got.alpn, offer)
	}
	if got.chose == "" || st.NegotiatedProtocol != got.chose {
		t.Errorf("%s: the client got ALPN %q, but the backend chose %q", c.name, st.NegotiatedProtocol, got.chose)
	}
	if c.pass && st.Version != got.version {
		t.Errorf("%s: passed through, but the client spoke TLS %x and the backend %x", c.name, st.Version, got.version)
	}
}
