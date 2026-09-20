package main

// End-to-end tests: real sockets, real proxy, synthetic ClientHellos and plain
// TCP backends (the proxy never decrypts, so backends don't speak TLS).

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const T = 10 * time.Second

type proxyUnderTest struct {
	addr string
	srv  *Server
}

// startProxy starts the proxy with rules (appended after [global]) on a free port.
func startProxy(t *testing.T, global, rules string) *proxyUnderTest {
	t.Helper()
	return startProxyText(t, "[global]\nport=1\nstats_interval=0\nmax_handshakes_per_ip=0\n"+global+"\n"+rules, "")
}

func startProxyText(t *testing.T, text, path string) *proxyUnderTest {
	t.Helper()
	cfg, err := ParseConfig(text)
	if err != nil {
		t.Fatalf("bad test config: %v\n%s", err, text)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	go srv.Serve(l, path)
	t.Cleanup(func() { l.Close() })
	return &proxyUnderTest{addr: l.Addr().String(), srv: srv}
}

func listen(t *testing.T) (net.Listener, int) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l, l.Addr().(*net.TCPAddr).Port
}

// backend runs handler for every accepted connection.
func backend(t *testing.T, handler func(*net.TCPConn)) int {
	l, port := listen(t)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); handler(c.(*net.TCPConn)) }()
		}
	}()
	return port
}

// echoBackend optionally sends tag first, then echoes until EOF, then half-closes.
func echoBackend(t *testing.T, tag string) int {
	return backend(t, func(c *net.TCPConn) {
		c.Write([]byte(tag))
		io.Copy(c, c)
		c.CloseWrite()
	})
}

func allowAll(port int) string {
	return fmt.Sprintf("[[host]]\npattern=.*\ntarget_host=127.0.0.1\ntarget_port=%d\n", port)
}

func dial(t *testing.T, p *proxyUnderTest) *net.TCPConn {
	t.Helper()
	c, err := net.Dial("tcp", p.addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetReadDeadline(time.Now().Add(T))
	return c.(*net.TCPConn)
}

func readN(t *testing.T, c net.Conn, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read failed or timed out: %v", err)
	}
	return buf
}

// readToEnd reads until the proxy closes. A reset also counts as closed; a
// timeout fails the test.
func readToEnd(t *testing.T, c net.Conn) []byte {
	t.Helper()
	data, err := io.ReadAll(c)
	if err != nil && isTimeout(err) {
		t.Fatalf("expected close, got timeout after %d bytes", len(data))
	}
	return data
}

// roundtrip sends a hello + "ping" and expects tag + hello + "ping" back.
func roundtrip(t *testing.T, p *proxyUnderTest, sni, tag string) {
	t.Helper()
	c := dial(t, p)
	defer c.Close()
	hello := clientHello(sni)
	c.Write(hello)
	c.Write([]byte("ping"))
	got := readN(t, c, len(tag)+len(hello)+4)
	want := append(append([]byte(tag), hello...), "ping"...)
	if !bytes.Equal(got, want) {
		t.Fatalf("%s: wrong backend or hello not forwarded verbatim (tag %q)", sni, got[:len(tag)])
	}
}

func expectDenied(t *testing.T, p *proxyUnderTest, hello []byte) {
	t.Helper()
	c := dial(t, p)
	defer c.Close()
	c.Write(hello)
	if got := readToEnd(t, c); !bytes.Equal(got, alertAccessDenied) {
		t.Fatalf("expected access_denied alert, got %x", got)
	}
}

func between(t *testing.T, since time.Time, lo, hi time.Duration) {
	t.Helper()
	if e := time.Since(since); e < lo || e > hi {
		t.Fatalf("took %v, want %v..%v", e, lo, hi)
	}
}

// pattern returns deterministic pseudo-random bytes (xorshift).
func pattern(n int, seed uint64) []byte {
	x := seed | 1
	out := make([]byte, n)
	for i := range out {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		out[i] = byte(x)
	}
	return out
}

// ---------------------------------------------------------------- routing

func TestForwardsHelloAndPayloadVerbatim(t *testing.T) {
	t.Parallel()
	p := startProxy(t, "", allowAll(echoBackend(t, "")))
	roundtrip(t, p, "any.example.com", "")
}

func TestRoutesBySNI(t *testing.T) {
	t.Parallel()
	a, b := echoBackend(t, "A"), echoBackend(t, "B")
	p := startProxy(t, "", fmt.Sprintf(
		"[[host]]\npattern=(.*)\\.a\\.test\ntarget_host=127.0.0.1\ntarget_port=%d\n"+
			"[[host]]\npattern=b\\.test|(.*)\\.b\\.test\ntarget_host=127.0.0.1\ntarget_port=%d\n"+
			"[[host]]\npattern=vip\\..*\ntarget_host=$0\n[[host]]\npattern=.*\naction=deny\n", a, b))
	roundtrip(t, p, "x.a.test", "A")
	roundtrip(t, p, "y.z.a.test", "A")
	roundtrip(t, p, "b.test", "B")
	roundtrip(t, p, "q.b.test", "B")
	roundtrip(t, p, "UPPER.A.TEST", "A") // case-insensitive
	expectDenied(t, p, clientHello("evil.test"))
	expectDenied(t, p, clientHello("x.a.test.evil.com")) // whole-name match
}

func TestCaptureGroupBuildsTarget(t *testing.T) {
	t.Parallel()
	port := echoBackend(t, "C")
	p := startProxy(t, "", fmt.Sprintf("[[host]]\npattern=(.*)\\.fwd\\.test\ntarget_host=$1\ntarget_port=%d\n", port))
	roundtrip(t, p, "127.0.0.1.fwd.test", "C")
	expectDenied(t, p, clientHello("nomatch.test")) // no rule matched
}

func TestMissingSNIMatchesEmptyString(t *testing.T) {
	t.Parallel()
	noSNI := wrapRecords(buildClientHello(nil, 0), 16384)
	expectDenied(t, startProxy(t, "", "[[host]]\npattern=.*\naction=deny\n"), noSNI)
	port := echoBackend(t, "N")
	p := startProxy(t, "", fmt.Sprintf("[[host]]\npattern=^$\ntarget_host=127.0.0.1\ntarget_port=%d\n", port))
	c := dial(t, p)
	c.Write(noSNI)
	if got := readN(t, c, 1); got[0] != 'N' {
		t.Fatal(got)
	}
}

func TestNonePatternRoutesClientsWithoutSNI(t *testing.T) {
	t.Parallel()
	def, named := echoBackend(t, "D"), echoBackend(t, "N")
	p := startProxy(t, "", fmt.Sprintf("[[host]]\npattern=NONE\ntarget_host=127.0.0.1\ntarget_port=%d\n"+
		"[[host]]\npattern=(.*)\\.named\\.test\ntarget_host=127.0.0.1\ntarget_port=%d\n"+
		"[[host]]\npattern=.*\naction=deny\n", def, named))
	noSNI := wrapRecords(buildClientHello(nil, 0), 16384)
	for i := 0; i < 2; i++ { // the second round is served from the route cache
		c := dial(t, p)
		c.Write(noSNI)
		got := readN(t, c, 1+len(noSNI))
		if got[0] != 'D' || !bytes.Equal(got[1:], noSNI) {
			t.Fatalf("no-SNI client must reach the default target, got tag %q", got[:1])
		}
		c.Close()
	}
	roundtrip(t, p, "a.named.test", "N")
	expectDenied(t, p, clientHello("none")) // a host called "none" has an SNI
	expectDenied(t, p, clientHello("other.test"))
}

func TestNonTLSIsDroppedWithoutReply(t *testing.T) {
	t.Parallel()
	p := startProxy(t, "", allowAll(echoBackend(t, "")))
	for _, junk := range []string{"GET / HTTP/1.1\r\nHost: x\r\n\r\n", "SSH-2.0-OpenSSH_9.0\r\n", "\x80\x2e\x01\x03\x01"} {
		c := dial(t, p)
		c.Write([]byte(junk))
		if got := readToEnd(t, c); len(got) != 0 {
			t.Fatalf("%q got reply %x", junk, got)
		}
	}
}

func TestHelloShapes(t *testing.T) {
	t.Parallel()
	p := startProxy(t, "buffer_size=512", allowAll(echoBackend(t, ""))) // tiny buffer forces the spill path
	frag, big, slow := "frag.test", "pq.test", "slow.test"
	for name, hello := range map[string][]byte{
		"fragmented":   wrapRecords(buildClientHello(&frag, 0), 10),
		"post-quantum": wrapRecords(buildClientHello(&big, 20000), 16384),
	} {
		c := dial(t, p)
		c.Write(hello)
		if !bytes.Equal(readN(t, c, len(hello)), hello) {
			t.Fatalf("%s hello not forwarded verbatim", name)
		}
	}
	c := dial(t, p)
	hello := clientHello(slow)
	for _, b := range hello { // byte by byte
		c.Write([]byte{b})
		time.Sleep(200 * time.Microsecond)
	}
	if !bytes.Equal(readN(t, c, len(hello)), hello) {
		t.Fatal("trickled hello")
	}
}

func TestCachedRoutesBehaveLikeUncached(t *testing.T) {
	t.Parallel()
	rules := fmt.Sprintf("[[host]]\npattern=(.*)\\.ok\\.test\ntarget_host=127.0.0.1\ntarget_port=%d\n[[host]]\npattern=.*\naction=deny\n", echoBackend(t, "A"))
	for _, global := range []string{"allow_cache_size=2\ndeny_cache_size=2", "allow_cache_size=0\ndeny_cache_size=0"} {
		p := startProxy(t, global, rules)
		for round := 0; round < 3; round++ {
			for i := 0; i < 5; i++ {
				name := fmt.Sprintf("h%d.ok.test", i)
				if round == 1 {
					name = strings.ToUpper(name) // same cache entry
				}
				roundtrip(t, p, name, "A")
				expectDenied(t, p, clientHello(fmt.Sprintf("h%d.bad.test", i)))
			}
		}
	}
}

// ---------------------------------------------------------------- transfer

func TestLargeBidirectionalTransferIntegrity(t *testing.T) {
	t.Parallel()
	for _, global := range []string{"", "buffer_size=512\nbuffer_pool_max_idle=1"} {
		p := startProxy(t, global, allowAll(echoBackend(t, "")))
		hello, data := clientHello("bulk.test"), pattern(16<<20, 42)
		c := dial(t, p)
		c.SetReadDeadline(time.Now().Add(60 * time.Second))
		go func() {
			c.Write(hello)
			c.Write(data)
			c.CloseWrite()
		}()
		got := readToEnd(t, c)
		if !bytes.Equal(got, append(append([]byte(nil), hello...), data...)) {
			t.Fatalf("payload corrupted or truncated: %d bytes", len(got))
		}
	}
}

func TestManyConcurrentConnections(t *testing.T) {
	t.Parallel()
	a, b := echoBackend(t, "A"), echoBackend(t, "B")
	p := startProxy(t, "", fmt.Sprintf("[[host]]\npattern=a\\d+\\.test\ntarget_host=127.0.0.1\ntarget_port=%d\n"+
		"[[host]]\npattern=b\\d+\\.test\ntarget_host=127.0.0.1\ntarget_port=%d\n", a, b))
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sni, tag := fmt.Sprintf("a%d.test", i), "A"
			if i%2 == 1 {
				sni, tag = fmt.Sprintf("b%d.test", i), "B"
			}
			for j := 0; j < 5; j++ {
				roundtrip(t, p, sni, tag)
			}
		}(i)
	}
	wg.Wait()
}

// ---------------------------------------------------------------- close / timeouts

func TestClientHalfCloseStillReceivesResponse(t *testing.T) {
	t.Parallel()
	port := backend(t, func(c *net.TCPConn) {
		data, _ := io.ReadAll(c)
		fmt.Fprintf(c, "got %d", len(data))
	})
	p := startProxy(t, "", allowAll(port))
	hello := clientHello("half.test")
	c := dial(t, p)
	c.Write(hello)
	c.Write([]byte("request"))
	c.CloseWrite()
	if got := string(readToEnd(t, c)); got != fmt.Sprintf("got %d", len(hello)+7) {
		t.Fatal(got)
	}
}

func TestUpstreamCloseAndUnreachable(t *testing.T) {
	t.Parallel()
	port := backend(t, func(c *net.TCPConn) {
		c.Write([]byte("bye"))
		c.CloseWrite()
		io.Copy(io.Discard, c) // drain first: closing with unread input sends RST
	})
	c := dial(t, startProxy(t, "", allowAll(port)))
	c.Write(clientHello("close.test"))
	if got := string(readToEnd(t, c)); got != "bye" {
		t.Fatal(got)
	}

	l, dead := listen(t)
	l.Close()
	c = dial(t, startProxy(t, "", allowAll(dead)))
	c.Write(clientHello("down.test"))
	if got := readToEnd(t, c); len(got) != 0 {
		t.Fatal(got)
	}
	c = dial(t, startProxy(t, "connect_timeout=3", "[[host]]\npattern=.*\ntarget_host=does-not-exist.invalid\n"))
	c.Write(clientHello("x.test"))
	if got := readToEnd(t, c); len(got) != 0 {
		t.Fatal(got)
	}
}

func TestHandshakeTimeout(t *testing.T) {
	t.Parallel()
	p := startProxy(t, "handshake_timeout=1", allowAll(echoBackend(t, "")))
	start := time.Now()
	c := dial(t, p)
	c.Write([]byte{0x16, 0x03}) // partial header, then silence
	readToEnd(t, c)
	between(t, start, 900*time.Millisecond, 3*time.Second)

	// Slowloris: one byte every 300ms must not extend the overall deadline.
	start = time.Now()
	c = dial(t, p)
	go func() {
		for _, b := range clientHello("slowloris.test") {
			if _, err := c.Write([]byte{b}); err != nil {
				return
			}
			time.Sleep(300 * time.Millisecond)
		}
	}()
	readToEnd(t, c)
	between(t, start, 900*time.Millisecond, 3*time.Second)
}

func TestIdleTimeout(t *testing.T) {
	t.Parallel()
	p := startProxy(t, "idle_timeout=1", allowAll(echoBackend(t, "")))
	hello := clientHello("idle.test")
	c := dial(t, p)
	c.Write(hello)
	readN(t, c, len(hello))
	for i := 0; i < 3; i++ { // activity resets the timer
		time.Sleep(500 * time.Millisecond)
		c.Write([]byte("x"))
		readN(t, c, 1)
	}
	start := time.Now()
	readToEnd(t, c)
	between(t, start, 800*time.Millisecond, 3*time.Second)

	// 0 disables it.
	p = startProxy(t, "idle_timeout=0", allowAll(echoBackend(t, "")))
	c = dial(t, p)
	c.Write(hello)
	readN(t, c, len(hello))
	time.Sleep(1500 * time.Millisecond)
	c.Write([]byte("still here"))
	if string(readN(t, c, 10)) != "still here" {
		t.Fatal("closed despite idle_timeout=0")
	}
}

func TestHalfOpenPeerIsReapedByIdleTimeout(t *testing.T) {
	t.Parallel()
	port := backend(t, func(c *net.TCPConn) { time.Sleep(60 * time.Second) }) // silent, never closes
	c := dial(t, startProxy(t, "idle_timeout=1\nhalf_close_timeout=30", allowAll(port)))
	c.Write(clientHello("halfopen.test"))
	start := time.Now()
	readToEnd(t, c)
	between(t, start, 800*time.Millisecond, 3*time.Second)
}

// lingeringBackend reads until EOF, optionally replies after a delay, then
// keeps its side open.
func lingeringBackend(t *testing.T, replyAfter time.Duration, reply string) int {
	return backend(t, func(c *net.TCPConn) {
		io.Copy(io.Discard, c)
		if reply != "" {
			time.Sleep(replyAfter)
			c.Write([]byte(reply))
		}
		time.Sleep(60 * time.Second)
	})
}

// trickleBackend: after the client's EOF, one byte every 400ms, count times.
func trickleBackend(t *testing.T, count int) int {
	return backend(t, func(c *net.TCPConn) {
		io.Copy(io.Discard, c)
		for i := 0; i < count; i++ {
			time.Sleep(400 * time.Millisecond)
			if _, err := c.Write([]byte("x")); err != nil {
				return
			}
		}
		time.Sleep(60 * time.Second)
	})
}

func halfClosedClient(t *testing.T, p *proxyUnderTest, sni string) *net.TCPConn {
	c := dial(t, p)
	c.Write(clientHello(sni))
	c.CloseWrite()
	return c
}

func TestHalfCloseTimeout(t *testing.T) {
	t.Parallel()
	t.Run("closes lingering side", func(t *testing.T) {
		t.Parallel()
		c := halfClosedClient(t, startProxy(t, "half_close_timeout=1", allowAll(lingeringBackend(t, 0, ""))), "linger.test")
		start := time.Now()
		if got := readToEnd(t, c); len(got) != 0 {
			t.Fatal(got)
		}
		between(t, start, 800*time.Millisecond, 3*time.Second)
	})
	t.Run("data still flows during grace", func(t *testing.T) {
		t.Parallel()
		c := halfClosedClient(t, startProxy(t, "half_close_timeout=2", allowAll(lingeringBackend(t, 500*time.Millisecond, "late reply"))), "grace.test")
		start := time.Now()
		if got := string(readToEnd(t, c)); got != "late reply" {
			t.Fatal(got)
		}
		between(t, start, 1800*time.Millisecond, 4*time.Second)
	})
	t.Run("zero waits indefinitely", func(t *testing.T) {
		t.Parallel()
		c := halfClosedClient(t, startProxy(t, "half_close_timeout=0\nidle_timeout=0", allowAll(lingeringBackend(t, 1500*time.Millisecond, "late reply"))), "nolimit.test")
		if got := string(readN(t, c, 10)); got != "late reply" {
			t.Fatal(got)
		}
	})
	t.Run("hard cap even with traffic", func(t *testing.T) {
		t.Parallel()
		c := halfClosedClient(t, startProxy(t, "half_close_timeout=1\nidle_timeout=30", allowAll(trickleBackend(t, 10))), "cap.test")
		start := time.Now()
		if got := readToEnd(t, c); len(got) < 1 || len(got) > 3 {
			t.Fatalf("got %d bytes", len(got))
		}
		between(t, start, 800*time.Millisecond, 2*time.Second)
	})
	t.Run("idle timeout applies while half closed", func(t *testing.T) {
		t.Parallel()
		c := halfClosedClient(t, startProxy(t, "idle_timeout=1\nhalf_close_timeout=30", allowAll(lingeringBackend(t, 0, ""))), "halfidle.test")
		start := time.Now()
		readToEnd(t, c)
		between(t, start, 800*time.Millisecond, 3*time.Second)
	})
	t.Run("traffic during half close resets idle", func(t *testing.T) {
		t.Parallel()
		c := halfClosedClient(t, startProxy(t, "idle_timeout=1\nhalf_close_timeout=30", allowAll(trickleBackend(t, 5))), "halfbusy.test")
		start := time.Now()
		if got := string(readToEnd(t, c)); got != "xxxxx" {
			t.Fatal(got)
		}
		between(t, start, 2800*time.Millisecond, 4*time.Second)
	})
	t.Run("upstream half close gives client grace", func(t *testing.T) {
		t.Parallel()
		received := make(chan int, 1)
		port := backend(t, func(c *net.TCPConn) {
			c.CloseWrite()
			data, _ := io.ReadAll(c)
			received <- len(data)
		})
		hello := clientHello("upclose.test")
		c := dial(t, startProxy(t, "half_close_timeout=1", allowAll(port)))
		c.Write(hello)
		if got := readToEnd(t, c); len(got) != 0 { // upstream's EOF arrives
			t.Fatal(got)
		}
		c.Write([]byte("after upstream eof")) // still delivered
		select {
		case n := <-received:
			if n != len(hello)+18 {
				t.Fatal(n)
			}
		case <-time.After(T):
			t.Fatal("backend never saw the end")
		}
	})
}

func TestMaxConnectionsEnforcedAndReleased(t *testing.T) {
	t.Parallel()
	p := startProxy(t, "max_connections=2", allowAll(echoBackend(t, "")))
	hello := clientHello("limit.test")
	var open []*net.TCPConn
	for i := 0; i < 2; i++ {
		c := dial(t, p)
		c.Write(hello)
		readN(t, c, len(hello))
		open = append(open, c)
	}
	c := dial(t, p) // third is rejected immediately
	c.Write(hello)
	if got := readToEnd(t, c); len(got) != 0 {
		t.Fatal(got)
	}
	open[0].Close()
	time.Sleep(300 * time.Millisecond)
	c = dial(t, p)
	c.Write(hello)
	readN(t, c, len(hello))
}

// ---------------------------------------------------------------- reload

func TestConfigReload(t *testing.T) {
	t.Parallel()
	a, b := echoBackend(t, "A"), echoBackend(t, "B")
	path := filepath.Join(t.TempDir(), "config.toml")
	write := func(body string, wait bool) string {
		text := "[global]\nport=1\nstats_interval=0\nreload_interval=5\n" + body
		if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
		if wait {
			time.Sleep(6 * time.Second) // reloads are gated to one per 5 s
		}
		return text
	}
	p := startProxyText(t, write(allowAll(a), false), path)

	hello := clientHello("long.test") // a long-lived connection under the first config
	long := dial(t, p)
	long.SetReadDeadline(time.Now().Add(60 * time.Second))
	long.Write(hello)
	if got := readN(t, long, 1+len(hello)); got[0] != 'A' {
		t.Fatal("wrong backend")
	}
	roundtrip(t, p, "svc.test", "A")
	roundtrip(t, p, "svc.test", "A") // served from the allow cache

	write("[[host]]\npattern=(\ntarget_host=x\n", true) // invalid: ignored
	roundtrip(t, p, "svc.test", "A")
	write(allowAll(b), true)
	roundtrip(t, p, "svc.test", "B") // a stale cache entry would still say A
	write("[[host]]\npattern=.*\naction=deny\n", true)
	expectDenied(t, p, clientHello("svc.test")) // cached allow must not survive
	write(allowAll(a)+"\n[global]\nbuffer_size=4096\n", true)
	roundtrip(t, p, "svc.test", "A") // nor the cached denial; pool replaced too

	long.Write([]byte("still alive")) // untouched by all four reloads
	if string(readN(t, long, 11)) != "still alive" {
		t.Fatal("existing connection broken by reload")
	}
}

// ---------------------------------------------------------------- global state

func TestStatsTrackConnectionsGoroutinesAndBytes(t *testing.T) {
	t.Parallel()
	p := startProxy(t, "", fmt.Sprintf("[[host]]\npattern=ok\\.test\ntarget_host=127.0.0.1\ntarget_port=%d\n", echoBackend(t, "")))
	st := p.srv.stats
	hello := clientHello("ok.test")
	var conns []*net.TCPConn
	for i := 0; i < 3; i++ {
		c := dial(t, p)
		c.Write(hello)
		c.Write(make([]byte, 1000))
		readN(t, c, len(hello)+1000)
		conns = append(conns, c)
	}
	if st.Active.Load() != 3 || st.OpenGoroutines() != 6 { // 2 goroutines per connection
		t.Fatalf("active=%d goroutines=%d", st.Active.Load(), st.OpenGoroutines())
	}
	// Bytes are counted right after they are written: the client can have read
	// everything a moment before the counters say so.
	want := 3 * int64(len(hello)+1000)
	for deadline := time.Now().Add(T); st.BytesUp.Load() != want || st.BytesDown.Load() != want; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("totals: up=%d down=%d, want %d each", st.BytesUp.Load(), st.BytesDown.Load(), want)
		}
	}
	st.mu.Lock()
	for _, c := range st.conns {
		if sni, dst, _ := c.info(); sni != "ok.test" || dst == "" || c.BytesUp.Load() != int64(len(hello)+1000) || c.BytesDown.Load() != int64(len(hello)+1000) {
			t.Errorf("conn #%d: sni=%q dst=%q up=%d down=%d", c.ID, sni, dst, c.BytesUp.Load(), c.BytesDown.Load())
		}
	}
	registered := len(st.conns)
	st.mu.Unlock()
	if registered != 3 {
		t.Fatal(registered)
	}
	st.Dump(p.srv.runtime.Load()) // must not panic or deadlock

	expectDenied(t, p, clientHello("nope.test"))
	for _, c := range conns {
		c.Close()
	}
	deadline := time.Now().Add(T)
	for st.OpenGoroutines() != 0 || st.Active.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("leak: active=%d goroutines=%d", st.Active.Load(), st.OpenGoroutines())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if st.Accepted.Load() != 4 || st.Completed.Load() != 3 || st.Denied.Load() != 1 ||
		st.BytesUp.Load() != want || st.BytesDown.Load() != want ||
		st.GoroutinesStarted.Load() != 7 || st.GoroutinesFinished.Load() != 7 {
		t.Fatalf("%s", st.Summary(p.srv.runtime.Load()))
	}
}

// IPv6 on both sides over real sockets: a dual-stack listener (bind = ::) takes
// IPv4 and IPv6 clients, and targets may be IPv6 addresses or names that
// resolve to one.
func TestIPv6DownstreamAndUpstream(t *testing.T) {
	up, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback here: %v", err)
	}
	t.Cleanup(func() { up.Close() })
	go func() {
		for {
			c, err := up.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	port := up.Addr().(*net.TCPAddr).Port
	cfg := mustParse(t, fmt.Sprintf("[global]\nbind=[::]\nport=1\nstats_interval=0\n"+
		"[[host]]\npattern=six.test\ntarget_host=::1\ntarget_port=%d\n"+
		"[[host]]\npattern=*.zone.test\ntarget_host=fe80::1%%lo0\ntarget_port=%d\n", port, port))
	if cfg.Bind != "::" {
		t.Fatalf("bind = [::] and bind = :: are the same: %q", cfg.Bind)
	}
	// A zoned link-local address is a valid target and keeps its zone.
	if got := route(t, cfg, "a.zone.test"); got != fmt.Sprintf("[fe80::1%%lo0]:%d", port) {
		t.Fatal(got)
	}
	l, err := net.Listen(listenNetwork(cfg.Bind), net.JoinHostPort(cfg.Bind, "0"))
	if err != nil {
		t.Fatal(err)
	}
	// bind = 0.0.0.0 means IPv4 only (Go's plain "tcp" would make it dual-stack).
	v4, err := net.Listen(listenNetwork("0.0.0.0"), "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer v4.Close()
	if c, err := net.DialTimeout("tcp", net.JoinHostPort("::1", strconv.Itoa(v4.Addr().(*net.TCPAddr).Port)), time.Second); err == nil {
		c.Close()
		t.Fatal("bind = 0.0.0.0 must not accept IPv6 clients")
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(l, "")
	t.Cleanup(func() { l.Close() })
	proxyPort := strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
	mark := len(testLog.String())
	for _, client := range []string{"127.0.0.1", "::1"} {
		c, err := net.DialTimeout("tcp", net.JoinHostPort(client, proxyPort), T)
		if err != nil {
			t.Fatalf("%s: the listener should be dual-stack: %v", client, err)
		}
		hello := clientHello("six.test")
		c.Write(hello)
		c.Write([]byte("ping"))
		got := make([]byte, len(hello)+4)
		c.SetReadDeadline(time.Now().Add(T))
		if _, err := io.ReadFull(c, got); err != nil || string(got[len(hello):]) != "ping" {
			t.Fatalf("%s: %v %q", client, err, got)
		}
		c.Close()
	}
	log := ""
	for deadline := time.Now().Add(T); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if log = testLog.String()[mark:]; strings.Count(log, fmt.Sprintf("-> [::1]:%d ([::1]", port)) == 2 {
			break
		}
	}
	for _, want := range []string{
		fmt.Sprintf("route sni=six.test -> [::1]:%d (ALLOW", port), // unambiguous, not ::1:443
		"accepted from 127.0.0.1:", "accepted from [::1]:",
		fmt.Sprintf("-> [::1]:%d ([::1]:%d)", port, port),
	} {
		if !strings.Contains(log, want) {
			t.Errorf("log lacks %q\n%s", want, log)
		}
	}
}
