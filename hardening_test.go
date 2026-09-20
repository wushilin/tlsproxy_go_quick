package main

// Tests for the remaining review items: asynchronous logging, rate-limited
// reject lines, the per-source handshake limit, several bind addresses, the
// caching Happy Eyeballs dialer, IP-address SNIs and the close_notify wording.

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------- logging

// stalledWriter blocks every write until released, like a full pipe or a dead disk.
type stalledWriter struct {
	release chan struct{}
	mu      sync.Mutex
	got     strings.Builder
}

func (w *stalledWriter) Write(p []byte) (int, error) {
	<-w.release
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.got.Write(p)
}

func TestAsyncLoggingNeverBlocksTheCaller(t *testing.T) {
	flushMu.Lock() // no other test logs into our writer halfway
	logMu.Lock()
	oldOut, oldErr, oldAsync := logOut, logErr, logAsync
	w := &stalledWriter{release: make(chan struct{})}
	logOut, logErr, logAsync = w, w, true
	pending, segments, droppedLog = nil, nil, 0
	logMu.Unlock()
	flushMu.Unlock()
	defer func() {
		FlushLogs()
		logMu.Lock()
		logOut, logErr, logAsync = oldOut, oldErr, oldAsync
		logMu.Unlock()
	}()

	// The destination is stalled, and logging still returns at once.
	start := time.Now()
	logf("first %d", 1)
	errorf("second %d", 2)
	logf("third")
	logf("fourth")
	if took := time.Since(start); took > time.Second {
		t.Fatalf("logging waited %s for a stalled destination", took)
	}
	// (Filtered: servers of earlier tests may still be logging in the background.)
	if got := RecentLog(10, " fourth"); len(got) != 1 || !strings.HasSuffix(got[0], " fourth") {
		t.Fatalf("the console's recent log is filled at once: %q", got)
	}
	logMu.Lock()
	segs := len(segments)
	logMu.Unlock()
	if segs != 3 { // out, problem, out+out: consecutive lines of a stream are written together
		t.Fatalf("%d segments", segs)
	}

	// Beyond maxPendingLog lines are counted, not kept: memory stays bounded.
	big := strings.Repeat("x", 64<<10)
	for i := 0; i < maxPendingLog/(64<<10)+10; i++ {
		logf("%s", big)
	}
	logMu.Lock()
	held, dropped := len(pending), droppedLog
	logMu.Unlock()
	if held > maxPendingLog || dropped < 5 {
		t.Fatalf("%d bytes held, %d dropped", held, dropped)
	}

	close(w.release)
	FlushLogs()
	w.mu.Lock()
	text := w.got.String()
	w.mu.Unlock()
	// Both streams share this destination: the order of logging is kept.
	i1, i2, i3 := strings.Index(text, " first 1\n"), strings.Index(text, " second 2\n"), strings.Index(text, " third\n")
	if i1 < 0 || !(i1 < i2 && i2 < i3) {
		t.Fatalf("order lost: %d %d %d", i1, i2, i3)
	}
	if !strings.Contains(text, fmt.Sprintf("log: %d lines were dropped", dropped)) {
		t.Fatal("dropped lines must be reported")
	}
}

func TestRateLimitedLog(t *testing.T) {
	var r rateLimitedLog
	mark := len(testLog.String())
	for i := 0; i < 1000; i++ {
		r.logf("flood-line %d", i)
	}
	if n := strings.Count(testLog.String()[mark:], "flood-line"); n != 1 {
		t.Fatalf("%d lines in one second", n)
	}
	r.mu.Lock()
	r.last = time.Now().Add(-2 * time.Second)
	r.mu.Unlock()
	r.logf("flood-line again")
	if log := testLog.String()[mark:]; !strings.Contains(log, "flood-line again (and 999 more like this in the last second, not logged)") {
		t.Fatalf("suppressed lines must be counted:\n%s", log)
	}
}

// ---------------------------------------------------------------- per-source handshake limit

func TestHandshakeSlotsPerSourceAreLimited(t *testing.T) {
	p := startProxy(t, "max_handshakes_per_ip=2\nhandshake_timeout=5", allowAll(echoBackend(t, "")))
	// Two connections that say nothing hold the two slots of 127.0.0.1.
	var idle []net.Conn
	for i := 0; i < 2; i++ {
		c, err := net.DialTimeout("tcp", p.addr, T)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		idle = append(idle, c)
	}
	waitActive := func(n int64) {
		t.Helper()
		for deadline := time.Now().Add(T); p.srv.stats.Active.Load() != n; time.Sleep(5 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("active=%d, want %d", p.srv.stats.Active.Load(), n)
			}
		}
	}
	waitActive(2)
	// The third is turned away at once, without waiting for handshake_timeout.
	c, err := net.DialTimeout("tcp", p.addr, T)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, io.EOF) && !strings.Contains(fmt.Sprint(err), "reset") {
		t.Fatalf("the third silent connection should be closed at once: %v", err)
	}
	if p.srv.stats.Rejected.Load() != 1 || !strings.Contains(testLog.String(), "are still sending their ClientHello (max_handshakes_per_ip)") {
		t.Fatalf("rejected=%d", p.srv.stats.Rejected.Load())
	}
	// A connection that completes its ClientHello no longer counts: the limit is
	// about idle handshakes, not about how many connections a source may have.
	hello := clientHello("a.test")
	idle[0].Write(hello)
	readN(t, idle[0], len(hello))
	c2, err := net.DialTimeout("tcp", p.addr, T)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	c2.Write(hello)
	if got := readN(t, c2, len(hello)); len(got) != len(hello) {
		t.Fatal("a freed slot should be usable")
	}
	if k := sourceKey(&net.TCPAddr{IP: net.ParseIP("2001:db8:1:2:aaaa:bbbb:cccc:dddd")}); k != netip.MustParseAddr("2001:db8:1:2::") {
		t.Fatalf("IPv6 sources are counted per /64: %s", k)
	}
	if k := sourceKey(&net.TCPAddr{IP: net.ParseIP("::ffff:10.1.2.3")}); k != netip.MustParseAddr("10.1.2.3") {
		t.Fatalf("%s", k)
	}
}

// ---------------------------------------------------------------- several bind addresses

func TestSeveralBindAddresses(t *testing.T) {
	c := mustParse(t, "[global]\nbind = 127.0.0.1; [::1]\nport=1\n")
	if fmt.Sprint(c.Binds) != "[127.0.0.1 ::1]" || c.Bind != "127.0.0.1; ::1" || listenAddrs(c) != "127.0.0.1:1, [::1]:1" {
		t.Fatalf("%v %q %q", c.Binds, c.Bind, listenAddrs(c))
	}
	for _, bad := range []string{"bind = 0.0.0.0, 0.0.0.0", "bind = ;"} {
		if _, err := ParseConfig("[global]\nport=1\n" + bad + "\n"); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
	six, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback here: %v", err)
	}
	four, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := mustParse(t, "[global]\nport=1\nstats_interval=0\n"+allowAll(echoBackend(t, "")))
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(four, "", six)
	t.Cleanup(func() { four.Close(); six.Close() })
	hello := clientHello("both.test")
	for _, addr := range []string{four.Addr().String(), six.Addr().String()} {
		conn, err := net.DialTimeout("tcp", addr, T)
		if err != nil {
			t.Fatalf("%s: %v", addr, err)
		}
		conn.Write(hello)
		if got := readN(t, conn, len(hello)); len(got) != len(hello) {
			t.Fatalf("%s: not served", addr)
		}
		conn.Close()
	}
}

// ---------------------------------------------------------------- resolving and connecting

type fakeConn struct {
	net.Conn
	addr   string
	closed *atomic.Int32
}

func (c *fakeConn) Close() error { c.closed.Add(1); return nil }

func TestTargetDialerCachesLookupsAndRacesFamilies(t *testing.T) {
	var lookups atomic.Int32
	var closed atomic.Int32
	addrs := []netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::2")}
	d := newTargetDialer()
	d.lookup = func(_ context.Context, host string) ([]netip.Addr, error) {
		lookups.Add(1)
		if host == "gone.test" {
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
		return addrs, nil
	}
	var mu sync.Mutex
	var tried []string
	behave := map[string]string{} // address -> "ok" | "refuse" | "hang"
	d.dial = func(ctx context.Context, addr string) (net.Conn, error) {
		mu.Lock()
		tried = append(tried, addr)
		how := behave[addr]
		mu.Unlock()
		switch how {
		case "ok":
			return &fakeConn{addr: addr, closed: &closed}, nil
		case "hang":
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("dial %s: connection refused", addr)
	}
	set := func(m map[string]string) {
		mu.Lock()
		behave, tried = m, nil
		mu.Unlock()
	}
	attempts := func() string {
		mu.Lock()
		defer mu.Unlock()
		return strings.Join(tried, " ")
	}

	// The preferred family (that of the first address) answers: nothing else is tried.
	set(map[string]string{"[2001:db8::1]:443": "ok"})
	c, err := d.Dial("svc.test", 443, T)
	if err != nil || c.(*fakeConn).addr != "[2001:db8::1]:443" || attempts() != "[2001:db8::1]:443" {
		t.Fatalf("%v %v %q", c, err, attempts())
	}
	// 100 more connections: one lookup in all. An IP address is never looked up.
	for i := 0; i < 100; i++ {
		d.Dial("svc.test", 443, T)
	}
	d.Dial("192.0.2.9", 443, T)
	if lookups.Load() != 1 {
		t.Fatalf("%d lookups for 101 connections", lookups.Load())
	}
	// After the TTL it is looked up again.
	e, _ := d.cache.Get("svc.test")
	e.expires = time.Now().Add(-time.Second)
	d.cache.Put("svc.test", e)
	d.Dial("svc.test", 443, T)
	if lookups.Load() != 2 {
		t.Fatalf("expired entry not refreshed: %d lookups", lookups.Load())
	}

	// IPv6 refuses at once: both IPv6 addresses, then IPv4 without waiting out the lag.
	set(map[string]string{"192.0.2.1:443": "ok"})
	start := time.Now()
	c, err = d.Dial("svc.test", 443, T)
	if err != nil || c.(*fakeConn).addr != "192.0.2.1:443" || time.Since(start) > happyEyeballsLag {
		t.Fatalf("%v %v after %s (%s)", c, err, time.Since(start), attempts())
	}
	if attempts() != "[2001:db8::1]:443 [2001:db8::2]:443 192.0.2.1:443" {
		t.Fatalf("order: %q", attempts())
	}
	// IPv6 hangs (a black hole): IPv4 is started after the lag and wins.
	set(map[string]string{"[2001:db8::1]:443": "hang", "[2001:db8::2]:443": "hang", "192.0.2.1:443": "ok"})
	start = time.Now()
	c, err = d.Dial("svc.test", 443, T)
	if took := time.Since(start); err != nil || c.(*fakeConn).addr != "192.0.2.1:443" || took < happyEyeballsLag || took > 3*time.Second {
		t.Fatalf("%v %v after %s", c, err, took)
	}
	// Everything fails: the preferred family's error is reported, within the timeout.
	set(map[string]string{"[2001:db8::1]:443": "hang", "[2001:db8::2]:443": "hang"})
	start = time.Now()
	_, err = d.Dial("svc.test", 443, time.Second)
	if took := time.Since(start); err == nil || took > 3*time.Second {
		t.Fatalf("%v after %s", err, took)
	}
	// A failed lookup is an error and is not cached.
	before := lookups.Load()
	if _, err := d.Dial("gone.test", 443, T); err == nil {
		t.Fatal("no such host")
	}
	d.Dial("gone.test", 443, T)
	if lookups.Load() != before+2 {
		t.Fatal("failures must not be cached")
	}
	if closed.Load() != 0 {
		t.Fatalf("%d winning connections were closed", closed.Load())
	}
}

// ---------------------------------------------------------------- SNI and close reasons

func TestIPAddressIsNotAnSNI(t *testing.T) {
	for _, name := range []string{"10.0.0.1", "127.0.0.1"} {
		if _, err := parseClientHello(clientHello(name)); err == nil || !strings.Contains(err.Error(), "an IP address is not a host name") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if sni, err := parseClientHello(clientHello("10.0.0.1.nip.io")); err != nil || sni != "10.0.0.1.nip.io" {
		t.Fatalf("a name made of numbers is still a name: %q %v", sni, err)
	}
	// A catch-all that follows the client's SNI is an open relay: say so.
	c := mustParse(t, "[global]\nport=1\n[[host]]\npattern=.*\ntarget_host=$0\n")
	if len(c.Warnings) != 1 || !strings.Contains(c.Warnings[0], "connects to whatever name a client sends") {
		t.Fatalf("%q", c.Warnings)
	}
	if c := mustParse(t, "[global]\nport=1\n[[host]]\npattern=(.*)\\.example\\.com\ntarget_host=$0\n[[host]]\npattern=.*\ntarget_host=fixed.lan\n"); len(c.Warnings) != 0 {
		t.Fatalf("%q", c.Warnings)
	}
}

// A TLS peer that just closes the TCP connection between records reads as a
// normal close; one that goes away inside a record is reported as exactly that.
func TestConnectionEndingInsideATLSRecord(t *testing.T) {
	ca := newTestCA(t)
	p := startProxy(t, "", fmt.Sprintf("[[host]]\npattern=nonotify.test\ncert=%s\nupstream_tls=false\ntarget_host=127.0.0.1\ntarget_port=%d\n",
		ca.certDir(t, "nonotify.test"), echoBackend(t, "")))
	raw, err := net.DialTimeout("tcp", p.addr, T)
	if err != nil {
		t.Fatal(err)
	}
	tc := tls.Client(raw, &tls.Config{ServerName: "nonotify.test", RootCAs: ca.pool})
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	tc.Write([]byte("hi"))
	readN(t, tc, 2)
	raw.Write([]byte{0x17, 3, 3, 0, 100, 1, 2, 3}) // a record of 100 bytes, of which 3 arrive
	raw.Close()
	reason := closeReason(t, "nonotify.test")
	if !strings.Contains(reason, "client closed in the middle of a TLS record, without close_notify; closed by proxy") || strings.Contains(reason, "error") {
		t.Fatalf("reason=%s", reason)
	}
}
