package main

// Checks the `reason=` logged for every way a relayed connection can end.

import (
	"bytes"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// capturedLog collects every log line of the test binary (tests run in
// parallel, so each test looks for lines carrying its own unique SNI).
type capturedLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *capturedLog) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}

func (c *capturedLog) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

var testLog = &capturedLog{}

func TestMain(m *testing.M) {
	logMu.Lock()
	logOut, logErr = testLog, testLog          // activity and problems alike
	certAttemptBackoff = 50 * time.Millisecond // don't wait 5 s between ACME attempts in tests
	pbkdf2Iterations = 1000                    // fast password hashing in tests
	logMu.Unlock()
	os.Exit(m.Run())
}

// closeReason waits for the closed line of sni and returns its reason.
func closeReason(t *testing.T, sni string) string {
	t.Helper()
	deadline := time.Now().Add(T)
	for {
		for _, line := range strings.Split(testLog.String(), "\n") {
			if strings.Contains(line, "] closed ") && strings.Contains(line, "sni="+sni+" ") {
				_, reason, _ := strings.Cut(line, "reason=")
				return reason
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no closed line for %s", sni)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestCloseReasons(t *testing.T) {
	t.Parallel()
	polite := backend(t, func(c *net.TCPConn) { io.Copy(io.Discard, c) }) // closes when the client does
	closesFirst := backend(t, func(c *net.TCPConn) {
		c.Write([]byte("bye"))
		c.CloseWrite()
		io.Copy(io.Discard, c)
	})
	lingers := lingeringBackend(t, 0, "") // never closes, never sends

	t.Run("one side closes, the other follows", func(t *testing.T) {
		t.Parallel()
		c := halfClosedClient(t, startProxy(t, "", allowAll(polite)), "mutual.test")
		readToEnd(t, c)
		if r := closeReason(t, "mutual.test"); !regexp.MustCompile(`^client closed, then upstream closed \d+ms later$`).MatchString(r) {
			t.Fatal(r)
		}
	})
	t.Run("upstream first, reports how long the client took", func(t *testing.T) {
		t.Parallel()
		c := dial(t, startProxy(t, "", allowAll(closesFirst)))
		c.Write(clientHello("upfirst.test"))
		readToEnd(t, c) // upstream's EOF arrives...
		time.Sleep(300 * time.Millisecond)
		c.Close() // ...and only then do we close
		r := closeReason(t, "upfirst.test")
		m := regexp.MustCompile(`^upstream closed, then client closed (\d+)ms later$`).FindStringSubmatch(r)
		if m == nil || len(m[1]) != 3 || m[1] < "250" {
			t.Fatal(r)
		}
	})
	t.Run("the other side never closes", func(t *testing.T) {
		t.Parallel()
		c := halfClosedClient(t, startProxy(t, "half_close_timeout=1", allowAll(lingers)), "grace-reason.test")
		readToEnd(t, c)
		if r := closeReason(t, "grace-reason.test"); r != "client closed, other direction still open after half_close_timeout (1.00s); closed by proxy" {
			t.Fatal(r)
		}
	})
	t.Run("idle", func(t *testing.T) {
		t.Parallel()
		p := startProxy(t, "idle_timeout=1", allowAll(lingers))
		c := dial(t, p)
		c.Write(clientHello("idle-reason.test"))
		readToEnd(t, c)
		if r := closeReason(t, "idle-reason.test"); r != "idle timeout (1.00s); closed by proxy" {
			t.Fatal(r)
		}
		c = halfClosedClient(t, p, "halfidle-reason.test") // closes, then silence
		readToEnd(t, c)
		if r := closeReason(t, "halfidle-reason.test"); r != "client closed, then idle timeout (1.00s); closed by proxy" {
			t.Fatal(r)
		}
	})
}
