package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

var selfCheckMu sync.Mutex

// ourPkg starts the names of this package's functions in a stack: "main." in
// the proxy, the module path in a test binary.
const ourPkg = "github.com/wushilin/tlsproxy_go_quick."

// contendOnPurpose makes goroutines wait for one mutex, so the test can see
// that the profile does record contention in this package.
func contendOnPurpose() {
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 200 {
				selfCheckMu.Lock()
				time.Sleep(10 * time.Microsecond)
				selfCheckMu.Unlock()
			}
		}()
	}
	wg.Wait()
}

// Many connections at once through shared rules, one listener and shared
// speed limits, passed through and terminated: the mutex profile (every
// contended lock, with the stack that waited) must not show the proxy's
// serving path waiting for a lock.
func TestServingPathTakesNoSharedLock(t *testing.T) {
	old := runtime.SetMutexProfileFraction(1)
	defer runtime.SetMutexProfileFraction(old)
	ca := newTestCA(t)
	port := echoBackend(t, "E")
	p := startProxy(t, "", fmt.Sprintf("[[host]]\nlistener=default\npattern=*.lock.test\ntarget_host=127.0.0.1\ntarget_port=%d\nmax_aggregated_speed=1Gbit\nmax_single_connection_speed=500Mbit\n", port)+
		fmt.Sprintf("[[host]]\nlistener=default\npattern=term.lock\ncert=%s\nupstream_tls=false\ntarget_host=127.0.0.1\ntarget_port=%d\nmax_aggregated_speed=1Gbit\n", ca.localCA(t), port))

	// The profile sees contention here, so a clean result below means something.
	before := mutexStacks(t)
	contendOnPurpose()
	seen := false
	for s, n := range mutexStacks(t) {
		seen = seen || (n > before[s] && strings.Contains(s, ourPkg+"contendOnPurpose"))
	}
	if !seen {
		t.Fatal("the mutex profile did not record deliberate contention; this test can't see anything")
	}

	// The first handshake for a local-CA name issues its certificate under
	// that name's lock (so racing handshakes share one): get that done first.
	// From then on the certificate is found without a lock.
	if tc, err := tlsDial(t, p, &tls.Config{RootCAs: ca.pool, ServerName: "term.lock"}); err != nil {
		t.Fatal(err)
	} else {
		tc.Close()
	}

	// The proxy logs asynchronously (tests normally log straight through,
	// which locks): do as it does for this run.
	FlushLogs()
	wasAsync := logAsync.Swap(true)
	defer func() { FlushLogs(); logAsync.Store(wasAsync) }()

	before = mutexStacks(t)
	var wg sync.WaitGroup
	for g := range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 40 {
				payload := bytes.Repeat([]byte("x"), 2048)
				if g%4 == 0 { // a quarter terminated here
					tc, err := tlsDial(t, p, &tls.Config{RootCAs: ca.pool, ServerName: "term.lock"})
					if err != nil {
						t.Error(err)
						return
					}
					tc.Write(payload)
					readN(t, tc, 1+len(payload))
					tc.Close()
					continue
				}
				c := dial(t, p)
				c.Write(clientHello(fmt.Sprintf("n%d.lock.test", (g*40+i)%7)))
				readN(t, c, 1)
				c.Write(payload)
				readN(t, c, len(payload))
				c.Close()
			}
		}()
	}
	wg.Wait()
	for s, n := range mutexStacks(t) {
		if n > before[s] && servingPath(s) {
			t.Errorf("the serving path waited for a lock:\n%s", s)
		}
	}
}

// servingPath reports whether a stack is the proxy serving a connection
// and waiting for a lock of its own. What counts is who took the lock: the
// first frame below sync and runtime. When that is the standard library
// (crypto/tls caching a key, fmt's sync.Pool, the Go runtime's heap and
// garbage collector) it is out of this program's hands and left out; when
// it is this package, on the way from accepting to relaying a connection,
// it is a failure. The test's own clients and backends don't count.
func servingPath(stack string) bool {
	if strings.HasPrefix(stack, "runtime.unlock") {
		return false // one of the Go runtime's own locks (heap, GC, scheduler)
	}
	frames := strings.Split(stack, "\n")
	for _, f := range frames {
		if strings.HasPrefix(f, "sync.") || strings.HasPrefix(f, "internal/sync.") || strings.HasPrefix(f, "runtime.") {
			continue
		}
		if !strings.HasPrefix(f, ourPkg) {
			return false // taken inside the standard library
		}
		break
	}
	return strings.Contains(stack, ourPkg+"(*Server).") || strings.Contains(stack, ourPkg+"(*relay).")
}

// mutexStacks maps each stack in the mutex profile (as text) to how many
// times it waited so far. The profile is cumulative: compare two calls.
func mutexStacks(t *testing.T) map[string]int64 {
	var buf bytes.Buffer
	if err := pprof.Lookup("mutex").WriteTo(&buf, 1); err != nil {
		t.Fatal(err)
	}
	out := map[string]int64{}
	for _, rec := range strings.Split(buf.String(), "\n\n") {
		var frames []string
		var count int64
		for _, l := range strings.Split(rec, "\n") {
			f := strings.Fields(l)
			switch {
			case len(f) >= 3 && f[0] == "#":
				frames = append(frames, f[2])
			case len(f) >= 3 && f[2] == "@": // "<cycles> <count> @ <pcs>"
				count, _ = strconv.ParseInt(f[1], 10, 64)
			}
		}
		if frames != nil {
			out[strings.Join(frames, "\n")] += count
		}
	}
	return out
}
