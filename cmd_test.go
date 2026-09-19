package main

// Command-driven mock upstream: the test client tells the backend, through
// the proxy, exactly how to (mis)behave, so every interruption is reproducible.
//
// After the ClientHello record the backend reads newline-terminated lines; a
// line holds one or more commands separated by ';':
//
//	PING                 reply "PONG\n"
//	SERVER_DATA n seed   send n pseudo-random bytes (pattern(n, seed))
//	CLIENT_DATA n        the next n bytes are payload; reply "GOT n <hash>\n"
//	SLEEP ms             do nothing (not even read) for ms
//	WRITER_CLOSE         CloseWrite: the proxy sees EOF from upstream
//	READER_CLOSE         CloseRead
//	CLOSE                close the socket cleanly and stop
//	RESET                close with unread input pending -> TCP RST
//
// Notable events go to a log the test can wait on.

import (
	"bytes"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type eventLog struct {
	mu     sync.Mutex
	events []string
}

func (l *eventLog) note(format string, a ...any) {
	l.mu.Lock()
	l.events = append(l.events, fmt.Sprintf(format, a...))
	l.mu.Unlock()
}

func (l *eventLog) waitFor(t *testing.T, prefix string) string {
	t.Helper()
	deadline := time.Now().Add(T)
	for {
		l.mu.Lock()
		for _, e := range l.events {
			if strings.HasPrefix(e, prefix) {
				l.mu.Unlock()
				return e
			}
		}
		snapshot := fmt.Sprint(l.events)
		l.mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatalf("no %q event; log: %s", prefix, snapshot)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func hashOf(data []byte) uint64 {
	h := fnv.New64a()
	h.Write(data)
	return h.Sum64()
}

// readLine reads one '\n'-terminated line unbuffered (so RESET really leaves
// input unread in the kernel).
func readLine(c net.Conn) (string, bool) {
	var line []byte
	b := make([]byte, 1)
	for {
		if n, err := c.Read(b); n != 1 || err != nil {
			return "", false
		}
		if b[0] == '\n' {
			return string(line), true
		}
		line = append(line, b[0])
	}
}

func commandSession(c *net.TCPConn, log *eventLog) {
	c.SetDeadline(time.Now().Add(30 * time.Second))
	hdr := make([]byte, 5) // swallow the ClientHello record
	if _, err := io.ReadFull(c, hdr); err != nil {
		log.note("no_hello")
		return
	}
	if _, err := io.CopyN(io.Discard, c, int64(hdr[3])<<8|int64(hdr[4])); err != nil {
		log.note("no_hello")
		return
	}
	for {
		line, ok := readLine(c)
		if !ok {
			log.note("eof")
			return
		}
		for _, cmd := range strings.Split(line, ";") {
			parts := strings.Fields(cmd)
			if len(parts) == 0 {
				continue
			}
			num := func(i int) int {
				if i < len(parts) {
					n, _ := strconv.Atoi(parts[i])
					return n
				}
				return 0
			}
			switch parts[0] {
			case "PING":
				c.Write([]byte("PONG\n"))
			case "SERVER_DATA":
				if _, err := c.Write(pattern(num(1), uint64(num(2)))); err != nil {
					log.note("server_data_failed")
				} else {
					log.note("server_data_sent %d", num(1))
				}
			case "CLIENT_DATA":
				data := make([]byte, num(1))
				got, _ := io.ReadFull(c, data)
				if got < len(data) {
					log.note("client_data_short %d", got)
					return
				}
				log.note("client_data %d %d", got, hashOf(data))
				fmt.Fprintf(c, "GOT %d %d\n", got, hashOf(data))
			case "SLEEP":
				time.Sleep(time.Duration(num(1)) * time.Millisecond)
			case "WRITER_CLOSE":
				c.CloseWrite()
			case "READER_CLOSE":
				c.CloseRead()
			case "CLOSE":
				log.note("closed")
				return
			case "RESET":
				time.Sleep(300 * time.Millisecond) // let the client's junk arrive, unread
				log.note("reset")
				return
			default:
				log.note("unknown %s", parts[0])
			}
		}
	}
}

func cmdProxy(t *testing.T, global string) (*proxyUnderTest, *eventLog) {
	log := &eventLog{}
	port := backend(t, func(c *net.TCPConn) { commandSession(c, log) })
	return startProxy(t, global, allowAll(port)), log
}

func cmdConnect(t *testing.T, p *proxyUnderTest, sni string) *net.TCPConn {
	c := dial(t, p)
	c.Write(clientHello(sni))
	return c
}

func send(c net.Conn, s string) { c.Write([]byte(s)) }

func expectLine(t *testing.T, c net.Conn, want string) {
	t.Helper()
	if got, ok := readLine(c); !ok || got != want {
		t.Fatalf("got %q (ok=%v), want %q", got, ok, want)
	}
}

// assertHealthy: the proxy must still be fully functional.
func assertHealthy(t *testing.T, p *proxyUnderTest) {
	t.Helper()
	c := cmdConnect(t, p, "health.test")
	defer c.Close()
	send(c, "PING\n")
	expectLine(t, c, "PONG")
}

func TestCmdServerSendsThenCloses(t *testing.T) {
	t.Parallel()
	p, _ := cmdProxy(t, "")
	c := cmdConnect(t, p, "a.test")
	send(c, "SERVER_DATA 3000000 11;CLOSE\n")
	if !bytes.Equal(readToEnd(t, c), pattern(3_000_000, 11)) {
		t.Fatal("data lost before close")
	}
	assertHealthy(t, p)
}

func TestCmdServerResetsConnection(t *testing.T) {
	t.Parallel()
	p, log := cmdProxy(t, "")
	c := cmdConnect(t, p, "rst.test")
	send(c, "RESET\n")
	c.Write(make([]byte, 4096)) // stays unread -> the server's close becomes RST
	start := time.Now()
	readToEnd(t, c) // must end promptly, not hang until the idle timeout
	between(t, start, 0, 5*time.Second)
	log.waitFor(t, "reset")
	assertHealthy(t, p)
}

func TestCmdWriterCloseClientCanStillUpload(t *testing.T) {
	t.Parallel()
	p, log := cmdProxy(t, "half_close_timeout=8")
	c := cmdConnect(t, p, "wc.test")
	send(c, "WRITER_CLOSE\n")
	if got := readToEnd(t, c); len(got) != 0 { // EOF propagated to the client
		t.Fatal(got)
	}
	data := pattern(2_000_000, 21)
	send(c, "CLIENT_DATA 2000000\n")
	c.Write(data)
	if e := log.waitFor(t, "client_data "); e != fmt.Sprintf("client_data 2000000 %d", hashOf(data)) {
		t.Fatal(e)
	}
}

func TestCmdReaderCloseServerCanStillSend(t *testing.T) {
	t.Parallel()
	p, _ := cmdProxy(t, "")
	c := cmdConnect(t, p, "rc.test")
	send(c, "READER_CLOSE;SLEEP 300;SERVER_DATA 500000 31;CLOSE\n")
	if got := readToEnd(t, c); !bytes.Equal(got, pattern(500_000, 31)) {
		t.Fatalf("got %d bytes", len(got))
	}
	assertHealthy(t, p)
}

func TestCmdReaderCloseWhileClientKeepsWriting(t *testing.T) {
	t.Parallel()
	// What the upstream's OS does with data for a closed reader differs: Linux
	// drops it silently, BSD/macOS answer with RST (killing both directions).
	// Either way the proxy must end promptly, deliver nothing corrupt, and
	// stay healthy.
	p, _ := cmdProxy(t, "half_close_timeout=2")
	c := cmdConnect(t, p, "rcw.test")
	send(c, "READER_CLOSE;SLEEP 300;SERVER_DATA 500000 31;CLOSE\n")
	go func() {
		junk := make([]byte, 8192)
		for i := 0; i < 200; i++ {
			if _, err := c.Write(junk); err != nil {
				return
			}
		}
	}()
	start := time.Now()
	got := readToEnd(t, c)
	between(t, start, 0, 6*time.Second)
	if full := pattern(500_000, 31); len(got) > len(full) || !bytes.Equal(got, full[:len(got)]) {
		t.Fatal("corrupt data")
	}
	assertHealthy(t, p)
}

func TestCmdClientAbortsMidDownload(t *testing.T) {
	t.Parallel()
	p, log := cmdProxy(t, "")
	c := cmdConnect(t, p, "abort-dl.test")
	send(c, "SERVER_DATA 200000000 41\n")
	readN(t, c, 1_000_000)
	c.Close() // the proxy is holding back-pressured data right now
	log.waitFor(t, "server_data_failed")
	assertHealthy(t, p)
}

func TestCmdClientAbortsMidUpload(t *testing.T) {
	t.Parallel()
	p, log := cmdProxy(t, "")
	c := cmdConnect(t, p, "abort-ul.test")
	send(c, "CLIENT_DATA 50000000\n")
	c.Write(pattern(1_000_000, 51))
	c.Close()
	if e := log.waitFor(t, "client_data_short"); e != "client_data_short 1000000" {
		t.Fatalf("bytes lost or invented on abort: %s", e)
	}
	assertHealthy(t, p)
}

func TestCmdBackpressureLosesNothing(t *testing.T) {
	t.Parallel()
	p, _ := cmdProxy(t, "")
	// Slow server: it isn't reading for 1.5 s while we push 8 MB.
	c := cmdConnect(t, p, "slow-srv.test")
	data := pattern(8_000_000, 61)
	send(c, "SLEEP 1500;CLIENT_DATA 8000000\n")
	c.Write(data)
	expectLine(t, c, fmt.Sprintf("GOT 8000000 %d", hashOf(data)))
	// Slow client: we aren't reading for 1.5 s while the server pushes 8 MB.
	c = cmdConnect(t, p, "slow-cli.test")
	send(c, "SERVER_DATA 8000000 71;CLOSE\n")
	time.Sleep(1500 * time.Millisecond)
	if !bytes.Equal(readToEnd(t, c), pattern(8_000_000, 71)) {
		t.Fatal("data lost under back-pressure")
	}
}

func TestCmdInterleavedBothDirections(t *testing.T) {
	t.Parallel()
	p, _ := cmdProxy(t, "buffer_size=1024")
	c := cmdConnect(t, p, "mix.test")
	for i := 0; i < 20; i++ {
		up := pattern(10_000+i*3_000, uint64(i))
		send(c, fmt.Sprintf("CLIENT_DATA %d\n", len(up)))
		c.Write(up)
		expectLine(t, c, fmt.Sprintf("GOT %d %d", len(up), hashOf(up)))
		n := 20_000 + i*7_000
		send(c, fmt.Sprintf("SERVER_DATA %d %d\n", n, i+100))
		if !bytes.Equal(readN(t, c, n), pattern(n, uint64(i+100))) {
			t.Fatalf("round %d", i)
		}
		send(c, "PING\n")
		expectLine(t, c, "PONG")
	}
}

func TestCmdBothSidesCloseAtOnce(t *testing.T) {
	t.Parallel()
	p, _ := cmdProxy(t, "")
	for i := 0; i < 50; i++ {
		c := cmdConnect(t, p, "both.test")
		send(c, "CLOSE\n")
		c.CloseWrite()
		if got := readToEnd(t, c); len(got) != 0 {
			t.Fatal(got)
		}
		c.Close()
	}
	assertHealthy(t, p)
}

func TestCmdInterruptionStormLeaksNothing(t *testing.T) {
	t.Parallel()
	p, _ := cmdProxy(t, "max_connections=40\nhalf_close_timeout=1")
	for round := 0; round < 4; round++ {
		var wg sync.WaitGroup
		for i := 0; i < 30; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				c, err := net.Dial("tcp", p.addr)
				if err != nil {
					return
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(T))
				c.Write(clientHello(fmt.Sprintf("storm%d.test", i)))
				switch (i + round) % 6 {
				case 0: // drop mid-download
					send(c, "SERVER_DATA 5000000 1\n")
					c.Read(make([]byte, 1000))
				case 1: // drop mid-upload
					send(c, "CLIENT_DATA 5000000\n")
					c.Write(make([]byte, 100_000))
				case 2:
					send(c, "RESET\n")
					c.Write(make([]byte, 1000))
					io.Copy(io.Discard, c)
				case 3: // server lingers; grace = 1 s
					send(c, "WRITER_CLOSE\n")
					io.Copy(io.Discard, c)
				case 4:
					send(c, "SERVER_DATA 100000 2;CLOSE\n")
					io.Copy(io.Discard, c)
				default: // vanish right after the hello
				}
			}(i)
		}
		wg.Wait()
	}
	// Everything must drain: no connection, goroutine or slot may be left.
	st := p.srv.stats
	deadline := time.Now().Add(T)
	for st.Active.Load() != 0 || st.OpenGoroutines() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("leak after storm: %s", st.Summary(p.srv.runtime.Load()))
		}
		time.Sleep(50 * time.Millisecond)
	}
	st.mu.Lock()
	left := len(st.conns)
	st.mu.Unlock()
	if left != 0 {
		t.Fatalf("%d connections left in the registry", left)
	}
	var held []*net.TCPConn // and every slot is usable again
	for i := 0; i < 40; i++ {
		c := cmdConnect(t, p, "after.test")
		send(c, "PING\n")
		expectLine(t, c, "PONG")
		held = append(held, c)
	}
}
