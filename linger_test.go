package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// fakeMover hands topUp the next of its scripted answers, and counts the calls.
type fakeMover struct {
	size    int
	queued  int   // what waiting reports
	answers []int // what each topUp adds; -1: as much as there is room for
	topUps  int
}

func (m *fakeMover) read() (int, error) { return 0, nil }
func (m *fakeMover) topUp(have int) (int, error) {
	m.topUps++
	more := 0
	if len(m.answers) > 0 {
		more, m.answers = m.answers[0], m.answers[1:]
	}
	if more < 0 {
		more = m.size - have
	}
	return more, nil
}
func (m *fakeMover) waiting() int           { return m.queued }
func (m *fakeMover) write(int) (int, error) { return 0, nil }
func (m *fakeMover) chunk() int             { return m.size }
func (m *fakeMover) close()                 {}

// stream calls batch for each read size in turn, back to back.
func stream(b *batcher, m mover, reads ...int) (held []int) {
	for _, n := range reads {
		got, _ := b.batch(m, n)
		held = append(held, got)
	}
	return held
}

// The first read of a stream is not lingered on (it may be a lone message);
// a short read right after one is, and moves with what the top-up added.
func TestLingerTopsUpAShortReadInAStream(t *testing.T) {
	m := &fakeMover{size: 65536, queued: -1, answers: []int{3000, 3000}}
	var b batcher
	held := stream(&b, m, 1000, 1000, 1000)
	if m.topUps != 2 || held[0] != 1000 || held[1] != 4000 || held[2] != 4000 {
		t.Fatalf("top-ups %d, held %v", m.topUps, held)
	}
}

// A full read moves at once.
func TestLingerNeverHoldsAFullRead(t *testing.T) {
	m := &fakeMover{size: 65536, queued: -1}
	var b batcher
	stream(&b, m, 65536, 65536, 65536)
	if m.topUps != 0 {
		t.Fatalf("%d top-ups for full reads", m.topUps)
	}
}

// A top-up that gets nothing lingers out: request and reply.
func TestLingerOutWhenNothingArrives(t *testing.T) {
	m := &fakeMover{size: 65536, queued: -1, answers: []int{0}}
	var b batcher
	stream(&b, m, 100, 100, 100, 100)
	if m.topUps != 1 {
		t.Fatalf("%d top-ups, want 1 then linger out", m.topUps)
	}
}

// A top-up that fills the chunk means the stream outruns a linger: reads as
// big as the one before it then move at once. Terminated TLS reads one record
// at a time, short of the chunk however much is waiting; without this, a bulk
// download would sleep after every chunk.
func TestLingerStopsWhenTheChunkFills(t *testing.T) {
	m := &fakeMover{size: 65536, queued: -1, answers: []int{-1}}
	var b batcher
	held := stream(&b, m, 16384, 16384, 16384, 16384)
	if m.topUps != 1 || held[1] != 65536 {
		t.Fatalf("top-ups %d, held %v", m.topUps, held)
	}
	// A smaller read still lingers: a slow patch of the same stream.
	if stream(&b, m, 8000); m.topUps != 2 {
		t.Fatalf("%d top-ups, want the smaller read to linger", m.topUps)
	}
}

// A top-up that takes less than the socket held means the pipe filled (a
// network card's packets, one per pipe slot): that is the full size now.
func TestLingerLearnsThePipeHoldsLess(t *testing.T) {
	m := &fakeMover{size: 65536, queued: 50000, answers: []int{13000}}
	var b batcher
	held := stream(&b, m, 10000, 10000, 23000, 23000)
	if m.topUps != 1 || held[1] != 23000 {
		t.Fatalf("top-ups %d, held %v", m.topUps, held)
	}
}

// After hintRecheck, lingering is tried again and the hint starts over.
func TestLingerRechecks(t *testing.T) {
	m := &fakeMover{size: 65536, queued: -1, answers: []int{0, 10}}
	var b batcher
	stream(&b, m, 100, 100, 100)
	if m.topUps != 1 {
		t.Fatalf("%d top-ups before the recheck", m.topUps)
	}
	b.checked = b.checked.Add(-hintRecheck)
	stream(&b, m, 100)
	if m.topUps != 2 {
		t.Fatalf("%d top-ups after the recheck, want 2", m.topUps)
	}
}

// Reads further apart than lingerGap are separate messages.
func TestLingerSkipsSeparateMessages(t *testing.T) {
	m := &fakeMover{size: 65536, queued: -1, answers: []int{10, 10}}
	var b batcher
	stream(&b, m, 100)
	b.lastRead = b.lastRead.Add(-lingerGap)
	stream(&b, m, 100)
	if m.topUps != 0 {
		t.Fatalf("%d top-ups for reads %v apart", m.topUps, lingerGap)
	}
}

func TestLowLatencyNeverLingers(t *testing.T) {
	m := &fakeMover{size: 65536, queued: -1, answers: []int{10, 10}}
	b := batcher{off: true}
	stream(&b, m, 100, 100, 100)
	if m.topUps != 0 {
		t.Fatalf("%d top-ups with low_latency", m.topUps)
	}
}

// A buffered top-up through TLS collects every record that has arrived, not
// just one, and returns without waiting once there is nothing more.
func TestBufferTopUpReadsEveryTLSRecord(t *testing.T) {
	ca := newTestCA(t)
	certPEM, keyPEM := ca.issue(t, time.Hour, "a.test")
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	srv := tls.Server(a, &tls.Config{Certificates: []tls.Certificate{cert}})
	cli := tls.Client(b, &tls.Config{RootCAs: ca.pool, ServerName: "a.test"})
	go func() {
		for range 8 {
			cli.Write(make([]byte, 1000)) // one record each
		}
	}()
	m := newBufferMover(srv, srv, NewBufferPool(65536, 0), 65536)
	defer m.close()
	n, err := m.read()
	if err != nil || n != 1000 {
		t.Fatalf("read %d, %v", n, err)
	}
	time.Sleep(20 * time.Millisecond) // the other seven records arrive
	start := time.Now()
	more, err := m.topUp(n)
	if err != nil || more != 7000 {
		t.Fatalf("top-up %d, %v; want 7000", more, err)
	}
	if took := time.Since(start); took > 50*time.Millisecond {
		t.Fatalf("top-up took %v", took)
	}
}

// End to end through terminated TLS: a bulk upload in small records keeps its
// speed with lingering on (the chunk fills, so it stops waiting).
func TestLingerKeepsBulkTLSInSmallRecordsFast(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	dir := ca.localCA(t)
	const total = 16 << 20
	sink := backend(t, func(c *net.TCPConn) {
		n, _ := io.Copy(io.Discard, c)
		fmt.Fprint(c, n)
	})
	timeIt := func(lowLatency bool) time.Duration {
		p := startProxy(t, fmt.Sprintf("low_latency=%t", lowLatency), fmt.Sprintf(
			"[[host]]\nlistener=default\npattern=a\\.test\ncert=%s\nupstream_tls=false\ntarget_host=127.0.0.1\ntarget_port=%d\n", dir, sink))
		tc, err := tlsDial(t, p, &tls.Config{RootCAs: ca.pool, ServerName: "a.test"})
		if err != nil {
			t.Fatal(err)
		}
		tc.SetDeadline(time.Now().Add(60 * time.Second))
		start := time.Now()
		record := make([]byte, 1024)
		for sent := 0; sent < total; sent += len(record) {
			if _, err := tc.Write(record); err != nil {
				t.Fatal(err)
			}
		}
		tc.CloseWrite()
		got := string(readToEnd(t, tc))
		if got != fmt.Sprint(total) {
			t.Fatalf("backend got %s bytes, want %d", got, total)
		}
		return time.Since(start)
	}
	off, on := timeIt(true), timeIt(false)
	t.Logf("16 MiB in 1 KiB records: %v without lingering, %v with", off, on)
	// Sleeping after every 64 KiB would take 256 × 5 ms = 1.3 s at least.
	if on > 2*off+500*time.Millisecond {
		t.Fatalf("lingering slowed a bulk TLS upload from %v to %v", off, on)
	}
}

// Request and reply: lingering out after the first empty wait keeps round
// trips fast (at most one message per hintRecheck is held lingerTime).
func TestLingerKeepsRoundTripsFast(t *testing.T) {
	t.Parallel()
	p := startProxy(t, "", allowAll(echoBackend(t, "")))
	c := dial(t, p)
	hello := clientHello("rt.test")
	c.Write(hello)
	readN(t, c, len(hello))
	const trips = 200
	msg := make([]byte, 64)
	start := time.Now()
	for range trips {
		c.Write(msg)
		readN(t, c, len(msg))
	}
	took := time.Since(start)
	t.Logf("%d round trips in %v", trips, took)
	// Held on every trip, each way, this would be 2 s.
	if limit := time.Duration(trips) * lingerTime / 4; took > limit {
		t.Fatalf("%d round trips took %v, over %v", trips, took, limit)
	}
}

// BenchmarkLingerCPU: 10 connections, each a 20 Mbit/s stream of 1448-byte
// segments, through the proxy for 3 seconds, with lingering off and on.
// Reports CPU seconds per second for the whole test (senders, proxy and
// backend) and the throughput reached as a share of the target. Run with
//
//	go test -run '^$' -bench LingerCPU -benchtime 1x
func BenchmarkLingerCPU(b *testing.B) {
	if !haveCPUTime {
		b.Skip("no CPU time on this platform")
	}
	const (
		conns   = 10
		rate    = 20e6 / 8 // bytes per second, each
		segment = 1448
		run     = 3 * time.Second
	)
	for _, mode := range []string{"low_latency", "linger"} {
		b.Run(mode, func(b *testing.B) {
			for range b.N {
				var mu sync.Mutex
				received := 0
				sink := backend(b, func(c *net.TCPConn) {
					n, _ := io.Copy(io.Discard, c)
					mu.Lock()
					received += int(n)
					mu.Unlock()
				})
				p := startProxy(b, fmt.Sprintf("low_latency=%t", mode == "low_latency"), allowAll(sink)).addr
				hello := clientHello("cpu.test")
				var wg sync.WaitGroup
				start, cpu0 := time.Now(), cpuTime()
				for range conns {
					wg.Add(1)
					go func() {
						defer wg.Done()
						c, err := net.Dial("tcp", p)
						if err != nil {
							b.Error(err)
							return
						}
						defer c.Close()
						c.Write(hello)
						seg := make([]byte, segment)
						gap := time.Duration(float64(time.Second) * segment / rate)
						next := time.Now()
						for time.Since(start) < run {
							c.Write(seg)
							next = next.Add(gap)
							if d := time.Until(next); d > 0 {
								time.Sleep(d)
							}
						}
						c.(*net.TCPConn).CloseWrite()
						io.Copy(io.Discard, c)
					}()
				}
				wg.Wait()
				elapsed, cpu := time.Since(start), cpuTime()-cpu0
				time.Sleep(100 * time.Millisecond) // the last bytes reach the sink
				mu.Lock()
				got := received
				mu.Unlock()
				b.ReportMetric(cpu.Seconds()/elapsed.Seconds(), "cpu-s/s")
				b.ReportMetric(100*float64(got)/(conns*rate*run.Seconds()), "%target")
			}
		})
	}
}
