package main

// Benchmarks: the token bucket the proxy uses (GCRA, one atomic timestamp,
// updated by whoever sends) against the alternative of a dedicated goroutine
// that refills every limiter on a tick, the senders only subtracting.
//
//	go test -run '^$' -bench 'Limiter' -benchtime 2s
//
// BenchmarkLimiterReserve is the bookkeeping cost per chunk, with a few
// hundred goroutines sending through one shared limiter (a rule's aggregate
// speed: the contended case) or each through its own (per connection), limits
// high enough never to wait. BenchmarkLimiterUnderLoad runs a few hundred
// limited senders for real and reports how close they get to the target,
// how fairly it is shared, and the CPU it costs.

import (
	"fmt"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// rateLimiter is what both designs offer the relay: charge n bytes, get how
// long to wait before sending them.
type rateLimiter interface {
	reserve(n int64) time.Duration
}

// ---------------------------------------------------------------- the alternative

// refillLimiter is a token bucket refilled by a goroutine: senders only
// subtract (one atomic add, no clock), going into debt; the refiller adds
// rate x tick to every limiter, never beyond the burst.
type refillLimiter struct {
	tokens atomic.Int64
	rate   float64
	burst  int64
}

func (l *refillLimiter) reserve(n int64) time.Duration {
	if left := l.tokens.Add(-n); left < 0 {
		return time.Duration(float64(-left) / l.rate * float64(time.Second)) // until the refills cover the debt
	}
	return 0
}

// refiller tops up its limiters every tick.
type refiller struct {
	mu       sync.Mutex
	limiters []*refillLimiter
	tick     time.Duration
	stop     chan struct{}
	rounds   atomic.Int64
}

func newRefiller(tick time.Duration) *refiller {
	r := &refiller{tick: tick, stop: make(chan struct{})}
	go func() {
		t := time.NewTicker(tick)
		defer t.Stop()
		last := time.Now()
		for {
			select {
			case <-r.stop:
				return
			case now := <-t.C:
				dt := now.Sub(last).Seconds()
				last = now
				r.mu.Lock()
				for _, l := range r.limiters {
					add := int64(l.rate * dt)
					for {
						cur := l.tokens.Load()
						next := min(cur+add, l.burst)
						if next <= cur || l.tokens.CompareAndSwap(cur, next) {
							break
						}
					}
				}
				r.mu.Unlock()
				r.rounds.Add(1)
			}
		}
	}()
	return r
}

func (r *refiller) add(rate float64, bufferSize int) *refillLimiter {
	l := &refillLimiter{rate: rate, burst: int64(limitedChunk(rate, bufferSize))}
	l.tokens.Store(l.burst)
	r.mu.Lock()
	r.limiters = append(r.limiters, l)
	r.mu.Unlock()
	return l
}

func (r *refiller) close() { close(r.stop) }

// ---------------------------------------------------------------- the benchmarks

const benchSenders = 300

// BenchmarkLimiterReserve: cost per chunk, nothing ever waits.
func BenchmarkLimiterReserve(b *testing.B) {
	huge := 1e15 // bytes per second: never limits
	for _, shared := range []bool{true, false} {
		for _, kind := range []string{"gcra", "refill"} {
			b.Run(fmt.Sprintf("%s/%s", map[bool]string{true: "shared", false: "per-conn"}[shared], kind), func(b *testing.B) {
				var r *refiller
				if kind == "refill" {
					r = newRefiller(10 * time.Millisecond)
					defer r.close()
				}
				make1 := func() rateLimiter {
					if r != nil {
						return r.add(huge, 65536)
					}
					return newLimiter(huge, 65536)
				}
				one := make1()
				b.SetParallelism((benchSenders + runtime.GOMAXPROCS(0) - 1) / runtime.GOMAXPROCS(0))
				b.ResetTimer()
				b.RunParallel(func(pb *testing.PB) {
					l := one
					if !shared {
						l = make1()
					}
					for pb.Next() {
						l.reserve(16384)
					}
				})
			})
		}
	}
}

// BenchmarkLimiterUnderLoad: 300 senders, each limited to 2 MB/s, all sharing
// a 200 MB/s aggregate (which binds: they would want 600 MB/s), sending
// chunks the way the relay does for 3 seconds. Reports the throughput as a
// share of the target, the slowest and fastest sender against the fair
// share, and CPU seconds per second of running.
func BenchmarkLimiterUnderLoad(b *testing.B) {
	const (
		perConn   = 2e6
		aggregate = 200e6
		run       = 3 * time.Second
	)
	for _, kind := range []string{"gcra", "refill"} {
		b.Run(kind, func(b *testing.B) {
			for range b.N {
				var r *refiller
				newL := func(rate float64) rateLimiter { return newLimiter(rate, 65536) }
				if kind == "refill" {
					r = newRefiller(10 * time.Millisecond)
					newL = func(rate float64) rateLimiter { return r.add(rate, 65536) }
				}
				agg := newL(aggregate)
				chunk := int64(limitedChunk(perConn, 65536)) // what pump uses for a limited flow
				sent := make([]int64, benchSenders)
				var wg sync.WaitGroup
				start, cpu0 := time.Now(), cpuTime()
				deadline := start.Add(run)
				for i := range benchSenders {
					wg.Add(1)
					go func() {
						defer wg.Done()
						own := newL(perConn)
						for time.Now().Before(deadline) {
							if d := max(own.reserve(chunk), agg.reserve(chunk)); d > 0 {
								time.Sleep(d)
							}
							sent[i] += chunk
						}
					}()
				}
				wg.Wait()
				elapsed, cpu := time.Since(start), cpuTime()-cpu0
				if r != nil {
					r.close()
				}
				var total int64
				for _, s := range sent {
					total += s
				}
				sort.Slice(sent, func(i, j int) bool { return sent[i] < sent[j] })
				fair := float64(total) / benchSenders
				b.ReportMetric(100*float64(total)/elapsed.Seconds()/aggregate, "%target")
				b.ReportMetric(100*float64(sent[0])/fair, "%fair-min")
				b.ReportMetric(100*float64(sent[len(sent)-1])/fair, "%fair-max")
				if haveCPUTime {
					b.ReportMetric(cpu.Seconds()/elapsed.Seconds(), "cpu-s/s")
				}
			}
		})
	}
}

// BenchmarkRefillerIdle: what the refiller costs with no traffic at all,
// for 10000 limiters (open connections, each with its own limit). The
// current design costs nothing while idle.
func BenchmarkRefillerIdle(b *testing.B) {
	for range b.N {
		r := newRefiller(10 * time.Millisecond)
		for range 10000 {
			r.add(2e6, 65536)
		}
		cpu0, t0 := cpuTime(), time.Now()
		time.Sleep(2 * time.Second)
		cpu, elapsed := cpuTime()-cpu0, time.Since(t0)
		r.close()
		if haveCPUTime {
			b.ReportMetric(cpu.Seconds()/elapsed.Seconds(), "cpu-s/s")
		}
		b.ReportMetric(float64(r.rounds.Load())/elapsed.Seconds(), "rounds/s")
	}
}
