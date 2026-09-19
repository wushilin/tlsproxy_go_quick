package main

// Global, always-current state: counters plus a registry of open connections.
// Everything hot is an atomic, so relaying never takes a lock for accounting.

import (
	"fmt"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Direction states.
const (
	dirOpen int32 = iota
	dirHalfClosed
)

// ConnState is the live state of one proxied connection, shared by its two
// relay goroutines and visible in the registry.
type ConnState struct {
	ID    uint64
	Src   string
	Start time.Time

	// Set once routing/connecting is done; read by the stats dump.
	mu             sync.Mutex
	SNI, Dst, Peer string
	firstClosed    string    // how the first direction ended, "" if none has
	firstClosedAt  time.Time // when, to report how long the other side took to follow
	closeReason    string
	closed         bool
	halfCloseTimer *time.Timer

	Mode string     // "" = passed through, otherwise how TLS was terminated
	host *HostStats // per-host counters this connection feeds

	CToS, SToC           atomic.Int32 // dirOpen / dirHalfClosed
	BytesUp, BytesDown   atomic.Int64
	lastActivityUnixNano atomic.Int64
}

func (c *ConnState) info() (sni, dst, peer string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.SNI, c.Dst, c.Peer
}

// Stats is the process-wide state.
type Stats struct {
	Accepted, Rejected, Denied, Failed, Completed atomic.Int64
	Active                                        atomic.Int64
	// Goroutines started/finished by the proxy (handlers + relay pumps).
	GoroutinesStarted, GoroutinesFinished atomic.Int64
	// Totals over all connections, live.
	BytesUp, BytesDown     atomic.Int64
	CacheHits, CacheMisses atomic.Int64

	mu    sync.Mutex
	conns map[uint64]*ConnState
	hosts map[string]*HostStats

	Started time.Time
	rateMu  sync.Mutex
	samples [rateWindow + 1]rateSample // one per second, ring
	sampleN int
}

// HostStats are the counters for one requested host name (SNI).
type HostStats struct {
	Active, Total      atomic.Int64
	BytesUp, BytesDown atomic.Int64
	Terminated         atomic.Int64 // connections whose TLS was terminated here
}

const (
	rateWindow   = 5    // seconds
	maxHostStats = 2000 // names come from clients; beyond this they share "(other)"
)

type rateSample struct {
	at                 time.Time
	up, down, accepted int64
}

// host returns the counters for an allowed name.
func (s *Stats) host(name string) *HostStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	if h := s.hosts[name]; h != nil {
		return h
	}
	if len(s.hosts) >= maxHostStats {
		name = "(other)"
		if h := s.hosts[name]; h != nil {
			return h
		}
	}
	h := &HostStats{}
	s.hosts[name] = h
	return h
}

// sample records the totals once a second for the rate display.
func (s *Stats) sample() {
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	s.samples[s.sampleN%len(s.samples)] = rateSample{time.Now(), s.BytesUp.Load(), s.BytesDown.Load(), s.Accepted.Load()}
	s.sampleN++
}

// Rates returns bytes/s up, bytes/s down and connections/s over the last
// rateWindow seconds.
func (s *Stats) Rates() (up, down, conns float64) {
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	if s.sampleN < 2 {
		return 0, 0, 0
	}
	newest := s.samples[(s.sampleN-1)%len(s.samples)]
	oldest := s.samples[max(0, s.sampleN-len(s.samples))%len(s.samples)]
	secs := newest.at.Sub(oldest.at).Seconds()
	if secs <= 0 {
		return 0, 0, 0
	}
	return float64(newest.up-oldest.up) / secs, float64(newest.down-oldest.down) / secs, float64(newest.accepted-oldest.accepted) / secs
}

func NewStats() *Stats {
	return &Stats{conns: make(map[uint64]*ConnState), hosts: make(map[string]*HostStats), Started: time.Now()}
}

func (s *Stats) register(c *ConnState) {
	s.mu.Lock()
	s.conns[c.ID] = c
	s.mu.Unlock()
}

func (s *Stats) unregister(c *ConnState) {
	s.mu.Lock()
	delete(s.conns, c.ID)
	s.mu.Unlock()
}

// OpenGoroutines is how many proxy goroutines are running right now.
func (s *Stats) OpenGoroutines() int64 {
	return s.GoroutinesStarted.Load() - s.GoroutinesFinished.Load()
}

// Summary is the one-line periodic report.
func (s *Stats) Summary(rt *Runtime) string {
	allow, deny := rt.cache.Len()
	return fmt.Sprintf("stats: active=%d accepted=%d completed=%d denied=%d failed=%d rejected=%d "+
		"goroutines=%d (started=%d finished=%d, runtime=%d) up=%s down=%s "+
		"cache=%d allow/%d deny (hits=%d misses=%d) pool_idle=%d",
		s.Active.Load(), s.Accepted.Load(), s.Completed.Load(), s.Denied.Load(), s.Failed.Load(), s.Rejected.Load(),
		s.OpenGoroutines(), s.GoroutinesStarted.Load(), s.GoroutinesFinished.Load(), runtime.NumGoroutine(),
		humanBytes(s.BytesUp.Load()), humanBytes(s.BytesDown.Load()),
		allow, deny, s.CacheHits.Load(), s.CacheMisses.Load(), rt.pool.Idle())
}

// Dump logs the summary and one line per open connection (SIGUSR1 / SIGINFO).
func (s *Stats) Dump(rt *Runtime) {
	s.mu.Lock()
	conns := make([]*ConnState, 0, len(s.conns))
	for _, c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	sort.Slice(conns, func(i, j int) bool { return conns[i].ID < conns[j].ID })
	logf("%s", s.Summary(rt))
	state := func(v int32) string {
		if v == dirOpen {
			return "open"
		}
		return "half-closed"
	}
	for _, c := range conns {
		sni, dst, peer := c.info()
		if sni == "" {
			sni = "<none>"
		}
		idle := time.Since(time.Unix(0, c.lastActivityUnixNano.Load()))
		logf("  [#%d] src=%s sni=%s dst=%s (%s) up=%s down=%s age=%s idle=%s c_to_s=%s s_to_c=%s",
			c.ID, c.Src, sni, dst, peer, humanBytes(c.BytesUp.Load()), humanBytes(c.BytesDown.Load()),
			humanDuration(time.Since(c.Start)), humanDuration(idle), state(c.CToS.Load()), state(c.SToC.Load()))
	}
}
