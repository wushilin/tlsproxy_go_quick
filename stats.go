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
	firstClosed    string // how the first direction ended, "" if none has
	closeReason    string
	closed         bool
	halfCloseTimer *time.Timer

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
}

func NewStats() *Stats { return &Stats{conns: make(map[uint64]*ConnState)} }

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
