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
	Local string // where the client connected (as the PROXY header says, if any)
	Start time.Time

	// Set once routing/connecting is done; read by the stats dump.
	mu             sync.Mutex
	SNI, Dst, Peer string
	routed         bool      // SNI is set: routing has decided
	UpLocal        string    // our end of the upstream connection
	firstClosed    string    // how the first direction ended, "" if none has
	firstClosedAt  time.Time // when, to report how long the other side took to follow
	closeReason    string
	closed         bool
	result         string // how it ended, for the flow log: flowClosed, flowDenied...
	endReason      string
	how            flowHow // how it is handled, for the flow log; filled in as it is learned
	halfCloseTimer *time.Timer

	Mode        string         // "" = passed through, otherwise how TLS was terminated
	host        *HostStats     // per-host counters this connection feeds
	Listener    string         // the listener it came in on
	lstats      *ListenerStats // whose counters it feeds
	RuleKey     string         // the rule that routed it ("" until routed)
	rulePattern string         // its pattern, for the console once the rule is gone
	rule        *RuleStats     // per-rule counters this connection feeds
	// kill ends the connection once it relays; until then a stop request is
	// remembered in killReason and applied when the relay starts.
	kill       func(reason string)
	killReason string

	CToS, SToC           atomic.Int32               // dirOpen / dirHalfClosed
	relaying, spliced    atomic.Int32               // directions relaying, and how many of them with splice(2)
	slot                 *atomic.Pointer[ConnState] // its place in Stats.conns
	BytesUp, BytesDown   atomic.Int64
	lastActivityUnixNano atomic.Int64
}

// stop ends the connection from outside (the console), now or as soon as it
// starts relaying.
func (c *ConnState) stop(reason string) {
	c.mu.Lock()
	kill := c.kill
	if kill == nil && c.killReason == "" {
		c.killReason = reason
	}
	c.mu.Unlock()
	if kill != nil {
		kill(reason)
	}
}

// setKill registers how to end the relaying connection, applying a stop
// requested earlier.
func (c *ConnState) setKill(kill func(string)) {
	c.mu.Lock()
	c.kill = kill
	reason := c.killReason
	c.mu.Unlock()
	if reason != "" {
		kill(reason)
	}
}

// setEnd records how the connection ended, for the flow log.
func (c *ConnState) setEnd(result, reason string) {
	c.mu.Lock()
	c.result, c.endReason = result, reason
	c.mu.Unlock()
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

	// Registries: no lock on the serving path (see syncMap).
	conns connTable
	hosts *hostTable
	rules syncMap[string, *RuleStats] // by Rule.Key
	lists syncMap[string, *ListenerStats]
	flows *flowLog

	Started time.Time
	rateMu  sync.Mutex
	samples [rateWindow + 1]rateSample // one per second, ring
	sampleN int
}

// ListenerStats are the counters for one listener (by name), kept across
// reloads.
type ListenerStats struct {
	Active, Accepted, Rejected atomic.Int64
	BytesUp, BytesDown         atomic.Int64
}

func (s *Stats) listener(name string) *ListenerStats {
	return s.lists.LoadOrMake(name, func() *ListenerStats { return &ListenerStats{} })
}

// listenerSnapshot returns a listener's counters, nil if it never had a connection.
func (s *Stats) listenerSnapshot(name string) *ListenerStats {
	l, _ := s.lists.Load(name)
	return l
}

// RuleStats are the counters for one rule (by Rule.Key), kept across reloads.
type RuleStats struct {
	Active, Total      atomic.Int64
	BytesUp, BytesDown atomic.Int64
}

// rule returns the counters for a rule key.
func (s *Stats) rule(key string) *RuleStats {
	return s.rules.LoadOrMake(key, func() *RuleStats { return &RuleStats{} })
}

// ruleSnapshot returns the counters of a rule, nil if it never had a connection.
func (s *Stats) ruleSnapshot(key string) *RuleStats {
	r, _ := s.rules.Load(key)
	return r
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
// The cap is approximate: racing first connections of new names may each
// get in before the count says full.
func (s *Stats) host(name string) *HostStats { return s.hosts.get(name) }

// prepare makes the counters of every rule and listener of cfg before it
// goes live, so connections only ever read them (a read never locks; adding
// a key to a sync.Map does).
func (s *Stats) prepare(cfg *Config) {
	for i := range cfg.Rules {
		s.rule(cfg.Rules[i].Key())
	}
	for _, l := range cfg.PortListeners() {
		s.listener(l.Name)
	}
	if cfg.Redirect != nil {
		s.rule(redirectKey)
	}
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
	s := &Stats{flows: newFlowLog(), hosts: newHostTable(), Started: time.Now()}
	// A sync.Map sets itself up under a lock on first use: do it now, not in
	// the first burst of connections.
	s.rules.init()
	s.lists.init()
	return s
}

func (s *Stats) register(c *ConnState) {
	c.slot = s.conns.add(c)
	s.flows.emit("open", c)
}

func (s *Stats) unregister(c *ConnState) {
	s.conns.remove(c.slot)
	s.flows.end(c)
}

// connList is the open connections, at most limit of them (0: all), and
// whether there were more.
func (s *Stats) connList(limit int) (out []*ConnState, truncated bool) {
	out = make([]*ConnState, 0, s.conns.Len())
	s.conns.Range(func(c *ConnState) bool {
		if limit > 0 && len(out) == limit {
			truncated = true
			return false
		}
		out = append(out, c)
		return true
	})
	return out, truncated
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
	conns, _ := s.connList(0)
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
