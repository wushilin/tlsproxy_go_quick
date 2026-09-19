package main

// Connection handling: accept, read ClientHello, route, relay, log.
//
// One goroutine per connection does the handshake and the client->server
// copy; a second does server->client. Goroutines are multiplexed over
// kqueue/epoll by the Go runtime, so this is plain blocking-style code.

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// TLS alert record: fatal (2), access_denied (49).
var alertAccessDenied = []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 49}

// Runtime is everything derived from one version of the config file. It is
// swapped atomically on reload: new connections use the new one, existing
// connections keep the one they started with. A new Runtime has empty caches.
type Runtime struct {
	cfg   *Config
	pool  *BufferPool
	cache *RouteCache
}

func newRuntime(cfg *Config, prev *Runtime) *Runtime {
	rt := &Runtime{cfg: cfg, cache: NewRouteCache(cfg.AllowCacheSize, cfg.DenyCacheSize)}
	if prev != nil && prev.cfg.BufferSize == cfg.BufferSize && prev.cfg.BufferPoolMaxIdle == cfg.BufferPoolMaxIdle {
		rt.pool = prev.pool
	} else {
		// A replaced pool is simply dropped: its parked buffers are garbage
		// collected, and buffers still in use are freed when returned.
		rt.pool = NewBufferPool(cfg.BufferSize, cfg.BufferPoolMaxIdle)
	}
	return rt
}

type Server struct {
	runtime atomic.Pointer[Runtime]
	stats   *Stats
	nextID  atomic.Uint64
}

func NewServer(cfg *Config) *Server {
	s := &Server{stats: NewStats()}
	s.runtime.Store(newRuntime(cfg, nil))
	return s
}

// Run binds to the configured address and serves forever.
func Run(cfg *Config, path string) error {
	l, err := net.Listen("tcp", net.JoinHostPort(cfg.Bind, strconv.Itoa(cfg.Port)))
	if err != nil {
		return err
	}
	// From here on the streams go to their log files, if configured.
	if err := ConfigureLogging(cfg.Log); err != nil {
		return err
	}
	return NewServer(cfg).Serve(l, path)
}

// Serve accepts connections on l. If path is non-empty the config file is
// watched and reloaded when it changes.
func (s *Server) Serve(l net.Listener, path string) error {
	rt := s.runtime.Load()
	logf("listening on %s with %s", l.Addr(), rt.cfg.Describe())
	for _, k := range rt.cfg.Ignored {
		logf("config: %q is not used by this version and was ignored", k)
	}
	if path != "" {
		go s.watchConfig(path)
	}
	go s.reportStats()
	watchSignals(s)
	for {
		sock, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			errorf("accept error: %v", err) // typically EMFILE; back off
			time.Sleep(200 * time.Millisecond)
			continue
		}
		rt := s.runtime.Load()
		id := s.nextID.Add(1)
		active := s.stats.Active.Add(1)
		if int(active) > rt.cfg.MaxConnections {
			logf("[#%d] rejected %s: too many connections (%d > %d)", id, sock.RemoteAddr(), active, rt.cfg.MaxConnections)
			s.stats.Active.Add(-1)
			s.stats.Rejected.Add(1)
			sock.Close()
			continue
		}
		s.stats.Accepted.Add(1)
		s.stats.GoroutinesStarted.Add(1)
		go func() {
			defer s.stats.GoroutinesFinished.Add(1)
			defer s.stats.Active.Add(-1)
			s.handle(id, sock.(*net.TCPConn), int(active), rt)
		}()
	}
}

func (s *Server) reportStats() {
	for {
		every := s.runtime.Load().cfg.StatsInterval
		if every == 0 {
			time.Sleep(5 * time.Second) // may be enabled by a reload
			continue
		}
		time.Sleep(every)
		logf("%s", s.stats.Summary(s.runtime.Load()))
	}
}

// watchConfig re-reads the config file every reload_interval and swaps in a
// new Runtime when its content changes. Comparing content (not mtime) means
// the newest version always wins and reloads happen at most once per interval.
func (s *Server) watchConfig(path string) {
	last, _ := os.ReadFile(path)
	haveLast := last != nil
	for {
		interval := s.runtime.Load().cfg.ReloadInterval
		if interval == 0 {
			logf("config reload disabled (reload_interval=0)")
			return
		}
		time.Sleep(interval)
		text, err := os.ReadFile(path)
		if err != nil {
			if haveLast {
				errorf("config reload: cannot read %s: %v; keeping current config", path, err)
				haveLast = false
			}
			continue
		}
		if haveLast && string(text) == string(last) {
			continue
		}
		last, haveLast = text, true
		cfg, err := ParseConfig(string(text))
		if err != nil {
			errorf("config reload: %s is invalid, keeping current config: %v", path, err)
			continue
		}
		old := s.runtime.Load()
		if cfg.Bind != old.cfg.Bind || cfg.Port != old.cfg.Port {
			errorf("config reload: bind/port change to %s:%d needs a restart; still listening on %s:%d",
				cfg.Bind, cfg.Port, old.cfg.Bind, old.cfg.Port)
		}
		if err := ConfigureLogging(cfg.Log); err != nil {
			errorf("config reload: %v; logging is unchanged", err)
		}
		rt := newRuntime(cfg, old)
		s.runtime.Store(rt)
		extra := ""
		if rt.pool != old.pool {
			extra = ", buffer pool replaced (old buffers freed)"
		}
		logf("config reloaded from %s: %s; route caches cleared%s; existing connections keep their settings",
			path, cfg.Describe(), extra)
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// readHello reads until the ClientHello is complete. It returns the SNI and
// every byte read (to be forwarded verbatim). buf is a pooled buffer; a hello
// that doesn't fit spills into a heap slice, which is returned instead.
func readHello(client net.Conn, buf []byte) (sni string, data []byte, err error) {
	data = buf[:0]
	for {
		if len(data) == cap(data) {
			if cap(data) > maxClientHello+16 {
				return "", data, errors.New("ClientHello too large")
			}
			bigger := make([]byte, len(data), 2*cap(data)+4096)
			copy(bigger, data)
			data = bigger
		}
		n, rerr := client.Read(data[len(data):cap(data)])
		data = data[:len(data)+n]
		if n > 0 {
			sni, perr := parseClientHello(data)
			if perr == nil {
				return sni, data, nil
			}
			if perr != errNeedMore {
				return "", data, perr
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				rerr = errors.New("closed before ClientHello was complete")
			}
			return "", data, rerr
		}
	}
}

func (s *Server) handle(id uint64, client *net.TCPConn, active int, rt *Runtime) {
	defer client.Close()
	cfg := rt.cfg
	start := time.Now()
	src := client.RemoteAddr().String()
	logf("[#%d] accepted from %s (active=%d)", id, src, active)

	c := &ConnState{ID: id, Src: src, Start: start}
	c.lastActivityUnixNano.Store(start.UnixNano())
	s.stats.register(c)
	defer s.stats.unregister(c)

	// One overall deadline: a slow trickle can't extend it.
	client.SetReadDeadline(start.Add(cfg.HandshakeTimeout))
	helloBuf := rt.pool.Get()
	sni, hello, err := readHello(client, helloBuf)
	if err != nil {
		rt.pool.Put(helloBuf)
		s.stats.Failed.Add(1)
		if isTimeout(err) {
			logf("[#%d] closed src=%s: no ClientHello within %s", id, src, humanDuration(cfg.HandshakeTimeout))
		} else {
			logf("[#%d] closed src=%s: bad ClientHello: %v after %s", id, src, err, humanDuration(time.Since(start)))
		}
		return
	}
	client.SetReadDeadline(time.Time{})
	sniDisp := sni
	if sni == "" {
		sniDisp = "<none>"
	}

	d, hit := rt.cache.GetOrRoute(sni, func() Decision { return cfg.Route(sni) })
	cached := ""
	if hit {
		cached = ", cached"
		s.stats.CacheHits.Add(1)
	} else {
		s.stats.CacheMisses.Add(1)
	}
	if !d.Allow {
		rt.pool.Put(helloBuf)
		s.stats.Denied.Add(1)
		switch {
		case d.Err != "":
			logf("[#%d] route sni=%s src=%s -> DENY (error: %s%s)", id, sniDisp, src, d.Err, cached)
		case d.RuleLine == 0:
			logf("[#%d] route sni=%s src=%s -> DENY (no rule matched%s)", id, sniDisp, src, cached)
		default:
			logf("[#%d] route sni=%s src=%s -> DENY (rule line %d%s)", id, sniDisp, src, d.RuleLine, cached)
		}
		client.Write(alertAccessDenied)
		return
	}
	dest := net.JoinHostPort(d.Host, strconv.Itoa(d.Port))
	destDisp := fmt.Sprintf("%s:%d", d.Host, d.Port)
	logf("[#%d] route sni=%s -> %s (ALLOW, rule line %d%s)", id, sniDisp, destDisp, d.RuleLine, cached)
	c.mu.Lock()
	c.SNI, c.Dst = sni, destDisp
	c.mu.Unlock()

	t0 := time.Now()
	dialer := net.Dialer{Timeout: cfg.ConnectTimeout}
	up, err := dialer.Dial("tcp", dest)
	if err != nil {
		rt.pool.Put(helloBuf)
		s.stats.Failed.Add(1)
		logf("[#%d] closed src=%s sni=%s dst=%s: connect failed: %v after %s", id, src, sniDisp, destDisp, err, humanDuration(time.Since(t0)))
		return
	}
	server := up.(*net.TCPConn)
	defer server.Close()
	peer := server.RemoteAddr().String()
	c.mu.Lock()
	c.Peer = peer
	c.mu.Unlock()
	logf("[#%d] connected %s -> %s (%s) in %s", id, src, destDisp, peer, humanDuration(time.Since(t0)))

	if cfg.IdleTimeout > 0 {
		server.SetWriteDeadline(time.Now().Add(cfg.IdleTimeout))
	}
	_, err = server.Write(hello)
	rt.pool.Put(helloBuf) // back to the pool before the (possibly long) relay
	if err != nil {
		s.stats.Failed.Add(1)
		logf("[#%d] closed src=%s sni=%s dst=%s: upstream write error: %v", id, src, sniDisp, destDisp, err)
		return
	}
	c.BytesUp.Add(int64(len(hello)))
	s.stats.BytesUp.Add(int64(len(hello)))
	c.touch()

	r := &relay{c: c, stats: s.stats, cfg: cfg, pool: rt.pool, client: client, server: server}
	var wg sync.WaitGroup
	wg.Add(1)
	s.stats.GoroutinesStarted.Add(1)
	go func() {
		defer s.stats.GoroutinesFinished.Add(1)
		defer wg.Done()
		r.pump(sToC)
	}()
	r.pump(cToS)
	wg.Wait()
	r.finish()
	s.stats.Completed.Add(1)
	logf("[#%d] closed src=%s sni=%s dst=%s (%s) up=%s down=%s duration=%s reason=%s",
		id, src, sniDisp, destDisp, peer, humanBytes(c.BytesUp.Load()), humanBytes(c.BytesDown.Load()),
		humanDuration(time.Since(start)), r.reason())
}

func (c *ConnState) touch() { c.lastActivityUnixNano.Store(time.Now().UnixNano()) }

type direction int

const (
	cToS direction = iota
	sToC
)

var (
	dirName        = [2]string{"client->upstream", "upstream->client"}
	closedLabel    = [2]string{"client closed", "upstream closed"}
	stoppedReading = [2]string{"upstream stopped reading", "client stopped reading"}
)

// relay is the pair of copy directions of one connection.
type relay struct {
	c              *ConnState
	stats          *Stats
	cfg            *Config
	pool           *BufferPool
	client, server *net.TCPConn
}

func (r *relay) dirState(d direction) *atomic.Int32 {
	if d == cToS {
		return &r.c.CToS
	}
	return &r.c.SToC
}

// pump copies one direction with a pooled buffer held for the life of the
// connection. Stale bytes in a reused buffer are never looked at: only
// buf[:n] from the latest read is used.
func (r *relay) pump(d direction) {
	from, to := r.client, r.server
	bytes, total := &r.c.BytesUp, &r.stats.BytesUp
	if d == sToC {
		from, to = r.server, r.client
		bytes, total = &r.c.BytesDown, &r.stats.BytesDown
	}
	buf := r.pool.Get()
	defer r.pool.Put(buf)
	idle := r.cfg.IdleTimeout
	for {
		if idle > 0 {
			// Idle means no traffic in EITHER direction, so the deadline
			// follows the shared last-activity time.
			from.SetReadDeadline(time.Unix(0, r.c.lastActivityUnixNano.Load()).Add(idle))
		}
		n, err := from.Read(buf)
		if n > 0 {
			if idle > 0 {
				to.SetWriteDeadline(time.Now().Add(idle))
			}
			if _, werr := to.Write(buf[:n]); werr != nil {
				if isTimeout(werr) {
					// Blocked for a whole idle period: nothing is moving.
					r.closeAll(fmt.Sprintf("%s error: write timed out", dirName[d]))
				} else {
					// The receiver won't take more. Only this direction is
					// over; data may still flow the other way.
					r.endDirection(d, stoppedReading[d], false)
				}
				return
			}
			bytes.Add(int64(n))
			total.Add(int64(n))
			r.c.touch()
			// Optional coalescing: after a short read the socket is drained;
			// pausing lets more data queue, so the next read is bigger (fewer
			// syscalls and goroutine wake-ups per byte).
			if n < len(buf) && r.cfg.ShortReadDelay > 0 && err == nil {
				time.Sleep(r.cfg.ShortReadDelay)
			}
		}
		if err == nil {
			continue
		}
		switch {
		case err == io.EOF:
			r.endDirection(d, closedLabel[d], true)
		case r.isClosed():
			// Woken up by closeAll; the reason is already recorded.
		case isTimeout(err):
			last := time.Unix(0, r.c.lastActivityUnixNano.Load())
			if time.Since(last) < idle {
				continue // the other direction was active; keep waiting
			}
			r.closeAll(r.idleReason())
		default:
			r.closeAll(fmt.Sprintf("%s error: %v", dirName[d], err))
		}
		return
	}
}

func (r *relay) isClosed() bool {
	r.c.mu.Lock()
	defer r.c.mu.Unlock()
	return r.c.closed
}

func (r *relay) reason() string {
	r.c.mu.Lock()
	defer r.c.mu.Unlock()
	return r.c.closeReason
}

func (r *relay) idleReason() string {
	r.c.mu.Lock()
	first := r.c.firstClosed
	r.c.mu.Unlock()
	if first != "" {
		first += ", then "
	}
	return fmt.Sprintf("%sidle timeout (%s); closed by proxy", first, humanDuration(r.cfg.IdleTimeout))
}

// endDirection: direction d is over, because its source reached EOF (forward
// the half-close) or its destination refused data. The other direction may
// continue until it ends or half_close_timeout fires.
func (r *relay) endDirection(d direction, how string, forward bool) {
	if forward {
		to := r.server
		if d == sToC {
			to = r.client
		}
		to.CloseWrite()
	}
	r.dirState(d).Store(dirHalfClosed)
	c := r.c
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	if r.dirState(1-d).Load() == dirHalfClosed {
		// The other side had already ended: a normal, mutual close.
		c.closed = true
		if c.firstClosed != "" {
			c.closeReason = fmt.Sprintf("%s, then %s %s later", c.firstClosed, how, humanDuration(time.Since(c.firstClosedAt)))
		} else {
			c.closeReason = how + ", both directions ended"
		}
		c.mu.Unlock()
		return
	}
	c.firstClosed, c.firstClosedAt = how, time.Now()
	if limit := r.cfg.HalfCloseTimeout; limit > 0 {
		c.halfCloseTimer = time.AfterFunc(limit, func() {
			r.closeAll(fmt.Sprintf("%s, other direction still open after half_close_timeout (%s); closed by proxy", how, humanDuration(limit)))
		})
	}
	c.mu.Unlock()
}

// closeAll ends the connection (the first reason wins) and unblocks both pumps.
func (r *relay) closeAll(reason string) {
	c := r.c
	c.mu.Lock()
	if !c.closed {
		c.closed, c.closeReason = true, reason
	}
	c.mu.Unlock()
	r.client.Close()
	r.server.Close()
}

func (r *relay) finish() {
	r.c.mu.Lock()
	if r.c.halfCloseTimer != nil {
		r.c.halfCloseTimer.Stop()
	}
	r.c.closed = true
	r.c.mu.Unlock()
}
