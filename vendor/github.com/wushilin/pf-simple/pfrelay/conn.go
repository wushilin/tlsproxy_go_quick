package pfrelay

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wushilin/pf-simple/internal/tunnel"
)

// Side is which end of the tunnel a connection belongs to.
type Side string

const (
	SideConnect Side = "connect" // opened by Dial, Connect or ConnectOne
	SideServe   Side = "serve"   // brought in by Listen, Serve or ServeOne
)

// ConnInfo is a snapshot of one connection.
type ConnInfo struct {
	ID       ConnID    // the server's connection id
	Side     Side      // which end of the tunnel this is
	Opened   time.Time // when the connection was opened
	Sent     int64     // bytes sent into the tunnel
	Received int64     // bytes received from the tunnel
	WroteEOF bool      // this end has half-closed
	ReadEOF  bool      // the far end has half-closed
}

// Stats counts a Client's connections, open and closed, since it was made.
// A Client serves or connects to one word, so these are that word's
// figures as this side sees them.
type Stats struct {
	Opened   uint64 // connections opened
	Active   uint64 // connections open now
	Failed   uint64 // connections that ended with an error
	Sent     int64  // bytes sent into the tunnel
	Received int64  // bytes received from the tunnel
}

// connRecord is the bookkeeping of one connection, shared by Conn and the
// forwarders.
type connRecord struct {
	id       ConnID
	side     Side
	opened   time.Time
	stream   *tunnel.Stream
	sent     atomic.Int64
	received atomic.Int64
	finished atomic.Bool
	dropped  atomic.Pointer[string] // the reason, once Drop was used
}

// registry holds a Client's live connections and its totals.
type registry struct {
	mu       sync.Mutex
	live     map[*connRecord]struct{}
	opened   uint64
	failed   uint64
	sent     int64 // of the connections that have ended
	received int64
}

func (r *registry) add(id string, side Side, s *tunnel.Stream) *connRecord {
	rec := &connRecord{id: ConnID{id}, side: side, opened: time.Now(), stream: s}
	r.mu.Lock()
	if r.live == nil {
		r.live = make(map[*connRecord]struct{})
	}
	r.live[rec] = struct{}{}
	r.opened++
	r.mu.Unlock()
	return rec
}

// finish moves rec out of the live set. It reports false if it already
// had.
func (r *registry) finish(rec *connRecord, failed bool) bool {
	if !rec.finished.CompareAndSwap(false, true) {
		return false
	}
	r.mu.Lock()
	delete(r.live, rec)
	if failed {
		r.failed++
	}
	r.sent += rec.sent.Load()
	r.received += rec.received.Load()
	r.mu.Unlock()
	return true
}

func (rec *connRecord) info() ConnInfo {
	return ConnInfo{
		ID: rec.id, Side: rec.side, Opened: rec.opened,
		Sent: rec.sent.Load(), Received: rec.received.Load(),
		WroteEOF: rec.stream.WroteEOF(), ReadEOF: rec.stream.HalfClosed(),
	}
}

// Stats returns this client's totals, open connections included.
func (c *Client) Stats() Stats {
	r := &c.reg
	r.mu.Lock()
	defer r.mu.Unlock()
	st := Stats{Opened: r.opened, Active: uint64(len(r.live)), Failed: r.failed, Sent: r.sent, Received: r.received}
	for rec := range r.live {
		st.Sent += rec.sent.Load()
		st.Received += rec.received.Load()
	}
	return st
}

// Conns lists this client's open connections, oldest first.
func (c *Client) Conns() []ConnInfo {
	r := &c.reg
	r.mu.Lock()
	out := make([]ConnInfo, 0, len(r.live))
	for rec := range r.live {
		out = append(out, rec.info())
	}
	r.mu.Unlock()
	for i := 1; i < len(out); i++ { // few connections: insertion sort
		for j := i; j > 0 && out[j].Opened.Before(out[j-1].Opened); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// Conn is one connection through a tunnel. It is a net.Conn, plus
// CloseWrite to half-close and Fail to drop it with a reason.
//
// Read returns io.EOF when the far end half-closes, and a *RemoteError when
// the far end or the server dropped the connection, with their reason. The
// connection's own end can be half-closed with CloseWrite; Close sends a
// half-close first if there was none, much as closing a TCP socket sends
// its FIN.
//
// Deadlines work as for any net.Conn. A read deadline that passes leaves
// the connection usable; a write deadline that passes during a write
// breaks it, as with crypto/tls, since part of a frame may have been sent.
type Conn struct {
	s   *tunnel.Stream
	c   *Client
	rec *connRecord

	rmu      sync.Mutex // serializes Read
	pending  []byte     // what the last chunk has left
	rerr     error      // the error that ends reading, once seen
	chunks   chan chunk
	taken    chan struct{}
	pumpOnce sync.Once

	wmu sync.Mutex // serializes Write
	rdl *deadline
	wdl *deadline

	failed  atomic.Bool
	failure atomic.Pointer[error] // the first error that broke the connection here
	// finish ends a clean finish on a reusable leg (protocol 2); nil else.
	finish    func(*tunnel.Stream) error
	done      chan struct{}
	closeOnce sync.Once
}

type chunk struct {
	b   []byte
	err error
}

var _ net.Conn = (*Conn)(nil)

func (c *Client) newConn(s *tunnel.Stream, id string, side Side) *Conn {
	conn := &Conn{
		s: s, c: c, rec: c.reg.add(id, side, s),
		chunks: make(chan chunk), taken: make(chan struct{}),
		rdl: newDeadline(), wdl: newDeadline(), done: make(chan struct{}),
	}
	c.opened(conn.rec)
	return conn
}

// broke records the first error that broke the connection.
func (c *Conn) broke(err error) {
	c.failed.Store(true)
	c.failure.CompareAndSwap(nil, &err)
}

// Err is why the connection failed, once that is known: the far end's or
// the server's reason (a *RemoteError), or a lost link. nil while it is
// fine or after a clean finish.
//
// It can say more than Read did: the server may pass on a failure of the
// far end as a half-close first, so Read returns io.EOF and the reason
// arrives just after it.
func (c *Conn) Err() error {
	if err := c.s.Failure(); err != nil {
		return err
	}
	select {
	case <-c.s.Gone():
		if r := c.s.GoneReason(); r != "" {
			return &RemoteError{Reason: r}
		}
	default:
	}
	return nil
}

// ID is the server's id for this connection, the same on both ends.
func (c *Conn) ID() ConnID { return c.rec.id }

// Info is a snapshot of this connection.
func (c *Conn) Info() ConnInfo { return c.rec.info() }

// pump reads the stream on its own goroutine, one chunk at a time, so that
// Read can give up at a deadline without losing what arrives later. It
// waits for each chunk to be used before reading the next, so a reader
// that stops reading still stops the far end.
func (c *Conn) pump() {
	buf := make([]byte, tunnel.ChunkSize)
	for {
		n, err := c.s.Read(buf)
		select {
		case c.chunks <- chunk{buf[:n], err}:
		case <-c.done:
			return
		}
		if err != nil {
			return
		}
		select {
		case <-c.taken:
		case <-c.done:
			return
		}
	}
}

func (c *Conn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for len(c.pending) == 0 {
		if c.rerr != nil {
			return 0, c.rerr
		}
		if isClosed(c.done) {
			return 0, net.ErrClosed
		}
		expired, moved, _ := c.rdl.wait()
		if isClosed(expired) {
			return 0, os.ErrDeadlineExceeded
		}
		c.pumpOnce.Do(func() { go c.pump() })
		select {
		case ch := <-c.chunks:
			c.pending = ch.b
			if ch.err != nil {
				c.rerr = ch.err
				if ch.err != io.EOF {
					c.broke(ch.err)
				}
			} else if len(ch.b) == 0 {
				c.release()
			}
		case <-expired:
			return 0, os.ErrDeadlineExceeded
		case <-moved: // look again
		case <-c.done:
			return 0, net.ErrClosed
		}
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	c.rec.received.Add(int64(n))
	if len(c.pending) == 0 && c.rerr == nil {
		c.release()
	}
	return n, nil
}

// release lets the pump read the next chunk.
func (c *Conn) release() {
	select {
	case c.taken <- struct{}{}:
	case <-c.done:
	}
}

func (c *Conn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if isClosed(c.done) {
		return 0, net.ErrClosed
	}
	expired, _, set := c.wdl.wait()
	if isClosed(expired) {
		return 0, os.ErrDeadlineExceeded
	}
	var timedOut atomic.Bool
	if set {
		stop := make(chan struct{})
		defer close(stop)
		go func() {
			select {
			case <-expired:
				timedOut.Store(true)
				c.s.ExpireWrites()
			case <-stop:
			}
		}()
	}
	n, err := c.s.Write(p)
	c.rec.sent.Add(int64(n))
	if err != nil {
		if timedOut.Load() {
			err = os.ErrDeadlineExceeded
		}
		c.broke(err)
	}
	return n, err
}

// CloseWrite half-closes: the far end reads io.EOF after what was written
// so far, and may go on sending.
func (c *Conn) CloseWrite() error { return c.s.CloseWrite() }

// Fail drops the connection and tells the far end why: its Read returns a
// *RemoteError with this reason.
func (c *Conn) Fail(reason string) {
	c.broke(&DroppedError{Reason: reason})
	c.closeOnce.Do(func() {
		close(c.done)
		c.s.Fail(reason)
		c.c.closed(c.rec, *c.failure.Load())
	})
}

// Close ends the connection. If this end has not half-closed, it does so
// first. When both ends had half-closed, the close is clean; otherwise the
// far end sees the connection cut.
func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		// The half-close first, as closing a TCP socket sends its FIN. Not
		// behind a Write that is stuck on a peer that does not read: then
		// the close below cuts the connection, and bounds that Write.
		if !c.s.WroteEOF() && !c.failed.Load() && c.wmu.TryLock() {
			c.s.Leg().SetTimeouts(tunnel.LinkSilence(), tunnel.WriteTimeout)
			if c.s.CloseWrite() != nil {
				c.failed.Store(true)
			}
			c.wmu.Unlock()
		}
		close(c.done)
		var err error
		if c.finish != nil && !c.failed.Load() && c.s.Reusable() && c.s.Clean() {
			err = c.finish(c.s) // the hub's verdict, and the leg kept if it may be
		} else {
			_ = c.s.Close()
		}
		if f := c.failure.Load(); f != nil {
			err = *f
		} else if err == nil {
			err = c.Err()
		}
		c.c.closed(c.rec, err)
	})
	return nil
}

func (c *Conn) LocalAddr() net.Addr  { return c.s.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr { return c.s.RemoteAddr() }

func (c *Conn) SetDeadline(t time.Time) error {
	c.rdl.set(t)
	c.wdl.set(t)
	return nil
}
func (c *Conn) SetReadDeadline(t time.Time) error  { c.rdl.set(t); return nil }
func (c *Conn) SetWriteDeadline(t time.Time) error { c.wdl.set(t); return nil }

// Dial opens one connection through the tunnel.
//
// The server answers before the serving side has: if the serving side
// cannot be reached, or cannot reach its target, the first Read returns a
// *RemoteError saying so.
func (c *Client) Dial(ctx context.Context) (*Conn, error) {
	stream, id, err := c.connectStream(ctx)
	if err != nil {
		return nil, explain(err)
	}
	return c.newConn(stream, id, SideConnect), nil
}

// listenBacklog is how many connections may wait for Accept. More are
// refused, and their connecting side is told why.
const listenBacklog = 128

// Listener serves the tunnel and hands each connection to Accept. It keeps
// itself registered with the server: a lost server is registered with
// again, with a growing pause, until Close. Connections that were open end
// when the server is lost.
type Listener struct {
	c      *Client
	conns  chan *Conn
	slots  chan struct{}
	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once
	up     atomic.Bool
	// mu orders a connection's arrival against Close: once closed, nothing
	// is put in conns, which Close has emptied.
	mu     sync.Mutex
	closed bool
}

var _ net.Listener = (*Listener)(nil)

// Listen registers the tunnel with the server and returns once it is
// registered. ctx bounds only the wait for that first registration. A
// refusal that waiting cannot cure (a wrong serve token, a word that
// belongs to another tenant, a server too old for what was asked) is
// returned as an error; anything else is retried until ctx ends.
func (c *Client) Listen(ctx context.Context) (*Listener, error) {
	if strings.TrimSpace(c.Name) == "" {
		return nil, errors.New("give the tunnel a name (Client.Name): the server shows it in its console and refuses a tunnel without one")
	}
	lctx, cancel := context.WithCancel(context.Background())
	l := &Listener{
		c: c, conns: make(chan *Conn, listenBacklog), slots: make(chan struct{}, listenBacklog),
		cancel: cancel, done: make(chan struct{}),
	}
	registered := make(chan struct{}, 1)
	up := func(on bool) {
		l.up.Store(on)
		if on {
			select {
			case registered <- struct{}{}:
			default:
			}
		}
	}
	target := c.Target
	if target == "" {
		target = "listener"
	}
	served := make(chan error, 1)
	go func() {
		served <- c.serve(lctx, target, func(reg *registration, id string, leg *tunnel.Stream) { l.open(lctx, reg, id, leg) }, up)
	}()
	select {
	case <-registered:
		return l, nil
	case err := <-served:
		l.Close()
		if err == nil {
			err = ctx.Err()
		}
		return nil, err
	case <-ctx.Done():
		l.Close()
		return nil, ctx.Err()
	}
}

// open answers the server's request for connection id. leg is its stream
// when it arrived on a reused leg (protocol 2); nil when this side brings a
// leg to accept.
func (l *Listener) open(ctx context.Context, reg *registration, id string, leg *tunnel.Stream) {
	c := l.c
	select {
	case l.slots <- struct{}{}:
	default:
		const reason = "the serving side is not accepting connections fast enough"
		c.logf("connection %s refused: %d connections are waiting to be accepted", short(id), listenBacklog)
		c.refused(id, reason)
		if leg != nil {
			leg.Fail(reason) // after "bound", a refusal is an err: (§12.7)
			return
		}
		_ = c.refuseOpen(ctx, reg, id, reason)
		return
	}
	if leg != nil && reg.abandoned(id) {
		<-l.slots
		leg.Fail(reasonLegLost) // asked for again: the new attempt carries it
		return
	}
	stream := leg
	if stream == nil {
		var err error
		if stream, err = c.accept(ctx, reg, id, true); err != nil {
			<-l.slots
			c.logf("connection %s failed: cannot bring it to the server: %v", short(id), explain(err))
			return
		}
	}
	conn := c.newConn(stream, id, SideServe)
	conn.finish = reg.finisher()
	if leg != nil && reg.abandoned(id) {
		c.abandon(id) // asked for again just as it opened
	}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		<-l.slots
		conn.Fail("the serving side stopped listening")
		return
	}
	l.conns <- conn // never blocks: a slot was taken for it
	l.mu.Unlock()
}

// Accept waits for the next connection; it is a *Conn.
func (l *Listener) Accept() (net.Conn, error) { return l.AcceptConn() }

// AcceptConn is Accept with the connection's own type.
func (l *Listener) AcceptConn() (*Conn, error) {
	select {
	case conn := <-l.conns:
		<-l.slots
		return conn, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

// Up reports whether the tunnel is registered with the server right now.
func (l *Listener) Up() bool { return l.up.Load() }

// Close stops serving: the registration ends, and connections not yet
// accepted are dropped. Accepted connections stay open until the server
// link they use ends or they are closed.
func (l *Listener) Close() error {
	l.once.Do(func() {
		l.cancel()
		l.mu.Lock()
		l.closed = true
		l.mu.Unlock()
		close(l.done)
		for {
			select {
			case conn := <-l.conns:
				conn.Fail("the serving side stopped listening")
			default:
				return
			}
		}
	})
	return nil
}

// Addr names the tunnel: the server and the start of the word.
func (l *Listener) Addr() net.Addr { return tunnelAddr(l.c.base + " " + l.c.wordLabel()) }

type tunnelAddr string

func (a tunnelAddr) Network() string { return "pfrelay" }
func (a tunnelAddr) String() string  { return string(a) }

// ---------- deadlines ----------

// deadline is a channel that is closed when a time passes; the same idea as
// net.Pipe's. moved is closed whenever the deadline is set again, so that
// whoever waits looks at the new one.
type deadline struct {
	mu    sync.Mutex
	timer *time.Timer
	ch    chan struct{}
	moved chan struct{}
	on    bool
}

func newDeadline() *deadline {
	return &deadline{ch: make(chan struct{}), moved: make(chan struct{})}
}

func (d *deadline) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
	close(d.moved)
	d.moved = make(chan struct{})
	d.on = !t.IsZero()
	ch := make(chan struct{})
	d.ch = ch
	switch dur := time.Until(t); {
	case t.IsZero():
	case dur > 0:
		d.timer = time.AfterFunc(dur, func() { close(ch) })
	default:
		close(ch)
	}
}

// wait returns the channel that closes at the deadline, the one that
// closes when the deadline is moved, and whether a deadline is set.
func (d *deadline) wait() (expired, moved <-chan struct{}, on bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.ch, d.moved, d.on
}

func isClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}
