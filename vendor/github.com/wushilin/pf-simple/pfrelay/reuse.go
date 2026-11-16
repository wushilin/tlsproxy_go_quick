package pfrelay

import (
	"context"
	"github.com/wushilin/pf-simple/internal/relayhook"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wushilin/pf-simple/internal/tunnel"
)

// Reusing accept legs: tunnel protocol 2, docs/PROTOCOL.md §12.
//
// A registration with a protocol 2 hub brings a session secret. Each accept
// sends it back, and the hub may offer reuse. When a connection on an
// offered leg finishes cleanly, the hub says "idle"; this side answers "idle"
// to keep the leg, which then waits for the hub's "bind <id>": the next
// connection, answered at once with "bound <id>".

// verdictWait is how long a client waits for the hub's verdict after both
// half-closes (§12.5); a variable so tests can shorten it.
var verdictWait = 3 * time.Second

const (
	defaultMaxIdleLegs = 16
	// reasonLegLost is how an attempt ends whose leg died before the hub
	// heard "bound": the hub asks again with an open message (§12.7).
	reasonLegLost = "the leg was lost before the server took the connection"
)

// registration is one control channel's life: its session secret, and the
// idle legs that belong to it.
type registration struct {
	c       *Client
	session string // "" when the hub does not reuse legs
	ctx     context.Context
	cancel  context.CancelFunc
	// open carries a connection the hub asked for: with an open message
	// (leg nil: bring one to accept) or on an idle leg (leg is its stream).
	open func(reg *registration, id string, leg *tunnel.Stream)

	mu   sync.Mutex
	idle int
	// bound and opened remember, for a while, the ids this registration
	// answered "bound" to and the ids that came with an open message: an
	// id that came both ways is the case of §12.7, a bound lost with its
	// leg and asked for again.
	bound  map[string]*attempt
	opened map[string]time.Time

	// alt holds the opens of a registration over another transport
	// (alt.go), until they are accepted or refused.
	alt      relayhook.Registration
	altOpens map[string]relayhook.Open
}

// attempt is a connection taken on a reused leg, until the hub has seen
// its "bound"; abandoned when the hub asks for it again.
type attempt struct {
	at        time.Time
	abandoned atomic.Bool
}

// recall is how long ids are remembered: well past the hub's 10 seconds
// to answer a connection.
const recall = 30 * time.Second

func (r *registration) prune() {
	for id, a := range r.bound {
		if time.Since(a.at) > recall {
			delete(r.bound, id)
		}
	}
	for id, at := range r.opened {
		if time.Since(at) > recall {
			delete(r.opened, id)
		}
	}
}

// takeBind records a bind of id. It refuses one for an id that already came
// with an open message: a bind that arrives after the hub fell back.
func (r *registration) takeBind(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prune()
	if _, ok := r.opened[id]; ok {
		return false
	}
	if r.bound == nil {
		r.bound = map[string]*attempt{}
	}
	r.bound[id] = &attempt{at: time.Now()}
	return true
}

// tookOpen records an open message for id, and reports whether it is for an
// id bound here: a new attempt, the old one being abandoned.
func (r *registration) tookOpen(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prune()
	if r.opened == nil {
		r.opened = map[string]time.Time{}
	}
	r.opened[id] = time.Now()
	if a := r.bound[id]; a != nil {
		a.abandoned.Store(true)
		return true
	}
	return false
}

// abandoned reports whether the attempt at id on a reused leg was given up
// because the hub asked for it again.
func (r *registration) abandoned(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	a := r.bound[id]
	return a != nil && a.abandoned.Load()
}

func (c *Client) newRegistration(ctx context.Context, h map[string][]string, open func(*registration, string, *tunnel.Stream)) *registration {
	reg := &registration{c: c, open: open}
	reg.ctx, reg.cancel = context.WithCancel(ctx)
	if tunnel.ServerProto(h) >= 2 && !c.NoReuse && c.maxProto() >= 2 {
		if v := firstHeader(h, tunnel.HeaderSession); len(v) == 32 {
			reg.session = v
		}
	}
	return reg
}

func firstHeader(h map[string][]string, name string) string {
	for k, v := range h {
		if strings.EqualFold(k, name) && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

// keep reserves room for one more idle leg.
func (r *registration) keep() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ctx.Err() != nil || r.idle >= r.c.maxIdleLegs() {
		return false
	}
	r.idle++
	return true
}

func (r *registration) release() {
	r.mu.Lock()
	r.idle--
	r.mu.Unlock()
}

func (c *Client) maxIdleLegs() int {
	if c.MaxIdleLegs > 0 {
		return c.MaxIdleLegs
	}
	return defaultMaxIdleLegs
}

// offered reports whether the hub's answer to an accept offered reuse: a
// protocol 2 answer with a keep-alive of 1 to 3600 seconds (§12.3).
func offered(h map[string][]string) bool {
	if tunnel.ServerProto(h) < 2 {
		return false
	}
	v := firstHeader(h, tunnel.HeaderKeepAlive)
	if v == "" || strings.TrimLeft(v, "0123456789") != "" {
		return false
	}
	n, err := strconv.Atoi(v)
	return err == nil && n >= 1 && n <= 3600
}

// accept brings this side's leg of connection id to the hub. reusable asks
// for reuse, which needs the registration's session.
func (c *Client) accept(ctx context.Context, reg *registration, id string, reusable bool) (*tunnel.Stream, error) {
	if reg != nil && reg.alt != nil {
		o := reg.takeAlt(id)
		if o == nil {
			return nil, errNoOpen
		}
		return o.Accept(ctx)
	}
	h := c.header(id)
	if reusable && reg != nil && reg.session != "" {
		h.Set(tunnel.HeaderSession, reg.session)
	}
	ws, err := c.dial(ctx, "accept", h)
	if err != nil {
		return nil, err
	}
	s := tunnel.NewStream(ws)
	if reusable && reg != nil && reg.session != "" && offered(ws.Header) {
		s.SetReusable(false)
	}
	return s, nil
}

// finisher ends a cleanly finished stream on a reusable leg: it waits for
// the hub's verdict, keeps the leg if it may, and returns the error the
// verdict reports, if any (§12.5).
func (reg *registration) finisher() func(s *tunnel.Stream) error {
	return func(s *tunnel.Stream) error {
		idle, reason := s.AwaitIdle(verdictWait)
		switch {
		case idle:
			// Bounded like any control write: a hub that stopped reading
			// must not hold this goroutine.
			s.Leg().SetTimeouts(tunnel.LinkSilence(), tunnel.WriteTimeout)
			if reg.keep() {
				if s.SendIdle() == nil {
					go reg.idleLeg(s.Detach())
					return nil
				}
				reg.release()
			}
			_ = s.Close() // the hub's "idle" is answered with a close: not kept
			return nil
		case reason != "":
			_ = s.Close()
			return &RemoteError{Reason: reason}
		}
		_ = s.Close() // the hub closed, or said nothing in time: protocol 1 rules
		return nil
	}
}

// idleLeg waits on an idle leg for the hub's "bind", until the leg or the
// registration ends.
func (reg *registration) idleLeg(conn *tunnel.Conn) {
	conn.SetTimeouts(tunnel.LinkSilence(), tunnel.WriteTimeout)
	stopPing := conn.KeepAlive(tunnel.PingEvery())
	stopWatch := context.AfterFunc(reg.ctx, func() { _ = conn.Close() })
	bound := false
	defer func() {
		if !bound {
			stopPing()
			stopWatch()
			_ = conn.Close()
			reg.release() // its place goes back, however it ended
		}
	}()
	var id string
	for {
		op, payload, err := conn.Next(tunnel.MaxSmallFrame)
		if err != nil || op != tunnel.OpText {
			return // closed, dead, or data: a violation
		}
		msg := string(payload)
		if v, ok := strings.CutPrefix(msg, tunnel.MsgBind+" "); ok && v != "" {
			id = v
			break
		}
		if knownLegFrame(msg) {
			return // a known frame in the wrong state: a violation (§12.4)
		}
		// Unknown text is ignored, as on any stream (§8.1).
	}
	if !reg.takeBind(id) {
		return // already asked for with an open message: the hub gave this leg up
	}
	stopPing()
	if !stopWatch() || conn.WriteFrame(tunnel.OpText, []byte(tunnel.MsgBound+" "+id)) != nil {
		return
	}
	bound = true
	reg.release()
	s := tunnel.NewStream(conn)
	s.SetReusable(false)
	reg.open(reg, id, s)
}

// abandon ends the serving side's attempt at connection id, which was bound
// on a reused leg that died before the hub heard "bound" (§12.7). The old
// attempt is reported as failed, and the new one goes on under the same id.
// Only the serving side's connections are touched: the same client may
// also be connecting through the tunnel, and its connection carries the
// same id.
func (c *Client) abandon(id string) {
	c.reg.mu.Lock()
	var rec *connRecord
	for r := range c.reg.live {
		if r.id.id == id && r.side == SideServe {
			rec = r
			break
		}
	}
	c.reg.mu.Unlock()
	if rec != nil {
		reason := reasonLegLost
		rec.dropped.Store(&reason)
		rec.stream.Fail(reason)
	}
}

// knownLegFrame reports whether msg is one of the text frames of streams and
// reused legs (§8.1, §12): such a frame where it does not belong is a
// violation, while any other text is ignored.
func knownLegFrame(msg string) bool {
	switch {
	case msg == "eof", msg == tunnel.MsgIdle, msg == tunnel.MsgBind, msg == tunnel.MsgBound,
		strings.HasPrefix(msg, "err:"), strings.HasPrefix(msg, tunnel.MsgBind+" "), strings.HasPrefix(msg, tunnel.MsgBound+" "):
		return true
	}
	return false
}
