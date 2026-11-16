package pfrelay

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/wushilin/pf-simple/internal/relayhook"
	"github.com/wushilin/pf-simple/internal/tunnel"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// Client talks to one relay hub about one tunnel (one word). It can serve
// the tunnel (Listen, Serve, ServeOne) or connect through it (Dial,
// Connect, ConnectOne, Check, Watch). Set its fields before first use; a
// Client is safe for concurrent use after that.
type Client struct {
	base string // https://host[:port]
	word string
	tls  *tls.Config
	http *http.Client
	// Logf receives what the client has to say about registrations,
	// retries and connections. Nil (the default) discards it; pf-client
	// sets log.Printf.
	Logf func(format string, args ...any)
	// ServeToken is a serve token of the server, and Name what the tunnel is
	// called in the server's console. Only Serve uses them; without a serve
	// token the registration is anonymous, which the server must allow.
	ServeToken string
	Name       string
	// Agent is what this program calls itself in the server's log and
	// console, such as "pf-client 0.15.0". Nothing is decided from it.
	// Empty means DefaultAgent.
	Agent string

	// Target is what Listen tells the server's console the tunnel leads
	// to. Empty means "listener". Serve sends its own target instead.
	Target string
	// ClientToken is a second secret the serving side may ask of whoever
	// connects. Serve registers it, and the connecting side must send it.
	ClientToken string
	// Events are called as connections open and close, and as the
	// tunnel comes and goes. None is set by default.
	Events Events

	// NoReuse turns off reusing the serving side's legs (protocol 2): each
	// connection then gets a new leg, as with a protocol 1 server.
	NoReuse bool
	// MaxIdleLegs is how many idle legs the serving side keeps for reuse
	// at most; 0 means 16.
	MaxIdleLegs int
	// MaxProto limits the tunnel protocol this client offers, to behave
	// like an older one: 0 means the newest it speaks, 1 like pf-client
	// 0.14, and -1 like one from before 0.14 that announces none. For
	// testing.
	MaxProto int

	reg registry // connections and totals

	// alt is a transport other than WebSocket, attached by pfrelayquic
	// (alt.go); nil for WebSocket.
	alt relayhook.Transport
}

// Close releases what the client keeps between requests: its idle HTTP
// connections to the server. Listeners, connections and forwarders have
// their own Close, or end with their context.
func (c *Client) Close() error {
	c.http.CloseIdleConnections()
	if c.alt != nil {
		return c.alt.Close()
	}
	return nil
}

// NewClient checks the relay URL and the word. tlsConfig may be nil.
func NewClient(base, word string, tlsConfig *tls.Config) (*Client, error) {
	base, err := normalizeBase(base)
	if err != nil {
		return nil, err
	}
	word, err = tunnel.NormalizeWord(word)
	if err != nil {
		return nil, err
	}
	// Check, Probe and the refusals at accept reuse a connection; one left
	// idle closes after a while. Watch, which checks every 30 seconds,
	// keeps reusing it.
	transport := &http.Transport{TLSClientConfig: tlsConfig, IdleConnTimeout: 90 * time.Second, MaxIdleConnsPerHost: 1}
	return &Client{
		base: base, word: word, tls: tlsConfig,
		http: &http.Client{Timeout: tunnel.HandshakeLimit, Transport: transport},
	}, nil
}

// normalizeBase accepts the relay's address with or without the console's
// /pf path, and insists on https.
func normalizeBase(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("invalid server URL %q: use https://host[:port]/", raw)
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("invalid server URL %q: only https:// is supported", raw)
	}
	if p := strings.TrimSuffix(u.Path, "/"); p != "" && p != "/pf" {
		return "", fmt.Errorf("invalid server URL %q: give the server's address only, like https://%s/", raw, u.Host)
	}
	return "https://" + u.Host, nil
}

// needs lists what a request to endpoint depends on beyond protocol 0.
func (c *Client) needs(endpoint string) []tunnel.Feature {
	var out []tunnel.Feature
	switch endpoint {
	case "serve":
		if c.ClientToken != "" {
			out = append(out, tunnel.FeatureClientToken)
		}
		if c.ServeToken == "" {
			out = append(out, tunnel.FeatureAnonymousServe)
		}
	case "connect", "check":
		if c.ClientToken != "" {
			out = append(out, tunnel.FeatureClientToken)
		}
	}
	return out
}

// offer adds the protocol range for a request to endpoint to its headers:
// from the newest protocol it depends on, so a server that knows about
// protocols refuses one it cannot honor.
func (c *Client) offer(endpoint string, h http.Header) {
	if c.MaxProto < 0 {
		return // like a client from before protocols were announced
	}
	max := c.maxProto()
	min := tunnel.ProtoMin
	for _, f := range c.needs(endpoint) {
		if p := tunnel.FeatureProto(f); p > min {
			min = p
		}
	}
	min = minInt(min, max)
	h.Set(tunnel.HeaderProto, tunnel.ProtoRange(min, max))
	agent := c.Agent
	if agent == "" {
		agent = DefaultAgent
	}
	h.Set(tunnel.HeaderVersion, agent)
}

// maxProto is the newest protocol this client offers.
func (c *Client) maxProto() int {
	switch {
	case c.MaxProto < 0:
		return 0
	case c.MaxProto == 0 || c.MaxProto > tunnel.ProtoMax:
		return tunnel.ProtoMax
	}
	return c.MaxProto
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// answered checks a response to endpoint: a server from before protocols
// were negotiated ignores what it does not know, so it is for this side to
// refuse when the run depends on something that server would not do.
func (c *Client) answered(endpoint string, h http.Header) error {
	proto := tunnel.ServerProto(h)
	for _, f := range c.needs(endpoint) {
		if proto < tunnel.FeatureProto(f) {
			return &tunnel.ProtoError{Server: proto, Need: f}
		}
	}
	return nil
}

func (c *Client) header(conn string) http.Header {
	h := http.Header{}
	h.Set(tunnel.HeaderWord, c.word)
	if conn != "" {
		h.Set(tunnel.HeaderConn, conn)
	}
	return h
}

// connectHeader is what the connecting side sends: the word, and the client
// token if the serving side asks for one.
func (c *Client) connectHeader() http.Header {
	h := c.header("")
	if c.ClientToken != "" {
		h.Set(tunnel.HeaderClientToken, c.ClientToken)
	}
	return h
}

func (c *Client) dial(ctx context.Context, endpoint string, h http.Header) (*tunnel.Conn, error) {
	c.offer(endpoint, h)
	ws, err := tunnel.Dial(ctx, c.base+tunnel.Path+"/"+endpoint, h, c.tls)
	var se *tunnel.StatusError
	switch {
	case err == nil:
		if perr := c.answered(endpoint, ws.Header); perr != nil {
			_ = ws.Close()
			return nil, perr
		}
	case errors.As(err, &se) && se.Code != http.StatusNotFound:
		// Refused, perhaps for the very thing the server is too old for.
		if perr := c.answered(endpoint, se.Header); perr != nil {
			return nil, perr
		}
	}
	return ws, err
}

// get makes a plain request; anything but 2xx is a *StatusError.
func (c *Client) get(ctx context.Context, endpoint string, h http.Header) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+tunnel.Path+"/"+endpoint, nil)
	if err != nil {
		return err
	}
	c.offer(endpoint, h)
	req.Header = h
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound { // 404: no hub there to be old
		if perr := c.answered(endpoint, resp.Header); perr != nil {
			return perr
		}
	}
	if resp.StatusCode/100 != 2 {
		return &tunnel.StatusError{Code: resp.StatusCode, Msg: tunnel.ErrorText(resp.Body), Header: resp.Header}
	}
	return nil
}

// explain turns the relay's refusals into something to act on.
func explain(err error) error {
	var se *tunnel.StatusError
	if !errors.As(err, &se) {
		return err
	}
	switch se.Code {
	case http.StatusForbidden:
		return ErrAccessDenied
	case http.StatusConflict:
		if se.Msg != "" {
			return errors.New(se.Msg)
		}
	case http.StatusUpgradeRequired:
		if se.Msg != "" { // the protocols do not meet; the server says how
			return errors.New(se.Msg)
		}
	case http.StatusNotFound:
		if se.Msg == "" {
			return errors.New("this server does not accept tunnels (it needs --tunnel or a [tunnel] table)")
		}
	}
	return err
}

// ErrNoProbe is a server that does not answer a version probe.
var ErrNoProbe = errors.New("this server does not answer a version probe: it is older than pf-simple 0.14.0, or its relay hub is off")

// Probe asks the server for its version and the tunnel protocols it
// speaks. It needs a valid serve token: without one the server says
// nothing about itself.
func (c *Client) Probe(ctx context.Context) (*ServerInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+tunnel.Path+"/version", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(tunnel.HeaderServe, c.ServeToken)
	c.offer("version", req.Header)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, ErrNoProbe
	case resp.StatusCode/100 != 2:
		return nil, explain(&tunnel.StatusError{Code: resp.StatusCode, Msg: tunnel.ErrorText(resp.Body), Header: resp.Header})
	}
	var info ServerInfo
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&info); err != nil || info.Version == "" {
		return nil, errors.New("the server's answer to the version probe is not understood")
	}
	return &info, nil
}

// Check asks the relay whether someone is serving this word.
func (c *Client) Check(ctx context.Context) error {
	if c.alt != nil {
		return explain(c.alt.Check(ctx, c.params()))
	}
	return explain(c.get(ctx, "check", c.connectHeader()))
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// retryTiming is how serving and watching retry.
type retryTiming struct {
	// A failed attempt is retried after min, doubling up to max.
	min, max time.Duration
	// settled is how long a control channel must have lasted for the next
	// failure to start again from min. A link that comes up and drops
	// straight away keeps backing off instead of retrying every second.
	settled time.Duration
	// A tunnel that is up is checked again this often by Watch.
	recheck time.Duration
}

// retry holds the timing in use: atomic, so tests can shorten it while
// goroutines of earlier tests are still winding down.
var retry atomic.Pointer[retryTiming]

func init() {
	retry.Store(&retryTiming{min: time.Second, max: 30 * time.Second, settled: time.Minute, recheck: 30 * time.Second})
}

func timing() retryTiming { return *retry.Load() }

// Serve offers target to whoever connects with the same word, for ever: it
// returns only when ctx ends, or when the relay refuses the very first
// registration for a reason that waiting cannot cure (a wrong serve token,
// a word that belongs to someone else), which is a mistake to report rather
// than retry. Everything else, including a relay that is down from the
// start, is retried with a growing pause. The connections that were open
// end with a lost relay, and the connecting side opens new ones.
func (c *Client) Serve(ctx context.Context, target string) error {
	return c.serve(ctx, target, func(reg *registration, id string, leg *tunnel.Stream) {
		c.serveConn(ctx, reg, id, target, leg)
	}, nil)
}

// ServeOne offers local, such as stdin/stdout, as the tunnel's only
// connection: it registers and waits like Serve, carries the first
// connection that arrives, and returns when that one ends, with nil if it
// ended cleanly. local can be read once, so nothing is retried after the
// connection has started, and others arriving meanwhile are refused.
func (c *Client) ServeOne(ctx context.Context, local HalfCloser) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var taken atomic.Bool
	done := make(chan error, 1)
	open := func(reg *registration, id string, _ *tunnel.Stream) {
		if !taken.CompareAndSwap(false, true) {
			c.logf("connection %s refused: this side carries one connection, and has one", short(id))
			const reason = "the serving side carries a single connection and already has one"
			c.refused(id, reason)
			_ = c.refuseOpen(ctx, reg, id, reason)
			return
		}
		stream, err := c.accept(ctx, reg, id, false)
		if err != nil {
			// Nothing was read from local yet, so the next one may have it.
			c.logf("connection %s failed: cannot bring it to the server: %v", short(id), explain(err))
			taken.Store(false)
			return
		}
		c.logf("connection %s open: tunnel -> stdin/stdout", short(id))
		started := time.Now()
		stop := context.AfterFunc(ctx, func() { _ = stream.Close() })
		defer stop()
		rec := c.reg.add(id, SideServe, stream)
		c.opened(rec)
		e := bridge(ctx, stream, local, partyServeStdio, rec, nil)
		c.closed(rec, e.err)
		c.logEnd(short(id), started, e, true)
		if e.err != nil {
			done <- &endError{e.reason, e.err}
			return
		}
		done <- nil
	}
	failed := make(chan error, 1)
	go func() { failed <- c.serve(ctx, tunnel.StdioTarget, open, nil) }()
	select {
	case err := <-done:
		return err
	case err := <-failed: // refused outright, or ctx ended while waiting
		_ = local.Close()
		return err
	}
}

// serve keeps a control channel registered and calls open, on its own
// goroutine, for each connection the relay asks for. up, if not nil, is
// called each time a registration succeeds (true) or its control channel is
// lost (false).
func (c *Client) serve(ctx context.Context, target string, open func(reg *registration, id string, leg *tunnel.Stream), up func(bool)) error {
	if c.alt != nil {
		return c.serveAlt(ctx, target, open, up)
	}
	h := c.header("")
	h.Set(tunnel.HeaderTarget, target)
	if c.ServeToken != "" {
		h.Set(tunnel.HeaderServe, c.ServeToken)
	}
	if c.ClientToken != "" {
		sum := sha256.Sum256([]byte(c.ClientToken))
		h.Set(tunnel.HeaderClientHash, hex.EncodeToString(sum[:]))
	}
	h.Set(tunnel.HeaderName, url.QueryEscape(c.Name))
	rt := timing()
	backoff, served := rt.min, false
	for attempt := 1; ; attempt++ {
		ws, err := c.dial(ctx, "serve", h)
		if ctx.Err() != nil {
			if ws != nil {
				_ = ws.Close()
			}
			return nil
		}
		if err != nil {
			var se *tunnel.StatusError
			var pe *tunnel.ProtoError
			if errors.As(err, &pe) { // the server cannot do what was asked: waiting will not change it
				return err
			}
			if !served && errors.As(err, &se) && se.Final() {
				return explain(err)
			}
			c.logf("cannot register with %s (%v); attempt %d, trying again in %s", c.base, explain(err), attempt, backoff)
		} else {
			if served {
				c.logf("registered again with %s after %d attempt(s): serving %q, tunnel %s -> %s", c.base, attempt, c.Name, c.wordLabel(), target)
			} else {
				c.logf("registered with %s: serving %q, tunnel %s -> %s", c.base, c.Name, c.wordLabel(), target)
			}
			served, attempt = true, 0
			started := time.Now()
			if up != nil {
				up(true)
			}
			c.serving(true)
			reg := c.newRegistration(ctx, ws.Header, open)
			err = c.control(ctx, ws, func(id string) {
				if reg.tookOpen(id) {
					c.abandon(id) // a bound id asked for again: a new attempt (§12.7)
				}
				open(reg, id, nil)
			})
			reg.cancel() // its idle legs go with it
			if up != nil {
				up(false)
			}
			c.serving(false)
			if ctx.Err() != nil {
				return nil
			}
			if time.Since(started) >= rt.settled {
				backoff = rt.min
			}
			c.logf("lost the server after %s (%v); its connections are closed; registering again in %s", fmtAge(time.Since(started)), err, backoff)
		}
		if !sleep(ctx, backoff) {
			return nil
		}
		backoff = min(backoff*2, rt.max)
	}
}

// Watch checks, until ctx ends, whether the tunnel can be reached, and
// says so in the log. It is for the connecting side, which keeps listening
// either way: a tunnel that is not there yet, or goes away, costs nothing
// but refused connections until it is back. Events.OnTunnel hears the
// first result and then every change: up, or down with why. A tunnel that
// is up is checked every 30 seconds; one that is down sooner, from 1
// second doubling to 30.
func (c *Client) Watch(ctx context.Context) {
	rt := timing()
	backoff, up := rt.min, false
	for first := true; ; first = false {
		err := c.Check(ctx)
		if ctx.Err() != nil {
			return
		}
		if c.Events.OnTunnel != nil && (first || up != (err == nil)) {
			c.Events.OnTunnel(err == nil, err)
		}
		wait := rt.recheck
		switch {
		case err == nil:
			if !up {
				c.logf("the tunnel is up")
			}
			up, backoff = true, rt.min
		case errors.As(err, new(*tunnel.ProtoError)):
			if up || first {
				c.logf("%v; connections are refused meanwhile, and this keeps checking", err)
			}
			up, wait = false, backoff
			backoff = min(backoff*2, rt.max)
		default:
			if up || first {
				c.logf("the tunnel is not available (%v): the word is wrong, nobody is serving it yet, or it asks for a client token that was not given; connections are refused until it is, and this keeps checking", err)
			}
			up, wait = false, backoff
			backoff = min(backoff*2, rt.max)
		}
		if !sleep(ctx, wait) {
			return
		}
	}
}

// control runs one control channel until it fails.
func (c *Client) control(ctx context.Context, ws *tunnel.Conn, open func(id string)) error {
	defer ws.Close()
	ws.SetTimeouts(tunnel.ControlSilence, tunnel.WriteTimeout)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		t := time.NewTicker(tunnel.ControlPing)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				_ = ws.WriteFrame(tunnel.OpClose, nil)
				_ = ws.Close()
				return
			case <-stop:
				return
			case <-t.C:
				if ws.WriteFrame(tunnel.OpPing, nil) != nil {
					_ = ws.Close()
					return
				}
			}
		}
	}()
	for {
		op, payload, err := ws.Next(tunnel.MaxSmallFrame)
		if err != nil {
			return err
		}
		var msg tunnel.ControlMessage
		if op == tunnel.OpText && json.Unmarshal(payload, &msg) == nil && msg.Open != "" {
			go open(msg.Open)
		}
	}
}

// serveConn carries one connection the relay asked for.
// leg is the connection's stream when it arrived on a reused leg (the hub
// already has "bound"); nil when it came with an open message, and this
// side brings a leg to accept.
func (c *Client) serveConn(ctx context.Context, reg *registration, id, target string, leg *tunnel.Stream) {
	const reason = "the serving side could not reach its target"
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", target)
	if err != nil {
		c.logf("connection %s failed: cannot reach the target %s: %v", short(id), target, err)
		c.refused(id, reason)
		if leg != nil {
			leg.Fail(reason) // after "bound", a refusal is an err: (§12.7)
			return
		}
		if err := c.refuseOpen(ctx, reg, id, reason); err != nil {
			c.logf("connection %s: could not tell the server: %v", short(id), explain(err))
		}
		return
	}
	if leg != nil && reg.abandoned(id) {
		// Asked for again while this side was dialing: the new attempt
		// carries it, and this one never opened.
		_ = conn.Close()
		leg.Fail(reasonLegLost)
		return
	}
	stream := leg
	if stream == nil {
		if stream, err = c.accept(ctx, reg, id, true); err != nil {
			c.logf("connection %s failed: cannot bring it to the server: %v", short(id), explain(err))
			_ = conn.Close()
			return
		}
	}
	c.logf("connection %s open: tunnel -> %s", short(id), target)
	stop := context.AfterFunc(ctx, func() { _ = stream.Close() })
	defer stop()
	rec := c.reg.add(id, SideServe, stream)
	c.opened(rec)
	if leg != nil && reg.abandoned(id) {
		c.abandon(id) // asked for again just as it opened
	}
	e := bridge(ctx, stream, conn.(*net.TCPConn), partyServe, rec, reg.finisher())
	c.closed(rec, e.err)
	c.logEnd(short(id), rec.opened, e, true)
}

func short(id string) string { return id[:min(len(id), 8)] }

// wordLabel is the word as logs show it: enough to tell tunnels apart, not
// enough to connect.
func (c *Client) wordLabel() string { return c.word[:4] + "-…" }

func fmtBytes(n int64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	v, i := float64(n), 0
	for v >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d B", n)
	}
	return fmt.Sprintf("%.1f %s", v, units[i])
}

func fmtAge(d time.Duration) string {
	if d < time.Minute {
		return d.Round(100 * time.Millisecond).String()
	}
	return d.Round(time.Second).String()
}

// logEnd reports a finished connection: how long it lasted, what it carried
// each way, and why it ended. The directions are named from the two ends of
// the whole tunnel, so both clients' logs read the same.
func (c *Client) logf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
	}
}

func (c *Client) logEnd(id string, started time.Time, e ended, serving bool) {
	toTarget, toApp := e.toFar, e.toLocal
	if serving { // here "local" is the target
		toTarget, toApp = e.toLocal, e.toFar
	}
	c.logf("connection %s closed after %s: app->target %s, target->app %s; %s",
		id, fmtAge(time.Since(started)), fmtBytes(toTarget), fmtBytes(toApp), e.reason)
}

// HalfCloser is the application's end of a forwarded connection: a TCP
// connection, stdin/stdout (Stdio), or anything else that can close its
// sending half on its own.
type HalfCloser interface {
	io.ReadWriteCloser
	CloseWrite() error
}

// copyEnd is how one direction of a connection stopped. Both nil: the
// source finished cleanly.
type copyEnd struct{ readErr, writeErr error }

func (e copyEnd) clean() bool { return e.readErr == nil && e.writeErr == nil }

// copyChunks is io.Copy with a buffer the size of the largest frame, a
// running byte count, and a result that says which side failed. Each read
// becomes one WebSocket frame, so a busy stream, whose reads come back
// full, travels in few large frames; nothing waits to be merged.
func copyChunks(dst io.Writer, src io.Reader, count *atomic.Int64) copyEnd {
	buf := make([]byte, tunnel.ChunkSize)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return copyEnd{writeErr: werr}
			}
			count.Add(int64(n))
		}
		if err == io.EOF {
			return copyEnd{}
		}
		if err != nil {
			return copyEnd{readErr: err}
		}
	}
}

// ended is the outcome of one carried connection.
type ended struct {
	toFar, toLocal int64  // bytes sent into the tunnel, and delivered from it
	reason         string // why it ended, for the log
	err            error  // nil after a clean finish
}

// party names the ends of the chain as one pf-client sees them, so a reason
// can say which hop broke:
//
//	application -- pf-client connect == server == pf-client serve -- target
type party struct {
	self  string // this program
	local string // what its TCP connection goes to
	far   string // what is at the other end of the tunnel
}

var (
	partyConnect = party{self: "pf-client connect", local: "the application", far: "the target"}
	partyServe   = party{self: "pf-client serve", local: "the target", far: "the application"}
	// With stdin/stdout on the serving side, that is the target.
	partyServeStdio = party{self: "pf-client serve", local: "stdin/stdout", far: "the application"}
)

// linkReason words a failure of the stream to the server. A *RemoteError is
// the cause as the server or the other pf-client reported it, and is
// already specific.
func (p party) linkReason(err error) string {
	var remote *tunnel.RemoteError
	var netErr net.Error
	switch {
	case errors.As(err, &remote):
		return remote.Reason
	case errors.Is(err, tunnel.ErrPeerClosed):
		return "the server closed the connection"
	case errors.As(err, &netErr) && netErr.Timeout():
		return fmt.Sprintf("the link between %s and the server was silent for %s", p.self, tunnel.LinkSilence())
	}
	return fmt.Sprintf("the link between %s and the server was lost (%v)", p.self, err)
}

// localReason words a failure of the local TCP connection.
func (p party) localReason(err error) string {
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return p.local + " reset its connection to " + p.self
	}
	return fmt.Sprintf("the connection between %s and %s failed (%v)", p.self, p.local, err)
}

// bridge copies both ways until both directions finish cleanly or either
// fails, then closes both ends. When this end is the one that saw the
// break, it tells the far end why, so both logs name the same cause.
// finish, if not nil, ends a cleanly finished stream on a reusable leg
// instead of closing it (protocol 2), and returns what the hub's verdict
// says went wrong, if anything.
func bridge(ctx context.Context, sess *tunnel.Stream, local HalfCloser, p party, rec *connRecord, finish func(*tunnel.Stream) error) ended {
	// If this program is stopped, whoever closes the stream says so.
	sess.CloseReason = func() string {
		if ctx.Err() != nil {
			return p.self + " is stopping"
		}
		return ""
	}
	toFar, toLocal := &rec.sent, &rec.received
	type result struct {
		outbound bool // local -> tunnel
		end      copyEnd
	}
	results := make(chan result, 2)
	go func() {
		end := copyChunks(sess, local, toFar)
		if end.clean() {
			end.writeErr = sess.CloseWrite()
		}
		results <- result{true, end}
	}()
	go func() {
		end := copyChunks(local, sess, toLocal)
		if end.clean() {
			_ = local.CloseWrite()
		}
		results <- result{false, end}
	}()
	// describe words one direction's end. mine is true when the cause is on
	// this side of the tunnel, which the far end cannot see for itself.
	describe := func(r result) (reason string, mine bool, err error) {
		switch {
		case r.end.clean() && r.outbound:
			return p.local + " closed the connection", true, nil
		case r.end.clean():
			return p.far + " closed the connection", false, nil
		case r.outbound && r.end.readErr != nil:
			return p.localReason(r.end.readErr), true, r.end.readErr
		case r.outbound:
			return p.linkReason(r.end.writeErr), false, r.end.writeErr
		case r.end.readErr != nil:
			// A silent link may still carry what this end sends, so say so.
			var netErr net.Error
			silent := errors.As(r.end.readErr, &netErr) && netErr.Timeout()
			return p.linkReason(r.end.readErr), silent, r.end.readErr
		}
		return p.localReason(r.end.writeErr), true, r.end.writeErr
	}

	reason, mine, err := describe(<-results)
	if err == nil {
		// One direction finished cleanly. Unless more is learned, the
		// reason stays who closed first. If that was the far end's
		// half-close, nothing reads the stream any more, so watch for the
		// far end going away while this end still has the floor.
		then := func(r result) {
			if why, whose, failed := describe(r); failed != nil {
				reason, mine, err = why, whose, failed
			}
		}
		select {
		case second := <-results:
			then(second)
		case <-sess.Gone():
			// After a clean finish the far end's close and our own last
			// result arrive together; give ours a moment before deciding
			// the far end left while we were still sending.
			select {
			case second := <-results:
				then(second)
			case <-time.After(200 * time.Millisecond):
				mine, err = false, tunnel.ErrPeerClosed
				if reason = sess.GoneReason(); reason == "" {
					reason = "the server closed the connection"
				}
			}
		}
	}
	if ctx.Err() != nil {
		reason, mine, err = p.self+" is stopping", true, ctx.Err()
	}
	switch {
	case mine && err != nil:
		sess.Fail(reason)
	case err == nil && finish != nil && sess.Reusable() && sess.Clean():
		if verr := finish(sess); verr != nil {
			reason, err = p.linkReason(verr), verr
		}
	default:
		_ = sess.Close()
	}
	_ = local.Close()
	return ended{toFar: toFar.Load(), toLocal: toLocal.Load(), reason: reason, err: err}
}

// Connect forwards every connection accepted on ln to the serving side.
func (c *Client) Connect(ctx context.Context, ln net.Listener) error {
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go func() {
			_ = c.carry(ctx, conn.(*net.TCPConn), conn.RemoteAddr().String())
		}()
	}
}

// ConnectOne carries a single connection, and logs how it went. An error
// it returns reads as the reason the connection ended, naming the hop.
func (c *Client) ConnectOne(ctx context.Context, local HalfCloser) error {
	return c.carry(ctx, local, "stdin/stdout")
}

// endError is a connection that ended badly: it reads as the reason, and
// unwraps to the underlying error.
type endError struct {
	reason string
	err    error
}

func (e *endError) Error() string { return e.reason }
func (e *endError) Unwrap() error { return e.err }

func (c *Client) carry(ctx context.Context, local HalfCloser, from string) error {
	stream, fullID, err := c.connectStream(ctx)
	if err != nil {
		_ = local.Close()
		err = explain(err)
		c.logf("connection from %s refused: %v", from, err)
		return err
	}
	id, started := short(fullID), time.Now()
	c.logf("connection %s open: %s -> tunnel %s", id, from, c.wordLabel())
	stop := context.AfterFunc(ctx, func() { _ = stream.Close() })
	defer stop()
	rec := c.reg.add(fullID, SideConnect, stream)
	c.opened(rec)
	e := bridge(ctx, stream, local, partyConnect, rec, nil)
	c.closed(rec, e.err)
	c.logEnd(id, started, e, false)
	if e.err != nil {
		return &endError{e.reason, e.err}
	}
	return nil
}

// Stdio is standard input and output as one connection, for use as an ssh
// ProxyCommand.
type Stdio struct {
	In  io.ReadCloser
	Out io.WriteCloser
}

func (s Stdio) Read(p []byte) (int, error)  { return s.In.Read(p) }
func (s Stdio) Write(p []byte) (int, error) { return s.Out.Write(p) }
func (s Stdio) CloseWrite() error           { return s.Out.Close() }
func (s Stdio) Close() error {
	err := s.In.Close()
	_ = s.Out.Close() // may be closed already, by CloseWrite
	return err
}

// ---------- certificate trust ----------

// ProbeCert connects once and returns the server's certificate, together
// with the reason it does not verify (nil when it does).
func ProbeCert(ctx context.Context, base string) (leaf *x509.Certificate, verifyErr error, err error) {
	base, err = normalizeBase(base)
	if err != nil {
		return nil, nil, err
	}
	u, _ := url.Parse(base)
	addr := u.Host
	if u.Port() == "" {
		addr = net.JoinHostPort(u.Hostname(), "443")
	}
	ctx, cancel := context.WithTimeout(ctx, tunnel.HandshakeLimit)
	defer cancel()
	raw, err := (&net.Dialer{Timeout: tunnel.DialTimeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, nil, err
	}
	defer raw.Close()
	conn := tls.Client(raw, &tls.Config{ServerName: u.Hostname(), InsecureSkipVerify: true})
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, nil, err
	}
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, nil, errors.New("the server sent no certificate")
	}
	opts := x509.VerifyOptions{DNSName: u.Hostname(), Intermediates: x509.NewCertPool()}
	for _, c := range certs[1:] {
		opts.Intermediates.AddCert(c)
	}
	_, verifyErr = certs[0].Verify(opts)
	return certs[0], verifyErr, nil
}

// Fingerprint is the certificate's SHA-256, as AA:BB:...
func Fingerprint(cert *x509.Certificate) string { return tunnel.Fingerprint(cert) }

// PinnedTLS accepts exactly this certificate and nothing else.
func PinnedTLS(cert *x509.Certificate) *tls.Config {
	want := sha256.Sum256(cert.Raw)
	return &tls.Config{
		InsecureSkipVerify: true, // replaced by the check below
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 || sha256.Sum256(cs.PeerCertificates[0].Raw) != want {
				return errors.New("the server's certificate is not the one that was trusted")
			}
			return nil
		},
	}
}
