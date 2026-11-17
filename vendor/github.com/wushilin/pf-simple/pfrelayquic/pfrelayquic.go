// Package pfrelayquic is the Go SDK for the pf-simple relay hub over QUIC:
// tunnel protocol 3 (docs/PROTOCOL.md §13).
//
// It gives the same *pfrelay.Client as pfrelay, with the same API: serve a
// tunnel or connect through one. Only the way to the hub differs. The
// client discovers the hub's QUIC listener over the hub's HTTPS endpoint,
// pins its certificate by the fingerprint that endpoint announced, and
// carries each request on a stream of one QUIC connection. A QUIC side
// works with a WebSocket side through the same hub, in either role.
//
// There is no fallback: where UDP is blocked, this fails to connect, and
// pfrelay (WebSocket) is the one to use.
//
// The package is licensed under the Apache License 2.0; see the LICENSE
// file in the pfrelay directory.
package pfrelayquic

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/quic-go/quic-go"

	"github.com/wushilin/pf-simple/internal/quictun"
	"github.com/wushilin/pf-simple/internal/relayhook"
	"github.com/wushilin/pf-simple/internal/tunnel"
	"github.com/wushilin/pf-simple/pfrelay"
)

// DefaultAgent is what a Client calls itself when Agent is empty: pfrelay's
// default names the WebSocket SDK.
const DefaultAgent = "pfrelayquic-go"

// Proto is the tunnel protocol this SDK speaks: protocol 3, which exists
// only over QUIC. It works with clients of protocols 0 to 2 (WebSocket)
// through the hub, which bridges the two.
const Proto = quictun.Proto

// errNoQUIC is what a hub that does not offer QUIC means.
var errNoQUIC = "this hub does not offer QUIC: it is older than pf-simple 0.16.0, or its relay hub is off; upgrade it, or use pf-client (WebSocket)"

// NewClient checks the relay URL and the word, as pfrelay.NewClient does,
// and makes the client reach the hub over QUIC. tlsConfig is for the hub's
// HTTPS endpoint, where the QUIC listener is discovered; it may be nil.
func NewClient(base, word string, tlsConfig *tls.Config) (*pfrelay.Client, error) {
	c, err := pfrelay.NewClient(base, word, tlsConfig)
	if err != nil {
		return nil, err
	}
	c.Agent = DefaultAgent
	relayhook.Attach(c, &transport{
		http:    &http.Client{Timeout: tunnel.HandshakeLimit, Transport: &http.Transport{TLSClientConfig: tlsConfig, MaxIdleConnsPerHost: 1}},
		dialing: make(chan struct{}, 1),
	})
	return c, nil
}

// transport reaches the hub over one QUIC connection, made again when it is
// lost.
type transport struct {
	http *http.Client
	// dialing is held while a connection is made, and taken with the
	// caller's context, so a caller can give up waiting and Close never
	// waits behind a discovery or a handshake.
	dialing chan struct{}

	mu      sync.Mutex
	conn    *qconn
	retired []*qconn // dropped, and closed once they hold nothing (§13.8)
}

// Close closes the QUIC connections to the hub (code none). Streams that
// sent an err, a refusal or an unregister FIN get up to DeliverWait for the
// hub to take it, as closing a connection drops what is still queued
// (§13.5, "Delivering a reason").
func (t *transport) Close() error {
	t.mu.Lock()
	conns := t.retired
	if t.conn != nil {
		conns = append(conns, t.conn)
	}
	t.conn, t.retired = nil, nil
	t.mu.Unlock()
	t.http.CloseIdleConnections()
	var wg sync.WaitGroup
	for _, qc := range conns {
		wg.Go(func() { qc.close() })
	}
	wg.Wait()
	return nil
}

// ---------- discovery and the connection ----------

// discover asks the hub's HTTPS endpoint where its QUIC listener is
// (§13.2). op is "serve" or "connect", and the credentials are the run's.
func (t *transport) discover(ctx context.Context, p relayhook.Params, op string) (*quictun.Discovery, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.Base+tunnel.APIPath+"/quic", nil)
	if err != nil {
		return nil, err
	}
	h := req.Header
	h.Set(tunnel.HeaderVersion, p.Agent)
	h.Set(tunnel.HeaderOp, op)
	if op == "serve" {
		if p.ServeToken != "" {
			h.Set(tunnel.HeaderServe, p.ServeToken)
		}
	} else {
		h.Set(tunnel.HeaderWord, p.Word)
		if p.ClientToken != "" {
			h.Set(tunnel.HeaderClientToken, p.ClientToken)
		}
	}
	resp, err := t.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	// A hub without QUIC does not know the endpoint (§13.2).
	if resp.StatusCode == http.StatusNotFound {
		return nil, &tunnel.StatusError{Code: http.StatusNotFound, Msg: errNoQUIC, Header: resp.Header}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &tunnel.StatusError{Code: resp.StatusCode, Msg: tunnel.ErrorText(resp.Body), Header: resp.Header}
	}
	var d quictun.Discovery
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&d); err != nil {
		return nil, errors.New("the hub's answer to QUIC discovery is not understood")
	}
	if err := d.Check(); err != nil {
		return nil, err
	}
	return &d, nil
}

// get returns the QUIC connection to the hub, making it if there is none:
// discovery, then a handshake that pins the certificate, with one more
// discovery after a mismatch (§13.3).
func (t *transport) get(ctx context.Context, p relayhook.Params, op string) (*qconn, error) {
	if qc := t.current(); qc != nil {
		return qc, nil
	}
	select {
	case t.dialing <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-t.dialing }()
	if qc := t.current(); qc != nil { // made meanwhile by another caller
		return qc, nil
	}
	var err error
	for try := 0; try < 2; try++ {
		var d *quictun.Discovery
		if d, err = t.discover(ctx, p, op); err != nil {
			return nil, err
		}
		var c *quic.Conn
		c, err = quic.DialAddr(ctx, d.Addr(), quictun.ClientTLS(d.Host, d.Fingerprints), quictun.ClientConfig())
		if err == nil {
			qc := &qconn{conn: c, regs: map[string]*registration{}, changed: make(chan struct{})}
			go qc.acceptOpens()
			t.mu.Lock()
			t.conn = qc
			t.mu.Unlock()
			return qc, nil
		}
		if !errors.Is(err, quictun.ErrPinMismatch) && !strings.Contains(err.Error(), quictun.ErrPinMismatch.Error()) {
			break
		}
	}
	return nil, dialError(err)
}

// current is the connection to use, if there is a live one.
func (t *transport) current() *qconn {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.conn != nil && t.conn.conn.Context().Err() == nil {
		return t.conn
	}
	t.conn = nil
	return nil
}

// dialError words a failure to reach the QUIC listener.
func dialError(err error) error {
	var vn *quic.VersionNegotiationError
	var te *quic.TransportError
	switch {
	case strings.Contains(err.Error(), quictun.ErrPinMismatch.Error()):
		return quictun.ErrPinMismatch
	case errors.As(err, &vn):
		return errors.New("the hub's QUIC listener does not speak QUIC version 1")
	case errors.As(err, &te) && te.ErrorCode == quic.ConnectionRefused:
		return &tunnel.StatusError{Code: http.StatusTooManyRequests, Msg: "the hub refused the QUIC connection; trying again later"}
	}
	return fmt.Errorf("cannot reach the hub over QUIC (UDP may be blocked on the way; pf-client over WebSocket works where QUIC does not): %w", err)
}

// drop forgets qc as the connection to use, if it still is, and closes it
// (none) once it holds no stream and no registration (§13.8).
func (t *transport) drop(qc *qconn) {
	t.mu.Lock()
	if t.conn == qc {
		t.conn = nil
	}
	live := t.retired[:0]
	for _, r := range t.retired {
		if r.conn.Context().Err() == nil && r != qc {
			live = append(live, r)
		}
	}
	t.retired = append(live, qc)
	t.mu.Unlock()
	qc.retire()
}

// request opens a stream on qc, or on the connection to the hub if qc is
// nil, sends req, and reads the hub's answer. A refusal comes back as a
// *tunnel.StatusError, after the stream is ended. release ends the
// stream's hold on its connection.
func (t *transport) request(ctx context.Context, p relayhook.Params, op string, req quictun.Request, qc *qconn) (_ *qconn, _ *quic.Stream, _ *quictun.Answer, release func(), _ error) {
	if qc == nil {
		var err error
		if qc, err = t.get(ctx, p, op); err != nil {
			return nil, nil, nil, nil, err
		}
	}
	release = qc.hold()
	req.Proto, req.Version, req.Word = tunnel.ProtoRange(Proto, Proto), p.Agent, p.Word
	s, err := qc.conn.OpenStreamSync(ctx)
	if err != nil {
		release()
		if ctx.Err() != nil {
			return nil, nil, nil, nil, ctx.Err()
		}
		if qc.conn.Context().Err() != nil {
			t.drop(qc)
		}
		return nil, nil, nil, nil, fmt.Errorf("the QUIC connection to the hub was lost: %w", err)
	}
	reset := func(code quic.StreamErrorCode) {
		s.CancelWrite(code)
		s.CancelRead(code)
		release()
	}
	stop := context.AfterFunc(ctx, func() { s.CancelWrite(quictun.CodeCancelled); s.CancelRead(quictun.CodeCancelled) })
	defer stop()
	_ = s.SetDeadline(time.Now().Add(quictun.AnswerWait))
	werr := quictun.WriteMessage(s, req)
	if errors.Is(werr, quictun.ErrMessage) { // too long: nothing was sent
		reset(quictun.CodeCancelled)
		return nil, nil, nil, nil, fmt.Errorf("the request is too long for the hub (over %d bytes): %w", quictun.MaxMessage, werr)
	}
	// Read the answer even after a failed write: the hub's refusal can
	// overtake the request, and it says why (§13.5).
	var a quictun.Answer
	rerr := quictun.ReadMessage(s, &a)
	_ = s.SetDeadline(time.Time{})
	if rerr != nil {
		reset(quictun.CodeRequestTimeout)
		switch {
		case ctx.Err() != nil:
			return nil, nil, nil, nil, ctx.Err()
		case werr != nil:
			return nil, nil, nil, nil, fmt.Errorf("cannot send the request to the hub: %w", werr)
		}
		return nil, nil, nil, nil, fmt.Errorf("the hub did not answer: %w", rerr)
	}
	// The status first: a refusal, a 426 included, carries the hub's own
	// protocol in proto, and its message says which side to upgrade (§13.4).
	if a.Status != http.StatusOK && a.Status != http.StatusNoContent {
		// The hub sends FIN and STOP_SENDING; end this direction too.
		s.CancelWrite(quictun.CodeRefused)
		quictun.Drain(s, &qc.lingers)
		release()
		if a.Status == http.StatusTooManyRequests && a.Scope == "connection" {
			t.drop(qc) // the next request opens a new connection (§13.8)
		}
		hd := http.Header{}
		hd.Set(tunnel.HeaderProto, strconv.Itoa(a.Proto))
		return nil, nil, nil, nil, &tunnel.StatusError{Code: a.Status, Msg: a.Error, Header: hd}
	}
	if werr != nil {
		reset(quictun.CodeBroken)
		return nil, nil, nil, nil, fmt.Errorf("cannot send the request to the hub: %w", werr)
	}
	if a.Proto != 0 && a.Proto != Proto {
		reset(quictun.CodeProtocol)
		// Final: retrying cannot help, one side must be upgraded.
		return nil, nil, nil, nil, &tunnel.StatusError{Code: http.StatusUpgradeRequired,
			Msg: fmt.Sprintf("the hub answered in QUIC protocol %d; this client speaks %d", a.Proto, Proto)}
	}
	return qc, s, &a, release, nil
}

// ---------- the requests ----------

func (t *transport) Check(ctx context.Context, p relayhook.Params) error {
	qc, s, _, release, err := t.request(ctx, p, "connect", quictun.Request{Op: "check", ClientToken: p.ClientToken}, nil)
	if err != nil {
		return err
	}
	quictun.FinishCounted(s, &qc.lingers)
	release()
	return nil
}

func (t *transport) Connect(ctx context.Context, p relayhook.Params) (*tunnel.Stream, string, error) {
	qc, s, a, release, err := t.request(ctx, p, "connect", quictun.Request{Op: "connect", ClientToken: p.ClientToken}, nil)
	if err != nil {
		return nil, "", err
	}
	sc := quictun.NewStreamConn(s, qc.conn, &qc.lingers)
	sc.OnDone = release
	return tunnel.NewStream(tunnel.NewFramed(sc)), a.Conn, nil
}

func (t *transport) Register(ctx context.Context, p relayhook.Params, target string) (relayhook.Registration, error) {
	req := quictun.Request{Op: "serve", ServeToken: p.ServeToken, Name: p.Name, Target: target}
	if p.ClientToken != "" {
		req.ClientTokenSHA256 = tunnel.HashClientToken(p.ClientToken)
	}
	qc, err := t.get(ctx, p, "serve")
	if err != nil {
		return nil, err
	}
	// An open may arrive before the answer (§13.4): the serve is counted on
	// the connection its request goes on, until its registration is there.
	qc.serving(1)
	defer qc.serving(-1)
	_, s, a, release, err := t.request(ctx, p, "serve", req, qc)
	if err != nil {
		return nil, err
	}
	r := &registration{qc: qc, s: s, id: a.Reg, opens: make(chan *open, openQueue), ended: make(chan struct{})}
	qc.add(r)
	release() // the registration holds the connection from now on
	go r.watch()
	return r, nil
}

// openQueue is how many opens wait for a registration's Next, beyond
// pfrelay's own backlog.
const openQueue = 128

// backlogFull is what an open is refused with when its registration's queue
// is full (§9), as pfrelay says it over WebSocket.
const backlogFull = "the serving side is not accepting connections fast enough"

// ---------- the connection's incoming streams ----------

// qconn is one QUIC connection to the hub and its registrations.
type qconn struct {
	conn    *quic.Conn
	lingers quictun.Lingers

	mu      sync.Mutex
	regs    map[string]*registration
	serves  int           // serve requests not yet answered
	changed chan struct{} // closed and replaced when regs or serves change
	held    int           // streams in use: requests, connections, opens
	retired bool          // no new request goes here; close it once it holds nothing
}

// hold counts a stream as in use; release, once, ends that.
func (qc *qconn) hold() (release func()) {
	qc.mu.Lock()
	qc.held++
	qc.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			qc.mu.Lock()
			qc.held--
			qc.mu.Unlock()
			qc.closeIfIdle()
		})
	}
}

func (qc *qconn) retire() {
	qc.mu.Lock()
	qc.retired = true
	qc.mu.Unlock()
	qc.closeIfIdle()
}

// closeIfIdle closes a retired connection that holds nothing any more.
func (qc *qconn) closeIfIdle() {
	qc.mu.Lock()
	idle := qc.retired && qc.held == 0 && len(qc.regs) == 0
	qc.mu.Unlock()
	if idle {
		go qc.close()
	}
}

// close closes the connection (none), after giving streams that wait for
// the hub's end of them up to DeliverWait.
func (qc *qconn) close() {
	qc.lingers.Wait(quictun.DeliverWait)
	_ = qc.conn.CloseWithError(quictun.CodeNone, "done")
}

func (qc *qconn) serving(d int) {
	qc.mu.Lock()
	qc.serves += d
	qc.notifyLocked()
	qc.mu.Unlock()
}

func (qc *qconn) add(r *registration) {
	qc.mu.Lock()
	qc.regs[r.id] = r
	qc.notifyLocked()
	qc.mu.Unlock()
}

func (qc *qconn) remove(r *registration) {
	qc.mu.Lock()
	delete(qc.regs, r.id)
	qc.notifyLocked()
	qc.mu.Unlock()
	qc.closeIfIdle()
}

func (qc *qconn) notifyLocked() {
	close(qc.changed)
	qc.changed = make(chan struct{})
}

// find returns the registration reg names. An open can arrive before the
// answer to its serve, streams not being ordered with one another, so it
// waits while serves are outstanding, up to RequestWait (§13.4).
func (qc *qconn) find(reg string) *registration {
	deadline := time.After(quictun.RequestWait)
	for {
		qc.mu.Lock()
		r, pending, changed := qc.regs[reg], qc.serves, qc.changed
		qc.mu.Unlock()
		if r != nil || pending == 0 {
			return r
		}
		select {
		case <-changed:
		case <-deadline:
			return nil
		}
	}
}

// acceptOpens reads each stream the hub opens: an open for one of this
// connection's registrations.
func (qc *qconn) acceptOpens() {
	for {
		s, err := qc.conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		release := qc.hold()
		go func() {
			_ = s.SetReadDeadline(time.Now().Add(quictun.RequestWait))
			var o quictun.Open
			err := quictun.ReadMessage(s, &o)
			_ = s.SetReadDeadline(time.Time{})
			if err != nil || o.Open == "" {
				code := quic.StreamErrorCode(quictun.CodeProtocol)
				if isTimeout(err) {
					code = quictun.CodeRequestTimeout
				}
				s.CancelWrite(code)
				s.CancelRead(code)
				release()
				return
			}
			op := &open{qc: qc, s: s, id: o.Open, release: release}
			r := qc.find(o.Reg)
			if r == nil {
				op.refuse(http.StatusGone, "no such registration")
				return
			}
			r.deliver(op)
		}()
	}
}

func isTimeout(err error) bool {
	var ne interface{ Timeout() bool }
	return errors.As(err, &ne) && ne.Timeout()
}

// registration is one registration over QUIC, until its serve stream ends.
type registration struct {
	qc    *qconn
	s     *quic.Stream
	id    string
	opens chan *open
	ended chan struct{}
	why   error

	mu   sync.Mutex
	done bool // ended: no open is queued any more
}

// deliver queues o for Next, or refuses it: 410 once the registration has
// ended, 502 with a reason when the queue is full (§9).
func (r *registration) deliver(o *open) {
	r.mu.Lock()
	if r.done {
		r.mu.Unlock()
		o.refuse(http.StatusGone, "no such registration")
		return
	}
	select {
	case r.opens <- o:
		r.mu.Unlock()
	default:
		r.mu.Unlock()
		o.refuse(http.StatusBadGateway, backlogFull)
	}
}

// watch reads the serve stream until it ends: the hub's end message, its
// FIN, or a lost connection.
func (r *registration) watch() {
	var why error
	for {
		var e quictun.End
		err := quictun.ReadMessage(r.s, &e)
		if err == nil && e.End == "" {
			continue // unknown messages are ignored
		}
		switch {
		case err == nil:
			why = endError(e)
			quictun.FinishCounted(r.s, &r.qc.lingers) // the hub's FIN follows; answer with ours
		case errors.Is(err, io.EOF):
			why = errors.New("the server ended the registration")
			_ = r.s.Close()
		case errors.Is(err, quictun.ErrMessage):
			why = errors.New("the server broke the protocol on the serve stream")
			r.s.CancelWrite(quictun.CodeProtocol)
			r.s.CancelRead(quictun.CodeProtocol)
		default:
			why = fmt.Errorf("the link to the server was lost (%v)", err)
		}
		break
	}
	r.end(why)
}

// end ends the registration once. The opens still queued are refused: the
// hub hears 410 at once, and their streams end (§13.5).
func (r *registration) end(why error) {
	r.mu.Lock()
	if r.done {
		r.mu.Unlock()
		return
	}
	r.done = true
	r.why = why
	close(r.ended)
	var queued []*open
	for {
		select {
		case o := <-r.opens:
			queued = append(queued, o)
			continue
		default:
		}
		break
	}
	r.mu.Unlock()
	for _, o := range queued {
		go o.refuse(http.StatusGone, "no such registration")
	}
	r.qc.remove(r)
}

// endError is the hub's end of a registration, as the user should read it.
func endError(e quictun.End) error {
	why := cleanText(e.Error, 200)
	if why == "" {
		why = "the server ended the registration"
	}
	if e.End == quictun.EndTakeover {
		why += " (another serving side registered the same word)"
	}
	return errors.New(why)
}

func (r *registration) Next(ctx context.Context) (relayhook.Open, error) {
	select {
	case <-r.ended: // an end wins over a queued open: those are refused
		return nil, r.why
	default:
	}
	select {
	case o := <-r.opens:
		return o, nil
	case <-r.ended:
		return nil, r.why
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Close unregisters: FIN on the serve stream (§13.4). watch reads on to the
// hub's FIN, which ends the stream; DeliverWait bounds the wait.
func (r *registration) Close() {
	r.end(errors.New("unregistered"))
	_ = r.s.Close()
	done := r.qc.lingers.Add()
	time.AfterFunc(quictun.DeliverWait, func() {
		r.s.CancelRead(quictun.CodeCancelled)
		done()
	})
}

// open is the hub asking for one connection, on a stream it opened.
type open struct {
	qc      *qconn
	s       *quic.Stream
	id      string
	release func() // the stream's hold on its connection
	once    sync.Once
}

func (o *open) ID() string { return o.id }

func (o *open) answer(a quictun.Answer) error {
	_ = o.s.SetWriteDeadline(time.Now().Add(tunnel.WriteTimeout))
	err := quictun.WriteMessage(o.s, a)
	_ = o.s.SetWriteDeadline(time.Time{})
	return err
}

func (o *open) Accept(context.Context) (*tunnel.Stream, error) {
	var err error = errors.New("this connection was answered already")
	o.once.Do(func() {
		if err = o.answer(quictun.Answer{Status: http.StatusOK}); err != nil {
			o.s.CancelWrite(quictun.CodeBroken)
			o.s.CancelRead(quictun.CodeBroken)
			o.release()
		}
	})
	if err != nil {
		return nil, err
	}
	sc := quictun.NewStreamConn(o.s, o.qc.conn, &o.qc.lingers)
	sc.OnDone = o.release
	return tunnel.NewStream(tunnel.NewFramed(sc)), nil
}

func (o *open) Refuse(reason string) {
	reason = cleanText(reason, 128)
	if reason == "" {
		reason = "the serving side refused the connection"
	}
	o.refuse(http.StatusBadGateway, reason)
}

// refuse answers the open with a refusal, then FIN, and lets the hub end
// its direction (§13.5).
func (o *open) refuse(status int, reason string) {
	o.once.Do(func() {
		_ = o.answer(quictun.Answer{Status: status, Error: reason})
		quictun.FinishCounted(o.s, &o.qc.lingers)
		o.release()
	})
}

// cleanText keeps printable ASCII, cut to max, as reasons travel (§6.6).
func cleanText(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= max {
			break
		}
		if r < 0x80 && unicode.IsPrint(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}
