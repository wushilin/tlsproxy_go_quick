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
		http: &http.Client{Timeout: tunnel.HandshakeLimit, Transport: &http.Transport{TLSClientConfig: tlsConfig, MaxIdleConnsPerHost: 1}},
	})
	return c, nil
}

// transport reaches the hub over one QUIC connection, made again when it is
// lost.
type transport struct {
	http *http.Client

	mu   sync.Mutex
	conn *qconn
}

func (t *transport) Close() error {
	t.mu.Lock()
	qc := t.conn
	t.conn = nil
	t.mu.Unlock()
	t.http.CloseIdleConnections()
	if qc != nil {
		_ = qc.conn.CloseWithError(quictun.CodeNone, "done")
	}
	return nil
}

// ---------- discovery and the connection ----------

// discover asks the hub's HTTPS endpoint where its QUIC listener is
// (§13.2). op is "serve" or "connect", and the credentials are the run's.
func (t *transport) discover(ctx context.Context, p relayhook.Params, op string) (*quictun.Discovery, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.Base+tunnel.Path+"/quic", nil)
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
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.conn != nil && t.conn.conn.Context().Err() == nil {
		return t.conn, nil
	}
	t.conn = nil
	var err error
	for try := 0; try < 2; try++ {
		var d *quictun.Discovery
		if d, err = t.discover(ctx, p, op); err != nil {
			return nil, err
		}
		var c *quic.Conn
		c, err = quic.DialAddr(ctx, d.Addr(), quictun.ClientTLS(d.Host, d.Fingerprints), quictun.Config())
		if err == nil {
			qc := &qconn{conn: c, regs: map[string]*registration{}, changed: make(chan struct{})}
			go qc.acceptOpens()
			t.conn = qc
			return qc, nil
		}
		if !errors.Is(err, quictun.ErrPinMismatch) && !strings.Contains(err.Error(), quictun.ErrPinMismatch.Error()) {
			break
		}
	}
	return nil, dialError(err)
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

// drop forgets qc as the connection to use, if it still is.
func (t *transport) drop(qc *qconn) {
	t.mu.Lock()
	if t.conn == qc {
		t.conn = nil
	}
	t.mu.Unlock()
}

// request opens a stream, sends req, and reads the hub's answer. A refusal
// comes back as a *tunnel.StatusError, after the stream is ended.
func (t *transport) request(ctx context.Context, p relayhook.Params, op string, req quictun.Request) (*qconn, *quic.Stream, *quictun.Answer, error) {
	qc, err := t.get(ctx, p, op)
	if err != nil {
		return nil, nil, nil, err
	}
	req.Proto, req.Version, req.Word = tunnel.ProtoRange(Proto, Proto), p.Agent, p.Word
	s, err := qc.conn.OpenStreamSync(ctx)
	if err != nil {
		t.drop(qc)
		return nil, nil, nil, fmt.Errorf("the QUIC connection to the hub was lost: %w", err)
	}
	stop := context.AfterFunc(ctx, func() { s.CancelWrite(quictun.CodeCancelled); s.CancelRead(quictun.CodeCancelled) })
	defer stop()
	_ = s.SetDeadline(time.Now().Add(quictun.AnswerWait))
	if err := quictun.WriteMessage(s, req); err != nil {
		return nil, nil, nil, err
	}
	var a quictun.Answer
	err = quictun.ReadMessage(s, &a)
	_ = s.SetDeadline(time.Time{})
	if err != nil {
		s.CancelWrite(quictun.CodeRequestTimeout)
		s.CancelRead(quictun.CodeRequestTimeout)
		if ctx.Err() != nil {
			return nil, nil, nil, ctx.Err()
		}
		return nil, nil, nil, fmt.Errorf("the hub did not answer: %w", err)
	}
	if a.Proto != 0 && a.Proto != Proto {
		s.CancelWrite(quictun.CodeProtocol)
		s.CancelRead(quictun.CodeProtocol)
		return nil, nil, nil, fmt.Errorf("the hub answered in QUIC protocol %d; this client speaks %d", a.Proto, Proto)
	}
	if a.Status != http.StatusOK && a.Status != http.StatusNoContent {
		// The hub sends FIN and STOP_SENDING; end this direction too.
		s.CancelWrite(quictun.CodeRefused)
		go drain(s)
		if a.Status == http.StatusTooManyRequests && a.Scope == "connection" {
			t.drop(qc) // the next request opens a new connection (§13.8)
		}
		hd := http.Header{}
		hd.Set(tunnel.HeaderProto, strconv.Itoa(a.Proto))
		return nil, nil, nil, &tunnel.StatusError{Code: a.Status, Msg: a.Error, Header: hd}
	}
	return qc, s, &a, nil
}

func drain(s *quic.Stream) {
	_ = s.SetReadDeadline(time.Now().Add(quictun.DeliverWait))
	_, _ = io.Copy(io.Discard, s)
	s.CancelRead(quictun.CodeCancelled)
}

// ---------- the requests ----------

func (t *transport) Check(ctx context.Context, p relayhook.Params) error {
	_, s, _, err := t.request(ctx, p, "connect", quictun.Request{Op: "check", ClientToken: p.ClientToken})
	if err != nil {
		return err
	}
	_ = s.Close()
	go drain(s)
	return nil
}

func (t *transport) Connect(ctx context.Context, p relayhook.Params) (*tunnel.Stream, string, error) {
	qc, s, a, err := t.request(ctx, p, "connect", quictun.Request{Op: "connect", ClientToken: p.ClientToken})
	if err != nil {
		return nil, "", err
	}
	return tunnel.NewStream(tunnel.NewFramed(quictun.NewStreamConn(s, qc.conn))), a.Conn, nil
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
	qc.serving(1) // an open may arrive before the answer (§13.4)
	defer qc.serving(-1)
	qc, s, a, err := t.request(ctx, p, "serve", req)
	if err != nil {
		return nil, err
	}
	r := &registration{qc: qc, s: s, id: a.Reg, opens: make(chan *open, 128), ended: make(chan struct{})}
	qc.add(r)
	go r.watch()
	return r, nil
}

// ---------- the connection's incoming streams ----------

// qconn is one QUIC connection to the hub and its registrations.
type qconn struct {
	conn *quic.Conn

	mu      sync.Mutex
	regs    map[string]*registration
	serves  int           // serve requests not yet answered
	changed chan struct{} // closed and replaced when regs or serves change
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
		go func() {
			_ = s.SetReadDeadline(time.Now().Add(quictun.RequestWait))
			var o quictun.Open
			err := quictun.ReadMessage(s, &o)
			_ = s.SetReadDeadline(time.Time{})
			if err != nil || o.Open == "" {
				s.CancelWrite(quictun.CodeProtocol)
				s.CancelRead(quictun.CodeProtocol)
				return
			}
			r := qc.find(o.Reg)
			op := &open{qc: qc, s: s, id: o.Open}
			if r == nil || !r.deliver(op) {
				// A refused open: the answer, then FIN (§13.5).
				_ = op.answer(quictun.Answer{Status: http.StatusGone, Error: "no such registration"})
				_ = s.Close()
				go drain(s)
			}
		}()
	}
}

// registration is one registration over QUIC, until its serve stream ends.
type registration struct {
	qc    *qconn
	s     *quic.Stream
	id    string
	opens chan *open
	ended chan struct{}
	why   error
	once  sync.Once
}

func (r *registration) deliver(o *open) bool {
	select {
	case <-r.ended:
		return false
	default:
	}
	select {
	case r.opens <- o:
		return true
	default:
		return false
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
			_ = r.s.Close() // the hub's FIN follows; answer with ours
			go drain(r.s)
		case errors.Is(err, io.EOF):
			why = errors.New("the server ended the registration")
			_ = r.s.Close()
		default:
			why = fmt.Errorf("the link to the server was lost (%v)", err)
		}
		break
	}
	r.end(why)
}

func (r *registration) end(why error) {
	r.once.Do(func() {
		r.why = why
		close(r.ended)
		r.qc.remove(r)
	})
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
	case o := <-r.opens:
		return o, nil
	case <-r.ended:
		return nil, r.why
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Close unregisters: FIN on the serve stream (§13.4).
func (r *registration) Close() {
	r.end(errors.New("unregistered"))
	_ = r.s.Close()
	go drain(r.s)
}

// open is the hub asking for one connection, on a stream it opened.
type open struct {
	qc   *qconn
	s    *quic.Stream
	id   string
	once sync.Once
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
		}
	})
	if err != nil {
		return nil, err
	}
	return tunnel.NewStream(tunnel.NewFramed(quictun.NewStreamConn(o.s, o.qc.conn))), nil
}

func (o *open) Refuse(reason string) {
	o.once.Do(func() {
		reason = cleanText(reason, 128)
		if reason == "" {
			reason = "the serving side refused the connection"
		}
		_ = o.answer(quictun.Answer{Status: http.StatusBadGateway, Error: reason})
		_ = o.s.Close()
		go drain(o.s)
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
