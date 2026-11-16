// Package tunnel holds what pf-simple (the relay) and pf-client share: a
// minimal WebSocket, the stream that carries one TCP connection over it, and
// the client side of ad-hoc tunnels.
package tunnel

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// A minimal RFC 6455 implementation. The server side pushes JSON text frames
// to the console and carries tunnels; the client side dials them. The
// standard library has no WebSocket support and this avoids a dependency.

const (
	OpCont   = 0x0
	OpText   = 0x1
	OpBinary = 0x2
	OpClose  = 0x8
	OpPing   = 0x9
	OpPong   = 0xA

	wsGUID         = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	MaxSmallFrame  = 4096    // control messages; the console never sends real data
	maxDataFrame   = 1 << 20 // tunnels send at most ChunkSize per frame
	WriteTimeout   = 10 * time.Second
	closeTimeout   = 3 * time.Second
	DialTimeout    = 10 * time.Second
	HandshakeLimit = 15 * time.Second
)

// Conn is one WebSocket connection.
type Conn struct {
	conn net.Conn
	rd   *bufio.Reader
	// Header is the server's handshake response, on a dialed connection.
	Header http.Header
	// client is true on the dialing side, which masks what it sends and
	// expects unmasked frames; the server side is the reverse.
	client bool
	// framed is true for a QUIC stream of protocol 3 (framed.go): the same
	// frames in another encoding, with FIN for the close.
	framed bool
	// writeTimeout bounds each frame write; zero means none, for tunnel data
	// that the network may hold back for as long as it likes. readTimeout,
	// when set, is how long the peer may stay silent. Both are durations;
	// atomic, as a leg that is handed on changes them while a ping of its
	// last owner may still be on its way out.
	writeTimeout atomic.Int64
	readTimeout  atomic.Int64

	wmu  sync.Mutex
	wbuf []byte // frame under construction; guarded by wmu

	// dmu orders write deadlines against BeginClose, so a writer cannot
	// clear the closing deadline and then block forever.
	// heard is when the last frame header arrived, in unix nanoseconds.
	heard atomic.Int64

	dmu     sync.Mutex
	closing bool
	closeBy time.Time // when closing began, plus closeTimeout: one deadline for all its writes
	expired bool      // ExpireWrites was called: every write fails at once
}

// SetTimeouts sets how long the peer may stay silent and how long one frame
// write may take; zero means no limit.
func (c *Conn) SetTimeouts(read, write time.Duration) {
	c.readTimeout.Store(int64(read))
	c.writeTimeout.Store(int64(write))
	if read == 0 {
		_ = c.conn.SetReadDeadline(time.Time{})
	}
}

func (c *Conn) LocalAddr() net.Addr  { return c.conn.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

// Close closes the connection. One that is closing keeps to its deadline:
// a TLS connection's close notice, which crypto/tls gives five seconds of
// its own, is let go when it cannot leave in time, and the socket under it
// closed, as on any cut.
func (c *Conn) Close() error {
	tc, ok := c.conn.(*tls.Conn)
	c.dmu.Lock()
	closing, by := c.closing, c.closeBy
	c.dmu.Unlock()
	if !ok || !closing {
		return c.conn.Close()
	}
	done := make(chan error, 1)
	go func() { done <- tc.Close() }()
	t := time.NewTimer(max(time.Until(by), 0))
	defer t.Stop()
	select {
	case err := <-done:
		return err
	case <-t.C:
		return tc.NetConn().Close() // the notice, if it goes at all, goes nowhere
	}
}

func HeaderHasToken(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, part := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

// sameOrigin blocks cross-site WebSocket hijacking: browsers always send
// Origin on WebSocket handshakes, and it must match the console's host.
func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true // not a browser
	}
	u, err := url.Parse(origin)
	return err == nil && strings.EqualFold(u.Host, r.Host)
}

func acceptKey(key string) string {
	sum := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// Upgrade answers a WebSocket handshake and takes over the connection. extra
// headers, if any, go into the 101 response.
func Upgrade(w http.ResponseWriter, r *http.Request, extra http.Header) (*Conn, error) {
	key := r.Header.Get("Sec-WebSocket-Key")
	if !HeaderHasToken(r.Header, "Connection", "upgrade") ||
		!HeaderHasToken(r.Header, "Upgrade", "websocket") ||
		r.Header.Get("Sec-WebSocket-Version") != "13" || key == "" {
		http.Error(w, "websocket upgrade required", http.StatusBadRequest)
		return nil, errors.New("not a websocket handshake")
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin websocket refused", http.StatusForbidden)
		return nil, errors.New("cross-origin websocket")
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "websocket unsupported", http.StatusInternalServerError)
		return nil, errors.New("response does not support hijacking")
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	b.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n")
	b.WriteString("Sec-WebSocket-Accept: " + acceptKey(key) + "\r\n")
	for name, values := range extra {
		for _, v := range values {
			b.WriteString(name + ": " + v + "\r\n")
		}
	}
	// What the handler set for the tunnel protocol goes out with the 101
	// as it would with any other response.
	for name, values := range w.Header() {
		if strings.HasPrefix(name, "X-Pf-") && len(extra.Values(name)) == 0 {
			for _, v := range values {
				b.WriteString(name + ": " + v + "\r\n")
			}
		}
	}
	b.WriteString("\r\n")
	_ = conn.SetWriteDeadline(time.Now().Add(WriteTimeout))
	if _, err = conn.Write([]byte(b.String())); err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	c := &Conn{conn: conn, rd: rw.Reader}
	c.writeTimeout.Store(int64(WriteTimeout))
	return c, nil
}

// StatusError is a handshake the server answered with something other than
// 101.
type StatusError struct {
	Code   int
	Msg    string
	Header http.Header // the response's headers
}

func (e *StatusError) Error() string {
	if e.Msg == "" {
		return fmt.Sprintf("the server answered %d %s", e.Code, http.StatusText(e.Code))
	}
	return fmt.Sprintf("%s (%d)", e.Msg, e.Code)
}

// Final reports whether trying again cannot help.
func (e *StatusError) Final() bool {
	return e.Code >= 400 && e.Code < 500 && e.Code != http.StatusTooManyRequests && e.Code != http.StatusRequestTimeout
}

// ErrorText reads the message out of an error response: pf-simple sends
// {"error": "..."}, a proxy in front of it may send anything.
func ErrorText(body io.Reader) string {
	raw, _ := io.ReadAll(io.LimitReader(body, 2048))
	var parsed struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(raw, &parsed) == nil && parsed.Error != "" {
		return parsed.Error
	}
	if text := strings.TrimSpace(string(raw)); len(text) < 200 && !strings.Contains(text, "<") {
		return text
	}
	return ""
}

// Dial opens a WebSocket to an https URL.
func Dial(ctx context.Context, rawURL string, header http.Header, tlsConfig *tls.Config) (*Conn, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" {
		return nil, errors.New("only https URLs are supported")
	}
	addr := u.Host
	if u.Port() == "" {
		addr = net.JoinHostPort(u.Hostname(), "443")
	}
	ctx, cancel := context.WithTimeout(ctx, HandshakeLimit)
	defer cancel()
	raw, err := (&net.Dialer{Timeout: DialTimeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{}
	if tlsConfig != nil {
		cfg = tlsConfig.Clone()
	}
	if cfg.ServerName == "" {
		cfg.ServerName = u.Hostname()
	}
	cfg.NextProtos = []string{"http/1.1"}
	conn := tls.Client(raw, cfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		conn.Close()
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(nonce[:])
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		conn.Close()
		return nil, err
	}
	for name, values := range header {
		req.Header[name] = values
	}
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Key", key)
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("User-Agent", "pf-client")
	_ = conn.SetDeadline(time.Now().Add(HandshakeLimit))
	// A cancelled ctx ends the upgrade at once, not after HandshakeLimit.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, err
	}
	rd := bufio.NewReader(conn)
	resp, err := http.ReadResponse(rd, req)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		msg := ErrorText(resp.Body)
		resp.Body.Close()
		conn.Close()
		return nil, &StatusError{Code: resp.StatusCode, Msg: msg, Header: resp.Header}
	}
	if resp.Header.Get("Sec-WebSocket-Accept") != acceptKey(key) {
		conn.Close()
		return nil, errors.New("the server's websocket handshake is invalid")
	}
	if !stop() {
		conn.Close() // cancelled just now: its deadline is already in the past
		return nil, ctx.Err()
	}
	_ = conn.SetDeadline(time.Time{})
	c := &Conn{conn: conn, rd: rd, Header: resp.Header, client: true}
	c.writeTimeout.Store(int64(WriteTimeout))
	return c, nil
}

func (c *Conn) WriteFrame(op byte, payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.framed {
		return c.writeFramed(op, payload)
	}
	buf := append(c.wbuf[:0], 0x80|op) // FIN
	var maskBit byte
	if c.client {
		maskBit = 0x80
	}
	switch n := len(payload); {
	case n < 126:
		buf = append(buf, maskBit|byte(n))
	case n <= 0xFFFF:
		buf = append(buf, maskBit|126, byte(n>>8), byte(n))
	default:
		buf = append(buf, maskBit|127)
		buf = binary.BigEndian.AppendUint64(buf, uint64(n))
	}
	if c.client {
		var mask [4]byte
		binary.BigEndian.PutUint32(mask[:], mrand.Uint32())
		buf = append(buf, mask[:]...)
		at := len(buf)
		buf = append(buf, payload...)
		for i, body := 0, buf[at:]; i < len(body); i++ {
			body[i] ^= mask[i%4]
		}
	} else {
		buf = append(buf, payload...)
	}
	c.wbuf = buf
	c.armWrite()
	_, err := c.conn.Write(buf)
	return err
}

// armWrite sets the write deadline for the next write. Call it under wmu.
func (c *Conn) armWrite() {
	c.dmu.Lock()
	switch {
	case c.expired:
		_ = c.conn.SetWriteDeadline(time.Unix(1, 0))
	case c.closing:
		_ = c.conn.SetWriteDeadline(c.closeBy)
	case c.writeTimeout.Load() > 0:
		_ = c.conn.SetWriteDeadline(time.Now().Add(time.Duration(c.writeTimeout.Load())))
	default:
		_ = c.conn.SetWriteDeadline(time.Time{})
	}
	c.dmu.Unlock()
}

// BeginClose bounds every write from now on, including one already blocked.
func (c *Conn) BeginClose() {
	c.dmu.Lock()
	if !c.closing {
		c.closing, c.closeBy = true, time.Now().Add(closeTimeout)
	}
	_ = c.conn.SetWriteDeadline(c.closeBy)
	c.dmu.Unlock()
}

// Heard is when a frame last arrived from the peer; zero if none has.
func (c *Conn) Heard() time.Time {
	if n := c.heard.Load(); n != 0 {
		return time.Unix(0, n)
	}
	return time.Time{}
}

// KeepAlive pings the peer every interval until stop is called, or a ping
// cannot be sent, which closes the connection to wake its reader.
func (c *Conn) KeepAlive(every time.Duration) (stop func()) {
	done := make(chan struct{})
	var once sync.Once
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				if c.WriteFrame(OpPing, nil) != nil {
					_ = c.Close()
					return
				}
			}
		}
	}()
	return func() { once.Do(func() { close(done) }) }
}

// ExpireWrites fails every write from now on, including one already
// blocked, as a write deadline that has passed does.
func (c *Conn) ExpireWrites() {
	c.dmu.Lock()
	c.expired = true
	_ = c.conn.SetWriteDeadline(time.Unix(1, 0))
	c.dmu.Unlock()
}

// frame is the header of the frame being read; left and at track how much of
// its payload readBody has yet to deliver.
type frame struct {
	op     byte
	left   uint64
	masked bool
	mask   [4]byte
	at     int
	synth  []byte // the whole payload, already read: framed text frames
}

func (c *Conn) readHeader() (frame, error) {
	if c.framed {
		return c.readFramedHeader()
	}
	if rt := time.Duration(c.readTimeout.Load()); rt > 0 {
		_ = c.conn.SetReadDeadline(time.Now().Add(rt))
	}
	var b [8]byte
	var f frame
	if _, err := io.ReadFull(c.rd, b[:2]); err != nil {
		return f, err
	}
	c.heard.Store(time.Now().UnixNano())
	f.op = b[0] & 0x0F
	f.masked = b[1]&0x80 != 0
	if f.masked == c.client {
		if c.client {
			return f, errors.New("masked server frame")
		}
		return f, errors.New("unmasked client frame")
	}
	f.left = uint64(b[1] & 0x7F)
	switch f.left {
	case 126:
		if _, err := io.ReadFull(c.rd, b[:2]); err != nil {
			return f, err
		}
		f.left = uint64(binary.BigEndian.Uint16(b[:2]))
	case 127:
		if _, err := io.ReadFull(c.rd, b[:8]); err != nil {
			return f, err
		}
		f.left = binary.BigEndian.Uint64(b[:8])
	}
	if f.masked {
		if _, err := io.ReadFull(c.rd, f.mask[:]); err != nil {
			return f, err
		}
	}
	return f, nil
}

// readBody reads some of the frame's remaining payload into p.
func (c *Conn) readBody(f *frame, p []byte) (int, error) {
	if uint64(len(p)) > f.left {
		p = p[:f.left]
	}
	if rt := time.Duration(c.readTimeout.Load()); rt > 0 && !c.framed {
		_ = c.conn.SetReadDeadline(time.Now().Add(rt))
	}
	n, err := c.rd.Read(p)
	if f.masked {
		for i := 0; i < n; i++ {
			p[i] ^= f.mask[(f.at+i)%4]
		}
		f.at = (f.at + n) % 4
	}
	f.left -= uint64(n)
	if n > 0 {
		return n, nil
	}
	return 0, err
}

func (c *Conn) readPayload(f frame, max uint64) ([]byte, error) {
	if f.synth != nil {
		return f.synth, nil
	}
	if f.left > max {
		return nil, errors.New("frame too large")
	}
	payload := make([]byte, f.left)
	for off := 0; off < len(payload); {
		n, err := c.readBody(&f, payload[off:])
		if err != nil {
			return nil, err
		}
		off += n
	}
	return payload, nil
}

// Next returns the next text or binary frame. It answers pings, skips pongs
// and returns io.EOF when the peer closes.
func (c *Conn) Next(max uint64) (op byte, payload []byte, err error) {
	for {
		f, err := c.readHeader()
		if err != nil {
			return 0, nil, err
		}
		payload, err := c.readPayload(f, max)
		if err != nil {
			return 0, nil, err
		}
		switch f.op {
		case OpClose:
			_ = c.WriteFrame(OpClose, payload[:min(len(payload), 2)])
			return 0, nil, io.EOF
		case OpPing:
			if err := c.WriteFrame(OpPong, payload); err != nil {
				return 0, nil, err
			}
		case OpPong:
		default:
			return f.op, payload, nil
		}
	}
}

// ReadLoop answers pings and returns when the peer closes or errors.
func (c *Conn) ReadLoop() error {
	for {
		if _, _, err := c.Next(MaxSmallFrame); err != nil {
			return err
		}
	}
}
