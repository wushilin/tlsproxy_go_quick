// Package quictun holds what the hub and pfrelayquic share of protocol 3,
// the QUIC transport (docs/PROTOCOL.md §13): the QUIC settings, the
// pinned certificate, the request and answer messages, the error codes, and
// a QUIC stream as a net.Conn for tunnel.NewFramed.
//
// Only the hub and pfrelayquic import it, so pf-client and pfrelay never
// carry the QUIC library.
package quictun

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// ALPN is the one ALPN protocol of the QUIC listener (§13.3).
const ALPN = "pf-tunnel"

// Proto is the protocol spoken over QUIC. It is negotiated in each
// request's "proto" field, over QUIC only: the WebSocket endpoints speak
// protocols 0 to 2 and know nothing of it. A client of one transport works
// with a client of the other through the hub, which bridges them.
const Proto = 3

// Error codes on RESET_STREAM, STOP_SENDING and CONNECTION_CLOSE (§13.7).
// They are for logs: nothing is decided from them.
const (
	CodeNone           = 0x0
	CodeBroken         = 0x1
	CodeRefused        = 0x2
	CodeProtocol       = 0x3
	CodeRequestTimeout = 0x4
	CodeCancelled      = 0x5
	CodeGoingAway      = 0x6
	CodeLimit          = 0x7
)

// Ends of a registration, in the hub's "end" message (§13.4).
const (
	EndTakeover = "takeover"
	EndTenant   = "tenant"
	EndOff      = "off"
	EndShutdown = "shutdown"
)

// Timing and sizes; variables so tests can shorten them.
var (
	IdleTimeout = 30 * time.Second // max_idle_timeout (§13.6)
	KeepAlive   = 10 * time.Second
	// RequestWait bounds the reading of a request, an open, or an answer
	// the hub owes (§13.4). AnswerWait is the client's wait for the hub.
	RequestWait = 10 * time.Second
	AnswerWait  = 15 * time.Second
	// DeliverWait is how long an end keeps a stream after its err, end or
	// refusal, for the peer to end its direction (§13.5).
	DeliverWait = 3 * time.Second
)

const (
	MaxMessage      = 4096
	StreamWindow    = 64 << 10 // the least stream receive window (§13.3)
	MaxStreamWindow = 1 << 20  // what a stream window may grow to
	// PreAuthWindow is the hub's connection window before the connection's
	// first successful request; ConnWindow is what it may grow to after.
	PreAuthWindow = 256 << 10
	ConnWindow    = 16 << 20
	MaxStreams    = 1000
)

// Config is the QUIC configuration both ends use, before the hub's own
// additions: QUIC version 1 only, the idle timeout and keepalive of §13.6,
// no 0-RTT, no unidirectional streams, no datagrams.
func Config() *quic.Config {
	return &quic.Config{
		Versions:                       []quic.Version{quic.Version1},
		HandshakeIdleTimeout:           10 * time.Second,
		MaxIdleTimeout:                 IdleTimeout,
		KeepAlivePeriod:                KeepAlive,
		InitialStreamReceiveWindow:     StreamWindow,
		MaxStreamReceiveWindow:         MaxStreamWindow,
		InitialConnectionReceiveWindow: PreAuthWindow,
		MaxConnectionReceiveWindow:     ConnWindow,
		MaxIncomingStreams:             MaxStreams,
		MaxIncomingUniStreams:          -1,
		Allow0RTT:                      false,
	}
}

// ClientConfig is Config for a client. Its connection window starts at
// ConnWindow, not at the hub's PreAuthWindow: quic-go counts what a stream
// has received and the application has not read against the connection
// window, so a small one lets a few stalled streams stop the hub from
// sending anything else on the connection, its answers and opens included
// (§13.3: one stalled stream must not starve the others). ConnWindow is 16
// times the largest stream window, as §13.3 asks.
func ClientConfig() *quic.Config {
	c := Config()
	c.InitialConnectionReceiveWindow = ConnWindow
	c.MaxConnectionReceiveWindow = ConnWindow
	return c
}

// ---------- the certificate ----------

// Fingerprint is the lowercase hex SHA-256 of a certificate's DER encoding.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// CertLifetime is how long a certificate NewCertificate makes is valid.
var CertLifetime = 60 * 24 * time.Hour

// NewCertificate makes the hub's self-signed certificate (§13.3): X.509 v3,
// ECDSA P-256, with host as its subject alternative name, valid for
// CertLifetime. It returns the certificate and key in PEM.
func NewCertificate(host string) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		// Only the advertised host, so the certificate tells nobody what
		// serves it (§13.3).
		Subject:               pkix.Name{CommonName: strings.TrimSpace(host)},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(CertLifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if host = strings.TrimSpace(host); host != "" {
		if ip := net.ParseIP(host); ip != nil {
			tmpl.IPAddresses = []net.IP{ip}
		} else {
			tmpl.DNSNames = []string{host}
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), nil
}

// ServerTLS is the hub's TLS configuration: its certificate, ALPN, TLS 1.3,
// and no session tickets, so every handshake shows the certificate (§13.3).
func ServerTLS(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates:           []tls.Certificate{cert},
		NextProtos:             []string{ALPN},
		MinVersion:             tls.VersionTLS13,
		SessionTicketsDisabled: true,
		CurvePreferences:       []tls.CurveID{tls.X25519, tls.CurveP256},
	}
}

// ErrPinMismatch is a hub certificate that is not one of the discovered
// fingerprints.
var ErrPinMismatch = errors.New("the hub's QUIC certificate does not match what its HTTPS endpoint announced")

// ClientTLS pins the hub's certificate to fingerprints. Only the chain, the
// name and the dates go unchecked: crypto/tls still verifies the handshake
// signature with the pinned certificate's key. No SNI for an IP host, and
// no session cache, so no resumption.
func ClientTLS(host string, fingerprints []string) *tls.Config {
	want := make(map[string]bool, len(fingerprints))
	for _, f := range fingerprints {
		want[strings.ToLower(f)] = true
	}
	sni := host
	if net.ParseIP(host) != nil {
		sni = ""
	}
	return &tls.Config{
		ServerName:         sni,
		NextProtos:         []string{ALPN},
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // replaced by the pin below
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 || !want[Fingerprint(raw[0])] {
				return ErrPinMismatch
			}
			return nil
		},
	}
}

// ---------- discovery (§13.2) ----------

// Discovery is the answer of GET /pf/api/tunnel/quic.
type Discovery struct {
	Host         string   `json:"host"`
	Port         int      `json:"port"`
	Fingerprints []string `json:"fingerprints"`
}

// Check reports what is wrong with a discovery answer, if anything.
func (d *Discovery) Check() error {
	switch {
	case d.Host == "" || strings.ContainsAny(d.Host, "[]/ "):
		return fmt.Errorf("the hub advertised a bad QUIC host %q", d.Host)
	case d.Port < 1 || d.Port > 65535:
		return fmt.Errorf("the hub advertised a bad QUIC port %d", d.Port)
	case len(d.Fingerprints) < 1 || len(d.Fingerprints) > 4:
		return errors.New("the hub advertised no usable certificate fingerprints")
	}
	for _, f := range d.Fingerprints {
		if b, err := hex.DecodeString(f); err != nil || len(b) != sha256.Size {
			return fmt.Errorf("the hub advertised a bad certificate fingerprint %q", f)
		}
	}
	return nil
}

// Addr is host:port to dial.
func (d *Discovery) Addr() string { return net.JoinHostPort(d.Host, fmt.Sprint(d.Port)) }

// ---------- messages (§13.4) ----------

// Request is a client's request on a stream it opens.
type Request struct {
	Op                string `json:"op"`
	Proto             string `json:"proto"`
	Version           string `json:"version,omitempty"`
	Word              string `json:"word,omitempty"`
	ServeToken        string `json:"serveToken,omitempty"`
	Name              string `json:"name,omitempty"`
	Target            string `json:"target,omitempty"`
	ClientTokenSHA256 string `json:"clientTokenSHA256,omitempty"`
	ClientToken       string `json:"clientToken,omitempty"`
}

// Answer is the hub's answer to a request, and a serving side's answer to
// an open.
type Answer struct {
	Status     int    `json:"status"`
	Proto      int    `json:"proto,omitempty"`
	Error      string `json:"error,omitempty"`
	Reg        string `json:"reg,omitempty"`
	Conn       string `json:"conn,omitempty"`
	RetryAfter int    `json:"retryAfter,omitempty"`
	Scope      string `json:"scope,omitempty"`
}

// Open is the hub's first message on a stream it opens to a serving side.
type Open struct {
	Open string `json:"open"`
	Reg  string `json:"reg"`
}

// End is the hub's last message on a serve stream.
type End struct {
	End   string `json:"end"`
	Error string `json:"error,omitempty"`
}

// ErrMessage is a message that breaks the protocol: too long, cut short,
// or not a JSON object.
var ErrMessage = errors.New("a malformed message")

// WriteMessage writes v as one message: a 2-byte length, then JSON.
func WriteMessage(w io.Writer, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(body) > MaxMessage {
		return ErrMessage
	}
	buf := binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(body)), uint16(len(body)))
	_, err = w.Write(append(buf, body...))
	return err
}

// ReadRaw reads one message without decoding it, reading exactly its bytes
// and nothing after, so the frames that follow are left for the framed
// Conn.
func ReadRaw(r io.Reader) ([]byte, error) {
	var n [2]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		if err == io.ErrUnexpectedEOF {
			return nil, ErrMessage
		}
		return nil, err
	}
	size := int(binary.BigEndian.Uint16(n[:]))
	if size > MaxMessage {
		return nil, ErrMessage
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(r, body); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return nil, ErrMessage
		}
		return nil, err
	}
	if !bytes.HasPrefix(bytes.TrimSpace(body), []byte("{")) {
		return nil, ErrMessage
	}
	return body, nil
}

// ReadMessage reads one message into v.
func ReadMessage(r io.Reader, v any) error {
	body, err := ReadRaw(r)
	if err != nil {
		return err
	}
	if json.Unmarshal(body, v) != nil {
		return ErrMessage
	}
	return nil
}

// ---------- a QUIC stream as a net.Conn ----------

// StreamConn is a QUIC stream as tunnel.NewFramed wants it: CloseWrite sends
// FIN; Close ends both directions as §13.5 asks.
type StreamConn struct {
	*quic.Stream
	local, remote net.Addr
	lingers       *Lingers
	mu            sync.Mutex
	finned        bool
	closed        bool
	readDone      chan struct{} // closed once a read saw the peer's direction end
	readOnce      sync.Once
	// OnDone, if set before the stream is used, is called once when the
	// stream has ended both ways: after a reset, or after the linger.
	OnDone   func()
	doneOnce sync.Once
}

func (c *StreamConn) ended() {
	c.doneOnce.Do(func() {
		if c.OnDone != nil {
			c.OnDone()
		}
	})
}

// NewStreamConn wraps s, a stream of conn. lingers, if not nil, counts the
// stream while it waits for the peer after this side's FIN.
func NewStreamConn(s *quic.Stream, conn *quic.Conn, lingers *Lingers) *StreamConn {
	return &StreamConn{Stream: s, local: conn.LocalAddr(), remote: conn.RemoteAddr(), lingers: lingers, readDone: make(chan struct{})}
}

func (c *StreamConn) LocalAddr() net.Addr  { return c.local }
func (c *StreamConn) RemoteAddr() net.Addr { return c.remote }

// Read reads from the stream, and notes when the peer's direction has ended
// (FIN or RESET_STREAM), so that Close need not wait for it.
func (c *StreamConn) Read(p []byte) (int, error) {
	n, err := c.Stream.Read(p)
	if err != nil && !isTimeout(err) {
		c.readOnce.Do(func() { close(c.readDone) })
	}
	return n, err
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// CloseWrite sends FIN.
func (c *StreamConn) CloseWrite() error {
	c.mu.Lock()
	c.finned = true
	c.mu.Unlock()
	return c.Stream.Close()
}

// Close ends the stream. After FIN it gives the peer DeliverWait to end its
// own direction, so what was sent last (an err, an end) is not dropped,
// then stops reading. Without FIN, it resets both directions at once.
func (c *StreamConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	finned := c.finned
	c.mu.Unlock()
	if !finned {
		c.Reset(CodeCancelled)
		c.ended()
		return nil
	}
	done := c.lingers.Add()
	go func() {
		t := time.NewTimer(DeliverWait)
		defer t.Stop()
		select {
		case <-c.readDone: // the peer ended its direction
		case <-t.C:
			c.Stream.CancelRead(CodeCancelled)
		}
		done()
		c.ended()
	}()
	return nil
}

// Reset ends both directions at once with code (§13.5).
func (c *StreamConn) Reset(code quic.StreamErrorCode) {
	c.Stream.CancelWrite(code)
	c.Stream.CancelRead(code)
}

// Broken ends both directions at once because the peer broke the protocol
// (§13.5): tunnel.Stream calls it, for instance, for a second eof.
func (c *StreamConn) Broken() {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	c.Reset(CodeProtocol)
	c.ended()
}

// Lingers counts the streams that wait, after this side's FIN, for the peer
// to end its direction (§13.5, "Delivering a reason"), so that a client
// closing its connection can let them finish first. The zero value is
// ready; a nil *Lingers counts nothing.
type Lingers struct {
	mu   sync.Mutex
	n    int
	zero chan struct{} // closed when n drops to 0; nil while n is 0
}

// Add counts one stream; the returned func ends its count, once.
func (l *Lingers) Add() func() {
	if l == nil {
		return func() {}
	}
	l.mu.Lock()
	l.n++
	if l.zero == nil {
		l.zero = make(chan struct{})
	}
	l.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			l.n--
			if l.n == 0 {
				close(l.zero)
				l.zero = nil
			}
			l.mu.Unlock()
		})
	}
}

// Wait waits until no stream lingers, or for at most d.
func (l *Lingers) Wait(d time.Duration) {
	if l == nil {
		return
	}
	l.mu.Lock()
	zero := l.zero
	l.mu.Unlock()
	if zero == nil {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-zero:
	case <-t.C:
	}
}

// Finish ends a stream on which only messages were sent: FIN, then, after
// the peer ended its direction or DeliverWait, stop reading. It reads and
// discards what comes meanwhile.
func Finish(s *quic.Stream) { FinishCounted(s, nil) }

// FinishCounted is Finish, with the stream counted in lingers until it ends.
func FinishCounted(s *quic.Stream, lingers *Lingers) {
	_ = s.Close()
	Drain(s, lingers)
}

// Drain reads and discards what the peer still sends, until it ends its
// direction or DeliverWait passes, then stops reading. The stream is
// counted in lingers meanwhile.
func Drain(s *quic.Stream, lingers *Lingers) {
	done := lingers.Add()
	go func() {
		defer done()
		_ = s.SetReadDeadline(time.Now().Add(DeliverWait))
		_, _ = io.Copy(io.Discard, s)
		s.CancelRead(CodeCancelled)
	}()
}

// Refuse ends a client stream after a refusal: FIN, and STOP_SENDING for
// whatever the client sent after its request (§13.5).
func Refuse(s *quic.Stream) {
	_ = s.Close()
	s.CancelRead(CodeRefused)
}
