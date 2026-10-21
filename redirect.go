package main

// http_to_https_redirect: a listener on port 80 that answers every plain
// HTTP request with a redirect to the same URL on https://. It does not
// look at the rules: whatever the name, the client is sent to port 443,
// where the rules decide as for any other connection. Keep-alive is
// supported; a request with a body is answered and the connection closed.

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"
)

// RedirectListenerName is the redirect listener's name, reserved: no
// [[listener]] may use it.
const RedirectListenerName = "http-to-https-redirect"

// redirectKey is what the redirect listener's connections count under in the
// per-rule statistics, so the console lists them like a rule's.
const redirectKey = RedirectListenerName + "\x00redirect"

// redirectPattern is how the console shows that pseudo-rule.
const redirectPattern = "http://* → https://*"

// maxRedirectHeader caps the request line and headers of one request.
const maxRedirectHeader = 8 << 10

// After the last response, the request body the client may still be sending
// is read and dropped, at most this much for at most this long: closing with
// unread data makes the kernel reset the connection, and a client can then
// lose the response it has not read yet.
const (
	redirectLingerBytes = 256 << 10
	redirectLingerTime  = 2 * time.Second
)

// countingConn counts the bytes a redirect connection reads and writes into
// its connection's counters and the totals.
type countingConn struct {
	net.Conn
	c *ConnState
	s *Stats
}

func (cc *countingConn) Read(b []byte) (int, error) {
	n, err := cc.Conn.Read(b)
	if n > 0 {
		cc.c.BytesUp.Add(int64(n))
		cc.c.rule.BytesUp.Add(int64(n))
		cc.c.lstats.BytesUp.Add(int64(n))
		cc.s.BytesUp.Add(int64(n))
		cc.c.touch()
	}
	return n, err
}

func (cc *countingConn) Write(b []byte) (int, error) {
	n, err := cc.Conn.Write(b)
	if n > 0 {
		cc.c.BytesDown.Add(int64(n))
		cc.c.rule.BytesDown.Add(int64(n))
		cc.c.lstats.BytesDown.Add(int64(n))
		cc.s.BytesDown.Add(int64(n))
		cc.c.touch()
	}
	return n, err
}

// redirectHost is the Host header without its port, lowercased; false when
// it is missing or not a host name or IP address.
func redirectHost(h string) (string, bool) {
	if strings.HasPrefix(h, "[") {
		end := strings.IndexByte(h, ']')
		if end < 0 {
			return "", false
		}
		if a, err := netip.ParseAddr(h[1:end]); err != nil || !a.Is6() || a.Zone() != "" {
			return "", false
		}
		if rest := h[end+1:]; rest != "" && !validPort(rest) {
			return "", false
		}
		return strings.ToLower(h[:end+1]), true
	}
	if i := strings.IndexByte(h, ':'); i >= 0 {
		if !validPort(h[i:]) {
			return "", false
		}
		h = h[:i]
	}
	if h == "" {
		return "", false
	}
	for i := 0; i < len(h); i++ {
		if !isHostChar(h[i]) {
			return "", false
		}
	}
	return strings.ToLower(h), true
}

// validPort is ":" and up to five digits.
func validPort(s string) bool {
	if len(s) < 2 || len(s) > 6 || s[0] != ':' {
		return false
	}
	for i := 1; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// writeRedirectResponse writes a response without a body.
func writeRedirectResponse(w io.Writer, status int, location string, keepAlive bool) error {
	conn := "close"
	if keepAlive {
		conn = "keep-alive"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\nServer: %s\r\n", status, http.StatusText(status), serverName)
	if location != "" {
		fmt.Fprintf(&b, "Location: %s\r\n", location)
	}
	fmt.Fprintf(&b, "Content-Length: 0\r\nConnection: %s\r\n\r\n", conn)
	_, err := io.WriteString(w, b.String())
	return err
}

// handleRedirect serves one connection of the redirect listener.
func (s *Server) handleRedirect(id uint64, sock net.Conn, active int, cfg *Config) {
	defer sock.Close()
	start := time.Now()
	name := cfg.listener.Name
	physicalKey := sourceKey(sock.RemoteAddr())
	slot := s.beginHandshake(physicalKey, cfg.MaxHandshakesPerIP)
	if slot == nil {
		s.handshakeLog.logf("[#%d] rejected %s: %d connections from this source are still sending their first request (max_handshakes_per_ip)", id, sock.RemoteAddr(), cfg.MaxHandshakesPerIP)
		s.stats.Rejected.Add(1)
		s.stats.flows.refused(id, name, start, sock.RemoteAddr(), sock.LocalAddr(), "too many handshakes from this source (max_handshakes_per_ip)")
		return
	}
	s.stats.Accepted.Add(1)
	defer func() {
		if slot != nil {
			s.endHandshake(slot)
		}
	}()

	// As on the TLS listeners: a PROXY header only from proxy_trust_source.
	sock.SetReadDeadline(start.Add(cfg.HandshakeTimeout))
	client, err := &proxyConn{Conn: sock}, error(nil)
	if cfg.trustsProxySource(sock.RemoteAddr()) {
		client, err = detectProxyProtocol(sock)
	}
	if err != nil {
		s.stats.Failed.Add(1)
		logf("[#%d] closed src=%s: bad PROXY protocol header: %v after %s", id, sock.RemoteAddr(), err, humanDuration(time.Since(start)))
		s.stats.flows.refused(id, name, start, sock.RemoteAddr(), sock.LocalAddr(), "bad PROXY protocol header: "+err.Error())
		return
	}
	if proxiedKey := sourceKey(client.RemoteAddr()); proxiedKey != physicalKey {
		proxiedSlot := s.beginHandshake(proxiedKey, cfg.MaxHandshakesPerIP)
		if proxiedSlot == nil {
			s.handshakeLog.logf("[#%d] rejected %s: %d connections from this source are still sending their first request (max_handshakes_per_ip)", id, client.RemoteAddr(), cfg.MaxHandshakesPerIP)
			s.stats.Accepted.Add(-1)
			s.stats.Rejected.Add(1)
			s.stats.flows.refused(id, name, start, client.RemoteAddr(), client.LocalAddr(), "too many handshakes from this source (max_handshakes_per_ip)")
			return
		}
		s.endHandshake(slot)
		slot = proxiedSlot
	}
	src := client.RemoteAddr().String()
	logf("[#%d] accepted from %s on %s (active=%d)", id, src, name, active)

	c := &ConnState{ID: id, Src: src, Local: client.LocalAddr().String(), Start: start, Listener: name, lstats: s.stats.listener(name),
		RuleKey: redirectKey, rulePattern: redirectPattern, rule: s.stats.rule(redirectKey)}
	c.lastActivityUnixNano.Store(start.UnixNano())
	if client.version > 0 {
		c.how.Via, c.how.ViaVersion = sock.RemoteAddr().String(), client.version
	}
	c.how.TLS = "http"
	c.rule.Active.Add(1)
	c.rule.Total.Add(1)
	defer c.rule.Active.Add(-1)
	s.stats.register(c)
	defer s.stats.unregister(c)

	var killed atomic.Pointer[string]
	c.setKill(func(reason string) {
		killed.CompareAndSwap(nil, &reason)
		sock.Close()
	})

	conn := &countingConn{Conn: client, c: c, s: s.stats}
	limited := &io.LimitedReader{R: conn}
	br := bufio.NewReader(limited)
	requests := 0
	answered := false // the last thing done was a response, and the connection is to close
	result, reason := flowClosed, ""
	for {
		if requests > 0 {
			if cfg.IdleTimeout > 0 {
				sock.SetReadDeadline(time.Now().Add(cfg.IdleTimeout))
			} else {
				sock.SetReadDeadline(time.Time{})
			}
		}
		limited.N = maxRedirectHeader
		req, err := http.ReadRequest(br)
		if slot != nil {
			s.endHandshake(slot)
			slot = nil
		}
		if err != nil {
			status := 0
			switch {
			case killed.Load() != nil:
				reason = *killed.Load()
			case isTimeout(err) && requests == 0:
				result, reason = flowFailed, fmt.Sprintf("no HTTP request within %s", humanDuration(cfg.HandshakeTimeout))
			case isTimeout(err):
				reason = fmt.Sprintf("idle for %s after %d request(s)", humanDuration(cfg.IdleTimeout), requests)
			case limited.N == 0:
				result, reason, status = flowFailed, fmt.Sprintf("request header larger than %d bytes", maxRedirectHeader), http.StatusRequestHeaderFieldsTooLarge
			case errors.Is(err, io.EOF) && requests > 0:
				reason = fmt.Sprintf("client closed after %d request(s)", requests)
			case errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed):
				result, reason = flowFailed, fmt.Sprintf("closed before a whole HTTP request (%d request(s) before)", requests)
			default:
				result, reason, status = flowFailed, fmt.Sprintf("bad HTTP request: %v", err), http.StatusBadRequest
			}
			if status != 0 {
				sock.SetWriteDeadline(time.Now().Add(cfg.HandshakeTimeout))
				answered = writeRedirectResponse(conn, status, "", false) == nil
			}
			break
		}
		requests++
		host, ok := redirectHost(req.Host)
		if !ok || req.RequestURI == "*" {
			result, reason = flowFailed, fmt.Sprintf("cannot redirect %s %s (Host: %q)", req.Method, req.RequestURI, req.Host)
			logf("[#%d] redirect %s %s Host=%q from %s: 400, no usable host or path", id, req.Method, req.RequestURI, req.Host, src)
			sock.SetWriteDeadline(time.Now().Add(cfg.HandshakeTimeout))
			answered = writeRedirectResponse(conn, http.StatusBadRequest, "", false) == nil
			break
		}
		location := "https://" + host + req.URL.RequestURI()
		status := http.StatusMovedPermanently
		if req.Method != http.MethodGet && req.Method != http.MethodHead {
			status = http.StatusPermanentRedirect // keeps the method and body
		}
		// A body is not read: answer, then close (the client may resend it
		// to the new location; with Expect: 100-continue it never sends it).
		keepAlive := !req.Close && req.ContentLength == 0 && len(req.TransferEncoding) == 0
		c.mu.Lock()
		changed := c.SNI != host
		c.SNI, c.Dst, c.routed = host, "https://"+host, true
		c.mu.Unlock()
		if changed {
			s.stats.flows.emit("route", c)
		}
		sock.SetWriteDeadline(time.Now().Add(cfg.HandshakeTimeout))
		err = writeRedirectResponse(conn, status, location, keepAlive)
		logf("[#%d] redirect %s http://%s%s -> %s (%d)", id, req.Method, req.Host, req.RequestURI, location, status)
		if err != nil {
			result, reason = flowFailed, fmt.Sprintf("write error after %d request(s): %v", requests, err)
			break
		}
		if !keepAlive {
			reason, answered = fmt.Sprintf("redirected %d request(s)", requests), true
			break
		}
	}
	if answered && killed.Load() == nil {
		if cw, ok := sock.(interface{ CloseWrite() error }); ok && cw.CloseWrite() == nil {
			sock.SetReadDeadline(time.Now().Add(redirectLingerTime))
			limited.N = redirectLingerBytes
			io.Copy(io.Discard, br) // what br holds, then at most limited.N more
		}
	}
	if result == flowClosed {
		s.stats.Completed.Add(1)
	} else {
		s.stats.Failed.Add(1)
	}
	c.setEnd(result, reason)
	logf("[#%d] closed src=%s on %s requests=%d up=%s down=%s duration=%s reason=%s", id, src, name, requests,
		humanBytes(c.BytesUp.Load()), humanBytes(c.BytesDown.Load()), humanDuration(time.Since(start)), reason)
}
