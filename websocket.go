package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// A minimal RFC 6455 server (from pf-simple): enough for the console to push JSON text frames
// and to answer the browser's close and ping frames. The standard library
// has no WebSocket support and this avoids a dependency.

const (
	wsOpText  = 0x1
	wsOpClose = 0x8
	wsOpPing  = 0x9
	wsOpPong  = 0xA

	wsGUID           = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	wsMaxClientFrame = 4096 // the console never sends real data
	wsWriteTimeout   = 10 * time.Second
)

type wsConn struct {
	conn net.Conn
	rd   *bufio.Reader
	wmu  sync.Mutex
}

func headerHasToken(h http.Header, name, token string) bool {
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

func upgradeWebSocket(w http.ResponseWriter, r *http.Request) (*wsConn, error) {
	key := r.Header.Get("Sec-WebSocket-Key")
	if !headerHasToken(r.Header, "Connection", "upgrade") ||
		!headerHasToken(r.Header, "Upgrade", "websocket") ||
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
	sum := sha1.Sum([]byte(key + wsGUID))
	accept := base64.StdEncoding.EncodeToString(sum[:])
	_ = conn.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
	_, err = conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"))
	if err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return &wsConn{conn: conn, rd: rw.Reader}, nil
}

func (c *wsConn) writeFrame(op byte, payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	hdr := make([]byte, 0, 10)
	hdr = append(hdr, 0x80|op) // FIN; server frames are never masked
	switch n := len(payload); {
	case n < 126:
		hdr = append(hdr, byte(n))
	case n <= 0xFFFF:
		hdr = append(hdr, 126, byte(n>>8), byte(n))
	default:
		hdr = append(hdr, 127)
		hdr = binary.BigEndian.AppendUint64(hdr, uint64(n))
	}
	_ = c.conn.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
	if _, err := c.conn.Write(append(hdr, payload...)); err != nil {
		return err
	}
	return nil
}

// readLoop answers pings and returns when the client closes or errors.
func (c *wsConn) readLoop() error {
	var hdr [14]byte
	for {
		if _, err := io.ReadFull(c.rd, hdr[:2]); err != nil {
			return err
		}
		op := hdr[0] & 0x0F
		if hdr[1]&0x80 == 0 {
			return errors.New("unmasked client frame")
		}
		n := uint64(hdr[1] & 0x7F)
		switch n {
		case 126:
			if _, err := io.ReadFull(c.rd, hdr[2:4]); err != nil {
				return err
			}
			n = uint64(binary.BigEndian.Uint16(hdr[2:4]))
		case 127:
			if _, err := io.ReadFull(c.rd, hdr[2:10]); err != nil {
				return err
			}
			n = binary.BigEndian.Uint64(hdr[2:10])
		}
		if n > wsMaxClientFrame {
			return errors.New("client frame too large")
		}
		var mask [4]byte
		if _, err := io.ReadFull(c.rd, mask[:]); err != nil {
			return err
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(c.rd, payload); err != nil {
			return err
		}
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
		switch op {
		case wsOpClose:
			_ = c.writeFrame(wsOpClose, payload[:min(len(payload), 2)])
			return io.EOF
		case wsOpPing:
			if err := c.writeFrame(wsOpPong, payload); err != nil {
				return err
			}
		}
	}
}

func (c *wsConn) Close() error { return c.conn.Close() }
