package tunnel

import (
	"bufio"
	"errors"
	"io"
	"net"
	"time"
	"unicode/utf8"
)

// Protocol 3 carries streams over QUIC (docs/PROTOCOL.md §13.5).
// Its frames are the WebSocket stream's frames in another encoding:
//
//	type (1 byte)  length (2 bytes, big-endian)  payload
//	0x00 data      0 to 65535                    the next bytes
//	0x01 eof       0                             the sender's half-close
//	0x02 err       1 to 1024                     why the stream is dropped
//
// and the stream's FIN takes the place of the WebSocket close. A Conn made
// by NewFramed speaks this encoding, so a Stream on it works exactly as on
// a WebSocket: data, "eof", "err:why" and the close map one to one. There
// are no pings: QUIC keeps the connection alive, not the stream.
//
// This package does not import a QUIC library; the caller hands in the
// QUIC stream as a net.Conn whose CloseWrite sends FIN and whose Close ends
// both directions.

const (
	frameData = 0x00
	frameEOF  = 0x01
	frameErr  = 0x02

	maxFramedData = 0xFFFF
	maxFramedErr  = 1024

	// NoReason is what an empty "err:" from a WebSocket becomes: a framed
	// err is never empty.
	NoReason = "the peer gave no reason"

	// ClosedEarly is the reason a protocol 3 stream is failed with when it
	// is closed after this side's half-close but before the far end's.
	ClosedEarly = "the connection was closed before the far end finished"
)

// CloseWriter is a connection that can half-close: a QUIC stream's FIN.
type CloseWriter interface {
	net.Conn
	CloseWrite() error
}

// NewFramed makes a Conn of a QUIC stream that has passed its request and
// answer (§13.4). Nothing may have been read from c through a buffer.
func NewFramed(c CloseWriter) *Conn {
	return &Conn{conn: c, rd: bufio.NewReader(c), framed: true}
}

// broken ends a protocol 3 stream whose peer broke the protocol: both
// directions reset ("protocol", §13.5) where the stream can say so.
func (c *Conn) broken() {
	if b, ok := c.conn.(interface{ Broken() }); ok {
		b.Broken()
		return
	}
	_ = c.conn.Close()
}

// Framed reports whether c is a protocol 3 stream.
func (c *Conn) Framed() bool { return c.framed }

// readFramedHeader reads the next frame. FIN at a frame boundary is the
// close; FIN inside a frame breaks the stream. A text frame comes back with
// its whole payload, as the WebSocket text frame it stands for.
func (c *Conn) readFramedHeader() (frame, error) {
	for {
		var b [3]byte
		n, err := io.ReadFull(c.rd, b[:])
		if n == 0 && err == io.EOF {
			return frame{op: OpClose, synth: []byte{}}, nil
		}
		if err == io.ErrUnexpectedEOF {
			return frame{}, errors.New("the stream ended inside a frame")
		}
		if err != nil {
			return frame{}, err
		}
		c.heard.Store(time.Now().UnixNano())
		size := uint64(b[1])<<8 | uint64(b[2])
		switch b[0] {
		case frameData:
			return frame{op: OpBinary, left: size}, nil
		case frameEOF:
			if size != 0 {
				return frame{}, errors.New("an eof frame with a payload")
			}
			return frame{op: OpText, synth: []byte(msgEOF)}, nil
		case frameErr:
			if size == 0 || size > maxFramedErr {
				return frame{}, errors.New("an err frame of a bad length")
			}
			reason := make([]byte, size)
			if _, err := io.ReadFull(c.rd, reason); err != nil {
				return frame{}, errors.New("the stream ended inside a frame")
			}
			return frame{op: OpText, synth: append([]byte(msgErrPrefix), reason...)}, nil
		default: // unknown: skipped by its length (§13.5)
			if _, err := io.CopyN(io.Discard, c.rd, int64(size)); err != nil {
				return frame{}, errors.New("the stream ended inside a frame")
			}
		}
	}
}

// writeFramed writes what WriteFrame was asked for, in protocol 3's
// encoding. Called under wmu.
func (c *Conn) writeFramed(op byte, payload []byte) error {
	switch op {
	case OpBinary, OpCont:
		for {
			n := min(len(payload), maxFramedData)
			if err := c.writeRaw(frameData, payload[:n]); err != nil {
				return err
			}
			payload = payload[n:]
			if len(payload) == 0 {
				return nil
			}
		}
	case OpText:
		msg := string(payload)
		if msg == msgEOF {
			return c.writeRaw(frameEOF, nil)
		}
		if reason, ok := cutErr(msg); ok {
			return c.writeRaw(frameErr, []byte(reason))
		}
		return nil // nothing else is said on a framed stream
	case OpClose:
		c.armWrite()
		return c.conn.(CloseWriter).CloseWrite()
	}
	return nil // pings and pongs: QUIC keeps the connection alive
}

// cutErr returns the reason of an "err:" message, never empty, cut at a
// UTF-8 boundary to fit a framed err.
func cutErr(msg string) (string, bool) {
	if len(msg) < len(msgErrPrefix) || msg[:len(msgErrPrefix)] != msgErrPrefix {
		return "", false
	}
	reason := msg[len(msgErrPrefix):]
	if reason == "" {
		reason = NoReason
	}
	for len(reason) > maxFramedErr {
		_, size := utf8.DecodeLastRuneInString(reason)
		reason = reason[:len(reason)-size]
	}
	return reason, true
}

func (c *Conn) writeRaw(typ byte, payload []byte) error {
	buf := append(c.wbuf[:0], typ, byte(len(payload)>>8), byte(len(payload)))
	buf = append(buf, payload...)
	c.wbuf = buf
	c.armWrite()
	_, err := c.conn.Write(buf)
	return err
}
