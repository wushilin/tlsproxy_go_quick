package main

// Minimal TLS ClientHello parser: finds the SNI in the bytes received so far.

import (
	"errors"
	"fmt"
	"strings"
)

const maxClientHello = 64 * 1024

// errNeedMore means the ClientHello is not complete yet.
var errNeedMore = errors.New("need more data")

// parseClientHello scans TLS records in data. It returns the lowercased SNI
// ("" if absent) once the whole ClientHello has arrived, errNeedMore if it
// has not, or an error if this is not a valid ClientHello. The ClientHello
// may span several records.
func parseClientHello(data []byte) (string, error) {
	var handshake []byte
	rest := data
	for records := 0; ; records++ {
		if len(handshake) >= 4 {
			if handshake[0] != 0x01 {
				return "", fmt.Errorf("first handshake message is not ClientHello (type %d)", handshake[0])
			}
			msgLen := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
			if 4+msgLen > maxClientHello {
				return "", errors.New("ClientHello too large")
			}
			if len(handshake) >= 4+msgLen {
				return parseSNI(handshake[4 : 4+msgLen])
			}
		}
		if len(rest) < 5 {
			if len(rest) > 0 && rest[0] != 0x16 {
				return "", fmt.Errorf("not a TLS handshake record (content type 0x%02x)", rest[0])
			}
			return "", errNeedMore
		}
		if rest[0] != 0x16 {
			return "", fmt.Errorf("not a TLS handshake record (content type 0x%02x)", rest[0])
		}
		if rest[1] != 0x03 {
			return "", fmt.Errorf("unsupported TLS record version %02x%02x", rest[1], rest[2])
		}
		n := int(rest[3])<<8 | int(rest[4])
		if n == 0 {
			return "", errors.New("empty TLS record")
		}
		if len(data)-len(rest)+5+n > maxClientHello {
			return "", errors.New("ClientHello too large")
		}
		if len(rest) < 5+n {
			return "", errNeedMore
		}
		if records == 0 {
			handshake = rest[5 : 5+n] // common case: no copy
		} else {
			handshake = append(append([]byte(nil), handshake...), rest[5:5+n]...)
		}
		rest = rest[5+n:]
	}
}

// cursor is a bounds-checked reader over a byte slice.
type cursor struct {
	b   []byte
	bad bool
}

func (c *cursor) take(n int) []byte {
	if c.bad || len(c.b) < n {
		c.bad = true
		return nil
	}
	out := c.b[:n]
	c.b = c.b[n:]
	return out
}

func (c *cursor) u8() int {
	if b := c.take(1); b != nil {
		return int(b[0])
	}
	return 0
}

func (c *cursor) u16() int {
	if b := c.take(2); b != nil {
		return int(b[0])<<8 | int(b[1])
	}
	return 0
}

func (c *cursor) vec8() []byte  { return c.take(c.u8()) }
func (c *cursor) vec16() []byte { return c.take(c.u16()) }

// parseSNI parses a ClientHello body (after the 4-byte handshake header).
func parseSNI(body []byte) (string, error) {
	c := &cursor{b: body}
	c.take(2)  // legacy_version
	c.take(32) // random
	c.vec8()   // session_id
	c.vec16()  // cipher_suites
	c.vec8()   // compression_methods
	if c.bad {
		return "", errors.New("truncated ClientHello")
	}
	if len(c.b) == 0 {
		return "", nil // no extensions at all
	}
	exts := &cursor{b: c.vec16()}
	if c.bad {
		return "", errors.New("truncated ClientHello")
	}
	for len(exts.b) > 0 {
		typ := exts.u16()
		data := exts.vec16()
		if exts.bad {
			return "", errors.New("truncated ClientHello")
		}
		if typ != 0 { // server_name
			continue
		}
		list := &cursor{b: data}
		names := &cursor{b: list.vec16()}
		for !list.bad && len(names.b) > 0 {
			nameType := names.u8()
			name := names.vec16()
			if names.bad {
				break
			}
			if nameType != 0 {
				continue
			}
			if len(name) == 0 || len(name) > 253 {
				return "", fmt.Errorf("invalid SNI host name %q", name)
			}
			for _, b := range name {
				if !isHostChar(b) {
					return "", fmt.Errorf("invalid SNI host name %q", name)
				}
			}
			return strings.ToLower(string(name)), nil
		}
		if list.bad || names.bad {
			return "", errors.New("truncated ClientHello")
		}
		return "", nil
	}
	return "", nil
}
