package main

// Minimal TLS ClientHello parser: finds the SNI in the bytes received so far.

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

const maxClientHello = 64 * 1024

// Real ClientHellos normally occupy one record (occasionally a small handful).
// Bound this independently from their byte size: otherwise a valid-looking
// hello split into tiny records turns parsing and repeated incremental reads
// into disproportionate work.
const maxClientHelloRecords = 32

// errNeedMore means the ClientHello is not complete yet.
var errNeedMore = errors.New("need more data")

// helloInfo is what the proxy needs from a ClientHello.
type helloInfo struct {
	SNI  string   // lowercased; "" if absent
	ALPN []string // offered application protocols, e.g. "h2", "acme-tls/1"
}

func (h helloInfo) offers(proto string) bool {
	for _, p := range h.ALPN {
		if p == proto {
			return true
		}
	}
	return false
}

// parseClientHello returns just the SNI (see parseHello).
func parseClientHello(data []byte) (string, error) {
	h, err := parseHello(data)
	return h.SNI, err
}

// parseHello scans TLS records in data. It returns the SNI and ALPN list once
// the whole ClientHello has arrived, errNeedMore if it has not, or an error
// if this is not a valid ClientHello. The ClientHello may span several records.
func parseHello(data []byte) (helloInfo, error) {
	var handshake []byte
	rest := data
	for records := 0; ; records++ {
		if len(handshake) >= 4 {
			if handshake[0] != 0x01 {
				return helloInfo{}, fmt.Errorf("first handshake message is not ClientHello (type %d)", handshake[0])
			}
			msgLen := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
			if 4+msgLen > maxClientHello {
				return helloInfo{}, errors.New("ClientHello too large")
			}
			if len(handshake) >= 4+msgLen {
				return parseExtensions(handshake[4 : 4+msgLen])
			}
		}
		if len(rest) < 5 {
			if len(rest) > 0 && rest[0] != 0x16 {
				return helloInfo{}, fmt.Errorf("not a TLS handshake record (content type 0x%02x)", rest[0])
			}
			return helloInfo{}, errNeedMore
		}
		if rest[0] != 0x16 {
			return helloInfo{}, fmt.Errorf("not a TLS handshake record (content type 0x%02x)", rest[0])
		}
		if records >= maxClientHelloRecords {
			return helloInfo{}, fmt.Errorf("ClientHello spans more than %d TLS records", maxClientHelloRecords)
		}
		if rest[1] != 0x03 {
			return helloInfo{}, fmt.Errorf("unsupported TLS record version %02x%02x", rest[1], rest[2])
		}
		n := int(rest[3])<<8 | int(rest[4])
		if n == 0 {
			return helloInfo{}, errors.New("empty TLS record")
		}
		if len(data)-len(rest)+5+n > maxClientHello {
			return helloInfo{}, errors.New("ClientHello too large")
		}
		if len(rest) < 5+n {
			return helloInfo{}, errNeedMore
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

// parseExtensions parses a ClientHello body (after the 4-byte handshake
// header) for the server_name and ALPN extensions.
func parseExtensions(body []byte) (helloInfo, error) {
	var info helloInfo
	truncated := errors.New("truncated ClientHello")
	c := &cursor{b: body}
	c.take(2)  // legacy_version
	c.take(32) // random
	c.vec8()   // session_id
	c.vec16()  // cipher_suites
	c.vec8()   // compression_methods
	if c.bad {
		return info, truncated
	}
	if len(c.b) == 0 {
		return info, nil // no extensions at all
	}
	exts := &cursor{b: c.vec16()}
	if c.bad {
		return info, truncated
	}
	seenSNI := false
	for len(exts.b) > 0 {
		typ := exts.u16()
		data := exts.vec16()
		if exts.bad {
			return info, truncated
		}
		switch typ {
		case 0: // server_name
			if seenSNI {
				continue
			}
			seenSNI = true
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
					return info, fmt.Errorf("invalid SNI host name %q", name)
				}
				for _, b := range name {
					if !isHostChar(b) {
						return info, fmt.Errorf("invalid SNI host name %q", name)
					}
				}
				// RFC 6066: literal IP addresses are not permitted. Refusing them
				// also keeps target_host = $0 rules from being pointed at
				// arbitrary addresses by the client.
				if _, err := netip.ParseAddr(string(name)); err == nil {
					return info, fmt.Errorf("invalid SNI host name %q: an IP address is not a host name", name)
				}
				info.SNI = strings.ToLower(string(name))
				break
			}
			if list.bad || names.bad {
				return info, truncated
			}
		case 16: // application_layer_protocol_negotiation
			list := &cursor{b: data}
			protos := &cursor{b: list.vec16()}
			for !list.bad && len(protos.b) > 0 {
				p := protos.vec8()
				if protos.bad {
					break
				}
				info.ALPN = append(info.ALPN, string(p))
			}
			if list.bad || protos.bad {
				return info, truncated
			}
		}
	}
	return info, nil
}
