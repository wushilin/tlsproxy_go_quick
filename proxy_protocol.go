package main

// PROXY protocol v1/v2, both ways.
//
// Outbound (a rule's proxy = true): the client's address and the address it
// connected to are sent to the target before anything else, the ClientHello
// or our own upstream TLS handshake included.
//
// Inbound (from peers listed in proxy_protocol_from only): a header in front
// of the ClientHello is consumed, and the addresses it states replace the
// socket's. A connection from such a peer which does not start with either
// complete signature is passed on byte-for-byte unchanged.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

const (
	proxyV1Prefix = "PROXY "
	proxyV1MaxLen = 108 // including the terminating CRLF
	proxyV2Sig    = "\r\n\r\n\x00\r\nQUIT\n"
)

// writeProxyProtocol writes the connection's original endpoints in the
// selected PROXY protocol version. It must be called before anything else is
// written to the upstream connection (including an upstream TLS handshake).
func writeProxyProtocol(conn net.Conn, version int, src, dst net.Addr) error {
	header, err := proxyProtocolHeader(version, src, dst)
	if err != nil {
		return err
	}
	for len(header) > 0 {
		n, err := conn.Write(header)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		header = header[n:]
	}
	return nil
}

func proxyProtocolHeader(version int, src, dst net.Addr) ([]byte, error) {
	s, sok := src.(*net.TCPAddr)
	d, dok := dst.(*net.TCPAddr)
	if !sok || !dok {
		return nil, fmt.Errorf("PROXY protocol needs TCP endpoints, got %T and %T", src, dst)
	}
	sip, sok := netip.AddrFromSlice(s.IP)
	dip, dok := netip.AddrFromSlice(d.IP)
	if !sok || !dok || s.Port < 0 || s.Port > 65535 || d.Port < 0 || d.Port > 65535 {
		return nil, errors.New("PROXY protocol has an invalid TCP endpoint")
	}
	sip, dip = sip.Unmap(), dip.Unmap()
	if sip.Is4() != dip.Is4() {
		// One header states one family. Mixed endpoints (an inbound header for
		// an IPv6 client on an IPv4 hop, say) are written as IPv6, the IPv4 one
		// in its IPv4-mapped form (::ffff:a.b.c.d), rather than refused.
		sip, dip = netip.AddrFrom16(sip.As16()), netip.AddrFrom16(dip.As16())
	}

	switch version {
	case 1:
		family := "TCP6"
		if sip.Is4() {
			family = "TCP4"
		}
		return []byte(fmt.Sprintf("PROXY %s %s %s %d %d\r\n", family, sip, dip, s.Port, d.Port)), nil
	case 2:
		header := append([]byte(proxyV2Sig), 0x21, 0)
		if sip.Is4() {
			header[13] = 0x11 // INET + STREAM
			header = binary.BigEndian.AppendUint16(header, 12)
			header = append(header, sip.AsSlice()...)
			header = append(header, dip.AsSlice()...)
		} else {
			header[13] = 0x21 // INET6 + STREAM
			header = binary.BigEndian.AppendUint16(header, 36)
			header = append(header, sip.AsSlice()...)
			header = append(header, dip.AsSlice()...)
		}
		header = binary.BigEndian.AppendUint16(header, uint16(s.Port))
		header = binary.BigEndian.AppendUint16(header, uint16(d.Port))
		return header, nil
	default:
		return nil, fmt.Errorf("unsupported PROXY protocol version %d", version)
	}
}

// proxyConn supplies the address asserted by a valid PROXY header and replays
// bytes consumed while deciding that an ordinary connection was not PROXY.
// Embedding net.Conn preserves deadlines; CloseWrite is forwarded for relay's
// half-close handling.
type proxyConn struct {
	net.Conn
	prefix []byte
	remote net.Addr
	local  net.Addr // the destination the header states: where the client really connected
}

func (c *proxyConn) Read(p []byte) (int, error) {
	if len(c.prefix) != 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

func (c *proxyConn) RemoteAddr() net.Addr {
	if c.remote != nil {
		return c.remote
	}
	return c.Conn.RemoteAddr()
}

func (c *proxyConn) LocalAddr() net.Addr {
	if c.local != nil {
		return c.local
	}
	return c.Conn.LocalAddr()
}

func (c *proxyConn) CloseWrite() error {
	cw, ok := c.Conn.(interface{ CloseWrite() error })
	if !ok {
		return errors.New("connection does not support CloseWrite")
	}
	return cw.CloseWrite()
}

// detectProxyProtocol consumes a valid PROXY v1 or v2 header. For ordinary
// traffic it keeps the bytes inspected in proxyConn.prefix, so TLS (and any
// other direct protocol) sees exactly the original stream.
func detectProxyProtocol(conn net.Conn) (*proxyConn, error) {
	c := &proxyConn{Conn: conn}
	var first [1]byte
	if _, err := io.ReadFull(conn, first[:]); err != nil {
		return nil, err
	}

	var signature string
	switch first[0] {
	case proxyV1Prefix[0]:
		signature = proxyV1Prefix
	case proxyV2Sig[0]:
		signature = proxyV2Sig
	default:
		c.prefix = append(c.prefix, first[0])
		return c, nil
	}

	seen := make([]byte, len(signature))
	seen[0] = first[0]
	n, err := io.ReadFull(conn, seen[1:])
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		c.prefix = seen[:1+n]
		return c, nil
	}
	if err != nil {
		return nil, fmt.Errorf("PROXY protocol signature: %w", err)
	}
	if string(seen) != signature {
		c.prefix = seen
		return c, nil
	}

	var parseErr error
	if signature == proxyV1Prefix {
		c.remote, c.local, parseErr = readProxyV1(conn, seen)
	} else {
		c.remote, c.local, parseErr = readProxyV2(conn)
	}
	if parseErr != nil {
		return nil, parseErr
	}
	// Both nil means v1 UNKNOWN or v2 LOCAL/UNSPEC: the socket's own addresses apply.
	return c, nil
}

func readProxyV1(conn net.Conn, line []byte) (src, dst net.Addr, err error) {
	for len(line) < proxyV1MaxLen {
		var b [1]byte
		if _, err := io.ReadFull(conn, b[:]); err != nil {
			return nil, nil, fmt.Errorf("PROXY protocol v1 header: %w", err)
		}
		line = append(line, b[0])
		if len(line) >= 2 && line[len(line)-2] == '\r' && line[len(line)-1] == '\n' {
			fields := strings.Split(string(line[:len(line)-2]), " ")
			if len(fields) >= 2 && fields[0] == "PROXY" && fields[1] == "UNKNOWN" {
				return nil, nil, nil
			}
			if len(fields) != 6 || fields[0] != "PROXY" || (fields[1] != "TCP4" && fields[1] != "TCP6") {
				return nil, nil, errors.New("invalid PROXY protocol v1 header")
			}
			srcIP, err := netip.ParseAddr(fields[2])
			if err != nil || fields[1] == "TCP4" && !srcIP.Is4() || fields[1] == "TCP6" && !srcIP.Is6() {
				return nil, nil, errors.New("invalid PROXY protocol v1 source address")
			}
			dstIP, err := netip.ParseAddr(fields[3])
			if err != nil || fields[1] == "TCP4" && !dstIP.Is4() || fields[1] == "TCP6" && !dstIP.Is6() {
				return nil, nil, errors.New("invalid PROXY protocol v1 destination address")
			}
			srcPort, err := parseProxyPort(fields[4])
			if err != nil {
				return nil, nil, errors.New("invalid PROXY protocol v1 source port")
			}
			dstPort, err := parseProxyPort(fields[5])
			if err != nil {
				return nil, nil, errors.New("invalid PROXY protocol v1 destination port")
			}
			return net.TCPAddrFromAddrPort(netip.AddrPortFrom(srcIP, uint16(srcPort))),
				net.TCPAddrFromAddrPort(netip.AddrPortFrom(dstIP, uint16(dstPort))), nil
		}
	}
	return nil, nil, fmt.Errorf("PROXY protocol v1 header exceeds %d bytes", proxyV1MaxLen)
}

func parseProxyPort(s string) (int, error) {
	p, err := strconv.Atoi(s)
	if err != nil || p < 0 || p > 65535 {
		return 0, errors.New("port out of range")
	}
	return p, nil
}

func readProxyV2(conn net.Conn) (src, dst net.Addr, err error) {
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, nil, fmt.Errorf("PROXY protocol v2 header: %w", err)
	}
	if header[0]>>4 != 2 {
		return nil, nil, errors.New("invalid PROXY protocol v2 version")
	}
	command := header[0] & 0x0f
	length := int(header[2])<<8 | int(header[3])
	if command == 0 { // LOCAL: the connection's physical peer is authoritative.
		if _, err := io.CopyN(io.Discard, conn, int64(length)); err != nil {
			return nil, nil, fmt.Errorf("PROXY protocol v2 LOCAL payload: %w", err)
		}
		return nil, nil, nil
	}
	if command != 1 {
		return nil, nil, errors.New("invalid PROXY protocol v2 command")
	}

	family, protocol := header[1]>>4, header[1]&0x0f
	if family > 3 || protocol > 2 {
		return nil, nil, errors.New("invalid PROXY protocol v2 address family")
	}
	need := 0
	switch family {
	case 1: // INET
		need = 12
	case 2: // INET6
		need = 36
	case 3: // UNIX; valid, but it cannot provide a TCP remote address.
		need = 216
	}
	if length < need {
		return nil, nil, errors.New("short PROXY protocol v2 address block")
	}
	if (family == 1 || family == 2) && protocol != 1 {
		return nil, nil, errors.New("PROXY protocol v2 IP address is not a stream")
	}

	addressBytes := need
	if addressBytes > 36 { // UNIX paths are not used for remote IP detection.
		addressBytes = 0
	}
	address := make([]byte, addressBytes)
	if _, err := io.ReadFull(conn, address); err != nil {
		return nil, nil, fmt.Errorf("PROXY protocol v2 address block: %w", err)
	}
	if _, err := io.CopyN(io.Discard, conn, int64(length-addressBytes)); err != nil {
		return nil, nil, fmt.Errorf("PROXY protocol v2 payload: %w", err)
	}
	if family == 1 {
		return &net.TCPAddr{IP: net.IP(append([]byte(nil), address[0:4]...)), Port: int(binary.BigEndian.Uint16(address[8:]))},
			&net.TCPAddr{IP: net.IP(append([]byte(nil), address[4:8]...)), Port: int(binary.BigEndian.Uint16(address[10:]))}, nil
	}
	if family == 2 {
		return &net.TCPAddr{IP: net.IP(append([]byte(nil), address[:16]...)), Port: int(binary.BigEndian.Uint16(address[32:]))},
			&net.TCPAddr{IP: net.IP(append([]byte(nil), address[16:32]...)), Port: int(binary.BigEndian.Uint16(address[34:]))}, nil
	}
	return nil, nil, nil
}
