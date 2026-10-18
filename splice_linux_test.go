//go:build linux

package main

import (
	"crypto/tls"
	"net"
	"testing"
)

// tcpPair is both ends of one loopback TCP connection.
func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	a, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	b, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close(); b.Close() })
	return a.(*net.TCPConn), b.(*net.TCPConn)
}

// Only plain TCP on both sides is spliced: a terminated side has to be
// decrypted, and a ClientHello still being replayed lives in user space.
func TestSpliceOnlyBetweenPlainSockets(t *testing.T) {
	a, b := tcpPair(t)
	for name, c := range map[string]struct {
		from, to duplex
		want     bool
	}{
		"tcp to tcp":           {a, b, true},
		"PROXY-wrapped client": {&proxyConn{Conn: a}, b, true},
		"replay pending":       {&proxyConn{Conn: a, prefix: []byte{0x16}}, b, false},
		"terminated client":    {tls.Server(a, &tls.Config{}), b, false},
		"terminated upstream":  {a, tls.Client(b, &tls.Config{}), false},
	} {
		m := newSpliceMover(c.from, c.to, 65536)
		if (m != nil) != c.want {
			t.Errorf("%s: spliced=%v, want %v", name, m != nil, c.want)
		}
		if m != nil {
			m.close()
		}
	}
}

// The pipe is sized to buffer_size where the kernel allows it, and a chunk
// never exceeds the pipe, so a full chunk always fits.
func TestSplicePipeSize(t *testing.T) {
	a, b := tcpPair(t)
	for _, size := range []int{minBufferSize, 65536, maxBufferSize} {
		m := newSpliceMover(a, b, size).(*spliceMover)
		if m.chunk() < 1 || m.chunk() > size {
			t.Errorf("buffer_size %d: chunk %d", size, m.chunk())
		}
		m.close()
	}
}
