package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func proxyV2Header(family byte, address []byte) []byte {
	b := append([]byte(proxyV2Sig), 0x21, family)
	b = binary.BigEndian.AppendUint16(b, uint16(len(address)))
	return append(b, address...)
}

func detectBytes(t *testing.T, input []byte) (*proxyConn, []byte, error) {
	t.Helper()
	server, client := net.Pipe()
	go func() {
		_, _ = client.Write(input)
		_ = client.Close()
	}()
	server.SetDeadline(time.Now().Add(time.Second))
	c, err := detectProxyProtocol(server)
	if err != nil {
		server.Close()
		return nil, nil, err
	}
	rest, readErr := io.ReadAll(c)
	c.Close()
	if readErr != nil {
		t.Fatalf("read remaining stream: %v", readErr)
	}
	return c, rest, nil
}

func TestProxyProtocolDirectTrafficIsUntouched(t *testing.T) {
	for _, input := range [][]byte{
		clientHello("direct.example"),
		[]byte("GET / HTTP/1.1\r\nHost: direct.example\r\n\r\n"),
		[]byte("POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n"),
	} {
		c, got, err := detectBytes(t, input)
		if err != nil {
			t.Fatalf("direct traffic rejected: %v", err)
		}
		if !bytes.Equal(got, input) {
			t.Fatalf("direct traffic changed:\n got %x\nwant %x", got, input)
		}
		if c.RemoteAddr().String() != "pipe" {
			t.Fatalf("direct remote address = %s, want physical peer", c.RemoteAddr())
		}
	}
}

func TestProxyProtocolV1IPv4AndIPv6(t *testing.T) {
	for _, tc := range []struct {
		name, header, want string
	}{
		{"IPv4", "PROXY TCP4 192.0.2.10 198.51.100.20 12345 443\r\n", "192.0.2.10:12345"},
		{"IPv6", "PROXY TCP6 2001:db8::10 2001:db8::20 23456 443\r\n", "[2001:db8::10]:23456"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := clientHello("v1.example")
			c, got, err := detectBytes(t, append([]byte(tc.header), payload...))
			if err != nil {
				t.Fatal(err)
			}
			if c.RemoteAddr().String() != tc.want {
				t.Fatalf("remote address = %s, want %s", c.RemoteAddr(), tc.want)
			}
			if !bytes.Equal(got, payload) {
				t.Fatal("v1 header was not stripped cleanly")
			}
		})
	}
}

func TestProxyProtocolV2IPv4AndIPv6(t *testing.T) {
	v4 := []byte{192, 0, 2, 11, 198, 51, 100, 21, 0x30, 0x39, 0x01, 0xbb}
	v6 := make([]byte, 36)
	copy(v6[:16], net.ParseIP("2001:db8::11").To16())
	copy(v6[16:32], net.ParseIP("2001:db8::21").To16())
	binary.BigEndian.PutUint16(v6[32:34], 23457)
	binary.BigEndian.PutUint16(v6[34:36], 443)

	for _, tc := range []struct {
		name   string
		header []byte
		want   string
	}{
		{"IPv4", proxyV2Header(0x11, v4), "192.0.2.11:12345"},
		{"IPv6", proxyV2Header(0x21, v6), "[2001:db8::11]:23457"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := clientHello("v2.example")
			c, got, err := detectBytes(t, append(tc.header, payload...))
			if err != nil {
				t.Fatal(err)
			}
			if c.RemoteAddr().String() != tc.want {
				t.Fatalf("remote address = %s, want %s", c.RemoteAddr(), tc.want)
			}
			if !bytes.Equal(got, payload) {
				t.Fatal("v2 header was not stripped cleanly")
			}
		})
	}
}

func TestProxyProtocolOutboundHeaders(t *testing.T) {
	src4 := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 12345}
	dst4 := &net.TCPAddr{IP: net.ParseIP("198.51.100.20"), Port: 443}
	v1, err := proxyProtocolHeader(1, src4, dst4)
	if err != nil || string(v1) != "PROXY TCP4 192.0.2.10 198.51.100.20 12345 443\r\n" {
		t.Fatalf("v1 header = %q, %v", v1, err)
	}
	v2, err := proxyProtocolHeader(2, src4, dst4)
	wantV2 := proxyV2Header(0x11, []byte{192, 0, 2, 10, 198, 51, 100, 20, 0x30, 0x39, 0x01, 0xbb})
	if err != nil || !bytes.Equal(v2, wantV2) {
		t.Fatalf("v2 header = %x, want %x, err=%v", v2, wantV2, err)
	}

	src6 := &net.TCPAddr{IP: net.ParseIP("2001:db8::10"), Port: 23456}
	dst6 := &net.TCPAddr{IP: net.ParseIP("2001:db8::20"), Port: 8443}
	v1, err = proxyProtocolHeader(1, src6, dst6)
	if err != nil || string(v1) != "PROXY TCP6 2001:db8::10 2001:db8::20 23456 8443\r\n" {
		t.Fatalf("v1 IPv6 header = %q, %v", v1, err)
	}
}

func TestProxyProtocolHeadersAreNotForwarded(t *testing.T) {
	port := echoBackend(t, "up:")
	p := startProxy(t, "proxy_protocol_from = 127.0.0.1", allowAll(port)) // the test client plays the load balancer
	payload := clientHello("proxy.example")

	v4 := []byte{203, 0, 113, 9, 127, 0, 0, 1, 0x9c, 0x40, 0x01, 0xbb}
	inputs := [][]byte{
		payload,
		append([]byte("PROXY TCP4 203.0.113.9 127.0.0.1 40000 443\r\n"), payload...),
		append(proxyV2Header(0x11, v4), payload...),
	}
	for _, input := range inputs {
		c := dial(t, p)
		if _, err := c.Write(input); err != nil {
			t.Fatal(err)
		}
		got := readN(t, c, len("up:")+len(payload))
		c.Close()
		if want := append([]byte("up:"), payload...); !bytes.Equal(got, want) {
			t.Fatal("backend received a PROXY header or altered ClientHello")
		}
	}
}

// headerBackend accepts connections, reads an optional PROXY header the way a
// backend would, and reports what it saw: the stated source and destination,
// and the first bytes that followed.
type seenByBackend struct {
	src, dst string
	payload  []byte
}

func headerBackend(t *testing.T, payloadLen int) (int, chan seenByBackend) {
	t.Helper()
	seen := make(chan seenByBackend, 8)
	port := backend(t, func(raw *net.TCPConn) {
		raw.SetReadDeadline(time.Now().Add(T))
		c, err := detectProxyProtocol(raw)
		if err != nil {
			seen <- seenByBackend{src: "error: " + err.Error()}
			return
		}
		got := seenByBackend{payload: make([]byte, payloadLen)}
		if c.remote != nil {
			got.src, got.dst = c.remote.String(), c.local.String()
		}
		io.ReadFull(c, got.payload)
		seen <- got
	})
	return port, seen
}

// A passed-through rule sends the header too: first the PROXY header, then the
// client's ClientHello, byte for byte.
func TestProxyProtocolOnPassThroughRules(t *testing.T) {
	hello := clientHello("pass.example")
	for _, version := range []string{"1", "2"} {
		port, seen := headerBackend(t, len(hello))
		p := startProxy(t, "", "[[host]]\npattern=pass.example\ntarget_host=127.0.0.1\ntarget_port="+strconv.Itoa(port)+"\nproxy=true\nproxy_version="+version+"\n")
		c := dial(t, p)
		c.Write(hello)
		got := <-seen
		if got.src != c.LocalAddr().String() || got.dst != p.addr || !bytes.Equal(got.payload, hello) {
			t.Fatalf("v%s: backend saw src=%q dst=%q (want %s and %s), hello intact=%v", version, got.src, got.dst, c.LocalAddr(), p.addr, bytes.Equal(got.payload, hello))
		}
		c.Close()
	}
	if !strings.Contains(testLog.String(), "(PROXY v2 header sent)") {
		t.Fatal("the connected line should say that a header was sent")
	}
}

// Only peers listed in proxy_protocol_from may state another source address.
func TestProxyProtocolIsOnlyAcceptedFromTrustedPeers(t *testing.T) {
	hello := clientHello("trust.example")
	forged := append([]byte("PROXY TCP4 203.0.113.9 198.51.100.7 40000 443\r\n"), hello...)
	rule := func(port int) string {
		return "[[host]]\npattern=trust.example\ntarget_host=127.0.0.1\ntarget_port=" + strconv.Itoa(port) + "\nproxy=true\n"
	}

	// Not listed (the default): the header is not looked for, so the stream is
	// not TLS and the connection is refused. Nothing reaches the backend and
	// the forged address appears nowhere.
	port, seen := headerBackend(t, len(hello))
	p := startProxy(t, "", rule(port))
	mark := len(testLog.String())
	c := dial(t, p)
	c.Write(forged)
	c.SetReadDeadline(time.Now().Add(T))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("a header from an unlisted peer must not be accepted")
	}
	c.Close()
	for deadline := time.Now().Add(T); !strings.Contains(testLog.String()[mark:], "bad ClientHello"); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("no bad ClientHello line")
		}
	}
	if log := testLog.String()[mark:]; strings.Contains(log, "203.0.113.9") {
		t.Fatalf("the forged address was believed:\n%s", log)
	}
	select {
	case got := <-seen:
		t.Fatalf("the backend was contacted: %+v", got)
	default:
	}

	// Listed (a network): the stated source AND destination are what the
	// backend is told, not this hop's addresses.
	port, seen = headerBackend(t, len(hello))
	p = startProxy(t, "proxy_protocol_from = 10.9.9.9; 127.0.0.0/8", rule(port))
	c = dial(t, p)
	c.Write(forged)
	if got := <-seen; got.src != "203.0.113.9:40000" || got.dst != "198.51.100.7:443" || !bytes.Equal(got.payload, hello) {
		t.Fatalf("%+v", got)
	}
	c.Close()
}

func TestProxyProtocolConfig(t *testing.T) {
	c := mustParse(t, "[global]\nport=1\nproxy_protocol_from = 192.0.2.10, 10.0.0.0/8; 2001:db8::/32\n"+
		"[[host]]\npattern=a.example\ntarget_host=a.lan\nproxy=yes\n[[host]]\npattern=b.example\ntarget_host=b.lan\n")
	if !c.Rules[0].Proxy || c.Rules[0].ProxyVersion != 2 || c.Rules[1].Proxy {
		t.Fatalf("%+v", c.Rules)
	}
	for addr, want := range map[string]bool{"192.0.2.10": true, "192.0.2.11": false, "10.200.1.1": true, "2001:db8:5::1": true, "2001:db9::1": false, "::ffff:10.1.1.1": true} {
		if got := c.trustsProxyProtocolFrom(&net.TCPAddr{IP: net.ParseIP(addr)}); got != want {
			t.Errorf("%s: trusted=%v", addr, got)
		}
	}
	if mustParse(t, "[global]\nport=1\n").trustsProxyProtocolFrom(&net.TCPAddr{IP: net.ParseIP("127.0.0.1")}) {
		t.Fatal("nobody is trusted by default")
	}
	for name, text := range map[string]string{
		"version without proxy": "[[host]]\npattern=a\ntarget_host=x\nproxy_version=1\n",
		"version 3":             "[[host]]\npattern=a\ntarget_host=x\nproxy=true\nproxy_version=3\n",
		"deny rule":             "[[host]]\npattern=a\naction=deny\nproxy=true\n",
		"not a bool":            "[[host]]\npattern=a\ntarget_host=x\nproxy=maybe\n",
	} {
		if _, err := ParseConfig("[global]\nport=1\n" + text); err == nil {
			t.Errorf("%s: should be rejected", name)
		}
	}
	if _, err := ParseConfig("[global]\nport=1\nproxy_protocol_from = lb.example.com\n"); err == nil {
		t.Error("a host name is not a trusted source")
	}
}

// An IPv6 client (stated by a load balancer) on an IPv4 hop: one header, one
// family, the IPv4 endpoint in its IPv4-mapped form.
func TestProxyProtocolMixedFamilies(t *testing.T) {
	src := &net.TCPAddr{IP: net.ParseIP("2001:db8::10"), Port: 5000}
	dst := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443}
	v1, err := proxyProtocolHeader(1, src, dst)
	if err != nil || string(v1) != "PROXY TCP6 2001:db8::10 ::ffff:192.0.2.1 5000 443\r\n" {
		t.Fatalf("%q %v", v1, err)
	}
	v2, err := proxyProtocolHeader(2, src, dst)
	if err != nil || v2[13] != 0x21 || len(v2) != 16+36 {
		t.Fatalf("%x %v", v2, err)
	}
	client, server := net.Pipe()
	go func() { client.Write(v2); client.Close() }()
	server.SetReadDeadline(time.Now().Add(T))
	c, err := detectProxyProtocol(server)
	if err != nil || c.RemoteAddr().String() != "[2001:db8::10]:5000" || c.LocalAddr().String() != "192.0.2.1:443" { // Go prints an IPv4-mapped address as IPv4
		t.Fatalf("%v %v %v", err, c.RemoteAddr(), c.LocalAddr())
	}
}
