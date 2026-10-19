package main

import (
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestNonceCache(t *testing.T) {
	c := newNonceCache()
	now := c.start
	d := uint64(0x0123_4567_89ab_cdef)
	if c.seen(d, now) {
		t.Fatal("never remembered")
	}
	c.remember(d, now)
	if !c.seen(d, now.Add(nonceTTL-nonceTick)) || c.seen(d, now.Add(nonceTTL)) {
		t.Fatal("remembered for nonceTTL")
	}
	// Same slot, other hash: not a match, and it evicts the first.
	other := d ^ 1<<40
	if c.seen(other, now) {
		t.Fatal("matched another hash in the same slot")
	}
	c.remember(other, now)
	if c.seen(d, now) || !c.seen(other, now) {
		t.Fatal("eviction by a newer hash")
	}
	// An all-zero hash is not special, and an empty slot matches nothing.
	if c.seen(0, now) || c.seen(1<<nonceIndexBits, now) {
		t.Fatal("an empty slot matched")
	}
	c.remember(0, now)
	if !c.seen(0, now) {
		t.Fatal("hash 0")
	}
	// Still right across the stamp's wrap-around.
	late := now.Add(nonceTick * (nonceStampMask - 3))
	c.remember(d, late)
	if !c.seen(d, late.Add(8*nonceTick)) || c.seen(d, late.Add(nonceTTL+nonceTick)) {
		t.Fatal("wrap-around")
	}
}

// helloWithRandom is clientHello(sni) with a random of its own.
func helloWithRandom(sni string, random byte) []byte {
	h := clientHello(sni)
	for i := range 32 {
		h[5+4+2+i] = random ^ byte(i) // record header, handshake header, legacy_version
	}
	return h
}

func TestHelloDigest(t *testing.T) {
	a, err := parseHello(helloWithRandom("a.test", 7))
	if err != nil || a.SNI != "a.test" || a.Digest == 0 {
		t.Fatal(a, err)
	}
	// The same message in other records, with bytes after it: the same digest.
	hs := buildClientHello(ptr("a.test"), 0)
	copy(hs[4+2:], helloWithRandom("a.test", 7)[5+4+2:5+4+2+32])
	b, err := parseHello(append(wrapRecords(hs, 100), 0x17, 0x03, 0x03, 0, 1, 0))
	if err != nil || b.Digest != a.Digest {
		t.Fatal("re-framed hello: digest differs", err)
	}
	// Another random, or another name: another digest.
	for _, h := range [][]byte{helloWithRandom("a.test", 8), helloWithRandom("b.test", 7)} {
		if c, _ := parseHello(h); c.Digest == a.Digest {
			t.Fatal("different hellos, same digest")
		}
	}
}

func ptr(s string) *string { return &s }

// A rule whose target is the proxy itself: the forwarded ClientHello comes
// back in, is recognised, and refused at the second hop.
func TestRememberNonceStopsLoop(t *testing.T) {
	for _, tc := range []struct {
		on     bool
		random byte
	}{{true, 0x5a}, {true, 0}, {false, 0x5a}} {
		on := tc.on
		t.Run(fmt.Sprintf("remember_nonce=%t,random=%#x", on, tc.random), func(t *testing.T) {
			l, port := listen(t)
			text := fmt.Sprintf("[[listener]]\nname=default\nport=1\n[global]\nstats_interval=0\nmax_handshakes_per_ip=0\nmax_connections=20\nremember_nonce=%t\nca_root=%s\n"+
				"[[host]]\nlistener=default\npattern=ANY\ntarget_host=127.0.0.1\ntarget_port=%d\n", on, testCARoot(), port)
			srv, err := NewServer(mustParse(t, text))
			if err != nil {
				t.Fatal(err)
			}
			go srv.Serve(l, "")
			c, err := net.Dial("tcp", l.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(T))
			h := helloWithRandom("loop.test", tc.random)
			if tc.random == 0 {
				clear(h[5+4+2 : 5+4+2+32]) // all zeros: no exemption, its loop is caught too
			}
			c.Write(h)
			got, _ := io.ReadAll(c) // the alert, relayed back through the first hop; or the connection cap
			if !on {
				// Without it each hop opens the next until max_connections.
				if n := srv.stats.Rejected.Load(); n == 0 {
					t.Fatalf("expected the loop to hit max_connections, rejected=%d", n)
				}
				return
			}
			if string(got) != string(alertAccessDenied) {
				t.Fatalf("got %x, want the access_denied alert", got)
			}
			if a := srv.stats.Accepted.Load(); a != 2 {
				t.Fatalf("accepted=%d, want 2 (the client's, and the one hop back)", a)
			}
			var loop *flowView
			for deadline := time.Now().Add(T); loop == nil && time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
				for _, f := range srv.stats.flows.closedSince(0) {
					if strings.Contains(f.Reason, "connection loop") {
						loop = &f
					}
				}
			}
			if loop == nil || loop.Result != flowDenied || loop.SNI != "loop.test" {
				t.Fatalf("%+v", loop)
			}
		})
	}
}
