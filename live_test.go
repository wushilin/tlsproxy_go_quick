package main

// Live tests against well-known public sites. They need internet access, so
// they only run with TLSPROXY_LIVE=1:
//
//	TLSPROXY_LIVE=1 go test -run Live -v ./...

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

var liveSites = []string{"www.google.com", "www.facebook.com", "www.cloudflare.com", "github.com"}

func requireLive(t *testing.T) {
	t.Helper()
	if os.Getenv("TLSPROXY_LIVE") == "" {
		t.Skip("set TLSPROXY_LIVE=1 to run tests against public sites")
	}
}

// clientVia returns an HTTP client whose every connection goes to the proxy,
// whatever host the URL names (like pointing DNS at the gateway).
func clientVia(p *proxyUnderTest, tlsCfg *tls.Config) *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, p.addr)
			},
			TLSClientConfig:   tlsCfg,
			ForceAttemptHTTP2: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func get(t *testing.T, c *http.Client, host string) *http.Response {
	t.Helper()
	resp, err := c.Get("https://" + host + "/")
	if err != nil {
		t.Fatalf("GET https://%s/: %v", host, err)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if resp.StatusCode >= 500 || (len(body) == 0 && resp.StatusCode == 200) {
		t.Fatalf("%s: status %d, %d body bytes", host, resp.StatusCode, len(body))
	}
	t.Logf("%-20s %s  HTTP %d  %6d bytes  cert CN=%s", host, resp.Proto, resp.StatusCode, len(body),
		resp.TLS.PeerCertificates[0].Subject.CommonName)
	return resp
}

// Pass-through: the client verifies the REAL site certificate with the system
// roots, so this proves the TLS stream reaches the site bit for bit.
func TestLivePassThrough(t *testing.T) {
	requireLive(t)
	p := startProxy(t, "", "[[host]]\npattern=(.*\\.)?(google|facebook|cloudflare|github)\\.com\ntarget_host=$0\n[[host]]\npattern=.*\naction=deny\n")
	c := clientVia(p, nil) // default config: full verification against system roots
	for _, host := range liveSites {
		resp := get(t, c, host)
		if resp.ProtoMajor != 2 {
			t.Errorf("%s: expected HTTP/2 end to end through the proxy, got %s", host, resp.Proto)
		}
		if err := resp.TLS.PeerCertificates[0].VerifyHostname(host); err != nil {
			t.Errorf("%s: %v", host, err)
		}
	}
	// A site outside the allowlist is refused by the proxy, not reached.
	if _, err := c.Get("https://www.wikipedia.org/"); err == nil {
		t.Error("www.wikipedia.org should have been denied")
	}
	if st := p.srv.stats; st.Denied.Load() < 1 || st.BytesDown.Load() < 10_000 {
		t.Errorf("stats look wrong: %s", st.Summary(p.srv.runtime.Load()))
	}
}

// Termination: the client sees OUR certificate; the proxy makes its own,
// verified TLS connection to the real site and carries HTTP/2 across.
func TestLiveTerminateWithVerifiedTLSUpstream(t *testing.T) {
	requireLive(t)
	ca := newTestCA(t)
	var rules strings.Builder
	for _, host := range liveSites {
		fmt.Fprintf(&rules, "[[host]]\npattern=%s\ncert=%s\ntarget_host=%s\n", strings.ReplaceAll(host, ".", `\.`), ca.certDir(t, host), host)
	}
	p := startProxy(t, "", rules.String()) // upstream_tls and upstream_tls_verify default to true
	c := clientVia(p, &tls.Config{RootCAs: ca.pool})
	for _, host := range liveSites {
		resp := get(t, c, host)
		if issuer := resp.TLS.PeerCertificates[0].Issuer.CommonName; issuer != "test CA" {
			t.Errorf("%s: the client should see the proxy's certificate, got issuer %q", host, issuer)
		}
		if resp.ProtoMajor != 2 {
			t.Errorf("%s: ALPN h2 should be negotiated end to end, got %s", host, resp.Proto)
		}
	}
}

// A real site's certificate must NOT verify for a different upstream name.
func TestLiveUpstreamVerificationCatchesWrongHost(t *testing.T) {
	requireLive(t)
	ca := newTestCA(t)
	ips, err := net.LookupHost("www.google.com")
	if err != nil {
		t.Skip(err)
	}
	// Connect to Google's address but expect a certificate for that bare IP: must fail.
	p := startProxy(t, "", fmt.Sprintf("[[host]]\npattern=victim\\.test\ncert=%s\ntarget_host=%s\n", ca.certDir(t, "victim.test"), ips[0]))
	c := clientVia(p, &tls.Config{RootCAs: ca.pool})
	if resp, err := c.Get("https://victim.test/"); err == nil {
		t.Fatalf("relayed despite an unverifiable upstream certificate: HTTP %d", resp.StatusCode)
	}
	if r := testLog.String(); !strings.Contains(r, "upstream TLS handshake failed") {
		t.Error("the log should say why")
	}
}
