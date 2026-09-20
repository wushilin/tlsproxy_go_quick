package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

// testCA issues leaf certificates for tests.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert, key, pool}
}

// issue returns PEM for a leaf valid for names (and 127.0.0.1) with the given life.
func (ca *testCA) issue(t *testing.T, life time.Duration, names ...string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:   time.Now().Add(-time.Hour), NotAfter: time.Now().Add(life),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// certDir writes cert.pem + key.pem for names into a fresh directory.
func (ca *testCA) certDir(t *testing.T, names ...string) string {
	t.Helper()
	dir := t.TempDir()
	certPEM, keyPEM := ca.issue(t, 12*time.Hour, names...)
	os.WriteFile(filepath.Join(dir, "cert.pem"), certPEM, 0o600)
	os.WriteFile(filepath.Join(dir, "key.pem"), keyPEM, 0o600)
	return dir
}

// tlsBackend is a TLS echo server (tag first) offering the given ALPN protocols.
func (ca *testCA) tlsBackend(t *testing.T, tag string, protos ...string) int {
	t.Helper()
	certPEM, keyPEM := ca.issue(t, 12*time.Hour, "backend.internal")
	cert, _ := tls.X509KeyPair(certPEM, keyPEM)
	return backend(t, func(c *net.TCPConn) {
		tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: protos})
		if tc.Handshake() != nil {
			return
		}
		fmt.Fprintf(tc, "%s[%s]", tag, tc.ConnectionState().NegotiatedProtocol)
		io.Copy(tc, tc)
		tc.CloseWrite()
	})
}

func tlsDial(t *testing.T, p *proxyUnderTest, cfg *tls.Config) (*tls.Conn, error) {
	t.Helper()
	raw := dial(t, p)
	tc := tls.Client(raw, cfg)
	tc.SetDeadline(time.Now().Add(T))
	return tc, tc.Handshake()
}

func TestTerminateWithPlaintextUpstream(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	port := backend(t, func(c *net.TCPConn) {
		data, _ := io.ReadAll(c) // plaintext: exactly what the client sent inside TLS
		fmt.Fprintf(c, "plain backend got %q", data)
	})
	p := startProxy(t, "", fmt.Sprintf("[[host]]\npattern=app\\.test\ncert=%s\nupstream_tls=false\ntarget_host=127.0.0.1\ntarget_port=%d\n",
		ca.certDir(t, "app.test"), port))
	tc, err := tlsDial(t, p, &tls.Config{RootCAs: ca.pool, ServerName: "app.test", NextProtos: []string{"h2", "http/1.1"}})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	st := tc.ConnectionState()
	if st.NegotiatedProtocol != "http/1.1" || st.PeerCertificates[0].DNSNames[0] != "app.test" {
		t.Fatalf("alpn=%q cert=%v", st.NegotiatedProtocol, st.PeerCertificates[0].DNSNames)
	}
	tc.Write([]byte("hello through tls"))
	tc.CloseWrite() // half-close must reach the backend as EOF, and the reply must come back
	if got := string(readToEnd(t, tc)); got != `plain backend got "hello through tls"` {
		t.Fatal(got)
	}
	if r := closeReason(t, "app.test"); !strings.HasPrefix(r, "client closed, then upstream closed") {
		t.Fatal(r)
	}
}

func TestTerminateWithTLSUpstreamNegotiatesALPNEndToEnd(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	port := ca.tlsBackend(t, "B", "h2", "http/1.1")
	rule := func(name, extra string) string {
		return fmt.Sprintf("[[host]]\npattern=%s\ncert=%s\n%starget_host=127.0.0.1\ntarget_port=%d\n", strings.ReplaceAll(name, ".", `\.`), ca.certDir(t, name), extra, port)
	}
	p := startProxy(t, "", rule("noverify.test", "upstream_tls_verify=false\n")+rule("verify.test", ""))

	for offer, want := range map[string]string{"h2,http/1.1": "h2", "http/1.1": "http/1.1", "": ""} {
		var protos []string
		if offer != "" {
			protos = strings.Split(offer, ",")
		}
		tc, err := tlsDial(t, p, &tls.Config{RootCAs: ca.pool, ServerName: "noverify.test", NextProtos: protos})
		if err != nil {
			t.Fatalf("offer %q: %v", offer, err)
		}
		if got := tc.ConnectionState().NegotiatedProtocol; got != want {
			t.Fatalf("offer %q: client negotiated %q, want %q", offer, got, want)
		}
		tc.Write([]byte("ping"))
		if got, wantEcho := string(readN(t, tc, len("B[]ping")+len(want))), "B["+want+"]ping"; got != wantEcho {
			t.Fatalf("offer %q: %q", offer, got) // the backend saw the same protocol
		}
		tc.Close()
	}

	// upstream_tls_verify defaults to true: the backend's CA is unknown to the
	// system roots, so the proxy must refuse to relay.
	raw := dial(t, p)
	tc := tls.Client(raw, &tls.Config{RootCAs: ca.pool, ServerName: "verify.test"})
	tc.SetDeadline(time.Now().Add(T))
	if err := tc.Handshake(); err == nil {
		if n, _ := tc.Read(make([]byte, 1)); n > 0 {
			t.Fatal("relayed to an unverified upstream")
		}
	}
}

func TestTerminationAndPassThroughSideBySide(t *testing.T) {
	t.Parallel()
	ca, backendCA := newTestCA(t), newTestCA(t)
	port := backendCA.tlsBackend(t, "P")
	p := startProxy(t, "", fmt.Sprintf(
		"[[host]]\npattern=term\\.test\ncert=%s\nupstream_tls_verify=false\ntarget_host=127.0.0.1\ntarget_port=%d\n"+
			"[[host]]\npattern=pass\\.test\ntarget_host=127.0.0.1\ntarget_port=%d\n", ca.certDir(t, "term.test"), port, port))
	// Terminated: the client sees OUR certificate.
	tc, err := tlsDial(t, p, &tls.Config{RootCAs: ca.pool, ServerName: "term.test"})
	if err != nil || tc.ConnectionState().PeerCertificates[0].Subject.CommonName != "term.test" {
		t.Fatalf("terminated: %v", err)
	}
	// Passed through: the client sees the BACKEND's certificate, end to end.
	tc, err = tlsDial(t, p, &tls.Config{RootCAs: backendCA.pool, ServerName: "backend.internal"})
	if err == nil {
		t.Fatal("SNI backend.internal matches no rule and must be denied")
	}
	raw := dial(t, p)
	tc = tls.Client(raw, &tls.Config{RootCAs: backendCA.pool, ServerName: "pass.test", InsecureSkipVerify: true})
	tc.SetDeadline(time.Now().Add(T))
	if err := tc.Handshake(); err != nil || tc.ConnectionState().PeerCertificates[0].Subject.CommonName != "backend.internal" {
		t.Fatalf("pass-through: %v", err)
	}
}

func TestTerminatedTransferIntegrity(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	plain := echoBackend(t, "")
	secure := ca.tlsBackend(t, "")
	dir := ca.certDir(t, "a.test", "b.test")
	p := startProxy(t, "buffer_size=4096", fmt.Sprintf(
		"[[host]]\npattern=a\\.test\ncert=%s\nupstream_tls=false\ntarget_host=127.0.0.1\ntarget_port=%d\n"+
			"[[host]]\npattern=b\\.test\ncert=%s\nupstream_tls_verify=false\ntarget_host=127.0.0.1\ntarget_port=%d\n", dir, plain, dir, secure))
	for _, name := range []string{"a.test", "b.test"} {
		tc, err := tlsDial(t, p, &tls.Config{RootCAs: ca.pool, ServerName: name})
		if err != nil {
			t.Fatal(err)
		}
		tc.SetDeadline(time.Now().Add(60 * time.Second))
		data := pattern(4<<20, 7)
		go func() { tc.Write(data); tc.CloseWrite() }()
		got := readToEnd(t, tc)
		if name == "b.test" {
			got = bytes.TrimPrefix(got, []byte("[]"))
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("%s: %d bytes back, corrupted or truncated", name, len(got))
		}
	}
}

func TestPlaceholderUntilAutomaticCertificateExists(t *testing.T) {
	t.Parallel()
	l, dead := listen(t)
	l.Close() // the "CA" is unreachable, so issuance fails and the placeholder stays
	p := startProxy(t, fmt.Sprintf("cert_path=%s\nacme_agree_tos=true\nacme_directory=https://127.0.0.1:%d/dir", t.TempDir(), dead),
		fmt.Sprintf("[[host]]\npattern=*.auto\\.test\ncert=auto\ncert_domains=www.auto.test\nupstream_tls=false\ntarget_host=127.0.0.1\ntarget_port=%d\n", echoBackend(t, "E")))
	tc, err := tlsDial(t, p, &tls.Config{InsecureSkipVerify: true, ServerName: "www.auto.test"})
	if err != nil {
		t.Fatal(err)
	}
	leaf := tc.ConnectionState().PeerCertificates[0]
	if leaf.Subject.Organization[0] != "tlsproxy placeholder" || leaf.DNSNames[0] != "www.auto.test" {
		t.Fatalf("%v %v", leaf.Subject, leaf.DNSNames)
	}
	tc.Write([]byte("x"))
	if got := string(readN(t, tc, 2)); got != "Ex" {
		t.Fatal(got) // reachable, just not trusted yet
	}
}

func TestAnswersTLSALPN01Challenge(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	p := startProxy(t, "", fmt.Sprintf("[[host]]\npattern=.*\ncert=%s\nupstream_tls=false\ntarget_host=127.0.0.1\ntarget_port=%d\n", ca.certDir(t, "x.test"), echoBackend(t, "")))
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	answer, err := (&acme.Client{Key: key}).TLSALPN01ChallengeCert("token-123", "x.test")
	if err != nil {
		t.Fatal(err)
	}
	m := p.srv.certs
	m.mu.Lock()
	m.challenges["x.test"] = &answer
	m.mu.Unlock()

	// What the CA does: connect with ALPN acme-tls/1 and look at the certificate.
	tc, err := tlsDial(t, p, &tls.Config{InsecureSkipVerify: true, ServerName: "x.test", NextProtos: []string{acme.ALPNProto}})
	if err != nil {
		t.Fatal(err)
	}
	st := tc.ConnectionState()
	leaf := st.PeerCertificates[0]
	hasACMEExt := false
	for _, e := range leaf.Extensions {
		if e.Id.String() == "1.3.6.1.5.5.7.1.31" && e.Critical {
			hasACMEExt = true
		}
	}
	if st.NegotiatedProtocol != acme.ALPNProto || !hasACMEExt || len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "x.test" {
		t.Fatalf("alpn=%q ext=%v names=%v", st.NegotiatedProtocol, hasACMEExt, leaf.DNSNames)
	}
	// An ordinary client to the same name still gets the real certificate.
	tc, err = tlsDial(t, p, &tls.Config{RootCAs: ca.pool, ServerName: "x.test"})
	if err != nil || tc.ConnectionState().PeerCertificates[0].Subject.CommonName != "x.test" {
		t.Fatal(err)
	}
}

func TestDirectoryCertificateIsReloadedAndRequiredAtStartup(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	dir := ca.certDir(t, "old.test")
	rules := fmt.Sprintf("[[host]]\npattern=.*\ncert=%s\nupstream_tls=false\ntarget_host=127.0.0.1\ntarget_port=%d\n", dir, echoBackend(t, ""))
	p := startProxy(t, "", rules)
	served := func() string {
		tc, err := tlsDial(t, p, &tls.Config{InsecureSkipVerify: true, ServerName: "whatever.test"})
		if err != nil {
			t.Fatal(err)
		}
		defer tc.Close()
		return tc.ConnectionState().PeerCertificates[0].Subject.CommonName
	}
	if served() != "old.test" {
		t.Fatal("initial certificate")
	}
	certPEM, keyPEM := ca.issue(t, time.Hour, "new.test")
	os.WriteFile(filepath.Join(dir, "key.pem"), keyPEM, 0o600)
	os.WriteFile(filepath.Join(dir, "cert.pem"), certPEM, 0o600)
	os.Chtimes(filepath.Join(dir, "cert.pem"), time.Now(), time.Now().Add(time.Minute)) // make sure mtime differs
	p.srv.certs.refreshFileCerts()
	if served() != "new.test" {
		t.Fatal("changed files were not picked up")
	}
	// A broken update keeps the previous certificate.
	os.WriteFile(filepath.Join(dir, "cert.pem"), []byte("garbage"), 0o600)
	os.Chtimes(filepath.Join(dir, "cert.pem"), time.Now(), time.Now().Add(2*time.Minute))
	p.srv.certs.refreshFileCerts()
	if served() != "new.test" {
		t.Fatal("a broken file must not replace a working certificate")
	}

	cfg := mustParse(t, "[global]\nport=1\n[[host]]\npattern=.*\ncert=/nonexistent/dir\ntarget_host=x.lan\n")
	if _, err := NewServer(cfg); err == nil || !strings.Contains(err.Error(), "line 3") {
		t.Fatalf("a missing certificate directory must be a startup error: %v", err)
	}
}

func TestCertConfigValidation(t *testing.T) {
	auto := "[global]\nbind=::\nport=443\nacme_agree_tos=true\npublic_ip_address=203.0.113.7; 2001:db8::1\n"
	c := mustParse(t, auto+"[[host]]\npattern=nas\\.example\\.com\ncert=auto\ntarget_host=10.0.0.5\n"+
		"[[host]]\npattern=*.wushilin\\.net\ncert=AUTO\ncert_domains = A.wushilin.net, b.wushilin.net;a.wushilin.net\nupstream_tls=no\ntarget_host=$1.lan\n"+
		"[[host]]\npattern=plain\\.example\\.com\ntarget_host=10.0.0.6\n")
	if got := fmt.Sprint(c.AutoDomains()); got != "[nas.example.com a.wushilin.net b.wushilin.net]" {
		t.Fatal(got) // literal pattern derived; list lowercased and de-duplicated
	}
	r := c.Rules
	if !r[0].UpstreamTLS || !r[0].UpstreamTLSVerify || r[1].UpstreamTLS || r[2].Terminates() || len(c.Warnings) != 0 ||
		fmt.Sprint(c.PublicIPs) != "[203.0.113.7 2001:db8::1]" || c.CertPath != "./certs" || c.ExpiryThresholdDays != 15 {
		t.Fatalf("%+v\n%+v", r, c)
	}
	// An IPv6 public address behind an IPv4-only listener: the CA could not get in.
	if c := mustParse(t, strings.Replace(auto, "bind=::", "bind=0.0.0.0", 1)+"[[host]]\npattern=a.b.com\ncert=auto\ntarget_host=x.lan\n"); len(c.Warnings) != 1 || !strings.Contains(c.Warnings[0], "listens on IPv4 only") {
		t.Fatalf("%q", c.Warnings)
	}
	c = mustParse(t, "[global]\nport=8443\nacme_agree_tos=true\n[[host]]\npattern=a\\.b\\.com\ncert=auto\ntarget_host=x.lan\n")
	if len(c.Warnings) != 2 { // not on 443, and no public_ip_address
		t.Fatal(c.Warnings)
	}
	for name, text := range map[string]string{
		"regex without cert_domains": auto + "[[host]]\npattern=*.x\\.com\ncert=auto\ntarget_host=$1.lan\n",
		"tos not agreed":             "[global]\nport=443\n[[host]]\npattern=a\\.x\\.com\ncert=auto\ntarget_host=x.lan\n",
		"domain outside the pattern": auto + "[[host]]\npattern=*.x\\.com\ncert=auto\ncert_domains=a.y.com\ntarget_host=x.lan\n",
		"wildcard":                   auto + "[[host]]\npattern=*.x\\.com\ncert=auto\ncert_domains=*.x.com\ntarget_host=x.lan\n",
		"auto without sni":           auto + "[[host]]\npattern=NONE\ncert=auto\ntarget_host=x.lan\n",
		"cert on deny":               auto + "[[host]]\npattern=.*\naction=deny\ncert=auto\n",
		"upstream_tls without cert":  auto + "[[host]]\npattern=.*\nupstream_tls=true\ntarget_host=x.lan\n",
		"cert_domains without auto":  auto + "[[host]]\npattern=.*\ncert=/tmp\ncert_domains=a.x.com\ntarget_host=x.lan\n",
		"bad bool":                   auto + "[[host]]\npattern=.*\ncert=/tmp\nupstream_tls=maybe\ntarget_host=x.lan\n",
		"bad ip":                     "[global]\nport=443\npublic_ip_address=not-an-ip\n",
		"bad threshold":              "[global]\nport=443\nexpiry_threshold_days=0\n",
	} {
		if _, err := ParseConfig(text); err == nil {
			t.Errorf("%s: should be rejected", name)
		}
	}
}

func TestRenewalScheduleAndPriority(t *testing.T) {
	leaf := func(life, age time.Duration) *tls.Certificate {
		nb := time.Now().Add(-age)
		return &tls.Certificate{Leaf: &x509.Certificate{NotBefore: nb, NotAfter: nb.Add(life)}}
	}
	day := 24 * time.Hour
	// 90-day certificate: due 15 days before expiry. 6-day certificate: a third of its life before.
	if got := renewAt(leaf(90*day, 0).Leaf, 15); got.Sub(time.Now()).Round(day) != 75*day {
		t.Fatal(got)
	}
	if got := renewAt(leaf(6*day, 0).Leaf, 15); got.Sub(time.Now()).Round(time.Hour) != 4*day {
		t.Fatal(got)
	}
	m := NewCertManager()
	m.cfg = mustParse(t, "[global]\nport=443\nacme_agree_tos=true\npublic_ip_address=1.2.3.4\n[[host]]\npattern=*.t\\.com\ncert=auto\n"+
		"cert_domains=fresh.t.com,due-later.t.com,missing.t.com,due-sooner.t.com,expired.t.com,backoff.t.com\ntarget_host=x.lan\n")
	m.auto["fresh.t.com"] = leaf(90*day, 10*day)
	m.auto["due-later.t.com"] = leaf(90*day, 80*day)
	m.auto["due-sooner.t.com"] = leaf(90*day, 88*day)
	m.auto["expired.t.com"] = leaf(90*day, 91*day)
	m.nextTry["backoff.t.com"] = time.Now().Add(time.Hour) // failed recently: left alone
	var order []string
	for _, j := range m.pendingJobs(time.Now()) {
		order = append(order, j.domain)
	}
	// Missing and expired first (config order), then renewals, most urgent first.
	if got := strings.Join(order, " "); got != "missing.t.com expired.t.com due-sooner.t.com due-later.t.com" {
		t.Fatal(got)
	}
}

// fakeDNS answers every A query with ip, and every AAAA query with ip6 if one
// is given (with no records otherwise).
func fakeDNS(t *testing.T, ip string, ip6 ...string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := buf[:n]
			end := 12 // skip the question name
			for end < n && q[end] != 0 {
				end += int(q[end]) + 1
			}
			end += 5
			if n < 12 || end > n {
				continue
			}
			resp := append([]byte(nil), q[:end]...)
			resp[2], resp[3] = 0x81, 0x80 // response, recursion available
			binary.BigEndian.PutUint16(resp[6:], 0)
			binary.BigEndian.PutUint16(resp[8:], 0)
			binary.BigEndian.PutUint16(resp[10:], 0)
			if binary.BigEndian.Uint16(q[end-4:]) == 1 { // type A
				binary.BigEndian.PutUint16(resp[6:], 1)
				resp = append(resp, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
				resp = append(resp, net.ParseIP(ip).To4()...)
			} else if binary.BigEndian.Uint16(q[end-4:]) == 28 && len(ip6) > 0 { // type AAAA
				binary.BigEndian.PutUint16(resp[6:], 1)
				resp = append(resp, 0xc0, 12, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16)
				resp = append(resp, net.ParseIP(ip6[0]).To16()...)
			}
			pc.WriteTo(resp, addr)
		}
	}()
	return pc.LocalAddr().String()
}

func TestDNSPreCheckUsesTheConfiguredResolvers(t *testing.T) {
	t.Parallel()
	dns := fakeDNS(t, "203.0.113.7")
	cfg := func(ips string) *Config {
		return mustParse(t, fmt.Sprintf("[global]\nport=443\ndns_resolvers=%s\npublic_ip_address=%s\n", dns, ips))
	}
	ctx, cancel := context.WithTimeout(context.Background(), T)
	defer cancel()
	if err := checkDNS(ctx, cfg("198.51.100.1;203.0.113.7"), "www.example.test"); err != nil {
		t.Fatalf("should pass: %v", err)
	}
	err := checkDNS(ctx, cfg("198.51.100.1"), "www.example.test")
	if err == nil || !strings.Contains(err.Error(), "203.0.113.7") || !strings.Contains(err.Error(), "not asking the CA") {
		t.Fatalf("should name the mismatch: %v", err)
	}
	if err := checkDNS(ctx, mustParse(t, "[global]\nport=443\n"), "anything.test"); err != nil {
		t.Fatalf("no public_ip_address = check skipped: %v", err)
	}
	// A and AAAA: the CA prefers IPv6, so a right A record is not enough when
	// the AAAA record leads elsewhere. Both must be ours.
	dns = fakeDNS(t, "203.0.113.7", "2001:db8::bad")
	err = checkDNS(ctx, cfg("203.0.113.7"), "www.example.test")
	if err == nil || !strings.Contains(err.Error(), "of which 2001:db8::bad is not in public_ip_address") || !strings.Contains(err.Error(), "prefers IPv6") {
		t.Fatalf("a stray AAAA record must fail the pre-check: %v", err)
	}
	if err := checkDNS(ctx, cfg("203.0.113.7; 2001:DB8::BAD"), "www.example.test"); err != nil {
		t.Fatalf("both addresses listed (in any spelling): %v", err)
	}
}

func TestIssuanceRetriesAndLogging(t *testing.T) {
	cfg := mustParse(t, "[global]\nport=443\nacme_agree_tos=true\npublic_ip_address=1.2.3.4\n[[host]]\npattern=*.retry\\.test\ncert=auto\n"+
		"cert_domains=flaky.retry.test,wrongdns.retry.test,down.retry.test\ntarget_host=x.lan\n")
	m := NewCertManager()
	m.cfg = cfg
	calls := map[string]int{}
	m.issueFunc = func(_ context.Context, _ *Config, domain string) error {
		calls[domain]++
		switch {
		case domain == "flaky.retry.test" && calls[domain] < 3:
			return fmt.Errorf("connection reset by peer")
		case domain == "wrongdns.retry.test":
			return permanentError{fmt.Errorf("DNS pre-check: resolves elsewhere")}
		case domain == "down.retry.test":
			return fmt.Errorf("ACME API unreachable")
		}
		return nil
	}
	mark := len(testLog.String())
	for _, job := range m.pendingJobs(time.Now()) {
		m.runJob(cfg, job)
	}
	log := testLog.String()[mark:]
	// A temporary failure is ridden out within the same job; a pointless one is not repeated.
	if calls["flaky.retry.test"] != 3 || calls["wrongdns.retry.test"] != 1 || calls["down.retry.test"] != 3 {
		t.Fatalf("attempts: %v", calls)
	}
	for _, want := range []string{
		"flaky.retry.test: issuing a new certificate (no certificate yet",
		"flaky.retry.test: attempt 1/3 failed: connection reset by peer; trying again in 50ms",
		"flaky.retry.test: attempt 2/3 failed",
		"wrongdns.retry.test: attempt 1/3 failed: DNS pre-check: resolves elsewhere (not retried right away",
		"down.retry.test: attempt 3/3 failed: ACME API unreachable",
		"down.retry.test: giving up for now; next attempt at ",
		"(in 6h00m00s); clients get a self-signed placeholder meanwhile",
	} {
		if !strings.Contains(log, want) {
			t.Errorf("log lacks %q\n%s", want, log)
		}
	}
	if strings.Contains(log, "flaky.retry.test: giving up") {
		t.Error("flaky name succeeded on the third attempt and must not back off")
	}
	// Until the 6-hour mark the failed names are left alone (the fake issuer
	// installs nothing, so the name that succeeded still counts as missing)...
	names := func(jobs []certJob) string {
		var out []string
		for _, j := range jobs {
			out = append(out, j.domain)
		}
		return strings.Join(out, " ")
	}
	if got := names(m.pendingJobs(time.Now().Add(5 * time.Hour))); got != "flaky.retry.test" {
		t.Fatalf("retried too early: %s", got)
	}
	// ...then they are retried, and the log says why.
	mark = len(testLog.String())
	later := m.pendingJobs(time.Now().Add(6*time.Hour + time.Minute))
	if got := names(later); got != "flaky.retry.test wrongdns.retry.test down.retry.test" {
		t.Fatal(got)
	}
	m.runJob(cfg, later[2])
	if log := testLog.String()[mark:]; !strings.Contains(log, "down.retry.test: issuing a new certificate, scheduled retry (the previous attempt failed: ACME API unreachable)") {
		t.Errorf("retry log:\n%s", log)
	}

	// Status lines: new name, healthy, expiring, expired.
	day := 24 * time.Hour
	leaf := func(age time.Duration) *tls.Certificate {
		nb := time.Now().Add(-age)
		return &tls.Certificate{Leaf: &x509.Certificate{NotBefore: nb, NotAfter: nb.Add(90 * day), Issuer: pkix.Name{CommonName: "R11"}}}
	}
	for want, c := range map[string]*tls.Certificate{
		"no certificate yet, will be issued":        nil,
		`(79 days left), issuer "R11", renews from`: leaf(10 * day),
		"expiring: valid until":                     leaf(80 * day),
		"EXPIRED on":                                leaf(91 * day),
	} {
		if got := certStatus(c, 15, time.Now()); !strings.Contains(got, want) {
			t.Errorf("status %q lacks %q", got, want)
		}
	}
}

func TestUpstreamSNIDefaultsToTheClientsName(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	certPEM, keyPEM := ca.issue(t, time.Hour, "app.sni.test", "override.internal")
	cert, _ := tls.X509KeyPair(certPEM, keyPEM)
	// An upstream that, like an SNI router, refuses connections without SNI
	// and reports the name it was asked for.
	port := backend(t, func(c *net.TCPConn) {
		var asked string
		tc := tls.Server(c, &tls.Config{GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if asked = h.ServerName; asked == "" {
				return nil, fmt.Errorf("no SNI")
			}
			return &cert, nil
		}})
		if tc.Handshake() == nil {
			fmt.Fprintf(tc, "sni=%s", asked)
			tc.CloseWrite()
		}
	})
	dir := ca.certDir(t, "app.sni.test", "other.sni.test")
	p := startProxy(t, "", fmt.Sprintf(
		"[[host]]\npattern=app\\.sni\\.test\ncert=%s\nupstream_tls_verify=false\ntarget_host=127.0.0.1\ntarget_port=%d\n"+
			"[[host]]\npattern=other\\.sni\\.test\ncert=%s\nupstream_sni=Override.Internal\nupstream_tls_verify=false\ntarget_host=127.0.0.1\ntarget_port=%d\n",
		dir, port, dir, port))
	for name, want := range map[string]string{"app.sni.test": "sni=app.sni.test", "other.sni.test": "sni=override.internal"} {
		tc, err := tlsDial(t, p, &tls.Config{RootCAs: ca.pool, ServerName: name})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := string(readToEnd(t, tc)); got != want {
			t.Fatalf("%s: upstream saw %q, want %q", name, got, want)
		}
	}
	for _, bad := range []string{
		"[global]\nport=1\n[[host]]\npattern=.*\ncert=/tmp\nupstream_sni=not a name\ntarget_host=x.lan\n",
		"[global]\nport=1\n[[host]]\npattern=.*\ncert=/tmp\nupstream_tls=false\nupstream_sni=a.b.com\ntarget_host=x.lan\n",
		"[global]\nport=1\n[[host]]\npattern=.*\nupstream_sni=a.b.com\ntarget_host=x.lan\n",
	} {
		if _, err := ParseConfig(bad); err == nil {
			t.Errorf("should be rejected: %q", bad)
		}
	}
}

func TestForeignTLSALPN01ChallengeGoesToTheUpstream(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	// The upstream runs its own ACME client: it answers acme-tls/1 itself.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	upstreamAnswer, _ := (&acme.Client{Key: key}).TLSALPN01ChallengeCert("upstream-token", "vq.test")
	tlsPort := backend(t, func(c *net.TCPConn) {
		tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{upstreamAnswer}, NextProtos: []string{acme.ALPNProto}})
		tc.Handshake()
	})
	dir := ca.certDir(t, "vq.test", "plain.test")
	p := startProxy(t, "", fmt.Sprintf(
		"[[host]]\npattern=vq\\.test\ncert=%s\nupstream_tls_verify=false\ntarget_host=127.0.0.1\ntarget_port=%d\n"+
			"[[host]]\npattern=plain\\.test\ncert=%s\nupstream_tls=false\ntarget_host=127.0.0.1\ntarget_port=%d\n",
		dir, tlsPort, dir, echoBackend(t, "")))
	challenge := func(name string) (*tls.Conn, error) {
		return tlsDial(t, p, &tls.Config{InsecureSkipVerify: true, ServerName: name, NextProtos: []string{acme.ALPNProto}})
	}

	// Not our challenge + TLS upstream: the CA must reach the UPSTREAM's answer,
	// even though this rule normally terminates TLS here.
	tc, err := challenge("vq.test")
	if err != nil {
		t.Fatal(err)
	}
	st := tc.ConnectionState()
	if st.NegotiatedProtocol != acme.ALPNProto || !bytes.Equal(st.PeerCertificates[0].Raw, upstreamAnswer.Certificate[0]) {
		t.Fatalf("the CA did not get the upstream's challenge certificate (alpn=%q)", st.NegotiatedProtocol)
	}
	// Ordinary clients of the same name are still terminated here.
	tc, err = tlsDial(t, p, &tls.Config{RootCAs: ca.pool, ServerName: "vq.test"})
	if err != nil || tc.ConnectionState().PeerCertificates[0].Subject.CommonName != "vq.test" {
		t.Fatalf("normal traffic must still be terminated here: %v", err)
	}

	// Once WE have a challenge pending for the name, we answer it ourselves.
	ours, _ := (&acme.Client{Key: key}).TLSALPN01ChallengeCert("our-token", "vq.test")
	m := p.srv.certs
	m.mu.Lock()
	m.challenges["vq.test"] = &ours
	m.mu.Unlock()
	if tc, err = challenge("vq.test"); err != nil || !bytes.Equal(tc.ConnectionState().PeerCertificates[0].Raw, ours.Certificate[0]) {
		t.Fatalf("our own pending challenge must be answered here: %v", err)
	}

	// Not ours + plaintext upstream: nobody can answer; refuse rather than
	// present an ordinary certificate to the CA.
	if tc, err := challenge("plain.test"); err == nil {
		t.Fatalf("expected a refusal, got a handshake with %q", tc.ConnectionState().PeerCertificates[0].Subject)
	}
	if !strings.Contains(testLog.String(), "passed through untouched to the TLS upstream") {
		t.Error("the pass-through decision should be logged")
	}
}

// Names are independent: several jobs run at once, but never two for one name.
func TestCertificateJobsRunInParallelPerName(t *testing.T) {
	names := []string{"a.par.test", "b.par.test", "c.par.test", "d.par.test", "e.par.test", "f.par.test"}
	cfg := mustParse(t, fmt.Sprintf("[global]\nport=443\nacme_agree_tos=true\npublic_ip_address=1.2.3.4\ncert_path=%s\n[[host]]\npattern=*.par\\.test\ncert=auto\ncert_domains=%s\ntarget_host=x.lan\n",
		t.TempDir(), strings.Join(names, ",")))
	m := NewCertManager()
	var mu sync.Mutex
	running, peak, done := map[string]int{}, 0, map[string]int{}
	m.issueFunc = func(_ context.Context, _ *Config, domain string) error {
		mu.Lock()
		running[domain]++
		if running[domain] > 1 {
			t.Errorf("%s: two jobs at the same time", domain)
		}
		peak = max(peak, len(running))
		mu.Unlock()
		time.Sleep(150 * time.Millisecond)
		nb := time.Now()
		m.mu.Lock()
		m.auto[domain] = &tls.Certificate{Leaf: &x509.Certificate{NotBefore: nb, NotAfter: nb.Add(90 * 24 * time.Hour)}}
		m.mu.Unlock()
		mu.Lock()
		delete(running, domain)
		done[domain]++
		mu.Unlock()
		return nil
	}
	if err := m.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	m.Start()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		mu.Lock()
		n := len(done)
		mu.Unlock()
		if n == len(names) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d of %d names issued", n, len(names))
		}
	}
	time.Sleep(300 * time.Millisecond) // a wrongly repeated job would show up now
	mu.Lock()
	defer mu.Unlock()
	if peak != maxParallelJobs {
		t.Errorf("peak concurrency %d, want %d", peak, maxParallelJobs)
	}
	for _, d := range names {
		if done[d] != 1 {
			t.Errorf("%s issued %d times", d, done[d])
		}
	}
}
