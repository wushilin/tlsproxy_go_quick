package main

// Renewal, tested mechanically: certificates are made to look as they will
// some weeks from now (a few days from expiry, or still well inside their
// life), then the renewal pass, the worker or a client's handshake runs, and
// what is on disk, in memory and in the handshake is compared.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const day = 24 * time.Hour

// leafWithDaysLeft is a certificate of l for name, issued life ago-plus-left
// and expiring in left: how a certificate looks after time has passed.
func leafWithDaysLeft(t *testing.T, l *localCA, name string, life, left time.Duration, serial int64) *tls.Certificate {
	t.Helper()
	ca := l.ca.Load()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: now.Add(left - life), NotAfter: now.Add(left),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// install puts c in place as name's certificate, on disk and in memory, as
// if it had been issued earlier in this run.
func install(t *testing.T, l *localCA, name string, c *tls.Certificate) {
	t.Helper()
	if err := l.save(name, c); err != nil {
		t.Fatal(err)
	}
	l.entry(name).cur.Store(&leafState{cert: c, ca: l.ca.Load()})
}

// ageCA re-signs the CA in dir with its own key, subject and lifetime so that
// it expires in left: the CA as it will be near the end of its life.
func ageCA(t *testing.T, dir string, left time.Duration) *x509.Certificate {
	t.Helper()
	keyPEM, _ := os.ReadFile(filepath.Join(dir, "ca_key.pem"))
	key, err := parseSigner(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	old, err := readCertFile(filepath.Join(dir, "ca_cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	life := old.NotAfter.Sub(old.NotBefore)
	now := time.Now()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(4242), Subject: old.Subject, NotBefore: now.Add(left - life), NotAfter: now.Add(left),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: old.SubjectKeyId}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca_cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

// served is the certificate a client gets for name, checked against roots.
func served(t *testing.T, p *proxyUnderTest, name string, roots *x509.CertPool) *x509.Certificate {
	t.Helper()
	tc, err := tlsDial(t, p, &tls.Config{ServerName: name, RootCAs: roots})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	defer tc.Close()
	return tc.ConnectionState().PeerCertificates[0]
}

// A local CA less than 15 days from expiry is renewed by the renewal pass,
// with the same key, so what it issued stays valid; a CA with years left is
// left exactly as it is.
func TestRenewalPassRenewsOnlyDueCAs(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	makeCA(t, root, "ca001")
	makeCA(t, root, "ca002")
	cfg := mustParse(t, "[[listener]]\nname=default\nport=1\n[global]\ncert_root="+root+"\n"+
		"[[host]]\nlistener=default\npattern=a.test\ncert=local-ca\ntarget_host=h\ntarget_port=443\n"+
		"[[host]]\nlistener=default\npattern=b.test\ncert=local-ca:ca002\ntarget_host=h\ntarget_port=443\n")
	m := NewCertManager()
	if err := m.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	due, fresh := m.LocalCA(cfg, "ca001"), m.LocalCA(cfg, "ca002")
	issued, err := due.certificate("a.test")
	if err != nil {
		t.Fatal(err)
	}
	aged := ageCA(t, due.dir, 14*day) // years old, 14 days left (the pass reads the CA from disk)
	freshBefore, _ := os.ReadFile(filepath.Join(fresh.dir, "ca_cert.pem"))
	freshMem := fresh.ca.Load().cert

	m.renewLocalCAs(context.Background())

	renewed := due.ca.Load().cert
	life := aged.NotAfter.Sub(aged.NotBefore)
	if got := renewed.NotAfter.Sub(renewed.NotBefore); got < life-day || got > life+day || renewed.NotAfter.Before(time.Now().Add(life-2*day)) {
		t.Fatalf("a CA 14 days from expiry is renewed for its own lifetime (%s): %s, until %s", life, got, renewed.NotAfter)
	}
	if onDisk, _ := readCertFile(filepath.Join(due.dir, "ca_cert.pem")); !onDisk.Equal(renewed) {
		t.Fatal("the renewed CA certificate is written to disk")
	}
	if renewed.Subject.String() != aged.Subject.String() || !publicKeyMatches(renewed, due.ca.Load().key) {
		t.Fatal("renewed with the same subject and key")
	}
	if err := issued.Leaf.CheckSignatureFrom(renewed); err != nil {
		t.Fatalf("what the CA issued before still verifies: %v", err)
	}
	if after, _ := os.ReadFile(filepath.Join(fresh.dir, "ca_cert.pem")); string(after) != string(freshBefore) {
		t.Fatal("a CA with years left must not be renewed: its file changed")
	}
	if fresh.ca.Load().cert != freshMem {
		t.Fatal("a CA with years left must not be renewed: the one in use changed")
	}
}

// A certificate a local CA issued, 14 days from expiry part way through a
// run, is renewed by the renewal pass, and the next handshake serves the
// renewed one. One with 45 of 90 days left (due at 30) is not touched, by
// the pass or by a handshake.
func TestLocalCertificateRenewedMidRun(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	makeCA(t, root, "ca001")
	p := startProxy(t, "cert_root="+root, fmt.Sprintf("[[host]]\nlistener=default\npattern=*.mid\\.test\ncert=local-ca\ncert_domains=*.mid.test\n"+
		"upstream_tls=false\ntarget_host=127.0.0.1\ntarget_port=%d\n", echoBackend(t, "E")))
	m := p.srv.certs
	l := m.LocalCA(p.srv.runtime.Load().cfg, "ca001")
	roots := x509.NewCertPool()
	roots.AddCert(l.ca.Load().cert)

	// Start of the run: both names get their first certificate.
	first := served(t, p, "due.mid.test", roots)
	if first.NotAfter.Before(time.Now().Add(80 * day)) {
		t.Fatalf("issued for 90 days: until %s", first.NotAfter)
	}
	served(t, p, "keep.mid.test", roots)

	// Weeks later: one is 14 days from expiry, the other has 45 left.
	install(t, l, "due.mid.test", leafWithDaysLeft(t, l, "due.mid.test", 90*day, 14*day, 1001))
	install(t, l, "keep.mid.test", leafWithDaysLeft(t, l, "keep.mid.test", 90*day, 45*day, 1002))

	m.renewLocalCAs(context.Background()) // the 6-hourly pass

	if s := diskSerial(t, l, "due.mid.test"); s.Int64() == 1001 {
		t.Fatal("a certificate 14 days from expiry is renewed by the pass")
	}
	if s := diskSerial(t, l, "keep.mid.test"); s.Int64() != 1002 {
		t.Fatal("a certificate with 45 of 90 days left is not renewed")
	}
	got := served(t, p, "due.mid.test", roots)
	if got.SerialNumber.Cmp(diskSerial(t, l, "due.mid.test")) != 0 || got.NotAfter.Before(time.Now().Add(80*day)) {
		t.Fatalf("the next handshake serves the renewed certificate: serial %s until %s", got.SerialNumber, got.NotAfter)
	}
	if got := served(t, p, "keep.mid.test", roots); got.SerialNumber.Int64() != 1002 {
		t.Fatalf("the certificate that is not due keeps being served: serial %s", got.SerialNumber)
	}

	// Without the pass, the handshake itself renews a due certificate.
	install(t, l, "due.mid.test", leafWithDaysLeft(t, l, "due.mid.test", 90*day, 14*day, 1003))
	if got := served(t, p, "due.mid.test", roots); got.SerialNumber.Int64() == 1003 || got.NotAfter.Before(time.Now().Add(80*day)) {
		t.Fatalf("a handshake for a due certificate gets a renewed one: serial %s until %s", got.SerialNumber, got.NotAfter)
	}
	if s := diskSerial(t, l, "due.mid.test"); s.Int64() == 1003 {
		t.Fatal("and it is written to disk")
	}
}

// The worker's pass is bounded by localRenewTimeout: it stops when the time
// is up, and what it did not get to is left for the next pass (or a
// handshake). A pass that is still running is not started again.
// Not parallel: it sets localRenewTimeout and beforeLocalRenew.
func TestRenewalPassTimeLimit(t *testing.T) {
	root := t.TempDir()
	makeCA(t, root, "ca001")
	cfg := mustParse(t, "[[listener]]\nname=default\nport=1\n[global]\ncert_root="+root+"\n"+
		"[[host]]\nlistener=default\npattern=*.slow.test\ncert=local-ca\ncert_domains=*.slow.test\ntarget_host=h\ntarget_port=443\n")
	m := NewCertManager()
	if err := m.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	l := m.LocalCA(cfg, "ca001")
	const n = 6
	for i := range n {
		name := fmt.Sprintf("n%d.slow.test", i)
		install(t, l, name, leafWithDaysLeft(t, l, name, 90*day, 10*day, int64(2000+i)))
	}
	timeout, hook := localRenewTimeout, beforeLocalRenew
	t.Cleanup(func() { localRenewTimeout, beforeLocalRenew = timeout, hook })
	var looked atomic.Int32
	localRenewTimeout = 250 * time.Millisecond
	beforeLocalRenew = func(string, string) { looked.Add(1); time.Sleep(100 * time.Millisecond) } // a slow disk

	m.startLocalPass()
	if m.startLocalPass(); !m.localPass.Load() {
		t.Fatal("the pass runs in the background")
	}
	for deadline := time.Now().Add(T); m.localPass.Load(); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the pass did not stop at its time limit")
		}
	}
	renewed := 0
	for i := range n {
		if diskSerial(t, l, fmt.Sprintf("n%d.slow.test", i)).Int64() != int64(2000+i) {
			renewed++
		}
	}
	if renewed == 0 || renewed == n || looked.Load() >= n {
		t.Fatalf("stopped part way: %d of %d renewed, %d looked at", renewed, n, looked.Load())
	}
	if !strings.Contains(testLog.String(), "renewal pass stopped after") {
		t.Fatalf("the stop is logged:\n%s", testLog.String())
	}
	// The next pass is localRenewInterval after this one started: not now.
	beforeLocalRenew = nil
	m.startLocalPass()
	if m.localPass.Load() {
		t.Fatal("a pass started again before localRenewInterval")
	}
	// When it comes, it renews the rest.
	m.localRenewed = time.Now().Add(-localRenewInterval)
	m.startLocalPass()
	for deadline := time.Now().Add(T); m.localPass.Load(); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the next pass did not finish")
		}
	}
	for i := range n {
		if s := diskSerial(t, l, fmt.Sprintf("n%d.slow.test", i)); s.Int64() == int64(2000+i) {
			t.Fatalf("n%d: the next pass renews what the first did not get to", i)
		}
	}
}

// An ACME certificate (from Pebble, in this process) that is 14 days from
// expiry is renewed by the worker without anyone asking, and the next
// handshake serves the new one; one with most of its 90 days left is not
// renewed.
func TestPebbleRenewsDueCertificate(t *testing.T) {
	t.Parallel()
	pb := newPebble(t, nil)
	root := t.TempDir()
	p := startProxy(t, pb.global(root),
		fmt.Sprintf("[[host]]\nlistener=default\npattern=*.renew\\.test\ncert=auto\ncert_domains=due.renew.test, keep.renew.test\n"+
			"upstream_tls=false\ntarget_host=127.0.0.1\ntarget_port=%d\n", echoBackend(t, "E")))
	_, proxyPort, _ := net.SplitHostPort(p.addr)
	m := p.srv.certs
	pb.start(t, proxyPort)
	retryCertificatesNow(m)
	auto := func(d string) *tls.Certificate {
		m.mu.RLock()
		defer m.mu.RUnlock()
		return m.auto[d]
	}
	for deadline := time.Now().Add(90 * time.Second); auto("due.renew.test") == nil || auto("keep.renew.test") == nil; time.Sleep(200 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("no certificates from Pebble after 90s; proxy log:\n%s", testLog.String())
		}
	}
	roots := pb.roots(t)
	keep := auto("keep.renew.test")
	if left := time.Until(keep.Leaf.NotAfter); left < 80*day {
		t.Fatalf("Pebble issues for 90 days: %s left", left)
	}
	if jobs := m.pendingJobs(time.Now()); len(jobs) != 0 {
		t.Fatalf("freshly issued certificates are not due: %+v", jobs)
	}

	// Weeks later: due.renew.test is 14 days from expiry (on disk and in
	// memory, as after a restart or a long run).
	cfg := p.srv.runtime.Load().cfg
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(3001), Subject: pkix.Name{CommonName: "due.renew.test"}, DNSNames: []string{"due.renew.test"},
		NotBefore: now.Add(-76 * day), NotAfter: now.Add(14 * day), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	dir := autoDir(cfg, "due.renew.test")
	os.WriteFile(filepath.Join(dir, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600)
	os.WriteFile(filepath.Join(dir, "cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	m.loadAutoFromDisk(cfg, "due.renew.test")
	if s := auto("due.renew.test").Leaf.SerialNumber.Int64(); s != 3001 {
		t.Fatalf("the aged certificate is the one in use: serial %d", s)
	}
	if jobs := m.pendingJobs(time.Now()); len(jobs) != 1 || jobs[0].domain != "due.renew.test" || jobs[0].urgent {
		t.Fatalf("only the certificate 14 days from expiry is due (a renewal, not urgent): %+v", jobs)
	}

	m.wake <- struct{}{} // the worker's next check (every 10 minutes)
	for deadline := time.Now().Add(90 * time.Second); auto("due.renew.test").Leaf.SerialNumber.Int64() == 3001; time.Sleep(200 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("not renewed after 90s; proxy log:\n%s", testLog.String())
		}
	}
	renewed := auto("due.renew.test")
	if !strings.Contains(renewed.Leaf.Issuer.CommonName, "Pebble") || time.Until(renewed.Leaf.NotAfter) < 80*day {
		t.Fatalf("renewed by the CA for 90 days: issuer %q until %s", renewed.Leaf.Issuer.CommonName, renewed.Leaf.NotAfter)
	}
	if onDisk, err := readCertFile(filepath.Join(dir, "cert.pem")); err != nil || !onDisk.Equal(renewed.Leaf) {
		t.Fatalf("the renewed certificate is on disk: %v", err)
	}
	if got := served(t, p, "due.renew.test", roots); !got.Equal(renewed.Leaf) {
		t.Fatalf("the next handshake serves the renewed certificate: serial %s", got.SerialNumber)
	}
	if auto("keep.renew.test") != keep || !served(t, p, "keep.renew.test", roots).Equal(keep.Leaf) {
		t.Fatal("the certificate that is not due is neither renewed nor replaced")
	}
	if log := testLog.String(); !strings.Contains(log, "cert: due.renew.test: renewing") || strings.Contains(log, "cert: keep.renew.test: renewing") {
		t.Fatalf("the log says which was renewed:\n%s", log)
	}
}
