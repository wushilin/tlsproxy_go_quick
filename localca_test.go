package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	mrand "math/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// trustCA is a pool with the CA in dir.
func trustCA(t *testing.T, dir string) *x509.CertPool {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "ca_cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		t.Fatal("no CA certificate")
	}
	return pool
}

// A rule with cert = local-ca: the CA is made on first use, a certificate is
// issued for the name a client asks for and kept on disk, and a restart uses
// it again.
func TestLocalCAIssuesOnDemand(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	makeCA(t, root, "ca002") // a rule only uses a CA that exists (made on the CAs page)
	port := echoBackend(t, "L:")
	rules := fmt.Sprintf("[[host]]\nlistener=default\npattern=*.lan.test\ncert=local-ca:ca002\nupstream_tls=false\ntarget_host=127.0.0.1\ntarget_port=%d\n", port)
	p := startProxy(t, "ca_root="+root, rules)
	caDir := filepath.Join(root, "ca002")
	pool := trustCA(t, caDir)

	tc, err := tlsDial(t, p, &tls.Config{RootCAs: pool, ServerName: "app.lan.test"})
	if err != nil {
		t.Fatalf("a client trusting the CA must accept the certificate: %v", err)
	}
	leaf := tc.ConnectionState().PeerCertificates[0]
	tc.Write([]byte("x"))
	if got := string(readN(t, tc, 3)); got != "L:x" {
		t.Fatal(got)
	}
	tc.Close()
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "app.lan.test" {
		t.Fatalf("names: %v", leaf.DNSNames)
	}
	if _, err := os.Stat(filepath.Join(caDir, "app.lan.test", "key.pem")); err != nil {
		t.Fatal("the certificate is not kept on disk:", err)
	}

	// A new process with the same ca_root serves the same certificate.
	p2 := startProxy(t, "ca_root="+root, rules)
	tc, err = tlsDial(t, p2, &tls.Config{RootCAs: pool, ServerName: "app.lan.test"})
	if err != nil {
		t.Fatal(err)
	}
	if again := tc.ConnectionState().PeerCertificates[0]; again.SerialNumber.Cmp(leaf.SerialNumber) != 0 {
		t.Fatal("after a restart the certificate on disk must be used, not a new one issued")
	}
	tc.Close()
}

// A certificate in the folder that this CA did not issue is never used: it
// is moved to the archive, and a new one is issued.
func TestLocalCAArchivesForeignCertificates(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	caDir := filepath.Join(root, "ca001")
	l, err := openLocalCA("ca001", caDir, true)
	if err != nil {
		t.Fatal(err)
	}
	other := newTestCA(t) // someone else's CA
	certPEM, keyPEM := other.issue(t, time.Hour, "foreign.test")
	os.MkdirAll(filepath.Join(caDir, "foreign.test"), 0o700)
	os.WriteFile(filepath.Join(caDir, "foreign.test", "cert.pem"), certPEM, 0o600)
	os.WriteFile(filepath.Join(caDir, "foreign.test", "key.pem"), keyPEM, 0o600)

	c, err := l.certificate("foreign.test")
	if err != nil {
		t.Fatal(err)
	}
	if c.Leaf.CheckSignatureFrom(l.ca.Load().cert) != nil {
		t.Fatal("served a certificate this CA did not issue")
	}
	archived, _ := os.ReadDir(filepath.Join(caDir, localArchiveName))
	if len(archived) != 1 || !strings.HasPrefix(archived[0].Name(), "foreign.test-") {
		t.Fatalf("archive: %v", archived)
	}
	moved, _ := os.ReadFile(filepath.Join(caDir, localArchiveName, archived[0].Name(), "cert.pem"))
	if string(moved) != string(certPEM) {
		t.Fatal("the foreign certificate must be kept in the archive as it was")
	}

	// Archived folders older than 14 days are deleted; younger ones stay.
	old := filepath.Join(caDir, localArchiveName, "stale.test-"+time.Now().Add(-15*24*time.Hour).UTC().Format("20060102150405"))
	os.MkdirAll(old, 0o700)
	l.pruneArchive()
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("an archive older than 14 days must be deleted")
	}
	if _, err := os.Stat(filepath.Join(caDir, localArchiveName, archived[0].Name())); err != nil {
		t.Fatal("a recent archive must stay")
	}
}

// A self-signed CA's certificate is renewed with the same key and subject:
// what it issued before still verifies against the new one.
func TestLocalCARenewsWithTheSameKey(t *testing.T) {
	t.Parallel()
	caDir := filepath.Join(t.TempDir(), "ca001")
	l, err := openLocalCA("ca001", caDir, true)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := l.certificate("keep.test")
	if err != nil {
		t.Fatal(err)
	}
	before := l.ca.Load().cert
	// Make the CA certificate due: re-sign it with a short life, same key.
	key := l.ca.Load().key
	// Same 10-year lifetime as when it was made, nearly over: due.
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: before.Subject, NotBefore: before.NotBefore.Add(-before.NotAfter.Sub(before.NotBefore) + 24*time.Hour),
		NotAfter: before.NotBefore.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: before.SubjectKeyId}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	os.WriteFile(filepath.Join(caDir, "ca_cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	if err := l.renewCA(); err != nil {
		t.Fatal(err)
	}
	after := l.ca.Load().cert
	if after.NotAfter.Before(time.Now().Add(365*24*time.Hour)) || after.Subject.String() != before.Subject.String() {
		t.Fatalf("not renewed: until %s, subject %s", after.NotAfter, after.Subject)
	}
	if err := issued.Leaf.CheckSignatureFrom(after); err != nil {
		t.Fatalf("a certificate issued before the renewal must verify against the renewed CA: %v", err)
	}
	if k, _ := os.ReadFile(filepath.Join(caDir, "ca_key.pem")); !strings.Contains(string(k), "PRIVATE KEY") {
		t.Fatal("key gone")
	}
}

// An external CA (an intermediate under someone's root) is pasted in: the
// certificates it issues come with the intermediate, so clients that trust
// the root accept them.
func TestImportedIntermediateCA(t *testing.T) {
	t.Parallel()
	root := newTestCA(t)
	ikey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	itmpl := &x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "Corp Issuing CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(5 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	ider, _ := x509.CreateCertificate(rand.Reader, itmpl, root.cert, &ikey.PublicKey, root.key)
	ikeyDER, _ := x509.MarshalPKCS8PrivateKey(ikey)
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ider}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.cert.Raw})...)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ikeyDER})

	dir := filepath.Join(t.TempDir(), "ca003")
	if _, err := importCA(dir, chain, keyPEM); err != nil {
		t.Fatal(err)
	}
	if _, err := importCA(dir, chain, keyPEM); err == nil {
		t.Fatal("importing over an existing CA must be refused")
	}
	l, err := openLocalCA("ca003", dir, false)
	if err != nil {
		t.Fatal(err)
	}
	c, err := l.certificate("svc.corp.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Certificate) != 2 {
		t.Fatalf("served %d certificates; want the leaf and the intermediate (not the root)", len(c.Certificate))
	}
	inter, _ := x509.ParseCertificate(c.Certificate[1])
	if _, err := c.Leaf.Verify(x509.VerifyOptions{Roots: root.pool, Intermediates: certPool(inter), DNSName: "svc.corp.test"}); err != nil {
		t.Fatalf("a client trusting the corporate root must accept it: %v", err)
	}

	// Mistakes are refused with a reason.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherDER, _ := x509.MarshalPKCS8PrivateKey(other)
	leafPEM, leafKey := root.issue(t, time.Hour, "not-a-ca.test")
	for name, tc := range map[string]struct{ cert, key []byte }{
		"wrong key":   {chain, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: otherDER})},
		"not a CA":    {leafPEM, leafKey},
		"no key":      {chain, []byte("nothing")},
		"chain order": {append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ider}), leafPEM...), keyPEM},
	} {
		if _, err := importCA(filepath.Join(t.TempDir(), "ca009"), tc.cert, tc.key); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func certPool(certs ...*x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	for _, c := range certs {
		p.AddCert(c)
	}
	return p
}

// cert_domains limits which names a local CA issues for; others get the
// placeholder. The config checks the CA name.
func TestLocalCAConfig(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	makeCA(t, root, "ca001") // a rule only uses a CA that exists (made on the CAs page)
	cfg := mustParse(t, "[[listener]]\nname=default\nport=1\n[global]\nca_root="+root+"\n[[host]]\nlistener=default\npattern=*.x.test\ncert=local-ca\ncert_domains=a.x.test\ntarget_host=h\ntarget_port=443\n")
	if r := cfg.Rules[0]; r.LocalCA() != "ca001" {
		t.Fatalf("plain local-ca is ca001, got %q", r.LocalCA())
	}
	m := NewCertManager()
	if err := m.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	if c, _ := m.CertificateFor(&cfg.Rules[0], "a.x.test"); c.Leaf.Issuer.CommonName != "tlsproxy CA ca001" {
		t.Fatalf("listed name: issued by %q", c.Leaf.Issuer.CommonName)
	}
	if c, err := m.CertificateFor(&cfg.Rules[0], "b.x.test"); c != nil || err == nil || !strings.Contains(err.Error(), "does not issue for b.x.test") {
		t.Fatalf("a name outside cert_domains gets nothing (the client is refused): %v %v", c, err)
	}

	// Globs, several of them; a * never crosses a dot.
	g := mustParse(t, "[[listener]]\nname=default\nport=1\n[global]\nca_root="+root+"\n[[host]]\nlistener=default\npattern=ANY\ncert=local-ca\ncert_domains=*.dev.abc.com, *.prod.abc.com;*.abc.com\ntarget_host=h\ntarget_port=443\n")
	for name, want := range map[string]bool{
		"api.dev.abc.com": true, "db.prod.abc.com": true, "www.abc.com": true,
		"abc.com": false, "a.b.dev.abc.com": false, "x.qa.abc.com": false, "evil.com": false,
	} {
		if got := g.Rules[0].LocalCAIssues(name); got != want {
			t.Errorf("%s: issues=%v, want %v", name, got, want)
		}
	}
	for text, want := range map[string]string{
		"cert=local-ca:ca1":                           "three digits",
		"cert=local-ca:ca001\ncert_validate_script=x": "only applies to cert = auto",
		"cert=local-ca\ncert_domains=a.y.test":        "does not match",
		"cert=local-ca\ncert_domains=**.x.test":       "not a host name or a glob",
		"cert=local-ca\ncert_domains=ANY":             "not a host name or a glob",
	} {
		if _, err := ParseConfig("[[listener]]\nname=default\nport=1\n[[host]]\nlistener=default\npattern=*.x.test\n" + text + "\ntarget_host=h\ntarget_port=443\n"); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", text, err, want)
		}
	}
}

// The console's CA page: generate, list, download (the certificate, never
// the key), import, and delete only what no rule uses.
func TestConsoleCAPage(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	makeCA(t, root, "ca001") // a rule only uses a CA that exists (made on the CAs page)
	p, c, _ := startConsoleProxyGlobal(t, "ca_root = "+root, "password = pw",
		"[[host]]\nlistener=default\npattern=svc.lan.test\ncert=local-ca\nupstream_tls=false\ntarget_host=127.0.0.1\ntarget_port=1\n")
	_ = p
	c.login("pw")
	_, list := c.get("/api/cas")
	cas := list["cas"].([]any)
	if len(cas) != 1 || cas[0].(map[string]any)["id"] != "ca001" || list["next"] != "ca002" {
		t.Fatalf("the rule's CA (ca001) is made and listed: %v", list)
	}
	if code, out := c.post("/api/cas/delete", map[string]any{"id": "ca001"}); code != 409 || !strings.Contains(out["error"].(string), "uses ca001") {
		t.Fatalf("a CA in use must not be deleted: %d %v", code, out)
	}

	if code, out := c.post("/api/cas/generate", map[string]any{"commonName": "Lab CA"}); code != 200 || out["id"] != "ca002" {
		t.Fatalf("generate: %d %v", code, out)
	}
	resp, err := c.http.Get(c.base + "/api/cas/cert?id=ca002")
	if err != nil {
		t.Fatal(err)
	}
	body := new(strings.Builder)
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		body.Write(buf[:n])
		if err != nil {
			break
		}
	}
	resp.Body.Close()
	if !strings.Contains(body.String(), "BEGIN CERTIFICATE") || strings.Contains(body.String(), "PRIVATE KEY") {
		t.Fatal("the download must be the certificate and nothing else")
	}

	// Import an existing CA (here: a fresh one, made the way a user would).
	ext := newTestCA(t)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(ext.key)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ext.cert.Raw}))
	if code, out := c.post("/api/cas/import", map[string]any{"cert": certPEM, "key": "garbage"}); code != 400 {
		t.Fatalf("a bad key must be refused: %d %v", code, out)
	}
	if code, out := c.post("/api/cas/import", map[string]any{"cert": certPEM, "key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))}); code != 200 || out["id"] != "ca003" {
		t.Fatalf("import: %d %v", code, out)
	}

	// Delete an unused one: it goes to the archive, and its id is not reused.
	if code, out := c.post("/api/cas/delete", map[string]any{"id": "ca002"}); code != 200 {
		t.Fatalf("delete: %d %v", code, out)
	}
	_, list = c.get("/api/cas")
	if n := len(list["cas"].([]any)); n != 2 || list["next"] != "ca004" {
		t.Fatalf("after delete: %d CAs, next %v", n, list["next"])
	}
}

// Through the proxy: a name the CA does not issue for is refused before the
// target is contacted, and the flow log says why; a matching one is served.
func TestLocalCARefusesUnlistedNames(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	makeCA(t, root, "ca001") // a rule only uses a CA that exists (made on the CAs page)
	dialed := make(chan struct{}, 4)
	port := backend(t, func(c *net.TCPConn) { dialed <- struct{}{}; c.Write([]byte("B")); io.Copy(c, c) })
	p := startProxy(t, "ca_root="+root, fmt.Sprintf("[[host]]\nlistener=default\npattern=*.lan.test\ncert=local-ca\ncert_domains=ok*.lan.test\nupstream_tls=false\ntarget_host=127.0.0.1\ntarget_port=%d\n", port))
	pool := trustCA(t, filepath.Join(root, "ca001"))

	if tc, err := tlsDial(t, p, &tls.Config{RootCAs: pool, ServerName: "nope.lan.test"}); err == nil {
		tc.Close()
		t.Fatal("a name outside cert_domains must be refused")
	}
	if f := flowFor(t, p, "nope.lan.test"); f.Result != flowFailed || !strings.Contains(f.Reason, "does not issue for nope.lan.test") {
		t.Fatalf("flow: %s %q", f.Result, f.Reason)
	}
	select {
	case <-dialed:
		t.Fatal("the target was contacted for a refused name")
	default:
	}

	tc, err := tlsDial(t, p, &tls.Config{RootCAs: pool, ServerName: "ok1.lan.test"})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(readN(t, tc, 1)); got != "B" {
		t.Fatal(got)
	}
	tc.Close()
}

// Many handshakes ask for the same new name at once: one certificate is
// issued, and all of them get it.
func TestLocalCAIssuesOncePerName(t *testing.T) {
	t.Parallel()
	l, err := openLocalCA("ca001", filepath.Join(t.TempDir(), "ca001"), true)
	if err != nil {
		t.Fatal(err)
	}
	const n = 50
	got := make([]*tls.Certificate, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() { defer wg.Done(); got[i], _ = l.certificate("race.test") }()
	}
	wg.Wait()
	for _, c := range got {
		if c == nil || c.Leaf.SerialNumber.Cmp(got[0].Leaf.SerialNumber) != 0 {
			t.Fatal("racing handshakes for one name must share one certificate")
		}
	}
}

// [certificates] in the CA's config.toml shapes what it issues; [ca] can't
// be changed once the CA exists.
func TestCAConfig(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "ca001")
	l, err := openLocalCA("ca001", dir, true)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.toml")
	text, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(text), "[certificates]") {
		t.Fatalf("a new CA gets its config.toml: %v", err)
	}
	// Edit [certificates]: RSA keys, SHA-384, 30 days, client auth too, an organisation.
	edited := string(text)
	for old, new := range map[string]string{
		"[certificates]\n# What it issues": "[certificates]\n# What it issues",
	} {
		edited = strings.Replace(edited, old, new, 1)
	}
	certSection := edited[strings.Index(edited, "[certificates]"):]
	newSection := certSection
	for k, v := range map[string]string{"key_algorithm": "rsa", "key_bits": "2048", "hash_algorithm": "sha384", "validity_days": "30",
		"ext_key_usage": `"serverAuth, clientAuth"`, "key_usage": `"digitalSignature, keyEncipherment"`, "organization": "Lab"} {
		lines := strings.Split(newSection, "\n")
		for i, line := range lines {
			if strings.HasPrefix(line, k+" ") {
				lines[i] = k + " = " + v
			}
		}
		newSection = strings.Join(lines, "\n")
	}
	edited = strings.Replace(edited, certSection, newSection, 1)
	os.WriteFile(path, []byte(edited), 0o600)
	os.Chtimes(path, time.Now(), time.Now().Add(time.Second)) // a new mtime: reread
	l.loadConfig()
	if s := l.conf.Load(); s.err != "" {
		t.Fatalf("a valid edit is refused: %s", s.err)
	}
	c, err := l.certificate("svc.lab.test")
	if err != nil {
		t.Fatal(err)
	}
	leaf := c.Leaf
	if _, ok := leaf.PublicKey.(*rsa.PublicKey); !ok || leaf.SignatureAlgorithm != x509.ECDSAWithSHA384 ||
		leaf.NotAfter.Sub(leaf.NotBefore) > 31*24*time.Hour || len(leaf.ExtKeyUsage) != 2 || leaf.Subject.Organization[0] != "Lab" ||
		leaf.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
		t.Fatalf("issued as: key %T, sig %s, life %s, ext %v, org %v", leaf.PublicKey, leaf.SignatureAlgorithm, leaf.NotAfter.Sub(leaf.NotBefore), leaf.ExtKeyUsage, leaf.Subject.Organization)
	}

	// [ca] describes the CA: changing it is refused, and the settings in use stay.
	bad := strings.Replace(edited, "key_bits = 256", "key_bits = 384", 1)
	if _, err := l.parseConfig(bad); err == nil || !strings.Contains(err.Error(), "[ca] key_bits") {
		t.Fatalf("a changed [ca] must be refused: %v", err)
	}
	os.WriteFile(path, []byte(bad), 0o600)
	os.Chtimes(path, time.Now(), time.Now().Add(2*time.Second))
	l.loadConfig()
	if s := l.conf.Load(); !strings.Contains(s.err, "can't change it") || s.c.Cert.KeyAlgorithm != "rsa" {
		t.Fatalf("after a bad edit: err %q, in use %s", s.err, s.c.Cert.KeyAlgorithm)
	}
	for text, want := range map[string]string{
		"[certificates]\nkey_bits = 1024\nkey_algorithm = rsa": "rsa key_bits",
		"[certificates]\nhash_algorithm = md5":                 "hash_algorithm",
		"[certificates]\next_key_usage = codeSigning":          "ext_key_usage",
		"[other]\n":      "unknown section",
		"key_bits = 256": "outside a section",
	} {
		if _, err := parseCAConfig("ca001", text); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", text, err, want)
		}
	}
}

// The console generates a CA as asked, and saves only [certificates] edits.
func TestConsoleGeneratesWithSettings(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	_, c, _ := startConsoleProxyGlobal(t, "ca_root = "+root, "password = pw", "[[host]]\nlistener=default\npattern=ANY\naction=deny\n")
	c.login("pw")
	if code, out := c.post("/api/cas/generate", map[string]any{"commonName": "Big CA", "organization": "Lab",
		"keyAlgorithm": "rsa", "keyBits": 2048, "hashAlgorithm": "sha384", "validityDays": 1000}); code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	ca, err := readCertFile(filepath.Join(root, "ca001", "ca_cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if k, ok := ca.PublicKey.(*rsa.PublicKey); !ok || k.N.BitLen() != 2048 || ca.SignatureAlgorithm != x509.SHA384WithRSA ||
		ca.Subject.CommonName != "Big CA" || ca.Subject.Organization[0] != "Lab" {
		t.Fatalf("made: %T %s %s", ca.PublicKey, ca.SignatureAlgorithm, ca.Subject)
	}
	_, got := c.get("/api/cas/config?id=ca001")
	text := got["text"].(string)
	if !strings.Contains(text, "key_bits = 2048") || !strings.Contains(text, "validity_days = 1000") {
		t.Fatalf("config.toml must say how the CA was made:\n%s", text)
	}
	if _, out := c.post("/api/cas/config", map[string]any{"id": "ca001", "text": strings.Replace(text, "common_name = \"Big CA\"", "common_name = Other", 1)}); out["ok"] != false || !strings.Contains(out["error"].(string), "[ca] common_name") {
		t.Fatalf("changing [ca] must be refused: %v", out)
	}
	if _, out := c.post("/api/cas/config", map[string]any{"id": "ca001", "text": strings.Replace(text, "validity_days = 90", "validity_days = 45", 1)}); out["ok"] != true {
		t.Fatalf("editing [certificates] must be accepted: %v", out)
	}
}

func readCertFile(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, _ := pem.Decode(data)
	return x509.ParseCertificate(b.Bytes)
}

// dueCert is a certificate for name from l's CA that is about to expire
// (an hour left of a 90-day life), as if issued long ago.
func dueCert(t *testing.T, l *localCA, name string) *tls.Certificate {
	t.Helper()
	ca := l.ca.Load()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(99), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: now.Add(-90*24*time.Hour + time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// diskSerial is the serial of name's certificate on disk.
func diskSerial(t *testing.T, l *localCA, name string) *big.Int {
	t.Helper()
	c, err := readCertFile(filepath.Join(l.dir, name, "cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	return c.SerialNumber
}

// The life of an issued certificate: issued, served until due, then renewed
// at the next handshake (a new one served and written to disk), and a due
// one found on disk at start-up replaced rather than used or archived.
func TestLocalCACertificateLifecycle(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "ca001")
	l, err := openLocalCA("ca001", dir, true)
	if err != nil {
		t.Fatal(err)
	}
	first, err := l.certificate("life.test")
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := l.certificate("life.test"); again != first {
		t.Fatal("a current certificate must be served as it is")
	}

	// Time passes: what is in memory is now due.
	due := dueCert(t, l, "life.test")
	l.entry("life.test").cur.Store(&leafState{cert: due, ca: l.ca.Load()})
	renewed, err := l.certificate("life.test")
	if err != nil {
		t.Fatal(err)
	}
	if renewed == due || renewed.Leaf.NotAfter.Before(time.Now().Add(80*24*time.Hour)) {
		t.Fatalf("a due certificate must be renewed at the next handshake: until %s", renewed.Leaf.NotAfter)
	}
	if diskSerial(t, l, "life.test").Cmp(renewed.Leaf.SerialNumber) != 0 {
		t.Fatal("the renewed certificate must replace the one on disk")
	}
	if again, _ := l.certificate("life.test"); again != renewed {
		t.Fatal("once renewed, it is served until due again")
	}

	// A restart finds a due certificate on disk: it is ours, so it is not
	// archived, but it is replaced, not served.
	if err := l.save("restart.test", dueCert(t, l, "restart.test")); err != nil {
		t.Fatal(err)
	}
	l2, err := openLocalCA("ca001", dir, false)
	if err != nil {
		t.Fatal(err)
	}
	c, err := l2.certificate("restart.test")
	if err != nil {
		t.Fatal(err)
	}
	if c.Leaf.SerialNumber.Cmp(big.NewInt(99)) == 0 || c.Leaf.NotAfter.Before(time.Now().Add(80*24*time.Hour)) {
		t.Fatal("a due certificate on disk must be replaced")
	}
	if diskSerial(t, l2, "restart.test").Cmp(c.Leaf.SerialNumber) != 0 {
		t.Fatal("and the replacement written to disk")
	}
	if archived, _ := os.ReadDir(filepath.Join(dir, localArchiveName)); len(archived) != 0 {
		t.Fatalf("a due certificate of our own is renewed, not archived: %v", archived)
	}
}

// renew_before_days decides when a certificate is due; 0 means a third of
// its lifetime before it expires.
func TestLocalCARenewBeforeDays(t *testing.T) {
	t.Parallel()
	l, err := openLocalCA("ca001", filepath.Join(t.TempDir(), "ca001"), true)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	leaf := &x509.Certificate{NotBefore: now, NotAfter: now.Add(90 * 24 * time.Hour)}
	if got := l.leafRenewDue(leaf); got.Sub(now).Round(time.Hour) != 60*24*time.Hour {
		t.Fatalf("default: due after %s, want 60 days (a third of 90 left)", got.Sub(now))
	}
	c := *l.config()
	c.Cert.RenewBeforeDays = 10
	l.conf.Store(&caConfigState{c: &c})
	if got := l.leafRenewDue(leaf); got.Sub(now).Round(time.Hour) != 80*24*time.Hour {
		t.Fatalf("renew_before_days = 10: due after %s, want 80 days", got.Sub(now))
	}
}

// Certificates are renewed ahead of expiry by the certificate worker, not
// only when a client next asks: a due one on disk is replaced without any
// handshake. A name no rule issues for any more is left alone.
func TestLocalCARenewsInTheBackground(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	makeCA(t, root, "ca001") // a rule only uses a CA that exists (made on the CAs page)
	cfg := mustParse(t, "[[listener]]\nname=default\nport=1\n[global]\nca_root="+root+"\n[[host]]\nlistener=default\npattern=*.bg.test\ncert=local-ca\ncert_domains=*.bg.test\ntarget_host=h\ntarget_port=443\n")
	m := NewCertManager()
	if err := m.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	l := m.LocalCA(cfg, "ca001")
	for _, name := range []string{"used.bg.test", "gone.example"} {
		if err := l.save(name, dueCert(t, l, name)); err != nil {
			t.Fatal(err)
		}
	}
	m.renewLocalCAs() // the worker's renewal pass
	if s := diskSerial(t, l, "used.bg.test"); s.Cmp(big.NewInt(99)) == 0 {
		t.Fatal("a due certificate a rule issues for must be renewed in the background")
	}
	c, err := readCertFile(filepath.Join(l.dir, "used.bg.test", "cert.pem"))
	if err != nil || c.NotAfter.Before(time.Now().Add(80*24*time.Hour)) {
		t.Fatalf("renewed until %v, %v", c.NotAfter, err)
	}
	if s := diskSerial(t, l, "gone.example"); s.Cmp(big.NewInt(99)) != 0 {
		t.Fatal("a name no rule issues for must not be renewed")
	}
}

// The certificate worker runs the renewal pass when it starts (then every
// 6 hours): a due certificate is renewed without anyone calling for it.
func TestLocalCARenewalRunsAtStart(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	makeCA(t, root, "ca001") // a rule only uses a CA that exists (made on the CAs page)
	cfg := mustParse(t, "[[listener]]\nname=default\nport=1\n[global]\nca_root="+root+"\n[[host]]\nlistener=default\npattern=*.start.test\ncert=local-ca\ntarget_host=h\ntarget_port=443\n")
	m := NewCertManager()
	if err := m.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	l := m.LocalCA(cfg, "ca001")
	if err := l.save("a.start.test", dueCert(t, l, "a.start.test")); err != nil {
		t.Fatal(err)
	}
	m.Start()
	for deadline := time.Now().Add(T); diskSerial(t, l, "a.start.test").Cmp(big.NewInt(99)) == 0; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the worker did not renew the due certificate at start")
		}
	}
}

// makeCA makes a CA in root, as the console's Generate does.
func makeCA(t *testing.T, root, id string) {
	t.Helper()
	if err := generateCA(filepath.Join(root, id), defaultCAConfig(id)); err != nil {
		t.Fatal(err)
	}
}

// One name, three sources: on three listeners, www.test.com is terminated
// with an automatic certificate, with CA 1 and with CA 2. Each listener
// always gets the certificate of its own rule's source, however often and in
// whatever order clients come (the route cache is per listener, and each
// source keeps its own certificates in its own folder).
func TestSameNameDifferentSourcesNeverMix(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	caA, caB := newTestCA(t), newTestCA(t)
	for i, ca := range []*testCA{caA, caB} {
		keyDER, _ := x509.MarshalPKCS8PrivateKey(ca.key)
		if _, err := importCA(filepath.Join(root, fmt.Sprintf("ca00%d", i+1)), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw}),
			pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})); err != nil {
			t.Fatal(err)
		}
	}
	port := echoBackend(t, "E")
	ports := []int{freePort(t), freePort(t)}
	text := fmt.Sprintf("[global]\nstats_interval = 0\nca_root = %s\ncert_path = %s\nacme_agree_tos = true\nacme_directory = https://127.0.0.1:1/dir\n"+
		"[[listener]]\nname = auto\nport = 1\n[[listener]]\nname = one\nbind = 127.0.0.1\nport = %d\n[[listener]]\nname = two\nbind = 127.0.0.1\nport = %d\n",
		root, t.TempDir(), ports[0], ports[1])
	for _, l := range []struct{ listener, cert string }{{"auto", "auto"}, {"one", "local-ca:ca001"}, {"two", "local-ca:ca002"}} {
		text += fmt.Sprintf("[[host]]\nlistener = %s\npattern = www.test.com\ncert = %s\nupstream_tls = false\ntarget_host = 127.0.0.1\ntarget_port = %d\n", l.listener, l.cert, port)
	}
	p := startProxyText(t, text, "")
	for _, port := range ports { // the extra listeners open in the background
		waitForPort(t, fmt.Sprintf("127.0.0.1:%d", port))
	}

	// The automatic one: as if the ACME CA had issued it (its own issuer).
	acme := newTestCA(t)
	certPEM, keyPEM := acme.issue(t, 90*24*time.Hour, "www.test.com")
	auto, _ := tls.X509KeyPair(certPEM, keyPEM)
	auto.Leaf, _ = x509.ParseCertificate(auto.Certificate[0])
	m := p.srv.certs
	m.lock()
	m.auto["www.test.com"] = &auto
	m.unlock()

	addrs := map[string]string{"auto": p.addr, "one": fmt.Sprintf("127.0.0.1:%d", ports[0]), "two": fmt.Sprintf("127.0.0.1:%d", ports[1])}
	want := map[string]*x509.Certificate{"auto": acme.cert, "one": caA.cert, "two": caB.cert}
	order := []string{"auto", "one", "two", "two", "one", "auto", "one", "auto", "two", "one", "two", "auto"}
	mrand.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
	for _, l := range order {
		raw, err := net.DialTimeout("tcp", addrs[l], T)
		if err != nil {
			t.Fatal(err)
		}
		tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, ServerName: "www.test.com"})
		if err := tc.Handshake(); err != nil {
			t.Fatalf("%s: %v", l, err)
		}
		leaf := tc.ConnectionState().PeerCertificates[0]
		tc.Close()
		if err := leaf.CheckSignatureFrom(want[l]); err != nil {
			t.Fatalf("listener %s served a www.test.com certificate from another source: %v", l, err)
		}
	}
	// And each CA keeps its own copy, in its own folder.
	a, errA := readCertFile(filepath.Join(root, "ca001", "www.test.com", "cert.pem"))
	b, errB := readCertFile(filepath.Join(root, "ca002", "www.test.com", "cert.pem"))
	if errA != nil || errB != nil || a.CheckSignatureFrom(caA.cert) != nil || b.CheckSignatureFrom(caB.cert) != nil {
		t.Fatalf("each CA's www.test.com must be its own: %v %v", errA, errB)
	}
}
