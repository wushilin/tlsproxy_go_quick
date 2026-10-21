package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func snapshotOf(m *CertManager, name string) *CertInfo {
	for _, c := range m.Snapshot() {
		if c.Name == name {
			return &c
		}
	}
	return nil
}

func archived(t *testing.T, dir, name string) int {
	t.Helper()
	entries, _ := os.ReadDir(filepath.Join(dir, localArchiveName))
	n := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), name+"-") {
			n++
		}
	}
	return n
}

// An automatic certificate can be removed only when something is wrong with
// it: expired, its last attempt failed, or its files are unusable. A valid
// one that renews normally is refused.
func TestRemoveAutoCertificateOnlyWhenSomethingIsWrong(t *testing.T) {
	certPath := t.TempDir()
	const name = "a.remove.test"
	cfg := mustParse(t, fmt.Sprintf("[[listener]]\nname=default\nport=443\n[global]\ncert_path=%s\nacme_agree_tos=true\n[[host]]\nlistener=default\npattern=%s\ncert=auto\ntarget_host=127.0.0.1\ntarget_port=443\n", certPath, name))
	m := NewCertManager()
	if err := m.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	ca := newTestCA(t)
	certPEM, keyPEM := ca.issue(t, 60*24*time.Hour, name)
	if err := m.installCertificate(m.cfgCtx, cfg, name, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	if c := snapshotOf(m, name); c == nil || c.Status != "ok" || c.Removable {
		t.Fatalf("valid certificate: %+v", c)
	}
	if err := m.RemoveCertificate("auto", "", name); err == nil || !strings.Contains(err.Error(), "nothing to remove") {
		t.Fatalf("valid certificate removed: %v", err)
	}
	if err := m.RemoveCertificate("auto", "", "other.remove.test"); err == nil {
		t.Fatal("removed a name no rule manages")
	}

	// A failed renewal makes it removable.
	m.lock()
	m.lastError[name], m.nextTry[name] = "DNS pre-check: cannot resolve", time.Now().Add(time.Hour)
	m.unlock()
	if c := snapshotOf(m, name); c == nil || !c.Removable {
		t.Fatalf("failing certificate: %+v", c)
	}
	if err := m.RemoveCertificate("auto", "", name); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(autoDir(cfg, name)); !os.IsNotExist(err) || archived(t, certPath, name) != 1 {
		t.Fatalf("not archived: %v", err)
	}
	if c := snapshotOf(m, name); c == nil || c.Status != "missing" || c.LastError != "" || c.Removable {
		t.Fatalf("after removal: %+v", c) // still wanted by its rule, so listed: nothing left to remove
	}
	if err := m.RemoveCertificate("auto", "", name); err == nil || !strings.Contains(err.Error(), "no certificate yet") {
		t.Fatalf("removed nothing: %v", err)
	}

	// Expired: removable without any error recorded.
	certPEM, keyPEM = ca.issue(t, -time.Minute, name)
	if err := os.MkdirAll(autoDir(cfg, name), 0o700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(autoDir(cfg, name), "cert.pem"), certPEM, 0o600)
	os.WriteFile(filepath.Join(autoDir(cfg, name), "key.pem"), keyPEM, 0o600)
	m.loadAutoFromDisk(cfg, name)
	if c := snapshotOf(m, name); c == nil || c.Status != "expired" || !c.Removable {
		t.Fatalf("expired certificate: %+v", c)
	}
	// Files that don't load: removable too.
	os.WriteFile(filepath.Join(autoDir(cfg, name), "cert.pem"), []byte("garbage"), 0o600)
	m.lock()
	delete(m.auto, name)
	m.unlock()
	if c := snapshotOf(m, name); c == nil || !c.Removable {
		t.Fatalf("unusable files: %+v", c)
	}
	if err := m.RemoveCertificate("auto", "", name); err != nil {
		t.Fatal(err)
	}
	if archived(t, certPath, name) != 2 {
		t.Fatal("second removal not archived")
	}

	// Being requested right now: refused, the job owns the folder.
	m.lock()
	m.lastError[name], m.inFlight[name] = "x", true
	m.unlock()
	if err := m.RemoveCertificate("auto", "", name); err == nil || !strings.Contains(err.Error(), "right now") {
		t.Fatalf("removed during a request: %v", err)
	}
}

// A local CA's certificate can always be removed: it is archived, and the
// next client gets a new one.
func TestRemoveLocalCertificate(t *testing.T) {
	root := t.TempDir()
	makeCA(t, root, "ca001")
	const name = "www.remove.test"
	cfg := mustParse(t, fmt.Sprintf("[[listener]]\nname=default\nport=443\n[global]\nca_root=%s\n[[host]]\nlistener=default\npattern=%s\ncert=local-ca\ntarget_host=127.0.0.1\ntarget_port=443\n", root, name))
	m := NewCertManager()
	if err := m.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	l := m.LocalCA(cfg, "ca001")
	first, err := l.certificate(name)
	if err != nil {
		t.Fatal(err)
	}
	if c := snapshotOf(m, name); c == nil || c.Status != "ok" || !c.Removable {
		t.Fatalf("issued certificate: %+v", c)
	}
	if err := m.RemoveCertificate("local-ca", "ca002", name); err == nil {
		t.Fatal("removed from a CA no rule uses")
	}
	if err := m.RemoveCertificate("local-ca", "ca001", name); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "ca001")
	if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) || archived(t, dir, name) != 1 {
		t.Fatalf("not archived: %v", err)
	}
	if c := snapshotOf(m, name); c != nil {
		t.Fatalf("still listed: %+v", c)
	}
	if err := m.RemoveCertificate("local-ca", "ca001", name); err == nil {
		t.Fatal("removed twice")
	}
	second, err := l.certificate(name)
	if err != nil {
		t.Fatal(err)
	}
	if second.Leaf.SerialNumber.Cmp(first.Leaf.SerialNumber) == 0 {
		t.Fatal("the removed certificate came back")
	}
	if _, err := os.Stat(filepath.Join(dir, name, "cert.pem")); err != nil {
		t.Fatalf("new certificate not saved: %v", err)
	}
}

// dns_resolvers is required when the DNS pre-check runs, and takes IP
// addresses only (v4 or v6, with or without a port).
func TestDNSResolversRequiredAndChecked(t *testing.T) {
	base := "[[listener]]\nname=default\nport=443\n[global]\nacme_agree_tos=true\n%s\n[[host]]\nlistener=default\npattern=a.example.com\ncert=auto\ntarget_host=127.0.0.1\ntarget_port=443\n"
	for _, tc := range []struct{ global, err string }{
		{"public_ip_address=203.0.113.7", "needs dns_resolvers"},
		{"public_ip_address=203.0.113.7\ndns_resolvers=dns.google", `"dns.google" is not an IP address`},
		{"public_ip_address=203.0.113.7\ndns_resolvers=1.1.1.1; 2606:4700:4700::1111; [2001:4860:4860::8888]:53, 8.8.8.8:53", ""},
		{"", ""}, // no public_ip_address: no pre-check, nothing to ask
	} {
		cfg, err := parseFixture(fmt.Sprintf(base, tc.global))
		switch {
		case tc.err == "" && err != nil:
			t.Errorf("%q: %v", tc.global, err)
		case tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)):
			t.Errorf("%q: got %v, want %q", tc.global, err, tc.err)
		case tc.err == "" && strings.Contains(tc.global, "2606") && len(cfg.DNSResolvers) != 4:
			t.Errorf("resolvers: %v", cfg.DNSResolvers)
		}
	}
	// Without cert = auto it isn't needed either.
	if _, err := parseFixture("[[listener]]\nname=default\nport=443\n[global]\npublic_ip_address=203.0.113.7\n[[host]]\nlistener=default\npattern=ANY\naction=deny\n"); err != nil {
		t.Fatal(err)
	}
}

// A certificate in memory is checked again when its CA's state changes: kept
// (with the CA's chain as it is now) if the CA still signed it, archived and
// replaced if the CA on disk is a different one now.
func TestCachedLocalCertificateFollowsItsCA(t *testing.T) {
	root := t.TempDir()
	makeCA(t, root, "ca001")
	dir := filepath.Join(root, "ca001")
	l, err := openLocalCA("ca001", dir, false)
	if err != nil {
		t.Fatal(err)
	}
	const name = "cached.test"
	first, err := l.certificate(name)
	if err != nil {
		t.Fatal(err)
	}
	// Same CA files read again (the 6-hourly pass does this): a new state,
	// the same CA. The certificate is kept, not issued again.
	if err := l.renewCA(); err != nil {
		t.Fatal(err)
	}
	if again, _ := l.certificate(name); again.Leaf.SerialNumber.Cmp(first.Leaf.SerialNumber) != 0 {
		t.Fatal("a certificate the CA still signs was replaced")
	}
	if st := l.find(name).cur.Load(); st.ca != l.ca.Load() {
		t.Fatal("not marked as checked against the current CA")
	}
	// A different CA in the same folder now.
	other := t.TempDir()
	makeCA(t, other, "x")
	for _, f := range []string{"ca_cert.pem", "ca_key.pem"} {
		data, err := os.ReadFile(filepath.Join(other, "x", f))
		if err != nil {
			t.Fatal(err)
		}
		if err := writeFileAtomic0600(filepath.Join(dir, f), data); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.renewCA(); err != nil {
		t.Fatal(err)
	}
	next, err := l.certificate(name)
	if err != nil {
		t.Fatal(err)
	}
	if next.Leaf.CheckSignatureFrom(l.ca.Load().cert) != nil {
		t.Fatal("served a certificate the current CA did not sign")
	}
	if archived(t, dir, name) != 1 {
		t.Fatal("the old CA's certificate was not archived")
	}
}
