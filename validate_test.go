//go:build unix

package main

// cert_validate_script: names outside cert_domains earn a certificate only if
// the rule's script accepts them, and the script runs only when a certificate
// has to be issued or renewed.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// validateScript writes a script that accepts names starting with "ok." and
// records every call in <dir>/calls.
func validateScript(t *testing.T, dir, body string) string {
	t.Helper()
	path := filepath.Join(dir, "domains.sh")
	text := "#!/bin/sh\necho \"$1\" >> " + filepath.Join(dir, "calls") + "\n" + body
	if err := os.WriteFile(path, []byte(text), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

const acceptOK = "case \"$1\" in ok.*) echo welcome; exit 0;; *) echo 'not a customer' >&2; exit 3;; esac\n"

func TestCertValidateScriptConfig(t *testing.T) {
	auto := "[global]\nport=443\nacme_agree_tos=true\n"
	// A regex pattern needs no cert_domains when a script decides; both together are fine.
	c := mustParse(t, auto+"[[host]]\npattern=*.x\\.com\ncert=auto\ncert_validate_script=./domains.sh\ntarget_host=x.lan\n"+
		"[[host]]\npattern=*.y\\.com\ncert=auto\ncert_domains=a.y.com\ncert_validate_script='/opt/d.sh'\ntarget_host=y.lan\n")
	if c.Rules[0].CertValidateScript != "./domains.sh" || len(c.Rules[0].CertDomains) != 0 || c.Rules[1].CertValidateScript != "/opt/d.sh" {
		t.Fatalf("%+v", c.Rules)
	}
	if scriptFor(c, "new.y.com") != "/opt/d.sh" || scriptFor(c, "a.y.com") != "" || scriptFor(c, "other.com") != "" || scriptFor(c, "-rf.x.com") != "" {
		t.Fatal("scriptFor: listed names, unrouted names and option-like names never reach a script")
	}
	for name, text := range map[string]string{
		"without cert":     auto + "[[host]]\npattern=a\\.x\\.com\ncert_validate_script=./d.sh\ntarget_host=x.lan\n",
		"with a directory": auto + "[[host]]\npattern=.*\ncert=/tmp\ncert_validate_script=./d.sh\ntarget_host=x.lan\n",
		"empty":            auto + "[[host]]\npattern=*.x\\.com\ncert=auto\ncert_validate_script=''\ntarget_host=x.lan\n",
	} {
		if _, err := ParseConfig(text); err == nil {
			t.Errorf("%s: should be rejected", name)
		}
	}
	// The script must exist and be executable, at startup and on reload.
	if err := NewCertManager().Check(c); err == nil || !strings.Contains(err.Error(), "cert_validate_script = ./domains.sh") {
		t.Fatalf("missing script: %v", err)
	}
}

func TestCertValidateScriptDecidesIssuanceAndRenewal(t *testing.T) {
	dir := t.TempDir()
	script := validateScript(t, dir, acceptOK)
	cfg := mustParse(t, fmt.Sprintf("[global]\nport=443\nacme_agree_tos=true\npublic_ip_address=1.2.3.4\ncert_path=%s\n"+
		"[[host]]\npattern=*.s\\.test\ncert=auto\ncert_domains=listed.s.test\ncert_validate_script=%s\ntarget_host=x.lan\n", filepath.Join(dir, "certs"), script))
	rule := &cfg.Rules[0]
	m := NewCertManager()
	if err := m.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	day := 24 * time.Hour
	leaf := func(age time.Duration) *tls.Certificate {
		nb := time.Now().Add(-age)
		return &tls.Certificate{Leaf: &x509.Certificate{NotBefore: nb, NotAfter: nb.Add(90 * day)}}
	}
	var issued []string
	m.issueFunc = func(_ context.Context, _ *Config, domain string) error {
		issued = append(issued, domain)
		m.mu.Lock()
		m.auto[domain] = leaf(0)
		m.mu.Unlock()
		return nil
	}
	pass := func() { // one round of the worker
		m.adoptCandidates(cfg)
		for _, job := range m.pendingJobs(time.Now()) {
			m.runJob(cfg, job)
		}
	}
	calls := func() string {
		data, _ := os.ReadFile(filepath.Join(dir, "calls"))
		return strings.Join(strings.Fields(string(data)), " ")
	}
	mark := len(testLog.String())

	// Clients ask for three names: one listed, one the script accepts, one it refuses.
	for _, sni := range []string{"listed.s.test", "ok.s.test", "bad.s.test", "ok.s.test", "bad.s.test"} {
		if c, err := m.CertificateFor(rule, sni); err != nil || c.Leaf.Subject.Organization[0] != "tlsproxy placeholder" {
			t.Fatalf("%s: connections are never held up; the placeholder is served: %v", sni, err)
		}
	}
	pass()
	if got := strings.Join(issued, " "); got != "listed.s.test ok.s.test" {
		t.Fatalf("issued: %q", got)
	}
	if got := calls(); got != "bad.s.test ok.s.test" { // never for a cert_domains name, once per name
		t.Fatalf("script calls: %q", got)
	}
	log := testLog.String()[mark:]
	for _, want := range []string{
		"ok.s.test: requested by a client, not in cert_domains and no certificate yet; cert_validate_script " + script + " will be asked",
		"ok.s.test: a new certificate is needed; asking cert_validate_script: " + script + " ok.s.test",
		"ok.s.test: ACCEPTED by cert_validate_script " + script + " (exit status 0 in ",
		`output "welcome"); requesting the certificate`,
		"bad.s.test: REFUSED by cert_validate_script " + script + " (exit status 3 in ",
		`output "not a customer"); no certificate is requested and clients get the self-signed placeholder`,
	} {
		if !strings.Contains(log, want) {
			t.Errorf("log lacks %q\n%s", want, log)
		}
	}

	// With a good certificate in place the script is left alone: not per
	// connection, not per worker round. A refused name is not asked about again
	// right away either.
	for i := 0; i < 3; i++ {
		m.CertificateFor(rule, "ok.s.test")
		m.CertificateFor(rule, "bad.s.test")
		pass()
	}
	if got := calls(); got != "bad.s.test ok.s.test" {
		t.Fatalf("script ran without a certificate being needed: %q", got)
	}
	if c, _ := m.CertificateFor(rule, "ok.s.test"); c.Leaf.Subject.Organization != nil {
		t.Fatal("the issued certificate should be served")
	}

	// Renewal time: the script is asked again. It now refuses, so the
	// certificate is kept but not renewed, and the name waits for the next try.
	validateScript(t, dir, "echo 'subscription ended'; exit 1\n")
	m.mu.Lock()
	m.auto["ok.s.test"] = leaf(80 * day)
	m.mu.Unlock()
	mark = len(testLog.String())
	pass()
	if got := calls(); got != "bad.s.test ok.s.test ok.s.test" || len(issued) != 2 {
		t.Fatalf("renewal: calls %q, issued %v", got, issued)
	}
	if log := testLog.String()[mark:]; !strings.Contains(log, "ok.s.test: its certificate is due for renewal; asking cert_validate_script") ||
		!strings.Contains(log, `(exit status 1 in `) || !strings.Contains(log, "the certificate is NOT renewed. The current one stays in use until ") {
		t.Fatalf("renewal refusal not logged clearly:\n%s", log)
	}
	if c, _ := m.CertificateFor(rule, "ok.s.test"); c.Leaf.Subject.Organization != nil {
		t.Fatal("a refused renewal keeps the current certificate in use")
	}
	pass()
	if got := calls(); got != "bad.s.test ok.s.test ok.s.test" {
		t.Fatalf("a refused renewal waits for the retry interval: %q", got)
	}

	// A reload forgets refusals: bad.s.test is asked about again when requested.
	if err := m.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	m.CertificateFor(rule, "bad.s.test")
	pass()
	if got := calls(); !strings.HasSuffix(got, " bad.s.test") {
		t.Fatalf("after a reload: %q", got)
	}
}

func TestCertValidateScriptAdoptsCertificatesOnDisk(t *testing.T) {
	dir := t.TempDir()
	script := validateScript(t, dir, "exit 1\n") // would refuse, but must not even be asked
	certPath := filepath.Join(dir, "certs")
	certPEM, keyPEM := newTestCA(t).issue(t, 12*time.Hour, "kept.s.test")
	os.MkdirAll(filepath.Join(certPath, "kept.s.test"), 0o700)
	os.MkdirAll(filepath.Join(certPath, "other.example.org"), 0o700) // not covered by the rule
	os.WriteFile(filepath.Join(certPath, "kept.s.test", "cert.pem"), certPEM, 0o600)
	os.WriteFile(filepath.Join(certPath, "kept.s.test", "key.pem"), keyPEM, 0o600)
	cfg := mustParse(t, fmt.Sprintf("[global]\nport=443\nacme_agree_tos=true\npublic_ip_address=1.2.3.4\ncert_path=%s\n"+
		"[[host]]\npattern=*.s\\.test\ncert=auto\ncert_validate_script=%s\ntarget_host=x.lan\n", certPath, script))
	m := NewCertManager()
	m.issueFunc = func(context.Context, *Config, string) error { t.Error("nothing needs issuing"); return nil }
	if err := m.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	m.adoptCandidates(cfg)
	if jobs := m.pendingJobs(time.Now()); len(jobs) != 0 {
		t.Fatalf("%v", jobs)
	}
	if c, _ := m.CertificateFor(&cfg.Rules[0], "kept.s.test"); c.Leaf.DNSNames[0] != "kept.s.test" || c.Leaf.Subject.Organization != nil {
		t.Fatal("the certificate from before the restart should be served")
	}
	if _, err := os.Stat(filepath.Join(dir, "calls")); err == nil {
		t.Fatal("the script was run although no certificate was needed")
	}
	if got := m.Snapshot(); len(got) != 1 || got[0].Name != "kept.s.test" || !strings.Contains(got[0].Detail, "accepted by cert_validate_script") {
		t.Fatalf("%+v", got)
	}
}

func TestCertValidateScriptTimeoutCountsAsRefusal(t *testing.T) {
	dir := t.TempDir()
	script := validateScript(t, dir, "sleep 30\n")
	old := validateScriptTimeout
	validateScriptTimeout = 200 * time.Millisecond
	defer func() { validateScriptTimeout = old }()
	start := time.Now()
	ok, _, err := runValidateScript(script, "slow.s.test")
	if ok || err == nil || !strings.Contains(err.Error(), "no answer within 200ms") || time.Since(start) > 5*time.Second {
		t.Fatalf("ok=%v err=%v after %s", ok, err, time.Since(start))
	}
	if ok, _, err := runValidateScript(filepath.Join(dir, "missing.sh"), "x.s.test"); ok || err == nil {
		t.Fatalf("a script that cannot run refuses: %v %v", ok, err)
	}
}

// A flood of random names must not cost a key and a certificate each: names the
// configuration does not list share one placeholder per rule.
func TestPlaceholderIsSharedForClientChosenNames(t *testing.T) {
	cfg := mustParse(t, "[global]\nport=443\nacme_agree_tos=true\npublic_ip_address=1.2.3.4\n"+
		"[[host]]\npattern=*.s3.test\ncert=auto\ncert_domains=www.s3.test\ncert_validate_script=/nonexistent\ntarget_host=x.lan\n"+
		"[[host]]\npattern=*.re\\.test\ncert=auto\ncert_validate_script=/nonexistent\ntarget_host=y.lan\n")
	m := NewCertManager()
	m.cfg = cfg // no worker: nothing is ever issued
	var first *tls.Certificate
	for i := 0; i < 5000; i++ {
		c, err := m.CertificateFor(&cfg.Rules[0], fmt.Sprintf("random-%d.s3.test", i))
		if err != nil {
			t.Fatal(err)
		}
		if first == nil {
			first = c
		}
		if c != first {
			t.Fatalf("name %d got a placeholder of its own", i)
		}
	}
	if first.Leaf.DNSNames[0] != "*.s3.test" || first.Leaf.Subject.Organization[0] != "tlsproxy placeholder" {
		t.Fatalf("a wildcard rule gets a wildcard placeholder: %v", first.Leaf.DNSNames)
	}
	if err := first.Leaf.VerifyHostname("random-7.s3.test"); err != nil {
		t.Fatalf("and it matches what the client asked for: %v", err)
	}
	// A configured name keeps its own; a regex rule shares one without a usable name.
	own, _ := m.CertificateFor(&cfg.Rules[0], "www.s3.test")
	re1, _ := m.CertificateFor(&cfg.Rules[1], "a.re.test")
	re2, _ := m.CertificateFor(&cfg.Rules[1], "b.re.test")
	if own == first || own.Leaf.DNSNames[0] != "www.s3.test" || re1 != re2 || re1 == first || re1.Leaf.DNSNames[0] != "placeholder.invalid" {
		t.Fatalf("%v %v", own.Leaf.DNSNames, re1.Leaf.DNSNames)
	}
	m.mu.RLock()
	n, queued := len(m.placeholders), len(m.candidates)
	m.mu.RUnlock()
	if n != 3 || queued > maxCandidates {
		t.Fatalf("%d placeholders, %d names queued", n, queued)
	}
	// An expiring placeholder is replaced, not served for ever.
	m.mu.Lock()
	first.Leaf.NotAfter = time.Now().Add(time.Minute)
	m.mu.Unlock()
	if c, _ := m.CertificateFor(&cfg.Rules[0], "random-1.s3.test"); c == first || time.Until(c.Leaf.NotAfter) < 6*24*time.Hour {
		t.Fatal("placeholder not renewed")
	}
}
