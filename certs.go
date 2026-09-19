package main

// Certificates for rules that terminate TLS.
//
//   cert = <dir>   cert.pem (leaf + chain) and key.pem, plus an optional
//                  ca.pem appended to the chain; re-read when the files change.
//   cert = auto    issued and renewed through ACME with the TLS-ALPN-01
//                  challenge (RFC 8737): the CA connects to port 443 with ALPN
//                  "acme-tls/1" and we answer with a special self-signed
//                  certificate. No port 80 involved.
//
// Issuance runs one job at a time in a background goroutine: names with no
// (or an expired) certificate first, renewals after. A failed name is retried
// after certRetryInterval. Before ordering, the name must resolve (via public
// resolvers, not the local one, which may be split-horizon) to one of
// public_ip_address, so misconfigured names don't burn the CA's rate limits.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
)

const (
	certRetryInterval = 6 * time.Hour
	certCheckInterval = 10 * time.Minute
	certJobTimeout    = 5 * time.Minute
)

type fileCert struct {
	cert    *tls.Certificate
	modTime time.Time
}

type CertManager struct {
	mu           sync.RWMutex
	cfg          *Config
	auto         map[string]*tls.Certificate // by domain
	files        map[string]*fileCert        // by directory
	challenges   map[string]*tls.Certificate // pending TLS-ALPN-01 answers, by domain
	placeholders map[string]*tls.Certificate
	nextTry      map[string]time.Time
	wake         chan struct{}
	started      bool

	// Overridable in tests.
	retryInterval time.Duration
	checkInterval time.Duration
}

func NewCertManager() *CertManager {
	return &CertManager{
		auto:          map[string]*tls.Certificate{},
		files:         map[string]*fileCert{},
		challenges:    map[string]*tls.Certificate{},
		placeholders:  map[string]*tls.Certificate{},
		nextTry:       map[string]time.Time{},
		wake:          make(chan struct{}, 1),
		retryInterval: certRetryInterval,
		checkInterval: certCheckInterval,
	}
}

// Apply validates cfg's certificate settings and makes them current. Directory
// certificates must load, otherwise the config is rejected (at startup and on
// reload). Automatic ones are picked up from disk if present; the rest is the
// background worker's job.
func (m *CertManager) Apply(cfg *Config) error {
	loaded := map[string]*fileCert{}
	for i := range cfg.Rules {
		dir := cfg.Rules[i].Cert
		if dir == "" || dir == "auto" || loaded[dir] != nil {
			continue
		}
		fc, err := loadDirCert(dir)
		if err != nil {
			return fmt.Errorf("[[host]] at line %d: cert = %s: %w", cfg.Rules[i].Line, dir, err)
		}
		loaded[dir] = fc
	}
	m.mu.Lock()
	m.cfg, m.files = cfg, loaded
	m.mu.Unlock()
	for _, d := range cfg.AutoDomains() {
		m.loadAutoFromDisk(cfg, d)
	}
	select {
	case m.wake <- struct{}{}:
	default:
	}
	return nil
}

// Start launches the background worker (once).
func (m *CertManager) Start() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.started {
		m.started = true
		go m.worker()
	}
}

func loadDirCert(dir string) (*fileCert, error) {
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	st, err := os.Stat(certFile)
	if err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	if ca, err := os.ReadFile(filepath.Join(dir, "ca.pem")); err == nil {
		for block, rest := pem.Decode(ca); block != nil; block, rest = pem.Decode(rest) {
			if block.Type == "CERTIFICATE" {
				cert.Certificate = append(cert.Certificate, block.Bytes)
			}
		}
	}
	if cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
		return nil, err
	}
	return &fileCert{cert: &cert, modTime: st.ModTime()}, nil
}

func autoDir(cfg *Config, domain string) string { return filepath.Join(cfg.CertPath, domain) }

func (m *CertManager) loadAutoFromDisk(cfg *Config, domain string) {
	fc, err := loadDirCert(autoDir(cfg, domain))
	if err != nil {
		return
	}
	m.mu.Lock()
	m.auto[domain] = fc.cert
	m.mu.Unlock()
}

// CertificateFor returns what to present for a terminating rule and SNI.
// Until an automatic certificate exists, a short-lived self-signed placeholder
// keeps the service reachable (with a browser warning).
func (m *CertManager) CertificateFor(rule *Rule, sni string) (*tls.Certificate, error) {
	m.mu.RLock()
	var cert *tls.Certificate
	if rule.Cert == "auto" {
		cert = m.auto[sni]
	} else if fc := m.files[rule.Cert]; fc != nil {
		cert = fc.cert
	}
	if cert == nil {
		cert = m.placeholders[sni]
	}
	m.mu.RUnlock()
	if cert != nil {
		return cert, nil
	}
	name := sni
	if name == "" {
		name = "localhost"
	}
	ph, err := selfSigned(name, 7*24*time.Hour)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	if len(m.placeholders) > 256 { // bounded: names come from clients
		m.placeholders = map[string]*tls.Certificate{}
	}
	m.placeholders[sni] = ph
	m.mu.Unlock()
	return ph, nil
}

// Challenge returns the pending TLS-ALPN-01 answer for a name, if any.
func (m *CertManager) Challenge(sni string) *tls.Certificate {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.challenges[sni]
}

func selfSigned(name string, life time.Duration) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name, Organization: []string{"tlsproxy placeholder"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(life),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(name); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{name}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	leaf, _ := x509.ParseCertificate(der)
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

// renewAt is when a certificate becomes due: threshold days before expiry,
// but never earlier than two thirds into its life (short-lived certificates).
func renewAt(leaf *x509.Certificate, thresholdDays int) time.Time {
	threshold := time.Duration(thresholdDays) * 24 * time.Hour
	if third := leaf.NotAfter.Sub(leaf.NotBefore) / 3; third < threshold {
		threshold = third
	}
	return leaf.NotAfter.Add(-threshold)
}

type certJob struct {
	domain string
	urgent bool // missing or expired
	due    time.Time
}

// pendingJobs lists what needs doing now: urgent names first, then renewals
// by due date.
func (m *CertManager) pendingJobs(now time.Time) []certJob {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.cfg == nil {
		return nil
	}
	var jobs []certJob
	for _, d := range m.cfg.AutoDomains() {
		if now.Before(m.nextTry[d]) {
			continue
		}
		c := m.auto[d]
		switch {
		case c == nil || c.Leaf == nil || now.After(c.Leaf.NotAfter):
			jobs = append(jobs, certJob{domain: d, urgent: true})
		case now.After(renewAt(c.Leaf, m.cfg.ExpiryThresholdDays)):
			jobs = append(jobs, certJob{domain: d, due: c.Leaf.NotAfter})
		}
	}
	sort.SliceStable(jobs, func(i, j int) bool {
		if jobs[i].urgent != jobs[j].urgent {
			return jobs[i].urgent
		}
		return jobs[i].due.Before(jobs[j].due)
	})
	return jobs
}

func (m *CertManager) worker() {
	for {
		m.refreshFileCerts()
		for _, job := range m.pendingJobs(time.Now()) {
			m.mu.RLock()
			cfg := m.cfg
			m.mu.RUnlock()
			kind := "renewing"
			if job.urgent {
				kind = "issuing"
			}
			logf("cert: %s %s", kind, job.domain)
			ctx, cancel := context.WithTimeout(context.Background(), certJobTimeout)
			err := m.issue(ctx, cfg, job.domain)
			cancel()
			m.mu.Lock()
			if err != nil {
				m.nextTry[job.domain] = time.Now().Add(m.retryInterval)
			} else {
				delete(m.nextTry, job.domain)
			}
			m.mu.Unlock()
			if err != nil {
				errorf("cert: %s failed: %v; next attempt in %s", job.domain, err, humanDuration(m.retryInterval))
			}
		}
		select {
		case <-m.wake:
		case <-time.After(m.checkInterval):
		}
	}
}

// refreshFileCerts re-reads cert = <dir> certificates whose files changed.
func (m *CertManager) refreshFileCerts() {
	m.mu.RLock()
	dirs := make(map[string]time.Time, len(m.files))
	for dir, fc := range m.files {
		dirs[dir] = fc.modTime
	}
	m.mu.RUnlock()
	for dir, old := range dirs {
		st, err := os.Stat(filepath.Join(dir, "cert.pem"))
		if err != nil || st.ModTime().Equal(old) {
			continue
		}
		fc, err := loadDirCert(dir)
		if err != nil {
			errorf("cert: %s changed but cannot be loaded, keeping the previous one: %v", dir, err)
			continue
		}
		m.mu.Lock()
		m.files[dir] = fc
		m.mu.Unlock()
		logf("cert: reloaded %s (expires %s)", dir, fc.cert.Leaf.NotAfter.UTC().Format("2006-01-02"))
	}
}

// checkDNS makes sure domain publicly resolves to one of our addresses.
func checkDNS(ctx context.Context, cfg *Config, domain string) error {
	if len(cfg.PublicIPs) == 0 {
		return nil
	}
	var lastErr error
	for _, server := range cfg.DNSResolvers {
		if _, _, err := net.SplitHostPort(server); err != nil {
			server = net.JoinHostPort(server, "53")
		}
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, server)
		}}
		addrs, err := r.LookupNetIP(ctx, "ip", domain)
		if err != nil {
			lastErr = err
			continue
		}
		var got []string
		for _, a := range addrs {
			ip := a.Unmap().String()
			got = append(got, ip)
			for _, want := range cfg.PublicIPs {
				if ip == want {
					return nil
				}
			}
		}
		return fmt.Errorf("DNS pre-check: %s resolves to %s, none of which is in public_ip_address (%s); not asking the CA",
			domain, strings.Join(got, ", "), strings.Join(cfg.PublicIPs, ", "))
	}
	return fmt.Errorf("DNS pre-check: cannot resolve %s: %w", domain, lastErr)
}

func (m *CertManager) acmeClient(cfg *Config) (*acme.Client, error) {
	dir := filepath.Join(cfg.CertPath, "_account")
	keyFile := filepath.Join(dir, "account.key")
	var key crypto.Signer
	if data, err := os.ReadFile(keyFile); err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("%s: not PEM", keyFile)
		}
		if key, err = x509.ParseECPrivateKey(block.Bytes); err != nil {
			return nil, fmt.Errorf("%s: %w", keyFile, err)
		}
	} else {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		der, _ := x509.MarshalECPrivateKey(k)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
		if err := writeFileAtomic(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})); err != nil {
			return nil, err
		}
		key = k
	}
	transport := &http.Transport{}
	client := &acme.Client{Key: key, DirectoryURL: cfg.AcmeDirectory, UserAgent: "tlsproxy_go_quick",
		HTTPClient: &http.Client{Timeout: time.Minute, Transport: &orderLocationFixer{next: transport}}}
	if cfg.AcmeCAFile != "" {
		pemData, err := os.ReadFile(cfg.AcmeCAFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemData) {
			return nil, fmt.Errorf("acme_ca_file %s: no certificates found", cfg.AcmeCAFile)
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool}
	}
	return client, nil
}

// orderLocationFixer works around a gap between x/crypto/acme and some ACME
// servers. After finalizing, the library polls the order at the URL from the
// response's Location header. RFC 8555 doesn't require that header there:
// Let's Encrypt sends it, Pebble doesn't, and without it the poll goes to "".
// Order URLs and finalize URLs are paired as the library sees them, and the
// header is filled in when missing.
type orderLocationFixer struct {
	next   http.RoundTripper
	mu     sync.Mutex
	orders map[string]string // finalize URL -> order URL
}

func (f *orderLocationFixer) pair(finalizeURL, orderURL string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.orders == nil {
		f.orders = map[string]string{}
	}
	f.orders[finalizeURL] = orderURL
}

func (f *orderLocationFixer) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := f.next.RoundTrip(req)
	if err != nil || resp.Header.Get("Location") != "" {
		return resp, err
	}
	f.mu.Lock()
	orderURL := f.orders[req.URL.String()]
	f.mu.Unlock()
	if orderURL != "" {
		resp.Header.Set("Location", orderURL)
	}
	return resp, nil
}

// issue obtains a certificate for one name and installs it.
func (m *CertManager) issue(ctx context.Context, cfg *Config, domain string) error {
	if err := checkDNS(ctx, cfg, domain); err != nil {
		return err
	}
	client, err := m.acmeClient(cfg)
	if err != nil {
		return err
	}
	acct := &acme.Account{}
	if cfg.AcmeEmail != "" {
		acct.Contact = []string{"mailto:" + cfg.AcmeEmail}
	}
	if _, err := client.Register(ctx, acct, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return fmt.Errorf("ACME account: %w", err)
	}
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(domain))
	if err != nil {
		return fmt.Errorf("ACME order: %w", err)
	}
	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return fmt.Errorf("ACME authorization: %w", err)
		}
		if authz.Status == acme.StatusValid {
			continue
		}
		var chal *acme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == "tls-alpn-01" {
				chal = c
			}
		}
		if chal == nil {
			return errors.New("the CA offers no tls-alpn-01 challenge for this name")
		}
		answer, err := client.TLSALPN01ChallengeCert(chal.Token, domain)
		if err != nil {
			return err
		}
		m.mu.Lock()
		m.challenges[domain] = &answer
		m.mu.Unlock()
		defer func() {
			m.mu.Lock()
			delete(m.challenges, domain)
			m.mu.Unlock()
		}()
		if _, err := client.Accept(ctx, chal); err != nil {
			return fmt.Errorf("ACME accept: %w", err)
		}
		if _, err := client.WaitAuthorization(ctx, authzURL); err != nil {
			return fmt.Errorf("TLS-ALPN-01 validation: %w", err)
		}
	}
	// Keep the finalize URL from the original order: the polled copy that
	// WaitOrder returns does not always carry it.
	finalizeURL := order.FinalizeURL
	if _, err = client.WaitOrder(ctx, order.URI); err != nil {
		return fmt.Errorf("ACME order: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{domain}}, key)
	if err != nil {
		return err
	}
	if fixer, ok := client.HTTPClient.Transport.(*orderLocationFixer); ok {
		fixer.pair(finalizeURL, order.URI)
	}
	chain, _, err := client.CreateOrderCert(ctx, finalizeURL, csr, true)
	if err != nil {
		return fmt.Errorf("ACME finalize: %w", err)
	}
	var certPEM []byte
	for _, der := range chain {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	dir := autoDir(cfg, domain)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// Key first: a cert.pem without its key would be unusable after a crash.
	if err := writeFileAtomic(filepath.Join(dir, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})); err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(dir, "cert.pem"), certPEM); err != nil {
		return err
	}
	fc, err := loadDirCert(dir)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.auto[domain] = fc.cert
	delete(m.placeholders, domain)
	m.mu.Unlock()
	logf("cert: %s issued, expires %s, renews from %s", domain,
		fc.cert.Leaf.NotAfter.UTC().Format("2006-01-02"), renewAt(fc.cert.Leaf, cfg.ExpiryThresholdDays).UTC().Format("2006-01-02"))
	return nil
}

func writeFileAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
