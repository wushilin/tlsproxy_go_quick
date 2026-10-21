package main

// Certificates for rules that terminate TLS.
//
//   cert = local-ca  issued by a CA of your own, per name (see localca.go).
//   cert = auto    issued and renewed through ACME with the TLS-ALPN-01
//                  challenge (RFC 8737): the CA connects to port 443 with ALPN
//                  "acme-tls/1" and we answer with a special self-signed
//                  certificate. No port 80 involved.
//
// Issuance runs in the background: names with no (or an expired) certificate
// first, renewals after. Names are independent of each other, so up to
// maxParallelJobs run at once; one name never has two jobs at a time. A failed
// name is retried after certRetryInterval. Before ordering, the name must resolve (via public
// resolvers, not the local one, which may be split-horizon) to one of
// public_ip_address, so misconfigured names don't burn the CA's rate limits.
//
// A rule's names are those in cert_domains. With cert_validate_script, other
// names matching the rule's pattern can earn a certificate too: the script is
// run as `<script> <name>` and exit status 0 accepts the name. It is asked only
// when a certificate has to be issued or renewed, never per connection and not
// for a name whose certificate on disk is still good.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/acme"
)

const (
	certRetryInterval  = 6 * time.Hour
	certCheckInterval  = 10 * time.Minute
	localRenewInterval = 6 * time.Hour // local CAs: renew what is due, empty old archives
	certJobTimeout     = 5 * time.Minute

	maxParallelJobs = 4 // names being validated / issued at the same time

	maxCandidates = 64   // names waiting for the script; they come from clients
	maxRejected   = 1024 // remembered refusals; likewise
)

// Overridable in tests.
var (
	validateScriptTimeout = 20 * time.Second // then the script is killed
	validateRejectTTL     = 10 * time.Minute // a refused name is not asked about again for this long
)

// Each job is tried this many times, this far apart, to ride out temporary
// failures (a dropped connection, an overloaded ACME API). Only then does the
// name wait for certRetryInterval. Overridable in tests.
var (
	certAttempts       = 3
	certAttemptBackoff = 5 * time.Second
)

// permanentError marks failures that an immediate retry cannot fix, or that
// are expensive to repeat: a DNS pre-check mismatch, and a validation the CA
// itself rejected (Let's Encrypt allows only 5 failed validations per name
// per hour, so hammering it would lock the name out).
type permanentError struct{ error }

func (e permanentError) Unwrap() error { return e.error }

type fileCert struct {
	cert    *tls.Certificate
	digests [3][32]byte
}

type CertManager struct {
	applyMu   sync.Mutex // serialises config changes with certificate file commits
	cfgCtx    context.Context
	cfgCancel context.CancelFunc
	// mu guards the maps below for the worker, reloads and the console.
	// Writers take it with lock/unlock, and unlock publishes a read-only copy
	// of what a handshake needs in view: handshakes never take mu.
	mu           sync.RWMutex
	view         atomic.Pointer[certView]
	proposals    *ring[string]             // names a handshake asks to put to the script; the worker takes them
	localCAs     syncMap[string, *localCA] // by dir (<cert_root>/caNNN); handshakes read it without a lock
	localLog     rateLimitedLog
	localRenewed time.Time // when the local CAs were last gone through
	cfg          *Config
	auto         map[string]*tls.Certificate // by domain
	challenges   map[string]*tls.Certificate // pending TLS-ALPN-01 answers, by domain
	placeholders map[string]*tls.Certificate
	nextTry      map[string]time.Time
	lastError    map[string]string // why a name is waiting for its next attempt
	announced    map[string]string // last status logged per name, to log changes only

	// Names decided by a rule's cert_validate_script rather than cert_domains.
	dynamic    map[string]bool      // accepted: managed like a cert_domains name
	candidates map[string]bool      // requested by a client, no usable certificate, script not asked yet
	rejected   map[string]time.Time // refused by the script; not asked again before this time
	queueFull  time.Time            // when "too many candidates" was last logged

	inFlight  map[string]bool // names with a job running: the per-name guard
	accountMu sync.Mutex      // the ACME account key is shared by all jobs: create it once
	wake      chan struct{}
	started   bool

	// Overridable in tests.
	issueFunc     func(ctx context.Context, cfg *Config, domain string) error
	retryInterval time.Duration
	checkInterval time.Duration
}

func NewCertManager() *CertManager {
	ctx, cancel := context.WithCancel(context.Background())
	m := &CertManager{
		cfgCtx:        ctx,
		cfgCancel:     cancel,
		auto:          map[string]*tls.Certificate{},
		challenges:    map[string]*tls.Certificate{},
		placeholders:  map[string]*tls.Certificate{},
		nextTry:       map[string]time.Time{},
		lastError:     map[string]string{},
		announced:     map[string]string{},
		dynamic:       map[string]bool{},
		candidates:    map[string]bool{},
		rejected:      map[string]time.Time{},
		inFlight:      map[string]bool{},
		wake:          make(chan struct{}, 1),
		proposals:     newRing[string](maxCandidates),
		retryInterval: certRetryInterval,
		checkInterval: certCheckInterval,
	}
	m.localCAs.init() // ready before the first handshake reads it
	return m
}

// certView is what handshakes read: copies of the maps, never changed once
// published (an ArcSwap: readers load a pointer, writers swap in a new one).
type certView struct {
	cfg              *Config
	auto, challenges map[string]*tls.Certificate
	dynamic          map[string]bool
	candidates       map[string]bool
	rejected         map[string]time.Time
	placeholders     map[string]*tls.Certificate
}

func (m *CertManager) lock() { m.mu.Lock() }

// unlock publishes the maps as they are now, then releases mu.
func (m *CertManager) unlock() {
	m.view.Store(&certView{
		cfg:  m.cfg,
		auto: maps.Clone(m.auto), challenges: maps.Clone(m.challenges),
		dynamic: maps.Clone(m.dynamic), candidates: maps.Clone(m.candidates), rejected: maps.Clone(m.rejected),
		placeholders: maps.Clone(m.placeholders),
	})
	m.mu.Unlock()
}

// current is the published view (an empty one before the first publish).
func (m *CertManager) current() *certView {
	if v := m.view.Load(); v != nil {
		return v
	}
	return &certView{}
}

// Apply validates cfg's certificate settings and makes them current. Every
// local CA a rule names must open, otherwise the config is rejected (at
// startup and on reload). Automatic certificates are picked up from disk if
// present; the rest is the background worker's job.
func (m *CertManager) Apply(cfg *Config) error {
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	if err := m.openLocalCAs(cfg); err != nil {
		return err
	}
	if err := checkScripts(cfg); err != nil {
		return err
	}
	m.lock()
	if m.cfgCancel != nil {
		m.cfgCancel() // jobs of the previous configuration stop
	}
	m.cfgCtx, m.cfgCancel = context.WithCancel(context.Background())
	m.cfg = cfg
	// The rules or the script may have changed: forget refusals, and let go of
	// accepted names that no rule with a script covers any more.
	m.rejected = map[string]time.Time{}
	for d := range m.dynamic {
		if scriptFor(cfg, d) == "" {
			delete(m.dynamic, d)
		}
	}
	for d := range m.candidates {
		if scriptFor(cfg, d) == "" {
			delete(m.candidates, d)
		}
	}
	// Certificates issued earlier for script-accepted names are picked up
	// again after a restart, so they keep being renewed.
	if entries, err := os.ReadDir(cfg.CertPath); err == nil {
		for _, e := range entries {
			if d := e.Name(); e.IsDir() && validDomain(d) && !m.dynamic[d] && scriptFor(cfg, d) != "" {
				m.candidates[d] = true
			}
		}
	}
	m.unlock()
	for _, d := range cfg.AutoDomains() {
		m.loadAutoFromDisk(cfg, d)
	}
	m.announce(cfg, time.Now())
	select {
	case m.wake <- struct{}{}:
	default:
	}
	return nil
}

// Check reports whether cfg's local CAs and scripts can be used, without
// changing anything (the console validates unsaved text with it).
func (m *CertManager) Check(cfg *Config) error {
	// Every CA a rule names must exist (made on the Certificates page) and load.
	for i := range cfg.Rules {
		if id := cfg.Rules[i].LocalCA(); id != "" {
			dir := filepath.Join(cfg.CARoot, id)
			if _, err := os.Stat(dir); id == defaultCAID && errors.Is(err, os.ErrNotExist) {
				continue // made when the configuration is applied
			}
			if _, err := openLocalCA(id, dir, false); err != nil {
				return fmt.Errorf("rule at line %d: cert: local-ca:%s: %w", cfg.Rules[i].Line, id, err)
			}
		}
	}
	return checkScripts(cfg)
}

// openLocalCAs opens every CA a rule of cfg uses; each must exist already
// (made on the Certificates page). One already open stays open: its certificates are
// kept.
func (m *CertManager) openLocalCAs(cfg *Config) error {
	// The default CA, whether a rule uses it or not: made if missing, then
	// renewed with the others. Only a rule that needs it fails without it.
	if dir := filepath.Join(cfg.CARoot, defaultCAID); !m.hasLocalCA(dir) {
		if l, err := openLocalCA(defaultCAID, dir, true); err != nil {
			errorf("cert: the default CA %s can't be made or opened in %s: %v", defaultCAID, dir, err)
		} else {
			m.localCAs.Store(dir, l)
		}
	}
	for i := range cfg.Rules {
		id := cfg.Rules[i].LocalCA()
		if id == "" {
			continue
		}
		dir := filepath.Join(cfg.CARoot, id)
		if _, ok := m.localCAs.Load(dir); ok {
			continue
		}
		l, err := openLocalCA(id, dir, false)
		if err != nil {
			return fmt.Errorf("rule at line %d: cert: local-ca:%s: %w", cfg.Rules[i].Line, id, err)
		}
		m.localCAs.Store(dir, l)
	}
	return nil
}

// localCAIssues reports whether a rule of cfg would have CA id issue for
// name: one using that CA matches the name, and its cert_domains allow it.
// A name with addresses (see sanKey) is a NONE or ANY rule's: the one its
// cert_domains make, or any one address with its host names when it lists
// none (the address a client connected to).
func localCAIssues(cfg *Config, id, name string) bool {
	ips, hosts := sanSplit(name)
	for i := range cfg.Rules {
		r := &cfg.Rules[i]
		if r.LocalCA() != id {
			continue
		}
		if len(ips) > 0 {
			if !r.NoSNI && r.Kind != kindCatchAll {
				continue
			}
			if len(r.certIPs) > 0 {
				if r.certKey == name {
					return true
				}
			} else if a, _ := netip.AddrFromSlice(ips[0]); len(ips) == 1 && sanKey([]netip.Addr{a.Unmap()}, r.certHosts) == name {
				return true
			}
			continue
		}
		if len(hosts) == 1 && r.LocalCAIssues(name) && (r.Kind == kindCatchAll || (r.Pattern != nil && r.Pattern.MatchString(name))) {
			return true
		}
	}
	return false
}

// LocalCA is the open CA id in cfg's cert_root, nil if no rule uses it.
func (m *CertManager) LocalCA(cfg *Config, id string) *localCA {
	l, _ := m.localCAs.Load(filepath.Join(cfg.CARoot, id))
	return l
}

// reloadLocalCAConfigs picks up edits of the CAs' config.yaml files.
func (m *CertManager) reloadLocalCAConfigs() {
	m.localCAs.Range(func(_ string, l *localCA) bool {
		l.loadConfig()
		return true
	})
}

// renewLocalCAs is the local CAs' renewal pass, run at start and every
// localRenewInterval: each CA's own certificate when due, every certificate
// it issued that is due (and a rule still issues for), and archives over 14
// days old (each CA's, cert_root's own of deleted CAs, and acme's of
// removed automatic certificates).
func (m *CertManager) renewLocalCAs() {
	cfg := m.current().cfg
	if cfg != nil {
		pruneArchiveDir(filepath.Join(cfg.CARoot, localArchiveName))
		pruneArchiveDir(filepath.Join(cfg.CertPath, localArchiveName))
	}
	m.localCAs.Range(func(_ string, l *localCA) bool {
		if err := l.renewCA(); err != nil {
			errorf("cert: CA %s: %v", l.id, err)
		}
		if cfg != nil {
			l.renewAll(func(name string) bool { return localCAIssues(cfg, l.id, name) })
		}
		l.pruneArchive()
		return true
	})
}

// checkScripts makes sure every cert_validate_script is there and executable.
func checkScripts(cfg *Config) error {
	for i := range cfg.Rules {
		script := cfg.Rules[i].CertValidateScript
		if script == "" {
			continue
		}
		st, err := os.Stat(script)
		if err == nil && (st.IsDir() || !scriptExecutable(script, st.Mode())) {
			err = errors.New("not an executable file")
		}
		if err != nil {
			return fmt.Errorf("rule at line %d: cert_validate_script: %s: %w", cfg.Rules[i].Line, script, err)
		}
	}
	return nil
}

// Windows does not expose Unix executable mode bits. Admission programs there
// must be native executables; no command shell is implicitly invoked.
func scriptExecutable(path string, mode os.FileMode) bool {
	if runtime.GOOS == "windows" {
		ext := filepath.Ext(path)
		return strings.EqualFold(ext, ".exe") || strings.EqualFold(ext, ".com")
	}
	return mode&0o111 != 0
}

// scriptFor returns the cert_validate_script in charge of a name: the name is
// routed to a cert = auto rule that has one and does not list it in
// cert_domains. "" otherwise.
func scriptFor(cfg *Config, domain string) string {
	if !validDomain(domain) || domain[0] == '-' { // never hand the script something that looks like an option
		return ""
	}
	d := cfg.Route(domain)
	if d.Rule == nil || d.Rule.Cert != "auto" || slices.Contains(d.Rule.CertDomains, domain) {
		return ""
	}
	return d.Rule.CertValidateScript
}

// scriptArgs are the arguments the script in charge of domain is run with:
// its rule's cert_validate_args with the captures filled in.
func scriptArgs(cfg *Config, domain string) []string {
	d := cfg.Route(domain)
	if d.Rule == nil {
		return []string{domain}
	}
	m := []int{0, len(domain)}
	if d.Rule.Pattern != nil {
		if got := d.Rule.Pattern.FindStringSubmatchIndex(domain); got != nil {
			m = got
		}
	}
	var out []string
	for _, a := range d.Rule.CertValidateArgs {
		v, err := expand(a, domain, m)
		if err != nil { // checked at load time; never hand the script half an argument
			return []string{domain}
		}
		out = append(out, v)
	}
	if len(out) == 0 {
		return []string{domain}
	}
	return out
}

// managedLocked lists every name with an automatic certificate: those from
// cert_domains, then those a script accepted.
func (m *CertManager) managedLocked(cfg *Config) []string {
	out := cfg.AutoDomains()
	var extra []string
	for d := range m.dynamic {
		if !slices.Contains(out, d) {
			extra = append(extra, d)
		}
	}
	sort.Strings(extra)
	return append(out, extra...)
}

// runValidateScript asks a cert_validate_script about one name. Exit status 0
// accepts it. detail describes the outcome for the log; err is set when the
// script could not give an answer at all (which counts as a refusal).
func runValidateScript(script string, args []string) (accepted bool, detail string, err error) {
	return runValidateScriptContext(context.Background(), script, args)
}

func runValidateScriptContext(parent context.Context, script string, args []string) (accepted bool, detail string, err error) {
	ctx, cancel := context.WithTimeout(parent, validateScriptTimeout)
	defer cancel()
	start := time.Now()
	out := &cappedBuffer{max: 300}
	cmd := exec.CommandContext(ctx, script, args...)
	cmd.Stdout, cmd.Stderr = out, out
	cmd.WaitDelay = 2 * time.Second // a child holding the pipes open can't stall us
	runErr := cmd.Run()
	said := ""
	if text := strings.Join(strings.Fields(string(out.b)), " "); text != "" {
		said = fmt.Sprintf(", output %q", text)
	}
	took := humanDuration(time.Since(start))
	var exit *exec.ExitError
	switch {
	case runErr == nil:
		return true, fmt.Sprintf("exit status 0 in %s%s", took, said), nil
	case ctx.Err() != nil:
		return false, "", fmt.Errorf("no answer within %s%s", humanDuration(validateScriptTimeout), said)
	case errors.As(runErr, &exit) && exit.ExitCode() > 0:
		return false, fmt.Sprintf("exit status %d in %s%s", exit.ExitCode(), took, said), nil
	default:
		return false, "", fmt.Errorf("%v%s", runErr, said)
	}
}

// quoteArgs shows arguments for the log, quoting those that need it.
func quoteArgs(args []string) string {
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = a
		if a == "" || strings.ContainsAny(a, " \t\"'\\$") {
			out[i] = strconv.Quote(a)
		}
	}
	return strings.Join(out, " ")
}

// cappedBuffer keeps the first max bytes written to it.
type cappedBuffer struct {
	b   []byte
	max int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if room := c.max - len(c.b); room > 0 {
		c.b = append(c.b, p[:min(room, len(p))]...)
	}
	return len(p), nil
}

// Start launches the background worker (once).
func (m *CertManager) Start() {
	m.lock()
	defer m.unlock()
	if !m.started {
		m.started = true
		go m.worker()
	}
}

// Read and parse the same snapshot, so the recorded digests describe the
// certificate actually installed. Missing ca.pem is allowed; other errors aren't.
func readCertFiles(dir string) (files [3][]byte, digests [3][32]byte, err error) {
	for i, name := range []string{"cert.pem", "key.pem", "ca.pem"} {
		files[i], err = os.ReadFile(filepath.Join(dir, name))
		if err != nil && !(i == 2 && errors.Is(err, os.ErrNotExist)) {
			return files, digests, err
		}
		digests[i] = sha256.Sum256(files[i])
	}
	return files, digests, nil
}

func parseDirCert(files [3][]byte, digests [3][32]byte) (*fileCert, error) {
	cert, err := tls.X509KeyPair(files[0], files[1])
	if err != nil {
		return nil, err
	}
	for block, rest := pem.Decode(files[2]); block != nil; block, rest = pem.Decode(rest) {
		if block.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, block.Bytes)
		}
	}
	if cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
		return nil, err
	}
	return &fileCert{cert: &cert, digests: digests}, nil
}

func loadDirCert(dir string) (*fileCert, error) {
	files, digests, err := readCertFiles(dir)
	if err != nil {
		return nil, err
	}
	return parseDirCert(files, digests)
}

func autoDir(cfg *Config, domain string) string { return filepath.Join(cfg.CertPath, domain) }

func (m *CertManager) loadAutoFromDisk(cfg *Config, domain string) {
	fc, err := loadDirCert(autoDir(cfg, domain))
	if err != nil {
		return
	}
	m.lock()
	m.auto[domain] = fc.cert
	m.unlock()
}

// CertificateFor returns what to present for a terminating rule and SNI.
// Until an automatic certificate exists, a short-lived self-signed placeholder
// keeps the service reachable (with a browser warning).
//
// Placeholders are never made per client-chosen name: a flood of random names
// would cost a key generation and a signature each. Only a name from
// cert_domains (a list the configuration bounds) gets its own; every other name
// shares one placeholder per rule, a wildcard where the pattern allows it.
//
// It runs in every terminated handshake and takes no lock: it reads the
// published view, which may be a moment behind the worker.
func (m *CertManager) CertificateFor(rule *Rule, sni string) (*tls.Certificate, error) {
	return m.CertificateForClient(rule, helloInfo{SNI: sni}, netip.Addr{})
}

// CertificateForClient is CertificateFor with what a local CA also needs for
// a client without a host name: an IP address it sent as its server name,
// and the address it connected to.
func (m *CertManager) CertificateForClient(rule *Rule, hello helloInfo, dialed netip.Addr) (*tls.Certificate, error) {
	sni := hello.SNI
	if rule.fixedCert != nil {
		return rule.fixedCert, nil
	}
	if id := rule.LocalCA(); id != "" {
		return m.localCertificate(rule, id, hello, dialed) // no placeholder: a name it doesn't issue for is refused
	}
	v := m.current()
	var cert *tls.Certificate
	propose := false
	if rule.Cert == "auto" {
		cert = v.auto[sni]
		// A name only the rule's script can vouch for, seen for the first time.
		// The connection is not held up: the worker asks the script, and
		// clients get the placeholder until a certificate is there.
		propose = cert == nil && rule.CertValidateScript != "" && !slices.Contains(rule.CertDomains, sni) &&
			!v.dynamic[sni] && !v.candidates[sni] && time.Now().After(v.rejected[sni])
	}
	key, name := placeholderFor(rule, sni)
	if cert == nil {
		if cert = v.placeholders[key]; cert != nil && time.Now().After(cert.Leaf.NotAfter.Add(-time.Hour)) {
			cert = nil // about to expire: make a new one
		}
	}
	if propose && m.proposals.TryPush(sni) { // full: it is proposed again when next requested
		select {
		case m.wake <- struct{}{}:
		default:
		}
	}
	if cert != nil {
		return cert, nil
	}
	ph, err := selfSigned(name, 7*24*time.Hour)
	if err != nil {
		return nil, err
	}
	// Keep it for the next handshake, unless the worker holds the lock right
	// now: then the next one makes its own, rather than this one waiting.
	if m.mu.TryLock() {
		if len(m.placeholders) > 256 { // keys come from the configuration; a backstop all the same
			m.placeholders = map[string]*tls.Certificate{}
		}
		m.placeholders[key] = ph
		m.unlock()
	}
	return ph, nil
}

// localCertificate is a cert = local-ca rule's certificate for a client (see
// Rule.LocalCAName). A name it does not issue for (outside cert_domains), a
// full CA or a failure is an error: the handshake fails and the client is
// refused, with no placeholder.
func (m *CertManager) localCertificate(rule *Rule, id string, hello helloInfo, dialed netip.Addr) (*tls.Certificate, error) {
	sni, err := rule.LocalCAName(hello.SNI, hello.SNIIP, dialed)
	if err != nil {
		return nil, fmt.Errorf("CA %s: %v", id, err)
	}
	cfg := m.current().cfg
	l := (*localCA)(nil)
	if cfg != nil {
		l = m.LocalCA(cfg, id)
	}
	if l == nil {
		return nil, fmt.Errorf("CA %s is not open", id)
	}
	c, err := l.certificate(sni)
	if err != nil {
		m.localLog.logf("cert: CA %s: %s refused: %v", id, sni, err)
		return nil, fmt.Errorf("CA %s: %v", id, err)
	}
	return c, nil
}

// placeholderFor says which placeholder serves sni under rule: the key it is
// kept under and the name it is made for.
func placeholderFor(rule *Rule, sni string) (key, name string) {
	if slices.Contains(rule.CertDomains, sni) {
		return sni, sni // a configured name: its own, replaced by the real certificate
	}
	key = fmt.Sprintf("rule %d %s", rule.Line, rule.Source)
	switch rest, ok := strings.CutPrefix(strings.ToLower(rule.Source), "*."); {
	case rule.Kind == kindWildcard && ok && validDomain(rest):
		return key, "*." + rest // *.s3.example.com: matches whatever the client asked for
	case rule.Kind == kindLiteral:
		return key, literalName(rule.Source)
	}
	return key, "placeholder.invalid" // several *, or ANY: no one certificate name fits
}

// takeProposals moves the names handshakes asked about into candidates.
func (m *CertManager) takeProposals() {
	for {
		sni, ok := m.proposals.TryPop()
		if !ok {
			return
		}
		m.mu.RLock()
		known := m.candidates[sni] || m.dynamic[sni]
		m.mu.RUnlock()
		if !known {
			m.propose(sni)
		}
	}
}

// propose queues a client-requested name for the rule's cert_validate_script.
func (m *CertManager) propose(sni string) {
	m.lock()
	cfg := m.cfg
	switch {
	case cfg == nil || scriptFor(cfg, sni) == "":
		m.unlock()
		return
	case len(m.candidates) >= maxCandidates:
		if time.Since(m.queueFull) > time.Minute {
			m.queueFull = time.Now()
			errorf("cert: %s: %d names are already waiting for a cert_validate_script decision; this one is not queued (it is considered again when it is next requested)", sni, maxCandidates)
		}
		m.unlock()
		return
	}
	m.candidates[sni] = true
	m.unlock()
	logf("cert: %s: requested by a client, not in cert_domains and no certificate yet; cert_validate_script %s will be asked", sni, scriptFor(cfg, sni))
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

// Challenge returns the pending TLS-ALPN-01 answer for a name, if any.
func (m *CertManager) Challenge(sni string) *tls.Certificate {
	return m.current().challenges[sni] // no lock: the published view
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

// adoptCandidates settles candidates that need no decision: a name whose
// certificate on disk is still good becomes managed without asking the script
// (it is asked at renewal), and one no script covers any more is dropped. The
// rest stay candidates and become urgent jobs.
func (m *CertManager) adoptCandidates(cfg *Config) {
	m.lock()
	defer m.unlock()
	if m.cfg != cfg {
		return
	}
	for d := range m.candidates {
		if scriptFor(cfg, d) == "" {
			delete(m.candidates, d)
			continue
		}
		fc, err := loadDirCert(autoDir(cfg, d))
		if err != nil || time.Now().After(fc.cert.Leaf.NotAfter) {
			continue
		}
		m.auto[d], m.dynamic[d] = fc.cert, true
		delete(m.candidates, d)
		logf("cert: %s: certificate found in %s, issued earlier with the approval of cert_validate_script; the script is asked again when it is due for renewal", d, autoDir(cfg, d))
	}
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
	candidates := make([]string, 0, len(m.candidates))
	for d := range m.candidates {
		candidates = append(candidates, d)
	}
	sort.Strings(candidates)
	for _, d := range append(m.managedLocked(m.cfg), candidates...) {
		if m.inFlight[d] || now.Before(m.nextTry[d]) {
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

// status describes one automatic certificate for the log.
func certStatus(c *tls.Certificate, thresholdDays int, now time.Time) string {
	if c == nil || c.Leaf == nil {
		return "no certificate yet, will be issued"
	}
	leaf := c.Leaf
	days := int(leaf.NotAfter.Sub(now).Hours() / 24)
	day := func(t time.Time) string { return t.UTC().Format("2006-01-02") }
	switch due := renewAt(leaf, thresholdDays); {
	case now.After(leaf.NotAfter):
		return fmt.Sprintf("EXPIRED on %s, will be re-issued", day(leaf.NotAfter))
	case now.After(due):
		return fmt.Sprintf("expiring: valid until %s (%d days left), renewal is due", day(leaf.NotAfter), days)
	default:
		return fmt.Sprintf("valid until %s (%d days left), issuer %q, renews from %s", day(leaf.NotAfter), days, leaf.Issuer.CommonName, day(due))
	}
}

// announce logs each name's status when it is new or has changed (so a name
// added by a reload, or one that has entered its renewal window, shows up).
func (m *CertManager) announce(cfg *Config, now time.Time) {
	m.lock()
	defer m.unlock()
	if m.cfg != cfg {
		return
	}
	current := map[string]bool{}
	for _, d := range m.managedLocked(cfg) {
		current[d] = true
		status := certStatus(m.auto[d], cfg.ExpiryThresholdDays, now)
		key := strings.SplitN(status, "(", 2)[0] // ignore the day counter
		if m.announced[d] == key {
			continue
		}
		if _, known := m.announced[d]; !known {
			logf("cert: %s: managed name, %s", d, status)
		} else {
			logf("cert: %s: %s", d, status)
		}
		m.announced[d] = key
	}
	for d := range m.announced {
		if !current[d] {
			logf("cert: %s: no longer configured; its certificate stays in %s", d, autoDir(cfg, d))
			delete(m.announced, d)
		}
	}
}

func (m *CertManager) worker() {
	for {
		m.takeProposals()
		m.reloadLocalCAConfigs()
		if time.Since(m.localRenewed) >= localRenewInterval {
			m.localRenewed = time.Now() // only this goroutine reads or writes it
			m.renewLocalCAs()
		}
		m.mu.RLock()
		cfg := m.cfg
		m.mu.RUnlock()
		if cfg != nil {
			m.adoptCandidates(cfg)
			m.announce(cfg, time.Now())
		}
		// Most urgent first, as many as there are free slots. A finished job
		// wakes this loop, which then starts whatever is next.
		for _, job := range m.pendingJobs(time.Now()) {
			if !m.startJob(cfg, job) {
				break
			}
		}
		select {
		case <-m.wake:
		case <-time.After(m.checkInterval):
		}
	}
}

// startJob runs a job in its own goroutine. False if every slot is taken.
func (m *CertManager) startJob(cfg *Config, job certJob) bool {
	m.lock()
	if cfg == nil || m.cfg != cfg || m.inFlight[job.domain] || len(m.inFlight) >= maxParallelJobs {
		m.unlock()
		return false
	}
	ctx := m.cfgCtx
	m.inFlight[job.domain] = true // pendingJobs skips it until the job is done
	m.unlock()
	go func() {
		defer func() {
			m.lock()
			delete(m.inFlight, job.domain)
			m.unlock()
			select {
			case m.wake <- struct{}{}:
			default:
			}
		}()
		m.runJobContext(ctx, cfg, job)
	}()
	return true
}

// runJob issues or renews one name: up to certAttempts tries a few seconds
// apart, then the name waits for retryInterval.
func (m *CertManager) runJob(cfg *Config, job certJob) {
	m.mu.RLock()
	ctx := m.cfgCtx
	m.mu.RUnlock()
	m.runJobContext(ctx, cfg, job)
}

func (m *CertManager) runJobContext(jobCtx context.Context, cfg *Config, job certJob) {
	m.mu.RLock()
	if cfg == nil || m.cfg != cfg || jobCtx.Err() != nil {
		m.mu.RUnlock()
		return
	}
	previous := m.lastError[job.domain]
	current := m.auto[job.domain]
	m.mu.RUnlock()
	if !slices.Contains(cfg.AutoDomains(), job.domain) && !m.scriptAllows(jobCtx, cfg, job, current) {
		return
	}
	what := "issuing a new certificate"
	if !job.urgent {
		what = "renewing"
	} else if current != nil {
		what = "re-issuing the expired certificate"
	}
	if previous != "" {
		logf("cert: %s: %s, scheduled retry (the previous attempt failed: %s)", job.domain, what, previous)
	} else {
		logf("cert: %s: %s (%s)", job.domain, what, certStatus(current, cfg.ExpiryThresholdDays, time.Now()))
	}
	var err error
	for attempt := 1; attempt <= certAttempts; attempt++ {
		ctx, cancel := context.WithTimeout(jobCtx, certJobTimeout)
		issue := m.issue
		if m.issueFunc != nil {
			issue = m.issueFunc
		}
		if jobCtx.Err() != nil {
			cancel()
			return
		}
		err = issue(ctx, cfg, job.domain)
		cancel()
		if jobCtx.Err() != nil {
			return
		}
		if err == nil {
			break
		}
		var permanent permanentError
		if errors.As(err, &permanent) {
			errorf("cert: %s: attempt %d/%d failed: %v (not retried right away: repeating this would not help)", job.domain, attempt, certAttempts, err)
			break
		}
		if attempt < certAttempts {
			errorf("cert: %s: attempt %d/%d failed: %v; trying again in %s", job.domain, attempt, certAttempts, err, humanDuration(certAttemptBackoff))
			if !waitForRetry(jobCtx, certAttemptBackoff) {
				return
			}
		} else {
			errorf("cert: %s: attempt %d/%d failed: %v", job.domain, attempt, certAttempts, err)
		}
	}
	m.lock()
	defer m.unlock()
	if m.cfg != cfg || jobCtx.Err() != nil {
		return
	}
	if err == nil {
		delete(m.nextTry, job.domain)
		delete(m.lastError, job.domain)
		return
	}
	next := time.Now().Add(m.retryInterval)
	m.nextTry[job.domain], m.lastError[job.domain] = next, err.Error()
	serving := "clients get a self-signed placeholder meanwhile"
	if current != nil && time.Now().Before(current.Leaf.NotAfter) {
		serving = fmt.Sprintf("the current certificate stays in use until %s", current.Leaf.NotAfter.UTC().Format("2006-01-02"))
	}
	errorf("cert: %s: giving up for now; next attempt at %s (in %s); %s", job.domain,
		next.UTC().Format("2006-01-02T15:04Z"), humanDuration(m.retryInterval), serving)
}

func waitForRetry(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// scriptAllows asks the rule's cert_validate_script whether a name that is not
// in cert_domains may get (or renew) its certificate, and logs the answer.
func (m *CertManager) scriptAllows(ctx context.Context, cfg *Config, job certJob, current *tls.Certificate) bool {
	domain := job.domain
	script := scriptFor(cfg, domain)
	usable := current != nil && current.Leaf != nil && time.Now().Before(current.Leaf.NotAfter)
	why := "a new certificate is needed"
	if !job.urgent {
		why = "its certificate is due for renewal"
	} else if current != nil {
		why = "its certificate has expired"
	}
	if script == "" { // the config changed under us
		m.lock()
		if m.cfg != cfg || ctx.Err() != nil {
			m.unlock()
			return false
		}
		delete(m.candidates, domain)
		delete(m.dynamic, domain)
		m.unlock()
		logf("cert: %s: no rule with a cert_validate_script covers this name any more; nothing is requested", domain)
		return false
	}
	args := scriptArgs(cfg, domain)
	logf("cert: %s: %s; asking cert_validate_script: %s %s", domain, why, script, quoteArgs(args))
	accepted, detail, err := runValidateScriptContext(ctx, script, args)
	m.lock()
	defer m.unlock()
	if m.cfg != cfg || ctx.Err() != nil {
		return false
	}
	if accepted {
		delete(m.candidates, domain)
		m.dynamic[domain] = true
		logf("cert: %s: ACCEPTED by cert_validate_script %s (%s); requesting the certificate", domain, script, detail)
		return true
	}
	if err != nil {
		errorf("cert: %s: cert_validate_script %s gave no answer, which counts as a refusal: %v", domain, script, err)
		detail = err.Error()
	}
	if usable {
		// Still serving a good certificate: keep it, ask again later.
		next := time.Now().Add(m.retryInterval)
		m.nextTry[domain], m.lastError[domain] = next, "not renewed: refused by cert_validate_script ("+detail+")"
		errorf("cert: %s: REFUSED by cert_validate_script %s (%s); the certificate is NOT renewed. The current one stays in use until %s; the script is asked again at %s",
			domain, script, detail, current.Leaf.NotAfter.UTC().Format("2006-01-02"), next.UTC().Format("2006-01-02T15:04Z"))
		return false
	}
	delete(m.candidates, domain)
	delete(m.dynamic, domain)
	delete(m.auto, domain)
	delete(m.nextTry, domain)
	delete(m.lastError, domain)
	if len(m.rejected) >= maxRejected {
		m.rejected = map[string]time.Time{}
	}
	m.rejected[domain] = time.Now().Add(validateRejectTTL)
	errorf("cert: %s: REFUSED by cert_validate_script %s (%s); no certificate is requested and clients get the self-signed placeholder. The script is asked again if the name is requested after %s, or after a config reload",
		domain, script, detail, humanDuration(validateRejectTTL))
	return false
}

// The DNS pre-check asks at most dnsAttempts times, each time the next
// resolver in dns_resolvers (round robin, so a single one is asked three
// times), and gives each attempt dnsAttemptTimeout to answer. A record
// that points here (yes), and no such record or one that points elsewhere
// (no), are final; anything else (no response, a timeout, refused, SERVFAIL)
// is tried again. No answer in all attempts is a no: the CA is not asked.
// Neither number is configurable.
const (
	dnsAttempts       = 3
	dnsAttemptTimeout = 3 * time.Second
)

// dnsErrText is a lookup error without the resolver's address, which names
// the system's resolver (Dial ignores the address it is given), not the one
// asked.
func dnsErrText(err error) string {
	var oe *net.OpError
	if errors.As(err, &oe) {
		return oe.Err.Error()
	}
	var de *net.DNSError
	if errors.As(err, &de) {
		return de.Err
	}
	return err.Error()
}

// checkDNS makes sure domain publicly resolves to one of our addresses.
func checkDNS(ctx context.Context, cfg *Config, domain string) error {
	if len(cfg.PublicIPs) == 0 {
		return nil
	}
	var errs []string
	for attempt := range dnsAttempts {
		if ctx.Err() != nil {
			break
		}
		server := cfg.DNSResolvers[attempt%len(cfg.DNSResolvers)]
		if _, _, err := net.SplitHostPort(server); err != nil {
			server = net.JoinHostPort(server, "53")
		}
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, server)
		}}
		one, cancel := context.WithTimeout(ctx, dnsAttemptTimeout)
		addrs, err := r.LookupNetIP(one, "ip", domain)
		cancel()
		if err != nil {
			// "No such record" is an answer, and final. Anything else (no
			// response, a timeout, refused, the resolver failing) is tried
			// again with the next resolver.
			var de *net.DNSError
			switch {
			case errors.As(err, &de) && de.IsNotFound:
				return fmt.Errorf("DNS pre-check: %s has no address record (resolver %s: %s); not asking the CA", domain, server, de.Err)
			case de != nil && de.IsTimeout:
				err = fmt.Errorf("no answer within %s", dnsAttemptTimeout)
			default:
				err = errors.New(dnsErrText(err))
			}
			errs = append(errs, fmt.Sprintf("%s: %v", server, err))
			continue
		}
		// Every address must be ours, A and AAAA alike: the CA picks one itself
		// and prefers IPv6, so a stray AAAA record fails the validation even
		// when the A record is right.
		var got, foreign []string
		for _, a := range addrs {
			ip := a.Unmap().String()
			got = append(got, ip)
			if !slices.Contains(cfg.PublicIPs, ip) {
				foreign = append(foreign, ip)
			}
		}
		if len(foreign) == 0 && len(got) > 0 {
			logf("cert: %s: DNS pre-check ok (%s via resolver %s)", domain, strings.Join(got, ", "), server)
			return nil
		}
		hint := ""
		if len(foreign) < len(got) {
			hint = ". The CA may validate against any of the name's addresses and prefers IPv6, so all of them must lead here"
		}
		return permanentError{fmt.Errorf("DNS pre-check: %s resolves to %s, of which %s is not in public_ip_address (%s)%s; not asking the CA",
			domain, strings.Join(got, ", "), strings.Join(foreign, ", "), strings.Join(cfg.PublicIPs, ", "), hint)}
	}
	return fmt.Errorf("DNS pre-check: cannot resolve %s; no answer in %d attempts (%s); not asking the CA", domain, len(errs), strings.Join(errs, "; "))
}

func (m *CertManager) acmeClient(cfg *Config) (*acme.Client, error) {
	dir := filepath.Join(cfg.CertPath, "_account")
	keyFile := filepath.Join(dir, "account.key")
	var key crypto.Signer
	m.accountMu.Lock() // two first-ever jobs must not each create a key
	defer m.accountMu.Unlock()
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
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment, IdleConnTimeout: time.Minute, TLSHandshakeTimeout: 15 * time.Second}
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
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := checkDNS(ctx, cfg, domain); err != nil {
		return err
	}
	client, err := m.acmeClient(cfg)
	if err != nil {
		return err
	}
	if fixer, ok := client.HTTPClient.Transport.(*orderLocationFixer); ok {
		if transport, ok := fixer.next.(*http.Transport); ok {
			defer transport.CloseIdleConnections()
		}
	}
	acct := &acme.Account{}
	if cfg.AcmeEmail != "" {
		acct.Contact = []string{"mailto:" + cfg.AcmeEmail}
	}
	switch _, err := client.Register(ctx, acct, acme.AcceptTOS); {
	case err == nil:
		logf("cert: registered a new ACME account at %s (key in %s)", cfg.AcmeDirectory, filepath.Join(cfg.CertPath, "_account"))
	case !errors.Is(err, acme.ErrAccountAlreadyExists):
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
		m.lock()
		if m.cfg != cfg || ctx.Err() != nil {
			m.unlock()
			return context.Canceled
		}
		m.challenges[domain] = &answer
		m.unlock()
		defer func() {
			m.lock()
			delete(m.challenges, domain)
			m.unlock()
		}()
		logf("cert: %s: order created, TLS-ALPN-01 answer ready; asking the CA to validate on port 443", domain)
		if _, err := client.Accept(ctx, chal); err != nil {
			return fmt.Errorf("ACME accept: %w", err)
		}
		if _, err := client.WaitAuthorization(ctx, authzURL); err != nil {
			// The CA tried and said no. Let's Encrypt allows 5 of these per
			// name per hour, so don't repeat it within seconds.
			return permanentError{fmt.Errorf("TLS-ALPN-01 validation rejected by the CA: %w", err)}
		}
		logf("cert: %s: validated by the CA", domain)
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
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return m.installCertificate(ctx, cfg, domain, certPEM, keyPEM)
}

func (m *CertManager) installCertificate(ctx context.Context, cfg *Config, domain string, certPEM, keyPEM []byte) error {
	// Config application and the on-disk/in-memory commit cannot cross. A CA
	// response that arrives after cancellation must not install an old result.
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	m.mu.RLock()
	currentConfig := m.cfg == cfg && ctx.Err() == nil
	m.mu.RUnlock()
	if !currentConfig {
		return context.Canceled
	}
	dir := autoDir(cfg, domain)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// Key first: a cert.pem without its key would be unusable after a crash.
	if err := writeFileAtomic(filepath.Join(dir, "key.pem"), keyPEM); err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(dir, "cert.pem"), certPEM); err != nil {
		return err
	}
	fc, err := loadDirCert(dir)
	if err != nil {
		return err
	}
	m.lock()
	m.auto[domain] = fc.cert
	delete(m.placeholders, domain)
	m.announced[domain] = "issued" // the next pass logs the new validity
	m.unlock()
	leaf := fc.cert.Leaf
	logf("cert: %s: ISSUED by %q, serial %x, valid %s to %s, renews from %s, saved in %s", domain, leaf.Issuer.CommonName,
		leaf.SerialNumber, leaf.NotBefore.UTC().Format("2006-01-02"), leaf.NotAfter.UTC().Format("2006-01-02"),
		renewAt(leaf, cfg.ExpiryThresholdDays).UTC().Format("2006-01-02"), dir)
	return nil
}

func writeFileAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

// CertInfo describes one certificate for the console.
type CertInfo struct {
	Name        string // the name it is for
	Source      string // "auto" or "local-ca"
	CA          string // local-ca: which CA issued it
	Dir         string // where it lives on disk
	RuleLines   []int  // rules using it
	Status      string // ok | expiring | expired | missing | failing
	Detail      string // human-readable status
	Issuer      string
	Names       []string // DNS names in the certificate
	NotBefore   string
	NotAfter    string
	DaysLeft    int
	Removable   bool   // RemoveCertificate accepts it: local-ca always, auto only when something is wrong
	RenewFrom   string // auto only
	LastError   string // auto only: why the last attempt failed
	NextAttempt string // auto only: when it is retried
}

// Snapshot lists every certificate in use: automatic ones and what each local
// CA issued.
func (m *CertManager) Snapshot() []CertInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.cfg == nil {
		return nil
	}
	now := time.Now()
	day := func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04Z") }
	fill := func(info *CertInfo, c *tls.Certificate) {
		if c == nil || c.Leaf == nil {
			info.Status = "missing"
			return
		}
		leaf := c.Leaf
		info.Issuer, info.Names = leaf.Issuer.CommonName, leaf.DNSNames
		for _, ip := range leaf.IPAddresses {
			info.Names = append(info.Names, ip.String())
		}
		info.NotBefore, info.NotAfter = day(leaf.NotBefore), day(leaf.NotAfter)
		info.DaysLeft = int(leaf.NotAfter.Sub(now).Hours() / 24)
		switch {
		case now.After(leaf.NotAfter):
			info.Status = "expired"
		case now.After(renewAt(leaf, m.cfg.ExpiryThresholdDays)):
			info.Status = "expiring"
		default:
			info.Status = "ok"
		}
	}
	lines := map[string][]int{}
	var order []string
	for i := range m.cfg.Rules {
		r := &m.cfg.Rules[i]
		keys := r.CertDomains
		if r.LocalCA() != "" {
			continue // listed below, from what each CA issued
		}
		for _, k := range keys {
			if _, seen := lines[k]; !seen {
				order = append(order, k)
			}
			lines[k] = append(lines[k], r.Line)
		}
	}
	for _, d := range m.managedLocked(m.cfg) { // names accepted by a script
		if _, seen := lines[d]; !seen {
			order, lines[d] = append(order, d), []int{m.cfg.Route(d).RuleLine}
		}
	}
	var out []CertInfo
	for _, k := range order {
		info := CertInfo{RuleLines: lines[k]}
		{
			info.Source, info.Name, info.Dir = "auto", k, autoDir(m.cfg, k)
			c := m.auto[k]
			fill(&info, c)
			info.Detail = certStatus(c, m.cfg.ExpiryThresholdDays, now)
			if m.dynamic[k] {
				info.Detail += "; accepted by cert_validate_script"
			}
			if c != nil && c.Leaf != nil {
				info.RenewFrom = day(renewAt(c.Leaf, m.cfg.ExpiryThresholdDays))
			}
			if e := m.lastError[k]; e != "" {
				info.LastError, info.NextAttempt = e, day(m.nextTry[k])
				if info.Status == "missing" || info.Status == "expired" {
					info.Status = "failing"
				}
			}
			info.Removable = autoRemovable(c, m.lastError[k], info.Dir, now)
		}
		out = append(out, info)
	}
	// What each local CA issued, by name.
	m.localCAs.Range(func(dir string, l *localCA) bool {
		var lines []int
		for i := range m.cfg.Rules {
			if r := &m.cfg.Rules[i]; filepath.Join(m.cfg.CARoot, r.LocalCA()) == dir && r.LocalCA() != "" {
				lines = append(lines, r.Line)
			}
		}
		leaves := l.leaves()
		sort.Slice(leaves, func(i, j int) bool { return leaves[i].name < leaves[j].name })
		for _, leaf := range leaves {
			name, c := leaf.name, leaf.cert
			info := CertInfo{Name: name, Source: "local-ca", CA: l.id, Dir: filepath.Join(dir, localCAFolder(name)), RuleLines: lines, Removable: true}
			fill(&info, c)
			if info.Status == "expiring" || info.Status == "ok" {
				info.Status = "ok" // the renewal pass takes care of it
			}
			info.RenewFrom = day(renewDue(c.Leaf))
			info.Detail = fmt.Sprintf("issued by CA %s on first use; renewed automatically from %s (checked every 6 hours)", l.id, info.RenewFrom)
			out = append(out, info)
		}
		return true
	})
	return out
}

// autoRemovable says whether an automatic certificate may be removed: only
// when something is wrong with it (expired, its last attempt failed, or its
// files are there but unusable). A valid one that renews normally may not.
func autoRemovable(c *tls.Certificate, lastError, dir string, now time.Time) bool {
	if c == nil || c.Leaf == nil {
		_, err := os.Stat(dir)
		return err == nil
	}
	return lastError != "" || now.After(c.Leaf.NotAfter)
}

// RemoveCertificate archives a certificate (local-ca: of CA ca) and forgets
// it. A local CA issues the name again when a client asks; an automatic name
// is requested again at once (a script-accepted one: when a client asks and
// the script agrees again).
func (m *CertManager) RemoveCertificate(source, ca, name string) error {
	if source == "local-ca" {
		cfg := m.current().cfg
		l := (*localCA)(nil)
		if cfg != nil {
			l = m.LocalCA(cfg, ca)
		}
		if l == nil {
			return fmt.Errorf("no rule uses a CA %q", ca)
		}
		return l.remove(name)
	}
	m.lock()
	cfg := m.cfg
	switch {
	case cfg == nil || !slices.Contains(m.managedLocked(cfg), name):
		m.unlock()
		return fmt.Errorf("%s is not an automatic certificate name", name)
	case m.inFlight[name]:
		m.unlock()
		return fmt.Errorf("%s is being requested right now; try again in a moment", name)
	case !autoRemovable(m.auto[name], m.lastError[name], autoDir(cfg, name), time.Now()):
		m.unlock()
		if m.auto[name] == nil {
			return fmt.Errorf("%s has no certificate yet: nothing to remove", name)
		}
		return fmt.Errorf("%s is valid and renews normally: nothing to remove", name)
	}
	to, err := moveToArchive(cfg.CertPath, name)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		m.unlock()
		return err
	}
	delete(m.auto, name)
	delete(m.dynamic, name)
	delete(m.nextTry, name)
	delete(m.lastError, name)
	m.unlock()
	logf("cert: %s: removed from the console; moved to %s, deleted after 14 days; requested again if a rule still asks for it", name, to)
	select {
	case m.wake <- struct{}{}:
	default:
	}
	return nil
}

// RetryNow clears a name's wait and wakes the worker. False if the name is
// not an automatic certificate.
func (m *CertManager) RetryNow(domain string) bool {
	m.lock()
	known := false
	if m.cfg != nil {
		known = slices.Contains(m.managedLocked(m.cfg), domain)
	}
	if known {
		delete(m.nextTry, domain)
	}
	m.unlock()
	if known {
		select {
		case m.wake <- struct{}{}:
		default:
		}
	}
	return known
}

// hasLocalCA reports whether the CA in dir is open.
func (m *CertManager) hasLocalCA(dir string) bool {
	_, ok := m.localCAs.Load(dir)
	return ok
}
