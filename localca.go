package main

// cert = local-ca: certificates from CAs of your own, for names that public
// CAs can't or shouldn't issue (internal hosts, no public DNS), or from your
// organisation's CA, pasted in.
//
// Every CA has a folder in cert_root, caNNN; a rule picks one with
// cert = local-ca:ca002 (plain cert = local-ca is ca001):
//
//	<cert_root>/ca001/ca_cert.pem        the CA certificate, then its issuers if it
//	                                   is an intermediate
//	<cert_root>/ca001/ca_key.pem         its private key
//	<cert_root>/ca001/<name>/cert.pem    one certificate per name (and the chain),
//	<cert_root>/ca001/<name>/key.pem     issued the first time a client asks for it,
//	                                   renewed before it expires (checked every 6
//	                                   hours; a handshake that finds it due renews
//	                                   it too)
//	<cert_root>/ca001/ip_<addresses>/    the same, for a client without a host name:
//	                                   ip_10.0.0.5, ip_fd00--1 (":" can't be in a
//	                                   file name on Windows), or several addresses
//	                                   and names in one certificate joined by "+"
//	<cert_root>/ca001/_archive/<name>-<UTC time>
//	                                   certificates found on disk that this CA did
//	                                   not issue (or that are broken): moved aside,
//	                                   never used, deleted after 14 days
//
// The default CA, ca001, is made at start-up when cert_root has none; others
// are made on the console's CAs page (generated, or an existing one pasted
// in), and a rule naming one that doesn't exist is a config error. A self-signed CA's
// certificate is renewed before it expires, with the same key and subject, so
// what it issued stays valid. A host name has no "_", so neither the CA files
// nor _archive nor ip_ can clash with a host name's folder.
//
// A handshake finds its certificate in a lock-free table: no lock, no file
// search. Issuing one is local and takes well under a millisecond, so the
// first client for a name gets it at once; two racing clients may both sign
// one, and the first to publish wins.

import (
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"hash/maphash"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	localArchiveName = "_archive"
	localArchiveKeep = 14 * 24 * time.Hour
	maxLocalCerts    = 10000
	localTableSize   = 16384 // a power of two, comfortably over maxLocalCerts
)

var errLocalCAFull = fmt.Errorf("the local CA already holds %d certificates", maxLocalCerts)

// localCA is one CA folder, <cert_root>/caNNN: its CA and the certificates it
// issued.
type localCA struct {
	id   string // caNNN
	dir  string
	ca   atomic.Pointer[caState]       // replaced whole when the CA certificate is renewed
	conf atomic.Pointer[caConfigState] // its config.yaml, as in use
	seed maphash.Seed
	slot [localTableSize]atomic.Pointer[localLeaf]
	n    atomic.Int64
}

type caState struct {
	cert  *x509.Certificate
	chain [][]byte // what is sent after a leaf: the CA and its issuers, roots left out
	key   crypto.Signer
}

type localLeaf struct {
	name string
	cur  atomic.Pointer[leafState] // read without a lock
	mu   sync.Mutex                // held to load, issue, renew or write this name's certificate
}

// leafState is a certificate in memory and the CA state it was checked
// against. When the CA's state is replaced (renewed, or its files changed on
// disk), the certificate is checked again, once, before it is served.
type leafState struct {
	cert *tls.Certificate
	ca   *caState
}

// current is the certificate in memory, nil if none.
func (e *localLeaf) current() *tls.Certificate {
	if st := e.cur.Load(); st != nil {
		return st.cert
	}
	return nil
}

// caLocks serialises the operations on one CA (by its folder): making it,
// renewing it, deleting it, saving its config.yaml. caRootLocks does the same
// for a cert_root, so two new CAs never take the same id.
var caLocks, caRootLocks syncMap[string, *sync.Mutex]

func lockPath(m *syncMap[string, *sync.Mutex], path string) (unlock func()) {
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	mu := m.LoadOrMake(filepath.Clean(path), func() *sync.Mutex { return new(sync.Mutex) })
	mu.Lock()
	return mu.Unlock
}

// lockCA holds the lock of the CA in dir until the returned func is called.
func lockCA(dir string) func() { return lockPath(&caLocks, dir) }

// lockCARoot holds the lock of a cert_root (choosing ids, making CA folders).
func lockCARoot(root string) func() { return lockPath(&caRootLocks, root) }

var caIDPattern = regexp.MustCompile(`^ca[0-9]{3}$`)

// openLocalCA loads the CA in dir. With create, a CA that is not there is
// made (a rule refers to it); otherwise its absence is an error.
// defaultCAID is the CA every proxy has: made at start-up when cert_root has
// none, and kept renewed like any CA. cert: local-ca names it.
const defaultCAID = "ca001"

func openLocalCA(id, dir string, create bool) (*localCA, error) {
	l := &localCA{id: id, dir: dir, seed: maphash.MakeSeed()}
	if create {
		defer lockCARoot(filepath.Dir(dir))() // the console may be making a CA with this id right now
	}
	made := false
	if _, err := os.Stat(filepath.Join(dir, "ca_key.pem")); errors.Is(err, os.ErrNotExist) {
		if !create {
			return nil, fmt.Errorf("no CA in %s", dir)
		}
		conf := defaultCAConfig(id)
		if id == defaultCAID {
			conf.CommonName, conf.ValidityDays = "Local CA", 20*365
		}
		if err := generateCA(dir, conf); err != nil {
			return nil, err
		}
		made = true
	}
	if err := l.renewCA(); err != nil {
		return nil, err
	}
	switch {
	case made && id == defaultCAID:
		sum := sha256.Sum256(l.ca.Load().cert.Raw)
		logf("cert: made the default CA %s, \"Local CA\", in %s: valid 20 years, renewed with the same key before it expires. Clients that should trust what cert: local-ca issues install %s (SHA-256 %X)",
			id, dir, filepath.Join(dir, "ca_cert.pem"), sum[:])
	case made:
		logf("cert: CA %s: made a new CA in %s (a rule uses it)", id, dir)
	}
	l.loadConfig()
	return l, nil
}

// generateCA makes a new CA in dir, which must not hold one yet, as conf's
// ca says, and writes conf as its config.yaml.
func generateCA(dir string, conf *caConfig) error {
	if err := conf.check(); err != nil {
		return err
	}
	defer lockCA(dir)()
	key, err := newKey(conf.KeyAlgorithm, conf.KeyBits)
	if err != nil {
		return err
	}
	subject := pkix.Name{CommonName: conf.CommonName}
	if conf.Organization != "" {
		subject.Organization = []string{conf.Organization}
	}
	der, err := signCA(subject, key, time.Duration(conf.ValidityDays)*24*time.Hour, conf.HashAlgorithm)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := writeCA(dir, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})); err != nil {
		return err
	}
	cert, _ := x509.ParseCertificate(der)
	return writeConfigFor(dir, conf, cert)
}

// writeConfigFor writes a new CA's config.yaml, its ca section as the
// certificate has it.
func writeConfigFor(dir string, conf *caConfig, cert *x509.Certificate) error {
	c := *conf
	setCAFromCert(&c, cert)
	return writeFileAtomic0600(filepath.Join(dir, caConfigFile), []byte(c.text()))
}

// setCAFromCert fills ca from the CA certificate: what it was made with.
// These are fixed once the CA exists; config.yaml can't change them.
func setCAFromCert(c *caConfig, cert *x509.Certificate) {
	c.CommonName, c.Organization = cert.Subject.CommonName, ""
	if len(cert.Subject.Organization) > 0 {
		c.Organization = cert.Subject.Organization[0]
	}
	describeKey(c, cert.PublicKey)
	c.ValidityDays = int((cert.NotAfter.Sub(cert.NotBefore) + 12*time.Hour) / (24 * time.Hour))
	switch cert.SignatureAlgorithm {
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384:
		c.HashAlgorithm = "sha384"
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512, x509.PureEd25519:
		c.HashAlgorithm = "sha512"
	default:
		c.HashAlgorithm = "sha256"
	}
}

// importCA checks an existing CA (certificate PEM, optionally followed by
// its issuers, and its private key) and stores it in dir.
func importCA(dir string, certPEM, keyPEM []byte) (*x509.Certificate, error) {
	defer lockCA(dir)()
	certs, err := parseCertChain(certPEM)
	if err != nil {
		return nil, err
	}
	key, err := parseSigner(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("private key: %v", err)
	}
	ca := certs[0]
	switch {
	case !ca.IsCA || !ca.BasicConstraintsValid:
		return nil, fmt.Errorf("the first certificate (%s) is not a CA certificate", ca.Subject.CommonName)
	case ca.KeyUsage != 0 && ca.KeyUsage&x509.KeyUsageCertSign == 0:
		return nil, fmt.Errorf("the certificate %s may not sign certificates (no keyCertSign)", ca.Subject.CommonName)
	case !publicKeyMatches(ca, key):
		return nil, fmt.Errorf("the private key does not belong to the certificate %s", ca.Subject.CommonName)
	case !time.Now().Before(ca.NotAfter):
		return nil, fmt.Errorf("the certificate %s expired on %s", ca.Subject.CommonName, ca.NotAfter.UTC().Format("2006-01-02"))
	}
	for i := 1; i < len(certs); i++ {
		if err := certs[i-1].CheckSignatureFrom(certs[i]); err != nil {
			return nil, fmt.Errorf("certificate %d (%s) is not signed by the next one (%s): put the CA first, then its issuers in order",
				i, certs[i-1].Subject.CommonName, certs[i].Subject.CommonName)
		}
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	var chain []byte
	for _, c := range certs {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	if err := writeCA(dir, chain, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})); err != nil {
		return nil, err
	}
	return ca, writeConfigFor(dir, defaultCAConfig(filepath.Base(dir)), ca)
}

// writeCA stores a new CA, refusing to overwrite one.
func writeCA(dir string, certPEM, keyPEM []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	keyPath := filepath.Join(dir, "ca_key.pem")
	f, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // O_EXCL: never replace a CA
	if err != nil {
		return fmt.Errorf("%s: %w", keyPath, err)
	}
	_, err = f.Write(keyPEM)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(keyPath)
		return err
	}
	return writeFileAtomic0600(filepath.Join(dir, "ca_cert.pem"), certPEM)
}

// signCA self-signs a CA certificate for key.
func signCA(subject pkix.Name, key crypto.Signer, life time.Duration, hash string) ([]byte, error) {
	now := time.Now()
	t := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               subject,
		SignatureAlgorithm:    signatureAlgorithm(key, hash),
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(life),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		SubjectKeyId:          keyID(key.Public()),
	}
	return x509.CreateCertificate(rand.Reader, t, t, key.Public(), key)
}

// renewCA loads the CA and, for a self-signed one, re-signs its certificate
// with the same key and subject once a third of its lifetime is left: what it
// issued stays valid. A CA issued by someone else (an intermediate) can't be
// renewed here; it is reported as it nears expiry.
func (l *localCA) renewCA() error {
	defer lockCA(l.dir)()
	keyPath, certPath := filepath.Join(l.dir, "ca_key.pem"), filepath.Join(l.dir, "ca_cert.pem")
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	key, err := parseSigner(keyPEM)
	if err != nil {
		return fmt.Errorf("%s: %v", keyPath, err)
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}
	certs, err := parseCertChain(certPEM)
	if err != nil {
		return fmt.Errorf("%s: %v", certPath, err)
	}
	ca := certs[0]
	if !publicKeyMatches(ca, key) {
		return fmt.Errorf("%s does not belong to %s", keyPath, certPath)
	}
	selfSigned := ca.CheckSignatureFrom(ca) == nil
	if selfSigned && !time.Now().Before(renewDue(ca)) {
		// Same key, name, lifetime and hash as before: from the certificate,
		// not config.yaml, whose ca can't change them.
		fixed := defaultCAConfig(l.id)
		setCAFromCert(fixed, ca)
		der, err := signCA(ca.Subject, key, time.Duration(fixed.ValidityDays)*24*time.Hour, fixed.HashAlgorithm)
		if err != nil {
			return err
		}
		if err := writeFileAtomic0600(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); err != nil {
			return err
		}
		ca, _ = x509.ParseCertificate(der)
		certs = []*x509.Certificate{ca}
		logf("cert: CA %s: certificate renewed with the same key, valid until %s (what it issued stays valid)", l.id, ca.NotAfter.UTC().Format("2006-01-02"))
	} else if !selfSigned && !time.Now().Before(renewDue(ca)) {
		errorf("cert: CA %s: %s expires on %s and was issued by %s, so it can't be renewed here: import a renewed one",
			l.id, ca.Subject.CommonName, ca.NotAfter.UTC().Format("2006-01-02"), ca.Issuer.CommonName)
	}
	var chain [][]byte
	for _, c := range certs {
		if c.CheckSignatureFrom(c) != nil { // roots are left out: clients have them
			chain = append(chain, c.Raw)
		}
	}
	l.ca.Store(&caState{cert: ca, chain: chain, key: key})
	return nil
}

// CAPEM is the CA certificate, for clients to trust.
func (l *localCA) CAPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: l.ca.Load().cert.Raw})
}

// renewDue is when a certificate is renewed: a third of its lifetime before
// it expires.
func renewDue(c *x509.Certificate) time.Time {
	return c.NotAfter.Add(-c.NotAfter.Sub(c.NotBefore) / 3)
}

// certificate returns the certificate for name, loading it from disk or
// issuing it on first use and renewing it when due.
//
// The usual case, a current certificate in memory that was checked against
// the CA as it is now, takes no lock and reads no file. Loading, issuing,
// renewing and checking again hold the name's lock: a second handshake for
// the same new name waits for the first (well under a millisecond) and gets
// its certificate, so only one is ever issued and its files are written once.
func (l *localCA) certificate(name string) (*tls.Certificate, error) {
	e := l.entry(name)
	if e == nil {
		return nil, errLocalCAFull
	}
	ca := l.ca.Load()
	if st := e.cur.Load(); st != nil && st.ca == ca && time.Now().Before(l.leafRenewDue(st.cert.Leaf)) {
		return st.cert, nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	ca = l.ca.Load()
	var cur *tls.Certificate
	if st := e.cur.Load(); st != nil { // again: the handshake we waited for may have done it
		cur = st.cert
		if st.ca != ca { // the CA changed since: is this still its certificate?
			if cur = withChain(cur, ca); cur == nil {
				l.archive(name, "not issued by the CA's current certificate")
				e.cur.Store(nil)
			} else {
				e.cur.Store(&leafState{cert: cur, ca: ca})
			}
		}
		if cur != nil && time.Now().Before(l.leafRenewDue(cur.Leaf)) {
			return cur, nil
		}
	}
	if cur == nil { // first use in this process: a certificate from an earlier run?
		if c := l.fromDisk(name, ca); c != nil {
			e.cur.Store(&leafState{cert: c, ca: ca})
			return c, nil
		}
	}
	c, err := l.issue(name, ca)
	if err != nil {
		if cur != nil {
			return cur, nil // keep serving the old one; renewal is tried again next time
		}
		return nil, err
	}
	if err := l.save(name, c); err != nil {
		errorf("cert: CA %s: %s: issued, but could not be saved (it is issued again after a restart): %v", l.id, name, err)
	}
	e.cur.Store(&leafState{cert: c, ca: ca})
	logf("cert: CA %s: %s %s, valid until %s", l.id, map[bool]string{true: "renewed", false: "issued"}[cur != nil], name,
		c.Leaf.NotAfter.UTC().Format("2006-01-02"))
	return c, nil
}

// entry finds (or adds) name's slot in the table; nil when the table is full.
func (l *localCA) entry(name string) *localLeaf {
	h := maphash.String(l.seed, name)
	for i := range uint64(localTableSize) {
		slot := &l.slot[(h+i)&(localTableSize-1)]
		e := slot.Load()
		if e == nil {
			if l.n.Load() >= maxLocalCerts {
				return nil
			}
			fresh := &localLeaf{name: name}
			if slot.CompareAndSwap(nil, fresh) {
				l.n.Add(1)
				return fresh
			}
			e = slot.Load()
		}
		if e.name == name {
			return e
		}
	}
	return nil
}

// find is name's slot, nil if it has none (unlike entry, it never adds one).
func (l *localCA) find(name string) *localLeaf {
	h := maphash.String(l.seed, name)
	for i := range uint64(localTableSize) {
		e := l.slot[(h+i)&(localTableSize-1)].Load()
		if e == nil || e.name == name {
			return e
		}
	}
	return nil
}

// withChain is c, checked against ca: nil if ca did not issue it, else c
// sent with ca's chain as it is now (an intermediate may have been replaced).
func withChain(c *tls.Certificate, ca *caState) *tls.Certificate {
	if c.Leaf.CheckSignatureFrom(ca.cert) != nil {
		return nil
	}
	out := *c
	out.Certificate = append([][]byte{c.Certificate[0]}, ca.chain...)
	return &out
}

// fromDisk loads name's certificate if ca issued it, it covers exactly that
// name and it is not due for renewal. Anything else in the folder is moved to
// the archive, so it is never used.
func (l *localCA) fromDisk(name string, ca *caState) *tls.Certificate {
	dir := filepath.Join(l.dir, localCAFolder(name))
	if _, err := os.Stat(dir); err != nil {
		return nil // nothing there: issue one
	}
	c, err := tls.LoadX509KeyPair(filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"))
	why := ""
	switch {
	case err != nil:
		why = err.Error()
	case c.Leaf.CheckSignatureFrom(ca.cert) != nil:
		why = "not issued by this CA"
	case leafKey(c.Leaf) != name:
		why = fmt.Sprintf("it is for %s, not %s", leafKey(c.Leaf), name)
	case !time.Now().Before(l.leafRenewDue(c.Leaf)):
		return nil // ours, but due: issue a new one (it overwrites this)
	default:
		return withChain(&c, ca)
	}
	l.archive(name, why)
	return nil
}

// archive moves name's folder aside, with the time in its name.
func (l *localCA) archive(name, why string) {
	if to, err := moveToArchive(l.dir, localCAFolder(name)); err == nil {
		errorf("cert: CA %s: %s: the certificate on disk is not used (%s); moved to %s, deleted after 14 days; a new one is issued", l.id, name, why, to)
		return
	}
	errorf("cert: CA %s: %s: the certificate on disk is not used (%s), and could not be moved aside", l.id, name, why)
}

// moveToArchive renames dir/name to dir/_archive/<name>-<UTC time>, where
// pruneArchiveDir deletes it after 14 days. A name archived twice in one
// second takes the next free second.
func moveToArchive(dir, name string) (string, error) {
	if err := os.MkdirAll(filepath.Join(dir, localArchiveName), 0o700); err != nil {
		return "", err
	}
	at := time.Now().UTC()
	for range 60 {
		to := filepath.Join(dir, localArchiveName, name+"-"+at.Format("20060102150405"))
		if _, err := os.Lstat(to); errors.Is(err, os.ErrNotExist) {
			return to, os.Rename(filepath.Join(dir, name), to)
		}
		at = at.Add(time.Second)
	}
	return "", fmt.Errorf("%s: no free name in %s", name, filepath.Join(dir, localArchiveName))
}

// remove archives name's certificate (from the console) and forgets it: the
// next client that asks for the name gets a new one, if a rule still issues it.
func (l *localCA) remove(name string) error {
	e := l.find(name)
	if e == nil || e.current() == nil {
		return fmt.Errorf("CA %s has no certificate for %s", l.id, name)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	to, err := moveToArchive(l.dir, localCAFolder(name))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	e.cur.Store(nil)
	logf("cert: CA %s: %s: removed from the console; moved to %s, deleted after 14 days; a new one is issued when a client asks for it", l.id, name, to)
	return nil
}

// renewAll renews, ahead of expiry, every certificate in the CA's folder that
// a rule still issues for (issues says which). The certificate worker runs
// it at start and every 6 hours; renewing at a handshake is only the fallback.
// Certificates found that this CA did not issue are archived on the way.
func (l *localCA) renewAll(issues func(name string) bool) {
	entries, err := os.ReadDir(l.dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name, ok := localCAName(e.Name())
		if !e.IsDir() || !ok || !issues(name) {
			continue
		}
		if _, err := l.certificate(name); err != nil {
			errorf("cert: CA %s: %s: could not renew: %v; tried again in 6 hours, or when a client asks for it", l.id, name, err)
		}
	}
}

// pruneArchive deletes archived folders older than localArchiveKeep.
func (l *localCA) pruneArchive() { pruneArchiveDir(filepath.Join(l.dir, localArchiveName)) }

// pruneArchiveDir deletes the entries of an archive (<name>-<UTC time>)
// older than localArchiveKeep.
func pruneArchiveDir(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		i := strings.LastIndexByte(e.Name(), '-')
		if i < 0 {
			continue
		}
		at, err := time.Parse("20060102150405", e.Name()[i+1:])
		if err != nil || time.Since(at) < localArchiveKeep {
			continue
		}
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err == nil {
			logf("cert: deleted %s from %s (archived over 14 days ago)", e.Name(), dir)
		}
	}
}

// leafRenewDue is when an issued certificate is renewed: renew_before_days
// before it expires, or when a third of its lifetime is left.
func (l *localCA) leafRenewDue(c *x509.Certificate) time.Time {
	if d := l.config().Cert.RenewBeforeDays; d > 0 {
		return c.NotAfter.Add(-time.Duration(d) * 24 * time.Hour)
	}
	return renewDue(c)
}

func (l *localCA) issue(name string, ca *caState) (*tls.Certificate, error) {
	conf := l.config().Cert
	key, err := newKey(conf.KeyAlgorithm, conf.KeyBits)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	subject := pkix.Name{CommonName: name}
	for _, f := range []struct {
		dst *[]string
		v   string
	}{{&subject.Organization, conf.Organization}, {&subject.OrganizationalUnit, conf.OrganizationalUnit},
		{&subject.Country, conf.Country}, {&subject.Province, conf.Province}, {&subject.Locality, conf.Locality}} {
		if f.v != "" {
			*f.dst = []string{f.v}
		}
	}
	var usage x509.KeyUsage
	for _, u := range conf.KeyUsage {
		usage |= keyUsages[u]
	}
	var ext []x509.ExtKeyUsage
	for _, u := range conf.ExtKeyUsage {
		ext = append(ext, extKeyUsages[u])
	}
	ips, hosts := sanSplit(name)
	tmpl := &x509.Certificate{
		SerialNumber:       randomSerial(),
		Subject:            subject,
		DNSNames:           hosts,
		IPAddresses:        ips,
		SignatureAlgorithm: signatureAlgorithm(ca.key, conf.HashAlgorithm),
		NotBefore:          now.Add(-time.Hour),
		NotAfter:           now.Add(time.Duration(conf.ValidityDays) * 24 * time.Hour),
		KeyUsage:           usage,
		ExtKeyUsage:        ext,
		AuthorityKeyId:     ca.cert.SubjectKeyId,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, key.Public(), ca.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: append([][]byte{der}, ca.chain...), PrivateKey: key, Leaf: leaf}, nil
}

func (l *localCA) save(name string, c *tls.Certificate) error {
	dir := filepath.Join(l.dir, localCAFolder(name))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(c.PrivateKey)
	if err != nil {
		return err
	}
	if err := writeFileAtomic0600(filepath.Join(dir, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err != nil {
		return err
	}
	var chain []byte
	for _, der := range c.Certificate {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return writeFileAtomic0600(filepath.Join(dir, "cert.pem"), chain)
}

// issuedLeaf is a certificate a local CA holds, by the name it is kept under.
type issuedLeaf struct {
	name string
	cert *tls.Certificate
}

// leaves lists the certificates issued (or loaded) in this process.
func (l *localCA) leaves() []issuedLeaf {
	var out []issuedLeaf
	for i := range l.slot {
		if e := l.slot[i].Load(); e != nil {
			if c := e.current(); c != nil {
				out = append(out, issuedLeaf{e.name, c})
			}
		}
	}
	return out
}

// isHostName is a valid host name that is not an IP address: 10.0.0.5 has
// only letters, digits and dots, but a certificate carries it as an address.
func isHostName(d string) bool {
	_, err := netip.ParseAddr(d)
	return err != nil && validDomain(d)
}

// sanKey is the name a certificate for these IP addresses and host names
// is kept under: one host name alone is itself; otherwise the addresses,
// then the names, each sorted, joined by ",": "10.0.0.5", "10.0.0.5,fd00::1",
// "10.0.0.5,box.lan".
func sanKey(ips []netip.Addr, hosts []string) string {
	if len(ips) == 0 && len(hosts) == 1 {
		return hosts[0]
	}
	ips, hosts = slices.Clone(ips), slices.Clone(hosts)
	for i, ip := range ips {
		ips[i] = ip.Unmap()
	}
	slices.SortFunc(ips, netip.Addr.Compare)
	slices.Sort(hosts)
	var parts []string
	for _, ip := range slices.Compact(ips) {
		parts = append(parts, ip.String())
	}
	return strings.Join(append(parts, slices.Compact(hosts)...), ",")
}

// sanSplit is the IP addresses and host names of a sanKey.
func sanSplit(key string) (ips []net.IP, hosts []string) {
	for _, part := range strings.Split(key, ",") {
		if ip, err := netip.ParseAddr(part); err == nil {
			ips = append(ips, net.IP(ip.AsSlice()))
		} else {
			hosts = append(hosts, part)
		}
	}
	return ips, hosts
}

// leafKey is the sanKey of what a certificate covers.
func leafKey(c *x509.Certificate) string {
	var ips []netip.Addr
	for _, ip := range c.IPAddresses {
		if a, ok := netip.AddrFromSlice(ip); ok {
			ips = append(ips, a.Unmap())
		}
	}
	return sanKey(ips, c.DNSNames)
}

// localCAFolder is the folder a certificate's name is kept in: a host name
// is itself, anything with an address is ip_ and the name with "," as "+"
// and ":" as "-" (fd00::1 is ip_fd00--1).
func localCAFolder(key string) string {
	if isHostName(key) {
		return key
	}
	return "ip_" + strings.NewReplacer(",", "+", ":", "-").Replace(key)
}

// localCAName reads a folder name back (see localCAFolder): false for a
// folder that is not a certificate's (_archive, or anything else).
func localCAName(folder string) (string, bool) {
	if isHostName(folder) {
		return folder, true
	}
	rest, ok := strings.CutPrefix(folder, "ip_")
	if !ok || rest == "" {
		return "", false
	}
	var ips []netip.Addr
	var hosts []string
	for _, part := range strings.Split(rest, "+") {
		if !strings.Contains(part, ".") { // an IPv6 address: its canonical form has no dot
			part = strings.ReplaceAll(part, "-", ":")
		}
		if ip, err := netip.ParseAddr(part); err == nil && ip.Zone() == "" {
			ips = append(ips, ip.Unmap())
		} else if isHostName(part) {
			hosts = append(hosts, part)
		} else {
			return "", false
		}
	}
	key := sanKey(ips, hosts)
	if len(ips) == 0 || localCAFolder(key) != folder {
		return "", false // not the way this proxy names one
	}
	return key, true
}

// parseSigner reads a private key in PEM: PKCS#8, EC or PKCS#1 (RSA).
func parseSigner(data []byte) (crypto.Signer, error) {
	for {
		var b *pem.Block
		if b, data = pem.Decode(data); b == nil {
			return nil, fmt.Errorf("no private key in the PEM data")
		}
		var k any
		var err error
		switch b.Type {
		case "PRIVATE KEY":
			k, err = x509.ParsePKCS8PrivateKey(b.Bytes)
		case "EC PRIVATE KEY":
			k, err = x509.ParseECPrivateKey(b.Bytes)
		case "RSA PRIVATE KEY":
			k, err = x509.ParsePKCS1PrivateKey(b.Bytes)
		case "ENCRYPTED PRIVATE KEY":
			return nil, fmt.Errorf("the key is encrypted: decrypt it first (openssl pkey -in key.pem -out plain.pem)")
		default:
			continue // e.g. EC PARAMETERS before the key
		}
		if err != nil {
			return nil, err
		}
		s, ok := k.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("unsupported key type %T", k)
		}
		return s, nil
	}
}

// parseCertChain reads one or more certificates in PEM, in order.
func parseCertChain(data []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var b *pem.Block
		if b, data = pem.Decode(data); b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no certificate in the PEM data")
	}
	return out, nil
}

func publicKeyMatches(c *x509.Certificate, key crypto.Signer) bool {
	pub, ok := c.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	return ok && pub.Equal(key.Public())
}

// keyID is the usual subject key identifier: SHA-1 of the public key.
func keyID(pub crypto.PublicKey) []byte {
	der, _ := x509.MarshalPKIXPublicKey(pub)
	sum := sha1.Sum(der)
	return sum[:]
}

func randomSerial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	return n
}

// writeFileAtomic0600 writes a private file whole: a reader never sees half.
func writeFileAtomic0600(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
