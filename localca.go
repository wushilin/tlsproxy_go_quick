package main

// cert = local-ca: certificates from CAs of your own, for names that public
// CAs can't or shouldn't issue (internal hosts, no public DNS), or from your
// organisation's CA, pasted in.
//
// Every CA has a folder in ca_root, caNNN; a rule picks one with
// cert = local-ca:ca002 (plain cert = local-ca is ca001):
//
//	<ca_root>/ca001/ca_cert.pem        the CA certificate, then its issuers if it
//	                                   is an intermediate
//	<ca_root>/ca001/ca_key.pem         its private key
//	<ca_root>/ca001/<name>/cert.pem    one certificate per name (and the chain),
//	<ca_root>/ca001/<name>/key.pem     issued the first time a client asks for it,
//	                                   renewed before it expires (checked every 6
//	                                   hours; a handshake that finds it due renews
//	                                   it too)
//	<ca_root>/ca001/_archive/<name>-<UTC time>
//	                                   certificates found on disk that this CA did
//	                                   not issue (or that are broken): moved aside,
//	                                   never used, deleted after 14 days
//
// A CA is made on the console's CAs page only (generated, or an existing one
// pasted in); a rule naming one that doesn't exist is a config error. A self-signed CA's
// certificate is renewed before it expires, with the same key and subject, so
// what it issued stays valid. A host name has no "_", so neither the CA files
// nor _archive can clash with a certificate's folder.
//
// A handshake finds its certificate in a lock-free table: no lock, no file
// search. Issuing one is local and takes well under a millisecond, so the
// first client for a name gets it at once; two racing clients may both sign
// one, and the first to publish wins.

import (
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"hash/maphash"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
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

// localCA is one CA folder, <ca_root>/caNNN: its CA and the certificates it
// issued.
type localCA struct {
	id   string // caNNN
	dir  string
	ca   atomic.Pointer[caState]       // replaced whole when the CA certificate is renewed
	conf atomic.Pointer[caConfigState] // its config.toml, as in use
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
	cert atomic.Pointer[tls.Certificate] // read without a lock
	mu   sync.Mutex                      // held to load, issue, renew or write this name's certificate
}

// caLocks serialises the operations on one CA (by its folder): making it,
// renewing it, deleting it, saving its config.toml. caRootLocks does the same
// for a ca_root, so two new CAs never take the same id.
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

// lockCARoot holds the lock of a ca_root (choosing ids, making CA folders).
func lockCARoot(root string) func() { return lockPath(&caRootLocks, root) }

var caIDPattern = regexp.MustCompile(`^ca[0-9]{3}$`)

// openLocalCA loads the CA in dir. With create, a CA that is not there is
// made (a rule refers to it); otherwise its absence is an error.
func openLocalCA(id, dir string, create bool) (*localCA, error) {
	l := &localCA{id: id, dir: dir, seed: maphash.MakeSeed()}
	if create {
		defer lockCARoot(filepath.Dir(dir))() // the console may be making a CA with this id right now
	}
	if _, err := os.Stat(filepath.Join(dir, "ca_key.pem")); errors.Is(err, os.ErrNotExist) {
		if !create {
			return nil, fmt.Errorf("no CA in %s", dir)
		}
		if err := generateCA(dir, defaultCAConfig(id)); err != nil {
			return nil, err
		}
		logf("cert: CA %s: made a new CA in %s (a rule uses it)", id, dir)
	}
	if err := l.renewCA(); err != nil {
		return nil, err
	}
	l.loadConfig()
	return l, nil
}

// generateCA makes a new CA in dir, which must not hold one yet, as conf's
// [ca] says, and writes conf as its config.toml.
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

// writeConfigFor writes a new CA's config.toml, its [ca] section as the
// certificate has it.
func writeConfigFor(dir string, conf *caConfig, cert *x509.Certificate) error {
	c := *conf
	setCAFromCert(&c, cert)
	return writeFileAtomic0600(filepath.Join(dir, "config.toml"), []byte(c.text()))
}

// setCAFromCert fills [ca] from the CA certificate: what it was made with.
// These are fixed once the CA exists; config.toml can't change them.
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
		// not config.toml, whose [ca] can't change them.
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
// The usual case, a current certificate in memory, takes no lock. Loading,
// issuing and renewing hold the name's lock: a second handshake for the same
// new name waits for the first (well under a millisecond) and gets its
// certificate, so only one is ever issued and its files are written once.
func (l *localCA) certificate(name string) (*tls.Certificate, error) {
	e := l.entry(name)
	if e == nil {
		return nil, errLocalCAFull
	}
	if cur := e.cert.Load(); cur != nil && time.Now().Before(l.leafRenewDue(cur.Leaf)) {
		return cur, nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	cur := e.cert.Load() // again: the handshake we waited for may have done it
	if cur != nil && time.Now().Before(l.leafRenewDue(cur.Leaf)) {
		return cur, nil
	}
	if cur == nil { // first use in this process: a certificate from an earlier run?
		if c := l.fromDisk(name); c != nil {
			e.cert.Store(c)
			return c, nil
		}
	}
	c, err := l.issue(name)
	if err != nil {
		if cur != nil {
			return cur, nil // keep serving the old one; renewal is tried again next time
		}
		return nil, err
	}
	if err := l.save(name, c); err != nil {
		errorf("cert: CA %s: %s: issued, but could not be saved (it is issued again after a restart): %v", l.id, name, err)
	}
	e.cert.Store(c)
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

// fromDisk loads name's certificate if this CA issued it, it covers exactly
// that name and it is not due for renewal. Anything else in the folder is
// moved to the archive, so it is never used.
func (l *localCA) fromDisk(name string) *tls.Certificate {
	dir := filepath.Join(l.dir, name)
	if _, err := os.Stat(dir); err != nil {
		return nil // nothing there: issue one
	}
	c, err := tls.LoadX509KeyPair(filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"))
	why := ""
	switch {
	case err != nil:
		why = err.Error()
	case c.Leaf.CheckSignatureFrom(l.ca.Load().cert) != nil:
		why = "not issued by this CA"
	case len(c.Leaf.DNSNames) != 1 || c.Leaf.DNSNames[0] != name:
		why = fmt.Sprintf("it is for %v, not %s", c.Leaf.DNSNames, name)
	case !time.Now().Before(l.leafRenewDue(c.Leaf)):
		return nil // ours, but due: issue a new one (it overwrites this)
	default:
		return &c
	}
	l.archive(name, why)
	return nil
}

// archive moves name's folder aside, with the time in its name.
func (l *localCA) archive(name, why string) {
	to := filepath.Join(l.dir, localArchiveName, name+"-"+time.Now().UTC().Format("20060102150405"))
	if err := os.MkdirAll(filepath.Join(l.dir, localArchiveName), 0o700); err == nil {
		err = os.Rename(filepath.Join(l.dir, name), to)
		if err == nil {
			errorf("cert: CA %s: %s: the certificate on disk is not used (%s); moved to %s, deleted after 14 days; a new one is issued", l.id, name, why, to)
			return
		}
	}
	errorf("cert: CA %s: %s: the certificate on disk is not used (%s), and could not be moved aside", l.id, name, why)
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
		name := e.Name()
		if !e.IsDir() || !validDomain(name) || !issues(name) {
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

func (l *localCA) issue(name string) (*tls.Certificate, error) {
	ca, conf := l.ca.Load(), l.config().Cert
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
	tmpl := &x509.Certificate{
		SerialNumber:       randomSerial(),
		Subject:            subject,
		DNSNames:           []string{name},
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
	dir := filepath.Join(l.dir, name)
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

// leaves lists the certificates issued (or loaded) in this process.
func (l *localCA) leaves() []*tls.Certificate {
	var out []*tls.Certificate
	for i := range l.slot {
		if e := l.slot[i].Load(); e != nil {
			if c := e.cert.Load(); c != nil {
				out = append(out, c)
			}
		}
	}
	return out
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
