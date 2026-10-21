package main

// Each CA folder has a config.yaml: how the CA itself is made and renewed
// (ca) and what the certificates it issues look like (certificates). It
// is written when the CA is made, read again whenever it changes, and a
// broken one keeps the previous settings (and says so).

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

type caConfig struct {
	// ca
	CommonName, Organization string
	KeyAlgorithm             string // ecdsa, rsa or ed25519: when the CA is generated
	KeyBits                  int
	HashAlgorithm            string // its own renewals
	ValidityDays             int

	// certificates
	Cert struct {
		KeyAlgorithm                string
		KeyBits                     int
		HashAlgorithm               string
		ValidityDays                int
		RenewBeforeDays             int // 0: when a third of the lifetime is left
		KeyUsage                    []string
		ExtKeyUsage                 []string
		Organization                string
		OrganizationalUnit          string
		Country, Province, Locality string
	}
}

func defaultCAConfig(id string) *caConfig {
	c := &caConfig{CommonName: "tlsproxy CA " + id, Organization: "tlsproxy", KeyAlgorithm: "ecdsa", KeyBits: 256,
		HashAlgorithm: "sha256", ValidityDays: 3650}
	c.Cert.KeyAlgorithm, c.Cert.KeyBits, c.Cert.HashAlgorithm, c.Cert.ValidityDays = "ecdsa", 256, "sha256", 90
	c.Cert.KeyUsage, c.Cert.ExtKeyUsage = []string{"digitalSignature"}, []string{"serverAuth"}
	return c
}

var (
	keyUsages = map[string]x509.KeyUsage{
		"digitalSignature": x509.KeyUsageDigitalSignature, "contentCommitment": x509.KeyUsageContentCommitment,
		"keyEncipherment": x509.KeyUsageKeyEncipherment, "dataEncipherment": x509.KeyUsageDataEncipherment,
		"keyAgreement": x509.KeyUsageKeyAgreement,
	}
	extKeyUsages = map[string]x509.ExtKeyUsage{"serverAuth": x509.ExtKeyUsageServerAuth, "clientAuth": x509.ExtKeyUsageClientAuth}
)

// checkKey says whether an algorithm and size go together.
func checkKey(alg string, bits int) error {
	switch alg {
	case "ecdsa":
		if bits != 256 && bits != 384 && bits != 521 {
			return fmt.Errorf("ecdsa key_bits must be 256, 384 or 521, got %d", bits)
		}
	case "rsa":
		if bits != 2048 && bits != 3072 && bits != 4096 {
			return fmt.Errorf("rsa key_bits must be 2048, 3072 or 4096, got %d", bits)
		}
	case "ed25519":
	default:
		return fmt.Errorf("key_algorithm must be ecdsa, rsa or ed25519, got %q", alg)
	}
	return nil
}

func checkHash(h string) error {
	if h != "sha256" && h != "sha384" && h != "sha512" {
		return fmt.Errorf("hash_algorithm must be sha256, sha384 or sha512, got %q", h)
	}
	return nil
}

func (c *caConfig) check() error {
	fail := func(section string, err error) error { return fmt.Errorf("[%s] %v", section, err) }
	if c.CommonName == "" {
		return fmt.Errorf("ca: common_name must not be empty")
	}
	if err := checkKey(c.KeyAlgorithm, c.KeyBits); err != nil {
		return fail("ca", err)
	}
	if err := checkHash(c.HashAlgorithm); err != nil {
		return fail("ca", err)
	}
	if c.ValidityDays < 1 || c.ValidityDays > 36500 {
		return fmt.Errorf("ca: validity_days must be 1..36500, got %d", c.ValidityDays)
	}
	if err := checkKey(c.Cert.KeyAlgorithm, c.Cert.KeyBits); err != nil {
		return fail("certificates", err)
	}
	if err := checkHash(c.Cert.HashAlgorithm); err != nil {
		return fail("certificates", err)
	}
	if c.Cert.ValidityDays < 1 || c.Cert.ValidityDays > 3650 {
		return fmt.Errorf("certificates: validity_days must be 1..3650, got %d", c.Cert.ValidityDays)
	}
	if c.Cert.RenewBeforeDays < 0 || c.Cert.RenewBeforeDays >= c.Cert.ValidityDays {
		return fmt.Errorf("certificates: renew_before_days must be 0 (a third of the lifetime) or less than validity_days, got %d", c.Cert.RenewBeforeDays)
	}
	for _, u := range c.Cert.KeyUsage {
		if _, ok := keyUsages[u]; !ok {
			return fmt.Errorf("certificates: key_usage: unknown %q (use %s)", u, strings.Join(sortedKeys(keyUsages), ", "))
		}
	}
	if len(c.Cert.ExtKeyUsage) == 0 {
		return fmt.Errorf("certificates: ext_key_usage must not be empty: serverAuth for TLS servers")
	}
	for _, u := range c.Cert.ExtKeyUsage {
		if _, ok := extKeyUsages[u]; !ok {
			return fmt.Errorf("certificates: ext_key_usage: unknown %q (use serverAuth, clientAuth)", u)
		}
	}
	if len(c.Cert.Country) > 2 {
		return fmt.Errorf("certificates: country is a two-letter code, got %q", c.Cert.Country)
	}
	return nil
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// caConfigFile is the name of a CA's settings in its folder; caConfigOld
// is the one before v1.5.0, which is no longer read.
const (
	caConfigFile = "config.yaml"
	caConfigOld  = "config.toml"
)

// parseCAConfig reads a CA's config.yaml: ca and certificates, keys as in
// the main config file. Anything not given keeps its default.
func parseCAConfig(id, text string) (*caConfig, error) {
	c := defaultCAConfig(id)
	doc, err := parseYAML(text)
	if err != nil {
		return nil, err
	}
	sections, err := pairs(doc.Content[0], "the file")
	if err != nil {
		return nil, err
	}
	for _, sec := range sections {
		section := sec[0].Value
		if section != "ca" && section != "certificates" {
			return nil, fmt.Errorf("line %d: unknown section %q: use ca or certificates", sec[0].Line, section)
		}
		if sec[1].Tag == "!!null" {
			continue
		}
		items, err := pairs(sec[1], section)
		if err != nil {
			return nil, err
		}
		for _, it := range items {
			key := it[0].Value
			fail := func(format string, a ...any) error {
				return fmt.Errorf("line %d: %s", it[0].Line, fmt.Sprintf(format, a...))
			}
			value, err := yamlValue(key, it[1])
			if err != nil {
				return nil, err
			}
			num := func(dst *int) error {
				x, err := strconv.Atoi(value)
				if err != nil {
					return fail("%s: expected a number, got %q", key, value)
				}
				*dst = x
				return nil
			}
			list := func(dst *[]string) { *dst = splitList(value) }
			lower := strings.ToLower(value)
			switch section + "." + key {
			case "ca.common_name":
				c.CommonName = value
			case "ca.organization":
				c.Organization = value
			case "ca.key_algorithm":
				c.KeyAlgorithm = lower
			case "ca.key_bits":
				err = num(&c.KeyBits)
			case "ca.hash_algorithm":
				c.HashAlgorithm = lower
			case "ca.validity_days":
				err = num(&c.ValidityDays)
			case "certificates.key_algorithm":
				c.Cert.KeyAlgorithm = lower
			case "certificates.key_bits":
				err = num(&c.Cert.KeyBits)
			case "certificates.hash_algorithm":
				c.Cert.HashAlgorithm = lower
			case "certificates.validity_days":
				err = num(&c.Cert.ValidityDays)
			case "certificates.renew_before_days":
				err = num(&c.Cert.RenewBeforeDays)
			case "certificates.key_usage":
				list(&c.Cert.KeyUsage)
			case "certificates.ext_key_usage":
				list(&c.Cert.ExtKeyUsage)
			case "certificates.organization":
				c.Cert.Organization = value
			case "certificates.organizational_unit":
				c.Cert.OrganizationalUnit = value
			case "certificates.country":
				c.Cert.Country = strings.ToUpper(value)
			case "certificates.province":
				c.Cert.Province = value
			case "certificates.locality":
				c.Cert.Locality = value
			default:
				return nil, fail("unknown key %q in %s", key, section)
			}
			if err != nil {
				return nil, err
			}
		}
	}
	if err := c.check(); err != nil {
		return nil, err
	}
	return c, nil
}

// text writes c as a commented config.yaml.
func (c *caConfig) text() string {
	q := strconv.Quote
	list := func(items []string) string {
		var out []string
		for _, s := range items {
			out = append(out, s)
		}
		return "[" + strings.Join(out, ", ") + "]"
	}
	return fmt.Sprintf(`# Settings of this CA, read again whenever this file changes. A mistake keeps
# the previous settings; the console's CAs page and the log say what is wrong.

ca:
  # The CA itself. Name and key are set when the CA is made and kept afterwards:
  # a new key or name would break every certificate it issued.
  common_name: %s
  organization: %s
  key_algorithm: %s          # ecdsa, rsa or ed25519
  key_bits: %d               # ecdsa: 256, 384, 521; rsa: 2048, 3072, 4096; ed25519: ignored
  # Used when it renews its own certificate (same key, same name):
  hash_algorithm: %s         # sha256, sha384 or sha512
  validity_days: %d

certificates:
  # What it issues: one certificate per name, the name as its common name.
  # Changes apply to new certificates and renewals.
  key_algorithm: %s          # ecdsa, rsa or ed25519
  key_bits: %d
  hash_algorithm: %s         # the CA's signature on them: sha256, sha384 or sha512
  validity_days: %d
  renew_before_days: %d      # 0 = when a third of the lifetime is left
  key_usage: %s              # digitalSignature, keyEncipherment (RSA keys, old clients), keyAgreement, ...
  ext_key_usage: %s          # serverAuth, clientAuth
  organization: %s
  organizational_unit: %s
  country: %s                # two letters, e.g. SG
  province: %s
  locality: %s
`, q(c.CommonName), q(c.Organization), c.KeyAlgorithm, c.KeyBits, c.HashAlgorithm, c.ValidityDays,
		c.Cert.KeyAlgorithm, c.Cert.KeyBits, c.Cert.HashAlgorithm, c.Cert.ValidityDays, c.Cert.RenewBeforeDays,
		list(c.Cert.KeyUsage), list(c.Cert.ExtKeyUsage),
		q(c.Cert.Organization), q(c.Cert.OrganizationalUnit), q(c.Cert.Country), q(c.Cert.Province), q(c.Cert.Locality))
}

// summary is one line for the console: what the certificates look like.
func (c *caConfig) summary() string {
	key := strings.ToUpper(c.Cert.KeyAlgorithm)
	switch c.Cert.KeyAlgorithm {
	case "ecdsa":
		key += fmt.Sprintf(" P-%d", c.Cert.KeyBits)
	case "rsa":
		key += fmt.Sprintf(" %d", c.Cert.KeyBits)
	case "ed25519":
		key = "Ed25519"
	}
	return fmt.Sprintf("%s · %s · %d days · %s", key, strings.ToUpper(c.Cert.HashAlgorithm), c.Cert.ValidityDays, strings.Join(c.Cert.ExtKeyUsage, ", "))
}

func newKey(alg string, bits int) (crypto.Signer, error) {
	switch alg {
	case "rsa":
		return rsa.GenerateKey(rand.Reader, bits)
	case "ed25519":
		_, k, err := ed25519.GenerateKey(rand.Reader)
		return k, err
	}
	curve := map[int]elliptic.Curve{256: elliptic.P256(), 384: elliptic.P384(), 521: elliptic.P521()}[bits]
	return ecdsa.GenerateKey(curve, rand.Reader)
}

// signatureAlgorithm is how key signs with hash. Ed25519 has its own hash.
func signatureAlgorithm(key crypto.Signer, hash string) x509.SignatureAlgorithm {
	switch key.Public().(type) {
	case *rsa.PublicKey:
		return map[string]x509.SignatureAlgorithm{"sha256": x509.SHA256WithRSA, "sha384": x509.SHA384WithRSA, "sha512": x509.SHA512WithRSA}[hash]
	case *ecdsa.PublicKey:
		return map[string]x509.SignatureAlgorithm{"sha256": x509.ECDSAWithSHA256, "sha384": x509.ECDSAWithSHA384, "sha512": x509.ECDSAWithSHA512}[hash]
	}
	return x509.PureEd25519
}

// describeKey fills the ca key settings from an existing key (an imported CA).
func describeKey(c *caConfig, pub crypto.PublicKey) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		c.KeyAlgorithm, c.KeyBits = "rsa", k.N.BitLen()
	case *ecdsa.PublicKey:
		c.KeyAlgorithm, c.KeyBits = "ecdsa", k.Curve.Params().BitSize
	case ed25519.PublicKey:
		c.KeyAlgorithm, c.KeyBits = "ed25519", 0
	}
}

// loadConfig reads the CA's config.yaml when it changed since last time,
// writing the defaults if there is none. It keeps the previous settings when
// the file is broken, and remembers why. A config.toml from before v1.5.0
// is not read: it is reported until a config.yaml says the same.
func (l *localCA) loadConfig() {
	defer lockCA(l.dir)()
	path := filepath.Join(l.dir, caConfigFile)
	fi, err := os.Stat(path)
	if os.IsNotExist(err) {
		if _, old := os.Stat(filepath.Join(l.dir, caConfigOld)); old == nil {
			msg := fmt.Sprintf("%s is no longer read: write its settings as %s (YAML: ca: and certificates:, key: value; see the console's CAs page for the form)", filepath.Join(l.dir, caConfigOld), path)
			if cur := l.conf.Load(); cur == nil || cur.err != msg {
				errorf("cert: CA %s: %s; the defaults are in use", l.id, msg)
			}
			c := defaultCAConfig(l.id)
			if st := l.ca.Load(); st != nil {
				setCAFromCert(c, st.cert)
			}
			l.setConfig(c, msg, time.Time{})
			return
		}
		c := defaultCAConfig(l.id)
		if st := l.ca.Load(); st != nil {
			setCAFromCert(c, st.cert)
		}
		if err := writeFileAtomic0600(path, []byte(c.text())); err != nil {
			l.setConfig(c, fmt.Sprintf("cannot write %s: %v", path, err), time.Time{})
			return
		}
		fi, _ = os.Stat(path)
		l.setConfig(c, "", fi.ModTime())
		return
	}
	if err != nil {
		l.setConfig(nil, err.Error(), time.Time{})
		return
	}
	if cur := l.conf.Load(); cur != nil && cur.mtime.Equal(fi.ModTime()) {
		return // unchanged
	}
	data, err := os.ReadFile(path)
	if err == nil {
		var c *caConfig
		if c, err = l.parseConfig(string(data)); err == nil {
			if old := l.conf.Load(); old != nil && old.c != nil {
				logf("cert: CA %s: settings reloaded from %s: certificates are %s", l.id, path, c.summary())
			}
			l.setConfig(c, "", fi.ModTime())
			return
		}
	}
	errorf("cert: CA %s: %s: %v; the previous settings stay in use", l.id, path, err)
	l.setConfig(nil, err.Error(), fi.ModTime())
}

// setConfig publishes settings; nil c keeps the ones in use, with the error.
func (l *localCA) setConfig(c *caConfig, problem string, mtime time.Time) {
	if c == nil {
		if old := l.conf.Load(); old != nil {
			c = old.c
		}
	}
	if c == nil {
		c = defaultCAConfig(l.id)
	}
	l.conf.Store(&caConfigState{c: c, err: problem, mtime: mtime})
}

// parseConfig reads a config.yaml for this CA: valid, and with ca as the CA
// was made (that section describes the CA; it can't change it).
func (l *localCA) parseConfig(text string) (*caConfig, error) {
	c, err := parseCAConfig(l.id, text)
	if err != nil {
		return nil, err
	}
	st := l.ca.Load()
	if st == nil {
		return c, nil
	}
	made := *c
	setCAFromCert(&made, st.cert)
	ed := made.KeyAlgorithm == "ed25519"
	for _, f := range []struct {
		key        string
		have, want any
		skip       bool
	}{
		{"common_name", c.CommonName, made.CommonName, false},
		{"organization", c.Organization, made.Organization, false},
		{"key_algorithm", c.KeyAlgorithm, made.KeyAlgorithm, false},
		{"key_bits", c.KeyBits, made.KeyBits, ed},
		{"hash_algorithm", c.HashAlgorithm, made.HashAlgorithm, ed},
		{"validity_days", c.ValidityDays, made.ValidityDays, false},
	} {
		if !f.skip && f.have != f.want {
			return nil, fmt.Errorf("ca: %s is %v, but this CA was made with %v: the ca section describes the CA and can't change it (only certificates can be edited)", f.key, f.have, f.want)
		}
	}
	return c, nil
}

type caConfigState struct {
	c     *caConfig
	err   string // why the file on disk is not what is in use
	mtime time.Time
}

func (l *localCA) config() *caConfig {
	if s := l.conf.Load(); s != nil {
		return s.c
	}
	return defaultCAConfig(l.id)
}
