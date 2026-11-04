package main

// The oidc section: identity providers that serve entries can ask a browser
// to sign in with (OpenID Connect, the authorization code flow with PKCE).
// The provider does the signing in, its second factor and who may use the
// application; a serve entry may then require more of whoever signed in.
//
//	oidc:
//	  - name: corp
//	    issuer: https://id.example.com/rust-oidc/example.com/v2.0
//	    client_id: 0b6f...
//	    client_secret_file: /etc/tlsproxy/corp.secret   # or client_certificate + client_key
//	    mfa_acr_values: "2"
//	routes:
//	  - listener: https
//	    rules:
//	      - domain: www.example.com
//	        cert: auto
//	        serve:
//	          - {type: reverse_proxy, prefix: /, target: "http://127.0.0.1:8080", oidc: corp}
//	          - {type: reverse_proxy, prefix: /admin/, target: "http://127.0.0.1:8080", oidc: corp,
//	             require_mfa: true, require_roles: [Admin]}
//
// The provider's application needs https://<each domain>/.tlsproxy/oidc/callback
// as a web redirect URI (see oidc.go).

import (
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// OIDCProvider is one oidc item.
type OIDCProvider struct {
	Name         string
	Line         int
	Issuer       string    // its discovery document is Issuer + /.well-known/openid-configuration
	ClientID     string    // the application's client id
	ClientSecret string    // from client_secret or client_secret_file
	SecretFile   string    // client_secret_file, as written
	CertFile     string    // client_certificate: authenticate with private_key_jwt instead of a secret
	KeyFile      string    // client_key, its RSA private key
	CertExpires  time.Time // the certificate's notAfter
	clientKey    *rsa.PrivateKey
	thumbprint   string        // base64url(SHA-1(certificate DER)): the assertion's x5t and kid
	Scopes       []string      // asked for; openid is always among them
	Session      time.Duration // how long a sign-in lasts here
	MFAAcr       []string      // mfa_acr_values: asked for to step up to MFA, and also accepted as MFA in acr
	CAFile       string        // extra root CA for the provider's HTTPS
	UserClaim    string        // the claim that names the user; "" = preferred_username, email, upn, sub
	GroupsClaim  string        // where the groups are: a claim name, or a dotted path into nested claims
	RolesClaim   string        // where the roles are, the same way
	// referenced are the groups and roles some serve entry requires, which a
	// session keeps when the provider sends too many to fit in a cookie.
	referenced map[string]bool
}

const (
	oidcDefaultSession = 8 * time.Hour
	oidcDefaultScopes  = "openid profile email"
)

// walkOIDC reads one oidc item.
func walkOIDC(item *yaml.Node) (*OIDCProvider, error) {
	p := &OIDCProvider{Line: item.Line, Session: oidcDefaultSession, Scopes: strings.Fields(oidcDefaultScopes), GroupsClaim: "groups", RolesClaim: "roles"}
	items, err := pairs(item, "an oidc item")
	if err != nil {
		return nil, err
	}
	var secretPlain bool
	for _, it := range items {
		k, line := it[0].Value, it[0].Line
		v, err := yamlValue(k, it[1])
		if err != nil {
			return nil, err
		}
		v = strings.TrimSpace(v)
		fail := func(format string, a ...any) error {
			return fmt.Errorf("line %d: oidc: %s", line, fmt.Sprintf(format, a...))
		}
		switch k {
		case "name":
			if p.Name = v; !listenerName.MatchString(v) {
				return nil, fail("name must be 1-64 letters, digits, spaces or -_@#~()[]<>\"' (no space at either end), got %q", v)
			}
		case "issuer":
			if err := checkIssuer(v); err != nil {
				return nil, fail("issuer: %v", err)
			}
			p.Issuer = strings.TrimSuffix(v, "/")
		case "client_id":
			if p.ClientID = v; v == "" {
				return nil, fail("client_id must not be empty")
			}
		case "client_secret":
			p.ClientSecret, secretPlain = v, true
		case "client_secret_file":
			if v == "" {
				return nil, fail("client_secret_file must not be empty")
			}
			b, err := os.ReadFile(v)
			if err != nil {
				return nil, fail("client_secret_file: %v", err)
			}
			if p.ClientSecret = strings.TrimSpace(string(b)); p.ClientSecret == "" {
				return nil, fail("client_secret_file %s is empty", v)
			}
			p.SecretFile = v
		case "scopes":
			p.Scopes = nil
			for _, s := range strings.FieldsFunc(v, func(r rune) bool { return r == ';' || r == ' ' || r == ',' }) {
				if s != "openid" {
					p.Scopes = append(p.Scopes, s)
				}
			}
			p.Scopes = append([]string{"openid"}, p.Scopes...)
		case "session":
			d, err := time.ParseDuration(v)
			if err != nil || d < time.Minute || d > 30*24*time.Hour {
				return nil, fail("session must be a duration from 1m to 720h, e.g. 8h or 90m, got %q", v)
			}
			p.Session = d
		case "mfa_acr_values":
			p.MFAAcr = splitList(v)
		case "ca_file":
			if v == "" {
				return nil, fail("ca_file must not be empty")
			}
			if _, err := os.Stat(v); err != nil {
				return nil, fail("ca_file: %v", err)
			}
			p.CAFile = v
		case "username_claim":
			p.UserClaim = v
		case "groups_claim", "roles_claim":
			if v == "" {
				return nil, fail("%s must not be empty", k)
			}
			if k == "groups_claim" {
				p.GroupsClaim = v
			} else {
				p.RolesClaim = v
			}
		case "client_certificate":
			if p.CertFile = v; v == "" {
				return nil, fail("client_certificate must not be empty")
			}
		case "client_key":
			if p.KeyFile = v; v == "" {
				return nil, fail("client_key must not be empty")
			}
		default:
			return nil, fail("unknown key %q (name, issuer, client_id, client_secret, client_secret_file, client_certificate, client_key, scopes, session, mfa_acr_values, ca_file, username_claim, groups_claim, roles_claim)", k)
		}
	}
	switch {
	case p.Name == "":
		return nil, fmt.Errorf("oidc at line %d: name is required", p.Line)
	case p.Issuer == "":
		return nil, fmt.Errorf("oidc at line %d (%s): issuer is required, e.g. https://id.example.com/rust-oidc/example.com/v2.0", p.Line, p.Name)
	case p.ClientID == "":
		return nil, fmt.Errorf("oidc at line %d (%s): client_id is required", p.Line, p.Name)
	case p.ClientSecret == "" && p.CertFile == "" && p.KeyFile == "":
		return nil, fmt.Errorf("oidc at line %d (%s): client_secret, client_secret_file, or client_certificate with client_key is required: the proxy is a confidential (web) client", p.Line, p.Name)
	case secretPlain && p.SecretFile != "":
		return nil, fmt.Errorf("oidc at line %d (%s): give client_secret or client_secret_file, not both", p.Line, p.Name)
	case p.ClientSecret != "" && (p.CertFile != "" || p.KeyFile != ""):
		return nil, fmt.Errorf("oidc at line %d (%s): give a client secret or a client certificate, not both", p.Line, p.Name)
	case (p.CertFile == "") != (p.KeyFile == ""):
		return nil, fmt.Errorf("oidc at line %d (%s): client_certificate and client_key go together", p.Line, p.Name)
	}
	if p.CertFile != "" {
		if err := p.loadClientCert(); err != nil {
			return nil, fmt.Errorf("oidc at line %d (%s): %v", p.Line, p.Name, err)
		}
	}
	return p, nil
}

// loadClientCert reads client_certificate and client_key: an RSA key (PKCS
// #1 or #8, PEM) that is the certificate's. The provider holds the
// certificate (rust-oidc: app key add --cert; Entra: Certificates & secrets)
// and checks private_key_jwt assertions with it, found by its thumbprint.
func (p *OIDCProvider) loadClientCert() error {
	certPEM, err := os.ReadFile(p.CertFile)
	if err != nil {
		return fmt.Errorf("client_certificate: %v", err)
	}
	var cert *x509.Certificate
	for rest := certPEM; ; {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			break
		}
		if b.Type == "CERTIFICATE" {
			if cert, err = x509.ParseCertificate(b.Bytes); err != nil {
				return fmt.Errorf("client_certificate %s: %v", p.CertFile, err)
			}
			break
		}
	}
	if cert == nil {
		return fmt.Errorf("client_certificate %s holds no PEM certificate", p.CertFile)
	}
	keyPEM, err := os.ReadFile(p.KeyFile)
	if err != nil {
		return fmt.Errorf("client_key: %v", err)
	}
	var key any
	for rest := keyPEM; key == nil; {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			break
		}
		switch b.Type {
		case "RSA PRIVATE KEY":
			key, err = x509.ParsePKCS1PrivateKey(b.Bytes)
		case "PRIVATE KEY":
			key, err = x509.ParsePKCS8PrivateKey(b.Bytes)
		}
		if err != nil {
			return fmt.Errorf("client_key %s: %v", p.KeyFile, err)
		}
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	switch {
	case key == nil:
		return fmt.Errorf("client_key %s holds no PEM private key (unencrypted PKCS #1 or #8)", p.KeyFile)
	case !ok:
		return fmt.Errorf("client_key %s is not an RSA key: private_key_jwt is signed RS256", p.KeyFile)
	case !rsaKey.PublicKey.Equal(cert.PublicKey):
		return fmt.Errorf("client_key %s is not the key of client_certificate %s", p.KeyFile, p.CertFile)
	}
	sum := sha1.Sum(cert.Raw)
	p.clientKey, p.thumbprint, p.CertExpires = rsaKey, base64.RawURLEncoding.EncodeToString(sum[:]), cert.NotAfter
	return nil
}

// checkIssuer accepts https://host/path, and http:// only to this machine
// (a provider under test).
func checkIssuer(v string) error {
	u, err := url.Parse(v)
	switch {
	case err != nil:
		return err
	case u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "":
		return fmt.Errorf("%q must be a URL like https://id.example.com/path, without user, query or fragment", v)
	case u.Scheme == "https":
		return nil
	case u.Scheme == "http":
		host := u.Hostname()
		if ip := net.ParseIP(host); host == "localhost" || ip != nil && ip.IsLoopback() {
			return nil
		}
		return fmt.Errorf("%q: http:// only to this machine (localhost); use https://", v)
	}
	return fmt.Errorf("%q must start with https://", v)
}

// resolveOIDC checks the oidc items and the serve entries that name them.
func (c *Config) resolveOIDC(providers []*OIDCProvider) error {
	c.OIDC = map[string]*OIDCProvider{}
	for _, p := range providers {
		if prev := c.OIDC[p.Name]; prev != nil {
			return fmt.Errorf("oidc at line %d: the name %s is already used at line %d", p.Line, p.Name, prev.Line)
		}
		p.referenced = map[string]bool{}
		c.OIDC[p.Name] = p
	}
	used := map[string]bool{}
	for i := range c.Rules {
		r := &c.Rules[i]
		for _, s := range r.Routes {
			if s.OIDC == "" {
				continue
			}
			if s.oidc = c.OIDC[s.OIDC]; s.oidc == nil {
				return fmt.Errorf("rule at line %d: %s: oidc: %s: there is no oidc item named %s", r.Line, s.Key, s.OIDC, s.OIDC)
			}
			used[s.OIDC] = true
			for _, g := range s.RequireGroups {
				s.oidc.referenced["g:"+g] = true
			}
			for _, g := range s.RequireRoles {
				s.oidc.referenced["r:"+g] = true
			}
		}
	}
	for name, p := range c.OIDC {
		if p.CertFile != "" && time.Until(p.CertExpires) < 30*24*time.Hour {
			c.Warnings = append(c.Warnings, fmt.Sprintf("oidc %s at line %d: client_certificate %s expires %s; the provider refuses an expired one", name, p.Line, p.CertFile, p.CertExpires.UTC().Format(time.DateOnly)))
		}
		if !used[name] {
			c.Warnings = append(c.Warnings, fmt.Sprintf("oidc %s at line %d is not used by any serve entry", name, p.Line))
		}
	}
	return nil
}
