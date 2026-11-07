package main

// The console's Authentication page, OIDC section: the oidc items, the
// serve entries that use each, and changes to them through a wizard. A
// client secret typed here is written to a file of its own next to the
// config file (client_secret_file), never into the config file and never
// sent back. A client certificate is made here (an RSA key that stays on
// this machine and a self-signed certificate to give the provider) or
// uploaded; the certificate, which is public, is shown again on its card.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

type oidcProviderView struct {
	Name          string        `json:"name"`
	Line          int           `json:"line"`
	Issuer        string        `json:"issuer"`
	ClientID      string        `json:"clientId"`
	Auth          string        `json:"auth"` // secret (in the file), secret_file, certificate
	SecretFile    string        `json:"secretFile,omitempty"`
	CertFile      string        `json:"certFile,omitempty"`
	KeyFile       string        `json:"keyFile,omitempty"`
	CertExpires   string        `json:"certExpires,omitempty"` // RFC 3339
	CertPEM       string        `json:"certPem,omitempty"`     // to give the provider again
	Scopes        []string      `json:"scopes"`
	Session       string        `json:"session"`
	MFAAcr        []string      `json:"mfaAcr"`
	CAFile        string        `json:"caFile,omitempty"`
	UsernameClaim string        `json:"usernameClaim,omitempty"`
	GroupsClaim   string        `json:"groupsClaim"`
	RolesClaim    string        `json:"rolesClaim"`
	UsedBy        []authUseView `json:"usedBy"`
	RedirectURIs  []string      `json:"redirectUris"` // to register with the provider
}

// oidcProviderViews lists cfg's oidc items, by name.
func oidcProviderViews(cfg *Config) []oidcProviderView {
	out := []oidcProviderView{}
	if cfg == nil {
		return out
	}
	for _, name := range sortedKeys(cfg.OIDC) {
		p := cfg.OIDC[name]
		v := oidcProviderView{Name: name, Line: p.Line, Issuer: p.Issuer, ClientID: p.ClientID, Auth: "secret",
			Scopes: p.Scopes, Session: formatSession(p.Session), MFAAcr: append([]string{}, p.MFAAcr...), CAFile: p.CAFile,
			UsernameClaim: p.UserClaim, GroupsClaim: p.GroupsClaim, RolesClaim: p.RolesClaim, UsedBy: []authUseView{}, RedirectURIs: []string{}}
		switch {
		case p.CertFile != "":
			v.Auth, v.CertFile, v.KeyFile, v.CertExpires = "certificate", p.CertFile, p.KeyFile, p.CertExpires.UTC().Format(time.RFC3339)
			if b, err := os.ReadFile(p.CertFile); err == nil {
				if blk, _ := pem.Decode(b); blk != nil && blk.Type == "CERTIFICATE" {
					v.CertPEM = string(pem.EncodeToMemory(blk))
				}
			}
		case p.SecretFile != "":
			v.Auth, v.SecretFile = "secret_file", p.SecretFile
		}
		for _, r := range cfg.Rules {
			for _, s := range r.Routes {
				if s.OIDC != name {
					continue
				}
				v.UsedBy = append(v.UsedBy, authUseView{Rule: r.Source, Line: r.Line, Prefix: s.Prefix})
				if u := callbackFor(cfg, &r); u != "" && !slices.Contains(v.RedirectURIs, u) {
					v.RedirectURIs = append(v.RedirectURIs, u)
				}
			}
		}
		out = append(out, v)
	}
	return out
}

// callbackFor is the redirect URI a provider needs for rule r: its domain,
// with its listener's port unless 443, as browsers send it in Host. ""
// for a rule that matches more than one name.
func callbackFor(cfg *Config, r *Rule) string {
	if strings.ContainsAny(r.Source, "*$") {
		return ""
	}
	host := r.Source
	if l := cfg.Listener(r.Listener); l != nil && l.Port != 443 && l.Port != 0 {
		host = net.JoinHostPort(host, strconv.Itoa(l.Port))
	}
	return "https://" + host + oidcCallback
}

// callbackCandidates are the redirect URIs of every rule that serves HTTP
// here: what to register for a provider no serve entry uses yet.
func callbackCandidates(cfg *Config) []string {
	out := []string{}
	if cfg == nil {
		return out
	}
	for i := range cfg.Rules {
		r := &cfg.Rules[i]
		if u := callbackFor(cfg, r); len(r.Routes) > 0 && !r.Console && u != "" && !slices.Contains(out, u) {
			out = append(out, u)
		}
	}
	return out
}

// formatSession writes a session length as the file would: 8h, 90m.
func formatSession(d time.Duration) string {
	if d%time.Hour == 0 {
		return strconv.Itoa(int(d/time.Hour)) + "h"
	}
	return strconv.Itoa(int(d/time.Minute)) + "m"
}

// oidcDiscover reads an issuer's discovery document for the wizard, before
// anything is saved: what it supports, to fill in and check the next steps.
func (c *Console) oidcDiscover(w http.ResponseWriter, r *http.Request) {
	var req struct{ Issuer, CAFile string }
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		fail(w, 400, "bad request")
		return
	}
	issuer := strings.TrimSuffix(strings.TrimSpace(req.Issuer), "/")
	if err := checkIssuer(issuer); err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": "issuer: " + err.Error()})
		return
	}
	ca := strings.TrimSpace(req.CAFile)
	if ca != "" {
		if _, err := os.Stat(ca); err != nil {
			writeJSON(w, 200, map[string]any{"ok": false, "error": "ca_file: " + err.Error()})
			return
		}
	}
	client, err := (&oidcAuth{clients: map[string]*oidcClient{}}).client(&OIDCProvider{Issuer: issuer, CAFile: ca})
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	var doc map[string]any
	if err := client.getJSON(ctx, issuer+"/.well-known/openid-configuration", &doc); err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	strs := func(k string) []string {
		out := []string{}
		if list, ok := doc[k].([]any); ok {
			for _, v := range list {
				if s, ok := v.(string); ok {
					out = append(out, s)
				}
			}
		}
		return out
	}
	str := func(k string) string { s, _ := doc[k].(string); return s }
	if str("authorization_endpoint") == "" || str("token_endpoint") == "" || str("jwks_uri") == "" {
		writeJSON(w, 200, map[string]any{"ok": false, "error": "this is not an OpenID Connect discovery document: it lacks authorization_endpoint, token_endpoint or jwks_uri"})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "issuer": str("issuer"), "endSession": str("end_session_endpoint") != "",
		"authMethods": strs("token_endpoint_auth_methods_supported"), "acrValues": strs("acr_values_supported"),
		"scopes": strs("scopes_supported"), "claims": strs("claims_supported"), "pkce": strs("code_challenge_methods_supported")})
}

// oidcEdit is one change from the wizard or a card.
type oidcEdit struct {
	Op            string // add, update, delete
	Name          string // the item changed (update, delete), or the new one (add)
	NewName       string // update: its name from now on ("" = unchanged)
	Issuer        string
	ClientID      string
	Credential    string // secret, generate, upload, keep (update: as it is)
	Secret        string // secret: written to a file, never to the config file
	CertPEM       string // upload
	KeyPEM        string // upload
	Scopes        []string
	Session       string
	MFAAcr        []string
	CAFile        string
	UsernameClaim string
	GroupsClaim   string
	RolesClaim    string
}

// oidcSave makes one change to the oidc items, through the same checks as
// every other save. Files it writes (a secret, a certificate and key) are
// removed again if the change is not saved.
func (c *Console) oidcSave(w http.ResponseWriter, r *http.Request) {
	var req struct {
		oidcEdit
		BaseHash, BaseMtime string
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		fail(w, 400, "bad request")
		return
	}
	configFileMu.Lock()
	defer configFileMu.Unlock()
	onDisk, ver, err := c.readConfig()
	if err != nil {
		fail(w, 500, "%v", err)
		return
	}
	if req.BaseMtime != ver.Mtime || req.BaseHash != ver.Hash {
		fail(w, http.StatusConflict, "not saved: the config file changed after this page loaded it. The page now shows the current version; try again")
		return
	}
	// Absolute paths: the proxy may be started from another folder.
	configPath := c.srv.configPath
	if abs, err := filepath.Abs(configPath); err == nil {
		configPath = abs
	}
	dir := filepath.Join(filepath.Dir(configPath), "oidc")
	full, res, err := editOIDC(string(onDisk), req.oidcEdit, dir)
	if err == nil {
		var cfg *Config
		if cfg, err = c.check(full); err == nil {
			for _, n := range res.notes {
				logf("console: %s", n)
			}
			what := map[string]string{"add": "oidc %s added", "update": "oidc %s changed", "delete": "oidc %s deleted"}[req.Op]
			res.cleanup = nil // in use now
			res.forget()
			c.commitWith(w, r, onDisk, full, cfg, fmt.Sprintf(what, req.Name), map[string]any{"certPem": res.certPEM})
			return
		}
	}
	res.undo()
	writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
}

// oidcCheckOne checks one saved oidc item against its provider (see
// oidc_check.go).
func (c *Console) oidcCheckOne(w http.ResponseWriter, r *http.Request) {
	var req struct{ Name string }
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		fail(w, 400, "bad request")
		return
	}
	pf := c.configFile()
	if pf.cfg == nil || pf.cfg.OIDC[req.Name] == nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": "there is no oidc item " + req.Name + " in the config file; reload the page"})
		return
	}
	if !oidcCheckMu.TryLock() {
		writeJSON(w, 200, map[string]any{"ok": false, "error": "a check is already running; try again in a moment"})
		return
	}
	defer oidcCheckMu.Unlock()
	rep := checkOIDC(r.Context(), pf.cfg, pf.cfg.OIDC[req.Name])
	writeJSON(w, 200, map[string]any{"ok": true, "report": rep, "text": formatOIDCReports([]oidcReport{rep})})
}

// oidcEditResult is what editOIDC did besides the text: notes for the log,
// a certificate it made, and the files it wrote, to remove if the change is
// not saved.
type oidcEditResult struct {
	notes    []string
	certPEM  string
	cleanup  []string // written by this change: removed if it is not saved
	obsolete []string // made by an earlier change, in dir, and no longer used: removed once it is saved
}

// forget removes the files a saved change left unused.
func (r *oidcEditResult) forget() {
	for _, f := range r.obsolete {
		os.Remove(f)
	}
}

func (r *oidcEditResult) undo() {
	if r == nil {
		return
	}
	for _, f := range r.cleanup {
		os.Remove(f)
	}
}

// oidcItem finds the oidc item named name.
func (d *yamlDoc) oidcItem(name string) *yaml.Node {
	list := mapGet(d.root, "oidc")
	if list == nil || list.Kind != yaml.SequenceNode {
		return nil
	}
	for _, it := range list.Content {
		if n := mapGet(it, "name"); n != nil && n.Value == name {
			return it
		}
	}
	return nil
}

// oidcRefs are the oidc: values of the serve entries that name name.
func (d *yamlDoc) oidcRefs(name string) []*yaml.Node {
	var out []*yaml.Node
	routes := mapGet(d.root, "routes")
	if routes == nil {
		return nil
	}
	for _, g := range routes.Content {
		rs := mapGet(g, "rules")
		if rs == nil {
			continue
		}
		for _, r := range rs.Content {
			serve := mapGet(r, "serve")
			if serve == nil || serve.Kind != yaml.SequenceNode {
				continue
			}
			for _, e := range serve.Content {
				if v := mapGet(e, "oidc"); v != nil && v.Value == name {
					out = append(out, v)
				}
			}
		}
	}
	return out
}

// fileSlug is name as a file name: letters, digits and - only.
func fileSlug(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

// editOIDC applies one change to the oidc items. Secrets and certificates
// go to files in dir (made if need be), named after the item.
func editOIDC(text string, e oidcEdit, dir string) (string, *oidcEditResult, error) {
	res := &oidcEditResult{}
	d, err := loadDoc(text)
	if err != nil {
		return "", res, err
	}
	e.Name, e.NewName = strings.TrimSpace(e.Name), strings.TrimSpace(e.NewName)
	item := d.oidcItem(e.Name)
	switch {
	case e.Op == "add" && item != nil:
		return "", res, fmt.Errorf("there is already an oidc item %s", e.Name)
	case e.Op != "add" && item == nil:
		return "", res, fmt.Errorf("there is no oidc item %s any more; reload and try again", e.Name)
	}
	// The files the item uses now that this console made (in dir): if the
	// change replaces or deletes them, they go once it is saved.
	inDir := func(p string) bool { return filepath.Dir(filepath.Clean(p)) == filepath.Clean(dir) }
	var old []string
	if item != nil {
		for _, k := range []string{"client_secret_file", "client_certificate", "client_key"} {
			if v := mapGet(item, k); v != nil && inDir(v.Value) {
				old = append(old, v.Value)
			}
		}
	}
	if e.Op == "delete" {
		res.obsolete = old
		if refs := d.oidcRefs(e.Name); len(refs) > 0 {
			return "", res, fmt.Errorf("oidc %s is used by %d serve entr%s: change them first", e.Name, len(refs), map[bool]string{true: "y", false: "ies"}[len(refs) == 1])
		}
		list := mapGet(d.root, "oidc")
		list.Content = slices.DeleteFunc(list.Content, func(n *yaml.Node) bool { return n == item })
		if len(list.Content) == 0 { // the last one: the section goes too
			for i := 0; i+1 < len(d.root.Content); i += 2 {
				if d.root.Content[i].Value == "oidc" {
					d.root.Content = slices.Delete(d.root.Content, i, i+2)
					break
				}
			}
		}
		return d.String(), res, nil
	}

	name := e.Name
	if e.Op == "update" && e.NewName != "" && e.NewName != e.Name {
		if d.oidcItem(e.NewName) != nil {
			return "", res, fmt.Errorf("there is already an oidc item %s", e.NewName)
		}
		name = e.NewName
	}
	if !listenerName.MatchString(name) {
		return "", res, fmt.Errorf("the name must be 1-64 letters, digits, spaces or -_@#~()[]<>\"' (no space at either end)")
	}
	if strings.TrimSpace(e.ClientID) == "" {
		return "", res, fmt.Errorf("the client id is required")
	}

	// The credential: the keys it is written as.
	var cred [][2]string
	keep := func() error {
		if item == nil {
			return fmt.Errorf("choose how the proxy authenticates: a client secret or a certificate")
		}
		for _, k := range []string{"client_secret", "client_secret_file", "client_certificate", "client_key"} {
			if v := mapGet(item, k); v != nil {
				cred = append(cred, [2]string{k, v.Value})
			}
		}
		return nil
	}
	write := func(path string, data []byte) error {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		if err := writeFileAtomic(path, data); err != nil {
			return err
		}
		res.cleanup = append(res.cleanup, path)
		return os.Chmod(path, 0o600)
	}
	// A new file per change, so an unsaved change never overwrites the
	// files the running config uses.
	stamp := time.Now().UTC().Format("20060102T150405")
	base := filepath.Join(dir, fileSlug(name)+"-"+stamp)
	switch e.Credential {
	case "keep", "":
		if err := keep(); err != nil {
			return "", res, err
		}
	case "secret":
		if e.Secret == "" {
			return "", res, fmt.Errorf("the client secret must not be empty")
		}
		if err := write(base+".secret", []byte(e.Secret+"\n")); err != nil {
			return "", res, err
		}
		cred = [][2]string{{"client_secret_file", base + ".secret"}}
	case "generate":
		certPEM, keyPEM, err := newClientCert(name)
		if err != nil {
			return "", res, err
		}
		if err := write(base+".key", keyPEM); err != nil {
			return "", res, err
		}
		if err := write(base+".crt", certPEM); err != nil {
			return "", res, err
		}
		cred, res.certPEM = [][2]string{{"client_certificate", base + ".crt"}, {"client_key", base + ".key"}}, string(certPEM)
	case "upload":
		if !strings.Contains(e.CertPEM, "BEGIN CERTIFICATE") || !strings.Contains(e.KeyPEM, "PRIVATE KEY") {
			return "", res, fmt.Errorf("paste the certificate (BEGIN CERTIFICATE) and its private key (BEGIN ... PRIVATE KEY), PEM")
		}
		if err := write(base+".key", []byte(strings.TrimSpace(e.KeyPEM)+"\n")); err != nil {
			return "", res, err
		}
		if err := write(base+".crt", []byte(strings.TrimSpace(e.CertPEM)+"\n")); err != nil {
			return "", res, err
		}
		cred = [][2]string{{"client_certificate", base + ".crt"}, {"client_key", base + ".key"}}
	default:
		return "", res, fmt.Errorf("unknown credential %q", e.Credential)
	}

	// The item, written whole, in the order the reference lists its keys.
	m := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	set := func(k, v string, quote bool) {
		if v = strings.TrimSpace(v); v == "" {
			return
		}
		n := scalar(v)
		if quote {
			n.Style = yaml.DoubleQuotedStyle
		}
		m.Content = append(m.Content, scalar(k), n)
	}
	list := func(k string, vs []string) {
		seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Style: yaml.FlowStyle}
		for _, v := range vs {
			if v = strings.TrimSpace(v); v != "" {
				n := scalar(v)
				n.Style = yaml.DoubleQuotedStyle
				seq.Content = append(seq.Content, n)
			}
		}
		if len(seq.Content) > 0 {
			m.Content = append(m.Content, scalar(k), seq)
		}
	}
	set("name", name, false)
	set("issuer", e.Issuer, true)
	set("client_id", e.ClientID, true)
	for _, kv := range cred {
		set(kv[0], kv[1], true)
	}
	if !slices.Equal(e.Scopes, strings.Fields(oidcDefaultScopes)) {
		list("scopes", e.Scopes)
	}
	if s := strings.TrimSpace(e.Session); s != "" && s != formatSession(oidcDefaultSession) {
		set("session", s, false)
	}
	list("mfa_acr_values", e.MFAAcr)
	set("ca_file", e.CAFile, true)
	set("username_claim", e.UsernameClaim, true)
	if g := strings.TrimSpace(e.GroupsClaim); g != "groups" {
		set("groups_claim", g, true)
	}
	if r := strings.TrimSpace(e.RolesClaim); r != "roles" {
		set("roles_claim", r, true)
	}

	for _, f := range old {
		if !slices.ContainsFunc(cred, func(kv [2]string) bool { return kv[1] == f }) {
			res.obsolete = append(res.obsolete, f)
		}
	}
	if item == nil {
		sec := d.section("oidc")
		sec.Content = append(sec.Content, m)
	} else {
		*item = *m
		if name != e.Name {
			if refs := d.oidcRefs(e.Name); len(refs) > 0 {
				for _, r := range refs {
					r.Value = name
				}
				res.notes = append(res.notes, fmt.Sprintf("Renames it in %d serve entr%s: oidc: %s becomes oidc: %s", len(refs), map[bool]string{true: "y", false: "ies"}[len(refs) == 1], e.Name, name))
			}
		}
	}
	return d.String(), res, nil
}

// newClientCert makes an RSA key and a self-signed certificate for it, good
// for two years, to authenticate to a provider with private_key_jwt.
func newClientCert(name string) (certPEM, keyPEM []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "tlsproxy oidc " + name},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(2, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	pk, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	if len(der) == 0 {
		return nil, nil, errors.New("no certificate")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}), nil
}
