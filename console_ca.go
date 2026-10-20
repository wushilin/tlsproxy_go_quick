package main

// The console's CA page: the certificate authorities in ca_root (caNNN),
// made here (generated, or an existing one pasted in), downloaded for
// clients to trust, and deleted once no rule uses them. A CA's private key
// never leaves the proxy.

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type caView struct {
	ID          string `json:"id"`
	Name        string `json:"name"`             // the CA certificate's subject
	Issuer      string `json:"issuer,omitempty"` // for an intermediate: who issued it
	SelfSigned  bool   `json:"selfSigned"`
	KeyType     string `json:"keyType"`
	NotAfter    string `json:"notAfter"`
	DaysLeft    int    `json:"daysLeft"`
	Fingerprint string `json:"fingerprint"` // SHA-256 of the certificate
	Issued      int    `json:"issued"`      // certificate folders on disk
	Rules       []int  `json:"rules"`       // lines of the rules that use it
	Settings    string `json:"settings"`    // what the certificates it issues look like
	ConfigError string `json:"configError,omitempty"`
	Error       string `json:"error,omitempty"`
}

// caIDs lists the CA folders in root (caNNN), and the highest number used
// there or in its archive, so a deleted CA's id is never handed out again.
func caIDs(root string) (ids []string, highest int) {
	scan := func(dir string, archive bool) {
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			name := e.Name()
			if archive {
				name, _, _ = strings.Cut(name, "-")
			}
			if !e.IsDir() || !caIDPattern.MatchString(name) {
				continue
			}
			n, _ := strconv.Atoi(name[2:])
			highest = max(highest, n)
			if !archive {
				ids = append(ids, name)
			}
		}
	}
	scan(root, false)
	scan(filepath.Join(root, localArchiveName), true)
	sort.Strings(ids)
	return ids, highest
}

func keyType(k any) string {
	switch k := k.(type) {
	case *ecdsa.PublicKey:
		return "ECDSA " + k.Curve.Params().Name
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d", k.N.BitLen())
	case ed25519.PublicKey:
		return "Ed25519"
	}
	return fmt.Sprintf("%T", k)
}

func (c *Console) caList(w http.ResponseWriter, r *http.Request) {
	cfg := c.srv.runtime.Load().cfg
	ids, highest := caIDs(cfg.CARoot)
	out := []caView{}
	for _, id := range ids {
		v := caView{ID: id, Rules: []int{}}
		for i := range cfg.Rules {
			if cfg.Rules[i].LocalCA() == id {
				v.Rules = append(v.Rules, cfg.Rules[i].Line)
			}
		}
		dir := filepath.Join(cfg.CARoot, id)
		l := c.srv.certs.LocalCA(cfg, id)
		if l == nil {
			var err error
			if l, err = openLocalCA(id, dir, false); err != nil {
				v.Error = err.Error()
				out = append(out, v)
				continue
			}
		}
		st := l.ca.Load()
		sum := sha256.Sum256(st.cert.Raw)
		v.Name, v.SelfSigned = st.cert.Subject.CommonName, st.cert.CheckSignatureFrom(st.cert) == nil
		if !v.SelfSigned {
			v.Issuer = st.cert.Issuer.CommonName
		}
		v.KeyType = keyType(st.cert.PublicKey)
		v.NotAfter = st.cert.NotAfter.UTC().Format("2006-01-02")
		v.DaysLeft = int(time.Until(st.cert.NotAfter).Hours() / 24)
		v.Fingerprint = strings.ToUpper(hex.EncodeToString(sum[:]))
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if _, ok := localCAName(e.Name()); e.IsDir() && ok {
				v.Issued++
			}
		}
		l.loadConfig()
		v.Settings = l.config().summary()
		if s := l.conf.Load(); s != nil {
			v.ConfigError = s.err
		}
		out = append(out, v)
	}
	writeJSON(w, 200, map[string]any{"caRoot": cfg.CARoot, "cas": out, "next": fmt.Sprintf("ca%03d", highest+1)})
}

// nextCADir is where a new CA goes: the next unused caNNN.
func nextCADir(root string) (string, string, error) {
	_, highest := caIDs(root)
	if highest >= 999 {
		return "", "", fmt.Errorf("ca_root already has ca999")
	}
	id := fmt.Sprintf("ca%03d", highest+1)
	return id, filepath.Join(root, id), nil
}

func (c *Console) caGenerate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CommonName, Organization, KeyAlgorithm, HashAlgorithm string
		KeyBits, ValidityDays                                 int
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || strings.ContainsAny(req.CommonName+req.Organization, "\r\n") ||
		len(req.CommonName) > 64 || len(req.Organization) > 64 {
		fail(w, 400, "bad request")
		return
	}
	root := c.srv.runtime.Load().cfg.CARoot
	unlock := lockCARoot(root) // the id stays ours until the CA is written
	defer unlock()
	id, dir, err := nextCADir(root)
	if err != nil {
		fail(w, 500, "%v", err)
		return
	}
	conf := defaultCAConfig(id)
	if s := strings.TrimSpace(req.CommonName); s != "" {
		conf.CommonName = s
	}
	conf.Organization = strings.TrimSpace(req.Organization)
	if req.KeyAlgorithm != "" {
		conf.KeyAlgorithm, conf.KeyBits = strings.ToLower(req.KeyAlgorithm), req.KeyBits
	}
	if req.HashAlgorithm != "" {
		conf.HashAlgorithm = strings.ToLower(req.HashAlgorithm)
	}
	if req.ValidityDays > 0 {
		conf.ValidityDays = req.ValidityDays
	}
	if err := conf.check(); err != nil {
		fail(w, 400, "%v", err)
		return
	}
	if err := generateCA(dir, conf); err != nil {
		fail(w, 500, "%v", err)
		return
	}
	logf("console: CA %s generated in %s from %s", id, dir, r.RemoteAddr)
	writeJSON(w, 200, map[string]any{"ok": true, "id": id})
}

func (c *Console) caImport(w http.ResponseWriter, r *http.Request) {
	var req struct{ Cert, Key string }
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.Cert == "" || req.Key == "" {
		fail(w, 400, "paste both the certificate and the private key")
		return
	}
	root := c.srv.runtime.Load().cfg.CARoot
	unlock := lockCARoot(root)
	defer unlock()
	id, dir, err := nextCADir(root)
	if err != nil {
		fail(w, 500, "%v", err)
		return
	}
	ca, err := importCA(dir, []byte(req.Cert), []byte(req.Key))
	if err != nil {
		os.Remove(dir) // only if nothing was written into it
		fail(w, 400, "%v", err)
		return
	}
	logf("console: CA %s imported (%s, issued by %s) into %s from %s", id, ca.Subject.CommonName, ca.Issuer.CommonName, dir, r.RemoteAddr)
	writeJSON(w, 200, map[string]any{"ok": true, "id": id})
}

func (c *Console) caDelete(w http.ResponseWriter, r *http.Request) {
	var req struct{ ID string }
	if json.NewDecoder(r.Body).Decode(&req) != nil || !caIDPattern.MatchString(req.ID) {
		fail(w, 400, "bad request")
		return
	}
	cfg := c.srv.runtime.Load().cfg
	for i := range cfg.Rules {
		if cfg.Rules[i].LocalCA() == req.ID {
			fail(w, 409, "the rule at line %d uses %s: change that rule first", cfg.Rules[i].Line, req.ID)
			return
		}
	}
	dir := filepath.Join(cfg.CARoot, req.ID)
	unlock := lockCA(dir)
	defer unlock()
	to := filepath.Join(cfg.CARoot, localArchiveName, req.ID+"-"+time.Now().UTC().Format("20060102150405"))
	if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
		fail(w, 500, "%v", err)
		return
	}
	if err := os.Rename(dir, to); err != nil {
		fail(w, 500, "%v", err)
		return
	}
	c.srv.certs.localCAs.Delete(dir)
	logf("console: CA %s deleted from %s: moved to %s, removed after 14 days", req.ID, r.RemoteAddr, to)
	writeJSON(w, 200, map[string]any{"ok": true, "archived": to})
}

// caFor is the CA with id, open in the proxy if a rule uses it.
func (c *Console) caFor(id string) (*localCA, error) {
	cfg := c.srv.runtime.Load().cfg
	if l := c.srv.certs.LocalCA(cfg, id); l != nil {
		return l, nil
	}
	return openLocalCA(id, filepath.Join(cfg.CARoot, id), false)
}

// caConfigGet is a CA's config.toml, as on disk.
func (c *Console) caConfigGet(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if !caIDPattern.MatchString(id) {
		fail(w, 400, "bad request")
		return
	}
	l, err := c.caFor(id)
	if err != nil {
		fail(w, 404, "%v", err)
		return
	}
	l.loadConfig()
	data, err := os.ReadFile(filepath.Join(l.dir, "config.toml"))
	if err != nil {
		fail(w, 500, "%v", err)
		return
	}
	st := l.conf.Load()
	writeJSON(w, 200, map[string]any{"text": string(data), "path": filepath.Join(l.dir, "config.toml"), "error": st.err, "settings": st.c.summary()})
}

// caConfigSave checks and writes a CA's config.toml. Only [certificates]
// may differ from what the CA was made with.
func (c *Console) caConfigSave(w http.ResponseWriter, r *http.Request) {
	var req struct{ ID, Text string }
	if json.NewDecoder(r.Body).Decode(&req) != nil || !caIDPattern.MatchString(req.ID) {
		fail(w, 400, "bad request")
		return
	}
	l, err := c.caFor(req.ID)
	if err != nil {
		fail(w, 404, "%v", err)
		return
	}
	conf, err := l.parseConfig(req.Text)
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error(), "line": lineOf(err.Error())})
		return
	}
	path := filepath.Join(l.dir, "config.toml")
	unlock := lockCA(l.dir)
	err = writeFileAtomic0600(path, []byte(req.Text))
	unlock()
	if err != nil {
		fail(w, 500, "%v", err)
		return
	}
	l.loadConfig()
	logf("console: CA %s settings saved from %s: certificates are %s", req.ID, r.RemoteAddr, conf.summary())
	writeJSON(w, 200, map[string]any{"ok": true, "settings": conf.summary()})
}

// caCert serves a CA's certificate (never its key), for clients to trust.
func (c *Console) caCert(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if !caIDPattern.MatchString(id) {
		fail(w, 400, "bad request")
		return
	}
	data, err := os.ReadFile(filepath.Join(c.srv.runtime.Load().cfg.CARoot, id, "ca_cert.pem"))
	if err != nil {
		fail(w, 404, "no CA %s", id)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="tlsproxy-`+id+`.pem"`)
	w.Write(data)
}
