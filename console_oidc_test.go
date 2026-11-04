package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The Authentication page's OIDC section, through its API: discover, add
// with a secret, check, rename and switch to a generated certificate, keep
// it through another change, delete. Secrets never reach the config file or
// the page; files the console made and no longer needs are removed.
func TestConsoleOIDCPage(t *testing.T) {
	t.Parallel()
	idp := newFakeIdP(t)
	_, c, path := startConsoleProxy(t, "password = pw", "[[host]]\nlistener=default\npattern=www.test\naction=deny\n")
	if c.login("pw") != 200 {
		t.Fatal("sign-in")
	}
	dir := filepath.Join(filepath.Dir(path), "oidc")
	files := func() []string {
		entries, _ := os.ReadDir(dir)
		var out []string
		for _, e := range entries {
			out = append(out, e.Name())
		}
		return out
	}
	version := func() (any, any) {
		_, list := c.get("/api/auth")
		f := list["file"].(map[string]any)
		return f["hash"], f["mtime"]
	}
	save := func(change map[string]any) map[string]any {
		t.Helper()
		change["baseHash"], change["baseMtime"] = version()
		_, out := c.post("/api/auth/oidc/save", change)
		return out
	}

	// Discover what the provider supports, before anything is saved.
	_, d := c.post("/api/auth/oidc/discover", map[string]any{"issuer": idp.issuerURL() + "/"})
	if d["ok"] != true || d["issuer"] != idp.issuerURL() || !strings.Contains(fmt.Sprint(d["authMethods"]), "client_secret_basic") {
		t.Fatalf("discover: %v", d)
	}
	if _, d := c.post("/api/auth/oidc/discover", map[string]any{"issuer": "http://evil.test/x"}); d["ok"] == true {
		t.Error("an http:// issuer elsewhere is refused")
	}

	// A refused change leaves no file behind.
	if out := save(map[string]any{"op": "add", "name": "bad one", "issuer": idp.issuerURL(), "clientId": "app", "credential": "secret", "secret": "s3cret", "session": "10s"}); out["ok"] == true {
		t.Fatalf("a bad session is refused: %v", out)
	}
	if f := files(); len(f) != 0 {
		t.Errorf("files left by a refused change: %v", f)
	}

	// Add, with a secret: written to a file of its own, mode 0600.
	out := save(map[string]any{"op": "add", "name": "corp", "issuer": idp.issuerURL(), "clientId": "app", "credential": "secret", "secret": "s3cret",
		"scopes": []string{"openid", "profile", "email"}, "session": "8h", "mfaAcr": []string{"2"}, "groupsClaim": "groups", "rolesClaim": "realm_access.roles"})
	if out["ok"] != true {
		t.Fatalf("add: %v", out)
	}
	text, _ := os.ReadFile(path)
	if strings.Contains(string(text), "s3cret") || !strings.Contains(string(text), "client_secret_file:") || !strings.Contains(string(text), `roles_claim: "realm_access.roles"`) ||
		strings.Contains(string(text), "scopes:") || strings.Contains(string(text), "session:") || strings.Contains(string(text), "groups_claim") {
		t.Errorf("written as:\n%s", text)
	}
	secretFiles := files()
	if len(secretFiles) != 1 || !strings.HasSuffix(secretFiles[0], ".secret") {
		t.Fatalf("files: %v", secretFiles)
	}
	if st, _ := os.Stat(filepath.Join(dir, secretFiles[0])); st.Mode().Perm() != 0o600 {
		t.Errorf("secret file mode %v", st.Mode().Perm())
	}
	_, list := c.get("/api/auth")
	if strings.Contains(fmt.Sprint(list), "s3cret") {
		t.Fatal("the secret is sent to the page")
	}
	p := list["oidc"].([]any)[0].(map[string]any)
	if p["name"] != "corp" || p["auth"] != "secret_file" || p["session"] != "8h" || fmt.Sprint(p["mfaAcr"]) != "[2]" || p["rolesClaim"] != "realm_access.roles" {
		t.Errorf("listed as: %v", p)
	}

	// Check it against the provider.
	_, chk := c.post("/api/auth/oidc/check", map[string]any{"name": "corp"})
	if chk["ok"] != true || chk["report"].(map[string]any)["ok"] != true || !strings.Contains(chk["text"].(string), "client credentials (client_secret_basic): accepted") {
		t.Errorf("check: %v", chk)
	}

	// Rename, and authenticate with a certificate made here instead: the
	// secret file goes, the certificate comes back to be registered.
	out = save(map[string]any{"op": "update", "name": "corp", "newName": "corp two", "issuer": idp.issuerURL(), "clientId": "app", "credential": "generate",
		"scopes": []string{"openid"}, "session": "90m"})
	if out["ok"] != true || !strings.Contains(fmt.Sprint(out["certPem"]), "BEGIN CERTIFICATE") {
		t.Fatalf("update with a new certificate: %v", out)
	}
	f := strings.Join(files(), " ")
	if strings.Contains(f, ".secret") || !strings.Contains(f, ".crt") || !strings.Contains(f, ".key") {
		t.Errorf("files after switching to a certificate: %s", f)
	}
	_, list = c.get("/api/auth")
	p = list["oidc"].([]any)[0].(map[string]any)
	if p["name"] != "corp two" || p["auth"] != "certificate" || !strings.Contains(fmt.Sprint(p["certPem"]), "BEGIN CERTIFICATE") || p["certExpires"] == "" || p["session"] != "90m" {
		t.Errorf("listed as: %v", p)
	}
	if strings.Contains(fmt.Sprint(list), "PRIVATE KEY") {
		t.Fatal("the private key is sent to the page")
	}

	// A change that keeps the credential keeps its files.
	before := files()
	if out := save(map[string]any{"op": "update", "name": "corp two", "issuer": idp.issuerURL(), "clientId": "app", "credential": "keep", "session": "2h"}); out["ok"] != true {
		t.Fatalf("keep: %v", out)
	}
	if after := files(); strings.Join(after, " ") != strings.Join(before, " ") {
		t.Errorf("files changed: %v -> %v", before, after)
	}

	// Delete: its files and the section go.
	if out := save(map[string]any{"op": "delete", "name": "corp two"}); out["ok"] != true {
		t.Fatalf("delete: %v", out)
	}
	text, _ = os.ReadFile(path)
	if f := files(); len(f) != 0 || strings.Contains(string(text), "oidc") {
		t.Errorf("after delete: files %v\n%s", f, text)
	}
}

// Renaming an oidc item renames it in its serve entries; one in use can't
// be deleted.
func TestEditOIDCRefs(t *testing.T) {
	text := `listeners:
  - {name: a, port: 1}
routes:
  - listener: a
    rules:
      - domain: x.test
        cert: local-ca
        serve:
          - {type: reverse_proxy, prefix: /, target: "http://127.0.0.1:1", oidc: corp}
oidc:
  - {name: corp, issuer: "https://id.test/x", client_id: app, client_secret: s}
`
	dir := t.TempDir()
	if _, _, err := editOIDC(text, oidcEdit{Op: "delete", Name: "corp"}, dir); err == nil || !strings.Contains(err.Error(), "used by 1 serve entry") {
		t.Errorf("delete in use: %v", err)
	}
	full, res, err := editOIDC(text, oidcEdit{Op: "update", Name: "corp", NewName: "main", Issuer: "https://id.test/x", ClientID: "app", Credential: "keep"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(full, "oidc: main}") || !strings.Contains(full, "name: main") || !strings.Contains(full, `client_secret: "s"`) || len(res.notes) != 1 {
		t.Errorf("renamed:\n%s\n%v", full, res.notes)
	}
	if _, err := ParseConfig(full); err != nil {
		t.Errorf("does not load: %v\n%s", err, full)
	}
	if _, _, err := editOIDC(text, oidcEdit{Op: "add", Name: "corp", Issuer: "https://id.test/x", ClientID: "app", Credential: "secret", Secret: "x"}, dir); err == nil {
		t.Error("a name given twice is refused")
	}
}

// The rule editor's Generate: a secret in a file named after the entry,
// mode 0600, good for identity_secret_file; again, the same file, a new
// secret.
func TestConsoleIdentitySecret(t *testing.T) {
	t.Parallel()
	_, c, path := startConsoleProxy(t, "password = pw", "[[host]]\nlistener=default\npattern=www.test\naction=deny\n")
	if c.login("pw") != 200 {
		t.Fatal("sign-in")
	}
	_, a := c.post("/api/auth/identity-secret", map[string]any{"domain": "home.example.com", "prefix": "/rest/"})
	if a["ok"] != true || filepath.Dir(a["path"].(string)) != filepath.Join(filepath.Dir(path), "identity") || len(a["secret"].(string)) < identityMinSecret {
		t.Fatalf("generate: %v", a)
	}
	st, err := os.Stat(a["path"].(string))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("file: %v %v", st, err)
	}
	if s, err := readIdentitySecret(a["path"].(string)); err != nil || string(s) != a["secret"] {
		t.Errorf("read back: %q %v", s, err)
	}
	_, b := c.post("/api/auth/identity-secret", map[string]any{"domain": "home.example.com", "prefix": "/rest/"})
	if b["path"] != a["path"] || b["secret"] == a["secret"] {
		t.Errorf("again: %v, then %v", a, b)
	}
	entries, _ := os.ReadDir(filepath.Dir(a["path"].(string)))
	if len(entries) != 1 {
		t.Errorf("%d files", len(entries))
	}
	if _, d := c.post("/api/auth/identity-secret", map[string]any{"domain": "", "prefix": ""}); d["ok"] == true {
		t.Error("no domain, no prefix: refused")
	}
}
