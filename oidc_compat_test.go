package main

// Signing in with a real rust-oidc (github.com/wushilin/rust-oidc), run
// when RUST_OIDC_BIN names its binary:
//
//	RUST_OIDC_BIN=~/workspace/rust-oidc/target/release/rust-oidc go test -run TestOIDCRustOIDC -v
//
// The test makes a tenant, an application with assignment required, users
// and an app role with the binary's CLI, serves it on a free port, and
// signs in through its own pages as a browser would, MFA set-up included.

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestOIDCRustOIDC(t *testing.T) {
	bin := os.Getenv("RUST_OIDC_BIN")
	if bin == "" {
		t.Skip("RUST_OIDC_BIN is not set")
	}
	dir := t.TempDir()
	db := "sqlite://" + filepath.Join(dir, "db.sqlite") + "?mode=rwc"
	run := func(args ...string) map[string]any {
		t.Helper()
		cmd := exec.Command(bin, args...)
		cmd.Env = append(os.Environ(), "RUST_OIDC_DATABASE="+db)
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("rust-oidc %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		var v map[string]any
		json.Unmarshal(out, &v)
		return v
	}
	const tenant = "contoso.test"
	run("bootstrap", "--domain", "root.test", "--admin-upn", "admin@root.test", "--password", "Adm1n-Passw0rd!")
	run("tenant", "create", "--name", "Contoso", "--domain", tenant)
	app, _ := run("app", "create", "--tenant", tenant, "--name", "tlsproxy")["appId"].(string)
	if app == "" {
		t.Fatal("app create gave no appId")
	}
	run("app", "add-redirect-uri", "--tenant", tenant, "--app", app, "--platform", "web", "--uri", "https://www.test/.tlsproxy/oidc/callback")
	run("app", "add-redirect-uri", "--tenant", tenant, "--app", app, "--platform", "web", "--uri", "https://cert.test/.tlsproxy/oidc/callback")
	run("app", "assignment-required", "--tenant", tenant, "--app", app, "--required", "true")
	secret, _ := run("app", "secret", "add", "--tenant", tenant, "--app", app)["secretText"].(string)
	// The same app may sign in with a certificate (private_key_jwt) instead.
	_, certPath, keyPath := clientCertFiles(t, time.Now().Add(365*24*time.Hour))
	run("app", "key", "add", "--tenant", tenant, "--app", app, "--cert", certPath, "--name", "tlsproxy")
	for _, role := range []string{"Admin", "Member"} {
		run("app", "role", "add", "--tenant", tenant, "--app", app, "--value", role, "--member-types", "User")
	}
	users := map[string]string{"alice": "Al1ce-Passw0rd!", "bob": "B0b-Passw0rd!xx", "carol": "C4rol-Passw0rd!"}
	for u, pw := range users {
		run("user", "create", "--tenant", tenant, "--upn", u+"@"+tenant, "--email", u+"@"+tenant, "--password", pw)
	}
	run("group", "create", "--tenant", tenant, "--name", "ops")
	run("group", "add-member", "--tenant", tenant, "--group", "ops", "--user", "alice@"+tenant)
	run("app", "role", "assign", "--tenant", tenant, "--resource", app, "--role", "Admin", "--user", "alice@"+tenant)
	run("app", "role", "assign", "--tenant", tenant, "--resource", app, "--role", "Member", "--user", "bob@"+tenant)
	// carol is not assigned.

	port := freePort(t)
	base := fmt.Sprintf("http://127.0.0.1:%d/rust-oidc", port)
	serve := exec.Command(bin, "serve", "--bind", fmt.Sprintf("127.0.0.1:%d", port), "--public-url", base)
	serve.Env = append(os.Environ(), "RUST_OIDC_DATABASE="+db)
	serve.Dir = dir
	logFile, _ := os.Create(filepath.Join(dir, "serve.log"))
	serve.Stdout, serve.Stderr = logFile, logFile
	if err := serve.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		serve.Process.Kill()
		serve.Wait()
		if t.Failed() {
			b, _ := os.ReadFile(filepath.Join(dir, "serve.log"))
			t.Logf("rust-oidc log:\n%s", b)
		}
	})
	issuer := base + "/" + tenant + "/v2.0"
	for deadline := time.Now().Add(15 * time.Second); ; {
		resp, err := http.Get(issuer + "/.well-known/openid-configuration")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("rust-oidc did not start: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}

	// The check (tlsproxy --test-oidc) against it: a good secret, the
	// certificate, a wrong secret.
	checkCfg, err := ParseConfig(fmt.Sprintf(`listeners:
  - {name: a, port: 1}
oidc:
  - {name: corp, issuer: "%[1]s", client_id: "%[2]s", client_secret: "%[3]s", mfa_acr_values: ["2"]}
  - {name: corpcert, issuer: "%[1]s", client_id: "%[2]s", client_certificate: "%[4]s", client_key: "%[5]s"}
  - {name: wrong, issuer: "%[1]s", client_id: "%[2]s", client_secret: "not-the-secret"}
`, issuer, app, secret, certPath, keyPath))
	if err != nil {
		t.Fatal(err)
	}
	reports, err := checkOIDCConfig(context.Background(), checkCfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range reports {
		text := formatOIDCReports([]oidcReport{r})
		if r.OK != (r.Name != "wrong") || r.Name == "wrong" && !strings.Contains(text, "FAIL client credentials") || strings.Contains(text, "WARN") {
			t.Errorf("check of %s against rust-oidc:\n%s", r.Name, text)
		}
		t.Logf("\n%s", text)
	}

	ca := newTestCA(t)
	backend := identityEcho(t)
	p := startProxyText(t, fmt.Sprintf(`global:
  stats_interval: 0
listeners:
  - {name: default, port: 1}
routes:
  - listener: default
    rules:
      - domain: www.test
        cert: %[1]s
        serve:
          - {type: reverse_proxy, prefix: /, target: "http://127.0.0.1:%[2]d", oidc: corp}
          - {type: reverse_proxy, prefix: /admin/, target: "http://127.0.0.1:%[2]d", oidc: corp, require_roles: [Admin]}
          - {type: reverse_proxy, prefix: /ops/, target: "http://127.0.0.1:%[2]d", oidc: corp, require_groups: [ops]}
          - {type: reverse_proxy, prefix: /secure/, target: "http://127.0.0.1:%[2]d", oidc: corp, require_mfa: true}
      - domain: cert.test
        cert: %[1]s
        serve:
          - {type: reverse_proxy, prefix: /, target: "http://127.0.0.1:%[2]d", oidc: corpcert, require_groups: [ops], require_roles: [Admin]}
oidc:
  - {name: corp, issuer: "%[3]s", client_id: "%[4]s", client_secret: "%[5]s", mfa_acr_values: ["2"]}
  - {name: corpcert, issuer: "%[3]s", client_id: "%[4]s", client_certificate: "%[6]s", client_key: "%[7]s"}
`, ca.localCA(t), backend, issuer, app, secret, certPath, keyPath), "")
	nav := []string{"Accept", "text/html", "Sec-Fetch-Mode", "navigate"}
	newBrowser := func() *oidcBrowser {
		b := &oidcBrowser{proxy: serveClient(p, ca, false), idp: &http.Client{Timeout: T, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
		b.proxy.Jar, _ = cookiejar.New(nil)
		b.idp.Jar, _ = cookiejar.New(nil)
		return b
	}
	// visit opens a page through the proxy, signing in at rust-oidc as user
	// when sent there: the last response and its body.
	visitURL := func(b *oidcBrowser, u, user string) (*http.Response, string) {
		t.Helper()
		resp, body := httpsGet(t, b.proxy, u, nav...)
		for step := 0; resp.StatusCode == 302 && step < 12; step++ {
			loc := resp.Header.Get("Location")
			if u, err := resp.Request.URL.Parse(loc); err == nil {
				loc = u.String()
			}
			if strings.HasPrefix(loc, "https://www.test/") || strings.HasPrefix(loc, "https://cert.test/") {
				resp, body = httpsGet(t, b.proxy, loc, nav...)
				continue
			}
			resp, body = b.idpGet(t, loc)
			for page := 0; resp.StatusCode == 200 && page < 6; page++ {
				resp, body = b.submit(t, resp, body, user+"@"+tenant, users[user])
			}
		}
		return resp, body
	}
	visit := func(b *oidcBrowser, path, user string) (*http.Response, string) {
		t.Helper()
		return visitURL(b, "https://www.test"+path, user)
	}

	// alice: assigned with the Admin role, in ops.
	alice := newBrowser()
	resp, body := visit(alice, "/hello", "alice")
	if resp.StatusCode != 200 || !strings.Contains(body, "user=alice@"+tenant) || !strings.Contains(body, "groups=ops") || !strings.Contains(body, "roles=Admin") || !strings.Contains(body, "mfa=false") {
		t.Fatalf("alice: %d %s", resp.StatusCode, body)
	}
	for _, path := range []string{"/admin/", "/ops/"} {
		if resp, body := visit(alice, path, "alice"); resp.StatusCode != 200 {
			t.Errorf("alice %s: %d %s", path, resp.StatusCode, body)
		}
	}
	// MFA: a step-up (acr_values=2) sets up her authenticator at rust-oidc.
	if resp, body := visit(alice, "/secure/", "alice"); resp.StatusCode != 200 || !strings.Contains(body, "mfa=true") {
		t.Errorf("alice /secure/ after step-up: %d %s", resp.StatusCode, body)
	}
	if alice.totp == "" {
		t.Error("the step-up did not go through MFA set-up")
	}

	// With the certificate: alice is still signed in at rust-oidc, so only
	// the token endpoint is new (private_key_jwt); groups and roles together.
	if resp, body := visitURL(alice, "https://cert.test/", "alice"); resp.StatusCode != 200 || !strings.Contains(body, "user=alice@"+tenant) || !strings.Contains(body, "groups=ops") {
		t.Errorf("alice with the certificate: %d %s", resp.StatusCode, body)
	}

	// bob: assigned, but not Admin, not in ops.
	bob := newBrowser()
	if resp, body := visit(bob, "/", "bob"); resp.StatusCode != 200 || !strings.Contains(body, "user=bob@"+tenant) || !strings.Contains(body, "roles=Member") {
		t.Errorf("bob: %d %s", resp.StatusCode, body)
	}
	for _, path := range []string{"/admin/", "/ops/"} {
		if resp, _ := visit(bob, path, "bob"); resp.StatusCode != 403 {
			t.Errorf("bob %s: %d, want 403", path, resp.StatusCode)
		}
	}
	if resp, _ := visitURL(bob, "https://cert.test/", "bob"); resp.StatusCode != 403 {
		t.Errorf("bob with the certificate: %d, want 403", resp.StatusCode)
	}

	// carol: not assigned. rust-oidc refuses her (AADSTS50105), on its own
	// page or back at the callback.
	resp, body = visit(newBrowser(), "/", "carol")
	if resp.StatusCode == 200 && strings.Contains(body, "user=carol") || !strings.Contains(body, "AADSTS50105") {
		t.Errorf("carol: %d %s", resp.StatusCode, body)
	}

	// Logout: rust-oidc's end-session sends the browser back to the callback.
	resp, _ = httpsGet(t, alice.proxy, "https://www.test/.tlsproxy/oidc/logout", nav...)
	if resp.StatusCode != 302 || !strings.HasPrefix(resp.Header.Get("Location"), base) {
		t.Fatalf("logout: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp, _ = alice.idpGet(t, resp.Header.Get("Location"))
	if loc := resp.Header.Get("Location"); resp.StatusCode != 302 || !strings.HasPrefix(loc, "https://www.test/.tlsproxy/oidc/callback") {
		t.Errorf("rust-oidc after logout: %d %s", resp.StatusCode, loc)
	} else if resp, body := httpsGet(t, alice.proxy, loc, nav...); resp.StatusCode != 200 || !strings.Contains(body, "signed out") {
		t.Errorf("signed out page: %d %s", resp.StatusCode, body)
	}
}

// oidcBrowser is a browser for TestOIDCRustOIDC: its cookies at the proxy
// and at rust-oidc, and the authenticator it set up there.
type oidcBrowser struct {
	proxy, idp *http.Client
	totp       string
	step       int64 // the last time step a code was sent for: rust-oidc takes each step once
}

// idpGet is a GET at rust-oidc.
func (b *oidcBrowser) idpGet(t *testing.T, u string) (*http.Response, string) {
	t.Helper()
	resp, err := b.idp.Get(u)
	if err != nil {
		t.Fatalf("GET %s: %v", u, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

var (
	formRe     = regexp.MustCompile(`(?s)<form[^>]*action="([^"]*)"[^>]*>(.*?)</form>`)
	inputRe    = regexp.MustCompile(`<(?:input|button)\b[^>]*>`)
	attrRe     = regexp.MustCompile(`\b(name|value|type)="([^"]*)"`)
	continueRe = regexp.MustCompile(`<a class="button" href="([^"]*)"`)
	tagRe      = regexp.MustCompile(`<[^>]*>`)
	secretRe   = regexp.MustCompile(`enter this key:\s*([A-Z2-7]{4}(?: [A-Z2-7]{1,4})+)`)
)

// submit fills in the form on a rust-oidc page as a person would: the user
// name and password, an authenticator code (setting the authenticator up
// first if the page offers its secret), consent. The response to it.
func (b *oidcBrowser) submit(t *testing.T, resp *http.Response, body, upn, password string) (*http.Response, string) {
	t.Helper()
	m := formRe.FindStringSubmatch(body)
	if m == nil {
		if c := continueRe.FindStringSubmatch(body); c != nil { // "Continue" after setting up the authenticator
			return b.idpGet(t, html.UnescapeString(c[1]))
		}
		return &http.Response{StatusCode: -resp.StatusCode, Header: resp.Header}, body // a page without a form: an error page
	}
	if s := secretRe.FindStringSubmatch(html.UnescapeString(tagRe.ReplaceAllString(body, " "))); s != nil {
		b.totp = strings.ReplaceAll(s[1], " ", "")
	}
	form := url.Values{}
	var buttons [][2]string
	for _, tag := range inputRe.FindAllString(m[2], -1) {
		attrs := map[string]string{}
		for _, a := range attrRe.FindAllStringSubmatch(tag, -1) {
			attrs[a[1]] = html.UnescapeString(a[2])
		}
		name := attrs["name"]
		switch {
		case name == "":
		case strings.HasPrefix(tag, "<button"):
			buttons = append(buttons, [2]string{name, attrs["value"]})
		case name == "upn":
			form.Set(name, upn)
		case name == "password":
			form.Set(name, password)
		case name == "code" || attrs["type"] == "text" && strings.Contains(tag, "one-time-code"):
			if b.totp == "" {
				t.Fatalf("rust-oidc asks for a code, and no authenticator is set up:\n%s", body)
			}
			// The next code, as a person would wait for, within the
			// step either side of now that rust-oidc allows.
			b.step = max(b.step+1, time.Now().Unix()/30)
			form.Set(name, totpCode(t, b.totp, b.step))
		default:
			form.Set(name, attrs["value"])
		}
	}
	for _, btn := range buttons { // consent: accept
		if btn[1] == "consent_accept" || form.Get(btn[0]) == "" {
			form.Set(btn[0], btn[1])
		}
	}
	action := html.UnescapeString(m[1])
	if u, err := resp.Request.URL.Parse(action); err == nil {
		action = u.String()
	}
	r, err := b.idp.PostForm(action, form)
	if err != nil {
		t.Fatalf("POST %s: %v", action, err)
	}
	defer r.Body.Close()
	out, _ := io.ReadAll(r.Body)
	return r, string(out)
}

// totpCode is RFC 6238's code for a base32 secret and a 30 s time step:
// SHA-1, 6 digits.
func totpCode(t *testing.T, secret string, step int64) string {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.TrimRight(secret, "="))
	if err != nil {
		t.Fatalf("authenticator secret %q: %v", secret, err)
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0xf
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[off:])&0x7fffffff)%1000000)
}
