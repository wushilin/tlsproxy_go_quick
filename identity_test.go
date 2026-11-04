package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// verifyHS256 checks an X-OIDC-Assertion as a target would, and returns its
// claims.
func verifyHS256(t *testing.T, token string, secret string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", token)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	if base64.RawURLEncoding.EncodeToString(mac.Sum(nil)) != parts[2] {
		t.Fatalf("signature does not verify with the secret")
	}
	var header map[string]string
	h, _ := base64.RawURLEncoding.DecodeString(parts[0])
	json.Unmarshal(h, &header)
	if header["alg"] != "HS256" {
		t.Errorf("alg %q", header["alg"])
	}
	var claims map[string]any
	b, _ := base64.RawURLEncoding.DecodeString(parts[1])
	json.Unmarshal(b, &claims)
	return claims
}

func writeSecret(t *testing.T, s string) string {
	p := filepath.Join(t.TempDir(), "identity.key")
	os.WriteFile(p, []byte("# for the rest API\n"+s+"\n"), 0o600)
	return p
}

func TestIdentityConfig(t *testing.T) {
	good := writeSecret(t, strings.Repeat("k", 40))
	short := writeSecret(t, "tooshort")
	head := "listeners:\n  - {name: a, port: 1}\nroutes:\n  - listener: a\n    rules:\n      - {domain: x.test, cert: local-ca, serve: [%s]}\nbasic_auth:\n  - {name: team, users: [{username: jack, password_plain: pw}]}\n"
	cfg, err := ParseConfig(fmt.Sprintf(head, `{type: reverse_proxy, prefix: /, target: "http://127.0.0.1:1", basic_auth: team, identity_secret_file: `+good+`}`))
	if err != nil {
		t.Fatal(err)
	}
	if r := cfg.Rules[0].Routes[0]; string(r.identitySecret) != strings.Repeat("k", 40) || r.IdentitySecretFile != good {
		t.Errorf("secret: %q", r.identitySecret)
	}
	for entry, want := range map[string]string{
		`{type: reverse_proxy, prefix: /, target: "http://127.0.0.1:1", basic_auth: team, identity_secret_file: ` + short + `}`:    "at least 32 characters",
		`{type: reverse_proxy, prefix: /, target: "http://127.0.0.1:1", basic_auth: team, identity_secret_file: /nonexistent/key}`: "identity_secret_file: open", // each system words the rest its own way
		`{type: reverse_proxy, prefix: /, target: "http://127.0.0.1:1", identity_secret_file: ` + good + `}`:                       "needs oidc: <name> or basic_auth",
		`{type: static_content, prefix: /, base_dir: /tmp, basic_auth: team, identity_secret_file: ` + good + `}`:                  "only applies to type: reverse_proxy",
	} {
		if _, err := ParseConfig(fmt.Sprintf(head, entry)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want %q", entry, err, want)
		}
	}
}

// assertionEcho answers with the X-OIDC-Assertion it got and the path.
func assertionEcho(t *testing.T) int {
	l, port := listen(t)
	go http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s %s", r.URL.Path, r.Header.Get("X-OIDC-Assertion"))
	}))
	return port
}

// A signed identity reaches the target, for basic_auth and for oidc; one a
// client sends never does.
func TestIdentityAssertion(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	idp := newFakeIdP(t)
	backend := assertionEcho(t)
	secret := strings.Repeat("s3cret-", 6)
	key := writeSecret(t, secret)
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
          - {type: reverse_proxy, prefix: /open/, target: "http://127.0.0.1:%[2]d"}
          - {type: reverse_proxy, prefix: /rest/, target: "http://127.0.0.1:%[2]d", strip_prefix: true, basic_auth: team, identity_secret_file: %[3]s}
          - {type: reverse_proxy, prefix: /app/, target: "http://127.0.0.1:%[2]d", oidc: corp, identity_secret_file: %[3]s}
          - {type: reverse_proxy, prefix: /plain/, target: "http://127.0.0.1:%[2]d", oidc: corp}
basic_auth:
  - {name: team, users: [{username: jack, password_plain: pw}]}
oidc:
  - {name: corp, issuer: "%[4]s", client_id: app, client_secret: s3cret, mfa_acr_values: ["2"]}
`, ca.localCA(t), backend, key, idp.issuerURL()), "")
	forged := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJyb290In0."
	c := serveClient(p, ca, false)

	// No sign-in, no signing: what a client sends is removed.
	if _, body := httpsGet(t, c, "https://www.test/open/x", "X-OIDC-Assertion", forged); body != "/open/x " {
		t.Errorf("open route: %q", body)
	}

	// basic_auth: sub is the user; htu is the path the target gets.
	before := time.Now().Unix()
	req, _ := http.NewRequest("GET", "https://www.test/rest/items?q=1", nil)
	req.SetBasicAuth("jack", "pw")
	req.Header.Set("X-OIDC-Assertion", forged)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var body strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		body.Write(buf[:n])
		if err != nil {
			break
		}
	}
	resp.Body.Close()
	path, token, _ := strings.Cut(body.String(), " ")
	cl := verifyHS256(t, token, secret)
	num := func(k string) int64 { f, _ := cl[k].(float64); return int64(f) }
	if path != "/items" || cl["sub"] != "jack" || cl["aud"] != "www.test/rest/" || cl["auth"] != "basic_auth:team" || cl["iss"] != "tlsproxy" ||
		cl["htm"] != "GET" || cl["htu"] != "/items" || cl["ip"] != "127.0.0.1" || num("exp")-num("iat") != 60 || num("iat") < before || cl["jti"] == "" {
		t.Errorf("basic_auth assertion: %s %v", path, cl)
	}
	if _, has := cl["groups"]; has {
		t.Errorf("basic_auth has no groups: %v", cl)
	}
	// Each request its own: a fresh jti.
	req2, _ := http.NewRequest("GET", "https://www.test/rest/items", nil)
	req2.SetBasicAuth("jack", "pw")
	if r2, err := c.Do(req2); err == nil {
		b := make([]byte, 4096)
		n, _ := r2.Body.Read(b)
		r2.Body.Close()
		_, t2, _ := strings.Cut(string(b[:n]), " ")
		if verifyHS256(t, t2, secret)["jti"] == cl["jti"] {
			t.Error("the same jti twice")
		}
	}

	// oidc: who signed in, with groups, roles and MFA.
	browser := serveClient(p, ca, false)
	browser.Jar, _ = cookiejar.New(nil)
	nav := []string{"Accept", "text/html", "Sec-Fetch-Mode", "navigate"}
	resp, _ = httpsGet(t, browser, "https://www.test/app/", nav...)
	httpsGet(t, browser, idp.signIn(resp.Header.Get("Location"), map[string]any{"sub": "u1", "preferred_username": "alice", "email": "alice@x.test", "groups": []string{"ops"}, "roles": []string{"Admin"}, "amr": []string{"pwd", "mfa"}}), nav...)
	_, b := httpsGet(t, browser, "https://www.test/app/page", append(nav, "X-OIDC-Assertion", forged)...)
	path, token, _ = strings.Cut(b, " ")
	cl = verifyHS256(t, token, secret)
	if path != "/app/page" || cl["sub"] != "alice" || cl["email"] != "alice@x.test" || cl["auth"] != "oidc:corp" || cl["mfa"] != true ||
		fmt.Sprint(cl["groups"]) != "[ops]" || fmt.Sprint(cl["roles"]) != "[Admin]" || cl["aud"] != "www.test/app/" || cl["htu"] != "/app/page" {
		t.Errorf("oidc assertion: %s %v", path, cl)
	}
	// The same session on an entry without a secret: nothing signed, and the
	// forged one is gone.
	if _, b := httpsGet(t, browser, "https://www.test/plain/x", append(nav, "X-OIDC-Assertion", forged)...); b != "/plain/x " {
		t.Errorf("unsigned oidc route: %q", b)
	}
	if len(token) > 1500 {
		t.Errorf("assertion is %d bytes", len(token))
	}
}
