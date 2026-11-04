package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestOIDCConfig(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(secret, []byte("s3cret\n"), 0o600)
	head := "listeners:\n  - {name: a, port: 1}\n"
	serve := func(entry string) string {
		return head + "routes:\n  - listener: a\n    rules:\n      - {domain: x.test, cert: local-ca, serve: [" + entry + "]}\n"
	}
	idp := "oidc:\n  - {name: corp, issuer: \"https://id.test/t/v2.0/\", client_id: app, client_secret_file: " + secret + ", mfa_acr_values: [\"2\"], session: 90m}\n"
	cfg, err := ParseConfig(serve("{type: reverse_proxy, prefix: /, target: \"http://127.0.0.1:1\", oidc: corp, require_mfa: true, require_roles: [Admin, Owner], require_groups: ops}") + idp)
	if err != nil {
		t.Fatal(err)
	}
	p, route := cfg.OIDC["corp"], cfg.Rules[0].Routes[0]
	if p.Issuer != "https://id.test/t/v2.0" || p.ClientSecret != "s3cret" || p.Session != 90*time.Minute || strings.Join(p.Scopes, " ") != "openid profile email" || len(p.MFAAcr) != 1 {
		t.Errorf("provider: %+v", p)
	}
	if route.oidc != p || !route.RequireMFA || strings.Join(route.RequireRoles, ",") != "Admin,Owner" || strings.Join(route.RequireGroups, ",") != "ops" || !p.referenced["r:Owner"] || !p.referenced["g:ops"] {
		t.Errorf("route: %+v", route)
	}
	if d := route.Describe(); d != "/ → http://127.0.0.1:1 (oidc corp, mfa, group ops, role Admin or Owner)" {
		t.Errorf("describe: %s", d)
	}
	bad := map[string]string{
		serve("{type: reverse_proxy, prefix: /, target: \"http://127.0.0.1:1\", oidc: nope}") + idp:                                                                                  "no oidc item named nope",
		serve("{type: reverse_proxy, prefix: /, target: \"http://127.0.0.1:1\", require_mfa: true}"):                                                                                 "require_mfa needs oidc",
		serve("{type: reverse_proxy, prefix: /, target: \"http://127.0.0.1:1\", oidc: corp, basic_auth: team}") + idp:                                                                "not both",
		head + "oidc:\n  - {name: a, issuer: \"http://id.test/x\", client_id: c, client_secret: s}\n":                                                                                "only to this machine",
		head + "oidc:\n  - {name: a, issuer: \"https://id.test/x\", client_id: c}\n":                                                                                                 "or client_certificate with client_key is required",
		head + "oidc:\n  - {name: a, issuer: \"https://id.test/x\", client_id: c, client_secret: s, session: 10s}\n":                                                                 "session must be",
		head + "oidc:\n  - {name: a, issuer: \"https://id.test/x\", client_id: c, client_secret: s, colour: red}\n":                                                                  "unknown key",
		head + "oidc:\n  - {name: a, issuer: \"https://id.test/x\", client_id: c, client_secret: s}\n  - {name: a, issuer: \"https://id.test/y\", client_id: c, client_secret: s}\n": "already used",
	}
	for text, want := range bad {
		if _, err := ParseConfig(text); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s\n  got %v, want %q", text, err, want)
		}
	}
	if _, err := ParseConfig(head + "oidc:\n  - {name: a, issuer: \"http://127.0.0.1:9/x\", client_id: c, client_secret: s}\n"); err != nil {
		t.Errorf("http:// to this machine: %v", err)
	}

	// A client certificate instead of a secret: its key must be its own,
	// and RSA.
	cert, certPath, keyPath := clientCertFiles(t, time.Now().Add(365*24*time.Hour))
	_, _, otherKey := clientCertFiles(t, time.Now().Add(365*24*time.Hour))
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecDER, _ := x509.MarshalPKCS8PrivateKey(ec)
	ecKey := filepath.Join(t.TempDir(), "ec.key")
	os.WriteFile(ecKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecDER}), 0o600)
	certItem := func(extra string) string {
		return head + "oidc:\n  - {name: a, issuer: \"https://id.test/x\", client_id: c" + extra + "}\n"
	}
	cfg, err = ParseConfig(certItem(", client_certificate: " + certPath + ", client_key: " + keyPath))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha1.Sum(cert.Raw)
	if p := cfg.OIDC["a"]; p.clientKey == nil || p.thumbprint != base64.RawURLEncoding.EncodeToString(sum[:]) || !p.CertExpires.Equal(cert.NotAfter) {
		t.Errorf("client certificate: %+v", p)
	}
	for extra, want := range map[string]string{
		", client_certificate: " + certPath + ", client_key: " + otherKey:                       "is not the key of client_certificate",
		", client_certificate: " + certPath + ", client_key: " + ecKey:                          "not an RSA key",
		", client_certificate: " + certPath:                                                     "go together",
		", client_certificate: " + certPath + ", client_key: " + keyPath + ", client_secret: s": "not both",
		", client_certificate: " + keyPath + ", client_key: " + keyPath:                         "holds no PEM certificate",
		", client_certificate: /nonexistent, client_key: " + keyPath:                            "client_certificate: open",
	} {
		if _, err := ParseConfig(certItem(extra)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want %q", extra, err, want)
		}
	}
	// One about to expire loads, with a warning.
	_, soonCert, soonKey := clientCertFiles(t, time.Now().Add(7*24*time.Hour))
	cfg, err = ParseConfig(serve("{type: reverse_proxy, prefix: /, target: \"http://127.0.0.1:1\", oidc: a}") + strings.TrimPrefix(certItem(", client_certificate: "+soonCert+", client_key: "+soonKey), head))
	if err != nil || !strings.Contains(strings.Join(cfg.Warnings, "\n"), "expires") {
		t.Errorf("a certificate about to expire: %v %v", err, cfg)
	}
}

// fakeIdP is an OpenID provider for tests: it signs in whoever next is,
// and checks what a client must do at its token endpoint.
type fakeIdP struct {
	t      *testing.T
	srv    *httptest.Server
	opts   fakeOpts
	mu     sync.Mutex
	key    *rsa.PrivateKey // signs ID tokens, as kid
	kid    string
	codes  map[string]url.Values // code -> the authorize request
	next   map[string]any        // claims of the next sign-in
	jtis   map[string]bool       // client assertions seen
	issuer string                // what tokens say; "" = the server's URL
	noMFA  atomic.Bool           // ignore acr_values: sign in without MFA when asked for it
	last   url.Values            // the last authorize request
	auth   string                // how the client authenticated last: basic, post or private_key_jwt
}

// fakeOpts is how a fakeIdP differs from the default: plain HTTP,
// client_secret_basic or _post with client "app" and secret "s3cret".
type fakeOpts struct {
	tls        bool              // HTTPS, with httptest's own certificate
	methods    []string          // token_endpoint_auth_methods_supported; nil = post and basic
	clientCert *x509.Certificate // accept private_key_jwt signed with its key (and nothing else)
}

func newFakeIdP(t *testing.T) *fakeIdP { return newFakeIdPWith(t, fakeOpts{}) }

func newFakeIdPWith(t *testing.T, opts fakeOpts) *fakeIdP {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	f := &fakeIdP{t: t, opts: opts, key: key, kid: "k1", codes: map[string]url.Values{}, jtis: map[string]bool{}}
	if opts.methods == nil {
		opts.methods = []string{"client_secret_post", "client_secret_basic"}
	}
	mux := http.NewServeMux()
	if opts.tls {
		f.srv = httptest.NewTLSServer(mux)
	} else {
		f.srv = httptest.NewServer(mux)
	}
	t.Cleanup(f.srv.Close)
	base := f.srv.URL + "/tenant/v2.0"
	mux.HandleFunc("/tenant/v2.0/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"issuer": base, "authorization_endpoint": f.srv.URL + "/authorize",
			"token_endpoint": f.srv.URL + "/token", "jwks_uri": f.srv.URL + "/keys", "end_session_endpoint": f.srv.URL + "/logout",
			"token_endpoint_auth_methods_supported": opts.methods})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		enc := base64.RawURLEncoding.EncodeToString
		f.mu.Lock()
		key, kid := f.key, f.kid
		f.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{"kty": "RSA", "use": "sig", "kid": kid,
			"n": enc(key.N.Bytes()), "e": enc(big.NewInt(int64(key.E)).Bytes())}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		fail := func(code string, why ...string) {
			if len(why) == 0 { // fail(why): a grant refused
				code, why = "invalid_grant", []string{code}
			}
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": why[0]})
		}
		if why := f.clientAuth(r); why != "" { // checked first, as RFC 6749 says
			w.WriteHeader(401)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client", "error_description": why})
			return
		}
		if r.Form.Get("grant_type") == "client_credentials" { // after the client, as rust-oidc does
			fail("invalid_scope", "no such resource: "+r.Form.Get("scope"))
			return
		}
		f.mu.Lock()
		req := f.codes[r.Form.Get("code")]
		delete(f.codes, r.Form.Get("code"))
		claims, key, kid := f.next, f.key, f.kid
		f.mu.Unlock()
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		switch {
		case req == nil:
			fail("unknown code")
		case r.Form.Get("redirect_uri") != req.Get("redirect_uri"):
			fail("redirect_uri")
		case base64.RawURLEncoding.EncodeToString(sum[:]) != req.Get("code_challenge") || req.Get("code_challenge_method") != "S256":
			fail("PKCE")
		default:
			now := time.Now().Unix()
			iss := f.issuer
			if iss == "" {
				iss = base
			}
			c := map[string]any{"iss": iss, "aud": "app", "iat": now, "exp": now + 3600, "nonce": req.Get("nonce")}
			for k, v := range claims {
				c[k] = v
			}
			if req.Get("acr_values") == "2" && !f.noMFA.Load() {
				c["amr"], c["acr"] = []string{"pwd", "mfa"}, "2"
			}
			json.NewEncoder(w).Encode(map[string]string{"id_token": signRS256(key, kid, c), "token_type": "Bearer"})
		}
	})
	return f
}

// clientAuth checks how the client authenticated at the token endpoint:
// "" if right, else why not.
func (f *fakeIdP) clientAuth(r *http.Request) string {
	allowed := func(m string) bool {
		return f.opts.methods == nil && m != "private_key_jwt" || slices.Contains(f.opts.methods, m)
	}
	id, secret, basic := r.BasicAuth()
	how := "basic"
	switch {
	case r.Form.Get("client_assertion") != "":
		how = "private_key_jwt"
	case r.Form.Has("client_secret"):
		how, id, secret = "post", r.Form.Get("client_id"), r.Form.Get("client_secret")
	case !basic:
		return "none"
	}
	f.mu.Lock()
	f.auth = how
	f.mu.Unlock()
	if !allowed("client_secret_"+how) && !allowed(how) {
		return how + " is not offered"
	}
	if how != "private_key_jwt" {
		if id != "app" || secret != "s3cret" || f.opts.clientCert != nil {
			return "wrong client or secret"
		}
		return ""
	}
	if f.opts.clientCert == nil || basic || r.Form.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		return "unexpected assertion"
	}
	tok := r.Form.Get("client_assertion")
	parts := strings.Split(tok, ".")
	var header struct{ X5t string }
	if len(parts) == 3 {
		hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
		json.Unmarshal(hb, &header)
	}
	sum := sha1.Sum(f.opts.clientCert.Raw)
	if header.X5t != base64.RawURLEncoding.EncodeToString(sum[:]) {
		return "x5t is not the certificate's thumbprint"
	}
	c, err := verifyJWT(tok, func(string) (crypto.PublicKey, error) { return f.opts.clientCert.PublicKey, nil })
	if err != nil {
		return err.Error()
	}
	exp, _ := c["exp"].(json.Number).Int64()
	jti, _ := c["jti"].(string)
	f.mu.Lock()
	replay := f.jtis[jti]
	f.jtis[jti] = true
	f.mu.Unlock()
	switch {
	case c["iss"] != "app" || c["sub"] != "app":
		return "iss and sub must be the client id"
	case c["aud"] != f.srv.URL+"/token":
		return fmt.Sprintf("aud %v is not the token endpoint", c["aud"])
	case exp <= time.Now().Unix() || exp > time.Now().Add(10*time.Minute).Unix():
		return "exp"
	case jti == "" || replay:
		return "jti missing or used before"
	}
	return ""
}

// rotate replaces the provider's signing key, with a new kid.
func (f *fakeIdP) rotate() {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	f.mu.Lock()
	f.key, f.kid = key, f.kid+"x"
	f.mu.Unlock()
}

// caFile writes the provider's HTTPS certificate as a CA file.
func (f *fakeIdP) caFile() string {
	path := filepath.Join(f.t.TempDir(), "idp-ca.pem")
	os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw}), 0o600)
	return path
}

// clientCertFiles makes a self-signed client certificate and its key, as
// files; the certificate is what a provider is given.
func clientCertFiles(t *testing.T, expires time.Time) (*x509.Certificate, string, string) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "tlsproxy"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: expires}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "client.crt"), filepath.Join(dir, "client.key")
	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	pk, _ := x509.MarshalPKCS8PrivateKey(key)
	os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}), 0o600)
	return cert, certPath, keyPath
}

func (f *fakeIdP) issuerURL() string { return f.srv.URL + "/tenant/v2.0" }

// signIn plays the provider's sign-in for an authorize URL: the callback
// URL it sends the browser to.
func (f *fakeIdP) signIn(authorize string, claims map[string]any) string {
	f.t.Helper()
	u, err := url.Parse(authorize)
	if err != nil || !strings.HasPrefix(authorize, f.srv.URL+"/authorize?") {
		f.t.Fatalf("not an authorize URL: %s", authorize)
	}
	q := u.Query()
	code := oidcToken()
	f.mu.Lock()
	f.codes[code], f.next, f.last = q, claims, q
	f.mu.Unlock()
	return q.Get("redirect_uri") + "?" + url.Values{"code": {code}, "state": {q.Get("state")}}.Encode()
}

func signRS256(key *rsa.PrivateKey, kid string, claims map[string]any) string {
	enc := base64.RawURLEncoding.EncodeToString
	h, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": kid, "typ": "JWT"})
	p, _ := json.Marshal(claims)
	in := enc(h) + "." + enc(p)
	sum := sha256.Sum256([]byte(in))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	return in + "." + enc(sig)
}

// identityEcho answers with who the proxy says signed in, and the cookies
// it passed on.
func identityEcho(t *testing.T) int {
	l, port := listen(t)
	go http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "user=%s email=%s groups=%s roles=%s mfa=%s cookie=%s", r.Header.Get("X-Forwarded-User"), r.Header.Get("X-Forwarded-Email"),
			r.Header.Get("X-Forwarded-Groups"), r.Header.Get("X-Forwarded-Roles"), r.Header.Get("X-Forwarded-Mfa"), r.Header.Get("Cookie"))
	}))
	return port
}

func TestOIDCSignIn(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	idp := newFakeIdP(t)
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
          - {type: reverse_proxy, prefix: /secure/, target: "http://127.0.0.1:%[2]d", oidc: corp, require_mfa: true}
          - {type: reverse_proxy, prefix: /open/, target: "http://127.0.0.1:%[2]d"}
oidc:
  - {name: corp, issuer: "%[3]s", client_id: app, client_secret: s3cret, mfa_acr_values: ["2"]}
`, ca.localCA(t), backend, idp.issuerURL()), "")
	var skew atomic.Int64
	p.srv.oidc.now = func() time.Time { return time.Now().Add(time.Duration(skew.Load())) }

	browser := serveClient(p, ca, false)
	browser.Jar, _ = cookiejar.New(nil)
	nav := []string{"Accept", "text/html", "Sec-Fetch-Mode", "navigate"}
	get := func(u string, header ...string) (*http.Response, string) {
		t.Helper()
		return httpsGet(t, browser, u, header...)
	}
	signIn := func(path string, claims map[string]any) (*http.Response, string) {
		t.Helper()
		resp, _ := get("https://www.test"+path, nav...)
		if resp.StatusCode != 302 {
			t.Fatalf("%s: %d, want a redirect to sign in", path, resp.StatusCode)
		}
		resp, _ = get(idp.signIn(resp.Header.Get("Location"), claims))
		if resp.StatusCode != 302 || resp.Header.Get("Location") != path {
			t.Fatalf("callback: %d %s, want 302 to %s", resp.StatusCode, resp.Header.Get("Location"), path)
		}
		return get("https://www.test"+path, nav...)
	}

	// Not a browser: 401, no redirect. A client's identity headers never
	// reach a backend.
	if resp, _ := httpsGet(t, serveClient(p, ca, false), "https://www.test/x"); resp.StatusCode != 401 {
		t.Errorf("a script: %d, want 401", resp.StatusCode)
	}
	if _, body := get("https://www.test/open/", "X-Forwarded-User", "root", "X-Forwarded-Roles", "Admin"); !strings.HasPrefix(body, "user= email= groups= roles= mfa=") {
		t.Errorf("open route passed a client's identity on: %s", body)
	}

	resp, _ := get("https://www.test/x?q=1", nav...)
	loc, _ := url.Parse(resp.Header.Get("Location"))
	q := loc.Query()
	if resp.StatusCode != 302 || q.Get("client_id") != "app" || q.Get("redirect_uri") != "https://www.test/.tlsproxy/oidc/callback" ||
		q.Get("code_challenge_method") != "S256" || q.Get("scope") != "openid profile email" || q.Get("acr_values") != "" || q.Get("nonce") == "" {
		t.Fatalf("redirect to sign in: %d %s", resp.StatusCode, loc)
	}
	// A callback without the browser's state cookie is refused.
	if resp, _ := httpsGet(t, serveClient(p, ca, false), idp.signIn(loc.String(), map[string]any{"sub": "u1"})); resp.StatusCode != 400 {
		t.Errorf("callback in another browser: %d", resp.StatusCode)
	}

	claims := map[string]any{"sub": "u1", "preferred_username": "alice@example.com", "email": "alice@example.com", "groups": []string{"eng"}, "roles": []string{"Reader"}}
	resp, body := signIn("/x?q=1", claims)
	if resp.StatusCode != 200 || body != "user=alice@example.com email=alice@example.com groups=eng roles=Reader mfa=false cookie=" {
		t.Errorf("signed in: %d %s", resp.StatusCode, body)
	}
	// Signed in, a script on the page may fetch too; the session cookie
	// stays here, other cookies go on.
	browser.Jar.SetCookies(&url.URL{Scheme: "https", Host: "www.test"}, []*http.Cookie{{Name: "app", Value: "1"}})
	if resp, body := get("https://www.test/api", "X-Forwarded-User", "root"); resp.StatusCode != 200 || !strings.HasPrefix(body, "user=alice@example.com") || !strings.HasSuffix(body, "cookie=app=1") {
		t.Errorf("fetch with the session: %d %s", resp.StatusCode, body)
	}

	// A role it lacks: 403, not another sign-in.
	if resp, body := get("https://www.test/admin/", nav...); resp.StatusCode != 403 || !strings.Contains(body, "role Admin") {
		t.Errorf("without the role: %d %s", resp.StatusCode, body)
	}
	// MFA: a session without it is sent to step up, even right after
	// signing in.
	resp, _ = get("https://www.test/secure/", nav...)
	if resp.StatusCode != 302 || !strings.Contains(resp.Header.Get("Location"), "acr_values=2") || !strings.Contains(resp.Header.Get("Location"), "login_hint=alice") {
		t.Fatalf("step up: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp, _ = get(idp.signIn(resp.Header.Get("Location"), map[string]any{"sub": "u1", "preferred_username": "alice@example.com", "roles": []string{"Admin"}}))
	if resp, body := get("https://www.test/secure/", nav...); resp.StatusCode != 200 || !strings.Contains(body, "mfa=true") {
		t.Errorf("after step up: %d %s", resp.StatusCode, body)
	}
	if resp, _ := get("https://www.test/admin/", nav...); resp.StatusCode != 200 {
		t.Errorf("with the role: %d", resp.StatusCode)
	}
	// A provider that signs in without MFA when asked for it: 403, not a
	// loop of sign-ins.
	idp.noMFA.Store(true)
	other := serveClient(p, ca, false)
	other.Jar, _ = cookiejar.New(nil)
	resp, _ = httpsGet(t, other, "https://www.test/secure/", nav...)
	if !strings.Contains(resp.Header.Get("Location"), "acr_values=2") {
		t.Fatalf("sign-in for an MFA page asks for it: %s", resp.Header.Get("Location"))
	}
	resp, _ = httpsGet(t, other, idp.signIn(resp.Header.Get("Location"), map[string]any{"sub": "u2"}))
	if resp, body := httpsGet(t, other, "https://www.test/secure/", nav...); resp.StatusCode != 403 || !strings.Contains(body, "without a second factor") {
		t.Errorf("MFA asked for, not done: %d %s", resp.StatusCode, body)
	}
	idp.noMFA.Store(false)

	// The session ends after session (8h).
	skew.Store(int64(9 * time.Hour))
	if resp, _ := get("https://www.test/x", nav...); resp.StatusCode != 302 {
		t.Errorf("expired session: %d", resp.StatusCode)
	}

	// What the provider says goes wrong is shown.
	resp, _ = get("https://www.test/y", nav...)
	loc, _ = url.Parse(resp.Header.Get("Location"))
	cb := "https://www.test/.tlsproxy/oidc/callback?" + url.Values{"state": {loc.Query().Get("state")}, "error": {"access_denied"}, "error_description": {"AADSTS50105: not assigned"}}.Encode()
	if resp, body := get(cb); resp.StatusCode != 403 || !strings.Contains(body, "AADSTS50105") {
		t.Errorf("provider error: %d %s", resp.StatusCode, body)
	}
	// A token from another issuer, or with another nonce, is refused.
	idp.issuer = "https://evil.test"
	resp, _ = get("https://www.test/z", nav...)
	if resp, _ := get(idp.signIn(resp.Header.Get("Location"), claims)); resp.StatusCode != 502 {
		t.Errorf("wrong issuer: %d", resp.StatusCode)
	}
	idp.issuer = ""
	resp, _ = get("https://www.test/z", nav...)
	if resp, _ := get(idp.signIn(resp.Header.Get("Location"), map[string]any{"sub": "u1", "nonce": "other"})); resp.StatusCode != 502 {
		t.Errorf("wrong nonce: %d", resp.StatusCode)
	}

	// Logout forgets the session and goes on to the provider, which comes
	// back to the callback: signed out.
	resp, _ = get("https://www.test/.tlsproxy/oidc/logout", nav...)
	if resp.StatusCode != 302 || !strings.HasPrefix(resp.Header.Get("Location"), idp.srv.URL+"/logout?") ||
		!strings.Contains(resp.Header.Get("Location"), url.QueryEscape("https://www.test/.tlsproxy/oidc/callback")) {
		t.Errorf("logout: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp, body := get("https://www.test/.tlsproxy/oidc/callback"); resp.StatusCode != 200 || !strings.Contains(body, "signed out") {
		t.Errorf("after logout: %d %s", resp.StatusCode, body)
	}
	if resp, _ := get("https://www.test/x", nav...); resp.StatusCode != 302 {
		t.Errorf("signed out, still in: %d", resp.StatusCode)
	}
	if !strings.Contains(testLog.String(), "(oidc: alice@example.com signed in with corp)") {
		t.Error("a sign-in is logged")
	}
}

func TestVerifyJWT(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keys := func(kid string) (crypto.PublicKey, error) {
		switch kid {
		case "r":
			return &rsaKey.PublicKey, nil
		case "e":
			return &ecKey.PublicKey, nil
		}
		return nil, fmt.Errorf("no key %s", kid)
	}
	enc := base64.RawURLEncoding.EncodeToString
	token := func(alg, kid string, sign func(in string) []byte) string {
		h, _ := json.Marshal(map[string]string{"alg": alg, "kid": kid})
		in := enc(h) + "." + enc([]byte(`{"sub":"x","exp":1}`))
		return in + "." + enc(sign(in))
	}
	es256 := func(in string) []byte {
		sum := sha256.Sum256([]byte(in))
		r, s, _ := ecdsa.Sign(rand.Reader, ecKey, sum[:])
		return append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	}
	if c, err := verifyJWT(signRS256(rsaKey, "r", map[string]any{"sub": "x"}), keys); err != nil || c["sub"] != "x" {
		t.Errorf("RS256: %v %v", c, err)
	}
	if c, err := verifyJWT(token("ES256", "e", es256), keys); err != nil || c["sub"] != "x" {
		t.Errorf("ES256: %v %v", c, err)
	}
	for name, tok := range map[string]string{
		"none":          token("none", "r", func(string) []byte { return nil }),
		"HS256":         token("HS256", "r", func(string) []byte { return []byte("mac") }),
		"EC key as RSA": token("RS256", "e", es256),
		"unknown kid":   token("ES256", "zz", es256),
		"tampered":      strings.Replace(signRS256(rsaKey, "r", map[string]any{"sub": "x"}), ".", ".e30", 1),
	} {
		if _, err := verifyJWT(tok, keys); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The console's rule editor writes oidc and its requirements back, lists as
// YAML lists.
func TestOIDCConsoleSave(t *testing.T) {
	text := `listeners:
  - {name: a, port: 1}
routes:
  - listener: a
    rules:
      - domain: x.test
        cert: local-ca
        serve:
          - {type: reverse_proxy, prefix: /, target: "http://127.0.0.1:1"}
oidc:
  - {name: corp, issuer: "https://id.test/t/v2.0", client_id: app, client_secret: s}
`
	values := map[string]any{"listener": "a", "domain": "x.test", "cert": "local-ca", "serve": []any{
		map[string]any{"type": "reverse_proxy", "prefix": "/", "target": "http://127.0.0.1:1", "oidc": "corp", "require_mfa": "true", "require_groups": []any{"ops", "sre"}},
	}}
	full, block, _, err := editRules(text, 6, values, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(block, "oidc: corp, require_mfa: true, require_groups: [ops, sre]") {
		t.Errorf("written as:\n%s", block)
	}
	cfg, err := ParseConfig(full)
	if err != nil {
		t.Fatalf("%v\n%s", err, full)
	}
	if r := cfg.Rules[0].Routes[0]; r.oidc == nil || !r.RequireMFA || strings.Join(r.RequireGroups, ",") != "ops,sre" {
		t.Errorf("read back: %+v", r)
	}
}

// The cases TestOIDCSignIn leaves out: a client certificate (private_key_jwt)
// at an HTTPS provider with its own CA, client_secret_post, two providers,
// username_claim, scopes and session, groups and roles together, a session
// too big for a cookie, static files, basic_auth's X-Forwarded-User, and a
// provider that rotates its signing key.
func TestOIDCMoreCases(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	clientCert, certPath, keyPath := clientCertFiles(t, time.Now().Add(365*24*time.Hour))
	corp := newFakeIdPWith(t, fakeOpts{tls: true, methods: []string{"private_key_jwt"}, clientCert: clientCert})
	partner := newFakeIdPWith(t, fakeOpts{methods: []string{"client_secret_post"}})
	backend := identityEcho(t)
	files := t.TempDir()
	os.WriteFile(filepath.Join(files, "index.html"), []byte("static ok"), 0o644)
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
          - {type: reverse_proxy, prefix: /both/, target: "http://127.0.0.1:%[2]d", oidc: corp, require_groups: [ops], require_roles: [Admin]}
          - {type: static_content, prefix: /files/, base_dir: %[3]s, oidc: corp}
          - {type: reverse_proxy, prefix: /basic/, target: "http://127.0.0.1:%[2]d", basic_auth: team}
      - domain: p.test
        cert: %[1]s
        serve:
          - {type: reverse_proxy, prefix: /, target: "http://127.0.0.1:%[2]d", oidc: partner}
      - domain: two.test
        cert: %[1]s
        serve:
          - {type: reverse_proxy, prefix: /, target: "http://127.0.0.1:%[2]d", oidc: corp}
          - {type: reverse_proxy, prefix: /p/, target: "http://127.0.0.1:%[2]d", oidc: partner}
basic_auth:
  - {name: team, users: [{username: jack, password_plain: pw}]}
oidc:
  - name: corp
    issuer: "%[4]s"
    client_id: app
    client_certificate: %[5]s
    client_key: %[6]s
    ca_file: %[7]s
    scopes: [openid, groups]
    session: 30m
    username_claim: email
  - {name: partner, issuer: "%[8]s", client_id: app, client_secret: s3cret}
`, ca.localCA(t), backend, files, corp.issuerURL(), certPath, keyPath, corp.caFile(), partner.issuerURL()), "")
	var skew atomic.Int64
	p.srv.oidc.now = func() time.Time { return time.Now().Add(time.Duration(skew.Load())) }

	nav := []string{"Accept", "text/html", "Sec-Fetch-Mode", "navigate"}
	newBrowser := func() *http.Client {
		c := serveClient(p, ca, false)
		c.Jar, _ = cookiejar.New(nil)
		return c
	}
	// signIn opens url, signs in at idp with claims, and opens it again.
	signIn := func(b *http.Client, idp *fakeIdP, u string, claims map[string]any) (*http.Response, string, *http.Response) {
		t.Helper()
		resp, _ := httpsGet(t, b, u, nav...)
		if resp.StatusCode != 302 {
			t.Fatalf("%s: %d, want a redirect to sign in", u, resp.StatusCode)
		}
		callback, _ := httpsGet(t, b, idp.signIn(resp.Header.Get("Location"), claims), nav...)
		if callback.StatusCode != 302 {
			t.Fatalf("%s: callback %d", u, callback.StatusCode)
		}
		resp, body := httpsGet(t, b, u, nav...)
		return resp, body, callback
	}

	// A client certificate, at an HTTPS provider trusted through ca_file;
	// the name from username_claim; the scopes asked for; the session's
	// length.
	alice := newBrowser()
	resp, body, callback := signIn(alice, corp, "https://www.test/", map[string]any{"sub": "a", "preferred_username": "alice-pref", "email": "alice@example.com", "groups": []string{"ops"}})
	if resp.StatusCode != 200 || !strings.HasPrefix(body, "user=alice@example.com email=alice@example.com groups=ops roles= mfa=false") {
		t.Errorf("signed in with a certificate: %d %s", resp.StatusCode, body)
	}
	if corp.auth != "private_key_jwt" || corp.last.Get("scope") != "openid groups" {
		t.Errorf("client auth %q, scope %q", corp.auth, corp.last.Get("scope"))
	}
	if sc := strings.Join(callback.Header.Values("Set-Cookie"), "\n"); !strings.Contains(sc, "Max-Age=1800") || !strings.Contains(sc, "__Host-tlsproxy-oidc-") ||
		!strings.Contains(sc, "HttpOnly") || !strings.Contains(sc, "Secure") || !strings.Contains(sc, "SameSite=Lax") {
		t.Errorf("session cookie: %s", sc)
	}
	// Static files behind sign-in.
	if resp, body := httpsGet(t, alice, "https://www.test/files/", nav...); resp.StatusCode != 200 || body != "static ok" {
		t.Errorf("static, signed in: %d %s", resp.StatusCode, body)
	}
	if resp, _ := httpsGet(t, newBrowser(), "https://www.test/files/", nav...); resp.StatusCode != 302 {
		t.Errorf("static, not signed in: %d", resp.StatusCode)
	}
	// Groups and roles together: both are needed.
	if resp, body := httpsGet(t, alice, "https://www.test/both/", nav...); resp.StatusCode != 403 || !strings.Contains(body, "role Admin") {
		t.Errorf("group, no role: %d %s", resp.StatusCode, body)
	}
	if resp, body, _ := signIn(newBrowser(), corp, "https://www.test/both/", map[string]any{"sub": "b", "email": "b@x", "roles": []string{"Admin"}}); resp.StatusCode != 403 || !strings.Contains(body, "group ops") {
		t.Errorf("role, no group: %d %s", resp.StatusCode, body)
	}
	// Both, among 300 groups: too many for a cookie, so it keeps the
	// groups some entry requires.
	many := []string{}
	for i := range 300 {
		many = append(many, fmt.Sprintf("some-rather-long-group-name-%03d", i))
	}
	many = append(many, "ops")
	resp, body, _ = signIn(newBrowser(), corp, "https://www.test/both/", map[string]any{"sub": "c", "email": "c@x", "groups": many, "roles": []string{"Admin", "Reader"}})
	if resp.StatusCode != 200 || !strings.Contains(body, "groups=ops roles=Admin ") {
		t.Errorf("group and role, many groups: %d %s", resp.StatusCode, body)
	}

	// basic_auth: the user goes on as X-Forwarded-User, not what the
	// client claims; no X-Forwarded-Mfa.
	req, _ := http.NewRequest("GET", "https://www.test/basic/", nil)
	req.SetBasicAuth("jack", "pw")
	req.Header.Set("X-Forwarded-User", "root")
	req.Header.Set("X-Forwarded-Mfa", "true")
	if r, err := serveClient(p, ca, false).Do(req); err != nil {
		t.Fatal(err)
	} else {
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if !strings.HasPrefix(string(b), "user=jack email= groups= roles= mfa= ") {
			t.Errorf("basic_auth identity: %s", b)
		}
	}

	// client_secret_post, when that is all the provider offers.
	if resp, body, _ := signIn(newBrowser(), partner, "https://p.test/", map[string]any{"sub": "d", "preferred_username": "dora"}); resp.StatusCode != 200 || !strings.HasPrefix(body, "user=dora") || partner.auth != "post" {
		t.Errorf("client_secret_post: %d %s (auth %q)", resp.StatusCode, body, partner.auth)
	}

	// The provider rotates its signing key: tokens with the new kid are
	// checked against the keys fetched again (at most every 30 s).
	corp.rotate()
	skew.Store(int64(time.Minute))
	if resp, body, _ := signIn(newBrowser(), corp, "https://www.test/", map[string]any{"sub": "e", "email": "e@x"}); resp.StatusCode != 200 || !strings.HasPrefix(body, "user=e@x") {
		t.Errorf("after key rotation: %d %s", resp.StatusCode, body)
	}
	// The session ends after session: 30m.
	skew.Store(int64(32 * time.Minute))
	if resp, _ := httpsGet(t, alice, "https://www.test/", nav...); resp.StatusCode != 302 {
		t.Errorf("after 30m: %d, want a sign-in", resp.StatusCode)
	}
	skew.Store(0)

	// Two providers on one host: a session for each; logout forgets both,
	// and says so here (there is no one provider to send the browser to).
	two := newBrowser()
	signIn(two, corp, "https://two.test/", map[string]any{"sub": "f", "email": "f@x"})
	if resp, body, _ := signIn(two, partner, "https://two.test/p/", map[string]any{"sub": "f2", "preferred_username": "f-partner"}); resp.StatusCode != 200 || !strings.HasPrefix(body, "user=f-partner") {
		t.Errorf("second provider on the host: %d %s", resp.StatusCode, body)
	}
	if resp, body := httpsGet(t, two, "https://two.test/", nav...); resp.StatusCode != 200 || !strings.HasPrefix(body, "user=f@x") {
		t.Errorf("first provider's session kept: %d %s", resp.StatusCode, body)
	}
	resp, body = httpsGet(t, two, "https://two.test/.tlsproxy/oidc/logout", nav...)
	if resp.StatusCode != 200 || !strings.Contains(body, "signed out here") || strings.Count(strings.Join(resp.Header.Values("Set-Cookie"), "\n"), "Max-Age=0") != 2 {
		t.Errorf("logout, two providers: %d %v %s", resp.StatusCode, resp.Header.Values("Set-Cookie"), body)
	}
	for _, path := range []string{"/", "/p/"} {
		if resp, _ := httpsGet(t, two, "https://two.test"+path, nav...); resp.StatusCode != 302 {
			t.Errorf("after logout %s: %d", path, resp.StatusCode)
		}
	}
}

// Checking oidc items against their providers, without signing in.
func TestOIDCCheck(t *testing.T) {
	t.Parallel()
	good := newFakeIdP(t)
	cert, certPath, keyPath := clientCertFiles(t, time.Now().Add(365*24*time.Hour))
	byCert := newFakeIdPWith(t, fakeOpts{tls: true, methods: []string{"private_key_jwt"}, clientCert: cert})
	postOnly := newFakeIdPWith(t, fakeOpts{methods: []string{"client_secret_post"}})
	cfg, err := ParseConfig(fmt.Sprintf(`listeners:
  - {name: a, port: 1}
routes:
  - listener: a
    rules:
      - domain: www.test
        cert: local-ca
        serve:
          - {type: reverse_proxy, prefix: /, target: "http://127.0.0.1:1", oidc: good}
          - {type: reverse_proxy, prefix: /m/, target: "http://127.0.0.1:1", oidc: good, require_mfa: true}
          - {type: reverse_proxy, prefix: /c/, target: "http://127.0.0.1:1", oidc: bycert}
      - domain: "*.test"
        cert: local-ca
        serve:
          - {type: reverse_proxy, prefix: /, target: "http://127.0.0.1:1", oidc: good}
oidc:
  - {name: good, issuer: "%[1]s", client_id: app, client_secret: s3cret}
  - {name: wrongsecret, issuer: "%[1]s", client_id: app, client_secret: nope}
  - {name: bycert, issuer: "%[2]s", client_id: app, client_certificate: %[3]s, client_key: %[4]s, ca_file: %[5]s}
  - {name: nocafile, issuer: "%[2]s", client_id: app, client_certificate: %[3]s, client_key: %[4]s}
  - {name: certvspost, issuer: "%[6]s", client_id: app, client_certificate: %[3]s, client_key: %[4]s}
  - {name: down, issuer: "http://127.0.0.1:%[7]d/x", client_id: app, client_secret: s}
`, good.issuerURL(), byCert.issuerURL(), certPath, keyPath, byCert.caFile(), postOnly.issuerURL(), freePort(t)))
	if err != nil {
		t.Fatal(err)
	}
	reports, err := checkOIDCConfig(context.Background(), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]oidcReport{}
	for _, r := range reports {
		got[r.Name] = r
	}
	find := func(name, what string) oidcCheck {
		for _, c := range got[name].Checks {
			if strings.HasPrefix(c.What, what) {
				return c
			}
		}
		return oidcCheck{}
	}
	want := []struct{ name, what, level, detail string }{
		{"good", "discovery", "ok", ""},
		{"good", "signing keys", "ok", "1 usable of 1"},
		{"good", "client credentials (client_secret_basic)", "ok", "accepted"},
		{"good", "mfa_acr_values", "warn", "no mfa_acr_values"},
		{"good", "redirect URI", "warn", "*.test"},
		{"good", "redirect URIs", "ok", "https://www.test:1/.tlsproxy/oidc/callback"},
		{"wrongsecret", "client credentials", "fail", "refused: invalid_client"},
		{"bycert", "client credentials (private_key_jwt)", "ok", "accepted"},
		{"bycert", "redirect URIs", "ok", "https://www.test:1/.tlsproxy/oidc/callback"},
		{"wrongsecret", "redirect URIs", "warn", "no serve entry uses it yet; register the URI of each site you will use it on: https://www.test:1/.tlsproxy/oidc/callback"},
		{"nocafile", "discovery", "fail", "certificate"},
		{"certvspost", "client authentication", "fail", "would use private_key_jwt; the provider offers client_secret_post"},
		{"down", "discovery", "fail", "connection refused"},
	}
	for _, w := range want {
		c := find(w.name, w.what)
		if c.Level != w.level || !strings.Contains(c.Detail, w.detail) {
			t.Errorf("%s %s: %s %q, want %s %q", w.name, w.what, c.Level, c.Detail, w.level, w.detail)
		}
	}
	for name, ok := range map[string]bool{"good": true, "bycert": true, "wrongsecret": false, "nocafile": false, "certvspost": false, "down": false} {
		if got[name].OK != ok {
			t.Errorf("%s: ok %v, want %v\n%s", name, got[name].OK, ok, formatOIDCReports([]oidcReport{got[name]}))
		}
	}
	if _, err := checkOIDCConfig(context.Background(), cfg, []string{"nope"}); err == nil {
		t.Error("an unknown name is an error")
	}
	if text := formatOIDCReports([]oidcReport{got["wrongsecret"]}); !strings.Contains(text, "  FAIL client credentials (client_secret_basic): refused") {
		t.Errorf("as text:\n%s", text)
	}
}

// Groups and roles from where the provider puts them.
func TestOIDCClaimPaths(t *testing.T) {
	var claims map[string]any
	json.Unmarshal([]byte(`{"iss": "i", "aud": "app", "exp": 9999999999, "nonce": "n", "sub": "s",
		"realm_access": {"roles": ["admin", "user"]}, "resource_access": {"app": {"roles": ["editor"]}},
		"https://example.com/groups": ["eng"], "groups": "solo"}`), &claims)
	for k, v := range claims {
		if f, ok := v.(float64); ok {
			claims[k] = json.Number(fmt.Sprint(int64(f)))
		}
	}
	for _, c := range []struct{ groups, roles, wantG, wantR string }{
		{"groups", "roles", "solo", ""},
		{"https://example.com/groups", "realm_access.roles", "eng", "admin,user"},
		{"no.such.path", "resource_access.app.roles", "", "editor"},
		{"realm_access", "sub", "", "s"},
	} {
		p := &OIDCProvider{ClientID: "app", GroupsClaim: c.groups, RolesClaim: c.roles}
		id, err := identityFrom(claims, p, "i", &oidcPending{Nonce: "n"}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if g, r := strings.Join(id.Groups, ","), strings.Join(id.Roles, ","); g != c.wantG || r != c.wantR {
			t.Errorf("%s / %s: groups %q roles %q, want %q %q", c.groups, c.roles, g, r, c.wantG, c.wantR)
		}
	}
}

// Providers kept for discovery and keys are capped: each reload with a new
// issuer adds one, and the least recently used go.
func TestOIDCClientsCapped(t *testing.T) {
	a := newOIDCAuth()
	first := &OIDCProvider{Issuer: "https://id0.test/x"}
	for i := range 3 * oidcMaxClients {
		a.client(first) // used all along: kept
		if _, err := a.client(&OIDCProvider{Issuer: fmt.Sprintf("https://id%d.test/x", i+1)}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Microsecond)
	}
	if len(a.clients) > oidcMaxClients || a.clients[first.Issuer+"\x00"] == nil {
		t.Errorf("%d clients kept (cap %d), the one in use kept: %v", len(a.clients), oidcMaxClients, a.clients[first.Issuer+"\x00"] != nil)
	}
}
