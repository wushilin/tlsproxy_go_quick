package main

// Signing in with OpenID Connect, for serve entries with oidc: <name>. The
// proxy is a confidential web client of the provider and uses the
// authorization code flow with PKCE:
//
//  1. A browser asks for a guarded path without a session cookie: it is sent
//     to the provider's authorize endpoint. What the callback needs (state,
//     nonce, PKCE verifier, where to go back to) goes with it in a short-lived
//     encrypted cookie. Other clients (scripts, fetch, WebSockets) get 401.
//  2. The provider signs the user in, with its second factor and its own
//     rules about who may use the application.
//  3. It sends the browser to https://<host>/.tlsproxy/oidc/callback with a
//     code, which the proxy redeems at the token endpoint, with the client
//     secret, for an ID token. The token's signature (the provider's JWKS),
//     issuer, audience, expiry and nonce are checked.
//  4. Who signed in goes into an encrypted session cookie (__Host-, HttpOnly,
//     SameSite=Lax) for oidc's session, and the browser goes back where it
//     was. Nothing is kept on the server.
//
// A serve entry may require more: require_mfa (amr has "mfa", or acr is one
// of mfa_acr_values; a session without it is sent back to step up, asking for
// mfa_acr_values, once: a session the provider made without MFA although it
// was asked for gets 403, not another loop), require_groups or require_roles
// (from the token's groups and roles claims). A signed-in user who lacks a
// group or role gets 403.
//
// /.tlsproxy/oidc/logout forgets the sessions on that host and goes on to the
// provider's end_session_endpoint, which sends the browser back to the
// callback (a registered redirect URI), which says it is signed out.
//
// The cookie key is made at start-up: a restart signs every browser in
// again, which the provider does without asking while its own session lasts.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	oidcPathPrefix  = "/.tlsproxy/oidc/"
	oidcCallback    = oidcPathPrefix + "callback"
	oidcLogout      = oidcPathPrefix + "logout"
	oidcStateTTL    = 10 * time.Minute // to finish signing in
	oidcCookieMax   = 3800             // bytes of a session cookie's value, under browsers' 4096 per cookie
	oidcHTTPTimeout = 10 * time.Second
	oidcDiscoTTL    = time.Hour
	oidcRetryAfter  = 10 * time.Second // after the provider could not be reached
	oidcKeysMinAge  = 30 * time.Second // between JWKS fetches for a key id not seen
	oidcClockSkew   = 2 * time.Minute
	oidcMaxClients  = 32 // providers kept: each reload with a new issuer or ca_file adds one
)

// oidcIdentity is who signed in: what a session cookie holds.
type oidcIdentity struct {
	User     string   `json:"u"`
	Email    string   `json:"e,omitempty"`
	Subject  string   `json:"s"`
	Groups   []string `json:"g,omitempty"`
	Roles    []string `json:"r,omitempty"`
	MFA      bool     `json:"m,omitempty"`
	AskedMFA bool     `json:"a,omitempty"` // MFA was asked for, and the provider signed in without: no step-up again
	Issued   int64    `json:"i"`
	Expires  int64    `json:"x"`
}

// oidcPending is a sign-in under way: the state cookie.
type oidcPending struct {
	Provider string `json:"p"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Return   string `json:"r"`
	MFA      bool   `json:"m,omitempty"` // MFA was asked for (acr_values)
	Expires  int64  `json:"x"`
}

// oidcAuth is the proxy's sign-in state that outlives reloads: the cookie
// key, and per issuer its discovery document and keys.
type oidcAuth struct {
	aead    cipher.AEAD
	mu      sync.Mutex
	clients map[string]*oidcClient // by issuer and ca_file; at most oidcMaxClients, the least recently used go
	now     func() time.Time
}

func newOIDCAuth() *oidcAuth {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	return &oidcAuth{aead: aead, clients: map[string]*oidcClient{}, now: time.Now}
}

// oidcDiscovery is what the proxy reads of a discovery document.
type oidcDiscovery struct {
	Issuer           string   `json:"issuer"`
	Authorize        string   `json:"authorization_endpoint"`
	Token            string   `json:"token_endpoint"`
	JWKS             string   `json:"jwks_uri"`
	EndSession       string   `json:"end_session_endpoint"`
	TokenAuthMethods []string `json:"token_endpoint_auth_methods_supported"`
}

// oidcClient talks to one provider: its discovery document and signing
// keys, fetched when first needed and cached.
type oidcClient struct {
	issuer string
	http   *http.Client
	mu     sync.Mutex
	disco  *oidcDiscovery
	discAt time.Time
	failAt time.Time // the last failure, to wait before trying again
	fail   error
	keys   map[string]crypto.PublicKey // by kid: the last JWKS fetched, replaced whole
	keysAt time.Time
	used   time.Time // last asked for, under oidcAuth.mu
}

// client is the oidcClient for p, made on first use.
func (a *oidcAuth) client(p *OIDCProvider) (*oidcClient, error) {
	id := p.Issuer + "\x00" + p.CAFile
	a.mu.Lock()
	defer a.mu.Unlock()
	if c := a.clients[id]; c != nil {
		c.used = time.Now()
		return c, nil
	}
	for len(a.clients) >= oidcMaxClients {
		var oldest string
		for k, c := range a.clients {
			if oldest == "" || c.used.Before(a.clients[oldest].used) {
				oldest = k
			}
		}
		delete(a.clients, oldest)
	}
	tlsConf := &tls.Config{MinVersion: tls.VersionTLS12}
	if p.CAFile != "" {
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		pem, err := os.ReadFile(p.CAFile)
		if err != nil {
			return nil, err
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ca_file %s holds no PEM certificate", p.CAFile)
		}
		tlsConf.RootCAs = pool
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsConf
	c := &oidcClient{issuer: p.Issuer, keys: map[string]crypto.PublicKey{}, used: time.Now(), http: &http.Client{
		Transport: tr,
		Timeout:   oidcHTTPTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
	a.clients[id] = c
	return c, nil
}

// getJSON fetches url into v.
func (c *oidcClient) getJSON(ctx context.Context, u string, v any) error {
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("GET %s: %v", u, err)
	}
	return nil
}

// discovery is the provider's discovery document, fetched at most once an
// hour, and not again for a while after a failure.
func (c *oidcClient) discovery(ctx context.Context, now time.Time) (*oidcDiscovery, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.disco != nil && now.Sub(c.discAt) < oidcDiscoTTL {
		return c.disco, nil
	}
	if c.fail != nil && now.Sub(c.failAt) < oidcRetryAfter {
		if c.disco != nil {
			return c.disco, nil // stale beats nothing
		}
		return nil, c.fail
	}
	var d oidcDiscovery
	err := c.getJSON(ctx, c.issuer+"/.well-known/openid-configuration", &d)
	if err == nil {
		switch {
		case d.Issuer == "", d.Authorize == "", d.Token == "", d.JWKS == "":
			err = fmt.Errorf("the discovery document of %s lacks issuer, authorization_endpoint, token_endpoint or jwks_uri", c.issuer)
		}
	}
	if err != nil {
		c.fail, c.failAt = err, now
		if c.disco != nil {
			return c.disco, nil
		}
		return nil, err
	}
	// The issuer the tokens carry is the document's: rust-oidc and Entra
	// publish a tenant's document under its domain and name the tenant by
	// its id in tokens. The document comes over HTTPS from the configured
	// address, and so do the keys that sign them.
	c.disco, c.discAt, c.fail = &d, now, nil
	return c.disco, nil
}

// key is the provider's signing key kid, fetching the JWKS again when the
// key is new (keys rotate), at most every oidcKeysMinAge.
func (c *oidcClient) key(ctx context.Context, d *oidcDiscovery, kid string, now time.Time) (crypto.PublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if k, ok := c.keys[kid]; ok {
		return k, nil
	}
	if !c.keysAt.IsZero() && now.Sub(c.keysAt) < oidcKeysMinAge {
		return nil, fmt.Errorf("no signing key %q", kid)
	}
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := c.getJSON(ctx, d.JWKS, &set); err != nil {
		return nil, err
	}
	keys := map[string]crypto.PublicKey{}
	for _, raw := range set.Keys {
		if id, k, err := parseJWK(raw); err == nil {
			keys[id] = k
		}
	}
	c.keys, c.keysAt = keys, now
	if k, ok := keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("no signing key %q in %s", kid, d.JWKS)
}

// parseJWK reads one RSA or EC (P-256, P-384) signing key of a JWKS.
func parseJWK(raw []byte) (string, crypto.PublicKey, error) {
	var k struct {
		Kty, Kid, Use, Crv, N, E, X, Y string
	}
	if err := json.Unmarshal(raw, &k); err != nil {
		return "", nil, err
	}
	if k.Use != "" && k.Use != "sig" {
		return "", nil, errors.New("not a signing key")
	}
	b := func(s string) *big.Int {
		v, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
		if err != nil || len(v) == 0 {
			return nil
		}
		return new(big.Int).SetBytes(v)
	}
	switch k.Kty {
	case "RSA":
		n, e := b(k.N), b(k.E)
		if n == nil || e == nil || !e.IsInt64() || n.BitLen() < 2048 {
			return "", nil, errors.New("bad RSA key")
		}
		return k.Kid, &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
	case "EC":
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		default:
			return "", nil, errors.New("unsupported curve")
		}
		x, y := b(k.X), b(k.Y)
		if x == nil || y == nil || !curve.IsOnCurve(x, y) {
			return "", nil, errors.New("bad EC key")
		}
		return k.Kid, &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	}
	return "", nil, errors.New("unsupported key type")
}

// verifyJWT checks a compact JWS signed with RS256/384/512, PS256 or
// ES256/384 by the key keyFor finds, and returns its claims.
func verifyJWT(token string, keyFor func(kid string) (crypto.PublicKey, error)) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("not a signed JWT")
	}
	var header struct{ Alg, Kid, Crit any }
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || json.Unmarshal(hb, &header) != nil {
		return nil, errors.New("bad JWT header")
	}
	if header.Crit != nil {
		return nil, errors.New("JWT with crit")
	}
	alg, _ := header.Alg.(string)
	kid, _ := header.Kid.(string)
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("bad JWT signature encoding")
	}
	var h crypto.Hash
	switch alg {
	case "RS256", "PS256", "ES256":
		h = crypto.SHA256
	case "RS384", "ES384":
		h = crypto.SHA384
	case "RS512":
		h = crypto.SHA512
	default:
		return nil, fmt.Errorf("JWT alg %q is not accepted", alg)
	}
	key, err := keyFor(kid)
	if err != nil {
		return nil, err
	}
	hasher := h.New()
	hasher.Write([]byte(parts[0] + "." + parts[1]))
	digest := hasher.Sum(nil)
	switch k := key.(type) {
	case *rsa.PublicKey:
		switch alg[:2] {
		case "RS":
			err = rsa.VerifyPKCS1v15(k, h, digest, sig)
		case "PS":
			err = rsa.VerifyPSS(k, h, digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		default:
			err = errors.New("an RSA key for alg " + alg)
		}
	case *ecdsa.PublicKey:
		size := (k.Curve.Params().BitSize + 7) / 8
		if alg[:2] != "ES" || len(sig) != 2*size || (alg == "ES256") != (size == 32) {
			return nil, errors.New("an EC key for alg " + alg)
		}
		r, s := new(big.Int).SetBytes(sig[:size]), new(big.Int).SetBytes(sig[size:])
		if !ecdsa.Verify(k, digest, r, s) {
			err = errors.New("bad signature")
		}
	default:
		err = errors.New("unsupported key")
	}
	if err != nil {
		return nil, fmt.Errorf("JWT signature: %v", err)
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("bad JWT payload")
	}
	var claims map[string]any
	dec := json.NewDecoder(bytes.NewReader(pb))
	dec.UseNumber()
	if err := dec.Decode(&claims); err != nil {
		return nil, errors.New("bad JWT payload")
	}
	return claims, nil
}

// --- cookies ---

// seal encrypts v for a cookie; purpose and bind are authenticated with it,
// so a cookie is good only for what and whom it was made.
func (a *oidcAuth) seal(purpose, bind string, v any) string {
	plain, _ := json.Marshal(v)
	nonce := make([]byte, a.aead.NonceSize())
	rand.Read(nonce)
	out := a.aead.Seal(nonce, nonce, plain, []byte(purpose+"\x00"+bind))
	return base64.RawURLEncoding.EncodeToString(out)
}

// open reverses seal.
func (a *oidcAuth) open(purpose, bind, value string, v any) bool {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) < a.aead.NonceSize() {
		return false
	}
	plain, err := a.aead.Open(nil, raw[:a.aead.NonceSize()], raw[a.aead.NonceSize():], []byte(purpose+"\x00"+bind))
	return err == nil && json.Unmarshal(plain, v) == nil
}

// oidcSessionCookie is the name of p's session cookie (the provider's name may
// hold characters a cookie name can't).
func oidcSessionCookie(p *OIDCProvider) string {
	h := sha256.Sum256([]byte(p.Name))
	return "__Host-tlsproxy-oidc-" + hex.EncodeToString(h[:6])
}

// sessionBind ties a session to the provider it came from: a change of
// issuer or client signs everyone in again.
func sessionBind(p *OIDCProvider) string { return p.Name + "\x00" + p.Issuer + "\x00" + p.ClientID }

func stateCookie(state string) string { return "__Host-tlsproxy-oidc-st-" + state[:16] }

func setCookie(w http.ResponseWriter, name, value string, maxAge time.Duration) {
	c := &http.Cookie{Name: name, Value: value, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: int(maxAge / time.Second)}
	if maxAge <= 0 {
		c.MaxAge = -1
	}
	http.SetCookie(w, c)
}

// session is the signed-in identity r carries for p, if any and still good.
func (a *oidcAuth) session(r *http.Request, p *OIDCProvider) *oidcIdentity {
	c, err := r.Cookie(oidcSessionCookie(p))
	if err != nil {
		return nil
	}
	var id oidcIdentity
	if !a.open("session", sessionBind(p), c.Value, &id) || a.now().Unix() >= id.Expires {
		return nil
	}
	return &id
}

// stripOIDCCookies takes the proxy's own cookies out of a request before it
// goes on: they are not the backend's.
func stripOIDCCookies(r *http.Request) {
	cookies := r.Cookies()
	keep := cookies[:0]
	for _, c := range cookies {
		if !strings.HasPrefix(c.Name, "__Host-tlsproxy-oidc-") {
			keep = append(keep, c)
		}
	}
	if len(keep) == len(cookies) {
		return
	}
	r.Header.Del("Cookie")
	for _, c := range keep {
		r.AddCookie(c)
	}
}

// --- the flow ---

func oidcToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// isNavigation reports whether r is a browser opening a page, which can
// follow a redirect to the provider and back. Anything else gets 401.
func isNavigation(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead || r.Header.Get("Upgrade") != "" {
		return false
	}
	if mode := r.Header.Get("Sec-Fetch-Mode"); mode != "" {
		return mode == "navigate"
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

func callbackURL(r *http.Request) string { return "https://" + r.Host + oidcCallback }

// oidcPage answers with a small HTML page.
func oidcPage(w http.ResponseWriter, code int, title, msg string, links ...string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	fmt.Fprintf(w, "<!doctype html><meta charset=utf-8><meta name=viewport content=\"width=device-width\"><title>%s</title>"+
		"<body style=\"font:16px system-ui,sans-serif;max-width:40em;margin:3em auto;padding:0 1em\"><h1 style=\"font-size:1.4em\">%s</h1><p>%s</p>",
		html.EscapeString(title), html.EscapeString(title), html.EscapeString(msg))
	for i := 0; i+1 < len(links); i += 2 {
		fmt.Fprintf(w, "<p><a href=\"%s\">%s</a></p>", html.EscapeString(links[i+1]), html.EscapeString(links[i]))
	}
}

// meets reports whether id satisfies route's requirements, and if not, what
// is missing.
func meets(id *oidcIdentity, route *ServiceRoute) (mfa bool, missing string) {
	if route.RequireMFA && !id.MFA {
		return false, "MFA"
	}
	if len(route.RequireGroups) > 0 && !slices.ContainsFunc(route.RequireGroups, func(g string) bool { return slices.Contains(id.Groups, g) }) {
		return true, "group " + strings.Join(route.RequireGroups, " or ")
	}
	if len(route.RequireRoles) > 0 && !slices.ContainsFunc(route.RequireRoles, func(g string) bool { return slices.Contains(id.Roles, g) }) {
		return true, "role " + strings.Join(route.RequireRoles, " or ")
	}
	return true, ""
}

// gate decides a request for an oidc route: the identity when it may go
// on, else nil, having answered it, and why for the log.
func (a *oidcAuth) gate(w http.ResponseWriter, r *http.Request, route *ServiceRoute) (*oidcIdentity, string) {
	p := route.oidc
	id := a.session(r, p)
	stepUp := false
	if id != nil {
		mfaOK, missing := meets(id, route)
		switch {
		case missing == "":
			return id, ""
		case !mfaOK && id.AskedMFA:
			oidcPage(w, http.StatusForbidden, "Multi-factor sign-in required",
				"You signed in as "+id.User+" without a second factor, and this page needs one. The identity provider was asked for one; ask its administrator to require MFA for you or for this application.",
				"Sign out", oidcLogout)
			return nil, "signed in without MFA although asked (" + id.User + ")"
		case !mfaOK:
			stepUp = true // and sign in again, below
		default:
			oidcPage(w, http.StatusForbidden, "Access denied", "You are signed in as "+id.User+", but this page needs "+missing+".", "Sign out", oidcLogout)
			return nil, id.User + " lacks " + missing
		}
	}
	if !isNavigation(r) {
		w.Header().Set("Cache-Control", "no-store")
		http.Error(w, "sign-in required: open this address in a browser", http.StatusUnauthorized)
		return nil, "not signed in"
	}
	c, err := a.client(p)
	if err != nil {
		http.Error(w, "the identity provider is not configured right", http.StatusInternalServerError)
		return nil, err.Error()
	}
	d, err := c.discovery(context.WithoutCancel(r.Context()), a.now())
	if err != nil {
		http.Error(w, "the identity provider can't be reached", http.StatusBadGateway)
		return nil, "discovery: " + err.Error()
	}
	state, verifier := oidcToken(), oidcToken()
	pending := oidcPending{Provider: p.Name, Nonce: oidcToken(), Verifier: verifier, Return: r.URL.RequestURI(), MFA: route.RequireMFA, Expires: a.now().Add(oidcStateTTL).Unix()}
	setCookie(w, stateCookie(state), a.seal("state", state, pending), oidcStateTTL)
	challenge := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {p.ClientID},
		"redirect_uri":          {callbackURL(r)},
		"scope":                 {strings.Join(p.Scopes, " ")},
		"state":                 {state},
		"nonce":                 {pending.Nonce},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(challenge[:])},
		"code_challenge_method": {"S256"},
	}
	if pending.MFA && len(p.MFAAcr) > 0 {
		q.Set("acr_values", strings.Join(p.MFAAcr, " "))
	}
	if id != nil && id.Email != "" {
		q.Set("login_hint", id.Email)
	}
	target := d.Authorize
	if strings.Contains(target, "?") {
		target += "&" + q.Encode()
	} else {
		target += "?" + q.Encode()
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, target, http.StatusFound)
	if stepUp {
		return nil, "to " + p.Name + " to step up to MFA"
	}
	return nil, "to sign in with " + p.Name
}

// handle answers the proxy's own paths under /.tlsproxy/oidc/ on a rule with
// oidc routes; false if path is not one of them.
func (a *oidcAuth) handle(w http.ResponseWriter, r *http.Request, rule *Rule) (bool, string) {
	switch r.URL.Path {
	case oidcCallback:
		return true, a.callback(w, r, rule)
	case oidcLogout:
		return true, a.logout(w, r, rule)
	}
	return false, ""
}

// providersOf are the oidc items rule's routes use, in route order.
func providersOf(rule *Rule) []*OIDCProvider {
	var out []*OIDCProvider
	for _, s := range rule.Routes {
		if s.oidc != nil && !slices.Contains(out, s.oidc) {
			out = append(out, s.oidc)
		}
	}
	return out
}

func (a *oidcAuth) callback(w http.ResponseWriter, r *http.Request, rule *Rule) string {
	q := r.URL.Query()
	state := q.Get("state")
	if state == "" && q.Get("code") == "" && q.Get("error") == "" {
		oidcPage(w, http.StatusOK, "Signed out", "You are signed out.", "Sign in again", "/")
		return " (oidc: signed out)"
	}
	var pending oidcPending
	if len(state) < 16 {
		oidcPage(w, http.StatusBadRequest, "Sign-in failed", "The sign-in response has no valid state.", "Try again", "/")
		return " (oidc: callback without state)"
	}
	ck, err := r.Cookie(stateCookie(state))
	if err != nil || !a.open("state", state, ck.Value, &pending) || a.now().Unix() > pending.Expires {
		oidcPage(w, http.StatusBadRequest, "Sign-in failed", "This sign-in has expired or was started in another browser. Please try again.", "Try again", "/")
		return " (oidc: unknown or expired state)"
	}
	setCookie(w, ck.Name, "", 0)
	back := pending.Return
	if !strings.HasPrefix(back, "/") || strings.HasPrefix(back, "//") || strings.HasPrefix(back, "/\\") {
		back = "/"
	}
	var p *OIDCProvider
	for _, x := range providersOf(rule) {
		if x.Name == pending.Provider {
			p = x
		}
	}
	if p == nil {
		oidcPage(w, http.StatusBadRequest, "Sign-in failed", "The configuration changed while you were signing in. Please try again.", "Try again", back)
		return " (oidc: provider " + pending.Provider + " no longer on this rule)"
	}
	if e := q.Get("error"); e != "" {
		desc := q.Get("error_description")
		oidcPage(w, http.StatusForbidden, "Sign-in failed", "The identity provider said: "+e+": "+desc, "Try again", back)
		return " (oidc: " + e + ")"
	}
	id, err := a.redeem(r, p, &pending, q.Get("code"))
	if err != nil {
		oidcPage(w, http.StatusBadGateway, "Sign-in failed", "The sign-in could not be completed. The proxy's log has the reason.", "Try again", back)
		return " (oidc: " + p.Name + ": " + err.Error() + ")"
	}
	value := a.seal("session", sessionBind(p), id)
	if len(value) > oidcCookieMax { // too many groups: keep the ones that are required somewhere
		keep := func(prefix string, list []string) []string {
			return slices.DeleteFunc(list, func(s string) bool { return !p.referenced[prefix+s] })
		}
		id.Groups, id.Roles = keep("g:", id.Groups), keep("r:", id.Roles)
		value = a.seal("session", sessionBind(p), id)
	}
	setCookie(w, oidcSessionCookie(p), value, time.Duration(id.Expires-a.now().Unix())*time.Second)
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, back, http.StatusFound)
	how := ""
	if id.MFA {
		how = ", mfa"
	}
	return fmt.Sprintf(" (oidc: %s signed in with %s%s)", id.User, p.Name, how)
}

// redeem trades code for an ID token at p's token endpoint and checks it.
func (a *oidcAuth) redeem(r *http.Request, p *OIDCProvider, pending *oidcPending, code string) (*oidcIdentity, error) {
	if code == "" {
		return nil, errors.New("no code")
	}
	c, err := a.client(p)
	if err != nil {
		return nil, err
	}
	now := a.now()
	ctx := context.WithoutCancel(r.Context()) // what is fetched is cached for everyone
	d, err := c.discovery(ctx, now)
	if err != nil {
		return nil, err
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {callbackURL(r)},
		"code_verifier": {pending.Verifier},
		"client_id":     {p.ClientID},
	}
	// A certificate: private_key_jwt. A secret: client_secret_basic, the
	// default, or client_secret_post when that is all the provider lists.
	post := len(d.TokenAuthMethods) > 0 && !slices.Contains(d.TokenAuthMethods, "client_secret_basic") && slices.Contains(d.TokenAuthMethods, "client_secret_post")
	switch {
	case p.clientKey != nil:
		assertion, err := clientAssertion(p, d.Token, now)
		if err != nil {
			return nil, err
		}
		form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		form.Set("client_assertion", assertion)
	case post:
		form.Set("client_secret", p.ClientSecret)
	}
	req, err := http.NewRequestWithContext(r.Context(), "POST", d.Token, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if p.clientKey == nil && !post {
		req.SetBasicAuth(url.QueryEscape(p.ClientID), url.QueryEscape(p.ClientSecret))
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token endpoint: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var tok struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
		Desc    string `json:"error_description"`
	}
	json.Unmarshal(body, &tok)
	if resp.StatusCode != http.StatusOK || tok.IDToken == "" {
		if tok.Error != "" {
			return nil, fmt.Errorf("token endpoint: %s: %s", tok.Error, tok.Desc)
		}
		return nil, fmt.Errorf("token endpoint: %s, no id_token", resp.Status)
	}
	claims, err := verifyJWT(tok.IDToken, func(kid string) (crypto.PublicKey, error) { return c.key(ctx, d, kid, now) })
	if err != nil {
		return nil, err
	}
	return identityFrom(claims, p, d.Issuer, pending, now)
}

// clientAssertion is a private_key_jwt client assertion (RFC 7523) for the
// token endpoint aud: RS256 with the certificate's thumbprint as x5t and
// kid, as Entra and rust-oidc look the certificate up, good for 5 minutes
// and once (jti).
func clientAssertion(p *OIDCProvider, aud string, now time.Time) (string, error) {
	enc := base64.RawURLEncoding.EncodeToString
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "x5t": p.thumbprint, "kid": p.thumbprint})
	claims, _ := json.Marshal(map[string]any{"iss": p.ClientID, "sub": p.ClientID, "aud": aud, "jti": oidcToken(),
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(5 * time.Minute).Unix()})
	in := enc(header) + "." + enc(claims)
	sum := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, p.clientKey, crypto.SHA256, sum[:])
	if err != nil {
		return "", fmt.Errorf("client assertion: %v", err)
	}
	return in + "." + enc(sig), nil
}

// identityFrom checks an ID token's claims and reads who signed in.
func identityFrom(claims map[string]any, p *OIDCProvider, issuer string, pending *oidcPending, now time.Time) (*oidcIdentity, error) {
	str := func(k string) string { s, _ := claims[k].(string); return s }
	list := func(k string) []string {
		switch v := claimAt(claims, k).(type) {
		case string:
			return []string{v}
		case []any:
			var out []string
			for _, x := range v {
				if s, ok := x.(string); ok {
					out = append(out, s)
				}
			}
			return out
		}
		return nil
	}
	unix := func(k string) (int64, bool) {
		n, ok := claims[k].(json.Number)
		if !ok {
			return 0, false
		}
		f, err := n.Float64()
		return int64(f), err == nil
	}
	if iss := str("iss"); iss != issuer {
		return nil, fmt.Errorf("ID token issuer %q, want %q", iss, issuer)
	}
	aud := list("aud")
	if !slices.Contains(aud, p.ClientID) {
		return nil, fmt.Errorf("ID token audience %v does not include client_id %s", aud, p.ClientID)
	}
	if azp := str("azp"); len(aud) > 1 && azp != p.ClientID {
		return nil, fmt.Errorf("ID token azp %q is not client_id %s", azp, p.ClientID)
	}
	exp, ok := unix("exp")
	if !ok || now.Add(-oidcClockSkew).Unix() >= exp {
		return nil, errors.New("ID token expired")
	}
	if iat, ok := unix("iat"); ok && iat > now.Add(oidcClockSkew).Unix() {
		return nil, errors.New("ID token issued in the future")
	}
	if nbf, ok := unix("nbf"); ok && nbf > now.Add(oidcClockSkew).Unix() {
		return nil, errors.New("ID token not valid yet")
	}
	if str("nonce") != pending.Nonce {
		return nil, errors.New("ID token nonce does not match")
	}
	sub := str("sub")
	if sub == "" {
		return nil, errors.New("ID token has no sub")
	}
	id := &oidcIdentity{Subject: sub, Email: str("email"), Groups: list(p.GroupsClaim), Roles: list(p.RolesClaim),
		MFA:    slices.Contains(list("amr"), "mfa") || str("acr") != "" && slices.Contains(p.MFAAcr, str("acr")),
		Issued: now.Unix(), Expires: now.Add(p.Session).Unix()}
	id.AskedMFA = pending.MFA && !id.MFA
	for _, k := range []string{p.UserClaim, "preferred_username", "email", "upn", "sub"} {
		if k != "" && str(k) != "" {
			id.User = str(k)
			break
		}
	}
	return id, nil
}

// claimAt is the claim named path, or, if there is none by that name, the
// value at path read as a dotted path into nested claims: Keycloak's
// realm_access.roles. A name with dots in it (Auth0's
// https://example.com/groups) is found first.
func claimAt(claims map[string]any, path string) any {
	if v, ok := claims[path]; ok {
		return v
	}
	var cur any = claims
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		if cur, ok = m[part]; !ok {
			return nil
		}
	}
	return cur
}

// logout forgets this host's sessions and sends the browser on to the
// provider's end_session_endpoint, if it has one.
func (a *oidcAuth) logout(w http.ResponseWriter, r *http.Request, rule *Rule) string {
	providers := providersOf(rule)
	for _, p := range providers {
		setCookie(w, oidcSessionCookie(p), "", 0)
	}
	w.Header().Set("Cache-Control", "no-store")
	if len(providers) == 1 {
		p := providers[0]
		if c, err := a.client(p); err == nil {
			if d, err := c.discovery(context.WithoutCancel(r.Context()), a.now()); err == nil && d.EndSession != "" {
				q := url.Values{"client_id": {p.ClientID}, "post_logout_redirect_uri": {callbackURL(r)}}
				sep := "?"
				if strings.Contains(d.EndSession, "?") {
					sep = "&"
				}
				http.Redirect(w, r, d.EndSession+sep+q.Encode(), http.StatusFound)
				return " (oidc: signed out, to " + p.Name + ")"
			}
		}
	}
	oidcPage(w, http.StatusOK, "Signed out", "You are signed out here.", "Sign in again", "/")
	return " (oidc: signed out)"
}

// oidcUserKey is the context key of the identity a request goes on with.
type oidcUserKey struct{}

// identityHeaders are set on a request sent on from an oidc route (to who
// signed in), and removed from every other: the backend would believe them.
var identityHeaders = []string{"X-Forwarded-User", "X-Forwarded-Email", "X-Forwarded-Groups", "X-Forwarded-Roles", "X-Forwarded-MFA"}

// setIdentityHeaders writes who signed in (if anyone) into out.
func setIdentityHeaders(out http.Header, id *oidcIdentity) {
	for _, h := range identityHeaders {
		out.Del(h)
	}
	if id == nil {
		return
	}
	// Claims are the provider's text: no control characters in a header.
	clean := func(s string) string {
		return strings.Map(func(r rune) rune {
			if r < 0x20 || r == 0x7f {
				return -1
			}
			return r
		}, s)
	}
	out.Set("X-Forwarded-User", clean(id.User))
	if id.Email != "" {
		out.Set("X-Forwarded-Email", clean(id.Email))
	}
	if len(id.Groups) > 0 {
		out.Set("X-Forwarded-Groups", clean(strings.Join(id.Groups, ",")))
	}
	if len(id.Roles) > 0 {
		out.Set("X-Forwarded-Roles", clean(strings.Join(id.Roles, ",")))
	}
	if id.Subject != "" { // signed in with oidc, not basic_auth
		out.Set("X-Forwarded-MFA", fmt.Sprint(id.MFA))
	}
}
