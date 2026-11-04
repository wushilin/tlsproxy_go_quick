package main

// Checking an oidc item against its provider without anyone signing in:
// what tlsproxy --test-oidc and the console's Config page (Check OIDC) show.
// It fetches the discovery document and the signing keys, compares what the
// item asks for with what the provider says it supports, and tries the
// client's credentials at the token endpoint (see credentialCheck). The redirect URIs to register are listed, not checked:
// that needs a browser.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// oidcCheck is one finding: ok, warn (works, but look) or fail.
type oidcCheck struct {
	Level  string `json:"level"`
	What   string `json:"what"`
	Detail string `json:"detail"`
}

// oidcReport is what checking one oidc item found.
type oidcReport struct {
	Name   string      `json:"name"`
	Issuer string      `json:"issuer"`
	OK     bool        `json:"ok"` // no fail
	Checks []oidcCheck `json:"checks"`
}

// checkOIDCConfig checks the oidc items of cfg (only those named, if any).
func checkOIDCConfig(ctx context.Context, cfg *Config, names []string) ([]oidcReport, error) {
	var out []oidcReport
	for _, name := range names {
		if cfg.OIDC[name] == nil {
			return nil, fmt.Errorf("there is no oidc item named %s", name)
		}
	}
	for _, name := range sortedKeys(cfg.OIDC) {
		if len(names) == 0 || slices.Contains(names, name) {
			out = append(out, checkOIDC(ctx, cfg, cfg.OIDC[name]))
		}
	}
	return out, nil
}

// checkOIDC checks one oidc item against its provider.
func checkOIDC(ctx context.Context, cfg *Config, p *OIDCProvider) oidcReport {
	rep := oidcReport{Name: p.Name, Issuer: p.Issuer, OK: true}
	add := func(level, what, format string, a ...any) {
		rep.Checks = append(rep.Checks, oidcCheck{level, what, fmt.Sprintf(format, a...)})
		if level == "fail" {
			rep.OK = false
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	// A client of its own: nothing cached, nothing left behind.
	c, err := (&oidcAuth{clients: map[string]*oidcClient{}}).client(p)
	if err != nil {
		add("fail", "ca_file", "%v", err)
		return rep
	}

	var doc map[string]any
	if err := c.getJSON(ctx, p.Issuer+"/.well-known/openid-configuration", &doc); err != nil {
		add("fail", "discovery", "%v", err)
		return rep
	}
	d, err := c.discovery(ctx, time.Now())
	if err != nil {
		add("fail", "discovery", "%v", err)
		return rep
	}
	if d.Issuer == p.Issuer {
		add("ok", "discovery", "%s/.well-known/openid-configuration", p.Issuer)
	} else {
		add("ok", "discovery", "the tokens' issuer is %s (the document's), not the configured %s; that is how rust-oidc and Entra name a tenant, and it is what is checked", d.Issuer, p.Issuer)
	}
	strs := func(k string) []string {
		var out []string
		if list, ok := doc[k].([]any); ok {
			for _, v := range list {
				if s, ok := v.(string); ok {
					out = append(out, s)
				}
			}
		}
		return out
	}
	if rt := strs("response_types_supported"); len(rt) > 0 && !slices.Contains(rt, "code") {
		add("fail", "response type", "the provider does not offer response_type=code (it offers %s)", strings.Join(rt, ", "))
	}
	if m := strs("code_challenge_methods_supported"); len(m) > 0 && !slices.Contains(m, "S256") {
		add("fail", "PKCE", "the provider does not offer S256 PKCE (it offers %s)", strings.Join(m, ", "))
	}
	if d.EndSession == "" {
		add("warn", "logout", "no end_session_endpoint: /.tlsproxy/oidc/logout forgets the session here, and the provider's own session lasts")
	}

	// The signing keys.
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := c.getJSON(ctx, d.JWKS, &set); err != nil {
		add("fail", "signing keys", "%v", err)
	} else {
		usable := 0
		for _, raw := range set.Keys {
			if _, _, err := parseJWK(raw); err == nil {
				usable++
			}
		}
		if usable == 0 {
			add("fail", "signing keys", "%s has no RSA or EC signing key this proxy can check tokens with (%d keys)", d.JWKS, len(set.Keys))
		} else {
			add("ok", "signing keys", "%d usable of %d at %s", usable, len(set.Keys), d.JWKS)
		}
	}
	if algs := strs("id_token_signing_alg_values_supported"); len(algs) > 0 && !slices.ContainsFunc(algs, func(a string) bool {
		return slices.Contains([]string{"RS256", "RS384", "RS512", "PS256", "ES256", "ES384"}, a)
	}) {
		add("fail", "token signatures", "the provider signs ID tokens with %s; this proxy checks RS256/384/512, PS256, ES256/384", strings.Join(algs, ", "))
	}

	// What the item asks for.
	method := "client_secret_basic"
	if p.clientKey != nil {
		method = "private_key_jwt"
	} else if len(d.TokenAuthMethods) > 0 && !slices.Contains(d.TokenAuthMethods, "client_secret_basic") && slices.Contains(d.TokenAuthMethods, "client_secret_post") {
		method = "client_secret_post"
	}
	if len(d.TokenAuthMethods) > 0 && !slices.Contains(d.TokenAuthMethods, method) {
		add("fail", "client authentication", "the proxy would use %s; the provider offers %s", method, strings.Join(d.TokenAuthMethods, ", "))
	}
	if sup := strs("scopes_supported"); len(sup) > 0 {
		var missing []string
		for _, s := range p.Scopes {
			if !slices.Contains(sup, s) {
				missing = append(missing, s)
			}
		}
		if len(missing) > 0 {
			add("warn", "scopes", "the provider does not list %s among its scopes_supported (it may still accept them)", strings.Join(missing, ", "))
		}
	}
	if len(p.MFAAcr) > 0 {
		if sup := strs("acr_values_supported"); len(sup) > 0 && !slices.ContainsFunc(p.MFAAcr, func(a string) bool { return slices.Contains(sup, a) }) {
			add("warn", "mfa_acr_values", "the provider's acr_values_supported are %s, none of %s", strings.Join(sup, ", "), strings.Join(p.MFAAcr, ", "))
		}
	} else if requiresMFA(cfg, p) {
		add("warn", "mfa_acr_values", "a serve entry has require_mfa, but no mfa_acr_values: a session without MFA can't ask the provider for it (and gets 403); the provider can still require MFA itself")
	}

	// The credentials, with a code that does not exist.
	add(credentialCheck(ctx, c, p, d, method))

	// Where the provider must send browsers back to.
	var uris []string
	for i := range cfg.Rules {
		r := &cfg.Rules[i]
		for _, s := range r.Routes {
			if s.oidc != p {
				continue
			}
			if u := callbackFor(cfg, r); u == "" {
				add("warn", "redirect URI", "rule at line %d (%s) matches more than one name: register https://<each name>/.tlsproxy/oidc/callback", r.Line, r.Source)
			} else if !slices.Contains(uris, u) {
				uris = append(uris, u)
			}
		}
	}
	if len(uris) > 0 {
		add("ok", "redirect URIs", "register as web redirect URIs: %s", strings.Join(uris, " "))
	} else if c := callbackCandidates(cfg); len(c) > 0 {
		add("warn", "redirect URIs", "no serve entry uses it yet; register the URI of each site you will use it on: %s", strings.Join(c, " "))
	}
	return rep
}

// requiresMFA reports whether a serve entry with p requires MFA.
func requiresMFA(cfg *Config, p *OIDCProvider) bool {
	for _, r := range cfg.Rules {
		for _, s := range r.Routes {
			if s.oidc == p && s.RequireMFA {
				return true
			}
		}
	}
	return false
}

// credentialCheck tries p's client credentials at the token endpoint: the
// level, what and detail of the finding. First with a made-up code: a
// provider that checks the client first (RFC 6749 5.2) answers
// invalid_client for a client it refuses, invalid_grant (for the code) for
// one it accepts. Some look the code up first (rust-oidc and Entra: the
// code says whether the client must authenticate at all) and answer
// invalid_grant either way; then the client_credentials grant, which only
// a client can use, decides: invalid_client, or past the client to the
// scope (openid is not one it gives out).
func credentialCheck(ctx context.Context, c *oidcClient, p *OIDCProvider, d *oidcDiscovery, method string) (string, string, string) {
	what := "client credentials (" + method + ")"
	status, code, said, err := tokenProbe(ctx, c, p, d, method, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"tlsproxy-check-" + oidcToken()},
		"redirect_uri":  {"https://tlsproxy.invalid" + oidcCallback},
		"code_verifier": {oidcToken() + oidcToken()},
	})
	switch {
	case err != nil:
		return "fail", what, err.Error()
	case code == "invalid_client" || status == http.StatusUnauthorized:
		return "fail", what, "refused: " + orStatus(said, http.StatusText(status))
	case code != "invalid_grant":
		return "warn", what, "can't tell: for a made-up code the provider answered " + orStatus(said, http.StatusText(status))
	}
	status, code, said, err = tokenProbe(ctx, c, p, d, method, url.Values{"grant_type": {"client_credentials"}, "scope": {"openid"}})
	switch {
	case err != nil:
		return "fail", what, err.Error()
	case code == "invalid_client" || status == http.StatusUnauthorized:
		return "fail", what, "refused: " + orStatus(said, http.StatusText(status))
	case status == http.StatusOK:
		return "ok", what, "accepted (the provider gave the client a token of its own; it was not used)"
	case code == "invalid_scope" || code == "invalid_request":
		return "ok", what, "accepted (the provider then refused the check's scope, as it should)"
	}
	return "warn", what, "can't tell: the provider answered " + orStatus(said, http.StatusText(status)) + " (it may not allow this client the client_credentials grant, which the check uses)"
}

// tokenProbe posts form to the token endpoint with p's credentials: the
// status and the error it answered with.
func tokenProbe(ctx context.Context, c *oidcClient, p *OIDCProvider, d *oidcDiscovery, method string, form url.Values) (int, string, string, error) {
	form.Set("client_id", p.ClientID)
	switch method {
	case "private_key_jwt":
		a, err := clientAssertion(p, d.Token, time.Now())
		if err != nil {
			return 0, "", "", err
		}
		form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		form.Set("client_assertion", a)
	case "client_secret_post":
		form.Set("client_secret", p.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", d.Token, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, "", "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if method == "client_secret_basic" {
		req.SetBasicAuth(url.QueryEscape(p.ClientID), url.QueryEscape(p.ClientSecret))
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, "", "", fmt.Errorf("token endpoint: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	var e struct {
		Error string `json:"error"`
		Desc  string `json:"error_description"`
	}
	json.Unmarshal(body, &e)
	said := e.Error
	if e.Desc != "" {
		said += ": " + e.Desc
	}
	return resp.StatusCode, e.Error, said, nil
}

func orStatus(said, status string) string {
	if said != "" {
		return said
	}
	return status
}

// formatOIDCReports is reports as text, for tlsproxy --test-oidc.
func formatOIDCReports(reports []oidcReport) string {
	var b strings.Builder
	mark := map[string]string{"ok": "ok  ", "warn": "WARN", "fail": "FAIL"}
	for i, r := range reports {
		if i > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "oidc %s (%s)\n", r.Name, r.Issuer)
		for _, c := range r.Checks {
			fmt.Fprintf(&b, "  %s %s: %s\n", mark[c.Level], c.What, c.Detail)
		}
	}
	return b.String()
}
