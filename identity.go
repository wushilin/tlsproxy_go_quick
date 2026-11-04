package main

// Vouching for who signed in, to a reverse_proxy target that wants proof:
// a serve entry with identity_secret_file sends, besides the plain
// X-Forwarded-User/-Email/-Groups/-Roles/-Mfa headers, X-OIDC-Assertion: a
// JWT signed with that entry's secret (HS256), good for 60 seconds, for
// this entry (aud) and this request (htm, htu, ip). A target verifies it
// with any JWT library and its secret, and can then trust its claims, or
// the plain headers that say the same. What a client sends in it is
// removed on every serve entry.
//
//	{"iss": "tlsproxy", "aud": "home.example.com/rest/", "sub": "alice@example.com",
//	 "email": "alice@example.com", "groups": ["ops"], "roles": ["Admin"], "mfa": true,
//	 "auth": "oidc:corp", "ip": "203.0.113.7", "htm": "GET", "htu": "/rest/items",
//	 "iat": 1793400000, "exp": 1793400060, "jti": "..."}

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	identityHeader    = "X-OIDC-Assertion"
	identityLifetime  = 60 * time.Second
	identityMinSecret = 32 // characters
)

// readIdentitySecret reads an identity_secret_file: its first line that is
// not empty or a # comment, of at least 32 characters. (A target can keep
// the old secret and the new one while it changes; the proxy signs with
// whatever this file says.)
func readIdentitySecret(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if line = strings.TrimSpace(line); line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(line) < identityMinSecret {
			return nil, fmt.Errorf("%s: the secret must be at least %d characters (make one in the console's rule editor, or with openssl rand -base64 32)", path, identityMinSecret)
		}
		return []byte(line), nil
	}
	return nil, fmt.Errorf("%s holds no secret", path)
}

// identityAssertion is the X-OIDC-Assertion for a request to route of rule
// by id, from client, sent on as method path.
func identityAssertion(rule *Rule, route *ServiceRoute, id *oidcIdentity, client, method, path string, now time.Time) string {
	claims := map[string]any{
		"iss": "tlsproxy", "aud": rule.Source + route.Prefix, "sub": id.User,
		"ip": client, "htm": method, "htu": path,
		"iat": now.Unix(), "exp": now.Add(identityLifetime).Unix(), "jti": oidcToken(),
	}
	if route.oidc != nil {
		claims["auth"] = "oidc:" + route.OIDC
		claims["mfa"] = id.MFA
		claims["groups"], claims["roles"] = nonNil(id.Groups), nonNil(id.Roles)
		if id.Email != "" {
			claims["email"] = id.Email
		}
	} else {
		claims["auth"] = "basic_auth:" + route.BasicAuth
	}
	enc := base64.RawURLEncoding.EncodeToString
	header, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	body, _ := json.Marshal(claims)
	in := enc(header) + "." + enc(body)
	mac := hmac.New(sha256.New, route.identitySecret)
	mac.Write([]byte(in))
	return in + "." + enc(mac.Sum(nil))
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
