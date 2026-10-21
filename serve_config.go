package main

// A rule's serve list, and basic_auth. A rule with serve entries answers
// HTTP itself, inside the TLS connection it terminates: no target, no
// extra hop.
//
//	routes:
//	  - listener: https
//	    rules:
//	      - domain: www.example.com
//	        cert: auto
//	        serve:
//	          - {type: reverse_proxy, prefix: /api/, target: "http://127.0.0.1:8080", strip_prefix: true}
//	          - {type: static_content, prefix: /, base_dir: /opt/www/site, basic_auth: team}
//	basic_auth:
//	  - name: team
//	    users:
//	      - {username: jack, password_hash: "$argon2id$v=19$m=65536,t=3,p=4$..."}
//	      - {username: jill, password_plain: secret}
//
// The longest matching prefix serves a request.

import (
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
)

const (
	routeProxy  = "reverse_proxy"
	routeStatic = "static_content"
)

// ServiceRoute is one serve entry of a rule.
type ServiceRoute struct {
	Key         string // which entry it is, for messages: "serve 2"
	Line        int
	Type        string // routeProxy or routeStatic
	Prefix      string // the request path it takes, starting with /
	Target      *url.URL
	StripPrefix bool   // reverse_proxy: the prefix is cut from the path sent on
	ForceHost   string // reverse_proxy: the Host sent on; "" = the client's
	TLSVerify   bool   // reverse_proxy to https://: verify the target's certificate
	BaseDir     string // static_content: the folder the prefix stands for
	BasicAuth   string // the basic_auth that guards it; "" = none
	auth        *BasicAuth
}

// TargetAddr is the host:port a reverse_proxy route connects to.
func (s *ServiceRoute) TargetAddr() string {
	if s.Target.Port() != "" {
		return s.Target.Host
	}
	port := "80"
	if s.Target.Scheme == "https" {
		port = "443"
	}
	return net.JoinHostPort(s.Target.Hostname(), port)
}

// Describe is the route as one line, for logs and the console.
func (s *ServiceRoute) Describe() string {
	out := s.Prefix + " → "
	if s.Type == routeStatic {
		out += s.BaseDir
	} else {
		out += s.Target.String()
	}
	if s.BasicAuth != "" {
		out += " (basic_auth " + s.BasicAuth + ")"
	}
	return out
}

// rawServiceRule is a serve entry as written, parsed once the rule is.
type rawServiceRule struct {
	key  string
	opts [][2]string // its keys and values, in order
	line int
}

// parseServiceRule reads one serve entry.
func parseServiceRule(key string, opts [][2]string, line int) (*ServiceRoute, error) {
	s := &ServiceRoute{Key: key, Line: line, TLSVerify: true}
	seen := map[string]bool{}
	var verify *bool
	for _, kv := range opts {
		k, v := strings.ToLower(kv[0]), strings.TrimSpace(kv[1])
		if seen[k] {
			return nil, fmt.Errorf("%s is given twice", k)
		}
		seen[k] = true
		var err error
		switch k {
		case "type":
			if s.Type = strings.ToLower(v); s.Type != routeProxy && s.Type != routeStatic {
				return nil, fmt.Errorf("type must be %s or %s, got %q", routeProxy, routeStatic, v)
			}
		case "prefix":
			if !strings.HasPrefix(v, "/") || strings.ContainsAny(v, "?# \t") {
				return nil, fmt.Errorf("prefix must be a path starting with /, without ? or #, got %q", v)
			}
			s.Prefix = v
		case "target":
			if s.Target, err = parseTarget(v); err != nil {
				return nil, fmt.Errorf("target: %v", err)
			}
		case "strip_prefix":
			if s.StripPrefix, err = parseBool(v); err != nil {
				return nil, fmt.Errorf("strip_prefix: %v", err)
			}
		case "force_host":
			if v == "" || strings.ContainsAny(v, " \t/\\@") {
				return nil, fmt.Errorf("force_host must be a host name (with an optional :port), got %q", v)
			}
			s.ForceHost = v
		case "tls_verify":
			b, err := parseBool(v)
			if err != nil {
				return nil, fmt.Errorf("tls_verify: %v", err)
			}
			verify, s.TLSVerify = &b, b
		case "base_dir":
			if v == "" {
				return nil, fmt.Errorf("base_dir must not be empty")
			}
			s.BaseDir = v
		case "basic_auth":
			if v == "" {
				return nil, fmt.Errorf("basic_auth must name a basic_auth item")
			}
			s.BasicAuth = v
		default:
			return nil, fmt.Errorf("unknown key %q in a serve entry (type, prefix, target, strip_prefix, force_host, tls_verify, base_dir, basic_auth)", k)
		}
	}
	only := func(opt, typ string) error {
		if seen[opt] && s.Type != typ {
			return fmt.Errorf("%s only applies to type: %s", opt, typ)
		}
		return nil
	}
	switch {
	case s.Type == "":
		return nil, fmt.Errorf("type is required: %s or %s", routeProxy, routeStatic)
	case s.Prefix == "":
		return nil, fmt.Errorf("prefix is required, e.g. prefix: / for everything")
	case s.Type == routeProxy && s.Target == nil:
		return nil, fmt.Errorf("type: %s needs target: http://host:port (or https://)", routeProxy)
	case s.Type == routeStatic && s.BaseDir == "":
		return nil, fmt.Errorf("type: %s needs base_dir, the folder the prefix stands for", routeStatic)
	case s.Type == routeStatic && !strings.HasSuffix(s.Prefix, "/"):
		return nil, fmt.Errorf("a %s prefix is a folder and ends with /, got %q", routeStatic, s.Prefix)
	case verify != nil && s.Target != nil && s.Target.Scheme != "https":
		return nil, fmt.Errorf("tls_verify only applies to an https:// target")
	}
	for _, opt := range []string{"target", "strip_prefix", "force_host", "tls_verify"} {
		if err := only(opt, routeProxy); err != nil {
			return nil, err
		}
	}
	if err := only("base_dir", routeStatic); err != nil {
		return nil, err
	}
	return s, nil
}

// parseTarget reads a reverse_proxy target: http:// or https://, a host
// and an optional port, nothing else.
func parseTarget(v string) (*url.URL, error) {
	u, err := url.Parse(v)
	switch {
	case err != nil:
		return nil, err
	case u.Scheme != "http" && u.Scheme != "https":
		return nil, fmt.Errorf("%q must start with http:// or https://", v)
	case u.Hostname() == "":
		return nil, fmt.Errorf("%q has no host", v)
	case u.User != nil:
		return nil, fmt.Errorf("%q: no user:password@ in a target", v)
	case u.Path != "" && u.Path != "/", u.RawQuery != "", u.Fragment != "":
		return nil, fmt.Errorf("%q: a target is scheme://host:port only; the request's path is sent as it is (or without the prefix, with strip_prefix: true)", v)
	}
	if p := u.Port(); p != "" {
		if _, err := parsePort(p); err != nil {
			return nil, err
		}
	}
	u.Path = ""
	return u, nil
}

// BasicAuth is one basic_auth item.
type BasicAuth struct {
	Name  string
	Line  int
	Users map[string]credential // by username
}

// credential is one user's password: plain, or a hash checkPassword reads.
type credential struct {
	plain, hash string
}

// addUser adds one item of a basic_auth's users.
func addUser(a *BasicAuth, opts [][2]string) error {
	var user string
	var cred credential
	for _, kv := range opts {
		switch k, v := kv[0], strings.TrimSpace(kv[1]); k {
		case "username":
			if user = v; user == "" || strings.Contains(user, ":") {
				return fmt.Errorf("username must be non-empty and without a colon")
			}
		case "password_plain":
			cred.plain = v
		case "password_hash":
			cred.hash = v
		default:
			return fmt.Errorf("unknown key %q in a user (username, password_plain, password_hash)", k)
		}
	}
	switch {
	case user == "":
		return fmt.Errorf("username is required")
	case cred.plain == "" && cred.hash == "":
		return fmt.Errorf("user %s: password_plain or password_hash is required (make a hash with tlsproxy --hash-password)", user)
	case cred.plain != "" && cred.hash != "":
		return fmt.Errorf("user %s: give password_plain or password_hash, not both", user)
	}
	if cred.hash != "" {
		if err := validHash(cred.hash); err != nil {
			return fmt.Errorf("user %s: password_hash: %v", user, err)
		}
	}
	if _, dup := a.Users[user]; dup {
		return fmt.Errorf("user %s is listed twice", user)
	}
	a.Users[user] = cred
	return nil
}

// resolveServe checks the serve entries once every section is read: the
// basic_auth each names, and prefixes given twice. The longest prefix comes
// first, so the first that matches a request is the one that serves it.
func (c *Config) resolveServe(auths []*BasicAuth) error {
	c.BasicAuth = map[string]*BasicAuth{}
	for _, a := range auths {
		if a.Name == "" {
			return fmt.Errorf("basic_auth at line %d: name is required", a.Line)
		}
		if len(a.Users) == 0 {
			return fmt.Errorf("basic_auth at line %d (%s): no users; add users: [{username: ..., password_hash: ...}]", a.Line, a.Name)
		}
		if prev := c.BasicAuth[a.Name]; prev != nil {
			return fmt.Errorf("basic_auth at line %d: the name %s is already used at line %d", a.Line, a.Name, prev.Line)
		}
		c.BasicAuth[a.Name] = a
	}
	used := map[string]bool{}
	for i := range c.Rules {
		r := &c.Rules[i]
		for _, s := range r.Routes {
			if s.BasicAuth == "" {
				continue
			}
			if s.auth = c.BasicAuth[s.BasicAuth]; s.auth == nil {
				return fmt.Errorf("rule at line %d: %s: basic_auth: %s: there is no basic_auth named %s", r.Line, s.Key, s.BasicAuth, s.BasicAuth)
			}
			used[s.BasicAuth] = true
		}
	}
	for name, a := range c.BasicAuth {
		if !used[name] {
			c.Warnings = append(c.Warnings, fmt.Sprintf("basic_auth %s at line %d is not used by any serve entry", name, a.Line))
		}
	}
	return nil
}

// serveSettings turns a rule's serve list into its routes. A rule with
// routes serves HTTP itself, so it has no target and nothing upstream.
func serveSettings(rule *Rule, r *rawRule) error {
	if len(r.serviceRules) == 0 {
		return nil
	}
	for _, kv := range []struct {
		name string
		v    *string
	}{{"target", r.target}, {"upstream_tls", r.upstreamTLS}, {"upstream_tls_verify", r.upstreamVerify},
		{"upstream_sni", r.upstreamSNI}, {"proxy", r.proxy}} {
		if kv.v != nil {
			return fmt.Errorf("%s does not apply to a rule with serve: it answers the requests itself (each serve entry says where they go)", kv.name)
		}
	}
	if r.action != nil && !strings.EqualFold(*r.action, "allow") {
		return fmt.Errorf("serve needs action: allow (or no action)")
	}
	if r.cert == nil || *r.cert == "" {
		return fmt.Errorf("serve needs cert: auto or cert: local-ca: the proxy has to decrypt the requests to serve them")
	}
	for _, raw := range r.serviceRules {
		s, err := parseServiceRule(raw.key, raw.opts, raw.line)
		if err != nil {
			return fmt.Errorf("%s (line %d): %v", raw.key, raw.line, err)
		}
		for _, prev := range rule.Routes {
			if prev.Prefix == s.Prefix {
				return fmt.Errorf("%s (line %d): prefix %s is already served by %s (line %d)", raw.key, raw.line, s.Prefix, prev.Key, prev.Line)
			}
		}
		rule.Routes = append(rule.Routes, s)
	}
	sort.SliceStable(rule.Routes, func(a, b int) bool { return len(rule.Routes[a].Prefix) > len(rule.Routes[b].Prefix) })
	return nil
}

// Serves reports whether the rule serves HTTP itself: it has service rules,
// or it is the console's.
func (r *Rule) Serves() bool { return len(r.Routes) > 0 || r.Console }

// RouteFor is the service rule for a request path, nil if none matches.
func (r *Rule) RouteFor(path string) *ServiceRoute {
	for _, s := range r.Routes {
		if strings.HasPrefix(path, s.Prefix) {
			return s
		}
	}
	return nil
}
