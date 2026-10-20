package main

// [[local_services]] and [[proxy_pass_rules]]: small HTTP services this
// proxy runs itself, on their own ports, usually behind one of its own
// terminating rules (target_host = 127.0.0.1, target_port = the service's).
//
//	[[local_services]]
//	name = web1                 what proxy_pass_rules refer to
//	type = http_server          http_server (static files) | reverse_proxy
//	bind = 127.0.0.1            default 127.0.0.1
//	port = 1080
//	doc_root = /opt/www/site    http_server only
//	proxy_version = auto        auto | none | v1 | v2: a PROXY header in front
//	proxy_trust_source = ...    who may send one; default loopback only
//	forwarded_proto = https     X-Forwarded-Proto sent upstream (reverse_proxy)
//
//	[[proxy_pass_rules]]
//	server = api                a reverse_proxy service
//	prefix = /asdf/             the longest matching prefix wins
//	target_host = 127.0.0.1
//	target_port = 8888
//	strip_prefix = false
//	force_host = backend.lan    default: the client's Host

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
)

const (
	serviceHTTP  = "http_server"
	serviceProxy = "reverse_proxy"
)

// LocalService is one [[local_services]] section.
type LocalService struct {
	Name  string
	Line  int
	Type  string // serviceHTTP or serviceProxy
	Bind  string
	Binds []string
	Port  int

	DocRoot string // http_server: the folder served
	// ProxyVersion is whether a connection starts with a PROXY protocol
	// header: "auto" (used if present), "none" (never looked for), "v1" or
	// "v2" (required). Only a peer in ProxyTrustSource may send one.
	ProxyVersion     string
	ProxyTrustSource []netip.Prefix
	ForwardedProto   string // reverse_proxy: X-Forwarded-Proto sent upstream

	// PassRules are a reverse_proxy's [[proxy_pass_rules]], the longest
	// prefix first.
	PassRules []*ProxyPassRule
}

// Addrs is every address the service binds.
func (l *LocalService) Addrs() []string {
	var out []string
	for _, b := range l.Binds {
		out = append(out, net.JoinHostPort(b, strconv.Itoa(l.Port)))
	}
	return out
}

// trusts reports whether peer may send a PROXY protocol header.
func (l *LocalService) trusts(peer netip.Addr) bool {
	for _, p := range l.ProxyTrustSource {
		if p.Contains(peer) {
			return true
		}
	}
	return false
}

// Route is the pass rule for a request path, nil if none matches.
func (l *LocalService) Route(path string) *ProxyPassRule {
	for _, r := range l.PassRules {
		if strings.HasPrefix(path, r.Prefix) {
			return r
		}
	}
	return nil
}

// ProxyPassRule is one [[proxy_pass_rules]] section.
type ProxyPassRule struct {
	Line        int
	Server      string // the reverse_proxy service it belongs to
	Prefix      string
	TargetHost  string
	TargetPort  int
	StripPrefix bool
	ForceHost   string // "" = the client's Host
}

// defaultServiceTrust is who may send a PROXY header to a local service
// unless proxy_trust_source says otherwise: this machine only (all of
// 127.0.0.0/8, ::1). Link-local addresses are other machines.
var defaultServiceTrust = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("::1/128"),
}

// serviceOption applies one key of a [[local_services]] section.
func serviceOption(l *LocalService, key, value string) error {
	var err error
	switch key {
	case "name":
		if !listenerName.MatchString(value) {
			return fmt.Errorf("name must be 1-64 letters, digits, spaces or -_@#~()[]<>\"' (no space at either end), got %q", value)
		}
		l.Name = value
	case "type":
		if l.Type = strings.ToLower(value); l.Type != serviceHTTP && l.Type != serviceProxy {
			return fmt.Errorf("type must be %s or %s, got %q", serviceHTTP, serviceProxy, value)
		}
	case "bind":
		if l.Binds, err = parseBinds(value); err == nil {
			l.Bind = strings.Join(l.Binds, "; ")
		}
	case "port":
		l.Port, err = parsePort(value)
	case "doc_root":
		if value == "" {
			return fmt.Errorf("doc_root must not be empty")
		}
		l.DocRoot = value
	case "proxy_version":
		switch v := strings.ToLower(value); v {
		case "auto", "none", "v1", "v2":
			l.ProxyVersion = v
		default:
			return fmt.Errorf("proxy_version must be auto, none, v1 or v2, got %q", value)
		}
	case "proxy_trust_source":
		l.ProxyTrustSource, err = parsePrefixes(value)
	case "proxy_protocol_from":
		return fmt.Errorf("%s", renamedProxyTrust(value))
	case "forwarded_proto":
		if l.ForwardedProto = strings.ToLower(value); l.ForwardedProto != "http" && l.ForwardedProto != "https" {
			return fmt.Errorf("forwarded_proto must be http or https, got %q", value)
		}
	default:
		return fmt.Errorf("unknown key %q in [[local_services]]", key)
	}
	return err
}

// passRuleOption applies one key of a [[proxy_pass_rules]] section.
func passRuleOption(r *ProxyPassRule, key, value string) error {
	var err error
	switch key {
	case "server":
		r.Server = value
	case "prefix":
		if !strings.HasPrefix(value, "/") || strings.ContainsAny(value, "?# \t") {
			return fmt.Errorf("prefix must be a path starting with /, without ? or #, got %q", value)
		}
		r.Prefix = value
	case "target_host":
		if strings.Contains(value, ":") {
			if _, perr := netip.ParseAddr(value); perr != nil {
				return fmt.Errorf("target_host %q must not contain a port: use target_port (an IPv6 address is written without brackets)", value)
			}
		} else if value == "" || strings.IndexFunc(value, func(c rune) bool { return c > 0x7f || !isHostChar(byte(c)) }) >= 0 {
			return fmt.Errorf("target_host %q is not a host name or an IP address", value)
		}
		r.TargetHost = value
	case "target_port":
		r.TargetPort, err = parsePort(value)
	case "strip_prefix":
		if r.StripPrefix, err = parseBool(value); err != nil {
			err = fmt.Errorf("strip_prefix: %v", err)
		}
	case "force_host":
		if value == "" || strings.ContainsAny(value, " \t/\\@") {
			return fmt.Errorf("force_host must be a host name (with an optional :port), got %q", value)
		}
		r.ForceHost = value
	default:
		return fmt.Errorf("unknown key %q in [[proxy_pass_rules]]", key)
	}
	return err
}

// resolveServices checks the [[local_services]] and [[proxy_pass_rules]]
// sections once the listeners and [console] are known: names, types, ports
// that clash with anything else this proxy opens, and which service each
// pass rule belongs to.
func (c *Config) resolveServices() error {
	type port struct {
		what  string
		binds []string
		port  int
	}
	var taken []port
	for _, l := range c.PortListeners() {
		what := fmt.Sprintf("[[listener]] %s at line %d", l.Name, l.Line)
		if l.IsRedirect {
			what = "http_to_https_redirect"
		}
		taken = append(taken, port{what, l.Binds, l.Port})
	}
	if c.Console != nil {
		taken = append(taken, port{"[console]", []string{c.Console.Listen}, c.Console.Port})
	}
	for i := range c.Services {
		l := &c.Services[i]
		fail := func(format string, a ...any) error {
			return fmt.Errorf("[[local_services]] at line %d: %s", l.Line, fmt.Sprintf(format, a...))
		}
		switch {
		case l.Name == "":
			return fail("name is required")
		case l.Type == "":
			return fail("type is required: %s or %s", serviceHTTP, serviceProxy)
		case l.Port == 0:
			return fail("port is required")
		case l.Type == serviceHTTP && l.DocRoot == "":
			return fail("type = %s needs doc_root, the folder it serves", serviceHTTP)
		case l.Type != serviceHTTP && l.DocRoot != "":
			return fail("doc_root only applies to type = %s", serviceHTTP)
		case l.Type != serviceProxy && l.ForwardedProto != "":
			return fail("forwarded_proto only applies to type = %s", serviceProxy)
		}
		if l.ProxyVersion == "" {
			l.ProxyVersion = "auto"
		}
		if l.ForwardedProto == "" {
			l.ForwardedProto = "https"
		}
		if l.ProxyTrustSource == nil {
			l.ProxyTrustSource = defaultServiceTrust
		}
		for _, prev := range c.Services[:i] {
			if strings.EqualFold(prev.Name, l.Name) {
				return fail("the name %s is already used at line %d (names are compared ignoring case)", l.Name, prev.Line)
			}
		}
		for _, t := range taken {
			if a, b, ok := bindsOverlap(l.Binds, t.binds); ok && l.Port == t.port {
				return fail("%s port %d overlaps %s on %s", a, l.Port, t.what, b)
			}
		}
		taken = append(taken, port{fmt.Sprintf("[[local_services]] %s at line %d", l.Name, l.Line), l.Binds, l.Port})
	}
	for i := range c.PassRules {
		r := &c.PassRules[i]
		fail := func(format string, a ...any) error {
			return fmt.Errorf("[[proxy_pass_rules]] at line %d: %s", r.Line, fmt.Sprintf(format, a...))
		}
		var svc *LocalService
		for j := range c.Services {
			if c.Services[j].Name == r.Server {
				svc = &c.Services[j]
			}
		}
		switch {
		case r.Server == "":
			return fail("server = <name> is required: the reverse_proxy service it belongs to")
		case svc == nil:
			return fail("server = %s: there is no [[local_services]] named %s", r.Server, r.Server)
		case svc.Type != serviceProxy:
			return fail("server = %s is a %s; proxy_pass_rules belong to a %s", r.Server, svc.Type, serviceProxy)
		case r.Prefix == "":
			return fail("prefix is required, e.g. prefix = / for everything")
		case r.TargetHost == "":
			return fail("target_host is required")
		case r.TargetPort == 0:
			return fail("target_port is required")
		}
		for _, prev := range svc.PassRules {
			if prev.Prefix == r.Prefix {
				return fail("prefix %s already has a rule for %s at line %d", r.Prefix, r.Server, prev.Line)
			}
		}
		svc.PassRules = append(svc.PassRules, r)
	}
	for i := range c.Services {
		l := &c.Services[i]
		sort.SliceStable(l.PassRules, func(a, b int) bool { return len(l.PassRules[a].Prefix) > len(l.PassRules[b].Prefix) })
		if l.Type == serviceProxy && len(l.PassRules) == 0 {
			c.Warnings = append(c.Warnings, fmt.Sprintf("[[local_services]] %s at line %d has no [[proxy_pass_rules]] (server = %s): it answers every request with 404", l.Name, l.Line, l.Name))
		}
		if l.ProxyVersion == "none" && !slices.Equal(l.ProxyTrustSource, defaultServiceTrust) {
			c.Warnings = append(c.Warnings, fmt.Sprintf("[[local_services]] %s at line %d: proxy_trust_source does nothing with proxy_version = none", l.Name, l.Line))
		}
	}
	c.warnServiceTargets()
	return nil
}

// warnServiceTargets points out [[host]] rules whose PROXY setting does not
// suit the local service they connect to.
func (c *Config) warnServiceTargets() {
	for i := range c.Rules {
		r := &c.Rules[i]
		host, err := netip.ParseAddr(r.TargetHost)
		if !r.Allow || err != nil {
			continue
		}
		host = host.Unmap()
		for j := range c.Services {
			l := &c.Services[j]
			if l.Port != r.TargetPort || !slices.ContainsFunc(l.Binds, func(b string) bool {
				a, err := netip.ParseAddr(b)
				return err == nil && (a.Unmap() == host || a.IsUnspecified())
			}) {
				continue
			}
			where := fmt.Sprintf("[[host]] at line %d connects to [[local_services]] %s", r.Line, l.Name)
			switch {
			case r.Proxy && l.ProxyVersion == "none":
				c.Warnings = append(c.Warnings, where+" with proxy = true, but the service has proxy_version = none: the header would reach it as part of the request")
			case !r.Proxy && (l.ProxyVersion == "v1" || l.ProxyVersion == "v2"):
				c.Warnings = append(c.Warnings, fmt.Sprintf("%s without proxy = true, but the service requires a PROXY %s header: every connection would be dropped", where, l.ProxyVersion))
			case r.Proxy && l.ProxyVersion != "auto" && l.ProxyVersion != "v"+strconv.Itoa(r.ProxyVersion):
				c.Warnings = append(c.Warnings, fmt.Sprintf("%s with proxy_version = %d, but the service requires %s", where, r.ProxyVersion, l.ProxyVersion))
			case r.Proxy && !host.IsLoopback() && !l.trusts(host):
				c.Warnings = append(c.Warnings, fmt.Sprintf("%s at %s with proxy = true, but the service only trusts PROXY headers from its proxy_trust_source, which does not cover %s", where, host, host))
			}
		}
	}
}

// bindsOverlap reports whether two bind lists share an address (a wildcard
// address overlaps everything), and which.
func bindsOverlap(a, b []string) (string, string, bool) {
	for _, x := range a {
		for _, y := range b {
			if x == y || isWildcard(x) || isWildcard(y) {
				return x, y, true
			}
		}
	}
	return "", "", false
}
