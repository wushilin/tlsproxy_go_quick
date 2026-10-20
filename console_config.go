package main

// console.toml: the web console's own file, given with --console. The
// console can edit config.toml but never this file, so no edit made from
// the console can change its password or take it off the network.
//
//	[console]
//	bind = 127.0.0.1              default 127.0.0.1; addresses separated by ;
//	port = 443
//	hostname = admin.example.com  the name it is served under
//	cert = auto                   auto | local-ca[:caNNN]; none: plain HTTP
//	password_hash = $argon2id$...
//
// With cert, the console is served over TLS like a rule with service_rule
// keys: on the [[listener]] of config.toml with exactly this bind and port
// (it gets one more rule there, for hostname, that config.toml cannot
// override), or on a listener of its own when there is none. Without cert,
// it listens on bind:port in plain HTTP, as older versions did.

import (
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
)

// consoleListener is the name of the listener the console gets when no
// [[listener]] has its address.
const consoleListener = "(console)"

// ConsoleConfig is console.toml's [console] section.
type ConsoleConfig struct {
	Bind         string   // normalised, as a listener's
	Binds        []string // its addresses
	Port         int
	Hostname     string   // TLS: the name it is served under; plain HTTP: one more name the Host check accepts
	Cert         string   // "" = plain HTTP; auto | local-ca[:caNNN]
	Password     string   // plaintext, only until the proxy replaces it with PasswordHash
	PasswordHash string   // argon2id or pbkdf2-sha256
	Hostnames    []string // plain HTTP: extra names the console may be addressed by (Host header check)
	SecureCookie bool     // plain HTTP published through TLS termination elsewhere: HTTPS-only cookies

	sourceHash string // exact bytes parsed, for the password rewrite and reload change detection
	Warnings   []string
}

// TLS reports whether the console is served over TLS by this proxy.
func (c *ConsoleConfig) TLS() bool { return c.Cert != "" }

// Addrs is every address the console is reached on.
func (c *ConsoleConfig) Addrs() []string {
	var out []string
	for _, b := range c.Binds {
		out = append(out, net.JoinHostPort(b, strconv.Itoa(c.Port)))
	}
	return out
}

// ParseConsole reads console.toml.
func ParseConsole(text string) (*ConsoleConfig, error) {
	c := &ConsoleConfig{Bind: "127.0.0.1", Binds: []string{"127.0.0.1"}, sourceHash: fileHash([]byte(text))}
	section := ""
	seen := false
	for idx, line := range strings.Split(text, "\n") {
		lineno := idx + 1
		fail := func(format string, a ...any) error {
			return fmt.Errorf("line %d: %s", lineno, fmt.Sprintf(format, a...))
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if section = strings.TrimSpace(strings.Trim(line, "[]")); section != "console" || !strings.HasSuffix(line, "]") || strings.HasPrefix(line, "[[") {
				return nil, fail("%s: this file holds only the [console] section; everything else belongs in config.toml", line)
			}
			seen = true
			continue
		}
		if section != "console" {
			return nil, fail("key outside of [console]")
		}
		key, raw, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fail("expected key = value")
		}
		key = strings.TrimSpace(key)
		value, err := parseValue(raw)
		if err != nil {
			return nil, fail("%v", err)
		}
		switch key {
		case "bind":
			if c.Binds, err = parseBinds(value); err != nil {
				return nil, fail("%v", err)
			}
			c.Bind = strings.Join(c.Binds, "; ")
		case "listen":
			return nil, fail("listen is now called bind, as in [[listener]]: write bind = %s", value)
		case "port":
			if c.Port, err = parsePort(value); err != nil {
				return nil, fail("%v", err)
			}
		case "hostname":
			if c.Hostname = strings.ToLower(value); !isHostName(c.Hostname) {
				return nil, fail("hostname must be a host name like admin.example.com (no * and no IP address), got %q", value)
			}
		case "cert":
			_, local := localCARef(value)
			if !local && !strings.EqualFold(value, "auto") {
				return nil, fail("cert must be auto or local-ca (local-ca:ca002), got %q; leave it out for plain HTTP", value)
			}
			c.Cert = value
			if strings.EqualFold(value, "auto") {
				c.Cert = "auto"
			}
		case "password":
			c.Password = value
		case "password_hash":
			if herr := validHash(value); herr != nil {
				return nil, fail("password_hash: %v", herr)
			}
			c.PasswordHash = value
		case "secure_cookie":
			if c.SecureCookie, err = parseBool(value); err != nil {
				return nil, fail("secure_cookie: %v", err)
			}
		case "hostnames":
			c.Hostnames = splitList(strings.ToLower(value))
		default:
			return nil, fail("unknown key %q in [console]", key)
		}
	}
	switch {
	case !seen:
		return nil, fmt.Errorf("no [console] section")
	case c.Port == 0:
		return nil, fmt.Errorf("[console] port is required")
	case c.Password == "" && c.PasswordHash == "":
		return nil, fmt.Errorf("[console] needs a password: set password = <text> (the proxy replaces it with a hash) or password_hash")
	case c.TLS() && c.Hostname == "":
		return nil, fmt.Errorf("[console] cert = %s needs hostname = <the name you open the console by>: it is served by that name, as a rule of its listener", c.Cert)
	case c.TLS() && len(c.Hostnames) > 0:
		return nil, fmt.Errorf("[console] hostnames only applies without cert (plain HTTP); with cert, the console answers to hostname")
	case c.TLS() && c.SecureCookie:
		return nil, fmt.Errorf("[console] secure_cookie only applies without cert: served over TLS, cookies are HTTPS-only anyway")
	}
	if !c.TLS() {
		for _, b := range c.Binds {
			if ip := net.ParseIP(b); ip == nil || !ip.IsLoopback() {
				c.Warnings = append(c.Warnings, fmt.Sprintf("[console] listens on %s over plain HTTP: the password crosses the network unencrypted. Set cert and hostname to serve it over TLS, or keep bind = 127.0.0.1", b))
				break
			}
		}
	}
	return c, nil
}

// sameBinds reports whether two bind lists name the same addresses.
func sameBinds(a, b []string) bool {
	return slices.Equal(slices.Sorted(slices.Values(a)), slices.Sorted(slices.Values(b)))
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

// applyConsole merges con into cfg once config.toml's rules are built.
// With TLS, the console's rule joins the [[listener]] with exactly its
// bind and port, or a listener of its own; a [[listener]] that only
// partly overlaps it, or a [[host]] for its hostname there, is an error.
// Plain HTTP, it only must not clash with a listener.
func (cfg *Config) applyConsole(con *ConsoleConfig) error {
	if con == nil {
		return nil
	}
	cfg.Console = con
	cfg.Warnings = append(cfg.Warnings, con.Warnings...)
	fail := func(format string, a ...any) error {
		return fmt.Errorf("console.toml: %s", fmt.Sprintf(format, a...))
	}
	var on *Listener
	for _, l := range cfg.PortListeners() {
		if l.Port != con.Port {
			continue
		}
		what := fmt.Sprintf("[[listener]] %s at line %d", l.Name, l.Line)
		if l.IsRedirect {
			what = "the http_to_https_redirect listener"
		}
		a, b, overlap := bindsOverlap(con.Binds, l.Binds)
		switch {
		case !overlap:
			continue
		case !con.TLS():
			return fail("the console (plain HTTP) on %s port %d overlaps %s on %s. Serve the console through that listener instead: set cert and hostname in console.toml, with bind = %s", a, con.Port, what, b, l.Bind)
		case l.IsRedirect || !sameBinds(con.Binds, l.Binds):
			return fail("the console on %s port %d overlaps %s on %s. It joins a listener only with exactly the same addresses: bind = %s", con.Bind, con.Port, what, l.Bind, l.Bind)
		}
		on = l
	}
	if !con.TLS() {
		return nil
	}
	if on == nil {
		cfg.Listeners = append(cfg.Listeners, Listener{Name: consoleListener, Bind: con.Bind, Binds: con.Binds, Port: con.Port})
		on = &cfg.Listeners[len(cfg.Listeners)-1]
	}
	on.Console = true
	for _, r := range cfg.Rules {
		if r.Listener == on.Name && r.Kind == kindLiteral && literalName(r.Source) == con.Hostname {
			return fmt.Errorf("[[host]] at line %d: %s is the console's hostname (console.toml) on listener %s, so it has no rule of its own there. Use another name, or another hostname for the console", r.Line, con.Hostname, on.Name)
		}
	}
	name, pattern, cert := on.Name, con.Hostname, con.Cert
	rule, err := buildRule(cfg, rawRule{listener: &name, pattern: &pattern, cert: &cert, console: true})
	if err != nil {
		return fail("%v", err)
	}
	cfg.Rules = append(cfg.Rules, rule)
	return nil
}

// ConsoleRule is the console's rule, nil if it has none (no console, or
// plain HTTP).
func (c *Config) ConsoleRule() *Rule {
	for i := range c.Rules {
		if c.Rules[i].Console {
			return &c.Rules[i]
		}
	}
	return nil
}
