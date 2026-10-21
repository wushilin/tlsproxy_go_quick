package main

// The web console's settings: given at start-up, never in config.yaml, so
// nothing saved from the console can change them or lock it out.
//
//	-console_domain admin.example.com   or $CONSOLE_DOMAIN   (required)
//	$CONSOLE_PASSWORD                    the password, or its $argon2id$ hash (required)
//	-console_bind 0.0.0.0                or $CONSOLE_BIND     (default: all addresses)
//	-console_port 443                    or $CONSOLE_PORT     (default 443)
//	-console_cert auto                   or $CONSOLE_CERT     (auto | local-ca[:caNNN])
//	-noconsole                           no console at all
//
// The console owns a listener: https on port 443, console_http on any
// other. Its name, bind, port and the rule for the console's domain are
// fixed; config.yaml may list it with other options (proxy_trust_source,
// max_connections, timeouts, speed limits, no bind or port) and route more
// rules to it. Another listener may not have exactly its bind and port.

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// ConsoleConfig is how the console is served.
type ConsoleConfig struct {
	Bind         string   // normalised, as a listener's
	Binds        []string // its addresses
	Port         int
	Domain       string // the name it is served under
	Cert         string // auto | local-ca[:caNNN]
	PasswordHash string // what sign-ins are checked against

	// certificate, when set, is served instead of one from Cert. Only
	// tests set it, for a console in a test whose CAs are its own.
	certificate *tls.Certificate
}

// ListenerName is the name of the listener the console owns.
func (c *ConsoleConfig) ListenerName() string {
	if c.Port == 443 {
		return "https"
	}
	return "console_http"
}

// Addrs is every address the console is reached on.
func (c *ConsoleConfig) Addrs() []string {
	var out []string
	for _, b := range c.Binds {
		out = append(out, net.JoinHostPort(b, strconv.Itoa(c.Port)))
	}
	return out
}

// consoleSetting is one of the console's settings as given: a flag wins
// over its environment variable.
type consoleSetting struct{ flag, env string }

func (s consoleSetting) value(flags map[string]string) string {
	if v, ok := flags[s.flag]; ok {
		return v
	}
	return os.Getenv(s.env)
}

var (
	consoleDomainSetting = consoleSetting{"console_domain", "CONSOLE_DOMAIN"}
	consoleBindSetting   = consoleSetting{"console_bind", "CONSOLE_BIND"}
	consolePortSetting   = consoleSetting{"console_port", "CONSOLE_PORT"}
	consoleCertSetting   = consoleSetting{"console_cert", "CONSOLE_CERT"}
)

// consoleMissing is what to tell someone who started without them.
const consoleMissing = "the web console needs its domain and password: set -console_domain <name> (or $CONSOLE_DOMAIN) and $CONSOLE_PASSWORD, or run with -noconsole"

// ConsoleFromSettings reads the console's settings from flags (by name,
// without the dash) and the environment. The password is hashed here,
// unless it is already a hash.
func ConsoleFromSettings(flags map[string]string) (*ConsoleConfig, error) {
	c := &ConsoleConfig{Bind: "0.0.0.0", Binds: []string{"0.0.0.0"}, Port: 443, Cert: "auto"}
	c.Domain = strings.ToLower(strings.TrimSpace(consoleDomainSetting.value(flags)))
	password := os.Getenv("CONSOLE_PASSWORD")
	switch {
	case c.Domain == "" && password == "":
		return nil, fmt.Errorf("%s", consoleMissing)
	case c.Domain == "":
		return nil, fmt.Errorf("the web console needs its domain: set -console_domain <name> (or $CONSOLE_DOMAIN), or run with -noconsole")
	case password == "":
		return nil, fmt.Errorf("the web console needs a password: set $CONSOLE_PASSWORD (the password, or a hash from tlsproxy --hash-password), or run with -noconsole")
	case !isHostName(c.Domain):
		return nil, fmt.Errorf("console domain %q is not a host name like admin.example.com (no * and no IP address)", c.Domain)
	}
	if v := consoleBindSetting.value(flags); v != "" {
		binds, err := parseBinds(v)
		if err != nil {
			return nil, fmt.Errorf("console bind: %v", err)
		}
		c.Binds, c.Bind = binds, strings.Join(binds, "; ")
	}
	if v := consolePortSetting.value(flags); v != "" {
		port, err := parsePort(v)
		if err != nil {
			return nil, fmt.Errorf("console port: %v", err)
		}
		c.Port = port
	}
	if v := consoleCertSetting.value(flags); v != "" {
		_, local := localCARef(v)
		if !local && !strings.EqualFold(v, "auto") {
			return nil, fmt.Errorf("console cert must be auto or local-ca (local-ca:ca002), got %q", v)
		}
		c.Cert = v
		if strings.EqualFold(v, "auto") {
			c.Cert = "auto"
		}
	}
	if strings.HasPrefix(password, "$argon2id$") || strings.HasPrefix(password, hashPrefix+"$") {
		if err := validHash(password); err != nil {
			return nil, fmt.Errorf("$CONSOLE_PASSWORD looks like a hash, but: %v", err)
		}
		c.PasswordHash = password
	} else {
		hash, err := hashPassword(password)
		if err != nil {
			return nil, err
		}
		c.PasswordHash = hash
	}
	return c, nil
}

// consoleAlias names the console's listener in config.yaml whatever its
// port (https or console_http), so moving the console breaks nothing.
const consoleAlias = "$console"

// resolveConsoleAlias turns $console in listeners and routes into the
// console's listener name. Without a console, $console is an error.
func (cfg *Config) resolveConsoleAlias(con *ConsoleConfig, raws []rawRule) error {
	name := ""
	if con != nil {
		name = con.ListenerName()
	}
	none := func(line int) error {
		return fmt.Errorf("line %d: %s names the web console's listener, and this proxy has no console (-noconsole)", line, consoleAlias)
	}
	for i := range cfg.Listeners {
		if l := &cfg.Listeners[i]; l.Name == consoleAlias {
			if con == nil {
				return none(l.Line)
			}
			l.Name = name
		}
	}
	for i := range raws {
		if r := &raws[i]; r.listener != nil && *r.listener == consoleAlias {
			if con == nil {
				return none(r.line)
			}
			r.listener = &name
		}
	}
	return nil
}

// placeConsoleListener gives the console its listener, before the
// listeners are checked: the one config.yaml lists by that name (with no
// bind or port of its own), or a new one.
func (cfg *Config) placeConsoleListener(con *ConsoleConfig) error {
	if con == nil {
		return nil
	}
	cfg.Console = con
	name := con.ListenerName()
	placed := false
	for i := range cfg.Listeners {
		l := &cfg.Listeners[i]
		if !strings.EqualFold(l.Name, name) {
			continue
		}
		if placed {
			return fmt.Errorf("line %d: the web console's listener (%s, or %s) is listed twice", l.Line, name, consoleAlias)
		}
		if l.bindSet || l.portSet {
			return fmt.Errorf("line %d: listener %s is the web console's: its bind and port come from the console's settings (%s), so leave them out here; its other options apply", l.Line, name, strings.Join(con.Addrs(), ", "))
		}
		l.Name, l.Bind, l.Binds, l.Port, l.Console = name, con.Bind, con.Binds, con.Port, true
		placed = true
	}
	if placed {
		return nil
	}
	cfg.Listeners = append(cfg.Listeners, Listener{Name: name, Bind: con.Bind, Binds: con.Binds, Port: con.Port, Console: true})
	return nil
}

// addConsoleRule adds the console's rule to its listener once config.yaml's
// rules are built. A rule there for the console's exact domain is an error.
func (cfg *Config) addConsoleRule(con *ConsoleConfig) error {
	if con == nil {
		return nil
	}
	name := con.ListenerName()
	for _, r := range cfg.Rules {
		if r.Listener == name && r.Kind == kindLiteral && literalName(r.Source) == con.Domain {
			return fmt.Errorf("rule at line %d: %s is the web console's domain on listener %s, so it can't have a rule of its own there. Use another name, or start the console with another -console_domain", r.Line, con.Domain, name)
		}
	}
	pattern, cert := con.Domain, con.Cert
	if con.certificate != nil {
		cert = "local-ca" // passes the checks; the certificate is con's own
	}
	rule, err := buildRule(cfg, rawRule{listener: &name, pattern: &pattern, cert: &cert, console: true})
	if err != nil {
		return fmt.Errorf("the web console (%s): %v", con.Domain, err)
	}
	rule.fixedCert = con.certificate
	cfg.Rules = append(cfg.Rules, rule)
	return nil
}

// ConsoleRule is the console's rule, nil without a console.
func (c *Config) ConsoleRule() *Rule {
	for i := range c.Rules {
		if c.Rules[i].Console {
			return &c.Rules[i]
		}
	}
	return nil
}

// sameBinds reports whether two bind lists name the same addresses.
func sameBinds(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for _, x := range a {
		found := false
		for _, y := range b {
			found = found || x == y
		}
		if !found {
			return false
		}
	}
	return true
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
