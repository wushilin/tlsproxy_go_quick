package main

// The web console's settings: given at start-up, never in config.yaml, so
// nothing saved from the console can change them or lock it out.
//
//	-console_domain admin.example.com   or $CONSOLE_DOMAIN   (default: none, see below)
//	$CONSOLE_PASSWORD                    the password, or its $argon2id$ hash (required)
//	-console_bind 0.0.0.0                or $CONSOLE_BIND     (default: all addresses)
//	-console_port 443                    or $CONSOLE_PORT     (default 443)
//	-console_cert auto                   or $CONSOLE_CERT     (auto | local-ca[:caNNN]; default
//	                                                           auto, local-ca without a host name)
//	-noconsole                           no console at all
//
// Without a domain (or with none, or $no_sni) the console is its listener's
// $no_sni rule: clients that send no name, by the address they connected to,
// with a certificate from a local CA for that address. An IP address as the
// domain is the same rule, its certificate for that address only (a client
// sending it as SNI routes as one without SNI, see helloInfo.SNIIP).
//
// The console owns a listener named $console, whatever its port. Its
// name, bind, port and the rule for the console's domain are
// fixed; config.yaml may list it with other options (proxy_trust_source,
// max_connections, timeouts, speed limits, no bind or port) and route more
// rules to it. Another listener may not have exactly its bind and port.

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// ConsoleConfig is how the console is served.
type ConsoleConfig struct {
	Bind         string   // normalised, as a listener's
	Binds        []string // its addresses
	Port         int
	Domain       string // the name it is served under; "" = clients without SNI, or an IP address
	Cert         string // auto | local-ca[:caNNN]
	PasswordHash string // what sign-ins are checked against

	// certificate, when set, is served instead of one from Cert. Only
	// tests set it, for a console in a test whose CAs are its own.
	certificate *tls.Certificate
}

// NoSNI reports whether the console is its listener's $no_sni rule: no
// domain, or an IP address.
func (c *ConsoleConfig) NoSNI() bool { return c.Domain == "" || c.IP().IsValid() }

// IP is the console's domain as an IP address, if it is one.
func (c *ConsoleConfig) IP() netip.Addr {
	a, _ := netip.ParseAddr(c.Domain)
	return a
}

// Name is the console's domain for messages.
func (c *ConsoleConfig) Name() string {
	if c.Domain == "" {
		return noSNI + " (clients without SNI)"
	}
	return c.Domain
}

// ListenerName is the name of the listener the console owns.
func (c *ConsoleConfig) ListenerName() string { return consoleAlias }

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

// consoleMissing is what to tell someone who started without a password.
const consoleMissing = "the web console needs a password: set $CONSOLE_PASSWORD (the password, or a hash from tlsproxy --hash-password), and -console_domain <name> (or $CONSOLE_DOMAIN; without one it answers clients without SNI), or run with -noconsole"

// ConsoleFromSettings reads the console's settings from flags (by name,
// without the dash) and the environment. The password is hashed here,
// unless it is already a hash.
func ConsoleFromSettings(flags map[string]string) (*ConsoleConfig, error) {
	c := &ConsoleConfig{Bind: "0.0.0.0", Binds: []string{"0.0.0.0"}, Port: 443, Cert: "auto"}
	c.Domain = strings.ToLower(strings.TrimSpace(consoleDomainSetting.value(flags)))
	password := os.Getenv("CONSOLE_PASSWORD")
	if password == "" {
		return nil, fmt.Errorf("%s", consoleMissing)
	}
	if c.Domain == "none" || c.Domain == noSNI {
		c.Domain = ""
	}
	if a, err := netip.ParseAddr(strings.Trim(c.Domain, "[]")); err == nil && a.Zone() == "" {
		c.Domain = a.Unmap().String()
	} else if c.Domain != "" && !isHostName(c.Domain) {
		return nil, fmt.Errorf("console domain %q is not a host name like admin.example.com (no *), an IP address, or none (clients without SNI)", c.Domain)
	}
	if c.NoSNI() {
		c.Cert = "local-ca" // ACME needs a host name; ca001 always exists
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
		if c.NoSNI() && c.Cert == "auto" {
			return nil, fmt.Errorf("console cert auto needs a host name as -console_domain: ACME can't issue for %s. Use local-ca (the default here)", c.Name())
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

// consoleAlias is the name of the console's listener, whatever its port,
// so moving the console breaks nothing. Only the console's listener can
// have it.
const consoleAlias = "$console"

// resolveConsoleAlias checks that $console in listeners and routes has a
// console to name: without one, it is an error.
func (cfg *Config) resolveConsoleAlias(con *ConsoleConfig, raws []rawRule) error {
	if con != nil {
		return nil
	}
	none := func(line int) error {
		return fmt.Errorf("line %d: %s names the web console's listener, and this proxy has no console (-noconsole)", line, consoleAlias)
	}
	for _, l := range cfg.Listeners {
		if l.Name == consoleAlias {
			return none(l.Line)
		}
	}
	for _, r := range raws {
		if r.listener != nil && *r.listener == consoleAlias {
			return none(r.line)
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
			return fmt.Errorf("line %d: the web console's listener (%s) is listed twice", l.Line, name)
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
// rules are built. A rule there for the console's exact domain (its $no_sni,
// for a console without a host name) is an error.
func (cfg *Config) addConsoleRule(con *ConsoleConfig) error {
	if con == nil {
		return nil
	}
	name := con.ListenerName()
	for _, r := range cfg.Rules {
		if r.Listener != name {
			continue
		}
		if con.NoSNI() && r.Kind == kindNone {
			return fmt.Errorf("rule at line %d: the web console answers clients without SNI (%s) on listener %s, so %s can't have a rule of its own there. Start the console with -console_domain <name>, or move this rule to another listener", r.Line, con.Name(), name, noSNI)
		}
		if !con.NoSNI() && r.Kind == kindLiteral && literalName(r.Source) == con.Domain {
			return fmt.Errorf("rule at line %d: %s is the web console's domain on listener %s, so it can't have a rule of its own there. Use another name, or start the console with another -console_domain", r.Line, con.Domain, name)
		}
	}
	raw := rawRule{listener: &name, cert: &con.Cert, console: true}
	pattern := con.Domain
	if con.NoSNI() {
		pattern = noSNI
	}
	raw.pattern = &pattern
	if ip := con.IP(); ip.IsValid() {
		only := ip.String() // its certificate, and the only address sent as SNI it takes
		raw.certDomains = &only
	}
	if con.certificate != nil {
		cert := "local-ca" // passes the checks; the certificate is con's own
		raw.cert = &cert
	}
	rule, err := buildRule(cfg, raw)
	if err != nil {
		return fmt.Errorf("the web console (%s): %v", con.Name(), err)
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
