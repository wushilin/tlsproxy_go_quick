package main

// Parser for config.toml, a small, lenient TOML subset:
//
//	[global]            section
//	[[host]]            appends a new rule
//	key = value         value may be "double quoted", 'single quoted' or bare
//	# comment           full line; also trailing " # ..." after a value
//
// Rules are evaluated by specificity, not by their position in the file (see
// ruleKind): NONE and literal names first, then wildcards (more literal
// characters first), ANY last. A host that matches no rule is denied. Patterns
// are host names with optional * wildcards; there are no regular expressions.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// MinReloadInterval gates reloads to at most one per this many seconds.
const MinReloadInterval = 5

type Config struct {
	sourceHash string // exact parsed bytes, for password rewrites and reload change detection
	// The listener's bind and port: the first [[listener]] as parsed, this
	// copy's own after ForListener. Bind is normalised: "0.0.0.0", or
	// "192.0.2.1; 2001:db8::1"; Binds holds its addresses.
	Bind               string
	Binds              []string
	Port               int
	HandshakeTimeout   time.Duration
	ConnectTimeout     time.Duration
	IdleTimeout        time.Duration // no traffic either way for this long closes; 0 = never
	HalfCloseTimeout   time.Duration // after one side closes, the other gets this long; 0 = unlimited
	MaxConnections     int
	MaxHandshakesPerIP int // connections per source still sending their ClientHello; 0 = unlimited
	// ProxyTrustSource lists who may put a PROXY protocol header in front of a
	// connection (a load balancer ahead of this proxy). Empty: nobody, headers
	// are never looked for.
	ProxyTrustSource  []netip.Prefix
	BufferSize        int
	BufferPoolMaxIdle int
	AllowCacheSize    int
	DenyCacheSize     int
	ReloadInterval    time.Duration // 0 = never
	StatsInterval     time.Duration // 0 = never
	ShortReadDelay    time.Duration // pause after a short read so data batches up; 0 = off
	Splice            bool          // relay passed-through connections with splice(2) (Linux only)
	RememberNonce     bool          // refuse a ClientHello this proxy itself forwarded seconds ago (a loop)
	Log               LogConfig     // the [logging] section

	// Certificates (only used by rules with cert = ...).
	CertPath            string   // where automatic certificates and the ACME account live
	CARoot              string   // where the local CAs (caNNN) and what they issued live
	ExpiryThresholdDays int      // renew this many days before expiry
	PublicIPs           []string // auto-issue only if the name resolves to one of these
	DNSResolvers        []string // public resolvers for that check (IP or IP:port); required when it runs
	AcmeEmail           string   // optional contact for the ACME account
	AcmeAgreeTOS        bool     // must be true before anything is issued
	AcmeDirectory       string   // ACME directory URL
	AcmeCAFile          string   // extra root CA for the ACME server's HTTPS (private CAs, Pebble)
	Warnings            []string // non-fatal findings, logged at startup / reload

	Console   *ConsoleConfig        // the [console] section; nil = no web console
	Rules     []Rule                // in file order
	Listeners []Listener            // in file order; at least one
	BasicAuth map[string]*BasicAuth // [[basic_auth]] sections, by name
	// Redirect is the port 80 listener of http_to_https_redirect = true, nil
	// when off. It has no rules and is not in Listeners: it answers every
	// plain HTTP request with a redirect to https:// (see redirect.go).
	Redirect *Listener
	// listener is set in the per-listener copies the proxy runs with (see
	// ForListener): whose rules Route uses and whose overrides apply.
	listener *Listener
	// Legacy settings that no longer apply and were ignored.
	Ignored []string
}

// Listener is one [[listener]] section: a port with its own rules. Zero or
// nil overrides mean the [global] value applies.
type Listener struct {
	Name  string
	Line  int
	Bind  string
	Binds []string
	Port  int

	ProxyTrustSource                                *[]netip.Prefix
	MaxConnections                                  int // on top of [global] max_connections
	HandshakeTimeout, IdleTimeout, HalfCloseTimeout *time.Duration
	MaxAggregatedSpeed, MaxSingleConnectionSpeed    float64 // bytes per second, each direction
	IsRedirect                                      bool    // the http_to_https_redirect listener
	// Console: the web console is served here (console.toml). A listener
	// of its own (consoleListener) has Line 0 and is not in config.toml.
	Console bool

	// How Route evaluates its rules: literal names by lookup, everything else
	// in order of specificity.
	literals   map[string]*Rule
	byPriority []*Rule
}

// Addrs is every address the listener binds, for display and listening.
func (l *Listener) Addrs() []string {
	var out []string
	for _, b := range l.Binds {
		out = append(out, net.JoinHostPort(b, strconv.Itoa(l.Port)))
	}
	return out
}

// ForListener returns the configuration a connection on l runs with: this
// one, with l's overrides applied. Rules and listeners are shared, so rule
// pointers stay the same.
func (c *Config) ForListener(l *Listener) *Config {
	eff := *c
	eff.listener = l
	eff.Bind, eff.Binds, eff.Port = l.Bind, l.Binds, l.Port
	if l.ProxyTrustSource != nil {
		eff.ProxyTrustSource = *l.ProxyTrustSource
	}
	for _, o := range []struct{ dst, v *time.Duration }{{&eff.HandshakeTimeout, l.HandshakeTimeout}, {&eff.IdleTimeout, l.IdleTimeout}, {&eff.HalfCloseTimeout, l.HalfCloseTimeout}} {
		if o.v != nil {
			*o.dst = *o.v
		}
	}
	return &eff
}

// Listener returns the listener named name, nil if there is none.
func (c *Config) Listener(name string) *Listener {
	for i := range c.Listeners {
		if c.Listeners[i].Name == name {
			return &c.Listeners[i]
		}
	}
	return nil
}

// PortListener returns the listener named name that opens a port: one of
// Listeners, or the redirect listener. Nil if there is none.
func (c *Config) PortListener(name string) *Listener {
	if c.Redirect != nil && c.Redirect.Name == name {
		return c.Redirect
	}
	return c.Listener(name)
}

// PortListeners is every listener that opens a port: Listeners, then the
// redirect listener if enabled.
func (c *Config) PortListeners() []*Listener {
	out := make([]*Listener, 0, len(c.Listeners)+1)
	for i := range c.Listeners {
		out = append(out, &c.Listeners[i])
	}
	if c.Redirect != nil {
		out = append(out, c.Redirect)
	}
	return out
}

// ruleKind is how specific a rule's pattern is. It decides which rule wins when
// several match, whatever their order in the file. All matching ignores case.
type ruleKind int

const (
	kindNone     ruleKind = iota // pattern = NONE: only clients without SNI
	kindLiteral                  // a plain host name: exact match, always wins over the kinds below
	kindWildcard                 // *.example.com, api-*.example.com: a * never crosses a dot
	kindCatchAll                 // pattern = ANY: everything, always last
)

func (k ruleKind) String() string {
	return [...]string{"no SNI", "literal", "wildcard", "catch-all"}[k]
}

type Rule struct {
	Listener     string // the listener's name
	Line         int
	Source       string
	Kind         ruleKind
	literalChars int // ranks wildcards: more literal characters is more specific
	// NoSNI is set by `pattern = NONE` (any case): the rule matches only
	// connections without an SNI, and Pattern is nil.
	NoSNI      bool
	Pattern    *regexp.Regexp
	Allow      bool
	TargetHost string
	TargetPort int

	// TLS termination: set when the rule has cert = auto | local-ca[:caNNN].
	// Without it the rule passes TLS through untouched.
	Cert        string           // "", "auto" or "local-ca:caNNN"
	CertDomains []string         // auto: names to issue for; local-ca: the names, globs and IPs that may get one
	certNames   []*regexp.Regexp // local-ca: CertDomains' names and globs compiled, anchored
	// local-ca, for clients without a host name (NONE, ANY): certIPs are the
	// IP addresses in cert_domains, all in the one certificate those clients
	// get (none listed: the address the client connected to). certHosts are a
	// NONE rule's host names, added to that certificate.
	certIPs   []netip.Addr
	certHosts []string
	certKey   string // certIPs and certHosts as the one certificate's name (sanKey), worked out at load
	// CertValidateScript decides about names that match the pattern but are
	// not in CertDomains: run as `<script> <name>` only when a certificate has
	// to be issued or renewed; exit status 0 accepts the name.
	CertValidateScript string
	// CertValidateArgs are the script's arguments, each expanded like
	// target_host (${1}, ${host}). Default: the name alone.
	CertValidateArgs  []string
	UpstreamTLS       bool   // connect to the target with TLS (default true)
	UpstreamTLSVerify bool   // verify the target's certificate (default true)
	UpstreamSNI       string // SNI sent to (and verified against) the target; "" = the client's SNI
	Proxy             bool   // send a PROXY protocol header to the target
	ProxyVersion      int    // PROXY protocol version (1 or 2; default 2)

	// Speed limits in bytes per second, each direction separately; 0 = none.
	MaxAggregatedSpeed       float64 // shared by every connection of this rule
	MaxSingleConnectionSpeed float64 // for each connection

	// Routes are the rule's service_rule keys, the longest prefix first: a
	// rule with routes serves HTTP itself instead of connecting to a target.
	Routes []*ServiceRoute
	// Console is set on the rule console.toml adds: it serves the web
	// console, is not in config.toml (Line 0), and cannot be stopped.
	Console bool
}

// Key identifies a rule across reloads and edits: two rules with the same key
// cannot both exist (the same pattern twice is a load error).
func (r *Rule) Key() string {
	pattern := ""
	switch {
	case r.NoSNI:
		pattern = "NONE"
	case r.Kind == kindCatchAll:
		pattern = "ANY"
	default:
		pattern = r.Pattern.String()
	}
	return r.Listener + "\x00" + pattern
}

// Terminates reports whether the proxy terminates TLS for this rule.
func (r *Rule) Terminates() bool { return r.Cert != "" }

// Decision is the outcome of routing one SNI.
type Decision struct {
	Allow    bool
	Host     string
	Port     int
	RuleLine int    // 0 = no rule matched
	Rule     *Rule  // the rule that matched (nil if none did)
	Err      string // non-empty: routing failed (treated as deny)
}

func isHostChar(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' ||
		b == '.' || b == '-' || b == '_'
}

// Route evaluates the rules for a lowercased SNI, most specific first. No SNI
// is matched by NONE, else by ANY; never by a literal or a wildcard.
func (c *Config) Route(sni string) Decision { return c.RouteExcept(sni, nil) }

// RouteExcept routes with the rules of this copy's listener (the first one
// for the configuration as parsed), as if the rules whose Key is in stopped
// were not configured: a name they would match falls through to the next
// rule.
func (c *Config) RouteExcept(sni string, stopped map[string]bool) Decision {
	l := c.listener
	if l == nil {
		l = &c.Listeners[0]
	}
	if r := l.literals[sni]; r != nil && !stopped[r.Key()] {
		return r.decide(sni, []int{0, len(sni)})
	}
	for _, r := range l.byPriority {
		if stopped[r.Key()] {
			continue
		}
		var m []int
		if r.NoSNI {
			if sni != "" {
				continue
			}
			m = []int{0, 0} // group 0 (the empty whole match); there are no others
		} else if m = r.Pattern.FindStringSubmatchIndex(sni); m == nil {
			continue
		}
		return r.decide(sni, m)
	}
	return Decision{}
}

// decide is the outcome of a rule that matched sni with submatch indexes m.
func (r *Rule) decide(sni string, m []int) Decision {
	if !r.Allow {
		return Decision{RuleLine: r.Line, Rule: r}
	}
	if r.Serves() {
		return Decision{Allow: true, RuleLine: r.Line, Rule: r} // served here: no target
	}
	host, err := expand(r.TargetHost, sni, m)
	if err == nil {
		if strings.Contains(host, ":") {
			// Only an IPv6 address has colons (fe80::1%em0 with its zone included).
			_, err = netip.ParseAddr(host)
		}
		for i := 0; i < len(host) && err == nil && !strings.Contains(host, ":"); i++ {
			if !isHostChar(host[i]) {
				err = fmt.Errorf("invalid")
			}
		}
		if host == "" || err != nil {
			err = fmt.Errorf("rule at line %d produced invalid target host %q", r.Line, host)
		}
	}
	if err != nil {
		return Decision{RuleLine: r.Line, Rule: r, Err: err.Error()}
	}
	return Decision{Allow: true, Host: host, Port: r.TargetPort, RuleLine: r.Line, Rule: r}
}

// classify works out what kind of pattern this is and returns the regular
// expression that implements it internally (unanchored; "" for NONE).
//
//	NONE                          only clients that send no SNI
//	vq.example.com                literal; vq\.example\.com and ^vq.example.com$ mean the same
//	*.example.com                 wildcard: a * that is a whole label is exactly one label, so
//	api-*.example.com               *.example.com does not match a.b.example.com (nor example.com);
//	*.*.example.com                 a * inside a label is any run of characters, none included:
//	                                api-*.x.com matches api-1.x.com and api-.x.com, abc*.x.com
//	                                matches abc.x.com. Each * is a capture: ${1}, ${2}, ... left to right
//	ANY                           everything, with or without SNI (".*" is accepted as an old spelling)
//
// Nothing else is a pattern: there are no regular expressions and no **.
func classify(pattern string) (kind ruleKind, expr string, literalChars int, err error) {
	switch {
	case strings.EqualFold(pattern, "none"):
		return kindNone, "", 0, nil
	case strings.EqualFold(pattern, "any"), strings.TrimSuffix(strings.TrimPrefix(pattern, "^"), "$") == ".*":
		return kindCatchAll, ".*", 0, nil
	}
	name := literalName(pattern) // ^ $ and \. are tolerated spellings, for literals and wildcards alike
	for i := 0; i < len(name); i++ {
		if !isHostChar(name[i]) && name[i] != '*' {
			return 0, "", 0, fmt.Errorf("pattern %q is not a host name: %s", pattern, patternHelp(pattern))
		}
	}
	if name == "" || strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") || strings.Contains(name, "..") {
		return 0, "", 0, fmt.Errorf("pattern %q is not a host name: %s", pattern, patternHelp(pattern))
	}
	if !strings.Contains(name, "*") {
		return kindLiteral, regexp.QuoteMeta(name), len(name), nil
	}
	if strings.Contains(name, "**") {
		return 0, "", 0, fmt.Errorf("pattern %q: ** is not supported. A * never crosses a dot: write one rule per depth (*.example.com, *.*.example.com)", pattern)
	}
	var out strings.Builder
	for n, label := range strings.Split(name, ".") {
		if n > 0 {
			out.WriteString(`\.`)
		}
		if label == "*" {
			out.WriteString(`([^.]+)`) // a whole label: there has to be one
			continue
		}
		for i := 0; i < len(label); i++ {
			if label[i] == '*' {
				out.WriteString(`([^.]*)`) // part of a label: may be nothing
			} else {
				out.WriteString(regexp.QuoteMeta(label[i : i+1]))
				literalChars++
			}
		}
	}
	return kindWildcard, out.String(), literalChars + strings.Count(name, "."), nil
}

// patternHelp says what to write instead of a pattern that is not one: most
// often a regular expression from a configuration written for an older version.
func patternHelp(pattern string) string {
	help := "Use a host name, with * for one label or part of one (*.example.com, api-*.example.com; each * is ${1}, ${2}, ... in target_host), NONE for clients without SNI, or ANY for everything"
	switch {
	case strings.Contains(pattern, "|"):
		return "regular expressions are no longer supported; write one rule per alternative. " + help
	case strings.ContainsAny(pattern, `()[]{}+?\^$`) || strings.Contains(pattern, ".*"):
		return "regular expressions are no longer supported; (.*) and .* become *. " + help
	}
	return help
}

// literalName is the host name a literal pattern stands for: vq\.example\.com,
// ^vq.example.com$ and VQ.example.com are all vq.example.com.
func literalName(pattern string) string {
	bare := strings.TrimSuffix(strings.TrimPrefix(pattern, "^"), "$")
	return strings.ToLower(strings.ReplaceAll(bare, `\.`, "."))
}

// prioritise builds the lookup structures Route uses and reports rules that
// can never match. Called once all rules are parsed (Rules no longer moves).
func (c *Config) prioritise() error {
	for i := range c.Listeners {
		if err := c.prioritiseListener(&c.Listeners[i]); err != nil {
			return err
		}
	}
	return nil
}

// prioritiseListener orders one listener's rules.
func (c *Config) prioritiseListener(l *Listener) error {
	l.literals = map[string]*Rule{}
	var rules []*Rule
	for i := range c.Rules {
		if c.Rules[i].Listener == l.Name {
			rules = append(rules, &c.Rules[i])
		}
	}
	var first [kindCatchAll + 1]*Rule // the first NONE and catch-all rule
	for _, r := range rules {
		switch r.Kind {
		case kindLiteral:
			name := literalName(r.Source)
			if prev := l.literals[name]; prev != nil {
				return fmt.Errorf("[[host]] at line %d: %s already has a rule at line %d; only one of them could ever match", r.Line, name, prev.Line)
			}
			l.literals[name] = r
			continue
		case kindWildcard:
			if prev := l.literals["\x00"+literalName(r.Source)]; prev != nil {
				return fmt.Errorf("[[host]] at line %d: pattern %s already has a rule at line %d; only one of them could ever match", r.Line, literalName(r.Source), prev.Line)
			}
			l.literals["\x00"+literalName(r.Source)] = r // never equals an SNI: only remembers the pattern
		case kindNone, kindCatchAll:
			if prev := first[r.Kind]; prev != nil {
				return fmt.Errorf("[[host]] at line %d: pattern = %s can never match, the rule at line %d (%s) already matches the same clients", r.Line, r.Source, prev.Line, prev.Source)
			}
			first[r.Kind] = r
		}
		l.byPriority = append(l.byPriority, r)
	}
	sort.SliceStable(l.byPriority, func(i, j int) bool {
		a, b := l.byPriority[i], l.byPriority[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.literalChars > b.literalChars // equally specific: file order (the sort is stable)
	})
	// Say so once when that differs from a top-to-bottom reading of the file:
	// a rule that an earlier, broader rule would have caught.
	var later []string
	for i, r := range rules {
		if r.Console {
			continue // not in the file, so in no file order
		}
		for _, prev := range rules[:i] {
			name := literalName(r.Source)
			if prev.Kind > r.Kind && (prev.Kind == kindCatchAll || r.Kind == kindLiteral && prev.Pattern.MatchString(name)) {
				later = append(later, fmt.Sprintf("line %d (%s, %s) wins over line %d (%s, %s)", r.Line, r.Source, r.Kind, prev.Line, prev.Source, prev.Kind))
				break
			}
		}
	}
	if len(later) > 0 {
		c.Warnings = append(c.Warnings, "rules are evaluated by specificity, not file order (literal names, then wildcards, ANY last): "+strings.Join(later, "; "))
	}
	return nil
}

// expand replaces ${N} in template with what the Nth * of the pattern
// matched, and ${host} (or ${0}) with the whole name. Captures that matched
// nothing expand to "". Nothing else may follow a $: a host name has no $,
// and a bare $1 is refused so that ${1}hello can never be misread.
func expand(template, input string, m []int) (string, error) {
	var out strings.Builder
	for i := 0; i < len(template); {
		if template[i] != '$' {
			j := strings.IndexByte(template[i:], '$')
			if j < 0 {
				j = len(template) - i
			}
			out.WriteString(template[i : i+j])
			i += j
			continue
		}
		if i+1 >= len(template) || template[i+1] != '{' {
			bare := template[i+1:]
			if k := strings.IndexFunc(bare, func(r rune) bool { return r < '0' || r > '9' }); k >= 0 {
				bare = bare[:k]
			}
			if bare != "" {
				return "", fmt.Errorf("write ${%s}, not $%s: captures are always in braces", bare, bare)
			}
			return "", fmt.Errorf("a $ must start ${1}, ${2}, ... or ${host}")
		}
		end := strings.IndexByte(template[i:], '}')
		if end < 0 {
			return "", fmt.Errorf("unterminated ${ in %q", template)
		}
		name := template[i+2 : i+end]
		i += end + 1
		if name == "host" {
			name = "0"
		}
		n, err := strconv.Atoi(name)
		if err != nil || n < 0 || strconv.Itoa(n) != name {
			return "", fmt.Errorf("unknown reference ${%s}: use ${1}, ${2}, ... for the *s, ${host} for the whole name", name)
		}
		if 2*n+1 >= len(m) {
			return "", fmt.Errorf("${%d} does not exist: the pattern has only %d capture(s)", n, len(m)/2-1)
		}
		if m[2*n] >= 0 {
			out.WriteString(input[m[2*n]:m[2*n+1]])
		}
	}
	return out.String(), nil
}

// listenNetwork makes a listen address mean what it says. Go's "tcp" turns
// 0.0.0.0 into a dual-stack [::] socket, which would also accept IPv6 clients;
// an IPv4 address gets "tcp4" instead. "::" stays dual-stack.
func listenNetwork(addr string) string {
	if a, err := netip.ParseAddr(addr); err == nil && a.Is4() {
		return "tcp4"
	}
	return "tcp"
}

// trustsProxySource reports whether a peer may assert another source
// address with a PROXY protocol header.
func (c *Config) trustsProxySource(peer net.Addr) bool {
	tcp, ok := peer.(*net.TCPAddr)
	if !ok || len(c.ProxyTrustSource) == 0 {
		return false
	}
	ip, _ := netip.AddrFromSlice(tcp.IP)
	ip = ip.Unmap()
	for _, prefix := range c.ProxyTrustSource {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// listenAddrs is every address the proxy listens on, for display: the
// listener's for a per-listener copy, all of them otherwise.
func listenAddrs(c *Config) string {
	var out []string
	for i := range c.Listeners {
		if l := &c.Listeners[i]; c.listener == nil || c.listener == l {
			out = append(out, l.Addrs()...)
		}
	}
	return strings.Join(out, ", ")
}

// LetsEncryptDirectory is the default ACME directory.
const LetsEncryptDirectory = "https://acme-v02.api.letsencrypt.org/directory"

type rawRule struct {
	cert, certDomains, certScript, certArgs, upstreamTLS, upstreamVerify, upstreamSNI *string
	proxy, proxyVersion                                                               *string
	aggSpeed, connSpeed, listener                                                     *string
	line                                                                              int
	pattern, action, targetHost, tport                                                *string
	serviceRules                                                                      []rawServiceRule
	console                                                                           bool // the console's own rule (applyConsole)
}

// buffer_size is clamped to this range.
const (
	minBufferSize = 4 << 10
	maxBufferSize = 128 << 10
)

// ParseConfig reads config.toml alone, without a console.
func ParseConfig(text string) (*Config, error) { return LoadConfig(text, nil) }

// LoadConfig reads config.toml with the console of console.toml (nil for
// none) merged in: on the listener with exactly its address and port, or on
// a listener of its own (see applyConsole). The proxy loads every version of
// the file this way, saved or only checked, so what passes a check is what
// a reload runs.
func LoadConfig(text string, console *ConsoleConfig) (*Config, error) {
	cfg := &Config{
		sourceHash:         fileHash([]byte(text)),
		HandshakeTimeout:   10 * time.Second,
		ConnectTimeout:     10 * time.Second,
		IdleTimeout:        600 * time.Second,
		HalfCloseTimeout:   30 * time.Second,
		MaxConnections:     1024,
		MaxHandshakesPerIP: 64,
		BufferSize:         64 * 1024,
		AllowCacheSize:     4096,
		DenyCacheSize:      4096,
		ReloadInterval:     5 * time.Second,
		StatsInterval:      60 * time.Second,
		Splice:             true,
		RememberNonce:      true,
		Log:                defaultLogConfig(),

		CertPath:            "./certs",
		CARoot:              "./ca",
		ExpiryThresholdDays: 15,
		AcmeDirectory:       LetsEncryptDirectory,
	}
	poolMaxIdle := -1
	httpRedirect := false
	var raws []rawRule
	var auths []*BasicAuth
	section := ""

	for idx, line := range strings.Split(text, "\n") {
		lineno := idx + 1
		fail := func(format string, a ...any) error {
			return fmt.Errorf("line %d: %s", lineno, fmt.Sprintf(format, a...))
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[[") {
			if !strings.HasSuffix(line, "]]") {
				return nil, fail("bad section header")
			}
			section = strings.TrimSpace(line[2 : len(line)-2])
			switch section {
			case "host":
				raws = append(raws, rawRule{line: lineno})
			case "listener":
				cfg.Listeners = append(cfg.Listeners, Listener{Line: lineno, Bind: "0.0.0.0", Binds: []string{"0.0.0.0"}})
			case "basic_auth":
				auths = append(auths, &BasicAuth{Line: lineno, Users: map[string]credential{}, keys: map[string]string{}})
			default:
				return nil, fail("unknown section [[%s]]", section)
			}
			continue
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") {
				return nil, fail("bad section header")
			}
			section = strings.TrimSpace(line[1 : len(line)-1])
			if section == "console" {
				return nil, fail("[console] has a file of its own now: move this section to console.toml (next to this file, or anywhere) and start the proxy with --console <that file>. The console can't change that file, so it can't lock itself out")
			}
			if section != "global" && section != "logging" {
				return nil, fail("unknown section [%s]", section)
			}
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			return nil, fail("expected key = value")
		}
		key := strings.TrimSpace(line[:eq])
		value, err := "", error(nil)
		if key == "cert_validate_args" {
			value, err = arrayValue(line[eq+1:]) // a TOML array of strings, kept as JSON
		} else {
			value, err = parseValue(line[eq+1:])
		}
		if err != nil {
			return nil, fail("%v", err)
		}
		num := func() (int, error) {
			n, err := strconv.ParseUint(value, 10, 31)
			if err != nil {
				return 0, fail("%s: expected a number, got %q", key, value)
			}
			return int(n), nil
		}
		secs := func(dst *time.Duration) error {
			n, err := num()
			*dst = time.Duration(n) * time.Second
			return err
		}
		count := func(dst *int) error {
			n, err := num()
			*dst = n
			return err
		}

		switch section {
		case "global":
			switch key {
			case "bind", "port":
				return nil, fail("[global] %s is no longer supported: every listen address is a [[listener]] section, as in\n\n"+
					"  [[listener]]\n  name = https\n  bind = 0.0.0.0\n  port = 443\n\n"+
					"move bind and port there, and name it in every rule: listener = https", key)
			case "handshake_timeout":
				err = secs(&cfg.HandshakeTimeout)
			case "connect_timeout":
				err = secs(&cfg.ConnectTimeout)
			case "idle_timeout":
				err = secs(&cfg.IdleTimeout)
			case "half_close_timeout":
				err = secs(&cfg.HalfCloseTimeout)
			case "stats_interval":
				err = secs(&cfg.StatsInterval)
			case "reload_interval":
				if err = secs(&cfg.ReloadInterval); err == nil {
					if s := int(cfg.ReloadInterval / time.Second); s != 0 && s < MinReloadInterval {
						err = fail("reload_interval must be 0 (off) or at least %d, got %d", MinReloadInterval, s)
					}
				}
			case "max_connections":
				err = count(&cfg.MaxConnections)
			case "max_handshakes_per_ip":
				err = count(&cfg.MaxHandshakesPerIP)
			case "proxy_protocol_from":
				return nil, fail("%s", renamedProxyTrust(value))
			case "proxy_trust_source":
				if cfg.ProxyTrustSource, err = parsePrefixes(value); err != nil {
					return nil, fail("%v", err)
				}
			case "allow_cache_size":
				err = count(&cfg.AllowCacheSize)
			case "deny_cache_size":
				err = count(&cfg.DenyCacheSize)
			case "buffer_pool_max_idle":
				err = count(&poolMaxIdle)
			case "buffer_size":
				// Below 4 KiB costs syscalls; past 128 KiB a step moves no more,
				// since a socket rarely holds more than that at once.
				if err = count(&cfg.BufferSize); err == nil && (cfg.BufferSize < minBufferSize || cfg.BufferSize > maxBufferSize) {
					clamped := max(minBufferSize, min(cfg.BufferSize, maxBufferSize))
					cfg.Warnings = append(cfg.Warnings, fmt.Sprintf("line %d: buffer_size = %d is outside %d..%d; using %d", lineno, cfg.BufferSize, minBufferSize, maxBufferSize, clamped))
					cfg.BufferSize = clamped
				}
			case "short_read_delay_us":
				var us int
				err = count(&us)
				cfg.ShortReadDelay = time.Duration(us) * time.Microsecond
			case "splice":
				if cfg.Splice, err = parseBool(value); err != nil {
					err = fail("splice: %v", err)
				}
			case "remember_nonce":
				if cfg.RememberNonce, err = parseBool(value); err != nil {
					err = fail("remember_nonce: %v", err)
				}
			case "http_to_https_redirect":
				if httpRedirect, err = parseBool(value); err != nil {
					err = fail("http_to_https_redirect: %v", err)
				}
			case "cert_path":
				cfg.CertPath = value
			case "ca_root":
				if value == "" {
					return nil, fail("ca_root must not be empty")
				}
				cfg.CARoot = value
			case "expiry_threshold_days":
				if err = count(&cfg.ExpiryThresholdDays); err == nil && cfg.ExpiryThresholdDays < 1 {
					err = fail("expiry_threshold_days must be at least 1")
				}
			case "public_ip_address":
				cfg.PublicIPs = nil
				for _, ip := range splitList(value) {
					addr, perr := netip.ParseAddr(ip)
					if perr != nil {
						return nil, fail("public_ip_address: %q is not an IP address", ip)
					}
					cfg.PublicIPs = append(cfg.PublicIPs, addr.Unmap().String())
				}
			case "dns_resolvers":
				if cfg.DNSResolvers = splitList(value); len(cfg.DNSResolvers) == 0 {
					err = fail("dns_resolvers must not be empty")
				}
				for _, server := range cfg.DNSResolvers {
					if !resolverAddress(server) {
						err = fail("dns_resolvers: %q is not an IP address or IP:port (an IPv6 one with a port is [2606:4700:4700::1111]:53)", server)
						break
					}
				}
			case "acme_email":
				cfg.AcmeEmail = value
			case "acme_agree_tos":
				if cfg.AcmeAgreeTOS, err = parseBool(value); err != nil {
					err = fail("acme_agree_tos: %v", err)
				}
			case "acme_directory":
				cfg.AcmeDirectory = value
			case "acme_ca_file":
				cfg.AcmeCAFile = value
			case "io_model", "worker_threads":
				// Legacy tuning knobs; goroutines make them moot.
				cfg.Ignored = append(cfg.Ignored, key)
			default:
				return nil, fail("unknown key %q in [global]", key)
			}
			if err != nil {
				return nil, err
			}
		case "logging":
			switch key {
			case "stdout":
				cfg.Log.Stdout = value
			case "stderr":
				cfg.Log.Stderr = value
			case "max_size":
				if cfg.Log.MaxSize, err = parseSize(value); err != nil {
					return nil, fail("%v", err)
				}
			case "max_keep":
				err = count(&cfg.Log.MaxKeep)
			case "compress_after":
				err = count(&cfg.Log.CompressAfter)
			default:
				return nil, fail("unknown key %q in [logging]", key)
			}
			if err != nil {
				return nil, err
			}
		case "listener":
			if err := listenerOption(&cfg.Listeners[len(cfg.Listeners)-1], key, value); err != nil {
				return nil, fail("%v", err)
			}
		case "basic_auth":
			if err := basicAuthOption(auths[len(auths)-1], key, value); err != nil {
				return nil, fail("%v", err)
			}
		case "host":
			r := &raws[len(raws)-1]
			v := value
			switch key {
			case "listener":
				r.listener = &v
			case "pattern":
				r.pattern = &v
			case "action":
				r.action = &v
			case "target_host":
				r.targetHost = &v
			case "target_port":
				r.tport = &v
			case "cert":
				r.cert = &v
			case "cert_domains":
				r.certDomains = &v
			case "cert_validate_script":
				r.certScript = &v
			case "cert_validate_args":
				r.certArgs = &v
			case "upstream_tls":
				r.upstreamTLS = &v
			case "upstream_tls_verify":
				r.upstreamVerify = &v
			case "upstream_sni":
				r.upstreamSNI = &v
			case "proxy":
				r.proxy = &v
			case "proxy_version":
				r.proxyVersion = &v
			case "max_aggregated_speed":
				r.aggSpeed = &v
			case "max_single_connection_speed":
				r.connSpeed = &v
			default:
				if !isServiceRuleKey(key) {
					return nil, fail("unknown key %q in [[host]]", key)
				}
				i := slices.IndexFunc(r.serviceRules, func(x rawServiceRule) bool { return x.key == key })
				if i < 0 {
					r.serviceRules = append(r.serviceRules, rawServiceRule{key, v, lineno})
					break
				}
				cfg.Warnings = append(cfg.Warnings, fmt.Sprintf("line %d: %s is also set at line %d; the last one wins", lineno, key, r.serviceRules[i].line))
				r.serviceRules[i] = rawServiceRule{key, v, lineno}
			}
		default:
			return nil, fail("key outside of any section")
		}
	}

	if poolMaxIdle < 0 {
		poolMaxIdle = 2 * cfg.MaxConnections
	}
	cfg.BufferPoolMaxIdle = poolMaxIdle
	if err := cfg.resolveListeners(); err != nil {
		return nil, err
	}
	if httpRedirect {
		if err := cfg.makeRedirectListener(); err != nil {
			return nil, err
		}
	}
	for _, r := range raws {
		rule, err := buildRule(cfg, r)
		if err != nil {
			return nil, fmt.Errorf("[[host]] at line %d: %v", r.line, err)
		}
		cfg.Rules = append(cfg.Rules, rule)
	}
	if err := cfg.applyConsole(console); err != nil {
		return nil, err
	}
	if err := cfg.prioritise(); err != nil {
		return nil, err
	}
	for i := range cfg.Rules {
		if r := &cfg.Rules[i]; r.Allow && r.Kind == kindCatchAll && strings.Contains(strings.ReplaceAll(r.TargetHost, "$$", ""), "$") {
			cfg.Warnings = append(cfg.Warnings, fmt.Sprintf("[[host]] at line %d: pattern = %s with target_host = %s connects to whatever name a client sends (port %d), internal names included. List the names or domains you mean to allow instead", r.Line, r.Source, r.TargetHost, r.TargetPort))
		}
	}
	if err := cfg.resolveServe(auths); err != nil {
		return nil, err
	}
	if auto := cfg.AutoDomains(); len(auto) > 0 {
		on443 := false
		for _, l := range cfg.Listeners {
			on443 = on443 || l.Port == 443
		}
		if !on443 {
			cfg.Warnings = append(cfg.Warnings, fmt.Sprintf("cert = auto: the CA validates on public port 443, but this proxy listens on %s; make sure 443 is forwarded here", listenAddrs(cfg)))
		}
		v4Only := true
		for _, l := range cfg.Listeners {
			for _, b := range l.Binds {
				if bind, err := netip.ParseAddr(b); err != nil || !bind.Unmap().Is4() {
					v4Only = false
				}
			}
		}
		if v4Only {
			for _, ip := range cfg.PublicIPs {
				if a, _ := netip.ParseAddr(ip); a.Is6() {
					cfg.Warnings = append(cfg.Warnings, fmt.Sprintf("cert = auto: public_ip_address lists the IPv6 address %s, but this proxy listens on IPv4 only (%s). The CA prefers IPv6 when a name has an AAAA record, and would not reach this proxy; use bind = :: to listen on both", ip, listenAddrs(cfg)))
					break
				}
			}
		}
		if len(cfg.PublicIPs) == 0 {
			cfg.Warnings = append(cfg.Warnings, "cert = auto without public_ip_address: the DNS pre-check is skipped, so a misconfigured name will burn CA rate limits")
		}
	}
	if len(cfg.PublicIPs) > 0 && len(cfg.DNSResolvers) == 0 && slices.ContainsFunc(cfg.Rules, func(r Rule) bool { return r.Cert == "auto" }) {
		return nil, fmt.Errorf("cert = auto with public_ip_address needs dns_resolvers in [global]: the public DNS servers that check each name resolves here " +
			"before the CA is asked (not the local resolver, which may answer with LAN addresses). " +
			"For example: dns_resolvers = 1.1.1.1; 8.8.8.8; 2606:4700:4700::1111; 2001:4860:4860::8888")
	}
	return cfg, nil
}

// buildRule turns one [[host]] section (or the console's rule, see
// applyConsole) into a Rule. Errors say what is wrong, not where.
func buildRule(cfg *Config, r rawRule) (Rule, error) {
	fail := func(format string, a ...any) error { return fmt.Errorf(format, a...) }
	if r.pattern == nil {
		return Rule{}, fail("pattern is required")
	}
	rule := Rule{Line: r.line, Source: *r.pattern}
	switch {
	case r.listener != nil:
		if cfg.Listener(*r.listener) == nil {
			return Rule{}, fail("listener = %s: there is no [[listener]] named %s (listeners: %s)", *r.listener, *r.listener, cfg.listenerNames())
		}
		rule.Listener = *r.listener
	default:
		return Rule{}, fail("listener = <name> is required (listeners: %s)", cfg.listenerNames())
	}
	groups := 0
	expr := ""
	var err error
	if rule.Kind, expr, rule.literalChars, err = classify(*r.pattern); err != nil {
		return Rule{}, fail("%v", err)
	}
	if rule.Kind == kindNone {
		rule.NoSNI = true
	} else {
		// Whole-name, case-insensitive match.
		rule.Pattern, err = regexp.Compile("(?i)^(?:" + expr + ")$")
		if err != nil {
			return Rule{}, fail("bad pattern %q: %v", *r.pattern, err)
		}
		groups = rule.Pattern.NumSubexp()
	}
	action := "allow"
	if r.action != nil {
		action = strings.ToLower(*r.action)
	}
	switch action {
	case "deny":
	case "allow":
		rule.Allow = true
		if len(r.serviceRules) > 0 || r.console {
			break // served here: serveSettings checks the rest
		}
		if r.targetHost == nil {
			return Rule{}, fail("target_host is required for allow")
		}
		rule.TargetHost = *r.targetHost
		// The port always goes in target_port. A ':' is only legal in an
		// IPv6 address; "host:8080" would otherwise be dialled as a name.
		if strings.Contains(rule.TargetHost, ":") {
			if _, err := netip.ParseAddr(rule.TargetHost); err != nil {
				return Rule{}, fail("target_host %q must not contain a port: use target_port (an IPv6 address is written without brackets)", rule.TargetHost)
			}
		}
		if r.tport == nil {
			return Rule{}, fail("target_port is required for allow")
		}
		if rule.TargetPort, err = parsePort(*r.tport); err != nil {
			return Rule{}, fail("%v", err)
		}
		// Catch bad group references now rather than per connection.
		probe := make([]int, 2*(groups+1))
		if _, err := expand(rule.TargetHost, "", probe); err != nil {
			return Rule{}, fail("target_host: %v", err)
		}
	default:
		return Rule{}, fail("action must be allow or deny, got %q", action)
	}
	if err := serveSettings(&rule, &r); err != nil {
		return Rule{}, fail("%v", err)
	}
	rule.Console = r.console
	if err := tlsSettings(cfg, &rule, r); err != nil {
		return Rule{}, fail("%v", err)
	}
	if rule.Serves() {
		rule.UpstreamTLS, rule.UpstreamTLSVerify = false, false // nothing upstream
	}
	if err := proxySettings(&rule, r); err != nil {
		return Rule{}, fail("%v", err)
	}
	if err := speedSettings(&rule, r); err != nil {
		return Rule{}, fail("%v", err)
	}
	return rule, nil
}

// parseBinds reads a bind list: addresses separated by ; or ,.
func parseBinds(value string) ([]string, error) {
	var binds []string
	for _, b := range splitList(value) {
		b = strings.Trim(b, "[]") // [::] and :: are the same thing
		if slices.Contains(binds, b) {
			return nil, fmt.Errorf("bind lists %s twice", b)
		}
		binds = append(binds, b)
	}
	if len(binds) == 0 {
		return nil, fmt.Errorf("bind must not be empty")
	}
	return binds, nil
}

// resolverAddress is an IP address, or IP:port, of a DNS server. Names are
// refused: looking one up would need the system's resolver, which is what
// dns_resolvers avoids.
func resolverAddress(v string) bool {
	if _, err := netip.ParseAddr(v); err == nil {
		return true
	}
	_, err := netip.ParseAddrPort(v)
	return err == nil
}

// renamedProxyTrust is the load error for proxy_protocol_from, renamed in
// v1.5.0 so that listeners and local services share one name.
func renamedProxyTrust(value string) string {
	return fmt.Sprintf("proxy_protocol_from is now called proxy_trust_source; write proxy_trust_source = %s", value)
}

// parsePrefixes reads proxy_trust_source: addresses or networks.
func parsePrefixes(value string) ([]netip.Prefix, error) {
	out := []netip.Prefix{}
	for _, item := range splitList(value) {
		prefix, perr := netip.ParsePrefix(item)
		if addr, aerr := netip.ParseAddr(item); aerr == nil {
			prefix, perr = netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen()), nil
		}
		if perr != nil {
			return nil, fmt.Errorf("proxy_trust_source: %q is not an IP address or a network (10.0.0.0/8)", item)
		}
		out = append(out, prefix.Masked())
	}
	return out, nil
}

// listenerName: letters, digits, space and -_@#~()[]<>"' (1-64, no space at
// either end). The console quotes names that need it when it writes them.
var listenerName = regexp.MustCompile(`^[A-Za-z0-9_@#~()\[\]<>"'-]([A-Za-z0-9 _@#~()\[\]<>"'-]{0,62}[A-Za-z0-9_@#~()\[\]<>"'-])?$`)

// listenerOption applies one key of a [[listener]] section.
func listenerOption(l *Listener, key, value string) error {
	secs := func(dst **time.Duration) error {
		n, err := strconv.ParseUint(value, 10, 31)
		if err != nil {
			return fmt.Errorf("%s: expected a number of seconds, got %q", key, value)
		}
		d := time.Duration(n) * time.Second
		*dst = &d
		return nil
	}
	var err error
	switch key {
	case "name":
		if !listenerName.MatchString(value) {
			return fmt.Errorf("name must be 1-64 letters, digits, spaces or -_@#~()[]<>\"' (no space at either end), got %q", value)
		}
		l.Name = value
	case "bind":
		if l.Binds, err = parseBinds(value); err == nil {
			l.Bind = strings.Join(l.Binds, "; ")
		}
	case "port":
		l.Port, err = parsePort(value)
	case "proxy_protocol_from":
		return errors.New(renamedProxyTrust(value))
	case "proxy_trust_source":
		var p []netip.Prefix
		if p, err = parsePrefixes(value); err == nil {
			l.ProxyTrustSource = &p
		}
	case "max_connections":
		var n uint64
		if n, err = strconv.ParseUint(value, 10, 31); err != nil {
			err = fmt.Errorf("max_connections: expected a number, got %q", value)
		}
		l.MaxConnections = int(n)
	case "handshake_timeout":
		err = secs(&l.HandshakeTimeout)
	case "idle_timeout":
		err = secs(&l.IdleTimeout)
	case "half_close_timeout":
		err = secs(&l.HalfCloseTimeout)
	case "max_aggregated_speed", "max_single_connection_speed":
		dst := &l.MaxAggregatedSpeed
		if key == "max_single_connection_speed" {
			dst = &l.MaxSingleConnectionSpeed
		}
		if *dst, err = parseRate(value); err != nil {
			err = fmt.Errorf("%s: %v", key, err)
		}
	default:
		return fmt.Errorf("unknown key %q in [[listener]]", key)
	}
	return err
}

func (c *Config) listenerNames() string {
	var names []string
	for _, l := range c.Listeners {
		names = append(names, l.Name)
	}
	return strings.Join(names, ", ")
}

// resolveListeners checks the [[listener]] sections.
func (c *Config) resolveListeners() error {
	if len(c.Listeners) == 0 {
		return fmt.Errorf("no [[listener]] section: add one, e.g. [[listener]] with name = https, bind = 0.0.0.0, port = 443")
	}
	for i := range c.Listeners {
		l := &c.Listeners[i]
		fail := func(format string, a ...any) error {
			return fmt.Errorf("[[listener]] at line %d: %s", l.Line, fmt.Sprintf(format, a...))
		}
		if l.Name == "" {
			return fail("name is required")
		}
		if strings.EqualFold(l.Name, RedirectListenerName) {
			return fail("the name %s is reserved for http_to_https_redirect", RedirectListenerName)
		}
		if strings.EqualFold(l.Name, consoleListener) {
			return fail("the name %s is reserved for the console's own listener", consoleListener)
		}
		if l.Port == 0 {
			return fail("port is required")
		}
		for _, prev := range c.Listeners[:i] {
			if strings.EqualFold(prev.Name, l.Name) {
				return fail("the name %s is already used at line %d (names are compared ignoring case)", l.Name, prev.Line)
			}
			if prev.Port != l.Port {
				continue
			}
			for _, a := range l.Binds {
				for _, b := range prev.Binds {
					if a == b || isWildcard(a) || isWildcard(b) {
						return fail("%s port %d overlaps %s (line %d) on %s", a, l.Port, prev.Name, prev.Line, b)
					}
				}
			}
		}
	}
	// The first listener's values stand for "the" bind and port in messages.
	c.Bind, c.Binds, c.Port = c.Listeners[0].Bind, c.Listeners[0].Binds, c.Listeners[0].Port
	return nil
}

// makeRedirectListener sets up the http_to_https_redirect listener: port 80
// on every address the other listeners bind (a wildcard address covers the
// specific ones of its family).
func (c *Config) makeRedirectListener() error {
	var binds []string
	any4, any6 := false, false
	for i := range c.Listeners {
		for _, b := range c.Listeners[i].Binds {
			if !slices.Contains(binds, b) {
				binds = append(binds, b)
			}
			if a, err := netip.ParseAddr(b); err == nil && a.IsUnspecified() {
				any4, any6 = any4 || a.Is4(), any6 || a.Is6()
			}
		}
	}
	binds = slices.DeleteFunc(binds, func(b string) bool {
		a, err := netip.ParseAddr(b)
		return err == nil && !a.IsUnspecified() && (a.Is4() && any4 || a.Is6() && any6)
	})
	for i := range c.Listeners {
		l := &c.Listeners[i]
		if l.Port != 80 {
			continue
		}
		where := fmt.Sprintf("[[listener]] %s at line %d", l.Name, l.Line)
		for _, a := range l.Binds {
			for _, b := range binds {
				if a == b || isWildcard(a) || isWildcard(b) {
					return fmt.Errorf("http_to_https_redirect listens on port 80, which %s also uses on %s", where, a)
				}
			}
		}
	}
	c.Redirect = &Listener{Name: RedirectListenerName, Bind: strings.Join(binds, "; "), Binds: binds, Port: 80, IsRedirect: true}
	return nil
}

func isWildcard(bind string) bool {
	a, err := netip.ParseAddr(bind)
	return err == nil && a.IsUnspecified()
}

// parseSize reads a byte count: plain, or with a K/M/G suffix (powers of
// 1024), e.g. "15MiB", "10M", "64k".
func parseSize(v string) (int64, error) {
	t := strings.ToUpper(strings.TrimSpace(v))
	t = strings.TrimSuffix(strings.TrimSuffix(t, "IB"), "B")
	unit := int64(1)
	if t != "" {
		switch t[len(t)-1] {
		case 'K':
			unit, t = 1<<10, t[:len(t)-1]
		case 'M':
			unit, t = 1<<20, t[:len(t)-1]
		case 'G':
			unit, t = 1<<30, t[:len(t)-1]
		}
	}
	n, err := strconv.ParseInt(strings.TrimSpace(t), 10, 64)
	if err != nil || n <= 0 || n > (1<<62)/unit {
		return 0, fmt.Errorf("invalid size %q (use a number with optional K, M or G)", v)
	}
	return n * unit, nil
}

// proxySettings validates and applies proxy / proxy_version. They apply to
// every allow rule: a passed-through backend needs the client's address as
// much as one behind a terminating rule.
func proxySettings(rule *Rule, r rawRule) error {
	rule.ProxyVersion = 2
	var err error
	if r.proxy != nil {
		if !rule.Allow {
			return fmt.Errorf("proxy makes no sense on a deny rule")
		}
		if rule.Proxy, err = parseBool(*r.proxy); err != nil {
			return fmt.Errorf("proxy: %v", err)
		}
	}
	if r.proxyVersion != nil {
		if !rule.Proxy {
			return fmt.Errorf("proxy_version only applies with proxy = true")
		}
		if rule.ProxyVersion, err = strconv.Atoi(*r.proxyVersion); err != nil || rule.ProxyVersion != 1 && rule.ProxyVersion != 2 {
			return fmt.Errorf("proxy_version must be 1 or 2, got %q", *r.proxyVersion)
		}
	}
	return nil
}

// speedSettings validates and applies max_aggregated_speed and
// max_single_connection_speed.
func speedSettings(rule *Rule, r rawRule) error {
	for _, kv := range []struct {
		name string
		v    *string
		dst  *float64
	}{{"max_aggregated_speed", r.aggSpeed, &rule.MaxAggregatedSpeed}, {"max_single_connection_speed", r.connSpeed, &rule.MaxSingleConnectionSpeed}} {
		if kv.v == nil {
			continue
		}
		if !rule.Allow {
			return fmt.Errorf("%s makes no sense on a deny rule", kv.name)
		}
		rate, err := parseRate(*kv.v)
		if err != nil {
			return fmt.Errorf("%s: %v", kv.name, err)
		}
		*kv.dst = rate
	}
	return nil
}

// tlsSettings validates and applies cert / cert_domains / upstream_tls*.
func tlsSettings(cfg *Config, rule *Rule, r rawRule) error {
	if r.cert == nil || *r.cert == "" {
		for _, kv := range []struct {
			name string
			v    *string
		}{{"cert_domains", r.certDomains}, {"cert_validate_script", r.certScript}, {"cert_validate_args", r.certArgs}, {"upstream_tls", r.upstreamTLS}, {"upstream_tls_verify", r.upstreamVerify}, {"upstream_sni", r.upstreamSNI}} {
			if kv.v != nil {
				return fmt.Errorf("%s only applies when the rule terminates TLS (set cert = auto or cert = local-ca)", kv.name)
			}
		}
		return nil
	}
	if !rule.Allow {
		return fmt.Errorf("cert makes no sense on a deny rule")
	}
	rule.Cert = *r.cert
	if _, local := localCARef(rule.Cert); !local && !strings.EqualFold(rule.Cert, "auto") {
		return fmt.Errorf("cert = %s: a certificate directory is no longer supported. Use cert = auto (ACME), or cert = local-ca: "+
			"import the CA that issued your certificate (its certificate and key) on the console's CAs page, and the proxy issues per name", rule.Cert)
	}
	rule.UpstreamTLS, rule.UpstreamTLSVerify = true, true
	var err error
	if r.upstreamTLS != nil {
		if rule.UpstreamTLS, err = parseBool(*r.upstreamTLS); err != nil {
			return fmt.Errorf("upstream_tls: %v", err)
		}
	}
	if r.upstreamVerify != nil {
		if rule.UpstreamTLSVerify, err = parseBool(*r.upstreamVerify); err != nil {
			return fmt.Errorf("upstream_tls_verify: %v", err)
		}
	}
	if r.upstreamSNI != nil {
		if rule.UpstreamSNI = strings.ToLower(*r.upstreamSNI); !validDomain(rule.UpstreamSNI) {
			return fmt.Errorf("upstream_sni: %q is not a valid host name", *r.upstreamSNI)
		}
		if !rule.UpstreamTLS {
			return fmt.Errorf("upstream_sni only applies with upstream_tls = true")
		}
	}
	if id, ok := localCARef(rule.Cert); ok {
		return localCASettings(rule, id, &r)
	}
	if !strings.EqualFold(rule.Cert, "auto") {
		if r.certDomains != nil {
			return fmt.Errorf("cert_domains only applies to cert = auto")
		}
		if r.certScript != nil {
			return fmt.Errorf("cert_validate_script only applies to cert = auto")
		}
		if r.certArgs != nil {
			return fmt.Errorf("cert_validate_args only applies to cert = auto")
		}
		return nil
	}
	rule.Cert = "auto"
	if !cfg.AcmeAgreeTOS {
		return fmt.Errorf("cert = auto needs acme_agree_tos = true in [global] (you accept the CA's terms of service)")
	}
	if rule.NoSNI {
		return fmt.Errorf("cert = auto needs a host name, and a pattern = NONE client sends none: use cert = local-ca, which issues for IP addresses")
	}
	if r.certDomains != nil {
		rule.CertDomains = splitList(strings.ToLower(*r.certDomains))
	} else if host, ok := literalHost(rule.Source); ok {
		rule.CertDomains = []string{host}
	}
	if r.certScript != nil {
		if rule.CertValidateScript = *r.certScript; rule.CertValidateScript == "" {
			return fmt.Errorf("cert_validate_script must not be empty")
		}
	}
	rule.CertValidateArgs = []string{"${host}"}
	if r.certArgs != nil {
		if r.certScript == nil {
			return fmt.Errorf("cert_validate_args needs a cert_validate_script")
		}
		json.Unmarshal([]byte(*r.certArgs), &rule.CertValidateArgs) // arrayValue made it
		if len(rule.CertValidateArgs) == 0 {
			return fmt.Errorf("cert_validate_args needs at least one argument, e.g. [\"${host}\"]: the script must be told the name")
		}
		groups := 0
		if rule.Pattern != nil {
			groups = rule.Pattern.NumSubexp()
		}
		probe := make([]int, 2*(groups+1))
		for _, a := range rule.CertValidateArgs {
			if _, err := expand(a, "", probe); err != nil {
				return fmt.Errorf("cert_validate_args: %q: %v", a, err)
			}
		}
	}
	if len(rule.CertDomains) == 0 && rule.CertValidateScript == "" {
		return fmt.Errorf("cert = auto with a wildcard or ANY pattern needs cert_domains = name1, name2 (certificates are issued per exact name) or a cert_validate_script that decides per name")
	}
	for _, d := range rule.CertDomains {
		if !validDomain(d) {
			return fmt.Errorf("cert_domains: %q is not a valid host name (wildcards are not possible with TLS-ALPN-01)", d)
		}
		if !rule.Pattern.MatchString(d) {
			return fmt.Errorf("cert_domains: %q does not match this rule's pattern %q", d, rule.Source)
		}
	}
	return nil
}

// literalHost reports whether a pattern is just one host name (dots escaped
// or not, optional ^ and $), and returns that name lowercased.
func literalHost(pattern string) (string, bool) {
	p := strings.TrimSuffix(strings.TrimPrefix(pattern, "^"), "$")
	p = strings.ToLower(strings.ReplaceAll(p, `\.`, "."))
	return p, validDomain(p)
}

func validDomain(d string) bool {
	if d == "" || len(d) > 253 || !strings.Contains(d, ".") || strings.HasPrefix(d, ".") || strings.HasSuffix(d, ".") || strings.Contains(d, "..") {
		return false
	}
	for i := 0; i < len(d); i++ {
		if !isHostChar(d[i]) || d[i] == '_' {
			return false
		}
	}
	return true
}

// splitList splits on ';' and ',' and drops empty items.
func splitList(v string) []string {
	var out []string
	for _, item := range strings.FieldsFunc(v, func(r rune) bool { return r == ';' || r == ',' }) {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func parseBool(v string) (bool, error) {
	switch strings.ToLower(v) {
	case "true", "yes", "on":
		return true, nil
	case "false", "no", "off":
		return false, nil
	}
	return false, fmt.Errorf("expected true or false, got %q", v)
}

func parsePort(v string) (int, error) {
	p, err := strconv.ParseUint(v, 10, 16)
	if err != nil || p == 0 {
		return 0, fmt.Errorf("invalid port %q", v)
	}
	return int(p), nil
}

func parseValue(v string) (string, error) {
	v = strings.TrimSpace(v)
	restIsComment := func(rest string) error {
		rest = strings.TrimSpace(rest)
		if rest == "" || strings.HasPrefix(rest, "#") {
			return nil
		}
		return fmt.Errorf("unexpected text after value: %q", rest)
	}
	if strings.HasPrefix(v, `"`) {
		var out strings.Builder
		body := v[1:]
		for i := 0; i < len(body); i++ {
			switch c := body[i]; c {
			case '"':
				return out.String(), restIsComment(body[i+1:])
			case '\\':
				i++
				if i >= len(body) {
					return "", fmt.Errorf("unterminated string")
				}
				switch body[i] {
				case '"':
					out.WriteByte('"')
				case '\\':
					out.WriteByte('\\')
				case 't':
					out.WriteByte('\t')
				case 'n':
					out.WriteByte('\n')
				default: // kept verbatim, so "\." works for regexes
					out.WriteByte('\\')
					out.WriteByte(body[i])
				}
			default:
				out.WriteByte(c)
			}
		}
		return "", fmt.Errorf("unterminated string")
	}
	if strings.HasPrefix(v, "'") {
		end := strings.IndexByte(v[1:], '\'')
		if end < 0 {
			return "", fmt.Errorf("unterminated string")
		}
		return v[1 : 1+end], restIsComment(v[2+end:])
	}
	// Bare value: up to a " #" comment.
	if i := strings.Index(v, " #"); i >= 0 {
		v = v[:i]
	} else if i := strings.Index(v, "\t#"); i >= 0 {
		v = v[:i]
	}
	return strings.TrimSpace(v), nil
}

// localCARef reads cert = local-ca or local-ca:caNNN, giving the CA's id.
func localCARef(cert string) (id string, ok bool) {
	rest, ok := strings.CutPrefix(strings.ToLower(cert), "local-ca")
	switch {
	case !ok:
		return "", false
	case rest == "":
		return "ca001", true
	case strings.HasPrefix(rest, ":"):
		return rest[1:], true
	}
	return "", false
}

// localCASettings checks a cert = local-ca rule. cert_domains, if given,
// limits which names get a certificate; otherwise any name the rule routes
// does. Its IP addresses (NONE and ANY rules only) are what a client without
// a host name gets a certificate for; a NONE rule's host names join them.
func localCASettings(rule *Rule, id string, r *rawRule) error {
	if !caIDPattern.MatchString(id) {
		return fmt.Errorf("cert = local-ca:%s: a CA is named ca001, ca002, ... (three digits)", id)
	}
	rule.Cert = "local-ca:" + id
	if r.certScript != nil || r.certArgs != nil {
		return fmt.Errorf("cert_validate_script only applies to cert = auto; with local-ca, cert_domains limits the names")
	}
	if r.certDomains == nil {
		return nil
	}
	// Host names or globs, the way patterns are written: *.dev.abc.com
	// (a * never crosses a dot), and IP addresses, separated by , or ;.
	rule.CertDomains = splitList(strings.ToLower(*r.certDomains))
	if len(rule.CertDomains) == 0 {
		return fmt.Errorf("cert_domains is empty: leave it out to issue for every name the rule matches")
	}
	noHost := rule.NoSNI || rule.Kind == kindCatchAll
	for _, d := range rule.CertDomains {
		if ip, err := netip.ParseAddr(strings.Trim(d, "[]")); err == nil {
			switch {
			case ip.Zone() != "":
				return fmt.Errorf("cert_domains: %q: an IP address in a certificate has no zone", d)
			case !noHost:
				return fmt.Errorf("cert_domains: %s is an IP address: it only applies to pattern = NONE or ANY, which serve clients that send no host name", d)
			case slices.Contains(rule.certIPs, ip.Unmap()):
				return fmt.Errorf("cert_domains lists %s twice", d)
			}
			rule.certIPs = append(rule.certIPs, ip.Unmap())
			continue
		}
		if rule.NoSNI {
			// The one certificate these clients get carries the names too.
			if !isHostName(d) {
				return fmt.Errorf("cert_domains: %q: a pattern = NONE rule takes IP addresses and plain host names (no *), all in the one certificate it serves", d)
			}
			if !slices.Contains(rule.certHosts, d) {
				rule.certHosts = append(rule.certHosts, d)
			}
			continue
		}
		kind, expr, _, err := classify(d)
		if err != nil || (kind != kindLiteral && kind != kindWildcard) {
			return fmt.Errorf("cert_domains: %q is not a host name, a glob like *.dev.example.com or an IP address", d)
		}
		if kind == kindLiteral && !rule.Pattern.MatchString(d) {
			return fmt.Errorf("cert_domains: %q does not match this rule's pattern %q", d, rule.Source)
		}
		rule.certNames = append(rule.certNames, regexp.MustCompile("^(?:"+expr+")$"))
	}
	if len(rule.certIPs) > 0 {
		rule.certKey = sanKey(rule.certIPs, rule.certHosts)
	}
	if key := sanKey(rule.certIPs, rule.certHosts); len(localCAFolder(key)) > 200 {
		return fmt.Errorf("cert_domains: too many names for one certificate (its folder name would be %d characters, at most 200)", len(localCAFolder(key)))
	}
	return nil
}

// LocalCAIssues reports whether a cert = local-ca rule issues for a host
// name: any name the rule routes, or only those cert_domains matches when it
// is set (a list of IP addresses alone issues for no host name).
func (r *Rule) LocalCAIssues(name string) bool {
	if len(r.CertDomains) == 0 {
		return true
	}
	for _, re := range r.certNames {
		if re.MatchString(name) {
			return true
		}
	}
	return false
}

// LocalCAName is the certificate a cert = local-ca rule serves a client:
// the host name it sent, or for a client without one (NONE, ANY), the
// rule's IP addresses (and a NONE rule's host names) in one certificate,
// else the address the client connected to (dialed). An IP address the
// client sent as its server name (sniIP) must be in cert_domains. The
// error is why the client is refused.
func (r *Rule) LocalCAName(sni string, sniIP, dialed netip.Addr) (string, error) {
	if sni != "" {
		if !isHostName(sni) {
			return "", fmt.Errorf("%q is not a host name to issue for", sni)
		}
		if !r.LocalCAIssues(sni) {
			return "", fmt.Errorf("it does not issue for %s: it matches none of cert_domains (%s)", sni, strings.Join(r.CertDomains, ", "))
		}
		return sni, nil
	}
	if sniIP.IsValid() && !slices.Contains(r.certIPs, sniIP) {
		return "", fmt.Errorf("the client asked for %s (an IP address as its server name), which cert_domains does not list", sniIP)
	}
	if r.certKey != "" {
		return r.certKey, nil
	}
	if !dialed.IsValid() {
		return "", fmt.Errorf("the client sent no host name, and the address it connected to is unknown")
	}
	return sanKey([]netip.Addr{dialed.WithZone("").Unmap()}, r.certHosts), nil
}

// LocalCA is the CA id of a cert = local-ca rule, "" for any other rule.
func (r *Rule) LocalCA() string {
	id, _ := strings.CutPrefix(r.Cert, "local-ca:")
	if id == r.Cert {
		return ""
	}
	return id
}

// arrayValue reads a TOML array of strings, ["a", 'b'], with an optional
// comment after it, and returns it as a JSON array.
func arrayValue(v string) (string, error) {
	v = strings.TrimSpace(v)
	if !strings.HasPrefix(v, "[") {
		return "", fmt.Errorf(`expected an array of strings, like ["${host}"] or ["--name", "${1}"]`)
	}
	var out []string
	rest := strings.TrimSpace(v[1:])
	for {
		if strings.HasPrefix(rest, "]") {
			rest = strings.TrimSpace(rest[1:])
			break
		}
		if rest == "" || (rest[0] != '"' && rest[0] != '\'') {
			return "", fmt.Errorf(`expected an array of quoted strings, like ["${host}"] or ["--name", "${1}"]`)
		}
		// One string: find its end the way parseValue reads it.
		end := -1
		if rest[0] == '\'' {
			if k := strings.IndexByte(rest[1:], '\''); k >= 0 {
				end = k + 2
			}
		} else {
			for i := 1; i < len(rest); i++ {
				if rest[i] == '\\' {
					i++
				} else if rest[i] == '"' {
					end = i + 1
					break
				}
			}
		}
		if end < 0 {
			return "", fmt.Errorf("unterminated string in array")
		}
		s, err := parseValue(rest[:end])
		if err != nil {
			return "", err
		}
		out = append(out, s)
		rest = strings.TrimSpace(rest[end:])
		if strings.HasPrefix(rest, ",") {
			rest = strings.TrimSpace(rest[1:])
		} else if !strings.HasPrefix(rest, "]") {
			return "", fmt.Errorf("expected , or ] in array")
		}
	}
	if rest != "" && !strings.HasPrefix(rest, "#") {
		return "", fmt.Errorf("unexpected text after array: %q", rest)
	}
	if out == nil {
		out = []string{}
	}
	data, _ := json.Marshal(out)
	return string(data), nil
}

// Describe summarises the settings for the startup / reload log line.
func (c *Config) Describe() string {
	return fmt.Sprintf("%d listener(s), %d rules (max_connections=%d, idle_timeout=%ds, half_close_timeout=%ds, buffer_size=%d, buffer_pool_max_idle=%d, allow_cache_size=%d, deny_cache_size=%d, short_read_delay_us=%d, splice=%t)",
		len(c.Listeners), len(c.Rules), c.MaxConnections, int(c.IdleTimeout.Seconds()), int(c.HalfCloseTimeout.Seconds()),
		c.BufferSize, c.BufferPoolMaxIdle, c.AllowCacheSize, c.DenyCacheSize, c.ShortReadDelay.Microseconds(), c.Splice)
}

// AutoDomains lists every name that needs an automatic certificate.
func (c *Config) AutoDomains() []string {
	seen := map[string]bool{}
	var out []string
	for i := range c.Rules {
		if c.Rules[i].Cert != "auto" {
			continue
		}
		for _, d := range c.Rules[i].CertDomains {
			if !seen[d] {
				seen[d] = true
				out = append(out, d)
			}
		}
	}
	return out
}
