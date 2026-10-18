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
	sourceHash         string   // exact parsed bytes, for password rewrites and reload change detection
	Bind               string   // as configured, normalised: "0.0.0.0", or "192.0.2.1; 2001:db8::1"
	Binds              []string // the addresses in Bind
	Port               int
	HandshakeTimeout   time.Duration
	ConnectTimeout     time.Duration
	IdleTimeout        time.Duration // no traffic either way for this long closes; 0 = never
	HalfCloseTimeout   time.Duration // after one side closes, the other gets this long; 0 = unlimited
	MaxConnections     int
	MaxHandshakesPerIP int // connections per source still sending their ClientHello; 0 = unlimited
	// ProxyProtocolFrom lists who may put a PROXY protocol header in front of a
	// connection (a load balancer ahead of this proxy). Empty: nobody, headers
	// are never looked for.
	ProxyProtocolFrom []netip.Prefix
	BufferSize        int
	BufferPoolMaxIdle int
	AllowCacheSize    int
	DenyCacheSize     int
	ReloadInterval    time.Duration // 0 = never
	StatsInterval     time.Duration // 0 = never
	ShortReadDelay    time.Duration // pause after a short read so data batches up; 0 = off
	Splice            bool          // relay passed-through connections with splice(2) (Linux only)
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

	Console   *ConsoleConfig // the [console] section; nil = no web console
	Rules     []Rule         // in file order
	Listeners []Listener     // in file order; one implicit "default" from [global] when the file has none
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
	Line  int // 0 = implicit, made from [global] bind and port
	Bind  string
	Binds []string
	Port  int

	ProxyProtocolFrom                               *[]netip.Prefix
	MaxConnections                                  int // on top of [global] max_connections
	HandshakeTimeout, IdleTimeout, HalfCloseTimeout *time.Duration
	MaxAggregatedSpeed, MaxSingleConnectionSpeed    float64 // bytes per second, each direction

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
	if l.ProxyProtocolFrom != nil {
		eff.ProxyProtocolFrom = *l.ProxyProtocolFrom
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

// ConsoleConfig is the [console] section: a web console on its own port.
// Plain HTTP by design: bind it to loopback and publish it through a
// terminating rule of this proxy if it must be reachable from elsewhere.
type ConsoleConfig struct {
	SecureCookie bool // require HTTPS for session cookies when published through TLS termination
	Listen       string
	Port         int
	Password     string   // plaintext, only until the proxy replaces it with PasswordHash
	PasswordHash string   // pbkdf2-sha256$...
	Hostnames    []string // extra names the console may be addressed by (Host header check)
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

	// TLS termination: set when the rule has cert = auto | <dir>. Without it
	// the rule passes TLS through untouched.
	Cert        string           // "", "auto", or a directory holding cert.pem + key.pem (+ ca.pem)
	CertDomains []string         // auto: names to issue for; local-ca: the glob patterns that may get one
	certNames   []*regexp.Regexp // local-ca: CertDomains compiled, anchored
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

// trustsProxyProtocolFrom reports whether a peer may assert another source
// address with a PROXY protocol header.
func (c *Config) trustsProxyProtocolFrom(peer net.Addr) bool {
	tcp, ok := peer.(*net.TCPAddr)
	if !ok || len(c.ProxyProtocolFrom) == 0 {
		return false
	}
	ip, _ := netip.AddrFromSlice(tcp.IP)
	ip = ip.Unmap()
	for _, prefix := range c.ProxyProtocolFrom {
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
}

// buffer_size is clamped to this range.
const (
	minBufferSize = 4 << 10
	maxBufferSize = 128 << 10
)

func ParseConfig(text string) (*Config, error) {
	cfg := &Config{
		sourceHash:         fileHash([]byte(text)),
		Bind:               "0.0.0.0",
		Binds:              []string{"0.0.0.0"},
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
		Log:                defaultLogConfig(),

		CertPath:            "./certs",
		CARoot:              "./ca",
		ExpiryThresholdDays: 15,
		AcmeDirectory:       LetsEncryptDirectory,
	}
	poolMaxIdle := -1
	globalListenLine := 0 // where [global] sets bind or port
	var raws []rawRule
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
				if cfg.Console == nil {
					cfg.Console = &ConsoleConfig{Listen: "127.0.0.1"}
				}
				continue
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
			case "bind":
				if cfg.Binds, err = parseBinds(value); err != nil {
					return nil, fail("%v", err)
				}
				cfg.Bind, globalListenLine = strings.Join(cfg.Binds, "; "), lineno
			case "port":
				if cfg.Port, err = parsePort(value); err != nil {
					return nil, fail("%v", err)
				}
				globalListenLine = lineno
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
				if cfg.ProxyProtocolFrom, err = parsePrefixes(value); err != nil {
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
		case "console":
			switch key {
			case "listen":
				cfg.Console.Listen = strings.Trim(value, "[]")
			case "port":
				if cfg.Console.Port, err = parsePort(value); err != nil {
					return nil, fail("%v", err)
				}
			case "password":
				cfg.Console.Password = value
			case "password_hash":
				if _, _, _, herr := parseHash(value); herr != nil {
					return nil, fail("password_hash: %v", herr)
				}
				cfg.Console.PasswordHash = value
			case "secure_cookie":
				if cfg.Console.SecureCookie, err = parseBool(value); err != nil {
					return nil, fail("secure_cookie: %v", err)
				}
			case "hostnames":
				cfg.Console.Hostnames = splitList(strings.ToLower(value))
			default:
				return nil, fail("unknown key %q in [console]", key)
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
				return nil, fail("unknown key %q in [[host]]", key)
			}
		default:
			return nil, fail("key outside of any section")
		}
	}

	if poolMaxIdle < 0 {
		poolMaxIdle = 2 * cfg.MaxConnections
	}
	cfg.BufferPoolMaxIdle = poolMaxIdle
	if err := cfg.resolveListeners(globalListenLine); err != nil {
		return nil, err
	}
	for _, r := range raws {
		fail := func(format string, a ...any) error {
			return fmt.Errorf("[[host]] at line %d: %s", r.line, fmt.Sprintf(format, a...))
		}
		if r.pattern == nil {
			return nil, fail("pattern is required")
		}
		rule := Rule{Line: r.line, Source: *r.pattern}
		switch {
		case r.listener != nil:
			if cfg.Listener(*r.listener) == nil {
				return nil, fail("listener = %s: there is no [[listener]] named %s (listeners: %s)", *r.listener, *r.listener, cfg.listenerNames())
			}
			rule.Listener = *r.listener
		case len(cfg.Listeners) == 1:
			rule.Listener = cfg.Listeners[0].Name
		default:
			return nil, fail("listener = <name> is required: this file has %d listeners (%s)", len(cfg.Listeners), cfg.listenerNames())
		}
		groups := 0
		expr := ""
		var err error
		if rule.Kind, expr, rule.literalChars, err = classify(*r.pattern); err != nil {
			return nil, fail("%v", err)
		}
		if rule.Kind == kindNone {
			rule.NoSNI = true
		} else {
			// Whole-name, case-insensitive match.
			rule.Pattern, err = regexp.Compile("(?i)^(?:" + expr + ")$")
			if err != nil {
				return nil, fail("bad pattern %q: %v", *r.pattern, err)
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
			if r.targetHost == nil {
				return nil, fail("target_host is required for allow")
			}
			rule.TargetHost = *r.targetHost
			// The port always goes in target_port. A ':' is only legal in an
			// IPv6 address; "host:8080" would otherwise be dialled as a name.
			if strings.Contains(rule.TargetHost, ":") {
				if _, err := netip.ParseAddr(rule.TargetHost); err != nil {
					return nil, fail("target_host %q must not contain a port: use target_port (an IPv6 address is written without brackets)", rule.TargetHost)
				}
			}
			rule.TargetPort = 443
			if r.tport != nil {
				if rule.TargetPort, err = parsePort(*r.tport); err != nil {
					return nil, fail("%v", err)
				}
			}
			// Catch bad group references now rather than per connection.
			probe := make([]int, 2*(groups+1))
			if _, err := expand(rule.TargetHost, "", probe); err != nil {
				return nil, fail("target_host: %v", err)
			}
		default:
			return nil, fail("action must be allow or deny, got %q", action)
		}
		if err := tlsSettings(cfg, &rule, r); err != nil {
			return nil, fail("%v", err)
		}
		if err := proxySettings(&rule, r); err != nil {
			return nil, fail("%v", err)
		}
		if err := speedSettings(&rule, r); err != nil {
			return nil, fail("%v", err)
		}
		cfg.Rules = append(cfg.Rules, rule)
	}
	if err := cfg.prioritise(); err != nil {
		return nil, err
	}
	for i := range cfg.Rules {
		if r := &cfg.Rules[i]; r.Allow && r.Kind == kindCatchAll && strings.Contains(strings.ReplaceAll(r.TargetHost, "$$", ""), "$") {
			cfg.Warnings = append(cfg.Warnings, fmt.Sprintf("[[host]] at line %d: pattern = %s with target_host = %s connects to whatever name a client sends (port %d), internal names included. List the names or domains you mean to allow instead", r.Line, r.Source, r.TargetHost, r.TargetPort))
		}
	}
	if c := cfg.Console; c != nil {
		if c.Port == 0 {
			return nil, fmt.Errorf("[console] port is required")
		}
		if c.Password == "" && c.PasswordHash == "" {
			return nil, fmt.Errorf("[console] needs a password: set password = <text> (the proxy replaces it with a hash) or password_hash")
		}
		if ip := net.ParseIP(c.Listen); ip == nil || !ip.IsLoopback() {
			cfg.Warnings = append(cfg.Warnings, fmt.Sprintf("[console] listens on %s over plain HTTP: the password crosses the network unencrypted. Prefer listen = 127.0.0.1 behind a terminating rule", c.Listen))
		}
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
					cfg.Warnings = append(cfg.Warnings, fmt.Sprintf("cert = auto: public_ip_address lists the IPv6 address %s, but bind = %s listens on IPv4 only. The CA prefers IPv6 when a name has an AAAA record, and would not reach this proxy; use bind = :: to listen on both", ip, cfg.Bind))
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

// parsePrefixes reads proxy_protocol_from: addresses or networks.
func parsePrefixes(value string) ([]netip.Prefix, error) {
	out := []netip.Prefix{}
	for _, item := range splitList(value) {
		prefix, perr := netip.ParsePrefix(item)
		if addr, aerr := netip.ParseAddr(item); aerr == nil {
			prefix, perr = netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen()), nil
		}
		if perr != nil {
			return nil, fmt.Errorf("proxy_protocol_from: %q is not an IP address or a network (10.0.0.0/8)", item)
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
		var p []netip.Prefix
		if p, err = parsePrefixes(value); err == nil {
			l.ProxyProtocolFrom = &p
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

// resolveListeners checks the [[listener]] sections, or makes the implicit
// one from [global] bind and port when there are none.
func (c *Config) resolveListeners(globalListenLine int) error {
	if len(c.Listeners) == 0 {
		if c.Port == 0 {
			return fmt.Errorf("[global] port is required (or define [[listener]] sections)")
		}
		c.Listeners = []Listener{{Name: "default", Bind: c.Bind, Binds: c.Binds, Port: c.Port}}
		return nil
	}
	if globalListenLine != 0 {
		return fmt.Errorf("line %d: with [[listener]] sections, bind and port belong in them, not in [global]", globalListenLine)
	}
	for i := range c.Listeners {
		l := &c.Listeners[i]
		fail := func(format string, a ...any) error {
			return fmt.Errorf("[[listener]] at line %d: %s", l.Line, fmt.Sprintf(format, a...))
		}
		if l.Name == "" {
			return fail("name is required")
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
		return fmt.Errorf("cert = auto needs a host name; a pattern = NONE rule can only use cert = <directory>")
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
// does.
func localCASettings(rule *Rule, id string, r *rawRule) error {
	if !caIDPattern.MatchString(id) {
		return fmt.Errorf("cert = local-ca:%s: a CA is named ca001, ca002, ... (three digits)", id)
	}
	rule.Cert = "local-ca:" + id
	if rule.NoSNI {
		return fmt.Errorf("cert = local-ca needs a host name to issue for; a pattern = NONE rule can only use cert = <directory>")
	}
	if r.certScript != nil || r.certArgs != nil {
		return fmt.Errorf("cert_validate_script only applies to cert = auto; with local-ca, cert_domains limits the names")
	}
	if r.certDomains != nil {
		// Host names or globs, the way patterns are written: *.dev.abc.com
		// (a * never crosses a dot), several separated by , or ;.
		rule.CertDomains = splitList(strings.ToLower(*r.certDomains))
		if len(rule.CertDomains) == 0 {
			return fmt.Errorf("cert_domains is empty: leave it out to issue for every name the rule matches")
		}
		for _, d := range rule.CertDomains {
			kind, expr, _, err := classify(d)
			if err != nil || (kind != kindLiteral && kind != kindWildcard) {
				return fmt.Errorf("cert_domains: %q is not a host name or a glob like *.dev.example.com", d)
			}
			if kind == kindLiteral && !rule.Pattern.MatchString(d) {
				return fmt.Errorf("cert_domains: %q does not match this rule's pattern %q", d, rule.Source)
			}
			rule.certNames = append(rule.certNames, regexp.MustCompile("^(?:"+expr+")$"))
		}
	}
	return nil
}

// LocalCAIssues reports whether a cert = local-ca rule issues for name: any
// name the rule routes, or only those cert_domains matches when it is set.
func (r *Rule) LocalCAIssues(name string) bool {
	if len(r.certNames) == 0 {
		return true
	}
	for _, re := range r.certNames {
		if re.MatchString(name) {
			return true
		}
	}
	return false
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
