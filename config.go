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
// characters first), then regexes in file order, the catch-all last. A host
// that matches no rule is denied.

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// MinReloadInterval gates reloads to at most one per this many seconds.
const MinReloadInterval = 5

type Config struct {
	Bind              string
	Port              int
	HandshakeTimeout  time.Duration
	ConnectTimeout    time.Duration
	IdleTimeout       time.Duration // no traffic either way for this long closes; 0 = never
	HalfCloseTimeout  time.Duration // after one side closes, the other gets this long; 0 = unlimited
	MaxConnections    int
	BufferSize        int
	BufferPoolMaxIdle int
	AllowCacheSize    int
	DenyCacheSize     int
	ReloadInterval    time.Duration // 0 = never
	StatsInterval     time.Duration // 0 = never
	ShortReadDelay    time.Duration // pause after a short read so data batches up; 0 = off
	Log               LogConfig     // the [logging] section

	// Certificates (only used by rules with cert = ...).
	CertPath            string   // where automatic certificates and the ACME account live
	ExpiryThresholdDays int      // renew this many days before expiry
	PublicIPs           []string // auto-issue only if the name resolves to one of these
	DNSResolvers        []string // public resolvers for that check (host or host:port)
	AcmeEmail           string   // optional contact for the ACME account
	AcmeAgreeTOS        bool     // must be true before anything is issued
	AcmeDirectory       string   // ACME directory URL
	AcmeCAFile          string   // extra root CA for the ACME server's HTTPS (private CAs, Pebble)
	Warnings            []string // non-fatal findings, logged at startup / reload

	Console *ConsoleConfig // the [console] section; nil = no web console
	Rules   []Rule         // in file order
	// How Route evaluates them: literal names by lookup, everything else in
	// order of specificity.
	literals   map[string]*Rule
	byPriority []*Rule
	// Legacy settings that no longer apply and were ignored.
	Ignored []string
}

// ConsoleConfig is the [console] section: a web console on its own port.
// Plain HTTP by design: bind it to loopback and publish it through a
// terminating rule of this proxy if it must be reachable from elsewhere.
type ConsoleConfig struct {
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
	kindWildcard                 // *.example.com: * is one label (or part of one), ** one or more labels
	kindRegex                    // anything else: a regular expression; file order among themselves
	kindCatchAll                 // .* (or * / **): always last
)

func (k ruleKind) String() string {
	return [...]string{"no SNI", "literal", "wildcard", "regex", "catch-all"}[k]
}

type Rule struct {
	Line   int
	Source string
	Kind   ruleKind
	// literalChars ranks wildcards (more is more specific); multiLabel (a **
	// in the pattern) ranks after an equally long single-label wildcard.
	literalChars int
	multiLabel   bool
	// NoSNI is set by `pattern = NONE` (any case): the rule matches only
	// connections without an SNI, and Pattern is nil.
	NoSNI      bool
	Pattern    *regexp.Regexp
	Allow      bool
	TargetHost string
	TargetPort int

	// TLS termination: set when the rule has cert = auto | <dir>. Without it
	// the rule passes TLS through untouched.
	Cert        string   // "", "auto", or a directory holding cert.pem + key.pem (+ ca.pem)
	CertDomains []string // names to issue for when Cert is "auto"
	// CertValidateScript decides about names that match the pattern but are
	// not in CertDomains: run as `<script> <name>` only when a certificate has
	// to be issued or renewed; exit status 0 accepts the name.
	CertValidateScript string
	UpstreamTLS        bool   // connect to the target with TLS (default true)
	UpstreamTLSVerify  bool   // verify the target's certificate (default true)
	UpstreamSNI        string // SNI sent to (and verified against) the target; "" = the client's SNI
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
// is matched as "" by regexes and the catch-all (after a NONE rule, if any).
func (c *Config) Route(sni string) Decision {
	if r := c.literals[sni]; r != nil {
		return r.decide(sni, []int{0, len(sni)})
	}
	for _, r := range c.byPriority {
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
		for i := 0; i < len(host); i++ {
			if !isHostChar(host[i]) && host[i] != ':' {
				err = fmt.Errorf("invalid")
				break
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
// expression that implements it (unanchored; "" for NONE).
//
//	NONE                          no SNI
//	vq.example.com                literal; so are vq\.example\.com and ^vq.example.com$
//	*.example.com  api-*.x.com    wildcard: * stays within one label, so *.example.com
//	**.example.com                does not match a.b.example.com; ** spans one or more labels
//	.*  (.*)  *  **               catch-all
//	anything else                 regular expression (RE2)
//
// A wildcard has no backslash and no empty label; its *s are capture groups,
// so $1 works in target_host as it does for a regex.
func classify(pattern string) (kind ruleKind, expr string, literalChars int, multiLabel bool, err error) {
	if strings.EqualFold(pattern, "none") {
		return kindNone, "", 0, false, nil
	}
	bare := strings.TrimSuffix(strings.TrimPrefix(pattern, "^"), "$")
	switch bare {
	case ".*", "(.*)":
		return kindCatchAll, pattern, 0, false, nil
	case "*", "**":
		return kindCatchAll, "(.*)", 0, false, nil
	}
	hostOnly := func(s string, star bool) bool {
		for i := 0; i < len(s); i++ {
			if !isHostChar(s[i]) && !(star && s[i] == '*') {
				return false
			}
		}
		return s != ""
	}
	if name := literalName(pattern); hostOnly(name, false) {
		return kindLiteral, regexp.QuoteMeta(name), len(name), false, nil
	}
	if !strings.Contains(pattern, "*") || !hostOnly(pattern, true) ||
		strings.HasPrefix(pattern, ".") || strings.HasSuffix(pattern, ".") || strings.Contains(pattern, "..") {
		return kindRegex, pattern, 0, false, nil
	}
	if strings.Contains(pattern, "***") {
		return 0, "", 0, false, fmt.Errorf("bad wildcard %q: use * for one label or ** for one or more", pattern)
	}
	var out strings.Builder
	for i := 0; i < len(pattern); i++ {
		switch {
		case strings.HasPrefix(pattern[i:], "**"):
			out.WriteString(`([^.]+(?:\.[^.]+)*)`)
			multiLabel = true
			i++
		case pattern[i] == '*':
			out.WriteString(`([^.]+)`)
		default:
			out.WriteString(regexp.QuoteMeta(pattern[i : i+1]))
			literalChars++
		}
	}
	return kindWildcard, out.String(), literalChars, multiLabel, nil
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
	c.literals = map[string]*Rule{}
	var first [kindCatchAll + 1]*Rule // the first NONE and catch-all rule
	for i := range c.Rules {
		r := &c.Rules[i]
		switch r.Kind {
		case kindLiteral:
			name := literalName(r.Source)
			if prev := c.literals[name]; prev != nil {
				return fmt.Errorf("[[host]] at line %d: %s already has a rule at line %d; only one of them could ever match", r.Line, name, prev.Line)
			}
			c.literals[name] = r
			continue
		case kindNone, kindCatchAll:
			if prev := first[r.Kind]; prev != nil {
				return fmt.Errorf("[[host]] at line %d: pattern = %s can never match, the rule at line %d (%s) already matches the same clients", r.Line, r.Source, prev.Line, prev.Source)
			}
			first[r.Kind] = r
		}
		c.byPriority = append(c.byPriority, r)
	}
	sort.SliceStable(c.byPriority, func(i, j int) bool {
		a, b := c.byPriority[i], c.byPriority[j]
		switch {
		case a.Kind != b.Kind:
			return a.Kind < b.Kind
		case a.Kind != kindWildcard:
			return false // regexes keep their file order
		case a.literalChars != b.literalChars:
			return a.literalChars > b.literalChars
		default:
			return !a.multiLabel && b.multiLabel
		}
	})
	// Say so once when that differs from a top-to-bottom reading of the file:
	// a rule that an earlier, broader rule would have caught.
	var later []string
	for i := range c.Rules {
		r := &c.Rules[i]
		for k := 0; k < i; k++ {
			prev := &c.Rules[k]
			name := literalName(r.Source)
			if prev.Kind > r.Kind && (prev.Kind == kindCatchAll || r.Kind == kindLiteral && prev.Pattern.MatchString(name)) {
				later = append(later, fmt.Sprintf("line %d (%s, %s) wins over line %d (%s, %s)", r.Line, r.Source, r.Kind, prev.Line, prev.Source, prev.Kind))
				break
			}
		}
	}
	if len(later) > 0 {
		c.Warnings = append(c.Warnings, "rules are evaluated by specificity, not file order (literal names, then wildcards, then regexes, the catch-all last): "+strings.Join(later, "; "))
	}
	return nil
}

// expand replaces $N / ${N} in template with capture groups ($0 = whole
// match, $$ = literal $). Groups that did not participate expand to "".
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
		i++
		var digits string
		switch {
		case i < len(template) && template[i] == '$':
			out.WriteByte('$')
			i++
			continue
		case i < len(template) && template[i] == '{':
			end := strings.IndexByte(template[i:], '}')
			if end < 0 {
				return "", fmt.Errorf("unterminated ${ in target")
			}
			digits = template[i+1 : i+end]
			i += end + 1
		default:
			j := i
			for j < len(template) && template[j] >= '0' && template[j] <= '9' {
				j++
			}
			digits = template[i:j]
			i = j
		}
		n, err := strconv.Atoi(digits)
		if err != nil || n < 0 {
			return "", fmt.Errorf("bad group reference in %q", template)
		}
		if 2*n+1 >= len(m) {
			return "", fmt.Errorf("group $%d does not exist in pattern", n)
		}
		if m[2*n] >= 0 {
			out.WriteString(input[m[2*n]:m[2*n+1]])
		}
	}
	return out.String(), nil
}

// LetsEncryptDirectory is the default ACME directory.
const LetsEncryptDirectory = "https://acme-v02.api.letsencrypt.org/directory"

type rawRule struct {
	cert, certDomains, certScript, upstreamTLS, upstreamVerify, upstreamSNI *string
	line                                                                    int
	pattern, action, targetHost, tport                                      *string
}

func ParseConfig(text string) (*Config, error) {
	cfg := &Config{
		Bind:             "0.0.0.0",
		HandshakeTimeout: 10 * time.Second,
		ConnectTimeout:   10 * time.Second,
		IdleTimeout:      600 * time.Second,
		HalfCloseTimeout: 30 * time.Second,
		MaxConnections:   1024,
		BufferSize:       64 * 1024,
		AllowCacheSize:   4096,
		DenyCacheSize:    4096,
		ReloadInterval:   5 * time.Second,
		StatsInterval:    60 * time.Second,
		Log:              defaultLogConfig(),

		CertPath:            "./certs",
		ExpiryThresholdDays: 15,
		DNSResolvers:        []string{"1.1.1.1", "8.8.8.8"},
		AcmeDirectory:       LetsEncryptDirectory,
	}
	poolMaxIdle := -1
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
			if section != "host" {
				return nil, fail("unknown section [[%s]]", section)
			}
			raws = append(raws, rawRule{line: lineno})
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
		value, err := parseValue(line[eq+1:])
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
				cfg.Bind = value
			case "port":
				if cfg.Port, err = parsePort(value); err != nil {
					return nil, fail("%v", err)
				}
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
			case "allow_cache_size":
				err = count(&cfg.AllowCacheSize)
			case "deny_cache_size":
				err = count(&cfg.DenyCacheSize)
			case "buffer_pool_max_idle":
				err = count(&poolMaxIdle)
			case "buffer_size":
				if err = count(&cfg.BufferSize); err == nil && (cfg.BufferSize < 512 || cfg.BufferSize > 1048576) {
					err = fail("buffer_size must be 512..=1048576, got %d", cfg.BufferSize)
				}
			case "short_read_delay_us":
				var us int
				err = count(&us)
				cfg.ShortReadDelay = time.Duration(us) * time.Microsecond
			case "cert_path":
				cfg.CertPath = value
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
				cfg.Console.Listen = value
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
		case "host":
			r := &raws[len(raws)-1]
			v := value
			switch key {
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
			case "upstream_tls":
				r.upstreamTLS = &v
			case "upstream_tls_verify":
				r.upstreamVerify = &v
			case "upstream_sni":
				r.upstreamSNI = &v
			default:
				return nil, fail("unknown key %q in [[host]]", key)
			}
		default:
			return nil, fail("key outside of any section")
		}
	}

	if poolMaxIdle < 0 {
		poolMaxIdle = 3 * cfg.MaxConnections
	}
	cfg.BufferPoolMaxIdle = poolMaxIdle
	if cfg.Port == 0 {
		return nil, fmt.Errorf("[global] port is required")
	}
	for _, r := range raws {
		fail := func(format string, a ...any) error {
			return fmt.Errorf("[[host]] at line %d: %s", r.line, fmt.Sprintf(format, a...))
		}
		if r.pattern == nil {
			return nil, fail("pattern is required")
		}
		rule := Rule{Line: r.line, Source: *r.pattern}
		groups := 0
		expr := ""
		var err error
		if rule.Kind, expr, rule.literalChars, rule.multiLabel, err = classify(*r.pattern); err != nil {
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
		cfg.Rules = append(cfg.Rules, rule)
	}
	if err := cfg.prioritise(); err != nil {
		return nil, err
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
		if cfg.Port != 443 {
			cfg.Warnings = append(cfg.Warnings, fmt.Sprintf("cert = auto: the CA validates on public port 443, but this proxy listens on %d; make sure 443 is forwarded here", cfg.Port))
		}
		if len(cfg.PublicIPs) == 0 {
			cfg.Warnings = append(cfg.Warnings, "cert = auto without public_ip_address: the DNS pre-check is skipped, so a misconfigured name will burn CA rate limits")
		}
	}
	return cfg, nil
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

// tlsSettings validates and applies cert / cert_domains / upstream_tls*.
func tlsSettings(cfg *Config, rule *Rule, r rawRule) error {
	if r.cert == nil || *r.cert == "" {
		for _, kv := range []struct {
			name string
			v    *string
		}{{"cert_domains", r.certDomains}, {"cert_validate_script", r.certScript}, {"upstream_tls", r.upstreamTLS}, {"upstream_tls_verify", r.upstreamVerify}, {"upstream_sni", r.upstreamSNI}} {
			if kv.v != nil {
				return fmt.Errorf("%s only applies when the rule terminates TLS (set cert = auto or a directory)", kv.name)
			}
		}
		return nil
	}
	if !rule.Allow {
		return fmt.Errorf("cert makes no sense on a deny rule")
	}
	rule.Cert = *r.cert
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
	if !strings.EqualFold(rule.Cert, "auto") {
		if r.certDomains != nil {
			return fmt.Errorf("cert_domains only applies to cert = auto")
		}
		if r.certScript != nil {
			return fmt.Errorf("cert_validate_script only applies to cert = auto")
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
	if len(rule.CertDomains) == 0 && rule.CertValidateScript == "" {
		return fmt.Errorf("cert = auto with a regex pattern needs cert_domains = name1, name2 (certificates are issued per exact name) or a cert_validate_script that decides per name")
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

// Describe summarises the settings for the startup / reload log line.
func (c *Config) Describe() string {
	return fmt.Sprintf("%d rules (max_connections=%d, idle_timeout=%ds, half_close_timeout=%ds, buffer_size=%d, buffer_pool_max_idle=%d, allow_cache_size=%d, deny_cache_size=%d, short_read_delay_us=%d)",
		len(c.Rules), c.MaxConnections, int(c.IdleTimeout.Seconds()), int(c.HalfCloseTimeout.Seconds()),
		c.BufferSize, c.BufferPoolMaxIdle, c.AllowCacheSize, c.DenyCacheSize, c.ShortReadDelay.Microseconds())
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
