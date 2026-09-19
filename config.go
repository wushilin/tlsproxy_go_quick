package main

// Parser for config.toml, a small, lenient TOML subset:
//
//	[global]            section
//	[[host]]            appends a new rule
//	key = value         value may be "double quoted", 'single quoted' or bare
//	# comment           full line; also trailing " # ..." after a value
//
// Rules are evaluated top to bottom; the first match wins. A host that
// matches no rule is denied.

import (
	"fmt"
	"regexp"
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
	Rules             []Rule
	// Settings from the Rust version that no longer apply and were ignored.
	Ignored []string
}

type Rule struct {
	Line       int
	Source     string
	Pattern    *regexp.Regexp
	Allow      bool
	TargetHost string
	TargetPort int
}

// Decision is the outcome of routing one SNI.
type Decision struct {
	Allow    bool
	Host     string
	Port     int
	RuleLine int    // 0 = no rule matched
	Err      string // non-empty: routing failed (treated as deny)
}

func isHostChar(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' ||
		b == '.' || b == '-' || b == '_'
}

// Route evaluates the rules for a lowercased SNI. No SNI is matched as "".
func (c *Config) Route(sni string) Decision {
	for i := range c.Rules {
		r := &c.Rules[i]
		m := r.Pattern.FindStringSubmatchIndex(sni)
		if m == nil {
			continue
		}
		if !r.Allow {
			return Decision{RuleLine: r.Line}
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
			return Decision{RuleLine: r.Line, Err: err.Error()}
		}
		return Decision{Allow: true, Host: host, Port: r.TargetPort, RuleLine: r.Line}
	}
	return Decision{}
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

type rawRule struct {
	line                               int
	pattern, action, targetHost, tport *string
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
			if section != "global" {
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
			case "io_model", "worker_threads":
				// Rust-version tuning knobs; goroutines make them moot.
				cfg.Ignored = append(cfg.Ignored, key)
			default:
				return nil, fail("unknown key %q in [global]", key)
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
		// Whole-name, case-insensitive match.
		re, err := regexp.Compile("(?i)^(?:" + *r.pattern + ")$")
		if err != nil {
			return nil, fail("bad pattern %q: %v", *r.pattern, err)
		}
		rule := Rule{Line: r.line, Source: *r.pattern, Pattern: re}
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
			rule.TargetPort = 443
			if r.tport != nil {
				if rule.TargetPort, err = parsePort(*r.tport); err != nil {
					return nil, fail("%v", err)
				}
			}
			// Catch bad group references now rather than per connection.
			probe := make([]int, 2*(re.NumSubexp()+1))
			if _, err := expand(rule.TargetHost, "", probe); err != nil {
				return nil, fail("target_host: %v", err)
			}
		default:
			return nil, fail("action must be allow or deny, got %q", action)
		}
		cfg.Rules = append(cfg.Rules, rule)
	}
	return cfg, nil
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
