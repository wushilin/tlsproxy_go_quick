package main

// Most tests describe their configuration compactly, the way the file
// looked before config.yaml: sections and key = value lines, a [[host]] per
// rule. yamlFixture turns that into the config.yaml the proxy reads, so a
// test about relaying, routing or certificates says what it needs in a few
// lines. The proxy itself reads YAML only; tests about the file format
// itself (config_yaml_test.go, the samples, the docs) are written in YAML.
//
//	[[listener]] name=default port=1       ->  listeners: - {name: default, port: 1}
//	[[host]] listener=default pattern=x     ->  routes: - {listener: default, rules: [{domain: x, ...}]}
//	  target_host=h target_port=443         ->        target: h:443
//	  proxy=true proxy_version=1            ->        proxy: v1
//	  service_rule1 = type=...; prefix=...  ->        serve: [{type: ..., prefix: ...}]
//	[[basic_auth]] user1 = username=a; ...  ->  basic_auth: - {name: ..., users: [{username: a, ...}]}

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// yamlListKeys are the keys whose value is a list in config.yaml.
var yamlListKeys = map[string]bool{"bind": true, "proxy_trust_source": true, "cert_domains": true, "public_ip_address": true, "dns_resolvers": true}

// isFixture reports whether text is in the compact form (not YAML yet).
func isFixture(text string) bool {
	for _, l := range strings.Split(text, "\n") {
		if l = strings.TrimSpace(l); strings.HasPrefix(l, "[") && strings.HasSuffix(l, "]") && !strings.Contains(l, ":") {
			return true
		}
	}
	return false
}

// yamlFixture converts the compact form to config.yaml; text that is
// already YAML is returned as it is.
func yamlFixture(text string) string {
	if !isFixture(text) {
		return text
	}
	type kv struct{ k, v string }
	type item struct {
		kind string // global, logging, listener, host, basic_auth, raw
		kvs  []kv
	}
	var items []*item
	var cur *item
	section := func(kind string) *item {
		if kind == "global" || kind == "logging" { // one of each; repeated headers add to it
			for _, it := range items {
				if it.kind == kind {
					return it
				}
			}
		}
		it := &item{kind: kind}
		items = append(items, it)
		return it
	}
	for _, line := range strings.Split(text, "\n") {
		t := strings.TrimSpace(line)
		switch {
		case t == "" || strings.HasPrefix(t, "#"):
		case strings.HasPrefix(t, "[[") && strings.HasSuffix(t, "]]"):
			cur = section(strings.TrimSpace(t[2 : len(t)-2]))
		case strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]"):
			cur = section(strings.TrimSpace(t[1 : len(t)-1]))
		default:
			k, v, ok := strings.Cut(t, "=")
			if !ok || cur == nil {
				// Not a key: keep it, so the parser reports it.
				items = append(items, &item{kind: "raw", kvs: []kv{{t, ""}}})
				continue
			}
			k = strings.TrimSpace(k)
			if k == "ca_root" { // cert_root since v1.5.0
				k = "cert_root"
			}
			if k == "cert_path" { // the ACME certificates are in <cert_root>/acme since v1.5.0
				if slices.ContainsFunc(cur.kvs, func(p kv) bool { return p.k == "cert_root" }) {
					continue // the test's CAs say where cert_root is
				}
				k = "cert_root"
			}
			if k == "cert_validate_args" {
				v = strings.TrimSpace(v) // a TOML array is a YAML flow list already
			} else {
				pv, err := parseValue(v)
				if err != nil {
					pv = strings.TrimSpace(v)
				}
				v = pv
			}
			if cur.kind == "global" || cur.kind == "logging" { // a key given again replaces it
				for i := range cur.kvs {
					if cur.kvs[i].k == k {
						cur.kvs = append(cur.kvs[:i], cur.kvs[i+1:]...)
						break
					}
				}
			}
			cur.kvs = append(cur.kvs, kv{k, v})
		}
	}
	q := strconv.Quote
	value := func(k, v string) string {
		if k == "cert_validate_args" {
			return v
		}
		if yamlListKeys[k] {
			var out []string
			for _, x := range splitList(v) {
				out = append(out, q(x))
			}
			return "[" + strings.Join(out, ", ") + "]"
		}
		return q(v)
	}
	var b strings.Builder
	for _, line := range strings.Split(text, "\n") { // the comments above the first section stay
		if t := strings.TrimSpace(line); strings.HasPrefix(t, "#") {
			b.WriteString(t + "\n")
		} else if t != "" {
			break
		}
	}
	mapping := func(name string, kind string) {
		first := true
		for _, it := range items {
			if it.kind != kind {
				continue
			}
			if first {
				fmt.Fprintf(&b, "%s:\n", name)
				first = false
			}
			for _, p := range it.kvs {
				fmt.Fprintf(&b, "  %s: %s\n", p.k, value(p.k, p.v))
			}
		}
	}
	mapping("global", "global")
	mapping("logging", "logging")
	for _, it := range items {
		switch it.kind {
		case "global", "logging", "listener", "host", "basic_auth", "raw":
		default:
			b.WriteString(it.kind + ":\n") // console, or a section that never was: refused
		}
		if it.kind == "raw" {
			b.WriteString(it.kvs[0].k + "\n")
		}
	}
	first := true
	for _, it := range items {
		if it.kind != "listener" {
			continue
		}
		if first {
			b.WriteString("listeners:\n")
			first = false
		}
		b.WriteString("  -")
		if len(it.kvs) == 0 {
			b.WriteString(" {}\n")
		}
		for i, p := range it.kvs {
			if i > 0 {
				b.WriteString("   ")
			}
			fmt.Fprintf(&b, " %s: %s\n", p.k, value(p.k, p.v))
		}
	}
	// Rules, grouped by listener in the order the listeners first appear.
	var order []string
	byListener := map[string][]*item{}
	for _, it := range items {
		if it.kind != "host" {
			continue
		}
		l := ""
		for _, p := range it.kvs {
			if p.k == "listener" {
				l = p.v
			}
		}
		if _, ok := byListener[l]; !ok {
			order = append(order, l)
		}
		byListener[l] = append(byListener[l], it)
	}
	if len(order) > 0 {
		b.WriteString("routes:\n")
	}
	for _, l := range order {
		if l == "" {
			b.WriteString("  - rules:\n") // no listener: the loader says so
		} else {
			fmt.Fprintf(&b, "  - listener: %s\n    rules:\n", q(l))
		}
		for _, it := range byListener[l] {
			var lines []string
			host, port := "", ""
			proxy, version := "", ""
			var serve []string
			for _, p := range it.kvs {
				switch p.k {
				case "listener":
				case "pattern":
					switch d := p.v; {
					case strings.EqualFold(d, "none"):
						lines = append(lines, "domain: $no_sni")
					case strings.EqualFold(d, "any") || strings.TrimSuffix(strings.TrimPrefix(d, "^"), "$") == ".*":
						lines = append(lines, "domain: $anything_else")
					default:
						lines = append(lines, "domain: "+q(p.v))
					}
				case "target_host":
					host = p.v
				case "target_port":
					port = p.v
				case "proxy":
					proxy = p.v
				case "proxy_version":
					version = p.v
				default:
					if strings.HasPrefix(p.k, "service_rule") {
						var opts []string
						for _, part := range strings.Split(p.v, ";") {
							if part = strings.TrimSpace(part); part == "" {
								continue
							}
							k, v, _ := strings.Cut(part, "=")
							opts = append(opts, strings.TrimSpace(k)+": "+q(strings.TrimSpace(v)))
						}
						serve = append(serve, "{"+strings.Join(opts, ", ")+"}")
						continue
					}
					lines = append(lines, p.k+": "+value(p.k, p.v))
				}
			}
			if host != "" || port != "" {
				if a, err := netip.ParseAddr(host); err == nil && a.Is6() || strings.Contains(host, ":") {
					host = "[" + host + "]"
				}
				if port == "" {
					lines = append(lines, "target: "+q(host)) // no port: refused
				} else {
					lines = append(lines, "target: "+q(host+":"+port))
				}
			}
			switch {
			case proxy != "" && parseBoolOr(proxy) && version != "":
				lines = append(lines, "proxy: v"+version)
			case proxy != "" && parseBoolOr(proxy):
				lines = append(lines, "proxy: v2")
			case proxy == "false" || proxy == "no" || proxy == "off":
				lines = append(lines, "proxy: none")
			case proxy != "":
				lines = append(lines, "proxy: "+q(proxy)) // not a bool: refused
			case version != "":
				lines = append(lines, "proxy_version: "+q(version)) // refused: proxy_version alone
			}
			if serve != nil {
				lines = append(lines, "serve: ["+strings.Join(serve, ", ")+"]")
			}
			if len(lines) == 0 {
				b.WriteString("      - {}\n")
			}
			for i, l := range lines {
				if i == 0 {
					b.WriteString("      - " + l + "\n")
				} else {
					b.WriteString("        " + l + "\n")
				}
			}
		}
	}
	first = true
	for _, it := range items {
		if it.kind != "basic_auth" {
			continue
		}
		if first {
			b.WriteString("basic_auth:\n")
			first = false
		}
		name := ""
		var users []string
		for _, p := range it.kvs {
			if p.k == "name" {
				name = p.v
				continue
			}
			var opts []string
			for _, part := range strings.Split(p.v, ";") {
				if part = strings.TrimSpace(part); part != "" {
					k, v, _ := strings.Cut(part, "=")
					opts = append(opts, strings.TrimSpace(k)+": "+q(strings.TrimSpace(v)))
				}
			}
			users = append(users, "{"+strings.Join(opts, ", ")+"}")
		}
		fmt.Fprintf(&b, "  - name: %s\n    users: [%s]\n", q(name), strings.Join(users, ", "))
	}
	return b.String()
}

func parseBoolOr(v string) bool {
	b, _ := parseBool(v)
	return b
}

// parseFixture and loadFixture are ParseConfig and LoadConfig for a
// configuration in either form.
func parseFixture(text string) (*Config, error) { return ParseConfig(yamlFixture(text)) }
func loadFixture(text string, con *ConsoleConfig) (*Config, error) {
	return LoadConfig(yamlFixture(text), con)
}

func TestYAMLFixture(t *testing.T) {
	got := yamlFixture("[[listener]]\nname=default\nbind=0.0.0.0; ::1\nport=1\n[global]\nconnect_timeout=3\n" +
		"[[host]]\nlistener=default\npattern=*.x\ntarget_host=${1}.lan\ntarget_port=443\nproxy=true\nproxy_version=1\n" +
		"[[host]]\nlistener=default\npattern=ANY\naction=deny\n")
	want := `global:
  connect_timeout: "3"
listeners:
  - name: "default"
    bind: ["0.0.0.0", "::1"]
    port: "1"
routes:
  - listener: "default"
    rules:
      - domain: "*.x"
        target: "${1}.lan:443"
        proxy: v1
      - domain: $anything_else
        action: "deny"
`
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
	if _, err := ParseConfig(got); err != nil {
		t.Fatal(err)
	}
}

// parseValue reads a value of the compact form: "double quoted", 'single
// quoted' or bare, up to a " #" comment.
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
