package main

// The config editor's Validate result: the settings the proxy would run
// with, as a tree (sections, listeners, their rules), each value marked with
// where it comes from, and every problem with the line it is about.

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

type treeItem struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	From  string `json:"from,omitempty"` // "" = written in this section; "default"; "[global]"
}

type treeNode struct {
	Title    string     `json:"title"`
	Note     string     `json:"note,omitempty"`
	Tag      string     `json:"tag,omitempty"` // a short chip: passthrough, terminate, deny...
	Line     int        `json:"line,omitempty"`
	Items    []treeItem `json:"items,omitempty"`
	Children []treeNode `json:"children,omitempty"`
}

type problem struct {
	Text string `json:"text"`
	Line int    `json:"line,omitempty"`
}

var problemLine = regexp.MustCompile(`\bline (\d+)`)

// lineOf is the first line number a message names, 0 if none.
func lineOf(msg string) int {
	if m := problemLine.FindStringSubmatch(msg); m != nil {
		n, _ := strconv.Atoi(m[1])
		return n
	}
	return 0
}

func problemsOf(msgs []string) []problem {
	out := []problem{}
	for _, m := range msgs {
		out = append(out, problem{Text: m, Line: lineOf(m)})
	}
	return out
}

func secs(d time.Duration, zero string) string {
	if d == 0 {
		return zero
	}
	if d%time.Second != 0 {
		return d.String()
	}
	return strconv.Itoa(int(d/time.Second)) + "s"
}

func prefixes(p []netip.Prefix) string {
	if len(p) == 0 {
		return "nobody"
	}
	var s []string
	for _, x := range p {
		s = append(s, x.String())
	}
	return strings.Join(s, ", ")
}

func listOr(v []string, none string) string {
	if len(v) == 0 {
		return none
	}
	return strings.Join(v, ", ")
}

// speed shows a limit as written, with what it comes to.
func speed(bytesPerSec float64, written string) string {
	if bytesPerSec == 0 {
		return "unlimited"
	}
	if human := humanRate(bytesPerSec); written != "" && strings.ReplaceAll(written, " ", "") != strings.ReplaceAll(human, " ", "") {
		return written + " (" + human + ") each direction"
	}
	return humanRate(bytesPerSec) + " each direction"
}

// configTree describes cfg, parsed from full; toEditor maps its lines to
// the editor's.
func configTree(cfg *Config, full string, toEditor func(int) int) []treeNode {
	lines := strings.Split(full, "\n")
	written := func(header string) map[string]string {
		if b := sectionBlocks(lines, header); len(b) > 0 {
			return blockValues(lines, b[0])
		}
		return map[string]string{}
	}
	hosts, lists := sectionBlocks(lines, "[[host]]"), sectionBlocks(lines, "[[listener]]")
	at := func(blocks []block, line int) map[string]string {
		if b := blockAt(blocks, line); b != nil {
			return blockValues(lines, *b)
		}
		return map[string]string{}
	}
	item := func(set map[string]string, key, value string) treeItem {
		it := treeItem{Key: key, Value: value}
		if _, ok := set[key]; !ok {
			it.From = "default"
		}
		return it
	}

	g := written("[global]")
	global := treeNode{Title: "[global]", Note: "applies to every listener unless it overrides it"}
	for _, it := range []treeItem{
		item(g, "handshake_timeout", secs(cfg.HandshakeTimeout, "none")),
		item(g, "connect_timeout", secs(cfg.ConnectTimeout, "none")),
		item(g, "idle_timeout", secs(cfg.IdleTimeout, "never")),
		item(g, "half_close_timeout", secs(cfg.HalfCloseTimeout, "unlimited")),
		item(g, "max_connections", strconv.Itoa(cfg.MaxConnections)),
		item(g, "max_handshakes_per_ip", map[bool]string{true: "unlimited", false: strconv.Itoa(cfg.MaxHandshakesPerIP)}[cfg.MaxHandshakesPerIP == 0]),
		item(g, "proxy_trust_source", prefixes(cfg.ProxyTrustSource)),
		item(g, "buffer_size", fmt.Sprintf("%d (%s)", cfg.BufferSize, humanBytes(int64(cfg.BufferSize)))),
		item(g, "splice", strconv.FormatBool(cfg.Splice)),
		item(g, "buffer_pool_max_idle", strconv.Itoa(cfg.BufferPoolMaxIdle)),
		item(g, "allow_cache_size", strconv.Itoa(cfg.AllowCacheSize)),
		item(g, "deny_cache_size", strconv.Itoa(cfg.DenyCacheSize)),
		item(g, "short_read_delay_us", strconv.Itoa(int(cfg.ShortReadDelay/time.Microsecond))),
		item(g, "reload_interval", secs(cfg.ReloadInterval, "never (console saves only)")),
		item(g, "stats_interval", secs(cfg.StatsInterval, "never")),
	} {
		global.Items = append(global.Items, it)
	}

	listeners := treeNode{Title: "Listeners", Note: fmt.Sprintf("%d", len(cfg.Listeners))}
	for i := range cfg.Listeners {
		l := &cfg.Listeners[i]
		n := treeNode{Title: l.Name, Note: strings.Join(l.Addrs(), ", ")}
		inherit := func(key, own, global string, set bool) treeItem {
			if set {
				return treeItem{Key: key, Value: own}
			}
			return treeItem{Key: key, Value: global, From: "[global]"}
		}
		n.Line = toEditor(l.Line)
		n.Items = append(n.Items, treeItem{Key: "bind", Value: l.Bind}, treeItem{Key: "port", Value: strconv.Itoa(l.Port)})
		ppf := cfg.ProxyTrustSource
		if l.ProxyTrustSource != nil {
			ppf = *l.ProxyTrustSource
		}
		dur := func(p *time.Duration, g time.Duration, zero string) (string, bool) {
			if p != nil {
				return secs(*p, zero), true
			}
			return secs(g, zero), false
		}
		hs, hsSet := dur(l.HandshakeTimeout, cfg.HandshakeTimeout, "none")
		idle, idleSet := dur(l.IdleTimeout, cfg.IdleTimeout, "never")
		half, halfSet := dur(l.HalfCloseTimeout, cfg.HalfCloseTimeout, "unlimited")
		lv := at(lists, l.Line)
		maxConns := "no own limit"
		if l.MaxConnections > 0 {
			maxConns = strconv.Itoa(l.MaxConnections)
		}
		n.Items = append(n.Items,
			inherit("proxy_trust_source", prefixes(ppf), prefixes(ppf), l.ProxyTrustSource != nil),
			treeItem{Key: "max_connections", Value: maxConns, From: map[bool]string{true: "", false: "default"}[l.MaxConnections > 0]},
			inherit("handshake_timeout", hs, hs, hsSet),
			inherit("idle_timeout", idle, idle, idleSet),
			inherit("half_close_timeout", half, half, halfSet),
			treeItem{Key: "max_aggregated_speed", Value: speed(l.MaxAggregatedSpeed, lv["max_aggregated_speed"]), From: map[bool]string{true: "", false: "default"}[l.MaxAggregatedSpeed > 0]},
			treeItem{Key: "max_single_connection_speed", Value: speed(l.MaxSingleConnectionSpeed, lv["max_single_connection_speed"]), From: map[bool]string{true: "", false: "default"}[l.MaxSingleConnectionSpeed > 0]},
		)
		count := 0
		for j := range cfg.Rules {
			if r := &cfg.Rules[j]; r.Listener == l.Name {
				n.Children = append(n.Children, ruleNode(r, at(hosts, r.Line), toEditor))
				count++
			}
		}
		n.Note += fmt.Sprintf(" · %d rule%s", count, map[bool]string{true: "", false: "s"}[count == 1])
		listeners.Children = append(listeners.Children, n)
	}

	out := []treeNode{global, listeners}

	if len(cfg.BasicAuth) > 0 {
		auths := treeNode{Title: "Basic auth", Note: fmt.Sprintf("%d", len(cfg.BasicAuth))}
		names := slices.Sorted(maps.Keys(cfg.BasicAuth))
		for _, name := range names {
			a := cfg.BasicAuth[name]
			users := slices.Sorted(maps.Keys(a.Users))
			n := treeNode{Title: name, Note: fmt.Sprintf("%d user(s)", len(users)), Line: toEditor(a.Line)}
			for _, u := range users {
				how := "password hash"
				if a.Users[u].hash == "" {
					how = "plain password"
				}
				n.Items = append(n.Items, treeItem{Key: u, Value: how})
			}
			auths.Children = append(auths.Children, n)
		}
		out = append(out, auths)
	}

	if auto := cfg.AutoDomains(); len(auto) > 0 || cfg.AcmeAgreeTOS {
		certs := treeNode{Title: "Automatic certificates", Note: fmt.Sprintf("%d name(s)", len(auto))}
		certs.Items = []treeItem{
			{Key: "names", Value: listOr(auto, "none (names may come from a validate script)")},
			item(g, "acme_directory", cfg.AcmeDirectory),
			item(g, "acme_agree_tos", strconv.FormatBool(cfg.AcmeAgreeTOS)),
			item(g, "acme_email", map[bool]string{true: "none", false: cfg.AcmeEmail}[cfg.AcmeEmail == ""]),
			item(g, "cert_path", cfg.CertPath),
			item(g, "expiry_threshold_days", strconv.Itoa(cfg.ExpiryThresholdDays)),
			item(g, "public_ip_address", listOr(cfg.PublicIPs, "not checked")),
			item(g, "dns_resolvers", listOr(cfg.DNSResolvers, "none (required when the pre-check runs)")),
		}
		out = append(out, certs)
	}

	lg := written("[logging]")
	logs := treeNode{Title: "[logging]"}
	logs.Items = []treeItem{
		item(lg, "stdout", map[bool]string{true: "the process's stdout", false: cfg.Log.Stdout}[cfg.Log.Stdout == ""]),
		item(lg, "stderr", map[bool]string{true: "the process's stderr", false: cfg.Log.Stderr}[cfg.Log.Stderr == ""]),
		item(lg, "max_size", humanBytes(cfg.Log.MaxSize)),
		item(lg, "max_keep", strconv.Itoa(cfg.Log.MaxKeep)),
		item(lg, "compress_after", strconv.Itoa(cfg.Log.CompressAfter)),
	}
	return append(out, logs)
}

func ruleNode(r *Rule, written map[string]string, toEditor func(int) int) treeNode {
	n := treeNode{Title: r.Source, Line: toEditor(r.Line), Note: r.Kind.String()}
	add := func(key, value string) { n.Items = append(n.Items, treeItem{Key: key, Value: value}) }
	if !r.Allow {
		n.Tag = "deny"
		add("action", "deny (TLS access_denied alert)")
		return n
	}
	switch {
	case r.Serves():
		n.Tag = "serve"
		add("cert", r.Cert)
		if len(r.CertDomains) > 0 {
			add("cert_domains", strings.Join(r.CertDomains, ", "))
		}
		for _, route := range r.Routes {
			add(route.Key, route.Describe())
		}
	case r.Terminates():
		add("target", fmt.Sprintf("%s:%d", r.TargetHost, r.TargetPort))
		n.Tag = "terminate"
		add("cert", r.Cert)
		if len(r.CertDomains) > 0 {
			add("cert_domains", strings.Join(r.CertDomains, ", "))
		}
		if r.CertValidateScript != "" {
			add("cert_validate_script", r.CertValidateScript)
			add("cert_validate_args", tomlArray(mustJSON(r.CertValidateArgs)))
		}
		if r.UpstreamTLS {
			add("upstream", map[bool]string{true: "TLS, certificate verified", false: "TLS, certificate not verified"}[r.UpstreamTLSVerify])
			if r.UpstreamSNI != "" {
				add("upstream_sni", r.UpstreamSNI)
			}
		} else {
			add("upstream", "plaintext")
		}
	default:
		add("target", fmt.Sprintf("%s:%d", r.TargetHost, r.TargetPort))
		n.Tag = "passthrough"
	}
	if r.Proxy {
		add("proxy", fmt.Sprintf("PROXY protocol v%d header", r.ProxyVersion))
	}
	if r.MaxAggregatedSpeed > 0 {
		add("max_aggregated_speed", speed(r.MaxAggregatedSpeed, written["max_aggregated_speed"]))
	}
	if r.MaxSingleConnectionSpeed > 0 {
		add("max_single_connection_speed", speed(r.MaxSingleConnectionSpeed, written["max_single_connection_speed"]))
	}
	return n
}

func mustJSON(v any) string {
	data, _ := json.Marshal(v)
	return string(data)
}
