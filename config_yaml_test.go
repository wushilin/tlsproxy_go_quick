package main

import (
	"strings"
	"testing"
)

// What config.yaml itself refuses: its shape, unknown and repeated keys,
// and the spellings of the file before it.
func TestYAMLShape(t *testing.T) {
	t.Parallel()
	l := "listeners:\n  - {name: a, port: 1}\n"
	rule := func(lines string) string {
		return l + "routes:\n  - listener: a\n    rules:\n      - domain: x.test\n" + lines
	}
	for text, want := range map[string]string{
		"- a\n- b\n":         "the file is a mapping of global, logging, listeners, routes, basic_auth",
		"globals:\n  x: 1\n": "unknown section \"globals\"",
		l + "global:\n  connect_timeout: 1\n  connect_timeout: 2\n": "line 5: connect_timeout is already given at line 4",
		l + "global: [1]\n":                                "global must be a mapping",
		l + "global:\n  connect_timeout: {a: 1}\n":         "connect_timeout takes a value or a list, not a mapping",
		"listeners: {name: a}\n":                           "listeners is a list",
		l + "routes:\n  - rules: []\n":                     "a routes item needs listener: <name>",
		l + "routes:\n  - listener: a\n    rule: []\n":     `unknown key "rule" in a routes item`,
		rule("        target_host: h\n"):                   `unknown key "target_host" in a rule`,
		rule("        pattern: y.test\n"):                  `unknown key "pattern" in a rule`,
		rule("        target: h\n"):                        "needs a port: host:port",
		rule("        target: \"2001:db8::1:443\"\n"):      "write an IPv6 target in brackets",
		rule("        target: \"[2001:db8::1]443\"\n"):     "write an IPv6 target as [2001:db8::1]:443",
		rule("        target: h:1\n        proxy: v3\n"):   "proxy must be v1 or v2",
		rule("        target: h:1\n        target: h:2\n"): "target is already given",
		rule("        target: [h, 1]\n"):                   "target: \"h; 1\" needs a port",
		rule("        cert_validate_args: \"${host}\"\n"):  "cert_validate_args is a list",
		l + "console:\n  password: x\n":                    "set at start-up with -console_domain",
		l + "basic_auth: x\n":                              "basic_auth is a list",
		"global:\n  bind: 0.0.0.0\n":                       "global has no bind",
		"x: [\n":                                           "line 1",
	} {
		if _, err := ParseConfig(text); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q:\n  %v, want %q", text, err, want)
		}
	}
	// Targets: a name, an IPv4 address, an IPv6 address in brackets, a capture.
	c := mustParse(t, l+"routes:\n  - listener: a\n    rules:\n"+
		"      - {domain: a.test, target: \"h.lan:443\", proxy: v1}\n"+
		"      - {domain: b.test, target: \"10.0.0.1:80\", proxy: none}\n"+
		"      - {domain: c.test, target: \"[2001:db8::1]:443\"}\n"+
		"      - {domain: \"*.d.test\", target: \"${1}.lan:8443\"}\n"+
		"      - {domain: $anything_else, action: deny}\n")
	for i, want := range []struct {
		host  string
		port  int
		proxy bool
		ver   int
	}{{"h.lan", 443, true, 1}, {"10.0.0.1", 80, false, 2}, {"2001:db8::1", 443, false, 2}, {"${1}.lan", 8443, false, 2}} {
		if r := c.Rules[i]; r.TargetHost != want.host || r.TargetPort != want.port || r.Proxy != want.proxy || r.ProxyVersion != want.ver {
			t.Errorf("rule %d: %s:%d proxy %v v%d", i, r.TargetHost, r.TargetPort, r.Proxy, r.ProxyVersion)
		}
	}
	// Lists may also be written as one value; an empty file loads to "no listeners".
	if c := mustParse(t, "listeners:\n  - {name: a, bind: \"127.0.0.1; ::1\", port: 1}\n"); c.Listeners[0].Bind != "127.0.0.1; ::1" {
		t.Errorf("bind as one value: %q", c.Listeners[0].Bind)
	}
	if _, err := ParseConfig(""); err == nil || !strings.Contains(err.Error(), "no listeners") {
		t.Errorf("empty: %v", err)
	}
}
