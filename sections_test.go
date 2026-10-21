package main

import (
	"strings"
	"testing"
)

const editFile = `# top comment
global:
  connect_timeout: 3 # seconds
listeners:
  - name: default
    port: 443
routes:
  - listener: default
    rules:
      # the wildcard rule
      - domain: "*.example.com" # all of them
        target: "${1}.internal:443"
        max_single_connection_speed: 1MB
      - domain: $anything_else
        action: deny
logging:
  max_keep: 3
`

// A rule edit changes that rule in the YAML tree: comments elsewhere stay,
// and so does a key's comment when only its value changes.
func TestEditRules(t *testing.T) {
	got, block, at, err := editRules(editFile, 11, map[string]any{"listener": "default", "domain": "*.example.com",
		"target": "${1}.lan:8443", "max_single_connection_speed": ""}, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"# top comment", "connect_timeout: 3 # seconds", "# the wildcard rule", `- domain: "*.example.com" # all of them`,
		"target: ${1}.lan:8443", "max_keep: 3"} {
		if !strings.Contains(got, want) {
			t.Errorf("edit: no %q in\n%s", want, got)
		}
	}
	if strings.Contains(got, "max_single_connection_speed") {
		t.Error("an empty value removes the key")
	}
	if !strings.Contains(block, "target: ${1}.lan:8443") || at != 11 {
		t.Errorf("the rule as written, and its line: %d\n%s", at, block)
	}
	cfg := mustParse(t, got)
	if r := cfg.Rules[0]; r.TargetHost != "${1}.lan" || r.TargetPort != 8443 || r.Line != at {
		t.Fatalf("%+v", r)
	}

	// Delete: the rule goes, the comments of the others stay.
	got, _, _, err = editRules(editFile, 11, nil, true)
	if err != nil || strings.Contains(got, "example.com") || !strings.Contains(got, "domain: $anything_else") {
		t.Fatalf("delete: %v\n%s", err, got)
	}

	// Add: on a listener with rules, after them; on another, in a new routes item.
	got, _, at, err = editRules(editFile, 0, map[string]any{"listener": "default", "domain": "a.test", "target": "10.0.0.1:443",
		"proxy": "v2", "max_aggregated_speed": "1Gbit", "cert_domains": []any{}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if c := mustParse(t, got); len(c.Rules) != 3 || c.Rules[2].Source != "a.test" || !c.Rules[2].Proxy || c.Rules[2].Line != at {
		t.Fatalf("add:\n%s", got)
	}

	// Moving a rule to another listener moves it to that listener's routes item.
	two := strings.Replace(editFile, "    port: 443\n", "    port: 443\n  - name: lan\n    port: 8443\n", 1)
	got, _, at, err = editRules(two, 13, map[string]any{"listener": "lan"}, false)
	if err != nil {
		t.Fatal(err)
	}
	c := mustParse(t, got)
	if len(c.Rules) != 2 || c.Rules[1].Listener != "lan" || c.Rules[1].Source != "*.example.com" || c.Rules[1].Line != at {
		t.Fatalf("move:\n%s", got)
	}

	// Serve entries are a list of objects; editing them replaces the list.
	got, _, _, err = editRules(editFile, 11, map[string]any{"target": "", "cert": "local-ca", "serve": []any{
		map[string]any{"type": "reverse_proxy", "prefix": "/api/", "target": "http://h:1", "strip_prefix": "true"},
		map[string]any{"type": "static_content", "prefix": "/", "base_dir": "/srv/www"},
	}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if c := mustParse(t, got); len(c.Rules[0].Routes) != 2 || c.Rules[0].Routes[0].Prefix != "/api/" {
		t.Fatalf("serve:\n%s", got)
	}
	if v := nodeValueOf(t, got, 11)["serve"].([]any); len(v) != 2 || v[0].(map[string]any)["strip_prefix"] != "true" {
		t.Fatalf("read back for the console: %v", v)
	}

	for name, err := range map[string]error{
		"no such rule": func() error {
			_, _, _, err := editRules(editFile, 99, map[string]any{"domain": "x"}, false)
			return err
		}(),
		"unknown key": func() error {
			_, _, _, err := editRules(editFile, 0, map[string]any{"listener": "default", "pattern": "x"}, false)
			return err
		}(),
		"no listener": func() error { _, _, _, err := editRules(editFile, 0, map[string]any{"domain": "x"}, false); return err }(),
		"newline": func() error {
			_, _, _, err := editRules(editFile, 11, map[string]any{"target": "a\nb"}, false)
			return err
		}(),
		"serve not list": func() error {
			_, _, _, err := editRules(editFile, 11, map[string]any{"serve": []any{"x"}}, false)
			return err
		}(),
	} {
		if err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// nodeValueOf is what the console reads of the rule on line.
func nodeValueOf(t *testing.T, text string, line int) map[string]any {
	t.Helper()
	rules, _ := fileValues(text)
	v, ok := rules[line]
	if !ok {
		t.Fatalf("no rule on line %d:\n%s", line, text)
	}
	return v
}

func TestEditListeners(t *testing.T) {
	got, block, at, notes, err := editListeners(editFile, 5, map[string]any{"name": "web", "bind": []any{"0.0.0.0", "::"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	c := mustParse(t, got)
	if c.Listeners[0].Name != "web" || c.Listeners[0].Bind != "0.0.0.0; ::" || c.Rules[0].Listener != "web" || len(notes) != 1 || at != 5 ||
		!strings.Contains(block, "name: web") {
		t.Fatalf("rename and rebind: %v %d\n%s", notes, at, got)
	}
	got, _, at, _, err = editListeners(editFile, 0, map[string]any{"name": "lan", "port": "8443"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if c := mustParse(t, got); len(c.Listeners) != 2 || c.Listeners[1].Port != 8443 || c.Listeners[1].Line != at {
		t.Fatalf("add:\n%s", got)
	}
	if !strings.Contains(got, "port: 8443") || strings.Contains(got, `"8443"`) {
		t.Errorf("a number is written as one:\n%s", got)
	}
	got, _, _, _, err = editListeners(editFile, 5, nil, true)
	if err != nil || strings.Contains(got, "name: default") {
		t.Fatalf("delete: %v\n%s", err, got)
	}
}
