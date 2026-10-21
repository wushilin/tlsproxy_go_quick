package main

import (
	"strings"
	"testing"
	"time"
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

func TestEditBasicAuth(t *testing.T) {
	text := `listeners:
  - {name: a, port: 1}
routes:
  - listener: a
    rules:
      - domain: www.test
        cert: local-ca
        serve:
          - {type: static_content, prefix: /, base_dir: /srv, basic_auth: team}
basic_auth:
  # the people
  - name: team
    users:
      - {username: jack, password_plain: x} # old
      - {username: jill, password_hash: "` + mustHash(t, "pw") + `"}
`
	fakeHash := func(p string) (string, error) { return "H(" + p + ")", nil }
	realHash := func(p string) (string, error) { return hashPassword(p) }
	edit := func(e authEdit, h func(string) (string, error)) (string, []string, error) {
		return editBasicAuth(text, e, h)
	}

	got, _, err := edit(authEdit{Op: "set_password", Group: "team", User: "jack", Password: "new"}, realHash)
	if err != nil || strings.Contains(got, "password_plain") || !strings.Contains(got, "# the people") || !strings.Contains(got, "# old") {
		t.Fatalf("set_password replaces password_plain with a hash, comments kept: %v\n%s", err, got)
	}
	if c := mustParse(t, got); !checkPassword(c.BasicAuth["team"].Users["jack"].hash, "new") {
		t.Fatal("the new hash checks the new password")
	}
	got, notes, err := edit(authEdit{Op: "rename_group", Group: "team", NewName: "crew"}, fakeHash)
	if c := mustParse(t, got); err != nil || c.BasicAuth["crew"] == nil || c.Rules[0].Routes[0].BasicAuth != "crew" || len(notes) != 1 {
		t.Fatalf("rename renames its serve entries: %v %v\n%s", err, notes, got)
	}
	got, _, err = edit(authEdit{Op: "add_user", Group: "team", User: "joe", Password: "p"}, fakeHash)
	if err != nil || !strings.Contains(got, `{username: joe, password_hash: "H(p)"}`) {
		t.Fatalf("add_user: %v\n%s", err, got)
	}
	got, _, err = edit(authEdit{Op: "delete_user", Group: "team", User: "jack"}, fakeHash)
	if err != nil || strings.Contains(got, "jack") {
		t.Fatalf("delete_user: %v\n%s", err, got)
	}
	got, _, err = edit(authEdit{Op: "add_group", Group: "ops", User: "root", Password: "p"}, realHash)
	if c := mustParse(t, got); err != nil || len(c.BasicAuth["ops"].Users) != 1 {
		t.Fatalf("add_group: %v\n%s", err, got)
	}
	unused := strings.Replace(text, ", basic_auth: team}", "}", 1)
	if got, _, err := editBasicAuth(unused, authEdit{Op: "delete_group", Group: "team"}, fakeHash); err != nil || strings.Contains(got, "basic_auth") && strings.Contains(got, "team") {
		t.Fatalf("delete_group: %v\n%s", err, got)
	}
	for name, e := range map[string]authEdit{
		"group in use":       {Op: "delete_group", Group: "team"},
		"no such group":      {Op: "add_user", Group: "nope", User: "a", Password: "p"},
		"user exists":        {Op: "add_user", Group: "team", User: "jill", Password: "p"},
		"group exists":       {Op: "add_group", Group: "team", User: "a", Password: "p"},
		"rename to existing": {Op: "rename_group", Group: "team", NewName: "team"},
		"empty password":     {Op: "set_password", Group: "team", User: "jill"},
		"no such user":       {Op: "set_password", Group: "team", User: "nobody", Password: "p"},
		"unknown":            {Op: "drop", Group: "team"},
	} {
		if _, _, err := edit(e, fakeHash); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// A group's last user can't go.
	one, _, _ := edit(authEdit{Op: "delete_user", Group: "team", User: "jack"}, fakeHash)
	if _, _, err := editBasicAuth(one, authEdit{Op: "delete_user", Group: "team", User: "jill"}, fakeHash); err == nil || !strings.Contains(err.Error(), "only user") {
		t.Fatalf("the last user: %v", err)
	}
}

// A user can be disabled and given an expiry; a new password keeps both.
func TestBasicAuthDisableAndExpiry(t *testing.T) {
	text := "listeners:\n  - {name: a, port: 1}\nbasic_auth:\n  - name: team\n    users:\n      - {username: jack, password_plain: x}\n"
	fakeHash := func(p string) (string, error) { return hashPassword(p) }
	got, _, err := editBasicAuth(text, authEdit{Op: "set_disabled", Group: "team", User: "jack", Disabled: true}, fakeHash)
	if err == nil {
		got, _, err = editBasicAuth(got, authEdit{Op: "set_expiry", Group: "team", User: "jack", Expires: "2031-01-02"}, fakeHash)
	}
	if err == nil {
		got, _, err = editBasicAuth(got, authEdit{Op: "set_password", Group: "team", User: "jack", Password: "n"}, fakeHash)
	}
	if err != nil {
		t.Fatal(err)
	}
	c := mustParse(t, got)
	u := c.BasicAuth["team"].Users["jack"]
	if !u.disabled || !u.expires.Equal(time.Date(2031, 1, 3, 0, 0, 0, 0, time.UTC)) || u.hash == "" || u.plain != "" {
		t.Fatalf("disabled, expiring at the end of 2031-01-02 UTC, with a hash: %+v\n%s", u, got)
	}
	if !strings.Contains(got, "disabled: true") || !strings.Contains(got, "expires:") {
		t.Fatalf("written:\n%s", got)
	}
	got, _, _ = editBasicAuth(got, authEdit{Op: "set_disabled", Group: "team", User: "jack", Disabled: false}, fakeHash)
	got, _, _ = editBasicAuth(got, authEdit{Op: "set_expiry", Group: "team", User: "jack"}, fakeHash)
	if strings.Contains(got, "disabled") || strings.Contains(got, "expires") {
		t.Fatalf("enabled and never expiring: the keys go\n%s", got)
	}
	if _, _, err := editBasicAuth(got, authEdit{Op: "set_expiry", Group: "team", User: "jack", Expires: "soon"}, fakeHash); err == nil {
		t.Fatal("a bad expiry accepted")
	}

	// What the check says, for the log.
	a := newAuthChecker()
	ba := &BasicAuth{Users: map[string]credential{
		"on":   {plain: "p"},
		"off":  {plain: "p", disabled: true},
		"old":  {plain: "p", expires: time.Now().Add(-time.Minute)},
		"soon": {plain: "p", expires: time.Now().Add(time.Hour)},
	}}
	for user, want := range map[string]string{"on": "", "off": "disabled", "old": "expired", "soon": "", "nobody": "no user"} {
		ok, why := a.check(ba, user, "p")
		if ok != (want == "") || !strings.Contains(why, want) {
			t.Errorf("%s: %v %q, want %q", user, ok, why, want)
		}
	}
	if ok, why := a.check(ba, "on", "wrong"); ok || !strings.Contains(why, "wrong password") {
		t.Errorf("wrong password: %v %q", ok, why)
	}
	for v, want := range map[string]string{"2026-12-31": "", "2026-12-31T18:00:00+08:00": "", "31/12/2026": "expires must be", "never": ""} {
		_, err := ParseConfig(text[:len(text)-2] + ", expires: \"" + v + "\"}\n")
		if (want == "") != (err == nil) || err != nil && !strings.Contains(err.Error(), want) {
			t.Errorf("expires %s: %v", v, err)
		}
	}
}
