package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// A serve entry's relay:// and relay+ssl:// targets are uses of the
// endpoint: renaming it renames them, keeping each one's scheme, and it
// cannot be deleted while they use it.
func TestEditRelaysServeEntries(t *testing.T) {
	text := relayListener + `routes:
  - listener: a
    rules:
      - domain: wiki.test
        cert: local-ca
        serve:
          - {type: reverse_proxy, prefix: /, target: "relay+ssl://office", tls_verify: false}
          - {type: reverse_proxy, prefix: /api/, target: "RELAY://office"}
          - {type: reverse_proxy, prefix: /other/, target: "http://10.0.0.1:8080"}
exchanges:
  - {name: home, hub: "https://relay.example.com/"}
endpoints:
  - {name: office, exchange: home, word: k3f9-x2mq-7hpa}
`
	cfg, err := ParseConfig(text)
	if err != nil {
		t.Fatal(err)
	}
	_, endpoints := relayViews(cfg, nil)
	if len(endpoints) != 1 || len(endpoints[0].UsedBy) != 2 || endpoints[0].UsedBy[0].Prefix == "" {
		t.Fatalf("used by: %+v", endpoints)
	}
	if _, _, err := editRelays(text, relayEdit{Kind: "endpoint", Op: "delete", Name: "office"}); err == nil || !strings.Contains(err.Error(), "used by 2 rules and serve entries") {
		t.Fatalf("delete: %v", err)
	}
	out, notes, err := editRelays(text, relayEdit{Kind: "endpoint", Op: "update", Name: "office", NewName: "head-office", Exchange: "home"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "relay+ssl://head-office") || !strings.Contains(out, "RELAY://head-office") || strings.Contains(out, "//office") || len(notes) != 1 {
		t.Fatalf("%v\n%s", notes, out)
	}
	cfg, err = ParseConfig(out)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, s := range cfg.Rules[0].Routes {
		if s.Prefix != "/other/" && (s.endpoint == nil || s.EndpointName != "head-office") {
			t.Errorf("%s: %+v", s.Prefix, s)
		}
	}
}

// The Relays page's edits: what they write, what they keep, what they
// rename, and what they refuse.
func TestEditRelays(t *testing.T) {
	text := relayListener + `routes:
  - listener: a
    rules:
      - {domain: office.test, target: relay://office}
      - {domain: other.test, target: "RELAY://office", cert: local-ca, upstream_tls: false}
      - {domain: plain.test, target: "10.0.0.1:443"}
`
	step := func(e relayEdit) string {
		t.Helper()
		out, _, err := editRelays(text, e)
		if err != nil {
			t.Fatalf("%+v: %v", e, err)
		}
		return out
	}
	fails := func(e relayEdit, want string) {
		t.Helper()
		if _, _, err := editRelays(text, e); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%+v: got %v, want %q", e, err, want)
		}
	}
	loads := func() *Config {
		t.Helper()
		cfg, err := ParseConfig(text)
		if err != nil {
			t.Fatalf("%v\n%s", err, text)
		}
		return cfg
	}

	// An endpoint on an exchange that does not exist is written, and refused
	// by the load that every save goes through.
	if out, _, err := editRelays(text, relayEdit{Kind: "endpoint", Op: "add", Name: "office", Exchange: "home", Word: "k3f9-x2mq-7hpa"}); err != nil {
		t.Fatal(err)
	} else if _, err := ParseConfig(out); err == nil || !strings.Contains(err.Error(), "there is no exchanges item of that name") {
		t.Fatalf("got %v", err)
	}
	text = step(relayEdit{Kind: "exchange", Op: "add", Name: "home", Hub: "https://relay.example.com/"})
	fails(relayEdit{Kind: "exchange", Op: "add", Name: "home", Hub: "https://x.example/"}, "there is already an exchange home")
	fails(relayEdit{Kind: "exchange", Op: "add", Name: "bad/name", Hub: "https://x.example/"}, "the name must be")
	fails(relayEdit{Kind: "exchange", Op: "add", Name: "x"}, "the hub's https address is required")
	fails(relayEdit{Kind: "endpoint", Op: "add", Name: "office", Exchange: "home"}, "the tunnel's word is required")
	fails(relayEdit{Kind: "endpoint", Op: "add", Name: "office", Word: "k3f9-x2mq-7hpa"}, "choose the exchange")
	text = step(relayEdit{Kind: "endpoint", Op: "add", Name: "office", Exchange: "home", Word: "k3f9-x2mq-7hpa", ClientToken: "correct-horse-battery"})
	cfg := loads()
	if e := cfg.Endpoints["office"]; e == nil || e.Word != "k3f9-x2mq-7hpa" || e.ClientToken != "correct-horse-battery" || e.Exchange() != cfg.Exchanges["home"] {
		t.Fatalf("endpoint office: %+v\n%s", e, text)
	}

	// Blank word and token keep them; NoToken clears the token.
	text = step(relayEdit{Kind: "endpoint", Op: "update", Name: "office", Exchange: "home"})
	if e := loads().Endpoints["office"]; e.Word != "k3f9-x2mq-7hpa" || e.ClientToken != "correct-horse-battery" {
		t.Fatalf("an edit with blanks lost the secrets: %+v", e)
	}
	text = step(relayEdit{Kind: "endpoint", Op: "update", Name: "office", Exchange: "home", Word: "h7cq-m2xe-9tka", NoToken: true})
	if e := loads().Endpoints["office"]; e.Word != "h7cq-m2xe-9tka" || e.ClientToken != "" {
		t.Fatalf("new word, no token: %+v", e)
	}

	// Renames follow into what uses them.
	text = step(relayEdit{Kind: "exchange", Op: "update", Name: "home", NewName: "home-hub", Hub: "https://relay.example.com:18222/"})
	text = step(relayEdit{Kind: "endpoint", Op: "update", Name: "office", NewName: "head-office", Exchange: "home-hub"})
	cfg = loads()
	if e := cfg.Endpoints["head-office"]; e == nil || e.ExchangeName != "home-hub" || e.Exchange().Hub != "https://relay.example.com:18222/" {
		t.Fatalf("after the renames: %+v\n%s", e, text)
	}
	for sni, want := range map[string]string{"office.test": "relay://head-office", "other.test": "relay://head-office", "plain.test": "10.0.0.1:443"} {
		if got := route(t, cfg, sni); got != want {
			t.Errorf("%s -> %s, want %s\n%s", sni, got, want, text)
		}
	}
	fails(relayEdit{Kind: "endpoint", Op: "update", Name: "office", Exchange: "home-hub"}, "there is no endpoint office any more")

	// New endpoint names keep to letters, digits and _+-; one already in the
	// config (written by hand, or before the rule) still loads and edits.
	fails(relayEdit{Kind: "endpoint", Op: "add", Name: "Venus(Test)", Exchange: "home-hub", Word: "k3f9-x2mq-7hpa", NoToken: true}, "an endpoint name must be")
	fails(relayEdit{Kind: "endpoint", Op: "update", Name: "head-office", NewName: "head office", Exchange: "home-hub"}, "an endpoint name must be")
	text = strings.ReplaceAll(text, "head-office", "Venus(Test)")
	if e := loads().Endpoints["Venus(Test)"]; e == nil {
		t.Fatalf("an old-style endpoint name no longer loads:\n%s", text)
	}
	text = step(relayEdit{Kind: "endpoint", Op: "update", Name: "Venus(Test)", Exchange: "home-hub", Word: "h7cq-m2xe-9tka"})
	text = step(relayEdit{Kind: "endpoint", Op: "update", Name: "Venus(Test)", NewName: "head-office", Exchange: "home-hub"})

	// Nothing used can go; the last item takes its section with it.
	fails(relayEdit{Kind: "exchange", Op: "delete", Name: "home-hub"}, "exchange home-hub is used by 1 endpoint: change them first")
	fails(relayEdit{Kind: "endpoint", Op: "delete", Name: "head-office"}, "endpoint head-office is used by 2 rules and serve entries: change them first")
	text = regexp.MustCompile(`(?i)['"]?relay://head-office['"]?`).ReplaceAllString(text, `"10.0.0.2:443"`)
	text = step(relayEdit{Kind: "endpoint", Op: "delete", Name: "head-office"})
	text = step(relayEdit{Kind: "exchange", Op: "delete", Name: "home-hub"})
	if strings.Contains(text, "endpoints") || strings.Contains(text, "exchanges") {
		t.Fatalf("empty sections left behind:\n%s", text)
	}
	loads()
}

// The Relays page's checks, against a real hub.
func TestRelayChecks(t *testing.T) {
	hub := startHub(t)
	echo := backend(t, func(c *net.TCPConn) {})
	const token = "correct-horse-battery"
	served := hub.serve(t, true, fmt.Sprintf("127.0.0.1:%d", echo), token)
	cfg := mustLoadYAML(t, relayListener+hub.exchange()+fmt.Sprintf(`  - {name: no-ca, hub: %q}
endpoints:
%s%s%s`, hub.url,
		endpointItem("served", served, token),
		endpointItem("wrong-token", served, "wrong-horse-battery"),
		endpointItem("unserved", "abcd-efgh-jkmn", "")))
	ctx := context.Background()

	if good, msg := checkHub(ctx, cfg.Exchanges["hub"]); !good || !strings.Contains(msg, "a pf-simple hub with QUIC") {
		t.Errorf("hub: %v %s", good, msg)
	}
	if good, msg := checkHub(ctx, cfg.Exchanges["no-ca"]); good || !strings.Contains(msg, "needs its ca.pem as ca_file") {
		t.Errorf("hub without its CA: %v %s", good, msg)
	}
	notHub := httptest.NewTLSServer(http.NotFoundHandler())
	defer notHub.Close()
	x := &Exchange{Name: "web", Hub: notHub.URL + "/", roots: nil}
	x.roots = notHub.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	if good, msg := checkHub(ctx, x); good || !strings.Contains(msg, "offers no QUIC tunnels") {
		t.Errorf("a web server: %v %s", good, msg)
	}

	for name, want := range map[string]string{
		"served":      "the tunnel is served",
		"wrong-token": "access denied",
		"unserved":    "access denied",
	} {
		good, msg := checkTunnel(ctx, cfg.Endpoints[name], "test")
		if good != (name == "served") || !strings.Contains(msg, want) {
			t.Errorf("%s: %v %s", name, good, msg)
		}
	}
}

// A hub at a path of its own (pf-simple [console] path): the exchange's hub
// has the path in it, and the checks and the tunnel go there; without the
// path the hub is not found.
func TestRelayHubAtPath(t *testing.T) {
	const path = "/xzfe-aeeg-e2da"
	hub := startHubAt(t, path)
	echo := backend(t, func(c *net.TCPConn) {})
	served := hub.serve(t, true, fmt.Sprintf("127.0.0.1:%d", echo), "")
	root := strings.TrimSuffix(hub.url, path+"/") + "/"
	cfg := mustLoadYAML(t, relayListener+hub.exchange()+fmt.Sprintf(`  - {name: no-path, hub: %q, ca_file: %q}
  - {name: no-slash, hub: %q, ca_file: %q}
endpoints:
%s  - {name: wrong-hub, exchange: no-path, word: %s}
`, root, hub.caFile, strings.TrimSuffix(hub.url, "/"), hub.caFile, endpointItem("served", served, ""), served))
	ctx := context.Background()

	for name, want := range map[string]string{
		"hub":      "a pf-simple hub with QUIC",
		"no-slash": "a pf-simple hub with QUIC",
		"no-path":  "the hub is at another path",
	} {
		good, msg := checkHub(ctx, cfg.Exchanges[name])
		if good != (name != "no-path") || !strings.Contains(msg, want) {
			t.Errorf("exchange %s (%s): %v %s", name, cfg.Exchanges[name].Hub, good, msg)
		}
	}
	if good, msg := checkTunnel(ctx, cfg.Endpoints["served"], "test"); !good {
		t.Errorf("the tunnel through %s: %s", hub.url, msg)
	}
	if good, msg := checkTunnel(ctx, cfg.Endpoints["wrong-hub"], "test"); good {
		t.Errorf("the tunnel without the hub's path: %s", msg)
	}
}
