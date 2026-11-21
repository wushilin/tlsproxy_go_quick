package main

// The console's Relays page (relay.go): the exchanges (pf-simple hubs) and
// the endpoints on them (tunnels, by word), the rules that use each, and
// changes to them. A word or client token is never sent back to the page:
// the page shows the word's first group, and an edit that leaves either
// blank keeps it.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/wushilin/pf-simple/pfrelay"
	"go.yaml.in/yaml/v3"
)

type exchangeView struct {
	Name      string   `json:"name"`
	Line      int      `json:"line"`
	Hub       string   `json:"hub"`
	CAFile    string   `json:"caFile"`
	Endpoints []string `json:"endpoints"` // on this exchange
}

type endpointUseView struct {
	Rule     string `json:"rule"` // the rule's domain
	Listener string `json:"listener"`
	Line     int    `json:"line"`
	Prefix   string `json:"prefix,omitempty"` // a serve entry's reverse proxy (relay:// or relay+ssl://)
}

type endpointView struct {
	Name        string            `json:"name"`
	Line        int               `json:"line"`
	Exchange    string            `json:"exchange"`
	Word        string            `json:"word"` // its first group only
	ClientToken bool              `json:"clientToken"`
	UsedBy      []endpointUseView `json:"usedBy"`
	Active      int               `json:"active"` // connections open through it now
}

// relayViews lists cfg's exchanges and endpoints, by name.
func relayViews(cfg *Config, pool *relayPool) ([]exchangeView, []endpointView) {
	exchanges, endpoints := []exchangeView{}, []endpointView{}
	if cfg == nil {
		return exchanges, endpoints
	}
	for _, name := range slices.Sorted(maps.Keys(cfg.Exchanges)) {
		x := cfg.Exchanges[name]
		v := exchangeView{Name: name, Line: x.Line, Hub: x.Hub, CAFile: x.CAFile, Endpoints: []string{}}
		for _, en := range slices.Sorted(maps.Keys(cfg.Endpoints)) {
			if cfg.Endpoints[en].ExchangeName == name {
				v.Endpoints = append(v.Endpoints, en)
			}
		}
		exchanges = append(exchanges, v)
	}
	for _, name := range slices.Sorted(maps.Keys(cfg.Endpoints)) {
		e := cfg.Endpoints[name]
		v := endpointView{Name: name, Line: e.Line, Exchange: e.ExchangeName, Word: e.WordLabel(), ClientToken: e.ClientToken != "", UsedBy: []endpointUseView{}}
		if pool != nil {
			v.Active = pool.active(e)
		}
		for _, r := range cfg.Rules {
			if r.EndpointName == name {
				v.UsedBy = append(v.UsedBy, endpointUseView{Rule: r.Source, Listener: r.Listener, Line: r.Line})
			}
			for _, s := range r.Routes {
				if s.EndpointName == name {
					v.UsedBy = append(v.UsedBy, endpointUseView{Rule: r.Source, Listener: r.Listener, Line: r.Line, Prefix: s.Prefix})
				}
			}
		}
		endpoints = append(endpoints, v)
	}
	return exchanges, endpoints
}

func (c *Console) relayList(w http.ResponseWriter, r *http.Request) {
	pf := c.configFile()
	exchanges, endpoints := relayViews(pf.cfg, c.srv.relays)
	writeJSON(w, 200, map[string]any{"ok": true, "exchanges": exchanges, "endpoints": endpoints, "file": pf.view})
}

// relayEdit is one change to the exchanges or endpoints.
type relayEdit struct {
	Kind    string // exchange or endpoint
	Op      string // add, update, delete
	Name    string // the item changed (update, delete), or the new one (add)
	NewName string // update: its name from now on ("" = unchanged)

	Hub    string // exchange
	CAFile string

	Exchange    string // endpoint
	Word        string // update: "" keeps the word
	ClientToken string // update: "" keeps the token, unless NoToken
	NoToken     bool   // the tunnel asks for no client token
}

// relaySave makes one change, through the same checks as every other save.
func (c *Console) relaySave(w http.ResponseWriter, r *http.Request) {
	var req struct {
		relayEdit
		BaseHash, BaseMtime string
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		fail(w, 400, "bad request")
		return
	}
	configFileMu.Lock()
	defer configFileMu.Unlock()
	onDisk, ver, err := c.readConfig()
	if err != nil {
		fail(w, 500, "%v", err)
		return
	}
	if req.BaseMtime != ver.Mtime || req.BaseHash != ver.Hash {
		fail(w, http.StatusConflict, "not saved: the config file changed after this page loaded it. The page now shows the current version; try again")
		return
	}
	full, notes, err := editRelays(string(onDisk), req.relayEdit)
	if err == nil {
		var cfg *Config
		if cfg, err = c.check(full); err == nil {
			for _, n := range notes {
				logf("console: %s", n)
			}
			c.commit(w, r, onDisk, full, cfg, fmt.Sprintf("%s %s %s", req.Kind, req.Name, map[string]string{"add": "added", "update": "changed", "delete": "deleted"}[req.Op]))
			return
		}
	}
	writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
}

// namedItem finds the item of the list section whose name is name.
func (d *yamlDoc) namedItem(section, name string) *yaml.Node {
	list := mapGet(d.root, section)
	if list == nil || list.Kind != yaml.SequenceNode {
		return nil
	}
	for _, it := range list.Content {
		if n := mapGet(it, "name"); n != nil && n.Value == name {
			return it
		}
	}
	return nil
}

// dropItem removes item from the list section, and the section with its
// last item.
func (d *yamlDoc) dropItem(section string, item *yaml.Node) {
	list := mapGet(d.root, section)
	list.Content = slices.DeleteFunc(list.Content, func(n *yaml.Node) bool { return n == item })
	if len(list.Content) > 0 {
		return
	}
	for i := 0; i+1 < len(d.root.Content); i += 2 {
		if d.root.Content[i].Value == section {
			d.root.Content = slices.Delete(d.root.Content, i, i+2)
			return
		}
	}
}

// exchangeRefs are the exchange: values of the endpoints on name.
func (d *yamlDoc) exchangeRefs(name string) []*yaml.Node {
	var out []*yaml.Node
	if list := mapGet(d.root, "endpoints"); list != nil {
		for _, it := range list.Content {
			if v := mapGet(it, "exchange"); v != nil && v.Value == name {
				out = append(out, v)
			}
		}
	}
	return out
}

// endpointRefs are the target: values that go through name: of rules
// (relay://) and of their serve entries (relay:// or relay+ssl://).
func (d *yamlDoc) endpointRefs(name string) []*yaml.Node {
	var out []*yaml.Node
	routes := mapGet(d.root, "routes")
	if routes == nil {
		return nil
	}
	add := func(v *yaml.Node, schemes ...string) {
		if v == nil {
			return
		}
		if scheme, n := relayTargetName(v.Value, schemes...); scheme != "" && n == name {
			out = append(out, v)
		}
	}
	for _, g := range routes.Content {
		rs := mapGet(g, "rules")
		if rs == nil {
			continue
		}
		for _, r := range rs.Content {
			add(mapGet(r, "target"), relayScheme)
			if serve := mapGet(r, "serve"); serve != nil && serve.Kind == yaml.SequenceNode {
				for _, e := range serve.Content {
					if e.Kind == yaml.MappingNode {
						add(mapGet(e, "target"), relayScheme, relaySSLScheme)
					}
				}
			}
		}
	}
	return out
}

// relayTargetName splits a target written with one of schemes into the
// scheme as written and the endpoint's name; "" if it has none of them.
func relayTargetName(v string, schemes ...string) (string, string) {
	v = strings.TrimSpace(v)
	for _, scheme := range schemes {
		if len(v) > len(scheme) && strings.EqualFold(v[:len(scheme)], scheme) {
			return v[:len(scheme)], strings.TrimSuffix(v[len(scheme):], "/")
		}
	}
	return "", ""
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// editRelays applies one change to the exchanges or endpoints. Renaming one
// renames it where it is used; deleting one that is used is refused.
func editRelays(text string, e relayEdit) (string, []string, error) {
	d, err := loadDoc(text)
	if err != nil {
		return "", nil, err
	}
	e.Name, e.NewName = strings.TrimSpace(e.Name), strings.TrimSpace(e.NewName)
	section, refs := "", func(string) []*yaml.Node { return nil }
	switch e.Kind {
	case "exchange":
		section, refs = "exchanges", d.exchangeRefs
	case "endpoint":
		section, refs = "endpoints", d.endpointRefs
	default:
		return "", nil, fmt.Errorf("unknown kind %q", e.Kind)
	}
	item := d.namedItem(section, e.Name)
	switch {
	case e.Op == "add" && item != nil:
		return "", nil, fmt.Errorf("there is already an %s %s", e.Kind, e.Name)
	case e.Op != "add" && item == nil:
		return "", nil, fmt.Errorf("there is no %s %s any more; reload and try again", e.Kind, e.Name)
	}
	if e.Op == "delete" {
		if n := len(refs(e.Name)); n > 0 {
			users := map[string]string{"exchange": plural(n, "endpoint", "endpoints"), "endpoint": plural(n, "rule or serve entry", "rules and serve entries")}[e.Kind]
			return "", nil, fmt.Errorf("%s %s is used by %s: change them first", e.Kind, e.Name, users)
		}
		d.dropItem(section, item)
		return d.String(), nil, nil
	}
	if e.Op != "add" && e.Op != "update" {
		return "", nil, fmt.Errorf("unknown change %q", e.Op)
	}

	name := e.Name
	if e.Op == "update" && e.NewName != "" && e.NewName != e.Name {
		if d.namedItem(section, e.NewName) != nil {
			return "", nil, fmt.Errorf("there is already an %s %s", e.Kind, e.NewName)
		}
		name = e.NewName
	}
	if !listenerName.MatchString(name) {
		return "", nil, fmt.Errorf("the name must be 1-64 letters, digits, spaces or -_@#~()[]<>\"' (no space at either end)")
	}
	// A new endpoint name (added, or renamed to) is what rules write after
	// relay://, so it keeps to a URL-like alphabet. Existing names that
	// predate this are left as they are.
	if e.Kind == "endpoint" && (e.Op == "add" || name != e.Name) {
		if !endpointName.MatchString(name) {
			return "", nil, fmt.Errorf("an endpoint name must be 1-64 letters, digits or _+- (rules write it as relay://<name>), got %q", name)
		}
	}
	old := func(key string) string {
		if item != nil {
			if v := mapGet(item, key); v != nil {
				return v.Value
			}
		}
		return ""
	}

	// The item, written whole, in the order the reference lists its keys.
	m := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	set := func(k, v string, quote bool) {
		if v = strings.TrimSpace(v); v == "" {
			return
		}
		n := scalar(v)
		if quote {
			n.Style = yaml.DoubleQuotedStyle
		}
		m.Content = append(m.Content, scalar(k), n)
	}
	set("name", name, false)
	if e.Kind == "exchange" {
		if strings.TrimSpace(e.Hub) == "" {
			return "", nil, fmt.Errorf("the hub's https address is required, e.g. https://relay.example.com/")
		}
		set("hub", e.Hub, true)
		set("ca_file", e.CAFile, true)
	} else {
		if strings.TrimSpace(e.Exchange) == "" {
			return "", nil, fmt.Errorf("choose the exchange the tunnel is on")
		}
		word := strings.TrimSpace(e.Word)
		if word == "" {
			if word = old("word"); word == "" {
				return "", nil, fmt.Errorf("the tunnel's word is required, e.g. k3f9-x2mq-7hpa")
			}
		}
		token := e.ClientToken
		if e.NoToken {
			token = ""
		} else if token == "" {
			token = old("client_token")
		}
		set("exchange", e.Exchange, false)
		set("word", word, false)
		set("client_token", token, true)
	}

	var notes []string
	if item == nil {
		sec := d.section(section)
		sec.Content = append(sec.Content, m)
		return d.String(), notes, nil
	}
	*item = *m
	if name != e.Name {
		if rs := refs(e.Name); len(rs) > 0 {
			for _, r := range rs {
				if e.Kind == "exchange" {
					r.Value = name
				} else {
					scheme, _ := relayTargetName(r.Value, relayScheme, relaySSLScheme)
					r.Value = scheme + name // relay:// or relay+ssl://, as it was
				}
			}
			users := map[string]string{"exchange": plural(len(rs), "endpoint", "endpoints"), "endpoint": plural(len(rs), "target", "targets")}[e.Kind]
			notes = append(notes, fmt.Sprintf("%s %s renamed %s in %s", e.Kind, e.Name, name, users))
		}
	}
	return d.String(), notes, nil
}

// relayCheck checks one saved exchange or endpoint:
//
//   - an exchange: its https answers, with a certificate it trusts, and it
//     is a pf-simple hub that offers QUIC. No word is sent, so this is never
//     counted as a wrong guess by the hub.
//   - an endpoint: the hub lets it connect (QUIC), and the tunnel is served.
func (c *Console) relayCheck(w http.ResponseWriter, r *http.Request) {
	var req struct{ Kind, Name string }
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		fail(w, 400, "bad request")
		return
	}
	pf := c.configFile()
	if pf.cfg == nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": "the config file does not load; fix it first"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	switch req.Kind {
	case "exchange":
		x := pf.cfg.Exchanges[req.Name]
		if x == nil {
			writeJSON(w, 200, map[string]any{"ok": false, "error": "there is no exchange " + req.Name + " in the config file; reload the page"})
			return
		}
		good, msg := checkHub(ctx, x)
		writeJSON(w, 200, map[string]any{"ok": true, "good": good, "message": msg})
	case "endpoint":
		e := pf.cfg.Endpoints[req.Name]
		if e == nil {
			writeJSON(w, 200, map[string]any{"ok": false, "error": "there is no endpoint " + req.Name + " in the config file; reload the page"})
			return
		}
		good, msg := checkTunnel(ctx, e, c.srv.relays.agent)
		writeJSON(w, 200, map[string]any{"ok": true, "good": good, "message": msg})
	default:
		fail(w, 400, "bad request")
	}
}

// hubPath is where a hub's address says it is mounted: the address's path
// without its trailing slash, or /pf when it has none (as the SDK reads it).
func hubPath(p string) string {
	if p = strings.TrimSuffix(p, "/"); p == "" {
		return "/pf"
	}
	return p
}

// checkHub asks x's hub where its QUIC listener is, without saying what
// for: a pf-simple hub that offers QUIC answers 400 (no X-PF-Op), one
// without it 404.
func checkHub(ctx context.Context, x *Exchange) (bool, string) {
	u, err := url.Parse(strings.TrimSpace(x.Hub))
	if err != nil {
		return false, err.Error()
	}
	cfg := x.tlsConfig()
	if cfg == nil {
		cfg = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
	defer client.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+u.Host+hubPath(u.Path)+"/api/tunnel/quic", nil)
	if err != nil {
		return false, err.Error()
	}
	resp, err := client.Do(req)
	if err != nil {
		var unknown x509.UnknownAuthorityError
		if errors.As(err, &unknown) && x.CAFile == "" {
			return false, fmt.Sprintf("cannot reach the hub over https: %v. A hub with its own CA (pf-simple tls = \"self_signed\") needs its ca.pem as ca_file", err)
		}
		return false, fmt.Sprintf("cannot reach the hub over https: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	until := ""
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		until = ", its certificate valid until " + resp.TLS.PeerCertificates[0].NotAfter.UTC().Format(time.DateOnly)
	}
	switch resp.StatusCode {
	case http.StatusBadRequest:
		return true, "a pf-simple hub with QUIC (0.16.0 or later)" + until + ". Check an endpoint to try a tunnel over QUIC"
	case http.StatusNotFound:
		return false, "the https answers" + until + ", but offers no QUIC tunnels at " + hubPath(u.Path) + ": not a pf-simple hub, one older than 0.16.0, its relay hub is off, or the hub is at another path (put it in the address: https://host/<path>/)"
	default:
		return false, fmt.Sprintf("the https answers %s%s: not what a pf-simple hub says", resp.Status, until)
	}
}

// checkTunnel asks e's hub, over QUIC, whether e's tunnel is served.
func checkTunnel(ctx context.Context, e *Endpoint, agent string) (bool, string) {
	c, err := newEndpointClient(e, agent)
	if err != nil {
		return false, err.Error()
	}
	defer c.Close()
	c.Logf = nil
	if err := c.Check(ctx); err != nil {
		if errors.Is(err, pfrelay.ErrAccessDenied) {
			return false, "access denied: the word or the client token is wrong, or nobody serves the tunnel now"
		}
		if ctx.Err() != nil {
			return false, "no answer from the hub within 15 s"
		}
		return false, err.Error()
	}
	return true, "the tunnel is served: connections through relay://" + e.Name + " go through, over QUIC"
}
