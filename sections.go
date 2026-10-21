package main

// Editing config.yaml one rule or listener at a time, for the console: the
// file is read into its YAML tree, the one item changes there, and the tree
// is written back, so comments and the rest of the file survive (spacing is
// the library's).
//
// Values come from the console as JSON: a string, a list of strings, or
// for serve a list of objects. An empty value or list removes the key.

import (
	"bytes"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// ruleKeys and listenerKeys are each item's keys, in the order a new item
// lists them. listener is not a key of a rule in the file: it is the routes
// item the rule sits in.
var (
	ruleKeys = []string{"domain", "action", "target", "cert", "cert_domains", "cert_validate_script", "cert_validate_args",
		"upstream_tls", "upstream_tls_verify", "upstream_sni", "proxy", "max_aggregated_speed", "max_single_connection_speed", "serve"}
	listenerKeys = []string{"name", "bind", "port", "proxy_trust_source", "max_connections",
		"handshake_timeout", "idle_timeout", "half_close_timeout", "max_aggregated_speed", "max_single_connection_speed"}
	serveKeys = []string{"type", "prefix", "target", "base_dir", "strip_prefix", "force_host", "tls_verify", "basic_auth"}
)

// yamlDoc is a config.yaml being edited.
type yamlDoc struct {
	doc  *yaml.Node
	root *yaml.Node // the top mapping
}

func loadDoc(text string) (*yamlDoc, error) {
	doc, err := parseYAML(text)
	if err != nil {
		return nil, err
	}
	return &yamlDoc{doc: doc, root: doc.Content[0]}, nil
}

// String writes the tree back, indented by two.
func (d *yamlDoc) String() string { return encodeNode(d.doc) }

func encodeNode(n *yaml.Node) string {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	enc.Encode(n)
	enc.Close()
	return buf.String()
}

// mapGet is the value of key in mapping m, nil if absent.
func mapGet(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// section is the top-level list key (listeners, routes), made if missing.
func (d *yamlDoc) section(key string) *yaml.Node {
	if v := mapGet(d.root, key); v != nil {
		if v.Kind != yaml.SequenceNode { // "routes:" with nothing after it
			*v = yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		}
		return v
	}
	v := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	d.root.Content = append(d.root.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, v)
	return v
}

// ruleAt finds the rule whose mapping starts on line, with the routes item
// holding it.
func (d *yamlDoc) ruleAt(line int) (group, rules, rule *yaml.Node) {
	routes := mapGet(d.root, "routes")
	if routes == nil || routes.Kind != yaml.SequenceNode {
		return nil, nil, nil
	}
	for _, g := range routes.Content {
		rs := mapGet(g, "rules")
		if rs == nil || rs.Kind != yaml.SequenceNode {
			continue
		}
		for _, r := range rs.Content {
			if r.Line == line && r.Kind == yaml.MappingNode {
				return g, rs, r
			}
		}
	}
	return nil, nil, nil
}

// groupFor is the routes item for a listener, made at the end if missing.
func (d *yamlDoc) groupFor(listener string) *yaml.Node {
	routes := d.section("routes")
	for _, g := range routes.Content {
		if l := mapGet(g, "listener"); l != nil && l.Value == listener {
			if mapGet(g, "rules") == nil {
				g.Content = append(g.Content, scalar("rules"), &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"})
			}
			return g
		}
	}
	g := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{
		scalar("listener"), scalar(listener), scalar("rules"), {Kind: yaml.SequenceNode, Tag: "!!seq"}}}
	routes.Content = append(routes.Content, g)
	return g
}

// scalar is a YAML value for s: a number or true/false as one, anything
// else a string (quoted when it has to be).
func scalar(s string) *yaml.Node {
	tag := "!!str"
	if _, err := strconv.ParseUint(s, 10, 63); err == nil && (s == "0" || !strings.HasPrefix(s, "0")) {
		tag = "!!int"
	} else if s == "true" || s == "false" {
		tag = "!!bool"
	}
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: s}
}

// valueNode turns one value from the console into YAML; nil means remove
// the key.
func valueNode(key string, v any) (*yaml.Node, error) {
	switch x := v.(type) {
	case nil:
		return nil, nil
	case string:
		x = strings.TrimSpace(x)
		if strings.ContainsAny(x, "\r\n") {
			return nil, fmt.Errorf("%s: values cannot span lines", key)
		}
		if x == "" {
			return nil, nil
		}
		return scalar(x), nil
	case []any:
		if len(x) == 0 {
			return nil, nil
		}
		seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		if key == "serve" {
			seq.Style = 0
			for i, it := range x {
				m, ok := it.(map[string]any)
				if !ok {
					return nil, fmt.Errorf("serve entry %d is not an object", i+1)
				}
				entry := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Style: yaml.FlowStyle}
				if err := setMapping(entry, serveKeys, m, true); err != nil {
					return nil, fmt.Errorf("serve entry %d: %v", i+1, err)
				}
				if len(entry.Content) > 0 {
					seq.Content = append(seq.Content, entry)
				}
			}
			if len(seq.Content) == 0 {
				return nil, nil
			}
			return seq, nil
		}
		seq.Style = yaml.FlowStyle
		for _, it := range x {
			s, ok := it.(string)
			if !ok {
				return nil, fmt.Errorf("%s: a list of values", key)
			}
			if s = strings.TrimSpace(s); s != "" {
				seq.Content = append(seq.Content, scalar(s))
			}
		}
		if len(seq.Content) == 0 {
			return nil, nil
		}
		return seq, nil
	case bool:
		return scalar(strconv.FormatBool(x)), nil
	case float64:
		return scalar(strconv.FormatFloat(x, 'f', -1, 64)), nil
	}
	return nil, fmt.Errorf("%s: unexpected value %v", key, v)
}

// setMapping applies values to mapping m: a changed key keeps its place
// and comments, an empty one goes, a new one is added in keys order. With
// strict, every value's key must be in keys.
func setMapping(m *yaml.Node, keys []string, values map[string]any, strict bool) error {
	for k := range values {
		if strict && !slices.Contains(keys, k) {
			return fmt.Errorf("unknown key %q", k)
		}
	}
	for _, k := range keys {
		v, given := values[k]
		if !given {
			continue // not part of this edit
		}
		node, err := valueNode(k, v)
		if err != nil {
			return err
		}
		i := -1
		for j := 0; j+1 < len(m.Content); j += 2 {
			if m.Content[j].Value == k {
				i = j
				break
			}
		}
		switch {
		case node == nil && i >= 0:
			m.Content = slices.Delete(m.Content, i, i+2)
		case node == nil:
		case i >= 0:
			if old := m.Content[i+1]; sameValue(old, node) {
				continue // unchanged: keep it as written
			} else {
				node.LineComment = old.LineComment
			}
			m.Content[i+1] = node
		default:
			// After the last key that comes before it in keys order.
			at := len(m.Content)
			for j := 0; j+1 < len(m.Content); j += 2 {
				if slices.Index(keys, m.Content[j].Value) > slices.Index(keys, k) {
					at = j
					break
				}
			}
			m.Content = slices.Insert(m.Content, at, scalar(k), node)
			m.Content[at].Tag = "!!str"
		}
	}
	return nil
}

// sameValue reports whether two value nodes read the same.
func sameValue(a, b *yaml.Node) bool {
	if a.Kind != b.Kind {
		return false
	}
	if a.Kind == yaml.ScalarNode {
		return a.Value == b.Value
	}
	if len(a.Content) != len(b.Content) {
		return false
	}
	for i := range a.Content {
		if !sameValue(a.Content[i], b.Content[i]) {
			return false
		}
	}
	return true
}

// nodeValues reads an item's keys for the console: a scalar as text, a
// list of scalars as a list, serve as a list of objects.
func nodeValues(m *yaml.Node) map[string]any {
	out := map[string]any{}
	for i := 0; i+1 < len(m.Content); i += 2 {
		k, v := m.Content[i].Value, m.Content[i+1]
		out[k] = nodeValue(v)
	}
	return out
}

func nodeValue(v *yaml.Node) any {
	switch v.Kind {
	case yaml.ScalarNode:
		if v.Tag == "!!null" {
			return ""
		}
		return v.Value
	case yaml.SequenceNode:
		var items []any
		for _, it := range v.Content {
			items = append(items, nodeValue(it))
		}
		return items
	case yaml.MappingNode:
		return nodeValues(v)
	}
	return ""
}

// ruleValues reads a rule for the console, with its routes item's listener.
func ruleValues(group, rule *yaml.Node) map[string]any {
	v := nodeValues(rule)
	if l := mapGet(group, "listener"); l != nil {
		v["listener"] = l.Value
	}
	return v
}

// editRules applies one change to the config text: values for the rule
// whose mapping starts on line (0 adds a new rule), or its deletion. It
// returns the new text, the rule as written and the line it starts on in
// the new text (empty and 0 after a delete).
func editRules(text string, line int, values map[string]any, del bool) (string, string, int, error) {
	full, block, rule, d, err := editRule(text, line, values, del)
	if err != nil || rule == nil {
		return full, "", 0, err
	}
	return full, block, d.lineAfter(full, rule), nil
}

// lineAfter is where node, a rule or listener of d, starts in full, the
// text d was written as.
func (d *yamlDoc) lineAfter(full string, node *yaml.Node) int {
	again, err := loadDoc(full)
	if err != nil {
		return 0
	}
	for _, key := range []string{"listeners", "routes"} {
		a, b := mapGet(d.root, key), mapGet(again.root, key)
		if a == nil || b == nil {
			continue
		}
		for i, item := range a.Content {
			if item == node && i < len(b.Content) {
				return b.Content[i].Line
			}
			ra, rb := mapGet(item, "rules"), (*yaml.Node)(nil)
			if i < len(b.Content) {
				rb = mapGet(b.Content[i], "rules")
			}
			if ra == nil || rb == nil {
				continue
			}
			for j, r := range ra.Content {
				if r == node && j < len(rb.Content) {
					return rb.Content[j].Line
				}
			}
		}
	}
	return 0
}

func editRule(text string, line int, values map[string]any, del bool) (string, string, *yaml.Node, *yamlDoc, error) {
	d, err := loadDoc(text)
	if err != nil {
		return "", "", nil, nil, err
	}
	listener, _ := values["listener"].(string)
	values = without(values, "listener")
	var rule *yaml.Node
	switch {
	case line == 0 && !del:
		if listener == "" {
			return "", "", nil, nil, fmt.Errorf("listener is required")
		}
		rule = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		if err := setMapping(rule, ruleKeys, values, true); err != nil {
			return "", "", nil, nil, err
		}
		rules := mapGet(d.groupFor(listener), "rules")
		rules.Content = append(rules.Content, rule)
	default:
		group, rules, r := d.ruleAt(line)
		if r == nil {
			return "", "", nil, nil, fmt.Errorf("there is no rule at line %d any more; reload and try again", line)
		}
		if del {
			rules.Content = slices.DeleteFunc(rules.Content, func(n *yaml.Node) bool { return n == r })
			d.dropEmptyGroup(group)
			return d.String(), "", nil, d, nil
		}
		if err := setMapping(r, ruleKeys, values, true); err != nil {
			return "", "", nil, nil, err
		}
		rule = r
		if l := mapGet(group, "listener"); listener != "" && (l == nil || l.Value != listener) {
			// Another listener: the rule moves to that listener's routes item.
			rules.Content = slices.DeleteFunc(rules.Content, func(n *yaml.Node) bool { return n == r })
			d.dropEmptyGroup(group)
			dst := mapGet(d.groupFor(listener), "rules")
			dst.Content = append(dst.Content, r)
		}
	}
	return d.String(), encodeNode(rule), rule, d, nil
}

// dropEmptyGroup removes a routes item that has no rules left.
func (d *yamlDoc) dropEmptyGroup(group *yaml.Node) {
	if rs := mapGet(group, "rules"); rs != nil && len(rs.Content) > 0 {
		return
	}
	routes := mapGet(d.root, "routes")
	routes.Content = slices.DeleteFunc(routes.Content, func(n *yaml.Node) bool { return n == group })
}

func without(m map[string]any, key string) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		if k != key {
			out[k] = v
		}
	}
	return out
}

// listenerAt finds the listener whose mapping starts on line.
func (d *yamlDoc) listenerAt(line int) *yaml.Node {
	ls := mapGet(d.root, "listeners")
	if ls == nil || ls.Kind != yaml.SequenceNode {
		return nil
	}
	for _, l := range ls.Content {
		if l.Line == line && l.Kind == yaml.MappingNode {
			return l
		}
	}
	return nil
}

// editListeners applies one change to a listener: values for the one on
// line (0 adds one), or its deletion. A rename renames it in its routes
// item too. It returns the new text, the listener as written, the line it
// starts on in the new text, and notes on any change beyond it.
func editListeners(text string, line int, values map[string]any, del bool) (string, string, int, []string, error) {
	full, block, node, notes, d, err := editListener(text, line, values, del)
	if err != nil || node == nil {
		return full, "", 0, notes, err
	}
	return full, block, d.lineAfter(full, node), notes, nil
}

func editListener(text string, line int, values map[string]any, del bool) (string, string, *yaml.Node, []string, *yamlDoc, error) {
	d, err := loadDoc(text)
	if err != nil {
		return "", "", nil, nil, nil, err
	}
	var notes []string
	if line == 0 {
		l := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		if err := setMapping(l, listenerKeys, values, true); err != nil {
			return "", "", nil, nil, nil, err
		}
		ls := d.section("listeners")
		ls.Content = append(ls.Content, l)
		return d.String(), encodeNode(l), l, nil, d, nil
	}
	l := d.listenerAt(line)
	if l == nil {
		return "", "", nil, nil, nil, fmt.Errorf("there is no listener at line %d any more; reload and try again", line)
	}
	if del {
		ls := mapGet(d.root, "listeners")
		ls.Content = slices.DeleteFunc(ls.Content, func(n *yaml.Node) bool { return n == l })
		return d.String(), "", nil, nil, d, nil
	}
	oldName := ""
	if n := mapGet(l, "name"); n != nil {
		oldName = n.Value
	}
	if err := setMapping(l, listenerKeys, values, true); err != nil {
		return "", "", nil, nil, nil, err
	}
	if newName, _ := values["name"].(string); newName != "" && newName != oldName && oldName != "" {
		if routes := mapGet(d.root, "routes"); routes != nil {
			for _, g := range routes.Content {
				if n := mapGet(g, "listener"); n != nil && n.Value == oldName {
					n.Value = newName
					notes = append(notes, fmt.Sprintf("Renames the listener in its routes: listener: %s becomes listener: %s", oldName, newName))
				}
			}
		}
	}
	return d.String(), encodeNode(l), l, notes, d, nil
}

// fileValues is what the console shows of each rule and listener in the
// file, by the line its mapping starts on.
func fileValues(text string) (rules, listeners map[int]map[string]any) {
	rules, listeners = map[int]map[string]any{}, map[int]map[string]any{}
	d, err := loadDoc(text)
	if err != nil {
		return
	}
	if ls := mapGet(d.root, "listeners"); ls != nil {
		for _, l := range ls.Content {
			if l.Kind == yaml.MappingNode {
				listeners[l.Line] = nodeValues(l)
			}
		}
	}
	if routes := mapGet(d.root, "routes"); routes != nil {
		for _, g := range routes.Content {
			if rs := mapGet(g, "rules"); rs != nil {
				for _, r := range rs.Content {
					if r.Kind == yaml.MappingNode {
						rules[r.Line] = ruleValues(g, r)
					}
				}
			}
		}
	}
	return
}

// sectionValues is a top-level mapping (global, logging) as text values.
func sectionValues(text, key string) map[string]string {
	out := map[string]string{}
	d, err := loadDoc(text)
	if err != nil {
		return out
	}
	if m := mapGet(d.root, key); m != nil && m.Kind == yaml.MappingNode {
		for k, v := range nodeValues(m) {
			out[k] = valueText(v)
		}
	}
	return out
}

// valueText is a value as one line: a list joined with ", ".
func valueText(v any) string {
	if items, ok := v.([]any); ok {
		var s []string
		for _, it := range items {
			s = append(s, fmt.Sprint(it))
		}
		return strings.Join(s, ", ")
	}
	return fmt.Sprint(v)
}
