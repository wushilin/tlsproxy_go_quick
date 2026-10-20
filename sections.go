package main

// Editing the config file one section at a time, for the console: a
// [[host]] or [[listener]] block is rewritten in place, so comments, order
// and spacing elsewhere survive.

import (
	"encoding/json"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
)

// hostKeys and listenerKeys are each section's options, in the order a new
// block lists them.
var (
	hostKeys = []string{"listener", "pattern", "action", "target_host", "target_port",
		"max_aggregated_speed", "max_single_connection_speed", "proxy", "proxy_version",
		"cert", "cert_domains", "cert_validate_script", "cert_validate_args", "upstream_tls", "upstream_tls_verify", "upstream_sni"}
	listenerKeys = []string{"name", "bind", "port", "proxy_trust_source", "max_connections",
		"handshake_timeout", "idle_timeout", "half_close_timeout", "max_aggregated_speed", "max_single_connection_speed"}
)

const (
	hostHeader     = "[[host]]"
	listenerHeader = "[[listener]]"
)

func isComment(l string) bool { return strings.HasPrefix(strings.TrimSpace(l), "#") }
func isBlank(l string) bool   { return strings.TrimSpace(l) == "" }
func isHeader(l string) bool  { return strings.HasPrefix(strings.TrimSpace(l), "[") }

// block is the lines [start, end) of one section: its header through its
// last key, without the blank lines and the comments that lead into the
// next section.
type block struct{ start, end int }

// sectionBlocks finds every section whose header is header ("[[host]]",
// "[global]").
func sectionBlocks(lines []string, header string) []block {
	var out []block
	for i := 0; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) != header {
			continue
		}
		next := i + 1
		for next < len(lines) && !isHeader(lines[next]) {
			next++
		}
		end := next
		if next < len(lines) {
			for end-1 > i && isComment(lines[end-1]) {
				end-- // a comment right above the next header describes that section
			}
		}
		for end-1 > i && isBlank(lines[end-1]) {
			end--
		}
		out = append(out, block{i, end})
		i = next - 1
	}
	return out
}

func hostBlocks(lines []string) []block { return sectionBlocks(lines, hostHeader) }

// blockValues reads the options of a block as raw strings.
func blockValues(lines []string, b block) map[string]string {
	vals := map[string]string{}
	for _, l := range lines[b.start+1 : b.end] {
		if isBlank(l) || isComment(l) {
			continue
		}
		if k, v, ok := strings.Cut(l, "="); ok {
			k = strings.TrimSpace(k)
			if k == "cert_validate_args" { // an array: kept as TOML text, comment dropped
				if js, err := arrayValue(v); err == nil {
					vals[k] = tomlArray(js)
				}
			} else if val, err := parseValue(v); err == nil {
				vals[k] = val
			}
		}
	}
	return vals
}

// fmtValue writes a value so that parseValue reads it back unchanged: as it
// is when that is safe, double-quoted otherwise.
var plainValue = regexp.MustCompile(`^[A-Za-z0-9._:/*+=%,${}-]+$`)

func fmtValue(v string) (string, error) {
	if strings.ContainsAny(v, "\r\n\x00") {
		return "", fmt.Errorf("values cannot span lines")
	}
	// An array of strings (cert_validate_args) is written as it is.
	if strings.HasPrefix(v, "[") {
		if _, err := arrayValue(v); err == nil {
			return v, nil
		}
	}
	// Anything but a plain token is written as a quoted TOML string.
	if !plainValue.MatchString(v) {
		return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\t", `\t`).Replace(v) + `"`, nil
	}
	return v, nil
}

// tomlArray writes a JSON array of strings (from arrayValue) as TOML.
func tomlArray(js string) string {
	var items []string
	json.Unmarshal([]byte(js), &items)
	out := make([]string, len(items))
	for i, s := range items {
		out[i] = `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\t", `\t`).Replace(s) + `"`
	}
	return "[" + strings.Join(out, ", ") + "]"
}

// newBlock is a fresh section with the non-empty values, in keys order.
func newBlock(header string, keys []string, values map[string]string) ([]string, error) {
	out := []string{header}
	for _, k := range keys {
		if v := values[k]; v != "" {
			fv, err := fmtValue(v)
			if err != nil {
				return nil, fmt.Errorf("%s: %v", k, err)
			}
			out = append(out, k+" = "+fv)
		}
	}
	return out, nil
}

// setValues rewrites the option lines of b: a value replaces the line of its
// key (or is added after the last option), "" removes it. Lines that keep
// their value are left alone, inline comments included.
func setValues(lines []string, b block, keys []string, values map[string]string) ([]string, error) {
	old := blockValues(lines, b)
	out := []string{lines[b.start]}
	lastKey := 0 // index in out of the last option line, where new options go
	written := map[string]bool{}
	for _, l := range lines[b.start+1 : b.end] {
		k, _, isKV := strings.Cut(l, "=")
		k = strings.TrimSpace(k)
		if isBlank(l) || isComment(l) || !isKV {
			out = append(out, l)
			continue
		}
		v, set := values[k]
		switch {
		case !set:
			out = append(out, l) // not part of this edit
		case written[k]:
			continue // a repeated option: its first line carries the value now
		case v == "":
			written[k] = true
			continue // removed
		case v == old[k]:
			out = append(out, l) // unchanged: keep the line, inline comment included
		default:
			fv, err := fmtValue(v)
			if err != nil {
				return nil, fmt.Errorf("%s: %v", k, err)
			}
			indent := l[:len(l)-len(strings.TrimLeft(l, " \t"))]
			out = append(out, indent+k+" = "+fv)
		}
		written[k] = true
		lastKey = len(out) - 1
	}
	var added []string
	for _, k := range keys {
		if v := values[k]; v != "" && !written[k] {
			fv, err := fmtValue(v)
			if err != nil {
				return nil, fmt.Errorf("%s: %v", k, err)
			}
			added = append(added, k+" = "+fv)
		}
	}
	out = slices.Insert(out, lastKey+1, added...)
	return slices.Concat(lines[:b.start], out, lines[b.end:]), nil
}

// deleteBlock removes b, the comment right above it and one blank line.
func deleteBlock(lines []string, b block) []string {
	start := b.start
	for start > 0 && isComment(lines[start-1]) {
		start-- // the comment that introduces the section goes with it
	}
	rest := lines[b.end:]
	if start > 0 && isBlank(lines[start-1]) && (len(rest) == 0 || isBlank(rest[0])) {
		start-- // don't leave two blank lines behind
	}
	return slices.Concat(lines[:start], rest)
}

// insertBlock puts a new section at line index at (the start of a section,
// before its introducing comment, or len(lines)), separated by blank lines.
func insertBlock(lines []string, at int, sec []string) []string {
	for at > 0 && at < len(lines) && isComment(lines[at-1]) {
		at-- // keep a section's comment attached to it
	}
	if at == len(lines) {
		body := lines
		for len(body) > 0 && isBlank(body[len(body)-1]) {
			body = body[:len(body)-1]
		}
		return slices.Concat(body, []string{""}, sec, []string{""})
	}
	return slices.Concat(lines[:at], sec, []string{""}, lines[at:])
}

// blockAt finds the block whose header is on line (1-based).
func blockAt(blocks []block, line int) *block {
	for i := range blocks {
		if blocks[i].start == line-1 {
			return &blocks[i]
		}
	}
	return nil
}

func checkKeys(keys []string, values map[string]string, section string) error {
	for k := range values {
		if !slices.Contains(keys, k) {
			return fmt.Errorf("unknown %s option %q", section, k)
		}
	}
	return nil
}

// editRules applies one change to the config text: values for the rule
// whose header is on line (1-based; 0 adds a new rule), or its deletion.
// An empty value removes that option.
func editRules(text string, line int, values map[string]string, del bool) (string, error) {
	routes, setRoutes := values[serviceRulesValue]
	if setRoutes {
		values = maps.Clone(values)
		delete(values, serviceRulesValue)
	}
	if err := checkKeys(hostKeys, values, hostHeader); err != nil {
		return "", err
	}
	routeLines, err := serviceRuleLines(routes)
	if err != nil {
		return "", err
	}
	lines := strings.Split(text, "\n")
	blocks := hostBlocks(lines)
	b := blockAt(blocks, line)
	if line != 0 && b == nil {
		return "", fmt.Errorf("there is no [[host]] rule at line %d any more; reload and try again", line)
	}
	switch {
	case del:
		return strings.Join(deleteBlock(lines, *b), "\n"), nil
	case line == 0:
		sec, err := newBlock(hostHeader, hostKeys, values)
		if err != nil {
			return "", err
		}
		sec = append(sec, routeLines...)
		if len(blocks) == 0 {
			return strings.Join(insertBlock(lines, len(lines), sec), "\n"), nil
		}
		at := blocks[len(blocks)-1].end // after the last rule: new rules sit with the others
		return strings.Join(slices.Concat(lines[:at], []string{""}, sec, lines[at:]), "\n"), nil
	}
	out, err := setValues(lines, *b, hostKeys, values)
	if err != nil || !setRoutes {
		return strings.Join(out, "\n"), err
	}
	return strings.Join(replaceServiceRules(out, *blockAt(hostBlocks(out), line), routeLines), "\n"), nil
}

// serviceRulesValue is the rule editor's one text box for a rule's
// service_rule keys: one per line, written back as service_rule1, 2, ...
const serviceRulesValue = "service_rules"

// serviceRuleLines turns the text box into service_rule lines, checking
// each the way the config loader will. Blank lines and # comments are left
// out.
func serviceRuleLines(text string) ([]string, error) {
	var out []string
	for i, l := range strings.Split(text, "\n") {
		if l = strings.TrimSpace(l); l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		key := fmt.Sprintf("service_rule%d", len(out)+1)
		if _, err := parseServiceRule(key, l, 0); err != nil {
			return nil, fmt.Errorf("service rule on line %d: %v", i+1, err)
		}
		fv, err := fmtValue(l)
		if err != nil {
			return nil, fmt.Errorf("service rule on line %d: %v", i+1, err)
		}
		out = append(out, key+" = "+fv)
	}
	return out, nil
}

// replaceServiceRules swaps a block's service_rule lines for routes, put
// where the first one was (after the last option if there was none).
func replaceServiceRules(lines []string, b block, routes []string) []string {
	out := []string{lines[b.start]}
	at := -1
	for _, l := range lines[b.start+1 : b.end] {
		if k, _, ok := strings.Cut(l, "="); ok && !isComment(l) && isServiceRuleKey(strings.TrimSpace(k)) {
			if at < 0 {
				at = len(out)
			}
			continue
		}
		out = append(out, l)
	}
	if at < 0 {
		at = len(out)
		for at > 1 && (isBlank(out[at-1]) || isComment(out[at-1])) {
			at--
		}
	}
	out = slices.Insert(out, at, routes...)
	return slices.Concat(lines[:b.start], out, lines[b.end:])
}

// hostValues is blockValues for a [[host]] block, with its service_rule
// keys gathered into the editor's one text box (each key's last value, in
// the order the keys first appear).
func hostValues(lines []string, b block) map[string]string {
	vals := blockValues(lines, b)
	var order []string
	last := map[string]string{}
	for _, l := range lines[b.start+1 : b.end] {
		k, v, ok := strings.Cut(l, "=")
		if k = strings.TrimSpace(k); !ok || isComment(l) || !isServiceRuleKey(k) {
			continue
		}
		val, err := parseValue(v)
		if err != nil {
			continue
		}
		if _, seen := last[k]; !seen {
			order = append(order, k)
		}
		last[k] = val
		delete(vals, k)
	}
	if len(order) > 0 {
		var text []string
		for _, k := range order {
			text = append(text, last[k])
		}
		vals[serviceRulesValue] = strings.Join(text, "\n")
	}
	return vals
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// editListeners applies one change to a [[listener]]: values for the one on
// line (0 adds one), or its deletion. A rename retags the rules that named
// the old name. It returns the new text, the line of the edited
// section (0 after a delete) and notes on any change beyond the section.
func editListeners(text string, line int, values map[string]string, del bool) (string, int, []string, error) {
	if err := checkKeys(listenerKeys, values, listenerHeader); err != nil {
		return "", 0, nil, err
	}
	var notes []string
	lines := strings.Split(text, "\n")
	blocks := sectionBlocks(lines, listenerHeader)
	if line == 0 { // add, after the last listener
		sec, err := newBlock(listenerHeader, listenerKeys, values)
		if err != nil {
			return "", 0, nil, err
		}
		at := len(lines)
		if len(blocks) > 0 {
			at = blocks[len(blocks)-1].end
		} else if hb := hostBlocks(lines); len(hb) > 0 {
			at = hb[0].start
		}
		lines = slices.Concat(lines[:at], []string{""}, sec, lines[at:])
		return strings.Join(lines, "\n"), at + 2, notes, nil
	}
	b := blockAt(blocks, line)
	if b == nil {
		return "", 0, nil, fmt.Errorf("there is no [[listener]] at line %d any more; reload and try again", line)
	}
	if del {
		return strings.Join(deleteBlock(lines, *b), "\n"), 0, notes, nil
	}
	oldName := blockValues(lines, *b)["name"]
	out, err := setValues(lines, *b, listenerKeys, values)
	if err != nil {
		return "", 0, nil, err
	}
	if newName, ok := values["name"]; ok && newName != "" && newName != oldName && oldName != "" {
		retagged := 0
		for _, hb := range hostBlocks(out) {
			if blockValues(out, hb)["listener"] == oldName {
				if out, err = setValues(out, hb, hostKeys, map[string]string{"listener": newName}); err != nil {
					return "", 0, nil, err
				}
				retagged++
			}
		}
		if retagged > 0 {
			notes = append(notes, fmt.Sprintf("Renames the listener in its %d rule(s): listener = %s becomes listener = %s", retagged, oldName, newName))
		}
	}
	return strings.Join(out, "\n"), line, notes, nil
}
