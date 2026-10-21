package main

// config.yaml: what the file looks like, and how it is read into the same
// per-key checks the proxy has always run (see LoadConfig).
//
//	global:          the whole proxy
//	  connect_timeout: 10
//	logging:         where the two log streams go
//	  stdout: /var/log/tlsproxy/out.log
//	listeners:       the ports, each with a name
//	  - name: lan
//	    bind: [0.0.0.0]
//	    port: 8443
//	routes:          rules, grouped by the listener they belong to
//	  - listener: lan
//	    rules:
//	      - domain: www.example.com
//	        target: "10.0.0.5:443"
//	basic_auth:      users that serve entries can ask for
//	  - name: team
//	    users:
//	      - {username: jack, password_hash: "$argon2id$..."}
//
// A list is a YAML list ("; " joined inside, which every list key reads).
// Unknown keys and keys given twice are errors, with their line.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"go.yaml.in/yaml/v3"
)

// topLevel are the file's sections, in the order a new file lists them.
var topLevel = []string{"global", "logging", "listeners", "routes", "basic_auth"}

// parseYAML reads text into its document node; an empty file is an empty
// mapping.
func parseYAML(text string) (*yaml.Node, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		return nil, yamlError(err)
	}
	if len(doc.Content) == 0 {
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}}
	}
	if root := doc.Content[0]; root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("line %d: the file is a mapping of %s", root.Line, strings.Join(topLevel, ", "))
	}
	return &doc, nil
}

// yamlError turns the YAML library's "yaml: line 3: ..." into "line 3: ...".
func yamlError(err error) error {
	return errors.New(strings.TrimPrefix(err.Error(), "yaml: "))
}

// pairs is a mapping's keys and values, refusing a key given twice and a
// key that is not a plain word.
func pairs(m *yaml.Node, where string) ([][2]*yaml.Node, error) {
	if m.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("line %d: %s must be a mapping of key: value", m.Line, where)
	}
	var out [][2]*yaml.Node
	seen := map[string]int{}
	for i := 0; i+1 < len(m.Content); i += 2 {
		k, v := m.Content[i], m.Content[i+1]
		if k.Kind != yaml.ScalarNode {
			return nil, fmt.Errorf("line %d: a key in %s must be a plain word", k.Line, where)
		}
		if prev, ok := seen[k.Value]; ok {
			return nil, fmt.Errorf("line %d: %s is already given at line %d", k.Line, k.Value, prev)
		}
		seen[k.Value] = k.Line
		out = append(out, [2]*yaml.Node{k, v})
	}
	return out, nil
}

// yamlValue is a value as the checks read it: a scalar's text, a list's
// items joined with "; ", nothing for null. cert_validate_args stays a
// list, as JSON.
func yamlValue(key string, v *yaml.Node) (string, error) {
	switch v.Kind {
	case yaml.ScalarNode:
		if v.Tag == "!!null" {
			return "", nil
		}
		if key == "cert_validate_args" {
			return "", fmt.Errorf("line %d: cert_validate_args is a list, e.g. [\"${host}\"]", v.Line)
		}
		return v.Value, nil
	case yaml.SequenceNode:
		var items []string
		for _, it := range v.Content {
			if it.Kind != yaml.ScalarNode {
				return "", fmt.Errorf("line %d: %s is a list of values", it.Line, key)
			}
			items = append(items, it.Value)
		}
		if key == "cert_validate_args" {
			js, _ := json.Marshal(items)
			return string(js), nil
		}
		return strings.Join(items, "; "), nil
	}
	return "", fmt.Errorf("line %d: %s takes a value or a list, not a mapping", v.Line, key)
}

// walkYAML reads the file into apply (global, logging, listener and rule
// keys), raws (the rules, built once the listeners are known) and auths.
func walkYAML(cfg *Config, text string, apply func(section, key, value string, line int) error, raws *[]rawRule, auths *[]*BasicAuth) error {
	doc, err := parseYAML(text)
	if err != nil {
		return err
	}
	top, err := pairs(doc.Content[0], "the file")
	if err != nil {
		return err
	}
	for _, kv := range top {
		k, v := kv[0], kv[1]
		switch k.Value {
		case "global", "logging":
			if v.Tag == "!!null" {
				continue
			}
			items, err := pairs(v, k.Value)
			if err != nil {
				return err
			}
			for _, it := range items {
				value, err := yamlValue(it[0].Value, it[1])
				if err != nil {
					return err
				}
				if err := apply(k.Value, it[0].Value, value, it[0].Line); err != nil {
					return err
				}
			}
		case "listeners":
			err = eachItem(v, "listeners", func(item *yaml.Node) error {
				items, err := pairs(item, "a listener")
				if err != nil {
					return err
				}
				cfg.Listeners = append(cfg.Listeners, Listener{Line: item.Line, Bind: "0.0.0.0", Binds: []string{"0.0.0.0"}})
				for _, it := range items {
					value, err := yamlValue(it[0].Value, it[1])
					if err != nil {
						return err
					}
					l := &cfg.Listeners[len(cfg.Listeners)-1]
					switch it[0].Value {
					case "bind":
						l.bindSet = true
					case "port":
						l.portSet = true
					}
					if err := apply("listener", it[0].Value, value, it[0].Line); err != nil {
						return err
					}
				}
				return nil
			})
		case "routes":
			err = eachItem(v, "routes", func(group *yaml.Node) error { return walkRoutes(group, apply, raws) })
		case "basic_auth":
			err = eachItem(v, "basic_auth", func(item *yaml.Node) error {
				a, err := walkBasicAuth(item)
				if err == nil {
					*auths = append(*auths, a)
				}
				return err
			})
		case "console":
			return fmt.Errorf("line %d: the console is not configured in this file: it is set at start-up with -console_domain and $CONSOLE_PASSWORD (or turned off with -noconsole)", k.Line)
		default:
			return fmt.Errorf("line %d: unknown section %q (sections: %s)", k.Line, k.Value, strings.Join(topLevel, ", "))
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// eachItem runs f on each item of a list (nothing for null).
func eachItem(v *yaml.Node, what string, f func(*yaml.Node) error) error {
	if v.Tag == "!!null" {
		return nil
	}
	if v.Kind != yaml.SequenceNode {
		return fmt.Errorf("line %d: %s is a list (each item starting with -)", v.Line, what)
	}
	for _, item := range v.Content {
		if err := f(item); err != nil {
			return err
		}
	}
	return nil
}

// walkRoutes reads one routes item: a listener and its rules.
func walkRoutes(group *yaml.Node, apply func(section, key, value string, line int) error, raws *[]rawRule) error {
	items, err := pairs(group, "a routes item")
	if err != nil {
		return err
	}
	var listener *string
	var rules *yaml.Node
	for _, it := range items {
		switch it[0].Value {
		case "listener":
			v, err := yamlValue("listener", it[1])
			if err != nil {
				return err
			}
			listener = &v
		case "rules":
			rules = it[1]
		default:
			return fmt.Errorf("line %d: unknown key %q in a routes item (listener, rules)", it[0].Line, it[0].Value)
		}
	}
	if listener == nil {
		return fmt.Errorf("line %d: a routes item needs listener: <name>, the listener its rules belong to", group.Line)
	}
	if rules == nil {
		return nil
	}
	return eachItem(rules, "rules", func(rule *yaml.Node) error {
		items, err := pairs(rule, "a rule")
		if err != nil {
			return err
		}
		name := *listener
		*raws = append(*raws, rawRule{line: rule.Line, listener: &name})
		r := &(*raws)[len(*raws)-1]
		for _, it := range items {
			key, v := it[0].Value, it[1]
			if key == "serve" {
				if err := walkServe(r, v); err != nil {
					return err
				}
				continue
			}
			value, err := yamlValue(key, v)
			if err != nil {
				return err
			}
			switch key {
			case "domain":
				key = "pattern"
			case "pattern", "target_host", "target_port", "proxy_version", "listener":
				return fmt.Errorf("line %d: unknown key %q in a rule (domain, action, target, cert, ..., proxy: v1 | v2; the listener comes from the routes item)", it[0].Line, key)
			case "target":
				r.target, r.targetLine = &value, it[0].Line // split once the domain is checked
				continue
			case "proxy":
				switch strings.ToLower(value) {
				case "v1", "v2":
					on, version := "true", value[1:]
					r.proxy, r.proxyVersion = &on, &version
				case "none", "false", "":
					off := "false"
					r.proxy = &off
				default:
					return fmt.Errorf("line %d: proxy must be v1 or v2 (the PROXY protocol header the target gets), or none, got %q", it[0].Line, value)
				}
				continue
			}
			if err := apply("host", key, value, it[0].Line); err != nil {
				return err
			}
		}
		return nil
	})
}

// splitTarget reads host:port, an IPv6 host in brackets.
func splitTarget(v string) (host, port string, err error) {
	if strings.HasPrefix(v, "[") {
		end := strings.Index(v, "]:")
		if end < 0 {
			return "", "", fmt.Errorf("%q: write an IPv6 target as [2001:db8::1]:443", v)
		}
		return v[1:end], v[end+2:], nil
	}
	i := strings.LastIndexByte(v, ':')
	if i < 0 {
		return "", "", fmt.Errorf("%q needs a port: host:port, e.g. 10.0.0.5:443", v)
	}
	host, port = v[:i], v[i+1:]
	if strings.Contains(host, ":") {
		if _, err := netip.ParseAddr(host); err == nil {
			return "", "", fmt.Errorf("%q: write an IPv6 target in brackets, [%s]:%s", v, host, port)
		}
		return "", "", fmt.Errorf("%q is not host:port", v)
	}
	return host, port, nil
}

// walkServe reads a rule's serve list into its service rules.
func walkServe(r *rawRule, v *yaml.Node) error {
	n := 0
	return eachItem(v, "serve", func(item *yaml.Node) error {
		n++
		items, err := pairs(item, "a serve entry")
		if err != nil {
			return err
		}
		raw := rawServiceRule{key: fmt.Sprintf("serve %d", n), line: item.Line}
		for _, it := range items {
			value, err := yamlValue(it[0].Value, it[1])
			if err != nil {
				return err
			}
			raw.opts = append(raw.opts, [2]string{it[0].Value, value})
		}
		r.serviceRules = append(r.serviceRules, raw)
		return nil
	})
}

// walkBasicAuth reads one basic_auth item.
func walkBasicAuth(item *yaml.Node) (*BasicAuth, error) {
	a := &BasicAuth{Line: item.Line, Users: map[string]credential{}}
	items, err := pairs(item, "a basic_auth item")
	if err != nil {
		return nil, err
	}
	for _, it := range items {
		switch it[0].Value {
		case "name":
			if a.Name = it[1].Value; !listenerName.MatchString(a.Name) {
				return nil, fmt.Errorf("line %d: name must be 1-64 letters, digits, spaces or -_@#~()[]<>\"' (no space at either end), got %q", it[0].Line, a.Name)
			}
		case "users":
			err = eachItem(it[1], "users", func(u *yaml.Node) error {
				fields, err := pairs(u, "a user")
				if err != nil {
					return err
				}
				var opts [][2]string
				for _, f := range fields {
					value, err := yamlValue(f[0].Value, f[1])
					if err != nil {
						return err
					}
					opts = append(opts, [2]string{f[0].Value, value})
				}
				if err := addUser(a, opts); err != nil {
					return fmt.Errorf("line %d: %v", u.Line, err)
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("line %d: unknown key %q in basic_auth (name, users)", it[0].Line, it[0].Value)
		}
	}
	return a, nil
}
