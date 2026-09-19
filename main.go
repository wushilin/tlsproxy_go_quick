// tlsproxy: SNI-routing TLS pass-through proxy. It peeks at the ClientHello,
// picks a backend from config.toml and relays the raw (still encrypted)
// stream. No TLS termination. Standard library only.
package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	args := os.Args[1:]
	for _, a := range args {
		if a == "-h" || a == "--help" {
			fmt.Fprintf(os.Stderr, "usage: %s [config.toml] [--test <sni>...]\n", os.Args[0])
			return
		}
	}
	path := "config.toml"
	if len(args) > 0 && args[0] != "--test" {
		path, args = args[0], args[1:]
	}
	var testSNIs []string
	testMode := false
	if len(args) > 0 {
		if args[0] != "--test" {
			fmt.Fprintf(os.Stderr, "unexpected argument %q; see --help\n", args[0])
			os.Exit(2)
		}
		testMode, testSNIs = true, args[1:]
	}

	text, err := os.ReadFile(path)
	var cfg *Config
	if err == nil {
		cfg, err = ParseConfig(string(text))
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading %s: %v\n", path, err)
		os.Exit(1)
	}

	if testMode { // dry run: print routing decisions and exit
		for _, sni := range testSNIs {
			d := cfg.Route(strings.ToLower(sni))
			if sni == "" {
				sni = "<none>" // --test "" asks about a client without SNI
			}
			switch {
			case d.Err != "":
				fmt.Printf("%s -> ERROR %s\n", sni, d.Err)
			case d.Allow:
				fmt.Printf("%s -> %s:%d (rule line %d)\n", sni, d.Host, d.Port, d.RuleLine)
			case d.RuleLine == 0:
				fmt.Printf("%s -> DENY (no rule matched)\n", sni)
			default:
				fmt.Printf("%s -> DENY (rule line %d)\n", sni, d.RuleLine)
			}
		}
		return
	}

	if err := Run(cfg, path); err != nil {
		logf("fatal: %v", err)
		os.Exit(1)
	}
}
