// tlsproxy: SNI-routing TLS proxy. It peeks at the ClientHello, picks a
// backend from config.toml and relays the raw (still encrypted) stream. Per
// rule it can terminate TLS instead, with certificates from ACME or a
// directory. Standard library plus the vendored golang.org/x/crypto/acme.
package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// version is set at build time: -ldflags "-X main.version=v0.3.0".
var version = "dev"

func main() {
	args := os.Args[1:]
	for _, a := range args {
		if a == "--version" {
			fmt.Println("tlsproxy", version)
			return
		}
		if a == "-h" || a == "--help" {
			fmt.Fprintf(os.Stderr, "usage: %s [config.toml] [--test <sni>...]\n       %s --hash-password    (reads a password from stdin, prints a [console] password_hash line)\n       %s --version\n", os.Args[0], os.Args[0], os.Args[0])
			return
		}
		if a == "--hash-password" {
			fmt.Fprint(os.Stderr, "Password (will be visible): ")
			line, err := bufio.NewReader(os.Stdin).ReadString('\n')
			if line = strings.TrimRight(line, "\r\n"); line == "" {
				fmt.Fprintf(os.Stderr, "no password given (%v)\n", err)
				os.Exit(2)
			}
			hash, err := hashPassword(line)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Printf("password_hash = \"%s\"\n", hash)
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
				fmt.Printf("%s -> %s (rule line %d, %s: %s)\n", sni, net.JoinHostPort(d.Host, strconv.Itoa(d.Port)), d.RuleLine, d.Rule.Kind, d.Rule.Source)
			case d.RuleLine == 0:
				fmt.Printf("%s -> DENY (no rule matched)\n", sni)
			default:
				fmt.Printf("%s -> DENY (rule line %d, %s: %s)\n", sni, d.RuleLine, d.Rule.Kind, d.Rule.Source)
			}
		}
		return
	}

	if err := Run(cfg, path); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}
