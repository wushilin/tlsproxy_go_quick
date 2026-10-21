// tlsproxy: SNI-routing TLS proxy. It peeks at the ClientHello, picks a
// backend from config.yaml and relays the raw (still encrypted) stream. Per
// rule it can terminate TLS instead, with certificates from ACME or its own
// CA, and serve HTTP itself. Standard library plus the vendored
// golang.org/x/crypto (acme, argon2).
package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
)

// version is set at build time: -ldflags "-X main.version=v1.2.0".
var version = "v1.4.1"

const usage = `usage: %[1]s [config.yaml] [-noconsole] [-console_domain <name>] [-console_bind <addr>] [-console_port <n>] [-console_cert <auto|local-ca[:caNNN]>] [--test <sni>...]
       %[1]s --hash-password    (reads a password from stdin, prints an argon2id hash for $CONSOLE_PASSWORD or basic_auth)
       %[1]s --version

The web console is on unless -noconsole: it needs -console_domain (or
$CONSOLE_DOMAIN) and $CONSOLE_PASSWORD. It listens on all addresses, port
443 (on its own listener, $console), with cert auto.
-console_bind, -console_port and -console_cert (or $CONSOLE_BIND,
$CONSOLE_PORT, $CONSOLE_CERT) change that. Flags take one dash or two, and
-flag value or -flag=value.
`

// consoleFlags are the flags that take a value.
var consoleFlags = []string{"console_domain", "console_bind", "console_port", "console_cert"}

func main() {
	args := os.Args[1:]
	for _, a := range args {
		switch strings.TrimLeft(a, "-") {
		case "version":
			fmt.Println("tlsproxy", version)
			return
		case "h", "help":
			fmt.Fprintf(os.Stderr, usage, os.Args[0])
			return
		case "hash-password":
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
			fmt.Println(hash)
			return
		}
	}
	path := "config.yaml"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		path, args = args[0], args[1:]
	}
	flags := map[string]string{}
	noConsole := false
	var testSNIs []string
	testMode := false
	for len(args) > 0 {
		name, value, hasValue := strings.Cut(strings.TrimLeft(args[0], "-"), "=")
		args = args[1:]
		switch {
		case name == "":
			fmt.Fprintf(os.Stderr, "unexpected argument %q; see --help\n", name)
			os.Exit(2)
		case name == "noconsole":
			noConsole = true
		case name == "test":
			testMode, testSNIs, args = true, args, nil // the rest are names
		case slices.Contains(consoleFlags, name):
			if !hasValue {
				if len(args) == 0 {
					fmt.Fprintf(os.Stderr, "-%s needs a value; see --help\n", name)
					os.Exit(2)
				}
				value, args = args[0], args[1:]
			}
			flags[name] = value
		default:
			fmt.Fprintf(os.Stderr, "unexpected argument %q; see --help\n", "-"+name)
			os.Exit(2)
		}
	}

	var console *ConsoleConfig
	if !noConsole {
		var err error
		if console, err = ConsoleFromSettings(flags); err != nil {
			if !testMode { // a dry run routes without the console
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
			console = nil
		}
	} else if len(flags) > 0 {
		fmt.Fprintln(os.Stderr, "-noconsole and console flags together: drop one; see --help")
		os.Exit(2)
	}
	text, err := os.ReadFile(path)
	var cfg *Config
	if err == nil {
		cfg, err = LoadConfig(string(text), console)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading %s: %v\n", path, err)
		os.Exit(1)
	}

	if testMode { // dry run: print routing decisions and exit
		for _, w := range cfg.Warnings {
			fmt.Fprintf(os.Stderr, "warning: %s\n", w)
		}
		for _, name := range testSNIs {
			for i := range cfg.Listeners {
				d := cfg.ForListener(&cfg.Listeners[i]).Route(strings.ToLower(name))
				sni := name
				if sni == "" {
					sni = "<none>" // --test "" asks about a client without SNI
				}
				if len(cfg.Listeners) > 1 {
					sni = cfg.Listeners[i].Name + ": " + sni // each listener has its own rules
				}
				switch {
				case d.Err != "":
					fmt.Printf("%s -> ERROR %s\n", sni, d.Err)
				case d.Allow && d.Rule.Console:
					fmt.Printf("%s -> served here: the web console\n", sni)
				case d.Allow && d.Rule.Serves():
					fmt.Printf("%s -> served here (rule line %d, %s: %s)\n", sni, d.RuleLine, d.Rule.Kind, d.Rule.Source)
				case d.Allow:
					fmt.Printf("%s -> %s (rule line %d, %s: %s)\n", sni, net.JoinHostPort(d.Host, strconv.Itoa(d.Port)), d.RuleLine, d.Rule.Kind, d.Rule.Source)
				case d.RuleLine == 0:
					fmt.Printf("%s -> DENY (no rule matched)\n", sni)
				default:
					fmt.Printf("%s -> DENY (rule line %d, %s: %s)\n", sni, d.RuleLine, d.Rule.Kind, d.Rule.Source)
				}
			}
		}
		return
	}

	if err := Run(cfg, path); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}
