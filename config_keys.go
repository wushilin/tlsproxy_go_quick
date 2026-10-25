package main

// The config reference shown by the console's Config file page (the ⓘ
// button): every key, by section, with its default and meaning. It is
// generated into console/reference.json, which the page renders; a test keeps
// that file in step with this table, and this table in step with the parser
// (TestConfigReference). Regenerate with:
//
//	UPDATE_REFERENCE=1 go test -run TestConfigReference

type keyDoc struct {
	Key     string `json:"key"`
	Default string `json:"default"`
	Meaning string `json:"meaning"`
}

type sectionDoc struct {
	Section string   `json:"section"`
	About   string   `json:"about"`
	Keys    []keyDoc `json:"keys"`
}

var configReference = []sectionDoc{
	{"global", "Settings for the whole proxy. Listeners may override some of them.", []keyDoc{
		{"handshake_timeout", "10", "Seconds to receive the whole ClientHello; a slow trickle can't extend it."},
		{"connect_timeout", "10", "Seconds to resolve and connect to the target."},
		{"idle_timeout", "600", "Close after N seconds with no traffic either way. 0 = never."},
		{"half_close_timeout", "30", "After one side closes, the other side gets N seconds. 0 = unlimited."},
		{"max_connections", "1024", "Open connections at most; more are rejected."},
		{"max_handshakes_per_ip", "64", "Connections from one source (IPv4 address or IPv6 /64) still sending their ClientHello. 0 = unlimited."},
		{"proxy_trust_source", "(nobody)", "A list of addresses or networks that may send a PROXY protocol header (v1 or v2). (Called proxy_protocol_from before v1.5.0.)"},
		{"buffer_size", "65536", "Bytes moved per step in each direction: the splice pipe size, or the size of each pooled buffer. Clamped to 4096..131072."},
		{"buffer_pool_max_idle", "2 × max_connections", "Free buffers kept for reuse."},
		{"splice", "true", "Linux: relay passed-through connections with splice(2), without copying them through the proxy."},
		{"remember_nonce", "true", "Remember a hash of every ClientHello passed through for 10 seconds (at most 1M, newest win) and refuse one that comes in again: it is this proxy's own connection come back (a name or ${host} target that points at this machine), which would otherwise loop until max_connections. Terminated connections are not covered."},
		{"http_to_https_redirect", "false", "Also listen on port 80 (every address the listeners use) and answer each plain HTTP request with a redirect to the same URL on https://: 301 for GET and HEAD, 308 for other methods. Every name is redirected; the HTTPS listeners' rules decide from there. The listener is named http-to-https-redirect (a reserved name); the console can stop and start it."},
		{"low_latency", "false", "Never hold a short read back to batch it. Off, a busy stream that arrives a little at a time waits 5 ms to move in bigger chunks, for much less CPU; replies to requests are not held."},
		{"allow_cache_size", "4096", "Cached allowed name → target decisions. 0 = off."},
		{"deny_cache_size", "4096", "Cached denied names, kept apart from the allowed ones. 0 = off."},
		{"reload_interval", "5", "Check the file every N seconds and apply changes (minimum 5). 0 = only on console saves."},
		{"stats_interval", "60", "Log a one-line summary every N seconds. 0 = never."},
		{"cert_root", "./certs", "Where all certificates live: your CAs, one folder each (ca001, the default CA, made at start-up; ca002, ...) with what they issued, and acme/ with the automatic certificates and the ACME account key. Was ca_root (and cert_path) before v1.5.0."},
		{"expiry_threshold_days", "15", "Renew this many days before expiry (or at a third of the lifetime left, if later)."},
		{"acme_agree_tos", "false", "Must be true for cert: auto: you accept the CA's terms of service."},
		{"acme_email", "(none)", "Contact address for the ACME account."},
		{"acme_directory", "Let's Encrypt production", "ACME directory URL."},
		{"acme_ca_file", "(none)", "Extra root CA for the ACME server's own HTTPS (a private CA, Pebble)."},
		{"public_ip_address", "(not checked)", "A list: cert: auto only asks the CA when the name resolves to one of these addresses."},
		{"dns_resolvers", "required with cert: auto and public_ip_address", "A list of public DNS servers for that check, IP or IP:port: three attempts, each the next server in turn, 3 s each; no answer means no certificate is requested. E.g. [1.1.1.1, 8.8.8.8, 2606:4700:4700::1111]."},
		{"io_model", "", "Legacy: accepted and ignored."},
		{"worker_threads", "", "Legacy: accepted and ignored."},
		{"short_read_delay_us", "", "Legacy: accepted and ignored; replaced by lingering, see low_latency."},
	}},
	{"listeners", "A list of ports, each with its own rules; at least one is required. Overrides apply to that listener only. With the web console on, its listener, $console, may be listed by name with options only: no bind or port.", []keyDoc{
		{"name", "(required)", "Up to 64 letters, digits, spaces and -_@#~()[]<>\"'; unique ignoring case. What listener: in routes refers to."},
		{"bind", "0.0.0.0", "Listen addresses, a list: 0.0.0.0 all IPv4, :: all IPv6 and IPv4. The web console's exact bind and port are reserved."},
		{"port", "(required)", "Listen port. Two listeners can't share a port on the same or a wildcard address."},
		{"proxy_trust_source", "global", "Overrides global for this listener."},
		{"max_connections", "(no own limit)", "A cap for this listener, on top of the global one."},
		{"handshake_timeout", "global", "Overrides global for this listener."},
		{"idle_timeout", "global", "Overrides global for this listener."},
		{"half_close_timeout", "global", "Overrides global for this listener."},
		{"max_aggregated_speed", "unlimited", "Shared by every connection on this listener, each direction, on top of each rule's limits. E.g. 1Gbit, 100MB/s, 64MiB/s."},
		{"max_single_connection_speed", "unlimited", "For each connection on this listener, each direction."},
	}},
	{"routes", "A list of items, each the rules of one listener.", []keyDoc{
		{"listener", "(required)", "The listener its rules belong to: a name from listeners, or $console (the web console's)."},
		{"rules", "(none)", "Its list of rules (see rules)."},
	}},
	{"rules", "Each item of a routes item's rules. The most specific domain wins: $no_sni and literal names, then wildcards (more fixed characters first), then $anything_else. A name no rule matches is denied.", []keyDoc{
		{"domain", "(required)", "A host name with * wildcards (a * never crosses a dot; as a whole label it is exactly one label), $no_sni for clients that send no name, or $anything_else for every name no other rule takes (checked last)."},
		{"action", "allow", "allow or deny. deny answers with a TLS access_denied alert."},
		{"target", "(required for allow)", "host:port to connect to; an IPv6 host in brackets, [2001:db8::1]:443. ${1}, ${2}, ... are what each * matched; ${host} (or ${0}) is the whole name. Always in braces."},
		{"cert", "(pass through)", "Terminate TLS here: auto (ACME, TLS-ALPN-01); or local-ca / local-ca:ca002 (your own CA in cert_root, made on the Certificates page, issuing one certificate per name on first use)."},
		{"cert_domains", "the literal domain", "A list. cert: auto: exact names to issue. cert: local-ca: names or globs (*.dev.example.com, several) that get a certificate; any other name is refused (default: every name the rule matches). With $no_sni or $anything_else it may list IP addresses: a client without a host name gets one certificate for all of them (and a $no_sni rule's names), otherwise one for the address it connected to; an IP address a client sends as SNI must be listed."},
		{"cert_validate_script", "(none)", "cert: auto: a script that decides per name not in cert_domains; exit 0 = issue."},
		{"cert_validate_args", "[\"${host}\"]", "The script's arguments, a list of strings with ${1}, ${host} ... filled in."},
		{"upstream_tls", "true", "Terminated rules: speak TLS to the target; false = plaintext."},
		{"upstream_tls_verify", "true", "Verify the target's certificate."},
		{"upstream_sni", "the client's name", "SNI sent to the target and checked in its certificate."},
		{"proxy", "none", "v1 or v2: send the target a PROXY protocol header with the client's address."},
		{"max_aggregated_speed", "unlimited", "Shared by every connection of this rule, each direction. E.g. 1Gbit, 100MB/s, 64MiB/s."},
		{"max_single_connection_speed", "unlimited", "For each connection of this rule, each direction."},
		{"serve", "(none)", "A list of entries: the rule answers HTTP itself instead of connecting to a target (needs cert; no target, upstream_* or proxy). The longest prefix wins; none = 404. See serve entries."},
	}},
	{"serve entries", "Each item of a rule's serve list. A reverse_proxy target gets X-Forwarded-For/-Proto/-Host/-Port/-Prefix, X-Real-IP, Forwarded, X-Forwarded-By and Via; what the client sent in those is replaced (Via is added to).", []keyDoc{
		{"type", "(required)", "reverse_proxy or static_content."},
		{"prefix", "(required)", "The request path it takes, starting with /. For /api/, a request for /api is redirected to /api/."},
		{"target", "(required for reverse_proxy)", "http://host:port or https://host:port, no path."},
		{"strip_prefix", "false", "reverse_proxy: /api/x is sent as /x."},
		{"force_host", "the client's Host", "reverse_proxy: the Host header sent on."},
		{"tls_verify", "true", "reverse_proxy to https://: check the target's certificate."},
		{"base_dir", "(required for static_content)", "The folder the prefix stands for: /assets/a.css is base_dir/a.css. A folder is served by its index.html, else index.htm, else a listing (directory_listing) or 403. No hidden files but .well-known, no symlinks out."},
		{"directory_listing", "false", "static_content: true lists a folder that has no index.html or index.htm (hidden files left out); false answers 403."},
		{"basic_auth", "(none)", "The name of a basic_auth item whose users may use it."},
	}},
	{"basic_auth", "A list of user groups that serve entries can ask for (basic_auth: <name>). A password a browser sends is checked once and remembered for 5 minutes.", []keyDoc{
		{"name", "(required)", "What basic_auth: in a serve entry names; unique."},
		{"users", "(at least one)", "A list of {username, password_hash} (argon2id, or pbkdf2-sha256; make one with tlsproxy --hash-password) or {username, password_plain}, each optionally with disabled: true and expires: 2026-12-31 (through that day, UTC) or an RFC 3339 time (default: never)."},
	}},
	{"logging", "Where the two log streams go: activity (stdout) and problems (stderr).", []keyDoc{
		{"stdout", "the process's stdout", "File for activity: accepted, route, connected, closed, stats, reloads."},
		{"stderr", "the process's stderr", "File for problems."},
		{"max_size", "15MiB", "Rotate a file once it reaches this size (K, M, G)."},
		{"max_keep", "10", "Rotated generations kept: file.1 (newest) .. file.N."},
		{"compress_after", "3", "Generations above this number are gzip-compressed."},
	}},
	{"console", "The web console is not in this file: it is set at start-up, so nothing saved from it can change it. On by default; -noconsole turns it off.", []keyDoc{
		{"-console_domain", "$CONSOLE_DOMAIN, or none", "The name it is served under, as a rule of its listener that this file can't override. Unset or none: that listener's $no_sni (clients by IP address), with a local CA's certificate; an IP address: the same, for that address."},
		{"$CONSOLE_PASSWORD", "(required)", "Its password, hashed at start-up, or a hash from tlsproxy --hash-password."},
		{"-console_bind", "$CONSOLE_BIND, or all addresses", "Where it listens."},
		{"-console_port", "$CONSOLE_PORT, or 443", "Its port. The console's listener is $console on any port; its bind and port are reserved."},
		{"-console_cert", "$CONSOLE_CERT, or auto (local-ca without a host name)", "auto (needs acme_agree_tos: true and a host name) or local-ca / local-ca:ca002."},
	}},
}
