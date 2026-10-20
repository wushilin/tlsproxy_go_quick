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
	{"[global]", "Settings for the whole proxy. Listeners may override some of them.", []keyDoc{
		{"handshake_timeout", "10", "Seconds to receive the whole ClientHello; a slow trickle can't extend it."},
		{"connect_timeout", "10", "Seconds to resolve and connect to the target."},
		{"idle_timeout", "600", "Close after N seconds with no traffic either way. 0 = never."},
		{"half_close_timeout", "30", "After one side closes, the other side gets N seconds. 0 = unlimited."},
		{"max_connections", "1024", "Open connections at most; more are rejected."},
		{"max_handshakes_per_ip", "64", "Connections from one source (IPv4 address or IPv6 /64) still sending their ClientHello. 0 = unlimited."},
		{"proxy_trust_source", "(nobody)", "Addresses or networks that may send a PROXY protocol header (v1 or v2), separated by ;. (Called proxy_protocol_from before v1.5.0.)"},
		{"buffer_size", "65536", "Bytes moved per step in each direction: the splice pipe size, or the size of each pooled buffer. Clamped to 4096..131072."},
		{"buffer_pool_max_idle", "2 × max_connections", "Free buffers kept for reuse."},
		{"splice", "true", "Linux: relay passed-through connections with splice(2), without copying them through the proxy."},
		{"remember_nonce", "true", "Remember a hash of every ClientHello passed through for 10 seconds (at most 1M, newest win) and refuse one that comes in again: it is this proxy's own connection come back (a name or ${host} target that points at this machine), which would otherwise loop until max_connections. Terminated connections are not covered."},
		{"http_to_https_redirect", "false", "Also listen on port 80 (every address the listeners use) and answer each plain HTTP request with a redirect to the same URL on https://: 301 for GET and HEAD, 308 for other methods. Every name is redirected; the HTTPS listeners' rules decide from there. The listener is named http-to-https-redirect (a reserved name); the console can stop and start it."},
		{"short_read_delay_us", "0", "Pause N microseconds after a short read so data batches up. 0 = off."},
		{"allow_cache_size", "4096", "Cached allowed name → target decisions. 0 = off."},
		{"deny_cache_size", "4096", "Cached denied names, kept apart from the allowed ones. 0 = off."},
		{"reload_interval", "5", "Check the file every N seconds and apply changes (minimum 5). 0 = only on console saves."},
		{"stats_interval", "60", "Log a one-line summary every N seconds. 0 = never."},
		{"cert_path", "./certs", "Where automatic certificates and the ACME account key are stored."},
		{"ca_root", "./ca", "Where your own CAs live, one folder each (ca001, ca002, ...), with the certificates they issued: see cert = local-ca."},
		{"expiry_threshold_days", "15", "Renew this many days before expiry (or at a third of the lifetime left, if later)."},
		{"acme_agree_tos", "false", "Must be true for cert = auto: you accept the CA's terms of service."},
		{"acme_email", "(none)", "Contact address for the ACME account."},
		{"acme_directory", "Let's Encrypt production", "ACME directory URL."},
		{"acme_ca_file", "(none)", "Extra root CA for the ACME server's own HTTPS (a private CA, Pebble)."},
		{"public_ip_address", "(not checked)", "cert = auto only asks the CA when the name resolves to one of these addresses, separated by ;."},
		{"dns_resolvers", "required with cert = auto and public_ip_address", "Public DNS servers for that check, IP or IP:port: three attempts, each the next server in turn, 3 s each; no answer means no certificate is requested. E.g. 1.1.1.1; 8.8.8.8; 2606:4700:4700::1111."},
		{"io_model", "", "Legacy: accepted and ignored."},
		{"worker_threads", "", "Legacy: accepted and ignored."},
	}},
	{"[[listener]]", "A port with its own rules; at least one is required. Overrides apply to this listener only.", []keyDoc{
		{"name", "(required)", "Up to 64 letters, digits, spaces and -_@#~()[]<>\"'; unique ignoring case. What listener = in a rule refers to."},
		{"bind", "0.0.0.0", "Listen address: 0.0.0.0 all IPv4, :: all IPv6 and IPv4, or addresses separated by ;."},
		{"port", "(required)", "Listen port. Two listeners can't share a port on the same or a wildcard address."},
		{"proxy_trust_source", "[global]", "Overrides [global] for this listener."},
		{"max_connections", "(no own limit)", "A cap for this listener, on top of the global one."},
		{"handshake_timeout", "[global]", "Overrides [global] for this listener."},
		{"idle_timeout", "[global]", "Overrides [global] for this listener."},
		{"half_close_timeout", "[global]", "Overrides [global] for this listener."},
		{"max_aggregated_speed", "unlimited", "Shared by every connection on this listener, each direction, on top of each rule's limits. E.g. 1Gbit, 100MB/s, 64MiB/s."},
		{"max_single_connection_speed", "unlimited", "For each connection on this listener, each direction."},
	}},
	{"[[host]]", "A rule. The most specific pattern wins: literal names, then wildcards (more fixed characters first), then ANY. A name no rule matches is denied.", []keyDoc{
		{"listener", "(required)", "The [[listener]] this rule belongs to."},
		{"pattern", "(required)", "A host name with * wildcards (a * never crosses a dot; as a whole label it is exactly one label), NONE for clients without SNI, or ANY for everything."},
		{"action", "allow", "allow or deny. deny answers with a TLS access_denied alert."},
		{"target_host", "(required for allow)", "Where to connect. ${1}, ${2}, ... are what each * matched; ${host} (or ${0}) is the whole name. Always in braces."},
		{"target_port", "(required for allow)", "Target port."},
		{"cert", "(pass through)", "Terminate TLS here: auto (ACME, TLS-ALPN-01); or local-ca / local-ca:ca002 (your own CA in ca_root, made on the CAs page, issuing one certificate per name on first use)."},
		{"cert_domains", "the literal pattern", "cert = auto: exact names to issue, separated by , or ;. cert = local-ca: names or globs (*.dev.example.com, several) that get a certificate; any other name is refused (default: every name the rule matches). With NONE or ANY it may list IP addresses: a client without a host name gets one certificate for all of them (and a NONE rule's names), otherwise one for the address it connected to; an IP address a client sends as SNI must be listed."},
		{"cert_validate_script", "(none)", "cert = auto: a script that decides per name not in cert_domains; exit 0 = issue."},
		{"cert_validate_args", "[\"${host}\"]", "The script's arguments, a TOML array of strings with ${1}, ${host} ... filled in."},
		{"upstream_tls", "true", "Terminated rules: speak TLS to the target; false = plaintext."},
		{"upstream_tls_verify", "true", "Verify the target's certificate."},
		{"upstream_sni", "the client's name", "SNI sent to the target and checked in its certificate."},
		{"proxy", "false", "Send the target a PROXY protocol header with the client's address."},
		{"proxy_version", "2", "PROXY protocol version, 1 or 2."},
		{"max_aggregated_speed", "unlimited", "Shared by every connection of this rule, each direction. E.g. 1Gbit, 100MB/s, 64MiB/s."},
		{"max_single_connection_speed", "unlimited", "For each connection of this rule, each direction."},
	}},
	{"[[local_services]]", "A small HTTP service this proxy runs itself, on its own port: static files, or a reverse proxy. Plain HTTP; put a terminating [[host]] rule in front (target_host = 127.0.0.1, target_port = its port). Follows hot reload.", []keyDoc{
		{"name", "(required)", "Unique, ignoring case; what server = in [[proxy_pass_rules]] refers to."},
		{"type", "(required)", "http_server (files from doc_root) or reverse_proxy (by [[proxy_pass_rules]])."},
		{"bind", "127.0.0.1", "Listen address: 127.0.0.1, 0.0.0.0, ::, or addresses separated by ;."},
		{"port", "(required)", "Listen port; may not clash with a listener, [console] or another service."},
		{"doc_root", "(required for http_server)", "The folder served: index.html for folders, no listings, no hidden files except /.well-known/, no symlinks out of it."},
		{"proxy_version", "auto", "auto: a PROXY v1/v2 header from a trusted peer is used if present. none: never looked for. v1, v2: required, or the connection is dropped. The address it states is the client's."},
		{"proxy_trust_source", "127.0.0.0/8; ::1", "Who may send a PROXY header: addresses or networks, separated by ;."},
		{"forwarded_proto", "https", "reverse_proxy: X-Forwarded-Proto sent upstream (http or https)."},
	}},
	{"[[proxy_pass_rules]]", "Where a reverse_proxy service sends a request: the longest matching prefix wins; none matches = 404. The client's X-Forwarded-For, X-Forwarded-Proto, X-Forwarded-Host and Forwarded are replaced, never kept.", []keyDoc{
		{"server", "(required)", "The [[local_services]] (type = reverse_proxy) this rule belongs to."},
		{"prefix", "(required)", "Path prefix, starting with /. / matches everything. For /asdf/, a request for /asdf is redirected (301) to /asdf/."},
		{"target_host", "(required)", "Upstream host name or IP address, plain HTTP."},
		{"target_port", "(required)", "Upstream port."},
		{"strip_prefix", "false", "true: /asdf/x is sent upstream as /x."},
		{"force_host", "the client's Host", "Host header sent upstream instead of the client's."},
	}},
	{"[logging]", "Where the two log streams go: activity (stdout) and problems (stderr).", []keyDoc{
		{"stdout", "the process's stdout", "File for activity: accepted, route, connected, closed, stats, reloads."},
		{"stderr", "the process's stderr", "File for problems."},
		{"max_size", "15MiB", "Rotate a file once it reaches this size (K, M, G)."},
		{"max_keep", "10", "Rotated generations kept: file.1 (newest) .. file.N."},
		{"compress_after", "3", "Generations above this number are gzip-compressed."},
	}},
	{"[console]", "This web console. Hidden from this editor: change it in the file itself. listen and port need a restart.", []keyDoc{
		{"listen", "127.0.0.1", "Bind address. The console is plain HTTP; keep it on loopback."},
		{"port", "(required)", "Console port."},
		{"password", "", "Plain text; replaced by password_hash when the proxy starts."},
		{"password_hash", "", "pbkdf2-sha256$...; make one with tlsproxy --hash-password."},
		{"secure_cookie", "false", "Mark the session cookie Secure; set true when the console is published through HTTPS."},
		{"hostnames", "(none)", "Names the console may be addressed by, besides IP addresses and localhost."},
	}},
}
