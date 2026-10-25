# Changelog

## Unreleased

- The console shows the proxy's version next to its name, once signed in.
- Busy streams are batched: when a read comes back short in the middle of a
  stream, the direction waits 5 ms and moves what arrived meanwhile with it,
  for far fewer wake-ups and system calls per byte. Spliced, copied and
  terminated connections alike; a request waiting for its reply is not held.
  `low_latency: true` in `global` turns it off. `short_read_delay_us` is
  replaced by it and now ignored, with a log line.

## v1.5.1

- The console's domain is optional. Unset, or `-console_domain none`, the
  console is its listener's `$no_sni` rule: clients reaching it by IP
  address, with a certificate from a local CA for the address they
  connected to (the default cert is `local-ca` then; `auto` is an error).
  An IP address as the domain is the same rule, its certificate for that
  address only. `config.yaml` can't have a `$no_sni` rule on the console's
  listener then; the console accepts any IP address in Host (or that one),
  never a host name. Useful for a console on a listener of its own, by IP.

## v1.5.0

Breaking:
- The configuration is YAML: `config.yaml` (the default path) with
  `global`, `logging`, `listeners`, `routes` (each a `listener` and its
  `rules`) and `basic_auth`. Lists are YAML lists. A rule's `pattern` is now
  `domain`, `target_host` + `target_port` are one `target: host:port` (IPv6
  in brackets), and `proxy` + `proxy_version` are `proxy: v1 | v2`. There is
  no converter: see `config.yaml` and `samples/` for the new form. (A local
  CA's own settings file, `<ca_root>/caNNN/config.toml`, is unchanged.)
- The web console is no longer configured in the file, and is on by
  default: `-console_domain <name>` (or `$CONSOLE_DOMAIN`) and
  `$CONSOLE_PASSWORD` (the password, or a hash) are required, or the proxy
  refuses to start and says so; `-noconsole` turns it off. It listens on
  all addresses, port 443, with `cert: auto`; `-console_bind`,
  `-console_port` and `-console_cert` (or `$CONSOLE_BIND`, `$CONSOLE_PORT`,
  `$CONSOLE_CERT`) change that. It is always served over TLS, inside the
  proxy, on a listener it owns, named `$console` on any port. That listener's name, bind and port, and the rule for the console's
  domain, can't be changed from `config.yaml`, which may still list the
  listener with other options (`proxy_trust_source`, `max_connections`,
  timeouts, speed limits) and route more rules to it. Another listener with
  exactly its bind and port is an error. The console can't stop its own rule
  or listener. Without a console, nothing is reserved.
- One folder for all certificates: `cert_root` (default `./certs`) holds the
  CAs (`ca001`, `ca002`, ...) and `acme/` (the automatic certificates and the
  ACME account). `ca_root` is renamed `cert_root` and `cert_path` is gone,
  both load errors that say what to write. Certificates in an old
  `cert_path` aren't read: each name is issued again, or move them into
  `<cert_root>/acme`.
- `proxy_protocol_from` is renamed `proxy_trust_source`. The old name is a
  load error that shows what to write.
- New password hashes (`tlsproxy --hash-password`) are argon2id. Existing
  `pbkdf2-sha256$...` hashes keep working.

Renewal:
- The local CAs' renewal pass (at start, then every 6 hours) runs on its own,
  so automatic certificates aren't held up while it works, and has 5 hours:
  what it doesn't get to by then waits for the next pass or a client's
  handshake, so two passes never overlap.
- A pass that finds a CA unchanged keeps it as it is, so what the CA issued
  is not checked against it again at its next handshake.
- Tests for renewal: a local CA 14 days from expiry is renewed (one with
  years left is not); an issued certificate 14 days from expiry part way
  through a run is renewed by the pass or the next handshake and served at
  once (one with 45 of 90 days left is not); the pass stops at its time
  limit and the next one finishes the job; an ACME certificate from Pebble
  14 days from expiry is renewed by the worker and served (a fresh one is
  not).

New:
- Serving HTTP here: a rule with `serve` entries answers HTTP itself, inside
  the TLS connection it terminates, with no target and no second hop.
  `{type: reverse_proxy, prefix: /api/, target: "http://h:p"}` (or
  `https://`; `strip_prefix`, `force_host`, `tls_verify`) and
  `{type: static_content, prefix: /assets/, base_dir: /folder}` (the prefix
  stands for the folder; no listings, no hidden files except `.well-known`,
  no symlinks out of it). The longest prefix wins; none is 404. The target
  gets the client's own address in `X-Forwarded-For` / `X-Real-IP`,
  `X-Forwarded-Proto: https`, `X-Forwarded-Host`, `X-Forwarded-Port`,
  `X-Forwarded-Prefix` (with `strip_prefix`), `Forwarded` (RFC 7239),
  `X-Forwarded-By: tlsproxy_go_quick/<version>` and `Via`; what the client
  sent in those is replaced (`Via` is added to).
  Clients get HTTP/2 if they ask. Each request is routed by its Host with the
  running configuration (a reload applies to the next request; a Host
  another rule serves gets 421).
- `basic_auth`: users (`username` with `password_hash` (argon2id or
  pbkdf2-sha256) or `password_plain`) that a serve entry asks for with
  `basic_auth: <name>`. A matched password is remembered for 5 minutes.
- `static_content` serves a folder's `index.html`, else its `index.htm`,
  else, with `directory_listing: true`, a listing page (sortable,
  filterable, light or dark; hidden files left out), else `403`. A
  `base_dir` that is missing at load is tried again on request, so making
  it later needs no reload.
- What the proxy answers itself (the console, serve entries, the port-80
  redirect) says `Server: tlsproxy_go_quick`; a reverse_proxy response's
  `Server` header is replaced with it. The directory listing links to the
  project on GitHub.
- The config editor's *Save & apply* validates first, as *Validate* does:
  an invalid file is not saved and the result points at its line; a valid
  one is saved and its settings tree and warnings are shown under the
  outcome.
- The console lists each listener's rules in the order they are tried
  (`$no_sni`, exact names, wildcards from the most specific, `$anything_else`
  last), and a rule's serve entries as a request tries them: the longest
  prefix first, `/` last; the editor saves them in that order.
- The console's rule editor has *Serve it here*, one card per serve entry:
  the prefix and target (or folder), the Host header on a row of its own,
  *strip the prefix* and *verify the target's certificate* as checkboxes,
  who may use it (anyone, or the users of a basic_auth group), and an example
  of where a request goes. It saves through the
  YAML tree: comments elsewhere in the file are kept. A **Basic auth** page
  adds, renames (with the serve entries that use it) and deletes groups, and
  adds, deletes, disables and sets the password and expiry of users;
  passwords are hashed in the proxy and never sent back to the page.
- A `basic_auth` user can have `disabled: true` and `expires:` (a date,
  through the end of that day UTC, or an RFC 3339 time; default never).
- `cert: local-ca` serves clients without SNI (`domain: NONE`, or `ANY`):
  a certificate for the IP address they connected to, or with IP addresses
  in `cert_domains`, one certificate for all of them (a `NONE` rule may add
  host names). An IP address sent as SNI is routed as no SNI and refused
  unless `cert_domains` lists it (it used to be a bad ClientHello).
  `cert: auto` on `NONE` stays an error, now pointing at `local-ca`.
- The console's Certificates and CAs pages are one **Certificates** page
  with a sub-tab per issuer (ACME, then each CA): the issuer on top, the
  certificates it issued in a table below; *+ New CA* and *Import CA…* sit
  in the sub-tab bar. The address remembers the sub-tab (`#certs/ca002`).
- `$console` in `listeners` and `routes` is the console's listener,
  whatever its port, so moving the console needs no edit. No other listener
  can be named so, and without a console it is an error; `https` is an
  ordinary name.
- What no rule takes is denied as before; the console now shows that as a
  locked `$anything_else → deny (implicit)` rule on each listener without
  one, with the connections it refused.
- A listener whose exact addresses another takes over (a rename) keeps its
  socket open instead of reopening the port.
- Error messages no longer mention the removed `cert = <directory>`.

## v1.4.1

Breaking:
- Every port is an explicit `[[listener]]`: `[global] bind` and `port` are
  gone, and a file needs at least one `[[listener]]`. A config that still
  sets them is refused with an error showing what to write instead:

      [[listener]]
      name = https
      bind = 0.0.0.0
      port = 443

  Names in logs, the console and the flow log are now the listener's own
  (it was `default` for the implicit one).

- Every `[[host]]` needs `listener = <name>`, even with a single listener.
- Every allow rule needs `target_port`; it no longer defaults to 443.

  Both are load errors that name the rule's line. The console's rule form
  asks for both.

## v1.4.0

- `[global] remember_nonce = true` (the default): loop detection. A hash of
  every ClientHello passed through is kept for 10 s (a fixed lock-free table
  of 1M entries); a connection whose ClientHello comes back is this proxy's
  own and is refused, instead of looping until `max_connections` runs out
  (e.g. `ANY` → `${host}` with a name that points at this machine).

## v1.3.0

- `[global] http_to_https_redirect = true` (default false): a listener named
  `http-to-https-redirect` on port 80 answers every plain HTTP request with a
  redirect to the same URL on `https://` (301 for GET/HEAD, 308 otherwise),
  whatever the name; keep-alive supported, request bodies never read. It
  follows hot reload, is shown in the console with Stop/Start and its
  connections (not editable), and its connections are in the flow log. The
  name is reserved.

## v1.2.1

Breaking:
- `dns_resolvers` has no default any more: `cert = auto` with
  `public_ip_address` needs it, or the config is refused with an error that
  says what to add (e.g. `dns_resolvers = 1.1.1.1; 8.8.8.8; 2606:4700:4700::1111`).
  Entries must be IP addresses or IP:port.

- Console: certificates are cards, with a filter (name, CA, status) and a
  Remove button. A local CA's certificate can always be removed (archived;
  the next client gets a new one); an ACME one only when something is wrong
  with it (expired, last attempt failed, unusable files). The server enforces
  the same rule. Removed ACME certificates go to `<cert_path>/_archive`,
  deleted after 14 days.
- A local CA's certificate in memory is checked again (once) whenever its CA
  changes, and served with the CA's current chain; one the CA did not sign is
  archived and replaced. Serving still reads no file.
- DNS pre-check: at most three attempts, each the next resolver in turn and
  each given 3 seconds (not configurable); no answer at all is a no. Errors
  name the resolver actually asked (not the system one), stop at a definite
  "no such host", and list every attempt that failed.
- Releases also push the image to `ghcr.io/wushilin/tlsproxy_go_quick`
  (listed under the repository's Packages); v1.2.0 is copied there as is.
- Release binaries no longer include FreeBSD arm64 (build it with
  `GOOS=freebsd GOARCH=arm64 go build`).

## v1.2.0

Breaking:
- `cert = <dir>` is removed: terminate TLS with `cert = auto` (ACME) or
  `cert = local-ca` (import the CA that issued your certificate). A config
  that still names a directory fails to load and says so.
- Capture references are written in braces: `${1}`, `${2}`, `${host}` (or
  `${0}`). A bare `$1` fails to load, naming the fix.

New:
- Local CAs (`cert = local-ca[:caNNN]`, `ca_root`): generate or import CAs on
  the console's CAs page; one certificate per name, issued on first use and
  renewed in the background; per-CA `config.toml`; `cert_domains` globs.
- Several `[[listener]]` sections, each with its own rules and overrides,
  opened, moved and closed live; start and stop from the console.
- Speed limits per rule and per listener (`max_aggregated_speed`,
  `max_single_connection_speed`).
- Zero-copy splice(2) relaying for passed-through connections on Linux.
- Console under `/tlsproxy_quick/`: Listeners page with wizards, Flow log,
  CAs page, config validation tree and a config reference.
- `cert_validate_args`; listener names with spaces and punctuation.
- Docker image `docker.io/wushilin/tlsproxy_go_quick` (linux/amd64, arm64).

Improved:
- No locks shared between connections on the serving path; a mutex-profile
  test keeps it that way.
- TLS-ALPN-01 is answered only for rules that terminate TLS here.
- The test suite is self-contained (Pebble runs in-process, dependencies are
  vendored) and needs no network; combination tests cover every TLS mode,
  backend and PROXY protocol setting.

## v1.1.1

- Build release binaries for Windows, Linux and FreeBSD on amd64 and arm64;
  add native Windows CI tests alongside Linux and FreeBSD checks.
- Handle Windows directory syncing, Ctrl+C log flushing, admission executables
  and test binary filenames explicitly.
- Prevent stale password rewrites and logins surviving password changes.
- Cancel obsolete certificate jobs on reload and reject stale script decisions
  and certificate results; detect changes to all certificate files by content.
- Add optional Secure console cookies and safely handle revoked sessions.
- Count partial writes in traffic statistics, including the initial ClientHello.
- Add regression coverage for authentication, certificate updates and reloads.
