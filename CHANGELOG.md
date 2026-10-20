# Changelog

## v1.5.0 (unreleased)

Breaking:
- `proxy_protocol_from` is renamed `proxy_trust_source`, in `[global]` and
  `[[listener]]`. The old name is a load error that shows the line to write.
- The web console's settings move out of `config.toml` into a file of their
  own, given with `--console console.toml`; without it there is no console.
  The console can edit `config.toml` but never that file, so no edit made
  from it can change its password or take it off the network. A `[console]`
  section in `config.toml` is a load error saying so, and `listen` is now
  `bind` (also a load error that says so).
- New password hashes (`tlsproxy --hash-password`, and the plaintext
  console `password` the proxy replaces) are argon2id. Existing
  `pbkdf2-sha256$...` hashes keep working.

New:
- Service rules: a `[[host]]` rule with `service_rule` keys serves HTTP
  itself, inside the TLS connection it terminates, with no target and no
  second hop. `type=reverse_proxy; prefix=/api/; target=http://h:p` (or
  `https://`; `strip_prefix`, `force_host`, `tls_verify`) and
  `type=static_content; prefix=/assets/; base_dir=/folder` (the prefix
  stands for the folder; no listings, no hidden files except `.well-known`,
  no symlinks out of it). The longest prefix wins; none is 404. The target
  gets the client's own address in `X-Forwarded-For` / `X-Real-IP`, and
  `X-Forwarded-Proto: https`; what the client sent in those is replaced.
  Clients get HTTP/2 if they ask. Each request is routed by its Host with the
  running configuration (a reload applies to the next request; a Host another
  rule serves gets 421). The console's rule editor has *Serve it here*, with
  the service rules in one box, checked as you type.
- The console over TLS: with `cert` and `hostname` in `console.toml`, it is
  served like a rule with service rules, on the `[[listener]]` with exactly
  its `bind` and `port` (one more rule there, which `config.toml` can't
  override), or on a listener of its own. The console can't stop its rule or
  listener; deleting that listener moves it to one of its own, handing the
  open socket over. Every load of `config.toml` (start-up, reload, each check
  and save in the console) merges `console.toml` in, which is read again on
  every reload. A listener whose addresses another takes over (a rename, the
  console moving) keeps its socket open instead of reopening it.
- `[[basic_auth]]`: users (`username` with `password_hash` (argon2id or
  pbkdf2-sha256) or `password_plain`) that a service rule asks for with
  `basic_auth=<name>`. A matched password is remembered for 5 minutes.
- `cert = local-ca` serves clients without SNI (`pattern = NONE`, or `ANY`):
  a certificate for the IP address they connected to, or with IP addresses
  in `cert_domains`, one certificate for all of them (a `NONE` rule may add
  host names). An IP address sent as SNI is routed as no SNI and refused
  unless `cert_domains` lists it (it used to be a bad ClientHello).
  `cert = auto` on `NONE` stays an error, now pointing at `local-ca`.
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
