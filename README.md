# tlsproxy_go_quick

An **extremely simple SNI router for a gateway**. It listens on one port,
reads the hostname in the TLS ClientHello (SNI), picks a backend from
`config.toml`, and relays the still-encrypted bytes to it. By default it never
decrypts anything, so it needs no certificates or keys. Per host it can
instead **terminate TLS**, with certificates issued and renewed automatically
by Let's Encrypt over TLS-ALPN-01 (port 443 only, no port 80), or by a CA of
your own (generated here, or your organisation's, imported).

It is written in Go because a firewall such as **pfSense** has no C compiler
or linker, so anything that needs one cannot be built on it, while Go can:

- **Standard library plus one vendored package.** ACME uses the Go team's
  `golang.org/x/crypto/acme`, which itself needs only the standard library and
  is vendored in `vendor/` (100 KB), so `go build` still works offline.
- **No `cc` needed.** Go has its own linker. Build on the box with the `go`
  package, or cross-compile anywhere: `GOOS=freebsd GOARCH=amd64 go build`.
- **Static binary.** It doesn't link libc, so one build runs on any FreeBSD
  version (14, 15, 16...).

## Build and run

```sh
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=$(git describe --tags --always)" -o tlsproxy .
./tlsproxy --version                                   # tlsproxy v1.1.1
./tlsproxy config.toml                                 # run (logs to stderr)
./tlsproxy config.toml --console console.toml          # with the web console (its own file)
./tlsproxy config.toml --test foo.wushilin.net x.com   # dry run: show routing only
./tlsproxy config.toml --test ""                       # dry run for a client without SNI
go test ./...                                          # ~50 s; needs no network
```

### Docker

Each release is also an image on Docker Hub,
[`docker.io/wushilin/tlsproxy_go_quick`](https://hub.docker.com/r/wushilin/tlsproxy_go_quick),
and the same image on the GitHub Container Registry,
[`ghcr.io/wushilin/tlsproxy_go_quick`](https://github.com/wushilin/tlsproxy_go_quick/pkgs/container/tlsproxy_go_quick)
(use either in the commands below), tagged with the version (`v1.2.0`) and `latest`, for `linux/amd64` and
`linux/arm64`: the static binary on a distroless base (CA certificates,
nothing else), running as uid 65532, about 12 MB.

These steps were run as written against the published `v1.2.0` image; they
are updated for v1.5.0 (the console's own file).

**1. A folder for the configuration and one for state:**

```sh
mkdir -p /srv/tlsproxy/etc /srv/tlsproxy/data
```

**2. A configuration.** A small one to start from (the image also carries
the full reference as `/etc/tlsproxy/config.toml.example`):

```sh
cat > /srv/tlsproxy/etc/config.toml <<'CONFIG'
[[listener]]
name = https
port = 443

# Pass TLS for this name through to a backend, untouched.
[[host]]
listener = https
pattern = www.example.com
target_host = 192.0.2.10
target_port = 443

# Everything else is refused.
[[host]]
listener = https
pattern = ANY
action = deny
CONFIG

# The web console has a file of its own, which the console itself can't change.
cat > /srv/tlsproxy/etc/console.toml <<'CONSOLE'
[console]
bind = 0.0.0.0            # inside the container; publish it on the host's loopback only
port = 9443
password = change-me      # replaced by password_hash on first start
CONSOLE
```

**3. Let the container's user own both** (it writes the configuration:
the password in `console.toml` becomes a hash, and the console saves its
edits to `config.toml`; and its state: certificates, CAs):

```sh
sudo chown -R 65532:65532 /srv/tlsproxy
```

**4. Run it:**

```sh
docker run -d --name tlsproxy --restart unless-stopped \
  -p 443:443 -p 127.0.0.1:9443:9443 \
  -v /srv/tlsproxy/etc:/etc/tlsproxy:Z \
  -v /srv/tlsproxy/data:/var/lib/tlsproxy:Z \
  docker.io/wushilin/tlsproxy_go_quick:latest \
  /etc/tlsproxy/config.toml --console /etc/tlsproxy/console.toml
```

Without the last line the image runs `/etc/tlsproxy/config.toml` alone:
no console.

`:Z` lets the container use the folders on SELinux hosts (Fedora, RHEL and
the like); elsewhere it does nothing. Without it, SELinux refuses with
`open /etc/tlsproxy/config.toml: permission denied`.

**5. Check it:**

```sh
docker logs tlsproxy
#   listening on https 0.0.0.0:443 with 1 listener(s), 2 rules (...)
#   console: replaced the plaintext password in /etc/tlsproxy/console.toml with its hash
#   console: listening on http://0.0.0.0:9443/tlsproxy_quick/ (plain HTTP; password required)
```

The console is at `http://127.0.0.1:9443/` on the host (it redirects to
`/tlsproxy_quick/`); sign in with the password from step 2. A warning that
the console listens on `0.0.0.0` is expected inside a container: the port is
only published on the host's loopback.

**Everyday commands:**

```sh
# Where would these names go? (a dry run with the same config)
docker run --rm -v /srv/tlsproxy/etc:/etc/tlsproxy:Z docker.io/wushilin/tlsproxy_go_quick:latest \
  /etc/tlsproxy/config.toml --test www.example.com other.example
#   www.example.com -> 192.0.2.10:443 (rule line 10, literal: www.example.com)
#   other.example -> DENY (rule line 16, catch-all: ANY)

# A password_hash line for console.toml or [[basic_auth]], without the password in a file
echo 'my secret' | docker run --rm -i docker.io/wushilin/tlsproxy_go_quick:latest --hash-password

# Upgrade: the configuration and state stay in the folders
docker pull docker.io/wushilin/tlsproxy_go_quick:latest
docker rm -f tlsproxy   # then step 4 again
```

**Port 443 and other runtimes.** The container runs as a non-root user.
Docker lets containers bind ports below 1024 by default; rootless Podman and
Kubernetes don't. With Podman add
`--sysctl net.ipv4.ip_unprivileged_port_start=0` to step 4 (a rootless user
also can't publish host port 443 itself: use e.g. `-p 8443:443` and forward,
and `podman unshare chown -R 65532:65532 /srv/tlsproxy` in step 3); in
Kubernetes set the same sysctl in the pod's `securityContext`, or listen on a
high port inside and map 443 to it.

**Build it yourself:**
`docker build --build-arg VERSION=$(git describe --tags) -t tlsproxy .`
needs nothing but this repository (dependencies are vendored).

## Platforms

Release builds cover **Linux and Windows** on **amd64 and arm64**, and
**FreeBSD on amd64** (for FreeBSD on arm64, build it yourself:
`GOOS=freebsd GOARCH=arm64 go build`). Windows binaries end in `.exe`. The core proxy, TLS, ACME, console,
PROXY protocol and log rotation have no Linux-only dependency.

- Linux and FreeBSD support `SIGUSR1` to dump connection state and
  `SIGTERM`/`SIGINT` to flush logs before exiting. Windows supports Ctrl+C
  log flushing; it has no `SIGUSR1` dump.
- On Windows, `cert_validate_script` must name a native `.exe` or `.com`
  admission program. Unix uses executable mode bits and can run scripts with
  a shebang. The supplied shell examples require Unix tools.
- Certificate and config writes flush file contents on every platform.
  Directory metadata is additionally synced on Unix; Windows skips that
  unsupported step. Unix mode `0600` does not set Windows ACLs: use the
  account's directory permissions to protect keys and configuration.

GitHub Actions tests on Linux and Windows and in a FreeBSD VM, cross-builds
all five release binaries with `CGO_ENABLED=0`, builds the container image,
and for a tag, after all checks pass, pushes the image and attaches the
binaries with `SHA256SUMS` and `config.toml` to the release.

## Configuration

```toml
[[listener]]
name = https
bind = 0.0.0.0
port = 443

[[host]]
listener = https
pattern = *.wushilin.net
action = allow
target_host = ${1}.wushilin.internal.net
target_port = 443

[[host]]
listener = https
pattern = ANY
action = deny
```

- **The most specific rule wins, wherever it stands in the file.** A hostname
  that matches no rule is denied. `pattern` is a host name, optionally with
  `*` wildcards. There are no regular expressions. All matching ignores case:

  | | form | example | matches |
  |---|---|---|---|
  | 1 | `NONE` | `NONE` | only clients that send **no SNI** |
  | 1 | literal name | `vq.example.com` | exactly that name. Looked up, not scanned |
  | 2 | wildcard | `*.example.com` `api-*.example.com` `*.*.example.com` | a `*` **never crosses a dot**. As a whole label it is exactly one label: `*.example.com` matches `a.example.com`, not `a.b.example.com` and not `example.com`. Inside a label it is any run of characters, none included: `abc*.example.com` matches `abc1.example.com` and `abc.example.com`. The pattern with more literal characters wins; then file order |
  | 3 | `ANY` | `ANY` | everything, with or without SNI; always last |

  So a literal `deny` beats a wildcard `allow`, a literal `allow` beats a
  broader `deny`, and an `ANY` in the middle of the file shadows nothing.
  There is no `**` and no "any depth": write one rule per depth you mean
  (`example.com`, `*.example.com`, `*.*.example.com`), which also means one
  more label never slips through an allowlist. There is no "a or b" either:
  one rule per name. The same pattern twice, two `ANY` or two `NONE` rules are
  start-up errors, since only one could ever match. If the file reads
  differently top to bottom than it is evaluated, one log line says which rules
  win over which. `--test` and the console's *Test routing* show the winning
  rule and its kind.
- **Coming from a version with regular expressions** (before v1.0.0): a regex
  pattern is now a load error that names the line and says what to write
  instead. `(.*)\.example\.com` becomes `*.example.com` (one label only),
  `(www|blog)\.example\.com` becomes two rules, `node(\d+)\.example\.com`
  becomes `node*.example.com`, `.*` becomes `ANY` (`.*` is still accepted as a
  spelling of `ANY`), `^$` becomes `NONE`. Escaped dots and `^...$` around a
  name are tolerated, so `vq\.example\.com` and `^vq.example.com$` keep working.
- `target_host` can use what each `*` matched: `${1}` is the first `*` from the
  left, `${2}` the second, and so on; `${host}` (or `${0}`) is the whole SNI.
  References are always in braces, so `${1}hello` is exact; a bare `$1`, an
  unknown `${...}` or a `*` the pattern doesn't have is rejected at load time.
- The port is always separate: `target_host` is a name or an IP address (IPv6
  without brackets) and the port goes in `target_port`. `target_host =
  10.0.0.1:8080` is rejected at load time.
- An SNI that is an IP address is refused (RFC 6066 forbids it), so a
  `target_host = ${host}` rule cannot be pointed at arbitrary addresses. An `ANY` rule
  whose target follows the client (`pattern = ANY` with `target_host = ${host}`)
  still connects to any *name* a client sends, internal ones included; that is
  logged as a warning at start-up.
- `action` is `allow` (the default) or `deny`. A denied client gets a TLS
  `access_denied` alert. An allow rule needs `target_port`: there is no
  default port.
- Every rule names its `listener`, even when there is only one.
- `pattern = NONE` (any letter case) is explicit: it matches only clients that
  send no SNI, for example to send them to a default target; its `target_host`
  must be a literal. Without such a rule only `ANY` takes them; a wildcard
  never matches a missing SNI. Hosts literally named `none` or `any` are
  matched with `^none$` / `^any$`. A client that sends an IP address as SNI
  (RFC 6066 forbids it) is treated as one without SNI.
- Values need no quotes: everything after the `=` up to the end of the line (or
  a ` #` comment) is the value, so `pattern = *.example.com` works as it is. `"double-quoted"` (with `\"`, `\\`,
  `\t`, `\n`; any other backslash is kept, so `"\."` works) and
  `'single-quoted'` (nothing is special) are there for values that start with a
  quote, contain ` #`, or need leading or trailing spaces.

Optional `[global]` settings; [`config.toml`](config.toml) lists every one
with its default, and a test keeps that file in step with the code:

| key                    | default | meaning                                                              |
|------------------------|---------|----------------------------------------------------------------------|
| `handshake_timeout`    | 10      | seconds to receive the whole ClientHello (a slow trickle can't extend it) |
| `connect_timeout`      | 10      | seconds to resolve and connect to the target                         |
| `idle_timeout`         | 600     | close after N seconds with no traffic in either direction (0 = never); also reaps half-open connections |
| `half_close_timeout`   | 30      | after one side closes, the other side gets N seconds to finish (0 = unlimited) |
| `max_connections`      | 1024    | further connections are rejected; goroutines ≤ 2 × this              |
| `proxy_trust_source`  | (none)  | who may put a PROXY protocol header in front of a connection: IP addresses or networks (`10.0.0.0/8`), `;`-separated. See [The client's address](#the-clients-address-proxy-protocol) |
| `max_handshakes_per_ip` | 64     | connections from one source (an IPv4 address, or an IPv6 /64) that have not sent their ClientHello yet. Further ones are closed at once, so one address cannot hold every slot with silent sockets for `handshake_timeout` each. Established connections don't count. 0 = unlimited |
| `buffer_size`          | 65536   | the most bytes moved per read/write or splice step, in each direction. Clamped to 4 KiB..128 KiB (4096..131072), with a warning in the log. A spliced connection uses it as its kernel pipe size and holds no buffer; any other (terminated TLS, non-Linux, or splice unavailable) holds two pooled buffers of this size |
| `buffer_pool_max_idle` | 2 × max_connections | capacity of the pool's channel                           |
| `allow_cache_size`     | 4096    | LRU cache of allowed SNI → target decisions (0 = off)                |
| `deny_cache_size`      | 4096    | separate LRU cache of denied SNIs (0 = off)                          |
| `reload_interval`      | 5       | check the config file every N seconds and apply changes; minimum 5, 0 = never |
| `stats_interval`       | 60      | log a one-line state summary every N seconds; 0 = never              |
| `short_read_delay_us`  | 0       | pause N µs after a short read so data batches up. Measured in Go: a few percent more throughput at best, +37 µs (50) or +210 µs (200) per round trip, so leave it off unless your box shows otherwise |
| `splice`               | true    | Linux only: relay passed-through connections with `splice(2)`, see [Zero-copy relaying](#zero-copy-relaying-linux) |
| `http_to_https_redirect` | false | also listen on port 80 and redirect every plain HTTP request to `https://`, see [HTTP to HTTPS redirect](#http-to-https-redirect) |
| `remember_nonce` | true | refuse a connection that is this proxy's own, come back to it: see [Loop detection](#loop-detection-remember_nonce) |

The legacy keys `io_model` and `worker_threads` are accepted and ignored (with
a log line), so older config files keep loading.
All options, by section, with a complete example in
[`samples/12-everything.toml`](samples/12-everything.toml) (a test fails if an
option is missing from it, from `config.toml` or from this README):

| section | options |
|---|---|
| `[global]` | `handshake_timeout` `connect_timeout` `idle_timeout` `half_close_timeout` · `max_connections` `max_handshakes_per_ip` `proxy_trust_source` `buffer_size` `buffer_pool_max_idle` `short_read_delay_us` `splice` · `http_to_https_redirect` `remember_nonce` · `allow_cache_size` `deny_cache_size` · `reload_interval` `stats_interval` · `cert_path` `ca_root` `expiry_threshold_days` `acme_agree_tos` `acme_email` `acme_directory` `acme_ca_file` `public_ip_address` `dns_resolvers` · ignored for compatibility: `io_model` `worker_threads` |
| `[[listener]]` | `name` `bind` `port` · `proxy_trust_source` `max_connections` `handshake_timeout` `idle_timeout` `half_close_timeout` `max_aggregated_speed` `max_single_connection_speed` |
| `[[host]]` | `listener` · `pattern` `action` `target_host` `target_port` · `cert` `cert_domains` `cert_validate_script` `cert_validate_args` `upstream_tls` `upstream_tls_verify` `upstream_sni` `proxy` `proxy_version` · `max_aggregated_speed` `max_single_connection_speed` · `service_rule1`, ... (`type` `prefix` `target` `strip_prefix` `force_host` `tls_verify` `base_dir` `basic_auth`) |
| `[[basic_auth]]` | `name` · `user1`, `user2`, ... (`username` with `password_hash` or `password_plain`) |
| `[logging]` | `stdout` `stderr` `max_size` `max_keep` `compress_after` |
| `[console]` (in `console.toml`) | `bind` `port` `hostname` `cert` · `password` `password_hash` · `hostnames` `secure_cookie` |

`proxy_trust_source` was called `proxy_protocol_from` before v1.5.0; the old
name is a load error that shows the line to write instead.

Samples, each with its expected routing checked by `go test`:

| file | shows |
|---|---|
| [`01-basic`](samples/01-basic.toml) | map `*.wushilin.net` to internal names with `${1}` |
| [`02-home-lab`](samples/02-home-lab.toml) | several internal services behind one public IP; a literal deny that beats a broader allow |
| [`03-egress-allowlist`](samples/03-egress-allowlist.toml) | outbound allowlist, one rule per name and depth, connecting to the real host with `${host}` |
| [`04-blocklist`](samples/04-blocklist.toml) | pass everything except blocked names |
| [`05-default-backend`](samples/05-default-backend.toml) | specific routes, then `ANY` as the default backend |
| [`06-multi-capture-rewrite`](samples/06-multi-capture-rewrite.toml) | several `*` in one pattern (`${1}`, `${2}`), a `*` inside a label |
| [`07-ipv6-and-tuning`](samples/07-ipv6-and-tuning.toml) | IPv6 listener, timeouts, limits, buffers, quoted values |
| [`08-no-sni`](samples/08-no-sni.toml) | `pattern = NONE` for clients without SNI |
| [`09-tls-termination`](samples/09-tls-termination.toml) | `cert = auto`, `cert_domains`, plaintext and TLS upstreams, pass-through side by side |
| [`10-logging`](samples/10-logging.toml) | rotating, compressed log files |
| [`11-web-console`](samples/11-web-console.toml) | the console on port 443 over TLS, sharing the listener ([its `console.toml`](samples/11-web-console.console.toml)) |
| [`12-everything`](samples/12-everything.toml) | every option, annotated |
| [`13-rule-precedence`](samples/13-rule-precedence.toml) | literal, wildcard and `ANY` rules written broadest first, and which one wins |
| [`14-listeners`](samples/14-listeners.toml) | several listeners (a public port and a VPN-only port), each with its own rules and overrides |

## Listeners

Every port the proxy listens on is a `[[listener]]` section, and a file needs
at least one, and every rule names the listener it belongs to. For more
ports, each with its own rules:

```toml
[[listener]]
name = public
port = 443

[[listener]]
name = lab
bind = 10.11.12.212
port = 9092
idle_timeout = 3600                # overrides [global] on this listener
max_aggregated_speed = 200Mbit     # all connections on this listener together

[[host]]
listener = public
pattern = www.example.com
target_host = 192.168.1.30
target_port = 443

[[host]]
listener = lab
pattern = kafka.example.com
target_host = 10.11.12.50
target_port = 9092
```

| `[[listener]]` | default | meaning |
|---|---|---|
| `name` | (required) | up to 64 letters, digits, spaces and `-` `_` `@` `#` `~` `(` `)` `[` `]` `<` `>` `"` `'`, no space at either end; unique, ignoring case. What `listener =` in a rule refers to. Quote it as a TOML string when it has spaces or quotes: `name = "Kafka (EU)"`, `listener = "Kafka (EU)"` (the console does this for you) |
| `bind` | 0.0.0.0 | listen address: `0.0.0.0` all IPv4, `::` all IPv6 and IPv4, or specific addresses, several separated by `;` |
| `port` | (required) | |
| `proxy_trust_source` `handshake_timeout` `idle_timeout` `half_close_timeout` | `[global]` | the same settings, for this listener only |
| `max_connections` | (none) | a cap for this listener, on top of the global `max_connections` |
| `max_aggregated_speed` `max_single_connection_speed` | unlimited | as for a rule (see [Speed limits](#speed-limits)), for every connection on this listener; they apply on top of each rule's own |

- `bind` and `port` exist only in `[[listener]]`. In `[global]` they are a
  load error; the message shows the `[[listener]]` to write instead. (Before
  v1.4.1 they made an implicit listener named `default`.)
- Each listener has its own rules, so the same pattern can appear on several
  listeners, and a name that matches nothing *on that listener* is denied.
- Every rule must name its `listener`, with one listener or many; a rule
  without one is a load error.
- Two listeners cannot share a port on the same (or a wildcard) address.
- **Listeners follow hot reload.** A new listener opens its port, a changed
  `bind` or `port` moves it, and a removed one closes its port, all without a
  restart; connections already open carry on. If a port cannot be opened (in
  use, say), at start-up or on a reload, that is logged and shown in the
  console (where Start retries it), and the other listeners keep working.
  The proxy refuses to start only when no listener can open its port.
- `--test` and the console's routing tests answer for every listener.

### HTTP to HTTPS redirect

```toml
[global]
http_to_https_redirect = true      # default false
```

adds one more listener, `http-to-https-redirect`, on port 80 of every address
the other listeners bind (a wildcard such as `0.0.0.0` covers the specific
addresses of its family). It answers every plain HTTP request with a redirect
to the same host, path and query on `https://` (no port, so 443):

- `301 Moved Permanently` for GET and HEAD, `308 Permanent Redirect` for the
  other methods, so a POST stays a POST.
- It does not look at the rules: every name is redirected, and the rules of
  the HTTPS listener refuse the ones they don't serve. The port in `Host` is
  dropped; a request without a usable `Host` gets `400`.
- Keep-alive works. A request with a body is answered without reading the
  body (a 10 GB upload gets its `308` straight after the headers), then the
  connection is closed; at most 256 KiB / 2 s of what is still arriving is
  read and dropped first, so the client gets the response instead of a reset.
- Headers are capped at 8 KiB (`431`). The first request must arrive within
  `handshake_timeout`, later ones within `idle_timeout`. `max_connections`,
  `max_handshakes_per_ip` and `proxy_trust_source` apply as on the other
  listeners.
- The name `http-to-https-redirect` is reserved: no `[[listener]]` and no
  rule may use it. A listener of your own on port 80 at an address the
  redirect also binds is a load error.
- It follows hot reload: setting it opens port 80, clearing it closes the
  port. In the console it is a listener card with Stop/Start and its open
  connections, but no Edit, Delete or rules. Each connection is in the flow
  log, and each request is a line in the log:
  `[#12] redirect GET http://www.example.com/a -> https://www.example.com/a (301)`.
- It plays no part in ACME, which only uses TLS-ALPN-01 on port 443.
- With Docker, publish the port too: `-p 80:80`.

### Loop detection (`remember_nonce`)

A rule can send a connection back to this proxy: `pattern = ANY` with
`target_host = ${host}` and a client asking for a name that resolves to this
machine (or to 127.0.0.1), or a target that is another of its listeners.
Each hop would open the next until `max_connections` runs out. With
`remember_nonce = true` (the default) the proxy remembers a hash of every
ClientHello it passes through, and refuses one that arrives again:

- The whole ClientHello message is hashed, so no field is trusted: a refused
  connection sent byte for byte the hello the proxy forwarded moments
  earlier. Real clients pick a fresh random for every connection, so they
  never do; a replayed hello is refused too.
- The hash is Go's `hash/maphash` (64-bit, seeded randomly at each start),
  several times cheaper than SHA-256. An accidental match is about 10⁻¹³ per
  connection, and without the seed nobody can aim for one.
- It is kept 10 seconds, in a fixed table of 1M entries (8 MiB) where a newer
  hello can take an older one's place: one atomic write to remember, one
  atomic read to check, nothing to clean up, no lock.
- The looped connection is refused with a TLS `access_denied` alert, which
  travels back to the client; the log and the flow log say `connection
  loop`.
- Only passed-through connections are covered. A terminated connection
  starts a new TLS session upstream; point those rules at fixed targets.

## IPv6

- **Several addresses.** `bind = 192.0.2.1; 2001:db8::1` listens on exactly
  those, each for its own family.
- **Clients.** `bind = ::` listens on IPv6 **and** IPv4 with one socket;
  `0.0.0.0`, the default, is IPv4 only (enforced: left to itself Go would make
  it dual-stack); a specific address of either family
  works too, and `[::]` is accepted as a spelling of `::`. Client addresses are
  logged as `[2001:db8::5]:49943`, IPv4 clients of a dual-stack listener as
  plain `10.0.0.5:49943`.
- **Targets.** `target_host` may be an IPv6 address, written without brackets
  (`target_host = 2001:db8::10`, or `fe80::1%em0` with its zone for a
  link-local address); logs show it as `[2001:db8::10]:443`. A host name with
  both A and AAAA records is dialled with Happy Eyeballs: the family the
  resolver prefers first, the other 0.3 s later (or at once if the first
  fails), whichever connects first wins, all within `connect_timeout`.
  Resolved addresses are cached for 5 seconds, so a busy name costs the
  resolver one lookup every few seconds, not one per connection.
- **Certificates.** Let's Encrypt validates over IPv6 when a name has an AAAA
  record. The DNS pre-check therefore requires **every** address of the name, A
  and AAAA, to be in `public_ip_address`; a stray AAAA record is reported
  instead of costing a failed validation. With an IPv6 address in
  `public_ip_address` and an IPv4-only `bind`, a warning tells you the CA could
  not reach the proxy. `dns_resolvers` may be IPv6 (`2606:4700:4700::1111`, or
  `[2606:4700:4700::1111]:53` with a port).
- The console's `bind` (in `console.toml`) follows the same rules, and its
  Host check accepts IPv6 literals.

## Serving HTTP here (service rules)

A rule can answer HTTP requests itself instead of connecting to a target:
give it `service_rule` keys. The proxy terminates TLS as for any `cert`
rule and hands the connection straight to an HTTP server inside the
process, with no second hop, no extra port and no PROXY header to set up:
the client's address is the connection's own.

```toml
[[host]]
listener = https
pattern = www.example.com
cert = auto
service_rule1 = type=reverse_proxy; prefix=/; target=http://127.0.0.1:8080
service_rule2 = type=reverse_proxy; prefix=/api/; target=http://127.0.0.1:7882; strip_prefix=true; basic_auth=team
service_rule3 = type=static_content; prefix=/assets/; base_dir=/opt/www/www.example.com/assets

[[basic_auth]]
name = team
user1 = username=jack; password_hash=$argon2id$v=19$m=65536,t=3,p=4$...
user2 = username=jill; password_plain=open sesame
```

- **Keys.** Any key starting `service_rule` is one (`service_rule1`,
  `service_rule_api`, ...). A key given twice keeps its last value, with a
  warning. A rule with service rules needs `cert = auto` or `local-ca`
  (the proxy has to decrypt the requests) and takes no `target_host`,
  `target_port`, `upstream_*` or `proxy`; speed limits apply as usual.
- **Options**, separated by `;` (a trailing `;` is fine; an unknown option is
  a load error):
  - `type=reverse_proxy`: `target=http://host:port` or `https://host:port`
    (no path), `strip_prefix=true` sends `/api/x` as `/x`,
    `force_host=name` replaces the Host sent on (default: the client's),
    `tls_verify=false` skips checking an `https://` target's certificate.
  - `type=static_content`: `base_dir=/folder`. The prefix stands for the
    folder, so `/assets/a.css` is `base_dir/a.css` (as nginx's `alias`); it
    ends in `/`. `GET` and `HEAD` only, `index.html` for a folder, never a
    listing, nothing hidden (a path part starting with `.`) except
    `.well-known` at its top, nothing through a symlink that leads out
    (`os.Root`). A `base_dir` that can't be opened answers `503`.
  - `basic_auth=<name>` on either type asks for a user of that
    `[[basic_auth]]` section; the `Authorization` header is not passed on.
- **Matching.** The longest `prefix` that matches the path serves the
  request, whatever its key is called; the same prefix twice is a load
  error, and a path no prefix matches gets `404`. For a prefix ending in
  `/`, the bare folder (`/api`) is redirected (`301`) to `/api/`, unless a
  prefix at least that long takes it.
- **Forwarding headers are set, never trusted.** The target gets
  `X-Forwarded-For` and `X-Real-IP` (the client's address: the TCP peer's,
  or what a trusted PROXY header in front of the listener said),
  `X-Forwarded-Proto: https` and `X-Forwarded-Host`. Whatever the client
  sent in those, or in `Forwarded`, is replaced.
- **HTTP/2** is offered to clients that ask for it; targets are spoken to in
  HTTP/1.1 (or HTTP/2 over `https://` when the target offers it). WebSocket
  upgrades and streamed responses pass through. An unreachable target gives
  `502`.
- **One connection, one rule.** Each request is routed again by its Host,
  with the configuration running at that moment: a reload applies to the
  next request even on a connection that is already open. A request for a
  name another rule serves (a browser reusing an HTTP/2 connection for a
  second name its certificate covers) is answered `421 Misdirected
  Request`, and the browser opens a connection of its own for it.
- **Logs.** Every request is logged on the connection's `[#id]`, with the
  service rule that served it, status, size and time.
- **`[[basic_auth]]`**: `name` and any number of keys starting `user`, each
  `username=<name>; password_hash=<hash>` or `username=<name>;
  password_plain=<password>` (a plain password can't contain `;`).
  `tlsproxy --hash-password` prints an argon2id hash; argon2id hashes from
  other tools and the older `pbkdf2-sha256` format work too. A browser
  sends the password with every request, so one that matched is remembered
  (in memory) for 5 minutes, and at most two hashes are worked out at once.
  A second section with the same name replaces the first, with a warning.
- **In the console**, the rule editor's *Serve it here* takes the service
  rules in one box, one per line, checked as you type, and saves them as
  `service_rule1`, `service_rule2`, ... `[[basic_auth]]` is edited in the
  Config file tab.

## The client's address (PROXY protocol)

A backend behind the proxy sees every connection coming from the proxy. The
ClientHello cannot carry the client's address: TLS covers every byte of the
handshake, so a hello changed in transit fails. The PROXY protocol solves it
without touching TLS: a small header is sent as the very first bytes of the
upstream connection, and the untouched stream follows.

```toml
[[host]]
listener = https
pattern = www.example.com          # passed through: header, then the client's ClientHello as it was
target_host = 192.168.1.30
target_port = 443
proxy = true                       # default false
proxy_version = 2                  # default 2 (binary); 1 is the text form

[[host]]
listener = https
pattern = api.example.com          # terminated: header, then our upstream TLS handshake (or plaintext)
cert = auto
upstream_tls = false
target_host = 192.168.1.31
target_port = 8080
proxy = true
```

- The header states the client's address and port, and the address and port it
  connected to. IPv4 and IPv6; if the two differ in family, the IPv4 one is
  written in its IPv4-mapped form. The `connected` log line says `PROXY v2
  header sent`.
- **The target must expect it**, on that port: nginx `listen 443 ssl
  proxy_protocol;` with `set_real_ip_from <this proxy>;`, HAProxy
  `accept-proxy`, Apache `mod_remoteip`, Traefik, Envoy, Caddy. A port that
  expects the header rejects connections without it and the reverse, so it is
  a per-rule setting. Your own server can accept both by looking at the first
  bytes: the v2 signature (`\r\n\r\n\0\r\nQUIT\n`) and `PROXY ` cannot begin a
  TLS or HTTP stream. It should only do so for connections from this proxy.
- **Incoming headers** (a load balancer in front of this proxy) are accepted
  only from the peers in `proxy_trust_source`, v1 or v2, detected
  automatically; a listed peer may also connect without one. The stated source
  then becomes the address that is logged, counted by `max_handshakes_per_ip`
  and passed on to targets, and the stated destination is passed on as well.
  From anybody else a header is never looked for (it is simply a bad
  ClientHello): otherwise any client could choose the address you log, evade
  the per-source limit, and lie to your backends.

## Speed limits

Any allow rule, passed through or terminated, can cap its bandwidth:

```toml
[[host]]
listener = https
pattern = *.downloads.example.com
target_host = 10.0.0.20
target_port = 443
max_aggregated_speed = 1Gbit             # all connections of this rule together
max_single_connection_speed = 15MiB/s    # each connection
```

| per rule | default | meaning |
|---|---|---|
| `max_aggregated_speed` | unlimited | shared by every connection this rule matches, whatever name it asked for: a wildcard rule has one budget for all its names |
| `max_single_connection_speed` | unlimited | for each connection on its own |

- When both are set, both apply: no connection exceeds its own cap, and all
  of them together never exceed the aggregate.
- Each limit applies to each direction separately (client to target and
  target to client), like a full-duplex link.
- Units: `B`, `KB`, `MB`, `GB` (1000-based), `KiB`, `MiB`, `GiB` (1024-based),
  or bit rates `bit`, `Kbit`, `Mbit`, `Gbit` (also `bps`, `Kbps`, `Mbps`,
  `Gbps`). `/s` is optional, so `512B/s`, `14KiB/s`, `100Mbit` and `1GiB/s`
  all work. The short forms are case sensitive: `Mb` is megabits, `MB`
  megabytes.
- On a terminated connection the limit counts the decrypted bytes. The
  ClientHello is forwarded without being counted against a limit.
- Limits keep the [splice](#zero-copy-relaying-linux) data path: the proxy
  reserves bandwidth before forwarding each chunk, and a limited direction
  moves smaller chunks (about 20 a second, at least 256 bytes) to keep the
  rate smooth.
- On a reload, a rule whose `pattern` and `max_aggregated_speed` are unchanged
  keeps its shared budget, so connections from before and after the reload
  share it. A changed rate starts a new budget; connections already open
  keep the one they started with.
- The `connected` log line notes the limits that apply.

## TLS termination and automatic certificates

Without `cert`, a rule passes TLS through untouched (the backend keeps its own
certificate). With `cert`, the proxy terminates TLS for that rule:

```toml
[global]
cert_path = /var/db/tlsproxy/certs
acme_agree_tos = true                 # required for cert = auto
acme_email = admin@example.com        # optional
public_ip_address = 203.0.113.7       # only ask the CA for names that point here

[[host]]
listener = https
pattern = nas.example.com             # literal pattern: the name comes from it
cert = auto
target_host = 192.168.1.10
target_port = 5001
upstream_tls_verify = false           # the NAS has a self-signed certificate
proxy = true                          # send the original connection addresses first
proxy_version = 2                     # v2 (default), or 1

[[host]]
listener = https
pattern = *.example.com               # wildcard: list the exact names
cert = auto
cert_domains = www.example.com, blog.example.com
target_host = 192.168.1.30
target_port = 8080
upstream_tls = false                  # plain HTTP backend

[[host]]
listener = https
pattern = intranet.example.com
cert = local-ca                       # your own CA (ca001 in ca_root, made on the CAs page)
target_host = 192.168.1.40
target_port = 443
```

| per rule | default | meaning |
|---|---|---|
| `cert` | (none) | `auto`: issue and renew via ACME. `local-ca` or `local-ca:ca002`: your own CA issues a certificate per name, or per IP address for clients without SNI (see [Your own CA](#your-own-ca-cert--local-ca)); the CA must exist (made on the CAs page). None: pass through |
| `cert_domains` | from a literal pattern | exact names to issue, separated by `,` or `;`. Required when `pattern` has a `*` or is `ANY`, unless a `cert_validate_script` decides (start-up error otherwise). Each must match the pattern. No wildcards: TLS-ALPN-01 can't issue them |
| `cert_validate_script` | (none) | decides about names that match the pattern but are not in `cert_domains`; see below. Must exist and be executable at start-up and on reload |
| `cert_validate_args` | `["${host}"]` | the script's arguments, a TOML array of strings. Each is fixed text with `${1}`, `${2}`, ... and `${host}` filled in as in `target_host`, e.g. `["--customer", "aaa-${1}", "${host}"]`. One argument stays one argument, spaces and all |
| `upstream_tls` | true | speak TLS to the target; `false` = plaintext |
| `upstream_tls_verify` | true | verify the target's certificate against the system roots |
| `upstream_sni` | the client's SNI | name sent to the target as SNI, and the name its certificate is verified against. The default passes the client's name through, so a target that routes or selects certificates by SNI works even when `target_host` is an IP address |
| `proxy` | false | for **any** allow rule, passed through or terminated: tell the target the client's address with a PROXY protocol header. See [The client's address](#the-clients-address-proxy-protocol) |
| `proxy_version` | 2 | PROXY protocol version, `1` or `2`; only valid when `proxy = true` |

| `[global]` | default | meaning |
|---|---|---|
| `cert_path` | ./certs | `<cert_path>/<name>/cert.pem`, `key.pem` (mode 0600); account key in `_account/` |
| `expiry_threshold_days` | 15 | renew this long before expiry, or when a third of the lifetime is left if that is later (short-lived certificates) |
| `acme_agree_tos` | false | must be `true` before anything is issued |
| `acme_email` | (none) | contact for the ACME account |
| `acme_directory` | Let's Encrypt production | use `https://acme-staging-v02.api.letsencrypt.org/directory` while testing |
| `acme_ca_file` | (none) | extra root for the ACME server's own HTTPS (private CA, Pebble) |
| `public_ip_address` | (none) | `;`-separated, IPv4 and IPv6. A name is only sent to the CA if **all** its public addresses (A and AAAA) are among these; without it the check is skipped (with a warning) |
| `dns_resolvers` | (required with `cert = auto` and `public_ip_address`) | public DNS servers for that check, IP or IP:port: three attempts, each the next server in turn and given 3 s (not configurable); no answer is a no. E.g. `1.1.1.1; 8.8.8.8; 2606:4700:4700::1111`; deliberately not the local one, which may return LAN addresses |

### Your own CA (`cert = local-ca`)

For names a public CA can't or shouldn't issue (internal hosts, no public
DNS, wildcards), the proxy runs CAs of its own, or uses your organisation's:

```toml
[global]
ca_root = /var/db/tlsproxy/ca          # default ./ca

[[host]]
listener = https
pattern = *.lab.internal
cert = local-ca:ca002                  # plain "local-ca" is ca001
cert_domains = *.dev.lab.internal, git.lab.internal   # optional: names or globs; others are refused
target_host = 10.0.0.30
target_port = 443
upstream_tls = false
```

```
<ca_root>/ca002/ca_cert.pem             the CA (then its issuers, for an intermediate)
<ca_root>/ca002/ca_key.pem              its private key
<ca_root>/ca002/config.toml             its settings (below)
<ca_root>/ca002/git.lab.internal/       one folder per name it issued: cert.pem, key.pem
<ca_root>/ca002/ip_203.0.113.5/         the same for clients without a host name (below)
<ca_root>/ca002/_archive/<name>-<time>  certificates it did not issue, moved aside
```

- **Clients without SNI** (they connect by IP address: `https://203.0.113.5/`)
  get a certificate too, with `pattern = NONE` (or `ANY`). Only `local-ca`
  can do this; `cert = auto` on a `NONE` rule is a load error, since ACME
  issues for host names.

  ```toml
  [[host]]
  listener = https
  pattern = NONE
  cert = local-ca
  cert_domains = 203.0.113.5, 198.51.100.7, gw.lab.internal   # optional
  upstream_tls = false
  target_host = 127.0.0.1
  target_port = 1081
  ```

  - Without `cert_domains`: one certificate for the address the client
    connected to (the destination in a PROXY header, if one came in). With
    two addresses on the box, a client gets the one it used.
  - With IP addresses in `cert_domains`: **one** certificate holding all of
    them, plus a `NONE` rule's host names, whichever address the client
    used. That is what works behind NAT, where the box only sees its private
    address and can't tell which public one the client typed. Every client
    sees the whole list in the certificate.
  - IP addresses in `cert_domains` are only for `NONE` and `ANY` rules. On
    an `ANY` rule they cover clients without SNI; its host names and globs
    keep limiting the names that do send one (a list of addresses alone
    issues for no host name).
  - RFC 6066 forbids an IP address as SNI, but some clients send one. It is
    routed as no SNI (so `target_host = ${host}` can't be pointed at an
    address), and refused unless `cert_domains` lists it.
  - An IPv6 address's folder has `-` for `:` (`ip_2001-db8--5`), which
    Windows can't have in a file name; several addresses and names are
    joined by `+`.

- **Certificates are issued on demand**: the first time a client asks for a
  name, in well under a millisecond, so even that client gets the real one.
  One name per certificate (for clients without SNI, see below), 90 days by default. They are kept in the CA's
  folder and used again after a restart.
- **Renewal runs in the background**, at start and every 6 hours: each CA's
  own certificate when due, and every certificate in its folder that is due
  (`renew_before_days`, by default when a third of its lifetime is left)
  and that a rule still issues for, so a name nobody asked for in a while
  doesn't expire. A handshake that finds its certificate due renews it too.
  Names no rule issues for any more are left to expire. A handshake finds its certificate in memory (a lock-free table),
  never by searching files.
- **Only what the CA issued is used.** A certificate in a name's folder is
  checked first: it must be signed by this CA's key, for exactly that name,
  and readable. Anything else is moved to `_archive/<name>-<UTC time>`, a new
  one is issued, and archived folders are deleted after 14 days.
- **CAs** are made on the console's **CAs** page only (generate one, or
  import yours: a CA certificate with its chain and its private key); a rule
  naming a CA that does not exist is a config error. A self-signed CA is renewed before it
  expires with the same key and subject, so certificates it issued stay
  valid; an imported intermediate is reported as it nears expiry (renew it
  where it came from and import again). Certificates from an intermediate are
  sent with its chain, without the root, so clients that trust your
  organisation's root accept them. A CA is deleted only when no rule uses it
  (moved to `<ca_root>/_archive`, removed after 14 days); its id is not
  reused.
- **Each CA's `config.toml`** is written when the CA is made, read again
  whenever it changes (a broken edit keeps the previous settings, logged and
  shown on the CAs page), and editable there with *Settings*:

  ```toml
  [ca]                    # how the CA was made: fixed, can't be changed
  common_name = "Home lab CA"
  organization = tlsproxy
  key_algorithm = ecdsa   # ecdsa, rsa or ed25519
  key_bits = 256          # ecdsa 256/384/521, rsa 2048/3072/4096
  hash_algorithm = sha256 # sha256, sha384, sha512 (its own renewals)
  validity_days = 3650

  [certificates]          # what it issues: editable
  key_algorithm = ecdsa
  key_bits = 256
  hash_algorithm = sha256 # the CA's signature on them
  validity_days = 90
  renew_before_days = 0   # 0 = when a third of the lifetime is left
  key_usage = digitalSignature        # add keyEncipherment for RSA keys and old clients
  ext_key_usage = serverAuth          # serverAuth, clientAuth
  organization = ""                   # subject fields; the common name is always the name
  organizational_unit = ""
  country = ""
  province = ""
  locality = ""
  ```

  `[ca]` is set by *Generate* (common name, organisation, key, hash,
  validity) and checked against the CA certificate on every read: an edit
  that changes it is refused, since a CA's key or name can't change without
  breaking everything it issued. Renewal reuses what the CA was made with.
  `[certificates]` changes apply to new certificates and renewals. ECDSA and
  Ed25519 keys take well under a millisecond to make; RSA keys take far
  longer (about 0.1 s for 2048 bits, seconds for 4096), and the first
  handshake for a new name waits for its key: prefer ECDSA unless clients
  need RSA.
- **No races.** A current certificate is found without a lock. Loading one
  from disk, issuing, renewing, archiving and writing its files hold that
  name's lock, so racing handshakes for a new name get one certificate
  between them. Making, renewing or deleting a CA and saving its settings
  hold that CA's lock; choosing a new CA's id holds the `ca_root`'s.
- **Clients must trust the CA**: download its certificate from the CAs page
  (the private key is never offered) and add it to their trust store.
- **`cert_domains` says which names get a certificate**: host names or globs
  written like patterns (`*.dev.abc.com, *.prod.abc.com, *.abc.com`; a `*`
  never crosses a dot). Any other name is refused: no certificate, no
  placeholder, the target is not contacted, and the flow log says why.
  Without it, every name the rule matches gets one, at most 10000 per CA
  (beyond that, names are refused and it is logged).

**Names decided by a script.** When the names are not known in advance
(customer subdomains, say), let a script decide per name:

```toml
[[host]]
listener = https
pattern = *.customers.example.com
cert = auto
cert_domains = www.customers.example.com        # optional: always issued, never put to the script
cert_validate_script = /usr/local/etc/tlsproxy/domains.sh
# cert_validate_args = ["${host}"]              # the default: the name alone
target_host = 192.168.1.50
target_port = 443
```

```sh
#!/bin/sh
# domains.sh <name>: exit 0 = issue a certificate for it, anything else = don't
grep -qxF "$1" /usr/local/etc/tlsproxy/customers.txt
```

A complete example is [`samples/s3-bucket-admission.sh`](samples/s3-bucket-admission.sh):
for an S3-compatible server with virtual-hosted buckets, `<bucket>.s3.example.com`
gets a certificate only if the bucket exists. It lists the buckets with a
SigV4-signed request, parses the answer as XML (`xmllint`, not `grep`), keeps
the secret key out of the process list, and tells "no such bucket" (exit 1)
from "could not find out" (exit 2).

- The script is run as `<script> <name>` (or with `cert_validate_args`),
  without a shell, and only for names that are valid host names matching the
  rule. Exit status 0 accepts the name;
  any other status refuses it. It is killed after 20 seconds, and no answer
  (killed, or it could not be started) counts as a refusal.
- **It runs only when a certificate has to be issued or renewed**: the first
  time a client asks for a name that has no certificate, and again each time
  that certificate comes up for renewal. Never per connection, and not after a
  restart for names whose certificate in `cert_path` is still good.
- Connections are never held up by it. The script runs in the background;
  until the certificate is there clients get the placeholder. Up to 4 names
  are handled at once, so the script may run up to 4 times in parallel, but
  never twice at the same time for the same name.
- A refused new name is not asked about again for 10 minutes (or until the
  config is reloaded). A refused **renewal** keeps the current certificate in
  use until it expires and asks again every 6 hours.
- Every decision is logged with the script's exit status, run time and the
  first 300 bytes of its output, so print the reason:
  `cert: x.customers.example.com: REFUSED by cert_validate_script /usr/.../domains.sh (exit status 1 in 12ms, output "unknown customer"); no certificate is requested ...`
  and `ACCEPTED by cert_validate_script ... (exit status 0 in 9ms); requesting the certificate`.
- Accepted names appear on the console's Certificates page like any other.
- At most 64 names wait for a decision at a time; the DNS pre-check and the
  3-tries-then-6-hours schedule apply to accepted names as usual. The script
  runs as the proxy's user, so whoever can edit the config (the console
  included) can run commands as that user.

How it works:

- **TLS-ALPN-01 only.** The CA connects to the name on public port 443 with
  ALPN `acme-tls/1`; the proxy already reads every ClientHello, so it answers
  those itself with the challenge certificate. Port 80 is never needed. If the
  proxy listens on another port, forward public 443 to it (a warning reminds
  you).
- **Challenges that are not ours go to the upstream.** A challenge is
  answered here only when the rule that routes the name (on the listener the
  CA connected to) terminates TLS here and an order for the name is in
  progress. A pass-through rule's `acme-tls/1` connections always go to its
  target untouched, like the rest of its traffic: the backend runs its own
  ACME client. A terminating rule's go to the upstream when no order is in
  progress here and `upstream_tls = true` (normal traffic for that name is
  still terminated here). With a plaintext upstream nobody could answer, so
  it is refused.
- **Urgent first, up to 4 names at once.** At startup and every 10 minutes:
  names with no or an expired certificate first, then renewals by due date.
  Names don't depend on each other, so a slow one (a hanging validation, a
  slow script) doesn't hold up the rest; one name never has two jobs running
  at the same time. A failure is retried after 6 hours. Certificates found in `cert_path` are
  reused after a restart.
- **Three quick tries, then six hours.** Each job is attempted up to 3 times,
  5 seconds apart, to ride out temporary failures. Two kinds of failure are
  not repeated right away because it would not help or would cost you: a DNS
  pre-check mismatch, and a validation the CA itself rejected (Let's Encrypt
  allows only 5 failed validations per name per hour).
- **Every step is logged**: a name's status when first seen or changed (`no
  certificate yet`, `valid until ... (N days left)`, `expiring`, `EXPIRED`),
  each attempt and why it failed, when the next attempt is and what clients
  get meanwhile, the scheduled retry with the previous error, account
  registration, the CA's validation, and the issued certificate's issuer,
  serial, validity and renewal date. Each terminated connection logs
  `TLS terminated here: client TLS 1.3 alpn=h2, cert=auto (issuer ..., expires
  ...); upstream tls alpn=h2`, or says when the placeholder was served.
- **DNS pre-check** before every order, so a name that doesn't point here
  never costs you the CA's failed-validation rate limit.
- **Placeholder.** Until a certificate exists (or for a name matched by the
  pattern but missing from `cert_domains`, or refused by the script) a
  self-signed placeholder keeps the service reachable, with a browser warning.
  A name from `cert_domains` gets its own. Names chosen by clients never do:
  they share **one placeholder per rule**, a wildcard (`*.s3.example.com`) when
  the pattern is one, so a flood of made-up names costs no key generation or
  signature at all. Placeholders live 7 days and are replaced before they
  expire.
- **ALPN end to end.** The upstream is contacted first and the client is
  offered exactly the protocol the upstream agreed to, so HTTP/2 works across
  the proxy. With a plaintext upstream only `http/1.1` is offered.
- Reload cancels certificate jobs from the previous config, including scripts
  and retry waits; obsolete results are discarded. Pending names are retried
  under the new settings. A rejected config leaves current jobs running.
- Reload applies certificate settings too; a config naming a CA that does
  not exist (or does not load) is rejected and the running config stays.
- Terminated connections are still plain TCP relaying: no HTTP parsing, no
  added headers. They cost more CPU and memory than pass-through.

## Logging to files

By default activity is written to the process's stdout and problems to its
stderr. Add a `[logging]` section to write to files instead, with rotation,
gzip compression and pruning built in (no `newsyslog`/`logrotate` needed):

```toml
[logging]
stdout = /var/log/tlsproxy/stdout.log   # activity: accepted / route / connected / closed, stats, reloads
stderr = /var/log/tlsproxy/stderr.log   # problems: accept errors, failed reloads, ...
max_size = 15MiB        # rotate once a file reaches this (K / M / G); default 15MiB
max_keep = 10           # generations kept: file.1 (newest) .. file.10; default 10
compress_after = 3      # file.1-.3 stay plain, file.4.gz and older are gzip; default 3
```

- With a file set, nothing of that stream reaches the terminal. Either key may
  be omitted, and both may name the same file. Relative paths are relative to
  the working directory.
- Rotation is numbered: `stdout.log` → `stdout.log.1` → `.2` → ... Generations
  above `compress_after` are gzip files (`stdout.log.4.gz`); anything beyond
  `max_keep` is deleted. `compress_after >= max_keep` disables compression and
  `max_keep = 0` just starts the file over.
- Compression is done **in-process**, in the background, under a **compress
  guard**: until it finishes the log does not rotate again, so the numbering
  can never shift under the compressor. The live file simply grows past
  `max_size` in the meantime; nothing blocks and nothing is lost.
- The settings follow hot reload. If a new log file can't be opened, the
  previous destinations stay in use.

## Web console

An optional console: live listeners, rules and connections, all editable
(start, stop, add, edit, delete), a flow log, certificates, the recent log and
a config editor. It is served under `/tlsproxy_quick/`; `/` redirects there.

Its settings are in a file of their own, given at start-up, which the console
can't see or change. No edit made from the console can change its password or
take it off the network:

```sh
tlsproxy config.toml --console console.toml
```

Without `--console` there is no console. A `[console]` section in
`config.toml` is an error that says to move it.

```toml
# console.toml
[console]
bind = 0.0.0.0                     # default 127.0.0.1
port = 443                         # required
hostname = console.example.com     # with cert: the name it is served under
cert = auto                        # auto or local-ca[:caNNN]: served over TLS; none = plain HTTP
password = change-me               # replaced by password_hash on start (see below)
```

**Over TLS (with `cert`).** The console is served like a rule with
`service_rule` keys, inside the TLS connection the proxy terminates, with a
certificate for `hostname`:

- On the `[[listener]]` of `config.toml` with **exactly** its `bind` and
  `port`, it is one more rule there, for `hostname`. Nothing in `config.toml`
  can override it: a `[[host]]` for that exact name on that listener is an
  error. Wildcards and `ANY` don't take it, since an exact name always wins.
- With no such listener, it gets **one of its own**, `(console)`. A listener
  that only partly overlaps its address (`0.0.0.0` against `::`, or one of
  several addresses) is an error: make the binds the same, or use another
  port.
- The console can't stop its rule or its listener. Deleting that listener
  in `config.toml` moves the console to a listener of its own, and adding
  one back moves it there. Either way the open socket is handed over, not
  reopened, so the port never closes, even for the signed-in session.
- Session cookies are HTTPS-only.

**Plain HTTP (no `cert`).** It listens on `bind:port` itself, as before
v1.5.0. Keep it on loopback: any other address logs a warning, because the
password would cross the network unencrypted. Its port may not overlap a
listener (to share one, set `cert` and `hostname`).

| `[console]` | default | meaning |
|---|---|---|
| `bind` | 127.0.0.1 | addresses, separated by `;`. With `cert`: the listener with exactly this bind and port serves it. `listen`, its name before v1.5.0, is an error that says so |
| `port` | (required) | its port |
| `hostname` | (required with `cert`) | the name it is served under. Without `cert`, one more name the Host check accepts |
| `cert` | (plain HTTP) | `auto` (ACME, with `acme_agree_tos` from `config.toml`) or `local-ca` / `local-ca:ca002` |
| `password` | | plain text, for convenience. At start-up and on every reload the proxy replaces this line with `password_hash` and logs it, so the secret is on disk only briefly. To change the password, put a `password =` line back |
| `password_hash` | | `$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>` (argon2id, 64 MiB, 3 passes), or `pbkdf2-sha256$<iterations>$<salt>$<hash>` from older versions. Generate one with `tlsproxy --hash-password`. One of the two is required |
| `secure_cookie` | false | plain HTTP only: set true when another proxy publishes the console over HTTPS, so session cookies are only sent over HTTPS |
| `hostnames` | (none) | plain HTTP only: `;` or `,` separated names the console answers to, besides IP addresses and `localhost`. Any other `Host` is refused: that defeats DNS rebinding |

`console.toml` is read again on every reload, like `config.toml`; one that
doesn't parse is logged and the console keeps its last good settings. Every
version of `config.toml` is loaded with it merged in: at start-up, on reload,
and for every check and save in the console, so what passes a check is what a
reload runs. The password, `hostname` and (with `cert`) `bind` and `port`
follow a reload; a plain HTTP `bind` or `port`, or switching between plain
HTTP and TLS, needs a restart. A changed password or cookie policy signs
everyone out.

**Pages**

The config file stays the source of truth: everything the console changes is
written to it (and every change to the file shows up in the console).

- **Listeners** (live: the state is pushed over a WebSocket, a frame only when
  something changed): totals, rates and a 2-minute throughput trace on top,
  then one card per listener (its addresses, overrides, connections and
  rates), and inside it one card per `[[host]]` rule of that listener in file
  order, with its target, kind, TLS mode, PROXY protocol and speed limits, its
  live and total connections and rates, and its open connections underneath. A connection row opens into its
  details: client, proxy and upstream addresses, bytes each way, the state of
  each direction, SNI and how TLS was handled.
  - **Add / Edit / Delete a listener** with the same guided form: name, bind
    and port, then any overrides. The new port opens (or moves) at once.
    Renaming a listener renames it in its rules. A listener
    that still has rules cannot be deleted.
  - **Stop / Start a listener.** Stop closes its port and its connections;
    like stopping a rule, it is not written to the file and lasts until Start
    or a restart. If Start cannot open the port (another process has it), the
    listener stays stopped and the card shows why. A save whose new or moved
    port cannot be opened says so too, and the card offers Start to retry.
  - **Stop / Start a rule.** A stopped rule is routed as if it were not
    configured: the names it matched go to the next rule that matches
    (another wildcard, `ANY`, or nothing: denied), and its open connections
    are closed. Stopping is not written to the file: it lasts until Start or
    a restart, and survives reloads.
  - **Add / Edit a rule** with a guided form: what to match, where to send
    it, then TLS, PROXY protocol and speed limits, showing only the fields
    that apply. Every change is validated against the whole file as you type,
    with a preview of the exact `[[host]]` block that will be written and a
    "try a name" box showing where sample names would be routed. Saving
    rewrites only that block (comments and the rest of the file are kept),
    with the same checks and backup as the config editor below, and applies
    it at once.
  - **Delete a rule**: its block (and the comment right above it) leaves the
    file. Its open connections keep running until they end.
  - **Stop a connection**: closes one connection.

  Start, Stop and Delete keep their buttons disabled until the pushed state
  shows the change (normally well under a second), so a card changes once.
  If the server refuses, the buttons come back and nothing changes.
- **Flow log**: every connection, including those too short to ever show on
  the Listeners page, and those refused before routing (limits, bad PROXY
  header). Each one is listed as it opens (client, listener), when it is
  routed (name, rule, target) and when it closes (duration, bytes each way,
  and the result: closed, denied, failed, rejected or ACME, with the reason).
  Tags say how each one is handled: end-to-end TLS (passed through) or
  terminated (with the TLS version, and whether the target gets TLS,
  unverified TLS or plaintext), the ALPN protocols, the PROXY header sent to
  the target (or none), the load balancer it came through, speed limits, a
  cached route, and **zero-copy** when both directions are spliced in the
  kernel.
  Events are pushed over their own WebSocket, open only while the page
  shows; every 5 seconds the server also sends the authoritative list of
  open connections, which repairs anything a dropped event missed. Open
  connections are listed first. A closed one fades out over 30 seconds;
  with **Show all closed** on, every closed connection the proxy still
  remembers (the last 2000) stays listed. Open connections can be stopped
  from here too.
- **Certificates**: every certificate in use, both those the proxy manages
  (`cert = auto`) and those your CAs issued (`cert = local-ca`): status (`ok`,
  `expiring`, `expired`, `missing`, `failing`), issuer, validity, days left,
  renewal date, the rules using it, the last error and next attempt, and a
  "retry now" button that skips the 6-hour wait.
- **Log**: the most recent 2,000 lines of both streams, filterable (for
  example by `[#42]` or a host name), wherever the log is configured to go.
- **Config file**: a text editor for the whole file, with line numbers.
  - *Validate* and *Test routing* work on the text in the editor, saved or not.
    *Validate* answers green with a tree of the settings the proxy would run
    with (each value marked when it is a default or inherited from
    `[global]`), yellow for each warning, red for an error, each with its
    line, which one click selects in the editor.
  - *Reference* (ⓘ) lists every key, by section, with its default and
    meaning; filter by name or word, click a key to copy `key = `. It is
    generated from the code, and a test keeps it complete.
  - *Save & apply* validates first (an invalid config is never written, and a
    `cert = local-ca` naming a CA that doesn't exist counts as invalid), keeps the previous
    file as `config.toml.<timestamp>.bak` (the last 10, loadable from the
    editor), and applies the change at once.
  - **Saves are race free**, here and in the rule editor. Every
    read-check-write of the file happens under one lock in the proxy, and a
    save must present the modification time and content hash the page
    loaded. If the file was changed by anything else in between (vim, another
    session, the proxy hashing a password), that save fails and nothing is
    written.
  - The editor shows `config.toml` only; `console.toml` is never shown or
    written. Text with a `[console]` section is rejected.

**Security**: a password is always required, even on loopback (a web page in
your browser could otherwise reach it). Sign-ins are rate limited globally
(5 failures, then 30 s doubling up to 15 min); sessions are random, in memory,
`HttpOnly`, `SameSite=Strict`, 12 hours; every POST needs the session's CSRF
token and a JSON content type; the WebSocket only accepts its own origin and
closes when the session ends; responses forbid framing. Whoever can save a
config controls the proxy (targets, certificate paths, log file locations), so
treat the console password like root access to the gateway.

## Logs and state

```
[#1] accepted from 10.0.0.5:49943 (active=1)
[#1] route sni=foo.wushilin.net -> foo.wushilin.internal.net:443 (ALLOW, rule line 51, cached)
[#1] connected 10.0.0.5:49943 -> foo.wushilin.internal.net:443 (192.168.1.10:443) in 2ms
[#1] closed src=10.0.0.5:49943 sni=foo.wushilin.net dst=foo.wushilin.internal.net:443 (192.168.1.10:443) up=533 B down=6.54 KiB duration=56ms reason=client closed, then upstream closed 1ms later
[#2] route sni=evil.com src=10.0.0.7:49945 -> DENY (rule line 57)
```

The `reason=` on the closing line says exactly how the connection ended:

| `reason=` | meaning |
|---|---|
| `client closed, then upstream closed 1ms later` | normal: one side finished, the other followed (either order); the time is how long the second side took |
| `client closed, other direction still open after half_close_timeout (30.00s); closed by proxy` | one side finished, the other never did, so the proxy ended it after the grace period |
| `client closed, then idle timeout (10m00s); closed by proxy` | one side finished, the other stayed open but silent |
| `idle timeout (10m00s); closed by proxy` | nobody closed and nothing moved for `idle_timeout` |
| `upstream stopped reading, then ...` | a write failed because the receiver closed its read side or vanished; the other direction still got its chance to finish |
| `client closed in the middle of a TLS record, without close_notify; closed by proxy` | terminated connections only: the TCP connection ended inside a TLS record, so the data was incomplete. (A peer that closes between records without `close_notify`, as many HTTP clients do, counts as a normal close) |
| `client->upstream error: ...` / `upstream->client error: ...` | a socket error such as a connection reset |

A global registry tracks everything live, lock-free on the data path:
connections (active, accepted, completed, denied, failed, rejected),
**goroutines started / finished / open**, total bytes up and down, cache hits
and misses, and per connection: source, SNI, target, bytes each way, age,
idle time and the state of each direction (`open` / `half-closed`).

- Every `stats_interval` seconds, one summary line:
  `stats: active=3 accepted=120 completed=113 denied=4 ... goroutines=6 (started=240 finished=234, runtime=11) up=1.20 GiB down=30.11 GiB cache=5 allow/2 deny (hits=101 misses=19) pool_idle=12`
- `kill -USR1 <pid>` logs that summary plus one line per open connection.

## Zero-copy relaying (Linux)

On Linux, a passed-through connection is relayed with `splice(2)`: each
direction has its own kernel pipe, and the bytes go

```
client socket ──splice──▶ kernel pipe ──splice──▶ upstream socket
```

without ever being copied into the proxy. A terminated connection cannot do
this, because the proxy has to decrypt and re-encrypt every record, so it
keeps the buffered copy. The same holds for the ClientHello itself, which
the proxy reads to route the connection: it is forwarded from user space,
and splicing starts with the first byte after it.

Go's `TCPConn.ReadFrom` also splices, but it only returns at EOF. The proxy
runs its own loop, one splice step at a time, so byte counts, the idle timer,
write timeouts and half-close work exactly as they do in the buffered copy.

- The pipe is `buffer_size` bytes (rounded up to a page), and a spliced
  connection holds no pooled buffer. It holds four extra file descriptors
  (two pipes) instead. Go raises the soft `RLIMIT_NOFILE` to the hard limit
  at start-up; with many connections, check that the hard limit allows
  about 6 × `max_connections`.
- Beyond `fs.pipe-user-pages-soft` (16384 pages per user by default, which
  is 64 MiB of pipes with 4 KiB pages), the kernel will not grow pipes and
  may hand out smaller ones. Splicing still works, in smaller steps. If no
  pipe can be created at all (out of descriptors), or the kernel refuses to
  splice a socket, that direction falls back to the buffered copy.
- `splice = false` in `[global]` turns it off. macOS, FreeBSD and Windows
  always use the buffered copy.

Measured on a 4 KiB-page arm64 Linux VM: one stream through loopback
reached 3,430 MiB/s spliced against 2,260 MiB/s buffered, and the whole test
(client, backend and proxy together) used 0.65 instead of 0.95 CPU-seconds
per GiB.

## Design notes

- **No locks on the serving path.** From accept to close a connection never
  waits for a lock another connection holds. Shared state is read lock-free
  and updated atomically, giving up a little freshness where that is needed:
  - The running configuration, the stopped rules, TLS ticket keys and the
    certificates a handshake can be given are immutable snapshots behind an
    atomic pointer (like Rust's `ArcSwap`): readers load the pointer, a
    reload or the certificate worker swaps in a new one.
  - The route and DNS caches are CLOCK caches: a hit is a lock-free map read
    and an atomic "recently used" flag; adding a name uses `TryLock` and
    skips caching rather than wait.
  - Open connections live in a slot table claimed with compare-and-swap;
    per-name counters in a fixed lock-free hash table; per-rule and
    per-listener counters are made when a configuration loads, so
    connections only read them.
  - Speed limits are GCRA token buckets: one compare-and-swap per chunk,
    however many connections share a rule's limit.
  - Handshakes in progress per source are counted in a fixed array of
    atomic counters (a keyed hash of the address picks one).
  - Buffers, log lines and new names for a `cert_validate_script` go through
    a lock-free bounded ring (Vyukov's MPMC queue); full means drop, never
    wait.
  A test drives concurrent passthrough and terminated traffic with shared
  speed limits and checks Go's mutex profile: any wait for a lock taken by
  this program on the way from accept to relay fails it. What remains is
  outside it: the Go runtime's own locks (heap, garbage collector) and the
  standard library's (crypto/tls caching a key). The console's live views
  and a page watching the flow log are not on the serving path.
- **Logging never holds up traffic.** A log call puts the line in a
  lock-free ring; a background goroutine writes it out ten times a second, and at
  once after a problem line. A slow disk or a stalled stdout pipe therefore
  cannot block connection handlers or the accept loop. If the destination
  cannot keep up, at most 4 MiB is held; further lines are dropped and the
  number is logged. `SIGTERM` / `SIGINT` write out what is pending before the
  process exits. Lines that a flood would repeat ("too many connections",
  `max_handshakes_per_ip`) are logged at most once a second, with a count.
- **Goroutines, no event loop.** One goroutine per connection reads the
  ClientHello, routes, connects and copies client → server; a second copies
  server → client. The Go runtime multiplexes them over kqueue/epoll.
- **Buffer pool = lock-free ring.** Borrow and return never block:
  borrowing from an empty pool allocates, returning to a full pool drops the
  buffer for the GC. In steady state every buffer is reused, so relaying
  allocates nothing per byte and the GC has next to nothing to do (byte
  slices hold no pointers, so pooled buffers are never scanned). Buffers are
  not cleared on reuse; only the bytes just read are ever used.
- **Route cache.** Two capped CLOCK caches (an approximation of LRU, lock-free
  on a hit) keyed by listener and lowercased SNI, one for allowed and one for
  denied names, so a flood of junk names can only evict
  other junk. Cached decisions are marked `cached` in the log.
- **Hot reload.** The config file is re-read every `reload_interval` seconds
  (content is compared, not mtime), so reloads happen at most once per 5 s
  and the newest version always wins. Config, caches and buffer pool swap
  together through one `atomic.Pointer`: caches start empty, a changed buffer
  size gets a fresh pool, an invalid file is logged and ignored, existing
  connections keep the settings they started with. Listeners open, move and
  close to match (see [Listeners](#listeners)); only a plain HTTP console's
  `bind` and `port` need a restart.
- **Half-close and interruptions.** EOF on one side is forwarded as a
  half-close and starts the `half_close_timeout` clock; the other direction
  keeps flowing until it ends or the clock fires. A write failure (receiver
  closed its read side) likewise ends only that direction. Idle means no
  traffic in *either* direction.

## Tests

`go test ./...` runs 100+ tests, also under the race detector in CI. The
suite is self-contained: everything it needs is in the repository
(dependencies, Pebble included, are vendored), and it talks to nothing but
localhost, so it runs on a fresh host with no network. Only the live-sites
test (`TLSPROXY_LIVE=1`) goes out to the internet.

- **Every combination, at once (`TestChaosCombinations`).** One proxy per
  relay mode (splice on, off), each case its own rule, backend and random
  payload: passed through to a TCP echo, a TLS echo or an HTTPS server, and
  terminated with a local CA to a TCP echo, TLS echo, HTTP or HTTPS server;
  each with no PROXY header, v1 or v2 to the backend, and none, v1 or v2
  from a load balancer in front; on either of two listeners, some with a
  speed limit. Each checks the certificate the client gets, that the right
  backend got it, what that backend saw (PROXY version, the client address,
  even one a load balancer stated; the TLS name; the ALPN protocols offered),
  that TLS and ALPN pass through untouched (the client ends up with the
  backend's TLS version and its choice of protocol, an unusual one only the
  backend would pick) and survive termination, the payload both ways, and
  the proxy's log and flow log (result, TLS mode, PROXY version, load
  balancer, splice or copy, bytes). Then the refusals: a deny rule, no
  matching rule, a name the local CA won't issue for, a backend that is down,
  an upstream certificate that fails verification. The backends parse PROXY
  headers with code of their own, so the proxy is checked against the
  specification, not against itself. Random choices come from a seed it
  logs: `TLSPROXY_CHAOS_SEED=<n>` repeats a run.
- **The same with `cert = auto`.** Every backend, PROXY out and PROXY in, with
  certificates Pebble issued over TLS-ALPN-01 through the proxy, verified
  against Pebble's root.
- **ACME, end to end.** Runs Pebble (Let's Encrypt's official test CA) in the
  test process, from its vendored packages, with a fake DNS server; Pebble
  validates TLS-ALPN-01 against the proxy exactly as Let's Encrypt would. Checks issuance for two names,
  the certificate served to clients, files and permissions, the DNS pre-check
  refusing a name that resolves elsewhere, renewal, and reuse after a restart.
- **Live sites (`TLSPROXY_LIVE=1`).** HTTPS GETs to Google, Facebook,
  Cloudflare and GitHub through the proxy: passed through (the client
  verifies the real certificates) and terminated (the proxy verifies them),
  HTTP/2 end to end both ways, and an upstream whose certificate doesn't match
  is refused.
- **TLS termination with mock backends:** plaintext and TLS upstreams, ALPN
  negotiation, half-close, 4 MiB integrity with 4 KiB buffers, termination and
  pass-through side by side, the placeholder, the challenge responder,
  start-up errors, config validation, renewal schedule and job priority, and
  the DNS check against a fake DNS server.
- **Local CAs:** issuance on first use, one certificate for racing
  handshakes, reuse after a restart, renewal (at a handshake, in the
  background, at start-up, `renew_before_days`), the CA renewing itself with
  the same key, foreign certificates archived and old archives pruned,
  imported intermediates served with their chain, refusals, `config.toml`
  (what `[certificates]` changes, `[ca]` locked), and the console's CAs page.
- **Unit:** ClientHello parsing (every prefix of a fragmented hello,
  post-quantum sizes, malformed input), config parsing and errors, routing,
  LRU eviction order and caps, a denial flood that cannot evict allowed
  names, the buffer pool, formatting. Every `samples/*.toml` must route as its
  `#> sni => target` comments say, and every default documented in
  `config.toml` must match the code.
- **End-to-end over real sockets:** routing, deny alerts, non-TLS traffic,
  16 MiB transfers verified byte for byte, half-close both ways, every
  timeout, `max_connections`, 100 concurrent clients, hot reload, and the
  global state (exact byte, connection and goroutine counts, no leaks).
- **Command-driven mock upstream:** the client tells the backend how to
  misbehave: `CLOSE`, `RESET` (TCP RST), `WRITER_CLOSE`, `READER_CLOSE`,
  `SERVER_DATA n seed`, `CLIENT_DATA n` (verified by hash), `SLEEP ms`
  (force back-pressure), `PING`, chainable with `;`. Covered: close and
  reset mid-stream, upload after the server's writer closed, download after
  its reader closed, client aborts mid-transfer with exact byte counts, 8 MB
  through a stalled peer with nothing lost, and an interruption storm after
  which no connection, goroutine or slot may be left.

## Performance

Measured on an Apple M3 Max, client, backend and proxy sharing the machine:

| | |
|---|---|
| 64-byte round trip, added (p50) | +20 µs |
| connect + ClientHello, added (p50) | +111 µs |
| new connections/s (32 parallel) | 9,800 |
| 1-stream throughput | 630–1,070 MiB/s (run to run) |
| proxy CPU per GiB relayed | 0.6–1.0 s |
| memory with 2,000 open connections | 121 MiB (~50 KiB each) |
| binary | 2.7 MB static |

At gateway speeds (1 Gbit/s ≈ 0.12 CPU-seconds per second) the per-byte cost
does not matter. Lower `buffer_size` if memory is tight.
