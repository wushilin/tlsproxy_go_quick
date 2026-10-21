# tlsproxy_go_quick

An **extremely simple SNI router for a gateway**. It listens on one port,
reads the hostname in the TLS ClientHello (SNI), picks a backend from
`config.yaml`, and relays the still-encrypted bytes to it. By default it never
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
CONSOLE_PASSWORD=secret ./tlsproxy config.yaml -console_domain admin.example.com   # run, with the web console
./tlsproxy config.yaml -noconsole                      # run without it (logs to stderr)
./tlsproxy config.yaml --test foo.wushilin.net x.com   # dry run: show routing only
./tlsproxy config.yaml --test ""                       # dry run for a client without SNI
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
are updated for v1.5.0 (`config.yaml`, and the console set at start-up).

**1. A folder for the configuration and one for state:**

```sh
mkdir -p /srv/tlsproxy/etc /srv/tlsproxy/data
```

**2. A configuration.** A small one to start from. The web console is on
by default, on port 443, on a listener it owns named `$console`, so this file
only adds rules to that listener (the full reference, [`config.yaml`](config.yaml),
is in this repository):

```sh
cat > /srv/tlsproxy/etc/config.yaml <<'CONFIG'
global:
  acme_agree_tos: true          # the console's certificate (cert auto) comes from Let's Encrypt

routes:
  - listener: $console          # the console's listener: its bind and port come from the console
    rules:
      # Pass TLS for this name through to a backend, untouched.
      - domain: www.example.com
        target: "192.0.2.10:443"

      # Everything else is refused (except the console's own name).
      - domain: $anything_else
        action: deny
CONFIG
```

**3. Let the container's user own both** (it writes the configuration: the
console saves its edits to `config.yaml`; and its state: certificates, CAs):

```sh
sudo chown -R 65532:65532 /srv/tlsproxy
```

**4. Run it**, with the console's name (it must resolve to this host, for
its certificate) and password. Put a hash from `--hash-password` (see below)
in `$CONSOLE_PASSWORD` rather than the password itself, so `docker inspect`
doesn't show the password (single quotes keep the shell off its `$`):

```sh
docker run -d --name tlsproxy --restart unless-stopped \
  -p 443:443 \
  -e CONSOLE_DOMAIN=admin.example.com \
  -e CONSOLE_PASSWORD='$argon2id$v=19$m=65536,t=3,p=4$...' \
  -v /srv/tlsproxy/etc:/etc/tlsproxy:Z \
  -v /srv/tlsproxy/data:/var/lib/tlsproxy:Z \
  docker.io/wushilin/tlsproxy_go_quick:latest \
  /etc/tlsproxy/config.yaml
```

Without `CONSOLE_DOMAIN` and `CONSOLE_PASSWORD` the proxy refuses to start;
add `-noconsole` after the file name to run without a console (then the file
names its own listeners: `listeners: [{name: https, port: 443}]`). To keep
the console off the public port, give it one of its own, published on the
host's loopback only: `-e CONSOLE_PORT=9443 -p 127.0.0.1:9443:9443` (or
`-console_port 9443` after the file name); its listener is still `$console`,
and port 443 is yours to define, under any name. Its certificate is still validated by the CA on port 443: the proxy
answers its own ACME challenges on any listener, so `cert: auto` works as
long as port 443 reaches the proxy (publish it, as above). Otherwise use
`-console_cert local-ca`: the default CA, `ca001`, always exists.

`:Z` lets the container use the folders on SELinux hosts (Fedora, RHEL and
the like); elsewhere it does nothing. Without it, SELinux refuses with
`open /etc/tlsproxy/config.yaml: permission denied`.

**5. Check it:**

```sh
docker logs tlsproxy
#   console: served at https://admin.example.com:443/tlsproxy_quick/ by listener $console on 0.0.0.0:443 (cert: auto; password required)
#   listening on https 0.0.0.0:443 with 1 listener(s), 3 rules (...)
```

The console is at `https://admin.example.com/` (it redirects to
`/tlsproxy_quick/`); sign in with the password from step 4.

**Everyday commands:**

```sh
# Where would these names go? (a dry run with the same config; the console's
# settings give it its listener $console, and any password will do)
docker run --rm -e CONSOLE_DOMAIN=admin.example.com -e CONSOLE_PASSWORD=x \
  -v /srv/tlsproxy/etc:/etc/tlsproxy:Z docker.io/wushilin/tlsproxy_go_quick:latest \
  /etc/tlsproxy/config.yaml --test www.example.com other.example admin.example.com
#   www.example.com -> 192.0.2.10:443 (rule line 8, literal: www.example.com)
#   other.example -> DENY (rule line 12, catch-all: $anything_else)
#   admin.example.com -> served here: the web console

# A hash for $CONSOLE_PASSWORD or a basic_auth user's password_hash
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
binaries with `SHA256SUMS` and `config.yaml` to the release.

## Configuration

The configuration is one YAML file, `config.yaml` by default
(`tlsproxy [config.yaml] ...`):

```yaml
listeners:
  - name: https
    bind: [0.0.0.0]
    port: 443

routes:
  - listener: https
    rules:
      - domain: "*.wushilin.net"
        action: allow
        target: "${1}.wushilin.internal.net:443"

      - domain: $anything_else
        action: deny
```

(Run like this, with `-noconsole`, or with the console on another port: on
port 443 the [web console](#web-console) owns that port on all addresses,
on its listener `$console`: route these rules to `$console` instead.)

- **The file has five sections**, each optional but `listeners` (unless the
  console provides the only one): `global`, `logging`, `listeners`, `routes`
  and `basic_auth`. `routes` is a list of items, one per listener: its name in
  `listener:` and its `rules`, a list. An unknown key, or a key given twice,
  is a load error with its line.
- **Coming from `config.toml`** (before v1.5.0): there is no built-in
  migration tool. The [samples](#samples) show each feature in the new form;
  in short, `[global]` and `[logging]` keep their keys, each `[[listener]]` is
  an item of `listeners`, each `[[host]]` is an item of the `rules` of its
  listener's `routes` item, `pattern` is `domain`, `target_host` and
  `target_port` are one `target: "host:port"`, `proxy = true` with
  `proxy_version = 2` is `proxy: v2`, `service_rule` keys are a `serve` list,
  `[[basic_auth]]`'s `user` keys are a `users` list, `NONE` and `ANY` are
  `$no_sni` and `$anything_else`, and `;`-separated values are YAML lists.
  The old keys and spellings in a rule are load errors that say what to
  write. `ca_root` is now `cert_root`, and `cert_path` is gone: the ACME
  certificates live in `<cert_root>/acme`, so the old folder isn't read and
  each name is issued again (or move its contents there). A local CA's own settings file is `config.yaml` too (`ca:` and
  `certificates:`); a `config.toml` there is no longer read, and the CAs
  page says so.
- **The most specific rule wins, wherever it stands in the file.** A hostname
  that matches no rule is denied. `domain` is a host name, optionally with
  `*` wildcards. There are no regular expressions. All matching ignores case:

  | | form | example | matches |
  |---|---|---|---|
  | 1 | `$no_sni` | `$no_sni` | only clients that send **no SNI** |
  | 1 | literal name | `vq.example.com` | exactly that name. Looked up, not scanned |
  | 2 | wildcard | `*.example.com` `api-*.example.com` `*.*.example.com` | a `*` **never crosses a dot**. As a whole label it is exactly one label: `*.example.com` matches `a.example.com`, not `a.b.example.com` and not `example.com`. Inside a label it is any run of characters, none included: `abc*.example.com` matches `abc1.example.com` and `abc.example.com`. The domain with more literal characters wins; then file order |
  | 3 | `$anything_else` | `$anything_else` | everything, with or without SNI; always last |

  So a literal `deny` beats a wildcard `allow`, a literal `allow` beats a
  broader `deny`, and an `$anything_else` in the middle of the file shadows nothing.
  There is no `**` and no "any depth": write one rule per depth you mean
  (`example.com`, `*.example.com`, `*.*.example.com`), which also means one
  more label never slips through an allowlist. There is no "a or b" either:
  one rule per name. The same domain twice, two `$anything_else` or two `$no_sni` rules on
  a listener are start-up errors, since only one could ever match. If the
  file reads differently top to bottom than it is evaluated, one log line says
  which rules win over which. `--test` and the console's *Test routing* show
  the winning rule and its kind.
- **Coming from a version with regular expressions** (before v1.0.0): a regex
  domain is now a load error that names the line and says what to write
  instead. `(.*)\.example\.com` becomes `*.example.com` (one label only),
  `(www|blog)\.example\.com` becomes two rules, `node(\d+)\.example\.com`
  becomes `node*.example.com`, `.*` becomes `$anything_else`, `^$` becomes
  `$no_sni`. Escaped dots and `^...$` around a
  name are tolerated, so `vq\.example\.com` and `^vq.example.com$` keep working.
- `target` is `host:port`: a name or an IP address, then the port, which is
  always given (there is no default port). An IPv6 address goes in brackets:
  `target: "[2001:db8::10]:443"`. The host can use what each `*` matched:
  `${1}` is the first `*` from the left, `${2}` the second, and so on;
  `${host}` (or `${0}`) is the whole SNI, as in `target: "${1}.internal:443"`.
  References are always in braces, so `${1}hello` is exact; a bare `$1`, an
  unknown `${...}` or a `*` the domain doesn't have is rejected at load time.
- An SNI that is an IP address (RFC 6066 forbids it) never fills `${host}`:
  it is routed as no SNI, so a `target: "${host}:443"` rule cannot be pointed
  at arbitrary addresses. An
  `$anything_else` rule whose target follows the client (`domain: $anything_else` with
  `target: "${host}:443"`) still connects to any *name* a client sends,
  internal ones included; that is logged as a warning at start-up.
- `action` is `allow` (the default) or `deny`. A denied client gets a TLS
  `access_denied` alert. An allow rule needs a `target` (or `serve`).
- Every rule belongs to a listener: the `listener` of its `routes` item, even
  when there is only one.
- **What no rule takes is denied**, as if the listener ended with
  `domain: $anything_else` and `action: deny`; you only write that rule to
  say so, or to do something else instead. The console shows the implicit
  deny as the last rule of a listener without one (locked), with the
  connections it refused.
- `domain: $no_sni` is explicit: it matches only clients that
  send no SNI, for example to send them to a default target; its `target`
  must be a literal. Without such a rule only `$anything_else` takes them; a wildcard
  never matches a missing SNI. Hosts literally named `none` or `any` are
  matched with `^none$` / `^any$`. A client that sends an IP address as SNI
  (RFC 6066 forbids it) is treated as one without SNI.
- **Quoting is YAML's.** Most values need no quotes, but quote one that
  starts with `*`, `[`, `{`, `$` or a quote, or that contains `: ` or ` #`:
  `domain: "*.example.com"`, `target: "${1}.lan:443"`, a `password_hash`. A
  bare `::` is not a string either: `bind: ["::"]`. Lists are written
  `[a, b]` or one `- item` per line; a single value also works where a list
  is expected (`bind: 0.0.0.0`).

Optional `global` settings; [`config.yaml`](config.yaml) lists every one
with its default, and a test keeps that file in step with the code:

| key                    | default | meaning                                                              |
|------------------------|---------|----------------------------------------------------------------------|
| `handshake_timeout`    | 10      | seconds to receive the whole ClientHello (a slow trickle can't extend it) |
| `connect_timeout`      | 10      | seconds to resolve and connect to the target                         |
| `idle_timeout`         | 600     | close after N seconds with no traffic in either direction (0 = never); also reaps half-open connections |
| `half_close_timeout`   | 30      | after one side closes, the other side gets N seconds to finish (0 = unlimited) |
| `max_connections`      | 1024    | further connections are rejected; goroutines ≤ 2 × this              |
| `proxy_trust_source`  | (none)  | who may put a PROXY protocol header in front of a connection: a list of IP addresses or networks (`[10.0.0.2, 10.1.0.0/16]`). See [The client's address](#the-clients-address-proxy-protocol) |
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
[`samples/12-everything.yaml`](samples/12-everything.yaml) (a test fails if an
option is missing from it, from `config.yaml` or from this README):

| section | options |
|---|---|
| `global:` | `handshake_timeout` `connect_timeout` `idle_timeout` `half_close_timeout` · `max_connections` `max_handshakes_per_ip` `proxy_trust_source` `buffer_size` `buffer_pool_max_idle` `short_read_delay_us` `splice` · `http_to_https_redirect` `remember_nonce` · `allow_cache_size` `deny_cache_size` · `reload_interval` `stats_interval` · `cert_root` `expiry_threshold_days` `acme_agree_tos` `acme_email` `acme_directory` `acme_ca_file` `public_ip_address` `dns_resolvers` · ignored for compatibility: `io_model` `worker_threads` |
| `listeners:` (a list) | `name` `bind` `port` · `proxy_trust_source` `max_connections` `handshake_timeout` `idle_timeout` `half_close_timeout` `max_aggregated_speed` `max_single_connection_speed` |
| `routes:` (a list) | `listener` · `rules` |
| each of `rules` | `domain` `action` `target` · `cert` `cert_domains` `cert_validate_script` `cert_validate_args` `upstream_tls` `upstream_tls_verify` `upstream_sni` `proxy` · `max_aggregated_speed` `max_single_connection_speed` · `serve`, a list of (`type` `prefix` `target` `strip_prefix` `force_host` `tls_verify` `base_dir` `basic_auth`) |
| `basic_auth:` (a list) | `name` · `users`, a list of (`username` with `password_hash` or `password_plain`; `disabled`, `expires`) |
| `logging:` | `stdout` `stderr` `max_size` `max_keep` `compress_after` |
| the web console (not in the file) | `-console_domain` / `$CONSOLE_DOMAIN` · `$CONSOLE_PASSWORD` · `-console_bind` / `$CONSOLE_BIND` · `-console_port` / `$CONSOLE_PORT` · `-console_cert` / `$CONSOLE_CERT` · `-noconsole` |

`proxy_trust_source` was called `proxy_protocol_from` before v1.5.0; the old
name is a load error that shows the line to write instead.

### Samples

Each with its expected routing checked by `go test`:

| file | shows |
|---|---|
| [`01-basic`](samples/01-basic.yaml) | map `*.wushilin.net` to internal names with `${1}` |
| [`02-home-lab`](samples/02-home-lab.yaml) | several internal services behind one public IP; a literal deny that beats a broader allow |
| [`03-egress-allowlist`](samples/03-egress-allowlist.yaml) | outbound allowlist, one rule per name and depth, connecting to the real host with `${host}` |
| [`04-blocklist`](samples/04-blocklist.yaml) | pass everything except blocked names |
| [`05-default-backend`](samples/05-default-backend.yaml) | specific routes, then `$anything_else` as the default backend |
| [`06-multi-capture-rewrite`](samples/06-multi-capture-rewrite.yaml) | several `*` in one domain (`${1}`, `${2}`), a `*` inside a label |
| [`07-ipv6-and-tuning`](samples/07-ipv6-and-tuning.yaml) | IPv6 listener and target, timeouts, limits, buffers, quoted values |
| [`08-no-sni`](samples/08-no-sni.yaml) | `domain: $no_sni` for clients without SNI |
| [`09-tls-termination`](samples/09-tls-termination.yaml) | `cert: auto`, `cert_domains`, plaintext and TLS upstreams, pass-through side by side |
| [`10-logging`](samples/10-logging.yaml) | rotating, compressed log files |
| [`11-web-console`](samples/11-web-console.yaml) | the console on port 443 over TLS, with more rules on its listener `$console` |
| [`12-everything`](samples/12-everything.yaml) | every option, annotated |
| [`13-rule-precedence`](samples/13-rule-precedence.yaml) | literal, wildcard and `$anything_else` rules written broadest first, and which one wins |
| [`14-listeners`](samples/14-listeners.yaml) | several listeners (a public port and a VPN-only port), each with its own rules and overrides |

## Listeners

Every port the proxy listens on is an item of `listeners`, and a file needs
at least one (the console's counts), and every rule belongs to a listener:
the `listener` of its `routes` item. For more ports, each with its own rules:

```yaml
listeners:
  - name: public
    port: 443

  - name: lab
    bind: [10.11.12.212]
    port: 9092
    idle_timeout: 3600                # overrides global on this listener
    max_aggregated_speed: 200Mbit     # all connections on this listener together

routes:
  - listener: public
    rules:
      - domain: www.example.com
        target: "192.168.1.30:443"

  - listener: lab
    rules:
      - domain: kafka.example.com
        target: "10.11.12.50:9092"
```

| each of `listeners` | default | meaning |
|---|---|---|
| `name` | (required) | up to 64 letters, digits, spaces and `-` `_` `@` `#` `~` `(` `)` `[` `]` `<` `>` `"` `'`, no space at either end; unique, ignoring case. What `listener:` in `routes` refers to. Quote it when it has spaces or quotes: `name: "Kafka (EU)"`, `listener: "Kafka (EU)"` (the console does this for you) |
| `bind` | 0.0.0.0 | listen addresses, a list: `0.0.0.0` all IPv4, `::` all IPv6 and IPv4 (quoted: `["::"]`), or specific addresses, `[192.0.2.1, "2001:db8::1"]` |
| `port` | (required) | |
| `proxy_trust_source` `handshake_timeout` `idle_timeout` `half_close_timeout` | `global` | the same settings, for this listener only |
| `max_connections` | (none) | a cap for this listener, on top of the global `max_connections` |
| `max_aggregated_speed` `max_single_connection_speed` | unlimited | as for a rule (see [Speed limits](#speed-limits)), for every connection on this listener; they apply on top of each rule's own |

- `bind` and `port` exist only in `listeners`. In `global` they are a load
  error; the message shows the listener to write instead. (Before v1.4.1
  they made an implicit listener named `default`.)
- Each listener has its own rules, so the same domain can appear on several
  listeners, and a name that matches nothing *on that listener* is denied.
  Several `routes` items may name the same listener; their rules add up.
- A `routes` item without `listener`, or naming a listener that doesn't
  exist, is a load error.
- Two listeners cannot share a port on the same (or a wildcard) address.
- **The web console's listener** is named `$console`, whatever its port:
  list it by that name with its other options only, no `bind` or `port`, and
  route rules to it. See [Web console](#web-console). Without a console,
  `$console` is an error and nothing is reserved; `https` is an ordinary name
  either way.
- **Listeners follow hot reload.** A new listener opens its port, a changed
  `bind` or `port` moves it, and a removed one closes its port, all without a
  restart; connections already open carry on. If a port cannot be opened (in
  use, say), at start-up or on a reload, that is logged and shown in the
  console (where Start retries it), and the other listeners keep working.
  The proxy refuses to start only when no listener can open its port.
- `--test` and the console's routing tests answer for every listener.

### HTTP to HTTPS redirect

```yaml
global:
  http_to_https_redirect: true      # default false
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
- The name `http-to-https-redirect` is reserved: no listener and no
  `routes` item may use it. A listener of your own on port 80 at an address the
  redirect also binds is a load error.
- It follows hot reload: setting it opens port 80, clearing it closes the
  port. In the console it is a listener card with Stop/Start and its open
  connections, but no Edit, Delete or rules. Each connection is in the flow
  log, and each request is a line in the log:
  `[#12] redirect GET http://www.example.com/a -> https://www.example.com/a (301)`.
- It plays no part in ACME, which only uses TLS-ALPN-01 on port 443.
- With Docker, publish the port too: `-p 80:80`.

### Loop detection (`remember_nonce`)

A rule can send a connection back to this proxy: `domain: $anything_else` with
`target: "${host}:443"` and a client asking for a name that resolves to this
machine (or to 127.0.0.1), or a target that is another of its listeners.
Each hop would open the next until `max_connections` runs out. With
`remember_nonce: true` (the default) the proxy remembers a hash of every
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

- **Several addresses.** `bind: [192.0.2.1, "2001:db8::1"]` listens on exactly
  those, each for its own family.
- **Clients.** `bind: ["::"]` listens on IPv6 **and** IPv4 with one socket;
  `0.0.0.0`, the default, is IPv4 only (enforced: left to itself Go would make
  it dual-stack); a specific address of either family
  works too, and `[::]` is accepted as a spelling of `::`. Client addresses are
  logged as `[2001:db8::5]:49943`, IPv4 clients of a dual-stack listener as
  plain `10.0.0.5:49943`.
- **Targets.** A `target` may be an IPv6 address, in brackets before the
  port (`target: "[2001:db8::10]:443"`, or `"[fe80::1%em0]:443"` with its zone
  for a link-local address); logs show it the same way. A host name with
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
  not reach the proxy. `dns_resolvers` may be IPv6 (`"2606:4700:4700::1111"`, or
  `"[2606:4700:4700::1111]:53"` with a port; quoted in YAML).
- The console's `-console_bind` follows the same rules (several addresses
  separated by `;` or `,`: `-console_bind '192.0.2.1;2001:db8::1'`).

## Serving HTTP here (serve entries)

A rule can answer HTTP requests itself instead of connecting to a target:
give it `serve`, a list of entries. The proxy terminates TLS as for any
`cert` rule and hands the connection straight to an HTTP server inside the
process, with no second hop, no extra port and no PROXY header to set up:
the client's address is the connection's own.

```yaml
routes:
  - listener: https
    rules:
      - domain: www.example.com
        cert: auto
        serve:
          - {type: reverse_proxy, prefix: /, target: "http://127.0.0.1:8080"}
          - {type: reverse_proxy, prefix: /api/, target: "http://127.0.0.1:7882", strip_prefix: true, basic_auth: team}
          - {type: static_content, prefix: /assets/, base_dir: /opt/www/www.example.com/assets}

basic_auth:
  - name: team
    users:
      - {username: jack, password_hash: "$argon2id$v=19$m=65536,t=3,p=4$..."}
      - {username: jill, password_plain: "open sesame"}
```

- **The rule.** A rule with `serve` needs `cert: auto` or `local-ca` (the
  proxy has to decrypt the requests) and takes no `target`, `upstream_*` or
  `proxy`; speed limits apply as usual. (Before v1.5.0 these were
  `service_rule` keys.)
- **Each entry** is a mapping (an unknown key, or one given twice, is a load
  error):
  - `type: reverse_proxy`: `target: "http://host:port"` or `https://host:port`
    (no path), `strip_prefix: true` sends `/api/x` as `/x`,
    `force_host: name` replaces the Host sent on (default: the client's),
    `tls_verify: false` skips checking an `https://` target's certificate.
  - `type: static_content`: `base_dir: /folder`. The prefix stands for the
    folder, so `/assets/a.css` is `base_dir/a.css` (as nginx's `alias`); it
    ends in `/`. `GET` and `HEAD` only, `index.html` for a folder, never a
    listing, nothing hidden (a path part starting with `.`) except
    `.well-known` at its top, nothing through a symlink that leads out
    (`os.Root`). A `base_dir` that can't be opened answers `503`.
  - `basic_auth: <name>` on either type asks for a user of the `basic_auth`
    item with that name; the `Authorization` header is not passed on.
- **Matching.** The longest `prefix` that matches the path serves the
  request, wherever it stands in the list; the same prefix twice is a load
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
  serve entry that served it, status, size and time.
- **`basic_auth`** is a list of items, each a `name` (unique) and `users`, a
  list of `{username, password_hash}` or `{username, password_plain}` (quote
  a hash: it starts with `$`). `tlsproxy --hash-password` prints an argon2id
  hash; argon2id hashes from other tools and the older `pbkdf2-sha256` format
  work too. A user with `disabled: true` is refused even with the right
  password, at once; one with `expires: 2026-12-31` signs in through the end
  of that day (UTC), or give an RFC 3339 time (`2026-12-31T18:00:00+08:00`);
  no `expires` is never. The log says why a sign-in was refused (no user,
  wrong password, disabled, expired); the client only gets `401`. A browser
  sends the password with every request, so one that
  matched is remembered (in memory) for 5 minutes, and at most two hashes are
  worked out at once. The same name twice, or the same user twice in an
  item, is a load error; an item no serve entry uses is a warning.
- **In the console**, the rule editor's *Serve it here* takes the serve
  entries as rows of a form, checked as you type, and saves them as the
  rule's `serve` list; a row's basic auth is chosen from the existing groups.
  The groups themselves are managed on the console's **Basic auth** page.

## The client's address (PROXY protocol)

A backend behind the proxy sees every connection coming from the proxy. The
ClientHello cannot carry the client's address: TLS covers every byte of the
handshake, so a hello changed in transit fails. The PROXY protocol solves it
without touching TLS: a small header is sent as the very first bytes of the
upstream connection, and the untouched stream follows.

```yaml
routes:
  - listener: https
    rules:
      - domain: www.example.com      # passed through: header, then the client's ClientHello as it was
        target: "192.168.1.30:443"
        proxy: v2                    # default none; v2 is binary, v1 the text form

      - domain: api.example.com      # terminated: header, then our upstream TLS handshake (or plaintext)
        cert: auto
        upstream_tls: false
        target: "192.168.1.31:8080"
        proxy: v1
```

- The header states the client's address and port, and the address and port it
  connected to. IPv4 and IPv6; if the two differ in family, the IPv4 one is
  written in its IPv4-mapped form. The `connected` log line says `PROXY v2
  header sent`. (Before v1.5.0 this was `proxy = true` with
  `proxy_version`.)
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

```yaml
      - domain: "*.downloads.example.com"
        target: "10.0.0.20:443"
        max_aggregated_speed: 1Gbit             # all connections of this rule together
        max_single_connection_speed: 15MiB/s    # each connection
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
- On a reload, a rule whose `domain` and `max_aggregated_speed` are unchanged
  keeps its shared budget, so connections from before and after the reload
  share it. A changed rate starts a new budget; connections already open
  keep the one they started with.
- The `connected` log line notes the limits that apply.

## TLS termination and automatic certificates

Without `cert`, a rule passes TLS through untouched (the backend keeps its own
certificate). With `cert`, the proxy terminates TLS for that rule:

```yaml
global:
  cert_root: /var/db/tlsproxy/certs
  acme_agree_tos: true                  # required for cert: auto
  acme_email: admin@example.com         # optional
  public_ip_address: [203.0.113.7]      # only ask the CA for names that point here
  dns_resolvers: [1.1.1.1, 8.8.8.8]     # public DNS servers for that check

routes:
  - listener: https
    rules:
      - domain: nas.example.com           # literal domain: the name comes from it
        cert: auto
        target: "192.168.1.10:5001"
        upstream_tls_verify: false        # the NAS has a self-signed certificate
        proxy: v2                         # send the original connection addresses first (v2 or v1)

      - domain: "*.example.com"           # wildcard: list the exact names
        cert: auto
        cert_domains: [www.example.com, blog.example.com]
        target: "192.168.1.30:8080"
        upstream_tls: false               # plain HTTP backend

      - domain: intranet.example.com
        cert: local-ca                    # your own CA: ca001 in cert_root, made at start-up
        target: "192.168.1.40:443"
```

| per rule | default | meaning |
|---|---|---|
| `cert` | (none) | `auto`: issue and renew via ACME. `local-ca` or `local-ca:ca002`: your own CA issues a certificate per name, or per IP address for clients without SNI (see [Your own CA](#your-own-ca-cert--local-ca)); the CA must exist (made on the Certificates page). None: pass through |
| `cert_domains` | from a literal domain | a list of exact names to issue. Required when `domain` has a `*` or is `$anything_else`, unless a `cert_validate_script` decides (start-up error otherwise). Each must match the domain. No wildcards: TLS-ALPN-01 can't issue them |
| `cert_validate_script` | (none) | decides about names that match the domain but are not in `cert_domains`; see below. Must exist and be executable at start-up and on reload |
| `cert_validate_args` | `["${host}"]` | the script's arguments, a list of strings. Each is fixed text with `${1}`, `${2}`, ... and `${host}` filled in as in `target`, e.g. `["--customer", "aaa-${1}", "${host}"]`. One argument stays one argument, spaces and all |
| `upstream_tls` | true | speak TLS to the target; `false` = plaintext |
| `upstream_tls_verify` | true | verify the target's certificate against the system roots |
| `upstream_sni` | the client's SNI | name sent to the target as SNI, and the name its certificate is verified against. The default passes the client's name through, so a target that routes or selects certificates by SNI works even when the `target` is an IP address |
| `proxy` | none | `v1` or `v2`, for **any** allow rule, passed through or terminated: tell the target the client's address with a PROXY protocol header of that version. See [The client's address](#the-clients-address-proxy-protocol) |

| `global` | default | meaning |
|---|---|---|
| `cert_root` | ./certs | every certificate: `<cert_root>/acme/<name>/cert.pem`, `key.pem` (mode 0600), the ACME account key in `acme/_account/`, and your CAs in `ca001/`, `ca002/`, ... (was `cert_path` and `cert_root` before v1.5.0) |
| `expiry_threshold_days` | 15 | renew this long before expiry, or when a third of the lifetime is left if that is later (short-lived certificates) |
| `acme_agree_tos` | false | must be `true` before anything is issued |
| `acme_email` | (none) | contact for the ACME account |
| `acme_directory` | Let's Encrypt production | use `https://acme-staging-v02.api.letsencrypt.org/directory` while testing |
| `acme_ca_file` | (none) | extra root for the ACME server's own HTTPS (private CA, Pebble) |
| `public_ip_address` | (none) | a list, IPv4 and IPv6. A name is only sent to the CA if **all** its public addresses (A and AAAA) are among these; without it the check is skipped (with a warning) |
| `dns_resolvers` | (required with `cert: auto` and `public_ip_address`) | a list of public DNS servers for that check, IP or IP:port: three attempts, each the next server in turn and given 3 s (not configurable); no answer is a no. E.g. `[1.1.1.1, 8.8.8.8, "2606:4700:4700::1111"]`; deliberately not the local one, which may return LAN addresses |

### Your own CA (`cert: local-ca`)

For names a public CA can't or shouldn't issue (internal hosts, no public
DNS, wildcards), the proxy runs CAs of its own, or uses your organisation's:

```yaml
global:
  cert_root: /var/db/tlsproxy/certs     # default ./certs

routes:
  - listener: https
    rules:
      - domain: "*.lab.internal"
        cert: local-ca:ca002            # plain "local-ca" is ca001
        cert_domains: ["*.dev.lab.internal", git.lab.internal]   # optional: names or globs; others are refused
        target: "10.0.0.30:443"
        upstream_tls: false
```

```
<cert_root>/ca002/ca_cert.pem             the CA (then its issuers, for an intermediate)
<cert_root>/ca002/ca_key.pem              its private key
<cert_root>/ca002/config.yaml             its settings (below)
<cert_root>/ca002/git.lab.internal/       one folder per name it issued: cert.pem, key.pem
<cert_root>/ca002/ip_203.0.113.5/         the same for clients without a host name (below)
<cert_root>/ca002/_archive/<name>-<time>  certificates it did not issue, moved aside
<cert_root>/ca001/...                     the default CA, the same way
<cert_root>/acme/<name>/                  the automatic certificates (cert: auto), and acme/_account/
```

`acme` is never a CA's folder: a CA's id is always `ca` and three digits.

- **Clients without SNI** (they connect by IP address: `https://203.0.113.5/`)
  get a certificate too, with `domain: $no_sni` (or `$anything_else`). Only `local-ca`
  can do this; `cert: auto` on a `$no_sni` rule is a load error, since ACME
  issues for host names.

  ```yaml
        - domain: $no_sni
          cert: local-ca
          cert_domains: [203.0.113.5, 198.51.100.7, gw.lab.internal]   # optional
          upstream_tls: false
          target: "127.0.0.1:1081"
  ```

  - Without `cert_domains`: one certificate for the address the client
    connected to (the destination in a PROXY header, if one came in). With
    two addresses on the box, a client gets the one it used.
  - With IP addresses in `cert_domains`: **one** certificate holding all of
    them, plus a `$no_sni` rule's host names, whichever address the client
    used. That is what works behind NAT, where the box only sees its private
    address and can't tell which public one the client typed. Every client
    sees the whole list in the certificate.
  - IP addresses in `cert_domains` are only for `$no_sni` and `$anything_else` rules. On
    an `$anything_else` rule they cover clients without SNI; its host names and globs
    keep limiting the names that do send one (a list of addresses alone
    issues for no host name).
  - RFC 6066 forbids an IP address as SNI, but some clients send one. It is
    routed as no SNI (so `target: "${host}:443"` can't be pointed at an
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
- **The default CA, `ca001`**, is made at start-up when `cert_root` has none,
  whether a rule uses it or not: "Local CA", ECDSA P-256, valid 20 years. The
  log names its certificate (`<cert_root>/ca001/ca_cert.pem`, to install in the
  clients that should trust it) with its fingerprint. Plain `cert: local-ca`
  names it, so the first local-CA setup needs no other step.
- **Other CAs** are made on the console's **CAs** page (generate one, or
  import yours: a CA certificate with its chain and its private key); a rule
  naming one that does not exist is a config error. A self-signed CA is renewed before it
  expires with the same key and subject, so certificates it issued stay
  valid; an imported intermediate is reported as it nears expiry (renew it
  where it came from and import again). Certificates from an intermediate are
  sent with its chain, without the root, so clients that trust your
  organisation's root accept them. A CA is deleted only when no rule uses it
  (moved to `<cert_root>/_archive`, removed after 14 days); its id is not
  reused.
- **Each CA's `config.yaml`** is written when the CA is made, read again
  whenever it changes (a broken edit keeps the previous settings, logged and
  shown on the Certificates page, one sub-tab per CA), and editable there with *Settings*:

  ```yaml
  ca:                       # how the CA was made: fixed, can't be changed
    common_name: "Home lab CA"
    organization: tlsproxy
    key_algorithm: ecdsa    # ecdsa, rsa or ed25519
    key_bits: 256           # ecdsa 256/384/521, rsa 2048/3072/4096
    hash_algorithm: sha256  # sha256, sha384, sha512 (its own renewals)
    validity_days: 3650

  certificates:             # what it issues: editable
    key_algorithm: ecdsa
    key_bits: 256
    hash_algorithm: sha256  # the CA's signature on them
    validity_days: 90
    renew_before_days: 0    # 0 = when a third of the lifetime is left
    key_usage: [digitalSignature]   # add keyEncipherment for RSA keys and old clients
    ext_key_usage: [serverAuth]     # serverAuth, clientAuth
    organization: ""                # subject fields; the common name is always the name
    organizational_unit: ""
    country: ""
    province: ""
    locality: ""
  ```

  A `config.toml` from before v1.5.0 is not read: the CA keeps its default
  settings, and the log and the Certificates page say to write `config.yaml`.

  `ca` is set by *Generate* (common name, organisation, key, hash,
  validity) and checked against the CA certificate on every read: an edit
  that changes it is refused, since a CA's key or name can't change without
  breaking everything it issued. Renewal reuses what the CA was made with.
  `certificates` changes apply to new certificates and renewals. ECDSA and
  Ed25519 keys take well under a millisecond to make; RSA keys take far
  longer (about 0.1 s for 2048 bits, seconds for 4096), and the first
  handshake for a new name waits for its key: prefer ECDSA unless clients
  need RSA.
- **No races.** A current certificate is found without a lock. Loading one
  from disk, issuing, renewing, archiving and writing its files hold that
  name's lock, so racing handshakes for a new name get one certificate
  between them. Making, renewing or deleting a CA and saving its settings
  hold that CA's lock; choosing a new CA's id holds the `cert_root`'s.
- **Clients must trust the CA**: download its certificate from its sub-tab on the Certificates page
  (the private key is never offered) and add it to their trust store.
- **`cert_domains` says which names get a certificate**: host names or globs
  written like domains (`["*.dev.abc.com", "*.prod.abc.com", "*.abc.com"]`; a `*`
  never crosses a dot). Any other name is refused: no certificate, no
  placeholder, the target is not contacted, and the flow log says why.
  Without it, every name the rule matches gets one, at most 10000 per CA
  (beyond that, names are refused and it is logged).

**Names decided by a script.** When the names are not known in advance
(customer subdomains, say), let a script decide per name:

```yaml
      - domain: "*.customers.example.com"
        cert: auto
        cert_domains: [www.customers.example.com]   # optional: always issued, never put to the script
        cert_validate_script: /usr/local/etc/tlsproxy/domains.sh
        # cert_validate_args: ["${host}"]           # the default: the name alone
        target: "192.168.1.50:443"
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
  restart for names whose certificate in `<cert_root>/acme` is still good.
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
  progress here and `upstream_tls: true` (normal traffic for that name is
  still terminated here). With a plaintext upstream nobody could answer, so
  it is refused.
- **Urgent first, up to 4 names at once.** At startup and every 10 minutes:
  names with no or an expired certificate first, then renewals by due date.
  Names don't depend on each other, so a slow one (a hanging validation, a
  slow script) doesn't hold up the rest; one name never has two jobs running
  at the same time. A failure is retried after 6 hours. Certificates found in `<cert_root>/acme` are
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
  domain but missing from `cert_domains`, or refused by the script) a
  self-signed placeholder keeps the service reachable, with a browser warning.
  A name from `cert_domains` gets its own. Names chosen by clients never do:
  they share **one placeholder per rule**, a wildcard (`*.s3.example.com`) when
  the domain is one, so a flood of made-up names costs no key generation or
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
stderr. Add a `logging` section to write to files instead, with rotation,
gzip compression and pruning built in (no `newsyslog`/`logrotate` needed):

```yaml
logging:
  stdout: /var/log/tlsproxy/stdout.log   # activity: accepted / route / connected / closed, stats, reloads
  stderr: /var/log/tlsproxy/stderr.log   # problems: accept errors, failed reloads, ...
  max_size: 15MiB        # rotate once a file reaches this (K / M / G); default 15MiB
  max_keep: 10           # generations kept: file.1 (newest) .. file.10; default 10
  compress_after: 3      # file.1-.3 stay plain, file.4.gz and older are gzip; default 3
```

- With a file set, nothing of that stream reaches the terminal. Either key may
  be omitted, and both may name the same file. Relative paths are relative to
  the working directory.
- Rotation is numbered: `stdout.log` → `stdout.log.1` → `.2` → ... Generations
  above `compress_after` are gzip files (`stdout.log.4.gz`); anything beyond
  `max_keep` is deleted. `compress_after >= max_keep` disables compression and
  `max_keep: 0` just starts the file over.
- Compression is done **in-process**, in the background, under a **compress
  guard**: until it finishes the log does not rotate again, so the numbering
  can never shift under the compressor. The live file simply grows past
  `max_size` in the meantime; nothing blocks and nothing is lost.
- The settings follow hot reload. If a new log file can't be opened, the
  previous destinations stay in use.

## Web console

A console: live listeners, rules and connections, all editable (start, stop,
add, edit, delete), a flow log, certificates, the recent log and a config
editor. It is served under `/tlsproxy_quick/`; `/` redirects there.

It is **on by default**, and its settings are not in `config.yaml`: they are
given at start-up, with flags or environment variables, so no edit made from
the console can change its password or take it off the network:

```sh
CONSOLE_PASSWORD='change-me' tlsproxy config.yaml -console_domain admin.example.com
tlsproxy config.yaml -noconsole                     # no console at all
```

| setting | default | meaning |
|---|---|---|
| `-console_domain` or `$CONSOLE_DOMAIN` | (required) | the name it is served under, as a rule of its listener that `config.yaml` can't override. A host name: no `*`, no IP address |
| `$CONSOLE_PASSWORD` | (required) | the password, hashed at start-up, or a hash: `$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>` (argon2id, 64 MiB, 3 passes) from `tlsproxy --hash-password`, or `pbkdf2-sha256$<iterations>$<salt>$<hash>` from older versions. Only in the environment, never a flag, so it is not in the process list |
| `-console_bind` or `$CONSOLE_BIND` | 0.0.0.0 (all IPv4 addresses) | where it listens; several addresses separated by `;` or `,` |
| `-console_port` or `$CONSOLE_PORT` | 443 | its port |
| `-console_cert` or `$CONSOLE_CERT` | auto | `auto` (ACME; needs `acme_agree_tos: true` in `config.yaml`) or `local-ca` (the default CA, `ca001`, always there) / `local-ca:ca002` (must exist) |
| `-noconsole` | | no console; together with any of the flags above it is an error |

Without a domain and a password the proxy refuses to start and says what is
missing. A flag wins over its variable. Flags take one dash or two, and
`-flag value` or `-flag=value`, after the config file's name:
`tlsproxy [config.yaml] [-noconsole] [-console_domain x] ... [--test <sni>...]`.
A `--test` dry run doesn't need the console's settings (without them it
routes without the console). A `console:` section in `config.yaml` is an
error that says to use the flags. (Before v1.5.0 the console had a
`[console]` section, then a `console.toml` of its own given with
`--console`; neither exists any more.)

**Always over TLS, in-process.** The console is served like a rule with
`serve` entries, inside the TLS connection the proxy terminates, with a
certificate for its domain (until there is one, a self-signed placeholder).
Session cookies are always `Secure`.

**It owns a listener**, named `$console` on any port, on its bind and port:

- That listener's name, bind and port, and the console's rule for its
  domain, are fixed. `config.yaml` may list the listener by name with its
  other options only (`proxy_trust_source`, `max_connections`, the timeouts,
  the speed limits; a `bind` or `port` there is an error), and `routes` may
  add rules to it, so the console and your sites share port 443. The name is
  the same whatever the port, so `-console_port` can change without
  editing the file:

  ```yaml
  global:
    acme_agree_tos: true            # for the console's cert: auto

  listeners:
    - name: $console                # the console's: no bind, no port
      max_connections: 512

  routes:
    - listener: $console
      rules:
        - domain: www.example.com
          target: "10.0.0.10:443"
        - domain: $anything_else               # doesn't take the console's name: an exact name always wins
          action: deny
  ```

- A rule for the console's exact domain on that listener is an error.
  Wildcards and `$anything_else` don't take it, since an exact name always wins.
- Another listener with exactly the console's bind and port is an error; one
  with a different bind on the same port is allowed.
- The console can't stop its rule or its listener.
- Without a console (`-noconsole`) nothing is reserved: you define and name
  all listeners yourself, and `$console` is an error.

With `cert: auto` the CA validates the console's name on public port 443, so
a console on another port gets its certificate only if that name also reaches
port 443 here; otherwise use `-console_cert local-ca` (make the CA on the
Certificates page first) or keep the placeholder.

The console's settings are read once, at start-up: a change needs a restart.
`config.yaml` follows hot reload as usual, and every version of it is loaded
with the console's listener and rule in place: at start-up, on reload, and
for every check and save in the console, so what passes a check is what a
reload runs.

**Pages**

The config file stays the source of truth: everything the console changes is
written to it (and every change to the file shows up in the console).

- **Listeners** (live: the state is pushed over a WebSocket, a frame only when
  something changed): totals, rates and a 2-minute throughput trace on top,
  then one card per listener (its addresses, overrides, connections and
  rates), and inside it one card per rule of that listener in file
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
    (another wildcard, `$anything_else`, or nothing: denied), and its open connections
    are closed. Stopping is not written to the file: it lasts until Start or
    a restart, and survives reloads.
  - **Add / Edit a rule** with a guided form: what to match, where to send
    it, then TLS, PROXY protocol and speed limits, showing only the fields
    that apply. Every change is validated against the whole file as you type,
    with a preview of the exact rule that will be written and a
    "try a name" box showing where sample names would be routed. Saving
    changes only that rule's item in the file (comments and the rest of the
    file are kept; the YAML library sets the spacing),
    with the same checks and backup as the config editor below, and applies
    it at once.
  - **Delete a rule**: its item leaves the file. Its open connections keep running until they end.
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
- **Basic auth**: one card per `basic_auth` group, with its users and the
  serve entries that use it. Add or delete a group (one still used by a serve
  entry can't be deleted), rename it (its serve entries are renamed with it),
  add or delete a user (a group keeps at least one), and set a user's
  password. A password typed here is hashed in the proxy (argon2id) before
  it is written as `password_hash`, replacing a `password_plain`; no password
  or hash is ever sent back to the page. Each user is a row of a table: its
  password kind, its status (active, disabled, expired), when it expires
  (never by default), and its buttons: Set password, Disable / Enable, Set
  expiry, Delete. Saved like every other edit.
- **Certificates**: every certificate in use, both those the proxy manages
  (`cert: auto`) and those your CAs issued (`cert: local-ca`): status (`ok`,
  `expiring`, `expired`, `missing`, `failing`), issuer, validity, days left,
  renewal date, the rules using it, the last error and next attempt, and a
  "retry now" button that skips the 6-hour wait.
- **Log**: the most recent 2,000 lines of both streams, filterable (for
  example by `[#42]` or a host name), wherever the log is configured to go.
- **Config file**: a text editor for the whole file, with line numbers.
  - *Validate* and *Test routing* work on the text in the editor, saved or not.
    *Validate* answers green with a tree of the settings the proxy would run
    with (each value marked when it is a default or inherited from
    `global`), yellow for each warning, red for an error, each with its
    line, which one click selects in the editor.
  - *Reference* (ⓘ) lists every key, by section, with its default and
    meaning; filter by name or word, click a key to copy `key: `. It is
    generated from the code, and a test keeps it complete.
  - *Save & apply* validates first (an invalid config is never written, and a
    `cert: local-ca` naming a CA that doesn't exist counts as invalid), keeps the previous
    file as `config.yaml.<timestamp>.bak` (the last 10, loadable from the
    editor), and applies the change at once.
  - **Saves are race free**, here and in the rule editor. Every
    read-check-write of the file happens under one lock in the proxy, and a
    save must present the modification time and content hash the page
    loaded. If the file was changed by anything else in between (vim, another
    session), that save fails and nothing is
    written.
  - The editor edits `config.yaml` only; the console's own settings are not
    in it, so nothing saved here can change them. Text with a `console:`
    section is rejected.

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
- `splice: false` in `global` turns it off. macOS, FreeBSD and Windows
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
  close to match (see [Listeners](#listeners)); only the console's own
  settings need a restart.
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
- **The same with `cert: auto`.** Every backend, PROXY out and PROXY in, with
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
  imported intermediates served with their chain, refusals, the CA's
  `config.yaml` (what `certificates` changes, `ca` locked), and the console's Certificates page (a sub-tab per CA).
- **Unit:** ClientHello parsing (every prefix of a fragmented hello,
  post-quantum sizes, malformed input), config parsing and errors, routing,
  LRU eviction order and caps, a denial flood that cannot evict allowed
  names, the buffer pool, formatting. Every `samples/*.yaml` must route as its
  `#> sni => target` comments say, and every default documented in
  `config.yaml` must match the code.
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
