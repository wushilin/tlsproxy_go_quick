# tlsproxy_go_quick

An **extremely simple SNI router for a gateway**. It listens on one port,
reads the hostname in the TLS ClientHello (SNI), picks a backend from
`config.toml`, and relays the still-encrypted bytes to it. By default it never
decrypts anything, so it needs no certificates or keys. Per host it can
instead **terminate TLS**, with certificates issued and renewed automatically
by Let's Encrypt over TLS-ALPN-01 (port 443 only, no port 80), or loaded from
a directory.

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
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o tlsproxy .
./tlsproxy config.toml                                 # run (logs to stderr)
./tlsproxy config.toml --test foo.wushilin.net x.com   # dry run: show routing only
./tlsproxy config.toml --test ""                       # dry run for a client without SNI
go test ./...                                          # ~25 s
```

## Configuration

```toml
[global]
bind = 0.0.0.0
port = 443

[[host]]
pattern = (.*)\.wushilin\.net
action = allow
target_host = $1.wushilin.internal.net
target_port = 443

[[host]]
pattern = .*
action = deny
```

- Rules are checked top to bottom. **The first match wins.** A hostname that
  matches no rule is denied.
- `pattern` is a regular expression ([RE2 syntax](https://pkg.go.dev/regexp/syntax))
  that must match the **whole** SNI, ignoring case. Matching time is linear
  in the name length, whatever the pattern.
- `target_host` can use `$1` / `${1}` for capture groups; `$0` is the whole
  SNI. A reference to a group that doesn't exist is rejected at load time.
- The port is always separate: `target_host` is a name or an IP address (IPv6
  without brackets) and the port goes in `target_port`. `target_host =
  10.0.0.1:8080` is rejected at load time.
- `action` is `allow` (the default) or `deny`. A denied client gets a TLS
  `access_denied` alert. `target_port` defaults to 443.
- `pattern = NONE` (any letter case) matches only clients that send **no SNI**,
  for example to send them to a default target; its `target_host` must be a
  literal. For regex patterns a missing SNI is matched as the empty string, so
  a catch-all `.*` also catches it. A host literally named `none` is matched
  with `^none$`.
- Values may be bare, `"double-quoted"` or `'single-quoted'`. `#` starts a comment.

Optional `[global]` settings; [`config.toml`](config.toml) lists every one
with its default, and a test keeps that file in step with the code:

| key                    | default | meaning                                                              |
|------------------------|---------|----------------------------------------------------------------------|
| `bind`                 | 0.0.0.0 | listen address (`::` for IPv6)                                       |
| `handshake_timeout`    | 10      | seconds to receive the whole ClientHello (a slow trickle can't extend it) |
| `connect_timeout`      | 10      | seconds to resolve and connect to the target                         |
| `idle_timeout`         | 600     | close after N seconds with no traffic in either direction (0 = never); also reaps half-open connections |
| `half_close_timeout`   | 30      | after one side closes, the other side gets N seconds to finish (0 = unlimited) |
| `max_connections`      | 1024    | further connections are rejected; goroutines ≤ 2 × this              |
| `buffer_size`          | 65536   | bytes per pooled buffer; each open connection holds two              |
| `buffer_pool_max_idle` | 3 × max_connections | capacity of the pool's channel                           |
| `allow_cache_size`     | 4096    | LRU cache of allowed SNI → target decisions (0 = off)                |
| `deny_cache_size`      | 4096    | separate LRU cache of denied SNIs (0 = off)                          |
| `reload_interval`      | 5       | check the config file every N seconds and apply changes; minimum 5, 0 = never |
| `stats_interval`       | 60      | log a one-line state summary every N seconds; 0 = never              |
| `short_read_delay_us`  | 0       | pause N µs after a short read so data batches up. Measured in Go: a few percent more throughput at best, +37 µs (50) or +210 µs (200) per round trip, so leave it off unless your box shows otherwise |

The legacy keys `io_model` and `worker_threads` are accepted and ignored (with
a log line), so older config files keep loading.
All options, by section, with a complete example in
[`samples/12-everything.toml`](samples/12-everything.toml) (a test fails if an
option is missing from it, from `config.toml` or from this README):

| section | options |
|---|---|
| `[global]` | `bind` `port` · `handshake_timeout` `connect_timeout` `idle_timeout` `half_close_timeout` · `max_connections` `buffer_size` `buffer_pool_max_idle` `short_read_delay_us` · `allow_cache_size` `deny_cache_size` · `reload_interval` `stats_interval` · `cert_path` `expiry_threshold_days` `acme_agree_tos` `acme_email` `acme_directory` `acme_ca_file` `public_ip_address` `dns_resolvers` · ignored for compatibility: `io_model` `worker_threads` |
| `[[host]]` | `pattern` `action` `target_host` `target_port` · `cert` `cert_domains` `cert_validate_script` `upstream_tls` `upstream_tls_verify` `upstream_sni` |
| `[logging]` | `stdout` `stderr` `max_size` `max_keep` `compress_after` |
| `[console]` | `listen` `port` `password` `password_hash` `hostnames` |

Samples, each with its expected routing checked by `go test`:

| file | shows |
|---|---|
| [`01-basic`](samples/01-basic.toml) | map `*.wushilin.net` to internal names with a capture group |
| [`02-home-lab`](samples/02-home-lab.toml) | several internal services behind one public IP; a deny ahead of a broader allow |
| [`03-egress-allowlist`](samples/03-egress-allowlist.toml) | outbound allowlist, connecting to the real host with `$0` |
| [`04-blocklist`](samples/04-blocklist.toml) | pass everything except blocked names |
| [`05-default-backend`](samples/05-default-backend.toml) | specific routes, then a catch-all backend |
| [`06-multi-capture-rewrite`](samples/06-multi-capture-rewrite.toml) | several capture groups, `${1}` form |
| [`07-ipv6-and-tuning`](samples/07-ipv6-and-tuning.toml) | IPv6 listener, timeouts, limits, buffers, quoted values |
| [`08-no-sni`](samples/08-no-sni.toml) | `pattern = NONE` for clients without SNI |
| [`09-tls-termination`](samples/09-tls-termination.toml) | `cert = auto`, `cert_domains`, plaintext and TLS upstreams, pass-through side by side |
| [`10-logging`](samples/10-logging.toml) | rotating, compressed log files |
| [`11-web-console`](samples/11-web-console.toml) | the console on loopback, published through a terminating rule |
| [`12-everything`](samples/12-everything.toml) | every option, annotated |

## TLS termination and automatic certificates

Without `cert`, a rule passes TLS through untouched (the backend keeps its own
certificate). With `cert`, the proxy terminates TLS for that rule:

```toml
[global]
port = 443
cert_path = /var/db/tlsproxy/certs
acme_agree_tos = true                 # required for cert = auto
acme_email = admin@example.com        # optional
public_ip_address = 203.0.113.7       # only ask the CA for names that point here

[[host]]
pattern = nas\.example\.com           # literal pattern: the name comes from it
cert = auto
target_host = 192.168.1.10
target_port = 5001
upstream_tls_verify = false           # the NAS has a self-signed certificate

[[host]]
pattern = (www|blog)\.example\.com    # regex: list the exact names
cert = auto
cert_domains = www.example.com, blog.example.com
target_host = 192.168.1.30
target_port = 8080
upstream_tls = false                  # plain HTTP backend

[[host]]
pattern = intranet\.example\.com
cert = /usr/local/etc/ssl/intranet    # cert.pem (leaf + chain), key.pem, optional ca.pem
target_host = 192.168.1.40
```

| per rule | default | meaning |
|---|---|---|
| `cert` | (none) | `auto`: issue and renew via ACME. `<dir>`: use `cert.pem` + `key.pem` (+ `ca.pem`) from that directory; must exist at startup, re-read when the files change. None: pass through |
| `cert_domains` | from a literal pattern | exact names to issue, separated by `,` or `;`. Required when `pattern` is a regex, unless a `cert_validate_script` decides (start-up error otherwise). Each must match the pattern. No wildcards: TLS-ALPN-01 can't issue them |
| `cert_validate_script` | (none) | decides about names that match the pattern but are not in `cert_domains`; see below. Must exist and be executable at start-up and on reload |
| `upstream_tls` | true | speak TLS to the target; `false` = plaintext |
| `upstream_tls_verify` | true | verify the target's certificate against the system roots |
| `upstream_sni` | the client's SNI | name sent to the target as SNI, and the name its certificate is verified against. The default passes the client's name through, so a target that routes or selects certificates by SNI works even when `target_host` is an IP address |

| `[global]` | default | meaning |
|---|---|---|
| `cert_path` | ./certs | `<cert_path>/<name>/cert.pem`, `key.pem` (mode 0600); account key in `_account/` |
| `expiry_threshold_days` | 15 | renew this long before expiry, or when a third of the lifetime is left if that is later (short-lived certificates) |
| `acme_agree_tos` | false | must be `true` before anything is issued |
| `acme_email` | (none) | contact for the ACME account |
| `acme_directory` | Let's Encrypt production | use `https://acme-staging-v02.api.letsencrypt.org/directory` while testing |
| `acme_ca_file` | (none) | extra root for the ACME server's own HTTPS (private CA, Pebble) |
| `public_ip_address` | (none) | `;`-separated. A name is only sent to the CA if it publicly resolves to one of these; without it the check is skipped (with a warning) |
| `dns_resolvers` | 1.1.1.1; 8.8.8.8 | resolvers for that check; deliberately not the local one, which may return LAN addresses |

**Names decided by a script.** When the names are not known in advance
(customer subdomains, say), let a script decide per name:

```toml
[[host]]
pattern = (.*)\.customers\.example\.com
cert = auto
cert_domains = www.customers.example.com        # optional: always issued, never put to the script
cert_validate_script = /usr/local/etc/tlsproxy/domains.sh
target_host = 192.168.1.50
```

```sh
#!/bin/sh
# domains.sh <name>: exit 0 = issue a certificate for it, anything else = don't
grep -qxF "$1" /usr/local/etc/tlsproxy/customers.txt
```

- The script is run as `<script> <name>`, without a shell, and only with names
  that are valid host names matching the rule. Exit status 0 accepts the name;
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
- **Challenges that are not ours go to the upstream.** Only a name with an
  order in progress here is answered here. Any other `acme-tls/1` connection
  belongs to an ACME client behind the proxy, so it is handed to the upstream
  untouched: always for pass-through rules, and for terminating rules too when
  `upstream_tls = true` (normal traffic for that name is still terminated
  here). With a plaintext upstream nobody could answer, so it is refused.
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
  pattern but missing from `cert_domains`) a self-signed placeholder keeps the
  service reachable, with a browser warning.
- **ALPN end to end.** The upstream is contacted first and the client is
  offered exactly the protocol the upstream agreed to, so HTTP/2 works across
  the proxy. With a plaintext upstream only `http/1.1` is offered.
- Reload applies certificate settings too; a config whose `cert = <dir>`
  cannot be loaded is rejected and the running config stays.
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

An optional console on its own port: a live dashboard, open connections,
certificates, the recent log and a config editor.

```toml
[console]
listen = 127.0.0.1                 # default
port = 9443                        # required
password = change-me               # replaced by password_hash on start (see below)
hostnames = console.example.com    # names it may be addressed by, besides IPs and localhost

# Publish it through the proxy itself, with a real certificate:
[[host]]
pattern = console\.example\.com
cert = auto
upstream_tls = false
target_host = 127.0.0.1
target_port = 9443
```

| `[console]` | default | meaning |
|---|---|---|
| `listen` | 127.0.0.1 | bind address. The console is **plain HTTP by design**; anything but loopback logs a warning, because the password would cross the network unencrypted. Keep it on loopback and publish it through a terminating rule as above |
| `port` | (required) | listen port |
| `password` | | plain text, for convenience. At start-up and on every reload the proxy replaces this line with `password_hash` and logs it, so the secret is on disk only briefly. To change the password, put a `password =` line back |
| `password_hash` | | `pbkdf2-sha256$<iterations>$<salt>$<hash>` (PBKDF2-HMAC-SHA256, 600,000 iterations). Generate one with `tlsproxy --hash-password`. One of the two is required |
| `hostnames` | (none) | `;` or `,` separated names the console answers to, besides IP addresses and `localhost`. Any other `Host` is refused: that defeats DNS rebinding |

`listen` and `port` need a restart; `password` and `hostnames` follow hot
reload (a changed password signs everyone out).

**Pages**

- **Dashboard** (refreshes every second): live connections, connections to
  date (relayed, denied, failed, rejected), total bytes received and sent,
  byte and connection rates over the last 5 seconds, route-cache figures, and
  per host (SNI): live and total connections, how many were TLS-terminated,
  bytes each way.
- **Connections**: every open connection with client, host, target,
  terminated or passed through, bytes, age, idle time and the state of each
  direction.
- **Certificates**: every certificate in use, both those the proxy manages
  (`cert = auto`) and those you manage (`cert = <dir>`): status (`ok`,
  `expiring`, `expired`, `missing`, `failing`), issuer, validity, days left,
  renewal date, the rules using it, the last error and next attempt, and a
  "retry now" button that skips the 6-hour wait.
- **Log**: the most recent 2,000 lines of both streams, filterable (for
  example by `[#42]` or a host name), wherever the log is configured to go.
- **Config**: a text editor for the config file, with line numbers.
  - *Validate* and *Test routing* work on the text in the editor, saved or not.
  - *Save & apply* validates first (an invalid config is never written, and a
    `cert = <dir>` that can't be loaded counts as invalid), keeps the previous
    file as `config.toml.<timestamp>.bak` (the last 10, loadable from the
    editor), and applies the change at once.
  - **Saves are race free.** Every read-check-write of the file happens under
    one lock in the proxy, and a save must present the modification time and
    content hash the editor loaded. If the file was changed by anything else in
    between (vim, another session, the proxy hashing a password), that save
    fails and nothing is written.
  - The `[console]` section is hidden from the editor and kept as it is; text
    containing its own `[console]` is rejected. Errors use the editor's line
    numbers.

**Security**: a password is always required, even on loopback (a web page in
your browser could otherwise reach it). Sign-ins are rate limited globally
(5 failures, then 30 s doubling up to 15 min); sessions are random, in memory,
`HttpOnly`, `SameSite=Strict`, 12 hours; every POST needs the session's CSRF
token and a JSON content type; responses forbid framing. Whoever can save a
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
| `client->upstream error: ...` / `upstream->client error: ...` | a socket error such as a connection reset |

A global registry tracks everything live, lock-free on the data path:
connections (active, accepted, completed, denied, failed, rejected),
**goroutines started / finished / open**, total bytes up and down, cache hits
and misses, and per connection: source, SNI, target, bytes each way, age,
idle time and the state of each direction (`open` / `half-closed`).

- Every `stats_interval` seconds, one summary line:
  `stats: active=3 accepted=120 completed=113 denied=4 ... goroutines=6 (started=240 finished=234, runtime=11) up=1.20 GiB down=30.11 GiB cache=5 allow/2 deny (hits=101 misses=19) pool_idle=12`
- `kill -USR1 <pid>` logs that summary plus one line per open connection.

## Design notes

- **Goroutines, no event loop.** One goroutine per connection reads the
  ClientHello, routes, connects and copies client → server; a second copies
  server → client. The Go runtime multiplexes them over kqueue/epoll.
- **Buffer pool = buffered channel.** Borrow and return never block:
  borrowing from an empty pool allocates, returning to a full pool drops the
  buffer for the GC. In steady state every buffer is reused, so relaying
  allocates nothing per byte and the GC has next to nothing to do (byte
  slices hold no pointers, so pooled buffers are never scanned). Buffers are
  not cleared on reuse; only the bytes just read are ever used.
- **Route cache.** Two capped LRU caches keyed by lowercased SNI, one for
  allowed and one for denied names, so a flood of junk names can only evict
  other junk. Cached decisions are marked `cached` in the log.
- **Hot reload.** The config file is re-read every `reload_interval` seconds
  (content is compared, not mtime), so reloads happen at most once per 5 s
  and the newest version always wins. Config, caches and buffer pool swap
  together through one `atomic.Pointer`: caches start empty, a changed buffer
  size gets a fresh pool, an invalid file is logged and ignored, existing
  connections keep the settings they started with. `bind`/`port` changes
  need a restart.
- **Half-close and interruptions.** EOF on one side is forwarded as a
  half-close and starts the `half_close_timeout` clock; the other direction
  keeps flowing until it ends or the clock fires. A write failure (receiver
  closed its read side) likewise ends only that direction. Idle means no
  traffic in *either* direction.

## Tests

`go test ./...` runs 80+ tests, also under the race detector in CI:

- **ACME, end to end (`TLSPROXY_PEBBLE=1`).** Starts Pebble (Let's Encrypt's
  official test CA) and its DNS server; Pebble validates TLS-ALPN-01 against
  the proxy exactly as Let's Encrypt would. Checks issuance for two names,
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
  certificate reload (and a broken update keeping the old one), start-up
  errors, config validation, renewal schedule and job priority, and the DNS
  check against a fake DNS server.
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
