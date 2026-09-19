# tlsproxy_go_quick

An **extremely simple SNI router for a gateway**. It listens on one port,
reads the hostname in the TLS ClientHello (SNI), picks a backend from
`config.toml`, and relays the still-encrypted bytes to it. It never decrypts
anything, so it needs no certificates or keys.

This is the Go port of [tlsproxy_rs_quick](https://github.com/wushilin/tlsproxy_rs_quick),
with identical behaviour, config format and log lines. It exists because a
firewall such as **pfSense** has no C compiler or linker, so Rust programs
cannot be built on it, while Go can:

- **Standard library only.** No modules to download; `go build` works offline.
- **No `cc` needed.** Go has its own linker. Build on the box with the `go`
  package, or cross-compile anywhere: `GOOS=freebsd GOARCH=amd64 go build`.
- **Static binary.** It doesn't link libc, so one build runs on any FreeBSD
  version (14, 15, 16...).

For the full-featured proxy (TLS termination, ACME, admin UI) see
[tlsproxy_rs](https://github.com/wushilin/tlsproxy_rs).

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

`io_model` and `worker_threads` from the Rust version
are accepted and ignored (with a log line), so the same file works for both.
More examples, each with its expected routing, are in [`samples/`](samples).

## Logs and state

```
[#1] accepted from 10.0.0.5:49943 (active=1)
[#1] route sni=foo.wushilin.net -> foo.wushilin.internal.net:443 (ALLOW, rule line 51, cached)
[#1] connected 10.0.0.5:49943 -> foo.wushilin.internal.net:443 (192.168.1.10:443) in 2ms
[#1] closed src=10.0.0.5:49943 sni=foo.wushilin.net dst=foo.wushilin.internal.net:443 (192.168.1.10:443) up=533 B down=6.54 KiB duration=56ms reason=client closed first
[#2] route sni=evil.com src=10.0.0.7:49945 -> DENY (rule line 57)
```

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

`go test ./...` runs 50+ tests, also under the race detector in CI:

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

Measured with the Rust repo's benchmark (`--proxy ./tlsproxy`) on an Apple M3
Max, client, backend and proxy sharing the machine:

| | Go (this) | Rust, event loop | Rust, threads |
|---|---|---|---|
| 64-byte round trip, added (p50) | +20 µs | +19 µs | +15 µs |
| connect + ClientHello, added (p50) | **+111 µs** | +197 µs | +165 µs |
| new connections/s (32 parallel) | **9,800** | 5,300 | 6,300 |
| 1-stream throughput | 630–1,070 MiB/s (run to run) | 730 MiB/s | 588 MiB/s |
| proxy CPU per GiB relayed | 0.6–1.0 s | 0.4–0.55 s | 0.5–0.75 s |
| memory with 2,000 open connections | 121 MiB (~50 KiB each) | 3.9 MiB | 130 MiB |
| binary | 2.7 MB static | 0.4 MB | 0.4 MB |

Go is the quickest at setting up connections and somewhat more expensive per
byte; at gateway speeds (1 Gbit/s ≈ 0.12 CPU-seconds per second) neither
matters. Lower `buffer_size` if memory is tight.
