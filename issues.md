# Issues

Findings of the code review of 2026-09-19 (design, memory, goroutines) and what
became of them. The write-ups below describe each problem as it was found
(line numbers as of `04f67e8`); the table says what is still open.

Priority: **P1** can be triggered by anyone who reaches the port · **P2** real
cost or leak in normal operation · **P3** edge case or polish.

| # | P | Area | Summary | Status |
|---|---|---|---|---|
| [1](#1-a-clienthello-in-thousands-of-records-burns-cpu) | P1 | DoS | ClientHello in thousands of tiny records: quadratic parsing | **fixed** `29fe7a8`, `d8b9845`: at most 32 records, framing scanned incrementally, parsed once |
| [2](#2-the-console-sign-in-limit-is-bypassed-by-parallel-requests) | P1 | DoS / auth | Console sign-in limit bypassed by parallel requests | **fixed** `29fe7a8`: verifications are serialised |
| [3](#3-every-certificate-attempt-leaves-a-connection-and-two-goroutines-behind) | P2 | goroutines | ACME HTTP transport never closed | **fixed** `29fe7a8`: idle connections closed, idle/handshake timeouts, proxy from environment |
| [4](#4-changing-logging-on-reload-leaks-the-old-log-files) | P2 | file descriptors | Old log files not closed when `[logging]` changes | **fixed** `29fe7a8` |
| [5](#5-terminated-clients-never-resume-a-tls-session) | P2 | performance | No TLS session resumption for terminated clients | **fixed** `29fe7a8`: shared ticket keys, rotated daily |
| [6](#6-the-buffer-pool-never-shrinks) | P2 | memory | Buffer pool never shrinks after a peak | **fixed** `29fe7a8`: default cap 2 x `max_connections`, half shed after a minute at the cap |
| [7](#7-logging-is-synchronous-under-one-lock-on-the-data-path) | P2 | blocking | Logging is synchronous, under one global lock, on the data path | **open** |
| [8](#8-no-upstream-tls-session-resumption) | P3 | performance | No upstream TLS session cache | **fixed** `29fe7a8`: one LRU cache per rule |
| [9](#9-the-console-server-has-no-read-or-write-timeout) | P3 | goroutines | Console `http.Server` has only `ReadHeaderTimeout` | **fixed** `29fe7a8`: 30 s read and write timeouts |
| [10](#10-no-caching-of-resolved-target-addresses) | P3 | performance | DNS lookup for every new connection to a host-name target | **open** |
| [11](#11-smaller-items) | P3 | various | see the list | partly open |
| [12](#12-a-placeholder-certificate-per-client-chosen-name) | P1 | DoS | A key and a self-signed certificate generated per made-up name | **fixed** in v0.3.0: one placeholder per rule |

Still open: **7**, **10**, and from 11: the `unexpected EOF` wording, `$0`
targets following the client's SNI, no per-source limit on handshake slots,
one `bind` address only.

---

## 1. A ClientHello in thousands of records burns CPU

**Where:** `sni.go:81` (`parseHello`), called from `readHello` in `proxy.go`.

**What happens.** A ClientHello may span several TLS records. The parser
reassembles it like this:

```go
handshake = append(append([]byte(nil), handshake...), rest[5:5+n]...)
```

For every record after the first it allocates a new buffer and copies
everything gathered so far. `readHello` calls the parser again from the start
after every `Read`. Both are quadratic: one parse of *k* records copies
1+2+...+*k* pieces, and data arriving in *k* reads causes *k* parses.

**Attack.** A 4-byte handshake header announcing a 60 KB message, followed by
~10,000 records of 1 byte each. This is valid TLS and within the 64 KB limit.
One parse of that input was measured at **8 ms** (about 50 MB copied, 10,000
allocations). Sent one record per packet, every packet triggers another such
parse, so a single connection keeps a core busy for the whole
`handshake_timeout` (10 s) with about 60 KB of traffic.

**Impact.** Unauthenticated, from anywhere that reaches port 443. A few dozen
connections at a time saturate a small gateway; legitimate handshakes slow
down or time out. `max_connections` does not help: the cost per connection is
the problem.

**Fix.** Refuse a hello of more than ~32 records (real clients send 1 to 3).
Optionally also append into one owned buffer so a parse is linear.

**Test.** A hello in 10,000 records is rejected quickly; a hello in 5 records
still parses (the existing fragmentation tests keep passing).

## 2. The console sign-in limit is bypassed by parallel requests

**Where:** `console.go:225-247` (`login`).

**What happens.**

```go
c.mu.Lock()
if wait := time.Until(c.lockedUntil); wait > 0 { /* refuse */ }  // 1. check
hash := c.hash
c.mu.Unlock()
ok := checkPassword(hash, req.Password)   // 2. ~0.2 s of PBKDF2, outside the lock
c.mu.Lock()
if !ok { c.failures++; /* lock after 5 */ }                      // 3. record
```

The lockout is checked before the slow step and updated after it. N requests
sent at the same moment all pass step 1, all hash in parallel, and only then
does the lockout engage.

**Impact.**
- The limit of 5 guesses becomes "as many as fit in one burst", repeatable
  each time the lock expires.
- Each guess is 600,000 PBKDF2 iterations (~0.2 s CPU). 500 parallel guesses
  are ~100 CPU-seconds: the box, proxy included, stalls for the burst. The
  password hash is deliberately slow to make guessing expensive for the
  attacker; here the defender pays.
- In the recommended setup the console is published through a terminating
  rule, so the endpoint is reachable from the internet.

**Fix.** A dedicated mutex around the verification so one password is checked
at a time, and re-check `lockedUntil` after acquiring it. Requests queued
behind a failure are then refused without hashing.

**Test.** 50 concurrent wrong passwords: at most 5 reach `checkPassword`, the
rest get 429.

## 3. Every certificate attempt leaves a connection and two goroutines behind

**Where:** `certs.go:829` (`acmeClient`), used by `issue`.

**What happens.** Each `issue()` builds a new ACME client with
`transport := &http.Transport{}` and never closes it. A transport keeps its
connections alive for reuse, each with a read-loop and a write-loop goroutine,
and the zero value has `IdleConnTimeout = 0`: never closed for idleness. The
goroutines reference the transport, so it is not garbage collected when
`issue()` returns. It lives until the CA's server drops the connection.

**Impact.** One TCP connection, one file descriptor and two goroutines per
attempt (each of the 3 quick tries, every 6-hour retry, every renewal) until
the remote side closes. Negligible with 3 names; relevant with
`cert_validate_script` and 4 parallel jobs. Shows as `runtime=` in the stats
line creeping up. The zero-value transport also ignores `HTTPS_PROXY` and has
no TLS handshake timeout.

**Fix.** `defer transport.CloseIdleConnections()` in `issue()`, or one shared
transport per `CertManager` with `IdleConnTimeout`, `TLSHandshakeTimeout` and
`Proxy: http.ProxyFromEnvironment`.

## 4. Changing `[logging]` on reload leaks the old log files

**Where:** `logx.go:48` (`ConfigureLogging`).

**What happens.** When a reload changes `[logging]`, new `FileLogger`s are
opened and `sinkCfg, sinkOut, sinkErr = &cfg, out, errl` overwrites the old
ones. Their `*os.File` is never closed.

**Impact.** Up to 2 file descriptors per such reload, for the life of the
process. On FreeBSD an open descriptor keeps a deleted file's blocks
allocated, so pointing the log elsewhere and deleting the old file does not
free the space until a restart. Only reloads that change `[logging]` are
affected (an identical config returns early).

**Fix.** Close the previous loggers' files after the swap. Two details: stdout
and stderr may share one `FileLogger` (close once), and a background gzip may
still be running for the old logger (it only touches rotated generations, not
the live file, so closing is safe).

## 5. Terminated clients never resume a TLS session

**Where:** `proxy.go:520` (`terminate`).

**What happens.** A new `tls.Config` is built for every terminated connection
(its `NextProtos` depends on what the upstream negotiated). Session-ticket
keys live in the `Config` and are generated per `Config`, so a ticket issued
on one connection can never be decrypted on the next. Every client connection
is a full handshake with an ECDSA signature.

**Impact.** More CPU and latency per terminated connection than necessary;
browsers open many connections per page.

**Fix.** Generate ticket keys once per server (rotate daily) and call
`SetSessionTicketKeys` on each per-connection config.

## 6. The buffer pool never shrinks

**Where:** `pool.go`.

**What happens.** Returned buffers are parked in a channel and stay there. After
one peak of `max_connections` (1024) connections, 2 x 1024 x 64 KiB = **128 MiB**
stays allocated for ever. The default cap of 3 x `max_connections` can never be
reached: at most 2 buffers per connection are in use at once.

**Impact.** Memory that a small gateway does not get back after a burst or an
attack.

**Fix.** A janitor that drops a share of the idle buffers when the pool has
been over-full for a minute; default cap 2 x `max_connections`.

Related, by design: every idle connection pins two 64 KiB buffers (Go cannot
wait for readability without a buffer), and terminated connections use at
most 16 KiB of theirs per read (`tls.Conn` returns one record at a time).

## 7. Logging is synchronous, under one lock, on the data path

**Where:** `logx.go:78` (`emit`), `proxy.go:133`.

**What happens.** Every connection writes 4 lines; each takes the global
`logMu` and does an unbuffered `write` to the file or stdout.

**Impact.** A slow disk or a stalled stdout pipe blocks every connection
handler. The accept loop logs too ("rejected: too many connections"), so a
flood beyond `max_connections` throttles accepting and fills the log.

**Fix.** Buffered writer flushed a few times per second (and on error lines);
rate-limit the "rejected" line to one per second with a count.

## 8. No upstream TLS session resumption

**Where:** `proxy.go:497`. The upstream `tls.Config` has no
`ClientSessionCache`, so every terminated connection does a full handshake
with the upstream as well. Fix: one `tls.NewLRUClientSessionCache` per rule.

## 9. The console server has no read or write timeout

**Where:** `console.go:107`. Only `ReadHeaderTimeout` is set. A client that
sends a POST body very slowly holds a goroutine indefinitely, before
authentication. Fix: `ReadTimeout` and `WriteTimeout` of ~30 s.

## 10. No caching of resolved target addresses

**Where:** `proxy.go:357`. The route cache remembers the decision, not the
address, so every new connection to a host-name target is a DNS lookup. Fine
with a local resolver (unbound on pfSense); a short positive cache (a few
seconds) would take the load off it at high connection rates.

## 11. Smaller items

- *(fixed `29fe7a8`: file and directory are synced)* **No fsync before rename** (`certs.go:997`, `writeFileAtomic`). A power loss
  right after a console save can leave an empty `config.toml` (or key/cert).
  Fix: `Sync()` the temporary file, then rename.
- *(fixed `29fe7a8`: a failed rotation is not repeated)* **Log rotation after a failed rename** (`rotate.go:108`). If renaming the
  live file fails after the generations were shifted, the shift is repeated on
  every following log line and history is deleted. Unlikely (same directory).
  Fix: rename the live file first, or stop rotating after an error.
- **`unexpected EOF` close reason.** Peers that skip the TLS `close_notify`
  (many HTTP clients) end terminated connections with `reason=... error:
  unexpected EOF`, and both directions close at once. Defensible (it could be
  truncation), but the wording looks like a fault. Fix: say "closed without
  close_notify".
- *(fixed `29fe7a8`: logged)* **A `[console]` section added by a reload is ignored silently**
  (`proxy.go:207`); it needs a restart. Fix: log that.
- *(fixed `29fe7a8`)* **Answered ACME challenges are not counted** (`proxy.go:313`): neither
  completed nor failed, so `accepted` drifts from the sum of the others.
- **`$0` / `$1` targets follow the client's SNI.** With a broad pattern and
  `target_host = $0`, an SNI such as `10.0.0.1` makes the proxy connect to that
  address on `target_port`. The samples use explicit names; the README should
  warn, or such rules could refuse SNIs that are IP addresses.
- **Slow handshakes hold slots cheaply.** `max_connections` slots can be held
  for `handshake_timeout` each at almost no cost; there is no per-source limit.
- **One `bind` address only.** One specific IPv4 plus one specific IPv6 address
  is not possible; a list would be.

## 12. A placeholder certificate per client-chosen name

**Where:** `certs.go`, `CertificateFor`.

**What happened.** For a terminating rule with a regex or wildcard pattern, every
name without a certificate got its own self-signed placeholder: a P-256 key
generation and a signature per new name. The map was capped at 256 entries and
then emptied, so it never grew, but the work was repeated for ever. A client
sending millions of made-up names under `*.s3.example.com` made the proxy
generate millions of keys.

**Fix (v0.3.0).** Only names from `cert_domains` (bounded by the configuration)
get their own placeholder. Every other name shares one per rule: a wildcard
certificate (`*.s3.example.com`) when the pattern has that form, otherwise one
for `placeholder.invalid`. The name on a self-signed certificate makes no
practical difference: verifying clients reject it either way. Placeholders are
also replaced before their 7 days are up. The sample admission script caches
the bucket list for a minute, so the same flood costs the S3 server one request
a minute instead of one per name.

## Done since the review

- `target_host` with a port (`10.0.0.1:8080`) was accepted and dialled as a
  name: rejected at load since `a8c0bd1`.
- IPv6: `bind = 0.0.0.0` was dual-stack, the DNS pre-check accepted a name with
  a stray AAAA record, zoned link-local targets failed, IPv6 targets were shown
  ambiguously, `bind = [::]` failed: all fixed in `04f67e8`.
- Terminated connections on a resumed TLS session were logged with `cert=?`:
  they now say the session was resumed (v0.3.0).
