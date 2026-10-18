# Changelog

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
