# Changelog

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
