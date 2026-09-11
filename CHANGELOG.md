# Changelog

## [1.1.7] - 2026-09-11

### Security

- Lifted transitive `hono`, `@hono/node-server`, `qs`, and `fast-uri` in the lockfile to clear four advisories. Three are unreachable because this is a stdio-only server that never instantiates the HTTP transport: `hono` (`toSSG()` path escape), `@hono/node-server` (`serve-static` traversal via `%5C`), and `qs` (array-limit bypass, reached via `express`).
- The high-severity one, `fast-uri` (host confusion via backslash authority introducer), is **not** a transport dependency — it sits under `ajv`, which the SDK uses for JSON Schema validation on a code path that is live in stdio mode. It is unreachable for a narrower reason: no schema in this server declares `format: "uri"`, and no tool declares an `outputSchema`, so ajv never invokes the format validator that calls `fast-uri`. `api_call`'s `url: z.url()` is zod's own parser, not `fast-uri`. Re-check this specific reasoning on the next `ajv` advisory rather than reusing the transport argument.

### Changed

- Updated `undici` 8.10.0 → 8.10.2 and `zod` 4.4.3 → 4.6.2.
- Updated dev dependencies: `vitest` 4.1.10 → 5.0.0, `@types/node` 26.1.2 → 26.5.1.
- `@hono/node-server` resolved to 2.1.1, a major bump, inside the range the SDK already declares (`^1.19.9 || ^2.0.5`). No `overrides` were used.
- Declared `engines: { node: ">=20" }`. `@hono/node-server` 2.x raises the floor from 18.14.1 to 20 and installs for every consumer, so the package now states what it supports instead of leaving consumers to hit `EBADENGINE`.

## [1.1.6] - 2026-08-05

### Security

- `api_call` now follows redirects itself instead of letting `fetch` do it. Every hop is re-checked against the SSRF guard and the destination allowlist, and the resolved IP is re-pinned for the new host. Previously only the first request was validated, so a `302` could send an injected secret to an internal address such as `169.254.169.254` or to a host outside `SECURE_API_ALLOWED_HOSTS`. Redirect chains are capped at 5 hops; `303` (and `POST` under `301`/`302`) downgrade to `GET` and drop the body, while `307`/`308` preserve both.

## [1.1.5] - 2026-08-04

### Security

- Bumped `undici` 8.8 → 8.10 to clear GHSA advisories in the HTTP client used by `api_call` (cross-user information disclosure, response desync via retries, cookie attribute injection, CRLF injection via blob body `type`). Reachable path, since `undici` performs every `api_call` request.

Note: remaining `ip-address`, `fast-uri`, and `@hono/node-server` advisories are transitive under the SDK's HTTP/Express transport machinery, which never executes in this stdio-only server — not reachable.

## [1.1.4] - 2026-08-04

### Fixed

- **IPv6 SSRF bypass** — `isPrivateIp()` blocked `::1` and `::ffff:` IPv4-mapped forms but treated the unspecified address `::` and IPv4-compatible IPv6 (`::a.b.c.d`, including the single-group `::N` form) as public. On Linux, `http://[::]/` reaches loopback-bound services. Now blocked, with embedded IPv4 decoded through the existing private-range check.

## [1.1.3] - 2026-07-21

### Fixed

- **Secret leakage via substring match** in `sync_env_example`'s port heuristic
- Hardened `api_call` destinations, `.my.cnf` includes, and request timeouts
- Bounded `timeout_ms` to a positive integer in `api_call` and `run_with_env`

## [1.1.2] - 2026-06-27

### Changed

- Bumped all dependencies to latest: zod 3→4, TypeScript 5→6, vitest 3→4, dotenv 16→17, ini 6→7, `@modelcontextprotocol/sdk` 1.27→1.29, undici 8.1→8.5, `@types/node` 22→26
- Migrated to zod 4 APIs in `api_call` schema (`z.record(z.string(), z.string())`, `z.url()`); no public behavior change

## [1.1.1] - 2026-04-13

### Fixed

- Excluded test files from published package (71 files / 35 kB down to 41 files / 21 kB)

## [1.1.0] - 2026-04-13

### Added

- **`read_mycnf` tool** — reads MySQL `.my.cnf` configuration with credentials redacted
- **`include_mycnf` option on `run_with_env`** — sanitizes `.my.cnf` credentials in command output
- **Named redaction tags** — `[REDACTED:KEY_NAME]` instead of `[REDACTED:1]` for easier debugging
- Comprehensive test suite (Vitest) covering sanitize, url-validator, path-validator, scanner
- GitHub Packages publishing and release workflow
- Claude code review workflow for PRs

### Fixed

- **`api_call` broken on all HTTPS requests** — DNS rebinding protection rewrote URLs to bare IPs, breaking TLS cert validation. Now pins the validated IP at the socket layer via undici dispatcher, preserving SNI/TLS while closing the TOCTOU window.
- IPv6 SSRF bypasses — 6to4 (`2002::/16`), Teredo (`2001::/32`), full `fe80::/10` link-local range, bracket handling
- `process.env` leaking unsanitized secrets to child processes
- TOCTOU race in env-loader file reads
- Symlink traversal in `sync_env_example`
- Audit double-count when `auth_env_key` and `{{KEY}}` template headers reference the same key
- Stale env cache when `.env` replaced with identical mtime
- Fetch errors now return structured `{status, headers, body}` instead of crashing
- Fetch error messages are sanitized for defense-in-depth
- `api_call` tool description now explains when to use it vs `run_with_env`+curl

## [1.0.0] - Initial release

- `get_env_keys` — list `.env` key names without exposing values
- `run_with_env` — run shell commands with `.env` injected, output sanitized
- `api_call` — HTTP requests with secret injection via `{{KEY}}` headers or `auth_env_key`
- `sync_env_example` — generate/update `.env.example` from `.env`
- SSRF protection — blocks private/internal IPs, dangerous schemes
- Path traversal protection — validates project directories
- Audit logging for all tool invocations
