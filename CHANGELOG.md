# Changelog

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
