# Changelog

## [1.2.0] - 2026-09-14

### Security

- `sync_env_example` no longer writes through a symlinked temp file. The temp path is predictable (`.env.example.tmp`), so a committed symlink there was written *through* — truncating and rewriting its target — before the rename moved the link aside. The write now uses `O_EXCL | O_NOFOLLOW`, which refuses any pre-existing entry. The comment claiming the rename closed symlink traversal was true only for `.env.example` itself.
- `sync_env_example` no longer copies multi-line secret values into `.env.example`. The tool split `.env` on newlines and redacted per line, but dotenv supports multi-line double-quoted values, so only the first line of a PEM private key or JSON service-account blob had `KEY=` shape. Every continuation line fell through and was written verbatim into a file meant to be committed. The key set now comes from dotenv's own parser — the one `env-loader.ts` already uses — and any line it does not recognize is dropped. Because dotenv's value pattern spans `#` as well as newlines, a continuation line beginning with `#` is secret material rather than a comment; the span scan marks those lines as value content so the comment-preservation path never sees them. No attacker was required to trigger this.
- `sync_env_example` no longer reads `.env.example` through a symlink. A committed `.env.example -> .env` had the victim's real values read as "existing placeholders" and copied back into the file. Keys that evade `SECRET_KEY_TOKENS` — `DATABASE_URL`, `REDIS_URL`, `SENTRY_DSN`, `MONGO_URI` — were harvested this way. The read now uses `O_NOFOLLOW` and refuses symlinks outright; containment would not have helped, since the dangerous case stays inside the project. A stored placeholder is also discarded now if it scans as a secret or carries URL userinfo.
- `api_call` sanitizes the blocked-redirect message. `Location` is attacker-controlled and can reflect a request header, and this check runs before the host-allowlist check, so an enforced `SECURE_API_ALLOWED_HOSTS` did not help — a blocked `302` could return a Bearer token verbatim to the model. Every other exit path was already sanitized.
- The SSRF guard now blocks 100.64.0.0/10 (CGNAT, RFC 6598). The range carries Alibaba Cloud's IMDS at `100.100.100.200`, which serves RAM role credentials, and every Tailscale/Headscale peer address.
- `read_mycnf` redacts the MySQL 8.0.27+ multifactor options `password1`, `password2`, and `password3`, which were returned verbatim despite the redaction contract. A `loose-` prefix is stripped before the match, since MySQL honours `loose-password=` as a live credential.
- `sync_env_example` parses assignments with dotenv's own prefix rather than `indexOf("=")`. dotenv accepts `:` as a separator too, so a `FOO: "..."` multi-line value never reached the quote tracking and its `#`-prefixed continuation lines were written verbatim — the same leak, through a different separator.
- `sync_env_example` refuses to write when it emits fewer keys than dotenv parsed. An unterminated quote leaves the tracker open for the rest of the file, so `.env.example` was renamed over the curated original having silently lost every later key.
- `read_mycnf` also strips a `loose_` prefix. MySQL's `my_getopt` accepts either delimiter after a special prefix, so `loose_password=` was as live and as exposed as `loose-password=`.
- `sanitize` matches secret values case-insensitively. Callers routinely hand it text that has passed through `new URL()`, which ASCII-lowercases the host, so a token reflected into a hostname arrived case-folded and a case-sensitive match missed it — in the blocked-redirect message, in the validator's own `reason` string, in the allowlist refusal, and in the unenforced-mode warning. Fixing the matcher closes all four at once. The base64 form stays exact, since that alphabet is case-significant.
- `sync_env_example` compares emitted keys against parsed keys as sets rather than counts. A `.env` that repeats a key emitted more lines than there were distinct keys, and that slack exactly covered for a key genuinely lost to an unterminated quote.
- `sync_env_example` regenerates a stored placeholder whose URL carries a credential query parameter, not just userinfo. `DATABASE_URL=postgres://host/db?password=x` clears both the key gate and the scanner, since `SECRET_KEY_TOKENS` is deliberately incomplete.
- `api_call` builds its blocked-redirect message from the raw `Location` header. `new URL().toString()` ASCII-lowercases the host and `sanitize` matches case-sensitively, so a mixed-case token reflected into the hostname reached the model case-folded but otherwise intact.
- `sync_env_example` drops an assignment whose key is value-fragment-shaped — 16 or more characters mixing upper and lower case. An unquoted or unterminated multi-line value leaves dotenv scanning each following line independently, and a base64 line whose only non-word character is its trailing `=` tokenizes as a key — writing a fragment of a private key into the committed file. Nothing downstream could catch it: the assignment path does not sanitize, `sanitize` cannot match a fragment, and `scanForSecrets` deliberately excludes generic base64. The padded tail of a PEM is where `=` actually lives, and it is short and often digit-free.
- `sync_env_example` suppresses comment redaction only for the value comments are actually scrubbed against. `parse()` keeps just the last occurrence of a repeated key, so an echoed `PORT=8080` earlier in the file dropped a later `PORT=<secret>` from the comment map entirely, and a comment naming it was written verbatim.
- `sync_env_example` checks a stored placeholder against every other live value, not only its own key's. A leak sitting under the wrong key — `APP_NAME=<the live DB_PASSWORD>` — cleared the key regex, the scanner, the URL check and the opaque-token check, and was written back into the committed file. The comment path already applied this treatment; the assignment path had the weaker check.
- `sync_env_example` scans the emitted assignment line, not only commented ones. The key is written verbatim, so a line whose key is itself a brand-prefixed token reached the committed file untouched.
- `sync_env_example` no longer redacts a value out of the comment beside it. `sanitize` matches every env value over three characters, case-insensitively, so ordinary short values mangled the prose — a file carrying `NODE_ENV=production` printed `# Use [REDACTED:NODE_ENV] credentials` on the next line. Values the file writes verbatim are excluded from the comment pass.
- `api_call` sanitizes `warnings` at the point they are built rather than at each exit, and sanitizes the first-hop allowlist refusal. Three returns remain unsanitized by design: two run before `loadEnv` and one is a constant string; a comment at the `loadEnv` call now marks that boundary.
- `sanitize` builds its replacement through a function, so a `$&` or `$1` in a key name cannot rebuild the value it just redacted. `read_mycnf` keys secrets `section.field` straight from the ini parse, so key names are not fully controlled.
- `read_mycnf` folds case before matching, since MySQL option names are case-insensitive and `PASSWORD=` was returned verbatim.
- `loadEnv` reads `.env` with `O_NOFOLLOW`, refusing a symlink that resolves outside the project. It is the read behind `api_call`, `run_with_env` and `get_env_keys`, so a cloned repo shipping `.env -> ~/.aws/credentials` previously parsed fine — and `run_with_env` injects the result into a subprocess whose output sanitization is best-effort by design. A symlink within the project, such as `.env -> .env.local`, still works.
- `sync_env_example` derives every assignment from dotenv's own `LINE` regex and match indices rather than re-deriving value boundaries by hand. The hand-rolled scanner diverged from the parser on the `:` separator, on a trailing `# comment`, on `JSON="{"a":1}"`, and on a `\\` run before the closing quote — and each divergence in the "closes early" direction wrote key material into a file meant to be committed.
- `sync_env_example` redacts preserved comments against the live `.env` values, not just known-brand prefixes, and routes a commented-out assignment through the placeholder generator. `# DB_PASSWORD=hunter2` matches no scanner pattern but is still a credential in a committed file. Applies to comments carried over from an existing `.env.example` too.
- `sync_env_example` unquotes a value before judging it. dotenv captures a value with its surrounding quotes and strips them later, so `DATABASE_URL="postgres://admin:s3cret@host/db"` made `new URL()` throw on the leading quote and walked through every credential check — while the unquoted spelling of the same line was caught.
- `sync_env_example` regenerates a stored placeholder that looks like an opaque credential — long, alphanumeric, mixing letters and digits — whether or not the live value has since rotated, and regenerates a placeholder byte-identical to the live value whenever it has a substitute of its own. `MAILGUN_SENDING=8f3a9c2e1b7d40561122` names no known brand and matched no previous gate. Punctuated config such as `TZ=America/New_York` is excluded, so a legitimately shared default still survives.
- `api_call` sanitizes response header *names* as well as values. HTTP token characters cover most secret alphabets, so a server can reflect a request header into a response header name.
- `read_mycnf` sanitizes non-secret field values instead of returning them verbatim. The field-name gate is a denylist over a format with other places to put a credential — `init-command` can interpolate the password into a SQL statement, and it is not in `SECRET_FIELDS`.
- `read_mycnf` reuses the loader's `secrets` map rather than re-deriving which fields are sensitive, so one predicate decides what the model sees.
- `api_call` sanitizes `warnings` as well as `body`. Warnings ride along on every exit path, and one entry interpolates a `Location`-derived hostname, so the same reflection channel reached the model unsanitized.

- `api_call` drops injected secrets on a cross-origin redirect. `Authorization` and any header carrying an injected value were forwarded verbatim to whatever host the remote server named in `Location`, and with `SECURE_API_ALLOWED_HOSTS` unset — the documented default — the destination check only warns. curl and browsers strip `Authorization` on cross-origin redirect for the same reason; the allowlist is now a narrowing control rather than the only one.
- `get_env_keys` and `run_with_env` filter out keys that are value fragments, identified by length plus mixed case, and warn when they drop one so a filtered key cannot read as a missing variable. A lowercase dotted key such as `spring.datasource.password` is kept. dotenv turns each line of an unquoted multi-line value into its own assignment, so a base64 chunk of a private key arrived as a key *name* — reaching the model despite "no values are exposed", and becoming a child-process variable name under `run_with_env`.
- `api_call` reads the response body inside its `try`. The read sat after the `finally`, so `timeout_ms` bounded time-to-headers only and a trickled body stalled indefinitely, while a mid-stream reset rejected past every `sanitize` call, past `auditLog`, and past the warnings.

### Changed

- `get_env_keys` and `run_with_env` omit keys of 16 or more characters that mix upper and lower case. That is a wider net than "base64 fragment" — `googleClientSecret` and `MyApp_Database_Url` match too — so under `run_with_env` with `env_keys` unset those stop being injected into the child process. Both tools warn, `env_keys` overrides, and the value stays in the sanitizer map either way, so there is no redaction gap.
- `loadEnv` refuses a `.env` symlinked outside the project. A monorepo or dotfiles layout pointing `.env` at a shared file outside the tree stops resolving; a symlink within the project still works. `api_call` and `get_env_keys` surface the refusal as a warning; `run_with_env` refuses outright, because with the read blocked its sanitizer map is empty and a command reading the symlink itself would get output the previous code scrubbed.
- `api_call` now refuses 100.64.0.0/10. Callers reaching an internal API over Tailscale or another CGNAT-addressed network lose `api_call` for that host, and `SECURE_API_ALLOWED_HOSTS` only narrows the allowed set — it cannot re-permit a blocked range. The Alibaba IMDS exposure outweighs the loss, but this is a behavior change, not purely a fix.

Each fix carries a test that fails against the previous implementation.

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
