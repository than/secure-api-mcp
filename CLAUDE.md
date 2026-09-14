# secure-api-mcp

An MCP server that holds secrets so the model never sees them. Every rule below
exists because breaking it leaks a credential.

## The contract

Tools take a *key name*, never a value. The server reads the secret, uses it,
and returns output with the value stripped. The model may learn that
`STRIPE_KEY` exists; it must never learn what it is.

Tools: `api_call`, `get_env_keys`, `read_mycnf`, `run_with_env`,
`sync_env_example` (`src/tools/`). Secret sources: `.env` via
`src/env-loader.ts`, `~/.my.cnf` via `src/mycnf-loader.ts`.

## Invariants

**Sanitize every exit path.** Any string returned to the model goes through
`sanitize(text, env)` — bodies, headers, *and* error and block messages. A
blocked-redirect message once carried a Bearer token because one early return
skipped it. When you add a `return` to `api_call`, sanitize it.

**Never hand-parse `.env`.** Use `parse()` from dotenv, the same parser
`env-loader.ts` uses. Splitting on `\n` and redacting per line looks correct and
isn't: dotenv supports multi-line double-quoted values, so a PEM body spans
lines with no `KEY=` shape — and its value pattern spans `#` too, so a
continuation line starting with `#` is secret material, not a comment.

**Open files defensively.** Symlinks are in the threat model — repos are
cloned from untrusted sources, and both the destination *and* any predictable
temp path are plantable. Realpath containment is not a substitute: a
`.env.example -> .env` symlink stays inside the project.

Every `.env` / `.env.example` read uses `O_NOFOLLOW`, and the temp write uses
`O_EXCL | O_NOFOLLOW`. Two containment policies, deliberately different:
`loadEnv` and the `.env` read in `sync_env_example` allow a symlink that
resolves inside the project (`.env -> .env.local` is ordinary); the
`.env.example` read refuses symlinks outright, because the dangerous case
(`.env.example -> .env`) stays inside the project and containment would pass
it.

**`SECRET_KEY_TOKENS` is deny-first and incomplete by nature.** It matches
whole underscore-delimited words, so `DATABASE_URL`, `REDIS_URL`, `SENTRY_DSN`
and `MONGO_URI` do *not* match. Anything that reuses a value for a
non-matching key must independently check `scanForSecrets` and URL userinfo.
Widening the regex is not the fix; assume it misses.

**Re-validate every redirect hop.** `validateUrl` runs per hop, the resolved IP
is re-pinned for each new host, and the allowlist is re-checked. `fetch` is
always called with `redirect: "manual"`.

**SSRF ranges are a denylist of real targets.** `isPrivateIpv4`
(`src/security/url-validator.ts`) blocks loopback, RFC 1918, link-local
(169.254 — AWS/GCP IMDS) and CGNAT (100.64/10 — Alibaba IMDS at
100.100.100.200, Tailscale). Adding a range needs a boundary test proving the
neighbours stay allowed.

## Testing

`npm test` (vitest). A security fix ships with a test **verified to fail
against the unfixed source** — run it against the old code before you claim it
works. Asserting `expect.anything()` on a security-critical argument proves
nothing.

## Releasing

1. Change lands via PR to `main`.
2. Version commit directly on `main`: flip `## [Unreleased]` to
   `## [x.y.z] - DATE` in `CHANGELOG.md`, bump `package.json` + lockfile.
3. `git tag vx.y.z && git push origin vx.y.z`.

**Pushing the tag publishes.** `.github/workflows/release.yml` fires on
`v*.*.*`, runs tests, publishes to GitHub Packages and creates the release.
There is no separate confirmation step — do not push a tag speculatively.

Node floor is `>=20` (`engines`), set by `@hono/node-server` 2.x under the SDK.

## Triaging advisories

Most `npm audit` hits are transitive under the SDK's HTTP/Express transport,
which never executes here — `StdioServerTransport` is the only transport
(`src/index.ts`). That argument is usually right and occasionally wrong: a
`fast-uri` advisory sat under `ajv`, which the SDK uses for JSON Schema
validation on a live stdio path. It was still unreachable, but only because no
schema declares `format: "uri"`. Establish *why* each one is unreachable rather
than reusing the transport reasoning.

<!-- sidecar:review-queue -->
## Sidecar board

Maintain `.sidecar/sidecar.md` — the live board the human watches with `sidecar`.
Move each item to the section that matches its state:

- `## 🧠 Needs action` — surfaced for the human to act on
- `## 🚧 In progress` — actively being worked
- `## 🚘 Parked` — deferred, not dropped
- `## ✅ Done` — merged, not yet released
- `## 📦 Shipped` — released (tag the version)

Write entries in Apple Developer documentation voice: declarative,
front-loaded verb, present tense, one fact per sentence. State outcomes,
not process.

One entry is at most:
- a status tag and title on the first line
- two sentences of detail — more belongs in the PR or issue you link
- bare URLs, each on its own line
- one `Next:` line naming the single next action (optional)

If sidecar isn't installed: `go install github.com/than/sidecar@latest`,
or a prebuilt binary from https://github.com/than/sidecar/releases/latest
<!-- /sidecar:review-queue -->
