# secure-api-mcp

MCP server that lets Claude Code **use** secrets without **seeing** them.

Claude Code [silently reads `.env` files](https://www.knostic.ai/blog/claude-loads-secrets-without-permission) and [caches them in plaintext](https://www.reddit.com/r/SideProject/comments/1rec44l/claude_code_silently_stores_your_env_api_keys_in/) in `~/.claude/file-history/`. This server injects secrets into commands and API calls at runtime, then sanitizes output to strip secret values before they reach Claude's context.

**Threat model — read this.** The strength of the guard differs by tool:

- **`api_call`** has the smallest attack surface: no shell, structured output, SSRF protection, and an optional destination allowlist (see below). Sanitization reliably covers its responses.
- **`run_with_env`** runs an arbitrary shell command. Output sanitization is **best-effort, not a hard boundary** — a command can re-encode, reverse, chunk, or otherwise transform a secret into a form the sanitizer won't recognize before printing it. Treat it as defense-in-depth.

A secret can only be protected if you control where it goes. Both tools can send a secret to an external destination *by design*; restrict that with deny rules, the `api_call` allowlist, and review of `run_with_env` commands.

## Tools

- **`get_env_keys(project_dir)`** — Returns key names from `.env`. No values exposed.
- **`run_with_env(project_dir, command, env_keys?, timeout_ms?, include_mycnf?)`** — Runs a shell command with `.env` vars injected. Output is sanitized — secret values replaced with `[REDACTED:KEY_NAME]`. Set `include_mycnf` to also sanitize MySQL credentials from `.my.cnf` in command output.
- **`api_call(project_dir, url, method?, headers?, body?, auth_env_key?, timeout_ms?)`** — HTTP request with secret injection. `auth_env_key` adds a Bearer token. Headers support `{{KEY_NAME}}` template syntax. When a secret is injected, the destination host is checked against `SECURE_API_ALLOWED_HOSTS` (see below). Redirects are followed manually, up to 5 hops, with the SSRF guard and the allowlist re-applied to every hop. Times out after `timeout_ms` (default 30s).
- **`read_mycnf(project_dir, section?)`** — Reads MySQL `.my.cnf` configuration. Returns section names and safe fields (`port`, `database`, `socket`) with credentials (`user`, `password`, `host`) redacted as `[REDACTED:section.field]`. Checks `~/.my.cnf` and project-local `.my.cnf`.
- **`sync_env_example(project_dir)`** — Generates/updates `.env.example` from `.env`. Preserves comments and structure, strips values, uses smart placeholders.

## Setup

```bash
npm install && npm run build
```

Register in Claude Code:
```bash
claude mcp add secure-api -- node /path/to/secure-api-mcp/dist/index.js
```

Pair with deny rules in `~/.claude/settings.json` to block direct `.env` reads:
```json
"deny": [
  "Read(.env)", "Read(**/.env)",
  "Read(.env.local)", "Read(**/.env.local)",
  "Edit(.env)", "Edit(**/.env)"
]
```

## Keeping `.env.example` in sync

Run `sync_env_example` to generate or update `.env.example` from your `.env`. It:

- Preserves comments and blank lines from `.env`
- Strips secret values, replacing them with smart placeholders (URLs stay URL-shaped, booleans stay as-is, numbers stay as-is, everything else blanked)
- Merges with any existing `.env.example` — custom placeholders you've added won't be overwritten
- Lets Claude read `.env.example` freely (since deny rules only block `.env`) so it knows what config exists without seeing values

Pair this with `get_env_keys` and Claude has full awareness of your project's config without any secret exposure.

## Restricting where `api_call` can send secrets

By default `api_call` will attach a secret to a request bound for any public host (internal/private IPs are always blocked for SSRF). To restrict this, set `SECURE_API_ALLOWED_HOSTS` to a comma-separated list of permitted hosts:

```bash
export SECURE_API_ALLOWED_HOSTS="api.stripe.com,api.github.com,*.internal.example.com"
```

- **Set** — a request that injects a secret is **blocked** unless its host matches. `*.example.com` matches any subdomain and the apex `example.com`. Matching is case-insensitive.
- **Unset** — secrets are still sent (so existing setups keep working), but the response includes a `warnings` entry naming the destination host.

Requests that inject no secret are never gated.

## MySQL `.my.cnf` support

Claude can work with MySQL configs without seeing your credentials. `read_mycnf` exposes structural fields (`port`, `database`, `socket`) while redacting `user`, `password`, and `host`. When running MySQL commands via `run_with_env`, set `include_mycnf: true` to sanitize any credential values that appear in command output — the `mysql` CLI reads `~/.my.cnf` natively, so no env var injection is needed.

Resolution order matches MySQL's own: `~/.my.cnf` (global), then `<project_dir>/.my.cnf` (project-local overrides global per-field). `!include` and `!includedir` directives are followed. Includes in the project-local chain are contained to the project directory (resolved through symlinks) so a crafted project `.my.cnf` can't disclose files elsewhere on disk; the trusted global `~/.my.cnf` chain is unrestricted.

## How sanitization works

Secret values of 4 or more characters are replaced in all output, sorted longest-first to prevent partial matches. A value like `sk-abc123xyz` becomes `[REDACTED:API_KEY]`. The literal value, its base64 form, and its URL-encoded form are all matched, followed by a pattern pass for common token shapes (AWS, GitHub, Stripe, Slack, JWTs, private keys). Values transformed in other ways (hex, reversed, split across lines) are **not** caught — this is why `run_with_env` output is best-effort, not a guarantee.

## License

MIT
