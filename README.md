# secure-api-mcp

MCP server that lets Claude Code **use** secrets without **seeing** them.

Claude Code [silently reads `.env` files](https://www.knostic.ai/blog/claude-loads-secrets-without-permission) and [caches them in plaintext](https://www.reddit.com/r/SideProject/comments/1rec44l/claude_code_silently_stores_your_env_api_keys_in/) in `~/.claude/file-history/`. This server injects secrets into commands and API calls at runtime, then sanitizes all output so secret values never reach Claude's context.

## Tools

- **`get_env_keys(project_dir)`** — Returns key names from `.env`. No values exposed.
- **`run_with_env(project_dir, command, env_keys?, timeout_ms?)`** — Runs a shell command with `.env` vars injected. Output is sanitized — secret values replaced with `[REDACTED:KEY_NAME]`.
- **`api_call(project_dir, url, method?, headers?, body?, auth_env_key?)`** — HTTP request with secret injection. `auth_env_key` adds a Bearer token. Headers support `{{KEY_NAME}}` template syntax.
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

## How sanitization works

Secret values longer than 4 characters are replaced in all output, sorted longest-first to prevent partial matches. A value like `sk-abc123xyz` in output becomes `[REDACTED:API_KEY]`.

## License

MIT
