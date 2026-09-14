import { z } from "zod";
import { isAbsolute } from "node:path";
import { readFileSync, writeFileSync, existsSync, realpathSync, openSync, closeSync, renameSync, unlinkSync, constants } from "node:fs";
import { join } from "node:path";
import { validateProjectDir } from "../security/path-validator.js";
import { auditLog } from "../security/audit.js";
import { sanitize } from "../utils/sanitize.js";
import { scanForSecrets } from "../security/scanner.js";
import { parse } from "dotenv";

export const SyncExampleSchema = z.object({
  project_dir: z
    .string()
    .refine((p) => isAbsolute(p), "project_dir must be an absolute path")
    .describe("Absolute path to the project directory"),
});

// Sensitive tokens that, appearing as a whole underscore-delimited word
// ANYWHERE in the key, force redaction regardless of any "safe" prefix. This
// is the deny-first gate: it runs before the safe allowlists so a key like
// POOL_PASSWORD or MIN_API_KEY (safe first token, secret later token) can't
// slip its value through. The trailing boundary means an appended `S` does NOT
// match, so count-style keys like MAX_TOKENS / MAX_KEYS stay preserved — while
// words that are themselves inherently plural (SECRETS, CREDENTIALS) are listed
// explicitly.
const SECRET_KEY_TOKENS =
  /(?:^|_)(?:SECRET|SECRETS|TOKEN|KEY|PASSWORD|PASSWD|PWD|PASS|PIN|CODE|AUTH|CREDENTIAL|CREDENTIALS|PRIVATE|CERT|SIGNATURE|SIGNING|SALT|NONCE|SEED|APIKEY)(?:_|$)/i;

// Keys where numeric values are safe to preserve (non-sensitive config).
// PORT may appear as any whole token (DB_PORT, API_PORT_NUMBER); the rest must
// lead the key. Every alternative ends at a `_`/end boundary so e.g.
// PORTAL_ACCESS_TOKEN or SIZEABLE_TOKEN don't match on the PORT/SIZE prefix.
const SAFE_NUMERIC_KEYS =
  /(?:(?:^|_)PORT|^(?:TIMEOUT|RETRIES|MAX|MIN|SIZE|LIMIT|WORKERS|THREADS|POOL|BATCH|INTERVAL|DELAY|TTL|DURATION|CONCURRENCY|BACKOFF))(?:_|$)/i;

// Boolean flag keys whose true/false value is safe to preserve. Each token is
// boundary-anchored so USE doesn't match USER_IS_ADMIN, IS doesn't match
// ISLAND, etc.
const BOOL_FLAG_KEYS =
  /^(?:ENABLE|ENABLED|USE|IS|HAS|ALLOW|ALLOWED|DEBUG|VERBOSE|STRICT|FORCE|FORCED)(?:_|$)/i;

function smartPlaceholder(key: string, value: string): string {
  // Deny-first: any key that names a secret is never echoed, whatever its value.
  if (SECRET_KEY_TOKENS.test(key)) return "";
  // URLs keep URL shape
  if (/^https?:\/\//.test(value)) return "https://example.com";
  // Booleans — only for clearly non-sensitive flag keys
  if ((value === "true" || value === "false") && BOOL_FLAG_KEYS.test(key)) {
    return value;
  }
  // Pure numbers — only preserve for clearly non-sensitive keys
  if (/^\d+$/.test(value) && SAFE_NUMERIC_KEYS.test(key)) {
    return value;
  }
  // Empty
  if (value === "") return "";
  // Default — don't leak potentially sensitive values
  return "";
}

/**
 * dotenv's LINE regex, copied verbatim from `dotenv/lib/main.js`. This is the
 * tokenizer of record: `parse()` is this pattern in a loop. Re-deriving where a
 * value starts and ends by hand kept diverging from it — on the `:` separator,
 * on a trailing `# comment`, on `JSON="{"a":1}"`, on a `\\` run before the
 * closing quote — and every divergence in the "closes early" direction wrote
 * key material into a file meant to be committed. Per CLAUDE.md: don't
 * hand-parse `.env`.
 */
const DOTENV_LINE =
  /(?:^|^)\s*(?:export\s+)?([\w.-]+)(?:\s*=\s*?|:\s+?)(\s*'(?:\\'|[^'])*'|\s*"(?:\\"|[^"])*"|\s*`(?:\\`|[^`])*`|[^#\r\n]+)?\s*(?:#.*)?(?:$|$)/gm;

/** Single-line `KEY=value`, for reading this tool's own output back. */
const SINGLE_ASSIGN = /^\s*(export\s+)?([\w.-]+)(?:\s*=\s*?|:\s+?)/;

/** Commented-out assignment, e.g. `# OLD_API_KEY=sk_live_...`. */
const COMMENTED_ASSIGN = /^(\s*#+\s*)((?:export\s+)?[\w.-]+)(?:\s*=\s*|:\s+)(.*)$/;

interface Assignment {
  key: string;
  exportPrefix: string;
  value: string;
  /** Source line the assignment starts on. */
  startLine: number;
  /** Last source line its value occupies; equals startLine unless multi-line. */
  endLine: number;
}

/**
 * Every assignment dotenv finds, with the exact source lines its value spans.
 * Uses match indices so the span comes from the parser rather than from
 * re-reading the text.
 */
function scanAssignments(content: string): Assignment[] {
  const countNewlines = (upTo: number) => {
    let n = 0;
    for (let i = 0; i < upTo; i++) if (content[i] === "\n") n++;
    return n;
  };

  const out: Assignment[] = [];
  const re = new RegExp(DOTENV_LINE.source, "dgm");
  let m: RegExpExecArray | null;
  while ((m = re.exec(content)) !== null) {
    if (m[0].length === 0) {
      re.lastIndex++;
      continue;
    }
    const indices = (m as RegExpExecArray & { indices: Array<[number, number] | undefined> })
      .indices;
    const keySpan = indices[1]!;
    const valueSpan = indices[2];
    out.push({
      key: m[1],
      exportPrefix: /^\s*(export\s+)/.exec(m[0])?.[1] ?? "",
      value: (m[2] ?? "").trim(),
      startLine: countNewlines(keySpan[0]),
      endLine: countNewlines(valueSpan ? valueSpan[1] : keySpan[1]),
    });
  }
  return out;
}

/**
 * True if a stored placeholder is a URL carrying credentials — either userinfo
 * (`postgres://user:pw@host`) or a credential-shaped query parameter
 * (`...?password=x`). The query case matters because SECRET_KEY_TOKENS is
 * deliberately incomplete: `DATABASE_URL` does not match it, so a value like
 * `postgres://host/db?password=x` clears both the key gate and the scanner.
 *
 * Deliberately NOT a byte-equality check against the live value: `.env` and
 * `.env.example` legitimately share non-secret defaults such as
 * `APP_ENV=production`, and blanking those is a regression the suite guards.
 */
function hasUrlCredentials(value: string): boolean {
  try {
    const u = new URL(value);
    if (u.username !== "" || u.password !== "") return true;
    for (const name of u.searchParams.keys()) {
      if (SECRET_KEY_TOKENS.test(name)) return true;
    }
    return false;
  } catch {
    return false;
  }
}

function parseExistingExample(
  path: string
): Map<string, { comment?: string; placeholder: string }> {
  const map = new Map<string, { comment?: string; placeholder: string }>();
  if (!existsSync(path)) return map;

  // Read with O_NOFOLLOW and refuse a symlink outright. A committed
  // `.env.example -> .env` would otherwise have its "placeholders" (the
  // victim's real values) read here and copied back into the file we write.
  // Containment is not enough: the in-project `-> .env` case stays inside the
  // project. No reuse is the safe degradation — placeholders regenerate.
  let fd: number;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch {
    // ELOOP: a symlink, refused deliberately. Anything else (EACCES, a race
    // after existsSync) also means "no placeholders to reuse" — degrade to
    // regenerating them rather than throwing past the structured error
    // contract every other failure here honours.
    return map;
  }
  let content: string;
  try {
    content = readFileSync(fd, "utf-8");
  } catch {
    // open(2) on a directory succeeds with O_RDONLY, so EISDIR lands here
    // rather than above.
    return map;
  } finally {
    closeSync(fd);
  }
  const lines = content.split("\n");
  let pendingComment: string | undefined;

  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith("#")) {
      pendingComment = trimmed;
      continue;
    }
    // `.env.example` is this tool's own output — single-line `KEY=value`. Use
    // the same tokenizer anyway so `export FOO` keys on `FOO` at lookup.
    const assign = SINGLE_ASSIGN.exec(line);
    if (assign !== null) {
      const key = assign[2];
      const placeholder = line.slice(assign[0].length).trim();
      map.set(key, { comment: pendingComment, placeholder });
      pendingComment = undefined;
    } else {
      pendingComment = undefined;
    }
  }
  return map;
}

export async function syncExample(
  args: z.infer<typeof SyncExampleSchema>
): Promise<{ path: string; keys_synced: number } | { error: string }> {
  const pathCheck = validateProjectDir(args.project_dir);
  if (!pathCheck.valid) {
    auditLog("sync_env_example", { status: "blocked" });
    return { error: pathCheck.reason! };
  }

  const envPath = join(args.project_dir, ".env");
  const examplePath = join(args.project_dir, ".env.example");

  if (!existsSync(envPath)) {
    return { path: examplePath, keys_synced: 0 };
  }

  // Read .env with O_NOFOLLOW to close the TOCTOU window between a symlink check
  // and the read. If the open throws ELOOP, the file is a symlink — validate the
  // target stays within the project before re-opening normally.
  let envContent: string;
  let fd: number;
  try {
    fd = openSync(envPath, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch (e: unknown) {
    const err = e as NodeJS.ErrnoException;
    if (err.code !== "ELOOP") throw e;
    // .env is a symlink — block if it resolves outside the project
    const realEnv = realpathSync(envPath);
    const realProject = realpathSync(args.project_dir);
    if (!realEnv.startsWith(realProject + "/") && realEnv !== realProject) {
      auditLog("sync_env_example", { status: "blocked" });
      return { error: "Refusing to read .env: symlink points outside project directory" };
    }
    fd = openSync(realEnv, constants.O_RDONLY);
  }
  try {
    envContent = readFileSync(fd, "utf-8");
  } finally {
    closeSync(fd);
  }

  const existing = parseExistingExample(examplePath);

  // dotenv is the authority on what is a key and what is value content. Its
  // multi-line quoted values span lines that have no `KEY=` shape — including
  // lines starting with `#`, which are secret material rather than comments.
  const envValues = parse(envContent);
  const validKeys = new Set(Object.keys(envValues));
  const lines = envContent.split("\n");

  // Lines consumed by a value that began earlier: never emitted, never treated
  // as comments.
  const assignments = scanAssignments(envContent);
  const assignmentAt = new Map<number, Assignment>();
  const consumed = new Set<number>();
  for (const a of assignments) {
    assignmentAt.set(a.startLine, a);
    for (let i = a.startLine + 1; i <= a.endLine; i++) consumed.add(i);
  }

  /**
   * Redact a comment before preserving it. `sanitize` against the live values
   * catches a comment echoing a secret that is currently in `.env` — something
   * `scanForSecrets` structurally cannot do, since it only knows a handful of
   * well-known prefixes. A commented-out assignment is additionally routed
   * through `smartPlaceholder`, catching a parked credential by shape rather
   * than by brand.
   */
  const safeComment = (line: string): string => {
    const commented = COMMENTED_ASSIGN.exec(line);
    if (commented !== null) {
      const [, hash, rawKey, rawValue] = commented;
      const key = rawKey.replace(/^export\s+/, "");
      return `${hash}${rawKey}=${smartPlaceholder(key, rawValue.trim())}`;
    }
    return sanitize(scanForSecrets(line), envValues);
  };

  const outputLines: string[] = [];
  const emitted = new Set<string>();

  for (let i = 0; i < lines.length; i++) {
    if (consumed.has(i)) continue;

    const line = lines[i];
    const assignment = assignmentAt.get(i);

    if (assignment === undefined) {
      const trimmed = line.trim();
      // Preserve blank lines and comments; drop anything else rather than
      // echoing it.
      if (trimmed === "") outputLines.push(line);
      else if (trimmed.startsWith("#")) outputLines.push(safeComment(line));
      continue;
    }

    const { key, exportPrefix, value } = assignment;
    if (!validKeys.has(key)) continue;

    // Reuse a curated placeholder from an existing .env.example, but NEVER for a
    // key that names a secret. An earlier (buggy) run may have written the real
    // value into the example file, and a stored value for a sensitive key is
    // indistinguishable from a leaked one — so regenerate, routing it back
    // through the deny-first gate. This heals leaks a value-equality check would
    // miss (a rotated secret, or quoting drift between .env and .env.example).
    // Non-sensitive keys keep their curated placeholder as before.
    const existingEntry = existing.get(key);
    const generated = smartPlaceholder(key, value);
    const reusable =
      existingEntry !== undefined &&
      !SECRET_KEY_TOKENS.test(key) &&
      // A stored placeholder that scans as a secret, or carries URL
      // credentials, is a leaked value from an earlier run — regenerate.
      scanForSecrets(existingEntry.placeholder) === existingEntry.placeholder &&
      !hasUrlCredentials(existingEntry.placeholder) &&
      // Residual case CLAUDE.md warns SECRET_KEY_TOKENS will miss:
      // SLACK_WEBHOOK=https://hooks.slack.com/services/T00/B00/XXXX clears the
      // key regex, the scanner and hasUrlCredentials, yet a stored copy
      // byte-identical to the live value is that value. Regenerate only when
      // this tool has an opinion of its own that differs — a blank generated
      // placeholder means no opinion, which is what keeps a curated
      // APP_ENV=production intact.
      !(
        generated !== "" &&
        generated !== value &&
        existingEntry.placeholder === value
      );
    const placeholder = reusable ? existingEntry!.placeholder : generated;

    // Preserve any custom comment from existing .env.example
    if (existingEntry?.comment && !outputLines.at(-1)?.trim().startsWith("#")) {
      // Redact this too: a `.env.example` from an earlier, leakier run can
      // already hold a parked credential, and it would otherwise be re-emitted
      // verbatim even while the value beside it is regenerated.
      outputLines.push(safeComment(existingEntry.comment));
    }

    outputLines.push(`${exportPrefix}${key}=${placeholder}`);
    emitted.add(key);
  }

  // Write atomically via temp file + rename. renameSync replaces the destination
  // path itself (including symlinks) rather than following it, closing both the
  // TOCTOU window and any symlink traversal on .env.example.
  // Backstop. If the span scan and dotenv's own parse ever disagree, a key
  // goes missing here rather than a value being echoed there — and .env.example
  // would be renamed over the curated original having silently lost it.
  // Compare membership rather than counts: a `.env` that repeats a key emits
  // more lines than validKeys has entries, and a count check would spend that
  // slack covering for a key that really was dropped.
  const missing = [...validKeys].filter((k) => !emitted.has(k));
  if (missing.length > 0) {
    auditLog("sync_env_example", { status: "blocked" });
    return {
      error:
        `Refusing to write .env.example: ${missing.length} key(s) parsed from .env ` +
        `were not emitted (${missing.slice(0, 3).join(", ")}). A quote in .env is ` +
        `probably unterminated.`,
    };
  }

  // The temp path is predictable, so a committed `.env.example.tmp` symlink
  // would be written *through* — truncating its target — before the rename
  // moved the link aside. O_EXCL|O_NOFOLLOW refuses any pre-existing entry,
  // symlink or not. A leftover .tmp from a crashed run is unlinked first;
  // unlink removes the link itself rather than following it, and the O_EXCL
  // create stays atomic against anything racing to recreate it.
  const tmpPath = join(args.project_dir, ".env.example.tmp");
  const tmpFlags =
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW;
  let tmpFd: number;
  try {
    tmpFd = openSync(tmpPath, tmpFlags);
  } catch (e: unknown) {
    if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
    try {
      // unlink removes the entry itself rather than following it; the O_EXCL
      // create then stays atomic against anything racing to recreate it.
      unlinkSync(tmpPath);
      tmpFd = openSync(tmpPath, tmpFlags);
    } catch {
      // A directory at the path, or a re-plant between the two calls. Return
      // the structured error every other failure here returns.
      auditLog("sync_env_example", { status: "blocked" });
      return { error: "Refusing to write .env.example: temp path is not writable" };
    }
  }
  try {
    writeFileSync(tmpFd, outputLines.join("\n") + "\n");
  } finally {
    closeSync(tmpFd);
  }
  renameSync(tmpPath, examplePath);
  auditLog("sync_env_example", { keysAccessedCount: emitted.size, status: "success" });
  return { path: examplePath, keys_synced: emitted.size };
}
