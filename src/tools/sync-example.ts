import { z } from "zod";
import { isAbsolute } from "node:path";
import { readFileSync, writeFileSync, existsSync, realpathSync, lstatSync } from "node:fs";
import { join } from "node:path";
import { validateProjectDir } from "../security/path-validator.js";
import { auditLog } from "../security/audit.js";

export const SyncExampleSchema = z.object({
  project_dir: z
    .string()
    .refine((p) => isAbsolute(p), "project_dir must be an absolute path")
    .describe("Absolute path to the project directory"),
});

// Keys where numeric values are safe to preserve (non-sensitive config)
const SAFE_NUMERIC_KEYS =
  /^(PORT|TIMEOUT|RETRIES|MAX_|MIN_|SIZE|LIMIT|WORKERS|THREADS|POOL|BATCH|INTERVAL|DELAY|TTL|DURATION|CONCURRENCY|BACKOFF)/i;

function smartPlaceholder(key: string, value: string): string {
  // URLs keep URL shape
  if (/^https?:\/\//.test(value)) return "https://example.com";
  // Booleans — only for clearly non-sensitive flag keys
  if (
    (value === "true" || value === "false") &&
    /^(ENABLE|USE|IS_|HAS_|ALLOW|DEBUG|VERBOSE|STRICT|FORCE)/i.test(key)
  ) {
    return value;
  }
  // Pure numbers — only preserve for clearly non-sensitive keys
  if (/^\d+$/.test(value) && SAFE_NUMERIC_KEYS.test(key)) {
    return value;
  }
  // Port-like
  if (key.toLowerCase().includes("port") && /^\d+$/.test(value)) return value;
  // Empty
  if (value === "") return "";
  // Default — don't leak potentially sensitive values
  return "";
}

function parseExistingExample(
  path: string
): Map<string, { comment?: string; placeholder: string }> {
  const map = new Map<string, { comment?: string; placeholder: string }>();
  if (!existsSync(path)) return map;

  const lines = readFileSync(path, "utf-8").split("\n");
  let pendingComment: string | undefined;

  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith("#")) {
      pendingComment = trimmed;
      continue;
    }
    const eqIndex = trimmed.indexOf("=");
    if (eqIndex > 0) {
      const key = trimmed.slice(0, eqIndex).trim();
      const placeholder = trimmed.slice(eqIndex + 1).trim();
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

  // Symlink traversal protection: if .env.example already exists as a symlink,
  // resolve it and confirm the real path stays within the project directory.
  if (existsSync(examplePath) && lstatSync(examplePath).isSymbolicLink()) {
    const realTarget = realpathSync(examplePath);
    const realProject = realpathSync(args.project_dir);
    if (!realTarget.startsWith(realProject + "/") && realTarget !== realProject) {
      auditLog("sync_env_example", { status: "blocked" });
      return { error: "Refusing to write .env.example: symlink points outside project directory" };
    }
  }

  const existing = parseExistingExample(examplePath);
  const envContent = readFileSync(envPath, "utf-8");
  const lines = envContent.split("\n");
  const outputLines: string[] = [];
  let keysCount = 0;

  for (const line of lines) {
    const trimmed = line.trim();

    // Preserve blank lines and comments
    if (trimmed === "" || trimmed.startsWith("#")) {
      outputLines.push(line);
      continue;
    }

    const eqIndex = trimmed.indexOf("=");
    if (eqIndex <= 0) {
      outputLines.push(line);
      continue;
    }

    const key = trimmed.slice(0, eqIndex).trim();
    const value = trimmed.slice(eqIndex + 1).trim();

    // Use existing example placeholder if it exists, otherwise generate
    const existingEntry = existing.get(key);
    const placeholder = existingEntry
      ? existingEntry.placeholder
      : smartPlaceholder(key, value);

    // Preserve any custom comment from existing .env.example
    if (existingEntry?.comment && !outputLines.at(-1)?.trim().startsWith("#")) {
      outputLines.push(existingEntry.comment);
    }

    outputLines.push(`${key}=${placeholder}`);
    keysCount++;
  }

  writeFileSync(examplePath, outputLines.join("\n") + "\n");
  auditLog("sync_env_example", { keysAccessedCount: keysCount, status: "success" });
  return { path: examplePath, keys_synced: keysCount };
}
