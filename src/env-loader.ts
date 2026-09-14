import { readFileSync, statSync, openSync, closeSync, realpathSync, constants } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { parse } from "dotenv";
import { auditLog } from "./security/audit.js";

export interface LoadEnvResult {
  env: Record<string, string>;
  /** Set when a policy decision — not a missing file — produced an empty env. */
  blocked?: string;
}

interface CacheEntry {
  mtime: number;
  contentHash: string;
  env: Record<string, string>;
}

const cache = new Map<string, CacheEntry>();

export function loadEnv(projectDir: string): Record<string, string> {
  return loadEnvChecked(projectDir).env;
}

/**
 * As `loadEnv`, but distinguishes "refused by policy" from "no .env here".
 * A refusal otherwise disappears: the tools see an empty env, skip injection,
 * skip the allowlist check (nothing was injected), and send the request with
 * the placeholder left literal — so the caller gets a bare 401 and no reason,
 * including when it was their own `.env -> ~/shared/project.env` layout that
 * tripped the policy rather than an attack.
 */
export function loadEnvChecked(projectDir: string): LoadEnvResult {
  const envPath = join(projectDir, ".env");

  // Read the file first, then stat — avoids TOCTOU race where file
  // could change between stat (mtime check) and read (content load)
  // Read with O_NOFOLLOW to close the TOCTOU window between a symlink check and
  // the read. A cloned repo shipping `.env -> ~/.aws/credentials` otherwise
  // parses fine here, and this is the read behind api_call, run_with_env and
  // get_env_keys — run_with_env injects the result into a subprocess whose
  // output sanitization is best-effort by design. Mirrors syncExample.
  let content: string;
  try {
    let fd: number;
    try {
      fd = openSync(envPath, constants.O_RDONLY | constants.O_NOFOLLOW);
    } catch (e: unknown) {
      if ((e as NodeJS.ErrnoException).code !== "ELOOP") throw e;
      // A symlink — allow it only if it resolves inside the project.
      const realEnv = realpathSync(envPath);
      const realProject = realpathSync(projectDir);
      if (!realEnv.startsWith(realProject + "/") && realEnv !== realProject) {
        auditLog("load_env", { status: "blocked" });
        return {
          env: {},
          blocked:
            ".env is a symlink pointing outside the project directory; refusing to read it",
        };
      }
      fd = openSync(realEnv, constants.O_RDONLY);
    }
    try {
      content = readFileSync(fd, "utf-8");
    } finally {
      closeSync(fd);
    }
  } catch {
    return { env: {} };
  }

  let mtime: number;
  try {
    mtime = statSync(envPath).mtimeMs;
  } catch {
    // File was deleted between read and stat — use what we read
    return { env: parse(content) };
  }

  // Hash the content so identical-mtime replacements (coarse clock,
  // touch -t, secret rotation scripts) are still detected.
  const contentHash = createHash("sha256").update(content).digest("hex");

  const cached = cache.get(envPath);
  if (cached && cached.mtime === mtime && cached.contentHash === contentHash) {
    return { env: cached.env };
  }

  const env = parse(content);
  cache.set(envPath, { mtime, contentHash, env });
  return { env };
}

export function getEnvPath(projectDir: string): string {
  return join(projectDir, ".env");
}
