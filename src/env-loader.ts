import { readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { parse } from "dotenv";

interface CacheEntry {
  mtime: number;
  env: Record<string, string>;
}

const cache = new Map<string, CacheEntry>();

export function loadEnv(projectDir: string): Record<string, string> {
  const envPath = join(projectDir, ".env");

  // Read the file first, then stat — avoids TOCTOU race where file
  // could change between stat (mtime check) and read (content load)
  let content: string;
  try {
    content = readFileSync(envPath, "utf-8");
  } catch {
    return {};
  }

  let mtime: number;
  try {
    mtime = statSync(envPath).mtimeMs;
  } catch {
    // File was deleted between read and stat — use what we read
    const env = parse(content);
    return env;
  }

  const cached = cache.get(envPath);
  if (cached && cached.mtime === mtime) {
    return cached.env;
  }

  const env = parse(content);
  cache.set(envPath, { mtime, env });
  return env;
}

export function getEnvPath(projectDir: string): string {
  return join(projectDir, ".env");
}
