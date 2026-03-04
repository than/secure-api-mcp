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

  let mtime: number;
  try {
    mtime = statSync(envPath).mtimeMs;
  } catch {
    return {};
  }

  const cached = cache.get(envPath);
  if (cached && cached.mtime === mtime) {
    return cached.env;
  }

  const content = readFileSync(envPath, "utf-8");
  const env = parse(content);
  cache.set(envPath, { mtime, env });
  return env;
}

export function getEnvPath(projectDir: string): string {
  return join(projectDir, ".env");
}
