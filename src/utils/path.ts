import { resolve, sep } from "node:path";

/**
 * True if `target` is `root` or sits beneath it. Uses the platform separator:
 * a hardcoded `/` never matches on Windows, so an ordinary in-project
 * `.env -> .env.local` would be refused — and `run_with_env` hard-fails on
 * that refusal, so the tool would stop working entirely for that layout.
 */
export function isWithin(root: string, target: string): boolean {
  const r = resolve(root);
  const t = resolve(target);
  return t === r || t.startsWith(r + sep);
}
