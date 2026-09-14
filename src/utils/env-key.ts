import { resolve, sep } from "node:path";

/**
 * A dotenv key of this shape is a fragment of a value, not a key.
 *
 * A multi-line value that is unquoted — or quoted in a way dotenv resolves to
 * its unquoted branch — leaves each following line scanned as its own
 * assignment. A base64 line whose only non-word characters are `.`/`-`/a
 * trailing `=` then tokenizes as `KEY=`; base64url bodies (JWTs, GCP
 * service-account keys) sit entirely within `[\w.-]`, so every line of one
 * qualifies, not just the padded tail.
 *
 * The tell is length without an underscore: real env var names of 16+
 * characters effectively always carry one, and base64 bodies never do.
 */
export const VALUE_FRAGMENT_KEY = /^[A-Za-z0-9.-]{16,}$/;

/** True if `key` is a plausible env var name rather than a value fragment. */
export function isPlausibleEnvKey(key: string): boolean {
  return !VALUE_FRAGMENT_KEY.test(key);
}

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
