/**
 * A dotenv key of this shape is a fragment of a value, not a key.
 *
 * A multi-line value that is unquoted — or quoted in a way dotenv resolves to
 * its unquoted branch — leaves each following line scanned as its own
 * assignment. A base64 line whose only non-word characters are `.`/`-`/`_` or a
 * trailing `=` then tokenizes as `KEY=`.
 *
 * The tell is length plus mixed case. base64 and base64url bodies of any real
 * length carry both cases; conventional env var names are SCREAMING_SNAKE or
 * lowercase_snake and carry one. Length alone is not enough, and "no
 * underscore" is worse than not enough — `_` is exactly the character that
 * distinguishes base64url from base64, and excluding it would also drop a
 * legitimate dotted key like `spring.datasource.password`.
 */
export const VALUE_FRAGMENT_KEY = /^(?=.*[a-z])(?=.*[A-Z])[\w.-]{16,}$/;

/** True if `key` is a plausible env var name rather than a value fragment. */
export function isPlausibleEnvKey(key: string): boolean {
  return !VALUE_FRAGMENT_KEY.test(key);
}
