/**
 * Destination host allowlist for api_call.
 *
 * A secret is only safe to attach to an outbound request if we know where it's
 * going. When SECURE_API_ALLOWED_HOSTS is set (comma-separated host patterns),
 * secrets are only attached to requests whose host matches — anything else is
 * blocked. When the variable is unset, enforcement is off: the secret still
 * goes through (so existing setups keep working), but callers get a warning so
 * exfiltration to an unexpected host is at least visible.
 *
 * Patterns support exact hostnames ("api.stripe.com") and leading-wildcard
 * subdomain matches ("*.example.com" — matches "a.example.com" and the apex
 * "example.com"). Matching is case-insensitive.
 */

export interface HostPolicy {
  /** True when an allowlist is configured, i.e. hard enforcement is active. */
  enforced: boolean;
  /** Returns true if `host` is permitted to receive secrets. */
  allows(host: string): boolean;
}

function parsePatterns(raw: string): string[] {
  return raw
    .split(",")
    .map((p) => p.trim().toLowerCase())
    .filter((p) => p.length > 0);
}

function matchPattern(pattern: string, host: string): boolean {
  if (pattern.startsWith("*.")) {
    const base = pattern.slice(2);
    return host === base || host.endsWith("." + base);
  }
  return host === pattern;
}

/** Strip surrounding brackets from an IPv6 literal hostname. */
function bareHost(host: string): string {
  if (host.startsWith("[") && host.endsWith("]")) {
    return host.slice(1, -1);
  }
  return host;
}

export function getHostPolicy(
  env: NodeJS.ProcessEnv = process.env
): HostPolicy {
  const raw = env.SECURE_API_ALLOWED_HOSTS;
  const patterns = raw ? parsePatterns(raw) : [];

  if (patterns.length === 0) {
    // Unset or empty — enforcement off, everything allowed.
    return { enforced: false, allows: () => true };
  }

  return {
    enforced: true,
    allows: (host: string) => {
      const h = bareHost(host).toLowerCase();
      return patterns.some((p) => matchPattern(p, h));
    },
  };
}
