/**
 * Pattern-based secret scanner.
 * Detects common secret formats in output text even if they're not in .env.
 * Applied as a second pass after env-value sanitization.
 *
 * Patterns are intentionally conservative to avoid false positives —
 * only match well-known token prefixes with high confidence.
 */

const SECRET_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
  // AWS Access Key IDs (always start with AKIA)
  { name: "aws-key", pattern: /\bAKIA[0-9A-Z]{16}\b/g },
  // GitHub tokens (well-defined prefixes)
  { name: "github-token", pattern: /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b/g },
  { name: "github-pat", pattern: /\bgithub_pat_[A-Za-z0-9_]{22,255}\b/g },
  // Stripe keys (well-defined prefixes)
  { name: "stripe-key", pattern: /\b[sr]k_(live|test)_[A-Za-z0-9]{24,}\b/g },
  // JWT tokens (three base64url segments starting with eyJ)
  { name: "jwt", pattern: /\beyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b/g },
  // Slack tokens (well-defined prefixes)
  { name: "slack-token", pattern: /\bxox[bpras]-[A-Za-z0-9-]{10,}\b/g },
  // Bearer tokens in verbose output (e.g., from curl -v)
  { name: "bearer", pattern: /Bearer\s+[A-Za-z0-9._~+/=-]{20,}/g },
  // Private keys
  { name: "private-key", pattern: /-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\sKEY-----/g },
];

// NOTE: Patterns intentionally excluded to avoid false positives:
// - Generic hex strings (40+ chars) — matches git commit SHAs, shasum output, content hashes
// - Generic base64 strings (40 chars) — matches too many benign encoded values

export function scanForSecrets(text: string): string {
  let result = text;

  for (const { pattern } of SECRET_PATTERNS) {
    // Reset regex lastIndex for global patterns
    pattern.lastIndex = 0;
    result = result.replace(pattern, "[REDACTED:detected]");
  }

  return result;
}
