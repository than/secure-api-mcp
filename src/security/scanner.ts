/**
 * Pattern-based secret scanner.
 * Detects common secret formats in output text even if they're not in .env.
 * Applied as a second pass after env-value sanitization.
 */

const SECRET_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
  // AWS Access Key IDs
  { name: "aws-key", pattern: /\bAKIA[0-9A-Z]{16}\b/g },
  // AWS Secret Access Keys (40 chars base64-ish)
  { name: "aws-secret", pattern: /\b[0-9a-zA-Z/+=]{40}\b/g },
  // GitHub tokens
  { name: "github-token", pattern: /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b/g },
  { name: "github-pat", pattern: /\bgithub_pat_[A-Za-z0-9_]{22,255}\b/g },
  // Stripe keys
  { name: "stripe-key", pattern: /\b[sr]k_(live|test)_[A-Za-z0-9]{24,}\b/g },
  // JWT tokens
  { name: "jwt", pattern: /\beyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b/g },
  // Slack tokens
  { name: "slack-token", pattern: /\bxox[bpras]-[A-Za-z0-9-]{10,}\b/g },
  // Generic long hex strings (likely tokens/hashes) — 40+ chars
  { name: "hex-token", pattern: /\b[0-9a-f]{40,}\b/gi },
  // Bearer tokens in output (e.g., from curl -v)
  { name: "bearer", pattern: /Bearer\s+[A-Za-z0-9._~+/=-]{20,}/g },
  // Private keys
  { name: "private-key", pattern: /-----BEGIN\s+(RSA\s+)?PRIVATE\sKEY-----/g },
];

export function scanForSecrets(text: string): string {
  let result = text;

  for (const { pattern } of SECRET_PATTERNS) {
    // Reset regex lastIndex for global patterns
    pattern.lastIndex = 0;
    result = result.replace(pattern, "[REDACTED:detected]");
  }

  return result;
}
