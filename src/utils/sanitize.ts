import { scanForSecrets } from "../security/scanner.js";

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function replaceCaseInsensitive(text: string, needle: string, tag: string): string {
  return text.replace(new RegExp(escapeRegExp(needle), "gi"), tag);
}

export function sanitize(
  text: string,
  env: Record<string, string>
): string {
  // Build replacements sorted longest-first to avoid partial matches
  const replacements = Object.entries(env)
    .filter(([, value]) => value.length > 3)
    .sort((a, b) => b[1].length - a[1].length);

  let result = text;

  for (const [key, value] of replacements) {
    const tag = `[REDACTED:${key}]`;

    // Match the literal secret value, case-insensitively. Callers routinely
    // hand us text that has passed through `new URL()`, which ASCII-lowercases
    // the host component — so a token reflected into a hostname reaches here
    // case-folded and a case-sensitive match would miss it entirely.
    result = replaceCaseInsensitive(result, value, tag);

    // Match base64-encoded form. Exact: base64's alphabet is case-significant,
    // so folding case here would both miss and over-match.
    const b64 = Buffer.from(value).toString("base64");
    if (b64.length > 4) {
      result = result.split(b64).join(tag);
    }

    // Match URL-encoded form. Percent escapes are hex, so case-insensitive is
    // safe and catches %2F as readily as %2f.
    const urlEncoded = encodeURIComponent(value);
    if (urlEncoded !== value) {
      result = replaceCaseInsensitive(result, urlEncoded, tag);
    }
  }

  // Second pass: scan for common secret patterns not in .env
  result = scanForSecrets(result);

  return result;
}
