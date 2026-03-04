import { scanForSecrets } from "../security/scanner.js";

export function sanitize(
  text: string,
  env: Record<string, string>
): string {
  // Build replacements sorted longest-first to avoid partial matches
  const replacements = Object.entries(env)
    .filter(([, value]) => value.length > 2)
    .sort((a, b) => b[1].length - a[1].length);

  let result = text;
  let index = 1;

  for (const [, value] of replacements) {
    const tag = `[REDACTED:${index}]`;

    // Match the literal secret value
    result = result.split(value).join(tag);

    // Match base64-encoded form
    const b64 = Buffer.from(value).toString("base64");
    if (b64.length > 4) {
      result = result.split(b64).join(tag);
    }

    // Match URL-encoded form
    const urlEncoded = encodeURIComponent(value);
    if (urlEncoded !== value) {
      result = result.split(urlEncoded).join(tag);
    }

    index++;
  }

  // Second pass: scan for common secret patterns not in .env
  result = scanForSecrets(result);

  return result;
}
