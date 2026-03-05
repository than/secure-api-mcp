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
    // Use split+join for global replace without regex escaping issues
    result = result.split(value).join(`[REDACTED:${key}]`);
  }
  return result;
}
