import { z } from "zod";
import { isAbsolute } from "node:path";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { validateProjectDir } from "../security/path-validator.js";

export const SyncExampleSchema = z.object({
  project_dir: z
    .string()
    .refine((p) => isAbsolute(p), "project_dir must be an absolute path")
    .describe("Absolute path to the project directory"),
});

function smartPlaceholder(key: string, value: string): string {
  // URLs keep URL shape
  if (/^https?:\/\//.test(value)) return "https://example.com";
  // Booleans
  if (value === "true" || value === "false") return value;
  // Pure numbers
  if (/^\d+$/.test(value)) return value;
  // Port-like
  if (key.toLowerCase().includes("port") && /^\d+$/.test(value)) return value;
  // Empty
  if (value === "") return "";
  // Default
  return "";
}

function parseExistingExample(
  path: string
): Map<string, { comment?: string; placeholder: string }> {
  const map = new Map<string, { comment?: string; placeholder: string }>();
  if (!existsSync(path)) return map;

  const lines = readFileSync(path, "utf-8").split("\n");
  let pendingComment: string | undefined;

  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith("#")) {
      pendingComment = trimmed;
      continue;
    }
    const eqIndex = trimmed.indexOf("=");
    if (eqIndex > 0) {
      const key = trimmed.slice(0, eqIndex).trim();
      const placeholder = trimmed.slice(eqIndex + 1).trim();
      map.set(key, { comment: pendingComment, placeholder });
      pendingComment = undefined;
    } else {
      pendingComment = undefined;
    }
  }
  return map;
}

export async function syncExample(
  args: z.infer<typeof SyncExampleSchema>
): Promise<{ path: string; keys_synced: number } | { error: string }> {
  const pathCheck = validateProjectDir(args.project_dir);
  if (!pathCheck.valid) {
    return { error: pathCheck.reason! };
  }

  const envPath = join(args.project_dir, ".env");
  const examplePath = join(args.project_dir, ".env.example");

  if (!existsSync(envPath)) {
    return { path: examplePath, keys_synced: 0 };
  }

  const existing = parseExistingExample(examplePath);
  const envContent = readFileSync(envPath, "utf-8");
  const lines = envContent.split("\n");
  const outputLines: string[] = [];
  let keysCount = 0;

  for (const line of lines) {
    const trimmed = line.trim();

    // Preserve blank lines and comments
    if (trimmed === "" || trimmed.startsWith("#")) {
      outputLines.push(line);
      continue;
    }

    const eqIndex = trimmed.indexOf("=");
    if (eqIndex <= 0) {
      outputLines.push(line);
      continue;
    }

    const key = trimmed.slice(0, eqIndex).trim();
    const value = trimmed.slice(eqIndex + 1).trim();

    // Use existing example placeholder if it exists, otherwise generate
    const existingEntry = existing.get(key);
    const placeholder = existingEntry
      ? existingEntry.placeholder
      : smartPlaceholder(key, value);

    // Preserve any custom comment from existing .env.example
    if (existingEntry?.comment && !outputLines.at(-1)?.trim().startsWith("#")) {
      outputLines.push(existingEntry.comment);
    }

    outputLines.push(`${key}=${placeholder}`);
    keysCount++;
  }

  writeFileSync(examplePath, outputLines.join("\n") + "\n");
  return { path: examplePath, keys_synced: keysCount };
}
