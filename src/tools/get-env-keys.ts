import { z } from "zod";
import { isAbsolute } from "node:path";
import { loadEnvChecked } from "../env-loader.js";
import { isPlausibleEnvKey, keyStub } from "../utils/env-key.js";
import { validateProjectDir } from "../security/path-validator.js";
import { auditLog } from "../security/audit.js";

export const GetEnvKeysSchema = z.object({
  project_dir: z
    .string()
    .refine((p) => isAbsolute(p), "project_dir must be an absolute path")
    .describe("Absolute path to the project directory"),
});

export async function getEnvKeys(
  args: z.infer<typeof GetEnvKeysSchema>
): Promise<{ keys: string[]; warnings?: string[] } | { error: string }> {
  const pathCheck = validateProjectDir(args.project_dir);
  if (!pathCheck.valid) {
    auditLog("get_env_keys", { status: "blocked" });
    return { error: pathCheck.reason! };
  }

  const { env, blocked } = loadEnvChecked(args.project_dir);
  // dotenv turns the lines of an unquoted multi-line value into keys, so a
  // base64 fragment of a private key can arrive here as a key *name*. The tool
  // promises "no values are exposed"; one predicate, every exit.
  const allKeys = Object.keys(env);
  const keys = allKeys.filter(isPlausibleEnvKey);
  const dropped = allKeys.filter((k) => !isPlausibleEnvKey(k));
  auditLog("get_env_keys", { keysAccessedCount: keys.length, status: "success" });
  // Distinguish "refused by policy" from "no keys here" — otherwise an empty
  // list reads as an empty .env.
  // A filtered key must not look like a missing variable — for a real secret
  // that is a functional break with no signal.
  const warnings = [
    ...(blocked ? [blocked] : []),
    ...(dropped.length > 0
      ? [
          `Omitted ${dropped.length} key(s) that look like fragments of a ` +
            `multi-line value rather than names: ${dropped.map(keyStub).join(", ")}. ` +
            `Check .env for an unquoted or unterminated multi-line value. If one ` +
            `is a real key, pass it to run_with_env via env_keys.`,
        ]
      : []),
  ];
  return warnings.length > 0 ? { keys, warnings } : { keys };
}
