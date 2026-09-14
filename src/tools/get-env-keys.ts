import { z } from "zod";
import { isAbsolute } from "node:path";
import { loadEnvChecked } from "../env-loader.js";
import { isPlausibleEnvKey } from "../utils/env-key.js";
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
  const keys = Object.keys(env).filter(isPlausibleEnvKey);
  auditLog("get_env_keys", { keysAccessedCount: keys.length, status: "success" });
  // Distinguish "refused by policy" from "no keys here" — otherwise an empty
  // list reads as an empty .env.
  return blocked ? { keys, warnings: [blocked] } : { keys };
}
