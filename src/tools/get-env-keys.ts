import { z } from "zod";
import { isAbsolute } from "node:path";
import { loadEnv } from "../env-loader.js";
import { validateProjectDir } from "../security/path-validator.js";

export const GetEnvKeysSchema = z.object({
  project_dir: z
    .string()
    .refine((p) => isAbsolute(p), "project_dir must be an absolute path")
    .describe("Absolute path to the project directory"),
});

export async function getEnvKeys(
  args: z.infer<typeof GetEnvKeysSchema>
): Promise<{ keys: string[] } | { error: string }> {
  const pathCheck = validateProjectDir(args.project_dir);
  if (!pathCheck.valid) {
    return { error: pathCheck.reason! };
  }

  const env = loadEnv(args.project_dir);
  return { keys: Object.keys(env) };
}
