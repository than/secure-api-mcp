import { z } from "zod";
import { loadEnv } from "../env-loader.js";

export const GetEnvKeysSchema = z.object({
  project_dir: z.string().describe("Absolute path to the project directory"),
});

export async function getEnvKeys(
  args: z.infer<typeof GetEnvKeysSchema>
): Promise<{ keys: string[] }> {
  const env = loadEnv(args.project_dir);
  return { keys: Object.keys(env) };
}
