import { z } from "zod";
import { isAbsolute } from "node:path";
import { execFile } from "node:child_process";
import { loadEnv } from "../env-loader.js";
import { sanitize } from "../utils/sanitize.js";
import { validateProjectDir } from "../security/path-validator.js";

export const RunWithEnvSchema = z.object({
  project_dir: z
    .string()
    .refine((p) => isAbsolute(p), "project_dir must be an absolute path")
    .describe("Absolute path to the project directory"),
  command: z.string().describe("Shell command to execute"),
  env_keys: z
    .array(z.string())
    .optional()
    .describe("Specific env keys to inject (default: all)"),
  timeout_ms: z
    .number()
    .optional()
    .default(30000)
    .describe("Command timeout in milliseconds"),
});

export async function runWithEnv(
  args: z.infer<typeof RunWithEnvSchema>
): Promise<
  { exit_code: number; stdout: string; stderr: string } | { error: string }
> {
  const pathCheck = validateProjectDir(args.project_dir);
  if (!pathCheck.valid) {
    return { error: pathCheck.reason! };
  }

  const env = loadEnv(args.project_dir);

  // Filter to requested keys if specified
  const injectedEnv: Record<string, string> = {};
  const keys = args.env_keys ?? Object.keys(env);
  for (const key of keys) {
    if (key in env) {
      injectedEnv[key] = env[key];
    }
  }

  // Only pass through safe, non-secret process env vars needed for commands to work.
  // This prevents the MCP server's own environment secrets from leaking unsanitized.
  const safeProcessEnv: Record<string, string> = {};
  const SAFE_KEYS = [
    "PATH", "HOME", "SHELL", "USER", "LOGNAME", "TERM", "LANG",
    "LC_ALL", "LC_CTYPE", "TMPDIR", "XDG_RUNTIME_DIR",
  ];
  for (const key of SAFE_KEYS) {
    if (process.env[key]) {
      safeProcessEnv[key] = process.env[key] as string;
    }
  }

  return new Promise((resolve) => {
    const child = execFile(
      "/bin/sh",
      ["-c", args.command],
      {
        cwd: args.project_dir,
        env: { ...safeProcessEnv, ...injectedEnv },
        timeout: args.timeout_ms,
        maxBuffer: 1024 * 1024,
      },
      (error, stdout, stderr) => {
        const exitCode =
          error && "code" in error ? (error.code as number) ?? 1 : 0;
        resolve({
          exit_code: exitCode,
          stdout: sanitize(stdout, env),
          stderr: sanitize(stderr, env),
        });
      }
    );
  });
}
