import { z } from "zod";
import { isAbsolute } from "node:path";
import { execFile } from "node:child_process";
import { loadEnvChecked } from "../env-loader.js";
import { loadMyCnf } from "../mycnf-loader.js";
import { homedir } from "node:os";
import { sanitize } from "../utils/sanitize.js";
import { validateProjectDir } from "../security/path-validator.js";
import { auditLog } from "../security/audit.js";

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
    .int()
    .positive()
    .optional()
    .default(30000)
    .describe("Command timeout in milliseconds"),
  include_mycnf: z
    .boolean()
    .optional()
    .default(false)
    .describe("Include .my.cnf secrets in output sanitization"),
});

// Best-effort exfiltration detection: matches direct invocations only.
// Bypassed by indirect execution (python -c, node -e, ./script.sh, env curl, etc.).
// This is a warning system, not a security boundary — output sanitization is the real guard.
const NETWORK_BINARIES = [
  "curl", "wget", "nc", "ncat", "netcat", "ssh", "scp", "sftp",
  "dig", "nslookup", "host", "telnet", "ftp",
];

// Patterns that indicate data exfiltration attempts
const EXFIL_PATTERNS = [
  /\|\s*curl\b/,    // piping to curl
  /\|\s*wget\b/,    // piping to wget
  /\|\s*nc\b/,      // piping to netcat
  />\s*\/dev\/tcp/,  // bash /dev/tcp exfil
  />\s*\/dev\/udp/,  // bash /dev/udp exfil
];

function detectCommandWarnings(command: string): string[] {
  const warnings: string[] = [];
  const lower = command.toLowerCase();

  for (const binary of NETWORK_BINARIES) {
    // Match the binary as a standalone word
    const regex = new RegExp(`\\b${binary}\\b`);
    if (regex.test(lower)) {
      warnings.push(
        `Command uses network-capable binary '${binary}' — secrets could be sent to external servers`
      );
    }
  }

  for (const pattern of EXFIL_PATTERNS) {
    if (pattern.test(command)) {
      warnings.push(
        `Command matches data exfiltration pattern — review carefully before use`
      );
      break; // One exfil warning is enough
    }
  }

  return warnings;
}

export async function runWithEnv(
  args: z.infer<typeof RunWithEnvSchema>
): Promise<
  { exit_code: number; stdout: string; stderr: string; warnings?: string[] } | { error: string }
> {
  const pathCheck = validateProjectDir(args.project_dir);
  if (!pathCheck.valid) {
    auditLog("run_with_env", { command: args.command, status: "blocked" });
    return { error: pathCheck.reason! };
  }

  const warnings = detectCommandWarnings(args.command);

  // A policy refusal must be visible here too. The env is {} either way, so
  // nothing is injected — but sanitizeSecrets is also {}, meaning a command
  // that reads the symlinked .env itself (`cat .env`) gets unredacted output
  // where it would previously have been scrubbed.
  const { env, blocked: envBlocked } = loadEnvChecked(args.project_dir);
  if (envBlocked) {
    // Refuse rather than warn. With the read blocked, sanitizeSecrets is empty,
    // so a command that reads the symlink itself (`cat .env`) would get output
    // the pre-refusal code scrubbed — refusing the read would strictly reduce
    // redaction coverage. Nothing is injected either way, so the run has no
    // reason to proceed. api_call and get_env_keys still warn: a request and a
    // key listing remain meaningful without secrets.
    auditLog("run_with_env", { status: "blocked" });
    return { error: envBlocked };
  }

  // Build combined secret map for sanitization
  let sanitizeSecrets: Record<string, string> = env;
  if (args.include_mycnf) {
    const mycnf = loadMyCnf(args.project_dir, homedir());
    sanitizeSecrets = { ...env, ...mycnf.secrets };
  }

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
        auditLog("run_with_env", {
          keysAccessedCount: Object.keys(injectedEnv).length,
          command: args.command,
          status: exitCode === 0 ? "success" : "error",
        });
        resolve({
          exit_code: exitCode,
          stdout: sanitize(stdout, sanitizeSecrets),
          stderr: sanitize(stderr, sanitizeSecrets),
          ...(warnings.length > 0 ? { warnings: warnings.map((w) => sanitize(w, sanitizeSecrets)) } : {}),
        });
      }
    );
  });
}
