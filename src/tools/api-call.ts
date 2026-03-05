import { z } from "zod";
import { isAbsolute } from "node:path";
import { loadEnv } from "../env-loader.js";
import { sanitize } from "../utils/sanitize.js";
import { validateUrl } from "../security/url-validator.js";
import { validateProjectDir } from "../security/path-validator.js";

export const ApiCallSchema = z.object({
  project_dir: z
    .string()
    .refine((p) => isAbsolute(p), "project_dir must be an absolute path")
    .describe("Absolute path to the project directory"),
  url: z.string().url().describe("Request URL"),
  method: z
    .enum(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"])
    .optional()
    .default("GET"),
  headers: z
    .record(z.string())
    .optional()
    .describe("Headers — use {{KEY_NAME}} to inject env values"),
  body: z.string().optional().describe("Request body"),
  auth_env_key: z
    .string()
    .optional()
    .describe("Env key to use as Bearer token"),
});

function interpolateHeaders(
  headers: Record<string, string>,
  env: Record<string, string>
): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    result[key] = value.replace(/\{\{(\w+)\}\}/g, (_, envKey: string) => {
      return env[envKey] ?? `{{${envKey}}}`;
    });
  }
  return result;
}

export async function apiCall(
  args: z.infer<typeof ApiCallSchema>
): Promise<{ status: number; headers: Record<string, string>; body: string }> {
  // Path traversal protection
  const pathCheck = validateProjectDir(args.project_dir);
  if (!pathCheck.valid) {
    return { status: 0, headers: {}, body: `Error: ${pathCheck.reason}` };
  }

  // SSRF protection: resolve DNS once and block private/internal IPs
  const urlCheck = await validateUrl(args.url);
  if (!urlCheck.allowed) {
    return {
      status: 0,
      headers: {},
      body: `Request blocked: ${urlCheck.reason}`,
    };
  }

  const env = loadEnv(args.project_dir);

  const headers: Record<string, string> = args.headers
    ? interpolateHeaders(args.headers, env)
    : {};

  if (args.auth_env_key && env[args.auth_env_key]) {
    headers["Authorization"] = `Bearer ${env[args.auth_env_key]}`;
  }

  // Use the resolved IP to prevent DNS rebinding attacks:
  // An attacker's DNS could return a safe IP during validation above,
  // then a private IP (127.0.0.1, 169.254.169.254) during fetch.
  // By rewriting the URL with the resolved IP and setting Host header,
  // we ensure fetch uses the same IP we validated.
  let fetchUrl = args.url;
  if (urlCheck.resolvedIp && urlCheck.hostname) {
    const parsed = new URL(args.url);
    parsed.hostname = urlCheck.resolvedIp;
    fetchUrl = parsed.toString();
    headers["Host"] = urlCheck.hostname;
  }

  const response = await fetch(fetchUrl, {
    method: args.method,
    headers,
    body: args.body,
  });

  const bodyText = await response.text();
  const responseHeaders: Record<string, string> = {};
  response.headers.forEach((value, key) => {
    responseHeaders[key] = sanitize(value, env);
  });

  return {
    status: response.status,
    headers: responseHeaders,
    body: sanitize(bodyText, env),
  };
}
