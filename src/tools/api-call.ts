import { z } from "zod";
import { loadEnv } from "../env-loader.js";
import { sanitize } from "../utils/sanitize.js";

export const ApiCallSchema = z.object({
  project_dir: z.string().describe("Absolute path to the project directory"),
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
  const env = loadEnv(args.project_dir);

  const headers: Record<string, string> = args.headers
    ? interpolateHeaders(args.headers, env)
    : {};

  if (args.auth_env_key && env[args.auth_env_key]) {
    headers["Authorization"] = `Bearer ${env[args.auth_env_key]}`;
  }

  const response = await fetch(args.url, {
    method: args.method,
    headers,
    body: args.body,
  });

  const bodyText = await response.text();
  const responseHeaders: Record<string, string> = {};
  response.headers.forEach((value, key) => {
    responseHeaders[key] = value;
  });

  return {
    status: response.status,
    headers: responseHeaders,
    body: sanitize(bodyText, env),
  };
}
