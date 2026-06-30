import { z } from "zod";
import { isAbsolute } from "node:path";
import { Agent } from "undici";
import { loadEnv } from "../env-loader.js";
import { sanitize } from "../utils/sanitize.js";
import { validateUrl } from "../security/url-validator.js";
import { validateProjectDir } from "../security/path-validator.js";
import { getHostPolicy } from "../security/host-allowlist.js";
import { auditLog } from "../security/audit.js";

export const ApiCallSchema = z.object({
  project_dir: z
    .string()
    .refine((p) => isAbsolute(p), "project_dir must be an absolute path")
    .describe("Absolute path to the project directory"),
  url: z.url().describe("Request URL"),
  method: z
    .enum(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"])
    .optional()
    .default("GET"),
  headers: z
    .record(z.string(), z.string())
    .optional()
    .describe("Headers — use {{KEY_NAME}} to inject env values"),
  body: z.string().optional().describe("Request body"),
  auth_env_key: z
    .string()
    .optional()
    .describe("Env key to use as Bearer token"),
  timeout_ms: z
    .number()
    .optional()
    .default(30000)
    .describe("Request timeout in milliseconds"),
});

interface InterpolationResult {
  headers: Record<string, string>;
  /** Env keys whose value was actually substituted into a header. */
  injectedKeys: string[];
}

function interpolateHeaders(
  headers: Record<string, string>,
  env: Record<string, string>
): InterpolationResult {
  const result: Record<string, string> = {};
  const injectedKeys: string[] = [];
  for (const [key, value] of Object.entries(headers)) {
    result[key] = value.replace(/\{\{(\w+)\}\}/g, (_, envKey: string) => {
      // Object.hasOwn, not `in`: `in` matches inherited Object.prototype names
      // (constructor, toString, __proto__, …), which would stringify a function
      // into the header and falsely flag the request as secret-bearing.
      if (Object.hasOwn(env, envKey)) {
        injectedKeys.push(envKey);
        return env[envKey];
      }
      return `{{${envKey}}}`;
    });
  }
  return { headers: result, injectedKeys };
}

interface ApiCallResult {
  status: number;
  headers: Record<string, string>;
  body: string;
  warnings?: string[];
}

export async function apiCall(
  args: z.infer<typeof ApiCallSchema>
): Promise<ApiCallResult> {
  // Path traversal protection
  const pathCheck = validateProjectDir(args.project_dir);
  if (!pathCheck.valid) {
    auditLog("api_call", { status: "blocked" });
    return { status: 0, headers: {}, body: `Error: ${pathCheck.reason}` };
  }

  // SSRF protection: resolve DNS once and block private/internal IPs
  const urlCheck = await validateUrl(args.url);
  if (!urlCheck.allowed) {
    auditLog("api_call", { status: "blocked" });
    return {
      status: 0,
      headers: {},
      body: `Request blocked: ${urlCheck.reason}`,
    };
  }

  const env = loadEnv(args.project_dir);

  const interpolated = args.headers
    ? interpolateHeaders(args.headers, env)
    : { headers: {}, injectedKeys: [] };
  const headers: Record<string, string> = interpolated.headers;
  const injectedKeys = new Set(interpolated.injectedKeys);

  if (args.auth_env_key && env[args.auth_env_key]) {
    headers["Authorization"] = `Bearer ${env[args.auth_env_key]}`;
    injectedKeys.add(args.auth_env_key);
  }

  // Destination control: a secret is only safe to send somewhere we trust.
  // If any secret was actually injected, check the host against the allowlist.
  // Enforced (SECURE_API_ALLOWED_HOSTS set): block non-matching hosts.
  // Unenforced (unset): allow but warn so an unexpected destination is visible.
  const warnings: string[] = [];
  if (injectedKeys.size > 0) {
    const policy = getHostPolicy();
    const host = new URL(args.url).hostname;
    if (policy.enforced) {
      if (!policy.allows(host)) {
        auditLog("api_call", { status: "blocked" });
        return {
          status: 0,
          headers: {},
          body: `Request blocked: host '${host}' is not in SECURE_API_ALLOWED_HOSTS — refusing to send secrets to an unapproved destination`,
        };
      }
    } else {
      // No allowlist configured — secret still goes out, but make it visible.
      warnings.push(
        `Secret(s) sent to '${host}'. Set SECURE_API_ALLOWED_HOSTS to restrict where secrets may be sent.`
      );
    }
  }

  // Pin the resolved IP at the socket layer to close the DNS rebinding
  // TOCTOU window. The URL keeps the original hostname (preserving TLS
  // SNI and cert validation), but undici's lookup callback returns the
  // IP that validateUrl already checked instead of re-resolving DNS.
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), args.timeout_ms);

  const fetchOptions: Record<string, unknown> = {
    method: args.method,
    headers,
    body: args.body,
    signal: controller.signal,
  };
  if (urlCheck.resolvedIp) {
    const pinnedIp = urlCheck.resolvedIp;
    fetchOptions.dispatcher = new Agent({
      connect: {
        lookup: (_hostname, _options, cb) => {
          cb(null, [{ address: pinnedIp, family: pinnedIp.includes(":") ? 6 : 4 }]);
        },
      },
    });
  }

  let response: Response;
  try {
    response = await fetch(args.url, fetchOptions);
  } catch (err) {
    auditLog("api_call", { status: "error" });
    const message =
      err instanceof Error && err.name === "AbortError"
        ? `Request timed out after ${args.timeout_ms}ms`
        : err instanceof Error
          ? err.message
          : String(err);
    return {
      status: 0,
      headers: {},
      body: sanitize(`Fetch failed: ${message}`, env),
      ...(warnings.length > 0 ? { warnings } : {}),
    };
  } finally {
    clearTimeout(timer);
  }

  const bodyText = await response.text();
  const responseHeaders: Record<string, string> = {};
  response.headers.forEach((value, key) => {
    responseHeaders[key] = sanitize(value, env);
  });

  // injectedKeys already holds the unique env keys whose values were actually
  // substituted — {{KEY}} templates that resolved plus auth_env_key — so it
  // deduplicates when the same key appears in both and excludes templates that
  // referenced a missing key.
  auditLog("api_call", {
    keysAccessedCount: injectedKeys.size,
    status: response.ok ? "success" : "error",
  });

  return {
    status: response.status,
    headers: responseHeaders,
    body: sanitize(bodyText, env),
    ...(warnings.length > 0 ? { warnings } : {}),
  };
}
