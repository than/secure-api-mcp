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
    .int()
    .positive()
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

/** Redirect hops followed before giving up. */
const MAX_REDIRECTS = 5;

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

/**
 * Applies the method and body rewrite a redirect implies.
 *
 * 303 always becomes GET. 301 and 302 keep the method in the spec but every
 * real client downgrades POST to GET, and servers expect that. 307 and 308
 * exist precisely to preserve the method, so they are left alone.
 */
function redirectedRequest(
  status: number,
  method: string,
  body: string | undefined
): { method: string; body: string | undefined } {
  if (status === 307 || status === 308) return { method, body };
  if (status === 303 || method === "POST") return { method: "GET", body: undefined };
  return { method, body };
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
  const policy = getHostPolicy();
  const checkDestination = (host: string): string | null => {
    if (injectedKeys.size === 0) return null;
    if (policy.enforced) {
      return policy.allows(host)
        ? null
        : `host '${host}' is not in SECURE_API_ALLOWED_HOSTS — refusing to send secrets to an unapproved destination`;
    }
    // No allowlist configured — secret still goes out, but make it visible.
    warnings.push(
      `Secret(s) sent to '${host}'. Set SECURE_API_ALLOWED_HOSTS to restrict where secrets may be sent.`
    );
    return null;
  };

  const blocked = checkDestination(new URL(args.url).hostname);
  if (blocked) {
    auditLog("api_call", { status: "blocked" });
    return { status: 0, headers: {}, body: `Request blocked: ${blocked}` };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), args.timeout_ms);

  // Pin the resolved IP at the socket layer to close the DNS rebinding
  // TOCTOU window. The URL keeps the original hostname (preserving TLS
  // SNI and cert validation), but undici's lookup callback returns the
  // IP that validateUrl already checked instead of re-resolving DNS.
  const pinnedDispatcher = (ip: string | undefined): Agent | undefined =>
    ip === undefined
      ? undefined
      : new Agent({
          connect: {
            lookup: (_hostname, _options, cb) => {
              cb(null, [{ address: ip, family: ip.includes(":") ? 6 : 4 }]);
            },
          },
        });

  let response: Response;
  let currentUrl = args.url;
  let currentIp = urlCheck.resolvedIp;
  let method: string = args.method;
  let body = args.body;

  try {
    // Redirects are followed by hand. Letting fetch follow them would skip
    // both the SSRF check and the allowlist on every hop after the first, so
    // a 302 to an internal address or an unapproved host would carry the
    // injected secret straight there. The pinned dispatcher is per-connection
    // and would not cover the new host either.
    for (let hop = 0; ; hop++) {
      const dispatcher = pinnedDispatcher(currentIp);
      response = await fetch(currentUrl, {
        method,
        headers,
        body,
        signal: controller.signal,
        redirect: "manual",
        ...(dispatcher ? { dispatcher } : {}),
      } as RequestInit);

      if (!REDIRECT_STATUSES.has(response.status)) break;

      const location = response.headers.get("location");
      if (!location) break;

      if (hop >= MAX_REDIRECTS) {
        auditLog("api_call", { status: "blocked" });
        return {
          status: 0,
          headers: {},
          body: `Request blocked: exceeded ${MAX_REDIRECTS} redirects`,
          ...(warnings.length > 0 ? { warnings } : {}),
        };
      }

      const nextUrl = new URL(location, currentUrl).toString();
      const nextCheck = await validateUrl(nextUrl);
      if (!nextCheck.allowed) {
        auditLog("api_call", { status: "blocked" });
        return {
          status: 0,
          headers: {},
          body: `Request blocked: redirect to ${nextUrl} — ${nextCheck.reason}`,
          ...(warnings.length > 0 ? { warnings } : {}),
        };
      }

      const nextBlocked = checkDestination(new URL(nextUrl).hostname);
      if (nextBlocked) {
        auditLog("api_call", { status: "blocked" });
        return {
          status: 0,
          headers: {},
          body: `Request blocked: redirect to ${nextBlocked}`,
          ...(warnings.length > 0 ? { warnings } : {}),
        };
      }

      ({ method, body } = redirectedRequest(response.status, method, body));
      currentUrl = nextUrl;
      currentIp = nextCheck.resolvedIp;
    }
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
