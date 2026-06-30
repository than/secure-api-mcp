import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Mock modules before importing the module under test
vi.mock("../security/audit.js");
vi.mock("../security/url-validator.js");
vi.mock("../env-loader.js");
vi.mock("../security/path-validator.js");

const { auditLog } = await import("../security/audit.js");
const { validateUrl } = await import("../security/url-validator.js");
const { loadEnv } = await import("../env-loader.js");
const { validateProjectDir } = await import("../security/path-validator.js");
const { apiCall } = await import("./api-call.js");

const mockAuditLog = vi.mocked(auditLog);
const mockValidateUrl = vi.mocked(validateUrl);
const mockLoadEnv = vi.mocked(loadEnv);
const mockValidateProjectDir = vi.mocked(validateProjectDir);

// Stub fetch globally
const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

beforeEach(() => {
  vi.clearAllMocks();
  mockValidateProjectDir.mockReturnValue({ valid: true });
  mockValidateUrl.mockResolvedValue({
    allowed: true,
    resolvedIp: "93.184.216.34",
  });
  mockLoadEnv.mockReturnValue({
    MY_TOKEN: "tok-secret",
    OTHER_KEY: "other-secret",
  });
  mockFetch.mockResolvedValue({
    ok: true,
    status: 200,
    text: async () => "OK",
    headers: { forEach: vi.fn() },
  });
});

describe("apiCall - audit keysAccessedCount", () => {
  it("counts 1 key when only auth_env_key is used", async () => {
    await apiCall({
      project_dir: "/fake/project",
      url: "https://example.com",
      auth_env_key: "MY_TOKEN",
    });
    expect(mockAuditLog).toHaveBeenCalledWith(
      "api_call",
      expect.objectContaining({ keysAccessedCount: 1 })
    );
  });

  it("counts 1 key when only a {{KEY}} template header is used", async () => {
    await apiCall({
      project_dir: "/fake/project",
      url: "https://example.com",
      headers: { "X-Api-Key": "{{MY_TOKEN}}" },
    });
    expect(mockAuditLog).toHaveBeenCalledWith(
      "api_call",
      expect.objectContaining({ keysAccessedCount: 1 })
    );
  });

  it("counts 2 distinct keys when template and auth_env_key reference different keys", async () => {
    await apiCall({
      project_dir: "/fake/project",
      url: "https://example.com",
      headers: { "X-Api-Key": "{{OTHER_KEY}}" },
      auth_env_key: "MY_TOKEN",
    });
    expect(mockAuditLog).toHaveBeenCalledWith(
      "api_call",
      expect.objectContaining({ keysAccessedCount: 2 })
    );
  });

  it("counts 1 (not 2) when auth_env_key and Authorization header reference same key", async () => {
    // Double-count bug: old code adds 1 for Authorization header + 1 for auth_env_key = 2
    await apiCall({
      project_dir: "/fake/project",
      url: "https://example.com",
      headers: { Authorization: "Bearer {{MY_TOKEN}}" },
      auth_env_key: "MY_TOKEN",
    });
    expect(mockAuditLog).toHaveBeenCalledWith(
      "api_call",
      expect.objectContaining({ keysAccessedCount: 1 })
    );
  });

  it("counts 0 keys when no secrets are referenced", async () => {
    await apiCall({
      project_dir: "/fake/project",
      url: "https://example.com",
      headers: { "Content-Type": "application/json" },
    });
    expect(mockAuditLog).toHaveBeenCalledWith(
      "api_call",
      expect.objectContaining({ keysAccessedCount: 0 })
    );
  });
});

describe("apiCall - fetch error handling", () => {
  it("returns a structured error when fetch throws", async () => {
    mockFetch.mockRejectedValue(new TypeError("fetch failed"));
    const result = await apiCall({
      project_dir: "/fake/project",
      url: "https://example.com",
    });
    expect(result).toEqual({
      status: 0,
      headers: {},
      body: "Fetch failed: fetch failed",
    });
    expect(mockAuditLog).toHaveBeenCalledWith(
      "api_call",
      expect.objectContaining({ status: "error" })
    );
  });

  it("sanitizes secret values in error messages", async () => {
    mockFetch.mockRejectedValue(new Error("connect to tok-secret failed"));
    const result = await apiCall({
      project_dir: "/fake/project",
      url: "https://example.com",
    });
    expect(result.body).toBe("Fetch failed: connect to [REDACTED:MY_TOKEN] failed");
  });

  it("uses the original URL with a pinned-IP dispatcher", async () => {
    await apiCall({
      project_dir: "/fake/project",
      url: "https://example.com/api/data",
      method: "GET",
    });
    expect(mockFetch).toHaveBeenCalledWith(
      "https://example.com/api/data",
      expect.objectContaining({ method: "GET", dispatcher: expect.anything() })
    );
  });

  it("reports a timeout when fetch aborts", async () => {
    // Reject with the *real* abort reason the runtime sets when apiCall's
    // internal AbortController fires (a DOMException), not a hand-built Error.
    // This verifies the friendly-message branch (instanceof Error && name ===
    // "AbortError") actually holds for a genuine abort on the Node target — a
    // synthetic Error would mask a regression if that ever stopped being true.
    mockFetch.mockImplementation(
      (_url: string, opts: { signal: AbortSignal }) =>
        new Promise((_resolve, reject) => {
          opts.signal.addEventListener("abort", () =>
            reject(opts.signal.reason)
          );
        })
    );
    const result = await apiCall({
      project_dir: "/fake/project",
      url: "https://example.com",
      timeout_ms: 1,
    });
    expect(result.body).toBe("Fetch failed: Request timed out after 1ms");
  });

  it("passes an abort signal to fetch", async () => {
    await apiCall({ project_dir: "/fake/project", url: "https://example.com" });
    expect(mockFetch).toHaveBeenCalledWith(
      "https://example.com",
      expect.objectContaining({ signal: expect.anything() })
    );
  });
});

describe("apiCall - destination allowlist", () => {
  const ORIGINAL = process.env.SECURE_API_ALLOWED_HOSTS;
  afterEach(() => {
    if (ORIGINAL === undefined) delete process.env.SECURE_API_ALLOWED_HOSTS;
    else process.env.SECURE_API_ALLOWED_HOSTS = ORIGINAL;
  });

  it("warns but still sends when no allowlist is configured", async () => {
    delete process.env.SECURE_API_ALLOWED_HOSTS;
    const result = await apiCall({
      project_dir: "/fake/project",
      url: "https://example.com",
      auth_env_key: "MY_TOKEN",
    });
    expect(mockFetch).toHaveBeenCalled();
    expect(result.warnings?.[0]).toContain("example.com");
  });

  it("blocks and does not send when host is off the allowlist", async () => {
    process.env.SECURE_API_ALLOWED_HOSTS = "api.allowed.com";
    const result = await apiCall({
      project_dir: "/fake/project",
      url: "https://example.com",
      auth_env_key: "MY_TOKEN",
    });
    expect(mockFetch).not.toHaveBeenCalled();
    expect(result.status).toBe(0);
    expect(result.body).toContain("Request blocked");
    expect(mockAuditLog).toHaveBeenCalledWith(
      "api_call",
      expect.objectContaining({ status: "blocked" })
    );
  });

  it("sends without warning when host is on the allowlist", async () => {
    process.env.SECURE_API_ALLOWED_HOSTS = "example.com";
    const result = await apiCall({
      project_dir: "/fake/project",
      url: "https://example.com",
      auth_env_key: "MY_TOKEN",
    });
    expect(mockFetch).toHaveBeenCalled();
    expect(result.warnings).toBeUndefined();
  });

  it("does not gate requests that carry no secret", async () => {
    process.env.SECURE_API_ALLOWED_HOSTS = "api.allowed.com";
    const result = await apiCall({
      project_dir: "/fake/project",
      url: "https://example.com",
      headers: { "Content-Type": "application/json" },
    });
    expect(mockFetch).toHaveBeenCalled();
    expect(result.body).toBe("OK");
  });

  it("treats inherited Object.prototype names as non-keys (no false secret injection)", async () => {
    // {{constructor}} is not a real env key; `in` would match Object.prototype
    // and wrongly classify this as secret-bearing, gating it against the allowlist.
    process.env.SECURE_API_ALLOWED_HOSTS = "api.allowed.com";
    await apiCall({
      project_dir: "/fake/project",
      url: "https://example.com",
      headers: { "X-Test": "{{constructor}}" },
    });
    // Not gated/blocked — the request carries no real secret...
    expect(mockFetch).toHaveBeenCalled();
    // ...and the template is left untouched (no stringified function leaked in).
    const sentHeaders = mockFetch.mock.calls[0][1].headers;
    expect(sentHeaders["X-Test"]).toBe("{{constructor}}");
  });
});
