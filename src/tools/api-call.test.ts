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
const { apiCall, ApiCallSchema } = await import("./api-call.js");

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

describe("ApiCallSchema - timeout_ms bounds", () => {
  const base = { project_dir: "/fake/project", url: "https://example.com" };

  it("defaults to 30000 when omitted", () => {
    expect(ApiCallSchema.parse(base).timeout_ms).toBe(30000);
  });

  it("rejects zero, negative, and non-integer timeouts", () => {
    for (const timeout_ms of [0, -1, 1.5]) {
      expect(ApiCallSchema.safeParse({ ...base, timeout_ms }).success).toBe(false);
    }
  });

  it("accepts a positive integer timeout", () => {
    expect(ApiCallSchema.safeParse({ ...base, timeout_ms: 5000 }).success).toBe(true);
  });
});

describe("apiCall - redirects", () => {
  // clearAllMocks leaves *Once queues intact, so a test that returns early
  // would hand its unused responses to the next one.
  beforeEach(() => {
    mockFetch.mockReset();
    mockValidateUrl.mockReset();
    mockValidateUrl.mockResolvedValue({
      allowed: true,
      resolvedIp: "93.184.216.34",
    });
  });

  /** Builds a fetch response; `location` makes it a redirect. */
  const reply = (status: number, location?: string, body = "OK") => ({
    ok: status >= 200 && status < 300,
    status,
    text: async () => body,
    headers: {
      get: (name: string) =>
        location && name.toLowerCase() === "location" ? location : null,
      forEach: vi.fn(),
    },
  });

  it("never lets fetch follow redirects itself", async () => {
    mockFetch.mockResolvedValueOnce(reply(200));
    await apiCall({ project_dir: "/fake/project", url: "https://example.com" });
    expect(mockFetch.mock.calls[0][1].redirect).toBe("manual");
  });

  it("revalidates each hop against the SSRF guard", async () => {
    mockFetch
      .mockResolvedValueOnce(reply(302, "http://169.254.169.254/latest/meta-data/"))
      .mockResolvedValueOnce(reply(200, undefined, "CREDENTIALS"));
    mockValidateUrl
      .mockResolvedValueOnce({ allowed: true, resolvedIp: "93.184.216.34" })
      .mockResolvedValueOnce({ allowed: false, reason: "private IP blocked" });

    const result = await apiCall({
      project_dir: "/fake/project",
      url: "https://example.com",
      auth_env_key: "MY_TOKEN",
    });

    expect(result.status).toBe(0);
    expect(result.body).toContain("private IP blocked");
    expect(result.body).not.toContain("CREDENTIALS");
    // The second request was never made.
    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(mockAuditLog).toHaveBeenCalledWith("api_call", { status: "blocked" });
  });

  it("blocks a redirect that would carry a secret off the allowlist", async () => {
    process.env.SECURE_API_ALLOWED_HOSTS = "example.com";
    mockFetch.mockResolvedValueOnce(reply(302, "https://evil.example/collect"));

    const result = await apiCall({
      project_dir: "/fake/project",
      url: "https://example.com",
      auth_env_key: "MY_TOKEN",
    });

    delete process.env.SECURE_API_ALLOWED_HOSTS;
    expect(result.status).toBe(0);
    expect(result.body).toContain("evil.example");
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it("follows an allowed redirect and pins the new host's IP", async () => {
    mockFetch
      .mockResolvedValueOnce(reply(302, "https://example.com/moved"))
      .mockResolvedValueOnce(reply(200, undefined, "ARRIVED"));
    mockValidateUrl
      .mockResolvedValueOnce({ allowed: true, resolvedIp: "93.184.216.34" })
      .mockResolvedValueOnce({ allowed: true, resolvedIp: "93.184.216.35" });

    const result = await apiCall({
      project_dir: "/fake/project",
      url: "https://example.com",
    });

    expect(result.status).toBe(200);
    expect(result.body).toBe("ARRIVED");
    expect(mockFetch).toHaveBeenCalledTimes(2);
    expect(mockFetch.mock.calls[1][0]).toBe("https://example.com/moved");
  });

  it("resolves a relative Location against the current URL", async () => {
    mockFetch
      .mockResolvedValueOnce(reply(302, "/moved"))
      .mockResolvedValueOnce(reply(200));
    await apiCall({ project_dir: "/fake/project", url: "https://example.com/a/b" });
    expect(mockFetch.mock.calls[1][0]).toBe("https://example.com/moved");
  });

  it("downgrades POST to GET and drops the body on a 303", async () => {
    mockFetch
      .mockResolvedValueOnce(reply(303, "https://example.com/done"))
      .mockResolvedValueOnce(reply(200));
    await apiCall({
      project_dir: "/fake/project",
      url: "https://example.com",
      method: "POST",
      body: "payload",
    });
    expect(mockFetch.mock.calls[1][1].method).toBe("GET");
    expect(mockFetch.mock.calls[1][1].body).toBeUndefined();
  });

  it("preserves method and body across a 307", async () => {
    mockFetch
      .mockResolvedValueOnce(reply(307, "https://example.com/done"))
      .mockResolvedValueOnce(reply(200));
    await apiCall({
      project_dir: "/fake/project",
      url: "https://example.com",
      method: "POST",
      body: "payload",
    });
    expect(mockFetch.mock.calls[1][1].method).toBe("POST");
    expect(mockFetch.mock.calls[1][1].body).toBe("payload");
  });

  it("stops after the redirect cap rather than looping", async () => {
    mockFetch.mockResolvedValue(reply(302, "https://example.com/next"));
    const result = await apiCall({
      project_dir: "/fake/project",
      url: "https://example.com",
    });
    expect(result.status).toBe(0);
    expect(result.body).toContain("exceeded 5 redirects");
    expect(mockFetch).toHaveBeenCalledTimes(6);
  });

  it("returns a 3xx without a Location as the final response", async () => {
    mockFetch.mockResolvedValueOnce(reply(302, undefined, "no location"));
    const result = await apiCall({
      project_dir: "/fake/project",
      url: "https://example.com",
    });
    expect(result.status).toBe(302);
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });
});
