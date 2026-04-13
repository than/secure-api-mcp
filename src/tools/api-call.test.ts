import { describe, it, expect, vi, beforeEach } from "vitest";

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

  it("uses the original URL directly (no IP rewriting)", async () => {
    await apiCall({
      project_dir: "/fake/project",
      url: "https://example.com/api/data",
      method: "GET",
    });
    expect(mockFetch).toHaveBeenCalledWith(
      "https://example.com/api/data",
      expect.objectContaining({ method: "GET" })
    );
  });
});
