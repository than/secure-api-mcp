import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock modules before importing the module under test
vi.mock("../security/audit.js");
vi.mock("../security/path-validator.js");
vi.mock("../mycnf-loader.js");

const { auditLog } = await import("../security/audit.js");
const { validateProjectDir } = await import("../security/path-validator.js");
const { loadMyCnf } = await import("../mycnf-loader.js");
const { readMyCnf } = await import("./read-mycnf.js");

const mockAuditLog = vi.mocked(auditLog);
const mockValidateProjectDir = vi.mocked(validateProjectDir);
const mockLoadMyCnf = vi.mocked(loadMyCnf);

beforeEach(() => {
  vi.clearAllMocks();
  mockValidateProjectDir.mockReturnValue({ valid: true });
  mockLoadMyCnf.mockReturnValue({
    sections: {
      client: { user: "root", password: "s3cret", host: "db.example.com", port: "3306" },
      mysqldump: { user: "backup", password: "dumppass", single_transaction: "true" },
    },
    secrets: {
      "client.user": "root",
      "client.password": "s3cret",
      "client.host": "db.example.com",
      "mysqldump.user": "backup",
      "mysqldump.password": "dumppass",
    },
  });
});

describe("readMyCnf", () => {
  it("returns safe fields with secrets redacted", async () => {
    const result = await readMyCnf({ project_dir: "/fake/project" });
    expect(result).toEqual({
      sections: {
        client: {
          user: "[REDACTED:client.user]",
          password: "[REDACTED:client.password]",
          host: "[REDACTED:client.host]",
          port: "3306",
        },
        mysqldump: {
          user: "[REDACTED:mysqldump.user]",
          password: "[REDACTED:mysqldump.password]",
          single_transaction: "true",
        },
      },
    });
  });

  it("filters to a requested section", async () => {
    const result = await readMyCnf({ project_dir: "/fake/project", section: "client" });
    expect(result).toEqual({
      sections: {
        client: {
          user: "[REDACTED:client.user]",
          password: "[REDACTED:client.password]",
          host: "[REDACTED:client.host]",
          port: "3306",
        },
      },
    });
  });

  it("returns error on invalid path", async () => {
    mockValidateProjectDir.mockReturnValue({ valid: false, reason: "Path traversal blocked" });
    const result = await readMyCnf({ project_dir: "/etc/passwd/../.." });
    expect(result).toEqual({ error: "Path traversal blocked" });
    expect(mockAuditLog).toHaveBeenCalledWith("read_mycnf", { status: "blocked" });
  });

  it("returns empty sections when no .my.cnf found", async () => {
    mockLoadMyCnf.mockReturnValue({ sections: {}, secrets: {} });
    const result = await readMyCnf({ project_dir: "/fake/project" });
    expect(result).toEqual({ sections: {} });
  });

  it("returns empty sections when filtered section does not exist", async () => {
    const result = await readMyCnf({ project_dir: "/fake/project", section: "nonexistent" });
    expect(result).toEqual({ sections: {} });
  });

  it("audit logs success with keysAccessedCount", async () => {
    await readMyCnf({ project_dir: "/fake/project" });
    expect(mockAuditLog).toHaveBeenCalledWith("read_mycnf", {
      keysAccessedCount: 5,
      status: "success",
    });
  });

  it("audit logs success with filtered keysAccessedCount", async () => {
    await readMyCnf({ project_dir: "/fake/project", section: "client" });
    expect(mockAuditLog).toHaveBeenCalledWith("read_mycnf", {
      keysAccessedCount: 3,
      status: "success",
    });
  });
});
