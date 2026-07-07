import { describe, it, expect, vi, beforeEach } from "vitest";
import { loadEnv } from "../env-loader.js";
import { loadMyCnf } from "../mycnf-loader.js";
import { validateProjectDir } from "../security/path-validator.js";
import { auditLog } from "../security/audit.js";
import { RunWithEnvSchema } from "./run-with-env.js";

vi.mock("../env-loader.js", () => ({ loadEnv: vi.fn() }));
vi.mock("../mycnf-loader.js", () => ({ loadMyCnf: vi.fn() }));
vi.mock("../security/path-validator.js", () => ({ validateProjectDir: vi.fn() }));
vi.mock("../security/audit.js", () => ({ auditLog: vi.fn() }));

const mockLoadEnv = vi.mocked(loadEnv);
const mockLoadMyCnf = vi.mocked(loadMyCnf);
const mockValidateProjectDir = vi.mocked(validateProjectDir);

// Import after mocks are set up
const { runWithEnv } = await import("./run-with-env.js");

describe("runWithEnv with include_mycnf", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockValidateProjectDir.mockReturnValue({ valid: true });
    mockLoadEnv.mockReturnValue({});
    mockLoadMyCnf.mockReturnValue({ sections: {}, secrets: {} });
  });

  it("redacts mycnf secrets from stdout when include_mycnf is true", async () => {
    mockLoadEnv.mockReturnValue({});
    mockLoadMyCnf.mockReturnValue({
      sections: { client: { password: "supersecretpass" } },
      secrets: { "client.password": "supersecretpass" },
    });

    const result = await runWithEnv({
      project_dir: "/tmp",
      command: "echo supersecretpass",
      timeout_ms: 30000,
      include_mycnf: true,
    });

    expect(result).toHaveProperty("stdout");
    const r = result as { stdout: string };
    expect(r.stdout).toContain("[REDACTED:client.password]");
    expect(r.stdout).not.toContain("supersecretpass");
  });

  it("does NOT load mycnf secrets when include_mycnf is false", async () => {
    mockLoadEnv.mockReturnValue({});
    mockLoadMyCnf.mockReturnValue({
      sections: { client: { password: "mysqlpass123" } },
      secrets: { "client.password": "mysqlpass123" },
    });

    const result = await runWithEnv({
      project_dir: "/tmp",
      command: "echo mysqlpass123",
      timeout_ms: 30000,
      include_mycnf: false,
    });

    expect(loadMyCnf).not.toHaveBeenCalled();
    const r = result as { stdout: string };
    expect(r.stdout).toContain("mysqlpass123");
  });

  it("does NOT load mycnf secrets when include_mycnf defaults to false", async () => {
    mockLoadEnv.mockReturnValue({});

    const result = await runWithEnv({
      project_dir: "/tmp",
      command: "echo hello",
      timeout_ms: 30000,
      include_mycnf: false,
    });

    expect(loadMyCnf).not.toHaveBeenCalled();
    const r = result as { stdout: string };
    expect(r.stdout).toContain("hello");
  });

  it("sanitizes both .env and .my.cnf secrets when both present", async () => {
    mockLoadEnv.mockReturnValue({ DB_TOKEN: "envtoken999" });
    mockLoadMyCnf.mockReturnValue({
      sections: { client: { password: "cnfpass888" } },
      secrets: { "client.password": "cnfpass888" },
    });

    const result = await runWithEnv({
      project_dir: "/tmp",
      command: "echo envtoken999 cnfpass888",
      timeout_ms: 30000,
      include_mycnf: true,
    });

    const r = result as { stdout: string };
    expect(r.stdout).toContain("[REDACTED:DB_TOKEN]");
    expect(r.stdout).toContain("[REDACTED:client.password]");
    expect(r.stdout).not.toContain("envtoken999");
    expect(r.stdout).not.toContain("cnfpass888");
  });
});

describe("RunWithEnvSchema - timeout_ms bounds", () => {
  const base = { project_dir: "/tmp", command: "echo hi" };

  it("defaults to 30000 when omitted", () => {
    expect(RunWithEnvSchema.parse(base).timeout_ms).toBe(30000);
  });

  it("rejects zero, negative, and non-integer timeouts", () => {
    for (const timeout_ms of [0, -1, 1.5]) {
      expect(RunWithEnvSchema.safeParse({ ...base, timeout_ms }).success).toBe(false);
    }
  });

  it("accepts a positive integer timeout", () => {
    expect(RunWithEnvSchema.safeParse({ ...base, timeout_ms: 5000 }).success).toBe(true);
  });
});
