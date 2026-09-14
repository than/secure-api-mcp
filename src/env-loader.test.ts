import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, writeFileSync, rmSync, utimesSync, symlinkSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

function makeTempDir(): string {
  return mkdtempSync(join(tmpdir(), "env-loader-test-"));
}

const temps: string[] = [];
function tempDir(): string {
  const dir = makeTempDir();
  temps.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of temps.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("loadEnv - basic", () => {
  it("returns empty object when .env does not exist", async () => {
    const { loadEnvChecked } = await import("./env-loader.js");
    const dir = tempDir();
    expect(loadEnvChecked(dir).env).toEqual({});
  });

  it("parses key=value pairs from .env", async () => {
    const { loadEnvChecked } = await import("./env-loader.js");
    const dir = tempDir();
    writeFileSync(join(dir, ".env"), "API_KEY=secret\nPORT=3000\n");
    expect(loadEnvChecked(dir).env).toEqual({ API_KEY: "secret", PORT: "3000" });
  });
});

describe("loadEnv - stale cache (mtime collision)", () => {
  it("returns updated values when content changes but mtime is identical", async () => {
    const { loadEnvChecked } = await import("./env-loader.js");
    const dir = tempDir();
    const envPath = join(dir, ".env");

    // Pin both writes to the same known fixed timestamp so the mtime
    // is guaranteed identical regardless of filesystem precision.
    const fixedTime = new Date("2020-06-15T12:00:00.000Z");

    writeFileSync(envPath, "API_KEY=original\n");
    utimesSync(envPath, fixedTime, fixedTime);
    const first = loadEnvChecked(dir).env;
    expect(first.API_KEY).toBe("original");

    // Same mtime, different content — simulates coarse-clock / touch -t attack
    writeFileSync(envPath, "API_KEY=rotated\n");
    utimesSync(envPath, fixedTime, fixedTime);

    // Must NOT serve stale cached value
    const second = loadEnvChecked(dir).env;
    expect(second.API_KEY).toBe("rotated");
  });
});

describe("loadEnv - symlink handling", () => {
  it("refuses a .env symlinked outside the project", async () => {
    const { loadEnvChecked } = await import("./env-loader.js");
    const project = tempDir();
    const outside = tempDir();
    const secrets = join(outside, "credentials");
    writeFileSync(secrets, "AWS_SECRET_ACCESS_KEY=live-secret-value\n");
    symlinkSync(secrets, join(project, ".env"));

    expect(loadEnvChecked(project).env).toEqual({});
  });

  it("reports the refusal rather than looking like a missing .env", async () => {
    const { loadEnvChecked } = await import("./env-loader.js");
    const project = tempDir();
    const outside = tempDir();
    writeFileSync(join(outside, "credentials"), "K=v\n");
    symlinkSync(join(outside, "credentials"), join(project, ".env"));

    const result = loadEnvChecked(project);
    expect(result.env).toEqual({});
    expect(result.blocked).toMatch(/symlink/i);
  });

  it("reports no refusal when there is simply no .env", async () => {
    const { loadEnvChecked } = await import("./env-loader.js");
    expect(loadEnvChecked(tempDir()).blocked).toBeUndefined();
  });

  it("still reads a .env symlinked within the project", async () => {
    const { loadEnvChecked } = await import("./env-loader.js");
    const project = tempDir();
    writeFileSync(join(project, ".env.local"), "APP_ENV=production\n");
    symlinkSync(join(project, ".env.local"), join(project, ".env"));

    expect(loadEnvChecked(project).env).toEqual({ APP_ENV: "production" });
  });
});
