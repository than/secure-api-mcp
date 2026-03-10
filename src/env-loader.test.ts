import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, writeFileSync, rmSync, utimesSync } from "node:fs";
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
    const { loadEnv } = await import("./env-loader.js");
    const dir = tempDir();
    expect(loadEnv(dir)).toEqual({});
  });

  it("parses key=value pairs from .env", async () => {
    const { loadEnv } = await import("./env-loader.js");
    const dir = tempDir();
    writeFileSync(join(dir, ".env"), "API_KEY=secret\nPORT=3000\n");
    expect(loadEnv(dir)).toEqual({ API_KEY: "secret", PORT: "3000" });
  });
});

describe("loadEnv - stale cache (mtime collision)", () => {
  it("returns updated values when content changes but mtime is identical", async () => {
    const { loadEnv } = await import("./env-loader.js");
    const dir = tempDir();
    const envPath = join(dir, ".env");

    // Pin both writes to the same known fixed timestamp so the mtime
    // is guaranteed identical regardless of filesystem precision.
    const fixedTime = new Date("2020-06-15T12:00:00.000Z");

    writeFileSync(envPath, "API_KEY=original\n");
    utimesSync(envPath, fixedTime, fixedTime);
    const first = loadEnv(dir);
    expect(first.API_KEY).toBe("original");

    // Same mtime, different content — simulates coarse-clock / touch -t attack
    writeFileSync(envPath, "API_KEY=rotated\n");
    utimesSync(envPath, fixedTime, fixedTime);

    // Must NOT serve stale cached value
    const second = loadEnv(dir);
    expect(second.API_KEY).toBe("rotated");
  });
});
