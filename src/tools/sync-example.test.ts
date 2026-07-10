import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, writeFileSync, symlinkSync, rmSync, readFileSync, lstatSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { syncExample } from "./sync-example.js";

function makeTempProject(): string {
  const dir = mkdtempSync(join(tmpdir(), "secure-api-test-"));
  writeFileSync(join(dir, "package.json"), "{}");
  return dir;
}

const temps: string[] = [];
function tempProject(): string {
  const dir = makeTempProject();
  temps.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of temps.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("syncExample - symlink traversal protection", () => {
  it("atomically replaces .env.example symlink without writing to its target", async () => {
    const project = tempProject();
    const external = tempProject();
    const targetFile = join(external, "sensitive-file.txt");
    writeFileSync(targetFile, "original content");
    writeFileSync(join(project, ".env"), "API_KEY=secret123\n");
    symlinkSync(targetFile, join(project, ".env.example"));

    const result = await syncExample({ project_dir: project });

    // Should succeed — rename replaces the symlink, not its target
    expect(result).toMatchObject({ keys_synced: 1 });
    // External target must be untouched
    expect(readFileSync(targetFile, "utf-8")).toBe("original content");
    // .env.example should now be a real file, not a symlink
    expect(lstatSync(join(project, ".env.example")).isSymbolicLink()).toBe(false);
  });

  it("blocks when .env is a symlink pointing outside the project", async () => {
    const project = tempProject();
    const external = tempProject();
    const externalFile = join(external, "arbitrary-file.txt");
    writeFileSync(externalFile, "root:x:0:0:root:/root:/bin/bash\n");

    symlinkSync(externalFile, join(project, ".env"));

    const result = await syncExample({ project_dir: project });

    expect(result).toMatchObject({ error: expect.stringMatching(/outside/i) });
  });

  it("treats a dangling .env symlink as no .env (existsSync returns false)", async () => {
    const project = tempProject();
    symlinkSync(join(project, "nonexistent-file"), join(project, ".env"));

    const result = await syncExample({ project_dir: project });

    // existsSync follows the symlink and sees no target — graceful no-op,
    // no unhandled throw from realpathSync
    expect(result).toMatchObject({ keys_synced: 0 });
  });

  it("allows .env that is a symlink pointing within the project", async () => {
    const project = tempProject();
    writeFileSync(join(project, ".env.production"), "API_KEY=secret\n");
    symlinkSync(join(project, ".env.production"), join(project, ".env"));

    const result = await syncExample({ project_dir: project });

    expect(result).toMatchObject({ keys_synced: 1 });
  });
});

describe("syncExample - normal operation", () => {
  it("generates .env.example stripping secret values", async () => {
    const project = tempProject();
    writeFileSync(join(project, ".env"), "API_KEY=supersecret\nPORT=3000\n");

    const result = await syncExample({ project_dir: project });

    expect(result).toMatchObject({ keys_synced: 2 });
    const example = readFileSync(join(project, ".env.example"), "utf-8");
    expect(example).toContain("API_KEY=");
    expect(example).not.toContain("supersecret");
    expect(example).toContain("PORT=3000");
  });
});

describe("syncExample - smart placeholder key-name matching", () => {
  it("does not leak numeric secrets whose key name merely contains 'port' as a substring", async () => {
    const project = tempProject();
    writeFileSync(
      join(project, ".env"),
      [
        "PORTAL_ACCESS_TOKEN=48213793029",
        "IMPORT_LICENSE_KEY=90210773",
        "SUPPORT_API_PIN=1234",
        "TRANSPORT_AUTH_CODE=5678",
        "EXPORT_ACCESS_CODE=1111",
        "REPORT_SECRET_TOKEN=2222",
      ].join("\n") + "\n"
    );

    const result = await syncExample({ project_dir: project });

    expect(result).toMatchObject({ keys_synced: 6 });
    const example = readFileSync(join(project, ".env.example"), "utf-8");
    for (const leaked of ["48213793029", "90210773", "1234", "5678", "1111", "2222"]) {
      expect(example).not.toContain(leaked);
    }
  });

  it("does not leak numeric secrets via the SAFE_NUMERIC_KEYS unbounded prefix match", async () => {
    const project = tempProject();
    writeFileSync(join(project, ".env"), "SIZEABLE_TOKEN=99887766\n");

    await syncExample({ project_dir: project });

    const example = readFileSync(join(project, ".env.example"), "utf-8");
    expect(example).not.toContain("99887766");
  });

  it("still preserves genuinely port-shaped and safe-numeric keys", async () => {
    const project = tempProject();
    writeFileSync(
      join(project, ".env"),
      "PORT=3000\nDB_PORT=5432\nAPI_PORT_NUMBER=8080\nMAX_RETRIES=3\nTIMEOUT_MS=5000\n"
    );

    const result = await syncExample({ project_dir: project });

    expect(result).toMatchObject({ keys_synced: 5 });
    const example = readFileSync(join(project, ".env.example"), "utf-8");
    expect(example).toContain("PORT=3000");
    expect(example).toContain("DB_PORT=5432");
    expect(example).toContain("API_PORT_NUMBER=8080");
    expect(example).toContain("MAX_RETRIES=3");
    expect(example).toContain("TIMEOUT_MS=5000");
  });

  it("redacts numeric secrets whose FIRST token is safe but a later token names a secret", async () => {
    const project = tempProject();
    writeFileSync(
      join(project, ".env"),
      [
        "POOL_PASSWORD=8377291",
        "MIN_API_KEY=442211",
        "BATCH_SECRET=555111",
        "TTL_SECRET=99999",
        "PORT_SECRET_TOKEN=13371337",
        "LIMIT_AUTH_CODE=246810",
      ].join("\n") + "\n"
    );

    await syncExample({ project_dir: project });

    const example = readFileSync(join(project, ".env.example"), "utf-8");
    for (const leaked of ["8377291", "442211", "555111", "99999", "13371337", "246810"]) {
      expect(example).not.toContain(leaked);
    }
  });

  it("preserves numeric config counts whose key ends in a plural of a secret word", async () => {
    // MAX_TOKENS / MAX_KEYS are counts, not secrets — TOKEN+S / KEY+S must not
    // trip the deny-first gate.
    const project = tempProject();
    writeFileSync(join(project, ".env"), "MAX_TOKENS=4096\nMAX_KEYS=32\n");

    await syncExample({ project_dir: project });

    const example = readFileSync(join(project, ".env.example"), "utf-8");
    expect(example).toContain("MAX_TOKENS=4096");
    expect(example).toContain("MAX_KEYS=32");
  });
});

describe("syncExample - boolean flag key boundaries", () => {
  it("does not preserve a flag value on a key that merely starts with a flag prefix", async () => {
    // USER_IS_ADMIN starts with 'USE' but is not a USE_* flag.
    const project = tempProject();
    writeFileSync(join(project, ".env"), "USER_IS_ADMIN=true\nDEBUG=true\n");

    await syncExample({ project_dir: project });

    const example = readFileSync(join(project, ".env.example"), "utf-8");
    expect(example).toContain("USER_IS_ADMIN=\n");
    expect(example).toContain("DEBUG=true");
  });
});

describe("syncExample - heals a previously leaked .env.example", () => {
  it("re-blanks an existing placeholder that is byte-for-byte the live secret", async () => {
    // Simulates a repo that ran the old buggy tool: the real secret is already
    // baked into .env.example. A re-sync must NOT trust it back into place.
    const project = tempProject();
    writeFileSync(join(project, ".env"), "PORTAL_ACCESS_TOKEN=48213793029\n");
    writeFileSync(
      join(project, ".env.example"),
      "PORTAL_ACCESS_TOKEN=48213793029\n"
    );

    await syncExample({ project_dir: project });

    const example = readFileSync(join(project, ".env.example"), "utf-8");
    expect(example).not.toContain("48213793029");
    expect(example).toContain("PORTAL_ACCESS_TOKEN=");
  });

  it("keeps a curated placeholder that differs from the live value", async () => {
    const project = tempProject();
    writeFileSync(join(project, ".env"), "API_KEY=realsecret123\n");
    writeFileSync(join(project, ".env.example"), "API_KEY=your-key-here\n");

    await syncExample({ project_dir: project });

    const example = readFileSync(join(project, ".env.example"), "utf-8");
    expect(example).toContain("API_KEY=your-key-here");
    expect(example).not.toContain("realsecret123");
  });
});
