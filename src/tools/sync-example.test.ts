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
