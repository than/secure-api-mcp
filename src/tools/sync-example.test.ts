import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, rmSync, existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { syncExample } from "./sync-example.js";

function makeTempProject(): string {
  const dir = mkdtempSync(join(tmpdir(), "secure-api-test-"));
  // Minimal project marker
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
  it("refuses to write .env.example when it is a symlink pointing outside the project", async () => {
    const project = tempProject();
    const target = tempProject();
    const targetFile = join(target, "sensitive-file.txt");
    writeFileSync(targetFile, "original content");

    // .env exists so syncExample has something to work with
    writeFileSync(join(project, ".env"), "API_KEY=secret123\n");

    // Pre-create .env.example as a symlink to a file outside the project
    symlinkSync(targetFile, join(project, ".env.example"));

    const result = await syncExample({ project_dir: project });

    expect(result).toMatchObject({ error: expect.stringMatching(/outside/i) });
    // The target file must not have been overwritten
    expect(readFileSync(targetFile, "utf-8")).toBe("original content");
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
