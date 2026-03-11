import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { validateProjectDir } from "./path-validator.js";

const tempDirs: string[] = [];

function makeTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "path-validator-test-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of tempDirs) {
    rmSync(dir, { recursive: true, force: true });
  }
  tempDirs.length = 0;
});

describe("validateProjectDir", () => {
  describe("rejects invalid paths", () => {
    it("rejects relative path", () => {
      const result = validateProjectDir("./project");
      expect(result.valid).toBe(false);
      expect(result.reason).toMatch(/absolute path/i);
    });

    it("rejects bare directory name", () => {
      const result = validateProjectDir("project");
      expect(result.valid).toBe(false);
      expect(result.reason).toMatch(/absolute path/i);
    });

    it("rejects absolute path with no project markers", () => {
      const dir = makeTempDir();
      const result = validateProjectDir(dir);
      expect(result.valid).toBe(false);
      expect(result.reason).toMatch(/project marker/i);
    });
  });

  describe("accepts directories with project markers", () => {
    it("accepts directory with .git", () => {
      const dir = makeTempDir();
      mkdirSync(join(dir, ".git"));
      const result = validateProjectDir(dir);
      expect(result.valid).toBe(true);
      expect(result.reason).toBeUndefined();
    });

    it("accepts directory with package.json", () => {
      const dir = makeTempDir();
      writeFileSync(join(dir, "package.json"), "{}");
      const result = validateProjectDir(dir);
      expect(result.valid).toBe(true);
    });

    it("accepts directory with Cargo.toml", () => {
      const dir = makeTempDir();
      writeFileSync(join(dir, "Cargo.toml"), "");
      const result = validateProjectDir(dir);
      expect(result.valid).toBe(true);
    });

    it("accepts directory with .env only", () => {
      const dir = makeTempDir();
      writeFileSync(join(dir, ".env"), "KEY=value");
      const result = validateProjectDir(dir);
      expect(result.valid).toBe(true);
    });

    it("accepts directory with requirements.txt", () => {
      const dir = makeTempDir();
      writeFileSync(join(dir, "requirements.txt"), "flask");
      const result = validateProjectDir(dir);
      expect(result.valid).toBe(true);
    });

    it("accepts directory with go.mod", () => {
      const dir = makeTempDir();
      writeFileSync(join(dir, "go.mod"), "");
      const result = validateProjectDir(dir);
      expect(result.valid).toBe(true);
    });

    it("accepts directory with pyproject.toml", () => {
      const dir = makeTempDir();
      writeFileSync(join(dir, "pyproject.toml"), "");
      const result = validateProjectDir(dir);
      expect(result.valid).toBe(true);
    });

    it("accepts directory with Makefile", () => {
      const dir = makeTempDir();
      writeFileSync(join(dir, "Makefile"), "");
      const result = validateProjectDir(dir);
      expect(result.valid).toBe(true);
    });

    it("accepts directory with Gemfile", () => {
      const dir = makeTempDir();
      writeFileSync(join(dir, "Gemfile"), "");
      const result = validateProjectDir(dir);
      expect(result.valid).toBe(true);
    });

    it("accepts directory with pom.xml", () => {
      const dir = makeTempDir();
      writeFileSync(join(dir, "pom.xml"), "");
      const result = validateProjectDir(dir);
      expect(result.valid).toBe(true);
    });

    it("accepts directory with build.gradle", () => {
      const dir = makeTempDir();
      writeFileSync(join(dir, "build.gradle"), "");
      const result = validateProjectDir(dir);
      expect(result.valid).toBe(true);
    });

    it("accepts directory with CMakeLists.txt", () => {
      const dir = makeTempDir();
      writeFileSync(join(dir, "CMakeLists.txt"), "");
      const result = validateProjectDir(dir);
      expect(result.valid).toBe(true);
    });

    it("accepts directory with composer.json", () => {
      const dir = makeTempDir();
      writeFileSync(join(dir, "composer.json"), "{}");
      const result = validateProjectDir(dir);
      expect(result.valid).toBe(true);
    });

    it("accepts directory with setup.py", () => {
      const dir = makeTempDir();
      writeFileSync(join(dir, "setup.py"), "");
      const result = validateProjectDir(dir);
      expect(result.valid).toBe(true);
    });
  });
});
