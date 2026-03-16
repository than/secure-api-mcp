import { describe, it, expect, afterEach } from "vitest";
import {
  mkdtempSync,
  writeFileSync,
  mkdirSync,
  rmSync,
  utimesSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

function makeTempDir(): string {
  return mkdtempSync(join(tmpdir(), "mycnf-loader-test-"));
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

describe("loadMyCnf - basic parsing", () => {
  it("parses [client] section fields", async () => {
    const { loadMyCnf } = await import("./mycnf-loader.js");
    const dir = tempDir();
    const home = tempDir();
    writeFileSync(
      join(home, ".my.cnf"),
      "[client]\nuser=root\npassword=secret123\nhost=localhost\nport=3306\n"
    );
    const result = loadMyCnf(dir, home);
    expect(result.sections.client).toEqual({
      user: "root",
      password: "secret123",
      host: "localhost",
      port: "3306",
    });
  });

  it("extracts secrets keyed as section.field", async () => {
    const { loadMyCnf } = await import("./mycnf-loader.js");
    const dir = tempDir();
    const home = tempDir();
    writeFileSync(
      join(home, ".my.cnf"),
      "[client]\nuser=root\npassword=secret123\nhost=db.example.com\nport=3306\n"
    );
    const result = loadMyCnf(dir, home);
    expect(result.secrets).toEqual({
      "client.user": "root",
      "client.password": "secret123",
      "client.host": "db.example.com",
    });
    // port is NOT a secret field
    expect(result.secrets).not.toHaveProperty("client.port");
  });
});

describe("loadMyCnf - multiple sections", () => {
  it("parses multiple sections and extracts secrets from each", async () => {
    const { loadMyCnf } = await import("./mycnf-loader.js");
    const dir = tempDir();
    const home = tempDir();
    writeFileSync(
      join(home, ".my.cnf"),
      "[client]\nuser=root\npassword=secret1\n\n[mysqldump]\nuser=backup\npassword=secret2\n"
    );
    const result = loadMyCnf(dir, home);
    expect(result.sections.client).toEqual({
      user: "root",
      password: "secret1",
    });
    expect(result.sections.mysqldump).toEqual({
      user: "backup",
      password: "secret2",
    });
    expect(result.secrets).toEqual({
      "client.user": "root",
      "client.password": "secret1",
      "mysqldump.user": "backup",
      "mysqldump.password": "secret2",
    });
  });
});

describe("loadMyCnf - project-local overrides", () => {
  it("project-local .my.cnf overrides global per-field", async () => {
    const { loadMyCnf } = await import("./mycnf-loader.js");
    const dir = tempDir();
    const home = tempDir();
    writeFileSync(
      join(home, ".my.cnf"),
      "[client]\nuser=global_user\npassword=global_pass\nhost=global.host\n"
    );
    writeFileSync(
      join(dir, ".my.cnf"),
      "[client]\npassword=local_pass\n"
    );
    const result = loadMyCnf(dir, home);
    // user and host come from global, password overridden by local
    expect(result.sections.client).toEqual({
      user: "global_user",
      password: "local_pass",
      host: "global.host",
    });
    expect(result.secrets["client.password"]).toBe("local_pass");
    expect(result.secrets["client.user"]).toBe("global_user");
  });
});

describe("loadMyCnf - missing files", () => {
  it("returns empty result when no .my.cnf files exist", async () => {
    const { loadMyCnf } = await import("./mycnf-loader.js");
    const dir = tempDir();
    const home = tempDir();
    const result = loadMyCnf(dir, home);
    expect(result.sections).toEqual({});
    expect(result.secrets).toEqual({});
  });

  it("returns global only when project-local is missing", async () => {
    const { loadMyCnf } = await import("./mycnf-loader.js");
    const dir = tempDir();
    const home = tempDir();
    writeFileSync(
      join(home, ".my.cnf"),
      "[client]\nuser=root\n"
    );
    const result = loadMyCnf(dir, home);
    expect(result.sections.client).toEqual({ user: "root" });
    expect(result.secrets).toEqual({ "client.user": "root" });
  });
});

describe("loadMyCnf - !include directive", () => {
  it("follows !include and merges included file", async () => {
    const { loadMyCnf } = await import("./mycnf-loader.js");
    const dir = tempDir();
    const home = tempDir();
    const includedPath = join(home, "extra.cnf");
    writeFileSync(includedPath, "[client]\npassword=from_include\n");
    writeFileSync(
      join(home, ".my.cnf"),
      `[client]\nuser=root\n!include ${includedPath}\n`
    );
    const result = loadMyCnf(dir, home);
    expect(result.sections.client?.user).toBe("root");
    expect(result.sections.client?.password).toBe("from_include");
  });

  it("resolves relative !include paths against parent file directory", async () => {
    const { loadMyCnf } = await import("./mycnf-loader.js");
    const dir = tempDir();
    const home = tempDir();
    // extra.cnf sits next to .my.cnf — use relative path in !include
    writeFileSync(join(home, "extra.cnf"), "[client]\npassword=relative_secret\n");
    writeFileSync(join(home, ".my.cnf"), "[client]\nuser=root\n!include extra.cnf\n");
    const result = loadMyCnf(dir, home);
    expect(result.sections.client?.password).toBe("relative_secret");
  });

  it("detects include cycles and does not loop", async () => {
    const { loadMyCnf } = await import("./mycnf-loader.js");
    const dir = tempDir();
    const home = tempDir();
    const fileA = join(home, ".my.cnf");
    const fileB = join(home, "b.cnf");
    writeFileSync(fileA, `[client]\nuser=root\n!include ${fileB}\n`);
    writeFileSync(fileB, `[client]\npassword=secret\n!include ${fileA}\n`);
    // Should not throw or loop forever
    const result = loadMyCnf(dir, home);
    expect(result.sections.client?.user).toBe("root");
    expect(result.sections.client?.password).toBe("secret");
  });
});

describe("loadMyCnf - !includedir directive", () => {
  it("includes all .cnf files from directory", async () => {
    const { loadMyCnf } = await import("./mycnf-loader.js");
    const dir = tempDir();
    const home = tempDir();
    const includeDir = join(home, "conf.d");
    mkdirSync(includeDir);
    writeFileSync(join(includeDir, "a.cnf"), "[client]\nuser=from_dir\n");
    writeFileSync(join(includeDir, "b.cnf"), "[client]\npassword=dir_pass\n");
    // non-.cnf files should be ignored
    writeFileSync(join(includeDir, "skip.txt"), "[client]\nhost=ignored\n");
    writeFileSync(
      join(home, ".my.cnf"),
      `!includedir ${includeDir}\n`
    );
    const result = loadMyCnf(dir, home);
    expect(result.sections.client?.user).toBe("from_dir");
    expect(result.sections.client?.password).toBe("dir_pass");
    expect(result.sections.client?.host).toBeUndefined();
  });
});

describe("loadMyCnf - caching", () => {
  it("returns same reference on cache hit", async () => {
    const { loadMyCnf } = await import("./mycnf-loader.js");
    const dir = tempDir();
    const home = tempDir();
    writeFileSync(join(home, ".my.cnf"), "[client]\nuser=root\n");
    const first = loadMyCnf(dir, home);
    const second = loadMyCnf(dir, home);
    expect(second).toBe(first);
  });

  it("returns fresh result when content changes but mtime is identical", async () => {
    const { loadMyCnf } = await import("./mycnf-loader.js");
    const dir = tempDir();
    const home = tempDir();
    const cnfPath = join(home, ".my.cnf");
    const fixedTime = new Date("2020-06-15T12:00:00.000Z");

    writeFileSync(cnfPath, "[client]\npassword=original\n");
    utimesSync(cnfPath, fixedTime, fixedTime);
    const first = loadMyCnf(dir, home);
    expect(first.secrets["client.password"]).toBe("original");

    writeFileSync(cnfPath, "[client]\npassword=rotated\n");
    utimesSync(cnfPath, fixedTime, fixedTime);
    const second = loadMyCnf(dir, home);
    expect(second.secrets["client.password"]).toBe("rotated");
  });
});
