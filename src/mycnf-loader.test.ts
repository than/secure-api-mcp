import { describe, it, expect, afterEach, vi } from "vitest";
import {
  mkdtempSync,
  writeFileSync,
  mkdirSync,
  rmSync,
  utimesSync,
  symlinkSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

// Spy on ini.parse (wrapping the real impl) so tests can assert whether a call
// re-parsed (full path) or served the cache fast path (no parse).
vi.mock("ini", async (importOriginal) => {
  const actual = await importOriginal<typeof import("ini")>();
  return { ...actual, parse: vi.fn(actual.parse) };
});

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

describe("loadMyCnf - include containment", () => {
  it("ignores a project-local !include that points outside the project", async () => {
    const { loadMyCnf } = await import("./mycnf-loader.js");
    const dir = tempDir();
    const home = tempDir();
    const outside = tempDir();
    // A file outside the project that a crafted include would try to disclose.
    writeFileSync(join(outside, "secrets.cnf"), "[client]\nport=9999\n");
    writeFileSync(
      join(dir, ".my.cnf"),
      `[client]\nuser=root\n!include ${join(outside, "secrets.cnf")}\n`
    );
    const result = loadMyCnf(dir, home);
    // The local section is read, but the out-of-bounds include is skipped.
    expect(result.sections.client?.user).toBe("root");
    expect(result.sections.client?.port).toBeUndefined();
  });

  it("still follows project-local includes that stay within the project", async () => {
    const { loadMyCnf } = await import("./mycnf-loader.js");
    const dir = tempDir();
    const home = tempDir();
    writeFileSync(join(dir, "extra.cnf"), "[client]\npassword=inproject\n");
    writeFileSync(
      join(dir, ".my.cnf"),
      "[client]\nuser=root\n!include extra.cnf\n"
    );
    const result = loadMyCnf(dir, home);
    expect(result.sections.client?.password).toBe("inproject");
  });

  it("ignores a project-local !include whose in-project target symlinks outside", async () => {
    const { loadMyCnf } = await import("./mycnf-loader.js");
    const dir = tempDir();
    const home = tempDir();
    const outside = tempDir();
    writeFileSync(join(outside, "secrets.cnf"), "[client]\nport=9999\n");
    // innocent.cnf lives inside the project but is a symlink to the outside file.
    symlinkSync(join(outside, "secrets.cnf"), join(dir, "innocent.cnf"));
    writeFileSync(
      join(dir, ".my.cnf"),
      "[client]\nuser=root\n!include ./innocent.cnf\n"
    );
    const result = loadMyCnf(dir, home);
    expect(result.sections.client?.user).toBe("root");
    expect(result.sections.client?.port).toBeUndefined();
  });

  it("ignores an !includedir entry that symlinks outside the project", async () => {
    const { loadMyCnf } = await import("./mycnf-loader.js");
    const dir = tempDir();
    const home = tempDir();
    const outside = tempDir();
    writeFileSync(join(outside, "secrets.cnf"), "[client]\nport=8888\n");
    const confd = join(dir, "conf.d");
    mkdirSync(confd);
    // An in-project includedir entry that is a symlink to the outside file.
    symlinkSync(join(outside, "secrets.cnf"), join(confd, "evil.cnf"));
    writeFileSync(
      join(dir, ".my.cnf"),
      "[client]\nuser=root\n!includedir ./conf.d\n"
    );
    const result = loadMyCnf(dir, home);
    expect(result.sections.client?.user).toBe("root");
    expect(result.sections.client?.port).toBeUndefined();
  });

  it("allows the global ~/.my.cnf chain to include files outside the home dir", async () => {
    const { loadMyCnf } = await import("./mycnf-loader.js");
    const dir = tempDir();
    const home = tempDir();
    const elsewhere = tempDir();
    writeFileSync(join(elsewhere, "system.cnf"), "[client]\npassword=systemwide\n");
    writeFileSync(
      join(home, ".my.cnf"),
      `[client]\nuser=root\n!include ${join(elsewhere, "system.cnf")}\n`
    );
    const result = loadMyCnf(dir, home);
    expect(result.sections.client?.password).toBe("systemwide");
  });

  // Regression guard for the integration boundary between containment (this PR)
  // and the cache fast-path (#48): containment must skip only files that EXIST
  // out of bounds. An absent in-project include target must still be tracked as
  // "missing" so the fast path notices it appearing later — otherwise a freshly
  // added credentials file would be served stale.
  it("picks up a contained in-project !include target created after the cache was populated", async () => {
    const { loadMyCnf } = await import("./mycnf-loader.js");
    const dir = tempDir();
    const home = tempDir();
    // Project-local root references later.cnf, which does not exist yet.
    writeFileSync(
      join(dir, ".my.cnf"),
      "[client]\nuser=root\n!include ./later.cnf\n"
    );
    const first = loadMyCnf(dir, home);
    expect(first.secrets["client.password"]).toBeUndefined();

    // The in-project include target appears mid-session.
    writeFileSync(join(dir, "later.cnf"), "[client]\npassword=appeared\n");
    const second = loadMyCnf(dir, home);
    expect(second.secrets["client.password"]).toBe("appeared");
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

  // Issue #58: a contained-out symlink entry in a project !includedir is skipped
  // at parse time, so it is never a "known file". The fast path must still serve
  // the cache (no reparse) instead of bailing on every call just because that
  // entry shows up in the directory listing.
  it("serves the cache fast path when an !includedir holds a contained-out symlink entry", async () => {
    const { loadMyCnf } = await import("./mycnf-loader.js");
    const { parse } = await import("ini");
    const mockParse = vi.mocked(parse);

    const dir = tempDir();
    const home = tempDir();
    const outside = tempDir();
    writeFileSync(join(outside, "secrets.cnf"), "[client]\nport=8888\n");
    const confd = join(dir, "conf.d");
    mkdirSync(confd);
    writeFileSync(join(confd, "ok.cnf"), "[client]\nuser=root\n");
    symlinkSync(join(outside, "secrets.cnf"), join(confd, "evil.cnf"));
    writeFileSync(join(dir, ".my.cnf"), "[client]\n!includedir ./conf.d\n");

    const first = loadMyCnf(dir, home); // warm the cache
    expect(first.sections.client?.user).toBe("root");
    expect(first.sections.client?.port).toBeUndefined(); // out-of-bounds not disclosed

    mockParse.mockClear();
    const second = loadMyCnf(dir, home);
    // Fast path served the cache — nothing was re-parsed...
    expect(mockParse).not.toHaveBeenCalled();
    // ...and the same cached result is returned, still without the secret.
    expect(second).toBe(first);
    expect(second.sections.client?.port).toBeUndefined();
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

  it("detects rotation in an !included file even when its mtime is frozen", async () => {
    const { loadMyCnf } = await import("./mycnf-loader.js");
    const dir = tempDir();
    const home = tempDir();
    const rootPath = join(home, ".my.cnf");
    const includedPath = join(home, "extra.cnf");
    const fixedTime = new Date("2020-06-15T12:00:00.000Z");

    // Root file !includes a secrets file. Freeze the included file's mtime so a
    // later rotation keeps the same mtime (NFS / backup-restore / touch -m).
    writeFileSync(rootPath, "[client]\nuser=root\n!include extra.cnf\n");
    writeFileSync(includedPath, "[client]\npassword=original\n");
    utimesSync(includedPath, fixedTime, fixedTime);
    const first = loadMyCnf(dir, home);
    expect(first.secrets["client.password"]).toBe("original");

    writeFileSync(includedPath, "[client]\npassword=rotated\n");
    utimesSync(includedPath, fixedTime, fixedTime);
    const second = loadMyCnf(dir, home);
    expect(second.secrets["client.password"]).toBe("rotated");
  });

  it("detects a new .cnf file added to an !includedir", async () => {
    const { loadMyCnf } = await import("./mycnf-loader.js");
    const dir = tempDir();
    const home = tempDir();
    const includeDir = join(home, "conf.d");
    mkdirSync(includeDir);
    writeFileSync(join(includeDir, "a.cnf"), "[client]\nuser=root\n");
    writeFileSync(join(home, ".my.cnf"), `!includedir ${includeDir}\n`);
    const first = loadMyCnf(dir, home);
    expect(first.secrets["client.password"]).toBeUndefined();

    // Drop a new credentials file into the included directory.
    writeFileSync(join(includeDir, "z-secret.cnf"), "[client]\npassword=dropped_in\n");
    const second = loadMyCnf(dir, home);
    expect(second.secrets["client.password"]).toBe("dropped_in");
  });

  it("detects a new .cnf in an !includedir even when the dir mtime is frozen", async () => {
    const { loadMyCnf } = await import("./mycnf-loader.js");
    const dir = tempDir();
    const home = tempDir();
    const includeDir = join(home, "conf.d");
    mkdirSync(includeDir);
    const dirTime = new Date("2020-06-15T12:00:00.000Z");
    writeFileSync(join(includeDir, "a.cnf"), "[client]\nuser=root\n");
    writeFileSync(join(home, ".my.cnf"), `!includedir ${includeDir}\n`);
    utimesSync(includeDir, dirTime, dirTime);
    const first = loadMyCnf(dir, home);
    expect(first.secrets["client.password"]).toBeUndefined();

    // Add a file but restore the directory mtime (NFS / touch -m on the dir).
    writeFileSync(join(includeDir, "z-secret.cnf"), "[client]\npassword=frozen_dir\n");
    utimesSync(includeDir, dirTime, dirTime);
    const second = loadMyCnf(dir, home);
    expect(second.secrets["client.password"]).toBe("frozen_dir");
  });

  it("detects a project-local .my.cnf created after only the global was cached", async () => {
    const { loadMyCnf } = await import("./mycnf-loader.js");
    const dir = tempDir();
    const home = tempDir();
    writeFileSync(join(home, ".my.cnf"), "[client]\nuser=root\n");
    const first = loadMyCnf(dir, home);
    expect(first.secrets["client.password"]).toBeUndefined();

    // Project-local file appears mid-session.
    writeFileSync(join(dir, ".my.cnf"), "[client]\npassword=local_secret\n");
    const second = loadMyCnf(dir, home);
    expect(second.secrets["client.password"]).toBe("local_secret");
  });

  it("detects a global ~/.my.cnf created after only the project-local was cached", async () => {
    const { loadMyCnf } = await import("./mycnf-loader.js");
    const dir = tempDir();
    const home = tempDir();
    writeFileSync(join(dir, ".my.cnf"), "[client]\nuser=proj\n");
    const first = loadMyCnf(dir, home);
    expect(first.secrets["client.password"]).toBeUndefined();

    // Global file appears mid-session.
    writeFileSync(join(home, ".my.cnf"), "[client]\npassword=home_secret\n");
    const second = loadMyCnf(dir, home);
    expect(second.secrets["client.password"]).toBe("home_secret");
  });

  it("detects an !include target created after the parent was cached", async () => {
    const { loadMyCnf } = await import("./mycnf-loader.js");
    const dir = tempDir();
    const home = tempDir();
    // Parent references extra.cnf, which does not exist yet.
    writeFileSync(join(home, ".my.cnf"), "[client]\nuser=root\n!include extra.cnf\n");
    const first = loadMyCnf(dir, home);
    expect(first.secrets["client.password"]).toBeUndefined();

    writeFileSync(join(home, "extra.cnf"), "[client]\npassword=included_secret\n");
    const second = loadMyCnf(dir, home);
    expect(second.secrets["client.password"]).toBe("included_secret");
  });
});
