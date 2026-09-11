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
    // SIZEABLE_COUNT (not ..._TOKEN) so the deny-first gate does NOT fire — this
    // isolates the SAFE_NUMERIC_KEYS `^SIZE(?:_|$)` boundary: an unbounded
    // `/^SIZE/` would wrongly preserve the value and fail this test.
    const project = tempProject();
    writeFileSync(join(project, ".env"), "SIZEABLE_COUNT=99887766\n");

    await syncExample({ project_dir: project });

    const example = readFileSync(join(project, ".env.example"), "utf-8");
    expect(example).not.toContain("99887766");
  });

  it("blanks a non-secret key whose name merely contains 'port' as a substring", async () => {
    // SUPPORT_NUMBER has no secret token, so the deny gate stays silent — this
    // isolates the SAFE_NUMERIC_KEYS port boundary: the old substring check
    // (`includes('port')`) would preserve the value; the token boundary blanks it.
    const project = tempProject();
    writeFileSync(join(project, ".env"), "SUPPORT_NUMBER=48213793029\n");

    await syncExample({ project_dir: project });

    const example = readFileSync(join(project, ".env.example"), "utf-8");
    expect(example).not.toContain("48213793029");
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
  it("re-blanks a secret key's stored placeholder equal to the live value", async () => {
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

  it("re-blanks a secret key's stale placeholder even when it differs from the live value (rotated secret)", async () => {
    // The leaked example value need not equal the current .env value — the
    // secret may have been rotated since the leak. A value-equality check would
    // miss this; keying off the sensitive NAME catches it.
    const project = tempProject();
    writeFileSync(join(project, ".env"), "API_KEY=newsecret999\n");
    writeFileSync(join(project, ".env.example"), "API_KEY=oldsecret111\n");

    await syncExample({ project_dir: project });

    const example = readFileSync(join(project, ".env.example"), "utf-8");
    expect(example).not.toContain("oldsecret111");
    expect(example).not.toContain("newsecret999");
    expect(example).toContain("API_KEY=");
  });

  it("keeps a curated placeholder on a NON-secret key", async () => {
    const project = tempProject();
    writeFileSync(join(project, ".env"), "LOG_LEVEL=info\n");
    writeFileSync(join(project, ".env.example"), "LOG_LEVEL=debug\n");

    await syncExample({ project_dir: project });

    const example = readFileSync(join(project, ".env.example"), "utf-8");
    expect(example).toContain("LOG_LEVEL=debug");
  });

  it("does not wipe a legitimate non-secret default that equals the live value", async () => {
    // Regression guard: a byte-equality heal would blank APP_ENV here. Keying
    // off the (non-secret) name keeps the documented default intact.
    const project = tempProject();
    writeFileSync(join(project, ".env"), "APP_ENV=production\n");
    writeFileSync(join(project, ".env.example"), "APP_ENV=production\n");

    await syncExample({ project_dir: project });

    const example = readFileSync(join(project, ".env.example"), "utf-8");
    expect(example).toContain("APP_ENV=production");
  });
});

describe("syncExample - temp file symlink traversal", () => {
  it("refuses to write through a pre-planted .env.example.tmp symlink", async () => {
    const project = tempProject();
    const external = tempProject();
    const victim = join(external, "shell-rc");
    writeFileSync(victim, "original content");
    writeFileSync(join(project, ".env"), "API_KEY=secret123\n");
    // The temp path is predictable, so it is plantable by a committed repo.
    symlinkSync(victim, join(project, ".env.example.tmp"));

    await syncExample({ project_dir: project });

    // The write must not have followed the link and truncated the target.
    expect(readFileSync(victim, "utf-8")).toBe("original content");
  });

  it("still succeeds when a plain leftover .tmp is present", async () => {
    const project = tempProject();
    writeFileSync(join(project, ".env"), "API_KEY=secret123\n");
    writeFileSync(join(project, ".env.example.tmp"), "stale from a crashed run");

    const result = await syncExample({ project_dir: project });

    expect(result).toMatchObject({ keys_synced: 1 });
    expect(readFileSync(join(project, ".env.example"), "utf-8")).toContain("API_KEY=");
  });
});

describe("syncExample - multi-line values", () => {
  it("does not copy the body of a multi-line quoted secret", async () => {
    const project = tempProject();
    const pem = [
      'PRIVATE_KEY="-----BEGIN PRIVATE KEY-----',
      "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ",
      "b2R5bGluZXdpdGhwYWRkaW5n==",
      '-----END PRIVATE KEY-----"',
      "",
    ].join("\n");
    writeFileSync(join(project, ".env"), pem);

    await syncExample({ project_dir: project });
    const out = readFileSync(join(project, ".env.example"), "utf-8");

    expect(out).not.toContain("MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ");
    expect(out).not.toContain("b2R5bGluZXdpdGhwYWRkaW5n");
    expect(out).not.toContain("-----END PRIVATE KEY-----");
    expect(out).toContain("PRIVATE_KEY=");
  });

  it("drops a #-prefixed line inside a quoted value instead of preserving it", async () => {
    const project = tempProject();
    // dotenv's value pattern spans newlines AND `#`, so this line is secret
    // material, not a comment. The comment-preservation path must not see it.
    writeFileSync(
      join(project, ".env"),
      'BLOB="line1\n# SECRETMARKER\nline3"\n'
    );

    await syncExample({ project_dir: project });
    const out = readFileSync(join(project, ".env.example"), "utf-8");

    expect(out).not.toContain("SECRETMARKER");
    expect(out).not.toContain("line3");
    expect(out).toContain("BLOB=");
  });

  it("keeps tracking a quoted value past an escaped quote", async () => {
    const project = tempProject();
    // dotenv treats `\"` as literal content and keeps scanning, so the value
    // is still open here. A naive endsWith would close it and let the next
    // line reach the comment passthrough.
    writeFileSync(
      join(project, ".env"),
      'BLOB="a\\"\n# SECRETMARKER\nmore"\n'
    );

    await syncExample({ project_dir: project });
    const out = readFileSync(join(project, ".env.example"), "utf-8");

    expect(out).not.toContain("SECRETMARKER");
    expect(out).toContain("BLOB=");
  });

  it("drops a #-prefixed continuation line when the assignment used a colon", async () => {
    const project = tempProject();
    // dotenv's LINE regex accepts `:` as well as `=`.
    writeFileSync(
      join(project, ".env"),
      'FOO: "line1\n# SECRETMARKER\nline3"\n'
    );

    await syncExample({ project_dir: project });
    const out = readFileSync(join(project, ".env.example"), "utf-8");

    expect(out).not.toContain("SECRETMARKER");
  });

  it("refuses to write a lossy file when a quote is unterminated", async () => {
    const project = tempProject();
    writeFileSync(join(project, ".env.example"), "API_HOST=example.com\nPORT=3000\n");
    // dotenv recovers and still parses API_HOST and PORT; the line tracker
    // cannot, so writing would silently drop them from the curated file.
    writeFileSync(
      join(project, ".env"),
      "GREETING='it's a test\nAPI_HOST=example.com\nPORT=3000\n"
    );

    const result = await syncExample({ project_dir: project });

    expect(result).toHaveProperty("error");
    // The curated original must survive untouched.
    expect(readFileSync(join(project, ".env.example"), "utf-8")).toContain("PORT=3000");
  });

  it("refuses a lossy write even when .env repeats a key", async () => {
    const project = tempProject();
    writeFileSync(join(project, ".env.example"), "A=1\nFOO=x\nBAR=3\n");
    // The duplicate A would buy one unit of slack in a count-based guard,
    // exactly covering for the dropped BAR.
    writeFileSync(join(project, ".env"), 'A=1\nA=2\nFOO="unclosed\nBAR=3\n');

    const result = await syncExample({ project_dir: project });

    expect(result).toHaveProperty("error");
    expect(readFileSync(join(project, ".env.example"), "utf-8")).toContain("BAR=3");
  });

  it("handles a trailing comment after a quoted value", async () => {
    const project = tempProject();
    // dotenv documents this shape. Testing the end of the line instead of the
    // first unescaped quote treats the value as open and eats the rest.
    writeFileSync(
      join(project, ".env"),
      'API_HOST="example.com"   # the public host\nAPI_KEY=sk-live-abc\nPORT=3000\n'
    );

    const result = await syncExample({ project_dir: project });
    const out = readFileSync(join(project, ".env.example"), "utf-8");

    expect(result).toMatchObject({ keys_synced: 3 });
    expect(out).toContain("API_HOST=");
    expect(out).toContain("API_KEY=");
    expect(out).toContain("PORT=");
    expect(out).not.toContain("sk-live-abc");
  });

  it("closes a multi-line value whose final line has a trailing comment", async () => {
    const project = tempProject();
    writeFileSync(
      join(project, ".env"),
      'KEY="-----BEGIN-----\nBODYLINE\n-----END-----"  # prod\nPORT=3000\n'
    );

    const result = await syncExample({ project_dir: project });
    const out = readFileSync(join(project, ".env.example"), "utf-8");

    expect(result).toMatchObject({ keys_synced: 2 });
    expect(out).not.toContain("BODYLINE");
    expect(out).toContain("PORT=");
  });

  it("redacts a commented-out credential rather than copying it", async () => {
    const project = tempProject();
    // Parking a rotated key behind a `#` is the usual habit; .env.example is
    // meant to be committed.
    // Assembled at runtime: a literal here is shaped exactly like a real
    // Stripe key and trips GitHub push protection.
    const fakeKey = ["sk", "live", "AbCdEf0123456789AbCdEf0123456789"].join("_");
    writeFileSync(
      join(project, ".env"),
      `# OLD_API_KEY=${fakeKey}\nAPP_ENV=production\n`
    );

    await syncExample({ project_dir: project });
    const out = readFileSync(join(project, ".env.example"), "utf-8");

    expect(out).not.toContain(fakeKey);
  });

  it("handles an export prefix separated by a tab", async () => {
    const project = tempProject();
    // dotenv's prefix is `export\s+`, so this key is DATABASE_URL to the parser.
    writeFileSync(project + "/.env", "export\tDATABASE_URL=postgres://u:p@h/db\n");

    await syncExample({ project_dir: project });
    const out = readFileSync(join(project, ".env.example"), "utf-8");

    expect(out).toContain("DATABASE_URL=");
    expect(out).not.toContain("postgres://u:p@h/db");
  });

  it("keeps the export prefix on keys that use it", async () => {
    const project = tempProject();
    writeFileSync(join(project, ".env"), "export DATABASE_URL=postgres://u:p@h/db\n");

    await syncExample({ project_dir: project });
    const out = readFileSync(join(project, ".env.example"), "utf-8");

    expect(out).toContain("export DATABASE_URL=");
    expect(out).not.toContain("postgres://u:p@h/db");
  });
});

describe("syncExample - placeholder reuse", () => {
  it("does not harvest real values through a .env.example symlink", async () => {
    const project = tempProject();
    writeFileSync(
      join(project, ".env"),
      "DATABASE_URL=postgres://real:hunter2@db.internal/prod\n"
    );
    // Classic committed-template trap: the "example" points at the real file.
    symlinkSync(join(project, ".env"), join(project, ".env.example"));

    await syncExample({ project_dir: project });
    const out = readFileSync(join(project, ".env.example"), "utf-8");

    expect(out).not.toContain("hunter2");
    expect(out).toContain("DATABASE_URL=");
  });

  it("still reuses a clean curated placeholder", async () => {
    // Guards the scanForSecrets gate: if the scanner ever normalized clean
    // text, reuse would silently die for every key.
    const project = tempProject();
    writeFileSync(join(project, ".env"), "APP_NAME=real-production-name\n");
    writeFileSync(
      join(project, ".env.example"),
      "# The display name\nAPP_NAME=my-app\n"
    );

    await syncExample({ project_dir: project });
    const out = readFileSync(join(project, ".env.example"), "utf-8");

    expect(out).toContain("APP_NAME=my-app");
    expect(out).toContain("# The display name");
    expect(out).not.toContain("real-production-name");
  });

  it("regenerates a stored placeholder whose URL carries a credential query param", async () => {
    const project = tempProject();
    // DATABASE_URL does not match SECRET_KEY_TOKENS and there is no userinfo,
    // so this clears both the key gate and the scanner.
    writeFileSync(join(project, ".env"), "DATABASE_URL=postgres://h/db?password=live\n");
    writeFileSync(
      join(project, ".env.example"),
      "DATABASE_URL=postgres://db.internal/prod?password=leakedFromLastRun\n"
    );

    await syncExample({ project_dir: project });
    const out = readFileSync(join(project, ".env.example"), "utf-8");

    expect(out).not.toContain("leakedFromLastRun");
  });

  it("regenerates a stored placeholder that carries URL userinfo", async () => {
    const project = tempProject();
    writeFileSync(join(project, ".env"), "DATABASE_URL=postgres://u:p@h/db\n");
    writeFileSync(
      join(project, ".env.example"),
      "DATABASE_URL=postgres://leaked:fromlastrun@db.internal/prod\n"
    );

    await syncExample({ project_dir: project });
    const out = readFileSync(join(project, ".env.example"), "utf-8");

    expect(out).not.toContain("fromlastrun");
  });
});
