import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, writeFileSync, symlinkSync, rmSync, readFileSync, lstatSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { syncExample, detectSpanDisagreement } from "./sync-example.js";

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

  it("recovers an unterminated quote the way dotenv does", async () => {
    const project = tempProject();
    writeFileSync(join(project, ".env.example"), "API_HOST=example.com\nPORT=3000\n");
    // Genuinely unterminated: no closing quote anywhere. dotenv recovers via
    // its unquoted branch and still parses API_HOST and PORT; the line tracker
    // cannot, so writing would silently drop them from the curated file.
    writeFileSync(
      join(project, ".env"),
      'GREETING="still open\nAPI_HOST=example.com\nPORT=3000\n'
    );

    // dotenv recovers via its unquoted branch, and the span scan is that same
    // regex — so all three keys are found and none of the value leaks.
    const result = await syncExample({ project_dir: project });
    const out = readFileSync(join(project, ".env.example"), "utf-8");

    expect(result).toMatchObject({ keys_synced: 3 });
    expect(out).toContain("PORT=3000");
    expect(out).not.toContain("still open");
  });

  it("handles a repeated key alongside an unclosed quote", async () => {
    const project = tempProject();
    writeFileSync(join(project, ".env.example"), "A=1\nFOO=x\nBAR=3\n");
    // The duplicate A would buy one unit of slack in a count-based guard,
    // exactly covering for the dropped BAR.
    writeFileSync(join(project, ".env"), 'A=1\nA=2\nFOO="unclosed\nBAR=3\n');

    const result = await syncExample({ project_dir: project });
    const out = readFileSync(join(project, ".env.example"), "utf-8");

    expect(out).toContain("BAR=");
    expect(out).not.toContain("unclosed");
    expect(result).not.toHaveProperty("error");
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

  it("keeps JSON in a quoted value from swallowing the rest of the file", async () => {
    const project = tempProject();
    // Every key here parses under dotenv; a clean-tail requirement would read
    // JSON_CONFIG as open and then blame a quote that is not unterminated.
    writeFileSync(
      join(project, ".env"),
      'API_HOST="example.com"\nJSON_CONFIG="{"a":1}"\nPORT=3000\n'
    );

    const result = await syncExample({ project_dir: project });
    const out = readFileSync(join(project, ".env.example"), "utf-8");

    expect(result).toMatchObject({ keys_synced: 3 });
    expect(out).toContain("PORT=");
  });

  it("redacts a poisoned comment carried over from .env.example", async () => {
    const project = tempProject();
    const fakeKey = ["sk", "live", "AbCdEf0123456789AbCdEf0123456789"].join("_");
    writeFileSync(join(project, ".env"), "APP_NAME=real-name\n");
    // Left behind by an earlier, leakier run; re-emitted as a pendingComment.
    writeFileSync(
      join(project, ".env.example"),
      `# see ${fakeKey}\nAPP_NAME=my-app\n`
    );

    await syncExample({ project_dir: project });
    const out = readFileSync(join(project, ".env.example"), "utf-8");

    expect(out).not.toContain(fakeKey);
  });

  it("keeps a value open across an even backslash run, as dotenv does", async () => {
    const project = tempProject();
    // `\\` is consumed by [^"], so the following `\"` escapes the quote and
    // dotenv keeps spanning. Closing early here put the comment line — real
    // secret material — straight into the committed file.
    writeFileSync(
      join(project, ".env"),
      'BLOB="a\\\\\\\\"\n# DB_PASSWORD=hunter2-prod\nend"\n'
    );

    await syncExample({ project_dir: project });
    const out = readFileSync(join(project, ".env.example"), "utf-8");

    expect(out).not.toContain("hunter2-prod");
    expect(out).toContain("BLOB=");
  });

  it("preserves prose comments that look like assignments", async () => {
    const project = tempProject();
    writeFileSync(
      join(project, ".env"),
      "# Note: rotate this quarterly\n# TODO: remove after migration\n" +
        "# Docs: https://stripe.com/docs\nAPP_ENV=production\n"
    );

    await syncExample({ project_dir: project });
    const out = readFileSync(join(project, ".env.example"), "utf-8");

    expect(out).toContain("# Note: rotate this quarterly");
    expect(out).toContain("# TODO: remove after migration");
    expect(out).toContain("# Docs: https://stripe.com/docs");
  });

  it("still blanks a commented assignment that uses a colon", async () => {
    const project = tempProject();
    // PASSWORD is named by the deny-first gate, so the `:` form is an
    // assignment rather than prose.
    writeFileSync(join(project, ".env"), "# PASSWORD: hunter2-prod-9f3a\nAPP_ENV=production\n");

    await syncExample({ project_dir: project });
    const out = readFileSync(join(project, ".env.example"), "utf-8");

    expect(out).not.toContain("hunter2-prod-9f3a");
  });

  it("regenerates a quoted credential URL identical to the live value", async () => {
    const project = tempProject();
    // dotenv's capture keeps the quotes, so an unquote-less check sees a
    // string new URL() rejects and lets the credential through.
    const line = 'DATABASE_URL="postgres://admin:s3cret@db.internal/app"';
    writeFileSync(join(project, ".env"), line + "\n");
    writeFileSync(join(project, ".env.example"), line + "\n");

    await syncExample({ project_dir: project });
    const out = readFileSync(join(project, ".env.example"), "utf-8");

    expect(out).not.toContain("s3cret");
  });

  it("regenerates an opaque token identical to the live value", async () => {
    const project = tempProject();
    // MAILGUN_SENDING misses SECRET_KEY_TOKENS, the scanner knows no Mailgun
    // prefix, and it is not a URL — the value shape is the only signal.
    const line = "MAILGUN_SENDING=8f3a9c2e1b7d40561122";
    writeFileSync(join(project, ".env"), line + "\n");
    writeFileSync(join(project, ".env.example"), line + "\n");

    await syncExample({ project_dir: project });
    const out = readFileSync(join(project, ".env.example"), "utf-8");

    expect(out).not.toContain("8f3a9c2e1b7d40561122");
  });

  it("regenerates an opaque stored token even after the live value rotated", async () => {
    const project = tempProject();
    // Equality no longer carries the decision: the stored shape does.
    writeFileSync(join(project, ".env"), "MAILGUN_SENDING=aa11bb22cc33dd44ee55ff66\n");
    writeFileSync(join(project, ".env.example"), "MAILGUN_SENDING=8f3a9c2e1b7d40561122\n");

    await syncExample({ project_dir: project });
    const out = readFileSync(join(project, ".env.example"), "utf-8");

    expect(out).not.toContain("8f3a9c2e1b7d40561122");
  });

  it("does not redact a value from the comment beside it", async () => {
    const project = tempProject();
    writeFileSync(
      join(project, ".env"),
      "NODE_ENV=production\n# Use production credentials only on the release host\n"
    );
    writeFileSync(join(project, ".env.example"), "NODE_ENV=production\n");

    await syncExample({ project_dir: project });
    const out = readFileSync(join(project, ".env.example"), "utf-8");

    // The file prints `production` verbatim one line up; redacting the prose
    // would contradict it.
    expect(out).toContain("# Use production credentials only on the release host");
  });

  it("still redacts a comment echoing a value the file does not carry", async () => {
    const project = tempProject();
    writeFileSync(
      join(project, ".env"),
      "API_SECRET=zulu-charlie-whiskey-42\n# rotate zulu-charlie-whiskey-42 quarterly\n"
    );

    await syncExample({ project_dir: project });
    const out = readFileSync(join(project, ".env.example"), "utf-8");

    expect(out).not.toContain("zulu-charlie-whiskey-42");
  });

  it("drops a base64 fragment that tokenizes as a key", async () => {
    const project = tempProject();
    // Unquoted multi-line value: dotenv scans each line on its own, and a
    // base64 line whose only non-word character is its trailing `=` becomes a
    // key. That "key" is a fragment of the private key.
    const fragment = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5";
    writeFileSync(
      join(project, ".env"),
      `PRIVATE_KEY=-----BEGIN RSA PRIVATE KEY-----\n${fragment}=\n-----END RSA PRIVATE KEY-----\n`
    );

    const result = await syncExample({ project_dir: project });
    const out = readFileSync(join(project, ".env.example"), "utf-8");

    expect(out).not.toContain(fragment);
    // Dropping it must not read as a lost key and refuse the whole write.
    expect(result).not.toHaveProperty("error");
  });

  it("drops a short digit-free base64 tail that tokenizes as a key", async () => {
    const project = tempProject();
    // The padded tail of a PEM is where `=` actually lives, and it is short and
    // often digit-free — under the OPAQUE_TOKEN shape, over the fragment one.
    writeFileSync(
      join(project, ".env"),
      'KEY="-----BEGIN-----\nZXhhbXBsZXNlY3JldA=\n'
    );

    await syncExample({ project_dir: project });
    const out = readFileSync(join(project, ".env.example"), "utf-8");

    expect(out).not.toContain("ZXhhbXBsZXNlY3JldA");
  });

  it("drops a base64url tail containing a hyphen", async () => {
    const project = tempProject();
    writeFileSync(
      join(project, ".env"),
      'KEY="-----BEGIN-----\nZXhhbXBsZS1zZWNyZXQtdg=\n'
    );

    await syncExample({ project_dir: project });

    expect(readFileSync(join(project, ".env.example"), "utf-8")).not.toContain(
      "ZXhhbXBsZS1zZWNyZXQtdg"
    );
  });

  it("does not refuse when an earlier duplicate is single-line", async () => {
    const project = tempProject();
    // parse() keeps only the last FOO, so comparing the first against it
    // reports a disagreement that does not exist.
    writeFileSync(join(project, ".env"), 'FOO=a\nFOO="x\ny"\n');

    const result = await syncExample({ project_dir: project });

    expect(result).not.toHaveProperty("error");
  });

  it("redacts a comment when a duplicate key was echoed under another value", async () => {
    const project = tempProject();
    // PORT=8080 is echoed verbatim (SAFE_NUMERIC_KEYS), but parse() keeps the
    // last PORT — so keying suppression on the echoed occurrence dropped the
    // live value from comment sanitization entirely.
    writeFileSync(
      join(project, ".env"),
      "PORT=8080\nPORT=super_secret_value_here\n" +
        "# see PORT=super_secret_value_here for the override\n"
    );

    await syncExample({ project_dir: project });
    const out = readFileSync(join(project, ".env.example"), "utf-8");

    expect(out).not.toContain("super_secret_value_here");
  });

  it("keeps a punctuated shared default such as a timezone", async () => {
    const project = tempProject();
    writeFileSync(join(project, ".env"), "TZ=America/New_York\n");
    writeFileSync(join(project, ".env.example"), "TZ=America/New_York\n");

    await syncExample({ project_dir: project });

    expect(readFileSync(join(project, ".env.example"), "utf-8")).toContain(
      "TZ=America/New_York"
    );
  });

  it("sanitizes a live secret used as a commented-out key", async () => {
    const project = tempProject();
    writeFileSync(
      join(project, ".env"),
      "TOKEN=SOME_SECRET_VALUE_HERE\n# SOME_SECRET_VALUE_HERE=x\n"
    );

    await syncExample({ project_dir: project });
    const out = readFileSync(join(project, ".env.example"), "utf-8");

    expect(out).not.toContain("# SOME_SECRET_VALUE_HERE=");
  });

  it("keeps a quoted port rather than blanking it", async () => {
    const project = tempProject();
    writeFileSync(join(project, ".env"), 'PORT="3000"\n');

    await syncExample({ project_dir: project });

    expect(readFileSync(join(project, ".env.example"), "utf-8")).toContain("3000");
  });

  it("redacts a non-brand credential parked in a comment", async () => {
    const project = tempProject();
    // scanForSecrets only knows well-known prefixes; this one has no brand.
    writeFileSync(
      join(project, ".env"),
      "# DB_PASSWORD=hunter2-prod-9f3a\nAPP_ENV=production\n"
    );

    await syncExample({ project_dir: project });
    const out = readFileSync(join(project, ".env.example"), "utf-8");

    expect(out).not.toContain("hunter2-prod-9f3a");
  });

  it("treats an apostrophe as closing a single-quoted value, as dotenv does", async () => {
    const project = tempProject();
    // dotenv's `'(?:\\'|[^'])*'` closes at the apostrophe, yielding `it`, and
    // keeps parsing the following lines as ordinary entries.
    writeFileSync(
      join(project, ".env"),
      "GREETING='it's a test\nAPI_HOST=example.com\nPORT=3000\n"
    );

    const result = await syncExample({ project_dir: project });

    expect(result).toMatchObject({ keys_synced: 3 });
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

  it("regenerates a stored webhook URL identical to the live value", async () => {
    const project = tempProject();
    // SLACK_WEBHOOK clears SECRET_KEY_TOKENS, the scanner and the userinfo /
    // query-param checks — the secret is in the path.
    const url = "https://hooks.slack.com/services/T00000/B00000/XXXXXXXXXXXX";
    writeFileSync(join(project, ".env"), `SLACK_WEBHOOK=${url}\n`);
    writeFileSync(join(project, ".env.example"), `SLACK_WEBHOOK=${url}\n`);

    await syncExample({ project_dir: project });
    const out = readFileSync(join(project, ".env.example"), "utf-8");

    expect(out).not.toContain(url);
    expect(out).toContain("SLACK_WEBHOOK=https://example.com");
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

describe("detectSpanDisagreement", () => {
  const span = (over: Partial<Parameters<typeof detectSpanDisagreement>[0][0]> = {}) => ({
    key: "BLOB",
    exportPrefix: "",
    value: '"opening',
    startLine: 0,
    endLine: 0,
    ...over,
  });

  it("refuses when a value dotenv spans across lines was scanned as one", () => {
    // The direction that leaks: continuation lines fall outside `consumed`,
    // reach the comment path, and sanitize cannot match a value fragment.
    const result = detectSpanDisagreement(
      [span()],
      { BLOB: "line1\n# DB_PASSWORD=hunter2\nline3" },
      new Set(["BLOB"])
    );
    expect(result).toMatch(/spans lines per dotenv/);
  });

  it("allows a single-line value whose \\n escape expands to a newline", () => {
    expect(
      detectSpanDisagreement(
        [span({ value: '"a\\nb"' })],
        { BLOB: "a\nb" },
        new Set(["BLOB"])
      )
    ).toBeNull();
  });

  it("refuses when a span closes one line early, not just wholly early", () => {
    // The partial under-span: the scan claims two lines, dotenv's value has
    // three newlines. The uncovered line reaches the comment path.
    expect(
      detectSpanDisagreement(
        [span({ startLine: 0, endLine: 1, value: '"a' })],
        { BLOB: "a\nb\n# c\nd" },
        new Set(["BLOB"])
      )
    ).toMatch(/spans lines per dotenv/);
  });

  it("refuses when a parsed key was never emitted", () => {
    expect(
      detectSpanDisagreement([span()], { BLOB: "v", PORT: "3000" }, new Set(["BLOB"]))
    ).toMatch(/were not emitted \(PORT\)/);
  });

  it("passes when the scan and the parser agree", () => {
    expect(
      detectSpanDisagreement([span({ value: "v" })], { BLOB: "v" }, new Set(["BLOB"]))
    ).toBeNull();
  });
});
