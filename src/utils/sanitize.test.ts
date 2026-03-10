import { describe, it, expect } from "vitest";
import { sanitize } from "./sanitize.js";

describe("sanitize - redaction tag format", () => {
  it("uses key name in redaction tag, not numeric index", () => {
    const result = sanitize("token is sk-abc123xyz", { API_KEY: "sk-abc123xyz" });
    expect(result).toBe("token is [REDACTED:API_KEY]");
    expect(result).not.toMatch(/\[REDACTED:\d+\]/);
  });

  it("uses distinct key names for different secrets", () => {
    const result = sanitize("a=secret1 b=secret2", {
      KEY_A: "secret1",
      KEY_B: "secret2",
    });
    expect(result).toContain("[REDACTED:KEY_A]");
    expect(result).toContain("[REDACTED:KEY_B]");
    expect(result).not.toMatch(/\[REDACTED:\d+\]/);
  });

  it("redacts base64-encoded secret with key name tag", () => {
    const secret = "mysecretvalue";
    const b64 = Buffer.from(secret).toString("base64");
    const result = sanitize(`encoded: ${b64}`, { MY_SECRET: secret });
    expect(result).toBe("encoded: [REDACTED:MY_SECRET]");
  });

  it("redacts url-encoded secret with key name tag", () => {
    const secret = "hello world";
    const result = sanitize(`q=${encodeURIComponent(secret)}`, { MY_KEY: secret });
    expect(result).toBe("q=[REDACTED:MY_KEY]");
  });
});
