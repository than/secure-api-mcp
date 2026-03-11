import { describe, it, expect } from "vitest";
import { sanitize } from "./sanitize.js";

describe("sanitize", () => {
  describe("verbatim secret redaction", () => {
    it("replaces secret value with [REDACTED:KEY_NAME]", () => {
      const result = sanitize("token is sk-abc123xyz", {
        API_KEY: "sk-abc123xyz",
      });
      expect(result).toBe("token is [REDACTED:API_KEY]");
    });

    it("uses distinct key names for different secrets", () => {
      const result = sanitize("a=secret1 b=secret2", {
        KEY_A: "secret1",
        KEY_B: "secret2",
      });
      expect(result).toContain("[REDACTED:KEY_A]");
      expect(result).toContain("[REDACTED:KEY_B]");
    });

    it("uses key name in tag, not numeric index", () => {
      const result = sanitize("token is sk-abc123xyz", {
        API_KEY: "sk-abc123xyz",
      });
      expect(result).not.toMatch(/\[REDACTED:\d+\]/);
    });
  });

  describe("base64-encoded secrets", () => {
    it("redacts base64-encoded form of a secret", () => {
      const secret = "mysecretvalue";
      const b64 = Buffer.from(secret).toString("base64");
      const result = sanitize(`encoded: ${b64}`, { MY_SECRET: secret });
      expect(result).toBe("encoded: [REDACTED:MY_SECRET]");
    });
  });

  describe("URL-encoded secrets", () => {
    it("redacts URL-encoded form of a secret", () => {
      const secret = "hello world&foo=bar";
      const result = sanitize(`q=${encodeURIComponent(secret)}`, {
        MY_KEY: secret,
      });
      expect(result).toBe("q=[REDACTED:MY_KEY]");
    });
  });

  describe("short values", () => {
    it("does NOT redact values with 3 or fewer characters", () => {
      const result = sanitize("port is 443", { PORT: "443" });
      expect(result).toBe("port is 443");
    });

    it("does NOT redact single-char values", () => {
      const result = sanitize("flag is Y", { FLAG: "Y" });
      expect(result).toBe("flag is Y");
    });

    it("redacts values with 4+ characters", () => {
      const result = sanitize("host is abcd", { HOST: "abcd" });
      expect(result).toBe("host is [REDACTED:HOST]");
    });
  });

  describe("ordering - longer secrets first", () => {
    it("replaces longer value before shorter to avoid partial-match corruption", () => {
      const result = sanitize("value is supersecretkey", {
        SHORT: "secret",
        LONG: "supersecretkey",
      });
      expect(result).toBe("value is [REDACTED:LONG]");
      // Should NOT produce "super[REDACTED:SHORT]key"
      expect(result).not.toContain("[REDACTED:SHORT]");
    });

    it("handles overlapping secrets correctly", () => {
      const result = sanitize("abc: mysecret and mysecretvalue here", {
        SMALL: "mysecret",
        LARGE: "mysecretvalue",
      });
      expect(result).toBe(
        "abc: [REDACTED:SMALL] and [REDACTED:LARGE] here"
      );
    });
  });

  describe("no-op cases", () => {
    it("returns output unchanged when secret is not present", () => {
      const result = sanitize("nothing here", { KEY: "missing" });
      expect(result).toBe("nothing here");
    });

    it("returns output unchanged with empty env", () => {
      const result = sanitize("some output", {});
      expect(result).toBe("some output");
    });

    it("returns empty string for empty input", () => {
      const result = sanitize("", { KEY: "secret" });
      expect(result).toBe("");
    });
  });

  describe("multiple occurrences", () => {
    it("replaces all occurrences of the same secret", () => {
      const result = sanitize("key=abcdef and also abcdef again", {
        TOKEN: "abcdef",
      });
      expect(result).toBe(
        "key=[REDACTED:TOKEN] and also [REDACTED:TOKEN] again"
      );
    });
  });

  describe("scanForSecrets integration", () => {
    it("also catches pattern-based secrets not in env", () => {
      const result = sanitize("key: AKIA1234567890ABCDEF", {});
      expect(result).toBe("key: [REDACTED:detected]");
    });
  });
});
