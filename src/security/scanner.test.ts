import { describe, it, expect } from "vitest";
import { scanForSecrets } from "./scanner.js";

describe("scanForSecrets", () => {
  describe("AWS Access Key IDs", () => {
    it("redacts AKIA keys", () => {
      const result = scanForSecrets("key is AKIA1234567890ABCDEF");
      expect(result).toBe("key is [REDACTED:detected]");
    });
  });

  describe("GitHub tokens", () => {
    it("redacts ghp_ personal tokens", () => {
      const token = "ghp_" + "a".repeat(36);
      const result = scanForSecrets(`token: ${token}`);
      expect(result).toBe("token: [REDACTED:detected]");
    });

    it("redacts gho_ OAuth tokens", () => {
      const token = "gho_" + "B".repeat(36);
      const result = scanForSecrets(`token: ${token}`);
      expect(result).toBe("token: [REDACTED:detected]");
    });

    it("redacts ghu_ tokens", () => {
      const token = "ghu_" + "c".repeat(36);
      const result = scanForSecrets(`token: ${token}`);
      expect(result).toBe("token: [REDACTED:detected]");
    });

    it("redacts ghs_ tokens", () => {
      const token = "ghs_" + "D".repeat(36);
      const result = scanForSecrets(`token: ${token}`);
      expect(result).toBe("token: [REDACTED:detected]");
    });

    it("redacts ghr_ tokens", () => {
      const token = "ghr_" + "e".repeat(36);
      const result = scanForSecrets(`token: ${token}`);
      expect(result).toBe("token: [REDACTED:detected]");
    });

    it("redacts github_pat_ fine-grained tokens", () => {
      const token = "github_pat_" + "f".repeat(22);
      const result = scanForSecrets(`pat: ${token}`);
      expect(result).toBe("pat: [REDACTED:detected]");
    });
  });

  describe("Stripe keys", () => {
    it("redacts sk_live_ keys", () => {
      const key = "sk_live_" + "a".repeat(24);
      const result = scanForSecrets(`stripe: ${key}`);
      expect(result).toBe("stripe: [REDACTED:detected]");
    });

    it("redacts sk_test_ keys", () => {
      const key = "sk_test_" + "b".repeat(24);
      const result = scanForSecrets(`stripe: ${key}`);
      expect(result).toBe("stripe: [REDACTED:detected]");
    });

    it("redacts rk_live_ restricted keys", () => {
      const key = "rk_live_" + "c".repeat(24);
      const result = scanForSecrets(`stripe: ${key}`);
      expect(result).toBe("stripe: [REDACTED:detected]");
    });
  });

  describe("JWTs", () => {
    it("redacts JWT tokens", () => {
      const jwt =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
      const result = scanForSecrets(`auth: ${jwt}`);
      expect(result).toBe("auth: [REDACTED:detected]");
    });
  });

  describe("Slack tokens", () => {
    it("redacts xoxb- bot tokens", () => {
      const result = scanForSecrets("token: xoxb-abc-123-xyzxyzxyz");
      expect(result).toBe("token: [REDACTED:detected]");
    });

    it("redacts xoxp- user tokens", () => {
      const result = scanForSecrets("token: xoxp-abc-123-xyzxyzxyz");
      expect(result).toBe("token: [REDACTED:detected]");
    });

    it("redacts xoxa- app tokens", () => {
      const result = scanForSecrets("token: xoxa-abc-123-xyzxyzxyz");
      expect(result).toBe("token: [REDACTED:detected]");
    });
  });

  describe("Bearer tokens", () => {
    it("redacts Bearer token in Authorization header", () => {
      const bearer = "Bearer " + "a".repeat(30);
      const result = scanForSecrets(`Authorization: ${bearer}`);
      expect(result).toBe("Authorization: [REDACTED:detected]");
    });
  });

  describe("Private keys", () => {
    it("redacts RSA private key header", () => {
      const result = scanForSecrets("-----BEGIN RSA PRIVATE KEY-----");
      expect(result).toBe("[REDACTED:detected]");
    });

    it("redacts EC private key header", () => {
      const result = scanForSecrets("-----BEGIN EC PRIVATE KEY-----");
      expect(result).toBe("[REDACTED:detected]");
    });

    it("redacts DSA private key header", () => {
      const result = scanForSecrets("-----BEGIN DSA PRIVATE KEY-----");
      expect(result).toBe("[REDACTED:detected]");
    });

    it("redacts OPENSSH private key header", () => {
      const result = scanForSecrets("-----BEGIN OPENSSH PRIVATE KEY-----");
      expect(result).toBe("[REDACTED:detected]");
    });

    it("redacts generic private key header", () => {
      const result = scanForSecrets("-----BEGIN PRIVATE KEY-----");
      expect(result).toBe("[REDACTED:detected]");
    });
  });

  describe("false positives - should NOT redact", () => {
    it("leaves git commit SHA unchanged", () => {
      const sha = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
      expect(scanForSecrets(sha)).toBe(sha);
    });

    it("leaves short hex string unchanged", () => {
      expect(scanForSecrets("deadbeef")).toBe("deadbeef");
    });

    it("leaves normal prose text unchanged", () => {
      const text = "This is a normal sentence with no secrets.";
      expect(scanForSecrets(text)).toBe(text);
    });
  });

  describe("edge cases", () => {
    it("redacts multiple secrets in the same string", () => {
      const aws = "AKIA1234567890ABCDEF";
      const ghp = "ghp_" + "x".repeat(36);
      const result = scanForSecrets(`keys: ${aws} and ${ghp}`);
      expect(result).toBe("keys: [REDACTED:detected] and [REDACTED:detected]");
    });

    it("redacts secret mid-sentence without corrupting text", () => {
      const result = scanForSecrets(
        "Found key AKIA1234567890ABCDEF in the config"
      );
      expect(result).toBe("Found key [REDACTED:detected] in the config");
    });

    it("returns empty string for empty input", () => {
      expect(scanForSecrets("")).toBe("");
    });

    it("handles consecutive calls correctly (regex lastIndex reset)", () => {
      const text = "key: AKIA1234567890ABCDEF";
      const result1 = scanForSecrets(text);
      const result2 = scanForSecrets(text);
      expect(result1).toBe("key: [REDACTED:detected]");
      expect(result2).toBe("key: [REDACTED:detected]");
    });
  });
});
