import { describe, it, expect, vi, beforeEach } from "vitest";
import * as dns from "node:dns/promises";

// Mock dns.lookup so tests don't make real network calls
vi.mock("node:dns/promises");
const mockLookup = vi.mocked(dns.lookup);

// Default: any hostname resolves to a public IP
beforeEach(() => {
  mockLookup.mockResolvedValue({ address: "93.184.216.34", family: 4 });
});

// Import after mocking
const { validateUrl } = await import("./url-validator.js");

describe("validateUrl - IPv6 private ranges (missing coverage)", () => {
  it("blocks 64:ff9b:: IPv4/IPv6 translation prefix (maps to private IPv4)", async () => {
    // 64:ff9b::10.0.0.1 translates to 10.0.0.1 — a private address
    const result = await validateUrl("http://[64:ff9b::a00:1]");
    expect(result.allowed).toBe(false);
  });

  it("blocks 100:: IPv6 discard prefix", async () => {
    const result = await validateUrl("http://[100::1]");
    expect(result.allowed).toBe(false);
  });
});

describe("validateUrl - existing IPv6 coverage (regression)", () => {
  it("blocks ::1 loopback", async () => {
    const result = await validateUrl("http://[::1]");
    expect(result.allowed).toBe(false);
  });

  it("blocks fe80:: link-local", async () => {
    const result = await validateUrl("http://[fe80::1]");
    expect(result.allowed).toBe(false);
  });

  it("blocks fc00:: unique local", async () => {
    const result = await validateUrl("http://[fc00::1]");
    expect(result.allowed).toBe(false);
  });

  it("blocks fd00:: unique local", async () => {
    const result = await validateUrl("http://[fd00::1]");
    expect(result.allowed).toBe(false);
  });

  it("blocks ::ffff:127.0.0.1 IPv4-mapped loopback", async () => {
    const result = await validateUrl("http://[::ffff:127.0.0.1]");
    expect(result.allowed).toBe(false);
  });

  it("blocks ::ffff:192.168.1.1 IPv4-mapped private", async () => {
    const result = await validateUrl("http://[::ffff:192.168.1.1]");
    expect(result.allowed).toBe(false);
  });
});

describe("validateUrl - private IPv4 (regression)", () => {
  it("blocks 127.0.0.1", async () => {
    expect((await validateUrl("http://127.0.0.1")).allowed).toBe(false);
  });

  it("blocks 10.0.0.1", async () => {
    expect((await validateUrl("http://10.0.0.1")).allowed).toBe(false);
  });

  it("blocks 172.16.0.1", async () => {
    expect((await validateUrl("http://172.16.0.1")).allowed).toBe(false);
  });

  it("blocks 172.31.255.255", async () => {
    expect((await validateUrl("http://172.31.255.255")).allowed).toBe(false);
  });

  it("blocks 192.168.1.1", async () => {
    expect((await validateUrl("http://192.168.1.1")).allowed).toBe(false);
  });

  it("blocks 169.254.169.254 (cloud metadata)", async () => {
    expect((await validateUrl("http://169.254.169.254")).allowed).toBe(false);
  });
});

describe("validateUrl - scheme blocking (regression)", () => {
  it("blocks file://", async () => {
    expect((await validateUrl("file:///etc/passwd")).allowed).toBe(false);
  });

  it("blocks ftp://", async () => {
    expect((await validateUrl("ftp://example.com")).allowed).toBe(false);
  });

  it("blocks javascript: (non-http)", async () => {
    expect((await validateUrl("javascript://x")).allowed).toBe(false);
  });
});

describe("validateUrl - allowed", () => {
  it("allows a public hostname that resolves to a public IP", async () => {
    const result = await validateUrl("https://example.com");
    expect(result.allowed).toBe(true);
    expect(result.resolvedIp).toBe("93.184.216.34");
    expect(result.hostname).toBe("example.com");
  });

  it("blocks a hostname that resolves to a private IP (DNS rebinding)", async () => {
    mockLookup.mockResolvedValue({ address: "192.168.1.1", family: 4 });
    const result = await validateUrl("https://evil.example.com");
    expect(result.allowed).toBe(false);
  });
});
