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

describe("validateUrl - private IPv4", () => {
  it("blocks 127.0.0.1 (loopback)", async () => {
    expect((await validateUrl("http://127.0.0.1")).allowed).toBe(false);
  });

  it("blocks 127.255.255.255 (loopback range)", async () => {
    expect((await validateUrl("http://127.255.255.255")).allowed).toBe(false);
  });

  it("blocks 10.0.0.1 (private)", async () => {
    expect((await validateUrl("http://10.0.0.1")).allowed).toBe(false);
  });

  it("blocks 172.16.0.1 (private)", async () => {
    expect((await validateUrl("http://172.16.0.1")).allowed).toBe(false);
  });

  it("blocks 172.31.255.255 (private upper bound)", async () => {
    expect((await validateUrl("http://172.31.255.255")).allowed).toBe(false);
  });

  it("blocks 192.168.1.1 (private)", async () => {
    expect((await validateUrl("http://192.168.1.1")).allowed).toBe(false);
  });

  it("blocks 169.254.169.254 (cloud metadata)", async () => {
    expect((await validateUrl("http://169.254.169.254")).allowed).toBe(false);
  });

  it("blocks 0.0.0.1 (current network)", async () => {
    expect((await validateUrl("http://0.0.0.1")).allowed).toBe(false);
  });

  it("blocks 0.0.0.0 (current network)", async () => {
    expect((await validateUrl("http://0.0.0.0")).allowed).toBe(false);
  });
});

describe("validateUrl - IPv6 loopback and private ranges", () => {
  it("blocks ::1 loopback", async () => {
    expect((await validateUrl("http://[::1]")).allowed).toBe(false);
  });

  it("blocks fe80:: link-local", async () => {
    expect((await validateUrl("http://[fe80::1]")).allowed).toBe(false);
  });

  it("blocks fe90:: link-local (fe80::/10 range)", async () => {
    expect((await validateUrl("http://[fe90::1]")).allowed).toBe(false);
  });

  it("blocks fea0:: link-local (fe80::/10 range)", async () => {
    expect((await validateUrl("http://[fea0::1]")).allowed).toBe(false);
  });

  it("blocks feb0:: link-local (fe80::/10 range)", async () => {
    expect((await validateUrl("http://[feb0::1]")).allowed).toBe(false);
  });

  it("blocks fc00:: unique local", async () => {
    expect((await validateUrl("http://[fc00::1]")).allowed).toBe(false);
  });

  it("blocks fd00:: unique local", async () => {
    expect((await validateUrl("http://[fd00::1]")).allowed).toBe(false);
  });

  it("blocks ::ffff:127.0.0.1 IPv4-mapped loopback", async () => {
    expect((await validateUrl("http://[::ffff:127.0.0.1]")).allowed).toBe(
      false
    );
  });

  it("blocks ::ffff:192.168.1.1 IPv4-mapped private", async () => {
    expect((await validateUrl("http://[::ffff:192.168.1.1]")).allowed).toBe(
      false
    );
  });
});

describe("validateUrl - IPv6 translation and tunnel addresses", () => {
  it("blocks 64:ff9b:: NAT64 prefix (maps to private IPv4)", async () => {
    expect((await validateUrl("http://[64:ff9b::a00:1]")).allowed).toBe(false);
  });

  it("blocks 100:: discard prefix", async () => {
    expect((await validateUrl("http://[100::1]")).allowed).toBe(false);
  });

  it("blocks 2002:7f00:1:: (6to4 encoding of 127.0.0.1)", async () => {
    expect((await validateUrl("http://[2002:7f00:1::]")).allowed).toBe(false);
  });

  it("blocks 2002:c0a8:101:: (6to4 encoding of 192.168.1.1)", async () => {
    expect((await validateUrl("http://[2002:c0a8:101::]")).allowed).toBe(false);
  });

  it("blocks 2002:a00:1:: (6to4 encoding of 10.0.0.1)", async () => {
    expect((await validateUrl("http://[2002:a00:1::]")).allowed).toBe(false);
  });

  it("allows 2002:808:808:: (6to4 encoding of public 8.8.8.8)", async () => {
    expect((await validateUrl("http://[2002:808:808::]")).allowed).toBe(true);
  });

  it("blocks 2001:0000:: Teredo prefix", async () => {
    expect((await validateUrl("http://[2001:0000::1]")).allowed).toBe(false);
  });

  it("blocks 2001:: Teredo abbreviated", async () => {
    expect((await validateUrl("http://[2001::1]")).allowed).toBe(false);
  });

  it("blocks 2001:db8:: documentation prefix", async () => {
    expect((await validateUrl("http://[2001:db8::1]")).allowed).toBe(false);
  });
});

describe("validateUrl - scheme blocking", () => {
  it("blocks file://", async () => {
    expect((await validateUrl("file:///etc/passwd")).allowed).toBe(false);
  });

  it("blocks ftp://", async () => {
    expect((await validateUrl("ftp://example.com")).allowed).toBe(false);
  });

  it("blocks gopher://", async () => {
    expect((await validateUrl("gopher://example.com")).allowed).toBe(false);
  });

  it("blocks data:", async () => {
    expect((await validateUrl("data:text/html,<h1>hi</h1>")).allowed).toBe(
      false
    );
  });

  it("blocks javascript: (non-http)", async () => {
    expect((await validateUrl("javascript://x")).allowed).toBe(false);
  });
});

describe("validateUrl - invalid URLs", () => {
  it("blocks non-URL strings", async () => {
    const result = await validateUrl("not-a-url");
    expect(result.allowed).toBe(false);
    expect(result.reason).toMatch(/Invalid URL/i);
  });
});

describe("validateUrl - DNS resolution", () => {
  it("allows hostname resolving to public IP", async () => {
    const result = await validateUrl("https://example.com");
    expect(result.allowed).toBe(true);
    expect(result.resolvedIp).toBe("93.184.216.34");
    expect(result.hostname).toBe("example.com");
  });

  it("blocks hostname resolving to private IP (DNS rebinding)", async () => {
    mockLookup.mockResolvedValue({ address: "192.168.1.1", family: 4 });
    const result = await validateUrl("https://evil.example.com");
    expect(result.allowed).toBe(false);
    expect(result.reason).toMatch(/private IP/i);
  });

  it("blocks hostname when DNS resolution fails", async () => {
    mockLookup.mockRejectedValue(new Error("ENOTFOUND"));
    const result = await validateUrl("https://nonexistent.invalid");
    expect(result.allowed).toBe(false);
    expect(result.reason).toMatch(/DNS resolution failed/i);
  });
});
