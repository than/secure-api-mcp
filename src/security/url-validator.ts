import { lookup } from "node:dns/promises";

const BLOCKED_SCHEMES = ["file:", "ftp:", "gopher:", "data:"];

/**
 * Parse an IPv4 address string into a 32-bit number.
 * Returns null if not a valid IPv4 address.
 */
function parseIpv4(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;

  let result = 0;
  for (const part of parts) {
    const n = Number(part);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    result = (result << 8) | n;
  }
  return result >>> 0; // unsigned
}

/**
 * Check if an IPv4 address (as 32-bit number) falls within private/reserved ranges.
 */
function isPrivateIpv4(ip: number): boolean {
  // 127.0.0.0/8 — loopback
  if ((ip >>> 24) === 127) return true;
  // 10.0.0.0/8 — private
  if ((ip >>> 24) === 10) return true;
  // 172.16.0.0/12 — private
  if ((ip >>> 20) === (172 << 4 | 1)) return true; // 0xAC1 = 172.16-31
  // 192.168.0.0/16 — private
  if ((ip >>> 16) === (192 << 8 | 168)) return true;
  // 169.254.0.0/16 — link-local (cloud metadata)
  if ((ip >>> 16) === (169 << 8 | 254)) return true;
  // 0.0.0.0/8 — current network
  if ((ip >>> 24) === 0) return true;
  return false;
}

/**
 * Check if an IP address string is private/reserved.
 * Handles IPv4, IPv6 loopback, and IPv6 private ranges.
 */
function isPrivateIp(ip: string): boolean {
  // IPv6 loopback
  if (ip === "::1") return true;
  // IPv6 link-local
  if (ip.toLowerCase().startsWith("fe80:")) return true;
  // IPv6 unique local (fc00::/7)
  if (/^f[cd]/i.test(ip)) return true;
  // IPv4-mapped IPv6 (::ffff:x.x.x.x)
  const v4mapped = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  if (v4mapped) {
    const parsed = parseIpv4(v4mapped[1]);
    if (parsed !== null) return isPrivateIpv4(parsed);
  }
  // Plain IPv4
  const parsed = parseIpv4(ip);
  if (parsed !== null) return isPrivateIpv4(parsed);

  return false;
}

export interface ValidatedUrl {
  allowed: boolean;
  reason?: string;
  /** The resolved IP address, available when allowed is true */
  resolvedIp?: string;
  /** The original hostname, available when allowed is true */
  hostname?: string;
}

export async function validateUrl(url: string): Promise<ValidatedUrl> {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return { allowed: false, reason: "Invalid URL" };
  }

  // Block dangerous schemes
  if (BLOCKED_SCHEMES.includes(parsed.protocol)) {
    return { allowed: false, reason: `Blocked scheme: ${parsed.protocol}` };
  }

  // Only allow http/https
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return {
      allowed: false,
      reason: `Only http and https schemes are allowed, got: ${parsed.protocol}`,
    };
  }

  const hostname = parsed.hostname;

  // Check if hostname is already a literal IP
  if (isPrivateIp(hostname)) {
    return {
      allowed: false,
      reason: "Blocked: request to private/internal IP address",
    };
  }

  // Resolve hostname and check the resolved IP
  try {
    const { address } = await lookup(hostname);
    if (isPrivateIp(address)) {
      return {
        allowed: false,
        reason: `Blocked: ${hostname} resolves to private IP ${address}`,
      };
    }
    return { allowed: true, resolvedIp: address, hostname };
  } catch {
    return {
      allowed: false,
      reason: `DNS resolution failed for ${hostname}`,
    };
  }
}
