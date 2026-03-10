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
 * Input must be a bare address without brackets.
 */
function isPrivateIp(ip: string): boolean {
  // IPv6 loopback
  if (ip === "::1") return true;
  // IPv6 link-local (fe80::/10 — covers fe80:: through febf::)
  if (/^fe[89ab][0-9a-f]:/i.test(ip)) return true;
  // IPv6 unique local (fc00::/7 — covers fc:: and fd::)
  if (/^f[cd]/i.test(ip)) return true;
  // IPv6 NAT64 translation prefix (64:ff9b::/96 — maps to IPv4 space)
  if (/^64:ff9b:/i.test(ip)) return true;
  // IPv6 discard prefix (100::/64)
  if (/^0*100:/i.test(ip)) return true;
  // IPv4-mapped IPv6 — dotted-decimal form: ::ffff:x.x.x.x
  const v4mapped = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  if (v4mapped) {
    const parsed = parseIpv4(v4mapped[1]);
    if (parsed !== null) return isPrivateIpv4(parsed);
  }
  // IPv4-mapped IPv6 — hex form after URL normalization: ::ffff:xxxx:xxxx
  // e.g. URL parser converts ::ffff:127.0.0.1 → ::ffff:7f00:1
  const v4mappedHex = ip.match(/^::ffff:([0-9a-f]+):([0-9a-f]+)$/i);
  if (v4mappedHex) {
    const high = parseInt(v4mappedHex[1], 16);
    const low = parseInt(v4mappedHex[2], 16);
    const ipNum = (((high << 16) | low) >>> 0);
    return isPrivateIpv4(ipNum);
  }
  // Plain IPv4
  const parsed = parseIpv4(ip);
  if (parsed !== null) return isPrivateIpv4(parsed);

  return false;
}

/**
 * Strip IPv6 brackets from a URL hostname.
 * URL.hostname returns "[::1]" for IPv6 literals — we need "::1" for isPrivateIp.
 */
function stripBrackets(hostname: string): string {
  if (hostname.startsWith("[") && hostname.endsWith("]")) {
    return hostname.slice(1, -1);
  }
  return hostname;
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
  // URL.hostname includes brackets for IPv6 literals (e.g., "[::1]") —
  // strip them before IP checks and DNS lookup.
  const bareHostname = stripBrackets(hostname);

  // Check if hostname is already a literal IP
  if (isPrivateIp(bareHostname)) {
    return {
      allowed: false,
      reason: "Blocked: request to private/internal IP address",
    };
  }

  // Resolve hostname and check the resolved IP
  try {
    const { address } = await lookup(bareHostname);
    if (isPrivateIp(address)) {
      return {
        allowed: false,
        reason: `Blocked: ${hostname} resolves to private IP ${address}`,
      };
    }
    return { allowed: true, resolvedIp: address, hostname: bareHostname };
  } catch {
    return {
      allowed: false,
      reason: `DNS resolution failed for ${hostname}`,
    };
  }
}
