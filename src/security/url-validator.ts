import { lookup } from "node:dns/promises";

const BLOCKED_IP_RANGES = [
  // Loopback
  /^127\./,
  /^::1$/,
  /^0\.0\.0\.0$/,
  // Private networks
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  // Link-local (cloud metadata)
  /^169\.254\./,
  // IPv6 private
  /^fe80:/i,
  /^fc00:/i,
  /^fd[0-9a-f]{2}:/i,
];

const BLOCKED_SCHEMES = ["file:", "ftp:", "gopher:", "data:"];

function isPrivateIp(ip: string): boolean {
  return BLOCKED_IP_RANGES.some((pattern) => pattern.test(ip));
}

export async function validateUrl(url: string): Promise<{
  allowed: boolean;
  reason?: string;
}> {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return { allowed: false, reason: "Invalid URL" };
  }

  // Block dangerous schemes
  if (BLOCKED_SCHEMES.includes(parsed.protocol)) {
    return {
      allowed: false,
      reason: `Blocked scheme: ${parsed.protocol}`,
    };
  }

  // Only allow http/https
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return {
      allowed: false,
      reason: `Only http and https schemes are allowed, got: ${parsed.protocol}`,
    };
  }

  // Check if hostname is already an IP
  const hostname = parsed.hostname;
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
  } catch {
    return {
      allowed: false,
      reason: `DNS resolution failed for ${hostname}`,
    };
  }

  return { allowed: true };
}
