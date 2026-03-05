import { appendFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { homedir } from "node:os";

interface AuditEntry {
  timestamp: string;
  tool: string;
  keysAccessedCount: number;
  commandHash?: string;
  status: "success" | "error" | "blocked";
}

function getLogPath(): string {
  return (
    process.env.SECURE_API_AUDIT_LOG ??
    join(homedir(), ".secure-api-mcp", "audit.log")
  );
}

function hashCommand(command: string): string {
  return createHash("sha256").update(command).digest("hex").slice(0, 16);
}

export function auditLog(
  tool: string,
  opts: {
    keysAccessedCount?: number;
    command?: string;
    status: "success" | "error" | "blocked";
  }
): void {
  const logPath = getLogPath();
  const dir = join(logPath, "..");

  try {
    mkdirSync(dir, { recursive: true });
  } catch {
    // Directory may already exist
  }

  const entry: AuditEntry = {
    timestamp: new Date().toISOString(),
    tool,
    keysAccessedCount: opts.keysAccessedCount ?? 0,
    ...(opts.command ? { commandHash: hashCommand(opts.command) } : {}),
    status: opts.status,
  };

  try {
    appendFileSync(logPath, JSON.stringify(entry) + "\n");
  } catch {
    // Audit logging should never crash the server
  }
}
