import { z } from "zod";
import { isAbsolute } from "node:path";
import { homedir } from "node:os";
import { loadMyCnf } from "../mycnf-loader.js";
import { validateProjectDir } from "../security/path-validator.js";
import { auditLog } from "../security/audit.js";

const SECRET_FIELDS = new Set(["user", "password", "host"]);

export const ReadMyCnfSchema = z.object({
  project_dir: z
    .string()
    .refine((p) => isAbsolute(p), "project_dir must be an absolute path")
    .describe("Absolute path to the project directory"),
  section: z
    .string()
    .optional()
    .describe("Filter to a specific section (e.g. 'client', 'mysqldump')"),
});

export async function readMyCnf(
  args: z.infer<typeof ReadMyCnfSchema>
): Promise<{ sections: Record<string, Record<string, string>> } | { error: string }> {
  const pathCheck = validateProjectDir(args.project_dir);
  if (!pathCheck.valid) {
    auditLog("read_mycnf", { status: "blocked" });
    return { error: pathCheck.reason! };
  }

  const { sections } = loadMyCnf(args.project_dir, homedir());

  // Build redacted view
  const redacted: Record<string, Record<string, string>> = {};
  let keysAccessedCount = 0;

  for (const [sectionName, fields] of Object.entries(sections)) {
    if (args.section && sectionName !== args.section) continue;
    redacted[sectionName] = {};
    for (const [field, value] of Object.entries(fields)) {
      if (SECRET_FIELDS.has(field)) {
        redacted[sectionName][field] = `[REDACTED:${sectionName}.${field}]`;
        keysAccessedCount++;
      } else {
        redacted[sectionName][field] = value;
      }
    }
  }

  auditLog("read_mycnf", { keysAccessedCount, status: "success" });
  return { sections: redacted };
}
