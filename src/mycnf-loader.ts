import { readFileSync, statSync, readdirSync, realpathSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join, resolve, sep } from "node:path";
import { parse } from "ini";

/** Fields whose values are considered secrets and fed to the sanitizer. */
const SECRET_FIELDS = new Set(["user", "password", "host"]);

export interface MyCnfResult {
  /** Map of section name to field map, e.g. { client: { user: "root", ... } } */
  sections: Record<string, Record<string, string>>;
  /** Flat record of secret values keyed as "section.field" */
  secrets: Record<string, string>;
}

interface CacheEntry {
  mtimes: Record<string, number>;
  contentHashes: Record<string, string>;
  result: MyCnfResult;
}

const cache = new Map<string, CacheEntry>();

/**
 * Read a file's content, returning null if it doesn't exist.
 * Reads first, then stats — same TOCTOU-prevention pattern as env-loader.
 */
function readFile(path: string): { content: string; mtime: number } | null {
  let content: string;
  try {
    content = readFileSync(path, "utf-8");
  } catch {
    return null;
  }

  let mtime: number;
  try {
    mtime = statSync(path).mtimeMs;
  } catch {
    // File deleted between read and stat — treat content as mtime 0
    return { content, mtime: 0 };
  }

  return { content, mtime };
}

/** True if `target` resolves to `root` or a path nested under it. */
function isWithin(root: string, target: string): boolean {
  const r = resolve(root);
  const t = resolve(target);
  return t === r || t.startsWith(r + sep);
}

/**
 * Canonical (symlink-resolved) path, or null if it can't be resolved (ENOENT).
 * Used for containment checks: a lexical `resolve()` does not follow symlinks,
 * so an in-project symlink could otherwise point at an out-of-bounds file.
 */
function tryRealpath(path: string): string | null {
  try {
    return realpathSync(path);
  } catch {
    return null;
  }
}

/**
 * Parse a single .my.cnf file, following !include / !includedir directives.
 * `visited` tracks resolved paths for cycle detection.
 *
 * `containTo`, when set, restricts !include / !includedir targets to paths
 * within that directory. This is applied to the project-local chain, whose
 * .my.cnf may be attacker-supplied (e.g. committed to a repo), to stop a
 * crafted include from pulling in arbitrary files elsewhere on disk —
 * read_mycnf returns non-secret fields verbatim, so an unbounded include
 * would be a file-disclosure primitive. The trusted global (~/.my.cnf) chain
 * is parsed with no containment so legitimate /etc includes still work.
 */
function parseFile(
  filePath: string,
  visited: Set<string>,
  containTo?: string
): {
  sections: Record<string, Record<string, string>>;
  files: Map<string, { mtime: number; contentHash: string }>;
} {
  const resolved = resolve(filePath);
  const sections: Record<string, Record<string, string>> = {};
  const files = new Map<string, { mtime: number; contentHash: string }>();

  if (visited.has(resolved)) {
    return { sections, files };
  }
  visited.add(resolved);

  // Containment for the untrusted project-local chain: the *real* (symlink-
  // resolved) path of every file we actually read must stay within `containTo`.
  // Enforcing here — at the read point — covers !include targets, !includedir
  // entries, and a symlinked .my.cnf alike. A purely lexical check on the
  // directive target would let an in-project symlink escape the project.
  if (containTo) {
    const real = tryRealpath(resolved);
    if (!real || !isWithin(containTo, real)) {
      return { sections, files };
    }
  }

  const fileData = readFile(resolved);
  if (!fileData) {
    return { sections, files };
  }

  const { content, mtime } = fileData;
  const contentHash = createHash("sha256").update(content).digest("hex");
  files.set(resolved, { mtime, contentHash });

  // Extract !include and !includedir lines before INI parsing
  // (ini package doesn't understand them)
  const lines = content.split("\n");
  const iniLines: string[] = [];

  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith("!include ")) {
      const baseDir = dirname(resolved);
      const target = resolve(baseDir, trimmed.slice("!include ".length).trim());
      // Containment is enforced authoritatively at parseFile's read point
      // (canonical-path check), which also catches symlinked targets.
      const sub = parseFile(target, visited, containTo);
      mergeSections(sections, sub.sections);
      for (const [k, v] of sub.files) files.set(k, v);
    } else if (trimmed.startsWith("!includedir ")) {
      const baseDir = dirname(resolved);
      const dir = resolve(baseDir, trimmed.slice("!includedir ".length).trim());
      // Skip listing a directory whose real path is out of bounds; each entry
      // is still re-checked by canonical path when parseFile reads it.
      if (containTo) {
        const realDir = tryRealpath(dir);
        if (!realDir || !isWithin(containTo, realDir)) continue;
      }
      let entries: string[];
      try {
        entries = readdirSync(dir).filter((f) => f.endsWith(".cnf")).sort();
      } catch {
        entries = [];
      }
      for (const entry of entries) {
        const sub = parseFile(join(dir, entry), visited, containTo);
        mergeSections(sections, sub.sections);
        for (const [k, v] of sub.files) files.set(k, v);
      }
    } else {
      iniLines.push(line);
    }
  }

  const parsed = parse(iniLines.join("\n"));
  // ini.parse returns top-level keys as strings and sections as objects
  for (const [section, value] of Object.entries(parsed)) {
    if (typeof value === "object" && value !== null) {
      if (!sections[section]) sections[section] = {};
      for (const [k, v] of Object.entries(value as Record<string, string>)) {
        sections[section][k] = String(v);
      }
    }
  }

  return { sections, files };
}

/** Merge `from` sections into `into`, with `from` values winning per-field. */
function mergeSections(
  into: Record<string, Record<string, string>>,
  from: Record<string, Record<string, string>>
): void {
  for (const [section, fields] of Object.entries(from)) {
    if (!into[section]) into[section] = {};
    Object.assign(into[section], fields);
  }
}

/** Extract secret fields from parsed sections. */
function extractSecrets(
  sections: Record<string, Record<string, string>>
): Record<string, string> {
  const secrets: Record<string, string> = {};
  for (const [section, fields] of Object.entries(sections)) {
    for (const [field, value] of Object.entries(fields)) {
      if (SECRET_FIELDS.has(field)) {
        secrets[`${section}.${field}`] = value;
      }
    }
  }
  return secrets;
}

/**
 * Load and merge MySQL .my.cnf files.
 *
 * Resolution order (matching MySQL's own):
 *   1. `<homeDir>/.my.cnf` (global)
 *   2. `<projectDir>/.my.cnf` (project-local, overrides global per-field)
 *
 * Results are cached with mtime + SHA256 content hash.
 */
export function loadMyCnf(projectDir: string, homeDir: string): MyCnfResult {
  const cacheKey = `${resolve(projectDir)}::${resolve(homeDir)}`;

  // Parse both files to collect all involved files and their metadata
  const globalVisited = new Set<string>();
  const globalResult = parseFile(join(homeDir, ".my.cnf"), globalVisited);

  // Contain the project-local chain to the project directory: its .my.cnf may
  // be untrusted, so its includes must not reach outside the project. Contain
  // against the canonical project path so a symlinked project root (e.g. macOS
  // /tmp -> /private/tmp) doesn't reject legitimate in-project includes.
  const localVisited = new Set<string>();
  const localResult = parseFile(
    join(projectDir, ".my.cnf"),
    localVisited,
    tryRealpath(projectDir) ?? resolve(projectDir)
  );

  // Collect all file metadata for cache comparison
  const allFiles = new Map<string, { mtime: number; contentHash: string }>();
  for (const [k, v] of globalResult.files) allFiles.set(k, v);
  for (const [k, v] of localResult.files) allFiles.set(k, v);

  // Check cache
  const mtimes: Record<string, number> = {};
  const contentHashes: Record<string, string> = {};
  for (const [path, meta] of allFiles) {
    mtimes[path] = meta.mtime;
    contentHashes[path] = meta.contentHash;
  }

  const cached = cache.get(cacheKey);
  if (
    cached &&
    JSON.stringify(cached.mtimes) === JSON.stringify(mtimes) &&
    JSON.stringify(cached.contentHashes) === JSON.stringify(contentHashes)
  ) {
    return cached.result;
  }

  // Merge: global first, then local overrides
  const sections: Record<string, Record<string, string>> = {};
  mergeSections(sections, globalResult.sections);
  mergeSections(sections, localResult.sections);

  const secrets = extractSecrets(sections);
  const result: MyCnfResult = { sections, secrets };

  cache.set(cacheKey, { mtimes, contentHashes, result });
  return result;
}
