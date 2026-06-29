import { readFileSync, statSync, readdirSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join, resolve } from "node:path";
import { parse } from "ini";

/** Fields whose values are considered secrets and fed to the sanitizer. */
export const SECRET_FIELDS = new Set(["user", "password", "host"]);

export interface MyCnfResult {
  /** Map of section name to field map, e.g. { client: { user: "root", ... } } */
  sections: Record<string, Record<string, string>>;
  /** Flat record of secret values keyed as "section.field" */
  secrets: Record<string, string>;
}

interface CacheEntry {
  /** All file paths involved (root files + includes) */
  filePaths: string[];
  mtimes: Record<string, number>;
  contentHashes: Record<string, string>;
  /** Directories referenced by `!includedir`, tracked to detect added/removed files */
  includeDirs: string[];
  dirMtimes: Record<string, number>;
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

/** Cheap mtime-only stat. Returns 0 if the path doesn't exist. */
function tryMtime(path: string): number {
  try {
    return statSync(path).mtimeMs;
  } catch {
    return 0;
  }
}

/**
 * Parse a single .my.cnf file, following !include / !includedir directives.
 * `visited` tracks resolved paths for cycle detection.
 */
function parseFile(
  filePath: string,
  visited: Set<string>
): {
  sections: Record<string, Record<string, string>>;
  files: Map<string, { mtime: number; contentHash: string }>;
  dirs: Set<string>;
} {
  const resolved = resolve(filePath);
  const sections: Record<string, Record<string, string>> = {};
  const files = new Map<string, { mtime: number; contentHash: string }>();
  const dirs = new Set<string>();

  if (visited.has(resolved)) {
    return { sections, files, dirs };
  }
  visited.add(resolved);

  const fileData = readFile(resolved);
  if (!fileData) {
    return { sections, files, dirs };
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
      const sub = parseFile(target, visited);
      mergeSections(sections, sub.sections);
      for (const [k, v] of sub.files) files.set(k, v);
      for (const d of sub.dirs) dirs.add(d);
    } else if (trimmed.startsWith("!includedir ")) {
      const baseDir = dirname(resolved);
      const dir = resolve(baseDir, trimmed.slice("!includedir ".length).trim());
      dirs.add(dir);
      let entries: string[];
      try {
        entries = readdirSync(dir).filter((f) => f.endsWith(".cnf")).sort();
      } catch {
        entries = [];
      }
      for (const entry of entries) {
        const sub = parseFile(join(dir, entry), visited);
        mergeSections(sections, sub.sections);
        for (const [k, v] of sub.files) files.set(k, v);
        for (const d of sub.dirs) dirs.add(d);
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

  return { sections, files, dirs };
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

  // Fast path: cheap stat check first, then re-hash every known file before
  // serving the cache. For a secrets server, mtime alone is not enough — a
  // rotation can preserve mtime (NFS, backup-restore, `touch -m`), so we
  // content-hash ALL files (roots + includes), not just the roots. We also
  // stat the tracked `!includedir` directories so a newly dropped .cnf
  // (which bumps the directory mtime) forces a full re-parse.
  const cached = cache.get(cacheKey);
  if (cached && cached.filePaths.length > 0) {
    const mtimesMatch =
      cached.filePaths.every((p) => tryMtime(p) === cached.mtimes[p]) &&
      cached.includeDirs.every((d) => tryMtime(d) === cached.dirMtimes[d]);

    if (mtimesMatch) {
      // Mtimes match — verify every file's content hash (catches same-mtime
      // rotation in roots and includes alike).
      let unchanged = true;
      for (const path of cached.filePaths) {
        const data = readFile(path);
        if (!data) {
          unchanged = false; // file was deleted
          break;
        }
        const hash = createHash("sha256").update(data.content).digest("hex");
        if (hash !== cached.contentHashes[path]) {
          unchanged = false;
          break;
        }
      }

      if (unchanged) {
        return cached.result;
      }
    }
  }

  // Cache miss or content changed — full read + parse
  const globalVisited = new Set<string>();
  const globalResult = parseFile(join(homeDir, ".my.cnf"), globalVisited);

  const localVisited = new Set<string>();
  const localResult = parseFile(join(projectDir, ".my.cnf"), localVisited);

  // Collect all file metadata
  const allFiles = new Map<string, { mtime: number; contentHash: string }>();
  for (const [k, v] of globalResult.files) allFiles.set(k, v);
  for (const [k, v] of localResult.files) allFiles.set(k, v);

  const filePaths = [...allFiles.keys()].sort();
  const mtimes: Record<string, number> = {};
  const contentHashes: Record<string, string> = {};
  for (const [path, meta] of allFiles) {
    mtimes[path] = meta.mtime;
    contentHashes[path] = meta.contentHash;
  }

  // Track !includedir directory mtimes so the fast path can spot added/removed files
  const includeDirs = [
    ...new Set([...globalResult.dirs, ...localResult.dirs]),
  ].sort();
  const dirMtimes: Record<string, number> = {};
  for (const d of includeDirs) dirMtimes[d] = tryMtime(d);

  // Check content hashes — handles mtime-identical but content-changed case
  if (
    cached &&
    filePaths.length === cached.filePaths.length &&
    filePaths.every((p, i) => p === cached.filePaths[i]) &&
    filePaths.every((p) => contentHashes[p] === cached.contentHashes[p])
  ) {
    // Content unchanged despite mtime change — update metadata and return cached
    cache.set(cacheKey, {
      filePaths,
      mtimes,
      contentHashes,
      includeDirs,
      dirMtimes,
      result: cached.result,
    });
    return cached.result;
  }

  // Merge: global first, then local overrides
  const sections: Record<string, Record<string, string>> = {};
  mergeSections(sections, globalResult.sections);
  mergeSections(sections, localResult.sections);

  const secrets = extractSecrets(sections);
  const result: MyCnfResult = { sections, secrets };

  cache.set(cacheKey, {
    filePaths,
    mtimes,
    contentHashes,
    includeDirs,
    dirMtimes,
    result,
  });
  return result;
}
