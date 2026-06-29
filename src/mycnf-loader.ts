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
  /** Directories referenced by `!includedir`, re-listed on the fast path to detect added files */
  includeDirs: string[];
  /** Referenced paths (roots / !include targets) that were absent — watched for appearance */
  missingPaths: string[];
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
  missing: Set<string>;
} {
  const resolved = resolve(filePath);
  const sections: Record<string, Record<string, string>> = {};
  const files = new Map<string, { mtime: number; contentHash: string }>();
  const dirs = new Set<string>();
  // Paths that were referenced (roots / !include targets) but did not exist.
  // Tracked so the cache fast path can detect one appearing later.
  const missing = new Set<string>();

  if (visited.has(resolved)) {
    return { sections, files, dirs, missing };
  }
  visited.add(resolved);

  const fileData = readFile(resolved);
  if (!fileData) {
    missing.add(resolved);
    return { sections, files, dirs, missing };
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
      for (const m of sub.missing) missing.add(m);
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
        for (const m of sub.missing) missing.add(m);
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

  return { sections, files, dirs, missing };
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

  // Fast path: serve the cache only when the on-disk state that determines the
  // secret set is provably unchanged. For a secrets server mtime alone is not
  // enough — a rotation can preserve mtime (NFS, backup-restore, `touch -m`) —
  // so we re-hash every known file's content. We also guard the two ways the
  // *set* of files can change while known files stay byte-identical:
  //   1. a referenced-but-absent path (a root or `!include` target) appearing
  //   2. a new `.cnf` dropped into an `!includedir`
  // (1) is checked via `missingPaths`; (2) by re-listing the includedirs, which
  // is robust even if the directory's own mtime was preserved.
  const cached = cache.get(cacheKey);
  if (cached) {
    const knownFiles = new Set(cached.filePaths);

    const appeared = cached.missingPaths.some((p) => tryMtime(p) !== 0);
    const mtimesMatch = cached.filePaths.every(
      (p) => tryMtime(p) === cached.mtimes[p]
    );
    const membershipUnchanged =
      !appeared &&
      cached.includeDirs.every((dir) => {
        let entries: string[];
        try {
          entries = readdirSync(dir).filter((f) => f.endsWith(".cnf"));
        } catch {
          entries = [];
        }
        return entries.every((e) => knownFiles.has(resolve(join(dir, e))));
      });

    if (mtimesMatch && membershipUnchanged) {
      // Verify every known file's content hash (catches same-mtime rotation in
      // roots and includes alike, and deletions via a now-missing read).
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

  // !includedir directories (re-listed on the fast path) and referenced-but-absent
  // paths (watched for appearance) — both needed to detect file-set changes.
  const includeDirs = [
    ...new Set([...globalResult.dirs, ...localResult.dirs]),
  ].sort();
  const missingPaths = [
    ...new Set([...globalResult.missing, ...localResult.missing]),
  ].sort();

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
      missingPaths,
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
    missingPaths,
    result,
  });
  return result;
}
