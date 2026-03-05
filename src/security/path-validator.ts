import { isAbsolute } from "node:path";
import { existsSync } from "node:fs";
import { join } from "node:path";

const PROJECT_MARKERS = [
  ".git",
  "package.json",
  "Cargo.toml",
  "go.mod",
  "pyproject.toml",
  "Gemfile",
  "pom.xml",
  "build.gradle",
  "Makefile",
  "CMakeLists.txt",
  ".env",
  "composer.json",
  "requirements.txt",
  "setup.py",
];

export function validateProjectDir(dir: string): {
  valid: boolean;
  reason?: string;
} {
  if (!isAbsolute(dir)) {
    return {
      valid: false,
      reason: "project_dir must be an absolute path",
    };
  }

  const hasMarker = PROJECT_MARKERS.some((marker) =>
    existsSync(join(dir, marker))
  );

  if (!hasMarker) {
    return {
      valid: false,
      reason: `project_dir must contain a project marker file (${PROJECT_MARKERS.slice(0, 5).join(", ")}, ...)`,
    };
  }

  return { valid: true };
}
