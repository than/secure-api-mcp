import { constants, lstatSync } from "node:fs";

/**
 * `O_NOFOLLOW` is POSIX-only, and `O_RDONLY | undefined` silently coerces to 0
 * — so on Windows the flag would vanish rather than fail loudly, and every
 * read-side symlink control would no-op without an error.
 */
export const O_NOFOLLOW = constants.O_NOFOLLOW ?? 0;

/**
 * Stand-in for `O_NOFOLLOW` where the platform lacks it. Throws `ELOOP` so
 * callers keep one code path. This reopens the TOCTOU window the flag closes;
 * a narrow window beats no control at all.
 */
export function refuseSymlink(path: string): void {
  if (O_NOFOLLOW !== 0) return;
  if (lstatSync(path, { throwIfNoEntry: false })?.isSymbolicLink()) {
    const err = new Error("ELOOP") as NodeJS.ErrnoException;
    err.code = "ELOOP";
    throw err;
  }
}
