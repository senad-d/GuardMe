import { randomUUID } from "node:crypto";
import { lstat, rename, rm, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

export async function writeTextAtomically(path: string, text: string, tempFilePrefix: string): Promise<void> {
  const directory = dirname(path);
  const tempPath = join(directory, `${tempFilePrefix}-${process.pid}-${Date.now()}-${randomUUID()}.tmp`);
  try {
    await writeFile(tempPath, text, { encoding: "utf8", flag: "wx", mode: 0o600 });
    await rename(tempPath, path);
  } catch (error) {
    await rm(tempPath, { force: true }).catch(() => {});
    throw error;
  }
}

export async function existingSymlinkInPath(targetPath: string, scopeRoot: string, includeTarget: boolean): Promise<string | undefined> {
  const rootPath = resolve(scopeRoot);
  const absoluteTargetPath = resolve(targetPath);
  if (!isPathInsideRoot(rootPath, absoluteTargetPath)) {
    return absoluteTargetPath;
  }

  const relativePath = relative(rootPath, absoluteTargetPath);
  if (relativePath === "") {
    return undefined;
  }
  const segments = relativePath.split(sep).filter(Boolean);
  let current = rootPath;

  for (const [index, segment] of segments.entries()) {
    current = join(current, segment);
    const isTarget = index === segments.length - 1;
    if (isTarget && !includeTarget) {
      break;
    }

    const inspection = await inspectSymlinkPathSegment(current, isTarget);
    if (inspection === "symlink") {
      return current;
    }
    if (inspection === "stop") {
      return undefined;
    }
  }

  return undefined;
}

type SymlinkPathSegmentInspection = "safe" | "stop" | "symlink";

async function inspectSymlinkPathSegment(path: string, isTarget: boolean): Promise<SymlinkPathSegmentInspection> {
  try {
    const stats = await lstat(path);
    if (stats.isSymbolicLink()) {
      return "symlink";
    }
    return !stats.isDirectory() && !isTarget ? "stop" : "safe";
  } catch (error) {
    if (isNodeError(error) && error.code === "ENOENT") {
      return "stop";
    }
    throw error;
  }
}

export function isPathInsideRoot(rootPath: string, childPath: string): boolean {
  const childRelative = relative(resolve(rootPath), resolve(childPath));
  return childRelative === "" || (!childRelative.startsWith("..") && !isAbsolute(childRelative));
}

export function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return typeof error === "object" && error !== null && "code" in error;
}
