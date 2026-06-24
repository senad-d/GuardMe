import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { realpath, stat } from "node:fs/promises";
import { homedir } from "node:os";

import type { PathTarget } from "./action.ts";

export interface NormalizePolicyPathOptions {
  readonly cwd: string;
  readonly homeDir?: string;
}

export interface NormalizedPolicyPath {
  readonly rawPath: string;
  readonly inputPath: string;
  readonly absolutePath: string;
  readonly canonicalPath: string;
  readonly projectRoot: string;
  readonly projectRelativePath?: string;
  readonly exists: boolean;
  readonly isInsideProject: boolean;
  readonly hadTraversal: boolean;
  readonly nearestExistingParent?: string;
}

export interface PolicyPathMatchOptions {
  readonly cwd: string;
  readonly homeDir?: string;
}

export interface PolicyPathMatchResult {
  readonly matched: boolean;
  readonly pattern: string;
  readonly normalizedPattern: string;
  readonly candidates: readonly string[];
}

export async function normalizePolicyPath(
  rawPath: string,
  options: NormalizePolicyPathOptions,
): Promise<NormalizedPolicyPath> {
  const homeDir = resolve(options.homeDir ?? homedir());
  const projectRoot = await canonicalizeProjectRoot(options.cwd);
  const inputPath = stripPiPathPrefix(rawPath.trim());
  const expandedPath = expandHome(inputPath, homeDir);
  const hadTraversal = hasTraversalSegment(expandedPath);
  const absolutePath = isAbsolute(expandedPath) ? resolve(expandedPath) : resolve(projectRoot, expandedPath);
  const canonical = await canonicalizePath(absolutePath);
  const isInsideProject = isPathInside(projectRoot, canonical.canonicalPath);
  const projectRelativePath = isInsideProject ? toPosixPath(relative(projectRoot, canonical.canonicalPath) || ".") : undefined;

  return {
    rawPath,
    inputPath,
    absolutePath,
    canonicalPath: canonical.canonicalPath,
    projectRoot,
    projectRelativePath,
    exists: canonical.exists,
    isInsideProject,
    hadTraversal,
    ...(canonical.nearestExistingParent ? { nearestExistingParent: canonical.nearestExistingParent } : {}),
  };
}

export function pathTargetFromNormalizedPath(normalizedPath: NormalizedPolicyPath): PathTarget {
  return {
    kind: "path",
    raw: normalizedPath.rawPath,
    absolutePath: normalizedPath.absolutePath,
    canonicalPath: normalizedPath.canonicalPath,
    projectRoot: normalizedPath.projectRoot,
    projectRelativePath: normalizedPath.projectRelativePath,
    exists: normalizedPath.exists,
    isInsideProject: normalizedPath.isInsideProject,
    hadTraversal: normalizedPath.hadTraversal,
  };
}

export function stripPiPathPrefix(pathValue: string): string {
  return pathValue.startsWith("@") ? pathValue.slice(1) : pathValue;
}

export function expandHome(pathValue: string, homeDir = homedir()): string {
  if (pathValue === "~") {
    return resolve(homeDir);
  }
  if (pathValue.startsWith(`~${sep}`) || pathValue.startsWith("~/")) {
    return join(resolve(homeDir), pathValue.slice(2));
  }
  return pathValue;
}

export function isPathInside(parentPath: string, childPath: string): boolean {
  const parent = resolve(parentPath);
  const child = resolve(childPath);
  const childRelative = relative(parent, child);
  return childRelative === "" || (!childRelative.startsWith("..") && !isAbsolute(childRelative));
}

export function matchPolicyPathPattern(
  pattern: string,
  normalizedPath: NormalizedPolicyPath,
  options?: Partial<PolicyPathMatchOptions>,
): PolicyPathMatchResult {
  const homeDir = resolve(options?.homeDir ?? homedir());
  const normalizedPattern = normalizePattern(pattern, normalizedPath.projectRoot, homeDir);
  const candidates = pathMatchCandidates(normalizedPath);
  const regex = globToRegExp(normalizedPattern);
  return {
    matched: candidates.some((candidate) => regex.test(candidate)),
    pattern,
    normalizedPattern,
    candidates,
  };
}

export function globToRegExp(pattern: string): RegExp {
  const normalized = toPosixPath(pattern);
  let source = "";
  for (let index = 0; index < normalized.length; index += 1) {
    const character = normalized[index];
    const next = normalized[index + 1];
    const afterNext = normalized[index + 2];

    if (character === "*" && next === "*" && afterNext === "/") {
      source += "(?:.*/)?";
      index += 2;
      continue;
    }
    if (character === "*" && next === "*") {
      source += ".*";
      index += 1;
      continue;
    }
    if (character === "*") {
      source += "[^/]*";
      continue;
    }
    if (character === "?") {
      source += "[^/]";
      continue;
    }
    source += escapeRegExp(character);
  }
  return new RegExp(`^${source}$`);
}

export function toPosixPath(pathValue: string): string {
  return pathValue.split(sep).join("/");
}

function normalizePattern(pattern: string, projectRoot: string, homeDir: string): string {
  const stripped = stripPiPathPrefix(pattern.trim());
  const expanded = expandHome(stripped, homeDir);
  if (isAbsolute(expanded)) {
    return toPosixPath(resolve(expanded));
  }
  if (expanded.startsWith("../") || expanded === "..") {
    return toPosixPath(resolve(projectRoot, expanded));
  }
  return toPosixPath(expanded.replace(/^\.\//, ""));
}

function pathMatchCandidates(normalizedPath: NormalizedPolicyPath): readonly string[] {
  const candidates = new Set<string>();
  candidates.add(toPosixPath(normalizedPath.canonicalPath));
  candidates.add(toPosixPath(normalizedPath.absolutePath));
  if (normalizedPath.projectRelativePath) {
    candidates.add(normalizedPath.projectRelativePath);
  }
  if (normalizedPath.inputPath !== "") {
    candidates.add(toPosixPath(normalizedPath.inputPath));
  }
  return [...candidates];
}

async function canonicalizeProjectRoot(cwd: string): Promise<string> {
  try {
    return await realpath(cwd);
  } catch {
    return resolve(cwd);
  }
}

async function canonicalizePath(absolutePath: string): Promise<{
  readonly canonicalPath: string;
  readonly exists: boolean;
  readonly nearestExistingParent?: string;
}> {
  try {
    await stat(absolutePath);
    return { canonicalPath: await realpath(absolutePath), exists: true };
  } catch (error) {
    if (!isMissingPathError(error)) {
      throw error;
    }
  }

  const missingSegments: string[] = [];
  let current = absolutePath;
  while (dirname(current) !== current) {
    missingSegments.unshift(current.slice(dirname(current).length + 1));
    current = dirname(current);
    try {
      await stat(current);
      const canonicalParent = await realpath(current);
      return {
        canonicalPath: resolve(canonicalParent, ...missingSegments),
        exists: false,
        nearestExistingParent: canonicalParent,
      };
    } catch (error) {
      if (!isMissingPathError(error)) {
        throw error;
      }
    }
  }

  return { canonicalPath: absolutePath, exists: false };
}

function hasTraversalSegment(pathValue: string): boolean {
  return pathValue.split(/[\\/]+/).includes("..");
}

function isMissingPathError(error: unknown): error is NodeJS.ErrnoException {
  return typeof error === "object" && error !== null && "code" in error && (error as NodeJS.ErrnoException).code === "ENOENT";
}

function escapeRegExp(character: string): string {
  return /[\\^$+?.()|[\]{}]/.test(character) ? `\\${character}` : character;
}
