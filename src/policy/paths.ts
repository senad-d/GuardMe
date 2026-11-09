import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { realpath, stat } from "node:fs/promises";
import { homedir } from "node:os";

import type { PathTarget, PolicyAction } from "./action.ts";
import { prepareShellHeredocs } from "./heredocs.ts";

export interface NormalizePolicyPathOptions {
  readonly cwd: string;
  readonly homeDir?: string;
  /**
   * Set when the raw path came from shell command text, where `$VAR`,
   * backticks, and `~user` would be expanded by the shell before use. GuardMe
   * cannot resolve those statically, so such paths are treated as
   * outside-project and fall through to the default-deny/approval flow.
   */
  readonly shellExpansion?: boolean;
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
  /** Mirrors PathTarget.discovery for targets synthesized by discovery scans. */
  readonly discovery?: boolean;
  /** Mirrors PathTarget.existenceCheck. */
  readonly existenceCheck?: boolean;
  /** Mirrors PathTarget.directoryChange. */
  readonly directoryChange?: boolean;
  /** Mirrors PathTarget.recursiveSearch and PathTarget.searchIncludesHidden. */
  readonly recursiveSearch?: boolean;
  readonly searchIncludesHidden?: boolean;
  /** Mirrors PathTarget.action: the access action this path is checked under. */
  readonly action?: PolicyAction;
}

export interface PolicyPathMatchOptions {
  readonly cwd: string;
  readonly homeDir?: string;
  /**
   * "all" (default) also matches the raw input path, which is safe only for
   * deny-direction rules. "resolved" matches canonical/absolute forms alone so
   * traversal (`docs/../..`) or symlink escapes cannot satisfy an allow rule
   * written for the un-escaped location.
   */
  readonly candidateScope?: "all" | "resolved";
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
  const unresolvedShellReference = options.shellExpansion === true && containsUnresolvedShellReference(expandedPath);
  const absolutePath = isAbsolute(expandedPath) ? resolve(expandedPath) : resolve(projectRoot, expandedPath);
  const canonical = await canonicalizePath(absolutePath);
  const isInsideProject = !unresolvedShellReference && isPathInside(projectRoot, canonical.canonicalPath);
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

/**
 * True when a policy pattern is anchored to an absolute or home-relative
 * location. Only anchored readOnlyPaths rules may grant outside-project
 * reads: relative and `**`-prefixed globs would otherwise match absolute
 * path candidates anywhere on disk.
 */
export function isAnchoredPolicyPathPattern(pattern: string): boolean {
  const stripped = stripPiPathPrefix(pattern.trim());
  return stripped.startsWith("~") || isAbsolute(stripped);
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
  const candidates = pathMatchCandidates(normalizedPath, options?.candidateScope ?? "all");
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

function pathMatchCandidates(normalizedPath: NormalizedPolicyPath, scope: "all" | "resolved"): readonly string[] {
  const candidates = new Set<string>();
  candidates.add(toPosixPath(normalizedPath.canonicalPath));
  candidates.add(toPosixPath(normalizedPath.absolutePath));
  if (normalizedPath.projectRelativePath) {
    candidates.add(normalizedPath.projectRelativePath);
  }
  if (scope === "all" && normalizedPath.inputPath !== "") {
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

export interface StableShellVariables {
  readonly HOME?: string;
  readonly TMPDIR?: string;
  readonly PWD?: string;
}

// A value written back into command text: absolute, no quotes, spaces or expansions.
const SAFE_VARIABLE_VALUE = /^\/[\w@%+=:,./-]*$/;

/**
 * Replaces `$HOME`, `$TMPDIR` and `$PWD` (bare or braced, outside single
 * quotes) with their values, so a path the shell would expand is checked as
 * the literal path it becomes. Left alone: a variable the command itself
 * names without `$` (assignment, export, unset, read, for), `$PWD` after a
 * directory change, heredoc bodies (they may be literal), and unsafe or
 * relative values.
 */
export function expandStableShellVariables(command: string, variables: StableShellVariables, cwd = variables.PWD): string {
  if (!command.includes("$")) {
    return command;
  }
  // Heredoc bodies stay literal; `cat > $TMPDIR/x <<'EOF'` still resolves its target.
  const heredocs = command.includes("<<") ? prepareShellHeredocs(command) : undefined;
  if (heredocs?.error) {
    return command;
  }
  const values = new Map<string, string>();
  // Only these path variables may be resolved, even when given a full process
  // environment. Reading them creates no temporary files or policy allowances.
  for (const name of ["HOME", "TMPDIR", "PWD"] as const) {
    const value = name === "PWD" ? cwd : variables[name];
    if (typeof value !== "string" || !SAFE_VARIABLE_VALUE.test(value)) continue;
    if (new RegExp(String.raw`(^|[^$\w{])${name}\b`).test(command)) continue;
    if (name === "PWD" && /(^|[\s;&|(])(cd|pushd|popd)\b/.test(command)) continue;
    values.set(name, value);
  }
  return values.size === 0 ? command : replaceOutsideSpans(command, heredocs?.bodies ?? [], values);
}

function replaceOutsideSpans(command: string, spans: readonly { readonly start: number; readonly end: number }[], values: ReadonlyMap<string, string>): string {
  let output = "";
  let offset = 0;
  for (const span of [...spans].sort((left, right) => left.start - right.start)) {
    output += replaceShellVariables(command.slice(offset, span.start), values) + command.slice(span.start, span.end);
    offset = span.end;
  }
  return output + replaceShellVariables(command.slice(offset), values);
}

function replaceShellVariables(command: string, values: ReadonlyMap<string, string>): string {
  let output = "";
  let singleQuoted = false;
  let doubleQuoted = false;
  for (let index = 0; index < command.length; index += 1) {
    const character = command[index] ?? "";
    if (character === "\\" && !singleQuoted) {
      output += command.slice(index, index + 2);
      index += 1;
      continue;
    }
    if (character === "'" && !doubleQuoted) singleQuoted = !singleQuoted;
    if (character === '"' && !singleQuoted) doubleQuoted = !doubleQuoted;
    const replacement = character === "$" && !singleQuoted ? shellVariableReplacement(command, index, values) : undefined;
    if (replacement) {
      output += replacement.value;
      index += replacement.length - 1;
      continue;
    }
    output += character;
  }
  return output;
}

function shellVariableReplacement(
  command: string,
  offset: number,
  values: ReadonlyMap<string, string>,
): { readonly value: string; readonly length: number } | undefined {
  const match = /^\$(?:\{(\w+)\}|(\w+))/.exec(command.slice(offset));
  if (!match) return undefined;
  const value = values.get(match[1] ?? match[2] ?? "");
  return value === undefined ? undefined : { value, length: match[0].length };
}

function containsUnresolvedShellReference(pathValue: string): boolean {
  return pathValue.includes("$") || pathValue.includes("`") || pathValue.startsWith("~");
}

function isMissingPathError(error: unknown): error is NodeJS.ErrnoException {
  return typeof error === "object" && error !== null && "code" in error && (error as NodeJS.ErrnoException).code === "ENOENT";
}

function escapeRegExp(character: string): string {
  return /[\\^$+?.()|[\]{}]/.test(character) ? `\\${character}` : character;
}
