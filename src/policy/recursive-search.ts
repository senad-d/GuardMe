import { homedir } from "node:os";
import { basename, relative, resolve } from "node:path";

import type { MergedGuardMePolicyConfig, SourcedGuardMePathRule } from "../config/merge-policy.ts";
import type { ExecutableCommandSegment } from "./commands.ts";
import { tokenizeShellCommand } from "./commands.ts";
import { isPathInside } from "./paths.ts";

// Reads are open across the system, so a recursive content search rooted
// outside the project (`rg token ~/.config`, `grep -r key ~`) could print a
// protected file it passes on the way. These helpers find such roots and the
// protected paths beneath them; the search is then approval-gated.

export interface RecursiveSearchRoot {
  readonly raw: string;
  /** False for rg without --hidden/-uu: dot-entries below the root are skipped. */
  readonly includesHidden: boolean;
}

const GREP_FAMILY = new Set(["grep", "ggrep", "rg"]);
const RG_HIDDEN_FLAGS = new Set(["--hidden", "-.", "-uu", "-uuu"]);
const GLOB_START = /[*?[{]/u;

export function recursiveSearchRoots(segments: readonly ExecutableCommandSegment[]): readonly RecursiveSearchRoot[] {
  const roots: RecursiveSearchRoot[] = [];
  for (const segment of segments) {
    const command = basename(segment.commandName ?? "");
    if (!GREP_FAMILY.has(command)) {
      continue;
    }
    const args = tokenizeShellCommand(segment.originalText).slice(1);
    const isRg = command === "rg";
    if (!isRg && !args.some(isGrepRecursiveFlag)) {
      continue;
    }
    const includesHidden = !isRg || args.some((arg) => RG_HIDDEN_FLAGS.has(arg));
    for (const access of segment.classification.pathAccesses) {
      if (access.action === "read") {
        roots.push({ raw: access.rawPath, includesHidden });
      }
    }
  }
  return roots;
}

function isGrepRecursiveFlag(arg: string): boolean {
  if (arg === "--recursive" || arg === "--dereference-recursive" || arg === "-d" || arg.startsWith("--directories=recurse")) {
    return true;
  }
  return /^-[A-Za-z]+$/u.test(arg) && /[rR]/u.test(arg);
}

/** True when a path component strictly below root starts with a dot. */
export function isHiddenBelow(root: string, path: string): boolean {
  return relative(root, path)
    .split(/[\\/]+/u)
    .some((segment) => segment.startsWith(".") && segment !== "." && segment !== "..");
}

export interface ProtectedRuleUnderRoot {
  readonly rule: SourcedGuardMePathRule;
  readonly base: string;
}

/**
 * First anchored zero-access, credential or read-denying rule whose fixed
 * location lies strictly beneath the search root.
 */
export function protectedRuleUnderRoot(
  policy: MergedGuardMePolicyConfig,
  root: string,
  includesHidden: boolean,
  homeDir = homedir(),
): ProtectedRuleUnderRoot | undefined {
  const denyReads = policy.denyPaths.filter((rule) => rule.actions?.includes("read") ?? true);
  for (const rule of [...policy.zeroAccessPaths, ...policy.protectedCredentialPaths, ...denyReads]) {
    const base = anchoredRuleBase(rule.pattern, homeDir);
    if (base === undefined || base === root || !isPathInside(root, base)) {
      continue;
    }
    if (!includesHidden && isHiddenBelow(root, base)) {
      continue;
    }
    return { rule, base };
  }
  return undefined;
}

function anchoredRuleBase(pattern: string, homeDir: string): string | undefined {
  const expanded = pattern === "~" || pattern.startsWith("~/") ? `${homeDir}${pattern.slice(1)}` : pattern;
  if (!expanded.startsWith("/")) {
    return undefined;
  }
  const globIndex = expanded.search(GLOB_START);
  const literal = globIndex < 0 ? expanded : expanded.slice(0, globIndex);
  const base = literal.endsWith("/") ? literal.slice(0, -1) : literal.slice(0, Math.max(literal.lastIndexOf("/"), 1));
  const resolved = resolve(globIndex < 0 ? expanded : base || "/");
  return resolved === "/" ? undefined : resolved;
}
