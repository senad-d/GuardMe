import { execFile } from "node:child_process";
import { open, realpath, stat } from "node:fs/promises";
import { isAbsolute, relative, resolve } from "node:path";

import type { PolicyAction, TrackedPath } from "./action.ts";
import { type CommandClassification, extractExecutableCommandSegments, isEnvAssignment, tokenizeShellCommand } from "./commands.ts";
import { isPathInside, toPosixPath } from "./paths.ts";

// Filesystem and git facts the synchronous policy evaluation cannot gather
// itself. Each helper fails open to "no fact" (the pre-existing decision).

const REMOVAL_ACTIONS: ReadonlySet<PolicyAction> = new Set(["delete", "move", "rename"]);
const UNRESOLVED_PATH = /[$`*?[\]{}]/u;
// Never resolve this policy probe through an agent-controlled PATH.
const GIT_EXECUTABLE = process.platform === "win32" ? String.raw`C:\Program Files\Git\cmd\git.exe` : "/usr/bin/git";
const GIT_TIMEOUT_MS = 3000;
const MAX_TRACKED_LOOKUPS = 16;
// ELF, Mach-O (32/64-bit, both byte orders), universal Mach-O and PE.
const NATIVE_MAGIC: ReadonlySet<string> = new Set(["7f454c46", "feedface", "feedfacf", "cefaedfe", "cffaedfe", "cafebabe"]);

/**
 * Delete, move and rename targets inside the project that git tracks, so a
 * recursive delete of committed source asks first while untracked build
 * output (target/, node_modules/) stays unattended.
 */
export async function trackedRemovalTargets(classification: CommandClassification, cwd: string): Promise<readonly TrackedPath[]> {
  const raws = [...new Set(classification.pathAccesses.filter((access) => REMOVAL_ACTIONS.has(access.action)).map((access) => access.rawPath))];
  const facts = await Promise.all(raws.slice(0, MAX_TRACKED_LOOKUPS).map((raw) => trackedPathFact(raw, cwd)));
  return facts.filter((fact): fact is TrackedPath => fact !== undefined);
}

async function trackedPathFact(raw: string, cwd: string): Promise<TrackedPath | undefined> {
  if (raw === "" || raw.startsWith("~") || UNRESOLVED_PATH.test(raw)) {
    return undefined;
  }
  const absolute = resolve(cwd, raw);
  if (!isPathInside(cwd, absolute) || absolute === resolve(cwd)) {
    return undefined;
  }
  const relativePath = toPosixPath(relative(cwd, absolute));
  const entries = await gitLsFiles(cwd, relativePath);
  if (entries.length === 0) {
    return undefined;
  }
  return { raw, tree: entries.some((entry) => entry !== relativePath) };
}

async function gitLsFiles(cwd: string, relativePath: string): Promise<readonly string[]> {
  const output = await new Promise<string>((resolveOutput) => {
    execFile(GIT_EXECUTABLE, ["ls-files", "-z", "--", `:(literal)${relativePath}`], { cwd, timeout: GIT_TIMEOUT_MS, maxBuffer: 1024 * 1024 }, (error, stdout) => {
      resolveOutput(error && !stdout ? "" : String(stdout));
    });
  });
  return output.split("\0").filter(Boolean);
}

/**
 * Executable tokens (`./target/debug/app`, `$TMPDIR/x/bin/app`) that resolve
 * to a native binary inside the project or the session TMPDIR.
 */
export async function nativeExecutableTokens(command: string, cwd: string, tmpDir: string | undefined): Promise<readonly string[]> {
  const roots = await executableRoots(cwd, tmpDir);
  const tokens = [...new Set(extractExecutableCommandSegments(command)
    .map((segment) => segmentExecutableToken(segment.normalizedText))
    .filter((token): token is string => Boolean(token)))];
  const native = await Promise.all(tokens.map((token) => isNativeExecutableIn(token, cwd, roots)));
  return tokens.filter((_token, index) => native[index]);
}

/** The executable word of a segment after leading `NAME=value` assignments. */
function segmentExecutableToken(segmentText: string): string | undefined {
  return tokenizeShellCommand(segmentText).find((token) => !isEnvAssignment(token));
}

async function executableRoots(cwd: string, tmpDir: string | undefined): Promise<readonly string[]> {
  const candidates = [cwd, ...(tmpDir && isAbsolute(tmpDir) ? [tmpDir] : [])];
  const roots = await Promise.all(candidates.map((candidate) => realpath(candidate).catch(() => undefined)));
  return roots.filter((root): root is string => root !== undefined && root !== "/");
}

async function isNativeExecutableIn(token: string, cwd: string, roots: readonly string[]): Promise<boolean> {
  if (!token.includes("/") || token.startsWith("~") || UNRESOLVED_PATH.test(token)) {
    return false;
  }
  const real = await realpath(resolve(cwd, token)).catch(() => undefined);
  if (!real || !roots.some((root) => isPathInside(root, real))) {
    return false;
  }
  const info = await stat(real).catch(() => undefined);
  if (!info?.isFile() || (info.mode & 0o111) === 0) {
    return false;
  }
  return hasNativeMagic(real);
}

async function hasNativeMagic(path: string): Promise<boolean> {
  const handle = await open(path, "r").catch(() => undefined);
  if (!handle) {
    return false;
  }
  try {
    const buffer = Buffer.alloc(4);
    const { bytesRead } = await handle.read(buffer, 0, 4, 0);
    const hex = buffer.subarray(0, bytesRead).toString("hex");
    return NATIVE_MAGIC.has(hex) || hex.startsWith("4d5a");
  } finally {
    await handle.close();
  }
}

// Shared temp roots: TMPDIR must sit strictly below one of these, so `cd /tmp/other` stays guarded.
const SHARED_TEMP_ROOTS: readonly string[] = ["/tmp", "/private/tmp", "/var/tmp", "/private/var/tmp"];
// macOS per-user temp directory (`$TMPDIR` by default): private to the user, so it may be the root itself.
const USER_TEMP_ROOT = /^\/(?:private\/)?var\/folders\/[^/]+\/[^/]+\/T(?:\/|$)/u;

/**
 * Session TMPDIR, canonical and as given (`/var/folders/..` and
 * `/private/var/folders/..` on macOS), when it is a private directory under
 * an OS temp root (`/tmp/mission/<project>/<objective>`, macOS
 * `/var/folders/../T`). `cd` into it and script runs or `test` on paths
 * inside it count like project paths. Empty for an unset, relative or shared
 * value such as `/tmp` itself.
 */
export async function sessionScratchRoots(tmpDir: string | undefined): Promise<readonly string[]> {
  if (!tmpDir || !isAbsolute(tmpDir) || UNRESOLVED_PATH.test(tmpDir)) {
    return [];
  }
  const real = await realpath(tmpDir).catch(() => undefined);
  if (!real) {
    return [];
  }
  const belowSharedRoot = SHARED_TEMP_ROOTS.some((root) => real !== root && isPathInside(root, real));
  if (!belowSharedRoot && !USER_TEMP_ROOT.test(real)) {
    return [];
  }
  const given = resolve(tmpDir);
  return given === real ? [real] : [real, given];
}
