import { tokenizeShellCommand, type ExecutableCommandSegment } from "./commands.ts";

// Plain POSIX built-ins and in-project script runs pass without an
// allowCommands rule, including inside inspected scripts where every other
// segment needs an exact rule (Mission QA 2026-11-09, F2/F16). Each check is
// narrow: no file redirection, no unresolved path, nothing outside the project
// or in .git. Path protections and deny rules run before this check, and a
// script run here still has its own content inspected by the guard.

/** Project-relative path of a raw operand, or undefined when it resolves outside the project. */
export type ProjectPathResolver = (rawPath: string) => string | undefined;

const OUTPUT_COMMANDS: ReadonlySet<string> = new Set(["echo", "printf"]);
const TEST_COMMANDS: ReadonlySet<string> = new Set(["test", "[", "[["]);
const SHELL_WRAPPERS: ReadonlySet<string> = new Set(["sh", "bash", "zsh"]);
const FD_DUPLICATION = /^\d?>&$/u;
const FD_NUMBER = /^\d$/u;
const REDIRECTION_START = /^(?:\d*|&)[<>]/u;
const UNRESOLVED_PATH = /[$`~*?[\]{}]/u;
const SUBSTITUTION_ASSIGNMENT = /^[A-Za-z_]\w*=\$$/u;

export function isHarmlessShellSegment(segment: ExecutableCommandSegment, resolveProjectPath: ProjectPathResolver): boolean {
  if (segment.hardDenied || segment.dangerous || segment.requiresUserDecision || segment.credentialAccess) {
    return false;
  }
  const tokens = tokenizeShellCommand(segment.normalizedText);
  if (hasFileRedirection(tokens)) {
    return false;
  }
  const commandTokens = withoutSubstitutionAssignment(withoutFdDuplications(tokens));
  const [name = "", ...args] = commandTokens;
  if (name === "set") {
    // Bare `set` prints every shell variable, environment included.
    return args.length > 0;
  }
  if (OUTPUT_COMMANDS.has(name)) {
    return true;
  }
  if (TEST_COMMANDS.has(name)) {
    return segment.targetPaths.every((path) => isProjectPath(path, resolveProjectPath));
  }
  if (name === "cd") {
    return isProjectDirectoryChange(args, resolveProjectPath);
  }
  return isProjectScriptRun(name, args, resolveProjectPath);
}

// `>&2` and `2>&1` duplicate descriptors and write no file; every other
// redirection keeps the normal write and path checks.
function hasFileRedirection(tokens: readonly string[]): boolean {
  return tokens.some((token, index) => (FD_DUPLICATION.test(token) ? !FD_NUMBER.test(tokens[index + 1] ?? "") : REDIRECTION_START.test(token)));
}

function withoutFdDuplications(tokens: readonly string[]): readonly string[] {
  return tokens.filter((token, index) => !FD_DUPLICATION.test(token) && !(FD_NUMBER.test(token) && FD_DUPLICATION.test(tokens[index - 1] ?? "")));
}

// `output=$(./hello.sh)` leaves the fragment `output=$ ( ./hello.sh`: the
// substituted command, which is also checked as its own segment.
function withoutSubstitutionAssignment(tokens: readonly string[]): readonly string[] {
  return SUBSTITUTION_ASSIGNMENT.test(tokens[0] ?? "") && tokens[1] === "(" ? tokens.slice(2) : tokens;
}

function isProjectDirectoryChange(args: readonly string[], resolveProjectPath: ProjectPathResolver): boolean {
  const [target] = args;
  // Bare `cd` goes to $HOME and `cd -` to $OLDPWD; neither is known here.
  return args.length === 1 && target !== undefined && !target.startsWith("-") && isProjectPath(target, resolveProjectPath);
}

// `./hello.sh`, `tests/run.sh arg`, `sh tests/x.sh`: a script file inside
// the project. A bare name runs from PATH, so direct runs need a slash; `sh
// name.sh` reads the file from the working directory. Options to the shell
// wrapper (`sh -c`, `bash -x`) do not qualify.
function isProjectScriptRun(name: string, args: readonly string[], resolveProjectPath: ProjectPathResolver): boolean {
  const viaShell = SHELL_WRAPPERS.has(name);
  const scriptPath = viaShell ? args[0] : name;
  if (!scriptPath || scriptPath.startsWith("-")) {
    return false;
  }
  if (!viaShell && !scriptPath.includes("/")) {
    return false;
  }
  return isProjectPath(scriptPath, resolveProjectPath) && resolveProjectPath(scriptPath) !== ".";
}

function isProjectPath(rawPath: string, resolveProjectPath: ProjectPathResolver): boolean {
  if (rawPath === "" || UNRESOLVED_PATH.test(rawPath)) {
    return false;
  }
  const relativePath = resolveProjectPath(rawPath);
  return relativePath !== undefined && relativePath !== ".git" && !relativePath.startsWith(".git/");
}
