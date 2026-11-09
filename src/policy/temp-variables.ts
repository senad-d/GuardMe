import { isAbsolute, join, normalize } from "node:path";

import { tokenizeShellCommand } from "./commands.ts";
import { prepareShellHeredocs } from "./heredocs.ts";

// Agents create scratch space with `d=$(mktemp -d /tmp/x.XXXXXX)` and then
// write, read and clean up "$d". An unresolved "$d" counts as an outside-project
// path, so every such command was blocked. This pass rewrites "$d" to the
// mktemp template path (X's included) when the shell is sure to have assigned
// it, so the normal temp-directory allowPaths decide.

interface Span {
  readonly start: number;
  readonly end: number;
}

interface MktempAssignment {
  readonly value: string;
  readonly position: number;
}

interface ScanState {
  singleQuoted: boolean;
  doubleQuoted: boolean;
  trapQuoted: boolean;
}

export interface MktempVariableEnvironment {
  readonly TMPDIR?: string;
}

// Absolute, no quotes, spaces or expansions: safe to write back into command text.
const SAFE_PATH_VALUE = /^\/[\w@%+=:,./-]*$/u;
const ASSIGNMENT_TOKEN = /^([A-Za-z_]\w*)=\$$/u;
const QUOTED_ASSIGNMENT_TOKEN = /^([A-Za-z_]\w*)=\$\((.*)\)$/su;
const TMPDIR_PREFIX = /^(?:\$\{TMPDIR(?::-([^}]*))?\}|\$TMPDIR(?!\w))/u;
const PWD_PREFIX = /^(?:\$\{PWD\}|\$PWD(?!\w))/u;
const KEYWORD_OPENERS = new Set(["if", "for", "while", "until", "case", "select"]);
const KEYWORD_CLOSERS = new Set(["fi", "done", "esac"]);
const COMMAND_POSITION_PREVIOUS = new Set([";", "&&", "||", "|", "&", "(", "{", "then", "do", "else", "elif", "!"]);
const DIRECTORY_CHANGE_COMMANDS = new Set(["cd", "pushd", "popd"]);
const MKTEMP_FLAGS = new Set(["d", "q", "u"]);
const MKTEMP_LONG_FLAGS = new Set(["--directory", "--quiet", "--dry-run"]);
const TRAP_PREFIX = /(^|[\s;&|(])trap\s+$/u;

export function expandMktempVariables(command: string, environment: MktempVariableEnvironment, cwd: string): string {
  if (!command.includes("mktemp") || !command.includes("$")) {
    return command;
  }
  const heredocs = prepareShellHeredocs(command);
  if (heredocs.error) {
    return command;
  }
  const bodies = heredocs.bodies ?? [];
  const visible = blankSpans(command, bodies);
  // Tokens come from the analysis form, where each heredoc body is one quoted
  // word, so an assignment inside a body never looks like a top-level one.
  const assignments = findMktempAssignments(heredocs.command, visible, environment, cwd);
  return assignments.size === 0 ? command : substituteAssignedVariables(command, assignments, bodies);
}

function blankSpans(command: string, spans: readonly Span[]): string {
  let output = command;
  for (const span of spans) {
    const blank = output.slice(span.start, span.end).replace(/[^\n]/gu, " ");
    output = output.slice(0, span.start) + blank + output.slice(span.end);
  }
  return output;
}

function findMktempAssignments(
  analysisCommand: string,
  visible: string,
  environment: MktempVariableEnvironment,
  cwd: string,
): Map<string, MktempAssignment> {
  const tokens = tokenizeShellCommand(analysisCommand);
  const changesDirectory = tokens.some((token, index) => DIRECTORY_CHANGE_COMMANDS.has(token) && isCommandPosition(tokens, index));
  const candidates = new Map<string, string>();
  let depth = 0;
  for (let index = 0; index < tokens.length; index += 1) {
    depth += depthChange(tokens, index);
    if (depth !== 0 || !isUnconditionalStart(tokens, index)) {
      continue;
    }
    const candidate = readMktempAssignment(tokens, index);
    const value = candidate ? mktempValue(candidate.args, environment, cwd, changesDirectory) : undefined;
    if (candidate && value) {
      candidates.set(candidate.name, value);
    }
  }

  const assignments = new Map<string, MktempAssignment>();
  for (const [name, value] of candidates) {
    const position = assignmentPosition(visible, name);
    if (position !== undefined && isSingleAssignment(tokens, name)) {
      assignments.set(name, { value, position });
    }
  }
  return assignments;
}

function isCommandPosition(tokens: readonly string[], index: number): boolean {
  const previous = tokens[index - 1];
  return previous === undefined || COMMAND_POSITION_PREVIOUS.has(previous);
}

// Only `;`/newline-separated top-level assignments always run; one after
// `&&`, `||`, a pipe or inside a group, loop or branch may never set the name.
function isUnconditionalStart(tokens: readonly string[], index: number): boolean {
  const previous = tokens[index - 1];
  return previous === undefined || previous === ";";
}

function depthChange(tokens: readonly string[], index: number): number {
  const token = tokens[index] ?? "";
  if (token === "(") {
    return 1;
  }
  if (token === ")") {
    return -1;
  }
  if (!isCommandPosition(tokens, index)) {
    return 0;
  }
  if (token === "{" || KEYWORD_OPENERS.has(token)) {
    return 1;
  }
  return token === "}" || KEYWORD_CLOSERS.has(token) ? -1 : 0;
}

function readMktempAssignment(tokens: readonly string[], index: number): { readonly name: string; readonly args: readonly string[] } | undefined {
  const token = tokens[index] ?? "";
  const quoted = QUOTED_ASSIGNMENT_TOKEN.exec(token);
  if (quoted) {
    const inner = tokenizeShellCommand(quoted[2] ?? "");
    return inner[0] === "mktemp" && followsWithSeparator(tokens, index + 1)
      ? { name: quoted[1] ?? "", args: inner.slice(1) }
      : undefined;
  }
  const bare = ASSIGNMENT_TOKEN.exec(token);
  if (!bare || tokens[index + 1] !== "(" || tokens[index + 2] !== "mktemp") {
    return undefined;
  }
  const close = tokens.indexOf(")", index + 3);
  if (close < 0 || !followsWithSeparator(tokens, close + 1)) {
    return undefined;
  }
  return { name: bare[1] ?? "", args: tokens.slice(index + 3, close) };
}

// `d=$(mktemp) cmd` sets d only for cmd; the shell keeps it only when a
// separator or the end of the command follows.
function followsWithSeparator(tokens: readonly string[], index: number): boolean {
  const next = tokens[index];
  return next === undefined || next === ";" || next === "&&";
}

function isSingleAssignment(tokens: readonly string[], name: string): boolean {
  let assignments = 0;
  for (const token of tokens) {
    if (token === name || token.startsWith(`${name}+=`)) {
      return false;
    }
    if (token.startsWith(`${name}=`)) {
      assignments += 1;
    }
  }
  return assignments === 1;
}

function assignmentPosition(visible: string, name: string): number | undefined {
  const match = new RegExp(String.raw`(^|[\s;])${name}="?\$\(\s*mktemp\b`, "u").exec(visible);
  return match ? match.index + (match[1]?.length ?? 0) : undefined;
}

function mktempValue(args: readonly string[], environment: MktempVariableEnvironment, cwd: string, changesDirectory: boolean): string | undefined {
  const tmpdir = resolveTmpdir(environment);
  let directory: string | undefined;
  let template: string | undefined;
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index] ?? "";
    if (arg === "-p") {
      directory = args[index + 1];
      index += 1;
    } else if (arg === "--tmpdir") {
      directory = tmpdir ?? "";
    } else if (arg.startsWith("--tmpdir=")) {
      directory = arg.slice("--tmpdir=".length);
    } else if (arg.startsWith("-")) {
      if (!isKnownMktempFlag(arg)) return undefined;
    } else if (template === undefined) {
      template = arg;
    } else {
      return undefined;
    }
  }
  return mktempPath(directory, template, tmpdir, cwd, changesDirectory);
}

function isKnownMktempFlag(arg: string): boolean {
  if (arg.startsWith("--")) {
    return MKTEMP_LONG_FLAGS.has(arg);
  }
  if (arg.length <= 1) {
    return false;
  }
  for (const flag of arg.slice(1)) {
    if (!MKTEMP_FLAGS.has(flag)) {
      return false;
    }
  }
  return true;
}

function mktempPath(
  directory: string | undefined,
  template: string | undefined,
  tmpdir: string | undefined,
  cwd: string,
  changesDirectory: boolean,
): string | undefined {
  const resolvedDirectory = directory === undefined ? undefined : resolveTmpdirPrefix(directory, tmpdir);
  if (template === undefined) {
    const base = resolvedDirectory ?? tmpdir;
    return base === undefined ? undefined : safePath(join(base, "tmp.XXXXXXXXXX"));
  }
  // $PWD is the project root unless the command changes directory first.
  const pwdTemplate = !changesDirectory && PWD_PREFIX.test(template) ? template.replace(PWD_PREFIX, cwd) : template;
  const resolvedTemplate = resolveTmpdirPrefix(pwdTemplate, tmpdir);
  if (resolvedTemplate === undefined || !resolvedTemplate.endsWith("XXX") || resolvedTemplate.split("/").includes("..")) {
    return undefined;
  }
  if (isAbsolute(resolvedTemplate)) {
    return resolvedDirectory === undefined ? safePath(resolvedTemplate) : undefined;
  }
  if (resolvedDirectory !== undefined) {
    return safePath(join(resolvedDirectory, resolvedTemplate));
  }
  return changesDirectory ? undefined : safePath(join(cwd, resolvedTemplate));
}

function resolveTmpdir(environment: MktempVariableEnvironment): string | undefined {
  const value = environment.TMPDIR;
  if (value === undefined || value === "") {
    return "/tmp";
  }
  return SAFE_PATH_VALUE.test(value) ? value : undefined;
}

function resolveTmpdirPrefix(value: string, tmpdir: string | undefined): string | undefined {
  const match = TMPDIR_PREFIX.exec(value);
  const fallback = match?.[1];
  let prefix: string | undefined = "";
  if (match) {
    prefix = fallback !== undefined && tmpdir === "/tmp" ? fallback : tmpdir;
  }
  const resolved = match ? `${prefix ?? ""}${value.slice(match[0].length)}` : value;
  if ((match && prefix === undefined) || /[$`'"\s]/u.test(resolved)) {
    return undefined;
  }
  return resolved;
}

function safePath(value: string): string | undefined {
  const normalized = normalize(value);
  return SAFE_PATH_VALUE.test(normalized) ? normalized : undefined;
}

function substituteAssignedVariables(command: string, assignments: ReadonlyMap<string, MktempAssignment>, bodies: readonly Span[]): string {
  const state: ScanState = { singleQuoted: false, doubleQuoted: false, trapQuoted: false };
  let output = "";
  for (let index = 0; index < command.length; index += 1) {
    const body = bodies.find((span) => span.start === index);
    if (body) {
      output += command.slice(body.start, body.end);
      index += body.end - index - 1;
      continue;
    }
    const character = command[index] ?? "";
    if (character === "\\" && !state.singleQuoted) {
      output += command.slice(index, index + 2);
      index += 1;
      continue;
    }
    updateQuoteState(state, character, output);
    const replacement = character === "$" && (!state.singleQuoted || state.trapQuoted)
      ? variableReplacement(command, index, assignments)
      : undefined;
    if (replacement) {
      output += replacement.value;
      index += replacement.length - 1;
      continue;
    }
    output += character;
  }
  return output;
}

// A single-quoted trap action runs later in this same shell, where the name
// is set; any other single-quoted text is literal or runs in a child shell.
function updateQuoteState(state: ScanState, character: string, output: string): void {
  if (character === "'" && !state.doubleQuoted) {
    state.singleQuoted = !state.singleQuoted;
    state.trapQuoted = state.singleQuoted && TRAP_PREFIX.test(output);
  }
  if (character === '"' && !state.singleQuoted) {
    state.doubleQuoted = !state.doubleQuoted;
  }
}

function variableReplacement(
  command: string,
  offset: number,
  assignments: ReadonlyMap<string, MktempAssignment>,
): { readonly value: string; readonly length: number } | undefined {
  const match = /^\$(?:\{(\w+)\}|(\w+))/u.exec(command.slice(offset));
  if (!match) {
    return undefined;
  }
  const assignment = assignments.get(match[1] ?? match[2] ?? "");
  if (!assignment || offset < assignment.position) {
    return undefined;
  }
  return { value: assignment.value, length: match[0].length };
}
