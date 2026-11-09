import { tokenizeShellCommand } from "./commands.ts";
import { isInsideSingleQuotes, resolveScriptDirnameZero } from "./paths.ts";
import { joinContinuationLines, stripShellComment } from "./script-content.ts";

// Mission live gate 2026-11-09 (G1/G2): facts about an inspected shell script
// that let later lines be judged on the literal paths they use.
//
// - A variable assigned exactly once, on a top-level line, to a literal path
//   or `$(dirname "$0")/<rel>` resolves in the lines after that assignment, so
//   `test -x "$script"` is checked as `test -x /project/scripts/hello.sh`.
// - Top-level lines are outside every if/loop/case/function/subshell/brace
//   group; only a `cd` on such a line moves the tracked shell directory.
//
// Everything fails closed: a name that appears anywhere else in the script
// (read, for, unset, a second assignment, `${name:=x}`, even a plain word),
// a heredoc, eval, source, trap or IFS in the script, or unbalanced structure
// leaves the variable unresolved, which keeps the existing guard. A `case`
// statement disables the scan too: its `pattern)` lines would close depth early.

export interface ResolvedScriptVariable {
  readonly line: number;
  readonly value: string;
}

export interface ScriptShellFacts {
  /** Logical-line starts (1-based) at depth 0 that open or close no block. */
  readonly topLevelLines: ReadonlySet<number>;
  readonly variables: ReadonlyMap<string, ResolvedScriptVariable>;
}

const EMPTY_FACTS: ScriptShellFacts = { topLevelLines: new Set(), variables: new Map() };

// Script-wide constructs that can rebind variables or hide lines from this scan.
const UNSAFE_SCRIPT_CONSTRUCT = /<<|\b(?:eval|source|trap|case|IFS)\b/u;

function hasDotSource(content: string): boolean {
  let commandPosition = true;
  for (let index = 0; index < content.length; index += 1) {
    const character = content[index]!;
    if (commandPosition && character === "." && /\s/u.test(content[index + 1] ?? "")) {
      return true;
    }
    if (/[;&|(\r\n\u2028\u2029]/u.test(character)) {
      commandPosition = true;
    } else if (!/\s/u.test(character)) {
      commandPosition = false;
    }
  }
  return false;
}
const KEYWORD_OPENERS: ReadonlySet<string> = new Set(["if", "for", "while", "until", "select"]);
const KEYWORD_CLOSERS: ReadonlySet<string> = new Set(["fi", "done", "esac", "}"]);
// After these tokens the next word is in command position.
const COMMAND_POSITION_PREFIXES: ReadonlySet<string> = new Set(["then", "do", "else", "elif", "!", "time", "{", "(", ")"]);
const SEPARATOR_TOKEN = /^[;&|]+$/u;
const ASSIGNMENT_LINE = /^([A-Za-z_]\w*)=(.*)$/su;
const SAFE_PATH_VALUE = /^[\w@%+=:,./-]+$/u;
// Names whose value changes how the shell itself splits words or finds programs.
const SHELL_CONTROL_NAMES: ReadonlySet<string> = new Set(["PATH", "CDPATH", "PWD", "OLDPWD", "IFS", "ENV", "BASH_ENV", "HOME", "TMPDIR"]);

export function analyzeScriptShellFacts(content: string, scriptDirectory: string): ScriptShellFacts {
  if (UNSAFE_SCRIPT_CONSTRUCT.test(content) || hasDotSource(content)) {
    return EMPTY_FACTS;
  }
  const topLevelLines = new Set<number>();
  const assignments: { readonly name: string; readonly line: number; readonly rawValue: string }[] = [];
  let depth = 0;
  for (const logicalLine of joinContinuationLines(content)) {
    const text = stripShellComment(logicalLine.text).trim();
    const change = blockDepthChange(tokenizeShellCommand(text));
    if (depth === 0 && change.opened === 0 && change.closed === 0) {
      topLevelLines.add(logicalLine.lineStart);
    }
    // `name=$(dirname "$0")/x` balances its own parentheses; the value check rejects anything else.
    const assignment = depth === 0 && change.opened === change.closed ? ASSIGNMENT_LINE.exec(text) : null;
    if (assignment?.[1] && assignment[2] !== undefined) {
      assignments.push({ name: assignment[1], line: logicalLine.lineStart, rawValue: assignment[2] });
    }
    depth += change.opened - change.closed;
    if (depth < 0) {
      // Unbalanced (a `case` pattern, an unmatched closer): nothing after is known.
      break;
    }
  }
  return { topLevelLines, variables: resolveAssignments(assignments, content, scriptDirectory) };
}

function resolveAssignments(
  assignments: readonly { readonly name: string; readonly line: number; readonly rawValue: string }[],
  content: string,
  scriptDirectory: string,
): ReadonlyMap<string, ResolvedScriptVariable> {
  const variables = new Map<string, ResolvedScriptVariable>();
  for (const assignment of assignments) {
    const value = literalAssignmentValue(assignment.rawValue, scriptDirectory);
    if (value !== undefined && !SHELL_CONTROL_NAMES.has(assignment.name) && nameBindingCount(content, assignment.name) === 1) {
      variables.set(assignment.name, { line: assignment.line, value });
    }
  }
  return variables;
}

/**
 * Replaces `$name` and `${name}` (outside single quotes, not escaped, not
 * `$$name`) with the resolved value of a variable assigned before `line`.
 */
export function substituteResolvedVariables(command: string, line: number, variables: ReadonlyMap<string, ResolvedScriptVariable>): string {
  if (variables.size === 0 || !command.includes("$")) {
    return command;
  }
  return command.replace(/\$(?:\{([A-Za-z_]\w*)\}|([A-Za-z_]\w*))/gu, (match: string, braced: string | undefined, bare: string | undefined, offset: number) => {
    const variable = variables.get(braced ?? bare ?? "");
    const previous = command[offset - 1];
    if (!variable || variable.line >= line || previous === "\\" || previous === "$" || isInsideSingleQuotes(command, offset)) {
      return match;
    }
    return variable.value;
  });
}

// Openers count in any position for `{`/`(` and in command position for
// keywords; closers count in command position, `)` anywhere. Miscounts can
// only overstate depth (fail closed) or drive it negative (stop the scan).
function blockDepthChange(tokens: readonly string[]): { readonly opened: number; readonly closed: number } {
  let opened = 0;
  let closed = 0;
  let commandPosition = true;
  for (const token of tokens) {
    if (token === "{" || token === "(" || (commandPosition && KEYWORD_OPENERS.has(token))) {
      opened += 1;
    } else if (token === ")" || (commandPosition && KEYWORD_CLOSERS.has(token))) {
      closed += 1;
    }
    commandPosition = SEPARATOR_TOKEN.test(token) || COMMAND_POSITION_PREFIXES.has(token);
  }
  return { opened, closed };
}

function literalAssignmentValue(rawValue: string, scriptDirectory: string): string | undefined {
  const resolved = resolveScriptDirnameZero(rawValue, scriptDirectory);
  const unquoted = stripWholeQuotes(resolved);
  return unquoted !== undefined && SAFE_PATH_VALUE.test(unquoted) ? unquoted : undefined;
}

function stripWholeQuotes(value: string): string | undefined {
  const quote = value[0];
  if (quote !== '"' && quote !== "'") {
    return value;
  }
  const inner = value.slice(1, -1);
  return value.length >= 2 && value.at(-1) === quote && !inner.includes(quote) ? inner : undefined;
}

// Every occurrence of the name that is not a `$name` or `${name}` expansion
// counts as a binding; only the single assignment itself may remain. Path
// parts and options (`/x`, `x.sh`, `-x`) cannot bind a variable.
function nameBindingCount(content: string, name: string): number {
  let count = 0;
  for (const match of content.matchAll(new RegExp(String.raw`(?<![\w/.$-])${name}(?![\w/.])`, "gu"))) {
    const offset = match.index;
    const bracedExpansion = content[offset - 1] === "{" && content[offset - 2] === "$" && content[offset + name.length] === "}";
    if (!bracedExpansion) {
      count += 1;
    }
  }
  return count;
}
