import { basename, extname } from "node:path";

import {
  containsCredentialStoreLiteral,
  containsProtectedEnvReference,
  extractExecutableCommandSegments,
  tokenizeShellCommand,
} from "./commands.ts";
import type { ExtractedScriptCommand } from "./script-content.ts";
import { collapseByCharacter } from "./text-utils.ts";

// Script files run by an interpreter (`python3 x.py`, `node x.js`, `./x.py`)
// skip every shell check unless GuardMe reads them first. This module finds
// such executions and reports what a script would do that GuardMe guards:
// shell commands it spawns, environment dumps, credential-store paths,
// writes or deletes on literal paths, and decode-then-execute tricks.
// Ordinary application code (named `process.env.PORT` reads, project file
// I/O, test cleanup) produces no finding.

export type ScriptLanguage = "javascript" | "python" | "ruby" | "perl" | "php";

export interface InterpreterScriptExecution {
  readonly rawPath: string;
  readonly invocation: string;
  readonly language: ScriptLanguage;
}

export type ScriptFindingSeverity = "hard" | "dangerous";

export interface ScriptFinding {
  readonly severity: ScriptFindingSeverity;
  readonly reason: string;
  readonly line: number;
  readonly preview: string;
  readonly marker: string;
}

export type ScriptPathAction = "write" | "delete";

export interface ScriptPathAccess {
  readonly path: string;
  readonly action: ScriptPathAction;
  readonly line: number;
  readonly preview: string;
}

export interface InterpreterScriptAnalysis {
  readonly findings: readonly ScriptFinding[];
  readonly commands: readonly ExtractedScriptCommand[];
  readonly pathAccesses: readonly ScriptPathAccess[];
}

interface SourceLine {
  readonly text: string;
  readonly number: number;
}

interface CallMatch {
  readonly api: string;
  readonly argsStart: number;
  /** False for `system "ls"`: the argument list ends at the line end. */
  readonly parenthesized: boolean;
}

const INTERPRETER_LANGUAGES: Readonly<Record<string, ScriptLanguage>> = {
  node: "javascript", nodejs: "javascript", bun: "javascript", deno: "javascript", tsx: "javascript", "ts-node": "javascript",
  python: "python", python2: "python", python3: "python", pypy: "python", pypy3: "python",
  ruby: "ruby", perl: "perl", php: "php",
};

const EXTENSION_LANGUAGES: Readonly<Record<string, ScriptLanguage>> = {
  ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".ts": "javascript", ".mts": "javascript", ".cts": "javascript",
  ".jsx": "javascript", ".tsx": "javascript",
  ".py": "python", ".pyw": "python",
  ".rb": "ruby", ".pl": "perl", ".pm": "perl", ".php": "php",
};

// Options whose next word is a value, not the script path.
const VALUE_OPTIONS = new Set([
  "-r", "--require", "--import", "--loader", "--experimental-loader", "--env-file", "--conditions", "-C", "--title",
  "--input-type", "--stack-size", "--max-old-space-size", "-X", "-W", "--config", "-c", "--cwd",
]);
// Options that mean the code comes from somewhere other than a script file.
const INLINE_OPTIONS = new Set(["-e", "-E", "-p", "--eval", "--print", "-m", "-r", "-c"]);
const RUN_SUBCOMMANDS = new Set(["run", "exec", "x"]);
const MULTI_FILE_FLAGS = new Set(["--test"]);
const SCRIPT_RUNNER_PREFIXES: readonly (readonly string[])[] = [["uv", "run"], ["poetry", "run"], ["pipenv", "run"], ["pnpm", "exec"], ["npx"], ["pdm", "run"], ["hatch", "run"]];

const RUNNER_VALUE_OPTIONS = new Set(["--with", "--python", "--project", "--directory", "--package", "-p", "--env-file", "--group", "--extra"]);
// For bun a bare word after `bun`/`bun run` is a package.json script name.
const EXTENSION_REQUIRED_INTERPRETERS = new Set(["bun"]);
const MAX_CALL_ARGUMENT_CHARS = 4000;
const STRING_LITERAL = /(["'`])((?:\\.|(?!\1)[^\\\n])*)\1/gu;

export function detectInterpreterScriptExecutions(command: string): readonly InterpreterScriptExecution[] {
  const executions: InterpreterScriptExecution[] = [];
  const seen = new Set<string>();
  for (const segment of extractExecutableCommandSegments(command)) {
    for (const execution of interpreterExecutionsFromTokens(stripRunnerPrefix(tokenizeShellCommand(segment.originalText)))) {
      const key = `${execution.rawPath}\u0000${execution.language}`;
      if (!seen.has(key)) {
        seen.add(key);
        executions.push(execution);
      }
    }
  }
  return executions;
}

function stripRunnerPrefix(tokens: readonly string[]): readonly string[] {
  const prefix = SCRIPT_RUNNER_PREFIXES.find((candidate) => candidate.every((word, index) => tokens[index] === word));
  if (!prefix) {
    return tokens;
  }
  const rest = tokens.slice(prefix.length);
  let index = 0;
  while (index < rest.length && (rest[index] ?? "").startsWith("-")) {
    index += RUNNER_VALUE_OPTIONS.has(rest[index] ?? "") ? 2 : 1;
  }
  return rest.slice(index);
}

function interpreterExecutionsFromTokens(tokens: readonly string[]): readonly InterpreterScriptExecution[] {
  const interpreter = basename(tokens[0] ?? "").toLowerCase();
  const language = INTERPRETER_LANGUAGES[interpreter] ?? INTERPRETER_LANGUAGES[interpreter.replace(/(?<=[a-z])[\d.]+$/u, "")];
  if (!language) {
    return [];
  }
  const args = tokens.slice(1);
  if (args.some((arg) => INLINE_OPTIONS.has(arg) && isInlineOption(arg, language))) {
    return [];
  }
  const positionals = scriptPositionals(args, interpreter);
  const multiFile = args.some((arg) => MULTI_FILE_FLAGS.has(arg));
  const requireExtension = multiFile || EXTENSION_REQUIRED_INTERPRETERS.has(interpreter);
  const eligible = requireExtension ? positionals.filter(hasScriptExtension) : positionals;
  const files = multiFile ? eligible : eligible.slice(0, 1);
  const invocation = tokens.join(" ");
  return files
    .filter((file) => file !== "-" && !file.startsWith("<"))
    .map((rawPath) => ({ rawPath, invocation, language: EXTENSION_LANGUAGES[extname(rawPath).toLowerCase()] ?? language }));
}

// `-r` means --require for node but a one-liner for ruby; `-c` is a config
// value for deno/bun but inline code for python.
function isInlineOption(arg: string, language: ScriptLanguage): boolean {
  if (arg === "-r") {
    return language === "php";
  }
  if (arg === "-c") {
    return language === "python";
  }
  if (arg === "-m") {
    return language === "python";
  }
  return true;
}

function scriptPositionals(args: readonly string[], interpreter: string): readonly string[] {
  const positionals: string[] = [];
  let index = 0;
  if ((interpreter === "deno" || interpreter === "bun") && RUN_SUBCOMMANDS.has(args[0] ?? "")) {
    index = 1;
  }
  for (; index < args.length; index += 1) {
    const arg = args[index] ?? "";
    if (arg === "--") {
      positionals.push(...args.slice(index + 1, index + 2));
      break;
    }
    if (arg.startsWith("-")) {
      index += VALUE_OPTIONS.has(arg) ? 1 : 0;
      continue;
    }
    positionals.push(arg);
  }
  return positionals;
}

function hasScriptExtension(path: string): boolean {
  return Object.hasOwn(EXTENSION_LANGUAGES, extname(path).toLowerCase());
}

/** Language of a directly executed file from its extension or shebang, if it is an interpreter script. */
export function interpreterScriptLanguage(path: string, content: string): ScriptLanguage | undefined {
  const byExtension = EXTENSION_LANGUAGES[extname(path).toLowerCase()];
  if (byExtension) {
    return byExtension;
  }
  const shebang = /^#!\s*(\S+)(?:\s+(\S+))?/u.exec(content);
  if (!shebang) {
    return undefined;
  }
  const program = basename(shebang[1] ?? "") === "env" ? (shebang[2] ?? "") : (shebang[1] ?? "");
  const name = basename(program).toLowerCase();
  return INTERPRETER_LANGUAGES[name] ?? INTERPRETER_LANGUAGES[name.replace(/(?<=[a-z])[\d.]+$/u, "")];
}

export function analyzeInterpreterScript(content: string, language: ScriptLanguage, sourcePath: string): InterpreterScriptAnalysis {
  const lines = codeLines(content, language);
  const findings: ScriptFinding[] = [];
  const commands: ExtractedScriptCommand[] = [];
  const pathAccesses: ScriptPathAccess[] = [];
  const subprocessContext = hasSubprocessContext(content, language);
  for (const [index, line] of lines.entries()) {
    findings.push(...envDumpFindings(lines, index, language), ...credentialFindings(line));
    pathAccesses.push(...literalPathAccesses(line, language));
  }
  for (const call of subprocessCalls(content, language, subprocessContext)) {
    const line = lineNumberAt(content, call.argsStart);
    const resolved = subprocessCommand(content, call);
    if (resolved === undefined) {
      findings.push(finding("dangerous", `Script runs a command GuardMe cannot read (${call.api} with a computed argument)`, line, lineText(content, line), call.api));
      continue;
    }
    commands.push(extractedCommand(resolved, line, sourcePath));
  }
  for (const backtick of backtickCommands(content, language)) {
    commands.push(extractedCommand(backtick.command, lineNumberAt(content, backtick.offset), sourcePath));
  }
  findings.push(...obfuscatedExecutionFindings(content, language));
  return { findings, commands, pathAccesses };
}

// Whole-line comments are dropped so documentation such as `# never run
// rm -rf ~` does not count as code.
const COMMENT_PREFIXES: Readonly<Record<ScriptLanguage, readonly string[]>> = {
  javascript: ["//", "*", "/*"], php: ["//", "#", "*", "/*"], python: ["#"], ruby: ["#"], perl: ["#"],
};

function codeLines(content: string, language: ScriptLanguage): readonly SourceLine[] {
  const commentPrefixes = COMMENT_PREFIXES[language];
  return content
    .split("\n")
    .map((text, index) => ({ text, number: index + 1 }))
    .filter((line) => !commentPrefixes.some((prefix) => line.text.trimStart().startsWith(prefix)));
}

// Printing or serializing the whole environment is always a dump.
const ENV_DUMP_SINKS: Readonly<Record<ScriptLanguage, readonly RegExp[]>> = {
  javascript: [
    /JSON\.stringify\(\s*(?:process\.env|Bun\.env)\s*[,)]/u,
    /console\.\w+\(\s*(?:process\.env|Bun\.env)\s*[,)]/u,
    /util\.inspect\(\s*process\.env\b/u,
    /Deno\.env\.toObject\(\s*\)/u,
  ],
  python: [/\b(?:print|pprint|repr|str|json\.dumps)\(\s*(?:dict\(\s*)?os\.environ\s*[,)]/u],
  ruby: [/\bENV\.(?:to_h|to_hash|inspect)\b/u, /\b(?:p|pp|puts|print)\b\s*(?:\(\s*)?ENV(?:\s*\))?$/u],
  perl: [/Dumper\(\s*\\?%ENV/u, /\bprint\b.*%ENV\b/u],
  php: [/\bgetenv\(\s*\)/u, /\b(?:print_r|var_dump|var_export|json_encode)\(\s*\$_(?:ENV|SERVER)\b/u],
};

// Enumerating the environment is also how child-process environments are
// built (`Object.entries(process.env).filter(...)`), so it counts only when
// output follows within a few lines.
const ENV_ENUMERATIONS: Readonly<Record<ScriptLanguage, readonly RegExp[]>> = {
  javascript: [
    /Object\.(?:keys|values|entries|getOwnPropertyNames)\(\s*(?:process\.env|Bun\.env)\s*\)/u,
    /\bfor\s*\(\s*(?:const|let|var)\s+\w+\s+(?:in|of)\s+(?:process\.env|Bun\.env)\b/u,
  ],
  python: [/\bos\.environ\.(?:items|keys|values)\(\s*\)/u, /\bfor\s+\w+(?:\s*,\s*\w+)?\s+in\s+(?:sorted\(\s*)?os\.environ\b/u],
  ruby: [/\bENV\.(?:each\w*|keys|values|map|select|filter)\b/u],
  perl: [/\b(?:keys|values|each)\s*(?:\(\s*)?%ENV\b/u],
  php: [/\bforeach\s*\(\s*\$_(?:ENV|SERVER)\b/u],
};

const OUTPUT_SINKS = /console\.|process\.std(?:out|err)|\bprint\b|pprint|sys\.std(?:out|err)|json\.dumps|JSON\.stringify|\bputs\b|\becho\b|fetch\(|requests\.|urlopen|\bsend\(/u;
const ENUMERATION_SINK_WINDOW = 2;

function envDumpFindings(lines: readonly SourceLine[], index: number, language: ScriptLanguage): readonly ScriptFinding[] {
  const line = lines[index]!;
  const direct = ENV_DUMP_SINKS[language].some((pattern) => pattern.test(line.text.trimEnd()));
  const enumerated = ENV_ENUMERATIONS[language].some((pattern) => pattern.test(line.text))
    && lines.slice(index, index + ENUMERATION_SINK_WINDOW + 1).some((candidate) => OUTPUT_SINKS.test(candidate.text));
  return direct || enumerated
    ? [finding("hard", "Script dumps the process environment, which may contain secrets", line.number, line.text, "env-dump")]
    : [];
}

const FILE_READ_MARKERS = [
  /readFile|readFileSync|createReadStream|\bopen\(|read_text|read_bytes|load_dotenv|dotenv/u,
  /config\(\s*\{\s*path|File\.read|IO\.read|File\.open|file_get_contents|fopen|parse_ini_file|copyFile|cpSync|shutil\.copy/u,
];

// A credential-store path anchored at / or ~ (or joined onto the home
// directory) is a target; a relative mention such as '.aws/credentials' in
// test data counts only when the same line reads a file.
function credentialFindings(line: SourceLine): readonly ScriptFinding[] {
  const literals = stringLiterals(line.text);
  const reads = FILE_READ_MARKERS.some((pattern) => pattern.test(line.text));
  const anchored = literals.some((literal) => containsCredentialStoreLiteral(literal) && (literal.startsWith("/") || literal.startsWith("~")));
  const homeJoined = hasHomeExpression(line.text) && literals.some(containsCredentialStoreLiteral);
  if (reads && literals.some(containsCredentialStoreLiteral)) {
    return [finding("hard", "Script reads a credential store (SSH, cloud, registry or keychain files)", line.number, line.text, "credential-literal")];
  }
  if (anchored || homeJoined) {
    return [finding("dangerous", "Script names a credential store path (SSH, cloud, registry or keychain files)", line.number, line.text, "credential-path")];
  }
  if (reads && literals.some(containsProtectedEnvReference)) {
    return [finding("dangerous", "Script reads a protected .env file", line.number, line.text, "env-file-literal")];
  }
  return [];
}

function stringLiterals(text: string): readonly string[] {
  return [...text.matchAll(STRING_LITERAL)].map((match) => match[2] ?? "");
}

const WRITE_MARKERS: Readonly<Record<ScriptLanguage, readonly RegExp[]>> = {
  javascript: [/\b(?:writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream|copyFile|copyFileSync|cpSync|renameSync|rename|mkdirSync|symlinkSync|chmodSync|chownSync)\s*\(/u],
  python: [
    /\bopen\([^)]*["'][wax+]|\.write_(?:text|bytes)\(/u,
    /shutil\.(?:copy\w*|move)\(|os\.(?:rename|replace|makedirs|mkdir|symlink|chmod|chown)\(/u,
  ],
  ruby: [/\bFile\.(?:write|open\([^)]*["'][wa])\b/u, /\bFileUtils\.(?:cp\w*|mv|mkdir_p|touch|chmod\w*|ln\w*)\b/u],
  perl: [/\bopen\b\s*(?:\(\s*)?(?:\w+\s*)?,\s*(?:["']\s*)?[>+]/u],
  php: [/\b(?:file_put_contents|fopen\([^)]*["'][wax]|copy|rename|mkdir|symlink|chmod)\s*\(/u],
};

const DELETE_MARKERS: Readonly<Record<ScriptLanguage, RegExp>> = {
  javascript: /\b(?:rmSync|rmdirSync|unlinkSync|rm|rmdir|unlink|remove|removeSync|emptyDirSync)\s*\(/u,
  python: /(?:shutil\.rmtree\(|os\.(?:remove|unlink|rmdir|removedirs)\(|\.unlink\(|\.rmdir\()/u,
  ruby: /\b(?:FileUtils\.(?:rm\w*|remove\w*)|File\.(?:delete|unlink)|Dir\.(?:delete|rmdir|unlink))\b/u,
  perl: /\b(?:unlink|rmdir|remove_tree|rmtree)\b/u,
  php: /\b(?:unlink|rmdir)\s*\(/u,
};

const HOME_EXPRESSIONS = [
  /\bos\.homedir\(\)|\bhomedir\(\)|expanduser\(\s*["']~["']\s*\)|\bPath\.home\(\)|Dir\.home\b/u,
  /process\.env\.HOME\b|os\.environ\[\s*["']HOME["']\s*\]|ENV\[\s*["']HOME["']\s*\]/u,
];

function hasHomeExpression(text: string): boolean {
  return HOME_EXPRESSIONS.some((pattern) => pattern.test(text));
}

// Writes and deletes are judged by the path policy later; only literal paths
// that leave the project (absolute or ~) or the home directory itself are
// reported, so project-relative file handling stays silent.
function literalPathAccesses(line: SourceLine, language: ScriptLanguage): readonly ScriptPathAccess[] {
  const action = scriptPathAction(line.text, language);
  if (!action) {
    return [];
  }
  const paths = stringLiterals(line.text).filter((literal) => literal.startsWith("/") || literal === "~" || literal.startsWith("~/"));
  if (hasHomeExpression(line.text) && !paths.some((path) => path.startsWith("~"))) {
    paths.push("~");
  }
  return paths.map((path) => ({ path, action, line: line.number, preview: line.text.trim().slice(0, 160) }));
}

function scriptPathAction(text: string, language: ScriptLanguage): ScriptPathAction | undefined {
  if (DELETE_MARKERS[language].test(text)) {
    return "delete";
  }
  return WRITE_MARKERS[language].some((pattern) => pattern.test(text)) ? "write" : undefined;
}

const SUBPROCESS_CONTEXT: Readonly<Record<ScriptLanguage, RegExp>> = {
  javascript: /child_process|Bun\.spawn|Bun\.\$|Deno\.Command|\bexeca\b|\bzx\b/u,
  python: /\bsubprocess\b|\bos\.(?:system|popen|exec|spawn)|\bpty\.spawn|create_subprocess/u,
  ruby: /./u,
  perl: /./u,
  php: /./u,
};

function hasSubprocessContext(content: string, language: ScriptLanguage): boolean {
  return SUBPROCESS_CONTEXT[language].test(content);
}

const SUBPROCESS_CALLS: Readonly<Record<ScriptLanguage, readonly RegExp[]>> = {
  javascript: [
    /(?<![\w.$])(execSync|execFileSync|spawnSync|execFile|exec|spawn|execa|execaSync|execaCommand|execaCommandSync)\s*\(/gu,
    /\b(?:child_process|childProcess|cp)\.(execSync|execFileSync|spawnSync|execFile|exec|spawn|execa|execaSync|execaCommand|execaCommandSync)\s*\(/gu,
    /Bun\.(spawn|spawnSync)\s*\(|new\s+Deno\.(Command)\s*\(/gu,
  ],
  python: [
    /\bsubprocess\.(run|call|check_call|check_output|Popen|getoutput|getstatusoutput)\s*\(/gu,
    /\bos\.(system|popen|execl|execlp|execv|execvp|execvpe|spawnl|spawnlp|spawnv|spawnvp)\s*\(/gu,
    /\bpty\.(spawn)\s*\(|\basyncio\.(create_subprocess_exec|create_subprocess_shell)\s*\(/gu,
  ],
  ruby: [
    /(?<![\w.])(system|exec|spawn)(?:\s*\(|\s+(?=["'\w]))/gu,
    /Open3\.(capture2e?|capture3|popen\w*)\s*\(|IO\.(popen)\s*\(/gu,
  ],
  perl: [/(?<![\w$])(system|exec)(?:\s*\(|\s+(?=["'\w$]))/gu],
  php: [/(?<![\w$>])(shell_exec|exec|system|passthru|proc_open|popen)\s*\(/gu],
};

// `from subprocess import run` then `run([...])`.
const PYTHON_IMPORTED_CALLS = /(?<![\w.])(run|call|check_call|check_output|Popen|getoutput)\s*\(/gu;

function subprocessCalls(content: string, language: ScriptLanguage, subprocessContext: boolean): readonly CallMatch[] {
  if (!subprocessContext) {
    return [];
  }
  const calls: CallMatch[] = [];
  const masked = maskComments(content, language);
  const matches = SUBPROCESS_CALLS[language].flatMap((pattern) => [...masked.matchAll(pattern)]).sort((a, b) => a.index - b.index);
  for (const match of matches) {
    if (isDefinitionAt(masked, match.index ?? 0, match[0].length)) {
      continue;
    }
    const api = match.slice(1).find((group) => group !== undefined) ?? match[0];
    calls.push({ api, argsStart: (match.index ?? 0) + match[0].length, parenthesized: match[0].trimEnd().endsWith("(") });
  }
  if (language === "python" && /from\s+subprocess\s+import/u.test(content)) {
    for (const match of masked.matchAll(PYTHON_IMPORTED_CALLS)) {
      calls.push({ api: match[1] ?? "run", argsStart: (match.index ?? 0) + match[0].length, parenthesized: true });
    }
  }
  return calls;
}

// `async exec(command, args) {` or `exec() {` defines a method; it runs nothing.
function isDefinitionAt(content: string, offset: number, length: number): boolean {
  const lineStart = content.lastIndexOf("\n", offset) + 1;
  const before = content.slice(lineStart, offset).trimEnd();
  const lineEnd = content.indexOf("\n", offset);
  const after = content.slice(offset + length, lineEnd < 0 ? undefined : lineEnd);
  return /\b(?:async|function|def|get|set)$/u.test(before) || /^[^()]*\)\s*(?:\{|=>)/u.test(after);
}

// Ruby, Perl and PHP run backtick and %x()/qx() strings through the shell.
const BACKTICK_COMMANDS = /`([^`\n]*)`|%x\(([^)\n]*)\)|qx\(([^)\n]*)\)|qx\{([^}\n]*)\}/gu;

function backtickCommands(content: string, language: ScriptLanguage): readonly { readonly command: string; readonly offset: number }[] {
  if (language === "javascript" || language === "python") {
    return [];
  }
  return [...maskComments(content, language).matchAll(BACKTICK_COMMANDS)].map((match) => ({
    command: replaceBracedInterpolations(match.slice(1).find((group) => group !== undefined) ?? "", ["#"]).replace(/\$\w+/gu, "$ARG"),
    offset: match.index ?? 0,
  }));
}

function maskComments(content: string, language: ScriptLanguage): string {
  const prefixes = language === "javascript" ? ["//"] : COMMENT_PREFIXES[language].filter((prefix) => prefix === "#" || prefix === "//");
  return content.split("\n").map((line) => prefixes.some((prefix) => line.trimStart().startsWith(prefix)) ? " ".repeat(line.length) : line).join("\n");
}

// Builds the shell command a call would run from literal arguments. Returns
// undefined when the command itself is computed.
function subprocessCommand(content: string, call: CallMatch): string | undefined {
  const window = content.slice(call.argsStart, call.argsStart + MAX_CALL_ARGUMENT_CHARS);
  const args = topLevelArguments(call.parenthesized ? window : window.split("\n")[0] ?? "");
  const first = args[0]?.trim();
  if (first === undefined || first === "") {
    return undefined;
  }
  const program = literalWords(first);
  if (program === undefined) {
    return undefined;
  }
  const second = args[1]?.trim();
  const rest = second?.startsWith("[") ? (literalWords(second) ?? ["$ARG"]) : [];
  return [...program, ...rest].join(" ");
}

const EXECUTABLE_EXPRESSIONS: Readonly<Record<string, string>> = { "process.execPath": "node", "sys.executable": "python3" };

function literalWords(argument: string): readonly string[] | undefined {
  const executable = EXECUTABLE_EXPRESSIONS[argument];
  if (executable) {
    return [executable];
  }
  if (argument.startsWith("[")) {
    const inner = argument.slice(1, argument.lastIndexOf("]"));
    return topLevelArguments(inner).map((element) => literalText(element.trim()) ?? EXECUTABLE_EXPRESSIONS[element.trim()] ?? "$ARG");
  }
  const text = literalText(argument);
  return text === undefined ? undefined : [text];
}

// A quoted literal, an f-string or a template literal with placeholders
// replaced by $ARG; anything else is computed.
function literalText(argument: string): string | undefined {
  const match = /^[fFrRbBuU]{0,2}(["'`])([\s\S]*)\1$/u.exec(argument);
  if (!match) {
    return undefined;
  }
  return replaceBracedInterpolations(match[2] ?? "", ["$", ""]).replaceAll(String.raw`\n`, "\n");
}

// Scan each placeholder once, including malformed/nested input, without
// retrying an unbounded regex at every opening brace.
function replaceBracedInterpolations(value: string, prefixes: readonly string[]): string {
  let output = "";
  let cursor = 0;
  let scan = 0;
  let open: number;
  while ((open = value.indexOf("{", scan)) >= 0) {
    const prefix = prefixes.find((candidate) => value.slice(open - candidate.length, open) === candidate);
    scan = open + 1;
    if (prefix === undefined) {
      continue;
    }
    const close = value.indexOf("}", scan);
    if (close < 0) {
      break;
    }
    output += value.slice(cursor, open - prefix.length) + "$ARG";
    cursor = close + 1;
    scan = cursor;
  }
  return output + value.slice(cursor);
}

function quotedArgumentCharacter(text: string, index: number, quote: string): { readonly text: string; readonly quote?: string; readonly skip: number } {
  const character = text[index] ?? "";
  if (character === "\\") {
    return { text: text.slice(index, index + 2), quote, skip: 1 };
  }
  return { text: character, quote: character === quote ? undefined : quote, skip: 0 };
}

function isArgumentTerminator(character: string, depth: number): boolean {
  return depth === 0 && (character === ";" || ")]}".includes(character));
}

function topLevelArguments(text: string): readonly string[] {
  const args: string[] = [];
  let depth = 0;
  let quote: string | undefined;
  let current = "";
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index] ?? "";
    if (quote) {
      const part = quotedArgumentCharacter(text, index, quote);
      current += part.text;
      quote = part.quote;
      index += part.skip;
      continue;
    }
    if ("'\"`".includes(character)) {
      quote = character;
      current += character;
      continue;
    }
    if ("([{".includes(character)) {
      depth += 1;
    }
    if (isArgumentTerminator(character, depth)) {
      break;
    }
    if (")]}".includes(character)) {
      depth -= 1;
    }
    if (character === "," && depth === 0) {
      args.push(current);
      current = "";
      continue;
    }
    current += character;
  }
  args.push(current);
  return args;
}

const DECODE_MARKERS = /\batob\(|Buffer\.from\([^)]*["']base64["']|base64\.b64decode|base64\.decodebytes|codecs\.decode|Base64\.decode64|base64_decode\(|unpack\(\s*["']m/u;
const DYNAMIC_EXEC_MARKERS: Readonly<Record<ScriptLanguage, RegExp>> = {
  javascript: /(?<![\w.])eval\s*\(|new\s+Function\s*\(|vm\.runIn\w*\(/u,
  python: /(?<![\w.])(?:exec|eval|compile)\s*\(/u,
  ruby: /(?<![\w.])(?:eval|instance_eval|class_eval)\b/u,
  perl: /(?<![\w$])eval\b/u,
  php: /(?<![\w$>])(?:eval|assert|create_function)\s*\(/u,
};

function obfuscatedExecutionFindings(content: string, language: ScriptLanguage): readonly ScriptFinding[] {
  if (!DECODE_MARKERS.test(content) || !DYNAMIC_EXEC_MARKERS[language].test(content)) {
    return [];
  }
  const line = lineNumberAt(content, content.search(DYNAMIC_EXEC_MARKERS[language]));
  return [finding("dangerous", "Script decodes data and executes it as code, which hides what it runs", line, lineText(content, line), "decode-exec")];
}

function extractedCommand(command: string, line: number, sourcePath: string): ExtractedScriptCommand {
  const preview = collapseByCharacter(command, (character) => /\s/u.test(character)).slice(0, 160);
  return {
    command,
    normalizedCommand: preview,
    lineStart: line,
    lineEnd: line,
    context: "unknown-command-content",
    label: `${basename(sourcePath)}:${line}`,
    preview,
    sourcePath,
  };
}

function finding(severity: ScriptFindingSeverity, reason: string, line: number, preview: string, marker: string): ScriptFinding {
  return { severity, reason, line, preview: preview.trim().slice(0, 160), marker };
}

function lineNumberAt(content: string, offset: number): number {
  return content.slice(0, Math.max(offset, 0)).split("\n").length;
}

function lineText(content: string, line: number): string {
  return content.split("\n")[line - 1] ?? "";
}
