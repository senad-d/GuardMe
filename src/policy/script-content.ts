import { basename, extname } from "node:path";

import { tokenizeShellCommand } from "./commands.ts";
import { redactSensitiveText } from "./redact.ts";

export type ScriptContentContext =
  | "shell-script"
  | "makefile-recipe"
  | "package-json-script"
  | "dockerfile-run"
  | "ci-run"
  | "heredoc-shell"
  | "unknown-command-content";

export interface ExtractedScriptCommand {
  readonly command: string;
  readonly normalizedCommand: string;
  readonly lineStart: number;
  readonly lineEnd: number;
  readonly context: ScriptContentContext;
  readonly label: string;
  readonly preview: string;
  readonly sourcePath?: string;
}

export interface UninspectableScriptContent {
  readonly reason: string;
  readonly context: ScriptContentContext;
  readonly lineStart?: number;
  readonly lineEnd?: number;
  readonly preview?: string;
  readonly sourcePath?: string;
}

export interface ScriptContentExtractionResult {
  readonly commandBearing: boolean;
  readonly commands: readonly ExtractedScriptCommand[];
  readonly uninspectable?: UninspectableScriptContent;
}

export interface ExtractScriptContentOptions {
  readonly path?: string;
  readonly content: string;
  readonly forceCommandBearing?: boolean;
  readonly shellHint?: boolean;
  readonly maxBytes?: number;
}

const DEFAULT_MAX_SCRIPT_BYTES = 256 * 1024;
const ANSI_ESCAPE = String.fromCodePoint(0x1b);
const ANSI_CSI = String.fromCodePoint(0x9b);
const SHELL_EXTENSIONS = new Set([".sh", ".bash", ".zsh", ".command", ".ksh"]);

interface AnsiStripStep {
  readonly index: number;
  readonly nextIndex: number;
  readonly text: string;
}
const CI_EXTENSIONS = new Set([".yml", ".yaml"]);
const SHELL_CONTROL_ONLY = new Set([
  "do",
  "done",
  "then",
  "else",
  "elif",
  "fi",
  "case",
  "esac",
  "{",
  "}",
  "(",
  ")",
]);

export function isCommandBearingPath(pathValue: string | undefined): boolean {
  if (!pathValue) {
    return false;
  }
  const normalized = pathValue.replaceAll("\\", "/");
  const name = basename(normalized).toLowerCase();
  const extension = extname(name);
  return (
    SHELL_EXTENSIONS.has(extension) ||
    name === "makefile" ||
    name.endsWith(".mk") ||
    name === "dockerfile" ||
    name.startsWith("dockerfile.") ||
    name === "package.json" ||
    (CI_EXTENSIONS.has(extension) && (normalized.includes(".github/workflows/") || normalized.includes("/workflows/")))
  );
}

export function extractScriptCommandsFromContent(options: ExtractScriptContentOptions): ScriptContentExtractionResult {
  const sourcePath = options.path;
  const detection = detectScriptContent(options);
  if (!detection.commandBearing) {
    return { commandBearing: false, commands: [] };
  }

  const uninspectable = uninspectableScriptContent(options.content, options.maxBytes ?? DEFAULT_MAX_SCRIPT_BYTES, sourcePath);
  if (uninspectable) {
    return { commandBearing: true, commands: [], uninspectable };
  }

  if (basename(sourcePath ?? "").toLowerCase() === "package.json") {
    return extractPackageJsonScripts(options.content, sourcePath);
  }

  const commands = extractRecognizedScriptCommands(options, detection.shebangShell);
  if (contentRequiresConfidentInspection(options, sourcePath, detection.shebangShell, commands)) {
    return {
      commandBearing: true,
      commands: [],
      uninspectable: unknownCommandContent("Local executable content is not a recognized text script and cannot be inspected confidently.", sourcePath),
    };
  }

  return { commandBearing: true, commands };
}

interface ScriptContentDetection {
  readonly commandBearing: boolean;
  readonly shebangShell: boolean;
}

function detectScriptContent(options: ExtractScriptContentOptions): ScriptContentDetection {
  const sourcePath = options.path;
  const shebangShell = hasShellShebang(options.content);
  return {
    shebangShell,
    commandBearing: Boolean(
      options.forceCommandBearing ||
        options.shellHint ||
        isCommandBearingPath(sourcePath) ||
        shebangShell ||
        contentHasObviousCommandContext(options.content),
    ),
  };
}

function uninspectableScriptContent(content: string, maxBytes: number, sourcePath: string | undefined): UninspectableScriptContent | undefined {
  const byteLength = Buffer.byteLength(content, "utf8");
  if (byteLength > maxBytes) {
    return unknownCommandContent(`Command-bearing content is too large to inspect safely (${byteLength} bytes).`, sourcePath);
  }
  if (content.includes("\0")) {
    return unknownCommandContent("Command-bearing content appears to be binary and cannot be inspected safely.", sourcePath);
  }
  return undefined;
}

function unknownCommandContent(reason: string, sourcePath: string | undefined): UninspectableScriptContent {
  return {
    reason,
    context: "unknown-command-content",
    ...(sourcePath ? { sourcePath } : {}),
  };
}

function extractRecognizedScriptCommands(options: ExtractScriptContentOptions, shebangShell: boolean): readonly ExtractedScriptCommand[] {
  const sourcePath = options.path;
  if (isMakefilePath(sourcePath)) {
    return extractMakefileRecipes(options.content, sourcePath);
  }
  if (isDockerfilePath(sourcePath)) {
    return extractDockerfileRuns(options.content, sourcePath);
  }
  if (isCiWorkflowPath(sourcePath) || contentHasCiRunBlock(options.content)) {
    return extractCiRunCommands(options.content, sourcePath);
  }
  if (options.shellHint || shebangShell || isShellPath(sourcePath)) {
    return extractShellScriptCommands(options.content, sourcePath);
  }
  return [];
}

function contentRequiresConfidentInspection(
  options: ExtractScriptContentOptions,
  sourcePath: string | undefined,
  shebangShell: boolean,
  commands: readonly ExtractedScriptCommand[],
): boolean {
  return commands.length === 0 && Boolean(options.forceCommandBearing) && !shebangShell && !isShellPath(sourcePath) && !options.shellHint;
}

export function redactedCommandPreview(command: string, maxLength = 160): string {
  const normalized = normalizeCommand(command);
  const redacted = stripAnsiControlSequences(redactSensitiveText(normalized));
  return redacted.length <= maxLength ? redacted : `${redacted.slice(0, Math.max(0, maxLength - 1))}…`;
}

function stripAnsiControlSequences(value: string): string {
  let output = "";
  for (let step = ansiStripStep(value, 0); step.index < value.length; step = ansiStripStep(value, step.nextIndex)) {
    output += step.text;
  }
  return output;
}

function ansiStripStep(value: string, index: number): AnsiStripStep {
  const character = value[index] ?? "";
  if (character !== ANSI_ESCAPE && character !== ANSI_CSI) {
    return { index, nextIndex: index + 1, text: character };
  }

  const endIndex = ansiControlSequenceEndIndex(value, index + 1);
  if (endIndex === undefined) {
    return { index, nextIndex: index + 1, text: character };
  }
  return { index, nextIndex: endIndex + 1, text: "" };
}

function ansiControlSequenceEndIndex(value: string, startIndex: number): number | undefined {
  let index = startIndex;
  while (index < value.length && isAnsiSequenceParameterOrIntermediate(value[index] ?? "")) {
    index += 1;
  }
  return index < value.length && isAnsiFinalByte(value[index] ?? "") ? index : undefined;
}

function isAnsiSequenceParameterOrIntermediate(character: string): boolean {
  return character === "[" || character === "\\" || character === "]" || character === "(" || character === ")" || character === "#" || character === ";" || character === "?" || isAsciiDigit(character);
}

function isAnsiFinalByte(character: string): boolean {
  const codePoint = character.codePointAt(0);
  return codePoint !== undefined && codePoint >= 0x40 && codePoint <= 0x7e;
}

function extractPackageJsonScripts(content: string, sourcePath: string | undefined): ScriptContentExtractionResult {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content) as unknown;
  } catch (error) {
    return {
      commandBearing: true,
      commands: [],
      uninspectable: {
        reason: `package.json scripts could not be parsed safely: ${error instanceof Error ? error.message : String(error)}`,
        context: "package-json-script",
        ...(sourcePath ? { sourcePath } : {}),
      },
    };
  }

  const scripts = isRecord(parsed) && isRecord(parsed.scripts) ? parsed.scripts : undefined;
  if (!scripts) {
    return { commandBearing: true, commands: [] };
  }

  const commands = Object.entries(scripts)
    .filter((entry): entry is [string, string] => typeof entry[1] === "string" && entry[1].trim() !== "")
    .map(([name, command]) => commandRecord(command, findLineNumber(content, JSON.stringify(name)), "package-json-script", `package.json script '${name}'`, sourcePath));

  return { commandBearing: true, commands };
}

function extractMakefileRecipes(content: string, sourcePath: string | undefined): readonly ExtractedScriptCommand[] {
  return splitLines(content).flatMap((line, index) => {
    if (!line.startsWith("\t")) {
      return [];
    }
    const command = trimMakefileRecipePrefix(line).trim();
    return shellLineLooksEvaluable(command) ? [commandRecord(command, index + 1, "makefile-recipe", "Makefile recipe", sourcePath)] : [];
  });
}

function trimMakefileRecipePrefix(line: string): string {
  let index = 1;
  while (index < line.length && isMakefileRecipeDecorator(line[index] ?? "")) {
    index += 1;
  }
  return line.slice(index);
}

function isMakefileRecipeDecorator(character: string): boolean {
  return character === "@" || character === "+" || character === "-";
}

function extractDockerfileRuns(content: string, sourcePath: string | undefined): readonly ExtractedScriptCommand[] {
  const logicalLines = joinContinuationLines(content);
  return logicalLines.flatMap((line) => {
    const command = dockerfileRunCommand(line.text);
    return command ? [commandRecord(command, line.lineStart, "dockerfile-run", "Dockerfile RUN", sourcePath, line.lineEnd)] : [];
  });
}

function dockerfileRunCommand(line: string): string | undefined {
  const trimmed = line.trimStart();
  if (trimmed.slice(0, 3).toLowerCase() !== "run" || !isScriptWhitespace(trimmed[3] ?? "")) {
    return undefined;
  }
  return trimmed.slice(4).trimStart();
}

function extractCiRunCommands(content: string, sourcePath: string | undefined): readonly ExtractedScriptCommand[] {
  const lines = splitLines(content);
  const commands: ExtractedScriptCommand[] = [];
  let index = 0;

  while (index < lines.length) {
    const result = extractCiRunCommandAtLine(lines, index, sourcePath);
    commands.push(...result.commands);
    index = result.nextIndex;
  }

  return commands;
}

function extractCiRunCommandAtLine(
  lines: readonly string[],
  index: number,
  sourcePath: string | undefined,
): { readonly commands: readonly ExtractedScriptCommand[]; readonly nextIndex: number } {
  const line = lines[index] ?? "";
  const header = parseCiRunHeader(line);
  if (!header) {
    return { commands: [], nextIndex: index + 1 };
  }

  const { indent, value } = header;
  if (isYamlBlockScalarHeader(value)) {
    return extractCiRunBlock(lines, index, indent, sourcePath);
  }
  if (value === "") {
    return { commands: [], nextIndex: index + 1 };
  }
  return {
    commands: [commandRecord(unquoteYamlScalar(value), index + 1, "ci-run", "CI run", sourcePath)],
    nextIndex: index + 1,
  };
}

function parseCiRunHeader(line: string): { readonly indent: number; readonly value: string } | undefined {
  const indent = countLeadingSpaces(line);
  let cursor = indent;
  if (line[cursor] === "-") {
    cursor += 1;
    while (isScriptWhitespace(line[cursor] ?? "")) {
      cursor += 1;
    }
  }
  if (line.slice(cursor, cursor + 4) !== "run:") {
    return undefined;
  }
  return { indent, value: line.slice(cursor + 4).trim() };
}

function extractCiRunBlock(
  lines: readonly string[],
  index: number,
  indent: number,
  sourcePath: string | undefined,
): { readonly commands: readonly ExtractedScriptCommand[]; readonly nextIndex: number } {
  const block: string[] = [];
  let blockIndex = index + 1;
  while (blockIndex < lines.length) {
    const blockLine = lines[blockIndex] ?? "";
    if (blockLine.trim() !== "" && countLeadingSpaces(blockLine) <= indent) {
      break;
    }
    block.push(blockLine.slice(Math.min(blockLine.length, indent + 2)));
    blockIndex += 1;
  }
  return {
    commands: extractShellScriptCommands(block.join("\n"), sourcePath, index + 2, "ci-run", "CI run block"),
    nextIndex: blockIndex,
  };
}

function extractShellScriptCommands(
  content: string,
  sourcePath: string | undefined,
  lineOffset = 1,
  context: ScriptContentContext = "shell-script",
  label = "shell script",
): readonly ExtractedScriptCommand[] {
  const commands: ExtractedScriptCommand[] = [];
  const lines = splitLines(content);
  const heredocRanges = findShellHeredocRanges(lines);

  for (const heredoc of heredocRanges) {
    commands.push(...extractShellScriptCommands(heredoc.body.join("\n"), sourcePath, lineOffset + heredoc.bodyStart, "heredoc-shell", "shell heredoc"));
  }

  for (const logicalLine of joinContinuationLines(content)) {
    if (lineIsInsideRanges(logicalLine.lineStart, heredocRanges)) {
      continue;
    }
    const command = stripShellComment(logicalLine.text).trim();
    if (!shellLineLooksEvaluable(command)) {
      continue;
    }
    commands.push(commandRecord(command, lineOffset + logicalLine.lineStart - 1, context, label, sourcePath, lineOffset + logicalLine.lineEnd - 1));
  }

  return commands;
}

interface ShellHeredocRange {
  readonly marker: string;
  readonly start: number;
  readonly bodyStart: number;
  readonly end: number;
  readonly body: readonly string[];
}

function findShellHeredocRanges(lines: readonly string[]): readonly ShellHeredocRange[] {
  const ranges: ShellHeredocRange[] = [];
  let index = 0;

  while (index < lines.length) {
    const range = parseShellHeredocRange(lines, index);
    if (!range) {
      index += 1;
      continue;
    }
    ranges.push(range);
    index = range.end;
  }

  return ranges;
}

function parseShellHeredocRange(lines: readonly string[], index: number): ShellHeredocRange | undefined {
  const marker = shellHeredocMarker(lines[index] ?? "");
  if (!marker) {
    return undefined;
  }
  const body: string[] = [];
  let bodyIndex = index + 1;
  while (bodyIndex < lines.length) {
    const bodyLine = lines[bodyIndex] ?? "";
    if (bodyLine.trim() === marker) {
      return { marker, start: index + 1, bodyStart: index + 1, end: bodyIndex + 1, body };
    }
    body.push(bodyLine);
    bodyIndex += 1;
  }
  return { marker, start: index + 1, bodyStart: index + 1, end: bodyIndex, body };
}

function shellHeredocMarker(line: string): string | undefined {
  const heredocIndex = line.indexOf("<<");
  if (heredocIndex < 0 || !lineStartsShellHeredoc(line.slice(0, heredocIndex))) {
    return undefined;
  }

  let markerStart = heredocIndex + 2;
  if (line[markerStart] === "-") {
    markerStart += 1;
  }
  while (isScriptWhitespace(line[markerStart] ?? "")) {
    markerStart += 1;
  }
  return readHeredocMarker(line, markerStart);
}

function lineStartsShellHeredoc(prefix: string): boolean {
  return tokenizeShellCommand(prefix).some((token) => SHELL_HEREDOC_COMMANDS.has(basename(token).toLowerCase()));
}

const SHELL_HEREDOC_COMMANDS = new Set(["bash", "sh", "zsh"]);

function readHeredocMarker(line: string, startIndex: number): string | undefined {
  const quote = line[startIndex] === "\"" || line[startIndex] === "'" ? line[startIndex] : undefined;
  let index = quote ? startIndex + 1 : startIndex;
  const first = line[index] ?? "";
  if (!isShellIdentifierStart(first)) {
    return undefined;
  }
  let marker = first;
  index += 1;
  while (isShellIdentifierPart(line[index] ?? "")) {
    marker += line[index];
    index += 1;
  }
  return marker;
}

function commandRecord(
  command: string,
  lineStart: number,
  context: ScriptContentContext,
  label: string,
  sourcePath: string | undefined,
  lineEnd = lineStart,
): ExtractedScriptCommand {
  const normalizedCommand = normalizeCommand(command);
  return {
    command,
    normalizedCommand,
    lineStart,
    lineEnd,
    context,
    label,
    preview: redactedCommandPreview(normalizedCommand),
    ...(sourcePath ? { sourcePath } : {}),
  };
}

function joinContinuationLines(content: string): readonly { readonly text: string; readonly lineStart: number; readonly lineEnd: number }[] {
  const joined: { text: string; lineStart: number; lineEnd: number }[] = [];
  let current = "";
  let start = 1;
  const lines = splitLines(content);

  for (const [index, line] of lines.entries()) {
    const lineNumber = index + 1;
    if (current === "") {
      start = lineNumber;
    }
    const trimmedEnd = line.trimEnd();
    if (trimmedEnd.endsWith("\\")) {
      current += `${trimmedEnd.slice(0, -1)} `;
      continue;
    }
    joined.push({ text: `${current}${line}`, lineStart: start, lineEnd: lineNumber });
    current = "";
  }

  if (current !== "") {
    joined.push({ text: current, lineStart: start, lineEnd: lines.length });
  }

  return joined;
}

function shellLineLooksEvaluable(line: string): boolean {
  if (line === "" || line.startsWith("#!")) {
    return false;
  }
  const withoutLeadingDecorators = trimLeadingShellDecorators(line).trim();
  if (withoutLeadingDecorators === "" || withoutLeadingDecorators.startsWith("#")) {
    return false;
  }
  if (isPlainShellAssignment(withoutLeadingDecorators) && !containsShellEvaluationOperator(withoutLeadingDecorators)) {
    return false;
  }
  if (isShellFunctionDeclaration(withoutLeadingDecorators)) {
    return false;
  }
  const firstToken = tokenizeShellCommand(withoutLeadingDecorators)[0]?.toLowerCase();
  return firstToken ? !SHELL_CONTROL_ONLY.has(firstToken) : false;
}

function trimLeadingShellDecorators(line: string): string {
  let index = 0;
  while (line[index] === "@" || line[index] === "+" || line[index] === "-") {
    index += 1;
  }
  return line.slice(index);
}

function isPlainShellAssignment(line: string): boolean {
  const withoutExport = trimLeadingExportKeyword(line);
  const equalsIndex = withoutExport.indexOf("=");
  return equalsIndex > 0 && isShellIdentifier(withoutExport.slice(0, equalsIndex));
}

function trimLeadingExportKeyword(line: string): string {
  if (!line.startsWith("export") || !isScriptWhitespace(line[6] ?? "")) {
    return line;
  }
  return line.slice(6).trimStart();
}

function containsShellEvaluationOperator(value: string): boolean {
  for (const character of value) {
    if (SHELL_EVALUATION_OPERATORS.has(character)) {
      return true;
    }
  }
  return false;
}

const SHELL_EVALUATION_OPERATORS = new Set([";", "&", "|", "`", "$", "(", ")", "<", ">"]);

function isShellFunctionDeclaration(line: string): boolean {
  const openParenIndex = line.indexOf("(");
  if (openParenIndex <= 0 || !isShellIdentifier(line.slice(0, openParenIndex).trim())) {
    return false;
  }
  let cursor = openParenIndex + 1;
  while (isScriptWhitespace(line[cursor] ?? "")) {
    cursor += 1;
  }
  if (line[cursor] !== ")") {
    return false;
  }
  cursor += 1;
  while (isScriptWhitespace(line[cursor] ?? "")) {
    cursor += 1;
  }
  if (line[cursor] === "{") {
    cursor += 1;
    while (isScriptWhitespace(line[cursor] ?? "")) {
      cursor += 1;
    }
  }
  return cursor === line.length;
}

function stripShellComment(line: string): string {
  let quote: '"' | "'" | undefined;
  let escaped = false;
  for (let index = 0; index < line.length; index += 1) {
    const character = line[index];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (character === "\\" && quote !== "'") {
      escaped = true;
      continue;
    }
    if ((character === '"' || character === "'") && !quote) {
      quote = character;
      continue;
    }
    if (character === quote) {
      quote = undefined;
      continue;
    }
    if (character === "#" && !quote && (index === 0 || isScriptWhitespace(line[index - 1] ?? ""))) {
      return line.slice(0, index);
    }
  }
  return line;
}

function normalizeCommand(command: string): string {
  return collapseWhitespace(command.trim());
}

function hasShellShebang(content: string): boolean {
  const firstLine = splitLines(content)[0] ?? "";
  if (!firstLine.startsWith("#!")) {
    return false;
  }
  const parts = splitWhitespace(firstLine.slice(2).trim());
  const executable = basename(parts[0] ?? "").toLowerCase();
  if (SHELL_EXECUTABLE_NAMES.has(executable)) {
    return true;
  }
  return executable === "env" && SHELL_EXECUTABLE_NAMES.has(basename(parts[1] ?? "").toLowerCase());
}

function contentHasObviousCommandContext(content: string): boolean {
  return splitLines(content).some((line) => ciRunLineHasValue(line) || dockerfileRunCommand(line) !== undefined);
}

function contentHasCiRunBlock(content: string): boolean {
  return splitLines(content).some(ciRunLineHasValue);
}

function isShellPath(pathValue: string | undefined): boolean {
  return pathValue ? SHELL_EXTENSIONS.has(extname(pathValue.toLowerCase())) : false;
}

function isMakefilePath(pathValue: string | undefined): boolean {
  const name = basename(pathValue ?? "").toLowerCase();
  return name === "makefile" || name.endsWith(".mk");
}

function isDockerfilePath(pathValue: string | undefined): boolean {
  const name = basename(pathValue ?? "").toLowerCase();
  return name === "dockerfile" || name.startsWith("dockerfile.");
}

function isCiWorkflowPath(pathValue: string | undefined): boolean {
  if (!pathValue) {
    return false;
  }
  const normalized = pathValue.replaceAll("\\", "/").toLowerCase();
  return CI_EXTENSIONS.has(extname(normalized)) && (normalized.includes(".github/workflows/") || normalized.includes("/workflows/"));
}

function findLineNumber(content: string, needle: string): number {
  const index = content.indexOf(needle);
  if (index < 0) {
    return 1;
  }
  return countLineBreaksBefore(content, index) + 1;
}

function countLineBreaksBefore(value: string, endIndex: number): number {
  let count = 0;
  for (let index = 0; index < endIndex; index += 1) {
    if (value[index] === "\n") {
      count += 1;
    }
  }
  return count;
}

function countLeadingSpaces(line: string): number {
  let count = 0;
  while (line[count] === " ") {
    count += 1;
  }
  return count;
}

function isYamlBlockScalarHeader(value: string): boolean {
  const header = stripYamlComment(value).trim();
  if (header === "|" || header === ">") {
    return true;
  }
  if (!header.startsWith("|") && !header.startsWith(">")) {
    return false;
  }
  return isYamlBlockScalarModifier(header.slice(1));
}

function stripYamlComment(value: string): string {
  const commentIndex = value.indexOf("#");
  if (commentIndex < 0) {
    return value;
  }
  return commentIndex === 0 || isScriptWhitespace(value[commentIndex - 1] ?? "") ? value.slice(0, commentIndex) : value;
}

function isYamlBlockScalarModifier(value: string): boolean {
  if (value === "" || value === "+" || value === "-") {
    return true;
  }
  const sign = value.startsWith("+") || value.startsWith("-") ? value[0] : undefined;
  const lastCharacter = value.at(-1);
  const hasTrailingSign = lastCharacter === "+" || lastCharacter === "-";
  let digits = value.slice(0, hasTrailingSign ? -1 : undefined);
  if (sign) {
    digits = value.slice(1);
  }
  const trailingSign = sign ? "" : value.slice(digits.length);
  return (trailingSign === "" || trailingSign === "+" || trailingSign === "-") && (digits === "" || allAsciiDigits(digits));
}

function unquoteYamlScalar(value: string): string {
  if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
    return value.slice(1, -1);
  }
  return value;
}

function ciRunLineHasValue(line: string): boolean {
  const header = parseCiRunHeader(line);
  return header !== undefined && header.value !== "";
}

function splitLines(value: string): string[] {
  return value.split("\n").map((line) => line.endsWith("\r") ? line.slice(0, -1) : line);
}

function splitWhitespace(value: string): string[] {
  const parts: string[] = [];
  let current = "";
  for (const character of value) {
    if (isScriptWhitespace(character)) {
      if (current !== "") {
        parts.push(current);
        current = "";
      }
      continue;
    }
    current += character;
  }
  if (current !== "") {
    parts.push(current);
  }
  return parts;
}

function collapseWhitespace(value: string): string {
  return splitWhitespace(value).join(" ");
}

function isScriptWhitespace(character: string): boolean {
  return character === " " || character === "\t" || character === "\n" || character === "\r" || character === "\f" || character === "\v";
}

function isShellIdentifier(value: string): boolean {
  if (!isShellIdentifierStart(value[0] ?? "")) {
    return false;
  }
  for (let index = 1; index < value.length; index += 1) {
    if (!isShellIdentifierPart(value[index] ?? "")) {
      return false;
    }
  }
  return true;
}

function isShellIdentifierStart(character: string): boolean {
  return character === "_" || isAsciiLetter(character);
}

function isShellIdentifierPart(character: string): boolean {
  return isShellIdentifierStart(character) || isAsciiDigit(character);
}

function allAsciiDigits(value: string): boolean {
  for (const character of value) {
    if (!isAsciiDigit(character)) {
      return false;
    }
  }
  return true;
}

function isAsciiLetter(character: string): boolean {
  const codePoint = character.codePointAt(0);
  return codePoint !== undefined && ((codePoint >= 65 && codePoint <= 90) || (codePoint >= 97 && codePoint <= 122));
}

function isAsciiDigit(character: string): boolean {
  const codePoint = character.codePointAt(0);
  return codePoint !== undefined && codePoint >= 48 && codePoint <= 57;
}

const SHELL_EXECUTABLE_NAMES = new Set(["bash", "sh", "zsh", "ksh"]);

function lineIsInsideRanges(lineNumber: number, ranges: readonly { readonly start: number; readonly end: number }[]): boolean {
  return ranges.some((range) => lineNumber >= range.start && lineNumber <= range.end);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
