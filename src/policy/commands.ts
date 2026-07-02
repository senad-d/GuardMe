import { basename, dirname, join } from "node:path";

import type { PolicyAction, RiskLevel } from "./action.ts";

export type CommandClassificationKind =
  | "hard-denied"
  | "dangerous"
  | "read"
  | "list"
  | "write"
  | "edit"
  | "delete"
  | "move"
  | "rename"
  | "shell"
  | "ambiguous";

export interface CommandClassification {
  readonly rawCommand: string;
  readonly normalizedCommand: string;
  readonly kind: CommandClassificationKind;
  readonly primaryAction: PolicyAction;
  readonly actions: readonly PolicyAction[];
  readonly risk: RiskLevel;
  readonly commandName?: string;
  readonly hardDenied: boolean;
  readonly dangerous: boolean;
  readonly requiresUserDecision: boolean;
  readonly reason: string;
  readonly matchedPatterns: readonly string[];
  readonly targetPaths: readonly string[];
  readonly credentialAccess: boolean;
}

export interface LocalScriptExecution {
  readonly rawPath: string;
  readonly invocation: string;
  readonly shellHint: boolean;
  readonly via: "direct" | "shell-wrapper";
}

export interface PackageScriptExecution {
  readonly rawPath: string;
  readonly invocation: string;
  readonly packageManager: "npm" | "pnpm" | "yarn" | "bun";
  readonly scriptName: string;
}

export type CommandSegmentSourceKind =
  | "top-level"
  | "pipeline"
  | "shell-wrapper"
  | "wrapper"
  | "substitution"
  | "process-substitution"
  | "backtick-substitution"
  | "find-exec"
  | "package-runner";

export interface ExecutableCommandSegment {
  readonly originalText: string;
  readonly normalizedText: string;
  readonly commandName?: string;
  readonly action: PolicyAction;
  readonly actions: readonly PolicyAction[];
  readonly risk: RiskLevel;
  readonly sourceKind: CommandSegmentSourceKind;
  readonly matchedPatterns: readonly string[];
  readonly targetPaths: readonly string[];
  readonly hardDenied: boolean;
  readonly dangerous: boolean;
  readonly requiresUserDecision: boolean;
  readonly reason: string;
  readonly credentialAccess: boolean;
  readonly classification: CommandClassification;
  readonly matchCandidates: readonly string[];
}

interface SegmentClassification extends CommandClassification {
  readonly priority: number;
}

type ShellQuote = "\"" | "'";

interface ShellSubcommand {
  readonly command: string;
  readonly syntax: "command substitution" | "process substitution" | "backtick substitution";
}

interface ShellTokenizerState {
  tokens: string[];
  current: string;
  quote?: ShellQuote;
  ansiCQuote: boolean;
  escaped: boolean;
  index: number;
}

interface ShellOperatorToken {
  readonly token: string;
  readonly nextIndex: number;
}

interface ShellSubcommandScanState {
  subcommands: ShellSubcommand[];
  quote?: ShellQuote;
  escaped: boolean;
  index: number;
}

interface BalancedParenthesisScanState {
  depth: number;
  quote?: ShellQuote;
  escaped: boolean;
  index: number;
}

interface UnwrappedExecutable {
  readonly commandName?: string;
  readonly args: readonly string[];
  readonly innerCommand?: string;
}

interface ClassificationOptions {
  readonly rawCommand: string;
  readonly kind: CommandClassificationKind;
  readonly primaryAction: PolicyAction;
  readonly risk: RiskLevel;
  readonly reason: string;
  readonly matchedPatterns: readonly string[];
  readonly targetPaths: readonly string[];
  readonly hardDenied: boolean;
  readonly dangerous: boolean;
  readonly requiresUserDecision: boolean;
  readonly credentialAccess?: boolean;
}

interface SegmentClassificationContext {
  readonly rawCommand: string;
  readonly commandName?: string;
  readonly args: readonly string[];
  readonly segmentTokens: readonly string[];
  readonly inputRedirectionTargets: readonly string[];
  readonly targetPaths: readonly string[];
  readonly credentialAccess: boolean;
  readonly credentialLiteralAccess: boolean;
  readonly cloudCliLiteralAccess: boolean;
}

interface ExecutableSegmentClassificationContext extends SegmentClassificationContext {
  readonly commandName: string;
}

type SegmentClassificationOptions = Omit<ClassificationOptions, "rawCommand" | "targetPaths"> & {
  readonly targetPaths?: readonly string[];
};

const CLOUD_CLI_COMMANDS = new Set(["aws", "az", "gcloud"]);
const READ_COMMANDS = new Set(["cat", "less", "more", "head", "tail"]);
const GREP_COMMANDS = new Set(["grep", "ggrep"]);
const ADDITIONAL_READ_COMMANDS = new Set(["awk", "base64", "md5sum", "od", "sed", "sha1sum", "sha256sum", "sha512sum", "shasum", "strings", "wc", "xxd"]);
const LIST_COMMANDS = new Set(["ls", "find", "tree"]);
const COPY_COMMANDS = new Set(["cp", "install"]);
const ARCHIVE_COMMANDS = new Set(["7z", "bunzip2", "bzip2", "gunzip", "gzip", "tar", "unxz", "xz", "zip"]);
const WRITE_COMMANDS = new Set(["mkdir", "touch"]);
const METADATA_EDIT_COMMANDS = new Set(["chgrp", "chmod", "chown"]);
const PATH_MUTATION_COMMANDS = new Set(["rm", "rmdir", "mv", "rename", "rsync"]);
const FIND_EXEC_OPTIONS = new Set(["-exec", "-execdir", "-ok", "-okdir"]);
const DISKUTIL_HARD_DENIED_SUBCOMMANDS = new Set(["erasedisk", "partitiondisk", "zerodisk"]);
const TEST_COMMANDS = new Set(["test", "[", "[["]);
const SHELL_WRAPPERS = new Set(["sh", "bash", "zsh"]);
const PREFIX_WRAPPERS = new Set(["command", "builtin", "noglob", "sudo", "doas"]);
const INLINE_CODE_INTERPRETERS = new Set(["node", "perl", "php", "python", "python2", "python3", "ruby"]);
const SHELL_LEADING_CONTROL_WORDS = new Set(["!", "(", "{", "if", "then", "do", "else", "elif", "while", "until", "for", "select", "case"]);
const SHELL_HARD_SEGMENT_BOUNDARY_TOKENS = new Set([";", "&&", "||", "|", "&"]);
const SHELL_COMMAND_POSITION_BOUNDARY_TOKENS = new Set(["(", "{", "then", "do", "else", "elif", "fi", "done", "esac"]);
const SHELL_CLOSING_SEGMENT_BOUNDARY_TOKENS = new Set([")", "}"]);
const OUTPUT_REDIRECTION_TOKENS = new Set([">", ">>", "1>", "1>>", "2>", "2>>", "<>", "0<>"]);
const INPUT_REDIRECTION_TOKENS = new Set(["<", "0<"]);
const REDIRECTION_TOKENS_WITH_TARGET = new Set([
  ...OUTPUT_REDIRECTION_TOKENS,
  ...INPUT_REDIRECTION_TOKENS,
  "<<",
  "0<<",
  "<<<",
  "0<<<",
  ">&",
  "1>&",
  "2>&",
  "<&",
  "0<&",
]);
const ANSI_C_SIMPLE_ESCAPES: Readonly<Record<string, string>> = {
  a: "\x07",
  b: "\b",
  e: "\x1b",
  E: "\x1b",
  f: "\f",
  n: "\n",
  r: "\r",
  t: "\t",
  v: "\v",
  "\\": "\\",
  "'": "'",
  '"': '"',
  "?": "?",
};
const DYNAMIC_EXECUTABLE_NAME_CHARS = new Set(["$", "`", "*", "?", "[", "]", "{", "}"]);
const LOCAL_SCRIPT_EXTENSIONS = new Set([".sh", ".bash", ".zsh", ".command", ".ksh"]);
const PRIVATE_KEY_FILE_NAMES = new Set(["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"]);
const CREDENTIAL_LITERAL_MARKERS = [
  ".npmrc",
  ".pypirc",
  ".netrc",
  ".ssh",
  "id_rsa",
  "id_dsa",
  "id_ecdsa",
  "id_ed25519",
  ".gnupg",
  ".1password",
  ".aws",
  ".azure",
  ".config/gcloud",
  ".docker/config.json",
] as const;

export function classifyShellCommand(command: string): CommandClassification {
  return classifyShellCommandInternal(command, 0);
}

export function commandRuleMatchCandidates(command: string): readonly string[] {
  return commandRuleMatchCandidatesInternal(command, 0);
}

export function commandSegmentRuleMatchCandidates(command: string): readonly string[] {
  const candidates = new Set<string>();
  addCommandRuleCandidate(candidates, command);
  for (const segment of splitCommandSegments(tokenizeShellCommand(command))) {
    const leadingWrapperCommand = leadingWrapperInvokedCommandText(segment);
    if (leadingWrapperCommand) {
      addCommandRuleCandidate(candidates, leadingWrapperCommand);
    }
  }
  return [...candidates];
}

export function extractExecutableCommandSegments(command: string): readonly ExecutableCommandSegment[] {
  return uniqueExecutableCommandSegments(extractExecutableCommandSegmentsInternal(command, 0, "top-level"));
}

export function detectLocalScriptExecutions(command: string): readonly LocalScriptExecution[] {
  return detectLocalScriptExecutionsInternal(command, 0);
}

export function detectPackageScriptExecutions(command: string): readonly PackageScriptExecution[] {
  return detectPackageScriptExecutionsInternal(command, 0);
}

function detectLocalScriptExecutionsInternal(command: string, depth: number): readonly LocalScriptExecution[] {
  const executions: LocalScriptExecution[] = [];
  for (const segment of splitCommandSegments(tokenizeShellCommand(command))) {
    const unwrapped = unwrapExecutable(segment);
    if (unwrapped.innerCommand && depth < 5) {
      executions.push(...detectLocalScriptExecutionsInternal(unwrapped.innerCommand, depth + 1));
    }
    const execution = localScriptExecutionFromSegment(segment);
    if (execution) {
      executions.push(execution);
    }
  }
  return uniqueLocalScriptExecutions(executions);
}

function detectPackageScriptExecutionsInternal(command: string, depth: number): readonly PackageScriptExecution[] {
  const executions: PackageScriptExecution[] = [];
  for (const segment of splitCommandSegments(tokenizeShellCommand(command))) {
    const unwrapped = unwrapExecutable(segment);
    if (unwrapped.innerCommand && depth < 5) {
      executions.push(...detectPackageScriptExecutionsInternal(unwrapped.innerCommand, depth + 1));
    }
    const execution = packageScriptExecutionFromSegment(segment);
    if (execution) {
      executions.push(execution);
    }
  }
  return uniquePackageScriptExecutions(executions);
}

function classifyShellCommandInternal(command: string, depth: number): CommandClassification {
  const tokens = tokenizeShellCommand(command);
  if (tokens.length === 0) {
    return classification({
      rawCommand: command,
      kind: "shell",
      primaryAction: "shell",
      risk: "low",
      reason: "Empty shell command.",
      matchedPatterns: [],
      targetPaths: [],
      hardDenied: false,
      dangerous: false,
      requiresUserDecision: false,
    });
  }

  const nestedClassifications = depth >= 5
    ? []
    : extractExecutableShellSubcommands(command).map((subcommand) =>
        withPriority(rebaseNestedClassification(command, subcommand, classifyShellCommandInternal(subcommand.command, depth + 1))),
      );
  const segments = splitCommandSegments(tokens);
  const classifications = [...nestedClassifications, ...segments.map((segment) => classifySegment(command, segment, depth))];
  const selected = [...classifications].sort((left, right) => right.priority - left.priority)[0];
  return selected
    ? aggregateCommandClassification(command, selected, classifications)
    : classification({
        rawCommand: command,
        kind: "shell",
        primaryAction: "shell",
        risk: "low",
        reason: "No classifiable shell command found.",
        matchedPatterns: [],
        targetPaths: [],
        hardDenied: false,
        dangerous: false,
        requiresUserDecision: false,
      });
}

function extractExecutableCommandSegmentsInternal(
  command: string,
  depth: number,
  sourceKind: CommandSegmentSourceKind,
): readonly ExecutableCommandSegment[] {
  if (depth >= 6) {
    return [];
  }

  const tokens = tokenizeShellCommand(command);
  if (tokens.length === 0) {
    return [];
  }

  const executableSegments: ExecutableCommandSegment[] = [];
  for (const subcommand of extractExecutableShellSubcommands(command)) {
    executableSegments.push(
      ...extractExecutableCommandSegmentsInternal(subcommand.command, depth + 1, sourceKindForSubcommand(subcommand)),
    );
  }

  for (const segmentTokens of splitCommandSegments(tokens)) {
    const segmentText = joinTokensAsRuleCommand(segmentTokens);
    if (!segmentText) {
      continue;
    }

    const unwrapped = unwrapExecutable(segmentTokens);
    if (unwrapped.innerCommand) {
      executableSegments.push(...extractExecutableCommandSegmentsInternal(unwrapped.innerCommand, depth + 1, "shell-wrapper"));
      continue;
    }

    const classified = classifySegment(segmentText, segmentTokens, depth);
    if (classified.commandName || classified.matchedPatterns.length > 0) {
      executableSegments.push(executableSegmentFromClassification(classified, segmentText, sourceKind));
    }

    const wrapperCommandName = unwrapped.commandName;
    const wrapperCommand = wrapperCommandName ? wrapperInvokedCommandText(wrapperCommandName, unwrapped.args) : undefined;
    if (wrapperCommand && wrapperCommandName) {
      executableSegments.push(
        ...extractExecutableCommandSegmentsInternal(
          wrapperCommand,
          depth + 1,
          sourceKindForWrapper(wrapperCommandName),
        ),
      );
    }
  }

  return executableSegments;
}

function executableSegmentFromClassification(
  classified: SegmentClassification,
  originalText: string,
  sourceKind: CommandSegmentSourceKind,
): ExecutableCommandSegment {
  const { priority: _priority, ...classificationWithoutPriority } = classified;
  const normalizedText = normalizeCommandText(classificationWithoutPriority.rawCommand || originalText);
  return {
    originalText,
    normalizedText,
    ...(classificationWithoutPriority.commandName ? { commandName: classificationWithoutPriority.commandName } : {}),
    action: classificationWithoutPriority.primaryAction,
    actions: classificationWithoutPriority.actions,
    risk: classificationWithoutPriority.risk,
    sourceKind,
    matchedPatterns: classificationWithoutPriority.matchedPatterns,
    targetPaths: classificationWithoutPriority.targetPaths,
    hardDenied: classificationWithoutPriority.hardDenied,
    dangerous: classificationWithoutPriority.dangerous,
    requiresUserDecision: classificationWithoutPriority.requiresUserDecision,
    reason: classificationWithoutPriority.reason,
    credentialAccess: classificationWithoutPriority.credentialAccess,
    classification: classificationWithoutPriority,
    matchCandidates: commandSegmentRuleMatchCandidates(normalizedText),
  };
}

function sourceKindForSubcommand(subcommand: ShellSubcommand): CommandSegmentSourceKind {
  if (subcommand.syntax === "process substitution") {
    return "process-substitution";
  }
  if (subcommand.syntax === "backtick substitution") {
    return "backtick-substitution";
  }
  return "substitution";
}

function sourceKindForWrapper(commandName: string): CommandSegmentSourceKind {
  if (commandName === "find") {
    return "find-exec";
  }
  if (commandName === "npx" || commandName === "bunx" || commandName === "npm" || commandName === "pnpm" || commandName === "yarn" || commandName === "bun") {
    return "package-runner";
  }
  return "wrapper";
}

function uniqueExecutableCommandSegments(segments: readonly ExecutableCommandSegment[]): readonly ExecutableCommandSegment[] {
  const seen = new Set<string>();
  return segments.filter((segment) => {
    const key = `${segment.sourceKind}\u0000${segment.normalizedText}\u0000${segment.action}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

export function tokenizeShellCommand(command: string): readonly string[] {
  const state = createShellTokenizerState();
  while (state.index < command.length) {
    advanceShellTokenizer(command, state);
  }
  pushShellTokenizerCurrent(state);
  return state.tokens;
}

function createShellTokenizerState(): ShellTokenizerState {
  return { tokens: [], current: "", ansiCQuote: false, escaped: false, index: 0 };
}

function advanceShellTokenizer(command: string, state: ShellTokenizerState): void {
  const character = command[state.index] ?? "";
  if (consumeEscapedShellCharacter(state, character)) {
    return;
  }
  if (consumeAnsiCShellEscape(command, state, character)) {
    return;
  }
  if (consumeShellEscapeStart(command, state, character)) {
    return;
  }
  if (consumeShellQuoteBoundary(state, character)) {
    return;
  }
  if (consumeShellLineSeparator(command, state, character)) {
    return;
  }
  if (consumeShellWhitespace(state, character)) {
    return;
  }
  if (consumeAnsiCQuotePrefix(command, state, character)) {
    return;
  }
  if (consumeShellOperatorToken(command, state, character)) {
    return;
  }

  state.current += character;
  state.index += 1;
}

function consumeEscapedShellCharacter(state: ShellTokenizerState, character: string): boolean {
  if (!state.escaped) {
    return false;
  }
  state.current += escapedShellOperatorToken(character, state.current);
  state.escaped = false;
  state.index += 1;
  return true;
}

function consumeAnsiCShellEscape(command: string, state: ShellTokenizerState, character: string): boolean {
  if (state.quote !== "'" || !state.ansiCQuote || character !== "\\") {
    return false;
  }
  const parsed = readAnsiCEscape(command, state.index);
  state.current += parsed.value;
  state.index = parsed.endIndex + 1;
  return true;
}

function consumeShellEscapeStart(command: string, state: ShellTokenizerState, character: string): boolean {
  if (character !== "\\" || state.quote === "'") {
    return false;
  }
  const next = command[state.index + 1];
  if (next && isShellLineSeparator(next)) {
    state.index += next === "\r" && command[state.index + 2] === "\n" ? 3 : 2;
    return true;
  }
  state.escaped = true;
  state.index += 1;
  return true;
}

function consumeShellQuoteBoundary(state: ShellTokenizerState, character: string): boolean {
  if (isShellQuote(character) && !state.quote) {
    state.quote = character;
    state.ansiCQuote = false;
    state.index += 1;
    return true;
  }
  if (character === state.quote) {
    state.quote = undefined;
    state.ansiCQuote = false;
    state.index += 1;
    return true;
  }
  return false;
}

function consumeShellLineSeparator(command: string, state: ShellTokenizerState, character: string): boolean {
  if (state.quote || !isShellLineSeparator(character)) {
    return false;
  }
  pushShellTokenizerCurrent(state);
  if (state.tokens.at(-1) !== ";") {
    state.tokens.push(";");
  }
  state.index += character === "\r" && command[state.index + 1] === "\n" ? 2 : 1;
  return true;
}

function consumeShellWhitespace(state: ShellTokenizerState, character: string): boolean {
  if (state.quote || !isShellWhitespace(character)) {
    return false;
  }
  pushShellTokenizerCurrent(state);
  state.index += 1;
  return true;
}

function consumeAnsiCQuotePrefix(command: string, state: ShellTokenizerState, character: string): boolean {
  const quote = command[state.index + 1];
  if (state.quote || character !== "$" || !isShellQuote(quote)) {
    return false;
  }
  state.quote = quote;
  state.ansiCQuote = quote === "'";
  state.index += 2;
  return true;
}

function consumeShellOperatorToken(command: string, state: ShellTokenizerState, character: string): boolean {
  if (state.quote || !isShellOperatorStart(character, command[state.index + 1])) {
    return false;
  }
  pushShellTokenizerCurrent(state);
  const operator = readShellOperatorToken(command, state.index);
  state.tokens.push(operator.token);
  state.index = operator.nextIndex;
  return true;
}

function readShellOperatorToken(command: string, index: number): ShellOperatorToken {
  const character = command[index] ?? "";
  const next = command[index + 1];
  if (isRepeatedShellOperator(character, next)) {
    return { token: `${character}${next}`, nextIndex: index + 2 };
  }
  if (character === ">" && next === "&") {
    return { token: ">&", nextIndex: index + 2 };
  }
  if (character === "<" && next === "<") {
    return readHereDocumentOperator(command, index);
  }
  if (character === "<" && (next === ">" || next === "&")) {
    return { token: `<${next}`, nextIndex: index + 2 };
  }
  if (isFileDescriptorRedirectionStart(character, next)) {
    return readFileDescriptorRedirectionOperator(command, index);
  }
  return { token: character, nextIndex: index + 1 };
}

function readHereDocumentOperator(command: string, index: number): ShellOperatorToken {
  return command[index + 2] === "<"
    ? { token: "<<<", nextIndex: index + 3 }
    : { token: "<<", nextIndex: index + 2 };
}

function readFileDescriptorRedirectionOperator(command: string, index: number): ShellOperatorToken {
  const character = command[index] ?? "";
  const next = command[index + 1] ?? "";
  const afterNext = command[index + 2];
  const tokenLength = afterNext === next || afterNext === "&" || (character === "0" && afterNext === ">") ? 3 : 2;
  return { token: command.slice(index, index + tokenLength), nextIndex: index + tokenLength };
}

function pushShellTokenizerCurrent(state: ShellTokenizerState): void {
  if (state.current !== "") {
    state.tokens.push(state.current);
    state.current = "";
  }
}

function isShellQuote(character: string | undefined): character is ShellQuote {
  return character === '"' || character === "'";
}

function isShellWhitespace(character: string): boolean {
  return character.trim() === "";
}

function isRepeatedShellOperator(character: string, next: string | undefined): boolean {
  return (character === ">" || character === "&" || character === "|") && next === character;
}

function isFileDescriptorRedirectionStart(character: string, next: string | undefined): boolean {
  return (character === "0" && next === "<") || ((character === "1" || character === "2") && next === ">");
}

function readAnsiCEscape(command: string, backslashIndex: number): { readonly value: string; readonly endIndex: number } {
  const escapeIndex = backslashIndex + 1;
  const escape = command[escapeIndex];
  if (escape === undefined) {
    return { value: "\\", endIndex: backslashIndex };
  }

  const simple = ANSI_C_SIMPLE_ESCAPES[escape];
  if (simple !== undefined) {
    return { value: simple, endIndex: escapeIndex };
  }

  if (escape === "x") {
    return readHexEscape(command, escapeIndex, 2);
  }
  if (escape === "u") {
    return readHexEscape(command, escapeIndex, 4);
  }
  if (escape === "U") {
    return readHexEscape(command, escapeIndex, 8);
  }
  if (isAsciiOctalDigit(escape)) {
    return readOctalEscape(command, escapeIndex);
  }
  if (escape === "c" && command[escapeIndex + 1]) {
    return { value: String.fromCodePoint((command.codePointAt(escapeIndex + 1) ?? 64) & 0x1f), endIndex: escapeIndex + 1 };
  }

  return { value: `\\${escape}`, endIndex: escapeIndex };
}

function readHexEscape(command: string, markerIndex: number, maxDigits: number): { readonly value: string; readonly endIndex: number } {
  let digits = "";
  let index = markerIndex + 1;
  while (digits.length < maxDigits && isAsciiHexDigit(command[index] ?? "")) {
    digits += command[index];
    index += 1;
  }
  if (digits.length === 0) {
    return { value: command.slice(markerIndex - 1, markerIndex + 1), endIndex: markerIndex };
  }
  return codePointEscapeValue(digits, 16, index - 1, command.slice(markerIndex - 1, index));
}

function readOctalEscape(command: string, firstDigitIndex: number): { readonly value: string; readonly endIndex: number } {
  let digits = "";
  let index = firstDigitIndex;
  while (digits.length < 3 && isAsciiOctalDigit(command[index] ?? "")) {
    digits += command[index];
    index += 1;
  }
  return codePointEscapeValue(digits, 8, index - 1, command.slice(firstDigitIndex - 1, index));
}

function codePointEscapeValue(
  digits: string,
  radix: number,
  endIndex: number,
  fallbackValue: string,
): { readonly value: string; readonly endIndex: number } {
  const codePoint = Number.parseInt(digits, radix);
  try {
    return { value: String.fromCodePoint(codePoint), endIndex };
  } catch {
    return { value: fallbackValue, endIndex };
  }
}

function classifySegment(rawCommand: string, segmentTokens: readonly string[], depth: number): SegmentClassification {
  const unwrapped = unwrapExecutable(segmentTokens);
  if (unwrapped.innerCommand) {
    return withPriority(classifyShellCommandInternal(unwrapped.innerCommand, depth + 1));
  }

  const context = createSegmentClassificationContext(rawCommand, segmentTokens, unwrapped);
  if (!hasExecutableSegmentContext(context)) {
    return withPriority(noExecutableClassification(rawCommand));
  }

  const preWrapperClassification = classifyPreWrapperSegment(context);
  if (preWrapperClassification) {
    return withPriority(preWrapperClassification);
  }

  const wrapperClassification = depth < 5 ? riskyWrapperCommandClassification(rawCommand, context.commandName, context.args, depth) : undefined;
  if (wrapperClassification) {
    return withPriority(wrapperClassification);
  }

  const classified = classifyPostWrapperSegment(context) ?? genericShellClassification(context);
  return withPriority(classified);
}

function createSegmentClassificationContext(
  rawCommand: string,
  segmentTokens: readonly string[],
  unwrapped: UnwrappedExecutable,
): SegmentClassificationContext {
  const commandName = unwrapped.commandName;
  const args = unwrapped.args;
  const inputRedirectionTargets = extractInputRedirectionTargets(segmentTokens);
  const targetPaths = uniqueStrings([...extractLikelyPathOperands(commandName, args, segmentTokens), ...inputRedirectionTargets]);
  const credentialAccess = targetPaths.some(isCredentialLikePath);
  const inlineCode = inlineCodeSnippets(commandName, args);
  return {
    rawCommand,
    ...(commandName ? { commandName } : {}),
    args,
    segmentTokens,
    inputRedirectionTargets,
    targetPaths,
    credentialAccess,
    credentialLiteralAccess: !credentialAccess && args.some(containsCredentialLikeLiteral),
    cloudCliLiteralAccess: inlineCode.some(containsCloudCliLiteral),
  };
}

function hasExecutableSegmentContext(context: SegmentClassificationContext): context is ExecutableSegmentClassificationContext {
  return typeof context.commandName === "string" && context.commandName !== "";
}

function noExecutableClassification(rawCommand: string): CommandClassification {
  return classification({
    rawCommand,
    kind: "shell",
    primaryAction: "shell",
    risk: "low",
    reason: "No executable found.",
    matchedPatterns: [],
    targetPaths: [],
    hardDenied: false,
    dangerous: false,
    requiresUserDecision: false,
  });
}

function classifyPreWrapperSegment(context: ExecutableSegmentClassificationContext): CommandClassification | undefined {
  if (TEST_COMMANDS.has(context.commandName)) {
    return shellTestClassification(context);
  }
  if (isDynamicExecutableName(context.commandName)) {
    return segmentClassification(context, {
      kind: "hard-denied",
      primaryAction: "shell",
      risk: "hard-denied",
      reason: "Shell-expanded command names are denied because GuardMe cannot safely classify the executable.",
      matchedPatterns: [context.commandName],
      hardDenied: true,
      dangerous: true,
      requiresUserDecision: false,
    });
  }
  if (CLOUD_CLI_COMMANDS.has(context.commandName)) {
    return segmentClassification(context, {
      kind: "hard-denied",
      primaryAction: "shell",
      risk: "hard-denied",
      reason: `Cloud CLI '${context.commandName}' is always denied by GuardMe.`,
      matchedPatterns: [context.commandName],
      hardDenied: true,
      dangerous: true,
      requiresUserDecision: false,
    });
  }
  if (context.cloudCliLiteralAccess) {
    return segmentClassification(context, {
      kind: "hard-denied",
      primaryAction: "shell",
      risk: "hard-denied",
      reason: "Inline code invokes a cloud CLI that GuardMe always denies.",
      matchedPatterns: ["cloud-cli-inline-code"],
      hardDenied: true,
      dangerous: true,
      requiresUserDecision: false,
    });
  }
  return undefined;
}

function shellTestClassification(context: ExecutableSegmentClassificationContext): CommandClassification {
  return segmentClassification(context, {
    kind: "list",
    primaryAction: "list",
    risk: context.credentialAccess ? "dangerous" : "low",
    reason: "Shell test inspects path existence or metadata.",
    matchedPatterns: [context.commandName],
    hardDenied: false,
    dangerous: context.credentialAccess,
    requiresUserDecision: context.credentialAccess,
    credentialAccess: context.credentialAccess,
  });
}

function classifyPostWrapperSegment(context: ExecutableSegmentClassificationContext): CommandClassification | undefined {
  return (
    classifyGuardedSegment(context) ??
    classifyMutationSegment(context) ??
    classifyReadListSegment(context) ??
    classifyAmbiguousSegment(context)
  );
}

function classifyGuardedSegment(context: ExecutableSegmentClassificationContext): CommandClassification | undefined {
  const diskReason = hardDeniedDiskReason(context.commandName, context.args);
  if (diskReason) {
    return segmentClassification(context, {
      kind: "hard-denied",
      primaryAction: "shell",
      risk: "hard-denied",
      reason: diskReason,
      matchedPatterns: [context.commandName],
      hardDenied: true,
      dangerous: true,
      requiresUserDecision: false,
    });
  }
  if (context.commandName === "dd") {
    return filesystemMutationClassification(context, "write", "dd copies between file operands.", [context.commandName]);
  }
  if (context.credentialAccess && isReadLikeCommand(context.commandName)) {
    return segmentClassification(context, {
      kind: "hard-denied",
      primaryAction: "read",
      risk: "hard-denied",
      reason: "Credential-like file read detected.",
      matchedPatterns: ["credential-read"],
      hardDenied: true,
      dangerous: true,
      requiresUserDecision: false,
      credentialAccess: true,
    });
  }
  if (context.credentialLiteralAccess) {
    return segmentClassification(context, {
      kind: "hard-denied",
      primaryAction: "read",
      risk: "hard-denied",
      reason: "Credential-like file reference detected in shell command.",
      matchedPatterns: ["credential-literal"],
      hardDenied: true,
      dangerous: true,
      requiresUserDecision: false,
      credentialAccess: true,
    });
  }
  return outputRedirectionClassification(context);
}

function outputRedirectionClassification(context: ExecutableSegmentClassificationContext): CommandClassification | undefined {
  const outputRedirectionTargets = extractOutputRedirectionTargets(context.segmentTokens);
  if (outputRedirectionTargets.length === 0) {
    return undefined;
  }
  const targetPaths = uniqueStrings([...context.inputRedirectionTargets, ...outputRedirectionTargets]);
  return segmentClassification(context, {
    kind: "write",
    primaryAction: "write",
    risk: mutationRisk(targetPaths),
    reason: "Shell redirection writes to a file.",
    matchedPatterns: ["redirection"],
    targetPaths,
    hardDenied: false,
    dangerous: isOutsideishMutation(targetPaths),
    requiresUserDecision: isOutsideishMutation(targetPaths),
  });
}

function classifyMutationSegment(context: ExecutableSegmentClassificationContext): CommandClassification | undefined {
  if (context.commandName === "rm") {
    return rmCommandClassification(context);
  }
  if (context.commandName === "rmdir") {
    return deleteCommandClassification(context, "Directory deletion command detected.", ["rmdir"]);
  }
  if (context.commandName === "mv" || context.commandName === "rename") {
    return moveOrRenameClassification(context);
  }
  if (context.commandName === "rsync" && hasRsyncDeleteOption(context.args)) {
    return dangerousDeleteClassification(context, "rsync --delete may remove files and requires user approval.", ["rsync --delete"]);
  }
  if (context.commandName === "find" && context.args.includes("-delete")) {
    return dangerousDeleteClassification(context, "find -delete may remove files and requires user approval.", ["find -delete"]);
  }
  return classifyFilesystemMutationCommand(context);
}

function classifyFilesystemMutationCommand(context: ExecutableSegmentClassificationContext): CommandClassification | undefined {
  if (COPY_COMMANDS.has(context.commandName)) {
    return filesystemMutationClassification(context, "write", `${context.commandName} copies file operands.`, [context.commandName]);
  }
  if (ARCHIVE_COMMANDS.has(context.commandName)) {
    return filesystemMutationClassification(context, "write", `${context.commandName} archives or extracts file operands.`, [context.commandName]);
  }
  if (WRITE_COMMANDS.has(context.commandName)) {
    return filesystemMutationClassification(context, "write", `${context.commandName} writes filesystem paths.`, [context.commandName]);
  }
  if (METADATA_EDIT_COMMANDS.has(context.commandName)) {
    return filesystemMutationClassification(context, "edit", `${context.commandName} mutates filesystem metadata.`, [context.commandName]);
  }
  if (context.commandName === "sed" && context.args.some((arg) => arg === "-i" || arg.startsWith("-i"))) {
    return segmentClassification(context, {
      kind: "edit",
      primaryAction: "edit",
      risk: mutationRisk(context.targetPaths),
      reason: "In-place sed edit detected.",
      matchedPatterns: ["sed -i"],
      hardDenied: false,
      dangerous: isOutsideishMutation(context.targetPaths),
      requiresUserDecision: isOutsideishMutation(context.targetPaths),
    });
  }
  if (context.commandName === "tee") {
    return filesystemMutationClassification(context, "write", "tee writes to file operands.", ["tee"]);
  }
  return undefined;
}

function rmCommandClassification(context: ExecutableSegmentClassificationContext): CommandClassification {
  if (context.targetPaths.some(isGitPath)) {
    return segmentClassification(context, {
      kind: "hard-denied",
      primaryAction: "delete",
      risk: "hard-denied",
      reason: "Deleting .git metadata is denied.",
      matchedPatterns: [".git-delete"],
      hardDenied: true,
      dangerous: true,
      requiresUserDecision: false,
    });
  }
  if (isRecursiveForceRm(context.args)) {
    return segmentClassification(context, {
      kind: "dangerous",
      primaryAction: "delete",
      risk: "dangerous",
      reason: "Recursive force deletion requires coaching or user approval.",
      matchedPatterns: ["rm -rf"],
      hardDenied: false,
      dangerous: true,
      requiresUserDecision: true,
    });
  }
  return deleteCommandClassification(context, "File deletion command detected.", ["rm"]);
}

function moveOrRenameClassification(context: ExecutableSegmentClassificationContext): CommandClassification {
  const primaryAction: PolicyAction = context.commandName === "rename" || looksLikeRename(context.targetPaths) ? "rename" : "move";
  const actionLabel = primaryAction === "rename" ? "Rename" : "Move";
  return segmentClassification(context, {
    kind: primaryAction,
    primaryAction,
    risk: mutationRisk(context.targetPaths),
    reason: `${actionLabel} command detected.`,
    matchedPatterns: [context.commandName],
    hardDenied: false,
    dangerous: isOutsideishMutation(context.targetPaths),
    requiresUserDecision: isOutsideishMutation(context.targetPaths),
  });
}

function filesystemMutationClassification(
  context: ExecutableSegmentClassificationContext,
  primaryAction: Extract<PolicyAction, "write" | "edit">,
  reason: string,
  matchedPatterns: readonly string[],
): CommandClassification {
  const dangerous = context.credentialAccess || isOutsideishMutation(context.targetPaths);
  return segmentClassification(context, {
    kind: primaryAction,
    primaryAction,
    risk: context.credentialAccess ? "dangerous" : mutationRisk(context.targetPaths),
    reason,
    matchedPatterns,
    hardDenied: false,
    dangerous,
    requiresUserDecision: dangerous,
    credentialAccess: context.credentialAccess,
  });
}

function deleteCommandClassification(
  context: ExecutableSegmentClassificationContext,
  reason: string,
  matchedPatterns: readonly string[],
): CommandClassification {
  return segmentClassification(context, {
    kind: "delete",
    primaryAction: "delete",
    risk: mutationRisk(context.targetPaths),
    reason,
    matchedPatterns,
    hardDenied: false,
    dangerous: isOutsideishMutation(context.targetPaths),
    requiresUserDecision: isOutsideishMutation(context.targetPaths),
  });
}

function dangerousDeleteClassification(
  context: ExecutableSegmentClassificationContext,
  reason: string,
  matchedPatterns: readonly string[],
): CommandClassification {
  return segmentClassification(context, {
    kind: "dangerous",
    primaryAction: "delete",
    risk: "dangerous",
    reason,
    matchedPatterns,
    hardDenied: false,
    dangerous: true,
    requiresUserDecision: true,
  });
}

function classifyReadListSegment(context: ExecutableSegmentClassificationContext): CommandClassification | undefined {
  if (GREP_COMMANDS.has(context.commandName) || READ_COMMANDS.has(context.commandName) || ADDITIONAL_READ_COMMANDS.has(context.commandName)) {
    return readCommandClassification(context);
  }
  if (LIST_COMMANDS.has(context.commandName)) {
    return segmentClassification(context, {
      kind: "list",
      primaryAction: "list",
      risk: context.credentialAccess ? "dangerous" : "low",
      reason: `${context.commandName} lists or discovers files.`,
      matchedPatterns: [context.commandName],
      hardDenied: false,
      dangerous: context.credentialAccess,
      requiresUserDecision: context.credentialAccess,
      credentialAccess: context.credentialAccess,
    });
  }
  return undefined;
}

function readCommandClassification(context: ExecutableSegmentClassificationContext): CommandClassification {
  return segmentClassification(context, {
    kind: "read",
    primaryAction: "read",
    risk: context.credentialAccess ? "dangerous" : "low",
    reason: `${context.commandName} reads file operands.`,
    matchedPatterns: [context.commandName],
    hardDenied: false,
    dangerous: context.credentialAccess,
    requiresUserDecision: context.credentialAccess,
    credentialAccess: context.credentialAccess,
  });
}

function classifyAmbiguousSegment(context: ExecutableSegmentClassificationContext): CommandClassification | undefined {
  if (!looksDestructiveButAmbiguous(context.commandName, context.args)) {
    return undefined;
  }
  return segmentClassification(context, {
    kind: "ambiguous",
    primaryAction: "shell",
    risk: "dangerous",
    reason: "Ambiguous destructive shell command requires user approval.",
    matchedPatterns: [context.commandName],
    hardDenied: false,
    dangerous: true,
    requiresUserDecision: true,
  });
}

function genericShellClassification(context: ExecutableSegmentClassificationContext): CommandClassification {
  return segmentClassification(context, {
    kind: "shell",
    primaryAction: "shell",
    risk: outsideishTargetPresent(context.targetPaths) ? "medium" : "low",
    reason: "Generic shell command detected.",
    matchedPatterns: [context.commandName],
    hardDenied: false,
    dangerous: false,
    requiresUserDecision: false,
  });
}

function segmentClassification(context: SegmentClassificationContext, options: SegmentClassificationOptions): CommandClassification {
  const { targetPaths = context.targetPaths, ...classificationOptions } = options;
  return classification({ rawCommand: context.rawCommand, targetPaths, ...classificationOptions });
}

function classification(options: ClassificationOptions): CommandClassification {
  const {
    rawCommand,
    kind,
    primaryAction,
    risk,
    reason,
    matchedPatterns,
    targetPaths,
    hardDenied,
    dangerous,
    requiresUserDecision,
    credentialAccess = false,
  } = options;

  return {
    rawCommand,
    normalizedCommand: normalizeCommandText(rawCommand),
    kind,
    primaryAction,
    actions: [primaryAction],
    risk,
    commandName: matchedPatterns[0],
    hardDenied,
    dangerous,
    requiresUserDecision,
    reason,
    matchedPatterns,
    targetPaths,
    credentialAccess,
  };
}

function commandRuleMatchCandidatesInternal(command: string, depth: number): readonly string[] {
  const candidates = new Set<string>();
  addCommandRuleCandidate(candidates, command);

  if (depth < 5) {
    addNestedCommandRuleCandidates(candidates, command, depth);
  }

  return [...candidates];
}

function addNestedCommandRuleCandidates(candidates: Set<string>, command: string, depth: number): void {
  for (const subcommand of extractExecutableShellSubcommands(command)) {
    addCommandRuleCandidatesFromNestedCommand(candidates, subcommand.command, depth);
  }
  for (const segment of splitCommandSegments(tokenizeShellCommand(command))) {
    addSegmentCommandRuleCandidates(candidates, segment, depth);
  }
}

function addSegmentCommandRuleCandidates(candidates: Set<string>, segment: readonly string[], depth: number): void {
  const segmentText = joinTokensAsRuleCommand(segment);
  if (segmentText) {
    addCommandRuleCandidate(candidates, segmentText);
  }

  const leadingWrapperCommand = leadingWrapperInvokedCommandText(segment);
  if (leadingWrapperCommand) {
    addCommandRuleCandidatesFromNestedCommand(candidates, leadingWrapperCommand, depth);
  }

  const unwrapped = unwrapExecutable(segment);
  if (unwrapped.innerCommand) {
    addCommandRuleCandidatesFromNestedCommand(candidates, unwrapped.innerCommand, depth);
  }
  addWrapperCommandRuleCandidates(candidates, unwrapped, depth);
}

function addWrapperCommandRuleCandidates(candidates: Set<string>, unwrapped: UnwrappedExecutable, depth: number): void {
  if (!unwrapped.commandName) {
    return;
  }
  const wrapperCommand = wrapperInvokedCommandText(unwrapped.commandName, unwrapped.args);
  if (wrapperCommand) {
    addCommandRuleCandidatesFromNestedCommand(candidates, wrapperCommand, depth);
  }
}

function addCommandRuleCandidatesFromNestedCommand(candidates: Set<string>, command: string, depth: number): void {
  for (const candidate of commandRuleMatchCandidatesInternal(command, depth + 1)) {
    addCommandRuleCandidate(candidates, candidate);
  }
}

function leadingWrapperInvokedCommandText(tokens: readonly string[]): string | undefined {
  let index = 0;
  while (index < tokens.length && isEnvAssignment(tokens[index] ?? "")) {
    index += 1;
  }
  while (index < tokens.length && SHELL_LEADING_CONTROL_WORDS.has(basename(tokens[index] ?? "").toLowerCase())) {
    index += 1;
  }

  const commandName = basename(tokens[index] ?? "").toLowerCase();
  if (commandName === "env") {
    const env = unwrapEnv(tokens, index + 1);
    if (env.innerCommand) {
      return env.innerCommand;
    }
    return env.index < tokens.length ? joinTokensAsCommand(tokens.slice(env.index)) : undefined;
  }

  if (commandName === "command" || commandName === "builtin" || commandName === "noglob") {
    const commandIndex = skipPrefixWrapper(commandName, tokens, index + 1);
    return commandIndex < tokens.length ? joinTokensAsCommand(tokens.slice(commandIndex)) : undefined;
  }

  return undefined;
}

function addCommandRuleCandidate(candidates: Set<string>, command: string): void {
  const normalized = normalizeCommandText(command);
  if (normalized === "") {
    return;
  }

  candidates.add(normalized);
  const basenameCandidate = basenameExecutableRuleCandidate(command);
  if (basenameCandidate) {
    candidates.add(basenameCandidate);
  }
}

function basenameExecutableRuleCandidate(command: string): string | undefined {
  const tokens = [...tokenizeShellCommand(command)];
  const commandIndex = firstExecutableTokenIndex(tokens);
  if (commandIndex === undefined) {
    return undefined;
  }

  const token = tokens[commandIndex] ?? "";
  const executableBasename = basename(token);
  if (executableBasename === token) {
    return undefined;
  }

  tokens[commandIndex] = executableBasename;
  return normalizeCommandText(joinTokensAsRuleCommand(tokens) ?? "");
}

function firstExecutableTokenIndex(tokens: readonly string[]): number | undefined {
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index] ?? "";
    if (isEnvAssignment(token) || SHELL_LEADING_CONTROL_WORDS.has(basename(token).toLowerCase())) {
      continue;
    }
    if (isShellControlToken(token)) {
      continue;
    }
    return index;
  }
  return undefined;
}

function normalizeCommandText(command: string): string {
  return collapseWhitespace(command.trim());
}

function joinTokensAsRuleCommand(tokens: readonly string[]): string | undefined {
  return tokens.length > 0
    ? tokens.map((token) => tokenNeedsShellQuoting(token) ? JSON.stringify(token) : token).join(" ")
    : undefined;
}

function tokenNeedsShellQuoting(token: string): boolean {
  for (const character of token) {
    if (isShellWhitespace(character) || SHELL_QUOTED_TOKEN_CHARS.has(character)) {
      return true;
    }
  }
  return false;
}

const SHELL_QUOTED_TOKEN_CHARS = new Set([";", "&", "|", "<", ">", "$", "(", ")", "`"]);

function collapseWhitespace(value: string): string {
  const parts: string[] = [];
  let current = "";
  for (const character of value) {
    if (isShellWhitespace(character)) {
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
  return parts.join(" ");
}

function withPriority(classified: CommandClassification): SegmentClassification {
  return { ...classified, priority: classificationPriority(classified) };
}

function classificationPriority(classified: CommandClassification): number {
  if (classified.hardDenied) {
    return 4;
  }
  if (classified.risk === "dangerous") {
    return 3;
  }
  if (classified.risk === "medium") {
    return 2;
  }
  return classified.primaryAction === "shell" ? 0 : 1;
}

function rebaseNestedClassification(
  rawCommand: string,
  subcommand: ShellSubcommand,
  classified: CommandClassification,
): CommandClassification {
  return {
    ...classified,
    rawCommand,
    normalizedCommand: normalizeCommandText(rawCommand),
    reason: `Nested ${subcommand.syntax}: ${classified.reason}`,
  };
}

function aggregateCommandClassification(
  rawCommand: string,
  selected: SegmentClassification,
  classifications: readonly SegmentClassification[],
): CommandClassification {
  const { priority: _priority, ...base } = selected;
  const targetPaths = uniqueStrings(classifications.flatMap((classification) => classification.targetPaths));
  const actions = uniquePolicyActions([base.primaryAction, ...classifications.flatMap((classification) => classification.actions)]);
  const matchedPatterns = uniqueStrings([
    ...base.matchedPatterns,
    ...classifications.flatMap((classification) => classification.matchedPatterns),
  ]);

  return {
    ...base,
    rawCommand,
    normalizedCommand: normalizeCommandText(rawCommand),
    actions,
    matchedPatterns,
    targetPaths,
    credentialAccess: classifications.some((classification) => classification.credentialAccess),
  };
}

function splitCommandSegments(tokens: readonly string[]): readonly (readonly string[])[] {
  const segments: string[][] = [[]];
  for (const token of tokens) {
    const current = segments.at(-1);
    if (!current) {
      segments.push([]);
      continue;
    }

    if (isShellSegmentBoundaryToken(token, current.length === 0)) {
      if (current.length > 0) {
        segments.push([]);
      }
      continue;
    }
    current.push(token);
  }
  return segments.filter((segment) => segment.length > 0);
}

function extractExecutableShellSubcommands(command: string): readonly ShellSubcommand[] {
  const state: ShellSubcommandScanState = { subcommands: [], escaped: false, index: 0 };
  while (state.index < command.length) {
    advanceShellSubcommandScanner(command, state);
  }
  return state.subcommands;
}

function advanceShellSubcommandScanner(command: string, state: ShellSubcommandScanState): void {
  const character = command[state.index] ?? "";
  if (consumeSubcommandEscapedCharacter(state)) {
    return;
  }
  if (consumeSubcommandEscapeStart(state, character)) {
    return;
  }
  if (consumeBacktickSubcommand(command, state, character)) {
    return;
  }
  if (consumeSubcommandQuoteBoundary(state, character)) {
    return;
  }
  if (state.quote === "'") {
    state.index += 1;
    return;
  }
  if (consumeCommandSubstitution(command, state, character)) {
    return;
  }
  if (consumeProcessSubstitution(command, state, character)) {
    return;
  }
  state.index += 1;
}

function consumeSubcommandEscapedCharacter(state: ShellSubcommandScanState): boolean {
  if (!state.escaped) {
    return false;
  }
  state.escaped = false;
  state.index += 1;
  return true;
}

function consumeSubcommandEscapeStart(state: ShellSubcommandScanState, character: string): boolean {
  if (character !== "\\" || state.quote === "'") {
    return false;
  }
  state.escaped = true;
  state.index += 1;
  return true;
}

function consumeBacktickSubcommand(command: string, state: ShellSubcommandScanState, character: string): boolean {
  if (state.quote === "'" || character !== "`") {
    return false;
  }
  const parsed = readBacktickSubcommand(command, state.index + 1);
  advanceSubcommandScanFromParsed(state, parsed, "backtick substitution");
  return true;
}

function consumeSubcommandQuoteBoundary(state: ShellSubcommandScanState, character: string): boolean {
  if (isShellQuote(character) && !state.quote) {
    state.quote = character;
    state.index += 1;
    return true;
  }
  if (character === state.quote) {
    state.quote = undefined;
    state.index += 1;
    return true;
  }
  return false;
}

function consumeCommandSubstitution(command: string, state: ShellSubcommandScanState, character: string): boolean {
  if (character !== "$" || command[state.index + 1] !== "(" || command[state.index + 2] === "(") {
    return false;
  }
  const parsed = readBalancedParenthesizedSubcommand(command, state.index + 2);
  advanceSubcommandScanFromParsed(state, parsed, "command substitution");
  return true;
}

function consumeProcessSubstitution(command: string, state: ShellSubcommandScanState, character: string): boolean {
  if ((character !== "<" && character !== ">") || command[state.index + 1] !== "(") {
    return false;
  }
  const parsed = readBalancedParenthesizedSubcommand(command, state.index + 2);
  advanceSubcommandScanFromParsed(state, parsed, "process substitution");
  return true;
}

function advanceSubcommandScanFromParsed(
  state: ShellSubcommandScanState,
  parsed: { readonly command: string; readonly endIndex: number } | undefined,
  syntax: ShellSubcommand["syntax"],
): void {
  if (!parsed) {
    state.index += 1;
    return;
  }
  addParsedShellSubcommand(state, parsed.command, syntax);
  state.index = parsed.endIndex + 1;
}

function addParsedShellSubcommand(state: ShellSubcommandScanState, command: string, syntax: ShellSubcommand["syntax"]): void {
  if (command.trim() !== "") {
    state.subcommands.push({ command, syntax });
  }
}

function readBalancedParenthesizedSubcommand(
  command: string,
  startIndex: number,
): { readonly command: string; readonly endIndex: number } | undefined {
  const state: BalancedParenthesisScanState = { depth: 1, escaped: false, index: startIndex };
  while (state.index < command.length) {
    if (scanBalancedParenthesisCharacter(command, state)) {
      return { command: command.slice(startIndex, state.index), endIndex: state.index };
    }
    state.index += 1;
  }
  return undefined;
}

function scanBalancedParenthesisCharacter(command: string, state: BalancedParenthesisScanState): boolean {
  const character = command[state.index] ?? "";
  if (state.escaped) {
    state.escaped = false;
    return false;
  }
  if (character === "\\" && state.quote !== "'") {
    state.escaped = true;
    return false;
  }
  if (consumeBalancedParenthesisQuoteBoundary(state, character) || state.quote) {
    return false;
  }
  if (character === "(") {
    state.depth += 1;
    return false;
  }
  if (character !== ")") {
    return false;
  }
  state.depth -= 1;
  return state.depth === 0;
}

function consumeBalancedParenthesisQuoteBoundary(state: BalancedParenthesisScanState, character: string): boolean {
  if (isShellQuote(character) && !state.quote) {
    state.quote = character;
    return true;
  }
  if (character === state.quote) {
    state.quote = undefined;
    return true;
  }
  return false;
}

function readBacktickSubcommand(
  command: string,
  startIndex: number,
): { readonly command: string; readonly endIndex: number } | undefined {
  let escaped = false;

  for (let index = startIndex; index < command.length; index += 1) {
    const character = command[index];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (character === "\\") {
      escaped = true;
      continue;
    }
    if (character === "`") {
      return { command: command.slice(startIndex, index), endIndex: index };
    }
  }

  return undefined;
}

function unwrapExecutable(tokens: readonly string[]): UnwrappedExecutable {
  let index = skipLeadingEnvAssignments(tokens, 0);
  while (index < tokens.length) {
    const step = unwrapExecutableStep(tokens, index);
    if (step.result) {
      return step.result;
    }
    index = step.nextIndex;
  }
  return { args: [] };
}

function unwrapExecutableStep(tokens: readonly string[], index: number): { readonly nextIndex: number; readonly result?: UnwrappedExecutable } {
  const commandName = basename(tokens[index] ?? "").toLowerCase();
  const args = tokens.slice(index + 1);
  if (SHELL_LEADING_CONTROL_WORDS.has(commandName)) {
    return { nextIndex: index + 1 };
  }
  if (PREFIX_WRAPPERS.has(commandName)) {
    return { nextIndex: skipPrefixWrapper(commandName, tokens, index + 1) };
  }
  if (commandName === "env") {
    return unwrapEnvExecutableStep(tokens, index);
  }
  if (SHELL_WRAPPERS.has(commandName)) {
    const innerCommand = shellCommandString(args);
    if (innerCommand) {
      return { nextIndex: tokens.length, result: { args: [], innerCommand } };
    }
  }
  return { nextIndex: tokens.length, result: { commandName, args } };
}

function unwrapEnvExecutableStep(tokens: readonly string[], index: number): { readonly nextIndex: number; readonly result?: UnwrappedExecutable } {
  const env = unwrapEnv(tokens, index + 1);
  if (env.innerCommand) {
    return { nextIndex: tokens.length, result: { args: [], innerCommand: env.innerCommand } };
  }
  return { nextIndex: env.index };
}

function skipLeadingEnvAssignments(tokens: readonly string[], startIndex: number): number {
  let index = startIndex;
  while (index < tokens.length && isEnvAssignment(tokens[index] ?? "")) {
    index += 1;
  }
  return index;
}

function localScriptExecutionFromSegment(tokens: readonly string[]): LocalScriptExecution | undefined {
  const executableIndex = localScriptExecutableTokenIndex(tokens);
  if (executableIndex === undefined) {
    return undefined;
  }

  const commandToken = tokens[executableIndex] ?? "";
  const commandName = basename(commandToken).toLowerCase();
  const args = tokens.slice(executableIndex + 1);
  const invocation = joinTokensAsCommand(tokens) ?? commandToken;

  if (SHELL_WRAPPERS.has(commandName)) {
    const scriptPath = shellWrapperScriptPath(args);
    return scriptPath ? { rawPath: scriptPath, invocation, shellHint: true, via: "shell-wrapper" } : undefined;
  }

  if (isLocalScriptExecutableToken(commandToken)) {
    return { rawPath: commandToken, invocation, shellHint: false, via: "direct" };
  }

  return undefined;
}

function localScriptExecutableTokenIndex(tokens: readonly string[]): number | undefined {
  let index = 0;
  while (index < tokens.length && isEnvAssignment(tokens[index] ?? "")) {
    index += 1;
  }

  while (index < tokens.length) {
    const token = tokens[index] ?? "";
    const commandName = basename(token).toLowerCase();
    if (SHELL_LEADING_CONTROL_WORDS.has(commandName) || isShellControlToken(token)) {
      index += 1;
      continue;
    }
    if (PREFIX_WRAPPERS.has(commandName)) {
      index = skipPrefixWrapper(commandName, tokens, index + 1);
      continue;
    }
    if (commandName === "env") {
      const env = unwrapEnv(tokens, index + 1);
      if (env.innerCommand) {
        return undefined;
      }
      index = env.index;
      continue;
    }
    return index < tokens.length ? index : undefined;
  }
  return undefined;
}

function shellWrapperScriptPath(args: readonly string[]): string | undefined {
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index] ?? "";
    if (arg === "--") {
      return args[index + 1];
    }
    if (isShellCommandStringOption(arg)) {
      return undefined;
    }
    if (arg === "-o" || arg === "--init-file" || arg === "--rcfile") {
      index += 1;
      continue;
    }
    if (arg.startsWith("-")) {
      continue;
    }
    return arg;
  }
  return undefined;
}

function isLocalScriptExecutableToken(token: string): boolean {
  if (token === "") {
    return false;
  }
  if (token.startsWith("./") || token.startsWith("../")) {
    return true;
  }
  return LOCAL_SCRIPT_EXTENSIONS.has(scriptExtension(token));
}

function scriptExtension(token: string): string {
  const dotIndex = token.lastIndexOf(".");
  return dotIndex < 0 ? "" : token.slice(dotIndex).toLowerCase();
}

function uniqueLocalScriptExecutions(executions: readonly LocalScriptExecution[]): readonly LocalScriptExecution[] {
  const seen = new Set<string>();
  return executions.filter((execution) => {
    const key = `${execution.rawPath}\u0000${execution.invocation}\u0000${execution.shellHint}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

function packageScriptExecutionFromSegment(tokens: readonly string[]): PackageScriptExecution | undefined {
  const unwrapped = unwrapExecutable(tokens);
  if (unwrapped.innerCommand || !isPackageManager(unwrapped.commandName)) {
    return undefined;
  }

  const scriptName = packageScriptName(unwrapped.commandName, unwrapped.args);
  if (!scriptName) {
    return undefined;
  }

  return {
    rawPath: packageScriptPackageJsonPath(unwrapped.args),
    invocation: joinTokensAsCommand(tokens) ?? `${unwrapped.commandName} ${scriptName}`,
    packageManager: unwrapped.commandName,
    scriptName,
  };
}

function packageScriptName(commandName: PackageScriptExecution["packageManager"], args: readonly string[]): string | undefined {
  const subcommand = packageManagerSubcommand(args);
  if (!subcommand) {
    return undefined;
  }

  if (commandName === "bun") {
    return subcommand.name === "run" ? scriptNameAfterRunSubcommand(args.slice(subcommand.index + 1)) : undefined;
  }

  if (subcommand.name === "run" || subcommand.name === "run-script") {
    return scriptNameAfterRunSubcommand(args.slice(subcommand.index + 1));
  }

  if (commandName === "npm" && subcommand.name === "t") {
    return "test";
  }

  return PACKAGE_SCRIPT_ALIASES.has(subcommand.name) ? subcommand.name : undefined;
}

function packageScriptPackageJsonPath(args: readonly string[]): string {
  const directory = packageManagerDirectoryOption(args);
  return directory ? join(directory, "package.json") : "package.json";
}

function packageManagerDirectoryOption(args: readonly string[]): string | undefined {
  let directory: string | undefined;
  let index = 0;
  while (index < args.length) {
    const step = readPackageManagerDirectoryOption(args, index);
    if (step.directory) {
      directory = step.directory;
    }
    if (step.stop) {
      break;
    }
    index = step.nextIndex;
  }
  return directory;
}

function readPackageManagerDirectoryOption(
  args: readonly string[],
  index: number,
): { readonly nextIndex: number; readonly directory?: string; readonly stop?: boolean } {
  const arg = args[index] ?? "";
  if (arg === "--") {
    return { nextIndex: index + 1, stop: true };
  }
  if (PACKAGE_MANAGER_CWD_OPTIONS_WITH_VALUES.has(arg)) {
    return { nextIndex: index + 2, directory: args[index + 1] };
  }
  const inlineLongOption = PACKAGE_MANAGER_CWD_LONG_OPTIONS_WITH_VALUES.find((option) => arg.startsWith(`${option}=`));
  if (inlineLongOption) {
    return { nextIndex: index + 1, directory: arg.slice(inlineLongOption.length + 1) };
  }
  if (arg.startsWith("-C") && arg.length > 2) {
    return { nextIndex: index + 1, directory: arg.slice(2) };
  }
  return { nextIndex: PACKAGE_MANAGER_OPTIONS_WITH_VALUES.has(arg) ? index + 2 : index + 1 };
}

function scriptNameAfterRunSubcommand(args: readonly string[]): string | undefined {
  const scriptIndex = firstNonOptionIndex(args, PACKAGE_EXEC_OPTIONS_WITH_VALUES);
  const scriptName = scriptIndex === undefined ? undefined : args[scriptIndex];
  return scriptName && !scriptName.startsWith("-") ? scriptName : undefined;
}

function isPackageManager(commandName: string | undefined): commandName is PackageScriptExecution["packageManager"] {
  return commandName === "npm" || commandName === "pnpm" || commandName === "yarn" || commandName === "bun";
}

function uniquePackageScriptExecutions(executions: readonly PackageScriptExecution[]): readonly PackageScriptExecution[] {
  const seen = new Set<string>();
  return executions.filter((execution) => {
    const key = `${execution.rawPath}\u0000${execution.invocation}\u0000${execution.scriptName}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

function riskyWrapperCommandClassification(
  rawCommand: string,
  commandName: string,
  args: readonly string[],
  depth: number,
): CommandClassification | undefined {
  const invokedCommand = wrapperInvokedCommandText(commandName, args);
  if (!invokedCommand) {
    return undefined;
  }

  const classified = classifyShellCommandInternal(invokedCommand, depth + 1);
  if (!classified.hardDenied && classified.risk !== "dangerous") {
    return undefined;
  }

  return {
    ...classified,
    rawCommand,
    normalizedCommand: normalizeCommandText(rawCommand),
    reason: `Command wrapper '${commandName}' invokes a guarded command: ${classified.reason}`,
    matchedPatterns: [commandName, ...classified.matchedPatterns],
  };
}

function wrapperInvokedCommandText(commandName: string, args: readonly string[]): string | undefined {
  if (commandName === "find") {
    return findExecCommandText(args);
  }
  if (commandName === "xargs" || commandName === "parallel") {
    return commandTextAfterOptions(args, WRAPPER_OPTIONS_WITH_VALUES);
  }
  if (commandName === "eval") {
    return evalCommandText(args);
  }
  if (commandName === "exec") {
    return commandTextAfterOptions(args, EXEC_OPTIONS_WITH_VALUES);
  }
  if (commandName === "nohup" || commandName === "time") {
    return commandTextAfterOptions(args, EMPTY_OPTIONS_WITH_VALUES);
  }
  if (commandName === "nice") {
    return niceCommandText(args);
  }
  if (commandName === "timeout" || commandName === "gtimeout") {
    return timeoutCommandText(args);
  }
  if (commandName === "watch") {
    return commandTextAfterOptions(args, WATCH_OPTIONS_WITH_VALUES);
  }
  if (commandName === "npx" || commandName === "bunx") {
    return packageRunnerCommandText(args);
  }
  if (commandName === "npm" || commandName === "pnpm" || commandName === "yarn" || commandName === "bun") {
    return packageManagerInvokedCommandText(args);
  }
  return undefined;
}

const EMPTY_OPTIONS_WITH_VALUES = new Set<string>();
const EXEC_OPTIONS_WITH_VALUES = new Set(["-a"]);
const WRAPPER_OPTIONS_WITH_VALUES = new Set(["-I", "-i", "-E", "-n", "-L", "-s", "-P", "-d", "--replace", "--eof", "--max-args", "--max-lines", "--max-chars", "--max-procs", "--delimiter"]);
const SUDO_DOAS_OPTIONS_WITH_VALUES = new Set(["-C", "-T", "-g", "-h", "-p", "-u", "--chdir", "--close-from", "--command-timeout", "--group", "--host", "--prompt", "--user"]);
const COMMAND_BUILTIN_OPTIONS_WITH_VALUES = new Set<string>();
const ENV_OPTIONS_WITH_VALUES = new Set(["-C", "--chdir", "-u", "--unset"]);
const TIMEOUT_OPTIONS_WITH_VALUES = new Set(["-s", "--signal", "-k", "--kill-after"]);
const WATCH_OPTIONS_WITH_VALUES = new Set(["-n", "--interval"]);
const PACKAGE_MANAGER_SUBCOMMANDS = new Set(["exec", "x", "dlx"]);
const PACKAGE_SCRIPT_ALIASES = new Set(["start", "stop", "restart", "test"]);
const PACKAGE_MANAGER_OPTIONS_WITH_VALUES = new Set(["-C", "--cwd", "--dir", "--prefix", "--cache", "--userconfig", "--registry", "--global-folder"]);
const PACKAGE_MANAGER_CWD_OPTIONS_WITH_VALUES = new Set(["-C", "--cwd", "--dir", "--prefix"]);
const PACKAGE_MANAGER_CWD_LONG_OPTIONS_WITH_VALUES = [...PACKAGE_MANAGER_CWD_OPTIONS_WITH_VALUES].filter((option) => option.startsWith("--"));
const PACKAGE_EXEC_OPTIONS_WITH_VALUES = new Set(["-p", "--package", "--cache", "--userconfig", "--registry", "--prefix"]);

function evalCommandText(args: readonly string[]): string | undefined {
  return args.length > 0 ? args.join(" ") : undefined;
}

function shellCommandString(args: readonly string[]): string | undefined {
  for (const [index, arg] of args.entries()) {
    if (arg === "--") {
      continue;
    }
    if (isShellCStringOption(arg)) {
      return args[index + 1];
    }
    if (isInlineShellCStringOption(arg)) {
      return arg.slice(2);
    }
  }
  return undefined;
}

function isShellCommandStringOption(arg: string): boolean {
  return isShellCStringOption(arg) || isInlineShellCStringOption(arg);
}

function isShellCStringOption(arg: string): boolean {
  return hasShortOptionFlag(arg, "c");
}

function isInlineShellCStringOption(arg: string): boolean {
  return arg.startsWith("-c") && arg.length > 2 && !isShellCStringOption(arg);
}

function unwrapEnv(tokens: readonly string[], startIndex: number): { readonly index: number; readonly innerCommand?: string } {
  let index = startIndex;
  while (index < tokens.length) {
    const step = readEnvUnwrapStep(tokens, index);
    if (step.result) {
      return step.result;
    }
    if (step.nextIndex === undefined) {
      break;
    }
    index = step.nextIndex;
  }
  return { index };
}

function readEnvUnwrapStep(
  tokens: readonly string[],
  index: number,
): { readonly nextIndex?: number; readonly result?: { readonly index: number; readonly innerCommand?: string } } {
  const token = tokens[index] ?? "";
  if (token === "--") {
    return { result: { index: index + 1 } };
  }
  if (token === "-S" || token === "--split-string") {
    return { result: envSplitStringResult(tokens, index) };
  }
  if (token.startsWith("--split-string=")) {
    return { result: { index: tokens.length, innerCommand: token.slice("--split-string=".length) } };
  }
  if (token.startsWith("-S") && token.length > 2) {
    return { result: { index: tokens.length, innerCommand: token.slice(2) } };
  }
  if (ENV_OPTIONS_WITH_VALUES.has(token)) {
    return { nextIndex: index + 2 };
  }
  if (hasInlineLongOptionValue(token, ENV_OPTIONS_WITH_VALUES) || token.startsWith("-") || isEnvAssignment(token)) {
    return { nextIndex: index + 1 };
  }
  return {};
}

function envSplitStringResult(tokens: readonly string[], index: number): { readonly index: number; readonly innerCommand?: string } {
  const innerCommand = tokens[index + 1];
  return innerCommand ? { index: tokens.length, innerCommand } : { index: index + 1 };
}

function skipPrefixWrapper(commandName: string, tokens: readonly string[], startIndex: number): number {
  const optionsWithValues = commandName === "sudo" || commandName === "doas"
    ? SUDO_DOAS_OPTIONS_WITH_VALUES
    : COMMAND_BUILTIN_OPTIONS_WITH_VALUES;
  let index = startIndex;
  while (index < tokens.length) {
    const token = tokens[index] ?? "";
    if (token === "--") {
      index += 1;
      break;
    }
    if (isEnvAssignment(token)) {
      index += 1;
      continue;
    }
    if (optionsWithValues.has(token)) {
      index += 2;
      continue;
    }
    if (hasInlineLongOptionValue(token, optionsWithValues)) {
      index += 1;
      continue;
    }
    if (token.startsWith("-") && token !== "-") {
      index += 1;
      continue;
    }
    break;
  }
  return index;
}

function findExecCommandText(args: readonly string[]): string | undefined {
  const commands: string[] = [];
  for (let index = 0; index < args.length; index += 1) {
    if (!FIND_EXEC_OPTIONS.has(args[index] ?? "")) {
      continue;
    }

    const commandTokens: string[] = [];
    index += 1;
    while (index < args.length && !isFindExecTerminator(args[index] ?? "")) {
      commandTokens.push(args[index] ?? "");
      index += 1;
    }

    const command = joinTokensAsCommand(commandTokens);
    if (command) {
      commands.push(command);
    }
  }

  return commands.length > 0 ? commands.join(" ; ") : undefined;
}

function isFindExecTerminator(token: string): boolean {
  return token === ";" || token === String.raw`\;` || token === "+";
}

function niceCommandText(args: readonly string[]): string | undefined {
  let index = 0;
  while (index < args.length) {
    const arg = args[index] ?? "";
    if (arg === "-n" || arg === "--adjustment") {
      index += 2;
      continue;
    }
    if (arg.startsWith("--adjustment=") || isNegativeIntegerOption(arg)) {
      index += 1;
      continue;
    }
    return joinTokensAsCommand(args.slice(index));
  }
  return undefined;
}

function isNegativeIntegerOption(arg: string): boolean {
  if (arg.length <= 1 || !arg.startsWith("-")) {
    return false;
  }
  for (let index = 1; index < arg.length; index += 1) {
    if (!isAsciiDigit(arg[index] ?? "")) {
      return false;
    }
  }
  return true;
}

function timeoutCommandText(args: readonly string[]): string | undefined {
  const durationIndex = firstNonOptionIndex(args, TIMEOUT_OPTIONS_WITH_VALUES);
  return durationIndex === undefined ? undefined : joinTokensAsCommand(args.slice(durationIndex + 1));
}

function commandTextAfterOptions(args: readonly string[], optionsWithValues: ReadonlySet<string>): string | undefined {
  const commandIndex = firstNonOptionIndex(args, optionsWithValues);
  return commandIndex === undefined ? undefined : joinTokensAsCommand(args.slice(commandIndex));
}

function packageRunnerCommandText(args: readonly string[]): string | undefined {
  const callCommand = packageRunnerCallCommand(args);
  if (callCommand) {
    return callCommand;
  }
  const commandIndex = firstNonOptionIndex(args, PACKAGE_EXEC_OPTIONS_WITH_VALUES);
  if (commandIndex === undefined) {
    return undefined;
  }
  return joinTokensAsCommand(args.slice(commandIndex).filter((token) => token !== "--"));
}

function packageRunnerCallCommand(args: readonly string[]): string | undefined {
  let index = 0;
  while (index < args.length) {
    const step = readPackageRunnerCallStep(args, index);
    if (step.kind === "command") {
      return step.command;
    }
    if (step.stop) {
      return undefined;
    }
    index = step.nextIndex;
  }
  return undefined;
}

function readPackageRunnerCallStep(
  args: readonly string[],
  index: number,
): { readonly kind: "command"; readonly command?: string } | { readonly kind: "advance"; readonly nextIndex: number; readonly stop?: boolean } {
  const arg = args[index] ?? "";
  if (arg === "--") {
    return { kind: "advance", nextIndex: index + 1, stop: true };
  }
  if (arg === "-c" || arg === "--call") {
    return { kind: "command", command: args[index + 1] };
  }
  if (arg.startsWith("--call=")) {
    return { kind: "command", command: arg.slice("--call=".length) };
  }
  if (arg.startsWith("-c") && arg.length > 2) {
    return { kind: "command", command: arg.slice(2) };
  }
  if (PACKAGE_EXEC_OPTIONS_WITH_VALUES.has(arg)) {
    return { kind: "advance", nextIndex: index + 2 };
  }
  if (hasInlineLongOptionValue(arg, PACKAGE_EXEC_OPTIONS_WITH_VALUES)) {
    return { kind: "advance", nextIndex: index + 1 };
  }
  return { kind: "advance", nextIndex: index + 1, stop: !arg.startsWith("-") || arg === "-" };
}

function packageManagerInvokedCommandText(args: readonly string[]): string | undefined {
  const subcommand = packageManagerSubcommand(args);
  if (!subcommand || !PACKAGE_MANAGER_SUBCOMMANDS.has(subcommand.name)) {
    return undefined;
  }
  return packageRunnerCommandText(args.slice(subcommand.index + 1));
}

function packageManagerSubcommand(args: readonly string[]): { readonly name: string; readonly index: number } | undefined {
  const subcommandIndex = firstNonOptionIndex(args, PACKAGE_MANAGER_OPTIONS_WITH_VALUES);
  if (subcommandIndex === undefined) {
    return undefined;
  }
  return { name: args[subcommandIndex] ?? "", index: subcommandIndex };
}

function firstNonOptionIndex(args: readonly string[], optionsWithValues: ReadonlySet<string>): number | undefined {
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index] ?? "";
    if (arg === "--") {
      return index + 1 < args.length ? index + 1 : undefined;
    }
    if (optionsWithValues.has(arg)) {
      index += 1;
      continue;
    }
    if (hasInlineLongOptionValue(arg, optionsWithValues)) {
      continue;
    }
    if (arg.startsWith("-") && arg !== "-") {
      continue;
    }
    return index;
  }
  return undefined;
}

function joinTokensAsCommand(tokens: readonly string[]): string | undefined {
  const meaningfulTokens = tokens.filter((token) => token !== "{}" && token !== "{}+");
  return meaningfulTokens.length > 0
    ? meaningfulTokens.map((token) => tokenNeedsShellQuoting(token) ? JSON.stringify(token) : token).join(" ")
    : undefined;
}

function inlineCodeSnippets(commandName: string | undefined, args: readonly string[]): readonly string[] {
  if (!commandName || !INLINE_CODE_INTERPRETERS.has(commandName)) {
    return [];
  }

  const snippets: string[] = [];
  for (const [index, arg] of args.entries()) {
    if (arg === "--") {
      break;
    }
    if (arg === "-c" || arg === "-e" || arg === "-E" || arg === "-r" || arg === "--eval") {
      const snippet = args[index + 1];
      if (snippet) {
        snippets.push(snippet);
      }
      continue;
    }
    if (arg.startsWith("--eval=")) {
      snippets.push(arg.slice("--eval=".length));
      continue;
    }
    if ((arg.startsWith("-e") || arg.startsWith("-E") || arg.startsWith("-r")) && arg.length > 2) {
      snippets.push(arg.slice(2));
    }
  }
  return snippets;
}

function hardDeniedDiskReason(commandName: string, args: readonly string[]): string | undefined {
  if (commandName === "diskutil" && args.some((arg) => DISKUTIL_HARD_DENIED_SUBCOMMANDS.has(arg.toLowerCase()))) {
    return "Disk formatting/raw disk operation is denied.";
  }
  if (commandName.startsWith("mkfs") || commandName === "fdisk") {
    return "Disk formatting/raw disk operation is denied.";
  }
  if (commandName === "dd" && args.some(isDdBlockDeviceOperand)) {
    return "dd access to block devices is denied.";
  }
  return undefined;
}

function extractLikelyPathOperands(commandName: string | undefined, args: readonly string[], segmentTokens: readonly string[]): readonly string[] {
  if (!commandName) {
    return [];
  }
  const argsWithoutRedirections = stripRedirectionOperands(args);
  if (GREP_COMMANDS.has(commandName)) {
    return grepPathOperands(argsWithoutRedirections);
  }
  if (commandName === "find") {
    return findPathOperands(argsWithoutRedirections);
  }
  if (commandName === "tee") {
    return argsWithoutRedirections.filter((arg) => !arg.startsWith("-"));
  }
  if (commandName === "sed") {
    return argsWithoutRedirections.filter((arg) => !arg.startsWith("-") && !looksLikeSedExpression(arg));
  }
  if (commandName === "dd") {
    return ddPathOperands(argsWithoutRedirections);
  }
  if (TEST_COMMANDS.has(commandName)) {
    return testPathOperands(argsWithoutRedirections);
  }
  if (
    READ_COMMANDS.has(commandName) ||
    ADDITIONAL_READ_COMMANDS.has(commandName) ||
    LIST_COMMANDS.has(commandName) ||
    COPY_COMMANDS.has(commandName) ||
    ARCHIVE_COMMANDS.has(commandName) ||
    WRITE_COMMANDS.has(commandName) ||
    METADATA_EDIT_COMMANDS.has(commandName) ||
    PATH_MUTATION_COMMANDS.has(commandName)
  ) {
    return argsWithoutRedirections.filter((arg) => !arg.startsWith("-") && !isShellControlToken(arg) && !arg.includes("="));
  }
  return extractOutputRedirectionTargets(segmentTokens);
}

function extractOutputRedirectionTargets(tokens: readonly string[]): readonly string[] {
  return extractFileRedirectionTargets(tokens, OUTPUT_REDIRECTION_TOKENS);
}

function extractInputRedirectionTargets(tokens: readonly string[]): readonly string[] {
  return extractFileRedirectionTargets(tokens, INPUT_REDIRECTION_TOKENS);
}

function extractFileRedirectionTargets(tokens: readonly string[], redirectionTokens: ReadonlySet<string>): readonly string[] {
  const targets: string[] = [];
  for (const [index, token] of tokens.entries()) {
    const target = tokens[index + 1];
    if (redirectionTokens.has(token) && target && isFileRedirectionTarget(target)) {
      targets.push(target);
    }
  }
  return targets;
}

function stripRedirectionOperands(args: readonly string[]): readonly string[] {
  const stripped: string[] = [];
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index] ?? "";
    if (REDIRECTION_TOKENS_WITH_TARGET.has(arg)) {
      index += 1;
      continue;
    }
    stripped.push(arg);
  }
  return stripped;
}

function isFileRedirectionTarget(token: string): boolean {
  return token !== "&" && !token.startsWith("&") && token !== "-";
}

function grepPathOperands(args: readonly string[]): readonly string[] {
  const operands = args.filter((arg) => !arg.startsWith("-"));
  if (operands.length > 1) {
    return operands.slice(1);
  }
  return grepArgsAreRecursive(args) && operands.length === 1 ? ["."] : [];
}

function grepArgsAreRecursive(args: readonly string[]): boolean {
  return args.some((arg) => arg === "--recursive" || hasShortOptionFlag(arg, "r"));
}

function findPathOperands(args: readonly string[]): readonly string[] {
  const paths: string[] = [];
  for (const arg of args) {
    if (arg === "--") {
      continue;
    }
    if (arg.startsWith("-") || isFindExpressionToken(arg)) {
      break;
    }
    paths.push(arg);
  }
  return paths.length > 0 ? paths : ["."];
}

function isFindExpressionToken(arg: string): boolean {
  return arg === "(" || arg === ")" || arg === "!" || arg === ",";
}

function ddPathOperands(args: readonly string[]): readonly string[] {
  return args.flatMap((arg) => {
    const path = ddOperandPath(arg);
    return path ? [path] : [];
  });
}

function ddOperandPath(arg: string): string | undefined {
  return arg.startsWith("if=") || arg.startsWith("of=") ? arg.slice(3) : undefined;
}

function isDdBlockDeviceOperand(arg: string): boolean {
  return ddOperandPath(arg)?.startsWith("/dev/") ?? false;
}

function testPathOperands(args: readonly string[]): readonly string[] {
  const nonPathTestTokens = new Set(["=", "==", "!=", "<", ">", "]", "]]", "!", "-a", "-o", "(", ")"]);
  return args.filter((arg) => !arg.startsWith("-") && !isShellControlToken(arg) && !nonPathTestTokens.has(arg));
}

function isRecursiveForceRm(args: readonly string[]): boolean {
  let recursive = false;
  let force = false;

  for (const arg of args) {
    const normalized = arg.toLowerCase();
    if (normalized === "--") {
      break;
    }
    if (!normalized.startsWith("-") || normalized === "-") {
      continue;
    }
    if (normalized === "--recursive") {
      recursive = true;
      continue;
    }
    if (normalized === "--force") {
      force = true;
      continue;
    }
    if (normalized.startsWith("--")) {
      continue;
    }

    const shortFlags = normalized.slice(1);
    recursive = recursive || shortFlags.includes("r");
    force = force || shortFlags.includes("f");
  }

  return recursive && force;
}

function hasRsyncDeleteOption(args: readonly string[]): boolean {
  return args.some((arg) => arg === "--delete" || arg.startsWith("--delete-") || arg.startsWith("--delete="));
}

function isReadLikeCommand(commandName: string): boolean {
  return READ_COMMANDS.has(commandName) || ADDITIONAL_READ_COMMANDS.has(commandName) || GREP_COMMANDS.has(commandName);
}

function isDynamicExecutableName(commandName: string): boolean {
  for (const character of commandName) {
    if (DYNAMIC_EXECUTABLE_NAME_CHARS.has(character)) {
      return true;
    }
  }
  return false;
}

function containsCloudCliLiteral(value: string): boolean {
  const lower = value.toLowerCase();
  for (const command of CLOUD_CLI_COMMANDS) {
    if (containsDelimitedLiteral(lower, command)) {
      return true;
    }
  }
  return false;
}

function containsCredentialLikeLiteral(value: string): boolean {
  const lower = value.toLowerCase();
  return containsProtectedEnvPathReference(lower) || CREDENTIAL_LITERAL_MARKERS.some((marker) => lower.includes(marker));
}

function isCredentialLikePath(pathValue: string): boolean {
  const lower = pathValue.toLowerCase();
  return (
    isProtectedEnvPathOperand(lower) ||
    lower.startsWith(".npmrc") ||
    lower.includes("/.npmrc") ||
    lower.startsWith(".pypirc") ||
    lower.includes("/.pypirc") ||
    lower.startsWith(".netrc") ||
    lower.includes("/.netrc") ||
    lower.startsWith(".ssh") ||
    lower.includes("~/.ssh") ||
    lower.includes("/.ssh") ||
    lower.startsWith(".gnupg") ||
    lower.includes("~/.gnupg") ||
    lower.includes("/.gnupg") ||
    lower.startsWith(".1password") ||
    lower.includes("~/.1password") ||
    lower.includes("/.1password") ||
    isPrivateKeyFilePath(lower) ||
    lower.startsWith(".aws") ||
    lower.includes("~/.aws") ||
    lower.includes("/.aws") ||
    lower.startsWith(".azure") ||
    lower.includes("~/.azure") ||
    lower.includes("/.azure") ||
    lower.startsWith(".config/gcloud") ||
    lower.includes("~/.config/gcloud") ||
    lower.includes("/.config/gcloud") ||
    lower.endsWith("/.docker/config.json") ||
    lower.includes("credential") ||
    lower.includes("secret") ||
    lower.includes("token")
  );
}

function isProtectedEnvPathOperand(pathValue: string): boolean {
  return pathValue
    .replaceAll("\\", "/")
    .split("/")
    .filter(Boolean)
    .some((segment) => segment === ".env" || (segment.startsWith(".env") && hasEnvGlobWildcard(segment)));
}

function hasEnvGlobWildcard(segment: string): boolean {
  return segment.includes("*") || segment.includes("?") || segment.includes("[") || segment.includes("]");
}

function containsProtectedEnvPathReference(value: string): boolean {
  const normalized = value.replaceAll("\\", "/");
  for (let index = 0; index < normalized.length; index += 1) {
    if (!envReferenceStartsAt(normalized, index)) {
      continue;
    }
    if (envReferenceHasLeftBoundary(normalized, index) && envReferenceHasRightBoundary(normalized, index + envReferenceLength(normalized, index))) {
      return true;
    }
  }
  return false;
}

function isGitPath(pathValue: string): boolean {
  const segments = trimTrailingSlashes(pathValue.replaceAll("\\", "/"))
    .split("/")
    .filter(Boolean);
  return segments.includes(".git");
}

function trimTrailingSlashes(value: string): string {
  let endIndex = value.length;
  while (endIndex > 0 && value[endIndex - 1] === "/") {
    endIndex -= 1;
  }
  return value.slice(0, endIndex);
}

function mutationRisk(targetPaths: readonly string[]): RiskLevel {
  return isOutsideishMutation(targetPaths) ? "dangerous" : "medium";
}

function isOutsideishMutation(targetPaths: readonly string[]): boolean {
  return targetPaths.some((target) => target.startsWith("/") || target.startsWith("~") || target.startsWith("..") || target.includes("/../"));
}

function outsideishTargetPresent(targetPaths: readonly string[]): boolean {
  return targetPaths.some((target) => target.startsWith("/") || target.startsWith("~") || target.startsWith(".."));
}

function looksLikeRename(targetPaths: readonly string[]): boolean {
  if (targetPaths.length !== 2) {
    return false;
  }
  return dirname(targetPaths[0] ?? "") === dirname(targetPaths[1] ?? "") && basename(targetPaths[0] ?? "") !== basename(targetPaths[1] ?? "");
}

function looksDestructiveButAmbiguous(commandName: string, args: readonly string[]): boolean {
  return (
    (commandName === "git" && args[0] === "clean" && args.some((arg) => arg.includes("f"))) ||
    (commandName === "python" && args.some((arg) => arg.includes("shutil.rmtree"))) ||
    (commandName === "node" && args.some((arg) => arg.includes("rmSync")))
  );
}

function looksLikeSedExpression(value: string): boolean {
  return value.startsWith("s/") || value.startsWith("s#") || value.startsWith("/s/");
}

function isEnvAssignment(value: string): boolean {
  const equalsIndex = value.indexOf("=");
  return equalsIndex > 0 && isShellIdentifier(value.slice(0, equalsIndex));
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

function containsDelimitedLiteral(value: string, literal: string): boolean {
  let index = value.indexOf(literal);
  while (index >= 0) {
    if (isLiteralBoundary(value[index - 1]) && isLiteralBoundary(value[index + literal.length])) {
      return true;
    }
    index = value.indexOf(literal, index + 1);
  }
  return false;
}

function isLiteralBoundary(character: string | undefined): boolean {
  return character === undefined || (!isAsciiLetter(character) && !isAsciiDigit(character) && character !== "_" && character !== "-");
}

function isPrivateKeyFilePath(pathValue: string): boolean {
  const segments = trimTrailingSlashes(pathValue).split("/").filter(Boolean);
  const fileName = segments.at(-1) ?? "";
  return PRIVATE_KEY_FILE_NAMES.has(fileName);
}

function envReferenceStartsAt(value: string, index: number): boolean {
  return value.startsWith(".env", index) || value.startsWith("./.env", index);
}

function envReferenceLength(value: string, index: number): number {
  return value.startsWith("./.env", index) ? 6 : 4;
}

function envReferenceHasLeftBoundary(value: string, index: number): boolean {
  return index === 0 || ENV_REFERENCE_LEFT_BOUNDARY_CHARS.has(value[index - 1] ?? "") || isShellWhitespace(value[index - 1] ?? "");
}

function envReferenceHasRightBoundary(value: string, index: number): boolean {
  return index >= value.length || ENV_REFERENCE_RIGHT_BOUNDARY_CHARS.has(value[index] ?? "") || isShellWhitespace(value[index] ?? "");
}

const ENV_REFERENCE_LEFT_BOUNDARY_CHARS = new Set(["'", "\"", "`", "(", "<", ">", "=", ":", ",", "/"]);
const ENV_REFERENCE_RIGHT_BOUNDARY_CHARS = new Set(["'", "\"", "`", ")", ">", ":", ",", "/", "*", "?", "[", "]"]);

function hasInlineLongOptionValue(arg: string, optionsWithValues: ReadonlySet<string>): boolean {
  for (const option of optionsWithValues) {
    if (option.startsWith("--") && arg.startsWith(`${option}=`)) {
      return true;
    }
  }
  return false;
}

function hasShortOptionFlag(arg: string, flag: string): boolean {
  if (!arg.startsWith("-") || arg.startsWith("--") || arg.length <= 1) {
    return false;
  }
  const flags = arg.slice(1);
  return [...flags].every(isAsciiLetter) && flags.toLowerCase().includes(flag.toLowerCase());
}

function isAsciiLetter(character: string): boolean {
  const codePoint = character.codePointAt(0);
  return codePoint !== undefined && ((codePoint >= 65 && codePoint <= 90) || (codePoint >= 97 && codePoint <= 122));
}

function isAsciiDigit(character: string): boolean {
  const codePoint = character.codePointAt(0);
  return codePoint !== undefined && codePoint >= 48 && codePoint <= 57;
}

function isAsciiOctalDigit(character: string): boolean {
  const codePoint = character.codePointAt(0);
  return codePoint !== undefined && codePoint >= 48 && codePoint <= 55;
}

function isAsciiHexDigit(character: string): boolean {
  const codePoint = character.codePointAt(0);
  return codePoint !== undefined && ((codePoint >= 48 && codePoint <= 57) || (codePoint >= 65 && codePoint <= 70) || (codePoint >= 97 && codePoint <= 102));
}

function isShellLineSeparator(character: string): boolean {
  return character === "\n" || character === "\r";
}

function isShellOperatorStart(character: string, next: string | undefined): boolean {
  return (
    character === ";" ||
    character === "&" ||
    character === "|" ||
    character === "(" ||
    character === ")" ||
    character === ">" ||
    character === "<" ||
    (character === "0" && next === "<") ||
    ((character === "1" || character === "2") && next === ">")
  );
}

function escapedShellOperatorToken(character: string, currentToken: string): string {
  return currentToken === "" && isShellOperatorStart(character, undefined) ? `\\${character}` : character;
}

function isShellSegmentBoundaryToken(token: string, atCommandPosition: boolean): boolean {
  return (
    SHELL_HARD_SEGMENT_BOUNDARY_TOKENS.has(token) ||
    SHELL_CLOSING_SEGMENT_BOUNDARY_TOKENS.has(token) ||
    (atCommandPosition && SHELL_COMMAND_POSITION_BOUNDARY_TOKENS.has(token))
  );
}

function isShellControlToken(token: string): boolean {
  return (
    SHELL_HARD_SEGMENT_BOUNDARY_TOKENS.has(token) ||
    SHELL_CLOSING_SEGMENT_BOUNDARY_TOKENS.has(token) ||
    SHELL_COMMAND_POSITION_BOUNDARY_TOKENS.has(token)
  );
}

function uniqueStrings(values: readonly string[]): readonly string[] {
  return [...new Set(values)];
}

function uniquePolicyActions(values: readonly PolicyAction[]): readonly PolicyAction[] {
  return [...new Set(values)];
}
