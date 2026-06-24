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

interface ShellSubcommand {
  readonly command: string;
  readonly syntax: "command substitution" | "process substitution" | "backtick substitution";
}

const CLOUD_CLI_COMMANDS = new Set(["aws", "az", "gcloud"]);
const READ_COMMANDS = new Set(["cat", "less", "more", "head", "tail"]);
const GREP_COMMANDS = new Set(["grep", "ggrep"]);
const ADDITIONAL_READ_COMMANDS = new Set(["awk", "base64", "md5sum", "od", "sed", "sha1sum", "sha256sum", "sha512sum", "shasum", "strings", "wc", "xxd"]);
const LIST_COMMANDS = new Set(["ls", "find", "tree"]);
const COPY_COMMANDS = new Set(["cp", "install"]);
const ARCHIVE_COMMANDS = new Set(["7z", "bunzip2", "bzip2", "gunzip", "gzip", "tar", "unxz", "xz", "zip"]);
const WRITE_COMMANDS = new Set(["mkdir", "touch"]);
const METADATA_EDIT_COMMANDS = new Set(["chgrp", "chmod", "chown"]);
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
const DYNAMIC_EXECUTABLE_NAME_PATTERN = /[$`*?\[\]{}]/u;
const CLOUD_CLI_LITERAL_PATTERN = /(?:^|[^a-z0-9_-])(?:aws|az|gcloud)(?:$|[^a-z0-9_-])/iu;
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
    return classification(command, "shell", "shell", "low", "Empty shell command.", [], [], false, false, false);
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
    : classification(command, "shell", "shell", "low", "No classifiable shell command found.", [], [], false, false, false);
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
  const tokens: string[] = [];
  let current = "";
  let quote: '"' | "'" | undefined;
  let ansiCQuote = false;
  let escaped = false;

  const pushCurrent = () => {
    if (current !== "") {
      tokens.push(current);
      current = "";
    }
  };

  for (let index = 0; index < command.length; index += 1) {
    const character = command[index];

    if (escaped) {
      current += escapedShellOperatorToken(character, current);
      escaped = false;
      continue;
    }

    if (quote === "'" && ansiCQuote && character === "\\") {
      const parsed = readAnsiCEscape(command, index);
      current += parsed.value;
      index = parsed.endIndex;
      continue;
    }

    if (character === "\\" && quote !== "'") {
      const next = command[index + 1];
      if (next && isShellLineSeparator(next)) {
        index += next === "\r" && command[index + 2] === "\n" ? 2 : 1;
        continue;
      }
      escaped = true;
      continue;
    }

    if ((character === '"' || character === "'") && !quote) {
      quote = character;
      ansiCQuote = false;
      continue;
    }
    if (character === quote) {
      quote = undefined;
      ansiCQuote = false;
      continue;
    }

    if (!quote && isShellLineSeparator(character)) {
      pushCurrent();
      if (tokens[tokens.length - 1] !== ";") {
        tokens.push(";");
      }
      if (character === "\r" && command[index + 1] === "\n") {
        index += 1;
      }
      continue;
    }

    if (!quote && /\s/.test(character)) {
      pushCurrent();
      continue;
    }

    if (!quote && character === "$" && (command[index + 1] === "'" || command[index + 1] === '"')) {
      quote = command[index + 1] as "'" | '"';
      ansiCQuote = quote === "'";
      index += 1;
      continue;
    }

    if (!quote && isShellOperatorStart(character, command[index + 1])) {
      pushCurrent();
      const next = command[index + 1];
      if ((character === ">" || character === "&" || character === "|") && next === character) {
        tokens.push(`${character}${next}`);
        index += 1;
      } else if (character === ">" && next === "&") {
        tokens.push(">&");
        index += 1;
      } else if (character === "<" && next === "<") {
        if (command[index + 2] === "<") {
          tokens.push("<<<");
          index += 2;
        } else {
          tokens.push("<<");
          index += 1;
        }
      } else if (character === "<" && (next === ">" || next === "&")) {
        tokens.push(`<${next}`);
        index += 1;
      } else if ((character === "0" && next === "<") || ((character === "1" || character === "2") && next === ">")) {
        const afterNext = command[index + 2];
        if (afterNext === next) {
          tokens.push(`${character}${next}${afterNext}`);
          index += 2;
        } else if (afterNext === "&" || (character === "0" && afterNext === ">")) {
          tokens.push(`${character}${next}${afterNext}`);
          index += 2;
        } else {
          tokens.push(`${character}${next}`);
          index += 1;
        }
      } else {
        tokens.push(character);
      }
      continue;
    }

    current += character;
  }

  pushCurrent();
  return tokens;
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
  if (/[0-7]/u.test(escape)) {
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
  while (digits.length < maxDigits && /[0-9a-f]/iu.test(command[index] ?? "")) {
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
  while (digits.length < 3 && /[0-7]/u.test(command[index] ?? "")) {
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

  const commandName = unwrapped.commandName;
  const args = unwrapped.args;
  const inputRedirectionTargets = extractInputRedirectionTargets(segmentTokens);
  const targetPaths = uniqueStrings([...extractLikelyPathOperands(commandName, args, segmentTokens), ...inputRedirectionTargets]);
  const credentialAccess = targetPaths.some(isCredentialLikePath);
  const inlineCode = inlineCodeSnippets(commandName, args);
  const credentialLiteralAccess = !credentialAccess && args.some(containsCredentialLikeLiteral);
  const cloudCliLiteralAccess = inlineCode.some(containsCloudCliLiteral);

  if (!commandName) {
    return withPriority(classification(rawCommand, "shell", "shell", "low", "No executable found.", [], [], false, false, false));
  }

  if (TEST_COMMANDS.has(commandName)) {
    return withPriority(
      classification(rawCommand, "list", "list", credentialAccess ? "dangerous" : "low", "Shell test inspects path existence or metadata.", [commandName], targetPaths, false, credentialAccess, credentialAccess, credentialAccess),
    );
  }

  if (isDynamicExecutableName(commandName)) {
    return withPriority(
      classification(rawCommand, "hard-denied", "shell", "hard-denied", "Shell-expanded command names are denied because GuardMe cannot safely classify the executable.", [commandName], targetPaths, true, true, false),
    );
  }

  if (CLOUD_CLI_COMMANDS.has(commandName)) {
    return withPriority(
      classification(rawCommand, "hard-denied", "shell", "hard-denied", `Cloud CLI '${commandName}' is always denied by GuardMe.`, [commandName], targetPaths, true, true, false),
    );
  }

  if (cloudCliLiteralAccess) {
    return withPriority(
      classification(rawCommand, "hard-denied", "shell", "hard-denied", "Inline code invokes a cloud CLI that GuardMe always denies.", ["cloud-cli-inline-code"], targetPaths, true, true, false),
    );
  }

  const wrapperClassification = depth < 5 ? riskyWrapperCommandClassification(rawCommand, commandName, args, depth) : undefined;
  if (wrapperClassification) {
    return withPriority(wrapperClassification);
  }

  const diskReason = hardDeniedDiskReason(commandName, args);
  if (diskReason) {
    return withPriority(
      classification(rawCommand, "hard-denied", "shell", "hard-denied", diskReason, [commandName], targetPaths, true, true, false),
    );
  }

  if (commandName === "dd") {
    return withPriority(
      classification(rawCommand, "write", "write", credentialAccess ? "dangerous" : mutationRisk(targetPaths), "dd copies between file operands.", [commandName], targetPaths, false, credentialAccess || isOutsideishMutation(targetPaths), credentialAccess || isOutsideishMutation(targetPaths), credentialAccess),
    );
  }

  if (credentialAccess && isReadLikeCommand(commandName)) {
    return withPriority(
      classification(rawCommand, "hard-denied", "read", "hard-denied", "Credential-like file read detected.", ["credential-read"], targetPaths, true, true, false, true),
    );
  }

  if (credentialLiteralAccess) {
    return withPriority(
      classification(rawCommand, "hard-denied", "read", "hard-denied", "Credential-like file reference detected in shell command.", ["credential-literal"], targetPaths, true, true, false, true),
    );
  }

  const outputRedirectionTargets = extractOutputRedirectionTargets(segmentTokens);
  if (outputRedirectionTargets.length > 0) {
    const redirectionTargets = uniqueStrings([...inputRedirectionTargets, ...outputRedirectionTargets]);
    return withPriority(
      classification(rawCommand, "write", "write", mutationRisk(redirectionTargets), "Shell redirection writes to a file.", ["redirection"], redirectionTargets, false, isOutsideishMutation(redirectionTargets), isOutsideishMutation(redirectionTargets)),
    );
  }

  if (commandName === "rm") {
    const deletesGit = targetPaths.some(isGitPath);
    if (deletesGit) {
      return withPriority(
        classification(rawCommand, "hard-denied", "delete", "hard-denied", "Deleting .git metadata is denied.", [".git-delete"], targetPaths, true, true, false),
      );
    }
    const recursiveForce = isRecursiveForceRm(args);
    return withPriority(
      classification(
        rawCommand,
        recursiveForce ? "dangerous" : "delete",
        "delete",
        recursiveForce ? "dangerous" : mutationRisk(targetPaths),
        recursiveForce ? "Recursive force deletion requires coaching or user approval." : "File deletion command detected.",
        recursiveForce ? ["rm -rf"] : ["rm"],
        targetPaths,
        false,
        recursiveForce || isOutsideishMutation(targetPaths),
        recursiveForce || isOutsideishMutation(targetPaths),
      ),
    );
  }

  if (commandName === "rmdir") {
    return withPriority(
      classification(rawCommand, "delete", "delete", mutationRisk(targetPaths), "Directory deletion command detected.", ["rmdir"], targetPaths, false, isOutsideishMutation(targetPaths), isOutsideishMutation(targetPaths)),
    );
  }

  if (commandName === "mv" || commandName === "rename") {
    const primaryAction: PolicyAction = commandName === "rename" || looksLikeRename(targetPaths) ? "rename" : "move";
    return withPriority(
      classification(rawCommand, primaryAction, primaryAction, mutationRisk(targetPaths), `${primaryAction === "rename" ? "Rename" : "Move"} command detected.`, [commandName], targetPaths, false, isOutsideishMutation(targetPaths), isOutsideishMutation(targetPaths)),
    );
  }

  if (commandName === "rsync" && hasRsyncDeleteOption(args)) {
    return withPriority(
      classification(rawCommand, "dangerous", "delete", "dangerous", "rsync --delete may remove files and requires user approval.", ["rsync --delete"], targetPaths, false, true, true),
    );
  }

  if (commandName === "find" && args.includes("-delete")) {
    return withPriority(
      classification(rawCommand, "dangerous", "delete", "dangerous", "find -delete may remove files and requires user approval.", ["find -delete"], targetPaths, false, true, true),
    );
  }

  if (COPY_COMMANDS.has(commandName)) {
    return withPriority(
      classification(rawCommand, "write", "write", credentialAccess ? "dangerous" : mutationRisk(targetPaths), `${commandName} copies file operands.`, [commandName], targetPaths, false, credentialAccess || isOutsideishMutation(targetPaths), credentialAccess || isOutsideishMutation(targetPaths), credentialAccess),
    );
  }

  if (ARCHIVE_COMMANDS.has(commandName)) {
    return withPriority(
      classification(rawCommand, "write", "write", credentialAccess ? "dangerous" : mutationRisk(targetPaths), `${commandName} archives or extracts file operands.`, [commandName], targetPaths, false, credentialAccess || isOutsideishMutation(targetPaths), credentialAccess || isOutsideishMutation(targetPaths), credentialAccess),
    );
  }

  if (WRITE_COMMANDS.has(commandName)) {
    return withPriority(
      classification(rawCommand, "write", "write", credentialAccess ? "dangerous" : mutationRisk(targetPaths), `${commandName} writes filesystem paths.`, [commandName], targetPaths, false, credentialAccess || isOutsideishMutation(targetPaths), credentialAccess || isOutsideishMutation(targetPaths), credentialAccess),
    );
  }

  if (METADATA_EDIT_COMMANDS.has(commandName)) {
    return withPriority(
      classification(rawCommand, "edit", "edit", credentialAccess ? "dangerous" : mutationRisk(targetPaths), `${commandName} mutates filesystem metadata.`, [commandName], targetPaths, false, credentialAccess || isOutsideishMutation(targetPaths), credentialAccess || isOutsideishMutation(targetPaths), credentialAccess),
    );
  }

  if (commandName === "sed" && args.some((arg) => arg === "-i" || arg.startsWith("-i"))) {
    return withPriority(
      classification(rawCommand, "edit", "edit", mutationRisk(targetPaths), "In-place sed edit detected.", ["sed -i"], targetPaths, false, isOutsideishMutation(targetPaths), isOutsideishMutation(targetPaths)),
    );
  }

  if (commandName === "tee") {
    return withPriority(
      classification(rawCommand, "write", "write", mutationRisk(targetPaths), "tee writes to file operands.", ["tee"], targetPaths, false, isOutsideishMutation(targetPaths), isOutsideishMutation(targetPaths)),
    );
  }

  if (GREP_COMMANDS.has(commandName)) {
    return withPriority(
      classification(rawCommand, "read", "read", credentialAccess ? "dangerous" : "low", `${commandName} reads file operands.`, [commandName], targetPaths, false, credentialAccess, credentialAccess, credentialAccess),
    );
  }

  if (READ_COMMANDS.has(commandName) || ADDITIONAL_READ_COMMANDS.has(commandName)) {
    return withPriority(
      classification(rawCommand, "read", "read", credentialAccess ? "dangerous" : "low", `${commandName} reads file operands.`, [commandName], targetPaths, false, credentialAccess, credentialAccess, credentialAccess),
    );
  }

  if (LIST_COMMANDS.has(commandName)) {
    return withPriority(
      classification(rawCommand, "list", "list", credentialAccess ? "dangerous" : "low", `${commandName} lists or discovers files.`, [commandName], targetPaths, false, credentialAccess, credentialAccess, credentialAccess),
    );
  }

  if (looksDestructiveButAmbiguous(commandName, args)) {
    return withPriority(
      classification(rawCommand, "ambiguous", "shell", "dangerous", "Ambiguous destructive shell command requires user approval.", [commandName], targetPaths, false, true, true),
    );
  }

  return withPriority(
    classification(rawCommand, "shell", "shell", outsideishTargetPresent(targetPaths) ? "medium" : "low", "Generic shell command detected.", [commandName], targetPaths, false, false, false),
  );
}

function classification(
  rawCommand: string,
  kind: CommandClassificationKind,
  primaryAction: PolicyAction,
  risk: RiskLevel,
  reason: string,
  matchedPatterns: readonly string[],
  targetPaths: readonly string[],
  hardDenied: boolean,
  dangerous: boolean,
  requiresUserDecision: boolean,
  credentialAccess = false,
): CommandClassification {
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

  if (depth >= 5) {
    return [...candidates];
  }

  for (const subcommand of extractExecutableShellSubcommands(command)) {
    for (const candidate of commandRuleMatchCandidatesInternal(subcommand.command, depth + 1)) {
      addCommandRuleCandidate(candidates, candidate);
    }
  }

  for (const segment of splitCommandSegments(tokenizeShellCommand(command))) {
    const segmentText = joinTokensAsRuleCommand(segment);
    if (segmentText) {
      addCommandRuleCandidate(candidates, segmentText);
    }

    const leadingWrapperCommand = leadingWrapperInvokedCommandText(segment);
    if (leadingWrapperCommand) {
      for (const candidate of commandRuleMatchCandidatesInternal(leadingWrapperCommand, depth + 1)) {
        addCommandRuleCandidate(candidates, candidate);
      }
    }

    const unwrapped = unwrapExecutable(segment);
    if (unwrapped.innerCommand) {
      for (const candidate of commandRuleMatchCandidatesInternal(unwrapped.innerCommand, depth + 1)) {
        addCommandRuleCandidate(candidates, candidate);
      }
    }

    const commandName = unwrapped.commandName;
    if (commandName) {
      const wrapperCommand = wrapperInvokedCommandText(commandName, unwrapped.args);
      if (wrapperCommand) {
        for (const candidate of commandRuleMatchCandidatesInternal(wrapperCommand, depth + 1)) {
          addCommandRuleCandidate(candidates, candidate);
        }
      }
    }
  }

  return [...candidates];
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
  return command.trim().replace(/\s+/g, " ");
}

function joinTokensAsRuleCommand(tokens: readonly string[]): string | undefined {
  return tokens.length > 0
    ? tokens.map((token) => /[\s;&|<>$()`]/u.test(token) ? JSON.stringify(token) : token).join(" ")
    : undefined;
}

function withPriority(classified: CommandClassification): SegmentClassification {
  const priority = classified.hardDenied ? 4 : classified.risk === "dangerous" ? 3 : classified.risk === "medium" ? 2 : classified.primaryAction === "shell" ? 0 : 1;
  return { ...classified, priority };
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
    const current = segments[segments.length - 1];
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
  const subcommands: ShellSubcommand[] = [];
  let quote: '"' | "'" | undefined;
  let escaped = false;

  for (let index = 0; index < command.length; index += 1) {
    const character = command[index];

    if (escaped) {
      escaped = false;
      continue;
    }

    if (character === "\\" && quote !== "'") {
      escaped = true;
      continue;
    }

    if (quote !== "'" && character === "`") {
      const parsed = readBacktickSubcommand(command, index + 1);
      if (parsed) {
        if (parsed.command.trim() !== "") {
          subcommands.push({ command: parsed.command, syntax: "backtick substitution" });
        }
        index = parsed.endIndex;
      }
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

    if (quote === "'") {
      continue;
    }

    if (character === "$" && command[index + 1] === "(" && command[index + 2] !== "(") {
      const parsed = readBalancedParenthesizedSubcommand(command, index + 2);
      if (parsed) {
        if (parsed.command.trim() !== "") {
          subcommands.push({ command: parsed.command, syntax: "command substitution" });
        }
        index = parsed.endIndex;
      }
      continue;
    }

    if ((character === "<" || character === ">") && command[index + 1] === "(") {
      const parsed = readBalancedParenthesizedSubcommand(command, index + 2);
      if (parsed) {
        if (parsed.command.trim() !== "") {
          subcommands.push({ command: parsed.command, syntax: "process substitution" });
        }
        index = parsed.endIndex;
      }
    }
  }

  return subcommands;
}

function readBalancedParenthesizedSubcommand(
  command: string,
  startIndex: number,
): { readonly command: string; readonly endIndex: number } | undefined {
  let depth = 1;
  let quote: '"' | "'" | undefined;
  let escaped = false;

  for (let index = startIndex; index < command.length; index += 1) {
    const character = command[index];

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

    if (quote) {
      continue;
    }

    if (character === "(") {
      depth += 1;
      continue;
    }
    if (character === ")") {
      depth -= 1;
      if (depth === 0) {
        return { command: command.slice(startIndex, index), endIndex: index };
      }
    }
  }

  return undefined;
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

function unwrapExecutable(tokens: readonly string[]): { readonly commandName?: string; readonly args: readonly string[]; readonly innerCommand?: string } {
  let index = 0;
  while (index < tokens.length && isEnvAssignment(tokens[index] ?? "")) {
    index += 1;
  }

  while (index < tokens.length) {
    const commandName = basename(tokens[index] ?? "").toLowerCase();
    const args = tokens.slice(index + 1);

    if (SHELL_LEADING_CONTROL_WORDS.has(commandName)) {
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
        return { args: [], innerCommand: env.innerCommand };
      }
      index = env.index;
      continue;
    }

    if (SHELL_WRAPPERS.has(commandName)) {
      const innerCommand = shellCommandString(args);
      if (innerCommand) {
        return { args: [], innerCommand };
      }
    }

    return { commandName, args };
  }
  return { args: [] };
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
    if (arg === "-c" || /^-[A-Za-z]*c[A-Za-z]*$/u.test(arg) || arg.startsWith("-c")) {
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
  if (token.startsWith("/") || token.startsWith("~/")) {
    return /\.(?:sh|bash|zsh|command|ksh)$/iu.test(token);
  }
  return /\.(?:sh|bash|zsh|command|ksh)$/iu.test(token);
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
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index] ?? "";
    if (arg === "--") {
      break;
    }
    if (PACKAGE_MANAGER_CWD_OPTIONS_WITH_VALUES.has(arg)) {
      const value = args[index + 1];
      if (value) {
        directory = value;
      }
      index += 1;
      continue;
    }
    const inlineLongOption = PACKAGE_MANAGER_CWD_LONG_OPTIONS_WITH_VALUES.find((option) => arg.startsWith(`${option}=`));
    if (inlineLongOption) {
      const value = arg.slice(inlineLongOption.length + 1);
      if (value) {
        directory = value;
      }
      continue;
    }
    if (arg.startsWith("-C") && arg.length > 2) {
      directory = arg.slice(2);
      continue;
    }
    if (PACKAGE_MANAGER_OPTIONS_WITH_VALUES.has(arg)) {
      index += 1;
    }
  }
  return directory;
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
    if (arg === "-c") {
      return args[index + 1];
    }
    if (/^-[A-Za-z]*c[A-Za-z]*$/u.test(arg)) {
      return args[index + 1];
    }
    if (arg.startsWith("-c") && arg.length > 2) {
      return arg.slice(2);
    }
  }
  return undefined;
}

function unwrapEnv(tokens: readonly string[], startIndex: number): { readonly index: number; readonly innerCommand?: string } {
  let index = startIndex;
  while (index < tokens.length) {
    const token = tokens[index] ?? "";
    if (token === "--") {
      return { index: index + 1 };
    }
    if (token === "-S" || token === "--split-string") {
      return tokens[index + 1] ? { index: tokens.length, innerCommand: tokens[index + 1] } : { index: index + 1 };
    }
    if (token.startsWith("--split-string=")) {
      return { index: tokens.length, innerCommand: token.slice("--split-string=".length) };
    }
    if (token.startsWith("-S") && token.length > 2) {
      return { index: tokens.length, innerCommand: token.slice(2) };
    }
    if (ENV_OPTIONS_WITH_VALUES.has(token)) {
      index += 2;
      continue;
    }
    if ([...ENV_OPTIONS_WITH_VALUES].some((option) => option.startsWith("--") && token.startsWith(`${option}=`))) {
      index += 1;
      continue;
    }
    if (token.startsWith("-") || isEnvAssignment(token)) {
      index += 1;
      continue;
    }
    break;
  }
  return { index };
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
    if ([...optionsWithValues].some((option) => option.startsWith("--") && token.startsWith(`${option}=`))) {
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
    if (!["-exec", "-execdir", "-ok", "-okdir"].includes(args[index] ?? "")) {
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
  return token === ";" || token === "\\;" || token === "+";
}

function niceCommandText(args: readonly string[]): string | undefined {
  let index = 0;
  while (index < args.length) {
    const arg = args[index] ?? "";
    if (arg === "-n" || arg === "--adjustment") {
      index += 2;
      continue;
    }
    if (/^--adjustment=/.test(arg) || /^-\d+$/.test(arg)) {
      index += 1;
      continue;
    }
    return joinTokensAsCommand(args.slice(index));
  }
  return undefined;
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
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index] ?? "";
    if (arg === "--") {
      return undefined;
    }
    if (arg === "-c" || arg === "--call") {
      return args[index + 1];
    }
    if (arg.startsWith("--call=")) {
      return arg.slice("--call=".length);
    }
    if (arg.startsWith("-c") && arg.length > 2) {
      return arg.slice(2);
    }
    if (PACKAGE_EXEC_OPTIONS_WITH_VALUES.has(arg)) {
      index += 1;
      continue;
    }
    if ([...PACKAGE_EXEC_OPTIONS_WITH_VALUES].some((option) => option.startsWith("--") && arg.startsWith(`${option}=`))) {
      continue;
    }
    if (!arg.startsWith("-") || arg === "-") {
      return undefined;
    }
  }
  return undefined;
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
    if ([...optionsWithValues].some((option) => option.startsWith("--") && arg.startsWith(`${option}=`))) {
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
    ? meaningfulTokens.map((token) => /[\s;&|<>$()`]/u.test(token) ? JSON.stringify(token) : token).join(" ")
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
  if (commandName === "diskutil" && args.some((arg) => ["erasedisk", "partitiondisk", "zerodisk"].includes(arg.toLowerCase()))) {
    return "Disk formatting/raw disk operation is denied.";
  }
  if (commandName.startsWith("mkfs") || commandName === "fdisk") {
    return "Disk formatting/raw disk operation is denied.";
  }
  if (commandName === "dd" && args.some((arg) => /^(if|of)=\/dev\//.test(arg))) {
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
    ["rm", "rmdir", "mv", "rename", "rsync"].includes(commandName)
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
  return args.some((arg) => arg === "--recursive" || /^-[A-Za-z]*[rR][A-Za-z]*$/u.test(arg));
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
    const match = /^(?:if|of)=(.+)$/u.exec(arg);
    return match?.[1] ? [match[1]] : [];
  });
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
  return args.some((arg) => /^--delete(?:$|[-=])/u.test(arg));
}

function isReadLikeCommand(commandName: string): boolean {
  return READ_COMMANDS.has(commandName) || ADDITIONAL_READ_COMMANDS.has(commandName) || GREP_COMMANDS.has(commandName);
}

function isDynamicExecutableName(commandName: string): boolean {
  return DYNAMIC_EXECUTABLE_NAME_PATTERN.test(commandName);
}

function containsCloudCliLiteral(value: string): boolean {
  return CLOUD_CLI_LITERAL_PATTERN.test(value);
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
    /(^|\/)id_(rsa|dsa|ecdsa|ed25519)$/.test(lower) ||
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
    .replace(/\\/g, "/")
    .split("/")
    .filter(Boolean)
    .some((segment) => segment === ".env" || (segment.startsWith(".env") && /[*?[\]]/u.test(segment)));
}

function containsProtectedEnvPathReference(value: string): boolean {
  return /(?:^|[\s'"`(<>=:,/])(?:\.\/)?\.env(?:$|[\s'"`)>:,/]|[*?[\]])/u.test(value.replace(/\\/g, "/"));
}

function isGitPath(pathValue: string): boolean {
  const segments = pathValue
    .replace(/\\/g, "/")
    .replace(/\/+$/u, "")
    .split("/")
    .filter(Boolean);
  return segments.includes(".git");
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
  return /^[A-Za-z_][A-Za-z0-9_]*=.*/.test(value);
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
