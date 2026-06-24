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
const SHELL_EXTENSIONS = new Set([".sh", ".bash", ".zsh", ".command", ".ksh"]);
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
  const normalized = pathValue.replace(/\\/g, "/");
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
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_SCRIPT_BYTES;
  const sourcePath = options.path;
  const byteLength = Buffer.byteLength(options.content, "utf8");
  const pathCommandBearing = isCommandBearingPath(sourcePath);
  const shebangShell = hasShellShebang(options.content);
  const commandBearing = options.forceCommandBearing || options.shellHint || pathCommandBearing || shebangShell || contentHasObviousCommandContext(options.content);

  if (!commandBearing) {
    return { commandBearing: false, commands: [] };
  }

  if (byteLength > maxBytes) {
    return {
      commandBearing: true,
      commands: [],
      uninspectable: {
        reason: `Command-bearing content is too large to inspect safely (${byteLength} bytes).`,
        context: "unknown-command-content",
        ...(sourcePath ? { sourcePath } : {}),
      },
    };
  }

  if (options.content.includes("\0")) {
    return {
      commandBearing: true,
      commands: [],
      uninspectable: {
        reason: "Command-bearing content appears to be binary and cannot be inspected safely.",
        context: "unknown-command-content",
        ...(sourcePath ? { sourcePath } : {}),
      },
    };
  }

  const lowerName = basename(sourcePath ?? "").toLowerCase();
  if (lowerName === "package.json") {
    return extractPackageJsonScripts(options.content, sourcePath);
  }

  const commands: ExtractedScriptCommand[] = [];
  if (isMakefilePath(sourcePath)) {
    commands.push(...extractMakefileRecipes(options.content, sourcePath));
  } else if (isDockerfilePath(sourcePath)) {
    commands.push(...extractDockerfileRuns(options.content, sourcePath));
  } else if (isCiWorkflowPath(sourcePath) || contentHasCiRunBlock(options.content)) {
    commands.push(...extractCiRunCommands(options.content, sourcePath));
  } else if (options.shellHint || shebangShell || isShellPath(sourcePath)) {
    commands.push(...extractShellScriptCommands(options.content, sourcePath));
  }

  if (commands.length === 0 && options.forceCommandBearing && !shebangShell && !isShellPath(sourcePath) && !options.shellHint) {
    return {
      commandBearing: true,
      commands: [],
      uninspectable: {
        reason: "Local executable content is not a recognized text script and cannot be inspected confidently.",
        context: "unknown-command-content",
        ...(sourcePath ? { sourcePath } : {}),
      },
    };
  }

  return { commandBearing: true, commands };
}

export function redactedCommandPreview(command: string, maxLength = 160): string {
  const normalized = normalizeCommand(command);
  const redacted = redactSensitiveText(normalized).replace(/[\u001B\u009B][[\]()#;?]*(?:[0-9]{1,4}(?:;[0-9]{0,4})*)?[0-9A-ORZcf-nqry=><]/g, "");
  return redacted.length <= maxLength ? redacted : `${redacted.slice(0, Math.max(0, maxLength - 1))}…`;
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
  return content.split(/\r?\n/).flatMap((line, index) => {
    if (!/^\t/.test(line)) {
      return [];
    }
    const command = line.replace(/^\t[@+-]*/u, "").trim();
    return shellLineLooksEvaluable(command) ? [commandRecord(command, index + 1, "makefile-recipe", "Makefile recipe", sourcePath)] : [];
  });
}

function extractDockerfileRuns(content: string, sourcePath: string | undefined): readonly ExtractedScriptCommand[] {
  const logicalLines = joinContinuationLines(content);
  return logicalLines.flatMap((line) => {
    const match = /^\s*RUN\s+(.+)$/iu.exec(line.text);
    return match?.[1]
      ? [commandRecord(match[1], line.lineStart, "dockerfile-run", "Dockerfile RUN", sourcePath, line.lineEnd)]
      : [];
  });
}

function extractCiRunCommands(content: string, sourcePath: string | undefined): readonly ExtractedScriptCommand[] {
  const lines = content.split(/\r?\n/);
  const commands: ExtractedScriptCommand[] = [];

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? "";
    const match = /^(\s*)(?:-\s*)?run:\s*(.*)$/u.exec(line);
    if (!match) {
      continue;
    }

    const indent = match[1]?.length ?? 0;
    const value = (match[2] ?? "").trim();
    if (isYamlBlockScalarHeader(value)) {
      const block: string[] = [];
      let endIndex = index;
      for (let blockIndex = index + 1; blockIndex < lines.length; blockIndex += 1) {
        const blockLine = lines[blockIndex] ?? "";
        if (blockLine.trim() !== "" && countLeadingSpaces(blockLine) <= indent) {
          break;
        }
        block.push(blockLine.slice(Math.min(blockLine.length, indent + 2)));
        endIndex = blockIndex;
      }
      commands.push(...extractShellScriptCommands(block.join("\n"), sourcePath, index + 2, "ci-run", "CI run block"));
      index = endIndex;
      continue;
    }

    if (value !== "") {
      commands.push(commandRecord(unquoteYamlScalar(value), index + 1, "ci-run", "CI run", sourcePath));
    }
  }

  return commands;
}

function extractShellScriptCommands(
  content: string,
  sourcePath: string | undefined,
  lineOffset = 1,
  context: ScriptContentContext = "shell-script",
  label = "shell script",
): readonly ExtractedScriptCommand[] {
  const commands: ExtractedScriptCommand[] = [];
  const lines = content.split(/\r?\n/);
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

function findShellHeredocRanges(lines: readonly string[]): readonly {
  readonly marker: string;
  readonly start: number;
  readonly bodyStart: number;
  readonly end: number;
  readonly body: readonly string[];
}[] {
  const ranges = [] as {
    readonly marker: string;
    readonly start: number;
    readonly bodyStart: number;
    readonly end: number;
    readonly body: readonly string[];
  }[];

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? "";
    const match = /(?:^|\s)(?:bash|sh|zsh)\b[^\n]*<<-?\s*['"]?([A-Za-z_][A-Za-z0-9_]*)['"]?/u.exec(line);
    if (!match?.[1]) {
      continue;
    }
    const marker = match[1];
    const body: string[] = [];
    let end = index;
    for (let bodyIndex = index + 1; bodyIndex < lines.length; bodyIndex += 1) {
      const bodyLine = lines[bodyIndex] ?? "";
      if (bodyLine.trim() === marker) {
        end = bodyIndex;
        break;
      }
      body.push(bodyLine);
      end = bodyIndex;
    }
    ranges.push({ marker, start: index + 1, bodyStart: index + 1, end: end + 1, body });
    index = end;
  }

  return ranges;
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
  const lines = content.split(/\r?\n/);

  for (const [index, line] of lines.entries()) {
    const lineNumber = index + 1;
    if (current === "") {
      start = lineNumber;
    }
    const trimmedEnd = line.replace(/\s+$/u, "");
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
  const withoutLeadingDecorators = line.replace(/^[@+-]+/u, "").trim();
  if (withoutLeadingDecorators === "" || withoutLeadingDecorators.startsWith("#")) {
    return false;
  }
  if (/^(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*=(?:.|\s)*$/u.test(withoutLeadingDecorators) && !/[;&|`$()<>]/u.test(withoutLeadingDecorators)) {
    return false;
  }
  if (/^[A-Za-z_][A-Za-z0-9_]*\s*\(\)\s*\{?\s*$/u.test(withoutLeadingDecorators)) {
    return false;
  }
  const firstToken = tokenizeShellCommand(withoutLeadingDecorators)[0]?.toLowerCase();
  return firstToken ? !SHELL_CONTROL_ONLY.has(firstToken) : false;
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
    if (character === "#" && !quote && (index === 0 || /\s/u.test(line[index - 1] ?? ""))) {
      return line.slice(0, index);
    }
  }
  return line;
}

function normalizeCommand(command: string): string {
  return command.trim().replace(/\s+/g, " ");
}

function hasShellShebang(content: string): boolean {
  const firstLine = content.split(/\r?\n/, 1)[0] ?? "";
  return /^#!.*\b(?:ba|z|k)?sh\b/u.test(firstLine) || /^#!.*\benv\s+(?:ba|z|k)?sh\b/u.test(firstLine);
}

function contentHasObviousCommandContext(content: string): boolean {
  return /^\s*run:\s*(?:\||>|\S)/mu.test(content) || /^\s*RUN\s+\S/imu.test(content);
}

function contentHasCiRunBlock(content: string): boolean {
  return /^\s*run:\s*(?:\||>|\S)/mu.test(content);
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
  const normalized = pathValue.replace(/\\/g, "/").toLowerCase();
  return CI_EXTENSIONS.has(extname(normalized)) && (normalized.includes(".github/workflows/") || normalized.includes("/workflows/"));
}

function findLineNumber(content: string, needle: string): number {
  const index = content.indexOf(needle);
  if (index < 0) {
    return 1;
  }
  return content.slice(0, index).split(/\r?\n/).length;
}

function countLeadingSpaces(line: string): number {
  return line.match(/^ */u)?.[0].length ?? 0;
}

function isYamlBlockScalarHeader(value: string): boolean {
  const header = value.replace(/\s+#.*$/u, "").trim();
  return /^[|>](?:[+-]?\d*|\d*[+-]?)$/u.test(header);
}

function unquoteYamlScalar(value: string): string {
  if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
    return value.slice(1, -1);
  }
  return value;
}

function lineIsInsideRanges(lineNumber: number, ranges: readonly { readonly start: number; readonly end: number }[]): boolean {
  return ranges.some((range) => lineNumber >= range.start && lineNumber <= range.end);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
