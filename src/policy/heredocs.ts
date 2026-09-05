import { basename } from "node:path";

export interface PreparedHeredocs {
  readonly command: string;
  readonly error?: string;
  readonly ranges?: readonly { readonly start: number; readonly end: number }[];
}

interface Heredoc {
  readonly marker: string;
  readonly stripTabs: boolean;
  readonly start: number;
  readonly end: number;
  readonly consumer: string;
}

interface Replacement {
  readonly start: number;
  readonly end: number;
  readonly text: string;
}

interface HeredocScan {
  index: number;
  commandStart: number;
  lineStart: number;
  ranges: { start: number; end: number }[];
  quote?: "'" | '"';
  escaped: boolean;
  complexLine: boolean;
  pending: Heredoc[];
  replacements: Replacement[];
  error?: string;
}

interface QuotedDelimiterScan {
  index: number;
  marker: string;
  quoted: boolean;
  quote?: "'" | '"';
  done: boolean;
  invalid: boolean;
}

const STDIN_CODE_OPTIONS: Readonly<Record<string, string>> = {
  node: "--eval", python: "-c", python2: "-c", python3: "-c", ruby: "-e", perl: "-e", php: "-r",
  bash: "-c", sh: "-c", zsh: "-c",
};
const DATA_CONSUMERS = new Set(["cat", "wc"]);

/**
 * Produce analysis-only inline-code equivalents for supported quoted stdin
 * heredocs. Never execute or rewrite the tool input. Quoted data stays data;
 * shell/interpreter bodies keep their existing command/content checks.
 * Unsupported routing fails closed rather than silently discarding a body.
 */
export function prepareShellHeredocs(command: string): PreparedHeredocs {
  if (!command.includes("<<")) {
    return { command };
  }
  const state: HeredocScan = { index: 0, commandStart: 0, lineStart: 0, ranges: [], escaped: false, complexLine: false, pending: [], replacements: [] };
  while (state.index < command.length && !state.error) {
    advanceHeredocScan(command, state);
  }
  if (state.pending.length > 0 && !state.error) {
    state.error = "Heredoc has no body or closing delimiter.";
  }
  if (state.error) {
    return { command, error: state.error };
  }
  let prepared = command;
  for (const replacement of [...state.replacements].sort((a, b) => b.start - a.start)) {
    prepared = prepared.slice(0, replacement.start) + replacement.text + prepared.slice(replacement.end);
  }
  return { command: prepared, ranges: state.ranges };
}

function advanceHeredocScan(command: string, state: HeredocScan): void {
  const char = command[state.index] ?? "";
  if (state.escaped) {
    state.escaped = false;
    state.index += 1;
    return;
  }
  if (char === "\\" && state.quote !== "'") {
    state.escaped = true;
    state.index += 1;
    return;
  }
  if (char === state.quote) {
    state.quote = undefined;
  } else if (!state.quote && (char === "'" || char === '"')) {
    state.quote = char;
  } else if (!state.quote) {
    advanceUnquotedHeredocScan(command, state, char);
    return;
  }
  state.index += 1;
}

function advanceUnquotedHeredocScan(command: string, state: HeredocScan, char: string): void {
  if (char === "#" && (state.index === 0 || /[\s;|&]/u.test(command[state.index - 1] ?? ""))) {
    const newline = command.indexOf("\n", state.index);
    state.index = newline < 0 ? command.length : newline;
    return;
  }
  if (char === "\n") {
    consumeHeredocBodies(command, state);
    state.commandStart = state.index;
    state.lineStart = state.index;
    state.complexLine = false;
    return;
  }
  if (char === "<" && command[state.index + 1] === "<") {
    if (command[state.index + 2] === "<") {
      state.index += 3;
    } else {
      consumeHeredocHeader(command, state);
    }
    return;
  }
  if ("|&()`".includes(char)) {
    state.complexLine = true;
  }
  if (char === ";") {
    state.commandStart = state.index + 1;
  }
  state.index += 1;
}

function consumeHeredocHeader(command: string, state: HeredocScan): void {
  const operator = state.index;
  const stripTabs = command[operator + 2] === "-";
  let start = operator;
  while (start > state.commandStart && /\d/u.test(command[start - 1] ?? "")) {
    start -= 1;
  }
  if (start > state.commandStart && !/\s/u.test(command[start - 1] ?? "")) start = operator;
  const descriptor = command.slice(start, operator);
  if (descriptor && descriptor !== "0") {
    state.error = "Only stdin (fd 0) heredocs can be inspected safely.";
    return;
  }
  let markerStart = operator + (stripTabs ? 3 : 2);
  while (/[\t ]/u.test(command[markerStart] ?? "")) markerStart += 1;
  const delimiter = readQuotedDelimiter(command, markerStart);
  if (!delimiter) {
    state.error = "Unquoted or unsupported heredoc delimiters cannot be inspected safely; use a literal quoted delimiter.";
    return;
  }
  const prefix = command.slice(state.commandStart, start).trim();
  const consumer = basename(prefix.split(/\s/u)[0] ?? "").toLowerCase();
  if ((!Object.hasOwn(STDIN_CODE_OPTIONS, consumer) && !DATA_CONSUMERS.has(consumer)) || /(?:^|\s)--(?:\s|$)/u.test(prefix)) {
    state.error = "Heredoc stdin consumer or argument routing cannot be inspected safely.";
    return;
  }
  state.pending.push({ marker: delimiter.marker, stripTabs, start, end: delimiter.end, consumer });
  state.index = delimiter.end;
}

function readQuotedDelimiter(command: string, start: number): { readonly marker: string; readonly end: number } | undefined {
  const state: QuotedDelimiterScan = { index: start, marker: "", quoted: false, done: false, invalid: false };
  while (state.index < command.length && !state.done && !state.invalid) {
    advanceQuotedDelimiter(command, state);
  }
  return state.quoted && !state.quote && !state.invalid ? { marker: state.marker, end: state.index } : undefined;
}

function advanceQuotedDelimiter(command: string, state: QuotedDelimiterScan): void {
  const char = command[state.index] ?? "";
  if (char === "\n" || char === "\r") {
    state.done = true;
    state.invalid = Boolean(state.quote);
    return;
  }
  if (char === state.quote) {
    state.quote = undefined;
    state.index += 1;
    return;
  }
  if (!state.quote && (char === "'" || char === '"')) {
    state.quote = char;
    state.quoted = true;
    state.index += 1;
    return;
  }
  if (char === "\\" && state.quote !== "'") {
    consumeDelimiterEscape(command, state);
    return;
  }
  if (!state.quote && /[\s;|&<>()[\]{}$`]/u.test(char)) {
    state.done = true;
    return;
  }
  state.marker += char;
  state.index += 1;
}

function consumeDelimiterEscape(command: string, state: QuotedDelimiterScan): void {
  // Keep supported delimiters simple: shell-special quoting is not guessed.
  const next = command[state.index + 1];
  if (!next || /\s/u.test(next) || (state.quote === '"' && !/[\\$`"']/u.test(next))) {
    state.invalid = true;
    return;
  }
  state.marker += next;
  state.quoted = true;
  state.index += 2;
}

function consumeHeredocBodies(command: string, state: HeredocScan): void {
  const start = state.index + 1;
  state.index = start;
  if (state.pending.length === 0) return;
  if (state.complexLine) {
    state.error = "Heredocs combined with pipelines, substitutions or compound routing cannot be inspected safely.";
    return;
  }
  for (const heredoc of state.pending) {
    const body = readHeredocBody(command, state.index, heredoc);
    if (!body) {
      state.error = `Heredoc closing delimiter '${heredoc.marker}' was not found.`;
      return;
    }
    const option = Object.hasOwn(STDIN_CODE_OPTIONS, heredoc.consumer) ? STDIN_CODE_OPTIONS[heredoc.consumer] : undefined;
    state.replacements.push({ start: heredoc.start, end: heredoc.end, text: option ? ` ${option} ${quoteLiteralShellWord(body.text)} ` : " " });
    state.index = body.end;
  }
  state.replacements.push({ start, end: state.index, text: "" });
  state.ranges.push({ start: state.lineStart, end: state.index });
  state.pending = [];
}

function readHeredocBody(command: string, start: number, heredoc: Heredoc): { readonly text: string; readonly end: number } | undefined {
  const lines: string[] = [];
  let index = start;
  while (index < command.length) {
    const newline = command.indexOf("\n", index);
    const end = newline < 0 ? command.length : newline;
    const rawLine = command.slice(index, end);
    const line = heredoc.stripTabs ? rawLine.replace(/^\t+/u, "") : rawLine;
    if (line === heredoc.marker) {
      return { text: lines.join("\n"), end: newline < 0 ? end : end + 1 };
    }
    lines.push(line);
    index = end + 1;
  }
  return undefined;
}

function quoteLiteralShellWord(value: string): string {
  const escaped = value.replaceAll("'", String.raw`'\''`);
  return `'${escaped}'`;
}
