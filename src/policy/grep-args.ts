// Option-aware argument split for grep and rg. Treating every non-option word
// as a path made search text such as `rg '\.env|token' src` look like a
// credential file reference and hard-denied ordinary content searches.

export interface GrepArgsSplit {
  /** Positional words after the search pattern (or all of them when the pattern came from -e/-f). */
  readonly operands: readonly string[];
  /** Files the tool reads through options such as -f or --ignore-file. */
  readonly optionFiles: readonly string[];
  /** Argument indexes that hold search text or exclusion globs, never files the tool opens. */
  readonly nonPathIndexes: ReadonlySet<number>;
  /** True when the pattern came from -e/--regexp/-f/--file or rg runs without a pattern (--files). */
  readonly explicitPattern: boolean;
}

// Short options whose next word (or attached rest) is a value.
const GREP_SHORT_VALUE_OPTIONS = new Set(["A", "B", "C", "e", "f", "m", "d", "D"]);
const RG_SHORT_VALUE_OPTIONS = new Set(["A", "B", "C", "e", "f", "g", "j", "m", "M", "r", "t", "T", "d", "E"]);

// Long options whose next word is a value when not written as --opt=value.
const GREP_LONG_VALUE_OPTIONS = new Set([
  "after-context", "before-context", "context", "regexp", "file", "max-count", "include", "exclude",
  "exclude-dir", "exclude-from", "label", "binary-files", "devices", "directories", "group-separator",
]);
const RG_LONG_VALUE_OPTIONS = new Set([
  "after-context", "before-context", "context", "regexp", "file", "max-count", "glob", "iglob", "type",
  "type-not", "type-add", "type-clear", "threads", "max-columns", "replace", "max-depth", "maxdepth",
  "encoding", "sort", "sortr", "color", "colors", "ignore-file", "max-filesize", "engine", "pre", "pre-glob",
  "context-separator", "field-match-separator", "field-context-separator", "path-separator",
  "dfa-size-limit", "regex-size-limit", "hyperlink-format",
]);

// Count options: only a numeric next word is consumed, so an optional-value
// form (BSD `--context`) never swallows a real operand.
const COUNT_OPTIONS = new Set(["A", "B", "C", "m", "M", "j", "d", "after-context", "before-context", "context", "max-count", "max-columns", "threads", "max-depth", "maxdepth"]);
const PATTERN_OPTIONS = new Set(["e", "regexp"]);
const PATTERN_FILE_OPTIONS = new Set(["f", "file"]);
const FILE_VALUE_OPTIONS = new Set(["exclude-from", "ignore-file"]);
const EXCLUSION_OPTIONS = new Set(["exclude", "exclude-dir"]);
const GLOB_OPTIONS = new Set(["g", "glob", "iglob"]);
const RG_PATTERNLESS_FLAGS = new Set(["--files", "--type-list"]);

// Generic exclusion flags (trivy, tar, rsync, linters): their values name
// what the tool must skip, so a protected name there is never accessed.
const GENERIC_EXCLUSION_OPTIONS = new Set(["--skip-files", "--skip-dirs", "--exclude", "--exclude-dir", "--ignore"]);

interface OptionValue {
  readonly name: string;
  readonly value: string | undefined;
  readonly valueIndex: number | undefined;
  readonly consumedNext: boolean;
}

export function splitGrepArgs(args: readonly string[], isRg: boolean): GrepArgsSplit {
  const positionals: { readonly value: string; readonly index: number }[] = [];
  const optionFiles: string[] = [];
  const nonPathIndexes = new Set<number>();
  let explicitPattern = isRg && args.some((arg) => RG_PATTERNLESS_FLAGS.has(arg));
  let afterDoubleDash = false;

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index] ?? "";
    if (afterDoubleDash || arg === "-" || !arg.startsWith("-")) {
      positionals.push({ value: arg, index });
      continue;
    }
    if (arg === "--") {
      afterDoubleDash = true;
      continue;
    }
    const option = readOptionValue(args, index, isRg);
    if (!option) {
      continue;
    }
    if (option.consumedNext) {
      index += 1;
    }
    explicitPattern = recordOptionValue(option, index, optionFiles, nonPathIndexes) || explicitPattern;
  }

  if (!explicitPattern && positionals[0]) {
    nonPathIndexes.add(positionals[0].index);
  }
  return {
    operands: (explicitPattern ? positionals : positionals.slice(1)).map((entry) => entry.value),
    optionFiles,
    nonPathIndexes,
    explicitPattern,
  };
}

/** Returns true when the option supplied the search pattern. */
function recordOptionValue(option: OptionValue, index: number, optionFiles: string[], nonPathIndexes: Set<number>): boolean {
  const valueIndex = option.valueIndex ?? index;
  if (PATTERN_OPTIONS.has(option.name)) {
    nonPathIndexes.add(valueIndex);
    return true;
  }
  if (PATTERN_FILE_OPTIONS.has(option.name)) {
    if (option.value !== undefined) optionFiles.push(option.value);
    return true;
  }
  if (FILE_VALUE_OPTIONS.has(option.name) && option.value !== undefined) {
    optionFiles.push(option.value);
    return false;
  }
  if (EXCLUSION_OPTIONS.has(option.name) || (GLOB_OPTIONS.has(option.name) && option.value?.startsWith("!"))) {
    nonPathIndexes.add(valueIndex);
  }
  return false;
}

function readOptionValue(args: readonly string[], index: number, isRg: boolean): OptionValue | undefined {
  const arg = args[index] ?? "";
  if (arg.startsWith("--")) {
    return readLongOptionValue(args, index, isRg ? RG_LONG_VALUE_OPTIONS : GREP_LONG_VALUE_OPTIONS);
  }
  return readShortOptionValue(args, index, isRg ? RG_SHORT_VALUE_OPTIONS : GREP_SHORT_VALUE_OPTIONS);
}

function readLongOptionValue(args: readonly string[], index: number, valueOptions: ReadonlySet<string>): OptionValue | undefined {
  const arg = args[index] ?? "";
  const equals = arg.indexOf("=");
  if (equals > 2) {
    return { name: arg.slice(2, equals), value: arg.slice(equals + 1), valueIndex: index, consumedNext: false };
  }
  const name = arg.slice(2);
  if (!valueOptions.has(name)) {
    return undefined;
  }
  return nextWordValue(args, index, name);
}

function readShortOptionValue(args: readonly string[], index: number, valueOptions: ReadonlySet<string>): OptionValue | undefined {
  const flags = (args[index] ?? "").slice(1);
  for (let position = 0; position < flags.length; position += 1) {
    const flag = flags[position] ?? "";
    if (!valueOptions.has(flag)) {
      continue;
    }
    const attached = flags.slice(position + 1);
    if (attached !== "") {
      return { name: flag, value: attached, valueIndex: index, consumedNext: false };
    }
    return nextWordValue(args, index, flag);
  }
  return undefined;
}

function nextWordValue(args: readonly string[], index: number, name: string): OptionValue {
  const next = args[index + 1];
  if (next === undefined || (COUNT_OPTIONS.has(name) && !/^\d+$/u.test(next))) {
    return { name, value: undefined, valueIndex: undefined, consumedNext: false };
  }
  return { name, value: next, valueIndex: index + 1, consumedNext: true };
}

/**
 * Arguments that can name a file the command touches. Search text, negated
 * globs and exclusion values are left out; a search pattern that starts with
 * `/` or `~` stays in, because it may be a mis-parsed path operand.
 */
export function credentialScanArgs(commandName: string | undefined, args: readonly string[], isGrep: boolean): readonly string[] {
  const skipped = isGrep ? splitGrepArgs(args, commandName === "rg").nonPathIndexes : new Set<number>();
  const kept: string[] = [];
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index] ?? "";
    if (isGenericExclusionValue(args, index)) {
      continue;
    }
    if (skipped.has(index) && !arg.startsWith("/") && !arg.startsWith("~")) {
      continue;
    }
    kept.push(arg);
  }
  return kept;
}

function isGenericExclusionValue(args: readonly string[], index: number): boolean {
  const arg = args[index] ?? "";
  const equals = arg.indexOf("=");
  if (arg.startsWith("--") && equals > 2 && GENERIC_EXCLUSION_OPTIONS.has(arg.slice(0, equals))) {
    return true;
  }
  return GENERIC_EXCLUSION_OPTIONS.has(args[index - 1] ?? "") && !arg.startsWith("-");
}
