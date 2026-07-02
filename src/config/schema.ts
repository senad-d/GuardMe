import { POLICY_VERSION } from "../constants.ts";
import {
  PATH_POLICY_ACTIONS,
  type PathPolicyAction,
  type PolicyAction,
  type PolicyDiagnostic,
  type RuleSource,
  type RuleSourceKind,
  isPolicyAction,
} from "../policy/action.ts";

export const PATH_RULE_SECTIONS = [
  "allowPaths",
  "denyPaths",
  "zeroAccessPaths",
  "readOnlyPaths",
  "noDeletePaths",
  "protectedCredentialPaths",
] as const;
export type PathRuleSection = (typeof PATH_RULE_SECTIONS)[number];

export const COMMAND_RULE_SECTIONS = ["allowCommands", "denyCommands", "dangerousCommands"] as const;
export type CommandRuleSection = (typeof COMMAND_RULE_SECTIONS)[number];

export const POLICY_CONFIG_SECTIONS = [...PATH_RULE_SECTIONS, ...COMMAND_RULE_SECTIONS] as const;
export type PolicyConfigSection = (typeof POLICY_CONFIG_SECTIONS)[number];

const PATH_RULE_SECTION_SET: ReadonlySet<string> = new Set(PATH_RULE_SECTIONS);
const COMMAND_RULE_SECTION_SET: ReadonlySet<string> = new Set(COMMAND_RULE_SECTIONS);
const POLICY_CONFIG_SECTION_SET: ReadonlySet<string> = new Set(POLICY_CONFIG_SECTIONS);

export interface GuardMeRule {
  readonly pattern: string;
  readonly actions?: readonly PolicyAction[];
  readonly reason?: string;
}

export interface GuardMePathRule extends GuardMeRule {
  readonly actions?: readonly PathPolicyAction[];
}

export interface GuardMePolicyConfig {
  readonly version: number;
  readonly allowPaths: readonly GuardMePathRule[];
  readonly denyPaths: readonly GuardMePathRule[];
  readonly zeroAccessPaths: readonly GuardMePathRule[];
  readonly readOnlyPaths: readonly GuardMePathRule[];
  readonly noDeletePaths: readonly GuardMePathRule[];
  readonly allowCommands: readonly GuardMeRule[];
  readonly denyCommands: readonly GuardMeRule[];
  readonly dangerousCommands: readonly GuardMeRule[];
  readonly protectedCredentialPaths: readonly GuardMePathRule[];
}

export interface ConfigValidationResult {
  readonly config: GuardMePolicyConfig;
  readonly diagnostics: readonly PolicyDiagnostic[];
}

export interface ParsePolicyYamlResult {
  readonly data: Record<string, unknown>;
  readonly diagnostics: readonly PolicyDiagnostic[];
}

const ALL_PATH_ACTIONS: readonly PathPolicyAction[] = PATH_POLICY_ACTIONS;

export function createEmptyPolicyConfig(version = POLICY_VERSION): GuardMePolicyConfig {
  return {
    version,
    allowPaths: [],
    denyPaths: [],
    zeroAccessPaths: [],
    readOnlyPaths: [],
    noDeletePaths: [],
    allowCommands: [],
    denyCommands: [],
    dangerousCommands: [],
    protectedCredentialPaths: [],
  };
}

export function createBuiltInDefaultPolicy(): GuardMePolicyConfig {
  return {
    ...createEmptyPolicyConfig(POLICY_VERSION),
    allowPaths: [
      {
        pattern: "*tmp*",
        actions: ["read", "list", "write", "edit", "delete", "move", "rename"],
        reason: "Pi skill files may be loaded from sibling repositories or global skill directories.",
      },
      {
        pattern: "/dev/null",
        actions: ["write"],
        reason: "Allow shell stderr/stdout redirection sink.",
      },
      {
        pattern: "**/.pi/skills",
        actions: ["read", "list"],
        reason: "Pi skill files may be loaded from sibling repositories or global skill directories.",
      },
      {
        pattern: "**/.pi/skills/**",
        actions: ["read", "list"],
        reason: "Pi skill files may be loaded from sibling repositories or global skill directories.",
      },
      {
        pattern: "**/.pi/skill",
        actions: ["read", "list"],
        reason: "Pi skill files may be loaded from sibling repositories or global skill directories.",
      },
      {
        pattern: "**/.pi/skill/**",
        actions: ["read", "list"],
        reason: "Pi skill files may be loaded from sibling repositories or global skill directories.",
      },
      {
        pattern: "/opt/homebrew/lib/node_modules/@earendil-works",
        actions: ["read", "list"],
        reason: "Pi package documentation may be loaded from the local Homebrew node_modules installation.",
      },
      {
        pattern: "/opt/homebrew/lib/node_modules/@earendil-works/**",
        actions: ["read", "list"],
        reason: "Pi package documentation may be loaded from the local Homebrew node_modules installation.",
      },
    ],
    allowCommands: [
      { pattern: "true", reason: "Allow no-op shell fallback in compound commands." },
      { pattern: "pwd *", reason: "Project working-directory discovery." },
      { pattern: "mkdir *", reason: "Project directory creation after path protections pass." },
      { pattern: "tree *", reason: "Project directory tree after path protections pass." },
      { pattern: "ls *", reason: "Project file listing after path protections pass." },
      { pattern: "cat *", reason: "Project file reads after path protections pass." },
      { pattern: "head *", reason: "Project file reads after path protections pass." },
      { pattern: "tail *", reason: "Project file reads after path protections pass." },
      { pattern: "wc *", reason: "Project file reads after path protections pass." },
      { pattern: "grep *", reason: "Project search after path protections pass." },
      { pattern: "find *", reason: "Project discovery after path protections pass." },
      { pattern: "rg *", reason: "Project discovery after path protections pass." },
      { pattern: "npm *", reason: "Common project npm command." },
      { pattern: "node *", reason: "Common project quick action command." },
      { pattern: "git *", reason: "Common project git command." },
      { pattern: "wc *", reason: "Common project wc command." },
      { pattern: "jq *", reason: "Common project jq command." },
      { pattern: "yq *", reason: "Common project yq command." },
      { pattern: "fd *", reason: "Common project fd command." },
      { pattern: "sed *", reason: "Common project sed command." },
      { pattern: "nl *", reason: "Common project nl command." },
      { pattern: "sort", reason: "Common project sort command." },
      { pattern: "gitleaks *", reason: "Common project gitleaks command." },
      { pattern: "trivy *", reason: "Common project trivy command." },
      { pattern: "grype *", reason: "Common project grype command." },
      { pattern: "snyk *", reason: "Common project snyk command." },
      { pattern: "ps", reason: "Common project ps command." },
      { pattern: "if *", reason: "Common project if command." },
      { pattern: "cp *", reason: "Common project cp command." },
      { pattern: "mv *", reason: "Common project mv command." },
      { pattern: "cat *", reason: "Common project cat command." },
      { pattern: "test *", reason: "Common project test command." },
      { pattern: "2>*", reason: "Common project redirection command." },
      { pattern: "echo *", reason: "Common project echo command." },
      { pattern: "printf *", reason: "Common project printf command." },
      { pattern: "chmod *", reason: "Common project chmod command." },
      { pattern: "chown *", reason: "Common project chown command." },
      { pattern: "python3 */*.py *", reason: "Common project python3 command." },
      { pattern: "bash *.sh *", reason: "Common project bash command." },
      { pattern: "sh *.sh *", reason: "Common project sh command." },
      { pattern: "make *", reason: "Common project make command." },
      { pattern: "just *", reason: "Common project just command." },
      { pattern: "task *", reason: "Common project task command." },
      { pattern: "pytest *", reason: "Common project pytest command." },
      { pattern: "ruff *", reason: "Common project ruff command." },
      { pattern: "cargo *", reason: "Common project cargo command." },
      { pattern: "go *", reason: "Common project go command." },
      { pattern: "docker *", reason: "Common project docker command." },
      { pattern: "set -*", reason: "Common project pipeline command." },
      { pattern: "date *", reason: "Common project date command." },
      { pattern: "gh *", reason: "Common project github cli command." },
    ],
    denyPaths: [
      {
        pattern: "**/.env",
        actions: ALL_PATH_ACTIONS,
        reason: "Environment files may contain credentials.",
      },
      {
        pattern: "**/.env.*",
        actions: ["delete", "move", "rename"],
        reason: "Environment template files can be read or edited, but destructive changes require review.",
      },
      {
        pattern: "**/.npmrc",
        actions: ALL_PATH_ACTIONS,
        reason: "npm config may contain registry tokens.",
      },
      {
        pattern: "**/.pypirc",
        actions: ALL_PATH_ACTIONS,
        reason: "Python package config may contain publish tokens.",
      },
      {
        pattern: "**/.netrc",
        actions: ALL_PATH_ACTIONS,
        reason: "netrc files may contain machine credentials.",
      },
    ],
    zeroAccessPaths: [
      {
        pattern: "~/.ssh/**",
        actions: ALL_PATH_ACTIONS,
        reason: "SSH keys and config are never available to LLM tool calls.",
      },
      {
        pattern: "~/.gnupg/**",
        actions: ALL_PATH_ACTIONS,
        reason: "GPG keys and trust material are never available to LLM tool calls.",
      },
      {
        pattern: "~/.1password/**",
        actions: ALL_PATH_ACTIONS,
        reason: "Password-manager local data is never available to LLM tool calls.",
      },
    ],
    readOnlyPaths: [
      {
        pattern: "**.pi/**",
        actions: ["read", "list"],
        reason: "Project GuardMe policy should be changed through /guardme or explicit user edits.",
      },
      {
        pattern: ".pi/agent/guardme.yaml",
        actions: ["read", "list"],
        reason: "Project GuardMe policy should be changed through /guardme or explicit user edits.",
      },
      {
        pattern: "~/.pi/agent/guardme.yaml",
        actions: ["read", "list"],
        reason: "Global GuardMe policy should be changed through /guardme or explicit user edits.",
      },
      {
        pattern: ".pi/agent/guardme-settings.json",
        actions: ["read", "list"],
        reason: "Project GuardMe runtime settings should be changed through /guardme.",
      },
    ],
    noDeletePaths: [
      {
        pattern: ".git",
        actions: ["delete", "move", "rename"],
        reason: "Repository metadata must not be deleted, moved, or renamed.",
      },
      {
        pattern: ".git/**",
        actions: ["delete", "move", "rename"],
        reason: "Repository metadata must not be deleted, moved, or renamed.",
      },
      {
        pattern: "**/.git",
        actions: ["delete", "move", "rename"],
        reason: "Repository metadata must not be deleted, moved, or renamed.",
      },
      {
        pattern: "**/.git/**",
        actions: ["delete", "move", "rename"],
        reason: "Repository metadata must not be deleted, moved, or renamed.",
      },
      {
        pattern: "package-lock.json",
        actions: ["delete", "move", "rename"],
        reason: "Package lockfiles should not be removed without explicit user intent.",
      },
      {
        pattern: "pnpm-lock.yaml",
        actions: ["delete", "move", "rename"],
        reason: "Package lockfiles should not be removed without explicit user intent.",
      },
      {
        pattern: "yarn.lock",
        actions: ["delete", "move", "rename"],
        reason: "Package lockfiles should not be removed without explicit user intent.",
      },
    ],
    denyCommands: [
      { pattern: "aws", reason: "Cloud CLIs are always denied by GuardMe." },
      { pattern: "aws *", reason: "Cloud CLIs are always denied by GuardMe." },
      { pattern: "az", reason: "Cloud CLIs are always denied by GuardMe." },
      { pattern: "az *", reason: "Cloud CLIs are always denied by GuardMe." },
      { pattern: "gcloud", reason: "Cloud CLIs are always denied by GuardMe." },
      { pattern: "gcloud *", reason: "Cloud CLIs are always denied by GuardMe." },
      { pattern: "sudo *", reason: "Privilege escalation is blocked by default." },
      { pattern: "sudoedit *", reason: "Privilege escalation is blocked by default." },
      { pattern: "doas *", reason: "Privilege escalation is blocked by default." },
      { pattern: "chmod 777 *", reason: "World-writable permissions are unsafe by default." },
    ],
    dangerousCommands: [
      { pattern: "rm -rf *", reason: "Recursive force deletion requires coaching or user approval." },
      { pattern: "rm -fr *", reason: "Recursive force deletion requires coaching or user approval." },
      { pattern: "rm --recursive --force *", reason: "Recursive force deletion requires coaching or user approval." },
      { pattern: "git clean -f*", reason: "Forced git clean can remove untracked work." },
      { pattern: "find * -delete", reason: "find -delete can remove many files." },
      { pattern: "rsync * --delete*", reason: "rsync --delete can remove destination files." },
    ],
    protectedCredentialPaths: [
      { pattern: "~/.aws/**", actions: ALL_PATH_ACTIONS, reason: "AWS credentials are protected." },
      { pattern: "~/.azure/**", actions: ALL_PATH_ACTIONS, reason: "Azure credentials are protected." },
      { pattern: "~/.config/gcloud/**", actions: ALL_PATH_ACTIONS, reason: "Google Cloud credentials are protected." },
      { pattern: "~/.docker/config.json", actions: ALL_PATH_ACTIONS, reason: "Docker registry credentials are protected." },
      { pattern: "~/.npmrc", actions: ALL_PATH_ACTIONS, reason: "npm tokens are protected." },
      { pattern: "~/.netrc", actions: ALL_PATH_ACTIONS, reason: "Machine credentials are protected." },
      { pattern: "**/*credential*", actions: ALL_PATH_ACTIONS, reason: "Credential-like files are protected." },
      { pattern: "**/*secret*", actions: ALL_PATH_ACTIONS, reason: "Secret-like files are protected." },
      { pattern: "**/*token*", actions: ALL_PATH_ACTIONS, reason: "Token-like files are protected." },
    ],
  };
}

export function validateGuardMeConfig(input: unknown, source: RuleSource): ConfigValidationResult {
  const diagnostics: PolicyDiagnostic[] = [];
  const config = createEmptyPolicyConfig(POLICY_VERSION);

  if (!isRecord(input)) {
    diagnostics.push(configDiagnostic("error", "config.invalidRoot", "GuardMe policy must be a YAML object.", source));
    return { config, diagnostics };
  }

  let versionSupported = true;
  const version = input.version;
  if (version !== undefined) {
    if (typeof version !== "number" || !Number.isInteger(version)) {
      versionSupported = false;
      diagnostics.push(configDiagnostic("error", "config.invalidVersion", "Policy version must be an integer.", source));
    } else if (version !== POLICY_VERSION) {
      versionSupported = false;
      diagnostics.push(
        configDiagnostic("error", "config.unsupportedVersion", `Unsupported GuardMe policy version ${version}.`, source),
      );
    }
  }

  const normalized: Record<PolicyConfigSection, readonly GuardMeRule[]> = Object.fromEntries(
    POLICY_CONFIG_SECTIONS.map((section) => [section, validateRuleSection(section, input[section], source, diagnostics)]),
  ) as Record<PolicyConfigSection, readonly GuardMeRule[]>;

  for (const key of Object.keys(input)) {
    if (key !== "version" && !POLICY_CONFIG_SECTION_SET.has(key)) {
      diagnostics.push(configDiagnostic("warning", "config.unknownKey", `Unknown GuardMe policy key '${key}' ignored.`, source));
    }
  }

  if (!versionSupported) {
    return { config, diagnostics };
  }

  return {
    config: {
      ...config,
      allowPaths: normalized.allowPaths as readonly GuardMePathRule[],
      denyPaths: normalized.denyPaths as readonly GuardMePathRule[],
      zeroAccessPaths: normalized.zeroAccessPaths as readonly GuardMePathRule[],
      readOnlyPaths: normalized.readOnlyPaths as readonly GuardMePathRule[],
      noDeletePaths: normalized.noDeletePaths as readonly GuardMePathRule[],
      allowCommands: normalized.allowCommands,
      denyCommands: normalized.denyCommands,
      dangerousCommands: normalized.dangerousCommands,
      protectedCredentialPaths: normalized.protectedCredentialPaths as readonly GuardMePathRule[],
    },
    diagnostics,
  };
}

export function parsePolicyYaml(text: string, source: RuleSource): ParsePolicyYamlResult {
  const state: PolicyYamlParseState = {
    data: {},
    diagnostics: [],
    source,
  };

  for (const [index, rawLine] of text.split(/\r?\n/).entries()) {
    const line = parseYamlLine(rawLine, index);
    if (!line) {
      continue;
    }
    parsePolicyYamlLine(line, state);
  }

  return { data: state.data, diagnostics: state.diagnostics };
}

interface ParsedYamlLine {
  readonly lineNumber: number;
  readonly withoutComment: string;
  readonly indent: number;
  readonly trimmed: string;
}

interface PolicyYamlParseState {
  readonly data: Record<string, unknown>;
  readonly diagnostics: PolicyDiagnostic[];
  readonly source: RuleSource;
  currentSection?: PolicyConfigSection;
  currentItem?: Record<string, unknown>;
}

function parseYamlLine(rawLine: string, index: number): ParsedYamlLine | undefined {
  const withoutComment = stripYamlComment(rawLine);
  const trimmed = withoutComment.trim();
  if (trimmed === "") {
    return undefined;
  }
  return {
    lineNumber: index + 1,
    withoutComment,
    indent: countLeadingSpaces(withoutComment),
    trimmed,
  };
}

function parsePolicyYamlLine(line: ParsedYamlLine, state: PolicyYamlParseState): void {
  if (line.indent === 0) {
    parsePolicyYamlTopLevelLine(line, state);
    return;
  }
  parsePolicyYamlNestedLine(line, state);
}

function parsePolicyYamlTopLevelLine(line: ParsedYamlLine, state: PolicyYamlParseState): void {
  state.currentSection = undefined;
  state.currentItem = undefined;
  const parsed = parseKeyValue(line.trimmed);
  if (!parsed) {
    state.diagnostics.push(lineDiagnostic("error", "yaml.expectedKeyValue", "Expected a top-level key/value pair.", state.source, line.lineNumber));
    return;
  }

  const [key, valueText] = parsed;
  if (key === "version") {
    state.data.version = parseScalar(valueText);
    return;
  }
  if (!isPolicyConfigSection(key)) {
    state.data[key] = parseScalar(valueText);
    return;
  }
  if (valueText.trim() !== "") {
    state.diagnostics.push(
      lineDiagnostic("error", "yaml.sectionMustBeList", `Section '${key}' must be written as a YAML list.`, state.source, line.lineNumber),
    );
    state.data[key] = parseScalar(valueText);
    return;
  }
  state.currentSection = key;
  state.data[key] = [];
}

function parsePolicyYamlNestedLine(line: ParsedYamlLine, state: PolicyYamlParseState): void {
  if (!state.currentSection) {
    state.diagnostics.push(lineDiagnostic("error", "yaml.unexpectedIndent", "Unexpected indented line outside a section.", state.source, line.lineNumber));
    return;
  }
  if (line.indent === 2 && line.trimmed.startsWith("-")) {
    parsePolicyYamlListItem(line, state, state.currentSection);
    return;
  }
  if (line.indent >= 4 && state.currentItem) {
    parsePolicyYamlRuleProperty(line, state);
    return;
  }
  state.diagnostics.push(lineDiagnostic("error", "yaml.invalidIndent", "Invalid indentation for GuardMe policy YAML.", state.source, line.lineNumber));
}

function parsePolicyYamlListItem(line: ParsedYamlLine, state: PolicyYamlParseState, section: PolicyConfigSection): void {
  const currentItem: Record<string, unknown> = {};
  state.currentItem = currentItem;
  (state.data[section] as Record<string, unknown>[]).push(currentItem);
  const itemText = line.trimmed.slice(1).trim();
  if (itemText === "") {
    return;
  }
  const parsedItem = parseKeyValue(itemText);
  if (parsedItem) {
    currentItem[parsedItem[0]] = parseScalar(parsedItem[1]);
    return;
  }
  currentItem.pattern = parseScalar(itemText);
}

function parsePolicyYamlRuleProperty(line: ParsedYamlLine, state: PolicyYamlParseState): void {
  const parsed = parseKeyValue(line.trimmed);
  if (!parsed) {
    state.diagnostics.push(lineDiagnostic("error", "yaml.expectedRuleProperty", "Expected a rule property key/value pair.", state.source, line.lineNumber));
    return;
  }
  state.currentItem![parsed[0]] = parseScalar(parsed[1]);
}

function isPolicyConfigSection(value: string): value is PolicyConfigSection {
  return POLICY_CONFIG_SECTION_SET.has(value);
}

function validateRuleSection(
  section: PolicyConfigSection,
  value: unknown,
  source: RuleSource,
  diagnostics: PolicyDiagnostic[],
): readonly GuardMeRule[] {
  if (value === undefined) {
    return [];
  }

  if (!Array.isArray(value)) {
    diagnostics.push(configDiagnostic("error", "config.sectionNotArray", `Section '${section}' must be a list.`, source));
    return [];
  }

  const rules: GuardMeRule[] = [];
  for (const [index, rawRule] of value.entries()) {
    const ruleSource = { ...source, index };
    const rule = validateRule(section, rawRule, ruleSource, diagnostics);
    if (rule) {
      rules.push(rule);
    }
  }
  return rules;
}

function validateRule(
  section: PolicyConfigSection,
  rawRule: unknown,
  source: RuleSource,
  diagnostics: PolicyDiagnostic[],
): GuardMeRule | undefined {
  if (typeof rawRule === "string") {
    return { pattern: rawRule };
  }

  if (!isRecord(rawRule)) {
    diagnostics.push(configDiagnostic("error", "config.ruleNotObject", `Rule in '${section}' must be an object or string pattern.`, source));
    return undefined;
  }

  if (typeof rawRule.pattern !== "string" || rawRule.pattern.trim() === "") {
    diagnostics.push(configDiagnostic("error", "config.missingPattern", `Rule in '${section}' must include a non-empty pattern.`, source));
    return undefined;
  }

  const validatedActions = validateActions(section, rawRule.actions, source, diagnostics);
  if (!validatedActions.usable) {
    return undefined;
  }
  const reason = rawRule.reason;
  if (reason !== undefined && typeof reason !== "string") {
    diagnostics.push(configDiagnostic("error", "config.invalidReason", `Rule reason in '${section}' must be a string.`, source));
  }

  return {
    pattern: rawRule.pattern.trim(),
    ...(validatedActions.actions.length > 0 ? { actions: validatedActions.actions } : {}),
    ...(typeof reason === "string" ? { reason } : {}),
  };
}

interface ActionValidationResult {
  readonly actions: readonly PolicyAction[];
  readonly usable: boolean;
}

function validateActions(
  section: PolicyConfigSection,
  value: unknown,
  source: RuleSource,
  diagnostics: PolicyDiagnostic[],
): ActionValidationResult {
  if (value === undefined) {
    return { actions: [], usable: true };
  }

  if (COMMAND_RULE_SECTION_SET.has(section)) {
    diagnostics.push(
      configDiagnostic(
        "error",
        "config.commandActionsUnsupported",
        `Command rules in '${section}' do not support actions; split behavior by command pattern instead.`,
        source,
      ),
    );
    return { actions: [], usable: false };
  }

  if (!Array.isArray(value)) {
    diagnostics.push(configDiagnostic("error", "config.actionsNotArray", `Rule actions in '${section}' must be a list.`, source));
    return { actions: [], usable: false };
  }

  if (value.length === 0) {
    diagnostics.push(configDiagnostic("error", "config.actionsEmpty", `Rule actions in '${section}' must include at least one action or be omitted.`, source));
    return { actions: [], usable: false };
  }

  let invalidActionFound = false;
  const actions: PolicyAction[] = [];
  for (const rawAction of value) {
    if (typeof rawAction !== "string" || !isPolicyAction(rawAction)) {
      invalidActionFound = true;
      diagnostics.push(configDiagnostic("error", "config.invalidAction", `Invalid policy action '${String(rawAction)}'.`, source));
      continue;
    }
    if (PATH_RULE_SECTION_SET.has(section) && rawAction === "shell") {
      invalidActionFound = true;
      diagnostics.push(configDiagnostic("error", "config.invalidPathAction", "Path rules cannot use the shell action.", source));
      continue;
    }
    if (!actions.includes(rawAction)) {
      actions.push(rawAction);
    }
  }
  return { actions, usable: actions.length > 0 || !invalidActionFound };
}

function parseKeyValue(text: string): readonly [string, string] | undefined {
  const colonIndex = text.indexOf(":");
  if (colonIndex < 0) {
    return undefined;
  }
  return [text.slice(0, colonIndex).trim(), text.slice(colonIndex + 1).trim()];
}

function parseScalar(text: string): unknown {
  const trimmed = text.trim();
  if (trimmed === "") {
    return "";
  }
  if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
    const inner = trimmed.slice(1, -1).trim();
    return inner === "" ? [] : inner.split(",").map((part) => parseScalar(part));
  }
  if (trimmed.startsWith('"') && trimmed.endsWith('"')) {
    try {
      return JSON.parse(trimmed) as unknown;
    } catch {
      return trimmed.slice(1, -1);
    }
  }
  if (trimmed.startsWith("'") && trimmed.endsWith("'")) {
    return trimmed.slice(1, -1).replaceAll("''", "'");
  }
  if (/^-?\d+$/.test(trimmed)) {
    return Number.parseInt(trimmed, 10);
  }
  return trimmed;
}

function stripYamlComment(line: string): string {
  const commentIndex = findYamlCommentIndex(line);
  return commentIndex < 0 ? line : line.slice(0, commentIndex);
}

type YamlQuote = '"' | "'";

interface YamlQuoteScanResult {
  readonly quote: YamlQuote | undefined;
  readonly skipNext: boolean;
  readonly handled: boolean;
}

function findYamlCommentIndex(line: string): number {
  let quote: YamlQuote | undefined;
  for (let index = 0; index < line.length; index += 1) {
    const quoted = scanQuotedYamlCharacter(line, index, quote);
    if (quoted.handled) {
      quote = quoted.quote;
      if (quoted.skipNext) {
        index += 1;
      }
      continue;
    }

    const character = line[index];
    if (character === "'" || character === '"') {
      quote = character;
      continue;
    }
    if (isYamlCommentStart(line, index)) {
      return index;
    }
  }
  return -1;
}

function scanQuotedYamlCharacter(line: string, index: number, quote: YamlQuote | undefined): YamlQuoteScanResult {
  if (!quote) {
    return { quote, skipNext: false, handled: false };
  }
  const character = line[index];
  if (quote === "'" && character === "'" && line[index + 1] === "'") {
    return { quote, skipNext: true, handled: true };
  }
  if (character === quote && quote === "'") {
    return { quote: undefined, skipNext: false, handled: true };
  }
  if (character === '"' && quote === '"' && !isEscapedDoubleQuote(line, index)) {
    return { quote: undefined, skipNext: false, handled: true };
  }
  return { quote, skipNext: false, handled: true };
}

function isYamlCommentStart(line: string, index: number): boolean {
  return line[index] === "#" && (index === 0 || /\s/u.test(line[index - 1] ?? ""));
}

function isEscapedDoubleQuote(line: string, quoteIndex: number): boolean {
  let backslashCount = 0;
  for (let index = quoteIndex - 1; index >= 0 && line[index] === "\\"; index -= 1) {
    backslashCount += 1;
  }
  return backslashCount % 2 === 1;
}

function countLeadingSpaces(line: string): number {
  const match = /^ */u.exec(line);
  return match?.[0].length ?? 0;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function configDiagnostic(
  severity: PolicyDiagnostic["severity"],
  code: string,
  message: string,
  source: RuleSource,
): PolicyDiagnostic {
  return { severity, code, message, source };
}

function lineDiagnostic(
  severity: PolicyDiagnostic["severity"],
  code: string,
  message: string,
  source: RuleSource,
  line: number,
): PolicyDiagnostic {
  return { severity, code, message, source, ruleIndex: line };
}

export function createRuleSource(kind: RuleSourceKind, path?: string): RuleSource {
  return { kind, ...(path ? { path } : {}) };
}
