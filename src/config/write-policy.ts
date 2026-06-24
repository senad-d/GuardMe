import { randomUUID } from "node:crypto";
import { lstat, mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

import { POLICY_VERSION } from "../constants.ts";
import type { PolicyDiagnostic, PolicyRequest, UserDecision } from "../policy/action.ts";
import { redactSensitiveText } from "../policy/redact.ts";
import { loadPolicyConfigFile, resolvePolicyConfigPaths } from "./load-config.ts";
import {
  COMMAND_RULE_SECTIONS,
  type CommandRuleSection,
  type GuardMePolicyConfig,
  type GuardMeRule,
  PATH_RULE_SECTIONS,
  type PathRuleSection,
  createEmptyPolicyConfig,
} from "./schema.ts";

export type PolicyWriteScope = "local" | "global";

export interface PersistUserDecisionRuleOptions {
  readonly cwd: string;
  readonly homeDir?: string;
  readonly policyPath?: string;
  readonly scope: PolicyWriteScope;
  readonly decision: UserDecision;
  readonly request: PolicyRequest;
  readonly hardDenied?: boolean;
  readonly reason?: string;
}

export interface PersistUserDecisionRuleResult {
  readonly saved: boolean;
  readonly path: string;
  readonly section?: PathRuleSection | CommandRuleSection;
  readonly diagnostics: readonly PolicyDiagnostic[];
  readonly reason?: string;
}

export interface AppendPolicyConfigRule {
  readonly section: PathRuleSection | CommandRuleSection;
  readonly rule: GuardMeRule;
}

export interface AppendPolicyConfigRulesOptions {
  readonly cwd: string;
  readonly homeDir?: string;
  readonly policyPath?: string;
  readonly scope: PolicyWriteScope;
  readonly rules: readonly AppendPolicyConfigRule[];
}

export interface AppendPolicyConfigRulesResult {
  readonly saved: boolean;
  readonly path: string;
  readonly diagnostics: readonly PolicyDiagnostic[];
  readonly added: number;
  readonly skipped: number;
  readonly created: boolean;
  readonly reason?: string;
}

export interface PolicyWriteTargetValidationOptions {
  readonly cwd: string;
  readonly homeDir?: string;
  readonly path: string;
  readonly scope: PolicyWriteScope;
}

export interface PolicyWriteTargetValidationResult {
  readonly safe: boolean;
  readonly diagnostics: readonly PolicyDiagnostic[];
  readonly reason?: string;
}

export async function persistUserDecisionRule(
  options: PersistUserDecisionRuleOptions,
): Promise<PersistUserDecisionRuleResult> {
  const path = options.policyPath ?? policyPathForScope(options.scope, options.cwd, options.homeDir);
  if (isAllowDecision(options.decision) && options.hardDenied) {
    return {
      saved: false,
      path,
      diagnostics: [
        {
          severity: "error",
          code: "policyWrite.hardDenyAllowRejected",
          message: "GuardMe refused to save an allow rule for a hard-denied action.",
          source: { kind: options.scope === "global" ? "global" : "local", path },
          path,
        },
      ],
      reason: "Hard-denied actions cannot be converted into allow rules.",
    };
  }

  const ruleResult = ruleFromDecision(options);
  if (!ruleResult) {
    return {
      saved: false,
      path,
      diagnostics: [
        {
          severity: "error",
          code: "policyWrite.unsupportedDecision",
          message: `Unsupported GuardMe user decision '${options.decision}'.`,
          source: { kind: options.scope === "global" ? "global" : "local", path },
          path,
        },
      ],
      reason: "Unsupported GuardMe user decision.",
    };
  }
  if ("rejected" in ruleResult) {
    return {
      saved: false,
      path,
      diagnostics: [
        {
          severity: "error",
          code: ruleResult.code,
          message: ruleResult.message,
          source: { kind: options.scope === "global" ? "global" : "local", path },
          path,
        },
      ],
      reason: ruleResult.reason,
    };
  }

  const rule = ruleResult;

  const safety = await validatePolicyWriteTarget({ cwd: options.cwd, homeDir: options.homeDir, path, scope: options.scope });
  if (!safety.safe) {
    return {
      saved: false,
      path,
      section: rule.section,
      diagnostics: safety.diagnostics,
      reason: safety.reason,
    };
  }

  const loaded = await loadPolicyConfigFile(path, options.scope === "global" ? "global" : "local");
  const errors = loaded.diagnostics.filter((diagnostic) => diagnostic.severity === "error");
  if (errors.length > 0) {
    return {
      saved: false,
      path,
      section: rule.section,
      diagnostics: loaded.diagnostics,
      reason: "Existing GuardMe YAML has validation errors or could not be loaded safely; refusing to rewrite it automatically.",
    };
  }

  const config = appendRule(loaded.found ? loaded.config : createEmptyPolicyConfig(POLICY_VERSION), rule.section, rule.rule);
  await writePolicyConfigFile(path, config, { cwd: options.cwd, homeDir: options.homeDir, scope: options.scope });

  return {
    saved: true,
    path,
    section: rule.section,
    diagnostics: loaded.diagnostics,
  };
}

export async function appendPolicyConfigRules(
  options: AppendPolicyConfigRulesOptions,
): Promise<AppendPolicyConfigRulesResult> {
  const path = options.policyPath ?? policyPathForScope(options.scope, options.cwd, options.homeDir);
  const source = { kind: options.scope === "global" ? "global" : "local", path } as const;
  const safety = await validatePolicyWriteTarget({ cwd: options.cwd, homeDir: options.homeDir, path, scope: options.scope });
  if (!safety.safe) {
    return {
      saved: false,
      path,
      diagnostics: safety.diagnostics,
      added: 0,
      skipped: 0,
      created: false,
      reason: safety.reason,
    };
  }

  const loaded = await loadPolicyConfigFile(path, options.scope === "global" ? "global" : "local");
  const errors = loaded.diagnostics.filter((diagnostic) => diagnostic.severity === "error");
  if (errors.length > 0) {
    return {
      saved: false,
      path,
      diagnostics: loaded.diagnostics,
      added: 0,
      skipped: 0,
      created: false,
      reason: "Existing GuardMe YAML has validation errors or could not be loaded safely; refusing to update it automatically.",
    };
  }

  const normalizedRules: AppendPolicyConfigRule[] = [];
  for (const entry of options.rules) {
    const normalizedRule = normalizeAppendRule(entry.section, entry.rule);
    if (!normalizedRule) {
      continue;
    }
    const secretDiagnostic = secretCommandRuleDiagnostic(entry.section, normalizedRule, source);
    if (secretDiagnostic) {
      return {
        saved: false,
        path,
        diagnostics: [...loaded.diagnostics, secretDiagnostic],
        added: 0,
        skipped: 0,
        created: !loaded.found,
        reason: "Command contains secret-like values; add a sanitized policy rule manually.",
      };
    }
    normalizedRules.push({ section: entry.section, rule: normalizedRule });
  }

  let config = loaded.found ? loaded.config : createEmptyPolicyConfig(POLICY_VERSION);
  const addedRules: AppendPolicyConfigRule[] = [];
  let skipped = options.rules.length - normalizedRules.length;
  for (const entry of normalizedRules) {
    const nextConfig = appendRule(config, entry.section, entry.rule);
    if (nextConfig === config) {
      skipped += 1;
      continue;
    }
    config = nextConfig;
    addedRules.push(entry);
  }

  if (addedRules.length === 0) {
    return {
      saved: false,
      path,
      diagnostics: loaded.diagnostics,
      added: 0,
      skipped,
      created: !loaded.found,
      reason: skipped > 0 ? "No new GuardMe rules to append; all submitted rules already exist." : "No GuardMe rules were submitted.",
    };
  }

  const text = loaded.found ? await readFile(path, "utf8") : "";
  const nextText = loaded.found && text.trim().length > 0
    ? appendRulesToPolicyYamlText(text, addedRules)
    : renderPolicyConfigYaml(config);
  await writePolicyTextAtomically(path, nextText, { cwd: options.cwd, homeDir: options.homeDir, scope: options.scope });

  return {
    saved: true,
    path,
    diagnostics: loaded.diagnostics,
    added: addedRules.length,
    skipped,
    created: !loaded.found,
  };
}

export async function validatePolicyWriteTarget(
  options: PolicyWriteTargetValidationOptions,
): Promise<PolicyWriteTargetValidationResult> {
  const targetPath = resolve(options.path);
  const scopeRoot = resolve(options.scope === "global" ? options.homeDir ?? homedir() : options.cwd);
  const source = { kind: options.scope === "global" ? "global" : "local", path: targetPath } as const;

  if (!isPathInsideRoot(scopeRoot, targetPath)) {
    return {
      safe: false,
      diagnostics: [
        {
          severity: "error",
          code: "policyWrite.pathEscapesScope",
          message: `Refusing to write GuardMe ${options.scope} policy outside its expected scope.`,
          source,
          path: targetPath,
        },
      ],
      reason: `GuardMe ${options.scope} policy path is outside its expected scope.`,
    };
  }

  const targetSymlink = await existingSymlinkInPath(targetPath, scopeRoot, true);
  if (targetSymlink) {
    return {
      safe: false,
      diagnostics: [
        {
          severity: "error",
          code: "policyWrite.symlinkRejected",
          message: "Refusing to write GuardMe policy through a symbolic link.",
          source,
          path: targetSymlink,
        },
      ],
      reason: "GuardMe policy writes do not follow symbolic links.",
    };
  }

  return { safe: true, diagnostics: [] };
}

export async function writePolicyConfigFile(
  path: string,
  config: GuardMePolicyConfig,
  options: Omit<PolicyWriteTargetValidationOptions, "path">,
): Promise<void> {
  const safety = await validatePolicyWriteTarget({ ...options, path });
  if (!safety.safe) {
    throw new Error(safety.reason ?? "Unsafe GuardMe policy write target.");
  }
  assertNoSecretCommandRules(config);
  await writePolicyTextAtomically(path, renderPolicyConfigYaml(config), options);
}

export function renderPolicyConfigYaml(config: GuardMePolicyConfig): string {
  const lines: string[] = [`version: ${POLICY_VERSION}`];
  for (const section of [...PATH_RULE_SECTIONS, ...COMMAND_RULE_SECTIONS]) {
    const rules = config[section];
    if (rules.length === 0) {
      continue;
    }
    lines.push("", `${section}:`);
    for (const rule of rules) {
      lines.push(`  - pattern: ${quoteYaml(rule.pattern)}`);
      if (rule.actions && rule.actions.length > 0) {
        lines.push(`    actions: [${rule.actions.join(", ")}]`);
      }
      if (rule.reason) {
        lines.push(`    reason: ${quoteYaml(rule.reason)}`);
      }
    }
  }
  return `${lines.join("\n")}\n`;
}

function appendRulesToPolicyYamlText(text: string, rules: readonly AppendPolicyConfigRule[]): string {
  const groupedRules = groupAppendRulesBySection(rules);
  return groupedRules.reduce((currentText, [section, sectionRules]) => appendRulesToSectionText(currentText, section, sectionRules), normalizeLineEndings(text));
}

function groupAppendRulesBySection(rules: readonly AppendPolicyConfigRule[]): readonly (readonly [PathRuleSection | CommandRuleSection, readonly GuardMeRule[]])[] {
  return [...PATH_RULE_SECTIONS, ...COMMAND_RULE_SECTIONS].flatMap((section) => {
    const sectionRules = rules.filter((entry) => entry.section === section).map((entry) => entry.rule);
    return sectionRules.length > 0 ? [[section, sectionRules] as const] : [];
  });
}

function appendRulesToSectionText(
  text: string,
  section: PathRuleSection | CommandRuleSection,
  rules: readonly GuardMeRule[],
): string {
  const body = text.endsWith("\n") ? text.slice(0, -1) : text;
  const lines = body.length > 0 ? body.split("\n") : [];
  const renderedRules = rules.flatMap((rule) => renderRuleYamlLines(rule));
  const sectionIndex = findLastSectionIndex(lines, section);

  if (sectionIndex < 0) {
    if (lines.length > 0 && lines[lines.length - 1]?.trim() !== "") {
      lines.push("");
    }
    lines.push(`${section}:`, ...renderedRules);
    return `${lines.join("\n")}\n`;
  }

  let insertIndex = lines.length;
  for (let index = sectionIndex + 1; index < lines.length; index += 1) {
    const line = lines[index] ?? "";
    const trimmed = line.trim();
    if (trimmed.length === 0 || trimmed.startsWith("#")) {
      continue;
    }
    if (!line.startsWith(" ")) {
      insertIndex = index;
      while (insertIndex > sectionIndex + 1 && lines[insertIndex - 1]?.trim() === "") {
        insertIndex -= 1;
      }
      break;
    }
  }
  lines.splice(insertIndex, 0, ...renderedRules);
  return `${lines.join("\n")}\n`;
}

function renderRuleYamlLines(rule: GuardMeRule): string[] {
  const lines = [`  - pattern: ${quoteYaml(rule.pattern)}`];
  if (rule.actions && rule.actions.length > 0) {
    lines.push(`    actions: [${rule.actions.join(", ")}]`);
  }
  if (rule.reason) {
    lines.push(`    reason: ${quoteYaml(rule.reason)}`);
  }
  return lines;
}

function findLastSectionIndex(lines: readonly string[], section: PathRuleSection | CommandRuleSection): number {
  let foundIndex = -1;
  const sectionPattern = new RegExp(`^${section}:\\s*(?:#.*)?$`);
  for (const [index, line] of lines.entries()) {
    if (sectionPattern.test(line.trim())) {
      foundIndex = index;
    }
  }
  return foundIndex;
}

function normalizeLineEndings(text: string): string {
  return text.replace(/\r\n?/g, "\n");
}

function normalizeAppendRule(section: PathRuleSection | CommandRuleSection, rule: GuardMeRule): GuardMeRule | undefined {
  const pattern = rule.pattern.trim();
  if (!pattern) {
    return undefined;
  }
  const actions = (PATH_RULE_SECTIONS as readonly string[]).includes(section) && rule.actions && rule.actions.length > 0 ? [...new Set(rule.actions)] : undefined;
  const reason = rule.reason?.trim();
  return {
    pattern,
    ...(actions ? { actions } : {}),
    ...(reason ? { reason } : {}),
  };
}

function secretCommandRuleDiagnostic(
  section: PathRuleSection | CommandRuleSection,
  rule: GuardMeRule,
  source: { readonly kind: "global" | "local"; readonly path: string },
): PolicyDiagnostic | undefined {
  if (!(COMMAND_RULE_SECTIONS as readonly string[]).includes(section)) {
    return undefined;
  }
  if (redactSensitiveText(rule.pattern) === rule.pattern) {
    return undefined;
  }
  return {
    severity: "error",
    code: "policyWrite.secretCommandRejected",
    message: "GuardMe refused to save a policy rule because the command contains secret-like values.",
    source,
    path: source.path,
  };
}

function isAllowDecision(decision: UserDecision): boolean {
  return decision === "allow-once" || decision === "allow-local" || decision === "allow-global";
}

function isDenyDecision(decision: UserDecision): boolean {
  return decision === "deny-once" || decision === "deny-local" || decision === "deny-global";
}

function policyPathForScope(scope: PolicyWriteScope, cwd: string, homeDir?: string): string {
  const paths = resolvePolicyConfigPaths(cwd, homeDir);
  return scope === "global" ? paths.globalPolicyPath : paths.localPolicyPath;
}

type DecisionRuleResult =
  | { readonly section: PathRuleSection | CommandRuleSection; readonly rule: GuardMeRule }
  | {
      readonly rejected: true;
      readonly code: string;
      readonly message: string;
      readonly reason: string;
    };

function ruleFromDecision(options: PersistUserDecisionRuleOptions): DecisionRuleResult | undefined {
  const allow = isAllowDecision(options.decision);
  const deny = isDenyDecision(options.decision);
  if (!allow && !deny) {
    return undefined;
  }

  const reason = options.reason ?? `Saved from GuardMe approval decision '${options.decision}'.`;
  if (options.request.command) {
    const commandPattern = options.request.command.trim().replace(/\s+/g, " ");
    if (redactSensitiveText(commandPattern) !== commandPattern) {
      return {
        rejected: true,
        code: "policyWrite.secretCommandRejected",
        message: "GuardMe refused to save a policy rule because the command contains secret-like values.",
        reason: "Command contains secret-like values; use allow once or add a sanitized policy rule manually.",
      };
    }
    return {
      section: allow ? "allowCommands" : "denyCommands",
      rule: {
        pattern: commandPattern,
        reason,
      },
    };
  }

  const pathTarget = options.request.targets.find((target) => target.kind === "path");
  if (!pathTarget) {
    return undefined;
  }

  return {
    section: allow ? "allowPaths" : "denyPaths",
    rule: {
      pattern: pathTarget.raw,
      actions: [options.request.action],
      reason,
    },
  };
}

function appendRule(
  config: GuardMePolicyConfig,
  section: PathRuleSection | CommandRuleSection,
  rule: GuardMeRule,
): GuardMePolicyConfig {
  const existingRules = config[section];
  const exists = existingRules.some((existing) => ruleKey(existing) === ruleKey(rule));
  if (exists) {
    return config;
  }
  return {
    ...config,
    [section]: [...existingRules, rule],
  };
}

function ruleKey(rule: GuardMeRule): string {
  return `${rule.pattern}\u0000${[...(rule.actions ?? [])].sort().join(",")}\u0000${rule.reason ?? ""}`;
}

function quoteYaml(value: string): string {
  return JSON.stringify(value);
}

function assertNoSecretCommandRules(config: GuardMePolicyConfig): void {
  for (const section of COMMAND_RULE_SECTIONS) {
    const rule = config[section].find((candidate) => redactSensitiveText(candidate.pattern) !== candidate.pattern);
    if (rule) {
      throw new Error(`GuardMe refused to write ${section} rule '${redactSensitiveText(rule.pattern)}' because it contains secret-like values.`);
    }
  }
}

async function writePolicyTextAtomically(
  path: string,
  text: string,
  options: Omit<PolicyWriteTargetValidationOptions, "path">,
): Promise<void> {
  const directory = dirname(path);
  await mkdir(directory, { recursive: true });
  const safety = await validatePolicyWriteTarget({ ...options, path });
  if (!safety.safe) {
    throw new Error(safety.reason ?? "Unsafe GuardMe policy write target.");
  }
  const tempPath = join(directory, `.guardme-${process.pid}-${Date.now()}-${randomUUID()}.tmp`);
  try {
    await writeFile(tempPath, text, { encoding: "utf8", flag: "wx", mode: 0o600 });
    await rename(tempPath, path);
  } catch (error) {
    await rm(tempPath, { force: true }).catch(() => {});
    throw error;
  }
}

async function existingSymlinkInPath(targetPath: string, scopeRoot: string, includeTarget: boolean): Promise<string | undefined> {
  const relativePath = relative(resolve(scopeRoot), resolve(targetPath));
  if (relativePath === "") {
    return undefined;
  }
  const segments = relativePath.split(sep).filter(Boolean);
  let current = resolve(scopeRoot);

  for (const [index, segment] of segments.entries()) {
    current = join(current, segment);
    const isTarget = index === segments.length - 1;
    if (isTarget && !includeTarget) {
      break;
    }

    try {
      const stats = await lstat(current);
      if (stats.isSymbolicLink()) {
        return current;
      }
      if (!stats.isDirectory() && !isTarget) {
        return undefined;
      }
    } catch (error) {
      if (isNodeError(error) && error.code === "ENOENT") {
        return undefined;
      }
      throw error;
    }
  }

  return undefined;
}

function isPathInsideRoot(rootPath: string, childPath: string): boolean {
  const childRelative = relative(resolve(rootPath), resolve(childPath));
  return childRelative === "" || (!childRelative.startsWith("..") && !isAbsolute(childRelative));
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return typeof error === "object" && error !== null && "code" in error;
}

