import { POLICY_VERSION } from "../constants.ts";
import { POLICY_ACTIONS, type PolicyAction, type PolicyDiagnostic, type RuleSource, type RuleSourceKind } from "../policy/action.ts";
import type {
  CommandRuleSection,
  GuardMePathRule,
  GuardMePolicyConfig,
  GuardMeRule,
  PathRuleSection,
  PolicyConfigSection,
} from "./schema.ts";
import { createEmptyPolicyConfig } from "./schema.ts";

export type PolicyConfigSourceKind = Extract<RuleSourceKind, "builtin" | "global" | "local">;

export interface PolicyConfigSource {
  readonly kind: PolicyConfigSourceKind;
  readonly path?: string;
  readonly config: GuardMePolicyConfig;
}

export interface SourcedGuardMeRule extends GuardMeRule {
  readonly section: PolicyConfigSection;
  readonly source: RuleSource;
}

export interface SourcedGuardMePathRule extends GuardMePathRule {
  readonly section: PathRuleSection;
  readonly source: RuleSource;
}

export interface MergedGuardMePolicyConfig {
  readonly version: number;
  readonly allowPaths: readonly SourcedGuardMePathRule[];
  readonly denyPaths: readonly SourcedGuardMePathRule[];
  readonly zeroAccessPaths: readonly SourcedGuardMePathRule[];
  readonly readOnlyPaths: readonly SourcedGuardMePathRule[];
  readonly noDeletePaths: readonly SourcedGuardMePathRule[];
  readonly allowCommands: readonly SourcedGuardMeRule[];
  readonly denyCommands: readonly SourcedGuardMeRule[];
  readonly dangerousCommands: readonly SourcedGuardMeRule[];
  readonly protectedCredentialPaths: readonly SourcedGuardMePathRule[];
}

export interface MergePolicyResult {
  readonly config: MergedGuardMePolicyConfig;
  readonly diagnostics: readonly PolicyDiagnostic[];
}

const PATH_SECTIONS: readonly PathRuleSection[] = [
  "allowPaths",
  "denyPaths",
  "zeroAccessPaths",
  "readOnlyPaths",
  "noDeletePaths",
  "protectedCredentialPaths",
];

const COMMAND_SECTIONS: readonly CommandRuleSection[] = ["allowCommands", "denyCommands", "dangerousCommands"];

const PROTECTION_PATH_SECTIONS: ReadonlySet<PathRuleSection> = new Set([
  "denyPaths",
  "zeroAccessPaths",
  "readOnlyPaths",
  "noDeletePaths",
  "protectedCredentialPaths",
]);

const DELETE_LIKE_ACTIONS = new Set(["delete", "move", "rename"]);
const MUTATION_ACTIONS = new Set(["write", "edit", "delete", "move", "rename"]);
const POLICY_ACTION_ORDER = new Map<PolicyAction, number>(POLICY_ACTIONS.map((action, index) => [action, index]));

export function mergePolicyConfigs(sources: readonly PolicyConfigSource[]): MergePolicyResult {
  const context: MergePolicyContext = {
    mutable: createMutableMergedConfig(),
    diagnostics: [],
    seenBySection: new Map(),
    existingProtections: [],
  };

  for (const source of sources) {
    mergePathSectionsFromSource(source, context);
    mergeCommandSectionsFromSource(source, context);
  }

  return { config: context.mutable, diagnostics: context.diagnostics };
}

interface MergePolicyContext {
  readonly mutable: MutableMergedGuardMePolicyConfig;
  readonly diagnostics: PolicyDiagnostic[];
  readonly seenBySection: Map<PolicyConfigSection, Set<string>>;
  readonly existingProtections: SourcedGuardMePathRule[];
}

function mergePathSectionsFromSource(source: PolicyConfigSource, context: MergePolicyContext): void {
  for (const section of PATH_SECTIONS) {
    for (const [index, rule] of source.config[section].entries()) {
      mergePathRule(source, section, rule, index, context);
    }
  }
}

function mergePathRule(
  source: PolicyConfigSource,
  section: PathRuleSection,
  rule: GuardMePathRule,
  index: number,
  context: MergePolicyContext,
): void {
  const sourcedRule: SourcedGuardMePathRule = sourceRule(section, rule, source, index);
  reportLocalAllowProtectionConflicts(source, section, sourcedRule, context);
  if (appendUnique(context.mutable[section], sourcedRule, section, context.seenBySection) && PROTECTION_PATH_SECTIONS.has(section)) {
    context.existingProtections.push(sourcedRule);
  }
}

function reportLocalAllowProtectionConflicts(
  source: PolicyConfigSource,
  section: PathRuleSection,
  sourcedRule: SourcedGuardMePathRule,
  context: MergePolicyContext,
): void {
  if (source.kind !== "local" || section !== "allowPaths") {
    return;
  }
  for (const conflict of context.existingProtections.filter((protection) => localAllowConflictsWithProtection(sourcedRule, protection))) {
    context.diagnostics.push({
      severity: "warning",
      code: "merge.localAllowCannotOverrideProtection",
      message: `Local allow rule '${sourcedRule.pattern}' cannot override ${conflict.source.kind} ${conflict.section} rule '${conflict.pattern}'. Deny/protection still wins.`,
      source: sourcedRule.source,
    });
  }
}

function mergeCommandSectionsFromSource(source: PolicyConfigSource, context: MergePolicyContext): void {
  for (const section of COMMAND_SECTIONS) {
    for (const [index, rule] of source.config[section].entries()) {
      const sourcedRule: SourcedGuardMeRule = sourceRule(section, rule, source, index);
      appendUnique(context.mutable[section], sourcedRule, section, context.seenBySection);
    }
  }
}

export function sourcePolicyConfig(kind: PolicyConfigSourceKind, config: GuardMePolicyConfig, path?: string): PolicyConfigSource {
  return { kind, config, ...(path ? { path } : {}) };
}

function createMutableMergedConfig(): MutableMergedGuardMePolicyConfig {
  return {
    ...createEmptyPolicyConfig(POLICY_VERSION),
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

interface MutableMergedGuardMePolicyConfig extends MergedGuardMePolicyConfig {
  readonly allowPaths: SourcedGuardMePathRule[];
  readonly denyPaths: SourcedGuardMePathRule[];
  readonly zeroAccessPaths: SourcedGuardMePathRule[];
  readonly readOnlyPaths: SourcedGuardMePathRule[];
  readonly noDeletePaths: SourcedGuardMePathRule[];
  readonly allowCommands: SourcedGuardMeRule[];
  readonly denyCommands: SourcedGuardMeRule[];
  readonly dangerousCommands: SourcedGuardMeRule[];
  readonly protectedCredentialPaths: SourcedGuardMePathRule[];
}

function sourceRule<T extends GuardMeRule, TSection extends PolicyConfigSection>(
  section: TSection,
  rule: T,
  source: PolicyConfigSource,
  index: number,
): T & { readonly section: TSection; readonly source: RuleSource } {
  return {
    ...rule,
    section,
    source: ruleSource(source, index),
  };
}

function ruleSource(source: PolicyConfigSource, index: number): RuleSource {
  return {
    kind: source.kind,
    ...(source.path ? { path: source.path } : {}),
    index,
  };
}

function appendUnique<T extends SourcedGuardMeRule>(
  target: T[],
  rule: T,
  section: PolicyConfigSection,
  seenBySection: Map<PolicyConfigSection, Set<string>>,
): boolean {
  const key = ruleDedupeKey(rule);
  let seen = seenBySection.get(section);
  if (!seen) {
    seen = new Set();
    seenBySection.set(section, seen);
  }
  if (seen.has(key)) {
    return false;
  }
  seen.add(key);
  target.push(rule);
  return true;
}

function ruleDedupeKey(rule: GuardMeRule): string {
  const actions = [...(rule.actions ?? [])].sort(comparePolicyActionOrder).join(",");
  return `${rule.pattern}\u0000${actions}\u0000${rule.reason ?? ""}`;
}

function comparePolicyActionOrder(left: PolicyAction, right: PolicyAction): number {
  return (POLICY_ACTION_ORDER.get(left) ?? Number.MAX_SAFE_INTEGER) - (POLICY_ACTION_ORDER.get(right) ?? Number.MAX_SAFE_INTEGER);
}

function localAllowConflictsWithProtection(allowRule: SourcedGuardMePathRule, protection: SourcedGuardMePathRule): boolean {
  if (allowRule.pattern !== protection.pattern) {
    return false;
  }

  if (protection.section === "readOnlyPaths") {
    return actionSetIntersects(allowRule.actions, MUTATION_ACTIONS);
  }
  if (protection.section === "noDeletePaths") {
    return actionSetIntersects(allowRule.actions, DELETE_LIKE_ACTIONS);
  }
  return true;
}

function actionSetIntersects(actions: readonly string[] | undefined, protectedActions: ReadonlySet<string>): boolean {
  if (!actions || actions.length === 0) {
    return true;
  }
  return actions.some((action) => protectedActions.has(action));
}
