export const POLICY_ACTIONS = ["read", "list", "write", "edit", "delete", "move", "rename", "shell"] as const;
export type PolicyAction = (typeof POLICY_ACTIONS)[number];

export const PATH_POLICY_ACTIONS = ["read", "list", "write", "edit", "delete", "move", "rename"] as const;
export type PathPolicyAction = (typeof PATH_POLICY_ACTIONS)[number];

export const RISK_LEVELS = ["low", "medium", "dangerous", "hard-denied"] as const;
export type RiskLevel = (typeof RISK_LEVELS)[number];

export const RULE_SOURCE_KINDS = ["builtin", "global", "local", "default", "user"] as const;
export type RuleSourceKind = (typeof RULE_SOURCE_KINDS)[number];

export const POLICY_RULE_CATEGORIES = [
  "allowPaths",
  "denyPaths",
  "zeroAccessPaths",
  "readOnlyPaths",
  "noDeletePaths",
  "allowCommands",
  "denyCommands",
  "dangerousCommands",
  "protectedCredentialPaths",
  "hardDeny",
  "defaultProjectPolicy",
  "commandDefaultDeny",
] as const;
export type PolicyRuleCategory = (typeof POLICY_RULE_CATEGORIES)[number];

export const DIAGNOSTIC_SEVERITIES = ["info", "warning", "error"] as const;
export type DiagnosticSeverity = (typeof DIAGNOSTIC_SEVERITIES)[number];

export const POLICY_DECISION_OUTCOMES = ["allow", "deny", "coach", "needs-user-decision"] as const;
export type PolicyDecisionOutcome = (typeof POLICY_DECISION_OUTCOMES)[number];

export const POLICY_REASON_CODES = [
  "dangerous-command",
  "policy-missing-command",
  "script-content-denied",
  "local-script-uninspectable",
  "hard-denied-command",
  "path-protected",
  "outside-project-path",
] as const;
export type PolicyReasonCode = (typeof POLICY_REASON_CODES)[number] | (string & {});

export const USER_DECISIONS = [
  "allow-once",
  "deny-once",
  "allow-local",
  "deny-local",
  "allow-global",
  "deny-global",
] as const;
export type UserDecision = (typeof USER_DECISIONS)[number];

const POLICY_ACTION_SET: ReadonlySet<string> = new Set(POLICY_ACTIONS);
const USER_DECISION_SET: ReadonlySet<string> = new Set(USER_DECISIONS);

export interface RuleSource {
  readonly kind: RuleSourceKind;
  readonly path?: string;
  readonly index?: number;
  readonly label?: string;
}

export interface MatchedRule {
  readonly category: PolicyRuleCategory;
  readonly source: RuleSource;
  readonly pattern?: string;
  readonly actions?: readonly PolicyAction[];
  readonly reason?: string;
}

export interface PolicyDiagnostic {
  readonly severity: DiagnosticSeverity;
  readonly code: string;
  readonly message: string;
  readonly source?: RuleSource;
  readonly path?: string;
  readonly ruleIndex?: number;
}

export interface PathTarget {
  readonly kind: "path";
  readonly raw: string;
  readonly absolutePath?: string;
  readonly canonicalPath?: string;
  readonly projectRoot?: string;
  readonly projectRelativePath?: string;
  readonly exists?: boolean;
  readonly isInsideProject?: boolean;
  readonly hadTraversal?: boolean;
}

export interface CommandTarget {
  readonly kind: "command";
  readonly raw: string;
  readonly normalized?: string;
}

export interface ToolTarget {
  readonly kind: "tool";
  readonly raw: string;
}

export type PolicyTarget = PathTarget | CommandTarget | ToolTarget;

export interface PolicyRequest {
  readonly toolName: string;
  readonly action: PolicyAction;
  readonly cwd: string;
  readonly targets: readonly PolicyTarget[];
  readonly command?: string;
  readonly riskHint?: RiskLevel;
  readonly fingerprintSeed?: string;
  readonly reasonCode?: PolicyReasonCode;
  readonly policyMissingReason?: string;
  readonly policyMissingGuidance?: string;
  readonly policyMissingRecommendation?: string;
  readonly requiresExactCommandAllow?: boolean;
}

interface PolicyDecisionBase {
  readonly outcome: PolicyDecisionOutcome;
  readonly action: PolicyAction;
  readonly risk: RiskLevel;
  readonly reason: string;
  readonly matchedRules: readonly MatchedRule[];
  readonly diagnostics?: readonly PolicyDiagnostic[];
  readonly recommendation?: string;
  readonly reasonCode?: PolicyReasonCode;
  readonly suggestedCommandRule?: string;
}

export interface AllowPolicyDecision extends PolicyDecisionBase {
  readonly outcome: "allow";
}

export interface DenyPolicyDecision extends PolicyDecisionBase {
  readonly outcome: "deny";
  readonly block: true;
  readonly hard: boolean;
}

export interface CoachPolicyDecision extends PolicyDecisionBase {
  readonly outcome: "coach";
  readonly block: true;
  readonly fingerprint: string;
  readonly guidance: string;
}

export interface NeedsUserDecisionPolicyDecision extends PolicyDecisionBase {
  readonly outcome: "needs-user-decision";
  readonly fingerprint: string;
  readonly prompt: true;
  readonly choices: readonly UserDecision[];
}

export type PolicyDecision =
  | AllowPolicyDecision
  | DenyPolicyDecision
  | CoachPolicyDecision
  | NeedsUserDecisionPolicyDecision;

export function isPolicyAction(value: string): value is PolicyAction {
  return POLICY_ACTION_SET.has(value);
}

export function isUserDecision(value: string): value is UserDecision {
  return USER_DECISION_SET.has(value);
}
