import { createHash } from "node:crypto";
import { relative, resolve } from "node:path";

import type { MergedGuardMePolicyConfig, SourcedGuardMePathRule, SourcedGuardMeRule } from "../config/merge-policy.ts";
import {
  PATH_POLICY_ACTIONS,
  type MatchedRule,
  type PathPolicyAction,
  type PathTarget,
  type PolicyAction,
  type PolicyDecision,
  type PolicyReasonCode,
  type PolicyRequest,
  type RiskLevel,
  USER_DECISIONS,
} from "./action.ts";
import {
  commandRuleMatchCandidates,
  commandSegmentRuleMatchCandidates,
  extractExecutableCommandSegments,
  type CommandClassification,
  type ExecutableCommandSegment,
  classifyShellCommand,
} from "./commands.ts";
import { type NormalizedPolicyPath, isPathInside, matchPolicyPathPattern, toPosixPath } from "./paths.ts";
import { redactSensitiveText } from "./redact.ts";

export interface EvaluatePolicyRequestOptions {
  readonly policy: MergedGuardMePolicyConfig;
  readonly request: PolicyRequest;
  readonly commandClassification?: CommandClassification;
  readonly warnedFingerprints?: ReadonlySet<string>;
}

const PATH_MUTATION_ACTIONS = new Set<PolicyAction>(["write", "edit", "delete", "move", "rename"]);
const DELETE_LIKE_ACTIONS = new Set<PolicyAction>(["delete", "move", "rename"]);
const DEFAULT_ALLOWED_PROJECT_ACTIONS = new Set<PolicyAction>(["read", "list", "write", "edit"]);
const PATH_RULE_ACTIONS = new Set<PolicyAction>(PATH_POLICY_ACTIONS);

export function evaluatePolicyRequest(options: EvaluatePolicyRequestOptions): PolicyDecision {
  const { policy, request } = options;
  const command = options.commandClassification ?? (request.command ? classifyShellCommand(request.command) : undefined);
  const pathTargets = request.targets.filter((target): target is PathTarget => target.kind === "path");
  const normalizedPaths = pathTargets.map((target) => normalizedPathFromTarget(target, request.cwd));

  if (command?.hardDenied) {
    return denyDecision(request, "hard-denied", command.reason, [hardDenyMatchedRule(command)], true, request.reasonCode ?? "hard-denied-command");
  }

  const commandDeny = request.command ? firstMatchingCommandRule(policy.denyCommands, request.command) : undefined;
  if (commandDeny) {
    return denyDecision(request, "medium", commandDeny.reason ?? `Command denied by ${commandDeny.source.kind} policy.`, [matchedRule(commandDeny)], false);
  }

  const credentialPathDenial = firstCredentialLikePathDenial(policy, normalizedPaths, request.action);
  if (credentialPathDenial) {
    return denyDecision(request, "hard-denied", credentialPathDenial.reason, [credentialPathDenial.matchedRule], true);
  }

  const hardPathDenial = firstHardPathDenial(policy, normalizedPaths, request.action);
  if (hardPathDenial) {
    return denyDecision(request, "hard-denied", hardPathDenial.reason, [matchedRule(hardPathDenial.rule)], true);
  }

  const pathDeny = firstMatchingPathRule(policy.denyPaths, normalizedPaths, request.action);
  if (pathDeny) {
    return denyDecision(request, "medium", pathDeny.reason ?? `Path denied by ${pathDeny.source.kind} policy.`, [matchedRule(pathDeny)], false);
  }

  const outsidePathDenial = firstOutsidePathDefaultDenial(policy, request, normalizedPaths);
  if (outsidePathDenial) {
    return outsidePathDenial;
  }

  if (request.command) {
    return evaluateCommandSegments(policy, request, command, options.warnedFingerprints);
  }

  if (normalizedPaths.length > 0) {
    return evaluatePathDefaultsAndAllows(policy, request, normalizedPaths, options.warnedFingerprints);
  }

  return allowDecision(request, "No GuardMe deny rule matched this request.", []);
}

export function createPolicyFingerprint(request: PolicyRequest): string {
  const payload = {
    action: request.action,
    command: redactSensitiveText(request.command ?? ""),
    fingerprintSeed: request.fingerprintSeed ? redactSensitiveText(request.fingerprintSeed) : undefined,
    reasonCode: request.reasonCode,
    targets: request.targets.map((target) => {
      if (target.kind === "path") {
        return { kind: target.kind, path: target.canonicalPath ?? target.absolutePath ?? target.raw };
      }
      return { kind: target.kind, value: redactSensitiveText(target.raw) };
    }),
  };
  return `sha256:${createHash("sha256").update(JSON.stringify(payload)).digest("hex")}`;
}

interface CommandSegmentFailure {
  readonly kind: "dangerous" | "policy-missing";
  readonly segment: ExecutableCommandSegment;
  readonly request: PolicyRequest;
  readonly reason: string;
  readonly matchedRules: readonly MatchedRule[];
  readonly risk: RiskLevel;
}

function evaluateCommandSegments(
  policy: MergedGuardMePolicyConfig,
  request: PolicyRequest,
  command: CommandClassification | undefined,
  warnedFingerprints: ReadonlySet<string> | undefined,
): PolicyDecision {
  const commandText = request.command ?? "";
  const wholeCommandAllow = firstMatchingExactWholeCommandAllowRule(policy.allowCommands, commandText);
  if (wholeCommandAllow) {
    return allowDecision(request, wholeCommandAllow.reason ?? `Command allowed exactly by ${wholeCommandAllow.source.kind} policy.`, [matchedRule(wholeCommandAllow)]);
  }

  const segments = extractExecutableCommandSegments(commandText);
  if (segments.length === 0) {
    return allowDecision(request, "No executable shell segment was found.", []);
  }

  const result = collectCommandSegmentEvaluations(policy, request, command, segments);
  if (result.failures.length === 0) {
    return allowDecision(request, commandSegmentsAllowedReason(segments, commandText), dedupeMatchedRules(result.matchedAllows));
  }

  return commandSegmentFailureDecision(request, result.failures, warnedFingerprints);
}

interface CommandSegmentEvaluationResult {
  readonly failures: readonly CommandSegmentFailure[];
  readonly matchedAllows: readonly MatchedRule[];
}

interface CommandSegmentEvaluation {
  readonly failure?: CommandSegmentFailure;
  readonly matchedAllow?: MatchedRule;
  readonly allowedSegment?: string;
}

function collectCommandSegmentEvaluations(
  policy: MergedGuardMePolicyConfig,
  request: PolicyRequest,
  command: CommandClassification | undefined,
  segments: readonly ExecutableCommandSegment[],
): CommandSegmentEvaluationResult {
  const failures: CommandSegmentFailure[] = [];
  const matchedAllows: MatchedRule[] = [];
  const allowedSegments: string[] = [];
  for (const segment of segments) {
    const evaluation = evaluateCommandSegment(policy, request, command, segment, allowedSegments, failures.length);
    if (evaluation.failure) {
      failures.push(evaluation.failure);
      continue;
    }
    if (evaluation.matchedAllow) {
      matchedAllows.push(evaluation.matchedAllow);
    }
    if (evaluation.allowedSegment) {
      allowedSegments.push(evaluation.allowedSegment);
    }
  }
  return { failures, matchedAllows };
}

function evaluateCommandSegment(
  policy: MergedGuardMePolicyConfig,
  request: PolicyRequest,
  command: CommandClassification | undefined,
  segment: ExecutableCommandSegment,
  allowedSegments: readonly string[],
  failureIndex: number,
): CommandSegmentEvaluation {
  const exactAllow = firstMatchingExactSegmentCommandRule(policy.allowCommands, segment);
  const wildcardOrExactAllow = firstMatchingSegmentCommandRule(policy.allowCommands, segment);
  const dangerousRule = firstMatchingSegmentCommandRule(policy.dangerousCommands, segment);
  const segmentRequiresExact = commandSegmentRequiresExactAllow(segment, Boolean(request.requiresExactCommandAllow));

  if (segmentRequiresApproval(segment, dangerousRule, segmentRequiresExact, exactAllow)) {
    return { failure: dangerousSegmentFailure(request, segment, dangerousRule, command, segmentRequiresExact, failureIndex) };
  }

  const compatibleAllow = request.requiresExactCommandAllow ? exactAllow : wildcardOrExactAllow;
  if (compatibleAllow) {
    return { matchedAllow: matchedRule(compatibleAllow), allowedSegment: segment.normalizedText };
  }

  return { failure: policyMissingSegmentFailure(request, segment, allowedSegments) };
}

function segmentRequiresApproval(
  segment: ExecutableCommandSegment,
  dangerousRule: SourcedGuardMeRule | undefined,
  segmentRequiresExact: boolean,
  exactAllow: SourcedGuardMeRule | undefined,
): boolean {
  return !exactAllow && (segment.dangerous || Boolean(dangerousRule) || segmentRequiresExact);
}

function dangerousSegmentFailure(
  request: PolicyRequest,
  segment: ExecutableCommandSegment,
  dangerousRule: SourcedGuardMeRule | undefined,
  command: CommandClassification | undefined,
  segmentRequiresExact: boolean,
  failureIndex: number,
): CommandSegmentFailure {
  return {
    kind: "dangerous",
    segment,
    request: commandSegmentPolicyRequest(request, segment),
    reason: commandSegmentDangerousReason(segment, dangerousRule, command, failureIndex),
    matchedRules: dangerousSegmentMatchedRules(segment, dangerousRule, segmentRequiresExact),
    risk: "dangerous",
  };
}

function dangerousSegmentMatchedRules(
  segment: ExecutableCommandSegment,
  dangerousRule: SourcedGuardMeRule | undefined,
  segmentRequiresExact: boolean,
): readonly MatchedRule[] {
  return [
    ...(dangerousRule ? [matchedRule(dangerousRule)] : []),
    ...(segment.dangerous ? [hardDenyMatchedRule(segment.classification, "dangerousCommands")] : []),
    ...(segmentRequiresExact && !segment.dangerous && !dangerousRule ? [commandSegmentExactAllowRequiredRule(segment)] : []),
  ];
}

function policyMissingSegmentFailure(
  request: PolicyRequest,
  segment: ExecutableCommandSegment,
  allowedSegments: readonly string[],
): CommandSegmentFailure {
  return {
    kind: "policy-missing",
    segment,
    request: commandSegmentPolicyRequest(request, segment),
    reason: commandSegmentPolicyMissingReason(segment, allowedSegments),
    matchedRules: [commandDefaultDenyRule(segment)],
    risk: segment.risk === "dangerous" ? "dangerous" : "medium",
  };
}

function commandSegmentsAllowedReason(segments: readonly ExecutableCommandSegment[], commandText: string): string {
  if (segments.length === 1) {
    return `Shell segment '${redactSensitiveText(segments[0]?.normalizedText ?? commandText)}' is allowed by GuardMe command policy.`;
  }
  return `All ${segments.length} shell command segments are allowed by GuardMe command policy.`;
}

function commandSegmentFailureDecision(
  request: PolicyRequest,
  failures: readonly CommandSegmentFailure[],
  warnedFingerprints: ReadonlySet<string> | undefined,
): PolicyDecision {
  const selectedFailure = selectHighestRiskSegmentFailure(failures);
  const reason = appendAdditionalFailureSummary(selectedFailure.reason, selectedFailure, failures);
  if (selectedFailure.kind === "dangerous") {
    return dangerousDecision(
      { ...selectedFailure.request, policyMissingReason: reason },
      reason,
      selectedFailure.matchedRules,
      warnedFingerprints,
      request.reasonCode ?? "dangerous-command",
    );
  }
  return policyMissingCommandDecision(
    { ...selectedFailure.request, policyMissingReason: reason },
    selectedFailure.segment.classification,
    warnedFingerprints,
  );
}

function evaluatePathDefaultsAndAllows(
  policy: MergedGuardMePolicyConfig,
  request: PolicyRequest,
  normalizedPaths: readonly NormalizedPolicyPath[],
  warnedFingerprints: ReadonlySet<string> | undefined,
): PolicyDecision {
  const explicitAllows = normalizedPaths.map((path) => firstPathAllow(policy, path, request.action));
  if (explicitAllows.every(Boolean)) {
    return allowDecision(
      request,
      `Path ${request.action} allowed by explicit GuardMe policy.`,
      explicitAllows.filter((rule): rule is SourcedGuardMePathRule => Boolean(rule)).map(matchedRule),
    );
  }

  const allInsideProject = normalizedPaths.every((path) => path.isInsideProject);
  if (allInsideProject && DEFAULT_ALLOWED_PROJECT_ACTIONS.has(request.action)) {
    return allowDecision(request, `Inside-project ${request.action} is allowed by default project policy.`, [
      {
        category: "defaultProjectPolicy",
        source: { kind: "default", label: "built-in project default" },
        actions: [request.action],
        reason: "Reads/lists/writes/edits inside ctx.cwd are allowed unless denied or protected.",
      },
    ]);
  }

  if (allInsideProject && DELETE_LIKE_ACTIONS.has(request.action)) {
    return dangerousDecision(
      request,
      `Inside-project ${request.action} requires explicit approval unless an allow rule matches.`,
      [
        {
          category: "defaultProjectPolicy",
          source: { kind: "default", label: "built-in project default" },
          actions: [request.action],
          reason: "Deletes, moves, and renames inside the project require stricter review.",
        },
      ],
      warnedFingerprints,
    );
  }

  if (request.action === "read" || request.action === "list") {
    return denyDecision(request, "medium", `Outside-project ${request.action} requires an explicit allowPaths or readOnlyPaths rule.`, [], false);
  }

  if (PATH_MUTATION_ACTIONS.has(request.action)) {
    return denyDecision(request, "dangerous", `Outside-project ${request.action} requires an explicit allowPaths rule and no matching protection.`, [], false);
  }

  return denyDecision(request, "medium", "No GuardMe path allow rule matched this request.", [], false);
}

function firstOutsidePathDefaultDenial(
  policy: MergedGuardMePolicyConfig,
  request: PolicyRequest,
  normalizedPaths: readonly NormalizedPolicyPath[],
): PolicyDecision | undefined {
  if (normalizedPaths.length === 0) {
    return undefined;
  }

  const outsideWithoutAllow = normalizedPaths.filter((path) => !path.isInsideProject && !firstPathAllow(policy, path, request.action));
  if (outsideWithoutAllow.length === 0) {
    return undefined;
  }

  if (request.action === "read" || request.action === "list") {
    return denyDecision(request, "medium", `Outside-project ${request.action} requires an explicit allowPaths or readOnlyPaths rule.`, [], false);
  }

  if (PATH_MUTATION_ACTIONS.has(request.action)) {
    return denyDecision(request, "dangerous", `Outside-project ${request.action} requires an explicit allowPaths rule and no matching protection.`, [], false);
  }

  return denyDecision(request, "medium", "Outside-project shell path access requires an explicit path allow rule.", [], false);
}

function firstCredentialLikePathDenial(
  policy: MergedGuardMePolicyConfig,
  paths: readonly NormalizedPolicyPath[],
  action: PolicyAction,
): { readonly matchedRule: MatchedRule; readonly reason: string } | undefined {
  for (const path of paths) {
    const pattern = credentialLikePathPattern(path);
    if (!pattern) {
      continue;
    }

    const policyRule = firstMatchingPathRule(policy.zeroAccessPaths, [path], action, true)
      ?? firstMatchingPathRule(policy.denyPaths, [path], action)
      ?? firstMatchingPathRule(policy.protectedCredentialPaths, [path], action, true);
    if (policyRule) {
      const rule = matchedRule(policyRule);
      return {
        reason: formatProtectedRuleReason(rule, policyRule.reason ?? "Credential-like path is protected by GuardMe."),
        matchedRule: rule,
      };
    }

    const matchedRuleFallback: MatchedRule = {
      category: "hardDeny",
      source: { kind: "builtin", label: "credential path classifier" },
      pattern,
      actions: [action],
      reason: "Credential-like files and directories are unavailable to LLM tool calls.",
    };
    return {
      reason: formatProtectedRuleReason(matchedRuleFallback, "Credential-like files and directories are unavailable to LLM tool calls."),
      matchedRule: matchedRuleFallback,
    };
  }
  return undefined;
}

function formatProtectedRuleReason(rule: MatchedRule, reason: string): string {
  const patternLabel = rule.pattern ? ` ${rule.pattern}` : "";
  return `Protected by GuardMe: ${rule.category}${patternLabel} -> ${reason}\nNote: Try using the tool when one is available that matches the command intent.`;
}

function firstHardPathDenial(
  policy: MergedGuardMePolicyConfig,
  paths: readonly NormalizedPolicyPath[],
  action: PolicyAction,
): { readonly rule: SourcedGuardMePathRule; readonly reason: string } | undefined {
  for (const path of paths) {
    const zero = firstMatchingPathRule(policy.zeroAccessPaths, [path], action, true);
    if (zero) {
      return { rule: zero, reason: zero.reason ?? "Path is blocked by zeroAccessPaths." };
    }

    const credential = firstMatchingPathRule(policy.protectedCredentialPaths, [path], action, true);
    if (credential) {
      return { rule: credential, reason: credential.reason ?? "Credential-like path is protected." };
    }

    if (PATH_MUTATION_ACTIONS.has(action)) {
      const readOnly = firstMatchingPathRule(policy.readOnlyPaths, [path], action, true);
      if (readOnly) {
        return { rule: readOnly, reason: readOnly.reason ?? "Path is read-only and cannot be mutated." };
      }
    }

    if (DELETE_LIKE_ACTIONS.has(action)) {
      const noDelete = firstMatchingPathRule(policy.noDeletePaths, [path], action, true);
      if (noDelete) {
        return { rule: noDelete, reason: noDelete.reason ?? "Path cannot be deleted, moved, or renamed." };
      }
    }
  }
  return undefined;
}

function firstPathAllow(
  policy: MergedGuardMePolicyConfig,
  path: NormalizedPolicyPath,
  action: PolicyAction,
): SourcedGuardMePathRule | undefined {
  const allow = firstMatchingPathRule(policy.allowPaths, [path], action);
  if (allow) {
    return allow;
  }
  if (action === "read" || action === "list") {
    return firstMatchingPathRule(policy.readOnlyPaths, [path], action, true);
  }
  return undefined;
}

function firstMatchingPathRule(
  rules: readonly SourcedGuardMePathRule[],
  paths: readonly NormalizedPolicyPath[],
  action: PolicyAction,
  ignoreRuleActions = false,
): SourcedGuardMePathRule | undefined {
  return rules.find((rule) => {
    if (!ignoreRuleActions && rule.actions && rule.actions.length > 0) {
      if (!isPathRuleAction(action) || !rule.actions.includes(action)) {
        return false;
      }
    }
    return paths.some((path) => matchPolicyPathPattern(rule.pattern, path).matched);
  });
}

function isPathRuleAction(action: PolicyAction): action is PathPolicyAction {
  return PATH_RULE_ACTIONS.has(action);
}

function firstMatchingCommandRule(rules: readonly SourcedGuardMeRule[], command: string): SourcedGuardMeRule | undefined {
  const candidates = commandRuleMatchCandidates(command);
  return firstMatchingCommandRuleForCandidates(rules, candidates);
}

function firstMatchingSegmentCommandRule(
  rules: readonly SourcedGuardMeRule[],
  segment: ExecutableCommandSegment,
): SourcedGuardMeRule | undefined {
  return firstMatchingCommandRuleForCandidates(rules, segment.matchCandidates);
}

function firstMatchingExactSegmentCommandRule(
  rules: readonly SourcedGuardMeRule[],
  segment: ExecutableCommandSegment,
): SourcedGuardMeRule | undefined {
  return firstMatchingExactCommandRuleForCandidates(rules, segment.matchCandidates);
}

function firstMatchingExactWholeCommandAllowRule(
  rules: readonly SourcedGuardMeRule[],
  command: string,
): SourcedGuardMeRule | undefined {
  const candidates = [normalizeCommandText(command), ...commandSegmentRuleMatchCandidates(command).filter((candidate) => !commandHasMultipleShellSegments(command))];
  return firstMatchingExactCommandRuleForCandidates(rules, uniqueStrings(candidates));
}

function firstMatchingCommandRuleForCandidates(
  rules: readonly SourcedGuardMeRule[],
  candidates: readonly string[],
): SourcedGuardMeRule | undefined {
  return rules.find((rule) => commandRuleMatchesCandidates(rule, candidates));
}

function firstMatchingExactCommandRuleForCandidates(
  rules: readonly SourcedGuardMeRule[],
  candidates: readonly string[],
): SourcedGuardMeRule | undefined {
  return rules.find((rule) => !hasCommandGlob(rule.pattern) && commandRuleMatchesCandidates(rule, candidates));
}

function commandRuleMatchesCandidates(rule: SourcedGuardMeRule, candidates: readonly string[]): boolean {
  const regex = commandGlobToRegExp(rule.pattern);
  return candidates.some((candidate) => regex.test(normalizeCommandText(candidate)));
}

function commandSegmentRequiresExactAllow(segment: ExecutableCommandSegment, requestRequiresExact: boolean): boolean {
  return (
    requestRequiresExact ||
    segment.risk === "dangerous" ||
    segment.action === "delete" ||
    segment.action === "move" ||
    segment.action === "rename"
  );
}

function commandSegmentPolicyRequest(parent: PolicyRequest, segment: ExecutableCommandSegment): PolicyRequest {
  const parentCommand = normalizeCommandText(parent.command ?? "");
  const segmentSeed = parentCommand !== segment.normalizedText || segment.sourceKind !== "top-level"
    ? `command-segment:${segment.sourceKind}:${segment.normalizedText}`
    : undefined;
  const fingerprintSeed = [parent.fingerprintSeed, segmentSeed].filter((value): value is string => Boolean(value)).join(":");
  return {
    ...parent,
    action: segment.action,
    command: segment.normalizedText,
    targets: segment.targetPaths.map((targetPath) => ({ kind: "path" as const, raw: targetPath })),
    riskHint: segment.risk,
    ...(fingerprintSeed ? { fingerprintSeed } : {}),
    policyMissingGuidance: parent.policyMissingGuidance ?? "Use guarded built-in tools when possible, ask the user for approval, or propose a narrow allowCommands rule for the exact segment.",
    policyMissingRecommendation: parent.policyMissingRecommendation ?? `Request user approval or add an exact allowCommands rule for '${redactSensitiveText(segment.normalizedText)}'.`,
  };
}

function commandSegmentDangerousReason(
  segment: ExecutableCommandSegment,
  dangerousRule: SourcedGuardMeRule | undefined,
  aggregateCommand: CommandClassification | undefined,
  failureIndex: number,
): string {
  const segmentLabel = redactSensitiveText(segment.normalizedText);
  const baseReason = dangerousRule?.reason ?? segment.reason ?? aggregateCommand?.reason ?? "Dangerous command segment requires coaching or user approval.";
  const prefix = failureIndex === 0 ? "" : "Another ";
  return `${prefix}Shell segment '${segmentLabel}' requires an exact allowCommands rule or user approval. ${baseReason}`;
}

function commandSegmentPolicyMissingReason(segment: ExecutableCommandSegment, allowedSegments: readonly string[]): string {
  const segmentLabel = redactSensitiveText(segment.normalizedText);
  return `No allowCommands rule matches shell segment '${segmentLabel}'. GuardMe blocks unclassified shell command segments by default.${allowedSegmentsSummary(allowedSegments)}`;
}

function allowedSegmentsSummary(allowedSegments: readonly string[]): string {
  if (allowedSegments.length === 0) {
    return "";
  }
  const suffix = allowedSegments.length === 1 ? "" : "s";
  return ` Previously allowed segment${suffix}: ${allowedSegments.map(redactSensitiveText).join(", ")}.`;
}

function commandDefaultDenyRule(segment: ExecutableCommandSegment): MatchedRule {
  return {
    category: "commandDefaultDeny",
    source: { kind: "default", label: "command default deny" },
    actions: [segment.action],
    pattern: segment.normalizedText,
    reason: "Every executable shell segment requires an explicit allowCommands rule after deny/path/script checks pass.",
  };
}

function commandSegmentExactAllowRequiredRule(segment: ExecutableCommandSegment): MatchedRule {
  return {
    category: "commandDefaultDeny",
    source: { kind: "default", label: "exact command allow required" },
    actions: [segment.action],
    pattern: segment.normalizedText,
    reason: "Dangerous, delete, move, and rename shell segments require an exact allowCommands rule or user approval.",
  };
}

function selectHighestRiskSegmentFailure(failures: readonly CommandSegmentFailure[]): CommandSegmentFailure {
  return [...failures].sort((left, right) => segmentFailurePriority(right) - segmentFailurePriority(left))[0] ?? failures[0]!;
}

function segmentFailurePriority(failure: CommandSegmentFailure): number {
  if (failure.kind === "dangerous" || failure.risk === "dangerous") {
    return 2;
  }
  return 1;
}

function appendAdditionalFailureSummary(
  reason: string,
  selectedFailure: CommandSegmentFailure,
  failures: readonly CommandSegmentFailure[],
): string {
  const additional = failures.filter((failure) => failure !== selectedFailure);
  if (additional.length === 0) {
    return reason;
  }
  const labels = additional.slice(0, 3).map((failure) => redactSensitiveText(failure.segment.normalizedText));
  const suffix = additional.length > labels.length ? ` and ${additional.length - labels.length} more` : "";
  return `${reason} Additional unapproved segment${additional.length === 1 ? "" : "s"}: ${labels.join(", ")}${suffix}.`;
}

function dedupeMatchedRules(rules: readonly MatchedRule[]): readonly MatchedRule[] {
  const seen = new Set<string>();
  return rules.filter((rule) => {
    const key = `${rule.category}\u0000${rule.source.kind}\u0000${rule.pattern ?? ""}\u0000${rule.reason ?? ""}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

function uniqueStrings(values: readonly string[]): readonly string[] {
  return [...new Set(values)];
}

function commandHasMultipleShellSegments(command: string): boolean {
  return /(?:\n|\r|;|&&|\|\||(?<![<>])\|(?![|&]))/u.test(command);
}

function hasCommandGlob(pattern: string): boolean {
  return /[*?]/u.test(pattern);
}

function normalizeCommandText(command: string): string {
  return command.trim().replaceAll(/\s+/g, " ");
}

export function commandGlobToRegExp(pattern: string): RegExp {
  const normalizedPattern = normalizeCommandText(pattern);
  const optionalTrailingArguments = normalizedPattern.endsWith(" *");
  const globPattern = optionalTrailingArguments ? normalizedPattern.slice(0, -2) : normalizedPattern;
  let source = "";
  for (const character of globPattern) {
    if (character === "*") {
      source += ".*";
      continue;
    }
    if (character === "?") {
      source += ".";
      continue;
    }
    source += escapeRegExp(character);
  }
  if (optionalTrailingArguments) {
    source += String.raw`(?:\s+.*)?`;
  }
  return new RegExp(`^${source}$`);
}

function escapeRegExp(character: string): string {
  return /[\\^$+?.()|[\]{}]/.test(character) ? `\\${character}` : character;
}

function allowDecision(request: PolicyRequest, reason: string, matchedRules: readonly MatchedRule[]): PolicyDecision {
  return {
    outcome: "allow",
    action: request.action,
    risk: request.riskHint ?? "low",
    reason,
    matchedRules,
    ...(request.reasonCode ? { reasonCode: request.reasonCode } : {}),
  };
}

function denyDecision(
  request: PolicyRequest,
  risk: PolicyDecision["risk"],
  reason: string,
  matchedRules: readonly MatchedRule[],
  hard: boolean,
  reasonCode?: PolicyReasonCode,
): PolicyDecision {
  return {
    outcome: "deny",
    action: request.action,
    risk,
    reason,
    matchedRules,
    block: true,
    hard,
    ...(reasonCode ?? request.reasonCode ? { reasonCode: reasonCode ?? request.reasonCode } : {}),
  };
}

function dangerousDecision(
  request: PolicyRequest,
  reason: string,
  matchedRules: readonly MatchedRule[],
  warnedFingerprints: ReadonlySet<string> | undefined,
  reasonCode: PolicyReasonCode = "dangerous-command",
): PolicyDecision {
  return coachableDecision({
    request,
    risk: "dangerous",
    reason,
    matchedRules,
    warnedFingerprints,
    reasonCode,
    guidance: "Narrow the scope, prefer non-destructive inspection first, or ask the user before retrying.",
    recommendation: "Use a safer, narrower command before retrying.",
  });
}

function policyMissingCommandDecision(
  request: PolicyRequest,
  command: CommandClassification | undefined,
  warnedFingerprints: ReadonlySet<string> | undefined,
): PolicyDecision {
  const commandLabel = request.command ? `'${redactSensitiveText(normalizeCommandText(request.command))}'` : "the requested shell command";
  return coachableDecision({
    request,
    risk: request.riskHint === "dangerous" || command?.risk === "dangerous" ? "dangerous" : "medium",
    reason: request.policyMissingReason ?? `No allowCommands rule matches ${commandLabel}. GuardMe blocks unclassified shell commands by default.`,
    matchedRules: [
      {
        category: "commandDefaultDeny",
        source: { kind: "default", label: "command default deny" },
        actions: [request.action],
        ...(request.command ? { pattern: normalizeCommandText(request.command) } : {}),
        reason: "Every executable shell segment requires an explicit allowCommands rule unless a stronger deny/dangerous/hard rule already matched.",
      },
    ],
    warnedFingerprints,
    reasonCode: request.reasonCode ?? "policy-missing-command",
    guidance: request.policyMissingGuidance ?? "Use a guarded built-in file tool when possible, ask the user for approval, or propose a narrow allowCommands rule for this exact command.",
    recommendation: request.policyMissingRecommendation ?? "Request user approval or add a narrow command policy rule before retrying.",
  });
}

function coachableDecision(options: {
  readonly request: PolicyRequest;
  readonly risk: RiskLevel;
  readonly reason: string;
  readonly matchedRules: readonly MatchedRule[];
  readonly warnedFingerprints: ReadonlySet<string> | undefined;
  readonly reasonCode: PolicyReasonCode;
  readonly guidance: string;
  readonly recommendation: string;
}): PolicyDecision {
  const fingerprint = createPolicyFingerprint(options.request);
  const suggestedCommandRule = options.request.command ? normalizeCommandText(options.request.command) : undefined;
  if (options.warnedFingerprints?.has(fingerprint)) {
    return {
      outcome: "needs-user-decision",
      action: options.request.action,
      risk: options.risk,
      reason: options.reason,
      matchedRules: options.matchedRules,
      fingerprint,
      prompt: true,
      choices: USER_DECISIONS,
      recommendation: options.recommendation,
      reasonCode: options.reasonCode,
      ...(suggestedCommandRule ? { suggestedCommandRule } : {}),
    };
  }

  return {
    outcome: "coach",
    action: options.request.action,
    risk: options.risk,
    reason: options.reason,
    matchedRules: options.matchedRules,
    block: true,
    fingerprint,
    guidance: options.guidance,
    recommendation: options.recommendation,
    reasonCode: options.reasonCode,
    ...(suggestedCommandRule ? { suggestedCommandRule } : {}),
  };
}

function credentialLikePathPattern(path: NormalizedPolicyPath): string | undefined {
  for (const candidate of credentialPathCandidates(path)) {
    const pattern = credentialCandidatePattern(candidate);
    if (pattern) {
      return pattern;
    }
  }
  return undefined;
}

const CREDENTIAL_BASENAME_PREFIXES = [".npmrc", ".pypirc", ".netrc"] as const;
const CREDENTIAL_SEGMENT_PREFIXES = [".ssh", ".gnupg", ".1password", ".aws", ".azure"] as const;

function credentialCandidatePattern(candidate: string): string | undefined {
  const basename = candidate.split("/").pop() ?? candidate;
  return envCredentialPattern(candidate, basename)
    ?? basenameCredentialPattern(basename)
    ?? segmentCredentialPattern(candidate)
    ?? cloudConfigCredentialPattern(candidate)
    ?? keywordCredentialPattern(basename);
}

function envCredentialPattern(candidate: string, basename: string): string | undefined {
  if (!isProtectedEnvPathCandidate(candidate)) {
    return undefined;
  }
  return basename === ".env" ? ".env" : ".env glob";
}

function basenameCredentialPattern(basename: string): string | undefined {
  return CREDENTIAL_BASENAME_PREFIXES.some((prefix) => basename.startsWith(prefix)) ? basename : undefined;
}

function segmentCredentialPattern(candidate: string): string | undefined {
  return CREDENTIAL_SEGMENT_PREFIXES.find((prefix) => hasPathSegmentPrefix(candidate, prefix));
}

function cloudConfigCredentialPattern(candidate: string): string | undefined {
  if (candidate.includes("/.config/gcloud") || candidate.startsWith(".config/gcloud")) {
    return ".config/gcloud";
  }
  return candidate.endsWith("/.docker/config.json") || candidate === ".docker/config.json" ? ".docker/config.json" : undefined;
}

function keywordCredentialPattern(basename: string): string | undefined {
  return /(credential|secret|token)/u.test(basename) ? "credential-like filename" : undefined;
}

function credentialPathCandidates(path: NormalizedPolicyPath): readonly string[] {
  return [path.rawPath, path.inputPath, path.projectRelativePath, path.absolutePath, path.canonicalPath]
    .filter((candidate): candidate is string => typeof candidate === "string" && candidate.trim() !== "")
    .map((candidate) => toPosixPath(candidate).toLowerCase());
}

function hasPathSegmentPrefix(path: string, segmentPrefix: string): boolean {
  return path.split("/").some((segment) => segment.startsWith(segmentPrefix));
}

function isProtectedEnvPathCandidate(path: string): boolean {
  return path
    .split("/")
    .filter(Boolean)
    .some((segment) => segment === ".env" || (segment.startsWith(".env") && /[*?[\]]/u.test(segment)));
}

function matchedRule(rule: SourcedGuardMeRule | SourcedGuardMePathRule): MatchedRule {
  return {
    category: rule.section,
    source: rule.source,
    pattern: rule.pattern,
    actions: rule.actions,
    reason: rule.reason,
  };
}

function hardDenyMatchedRule(command: CommandClassification, category: MatchedRule["category"] = "hardDeny"): MatchedRule {
  return {
    category,
    source: { kind: "builtin", label: "command classifier" },
    pattern: command.matchedPatterns.join(" ") || command.commandName,
    actions: command.actions,
    reason: command.reason,
  };
}

function normalizedPathFromTarget(target: PathTarget, cwd: string): NormalizedPolicyPath {
  const projectRoot = target.projectRoot ?? resolve(cwd);
  const absolutePath = target.absolutePath ?? target.canonicalPath ?? resolve(projectRoot, target.raw);
  const canonicalPath = target.canonicalPath ?? absolutePath;
  const isInsideProject = target.isInsideProject ?? isPathInside(projectRoot, canonicalPath);
  const projectRelativePath = target.projectRelativePath ?? (isInsideProject ? toPosixPath(relative(projectRoot, canonicalPath) || ".") : undefined);

  return {
    rawPath: target.raw,
    inputPath: target.raw,
    absolutePath,
    canonicalPath,
    projectRoot,
    projectRelativePath,
    exists: target.exists ?? false,
    isInsideProject,
    hadTraversal: target.hadTraversal ?? false,
  };
}

