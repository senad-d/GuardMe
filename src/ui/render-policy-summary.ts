import type { MatchedRule, PolicyDecision, PolicyRequest } from "../policy/action.ts";
import { redactSensitiveText as redactPolicyText } from "../policy/redact.ts";
import { sanitizeTerminalText } from "./text.ts";

export interface PolicySummaryLine {
  readonly label: string;
  readonly value: string;
}

export function renderPolicySummary(request: PolicyRequest, decision: PolicyDecision): readonly PolicySummaryLine[] {
  return [
    { label: "Risk", value: sanitizeTerminalText(decision.risk) },
    { label: "Action", value: sanitizeTerminalText(`${request.toolName}:${request.action}`) },
    { label: "Target", value: summarizeRequestTarget(request) },
    { label: "Project", value: sanitizeTerminalText(request.cwd) },
    { label: "Reason", value: redactSensitiveText(decision.reason) },
    { label: "Recommendation", value: redactSensitiveText(decision.recommendation ?? "Deny unless you understand and trust the requested scope.") },
  ];
}

export function renderMatchedRules(matchedRules: readonly MatchedRule[]): readonly string[] {
  if (matchedRules.length === 0) {
    return ["No explicit rule matched; default policy applies."];
  }

  return matchedRules.map((rule) => {
    const source = sanitizeTerminalText([rule.source.kind, rule.source.path].filter(Boolean).join(":"));
    const pattern = rule.pattern ? ` ${redactSensitiveText(rule.pattern)}` : "";
    const reason = rule.reason ? ` — ${redactSensitiveText(rule.reason)}` : "";
    return `${sanitizeTerminalText(rule.category)}${pattern} (${source})${reason}`;
  });
}

export function summarizeRequestTarget(request: PolicyRequest): string {
  if (request.command) {
    return redactSensitiveText(request.command);
  }

  const targets = request.targets.map((target) => redactSensitiveText(target.raw)).filter(Boolean);
  return targets.length > 0 ? targets.join(", ") : "<unknown>";
}

export function redactSensitiveText(value: string): string {
  return sanitizeTerminalText(redactPolicyText(value));
}
