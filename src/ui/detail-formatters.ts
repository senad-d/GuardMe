import type { PolicyDiagnostic } from "../policy/action.ts";
import type {
  AutomaticDecisionStateRecord,
  GuardMeStateRecord,
  UserDecisionStateRecord,
  WarningStateRecord,
} from "../state/warnings.ts";
import { renderMatchedRules } from "./render-policy-summary.ts";

export function formatWarningDecisionRecords(records: readonly GuardMeStateRecord[]): readonly string[] {
  if (records.length === 0) {
    return ["No warning or decision records found for this project/session."];
  }

  const lines: string[] = [];
  for (const [index, record] of records.entries()) {
    if (index > 0) {
      lines.push("");
    }
    lines.push(...formatWarningDecisionRecord(record));
  }

  return lines;
}

function formatWarningDecisionRecord(record: GuardMeStateRecord): readonly string[] {
  if (record.type === "warning") {
    return formatWarningRecord(record);
  }
  if (record.type === "automatic-decision") {
    return formatAutomaticDecisionRecord(record);
  }
  return formatUserDecisionRecord(record);
}

function formatWarningRecord(record: WarningStateRecord): readonly string[] {
  return [
    `WARNING ${record.timestamp}`,
    `  Scope       ${record.scope}`,
    `  Tool        ${record.toolName}`,
    `  Action      ${record.action}`,
    `  Risk        ${record.risk}`,
    ...(record.reasonCode ? [`  Reason code ${record.reasonCode}`] : []),
    `  Target      ${record.target}`,
    ...(record.reason ? [`  Reason      ${record.reason}`] : []),
    ...formatMatchedRuleLines(record),
    `  Fingerprint ${record.fingerprint}`,
    `  Count       ${record.count}`,
  ];
}

function formatAutomaticDecisionRecord(record: AutomaticDecisionStateRecord): readonly string[] {
  return [
    `AUTOMATIC DECISION ${record.timestamp}`,
    `  Scope       ${record.scope}`,
    `  Mode        ${record.approvalMode}`,
    `  Decision    ${record.decision}`,
    `  Persisted   ${record.persistedTo}`,
    ...(record.reason ? [`  Reason      ${record.reason}`] : []),
    `  Fingerprint ${record.fingerprint}`,
  ];
}

function formatUserDecisionRecord(record: UserDecisionStateRecord): readonly string[] {
  return [
    `DECISION ${record.timestamp}`,
    `  Scope       ${record.scope}`,
    `  Decision    ${record.decision}`,
    `  Persisted   ${record.persistedTo}`,
    ...(record.reason ? [`  Reason      ${record.reason}`] : []),
    `  Fingerprint ${record.fingerprint}`,
  ];
}

function formatMatchedRuleLines(record: WarningStateRecord): readonly string[] {
  if (!record.matchedRules?.length) {
    return [];
  }

  const lines: string[] = [];
  for (const [index, rule] of renderMatchedRules(record.matchedRules).entries()) {
    lines.push(formatMatchedRuleLine(rule, index));
  }
  return lines;
}

function formatMatchedRuleLine(rule: string, index: number): string {
  return `  ${index === 0 ? "Rule        " : "            "}${rule}`;
}

export function formatDiagnostics(diagnostics: readonly PolicyDiagnostic[]): readonly string[] {
  if (diagnostics.length === 0) {
    return ["No diagnostics found.", "GuardMe policy and state loaded successfully."];
  }

  const lines: string[] = [];
  for (const [index, diagnostic] of diagnostics.entries()) {
    if (index > 0) {
      lines.push("");
    }
    lines.push(
      `${diagnostic.severity.toUpperCase()} ${diagnostic.code}`,
      `  Message  ${diagnostic.message}`,
    );

    const source = formatDiagnosticSource(diagnostic);
    if (source) {
      lines.push(`  Source   ${source}`);
    }
    if (diagnostic.ruleIndex !== undefined) {
      lines.push(`  Source line ${diagnostic.ruleIndex}`);
    }

    const action = formatDiagnosticAction(diagnostic);
    if (action) {
      lines.push(`  Action   ${action}`);
    }
  }

  return lines;
}

function formatDiagnosticSource(diagnostic: PolicyDiagnostic): string | undefined {
  if (diagnostic.source) {
    return [diagnostic.source.kind, diagnostic.source.path ?? diagnostic.path].filter(Boolean).join(" ");
  }
  return diagnostic.path;
}

function formatDiagnosticAction(diagnostic: PolicyDiagnostic): string | undefined {
  const sourcePath = diagnostic.source?.path ?? diagnostic.path;
  if (!sourcePath) {
    return undefined;
  }
  if (sourcePath.endsWith("guardme.yaml")) {
    return "Fix policy YAML or use Setup to recreate it.";
  }
  if (sourcePath.endsWith("guardme-settings.json")) {
    return "Fix runtime settings JSON or delete it to reset defaults.";
  }
  if (sourcePath.endsWith("guardme-state.jsonl")) {
    return "Fix or rotate state JSONL, then rerun /guardme diagnostics.";
  }
  return "Review the source file, then rerun /guardme diagnostics.";
}
