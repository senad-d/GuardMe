import type { PolicyDiagnostic } from "../policy/action.ts";
import type { GuardMeStateRecord } from "../state/warnings.ts";
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
    if (record.type === "warning") {
      lines.push(
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
      );
      continue;
    }

    lines.push(
      `DECISION ${record.timestamp}`,
      `  Scope       ${record.scope}`,
      `  Decision    ${record.decision}`,
      `  Persisted   ${record.persistedTo}`,
      ...(record.reason ? [`  Reason      ${record.reason}`] : []),
      `  Fingerprint ${record.fingerprint}`,
    );
  }

  return lines;
}

function formatMatchedRuleLines(record: GuardMeStateRecord): readonly string[] {
  if (record.type !== "warning" || !record.matchedRules || record.matchedRules.length === 0) {
    return [];
  }

  return renderMatchedRules(record.matchedRules).map((rule, index) => `  ${index === 0 ? "Rule        " : "Rule        "}${rule}`);
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
