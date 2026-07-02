import assert from "node:assert/strict";
import test from "node:test";

import { formatDiagnostics, formatWarningDecisionRecords } from "../src/ui/detail-formatters.ts";

test("warning and decision records render in human-readable form", () => {
  const lines = formatWarningDecisionRecords([
    {
      type: "warning",
      version: 1,
      timestamp: "2026-06-22T10:00:00.000Z",
      fingerprint: "sha256:abc",
      scope: "project",
      cwd: "/repo",
      toolName: "bash",
      action: "delete",
      risk: "dangerous",
      reasonCode: "dangerous-command",
      target: "rm -rf build",
      reason: "Protected by GuardMe: dangerousCommands rm -rf * -> Recursive force deletion requires coaching or user approval.",
      matchedRules: [
        {
          category: "dangerousCommands",
          source: { kind: "builtin", label: "command classifier" },
          pattern: "rm -rf *",
          actions: ["delete"],
          reason: "Recursive force deletion requires coaching or user approval.",
        },
        {
          category: "noDeletePaths",
          source: { kind: "builtin", label: "repository metadata" },
          pattern: ".git/**",
          actions: ["delete"],
          reason: "Repository metadata is protected.",
        },
      ],
      count: 2,
    },
    {
      type: "decision",
      version: 1,
      timestamp: "2026-06-22T10:05:00.000Z",
      fingerprint: "sha256:abc",
      scope: "project",
      cwd: "/repo",
      decision: "deny-once",
      persistedTo: "none",
      reason: "User selected deny-once.",
    },
  ]);

  assert.ok(lines.includes("WARNING 2026-06-22T10:00:00.000Z"));
  assert.ok(lines.includes("  Tool        bash"));
  assert.ok(lines.includes("  Reason code dangerous-command"));
  assert.ok(lines.includes("  Target      rm -rf build"));
  assert.ok(lines.includes("  Reason      Protected by GuardMe: dangerousCommands rm -rf * -> Recursive force deletion requires coaching or user approval."));
  assert.ok(lines.some((line) => line.includes("dangerousCommands rm -rf *")));
  assert.ok(lines.some((line) => line.startsWith("              noDeletePaths .git/**")), "subsequent matched rules should align without repeating the Rule label");
  assert.ok(lines.includes("DECISION 2026-06-22T10:05:00.000Z"));
  assert.ok(lines.includes("  Decision    deny-once"));
  assert.ok(lines.includes("  Reason      User selected deny-once."));
});

test("warning and decision formatter renders a helpful empty state", () => {
  assert.deepEqual(formatWarningDecisionRecords([]), ["No warning or decision records found for this project/session."]);
});

test("diagnostics render severity code message and source metadata", () => {
  const lines = formatDiagnostics([
    {
      severity: "error",
      code: "config.invalidRoot",
      message: "GuardMe policy must be a YAML object.",
      source: { kind: "local", path: "/repo/.pi/agent/guardme.yaml" },
      path: "/repo/.pi/agent/guardme.yaml",
      ruleIndex: 12,
    },
    {
      severity: "warning",
      code: "state.malformedJsonl",
      message: "Ignoring malformed GuardMe state JSONL line 2.",
    },
  ]);

  assert.ok(lines.includes("ERROR config.invalidRoot"));
  assert.ok(lines.includes("  Message  GuardMe policy must be a YAML object."));
  assert.ok(lines.includes("  Source   local /repo/.pi/agent/guardme.yaml"));
  assert.ok(lines.includes("  Source line 12"));
  assert.ok(lines.includes("  Action   Fix policy YAML or use Setup to recreate it."));
  assert.ok(lines.includes("WARNING state.malformedJsonl"));
});

test("diagnostics formatter renders a success empty state", () => {
  assert.deepEqual(formatDiagnostics([]), ["No diagnostics found.", "GuardMe policy and state loaded successfully."]);
});
