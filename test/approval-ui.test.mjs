import assert from "node:assert/strict";
import { mkdir, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { APPROVAL_CHOICES, requestApprovalDecision } from "../src/ui/approval-modal.ts";
import { USER_DECISIONS } from "../src/policy/action.ts";
import { evaluateGuardedToolCall } from "../src/events/register-guard.ts";
import { startGuardMeSession, stopGuardMeSession } from "../src/events/register-lifecycle.ts";

function needsDecisionFixture() {
  const request = {
    toolName: "bash",
    action: "delete",
    cwd: "/repo",
    command: "SECRET_KEY=supersecret rm -rf build --password hunter2",
    targets: [],
  };
  const decision = {
    outcome: "needs-user-decision",
    action: "delete",
    risk: "dangerous",
    reason: "Dangerous command requires approval.",
    matchedRules: [
      {
        category: "dangerousCommands",
        source: { kind: "builtin", label: "test" },
        pattern: "rm -rf *",
        actions: ["delete"],
        reason: "Recursive delete",
      },
    ],
    fingerprint: "sha256:test",
    prompt: true,
    choices: USER_DECISIONS,
    recommendation: "Prefer a narrower command.",
  };
  return { request, decision };
}

test("approval flow blocks when no UI is available", async () => {
  const { request, decision } = needsDecisionFixture();

  const result = await requestApprovalDecision({ cwd: request.cwd, hasUI: false, mode: "print", ui: {} }, request, decision);

  assert.equal(result.kind, "blocked");
  assert.match(result.reason, /no UI/i);
});

test("approval select fallback returns the selected decision", async () => {
  const { request, decision } = needsDecisionFixture();
  const label = `${APPROVAL_CHOICES[0].label} — ${APPROVAL_CHOICES[0].description}`;
  const ctx = {
    cwd: request.cwd,
    hasUI: true,
    mode: "rpc",
    ui: {
      select: async (title, options) => {
        assert.match(title, /GuardMe approval required/);
        assert.equal(options.length, 6);
        return label;
      },
    },
  };

  const result = await requestApprovalDecision(ctx, request, decision);

  assert.deepEqual(
    APPROVAL_CHOICES.map((choice) => choice.decision),
    ["allow-once", "deny-once", "allow-local", "deny-local", "allow-global", "deny-global"],
  );
  assert.deepEqual(result, { kind: "decision", decision: "allow-once" });
});

test("TUI approval frame renders facts, redacts secrets, and escape denies once", async () => {
  const { request, decision } = needsDecisionFixture();
  let rendered = [];
  const ctx = {
    cwd: request.cwd,
    hasUI: true,
    mode: "tui",
    ui: {
      custom: async (factory, options) => {
        assert.equal(options?.overlay, undefined);
        let selected;
        const component = factory(
          { requestRender: () => {} },
          { fg: (_color, text) => text, bold: (text) => text },
          {},
          (value) => {
            selected = value;
          },
        );
        rendered = component.render(88);
        component.handleInput("\u001B");
        return selected;
      },
    },
  };

  const result = await requestApprovalDecision(ctx, request, decision);

  assert.deepEqual(result, { kind: "decision", decision: "deny-once" });
  assert.ok(rendered.some((line) => line.includes("GuardMe approval required")));
  assert.equal(rendered.some((line) => line.includes("▶ Approval")), false);
  assert.equal(rendered.some((line) => line.includes("…") || line.includes("...")), false);
  assert.ok(rendered.some((line) => line.includes("Risk:")));
  assert.ok(rendered.some((line) => line.includes("dangerousCommands")));
  assert.ok(rendered.some((line) => line.includes("Allow + save project rule")));
  assert.ok(rendered.some((line) => line.includes("Run now and save an allow rule")));
  assert.equal(rendered.some((line) => line.includes("supersecret")), false);
  assert.equal(rendered.some((line) => line.includes("hunter2")), false);
  assert.ok(rendered.some((line) => line.includes("SECRET_KEY=<redacted>")));
  assert.ok(rendered.some((line) => line.includes("--password <redacted>")));
});

test("TUI approval frame strips terminal control sequences from untrusted text", async () => {
  const { request, decision } = needsDecisionFixture();
  const unsafeRequest = {
    ...request,
    cwd: "/repo/\u001B[31mred",
    command: "echo safe\u001B]52;c;Zm9v\u0007 --token secret-token",
  };
  const unsafeDecision = {
    ...decision,
    reason: "Needs approval\u001B[2J",
    matchedRules: [
      {
        ...decision.matchedRules[0],
        pattern: "rm -rf *\u001B[31m",
        reason: "Recursive delete\u0007",
        source: { kind: "local", path: "/repo/\u001B[31mguardme.yaml" },
      },
    ],
  };
  let rendered = [];
  const ctx = {
    cwd: unsafeRequest.cwd,
    hasUI: true,
    mode: "tui",
    ui: {
      custom: async (factory) => {
        const component = factory(
          { requestRender: () => {} },
          { fg: (_color, text) => text, bold: (text) => text },
          {},
          () => {},
        );
        rendered = component.render(120);
        return "deny-once";
      },
    },
  };

  await requestApprovalDecision(ctx, unsafeRequest, unsafeDecision);

  assert.equal(rendered.some((line) => /[\u001B\u0007]/u.test(line)), false);
  assert.equal(rendered.some((line) => line.includes("secret-token")), false);
  assert.ok(rendered.some((line) => line.includes("--token <redacted>")));
});

test("TUI approval selection wraps between first and last choices", async () => {
  const { request, decision } = needsDecisionFixture();
  const ctx = {
    cwd: request.cwd,
    hasUI: true,
    mode: "tui",
    ui: {
      custom: async (factory) => {
        let selected;
        const component = factory(
          { requestRender: () => {} },
          { fg: (_color, text) => text, bold: (text) => text },
          {},
          (value) => {
            selected = value;
          },
        );
        component.handleInput("\u001B[A");
        component.handleInput("\u001B[A");
        component.handleInput("\n");
        return selected;
      },
    },
  };

  const result = await requestApprovalDecision(ctx, request, decision);

  assert.deepEqual(result, { kind: "decision", decision: "deny-global" });
});

test("guard uses approval fallback for repeated dangerous actions", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-approval-guard-"));
  const home = join(root, "home");
  const cwd = join(root, "project");
  await mkdir(cwd, { recursive: true });
  const allowLabel = `${APPROVAL_CHOICES[0].label} — ${APPROVAL_CHOICES[0].description}`;
  const ctx = {
    cwd,
    hasUI: true,
    mode: "rpc",
    isProjectTrusted: () => true,
    ui: {
      setStatus: () => {},
      notify: () => {},
      select: async () => allowLabel,
    },
  };
  await startGuardMeSession(ctx, { homeDir: home });

  const first = await evaluateGuardedToolCall({ toolName: "bash", input: { command: "rm -rf build" } }, ctx);
  const second = await evaluateGuardedToolCall({ toolName: "bash", input: { command: "rm -rf build" } }, ctx);

  assert.equal(first?.block, true);
  assert.equal(second, undefined);
  stopGuardMeSession(ctx);
});
