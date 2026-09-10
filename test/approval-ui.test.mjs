import assert from "node:assert/strict";
import { mkdir, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { APPROVAL_CHOICES, approvalRowBudget, requestApprovalDecision } from "../src/ui/approval-modal.ts";
import { visibleWidth } from "../src/ui/text.ts";
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

  const result = await requestApprovalDecision({ cwd: request.cwd, hasUI: false, mode: "print", approvalMode: "auto", ui: {} }, request, decision);

  assert.equal(result.kind, "blocked");
  assert.match(result.reason, /interactive approval is unavailable|no UI/i);
});

test("auto mode suppresses approval UI in RPC even when UI methods exist", async () => {
  const { request, decision } = needsDecisionFixture();
  let interactiveCalls = 0;
  const result = await requestApprovalDecision(
    {
      cwd: request.cwd,
      hasUI: true,
      mode: "rpc",
      approvalMode: "auto",
      ui: {
        custom: async () => {
          interactiveCalls += 1;
        },
        select: async () => {
          interactiveCalls += 1;
          return undefined;
        },
        confirm: async () => {
          interactiveCalls += 1;
          return false;
        },
      },
    },
    request,
    decision,
  );

  assert.equal(result.kind, "blocked");
  assert.match(result.reason, /interactive approval is unavailable|not 'tui'/i);
  assert.equal(interactiveCalls, 0);
});

test("agent mode suppresses approval UI outside TUI", async () => {
  const { request, decision } = needsDecisionFixture();
  let interactiveCalls = 0;
  const result = await requestApprovalDecision(
    {
      cwd: request.cwd,
      hasUI: true,
      mode: "rpc",
      approvalMode: "agent",
      ui: {
        select: async () => {
          interactiveCalls += 1;
          return undefined;
        },
      },
    },
    request,
    decision,
  );

  assert.equal(result.kind, "blocked");
  assert.match(result.reason, /agent.*never invokes interactive approval UI/i);
  assert.equal(interactiveCalls, 0);
});

test("agent mode suppresses the approval prompt in TUI as well", async () => {
  const { request, decision } = needsDecisionFixture();
  let interactiveCalls = 0;
  const result = await requestApprovalDecision(
    {
      cwd: request.cwd,
      hasUI: true,
      mode: "tui",
      approvalMode: "agent",
      ui: {
        custom: async () => {
          interactiveCalls += 1;
        },
        select: async () => {
          interactiveCalls += 1;
          return undefined;
        },
      },
    },
    request,
    decision,
  );

  assert.equal(result.kind, "blocked");
  assert.match(result.reason, /agent.*never invokes interactive approval UI/i);
  assert.equal(interactiveCalls, 0);
});

test("block mode suppresses every approval UI method in TUI", async () => {
  const { request, decision } = needsDecisionFixture();
  let interactiveCalls = 0;
  const result = await requestApprovalDecision(
    {
      cwd: request.cwd,
      hasUI: true,
      mode: "tui",
      approvalMode: "block",
      ui: {
        custom: async () => {
          interactiveCalls += 1;
        },
        select: async () => {
          interactiveCalls += 1;
          return undefined;
        },
        confirm: async () => {
          interactiveCalls += 1;
          return false;
        },
      },
    },
    request,
    decision,
  );

  assert.equal(result.kind, "blocked");
  assert.match(result.reason, /approvalMode is 'block'/i);
  assert.equal(interactiveCalls, 0);
});

test("approval select fallback returns the selected decision", async () => {
  const { request, decision } = needsDecisionFixture();
  const label = `${APPROVAL_CHOICES[0].label} — ${APPROVAL_CHOICES[0].description}`;
  const ctx = {
    cwd: request.cwd,
    hasUI: true,
    mode: "rpc",
    approvalMode: "interactive",
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

test("approval falls back to native select when custom TUI creation fails", async () => {
  const { request, decision } = needsDecisionFixture();
  const selectedLabel = `${APPROVAL_CHOICES[4].label} — ${APPROVAL_CHOICES[4].description}`;
  const result = await requestApprovalDecision(
    {
      cwd: request.cwd,
      hasUI: true,
      mode: "tui",
      approvalMode: "auto",
      ui: {
        custom: async () => {
          throw new Error("custom TUI unavailable");
        },
        select: async (_title, options) => {
          assert.equal(options.length, 6);
          return selectedLabel;
        },
      },
    },
    request,
    decision,
  );

  assert.deepEqual(result, { kind: "decision", decision: "allow-global" });
});

test("native approval cancellation denies once", async () => {
  const { request, decision } = needsDecisionFixture();
  const result = await requestApprovalDecision(
    {
      cwd: request.cwd,
      hasUI: true,
      mode: "rpc",
      approvalMode: "interactive",
      ui: { select: async () => undefined },
    },
    request,
    decision,
  );

  assert.deepEqual(result, { kind: "decision", decision: "deny-once" });
});

test("TUI approval frame renders facts, redacts secrets, and escape denies once", async () => {
  const { request, decision } = needsDecisionFixture();
  let rendered = [];
  const ctx = {
    cwd: request.cwd,
    hasUI: true,
    mode: "tui",
    approvalMode: "auto",
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
  assert.ok(rendered.some((line) => line.includes("Block this call only")));
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
    approvalMode: "auto",
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
    approvalMode: "auto",
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

test("TUI approval uses injected selection keybindings for navigation, confirm, and cancel", async () => {
  const { request, decision } = needsDecisionFixture();
  const actionForInput = new Map([
    ["custom-up", "tui.select.up"],
    ["custom-down", "tui.select.down"],
    ["custom-confirm", "tui.select.confirm"],
    ["custom-cancel", "tui.select.cancel"],
  ]);
  const keybindings = { matches: (data, action) => actionForInput.get(data) === action };
  let call = 0;
  const ctx = {
    cwd: request.cwd,
    hasUI: true,
    mode: "tui",
    approvalMode: "auto",
    ui: {
      custom: async (factory) => {
        call += 1;
        let selected;
        const component = factory(
          { requestRender: () => {}, terminal: { rows: 24 } },
          { fg: (_color, text) => text, bold: (text) => text },
          keybindings,
          (value) => {
            selected = value;
          },
        );
        if (call === 1) {
          component.handleInput("custom-down");
          component.handleInput("custom-up");
          component.handleInput("custom-confirm");
        } else {
          component.handleInput("custom-cancel");
        }
        return selected;
      },
    },
  };

  assert.deepEqual(await requestApprovalDecision(ctx, request, decision), { kind: "decision", decision: "deny-once" });
  assert.deepEqual(await requestApprovalDecision(ctx, request, decision), { kind: "decision", decision: "deny-once" });
});

test("TUI approval stays width- and height-bounded in short and narrow panes", async () => {
  const { request, decision } = needsDecisionFixture();
  const terminal = { rows: 16 };
  const renderedBySize = [];
  const ctx = {
    cwd: request.cwd,
    hasUI: true,
    mode: "tui",
    approvalMode: "auto",
    ui: {
      custom: async (factory) => {
        const component = factory(
          { requestRender: () => {}, terminal },
          { fg: (_color, text) => text, bold: (text) => text },
          { matches: () => false },
          () => {},
        );
        renderedBySize.push({ width: 44, rows: terminal.rows, lines: component.render(44) });
        terminal.rows = 30;
        renderedBySize.push({ width: 44, rows: terminal.rows, lines: component.render(44) });
        renderedBySize.push({ width: 18, rows: terminal.rows, lines: component.render(18) });
        terminal.rows = 8;
        renderedBySize.push({ width: 44, rows: terminal.rows, lines: component.render(44) });
        return "deny-once";
      },
    },
  };

  await requestApprovalDecision(ctx, request, decision);

  for (const rendered of renderedBySize) {
    assert.ok(rendered.lines.length <= approvalRowBudget(rendered.rows));
    assert.ok(rendered.lines.every((line) => visibleWidth(line) <= rendered.width));
    assert.ok(rendered.lines.some((line) => line.includes("2/6")));
    assert.ok(rendered.lines.some((line) => line.includes("Deny once")));
    assert.ok(rendered.lines.some((line) => /Esc.*Deny once|Esc cancel = Deny once/.test(line)));
  }
  assert.notEqual(renderedBySize[0].lines.length, renderedBySize[1].lines.length);
});

test("short TUI approval keeps all six decisions reachable and reports omitted rules", async () => {
  const { request, decision } = needsDecisionFixture();
  const manyRulesDecision = {
    ...decision,
    matchedRules: Array.from({ length: 12 }, (_value, index) => ({
      ...decision.matchedRules[0],
      pattern: `rule-${index}`,
    })),
  };
  const visited = [];
  let fullLines = [];
  const ctx = {
    cwd: request.cwd,
    hasUI: true,
    mode: "tui",
    approvalMode: "auto",
    ui: {
      custom: async (factory) => {
        const terminal = { rows: 16 };
        const component = factory(
          { requestRender: () => {}, terminal },
          { fg: (_color, text) => text, bold: (text) => text },
          { matches: (data, action) => data === "next" && action === "tui.select.down" },
          () => {},
        );
        for (let index = 0; index < APPROVAL_CHOICES.length; index += 1) {
          const lines = component.render(70);
          visited.push(APPROVAL_CHOICES.find((choice) => lines.some((line) => line.includes(`Selected: ${choice.label}`)))?.decision);
          component.handleInput("next");
        }
        terminal.rows = 40;
        fullLines = component.render(100);
        return "deny-once";
      },
    },
  };

  await requestApprovalDecision(ctx, request, manyRulesDecision);

  assert.deepEqual(new Set(visited), new Set(APPROVAL_CHOICES.map((choice) => choice.decision)));
  assert.ok(fullLines.some((line) => /matched rules? omitted/.test(line)));
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
  await startGuardMeSession(ctx, {
    homeDir: home,
    environment: { GUARDME_APPROVAL_MODE: "interactive" },
  });

  const first = await evaluateGuardedToolCall({ toolName: "bash", input: { command: "find build -delete" } }, ctx);
  const second = await evaluateGuardedToolCall({ toolName: "bash", input: { command: "find build -delete" } }, ctx);

  assert.equal(first?.block, true);
  assert.equal(second, undefined);
  stopGuardMeSession(ctx);
});
