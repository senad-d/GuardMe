import assert from "node:assert/strict";
import test from "node:test";

import { createBuiltInDefaultPolicy } from "../src/config/schema.ts";
import { createRuleGroups, renderConfigPane, requestGuardMeConfigAction, requestPolicyWriteConfirmationAction, showPolicyWriteSuccess } from "../src/ui/config-tui.ts";

function snapshotFixture(config = createBuiltInDefaultPolicy()) {
  return {
    cwd: "/repo",
    projectTrusted: true,
    guardMe: "active",
    insecureEdits: false,
    policyRules: 46,
    warnedFingerprints: 0,
    warningRecords: [],
    diagnostics: [],
    settingsPath: ".pi/agent/guardme-settings.json",
    globalPolicyPath: "~/.pi/agent/guardme.yaml",
    localPolicyPath: "/repo/.pi/agent/guardme.yaml",
    globalStatePath: "~/.pi/agent/guardme-state.jsonl",
    localStatePath: "/repo/.pi/agent/guardme-state.jsonl",
    ruleGroups: createRuleGroups(config),
  };
}

test("config panes keep a stable frame height across sections", () => {
  const snapshot = snapshotFixture();
  const heights = ["General", "Policies", "Rules", "Setup"].map((pane) => renderConfigPane(snapshot, pane, 120).split("\n").length);

  assert.deepEqual([...new Set(heights)], [18]);
});

test("Setup pane includes append custom rule actions", () => {
  const output = renderConfigPane(snapshotFixture(), "Setup", 120);
  const lines = output.split("\n");
  const projectDefaultsLine = lines.findIndex((line) => line.includes("Create project policy with sensible defaults"));
  const buildGlobalLine = lines.findIndex((line) => line.includes("Build custom global policy"));
  const buildProjectLine = lines.findIndex((line) => line.includes("Build custom project policy"));
  const addGlobalLine = lines.findIndex((line) => line.includes("Add custom rule globally"));

  assert.match(output, /SETUP\s+1\/6/);
  assert.match(output, /Create global policy with sensible defaults/);
  assert.match(output, /Add custom rule globally/);
  assert.match(output, /Add custom rule locally/);
  assert.equal(buildGlobalLine, projectDefaultsLine + 2);
  assert.equal(addGlobalLine, buildProjectLine + 2);
});

test("Rules pane labels each count with its meaning", () => {
  const snapshot = {
    ...snapshotFixture(),
    policyRules: 47,
    ruleGroups: [
      { label: "Protected policy files", count: 3, description: "" },
      { label: "Dangerous shell commands", count: 16, description: "" },
      { label: "Secret and credential paths", count: 17, description: "" },
      { label: "Package manager operations", count: 7, description: "" },
      { label: "Git destructive operations", count: 7, description: "" },
      { label: "Project policy file", count: 47, description: "" },
    ],
  };
  const output = renderConfigPane(snapshot, "Rules", 120);

  assert.match(output, /CATEGORY MATCHES\s+COUNT/);
  assert.match(output, /Protected policy files\s+3 matching rules/);
  assert.match(output, /Dangerous shell commands\s+16 matching rules/);
  assert.match(output, /Secret and credential paths\s+17 matching rules/);
  assert.match(output, /SOURCE \/ TOTAL\s+RULES/);
  assert.match(output, /Project policy file\s+47 rules in file/);
  assert.match(output, /Merged active policy\s+47 active rules/);
  assert.match(output, /Category rows can overlap/);
  assert.doesNotMatch(output, /Custom project rules/);
  assert.doesNotMatch(output, /TOTAL:/);
});

test("General pane shows the current project path without tail truncation", () => {
  const cwd = "/Users/senad/Documents/Code/Moj_git/guardme";
  const output = renderConfigPane({ ...snapshotFixture(), cwd }, "General", 120);

  assert.match(output, /Current project/);
  assert.match(output, /\/Users\/senad\/Documents\/Code\/Moj_git\/guardme/);
  assert.match(output, /Policy rules\s+46/);
  assert.ok(output.indexOf("Policy rules") > output.indexOf("Current project"));
  assert.doesNotMatch(output, /PROJECT/);
  assert.doesNotMatch(output, /…uments\/Code\/Moj_git\/guardme/);
});

test("General pane shows Insecure edits directly below GuardMe", () => {
  const output = renderConfigPane(snapshotFixture(), "General", 120);
  const guardMeIndex = output.split("\n").findIndex((line) => /[▶ ] GuardMe\s+active/.test(line));
  const insecureIndex = output.split("\n").findIndex((line) => /[▶ ] Insecure edits\s+OFF/.test(line));
  const trustIndex = output.split("\n").findIndex((line) => /[▶ ] Pi project trust/.test(line));

  assert.ok(guardMeIndex >= 0);
  assert.equal(insecureIndex, guardMeIndex + 1);
  assert.equal(trustIndex, insecureIndex + 1);
});

test("config TUI routes setup default actions to the correct policy target", async () => {
  const defaults = createBuiltInDefaultPolicy();

  for (const scenario of [
    { setupRowMoves: 0, scope: "global", displayPath: "~/.pi/agent/guardme.yaml" },
    { setupRowMoves: 1, scope: "local", displayPath: ".pi/agent/guardme.yaml" },
  ]) {
    const result = await requestGuardMeConfigAction(
      {
        cwd: "/repo",
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
            component.handleInput("\n");
            for (let index = 0; index < scenario.setupRowMoves; index += 1) {
              component.handleInput("\u001B[B");
            }
            component.handleInput("\n");
            for (let attempt = 0; attempt < 10; attempt += 1) {
              await new Promise((resolve) => setTimeout(resolve, 1));
              if (component.render(120).some((line) => line.includes("CONFIRM WRITE"))) {
                break;
              }
            }
            component.handleInput("\n");
            return selected;
          },
        },
      },
      snapshotFixture(defaults),
      defaults,
      async (setupConfig) => ({
        ok: true,
        plan: {
          scope: setupConfig.scope,
          targetPath: setupConfig.scope === "global" ? "/home/.pi/agent/guardme.yaml" : "/repo/.pi/agent/guardme.yaml",
          displayPath: setupConfig.scope === "global" ? "~/.pi/agent/guardme.yaml" : ".pi/agent/guardme.yaml",
          policyKind: "default",
          existing: false,
          rules: 46,
        },
      }),
    );

    assert.equal(result.kind, "write");
    assert.equal(result.setupConfig.scope, scenario.scope);
    assert.equal(result.plan.displayPath, scenario.displayPath);
  }
});

test("policy write confirmation distinguishes Go back from Cancel", async () => {
  const setupConfig = {
    scope: "local",
    config: createBuiltInDefaultPolicy(),
    summary: "custom project policy (46 rules)",
    writeMode: "replace",
  };
  const plan = {
    scope: "local",
    targetPath: "/repo/.pi/agent/guardme.yaml",
    displayPath: ".pi/agent/guardme.yaml",
    policyKind: "custom",
    existing: false,
    rules: 46,
  };

  async function chooseAfterDownMoves(downMoves) {
    return requestPolicyWriteConfirmationAction(
      {
        cwd: "/repo",
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
            for (let index = 0; index < downMoves; index += 1) {
              component.handleInput("\u001B[B");
            }
            component.handleInput("\n");
            return selected;
          },
        },
      },
      setupConfig,
      plan,
    );
  }

  assert.equal(await chooseAfterDownMoves(1), "back");
  assert.equal(await chooseAfterDownMoves(2), "cancel");
});

test("config TUI policy write success references the written policy instead of runtime settings", async () => {
  const plan = {
    scope: "local",
    targetPath: "/repo/.pi/agent/guardme.yaml",
    displayPath: ".pi/agent/guardme.yaml",
    policyKind: "default",
    existing: false,
    rules: 46,
  };
  let rendered = [];

  await showPolicyWriteSuccess(
    {
      cwd: "/repo",
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
          rendered = component.render(140);
          component.handleInput("q");
        },
      },
    },
    snapshotFixture(),
    plan,
  );

  assert.ok(rendered.some((line) => line.includes("wrote .pi/agent/guardme.yaml")));
  assert.ok(rendered.some((line) => line.includes("Created project policy")));
  assert.ok(rendered.some((line) => line.includes(".pi/agent/guardme.yaml")));
  assert.ok(rendered.some((line) => line.includes("General reloaded")));
  assert.equal(rendered.some((line) => line.includes("guardme-settings.json")), false);
});

test("config TUI global policy write success references the written policy instead of runtime settings", async () => {
  const plan = {
    scope: "global",
    targetPath: "/home/.pi/agent/guardme.yaml",
    displayPath: "~/.pi/agent/guardme.yaml",
    policyKind: "default",
    existing: false,
    rules: 46,
  };
  let rendered = [];

  await showPolicyWriteSuccess(
    {
      cwd: "/repo",
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
          rendered = component.render(140);
          component.handleInput("q");
        },
      },
    },
    snapshotFixture(),
    plan,
  );

  assert.ok(rendered.some((line) => line.includes("wrote ~/.pi/agent/guardme.yaml")));
  assert.ok(rendered.some((line) => line.includes("Created global policy")));
  assert.ok(rendered.some((line) => line.includes("General reloaded")));
  assert.equal(rendered.some((line) => line.includes("guardme-settings.json")), false);
});

test("config TUI policy write success explains untrusted project-local loading", async () => {
  const plan = {
    scope: "local",
    targetPath: "/repo/.pi/agent/guardme.yaml",
    displayPath: ".pi/agent/guardme.yaml",
    policyKind: "default",
    existing: false,
    rules: 46,
  };
  let rendered = [];

  await showPolicyWriteSuccess(
    {
      cwd: "/repo",
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
          rendered = component.render(140);
          component.handleInput("q");
        },
      },
    },
    { ...snapshotFixture(), projectTrusted: false },
    plan,
  );

  assert.ok(rendered.some((line) => line.includes("wrote .pi/agent/guardme.yaml")));
  assert.ok(rendered.some((line) => line.includes("enable project trust to load")));
  assert.equal(rendered.some((line) => line.includes("guardme-settings.json")), false);
});

test("config TUI policy write success keeps General actions interactive", async () => {
  const plan = {
    scope: "local",
    targetPath: "/repo/.pi/agent/guardme.yaml",
    displayPath: ".pi/agent/guardme.yaml",
    policyKind: "default",
    existing: false,
    rules: 46,
  };
  let initialLines = [];
  let confirmLines = [];

  const result = await showPolicyWriteSuccess(
    {
      cwd: "/repo",
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
          initialLines = component.render(140);
          component.handleInput("\n");
          confirmLines = component.render(140);
          component.handleInput("\u001B");
          component.handleInput("q");
          return selected;
        },
      },
    },
    snapshotFixture(),
    plan,
    {
      sensibleDefaults: createBuiltInDefaultPolicy(),
      createPlan: async () => ({ ok: false, reason: "createPlan should not run for General actions" }),
    },
  );

  assert.ok(initialLines.some((line) => line.includes("Enter select")));
  assert.equal(initialLines.some((line) => line.includes("Enter close")), false);
  assert.ok(confirmLines.some((line) => line.includes("CONFIRM GUARDME OFF")));
  assert.deepEqual(result, { kind: "closed" });
});

test("config TUI policy write success summary does not close on Enter", async () => {
  const plan = {
    scope: "local",
    targetPath: "/repo/.pi/agent/guardme.yaml",
    displayPath: ".pi/agent/guardme.yaml",
    policyKind: "default",
    existing: false,
    rules: 46,
  };
  let selectedBeforeQuit;
  let initialLines = [];
  let afterEnterLines = [];

  const result = await showPolicyWriteSuccess(
    {
      cwd: "/repo",
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
          initialLines = component.render(140);
          component.handleInput("\n");
          selectedBeforeQuit = selected;
          afterEnterLines = component.render(140);
          component.handleInput("q");
          return selected;
        },
      },
    },
    snapshotFixture(),
    plan,
  );

  assert.equal(selectedBeforeQuit, undefined);
  assert.ok(initialLines.some((line) => line.includes("Enter inspect")));
  assert.equal(initialLines.some((line) => line.includes("Enter close")), false);
  assert.ok(afterEnterLines.some((line) => line.includes("GuardMe settings are available from /guardme")));
  assert.deepEqual(result, { kind: "closed" });
});

test("config TUI policy write success can launch another setup workflow", async () => {
  const plan = {
    scope: "local",
    targetPath: "/repo/.pi/agent/guardme.yaml",
    displayPath: ".pi/agent/guardme.yaml",
    policyKind: "append",
    existing: true,
    rules: 1,
  };
  let rendered = [];

  const result = await showPolicyWriteSuccess(
    {
      cwd: "/repo",
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
          component.handleInput("\t");
          component.handleInput("\u001B[A");
          component.handleInput("\n");
          component.handleInput("\u001B[A");
          rendered = component.render(140);
          component.handleInput("\n");
          return selected;
        },
      },
    },
    snapshotFixture(),
    plan,
    {
      sensibleDefaults: createBuiltInDefaultPolicy(),
      createPlan: async () => {
        throw new Error("append action should not create a default write plan");
      },
    },
  );

  assert.deepEqual(result, { kind: "append-rules", scope: "local" });
  assert.ok(rendered.some((line) => line.includes("Add custom rule locally")));
  assert.ok(rendered.some((line) => line.includes("Enter select")));
});

test("config TUI starts on General and setup selection wraps to local append rules", async () => {
  const defaults = createBuiltInDefaultPolicy();
  let initialLines = [];
  const result = await requestGuardMeConfigAction(
    {
      cwd: "/repo",
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
          initialLines = component.render(120);
          component.handleInput("\u001B[A");
          component.handleInput("\n");
          component.handleInput("\u001B[A");
          component.handleInput("\n");
          return selected;
        },
      },
    },
    snapshotFixture(defaults),
    defaults,
    async () => ({ ok: false, reason: "createPlan should not run for custom setup choices" }),
  );

  assert.ok(initialLines.some((line) => line.includes("GENERAL")));
  assert.ok(initialLines.some((line) => line.includes("▶ General")));
  assert.ok(initialLines.some((line) => line.includes("Enter open")));
  assert.equal(initialLines.some((line) => line.includes("▶ GuardMe")), false);
  assert.deepEqual(result, { kind: "append-rules", scope: "local" });
});

test("config TUI Escape exits the panel", async () => {
  const defaults = createBuiltInDefaultPolicy();
  for (const escapeInput of ["\u001B", "esc", "\u001B[27u", "\u001B[27;1;27~"]) {
    const result = await requestGuardMeConfigAction(
      {
        cwd: "/repo",
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
            component.handleInput(escapeInput);
            return selected;
          },
        },
      },
      snapshotFixture(defaults),
      defaults,
      async () => ({ ok: false, reason: "createPlan should not run when closing" }),
    );

    assert.deepEqual(result, { kind: "closed" });
  }
});

test("config TUI Escape clears search before closing the panel", async () => {
  const defaults = createBuiltInDefaultPolicy();
  let searchLines = [];
  let clearedLines = [];
  const result = await requestGuardMeConfigAction(
    {
      cwd: "/repo",
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
          component.handleInput("/");
          component.handleInput("d");
          searchLines = component.render(120);
          component.handleInput("\u001B");
          clearedLines = component.render(120);
          component.handleInput("q");
          return selected;
        },
      },
    },
    snapshotFixture(defaults),
    defaults,
    async () => ({ ok: false, reason: "createPlan should not run while searching" }),
  );

  assert.ok(searchLines.some((line) => line.includes("SEARCH D")));
  assert.equal(clearedLines.some((line) => line.includes("SEARCH")), false);
  assert.ok(clearedLines.some((line) => line.includes("GENERAL")));
  assert.deepEqual(result, { kind: "closed" });
});

test("config TUI keeps sidebar navigation while General rows are interactive", async () => {
  const defaults = createBuiltInDefaultPolicy();
  let sidebarLines = [];
  let statusLines = [];
  let policiesLines = [];
  const result = await requestGuardMeConfigAction(
    {
      cwd: "/repo",
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
          sidebarLines = component.render(120);
          component.handleInput("\n");
          statusLines = component.render(120);
          component.handleInput("\t");
          component.handleInput("\u001B[B");
          policiesLines = component.render(120);
          component.handleInput("q");
          return selected;
        },
      },
    },
    snapshotFixture(defaults),
    defaults,
    async () => ({ ok: false, reason: "createPlan should not run on info panes" }),
  );

  assert.ok(sidebarLines.some((line) => line.includes("▶ General")));
  assert.ok(sidebarLines.some((line) => line.includes("Enter open")));
  assert.ok(statusLines.some((line) => line.includes("GENERAL")));
  assert.ok(statusLines.some((line) => line.includes("Enter select")));
  assert.ok(statusLines.some((line) => line.includes("Esc/q quit")));
  assert.ok(policiesLines.some((line) => line.includes("POLICIES")));
  assert.deepEqual(result, { kind: "closed" });
});

test("config TUI GuardMe toggle requires confirmation before returning an action", async () => {
  const defaults = createBuiltInDefaultPolicy();
  let confirmLines = [];
  const result = await requestGuardMeConfigAction(
    {
      cwd: "/repo",
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
          component.handleInput("\n");
          component.handleInput("\n");
          confirmLines = component.render(120);
          component.handleInput("\n");
          return selected;
        },
      },
    },
    snapshotFixture(defaults),
    defaults,
    async () => ({ ok: false, reason: "createPlan should not run for GuardMe toggle" }),
  );

  assert.ok(confirmLines.some((line) => line.includes("CONFIRM GUARDME OFF")));
  assert.ok(confirmLines.some((line) => line.includes("GuardMe will stop blocking, coaching, or asking about")));
  assert.ok(confirmLines.some((line) => line.includes("guarded tool calls for this project.")));
  assert.equal(confirmLines.some((line) => line.includes("proj…")), false);
  assert.deepEqual(result, { kind: "set-guardme-enabled", enabled: false });
});

test("config TUI GuardMe off toggles active without confirmation", async () => {
  const defaults = createBuiltInDefaultPolicy();
  const result = await requestGuardMeConfigAction(
    {
      cwd: "/repo",
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
          component.handleInput("\n");
          component.handleInput("\n");
          return selected;
        },
      },
    },
    { ...snapshotFixture(defaults), guardMe: "off" },
    defaults,
    async () => ({ ok: false, reason: "createPlan should not run for GuardMe toggle" }),
  );

  assert.deepEqual(result, { kind: "set-guardme-enabled", enabled: true });
});

test("config TUI Insecure edits toggle requires confirmation before enabling", async () => {
  const defaults = createBuiltInDefaultPolicy();
  let confirmLines = [];
  const result = await requestGuardMeConfigAction(
    {
      cwd: "/repo",
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
          component.handleInput("\n");
          component.handleInput("\u001B[B");
          component.handleInput("\n");
          confirmLines = component.render(120);
          component.handleInput("\n");
          return selected;
        },
      },
    },
    snapshotFixture(defaults),
    defaults,
    async () => ({ ok: false, reason: "createPlan should not run for insecure edits toggle" }),
  );

  assert.ok(confirmLines.some((line) => line.includes("CONFIRM INSECURE EDITS")));
  assert.ok(confirmLines.some((line) => line.includes("Write and edit tool calls will bypass GuardMe policy.")));
  assert.deepEqual(result, { kind: "set-insecure-edits", enabled: true });
});

test("config TUI Insecure edits on toggles off without confirmation", async () => {
  const defaults = createBuiltInDefaultPolicy();
  const result = await requestGuardMeConfigAction(
    {
      cwd: "/repo",
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
          component.handleInput("\n");
          component.handleInput("\u001B[B");
          component.handleInput("\n");
          return selected;
        },
      },
    },
    { ...snapshotFixture(defaults), insecureEdits: true },
    defaults,
    async () => ({ ok: false, reason: "createPlan should not run for insecure edits toggle" }),
  );

  assert.deepEqual(result, { kind: "set-insecure-edits", enabled: false });
});

test("config TUI Pi project trust toggle returns a guarded trust action", async () => {
  const defaults = createBuiltInDefaultPolicy();
  let confirmLines = [];
  const result = await requestGuardMeConfigAction(
    {
      cwd: "/repo",
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
          component.handleInput("\n");
          component.handleInput("\u001B[B");
          component.handleInput("\u001B[B");
          component.handleInput("\n");
          confirmLines = component.render(120);
          component.handleInput("\n");
          return selected;
        },
      },
    },
    snapshotFixture(defaults),
    defaults,
    async () => ({ ok: false, reason: "createPlan should not run for project trust" }),
  );

  assert.ok(confirmLines.some((line) => line.includes("CONFIRM PI PROJECT TRUST")));
  assert.ok(confirmLines.some((line) => line.includes("Pi project trust → OFF • GuardMe skips project policy/settings/state until trusted again")));
  assert.equal(confirmLines.some((line) => line.includes("rel…")), false);
  assert.deepEqual(result, { kind: "set-project-trusted", trusted: false });
});

test("config TUI opens warning and diagnostic detail screens and Esc returns to General", async () => {
  const defaults = createBuiltInDefaultPolicy();
  const snapshot = {
    ...snapshotFixture(defaults),
    warnedFingerprints: 1,
    warningRecords: [
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
        target: "rm -rf build",
        count: 1,
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
    ],
    diagnostics: [
      {
        severity: "error",
        code: "config.invalidRoot",
        message: "GuardMe policy must be a YAML object.",
        source: { kind: "local", path: "/repo/.pi/agent/guardme.yaml" },
        path: "/repo/.pi/agent/guardme.yaml",
        ruleIndex: 12,
      },
    ],
  };
  let warningLines = [];
  let generalAfterWarning = [];
  let diagnosticLines = [];
  const result = await requestGuardMeConfigAction(
    {
      cwd: "/repo",
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
          component.handleInput("\n");
          component.handleInput("\u001B[B");
          component.handleInput("\u001B[B");
          component.handleInput("\u001B[B");
          component.handleInput("\n");
          warningLines = component.render(120);
          component.handleInput("\u001B");
          generalAfterWarning = component.render(120);
          component.handleInput("\u001B[B");
          component.handleInput("\n");
          diagnosticLines = component.render(120);
          component.handleInput("\u001B");
          component.handleInput("q");
          return selected;
        },
      },
    },
    snapshot,
    defaults,
    async () => ({ ok: false, reason: "createPlan should not run for detail screens" }),
  );

  assert.ok(warningLines.some((line) => line.includes("WARNINGS & DECISIONS")));
  assert.ok(warningLines.some((line) => line.includes("Line 1/")));
  assert.ok(warningLines.some((line) => line.includes("WARNING 2026-06-22")));
  assert.ok(warningLines.some((line) => line.includes("DECISION 2026-06-22")));
  assert.ok(generalAfterWarning.some((line) => line.includes("GENERAL")));
  assert.ok(diagnosticLines.some((line) => line.includes("DIAGNOSTIC DETAILS")));
  assert.ok(diagnosticLines.some((line) => line.includes("Line 1/")));
  assert.ok(diagnosticLines.some((line) => line.includes("ERROR config.invalidRoot")));
  assert.deepEqual(result, { kind: "closed" });
});

test("config TUI wraps long warning detail fields without truncating text", async () => {
  const defaults = createBuiltInDefaultPolicy();
  const target = "git diff -- src/ui/config-tui.ts src/commands/guardme-command.ts src/config/schema.ts test/config-tui.test.mjs test/guardme-command.test.mjs";
  const snapshot = {
    ...snapshotFixture(defaults),
    warnedFingerprints: 1,
    warningRecords: [
      {
        type: "warning",
        version: 1,
        timestamp: "2026-06-22T10:00:00.000Z",
        fingerprint: "sha256:wrapped",
        scope: "project",
        cwd: "/repo",
        toolName: "bash",
        action: "shell",
        risk: "medium",
        target,
        count: 1,
        reasonCode: "policy-missing-command",
        reason: `No allowCommands rule matches shell segment '${target}'. GuardMe blocks unclassified shell command segments by default.`,
        matchedRules: [
          {
            category: "commandDefaultDeny",
            source: { kind: "default", label: "default" },
            pattern: target,
            actions: ["shell"],
            reason: "Every executable shell segment requires an explicit allowCommands rule unless a stronger deny rule applies.",
          },
        ],
      },
    ],
  };
  let reasonLines = [];
  let ruleLines = [];

  const result = await requestGuardMeConfigAction(
    {
      cwd: "/repo",
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
          component.handleInput("\n");
          component.handleInput("\u001B[B");
          component.handleInput("\u001B[B");
          component.handleInput("\u001B[B");
          component.handleInput("\n");
          for (let index = 0; index < 7; index += 1) {
            component.handleInput("\u001B[B");
          }
          reasonLines = component.render(120);
          component.handleInput("\u001B[B");
          ruleLines = component.render(120);
          component.handleInput("q");
          component.handleInput("q");
          return selected;
        },
      },
    },
    snapshot,
    defaults,
    async () => ({ ok: false, reason: "createPlan should not run for detail screens" }),
  );

  const reasonScreen = reasonLines.join("\n");
  const ruleScreen = ruleLines.join("\n");
  assert.doesNotMatch(reasonScreen, /…/u);
  assert.match(reasonScreen, /Reason\s+No allowCommands rule matches shell segment 'git diff -- src\/ui\/config-tui\.ts/);
  assert.match(reasonScreen, /src\/commands\/guardme-command\.ts src\/config\/schema\.ts/);
  assert.match(reasonScreen, /test\/guardme-command\.test\.mjs'\. GuardMe blocks unclassified shell command/);
  assert.match(reasonScreen, /segments by default\./);
  assert.doesNotMatch(ruleScreen, /…/u);
  assert.match(ruleScreen, /Rule\s+commandDefaultDeny git diff -- src\/ui\/config-tui\.ts/);
  assert.match(ruleScreen, /test\/guardme-command\.test\.mjs \(default\) — Every executable shell segment requires/);
  assert.match(ruleScreen, /a stronger deny rule applies\./);
  assert.deepEqual(result, { kind: "closed" });
});

test("config TUI keeps warning detail scroll anchored on blank separator rows", async () => {
  const defaults = createBuiltInDefaultPolicy();
  const warningRecord = (timestamp, fingerprint, target) => ({
    type: "warning",
    version: 1,
    timestamp,
    fingerprint,
    scope: "project",
    cwd: "/repo",
    toolName: "bash",
    action: "shell",
    risk: "medium",
    target,
    count: 1,
    reasonCode: "policy-missing-command",
    reason: `No allowCommands rule matches shell segment '${target}'.`,
    matchedRules: [
      {
        category: "commandDefaultDeny",
        source: { kind: "default", label: "default" },
        pattern: target,
        actions: ["shell"],
        reason: "Every executable shell segment requires an explicit allowCommands rule.",
      },
    ],
  });
  const snapshot = {
    ...snapshotFixture(defaults),
    warnedFingerprints: 2,
    warningRecords: [
      warningRecord("2026-06-22T10:00:00.000Z", "sha256:first", "npm run first"),
      warningRecord("2026-06-22T10:05:00.000Z", "sha256:second", "npm run second"),
    ],
  };
  let separatorLines = [];

  const result = await requestGuardMeConfigAction(
    {
      cwd: "/repo",
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
          component.handleInput("\n");
          component.handleInput("\u001B[B");
          component.handleInput("\u001B[B");
          component.handleInput("\u001B[B");
          component.handleInput("\n");
          for (let index = 0; index < 11; index += 1) {
            component.handleInput("\u001B[B");
          }
          separatorLines = component.render(120);
          component.handleInput("q");
          component.handleInput("q");
          return selected;
        },
      },
    },
    snapshot,
    defaults,
    async () => ({ ok: false, reason: "createPlan should not run for detail screens" }),
  );

  const separatorScreen = separatorLines.join("\n");
  assert.match(separatorScreen, /WARNINGS & DECISIONS\s+Line 12\/23/);
  assert.match(separatorScreen, /WARNING 2026-06-22T10:05:00\.000Z/);
  assert.doesNotMatch(separatorScreen, /WARNING 2026-06-22T10:00:00\.000Z/);
  assert.deepEqual(result, { kind: "closed" });
});

test("config TUI search can focus new General labels", async () => {
  const defaults = createBuiltInDefaultPolicy();
  let focusedLines = [];
  const result = await requestGuardMeConfigAction(
    {
      cwd: "/repo",
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
          component.handleInput("/");
          for (const char of "trust") {
            component.handleInput(char);
          }
          component.handleInput("\n");
          focusedLines = component.render(120);
          component.handleInput("q");
          return selected;
        },
      },
    },
    snapshotFixture(defaults),
    defaults,
    async () => ({ ok: false, reason: "createPlan should not run during search" }),
  );

  assert.ok(focusedLines.some((line) => line.includes("▶ Pi project trust")));
  assert.deepEqual(result, { kind: "closed" });
});
