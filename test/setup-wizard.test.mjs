import assert from "node:assert/strict";
import test from "node:test";

import { createBuiltInDefaultPolicy } from "../src/config/schema.ts";
import { requestSetupConfiguration, requestSetupMode } from "../src/ui/setup-wizard.ts";

test("TUI setup element renders an intuitive setup menu", async () => {
  let rendered = [];
  const mode = await requestSetupMode({
    cwd: "/repo",
    hasUI: true,
    mode: "tui",
    ui: {
      custom: async (factory) => {
        let selected;
        const component = factory(
          { requestRender: () => {} },
          { fg: (_color, text) => text },
          {},
          (value) => {
            selected = value;
          },
        );
        rendered = component.render(100);
        component.handleInput("\n");
        return selected;
      },
    },
  });

  assert.equal(mode, "global-defaults");
  assert.ok(rendered.some((line) => line.includes("GuardMe setup")));
  const projectDefaultsLine = rendered.findIndex((line) => line.includes("Create project policy with sensible defaults"));
  const buildGlobalLine = rendered.findIndex((line) => line.includes("Build custom global policy"));
  const buildProjectLine = rendered.findIndex((line) => line.includes("Build custom project policy"));
  const addGlobalLine = rendered.findIndex((line) => line.includes("Add custom rule globally"));

  assert.ok(rendered.some((line) => line.includes("Create global policy with sensible defaults")));
  assert.ok(rendered.some((line) => line.includes("Build custom project policy")));
  assert.ok(rendered.some((line) => line.includes("Add custom rule globally")));
  assert.ok(rendered.some((line) => line.includes("Add custom rule locally")));
  assert.equal(buildGlobalLine, projectDefaultsLine + 2);
  assert.equal(addGlobalLine, buildProjectLine + 2);
  assert.ok(rendered.some((line) => line.includes("custom rules available")));
  assert.equal(rendered.some((line) => line.includes("Cancel setup")), false);
});

test("TUI setup selection wraps between first and last options", async () => {
  const mode = await requestSetupMode({
    cwd: "/repo",
    hasUI: true,
    mode: "tui",
    ui: {
      custom: async (factory) => {
        let selected;
        const component = factory(
          { requestRender: () => {} },
          { fg: (_color, text) => text },
          {},
          (value) => {
            selected = value;
          },
        );
        component.handleInput("\u001B[A");
        component.handleInput("\n");
        return selected;
      },
    },
  });

  assert.equal(mode, "local-add-rule");
});

test("TUI custom setup uses framed rule-section selector and in-frame rule inputs", async () => {
  const rendered = [];
  let customCalls = 0;

  const result = await requestSetupConfiguration(
    {
      cwd: "/repo",
      hasUI: true,
      mode: "tui",
      ui: {
        custom: async (factory) => {
          customCalls += 1;
          let selected;
          const component = factory(
            { requestRender: () => {} },
            { fg: (_color, text) => text, bold: (text) => text },
            {},
            (value) => {
              selected = value;
            },
          );

          if (customCalls === 1) {
            component.handleInput("\u001B[B");
            component.handleInput("\u001B[B");
            component.handleInput("\u001B[B");
            component.handleInput("\n");
            return selected;
          }

          const lines = component.render(120);
          rendered.push(...lines);
          if (lines.some((line) => line.includes("CUSTOM POLICY START"))) {
            component.handleInput("\u001B[B");
            component.handleInput("\n");
            return selected;
          }
          if (lines.some((line) => line.includes("RULE SECTION"))) {
            component.handleInput("\n");
            return selected;
          }
          if (lines.some((line) => line.includes("PATTERN FOR ALLOWPATHS"))) {
            for (const char of "custom/**") {
              component.handleInput(char);
            }
            rendered.push(...component.render(120));
            component.handleInput("\n");
            return selected;
          }
          if (lines.some((line) => line.includes("ACTIONS FOR ALLOWPATHS"))) {
            for (const char of "read,write") {
              component.handleInput(char);
            }
            rendered.push(...component.render(120));
            component.handleInput("\n");
            return selected;
          }
          if (lines.some((line) => line.includes("RULE REASON"))) {
            for (const char of "Custom project files") {
              component.handleInput(char);
            }
            rendered.push(...component.render(120));
            component.handleInput("\n");
            return selected;
          }
          if (lines.some((line) => line.includes("CUSTOM RULES"))) {
            component.handleInput("\u001B[B");
            component.handleInput("\n");
            return selected;
          }
          component.handleInput("\n");
          return selected;
        },
        confirm: async () => false,
      },
    },
    createBuiltInDefaultPolicy(),
  );

  assert.equal(result?.scope, "local");
  assert.equal(result?.config.allowPaths[0]?.pattern, "custom/**");
  assert.ok(rendered.some((line) => line.includes("GuardMe Config")));
  assert.ok(rendered.some((line) => line.includes("custom project policy • writes .pi/agent/guardme.yaml")));
  assert.ok(rendered.some((line) => line.includes("CUSTOM POLICY START")));
  assert.ok(rendered.some((line) => line.includes("No, start blank")));
  assert.ok(rendered.some((line) => line.includes("RULE SECTION")));
  assert.ok(rendered.some((line) => line.includes("allowPaths")));
  assert.ok(rendered.some((line) => line.includes("Save policy")));
  assert.ok(rendered.some((line) => line.includes("PATTERN FOR ALLOWPATHS")));
  assert.ok(rendered.some((line) => line.includes("> custom/**")));
  assert.ok(rendered.some((line) => line.includes("ACTIONS FOR ALLOWPATHS")));
  assert.ok(rendered.some((line) => line.includes("RULE REASON")));
  assert.ok(rendered.some((line) => line.includes("CUSTOM RULES")));
  assert.ok(rendered.some((line) => line.includes("No, save policy")));
  assert.equal(rendered.some((line) => line.includes("Choose rule section")), false);
});

test("TUI setup can collect custom rules for append mode", async () => {
  const rendered = [];
  let customCalls = 0;

  const result = await requestSetupConfiguration(
    {
      cwd: "/repo",
      hasUI: true,
      mode: "tui",
      ui: {
        custom: async (factory) => {
          customCalls += 1;
          let selected;
          const component = factory(
            { requestRender: () => {} },
            { fg: (_color, text) => text, bold: (text) => text },
            {},
            (value) => {
              selected = value;
            },
          );

          if (customCalls === 1) {
            for (let index = 0; index < 4; index += 1) {
              component.handleInput("\u001B[B");
            }
            component.handleInput("\n");
            return selected;
          }

          const lines = component.render(120);
          rendered.push(...lines);
          if (lines.some((line) => line.includes("RULE SECTION"))) {
            if (rendered.some((line) => line.includes("PATTERN FOR ALLOWPATHS"))) {
              component.handleInput("\u001B[A");
            }
            component.handleInput("\n");
            return selected;
          }
          if (lines.some((line) => line.includes("PATTERN FOR ALLOWPATHS"))) {
            for (const char of "src/**") {
              component.handleInput(char);
            }
            component.handleInput("\n");
            return selected;
          }
          if (lines.some((line) => line.includes("ACTIONS FOR ALLOWPATHS"))) {
            for (const char of "read") {
              component.handleInput(char);
            }
            component.handleInput("\n");
            return selected;
          }
          if (lines.some((line) => line.includes("RULE REASON"))) {
            for (const char of "Source reads") {
              component.handleInput(char);
            }
            component.handleInput("\n");
            return selected;
          }
          component.handleInput("\n");
          return selected;
        },
      },
    },
    createBuiltInDefaultPolicy(),
  );

  assert.equal(result?.scope, "global");
  assert.equal(result?.writeMode, "append");
  assert.match(result?.summary ?? "", /append custom rules/);
  assert.equal(result?.config.allowPaths[0]?.pattern, "src/**");
  assert.deepEqual(result?.config.allowPaths[0]?.actions, ["read"]);
  assert.ok(rendered.some((line) => line.includes("custom global policy • writes ~/.pi/agent/guardme.yaml")));
  assert.ok(rendered.some((line) => line.includes("PATTERN FOR ALLOWPATHS")));
});

test("setup wizard can build fully custom project rules", async () => {
  const selectResponses = [
    "Build custom project policy — Start from defaults or blank, then add fully custom rules.",
    "allowPaths — allow matching path actions",
  ];
  const inputResponses = ["custom/**", "read,write", "Custom project files"];
  const confirmResponses = [false, false];

  const result = await requestSetupConfiguration(
    {
      cwd: "/repo",
      hasUI: true,
      mode: "rpc",
      ui: {
        select: async () => selectResponses.shift(),
        input: async () => inputResponses.shift(),
        confirm: async () => confirmResponses.shift() ?? false,
      },
    },
    createBuiltInDefaultPolicy(),
  );

  assert.equal(result?.scope, "local");
  assert.match(result?.summary ?? "", /custom project policy/);
  assert.equal(result?.config.allowPaths[0]?.pattern, "custom/**");
  assert.deepEqual(result?.config.allowPaths[0]?.actions, ["read", "write"]);
  assert.equal(result?.config.allowPaths[0]?.reason, "Custom project files");
  assert.equal(result?.config.zeroAccessPaths.length, 0);
});

test("setup wizard does not add path rules when custom actions are invalid", async () => {
  const selectResponses = [
    "Build custom project policy — Start from defaults or blank, then add fully custom rules.",
    "allowPaths — allow matching path actions",
  ];
  const inputResponses = ["custom/**", "shell", "Custom project files"];
  const confirmResponses = [false, false];

  const result = await requestSetupConfiguration(
    {
      cwd: "/repo",
      hasUI: true,
      mode: "rpc",
      ui: {
        select: async () => selectResponses.shift(),
        input: async () => inputResponses.shift(),
        confirm: async () => confirmResponses.shift() ?? false,
      },
    },
    createBuiltInDefaultPolicy(),
  );

  assert.equal(result?.scope, "local");
  assert.deepEqual(result?.config.allowPaths, []);
});

test("setup wizard sensible defaults include required GuardMe protection sections", async () => {
  const result = await requestSetupConfiguration(
    {
      cwd: "/repo",
      hasUI: true,
      mode: "rpc",
      ui: {
        select: async () => "Create global policy with sensible defaults — Recommended first install: writes ~/.pi/agent/guardme.yaml.",
      },
    },
    createBuiltInDefaultPolicy(),
  );

  assert.equal(result?.scope, "global");
  assert.ok((result?.config.zeroAccessPaths.length ?? 0) > 0);
  assert.ok((result?.config.noDeletePaths.length ?? 0) > 0);
  assert.ok((result?.config.denyCommands.length ?? 0) > 0);
  assert.ok((result?.config.protectedCredentialPaths.length ?? 0) > 0);
});
