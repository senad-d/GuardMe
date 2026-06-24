import { ProjectTrustStore } from "@earendil-works/pi-coding-agent";
import assert from "node:assert/strict";
import { access, mkdir, mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { resolvePolicyConfigPaths } from "../src/config/load-config.ts";
import { resolveRuntimeSettingsPath } from "../src/config/runtime-settings.ts";
import {
  getGuardMeArgumentCompletions,
  handleGuardMeCommand,
  registerGuardMeCommand,
  renderHelp,
  renderPaths,
} from "../src/commands/guardme-command.ts";
import { startGuardMeSession, stopGuardMeSession } from "../src/events/register-lifecycle.ts";

function commandContext(cwd, options = {}) {
  const notifications = [];
  return {
    ctx: {
      cwd,
      homeDir: options.homeDir,
      hasUI: options.hasUI ?? true,
      mode: options.mode,
      isProjectTrusted: () => options.trusted ?? true,
      ui: {
        notify: (message, type) => notifications.push([message, type]),
        confirm: options.confirm,
        select: options.select,
        input: options.input,
        custom: options.custom,
        setStatus: () => {},
      },
    },
    notifications,
  };
}

async function pathExists(path) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

test("/guardme command registration wires the command handler and user-facing help completion", () => {
  const commands = new Map();
  registerGuardMeCommand({ registerCommand: (name, options) => commands.set(name, options) });

  assert.equal(commands.has("guardme"), true);
  assert.match(commands.get("guardme").description, /GuardMe configuration/);
  assert.equal(typeof commands.get("guardme").handler, "function");
  assert.equal(typeof commands.get("guardme").getArgumentCompletions, "function");
  assert.deepEqual(
    commands.get("guardme").getArgumentCompletions("h").map((item) => item.value),
    ["help"],
  );
  assert.deepEqual(
    getGuardMeArgumentCompletions("").map((item) => item.value),
    ["help"],
  );
});

test("/guardme help and paths render usage and approved paths", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "guardme-command-help-"));
  const { ctx, notifications } = commandContext(cwd);

  await handleGuardMeCommand("help", ctx);
  await handleGuardMeCommand("paths", ctx);

  assert.match(renderHelp(), /\/guardme\b/);
  assert.match(renderHelp(), /\/guardme help/);
  assert.doesNotMatch(renderHelp(), /\/guardme status/);
  assert.doesNotMatch(renderHelp(), /\/guardme conf/);
  assert.match(renderPaths(ctx), /~\/\.pi\/agent\/guardme.yaml/);
  assert.match(notifications[0][0], /GuardMe usage/);
  assert.match(notifications[1][0], /Policy paths:/);
});

test("/guardme notifications strip terminal control sequences from user input", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "guardme-command-sanitize-"));
  const { ctx, notifications } = commandContext(cwd);

  await handleGuardMeCommand("unknown\u001B]52;c;Zm9v\u0007", ctx);

  const output = notifications.at(-1)?.[0] ?? "";
  assert.doesNotMatch(output, /[\u001B\u0007]/u);
  assert.match(output, /Unknown GuardMe command/);
});

test("/guardme status shows current status paths and diagnostics", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-command-status-"));
  const home = join(root, "home");
  const cwd = join(root, "project");
  await mkdir(cwd, { recursive: true });
  const { ctx, notifications } = commandContext(cwd);
  await startGuardMeSession(ctx, { homeDir: home });

  await handleGuardMeCommand("status", ctx);
  const output = notifications.at(-1)?.[0] ?? "";

  assert.match(output, /GuardMe: active/);
  assert.doesNotMatch(output, /│▶ General\s+│▶ GuardMe/);
  assert.match(output, /Policy rules:/);
  assert.match(output, /Diagnostics: none/);
  assert.match(output, /State paths:/);
  stopGuardMeSession(ctx);
});

test("/guardme setup degrades safely without UI confirmation", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-command-setup-nonui-"));
  const cwd = join(root, "project");
  await mkdir(cwd, { recursive: true });
  const paths = resolvePolicyConfigPaths(cwd, join(root, "home"));
  const { ctx, notifications } = commandContext(cwd, { hasUI: false });

  await handleGuardMeCommand("setup", ctx);

  assert.match(notifications.at(-1)?.[0] ?? "", /requires an interactive UI/);
  await assert.rejects(access(paths.localPolicyPath));
});

test("/guardme setup writes local YAML with sensible defaults from setup UI", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-command-setup-"));
  const homeDir = join(root, "home");
  const cwd = join(root, "project");
  await mkdir(cwd, { recursive: true });
  const paths = resolvePolicyConfigPaths(cwd, homeDir);
  const settingsPath = resolveRuntimeSettingsPath(cwd).settingsPath;
  const { ctx, notifications } = commandContext(cwd, {
    homeDir,
    select: async (_title, options) => options.find((option) => option.startsWith("Create project policy with sensible defaults")),
  });

  await assert.rejects(access(paths.localPolicyPath));
  await handleGuardMeCommand("setup", ctx);
  const yaml = await readFile(paths.localPolicyPath, "utf8");

  assert.match(notifications.at(-1)?.[0] ?? "", /Created GuardMe project policy/);
  assert.match(yaml, /zeroAccessPaths:/);
  assert.match(yaml, /noDeletePaths:/);
  assert.match(yaml, /protectedCredentialPaths:/);
  assert.equal(await pathExists(paths.globalPolicyPath), false);
  assert.equal(await pathExists(settingsPath), false);
  stopGuardMeSession(ctx);
});

test("/guardme setup confirmation Go back returns to setup options", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-command-setup-back-"));
  const homeDir = join(root, "home");
  const cwd = join(root, "project");
  await mkdir(cwd, { recursive: true });
  const paths = resolvePolicyConfigPaths(cwd, homeDir);
  const renderedAfterBack = [];
  let customCalls = 0;
  const { ctx, notifications } = commandContext(cwd, {
    homeDir,
    mode: "tui",
    custom: async (factory) => {
      customCalls += 1;
      let result;
      const component = factory(
        { requestRender: () => {} },
        { fg: (_color, text) => text, bold: (text) => text },
        {},
        (value) => {
          result = value;
        },
      );

      if (customCalls === 1) {
        component.handleInput("\u001B[B");
        component.handleInput("\n");
        return result;
      }

      if (customCalls === 2) {
        component.handleInput("\u001B[B");
        component.handleInput("\n");
        return result;
      }

      if (customCalls === 3) {
        renderedAfterBack.push(...component.render(120));
        component.handleInput("\u001B[B");
        component.handleInput("\n");
        return result;
      }

      if (customCalls === 4) {
        component.handleInput("\n");
        return result;
      }

      if (customCalls === 5) {
        component.handleInput("q");
        return result;
      }

      throw new Error(`unexpected setup custom call ${customCalls}`);
    },
  });

  await handleGuardMeCommand("setup", ctx);
  const yaml = await readFile(paths.localPolicyPath, "utf8");

  assert.equal(customCalls, 5);
  assert.ok(renderedAfterBack.some((line) => line.includes("GuardMe setup")));
  assert.match(yaml, /zeroAccessPaths:/);
  assert.equal(notifications.some(([message]) => /cancelled/i.test(message)), false);
  stopGuardMeSession(ctx);
});

test("/guardme config custom rule confirmation Go back returns to rule section", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-command-config-rule-back-"));
  const homeDir = join(root, "home");
  const cwd = join(root, "project");
  await mkdir(cwd, { recursive: true });
  const paths = resolvePolicyConfigPaths(cwd, homeDir);
  const renderedAfterBack = [];
  let customCalls = 0;
  const { ctx } = commandContext(cwd, {
    homeDir,
    mode: "tui",
    custom: async (factory) => {
      customCalls += 1;
      let result;
      const component = factory(
        { requestRender: () => {} },
        { fg: (_color, text) => text, bold: (text) => text },
        {},
        (value) => {
          result = value;
        },
      );

      if (customCalls === 1) {
        component.handleInput("\u001B[A");
        component.handleInput("\n");
        component.handleInput("\u001B[A");
        component.handleInput("\n");
        return result;
      }

      if (customCalls === 2 || customCalls === 8) {
        if (customCalls === 8) {
          renderedAfterBack.push(...component.render(120));
        }
        component.handleInput("\n");
        return result;
      }

      if (customCalls === 3 || customCalls === 9) {
        for (const char of customCalls === 3 ? "src/**" : "docs/**") {
          component.handleInput(char);
        }
        component.handleInput("\n");
        return result;
      }

      if (customCalls === 4 || customCalls === 10) {
        for (const char of "read") {
          component.handleInput(char);
        }
        component.handleInput("\n");
        return result;
      }

      if (customCalls === 5 || customCalls === 11) {
        for (const char of customCalls === 5 ? "Source reads" : "Docs reads") {
          component.handleInput(char);
        }
        component.handleInput("\n");
        return result;
      }

      if (customCalls === 6 || customCalls === 12) {
        component.handleInput("\u001B[A");
        component.handleInput("\n");
        return result;
      }

      if (customCalls === 7) {
        component.handleInput("\u001B[B");
        component.handleInput("\n");
        return result;
      }

      if (customCalls === 13) {
        component.handleInput("\n");
        return result;
      }

      if (customCalls === 14) {
        component.handleInput("q");
        return result;
      }

      throw new Error(`unexpected custom call ${customCalls}`);
    },
  });

  await handleGuardMeCommand("", ctx);
  const yaml = await readFile(paths.localPolicyPath, "utf8");

  assert.ok(renderedAfterBack.some((line) => line.includes("RULE SECTION")));
  assert.equal(renderedAfterBack.some((line) => line.includes("GENERAL")), false);
  assert.match(yaml, /src\/\*\*/);
  assert.match(yaml, /docs\/\*\*/);
  stopGuardMeSession(ctx);
});

test("/guardme setup writes global YAML only for global sensible defaults", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-command-setup-global-"));
  const homeDir = join(root, "home");
  const cwd = join(root, "project");
  await mkdir(cwd, { recursive: true });
  const paths = resolvePolicyConfigPaths(cwd, homeDir);
  const settingsPath = resolveRuntimeSettingsPath(cwd).settingsPath;
  const { ctx, notifications } = commandContext(cwd, {
    homeDir,
    select: async (_title, options) => options.find((option) => option.startsWith("Create global policy with sensible defaults")),
  });

  await handleGuardMeCommand("setup", ctx);
  const yaml = await readFile(paths.globalPolicyPath, "utf8");

  assert.match(notifications.at(-1)?.[0] ?? "", /Created GuardMe global policy/);
  assert.match(yaml, /zeroAccessPaths:/);
  assert.equal(await pathExists(paths.localPolicyPath), false);
  assert.equal(await pathExists(settingsPath), false);
  stopGuardMeSession(ctx);
});

test("/guardme setup creates untrusted project policy but explains trust is required to load it", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-command-setup-untrusted-"));
  const homeDir = join(root, "home");
  const cwd = join(root, "project");
  await mkdir(cwd, { recursive: true });
  const paths = resolvePolicyConfigPaths(cwd, homeDir);
  const settingsPath = resolveRuntimeSettingsPath(cwd).settingsPath;
  const { ctx, notifications } = commandContext(cwd, {
    homeDir,
    trusted: false,
    select: async (_title, options) => options.find((option) => option.startsWith("Create project policy with sensible defaults")),
  });

  await handleGuardMeCommand("setup", ctx);
  const yaml = await readFile(paths.localPolicyPath, "utf8");

  assert.match(yaml, /zeroAccessPaths:/);
  assert.equal(await pathExists(paths.globalPolicyPath), false);
  assert.equal(await pathExists(settingsPath), false);
  assert.match(notifications.at(-1)?.[0] ?? "", /Project is not trusted/);
  assert.match(notifications.at(-1)?.[0] ?? "", /load after project trust is enabled/);
  stopGuardMeSession(ctx);
});

test("/guardme opens framed setup confirmation before writing", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-command-conf-"));
  const homeDir = join(root, "home");
  const cwd = join(root, "project");
  await mkdir(cwd, { recursive: true });
  const paths = resolvePolicyConfigPaths(cwd, homeDir);
  const rendered = [];
  let customCalls = 0;
  const { ctx } = commandContext(cwd, {
    homeDir,
    mode: "tui",
    custom: async (factory, options) => {
      assert.equal(options?.overlay, undefined);
      customCalls += 1;
      let result;
      const component = factory(
        { requestRender: () => {} },
        { fg: (_color, text) => text, bold: (text) => text },
        {},
        (value) => {
          result = value;
        },
      );

      if (customCalls === 1) {
        rendered.push(...component.render(120));
        component.handleInput("\u001B[A");
        component.handleInput("\n");
        component.handleInput("\u001B[B");
        component.handleInput("\n");
        let confirmLines = [];
        for (let attempt = 0; attempt < 10; attempt += 1) {
          await new Promise((resolve) => setTimeout(resolve, 1));
          confirmLines = component.render(120);
          if (confirmLines.some((line) => line.includes("CONFIRM WRITE"))) {
            break;
          }
        }
        rendered.push(...confirmLines);
        await assert.rejects(access(paths.localPolicyPath));
        component.handleInput("\n");
        return result;
      }

      rendered.push(...component.render(120));
      component.handleInput("\t");
      component.handleInput("\u001B[B");
      rendered.push(...component.render(120));
      component.handleInput("q");
      return result;
    },
  });

  await handleGuardMeCommand("", ctx);
  const yaml = await readFile(paths.localPolicyPath, "utf8");

  assert.ok(rendered.some((line) => line.includes("GuardMe Config")));
  assert.ok(rendered.some((line) => line.includes("CONFIRM WRITE")));
  assert.ok(rendered.some((line) => line.includes("GENERAL")));
  assert.ok(rendered.some((line) => line.includes("POLICIES")));
  assert.ok(rendered.some((line) => line.includes("General reloaded")));
  assert.equal(rendered.some((line) => line.includes("SETUP COMPLETE")), false);
  assert.match(yaml, /zeroAccessPaths:/);
});

test("/guardme General toggle persists GuardMe off for the project", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-command-toggle-"));
  const homeDir = join(root, "home");
  const cwd = join(root, "project");
  await mkdir(cwd, { recursive: true });
  const settingsPath = resolveRuntimeSettingsPath(cwd).settingsPath;
  let customCalls = 0;
  let reopenedLines = [];
  const { ctx, notifications } = commandContext(cwd, {
    homeDir,
    mode: "tui",
    custom: async (factory) => {
      customCalls += 1;
      let result;
      const component = factory(
        { requestRender: () => {} },
        { fg: (_color, text) => text, bold: (text) => text },
        {},
        (value) => {
          result = value;
        },
      );

      if (customCalls === 1) {
        component.handleInput("\n");
        component.handleInput("\n");
        component.handleInput("\n");
        return result;
      }

      reopenedLines = component.render(120);
      component.handleInput("q");
      return result;
    },
  });
  await startGuardMeSession(ctx, { homeDir });

  await handleGuardMeCommand("", ctx);
  const saved = JSON.parse(await readFile(settingsPath, "utf8"));

  assert.equal(saved.enabled, false);
  assert.ok(reopenedLines.some((line) => line.includes("off")));
  assert.match(notifications.at(-1)?.[0] ?? "", /GuardMe is off/);
  stopGuardMeSession(ctx);
});

test("/guardme General toggle in an untrusted project explains settings apply after trust", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-command-toggle-untrusted-"));
  const homeDir = join(root, "home");
  const cwd = join(root, "project");
  await mkdir(cwd, { recursive: true });
  const settingsPath = resolveRuntimeSettingsPath(cwd).settingsPath;
  let customCalls = 0;
  let reopenedLines = [];
  const { ctx, notifications } = commandContext(cwd, {
    homeDir,
    trusted: false,
    mode: "tui",
    custom: async (factory) => {
      customCalls += 1;
      let result;
      const component = factory(
        { requestRender: () => {} },
        { fg: (_color, text) => text, bold: (text) => text },
        {},
        (value) => {
          result = value;
        },
      );

      if (customCalls === 1) {
        component.handleInput("\n");
        component.handleInput("\n");
        component.handleInput("\n");
        return result;
      }

      reopenedLines = component.render(120);
      component.handleInput("q");
      return result;
    },
  });
  await startGuardMeSession(ctx, { homeDir });

  await handleGuardMeCommand("", ctx);
  const saved = JSON.parse(await readFile(settingsPath, "utf8"));

  assert.equal(saved.enabled, false);
  assert.ok(reopenedLines.some((line) => line.includes("active")));
  assert.match(notifications.at(-1)?.[0] ?? "", /will apply after project trust is enabled/);
  stopGuardMeSession(ctx);
});

test("/guardme General project trust toggle writes Pi trust store", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-command-trust-"));
  const homeDir = join(root, "home");
  const cwd = join(root, "project");
  await mkdir(cwd, { recursive: true });
  let customCalls = 0;
  let reopenedLines = [];
  const { ctx, notifications } = commandContext(cwd, {
    homeDir,
    trusted: false,
    mode: "tui",
    custom: async (factory) => {
      customCalls += 1;
      let result;
      const component = factory(
        { requestRender: () => {} },
        { fg: (_color, text) => text, bold: (text) => text },
        {},
        (value) => {
          result = value;
        },
      );

      if (customCalls === 1) {
        component.handleInput("\n");
        component.handleInput("\u001B[B");
        component.handleInput("\n");
        component.handleInput("\n");
        return result;
      }

      reopenedLines = component.render(120);
      component.handleInput("q");
      return result;
    },
  });
  await startGuardMeSession(ctx, { homeDir });

  await handleGuardMeCommand("", ctx);
  const trust = new ProjectTrustStore(join(homeDir, ".pi", "agent"));

  assert.equal(trust.get(cwd), true);
  assert.ok(reopenedLines.some((line) => line.includes("Pi project trust") && line.includes("ON")));
  assert.match(notifications.at(-1)?.[0] ?? "", /Pi project trust saved as ON/);
  stopGuardMeSession(ctx);
});

test("/guardme setup cancellation writes nothing", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "guardme-command-setup-cancel-"));
  const paths = resolvePolicyConfigPaths(cwd);
  const { ctx, notifications } = commandContext(cwd, { select: async () => undefined });

  await handleGuardMeCommand("setup", ctx);

  assert.match(notifications.at(-1)?.[0] ?? "", /cancelled/);
  await assert.rejects(access(paths.localPolicyPath));
});
