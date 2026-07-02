import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { handleGuardMeCommand, renderHelp } from "../../../src/commands/guardme-command.ts";
import { loadGuardMeConfig } from "../../../src/config/load-config.ts";
import { resolveRuntimeSettingsPath } from "../../../src/config/runtime-settings.ts";
import { COMMAND_RULE_SECTIONS, PATH_RULE_SECTIONS, createBuiltInDefaultPolicy } from "../../../src/config/schema.ts";
import { USER_DECISIONS } from "../../../src/policy/action.ts";
import { appendDecisionRecord, appendWarningRecord, loadWarningState, resolveStatePaths } from "../../../src/state/warnings.ts";
import {
  createRuleGroups,
  renderConfigPane,
  requestGuardMeConfigAction,
  requestPolicyWriteConfirmation,
  showPolicyWriteSuccess,
} from "../../../src/ui/config-tui.ts";
import { requestApprovalDecision } from "../../../src/ui/approval-modal.ts";
import { formatDiagnostics, formatWarningDecisionRecords } from "../../../src/ui/detail-formatters.ts";
import { requestSetupConfiguration, requestSetupMode, setupConfigForMode } from "../../../src/ui/setup-wizard.ts";
import { stripAnsiEscapes } from "../../../src/ui/text.ts";
import { createProjectFixture } from "./project-fixture.mjs";

export const DEFAULT_TUI_ARTIFACT_PATH = join(process.cwd(), "tmp", "e2e", "guardme-tui-panels.txt");

const CAPTURE_WIDTH = 120;
const PLAIN_THEME = { fg: (_color, text) => text, bold: (text) => text };
const ENTER = "\n";
const DOWN = "\u001B[B";
const ESC = "\u001B";

export async function captureGuardMeTuiPanels(options = {}) {
  const artifactPath = options.artifactPath ?? DEFAULT_TUI_ARTIFACT_PATH;
  const fixture = await createProjectFixture("tui");
  try {
    const notifications = [];
    await handleGuardMeCommand("setup", {
      cwd: fixture.projectDir,
      homeDir: fixture.homeDir,
      hasUI: true,
      mode: "rpc",
      isProjectTrusted: () => true,
      ui: {
        notify: (message, type) => notifications.push({ message, type }),
        select: async (_title, choices) => choices.find((choice) => choice.startsWith("Create project policy with sensible defaults")),
        confirm: async () => true,
        setStatus: () => {},
      },
    });

    await seedWarningAndDecisionRecords(fixture);
    const snapshot = await createSnapshot(fixture);
    const diagnosticSnapshot = withDiagnosticFixture(snapshot);
    const defaults = createBuiltInDefaultPolicy();
    const setupConfig = setupConfigForMode("local-defaults", defaults);
    if (!setupConfig) {
      throw new Error("Unable to build local defaults setup configuration for TUI capture.");
    }
    const setupPlan = createCapturePlan(fixture, setupConfig);

    const sections = [];
    const addSection = (title, body) => {
      sections.push([title, normalizeSectionBody(body)]);
    };

    addSection("Command - Help", renderHelp());
    addSection("Setup - Select Local Defaults", await captureSetupModeScreen());
    addSection("Setup - Custom Defaults Confirm", await captureCustomDefaultsConfirm(defaults));
    addSection("Setup - Confirm Write", await capturePolicyWriteConfirmation(setupConfig, setupPlan));
    addSection("Setup - Complete Notification", notifications.map((notification) => notification.message).join("\n"));
    addSection("Setup - Success Screen", await capturePolicyWriteSuccess(snapshot, setupPlan));
    addSection("Setup - Custom Rule Section", await captureCustomRuleSection(defaults));
    addSection("Setup - Custom Add Another Confirm", await captureCustomAddAnotherConfirm(defaults));

    for (const pane of ["General", "Policies", "Rules", "Setup"]) {
      addSection(pane.toUpperCase(), pane === "General" ? await captureInitialConfigScreen(snapshot, defaults) : renderConfigPane(snapshot, pane, CAPTURE_WIDTH));
    }

    addSection("GENERAL - GuardMe Off", renderConfigPane({ ...snapshot, guardMe: "off" }, "General", CAPTURE_WIDTH));
    addSection("GENERAL - Project Untrusted", renderConfigPane({ ...snapshot, projectTrusted: false }, "General", CAPTURE_WIDTH, 2));
    addSection("Search - Results", await captureSearchScreen(snapshot, defaults));
    addSection("Warning Detail Screen", await captureWarningDetailScreen(diagnosticSnapshot, defaults));
    addSection("Diagnostic Detail Screen", await captureDiagnosticDetailScreen(diagnosticSnapshot, defaults));
    addSection("Confirm - GuardMe Off", await captureGuardMeOffConfirmation(snapshot, defaults));
    addSection("Confirm - Pi project trust", await captureProjectTrustConfirmation(snapshot, defaults));
    addSection("Approval - Decision Modal", await captureApprovalModal(snapshot));
    addSection("Warning and Decision Details - Plain Text", formatWarningDecisionRecords(snapshot.warningRecords).join("\n"));
    addSection("Diagnostic Details - Plain Text", formatDiagnostics(diagnosticSnapshot.diagnostics).join("\n"));

    const indexedSections = [["Captured Screen Index", sections.map(([title], index) => `${index + 1}. ${title}`).join("\n")], ...sections];
    const artifact = sanitizeTuiText(
      ["# GuardMe TUI Capture", "", ...indexedSections.flatMap(([title, body]) => [`## ${title}`, "", body, ""])].join("\n"),
    );
    await mkdir(join(process.cwd(), "tmp", "e2e"), { recursive: true });
    await writeFile(artifactPath, artifact, "utf8");
    return { artifactPath, artifact, fixtureRoot: fixture.rootDir };
  } finally {
    await fixture.cleanup();
  }
}

export function sanitizeTuiText(text) {
  return removeTerminalControlCharacters(stripAnsiEscapes(text));
}

function removeTerminalControlCharacters(text) {
  let output = "";
  for (const character of text) {
    const codePoint = character.codePointAt(0);
    if (codePoint === undefined || shouldRemoveTerminalControlCode(codePoint)) {
      continue;
    }
    output += character;
  }
  return output;
}

function shouldRemoveTerminalControlCode(codePoint) {
  return (codePoint >= 0x00 && codePoint <= 0x08) || (codePoint >= 0x0b && codePoint <= 0x1f) || (codePoint >= 0x7f && codePoint <= 0x9f);
}

async function captureSetupModeScreen() {
  let rendered = [];
  await requestSetupMode({
    cwd: "/repo",
    hasUI: true,
    mode: "tui",
    ui: {
      custom: async (factory) => {
        let selected;
        const component = factory(
          { requestRender: () => {} },
          PLAIN_THEME,
          {},
          (value) => {
            selected = value;
          },
        );
        component.handleInput(DOWN);
        rendered = component.render(CAPTURE_WIDTH);
        component.handleInput(ESC);
        return selected;
      },
    },
  });
  return rendered.join("\n");
}

async function captureCustomDefaultsConfirm(defaults) {
  let rendered = [];
  let customCalls = 0;
  await requestSetupConfiguration(
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
            PLAIN_THEME,
            {},
            (value) => {
              selected = value;
            },
          );

          if (customCalls === 1) {
            component.handleInput(DOWN);
            component.handleInput(DOWN);
            component.handleInput(DOWN);
            component.handleInput(ENTER);
            return selected;
          }

          if (customCalls === 2) {
            rendered = component.render(CAPTURE_WIDTH);
            component.handleInput(ENTER);
            return selected;
          }

          component.handleInput("q");
          return selected;
        },
        confirm: async () => true,
        input: async () => undefined,
      },
    },
    defaults,
  );
  return rendered.join("\n");
}

async function capturePolicyWriteConfirmation(setupConfig, plan) {
  let rendered = [];
  await requestPolicyWriteConfirmation(
    {
      cwd: "/repo",
      hasUI: true,
      mode: "tui",
      ui: {
        custom: async (factory) => {
          let selected;
          const component = factory(
            { requestRender: () => {} },
            PLAIN_THEME,
            {},
            (value) => {
              selected = value;
            },
          );
          rendered = component.render(CAPTURE_WIDTH);
          component.handleInput("q");
          return selected;
        },
      },
    },
    setupConfig,
    plan,
  );
  return rendered.join("\n");
}

async function capturePolicyWriteSuccess(snapshot, plan) {
  let rendered = [];
  await showPolicyWriteSuccess(
    {
      cwd: snapshot.cwd,
      hasUI: true,
      mode: "tui",
      ui: {
        custom: async (factory) => {
          const component = factory(
            { requestRender: () => {} },
            PLAIN_THEME,
            {},
            () => {},
          );
          rendered = component.render(CAPTURE_WIDTH);
          component.handleInput("q");
        },
      },
    },
    snapshot,
    plan,
  );
  return rendered.join("\n");
}

async function captureCustomRuleSection(defaults) {
  let rendered = [];
  let customCalls = 0;
  await requestSetupConfiguration(
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
            PLAIN_THEME,
            {},
            (value) => {
              selected = value;
            },
          );
          if (customCalls === 1) {
            component.handleInput(DOWN);
            component.handleInput(DOWN);
            component.handleInput(DOWN);
            component.handleInput(ENTER);
            return selected;
          }

          rendered = component.render(CAPTURE_WIDTH);
          component.handleInput("q");
          return selected;
        },
        confirm: async () => false,
        input: async () => undefined,
      },
    },
    defaults,
  );
  return rendered.join("\n");
}

async function captureCustomAddAnotherConfirm(defaults) {
  let rendered = [];
  let customCalls = 0;
  await requestSetupConfiguration(
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
            PLAIN_THEME,
            {},
            (value) => {
              selected = value;
            },
          );

          if (customCalls === 1) {
            component.handleInput(DOWN);
            component.handleInput(DOWN);
            component.handleInput(DOWN);
            component.handleInput(ENTER);
            return selected;
          }

          const lines = component.render(CAPTURE_WIDTH);
          if (lines.some((line) => line.includes("CUSTOM POLICY START"))) {
            component.handleInput(DOWN);
            component.handleInput(ENTER);
            return selected;
          }
          if (lines.some((line) => line.includes("RULE SECTION"))) {
            component.handleInput(ENTER);
            return selected;
          }
          if (lines.some((line) => line.includes("PATTERN FOR ALLOWPATHS"))) {
            for (const char of "custom/**") {
              component.handleInput(char);
            }
            component.handleInput(ENTER);
            return selected;
          }
          if (lines.some((line) => line.includes("ACTIONS FOR ALLOWPATHS"))) {
            for (const char of "read,list") {
              component.handleInput(char);
            }
            component.handleInput(ENTER);
            return selected;
          }
          if (lines.some((line) => line.includes("RULE REASON"))) {
            for (const char of "Custom setup capture rule") {
              component.handleInput(char);
            }
            component.handleInput(ENTER);
            return selected;
          }
          if (lines.some((line) => line.includes("CUSTOM RULES"))) {
            rendered = lines;
            component.handleInput("q");
            return selected;
          }

          component.handleInput("q");
          return selected;
        },
        confirm: async () => false,
      },
    },
    defaults,
  );
  return rendered.join("\n");
}

async function captureSearchScreen(snapshot, defaults) {
  return captureConfigScreen(snapshot, defaults, async (component) => {
    component.handleInput("/");
    for (const char of "trust") {
      component.handleInput(char);
    }
    const rendered = component.render(CAPTURE_WIDTH);
    component.handleInput(ESC);
    component.handleInput("q");
    return rendered;
  });
}

async function captureInitialConfigScreen(snapshot, defaults) {
  return captureConfigScreen(snapshot, defaults, async (component) => {
    const rendered = component.render(CAPTURE_WIDTH);
    component.handleInput("q");
    return rendered;
  });
}

async function captureWarningDetailScreen(snapshot, defaults) {
  return captureConfigScreen(snapshot, defaults, async (component) => {
    component.handleInput(ENTER);
    component.handleInput(DOWN);
    component.handleInput(DOWN);
    component.handleInput(DOWN);
    component.handleInput(ENTER);
    const rendered = component.render(CAPTURE_WIDTH);
    component.handleInput(ESC);
    component.handleInput("q");
    return rendered;
  });
}

async function captureDiagnosticDetailScreen(snapshot, defaults) {
  return captureConfigScreen(snapshot, defaults, async (component) => {
    component.handleInput(ENTER);
    component.handleInput(DOWN);
    component.handleInput(DOWN);
    component.handleInput(DOWN);
    component.handleInput(DOWN);
    component.handleInput(ENTER);
    const rendered = component.render(CAPTURE_WIDTH);
    component.handleInput(ESC);
    component.handleInput("q");
    return rendered;
  });
}

async function captureGuardMeOffConfirmation(snapshot, defaults) {
  return captureConfigScreen(snapshot, defaults, async (component) => {
    component.handleInput(ENTER);
    component.handleInput(ENTER);
    const rendered = component.render(CAPTURE_WIDTH);
    component.handleInput("q");
    return rendered;
  });
}

async function captureProjectTrustConfirmation(snapshot, defaults) {
  return captureConfigScreen(snapshot, defaults, async (component) => {
    component.handleInput(ENTER);
    component.handleInput(DOWN);
    component.handleInput(DOWN);
    component.handleInput(ENTER);
    const rendered = component.render(CAPTURE_WIDTH);
    component.handleInput("q");
    return rendered;
  });
}

async function captureConfigScreen(snapshot, defaults, interaction) {
  let rendered = [];
  await requestGuardMeConfigAction(
    {
      cwd: snapshot.cwd,
      hasUI: true,
      mode: "tui",
      ui: {
        custom: async (factory) => {
          let selected;
          const component = factory(
            { requestRender: () => {} },
            PLAIN_THEME,
            {},
            (value) => {
              selected = value;
            },
          );
          rendered = await interaction(component);
          return selected;
        },
      },
    },
    snapshot,
    defaults,
    async () => ({ ok: false, reason: "TUI capture does not write policy files." }),
  );
  return rendered.join("\n");
}

async function captureApprovalModal(snapshot) {
  let rendered = [];
  const request = {
    toolName: "bash",
    action: "delete",
    cwd: snapshot.cwd,
    command: "rm -rf build",
    targets: [],
  };
  const decision = {
    outcome: "needs-user-decision",
    action: "delete",
    risk: "dangerous",
    reason: "Recursive force deletion requires approval.",
    matchedRules: [
      {
        category: "dangerousCommands",
        source: { kind: "builtin", label: "GuardMe defaults" },
        pattern: "rm -rf *",
        actions: ["delete"],
        reason: "Recursive force deletion",
      },
    ],
    fingerprint: "sha256:e2e-approval",
    prompt: true,
    choices: USER_DECISIONS,
    recommendation: "Prefer a narrower command.",
  };

  await requestApprovalDecision(
    {
      cwd: snapshot.cwd,
      hasUI: true,
      mode: "tui",
      ui: {
        custom: async (factory) => {
          let selected;
          const component = factory(
            { requestRender: () => {} },
            PLAIN_THEME,
            {},
            (value) => {
              selected = value;
            },
          );
          rendered = component.render(CAPTURE_WIDTH);
          component.handleInput(ESC);
          return selected;
        },
      },
    },
    request,
    decision,
  );
  return rendered.join("\n");
}

async function seedWarningAndDecisionRecords(fixture) {
  await appendWarningRecord(fixture.localStatePath, {
    fingerprint: "sha256:e2e-warning",
    scope: "project",
    cwd: fixture.projectDir,
    toolName: "bash",
    action: "shell",
    risk: "medium",
    target: "node -e \"console.log('guardme generic')\"",
    reasonCode: "policy-missing-command",
  });
  await appendDecisionRecord(fixture.localStatePath, {
    fingerprint: "sha256:e2e-decision",
    scope: "project",
    cwd: fixture.projectDir,
    decision: "deny-once",
    persistedTo: "none",
    reason: "Seeded deterministic e2e decision for TUI detail capture.",
  });
}

async function createSnapshot(fixture) {
  const loadedConfig = await loadGuardMeConfig({ cwd: fixture.projectDir, homeDir: fixture.homeDir, loadLocalPolicy: true });
  const warnings = await loadWarningState({ cwd: fixture.projectDir, homeDir: fixture.homeDir, loadLocalState: true });
  const settingsPaths = resolveRuntimeSettingsPath(fixture.projectDir);
  const statePaths = resolveStatePaths(fixture.projectDir, fixture.homeDir);
  const localPolicyFile = loadedConfig.files.find((file) => file.sourceKind === "local" && file.found);
  const localPolicyRules = localPolicyFile ? countPolicyRules(localPolicyFile.config) : 0;
  const diagnostics = [...loadedConfig.diagnostics, ...warnings.diagnostics];

  return {
    cwd: fixture.projectDir,
    projectTrusted: true,
    guardMe: diagnostics.some((diagnostic) => diagnostic.severity === "error") ? "degraded" : "active",
    insecureEdits: false,
    policyRules: countPolicyRules(loadedConfig.config),
    warnedFingerprints: warnings.warnedFingerprints.size,
    warningRecords: warnings.records,
    diagnostics,
    settingsPath: settingsPaths.displaySettingsPath,
    globalPolicyPath: loadedConfig.paths.displayGlobalPolicyPath,
    localPolicyPath: loadedConfig.paths.displayLocalPolicyPath,
    globalStatePath: statePaths.displayGlobalStatePath,
    localStatePath: statePaths.displayLocalStatePath,
    ruleGroups: createRuleGroups(loadedConfig.config, localPolicyRules),
  };
}

function createCapturePlan(fixture, setupConfig) {
  return {
    scope: setupConfig.scope,
    targetPath: fixture.localPolicyPath,
    displayPath: ".pi/agent/guardme.yaml",
    policyKind: setupConfig.summary.includes("custom") ? "custom" : "default",
    existing: false,
    rules: countPolicyRules(setupConfig.config),
  };
}

function withDiagnosticFixture(snapshot) {
  const diagnostic = {
    severity: "error",
    code: "config.invalidRoot",
    message: "GuardMe policy must be a YAML object.",
    source: { kind: "local", path: snapshot.localPolicyPath },
    path: snapshot.localPolicyPath,
    ruleIndex: 12,
  };
  return {
    ...snapshot,
    guardMe: "degraded",
    diagnostics: [diagnostic],
  };
}

function normalizeSectionBody(body) {
  if (Array.isArray(body)) {
    return body.join("\n");
  }
  const text = String(body ?? "");
  return text.trim().length > 0 ? text : "<empty>";
}

function countPolicyRules(config) {
  return [...PATH_RULE_SECTIONS, ...COMMAND_RULE_SECTIONS].reduce((count, section) => count + (config[section]?.length ?? 0), 0);
}
