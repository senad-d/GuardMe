import { ProjectTrustStore, type ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { access } from "node:fs/promises";
import { homedir } from "node:os";
import { join, resolve } from "node:path";

import { GUARDME_COMMAND_NAME } from "../constants.ts";
import { resolvePolicyConfigPaths } from "../config/load-config.ts";
import { resolveRuntimeSettingsPath, writeGuardMeRuntimeSettings } from "../config/runtime-settings.ts";
import type { MergedGuardMePolicyConfig } from "../config/merge-policy.ts";
import { appendPolicyConfigRules, validatePolicyWriteTarget, writePolicyConfigFile, type AppendPolicyConfigRule } from "../config/write-policy.ts";
import { COMMAND_RULE_SECTIONS, PATH_RULE_SECTIONS, type GuardMePolicyConfig, createBuiltInDefaultPolicy } from "../config/schema.ts";
import { redactSensitiveText } from "../policy/redact.ts";
import { resolveStatePaths } from "../state/warnings.ts";
import { formatDiagnostics } from "../ui/detail-formatters.ts";
import { stripAnsiEscapes } from "../ui/text.ts";
import { getGuardMeSessionState } from "../events/session-store.ts";
import { startGuardMeSession } from "../events/register-lifecycle.ts";
import {
  collectCustomPolicy,
  collectCustomRuleAdditions,
  countSetupRules,
  createAppendRulesSetupConfig,
  requestSetupMode,
  setupConfigForMode,
  setupScopeLabel,
  type SetupMode,
  type SetupWizardConfig,
  type SetupWizardContext,
} from "../ui/setup-wizard.ts";
import {
  createRuleGroups,
  renderConfigPane,
  renderGuardMeHelp,
  requestGuardMeConfigAction,
  requestPolicyWriteConfirmationAction,
  showPolicyWriteSuccess,
  type ConfigAction,
  type ConfigSnapshot,
  type ConfigTuiContext,
  type PolicyWriteConfirmationAction,
  type PolicyWriteSuccessOptions,
  type PolicyWriteSuccessResult,
  type SetupWritePlan,
  type SetupWritePlanResult,
} from "../ui/config-tui.ts";

interface GuardMeAutocompleteItem {
  readonly value: string;
  readonly label: string;
  readonly description?: string;
}

const GUARDME_SUBCOMMANDS: readonly GuardMeAutocompleteItem[] = [
  { value: "help", label: "help", description: "Show /guardme command usage" },
];

type GuardMeNotificationType = "info" | "warning" | "error";
type SetupPolicyMode = Extract<SetupMode, "global-custom" | "local-custom">;
type PolicyWriteAction = "create" | "overwrite" | "update";
type ConfigActionFlowResult = ConfigAction | "continue" | undefined;

interface SetupPolicyFlowResult {
  readonly written: boolean;
  readonly next?: PolicyWriteSuccessResult;
  readonly back?: boolean;
}

export interface GuardMeCommandContext {
  readonly cwd: string;
  readonly hasUI: boolean;
  readonly mode?: string;
  readonly homeDir?: string;
  readonly isProjectTrusted?: () => boolean;
  readonly ui: {
    readonly notify?: (message: string, type?: GuardMeNotificationType) => void;
    readonly confirm?: (title: string, message: string) => Promise<boolean>;
    readonly select?: (title: string, options: string[]) => Promise<string | undefined>;
    readonly input?: (title: string, placeholder?: string) => Promise<string | undefined>;
    readonly custom?: unknown;
    readonly setStatus?: (key: string, text: string | undefined) => void;
  };
}

type GuardMeStatusContext = Pick<GuardMeCommandContext, "cwd" | "homeDir" | "isProjectTrusted">;

/** Register the /guardme command. */
export function registerGuardMeCommand(pi: ExtensionAPI): void {
  pi.registerCommand(GUARDME_COMMAND_NAME, {
    description: "Open GuardMe configuration, general settings, policies, rules, and setup",
    getArgumentCompletions: getGuardMeArgumentCompletions,
    handler: async (args, ctx) => {
      await handleGuardMeCommand(args, ctx);
    },
  });
}

export function getGuardMeArgumentCompletions(prefix: string): GuardMeAutocompleteItem[] | null {
  const normalizedPrefix = prefix.trimStart().toLowerCase();
  const filtered = GUARDME_SUBCOMMANDS.filter((command) => command.value.startsWith(normalizedPrefix));
  return filtered.length > 0 ? [...filtered] : null;
}

export async function handleGuardMeCommand(args: string, ctx: GuardMeCommandContext): Promise<void> {
  const subcommand = args.trim().split(/\s+/).find(Boolean) ?? "conf";
  switch (subcommand.toLowerCase()) {
    case "conf":
    case "config":
    case "":
      await runConfig(ctx);
      return;
    case "help":
    case "--help":
    case "-h":
      notify(ctx, renderHelp(), "info");
      return;
    case "paths":
    case "policies":
      notify(ctx, renderPaths(ctx), "info");
      return;
    case "diagnostics":
      notify(ctx, renderDiagnostics(ctx), "info");
      return;
    case "status":
      notify(ctx, renderStatus(ctx), "info");
      return;
    case "setup":
      await runSetup(ctx);
      return;
    default:
      notify(ctx, `Unknown GuardMe command '${subcommand}'.\n\n${renderHelp()}`, "warning");
  }
}

export function renderStatus(ctx: GuardMeStatusContext): string {
  const snapshot = createConfigSnapshot(ctx);
  return `${renderConfigPane(snapshot, "General")}\n\n${renderLegacyStatusSummary(snapshot)}`;
}

export function renderDiagnostics(ctx: GuardMeStatusContext): string {
  return formatDiagnostics(createConfigSnapshot(ctx).diagnostics).join("\n");
}

export function renderHelp(): string {
  return `${renderGuardMeHelp()}\n\nGuardMe usage:\n- /guardme\n- /guardme help`;
}

export function renderPaths(ctx: GuardMeStatusContext): string {
  const snapshot = createConfigSnapshot(ctx);
  return `${renderConfigPane(snapshot, "Policies")}\n\n${renderLegacyPathsSummary(snapshot)}`;
}

export async function runSetup(ctx: GuardMeCommandContext): Promise<void> {
  if (!ctx.hasUI) {
    notify(ctx, "GuardMe setup requires an interactive UI. No files were written.", "warning");
    return;
  }

  const sensibleDefaults = createBuiltInDefaultPolicy();
  for (let iteration = 0; iteration < 8; iteration += 1) {
    const mode = await requestSetupMode(toSetupWizardContext(ctx));
    if (!mode || mode === "cancel") {
      notify(ctx, "GuardMe setup cancelled. No files were written.", "info");
      return;
    }

    if (mode === "global-custom" || mode === "local-custom") {
      await runCustomSetupFromConfig(ctx, mode, sensibleDefaults);
      return;
    }

    if (mode === "global-add-rule" || mode === "local-add-rule") {
      await runAppendRulesFromConfig(ctx, mode.startsWith("global") ? "global" : "local");
      return;
    }

    const setupConfig = setupConfigForMode(mode, sensibleDefaults);
    if (!setupConfig) {
      notify(ctx, "GuardMe setup could not prepare that option. No files were written.", "warning");
      return;
    }

    const result = await confirmAndWriteSetupPolicy(ctx, setupConfig);
    if (result.back) {
      continue;
    }
    return;
  }

  notify(ctx, "GuardMe setup stopped after several back-navigation attempts. No files were written.", "info");
}

async function runConfig(ctx: GuardMeCommandContext): Promise<void> {
  const sensibleDefaults = createBuiltInDefaultPolicy();
  if (!ctx.hasUI) {
    notify(ctx, renderConfigPane(createConfigSnapshot(ctx), "General"), "warning");
    return;
  }

  if (ctx.mode !== "tui" || typeof ctx.ui.custom !== "function") {
    notify(ctx, renderConfigPane(createConfigSnapshot(ctx), "General"), "info");
    return;
  }

  let pendingAction: ConfigAction | undefined;
  const successOptions = successOptionsForConfig(ctx, sensibleDefaults);

  for (let iteration = 0; iteration < 8; iteration += 1) {
    const action = pendingAction ?? await requestGuardMeConfigAction(
      toConfigTuiContext(ctx),
      createConfigSnapshot(ctx),
      sensibleDefaults,
      (setupConfig) => createSetupWritePlan(ctx, setupConfig),
    );
    pendingAction = undefined;

    if (!action || action.kind === "closed") {
      return;
    }

    const next = await handleConfigAction(ctx, action, sensibleDefaults, successOptions);
    if (next === "continue") {
      continue;
    }
    if (next) {
      pendingAction = next;
      continue;
    }
    return;
  }

  notify(ctx, "GuardMe config stopped after several consecutive setting changes. Reopen /guardme to continue.", "info");
}

function successOptionsForConfig(ctx: GuardMeCommandContext, sensibleDefaults: GuardMePolicyConfig): PolicyWriteSuccessOptions {
  return {
    sensibleDefaults,
    createPlan: (setupConfig) => createSetupWritePlan(ctx, setupConfig),
  };
}

function nextActionAfterSetupFlow(result: SetupPolicyFlowResult): ConfigActionFlowResult {
  if (result.back) {
    return "continue";
  }
  if (!result.written || !result.next || result.next.kind === "closed") {
    return undefined;
  }
  if (result.next.kind === "continue") {
    return "continue";
  }
  return result.next;
}

async function handleConfigAction(
  ctx: GuardMeCommandContext,
  action: ConfigAction,
  sensibleDefaults: GuardMePolicyConfig,
  successOptions: PolicyWriteSuccessOptions,
): Promise<ConfigActionFlowResult> {
  if (action.kind === "closed") {
    return undefined;
  }
  if (action.kind === "custom") {
    return nextActionAfterSetupFlow(await runCustomSetupFromConfig(ctx, action.mode, sensibleDefaults, successOptions));
  }
  if (action.kind === "append-rules") {
    return nextActionAfterSetupFlow(await runAppendRulesFromConfig(ctx, action.scope, successOptions));
  }
  if (action.kind === "set-guardme-enabled") {
    return (await setGuardMeEnabled(ctx, action.enabled)) ? "continue" : undefined;
  }
  if (action.kind === "set-insecure-edits") {
    return (await setInsecureEdits(ctx, action.enabled)) ? "continue" : undefined;
  }
  if (action.kind === "set-project-trusted") {
    return (await setProjectTrusted(ctx, action.trusted)) ? "continue" : undefined;
  }
  return handleConfigPolicyWriteAction(ctx, action, successOptions);
}

async function handleConfigPolicyWriteAction(
  ctx: GuardMeCommandContext,
  action: Extract<ConfigAction, { readonly kind: "write" }>,
  successOptions: PolicyWriteSuccessOptions,
): Promise<ConfigActionFlowResult> {
  const written = await writeConfirmedSetupPolicy(ctx, action.setupConfig, action.plan);
  if (!written) {
    return undefined;
  }
  const snapshot = createConfigSnapshot(ctx);
  const next = await showPolicyWriteSuccess(toConfigTuiContext(ctx), snapshot, action.plan, successOptions);
  if (next.kind === "continue") {
    return "continue";
  }
  return next.kind === "closed" ? undefined : next;
}

async function runCustomSetupFromConfig(
  ctx: GuardMeCommandContext,
  mode: SetupPolicyMode,
  sensibleDefaults: GuardMePolicyConfig,
  successOptions?: PolicyWriteSuccessOptions,
): Promise<SetupPolicyFlowResult> {
  const scope = mode.startsWith("global") ? "global" : "local";
  let config: GuardMePolicyConfig | undefined;

  for (let iteration = 0; iteration < 8; iteration += 1) {
    config = await collectCustomPolicy(toSetupWizardContext(ctx), sensibleDefaults, scope, config);
    if (!config) {
      notify(ctx, "GuardMe setup cancelled. No files were written.", "info");
      return { written: false };
    }

    const setupConfig: SetupWizardConfig = {
      scope,
      config,
      summary: `custom ${setupScopeLabel(scope)} (${countSetupRules(config)} rule${countSetupRules(config) === 1 ? "" : "s"})`,
      writeMode: "replace",
    };
    const result = await confirmAndWriteSetupPolicy(ctx, setupConfig, successOptions);
    if (result.back) {
      continue;
    }
    return result;
  }

  notify(ctx, "GuardMe setup stopped after several back-navigation attempts. No files were written.", "info");
  return { written: false };
}

async function runAppendRulesFromConfig(
  ctx: GuardMeCommandContext,
  scope: SetupWizardConfig["scope"],
  successOptions?: PolicyWriteSuccessOptions,
): Promise<SetupPolicyFlowResult> {
  let config: GuardMePolicyConfig | undefined;

  for (let iteration = 0; iteration < 8; iteration += 1) {
    config = await collectCustomRuleAdditions(toSetupWizardContext(ctx), scope, config);
    if (!config || countSetupRules(config) === 0) {
      notify(ctx, "GuardMe custom rule setup cancelled. No files were written.", "info");
      return { written: false };
    }

    const result = await confirmAndWriteSetupPolicy(ctx, createAppendRulesSetupConfig(scope, config), successOptions);
    if (result.back) {
      continue;
    }
    return result;
  }

  notify(ctx, "GuardMe setup stopped after several back-navigation attempts. No files were written.", "info");
  return { written: false };
}

async function confirmAndWriteSetupPolicy(
  ctx: GuardMeCommandContext,
  setupConfig: SetupWizardConfig,
  successOptions: PolicyWriteSuccessOptions = {},
): Promise<SetupPolicyFlowResult> {
  const planResult = await createSetupWritePlan(ctx, setupConfig);
  if (!planResult.ok) {
    notify(ctx, planResult.reason, "warning");
    return { written: false };
  }

  const confirmation = await confirmPolicyWrite(ctx, setupConfig, planResult.plan);
  if (confirmation === "back") {
    return { written: false, back: true };
  }
  if (confirmation !== "write") {
    notify(ctx, "GuardMe setup cancelled. No files were written.", "info");
    return { written: false };
  }

  const written = await writeConfirmedSetupPolicy(ctx, setupConfig, planResult.plan);
  const shouldCaptureNext = Boolean(successOptions.sensibleDefaults && successOptions.createPlan);
  if (written && ctx.mode === "tui" && typeof ctx.ui.custom === "function") {
    const next = await showPolicyWriteSuccess(toConfigTuiContext(ctx), createConfigSnapshot(ctx), planResult.plan, successOptions);
    return shouldCaptureNext ? { written, next } : { written };
  }
  return { written };
}

async function confirmPolicyWrite(
  ctx: GuardMeCommandContext,
  setupConfig: SetupWizardConfig,
  plan: SetupWritePlan,
): Promise<PolicyWriteConfirmationAction> {
  if (ctx.mode === "tui" && typeof ctx.ui.custom === "function") {
    return requestPolicyWriteConfirmationAction(toConfigTuiContext(ctx), setupConfig, plan);
  }

  const action = policyWriteAction(setupConfig, plan);
  const message = policyWriteConfirmationMessage(setupConfig, plan);

  if (ctx.ui.confirm) {
    return (await ctx.ui.confirm(`${confirmActionLabel(action)} GuardMe policy?`, message)) ? "write" : "cancel";
  }

  if (ctx.ui.select) {
    const writeLabel = `Write policy — ${message}`;
    const compatibilityLabel = `${setupLabelForConfig(setupConfig)} — Confirm write policy`;
    const selected = await ctx.ui.select("GuardMe confirm write", [writeLabel, compatibilityLabel, "Go back", "Cancel"]);
    if (selected === writeLabel || selected === compatibilityLabel) {
      return "write";
    }
    if (selected === "Go back") {
      return "back";
    }
    return "cancel";
  }

  return "cancel";
}

function policyWriteAction(setupConfig: SetupWizardConfig, plan: SetupWritePlan): PolicyWriteAction {
  if (setupConfig.writeMode === "append") {
    return plan.existing ? "update" : "create";
  }
  if (plan.existing) {
    return "overwrite";
  }
  return "create";
}

function policyWriteConfirmationMessage(setupConfig: SetupWizardConfig, plan: SetupWritePlan): string {
  const scopeLabel = setupScopeLabel(plan.scope);
  if (setupConfig.writeMode === "append") {
    return plan.existing
      ? `This will append ${setupConfig.summary} to the existing ${scopeLabel} file at ${plan.displayPath}.`
      : `This will create ${scopeLabel} at ${plan.displayPath} with ${setupConfig.summary}.`;
  }
  if (plan.existing) {
    return `This will overwrite the existing ${scopeLabel} file at ${plan.displayPath} with ${setupConfig.summary}.`;
  }
  return `This will create ${scopeLabel} at ${plan.displayPath} with ${setupConfig.summary}.`;
}

function setupPolicyKind(setupConfig: SetupWizardConfig): SetupWritePlan["policyKind"] {
  if (setupConfig.writeMode === "append") {
    return "append";
  }
  if (setupConfig.summary.includes("custom")) {
    return "custom";
  }
  return "default";
}

async function createSetupWritePlan(ctx: GuardMeCommandContext, setupConfig: SetupWizardConfig): Promise<SetupWritePlanResult> {
  const paths = resolvePolicyConfigPaths(ctx.cwd, ctx.homeDir);
  const targetPath = setupConfig.scope === "global" ? paths.globalPolicyPath : paths.localPolicyPath;
  const displayPath = setupConfig.scope === "global" ? paths.displayGlobalPolicyPath : paths.displayLocalPolicyPath;

  try {
    const safety = await validatePolicyWriteTarget({ cwd: ctx.cwd, homeDir: ctx.homeDir, path: targetPath, scope: setupConfig.scope });
    if (!safety.safe) {
      return {
        ok: false,
        reason: safety.reason ?? `GuardMe refused to write ${displayPath} because the target is unsafe.`,
      };
    }

    return {
      ok: true,
      plan: {
        scope: setupConfig.scope,
        targetPath,
        displayPath,
        policyKind: setupPolicyKind(setupConfig),
        existing: await fileExists(targetPath),
        rules: countPolicyRules(setupConfig.config),
      },
    };
  } catch (error) {
    return {
      ok: false,
      reason: `GuardMe could not inspect ${displayPath}: ${formatCommandError(error)}`,
    };
  }
}

async function writeConfirmedSetupPolicy(
  ctx: GuardMeCommandContext,
  setupConfig: SetupWizardConfig,
  plan: SetupWritePlan,
): Promise<boolean> {
  const safety = await validatePolicyWriteTarget({ cwd: ctx.cwd, homeDir: ctx.homeDir, path: plan.targetPath, scope: setupConfig.scope });
  if (!safety.safe) {
    notify(ctx, safety.reason ?? `GuardMe refused to write ${plan.displayPath} because the target is unsafe.`, "warning");
    return false;
  }

  try {
    if (setupConfig.writeMode === "append") {
      const result = await appendPolicyConfigRules({
        cwd: ctx.cwd,
        homeDir: ctx.homeDir,
        policyPath: plan.targetPath,
        scope: setupConfig.scope,
        rules: policyConfigRules(setupConfig.config),
      });
      if (!result.saved) {
        notify(ctx, result.reason ?? `GuardMe did not update ${plan.displayPath}.`, "warning");
        return false;
      }
    } else {
      await writePolicyConfigFile(plan.targetPath, setupConfig.config, { cwd: ctx.cwd, homeDir: ctx.homeDir, scope: setupConfig.scope });
    }
    await reloadSessionState(ctx);
  } catch (error) {
    notify(ctx, `GuardMe could not write ${plan.displayPath}: ${formatCommandError(error)}`, "error");
    return false;
  }

  const action = plan.existing ? "Updated" : "Created";
  const trustGuidance = setupConfig.scope === "local" && currentProjectTrusted(ctx) === false
    ? " Project is not trusted, so this project policy will load after project trust is enabled."
    : "";
  notify(ctx, `${action} GuardMe ${setupScopeLabel(setupConfig.scope)} at ${plan.displayPath} (${setupConfig.summary}).${trustGuidance}`, "info");
  return true;
}

async function setGuardMeEnabled(ctx: GuardMeCommandContext, enabled: boolean): Promise<boolean> {
  const projectTrusted = currentProjectTrusted(ctx) ?? ctx.isProjectTrusted?.() ?? true;
  try {
    await writeGuardMeRuntimeSettings({ cwd: ctx.cwd, enabled });
    await reloadSessionState(ctx);
  } catch (error) {
    notify(ctx, `GuardMe could not write .pi/agent/guardme-settings.json: ${formatCommandError(error)}`, "error");
    return false;
  }

  if (projectTrusted) {
    notify(ctx, enabled ? "GuardMe is active for this project." : "GuardMe is off for this project.", "info");
    return true;
  }

  notify(
    ctx,
    `GuardMe ${enabled ? "on" : "off"} setting saved in .pi/agent/guardme-settings.json. Project is not trusted, so this setting will apply after project trust is enabled.`,
    "info",
  );
  return true;
}

async function setInsecureEdits(ctx: GuardMeCommandContext, enabled: boolean): Promise<boolean> {
  const projectTrusted = currentProjectTrusted(ctx) ?? ctx.isProjectTrusted?.() ?? true;
  try {
    await writeGuardMeRuntimeSettings({ cwd: ctx.cwd, insecureEdits: enabled });
    await reloadSessionState(ctx);
  } catch (error) {
    notify(ctx, `GuardMe could not write .pi/agent/guardme-settings.json: ${formatCommandError(error)}`, "error");
    return false;
  }

  const stateMessage = enabled
    ? "Insecure edits are ON: write/edit content scanning is skipped, but path protections still apply."
    : "Insecure edits are OFF: write/edit content scanning is guarded again.";
  if (projectTrusted) {
    notify(ctx, stateMessage, "info");
    return true;
  }

  notify(
    ctx,
    `${stateMessage} Project is not trusted, so this setting will apply after project trust is enabled.`,
    "info",
  );
  return true;
}

async function setProjectTrusted(ctx: GuardMeCommandContext, trusted: boolean): Promise<boolean> {
  try {
    const store = new ProjectTrustStore(join(resolve(ctx.homeDir ?? homedir()), ".pi", "agent"));
    store.set(ctx.cwd, trusted);
    await reloadSessionState(ctx, trusted);
  } catch (error) {
    notify(ctx, `GuardMe could not update Pi project trust: ${formatCommandError(error)}`, "error");
    return false;
  }

  notify(
    ctx,
    `Pi project trust saved as ${trusted ? "ON" : "OFF"}. Project-local Pi resources may require reload/restart to fully apply.`,
    "info",
  );
  return true;
}

async function reloadSessionState(ctx: GuardMeCommandContext, projectTrustedOverride?: boolean): Promise<void> {
  if (!ctx.ui.setStatus) {
    return;
  }
  const sessionOptions = projectTrustedOverride === undefined
    ? { homeDir: ctx.homeDir }
    : { homeDir: ctx.homeDir, projectTrusted: projectTrustedOverride };

  await startGuardMeSession(
    {
      cwd: ctx.cwd,
      hasUI: ctx.hasUI,
      isProjectTrusted: () => projectTrustedOverride ?? ctx.isProjectTrusted?.() ?? true,
      ui: {
        setStatus: ctx.ui.setStatus,
        notify: ctx.ui.notify,
      },
    },
    sessionOptions,
  );
}

function snapshotGuardMeStatus(state: NonNullable<ReturnType<typeof getGuardMeSessionState>> | undefined): ConfigSnapshot["guardMe"] {
  if (!state) {
    return "inactive";
  }
  if (!state.enabled) {
    return "off";
  }
  if (state.degraded) {
    return "degraded";
  }
  return "active";
}

function createConfigSnapshot(ctx: GuardMeStatusContext): ConfigSnapshot {
  const currentState = getGuardMeSessionState();
  const state = currentState && resolve(currentState.cwd) === resolve(ctx.cwd) ? currentState : undefined;
  const trusted = state?.projectTrusted ?? ctx.isProjectTrusted?.() ?? false;
  const configPaths = resolvePolicyConfigPaths(ctx.cwd, ctx.homeDir);
  const settingsPaths = resolveRuntimeSettingsPath(ctx.cwd);
  const statePaths = resolveStatePaths(ctx.cwd, ctx.homeDir);
  const config = state?.config.config ?? createBuiltInDefaultPolicy();
  const localPolicyFile = state?.config.files.find((file) => file.sourceKind === "local" && file.found);
  const localPolicyRules = localPolicyFile ? countPolicyRules(localPolicyFile.config) : 0;

  return {
    cwd: ctx.cwd,
    projectTrusted: trusted,
    guardMe: snapshotGuardMeStatus(state),
    insecureEdits: state?.insecureEdits ?? false,
    policyRules: countPolicyRules(config),
    warnedFingerprints: state?.warnings.warnedFingerprints.size ?? 0,
    warningRecords: state?.warnings.records ?? [],
    diagnostics: state?.diagnostics ?? [],
    settingsPath: settingsPaths.displaySettingsPath,
    globalPolicyPath: configPaths.displayGlobalPolicyPath,
    localPolicyPath: configPaths.displayLocalPolicyPath,
    globalStatePath: statePaths.displayGlobalStatePath,
    localStatePath: statePaths.displayLocalStatePath,
    ruleGroups: createRuleGroups(config, localPolicyRules),
  };
}

function currentProjectTrusted(ctx: Pick<GuardMeCommandContext, "cwd" | "isProjectTrusted">): boolean | undefined {
  const currentState = getGuardMeSessionState();
  if (currentState && resolve(currentState.cwd) === resolve(ctx.cwd)) {
    return currentState.projectTrusted;
  }
  return ctx.isProjectTrusted?.();
}

function renderLegacyStatusSummary(snapshot: ConfigSnapshot): string {
  return [
    `GuardMe: ${snapshot.guardMe}`,
    `Insecure edits: ${snapshot.insecureEdits ? "on" : "off"}`,
    `Project: ${snapshot.cwd}`,
    `Pi project trust: ${snapshot.projectTrusted ? "yes" : "no"}`,
    `Policy rules: ${snapshot.policyRules}`,
    `Warned fingerprints: ${snapshot.warnedFingerprints}`,
    `Settings: ${snapshot.settingsPath}`,
    renderLegacyPathsSummary(snapshot),
    renderLegacyDiagnosticsSummary(snapshot),
  ].join("\n");
}

function renderLegacyDiagnosticsSummary(snapshot: ConfigSnapshot): string {
  if (snapshot.diagnostics.length === 0) {
    return "Diagnostics: none";
  }
  const visibleDiagnostics = snapshot.diagnostics.slice(0, 8).map((diagnostic) => `- ${diagnostic.severity} ${diagnostic.code}: ${diagnostic.message}`);
  const hiddenDiagnosticCount = snapshot.diagnostics.length - visibleDiagnostics.length;
  const overflow = hiddenDiagnosticCount > 0 ? [`- … ${hiddenDiagnosticCount} more`] : [];
  return [`Diagnostics: ${snapshot.diagnostics.length}`, ...visibleDiagnostics, ...overflow].join("\n");
}

function renderLegacyPathsSummary(snapshot: ConfigSnapshot): string {
  return [
    "Policy paths:",
    `- global: ${snapshot.globalPolicyPath}`,
    `- local: ${snapshot.localPolicyPath}`,
    "State paths:",
    `- global: ${snapshot.globalStatePath}`,
    `- local: ${snapshot.localStatePath}`,
  ].join("\n");
}

function confirmActionLabel(action: "create" | "overwrite" | "update"): string {
  switch (action) {
    case "overwrite":
      return "Overwrite";
    case "update":
      return "Update";
    case "create":
    default:
      return "Create";
  }
}

function setupLabelForConfig(setupConfig: SetupWizardConfig): string {
  if (setupConfig.writeMode === "append") {
    return setupConfig.scope === "global" ? "Add custom rule globally" : "Add custom rule locally";
  }
  if (setupConfig.summary.includes("custom")) {
    return setupConfig.scope === "global" ? "Build custom global policy" : "Build custom project policy";
  }
  return setupConfig.scope === "global"
    ? "Create global policy with sensible defaults"
    : "Create project policy with sensible defaults";
}

function toConfigTuiContext(ctx: GuardMeCommandContext) {
  const custom = typeof ctx.ui.custom === "function"
    ? (ctx.ui.custom as ConfigTuiContext["ui"]["custom"])
    : undefined;
  return {
    cwd: ctx.cwd,
    hasUI: ctx.hasUI,
    mode: ctx.mode,
    ui: {
      ...(custom ? { custom } : {}),
    },
  };
}

function toSetupWizardContext(ctx: GuardMeCommandContext): SetupWizardContext {
  return {
    cwd: ctx.cwd,
    hasUI: ctx.hasUI,
    mode: ctx.mode,
    ui: ctx.ui,
  } as SetupWizardContext;
}

function notify(ctx: GuardMeCommandContext, message: string, type: GuardMeNotificationType): void {
  ctx.ui.notify?.(sanitizeNotificationText(redactSensitiveText(message)), type);
}

function sanitizeNotificationText(message: string): string {
  return stripAnsiEscapes(message)
    .replaceAll(/\r\n?/g, "\n")
    .replaceAll(/[\u0000-\u0009\u000B-\u001F\u007F-\u009F]/g, " ");
}

function policyConfigRules(config: GuardMePolicyConfig): AppendPolicyConfigRule[] {
  return [...PATH_RULE_SECTIONS, ...COMMAND_RULE_SECTIONS].flatMap((section) =>
    config[section].map((rule) => ({ section, rule })),
  );
}

function countPolicyRules(config: MergedGuardMePolicyConfig | GuardMePolicyConfig): number {
  return (
    config.allowPaths.length +
    config.denyPaths.length +
    config.zeroAccessPaths.length +
    config.readOnlyPaths.length +
    config.noDeletePaths.length +
    config.allowCommands.length +
    config.denyCommands.length +
    config.dangerousCommands.length +
    config.protectedCredentialPaths.length
  );
}

function formatCommandError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

async function fileExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}
