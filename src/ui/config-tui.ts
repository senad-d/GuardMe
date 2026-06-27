import type { GuardMePolicyConfig } from "../config/schema.ts";
import type { PolicyDiagnostic } from "../policy/action.ts";
import type { GuardMeStateRecord } from "../state/warnings.ts";
import { SETUP_MODE_CHOICES, type SetupMode, type SetupScope, type SetupWizardConfig, setupConfigForMode, setupModeRows, setupScopeLabel } from "./setup-wizard.ts";
import { fitCell, footerSegments, type ConfigFrameTheme, type FrameMainRow, type FrameSidebarItem, renderGuardMeFrame } from "./config-frame.ts";
import { formatDiagnostics, formatWarningDecisionRecords } from "./detail-formatters.ts";
import { visibleWidth } from "./text.ts";

export type ConfigPane = "Setup" | "General" | "Policies" | "Rules";
type FocusBox = "sidebar" | "main";
export type ConfigAction =
  | { readonly kind: "closed" }
  | { readonly kind: "custom"; readonly mode: Extract<SetupMode, "global-custom" | "local-custom"> }
  | { readonly kind: "append-rules"; readonly scope: SetupScope }
  | { readonly kind: "write"; readonly setupConfig: SetupWizardConfig; readonly plan: SetupWritePlan }
  | { readonly kind: "set-guardme-enabled"; readonly enabled: boolean }
  | { readonly kind: "set-insecure-edits"; readonly enabled: boolean }
  | { readonly kind: "set-project-trusted"; readonly trusted: boolean };

export interface ConfigTuiContext {
  readonly cwd: string;
  readonly mode?: string;
  readonly hasUI: boolean;
  readonly ui: {
    readonly custom?: <T>(factory: (...args: any[]) => unknown, options?: Record<string, unknown>) => Promise<T>;
  };
}

export interface SetupWritePlan {
  readonly scope: SetupScope;
  readonly targetPath: string;
  readonly displayPath: string;
  readonly policyKind: "default" | "custom" | "append";
  readonly existing: boolean;
  readonly rules: number;
}

export type SetupWritePlanResult =
  | { readonly ok: true; readonly plan: SetupWritePlan }
  | { readonly ok: false; readonly reason: string };

export type PolicyWriteSuccessResult = ConfigAction | { readonly kind: "continue" };
export type PolicyWriteConfirmationAction = "write" | "back" | "cancel";

export interface PolicyWriteSuccessOptions {
  readonly sensibleDefaults?: GuardMePolicyConfig;
  readonly createPlan?: (setupConfig: SetupWizardConfig) => Promise<SetupWritePlanResult>;
}

export interface ConfigSnapshot {
  readonly cwd: string;
  readonly projectTrusted: boolean;
  readonly guardMe: "active" | "off" | "inactive" | "degraded";
  readonly insecureEdits: boolean;
  readonly policyRules: number;
  readonly warnedFingerprints: number;
  readonly warningRecords: readonly GuardMeStateRecord[];
  readonly diagnostics: readonly PolicyDiagnostic[];
  readonly settingsPath: string;
  readonly globalPolicyPath: string;
  readonly localPolicyPath: string;
  readonly globalStatePath: string;
  readonly localStatePath: string;
  readonly ruleGroups: readonly RuleGroupSummary[];
}

export interface RuleGroupSummary {
  readonly label: string;
  readonly count: number;
  readonly description: string;
}

interface ConfigComponentState {
  pane: ConfigPane;
  sidebarIndex: number;
  focus: FocusBox;
  setupIndex: number;
  statusIndex: number;
  policiesIndex: number;
  rulesIndex: number;
  searchActive: boolean;
  searchQuery: string;
  searchIndex: number;
  detail?: ConfigDetailState;
  confirm?: ConfirmState;
  busy: boolean;
  footerOverride?: string;
}

interface PolicyWriteConfirmState {
  readonly kind: "policy-write";
  readonly setupConfig: SetupWizardConfig;
  readonly plan: SetupWritePlan;
  selectedIndex: number;
}

interface GuardMeOffConfirmState {
  readonly kind: "guardme-off";
  selectedIndex: number;
}

interface InsecureEditsConfirmState {
  readonly kind: "insecure-edits";
  selectedIndex: number;
}

interface ProjectTrustConfirmState {
  readonly kind: "project-trust";
  readonly trusted: boolean;
  selectedIndex: number;
}

type ConfirmState = PolicyWriteConfirmState | GuardMeOffConfirmState | InsecureEditsConfirmState | ProjectTrustConfirmState;

type ConfirmInputResult =
  | { readonly kind: "write" }
  | { readonly kind: "back" }
  | { readonly kind: "cancel" }
  | { readonly kind: "set-guardme-enabled"; readonly enabled: boolean }
  | { readonly kind: "set-insecure-edits"; readonly enabled: boolean }
  | { readonly kind: "set-project-trusted"; readonly trusted: boolean };

interface ConfigDetailState {
  readonly kind: "warnings" | "diagnostics";
  selectedIndex: number;
}

interface WrappedDetailLine {
  readonly text: string;
  readonly continuation?: boolean;
}

interface SearchResult {
  readonly pane: ConfigPane;
  readonly selectionIndex: number;
  readonly label: string;
  readonly value?: string | number | boolean;
  readonly valueKind?: "auto" | "boolean" | "empty" | "number" | "path" | "slider" | "status" | "text";
  readonly description?: string;
}

type ConfigTheme = ConfigFrameTheme;

const CONFIG_PANES: readonly ConfigPane[] = ["General", "Policies", "Rules", "Setup"];
const CONFIG_FRAME_BODY_ROWS = 11;
const DETAIL_ROW_MARKER_WIDTH = 2;
const DETAIL_FIELD_LABELS = ["Reason code", "Fingerprint", "Persisted", "Decision", "Message", "Source line", "Source", "Action", "Target", "Reason", "Scope", "Tool", "Risk", "Rule", "Count"] as const;
const SETUP_PANE_INDEX = CONFIG_PANES.indexOf("Setup");
const POLICY_WRITE_CONFIRM_CHOICES = ["Write policy", "Go back", "Cancel"] as const;
const GUARDME_OFF_CONFIRM_CHOICES = ["Turn off GuardMe", "Go back"] as const;
const INSECURE_EDITS_CONFIRM_CHOICES = ["Turn on insecure edits", "Go back"] as const;
const PROJECT_TRUST_CONFIRM_CHOICES = ["Save trust decision", "Go back"] as const;
const CONFIRM_HELP = "↑↓ choice  Enter select  Esc/q quit";

export async function requestGuardMeConfigAction(
  ctx: ConfigTuiContext,
  snapshot: ConfigSnapshot,
  sensibleDefaults: GuardMePolicyConfig,
  createPlan: (setupConfig: SetupWizardConfig) => Promise<SetupWritePlanResult>,
): Promise<ConfigAction> {
  if (ctx.mode !== "tui" || typeof ctx.ui.custom !== "function") {
    return { kind: "closed" };
  }

  return ctx.ui.custom<ConfigAction>(
    (tui: { requestRender?: () => void }, theme: ConfigTheme, _keybindings: unknown, done: (value: ConfigAction) => void) =>
      createConfigComponent(tui, theme, done, snapshot, sensibleDefaults, createPlan),
  );
}

export async function requestPolicyWriteConfirmationAction(
  ctx: ConfigTuiContext,
  setupConfig: SetupWizardConfig,
  plan: SetupWritePlan,
): Promise<PolicyWriteConfirmationAction> {
  if (ctx.mode !== "tui" || typeof ctx.ui.custom !== "function") {
    return "cancel";
  }

  const result = await ctx.ui.custom<PolicyWriteConfirmationAction>(
    (tui: { requestRender?: () => void }, theme: ConfigTheme, _keybindings: unknown, done: (value: PolicyWriteConfirmationAction) => void) =>
      createStandaloneConfirmComponent(tui, theme, done, setupConfig, plan),
  );
  return result ?? "cancel";
}

export async function requestPolicyWriteConfirmation(
  ctx: ConfigTuiContext,
  setupConfig: SetupWizardConfig,
  plan: SetupWritePlan,
): Promise<boolean> {
  return (await requestPolicyWriteConfirmationAction(ctx, setupConfig, plan)) === "write";
}

export async function showPolicyWriteSuccess(
  ctx: ConfigTuiContext,
  snapshot: ConfigSnapshot,
  plan: SetupWritePlan,
  options: PolicyWriteSuccessOptions = {},
): Promise<PolicyWriteSuccessResult> {
  if (ctx.mode !== "tui" || typeof ctx.ui.custom !== "function") {
    return { kind: "closed" };
  }

  const result = await ctx.ui.custom<PolicyWriteSuccessResult>(
    (tui: { requestRender?: () => void }, theme: ConfigTheme, _keybindings: unknown, done: (value: PolicyWriteSuccessResult) => void) =>
      createSuccessComponent(tui, theme, done, snapshot, plan, options),
  );
  return result ?? { kind: "closed" };
}

export function renderConfigPane(snapshot: ConfigSnapshot, pane: ConfigPane, width = 100, selectedIndex?: number): string {
  return renderPaneScreen(snapshot, pane, selectedIndex ?? selectedIndexForPane(pane, undefined), width).join("\n");
}

export function renderGuardMeHelp(width = 100): string {
  return renderSimpleFrame(
    "GuardMe Help",
    [
      "/guardme             Open general settings, policies, rules, and setup",
      "/guardme help        Show this help",
      "",
      "Run /guardme to create a global or project policy and inspect current GuardMe state.",
    ],
    "GuardMe uses one main command for general configuration work.",
    width,
  ).join("\n");
}

export function createRuleGroups(config: GuardMePolicyConfig, localPolicyRules = 0): readonly RuleGroupSummary[] {
  const protectedPolicyRules = config.readOnlyPaths.filter((rule) => rule.pattern.includes("guardme")).length;
  const dangerousShellRules = config.denyCommands.length + config.dangerousCommands.length;
  const secretPathRules = config.denyPaths.length + config.zeroAccessPaths.length + config.protectedCredentialPaths.length;
  const packageManagerRules =
    config.allowCommands.filter((rule) => /npm|pnpm|yarn|package/i.test(rule.pattern)).length +
    config.noDeletePaths.filter((rule) => /package-lock|pnpm-lock|yarn\.lock/i.test(rule.pattern)).length;
  const gitRules =
    config.noDeletePaths.filter((rule) => /\.git/i.test(rule.pattern)).length +
    config.dangerousCommands.filter((rule) => /git|find|rsync/i.test(rule.pattern)).length;

  return [
    {
      label: "Protected policy files",
      count: protectedPolicyRules,
      description: "Rules that protect GuardMe policy files and state files from accidental edits.",
    },
    {
      label: "Dangerous shell commands",
      count: dangerousShellRules,
      description: "Commands that are denied or require coaching and approval before running.",
    },
    {
      label: "Secret and credential paths",
      count: secretPathRules,
      description: "Rules that keep credentials, tokens, SSH keys, and environment files unavailable.",
    },
    {
      label: "Package manager operations",
      count: packageManagerRules,
      description: "Rules related to common package-manager validation and lockfile protection.",
    },
    {
      label: "Git destructive operations",
      count: gitRules,
      description: "Rules that protect repository metadata and risky cleanup operations.",
    },
    {
      label: "Project policy file",
      count: localPolicyRules,
      description: "Rules loaded from the project-local GuardMe policy file; this source count is not an extra category.",
    },
  ];
}

function renderSimpleFrame(title: string, body: readonly string[], footer: string, requestedWidth: number): string[] {
  const width = Math.max(20, Math.floor(requestedWidth));
  const innerWidth = width - 2;
  const topLeft = `╭─ ${title} `;
  const topRight = "─╮";
  const topLine = visibleWidth(topLeft) + visibleWidth(topRight) <= width
    ? `${topLeft}${"─".repeat(Math.max(0, width - visibleWidth(topLeft) - visibleWidth(topRight)))}${topRight}`
    : `╭${"─".repeat(innerWidth)}╮`;
  return [
    topLine,
    ...body.map((line) => `│${fitCell(line, innerWidth)}│`),
    `├${"─".repeat(innerWidth)}┤`,
    `│${fitCell(footer, innerWidth)}│`,
    `╰${"─".repeat(innerWidth)}╯`,
  ];
}

function createConfigComponent(
  tui: { requestRender?: () => void },
  theme: ConfigTheme,
  done: (value: ConfigAction) => void,
  snapshot: ConfigSnapshot,
  sensibleDefaults: GuardMePolicyConfig,
  createPlan: (setupConfig: SetupWizardConfig) => Promise<SetupWritePlanResult>,
): { render: (width: number) => string[]; invalidate: () => void; handleInput: (data: string) => void } {
  const state: ConfigComponentState = {
    pane: "General",
    sidebarIndex: 0,
    focus: "sidebar",
    setupIndex: 0,
    statusIndex: 0,
    policiesIndex: 0,
    rulesIndex: 0,
    searchActive: false,
    searchQuery: "",
    searchIndex: 0,
    busy: false,
  };
  let cachedKey = "";
  let cachedLines: string[] | undefined;

  const invalidate = () => {
    cachedKey = "";
    cachedLines = undefined;
  };
  const rerender = () => {
    invalidate();
    tui.requestRender?.();
  };

  const openConfirmForMode = (mode: SetupMode) => {
    if (mode === "cancel") {
      done({ kind: "closed" });
      return;
    }
    if (mode === "global-custom" || mode === "local-custom") {
      done({ kind: "custom", mode });
      return;
    }
    if (mode === "global-add-rule" || mode === "local-add-rule") {
      done({ kind: "append-rules", scope: mode.startsWith("global") ? "global" : "local" });
      return;
    }

    const setupConfig = setupConfigForMode(mode, sensibleDefaults);
    if (!setupConfig) {
      state.footerOverride = "Unable to prepare this setup option. No files were written.";
      rerender();
      return;
    }

    state.busy = true;
    state.footerOverride = "Checking target policy file before confirmation…";
    rerender();
    void createPlan(setupConfig)
      .then((result) => {
        state.busy = false;
        if (!result.ok) {
          state.footerOverride = result.reason;
          rerender();
          return;
        }
        state.footerOverride = undefined;
        state.confirm = { kind: "policy-write", setupConfig, plan: result.plan, selectedIndex: 0 };
        state.pane = "Setup";
        state.sidebarIndex = SETUP_PANE_INDEX;
        state.focus = "main";
        rerender();
      })
      .catch((error) => {
        state.busy = false;
        state.footerOverride = `Unable to check target policy file: ${formatConfigActionError(error)}`;
        rerender();
      });
  };

  const openGuardMeToggle = () => {
    if (snapshot.guardMe === "off") {
      done({ kind: "set-guardme-enabled", enabled: true });
      return;
    }
    if (snapshot.guardMe === "inactive") {
      state.footerOverride = "GuardMe session state is not initialized. Start a session before changing enforcement.";
      rerender();
      return;
    }
    state.confirm = { kind: "guardme-off", selectedIndex: 0 };
    state.pane = "General";
    state.sidebarIndex = 0;
    state.focus = "main";
    rerender();
  };

  const openInsecureEditsToggle = () => {
    if (snapshot.guardMe === "inactive") {
      state.footerOverride = "GuardMe session state is not initialized. Start a session before changing insecure edits.";
      rerender();
      return;
    }
    if (snapshot.insecureEdits) {
      done({ kind: "set-insecure-edits", enabled: false });
      return;
    }
    state.confirm = { kind: "insecure-edits", selectedIndex: 0 };
    state.pane = "General";
    state.sidebarIndex = 0;
    state.focus = "main";
    rerender();
  };

  const openProjectTrustToggle = () => {
    state.confirm = { kind: "project-trust", trusted: !snapshot.projectTrusted, selectedIndex: 0 };
    state.pane = "General";
    state.sidebarIndex = 0;
    state.focus = "main";
    rerender();
  };

  const activateGeneralRow = () => {
    switch (state.statusIndex) {
      case 0:
        openGuardMeToggle();
        return;
      case 1:
        openInsecureEditsToggle();
        return;
      case 2:
        openProjectTrustToggle();
        return;
      case 3:
        state.detail = { kind: "warnings", selectedIndex: 0 };
        state.footerOverride = undefined;
        rerender();
        return;
      case 4:
        state.detail = { kind: "diagnostics", selectedIndex: 0 };
        state.footerOverride = undefined;
        rerender();
        return;
      default:
        state.footerOverride = "This General row is read-only.";
        rerender();
    }
  };

  return {
    render(width: number): string[] {
      const key = JSON.stringify({ width, state });
      if (cachedLines && cachedKey === key) {
        return cachedLines;
      }
      cachedKey = key;
      cachedLines = state.confirm
        ? renderConfirmScreen(state.confirm, width, state.footerOverride, theme)
        : state.detail
          ? renderDetailScreen(snapshot, state.detail, width, state.footerOverride, theme)
          : state.searchActive
            ? renderSearchScreen(snapshot, state, width, state.footerOverride, theme)
            : renderPaneScreen(snapshot, state.pane, selectedIndexForPane(state.pane, state), width, state.footerOverride, state.busy, state.focus, theme);
      return cachedLines;
    },
    invalidate,
    handleInput(data: string): void {
      if (state.searchActive) {
        handleSearchInput(data, state, snapshot, rerender);
        return;
      }
      if (state.detail) {
        if (isEscape(data) || isQuit(data)) {
          state.detail = undefined;
          state.pane = "General";
          state.sidebarIndex = 0;
          state.focus = "main";
          state.footerOverride = undefined;
          rerender();
          return;
        }
        if (isUp(data) || isDown(data)) {
          state.detail.selectedIndex = moveDetailSelection(snapshot, state.detail, isDown(data) ? 1 : -1);
          state.footerOverride = undefined;
          rerender();
        }
        return;
      }
      if (state.busy) {
        return;
      }
      if (state.confirm) {
        const confirm = state.confirm;
        handleConfirmInput(data, confirm, () => {
          state.confirm = undefined;
          if (confirm.kind === "policy-write") {
            state.pane = "Setup";
            state.sidebarIndex = SETUP_PANE_INDEX;
          } else {
            state.pane = "General";
            state.sidebarIndex = 0;
          }
          state.focus = "main";
          rerender();
        }, (action) => {
          switch (action.kind) {
            case "write":
              if (confirm.kind === "policy-write") {
                done({ kind: "write", setupConfig: confirm.setupConfig, plan: confirm.plan });
              }
              return;
            case "set-guardme-enabled":
              done(action);
              return;
            case "set-insecure-edits":
              done(action);
              return;
            case "set-project-trusted":
              done(action);
              return;
            case "back":
              state.confirm = undefined;
              if (confirm.kind === "policy-write") {
                state.pane = "Setup";
                state.sidebarIndex = SETUP_PANE_INDEX;
              } else {
                state.pane = "General";
                state.sidebarIndex = 0;
              }
              state.focus = "main";
              rerender();
              return;
            case "cancel":
            default:
              done({ kind: "closed" });
          }
        }, rerender);
        return;
      }
      if (isQuit(data) || isEscape(data)) {
        done({ kind: "closed" });
        return;
      }
      if (data === "/") {
        state.searchActive = true;
        state.searchQuery = "";
        state.searchIndex = 0;
        state.focus = "main";
        state.footerOverride = undefined;
        rerender();
        return;
      }
      if (isTab(data)) {
        state.focus = paneIsReadOnly(state.pane) ? "sidebar" : state.focus === "sidebar" ? "main" : "sidebar";
        state.footerOverride = undefined;
        rerender();
        return;
      }
      const navigationFocus = paneIsReadOnly(state.pane) ? "sidebar" : state.focus;
      if (navigationFocus === "sidebar") {
        if (isUp(data) || isDown(data)) {
          moveSidebarSelection(state, isDown(data) ? 1 : -1);
          state.footerOverride = undefined;
          rerender();
          return;
        }
        if (isEnter(data) && !paneIsReadOnly(state.pane)) {
          state.focus = "main";
          state.footerOverride = undefined;
          rerender();
          return;
        }
        return;
      }
      if (isUp(data) || isDown(data)) {
        moveSelection(state, isDown(data) ? 1 : -1, snapshot);
        state.footerOverride = undefined;
        rerender();
        return;
      }
      if (isEnter(data) && state.pane === "Setup") {
        openConfirmForMode(setupModeAt(state.setupIndex));
        return;
      }
      if (isEnter(data) && state.pane === "General") {
        activateGeneralRow();
        return;
      }
      if (data === "r" || data === "R") {
        state.footerOverride = "Refresh requested. Reopen /guardme to reload policy files from disk.";
        rerender();
      }
    },
  };
}

function createStandaloneConfirmComponent(
  tui: { requestRender?: () => void },
  theme: ConfigTheme,
  done: (value: "write" | "back" | "cancel") => void,
  setupConfig: SetupWizardConfig,
  plan: SetupWritePlan,
): { render: (width: number) => string[]; invalidate: () => void; handleInput: (data: string) => void } {
  const confirm: ConfirmState = { kind: "policy-write", setupConfig, plan, selectedIndex: 0 };
  let cachedWidth = 0;
  let cachedLines: string[] | undefined;
  const invalidate = () => {
    cachedWidth = 0;
    cachedLines = undefined;
  };
  const rerender = () => {
    invalidate();
    tui.requestRender?.();
  };

  return {
    render(width: number): string[] {
      if (cachedLines && cachedWidth === width) {
        return cachedLines;
      }
      cachedWidth = width;
      cachedLines = renderConfirmScreen(confirm, width, undefined, theme);
      return cachedLines;
    },
    invalidate,
    handleInput(data: string): void {
      handleConfirmInput(
        data,
        confirm,
        () => done("back"),
        (result) => {
          if (result.kind === "write" || result.kind === "back" || result.kind === "cancel") {
            done(result.kind);
          }
        },
        rerender,
      );
    },
  };
}

function createSuccessComponent(
  tui: { requestRender?: () => void },
  theme: ConfigTheme,
  done: (value: PolicyWriteSuccessResult) => void,
  snapshot: ConfigSnapshot,
  plan: SetupWritePlan,
  options: PolicyWriteSuccessOptions = {},
): { render: (width: number) => string[]; invalidate: () => void; handleInput: (data: string) => void } {
  const actionsEnabled = Boolean(options.sensibleDefaults && options.createPlan);
  const state: ConfigComponentState = {
    pane: "General",
    sidebarIndex: 0,
    focus: "main",
    setupIndex: 0,
    statusIndex: 0,
    policiesIndex: 0,
    rulesIndex: 0,
    searchActive: false,
    searchQuery: "",
    searchIndex: 0,
    busy: false,
    footerOverride: policyWriteSuccessFooter(snapshot, plan),
  };
  let cachedKey = "";
  let cachedLines: string[] | undefined;
  const invalidate = () => {
    cachedKey = "";
    cachedLines = undefined;
  };
  const rerender = () => {
    invalidate();
    tui.requestRender?.();
  };
  const returnFromConfirm = (confirm: ConfirmState) => {
    state.confirm = undefined;
    if (confirm.kind === "policy-write") {
      state.pane = "Setup";
      state.sidebarIndex = SETUP_PANE_INDEX;
    } else {
      state.pane = "General";
      state.sidebarIndex = 0;
    }
    state.focus = "main";
    rerender();
  };
  const explainUnavailableAction = (message: string) => {
    state.footerOverride = `${message}. Press Esc/q to close this setup summary.`;
    rerender();
  };

  const openSetupActionForMode = (mode: SetupMode) => {
    if (!actionsEnabled || !options.sensibleDefaults || !options.createPlan) {
      explainUnavailableAction("Setup changes are available from /guardme");
      return;
    }
    if (mode === "cancel") {
      done({ kind: "closed" });
      return;
    }
    if (mode === "global-custom" || mode === "local-custom") {
      done({ kind: "custom", mode });
      return;
    }
    if (mode === "global-add-rule" || mode === "local-add-rule") {
      done({ kind: "append-rules", scope: mode.startsWith("global") ? "global" : "local" });
      return;
    }

    const setupConfig = setupConfigForMode(mode, options.sensibleDefaults);
    if (!setupConfig) {
      state.footerOverride = "Unable to prepare this setup option. No files were written.";
      rerender();
      return;
    }

    state.busy = true;
    state.footerOverride = "Checking target policy file before confirmation…";
    rerender();
    void options.createPlan(setupConfig)
      .then((result) => {
        state.busy = false;
        if (!result.ok) {
          state.footerOverride = result.reason;
          rerender();
          return;
        }
        state.footerOverride = undefined;
        state.confirm = { kind: "policy-write", setupConfig, plan: result.plan, selectedIndex: 0 };
        state.pane = "Setup";
        state.sidebarIndex = SETUP_PANE_INDEX;
        state.focus = "main";
        rerender();
      })
      .catch((error) => {
        state.busy = false;
        state.footerOverride = `Unable to check target policy file: ${formatConfigActionError(error)}`;
        rerender();
      });
  };

  const openGuardMeToggle = () => {
    if (!actionsEnabled) {
      explainUnavailableAction("GuardMe settings are available from /guardme");
      return;
    }
    if (snapshot.guardMe === "off") {
      done({ kind: "set-guardme-enabled", enabled: true });
      return;
    }
    if (snapshot.guardMe === "inactive") {
      state.footerOverride = "GuardMe session state is not initialized. Start a session before changing enforcement.";
      rerender();
      return;
    }
    state.confirm = { kind: "guardme-off", selectedIndex: 0 };
    state.pane = "General";
    state.sidebarIndex = 0;
    state.focus = "main";
    rerender();
  };

  const openInsecureEditsToggle = () => {
    if (!actionsEnabled) {
      explainUnavailableAction("Insecure edits settings are available from /guardme");
      return;
    }
    if (snapshot.guardMe === "inactive") {
      state.footerOverride = "GuardMe session state is not initialized. Start a session before changing insecure edits.";
      rerender();
      return;
    }
    if (snapshot.insecureEdits) {
      done({ kind: "set-insecure-edits", enabled: false });
      return;
    }
    state.confirm = { kind: "insecure-edits", selectedIndex: 0 };
    state.pane = "General";
    state.sidebarIndex = 0;
    state.focus = "main";
    rerender();
  };

  const openProjectTrustToggle = () => {
    if (!actionsEnabled) {
      explainUnavailableAction("Pi project trust changes are available from /guardme");
      return;
    }
    state.confirm = { kind: "project-trust", trusted: !snapshot.projectTrusted, selectedIndex: 0 };
    state.pane = "General";
    state.sidebarIndex = 0;
    state.focus = "main";
    rerender();
  };

  const activateGeneralRow = () => {
    switch (state.statusIndex) {
      case 0:
        openGuardMeToggle();
        return;
      case 1:
        openInsecureEditsToggle();
        return;
      case 2:
        openProjectTrustToggle();
        return;
      case 3:
        state.detail = { kind: "warnings", selectedIndex: 0 };
        state.footerOverride = undefined;
        rerender();
        return;
      case 4:
        state.detail = { kind: "diagnostics", selectedIndex: 0 };
        state.footerOverride = undefined;
        rerender();
        return;
      default:
        state.footerOverride = "This General row is read-only.";
        rerender();
    }
  };

  return {
    render(width: number): string[] {
      const key = JSON.stringify({ width, state });
      if (cachedLines && cachedKey === key) {
        return cachedLines;
      }
      cachedKey = key;
      const successContext = state.pane === "General" ? policyWriteSuccessContext(snapshot, plan, actionsEnabled) : undefined;
      const successFooterMode = state.pane === "General" ? "replace" : "prefix";
      cachedLines = state.confirm
        ? renderConfirmScreen(state.confirm, width, state.footerOverride, theme)
        : state.detail
          ? renderDetailScreen(snapshot, state.detail, width, state.footerOverride, theme)
          : state.searchActive
            ? renderSearchScreen(snapshot, state, width, state.footerOverride, theme)
            : renderPaneScreen(
                snapshot,
                state.pane,
                selectedIndexForPane(state.pane, state),
                width,
                state.footerOverride,
                state.busy,
                state.focus,
                theme,
                successContext,
                successFooterMode,
                successKeysForState(state, actionsEnabled),
              );
      return cachedLines;
    },
    invalidate,
    handleInput(data: string): void {
      if (state.searchActive) {
        handleSearchInput(data, state, snapshot, rerender);
        return;
      }
      if (state.detail) {
        if (isEscape(data) || isQuit(data)) {
          state.detail = undefined;
          state.pane = "General";
          state.sidebarIndex = 0;
          state.focus = "main";
          state.footerOverride = undefined;
          rerender();
          return;
        }
        if (isUp(data) || isDown(data)) {
          state.detail.selectedIndex = moveDetailSelection(snapshot, state.detail, isDown(data) ? 1 : -1);
          state.footerOverride = undefined;
          rerender();
        }
        return;
      }
      if (state.busy) {
        return;
      }
      if (state.confirm) {
        const confirm = state.confirm;
        handleConfirmInput(data, confirm, () => returnFromConfirm(confirm), (action) => {
          switch (action.kind) {
            case "write":
              if (confirm.kind === "policy-write") {
                done({ kind: "write", setupConfig: confirm.setupConfig, plan: confirm.plan });
              }
              return;
            case "set-guardme-enabled":
              done(action);
              return;
            case "set-insecure-edits":
              done(action);
              return;
            case "set-project-trusted":
              done(action);
              return;
            case "back":
              returnFromConfirm(confirm);
              return;
            case "cancel":
            default:
              done({ kind: "closed" });
          }
        }, rerender);
        return;
      }
      if (isQuit(data) || isEscape(data)) {
        done({ kind: "closed" });
        return;
      }
      if (data === "/") {
        state.searchActive = true;
        state.searchQuery = "";
        state.searchIndex = 0;
        state.focus = "main";
        rerender();
        return;
      }
      if (isTab(data)) {
        state.focus = paneIsReadOnly(state.pane) ? "sidebar" : state.focus === "sidebar" ? "main" : "sidebar";
        rerender();
        return;
      }

      const navigationFocus = paneIsReadOnly(state.pane) ? "sidebar" : state.focus;
      if (navigationFocus === "sidebar") {
        if (isUp(data) || isDown(data)) {
          moveSidebarSelection(state, isDown(data) ? 1 : -1);
          rerender();
          return;
        }
        if (isEnter(data) && !paneIsReadOnly(state.pane)) {
          state.focus = "main";
          rerender();
        }
        return;
      }

      if (isUp(data) || isDown(data)) {
        moveSelection(state, isDown(data) ? 1 : -1, snapshot);
        rerender();
        return;
      }
      if (isEnter(data) && state.pane === "Setup") {
        openSetupActionForMode(setupModeAt(state.setupIndex));
        return;
      }
      if (isEnter(data) && state.pane === "General") {
        activateGeneralRow();
      }
    },
  };
}

function successKeysForState(state: ConfigComponentState, actionsEnabled = false): string | undefined {
  if (state.focus !== "main" || paneIsReadOnly(state.pane)) {
    return undefined;
  }
  if (state.pane === "Setup") {
    return actionsEnabled ? "↑↓ option  Enter select  Tab pane  / search  Esc/q quit" : "↑↓ option  Tab pane  / search  Esc/q quit";
  }
  if (state.pane === "General") {
    return actionsEnabled ? "↑↓ row  Enter select  Tab pane  / search  Esc/q quit" : "↑↓ row  Enter inspect  Tab pane  / search  Esc/q quit";
  }
  return undefined;
}

function handleConfirmInput(
  data: string,
  confirm: ConfirmState,
  goBack: () => void,
  done: (value: ConfirmInputResult) => void,
  rerender: () => void,
): void {
  if (isQuit(data)) {
    done({ kind: "cancel" });
    return;
  }
  if (isEscape(data)) {
    goBack();
    return;
  }
  if (isUp(data) || isDown(data)) {
    confirm.selectedIndex = wrap(confirm.selectedIndex + (isDown(data) ? 1 : -1), 0, confirmChoices(confirm).length - 1);
    rerender();
    return;
  }
  if (isEnter(data)) {
    const choice = confirmChoices(confirm)[confirm.selectedIndex];
    if (!choice || choice === "Go back") {
      done({ kind: "back" });
      return;
    }
    if (confirm.kind === "policy-write" && choice === "Write policy") {
      done({ kind: "write" });
      return;
    }
    if (choice === "Cancel") {
      done({ kind: "cancel" });
      return;
    }
    if (confirm.kind === "guardme-off" && choice === "Turn off GuardMe") {
      done({ kind: "set-guardme-enabled", enabled: false });
      return;
    }
    if (confirm.kind === "insecure-edits" && choice === "Turn on insecure edits") {
      done({ kind: "set-insecure-edits", enabled: true });
      return;
    }
    if (confirm.kind === "project-trust" && choice === "Save trust decision") {
      done({ kind: "set-project-trusted", trusted: confirm.trusted });
    }
  }
}

function confirmChoices(confirm: ConfirmState): readonly string[] {
  switch (confirm.kind) {
    case "policy-write":
      return POLICY_WRITE_CONFIRM_CHOICES;
    case "guardme-off":
      return GUARDME_OFF_CONFIRM_CHOICES;
    case "insecure-edits":
      return INSECURE_EDITS_CONFIRM_CHOICES;
    case "project-trust":
      return PROJECT_TRUST_CONFIRM_CHOICES;
  }
}

function handleSearchInput(data: string, state: ConfigComponentState, snapshot: ConfigSnapshot, rerender: () => void): void {
  if (isEscape(data)) {
    clearSearch(state);
    rerender();
    return;
  }

  if (isUp(data) || isDown(data)) {
    const results = searchResults(snapshot, state.searchQuery);
    state.searchIndex = wrap(state.searchIndex + (isDown(data) ? 1 : -1), 0, results.length - 1);
    rerender();
    return;
  }

  if (isEnter(data)) {
    const result = searchResults(snapshot, state.searchQuery)[state.searchIndex];
    if (result) {
      state.pane = result.pane;
      state.sidebarIndex = CONFIG_PANES.indexOf(result.pane);
      setSelectedIndexForPane(state, result.pane, result.selectionIndex);
    }
    clearSearch(state);
    state.focus = result && paneIsReadOnly(result.pane) ? "sidebar" : "main";
    rerender();
    return;
  }

  if (isBackspace(data)) {
    state.searchQuery = Array.from(state.searchQuery).slice(0, -1).join("");
    state.searchIndex = clampSearchIndex(snapshot, state.searchQuery, state.searchIndex);
    rerender();
    return;
  }

  if (isPrintable(data)) {
    state.searchQuery = `${state.searchQuery}${data}`;
    state.searchIndex = clampSearchIndex(snapshot, state.searchQuery, 0);
    rerender();
  }
}

function clearSearch(state: ConfigComponentState): void {
  state.searchActive = false;
  state.searchQuery = "";
  state.searchIndex = 0;
}

function clampSearchIndex(snapshot: ConfigSnapshot, query: string, selectedIndex: number): number {
  return clamp(selectedIndex, 0, Math.max(0, searchResults(snapshot, query).length - 1));
}

function renderSearchScreen(
  snapshot: ConfigSnapshot,
  state: ConfigComponentState,
  width: number,
  footerOverride?: string,
  theme?: ConfigTheme,
): string[] {
  const results = searchResults(snapshot, state.searchQuery);
  const selectedIndex = clamp(state.searchIndex, 0, Math.max(0, results.length - 1));
  const counter = results.length === 0 ? "0/0" : `${selectedIndex + 1}/${results.length}`;
  const rows: FrameMainRow[] = [
    { kind: "heading", label: state.searchQuery.trim().length > 0 ? `SEARCH ${state.searchQuery}` : "SEARCH", value: counter },
    ...(results.length === 0
      ? [{ kind: "text", text: "No matching settings", tone: "warning" } satisfies FrameMainRow]
      : results.map<FrameMainRow>((result, index) => {
          if (result.value === undefined) {
            return {
              kind: "text",
              text: `${result.label} (${result.pane})`,
              selected: index === selectedIndex,
              description: result.description,
            };
          }
          return {
            kind: "value",
            label: `${result.label} (${result.pane})`,
            value: result.value,
            valueKind: result.valueKind,
            selected: index === selectedIndex,
            description: result.description,
          };
        })),
  ];
  const baseFooter = searchFooter(state.searchQuery, results, selectedIndex);

  return renderGuardMeFrame(
    {
      title: "GuardMe Config",
      activePane: state.searchQuery.trim().length > 0 ? "Search" : state.pane,
      context: contextForPane(snapshot, state.pane),
      keys: keysForPane(state.pane, "main"),
      sidebar: sidebarForPane(state.pane),
      rows,
      footer: footerOverride ? footerSegments(footerOverride, baseFooter) : baseFooter,
      minContentRows: CONFIG_FRAME_BODY_ROWS,
      focus: "main",
      searchActive: true,
      theme,
    },
    width,
  );
}

function searchFooter(query: string, results: readonly SearchResult[], selectedIndex: number): string {
  const counter = results.length === 0 ? "0/0" : `${selectedIndex + 1}/${results.length}`;
  const selected = results[selectedIndex];
  return footerSegments(
    query.trim().length > 0 ? `Search: ${query}` : "Search: type to filter all settings",
    counter,
    selected?.description ?? selected?.label ?? "No matching settings",
  );
}

function searchResults(snapshot: ConfigSnapshot, query: string): readonly SearchResult[] {
  const normalizedQuery = query.trim().toLowerCase();
  const candidates = CONFIG_PANES.flatMap((pane) => searchCandidatesForPane(snapshot, pane));
  if (normalizedQuery.length === 0) {
    return candidates;
  }
  return candidates.filter((result) => {
    const haystack = `${result.label} ${result.pane} ${String(result.value ?? "")} ${result.description ?? ""}`.toLowerCase();
    return haystack.includes(normalizedQuery);
  });
}

function searchCandidatesForPane(snapshot: ConfigSnapshot, pane: ConfigPane): readonly SearchResult[] {
  if (pane === "General") {
    return generalSearchCandidates(snapshot);
  }

  let selectionIndex = 0;
  return rowsForPane(snapshot, pane, 0).flatMap<SearchResult>((row) => {
    if (row.kind === "blank" || row.kind === "heading") {
      return [];
    }
    const result: SearchResult = row.kind === "text"
      ? {
          pane,
          selectionIndex: selectionIndex++,
          label: row.text,
          ...(row.value !== undefined ? { value: row.value, valueKind: "text" } : {}),
          description: row.description,
        }
      : {
          pane,
          selectionIndex: selectionIndex++,
          label: row.label,
          value: row.value,
          valueKind: row.valueKind,
          description: row.description,
        };
    return [result];
  });
}

function generalSearchCandidates(snapshot: ConfigSnapshot): readonly SearchResult[] {
  return [
    {
      pane: "General",
      selectionIndex: 0,
      label: "GuardMe",
      value: snapshot.guardMe,
      valueKind: "status",
      description: "Toggle GuardMe active/off for this project",
    },
    {
      pane: "General",
      selectionIndex: 1,
      label: "Insecure edits",
      value: snapshot.insecureEdits,
      valueKind: "boolean",
      description: "Skip write/edit content scanning while preserving path protections",
    },
    {
      pane: "General",
      selectionIndex: 2,
      label: "Pi project trust",
      value: snapshot.projectTrusted,
      valueKind: "boolean",
      description: "Focus trust row; Pi trust controls project policy/settings/state",
    },
    {
      pane: "General",
      selectionIndex: 3,
      label: "Warned fingerprints",
      value: snapshot.warnedFingerprints,
      valueKind: "number",
      description: "Open warning and decision records",
    },
    {
      pane: "General",
      selectionIndex: 4,
      label: "Diagnostics",
      value: diagnosticsSummary(snapshot.diagnostics),
      valueKind: "text",
      description: "Open diagnostic details",
    },
  ];
}

function setSelectedIndexForPane(state: ConfigComponentState, pane: ConfigPane, selectedIndex: number): void {
  switch (pane) {
    case "Setup":
      state.setupIndex = clamp(selectedIndex, 0, SETUP_MODE_CHOICES.length - 1);
      return;
    case "General":
      state.statusIndex = clamp(selectedIndex, 0, 4);
      return;
    case "Policies":
      state.policiesIndex = clamp(selectedIndex, 0, 3);
      return;
    case "Rules":
      state.rulesIndex = clamp(selectedIndex, 0, 6);
      return;
  }
}

function renderPaneScreen(
  snapshot: ConfigSnapshot,
  pane: ConfigPane,
  selectedIndex: number,
  width: number,
  footerOverride?: string,
  busy = false,
  focus: FocusBox = "main",
  theme?: ConfigTheme,
  contextOverride?: string,
  footerOverrideMode: "prefix" | "replace" = "prefix",
  keysOverride?: string,
): string[] {
  const effectiveFocus: FocusBox = paneIsReadOnly(pane) ? "sidebar" : focus;
  const rows = rowsForPane(snapshot, pane, selectedIndex, mainContentWidthForFrame(width));
  const baseFooter = footerForPane(snapshot, pane, selectedIndex, busy, effectiveFocus);
  return renderGuardMeFrame(
    {
      title: "GuardMe Config",
      activePane: pane,
      context: contextOverride ?? contextForPane(snapshot, pane),
      keys: keysOverride ?? keysForPane(pane, effectiveFocus),
      sidebar: sidebarForPane(pane),
      rows,
      footer: footerOverride
        ? footerOverrideMode === "replace"
          ? footerOverride
          : footerSegments(footerOverride, baseFooter)
        : baseFooter,
      minContentRows: CONFIG_FRAME_BODY_ROWS,
      focus: effectiveFocus,
      theme,
    },
    width,
  );
}

function renderDetailScreen(
  snapshot: ConfigSnapshot,
  detail: ConfigDetailState,
  width: number,
  footerOverride?: string,
  theme?: ConfigTheme,
): string[] {
  const rows = rowsForDetail(snapshot, detail, mainContentWidthForFrame(width));
  const baseFooter = detailFooter(snapshot, detail);
  return renderGuardMeFrame(
    {
      title: "GuardMe Config",
      activePane: "General",
      context: contextForPane(snapshot, "General"),
      keys: "↑↓ scroll  Esc back  q back",
      sidebar: sidebarForPane("General"),
      rows,
      footer: footerOverride ? footerSegments(footerOverride, baseFooter) : baseFooter,
      minContentRows: CONFIG_FRAME_BODY_ROWS,
      focus: "main",
      theme,
    },
    width,
  );
}

function renderConfirmScreen(confirm: ConfirmState, width: number, footerOverride?: string, theme?: ConfigTheme): string[] {
  const rows = confirmRows(confirm);
  const footer = confirmStateFooter(confirm);
  const activePane = confirm.kind === "policy-write" ? "Setup" : "General";

  return renderGuardMeFrame(
    {
      title: "GuardMe Config",
      activePane,
      context: confirmContext(confirm),
      keys: CONFIRM_HELP,
      sidebar: sidebarForPane(activePane),
      rows,
      footer: footerOverride ? footerSegments(footerOverride, footer) : footer,
      minContentRows: CONFIG_FRAME_BODY_ROWS,
      focus: "main",
      theme,
    },
    width,
  );
}

function confirmRows(confirm: ConfirmState): readonly FrameMainRow[] {
  const choices = confirmChoices(confirm);
  if (confirm.kind === "policy-write") {
    const plan = confirm.plan;
    return [
      { kind: "heading", label: "CONFIRM WRITE", value: `${confirm.selectedIndex + 1}/${choices.length}` },
      { kind: "value", label: "Policy scope", value: setupScopeLabel(plan.scope) },
      { kind: "value", label: plan.policyKind === "append" ? "Update type" : "Starting rules", value: setupPolicyKindLabel(plan.policyKind) },
      { kind: "value", label: "Target file", value: plan.displayPath },
      { kind: "value", label: "Rules", value: plan.rules },
      { kind: "value", label: "Existing file", value: plan.existing ? "yes" : "no", valueKind: "text" },
      { kind: "blank" },
      ...choices.map<FrameMainRow>((choice, index) => ({ kind: "text", text: choice, selected: index === confirm.selectedIndex })),
    ];
  }

  if (confirm.kind === "guardme-off") {
    return [
      { kind: "heading", label: "CONFIRM GUARDME OFF", value: `${confirm.selectedIndex + 1}/${choices.length}` },
      { kind: "text", text: "GuardMe will stop blocking, coaching, or asking about", tone: "warning" },
      { kind: "text", text: "guarded tool calls for this project.", tone: "warning" },
      { kind: "text", text: "This setting is saved in .pi/agent/guardme-settings.json." },
      { kind: "blank" },
      ...choices.map<FrameMainRow>((choice, index) => ({ kind: "text", text: choice, selected: index === confirm.selectedIndex })),
    ];
  }

  if (confirm.kind === "insecure-edits") {
    return [
      { kind: "heading", label: "CONFIRM INSECURE EDITS", value: `${confirm.selectedIndex + 1}/${choices.length}` },
      { kind: "text", text: "Write and edit content scanning will be skipped.", tone: "warning" },
      { kind: "text", text: "Path protections, deny rules, and credential paths still apply.", tone: "warning" },
      { kind: "text", text: "Bash execution, reads, grep, find, and ls stay guarded." },
      { kind: "text", text: "This project-local setting is saved in .pi/agent/guardme-settings.json." },
      { kind: "blank" },
      ...choices.map<FrameMainRow>((choice, index) => ({ kind: "text", text: choice, selected: index === confirm.selectedIndex })),
    ];
  }

  return [
    { kind: "heading", label: "CONFIRM PI PROJECT TRUST", value: `${confirm.selectedIndex + 1}/${choices.length}` },
    { kind: "text", text: confirm.trusted ? "Trust this project for future Pi sessions?" : "Mark this project as not trusted for future Pi sessions?" },
    { kind: "text", text: "Writes ~/.pi/agent/trust.json and changes Pi's saved project trust.", tone: "warning" },
    {
      kind: "text",
      text: confirm.trusted
        ? "GuardMe may load project policy, settings, and state for this project."
        : "GuardMe will skip project policy, settings, and state until trusted again.",
      tone: "warning",
    },
    { kind: "blank" },
    ...choices.map<FrameMainRow>((choice, index) => ({ kind: "text", text: choice, selected: index === confirm.selectedIndex })),
  ];
}

function confirmContext(confirm: ConfirmState): string {
  if (confirm.kind === "policy-write") {
    return `writes ${confirm.plan.displayPath} • ${setupScopeLabel(confirm.plan.scope)} • ${setupPolicyKindLabel(confirm.plan.policyKind)} • rules ${confirm.plan.rules}`;
  }
  if (confirm.kind === "guardme-off") {
    return "writes .pi/agent/guardme-settings.json • GuardMe off is project-local";
  }
  if (confirm.kind === "insecure-edits") {
    return "writes .pi/agent/guardme-settings.json • content-scan bypass is project-local";
  }
  return confirm.trusted
    ? "Pi project trust → ON • project policy/settings/state may load after reload"
    : "Pi project trust → OFF • GuardMe skips project policy/settings/state until trusted again";
}

function setupPolicyKindLabel(kind: SetupWritePlan["policyKind"]): string {
  switch (kind) {
    case "default":
      return "sensible defaults";
    case "append":
      return "custom rule append";
    case "custom":
    default:
      return "custom rules";
  }
}

function confirmStateFooter(confirm: ConfirmState): string {
  if (confirm.kind === "policy-write") {
    return confirmFooter(confirm.plan, confirm.selectedIndex);
  }
  if (confirm.kind === "guardme-off") {
    return confirm.selectedIndex === 0
      ? footerSegments("1/2", "Turn off GuardMe for this project")
      : footerSegments("2/2", "Return to General", "GuardMe remains active");
  }
  if (confirm.kind === "insecure-edits") {
    return confirm.selectedIndex === 0
      ? footerSegments("1/2", "Turn on content-scan bypass", "path protections still apply")
      : footerSegments("2/2", "Return to General", "content scanning remains guarded");
  }
  return confirm.selectedIndex === 0
    ? footerSegments("1/2", confirm.trusted ? "Save trusted project decision" : "Save untrusted project decision", "restart or reload may be required")
    : footerSegments("2/2", "Return to General", "Pi trust is unchanged");
}

function mainContentWidthForFrame(width: number): number {
  if (width < 24) {
    return Math.max(1, width);
  }
  if (width < 72) {
    return Math.max(1, width - 2);
  }
  const leftWidth = Math.min(22, Math.max(16, Math.floor(width * 0.27)));
  return Math.max(10, width - leftWidth - 3);
}

function policyWriteSuccessContext(snapshot: ConfigSnapshot, plan: SetupWritePlan, actionsEnabled = true): string {
  if (plan.scope === "local" && !snapshot.projectTrusted) {
    return actionsEnabled ? `wrote ${plan.displayPath} • enable project trust to load project policy` : `wrote ${plan.displayPath} • run /guardme to enable project trust`;
  }
  return actionsEnabled ? `wrote ${plan.displayPath} • General settings available here` : `wrote ${plan.displayPath} • setup summary; run /guardme for settings`;
}

function policyWriteSuccessFooter(snapshot: ConfigSnapshot, plan: SetupWritePlan): string {
  const action = plan.existing ? "Updated" : "Created";
  const scopeLabel = plan.scope === "local" ? "project" : "global";
  const loadStatus = plan.scope === "local" && !snapshot.projectTrusted ? "enable project trust to load" : "General reloaded";
  return footerSegments(`${action} ${scopeLabel} policy`, plan.displayPath, loadStatus);
}

function projectSummaryRows(snapshot: ConfigSnapshot, contentWidth = 80): readonly FrameMainRow[] {
  const pathWidth = Math.max(12, contentWidth - 2);
  return [
    { kind: "text", text: "Current project" },
    ...splitPathForRows(snapshot.cwd, pathWidth).map<FrameMainRow>((line) => ({ kind: "text", text: line, tone: "dim" })),
    { kind: "blank" },
    { kind: "value", label: "Policy rules", value: snapshot.policyRules },
  ];
}

function splitPathForRows(path: string, maxWidth: number): readonly string[] {
  if (visibleWidth(path) <= maxWidth) {
    return [path];
  }

  const lines: string[] = [];
  let remaining = path;
  while (visibleWidth(remaining) > maxWidth) {
    const cutIndex = pathSplitIndex(remaining, maxWidth);
    lines.push(remaining.slice(0, cutIndex));
    remaining = remaining.slice(cutIndex);
  }
  if (remaining.length > 0) {
    lines.push(remaining);
  }
  return lines;
}

function pathSplitIndex(value: string, maxWidth: number): number {
  const hardCut = Math.max(1, Array.from(value).slice(0, maxWidth).join("").length);
  const slashCut = Math.max(value.lastIndexOf("/", hardCut), value.lastIndexOf("\\", hardCut));
  if (slashCut > 0 && slashCut >= Math.floor(maxWidth * 0.4)) {
    return slashCut + 1;
  }
  return hardCut;
}

function formatRuleCountRows(snapshot: ConfigSnapshot, contentWidth = 80): readonly FrameMainRow[] {
  const projectPolicyGroup = snapshot.ruleGroups.find((group) => group.label === "Project policy file");
  const categoryGroups = snapshot.ruleGroups.filter((group) => group !== projectPolicyGroup);
  const categoryRows = formatRuleMeaningRows(
    categoryGroups.map((group) => ({
      label: group.label,
      countText: ruleCountPhrase(group.count, "matching"),
      description: group.description,
    })),
    contentWidth,
  );
  const sourceRows = formatRuleMeaningRows(
    [
      ...(projectPolicyGroup
        ? [
            {
              label: projectPolicyGroup.label,
              countText: `${projectPolicyGroup.count} ${pluralize("rule", projectPolicyGroup.count)} in file`,
              description: projectPolicyGroup.description,
            },
          ]
        : []),
      {
        label: "Merged active policy",
        countText: ruleCountPhrase(snapshot.policyRules, "active"),
        description: "Total active rules after loading and merging policy files.",
      },
    ],
    contentWidth,
  );

  return [
    { kind: "heading", label: "CATEGORY MATCHES", value: "COUNT" },
    ...categoryRows,
    { kind: "heading", label: "SOURCE / TOTAL", value: "RULES" },
    ...sourceRows,
  ];
}

function formatRuleMeaningRows(
  rows: readonly { readonly label: string; readonly countText: string; readonly description: string }[],
  contentWidth: number,
): readonly FrameMainRow[] {
  const countWidth = Math.max(...rows.map((row) => visibleWidth(row.countText)), "COUNT".length);
  const rowWidth = Math.max(20, contentWidth - 2);
  const labelWidth = Math.max(10, Math.min(44, rowWidth - countWidth - 2));
  return rows.map((row) => ({
    kind: "text",
    text: `${fitCell(row.label, labelWidth)}  ${row.countText}`,
    description: row.description,
  }));
}

function ruleCountPhrase(count: number, qualifier: string): string {
  return `${count} ${qualifier} ${pluralize("rule", count)}`;
}

function pluralize(singular: string, count: number, plural = `${singular}s`): string {
  return count === 1 ? singular : plural;
}

function rowsForPane(snapshot: ConfigSnapshot, pane: ConfigPane, selectedIndex: number, contentWidth?: number): readonly FrameMainRow[] {
  switch (pane) {
    case "Setup": {
      const setupIndex = clamp(selectedIndex, 0, SETUP_MODE_CHOICES.length - 1);
      return [
        { kind: "heading", label: "SETUP", value: `${setupIndex + 1}/${SETUP_MODE_CHOICES.length}` },
        ...setupModeRows(setupIndex, { includeDescriptions: true }),
      ];
    }
    case "General":
      return [
        { kind: "heading", label: "GENERAL", value: "1/4" },
        { kind: "value", label: "GuardMe", value: snapshot.guardMe, valueKind: "status", selected: selectedIndex === 0 },
        { kind: "value", label: "Insecure edits", value: snapshot.insecureEdits, valueKind: "boolean", selected: selectedIndex === 1 },
        { kind: "value", label: "Pi project trust", value: snapshot.projectTrusted, valueKind: "boolean", selected: selectedIndex === 2 },
        { kind: "value", label: "Warned fingerprints", value: snapshot.warnedFingerprints, selected: selectedIndex === 3 },
        { kind: "value", label: "Diagnostics", value: diagnosticsSummary(snapshot.diagnostics), selected: selectedIndex === 4 },
        { kind: "blank" },
        ...projectSummaryRows(snapshot, contentWidth),
      ];
    case "Policies":
      return [
        { kind: "heading", label: "POLICIES", value: "2/4" },
        { kind: "value", label: "Global policy", value: snapshot.globalPolicyPath, valueKind: "path" },
        { kind: "value", label: "Project policy", value: snapshot.localPolicyPath, valueKind: "path" },
        { kind: "blank" },
        { kind: "heading", label: "STATE FILES" },
        { kind: "value", label: "Global state", value: snapshot.globalStatePath, valueKind: "path" },
        { kind: "value", label: "Project state", value: snapshot.localStatePath, valueKind: "path" },
        { kind: "blank" },
        { kind: "heading", label: "LOAD ORDER" },
        { kind: "text", text: "global policy → project policy" },
      ];
    case "Rules": {
      return [
        { kind: "heading", label: "RULES", value: "3/4" },
        ...formatRuleCountRows(snapshot, contentWidth),
      ];
    }
  }
}

function rowsForDetail(snapshot: ConfigSnapshot, detail: ConfigDetailState, contentWidth = 80): readonly FrameMainRow[] {
  const lines = detailLines(snapshot, detail.kind);
  const selectedIndex = clamp(detail.selectedIndex, 0, Math.max(0, lines.length - 1));
  const heading = detail.kind === "warnings" ? "WARNINGS & DECISIONS" : "DIAGNOSTIC DETAILS";
  const counter = detailLineCounter(selectedIndex, lines.length);
  const textWidth = Math.max(1, contentWidth - DETAIL_ROW_MARKER_WIDTH);
  return [
    { kind: "heading", label: heading, value: counter },
    ...lines.flatMap<FrameMainRow>((line, index) => {
      if (line.trim().length === 0) {
        return [{ kind: "blank", selected: index === selectedIndex }];
      }
      return wrapDetailLine(line, textWidth).map<FrameMainRow>((wrappedLine, segmentIndex) => ({
        kind: "text",
        text: wrappedLine.text,
        selected: index === selectedIndex && segmentIndex === 0,
        tone: detailLineTone(line),
        preserveIndent: Boolean(wrappedLine.continuation),
      }));
    }),
  ];
}

function wrapDetailLine(line: string, maxWidth: number): readonly WrappedDetailLine[] {
  const text = line.trimStart();
  if (text.length === 0 || visibleWidth(text) <= maxWidth) {
    return [{ text }];
  }

  const field = splitDetailField(text);
  if (!field || visibleWidth(field.prefix) + 8 >= maxWidth) {
    return wrapText(text, maxWidth).map((segment) => ({ text: segment }));
  }

  const indent = " ".repeat(visibleWidth(field.prefix));
  const firstWidth = Math.max(1, maxWidth - visibleWidth(field.prefix));
  const continuationWidth = Math.max(1, maxWidth - visibleWidth(indent));
  const segments = wrapTextWithFirstWidth(field.value, firstWidth, continuationWidth);
  return segments.map<WrappedDetailLine>((segment, index) => ({
    text: index === 0 ? `${field.prefix}${segment}` : `${indent}${segment}`,
    continuation: index > 0,
  }));
}

function splitDetailField(text: string): { readonly prefix: string; readonly value: string } | undefined {
  for (const label of DETAIL_FIELD_LABELS) {
    if (!text.startsWith(label) || text[label.length] !== " ") {
      continue;
    }
    let valueStart = label.length;
    while (text[valueStart] === " ") {
      valueStart += 1;
    }
    if (valueStart >= text.length) {
      return undefined;
    }
    return { prefix: text.slice(0, valueStart), value: text.slice(valueStart) };
  }
  return undefined;
}

function wrapText(text: string, maxWidth: number): readonly string[] {
  return wrapTextWithFirstWidth(text, maxWidth, maxWidth);
}

function wrapTextWithFirstWidth(text: string, firstWidth: number, continuationWidth: number): readonly string[] {
  const words = text.trim().split(/\s+/u).filter(Boolean);
  const lines: string[] = [];
  let line = "";
  let currentWidth = Math.max(1, firstWidth);

  const pushLine = () => {
    if (line.length > 0) {
      lines.push(line);
      line = "";
      currentWidth = Math.max(1, continuationWidth);
    }
  };

  for (const word of words) {
    const chunks = splitLongWord(word, currentWidth);
    for (const chunk of chunks) {
      const chunkWidth = visibleWidth(chunk);
      if (line.length === 0) {
        line = chunk;
        continue;
      }
      if (visibleWidth(line) + 1 + chunkWidth <= currentWidth) {
        line = `${line} ${chunk}`;
        continue;
      }
      pushLine();
      line = chunk;
    }
  }

  pushLine();
  return lines.length > 0 ? lines : [""];
}

function splitLongWord(word: string, maxWidth: number): readonly string[] {
  const width = Math.max(1, maxWidth);
  if (visibleWidth(word) <= width) {
    return [word];
  }

  const chunks: string[] = [];
  let chunk = "";
  let chunkWidth = 0;
  for (const character of Array.from(word)) {
    const characterWidth = visibleWidth(character);
    if (chunk.length > 0 && chunkWidth + characterWidth > width) {
      chunks.push(chunk);
      chunk = "";
      chunkWidth = 0;
    }
    chunk = `${chunk}${character}`;
    chunkWidth += characterWidth;
  }
  if (chunk.length > 0) {
    chunks.push(chunk);
  }
  return chunks;
}

function detailLines(snapshot: ConfigSnapshot, kind: ConfigDetailState["kind"]): readonly string[] {
  return kind === "warnings"
    ? formatWarningDecisionRecords(snapshot.warningRecords)
    : formatDiagnostics(snapshot.diagnostics);
}

function detailLineTone(line: string): "dim" | "normal" | "warning" {
  return /^(ERROR|WARNING)\b/u.test(line) ? "warning" : line.startsWith("  ") ? "dim" : "normal";
}

function detailFooter(snapshot: ConfigSnapshot, detail: ConfigDetailState): string {
  const lines = detailLines(snapshot, detail.kind);
  const selectedIndex = clamp(detail.selectedIndex, 0, Math.max(0, lines.length - 1));
  const counter = detailLineCounter(selectedIndex, lines.length);
  return footerSegments(counter, detail.kind === "warnings" ? "Current warning and decision records" : diagnosticsSummary(snapshot.diagnostics), "Esc back to General");
}

function detailLineCounter(selectedIndex: number, lineCount: number): string {
  return lineCount === 0 ? "Line 0/0" : `Line ${selectedIndex + 1}/${lineCount}`;
}

function moveDetailSelection(snapshot: ConfigSnapshot, detail: ConfigDetailState, delta: number): number {
  return wrap(detail.selectedIndex + delta, 0, Math.max(0, detailLines(snapshot, detail.kind).length - 1));
}

function contextForPane(snapshot: ConfigSnapshot, pane: ConfigPane): string {
  if (pane === "Setup") {
    return "writes ~/.pi/agent/guardme.yaml or .pi/agent/guardme.yaml • external overrides may apply";
  }
  if (pane === "General") {
    return `writes ${snapshot.settingsPath} • Pi project trust writes ~/.pi/agent/trust.json`;
  }
  return `loads ${snapshot.globalPolicyPath} → ${snapshot.localPolicyPath} • external overrides may apply`;
}

function keysForPane(pane: ConfigPane, focus: FocusBox): string {
  if (paneIsReadOnly(pane)) {
    return "↑↓ pane  / search  Esc/q quit";
  }
  if (focus === "sidebar") {
    return "↑↓ pane  Enter open  Tab rows  / search  Esc/q quit";
  }
  return pane === "General"
    ? "↑↓ row  Enter select  Tab pane  / search  Esc/q quit"
    : "↑↓ option  Enter select  Tab pane  / search  Esc/q quit";
}

function footerForPane(snapshot: ConfigSnapshot, pane: ConfigPane, selectedIndex: number, busy: boolean, focus: FocusBox = "main"): string {
  if (busy) {
    return footerSegments("Preparing confirmation…", setupFooter(selectedIndex));
  }
  if (focus === "sidebar" && !paneIsReadOnly(pane)) {
    return sidebarFooter(pane);
  }
  switch (pane) {
    case "Setup":
      return setupFooter(selectedIndex);
    case "General":
      return statusFooter(snapshot, selectedIndex);
    case "Policies":
      return policiesFooter(selectedIndex);
    case "Rules":
      return rulesFooter(snapshot, selectedIndex);
  }
}

function sidebarFooter(pane: ConfigPane): string {
  const paneIndex = CONFIG_PANES.indexOf(pane);
  const counter = paneIndex === -1 ? "Pane" : `Pane ${paneIndex + 1}/${CONFIG_PANES.length}`;
  return footerSegments(counter, `${pane} selected`, pane === "General" ? "Enter/Tab to inspect rows" : "Enter/Tab to inspect options");
}

function setupFooter(selectedIndex: number): string {
  const index = clamp(selectedIndex, 0, SETUP_MODE_CHOICES.length - 1);
  const choice = SETUP_MODE_CHOICES[index];
  return footerSegments(`${index + 1}/${SETUP_MODE_CHOICES.length}`, choice?.description ?? "Choose a GuardMe setup action");
}

function statusFooter(snapshot: ConfigSnapshot, selectedIndex: number): string {
  switch (selectedIndex) {
    case 0:
      return footerSegments(
        "Row 1/5",
        snapshot.guardMe === "off" ? "Enter to turn GuardMe active" : "Enter to turn GuardMe off with confirmation",
        `settings ${snapshot.settingsPath}`,
      );
    case 1:
      return footerSegments(
        "Row 2/5",
        `Insecure edits ${snapshot.insecureEdits ? "ON" : "OFF"}`,
        snapshot.insecureEdits ? "Enter: turn off content-scan bypass" : "Enter: turn on with confirmation",
        "path protections still apply while ON",
      );
    case 2:
      return footerSegments(
        "Row 3/5",
        `Trust ${snapshot.projectTrusted ? "ON" : "OFF"}`,
        snapshot.projectTrusted ? "Enter: mark untrusted" : "Enter: trust project",
        snapshot.projectTrusted
          ? "after reload/restart: project policy/settings/state skipped"
          : "after reload/restart: project policy/settings/state can load",
      );
    case 3:
      return footerSegments("Row 4/5", `${snapshot.warnedFingerprints} warned fingerprint${snapshot.warnedFingerprints === 1 ? "" : "s"}`, "Enter details");
    case 4:
      return footerSegments("Row 5/5", `diagnostics ${diagnosticsSummary(snapshot.diagnostics)}`, "Enter details");
    default:
      return footerSegments("Row 1/5", `GuardMe is ${snapshot.guardMe}`, `insecure edits ${snapshot.insecureEdits ? "ON" : "OFF"}`, `diagnostics ${diagnosticsSummary(snapshot.diagnostics)}`);
  }
}

function policiesFooter(_selectedIndex: number): string {
  return footerSegments("2/4", "Global policy applies across projects", "project policy applies only here when trusted");
}

function rulesFooter(snapshot: ConfigSnapshot, _selectedIndex: number): string {
  return footerSegments("3/4", "Category rows can overlap", `Total is ${snapshot.policyRules} active rules`, "Use Setup or edit YAML");
}


function confirmFooter(plan: SetupWritePlan, selectedIndex: number): string {
  switch (selectedIndex) {
    case 0:
      return footerSegments(
        "1/3",
        plan.policyKind === "append" ? `Append to ${setupScopeLabel(plan.scope)}` : `Write ${setupScopeLabel(plan.scope)}`,
        `from ${setupPolicyKindLabel(plan.policyKind)}`,
        plan.policyKind === "append"
          ? plan.existing
            ? "updates the existing policy file"
            : "creates a new policy file"
          : plan.existing
            ? "overwrites the existing policy file"
            : "creates a new policy file",
      );
    case 1:
      return footerSegments("2/3", "Return to setup options", "no files will be written");
    case 2:
    default:
      return footerSegments("3/3", "Cancel /guardme", "no files will be written");
  }
}

function sidebarForPane(activePane: ConfigPane): readonly FrameSidebarItem[] {
  return CONFIG_PANES.map((pane) => ({ label: pane, active: pane === activePane }));
}

function paneIsReadOnly(pane: ConfigPane): boolean {
  return pane !== "Setup" && pane !== "General";
}

function moveSidebarSelection(state: ConfigComponentState, delta: number): void {
  state.sidebarIndex = wrap(state.sidebarIndex + delta, 0, CONFIG_PANES.length - 1);
  state.pane = CONFIG_PANES[state.sidebarIndex] ?? "Setup";
  if (paneIsReadOnly(state.pane)) {
    state.focus = "sidebar";
  }
}

function selectedIndexForPane(pane: ConfigPane, state: ConfigComponentState | undefined): number {
  if (!state) {
    return 0;
  }
  switch (pane) {
    case "Setup":
      return state.setupIndex;
    case "General":
      return state.statusIndex;
    case "Policies":
      return state.policiesIndex;
    case "Rules":
      return state.rulesIndex;
  }
}

function moveSelection(state: ConfigComponentState, delta: number, snapshot: ConfigSnapshot): void {
  switch (state.pane) {
    case "Setup":
      state.setupIndex = wrap(state.setupIndex + delta, 0, SETUP_MODE_CHOICES.length - 1);
      return;
    case "General":
      state.statusIndex = wrap(state.statusIndex + delta, 0, 4);
      return;
    case "Policies":
      state.policiesIndex = wrap(state.policiesIndex + delta, 0, 3);
      return;
    case "Rules":
      state.rulesIndex = wrap(state.rulesIndex + delta, 0, Math.max(0, snapshot.ruleGroups.length - 1));
      return;
  }
}

function setupModeAt(index: number): SetupMode {
  return SETUP_MODE_CHOICES[index]?.mode ?? "global-defaults";
}

function diagnosticsSummary(diagnostics: readonly PolicyDiagnostic[]): string {
  if (diagnostics.length === 0) {
    return "none";
  }
  const errors = diagnostics.filter((diagnostic) => diagnostic.severity === "error").length;
  const warnings = diagnostics.filter((diagnostic) => diagnostic.severity === "warning").length;
  const parts = [
    errors > 0 ? `${errors} error${errors === 1 ? "" : "s"}` : undefined,
    warnings > 0 ? `${warnings} warning${warnings === 1 ? "" : "s"}` : undefined,
  ].filter(Boolean);
  return parts.length > 0 ? parts.join(", ") : `${diagnostics.length} diagnostic${diagnostics.length === 1 ? "" : "s"}`;
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

function wrap(value: number, min: number, max: number): number {
  if (max < min) {
    return min;
  }
  const length = max - min + 1;
  return ((((value - min) % length) + length) % length) + min;
}

function formatConfigActionError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isUp(data: string): boolean {
  return data === "\u001B[A" || data === "k";
}

function isDown(data: string): boolean {
  return data === "\u001B[B" || data === "j";
}

function isEnter(data: string): boolean {
  return data === "\r" || data === "\n";
}

function isEscape(data: string): boolean {
  const normalized = data.toLowerCase();
  return (
    data === "\u001B" ||
    normalized === "escape" ||
    normalized === "esc" ||
    /^\u001B\[27(?:;1)?(?::1)?u$/.test(data) ||
    data === "\u001B[27;1;27~"
  );
}

function isTab(data: string): boolean {
  return data === "\t" || data === "tab";
}

function isBackspace(data: string): boolean {
  return data === "\b" || data === "\u007F" || data === "backspace";
}

function isPrintable(data: string): boolean {
  return data.length === 1 && data >= " " && data !== "\u007F";
}

function isQuit(data: string): boolean {
  return data === "q" || data === "Q";
}
