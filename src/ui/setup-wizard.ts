import type { GuardMePolicyConfig, GuardMeRule, PolicyConfigSection } from "../config/schema.ts";
import { COMMAND_RULE_SECTIONS, PATH_RULE_SECTIONS, createEmptyPolicyConfig } from "../config/schema.ts";
import type { PolicyAction } from "../policy/action.ts";
import { footerSegments, type FrameMainRow, renderGuardMeFrame } from "./config-frame.ts";
import { isBackspace, isCtrlC, isDown, isEnter, isEscape, isPrintable, isQuit, isUp } from "./key-input.ts";

export type SetupScope = "global" | "local";
export type SetupMode =
  | "global-defaults"
  | "local-defaults"
  | "global-custom"
  | "local-custom"
  | "global-add-rule"
  | "local-add-rule"
  | "cancel";
export type SetupWriteMode = "replace" | "append";

export interface SetupWizardConfig {
  readonly scope: SetupScope;
  readonly config: GuardMePolicyConfig;
  readonly summary: string;
  readonly writeMode?: SetupWriteMode;
}

export interface SetupWizardContext {
  readonly cwd: string;
  readonly hasUI: boolean;
  readonly mode?: string;
  readonly ui: {
    readonly custom?: <T>(factory: (...args: any[]) => unknown, options?: Record<string, unknown>) => Promise<T>;
    readonly select?: (title: string, options: string[]) => Promise<string | undefined>;
    readonly input?: (title: string, placeholder?: string) => Promise<string | undefined>;
    readonly confirm?: (title: string, message: string) => Promise<boolean>;
  };
}

interface SetupModeChoice {
  readonly mode: SetupMode;
  readonly label: string;
  readonly description: string;
}

type RuleSectionSelection = PolicyConfigSection | "save";

interface RuleSectionChoice {
  readonly section: RuleSectionSelection;
  readonly label: string;
  readonly value: string;
  readonly description: string;
}

export const SETUP_MODE_CHOICES: readonly SetupModeChoice[] = [
  {
    mode: "global-defaults",
    label: "Create global policy with sensible defaults",
    description: "Recommended first install. Writes ~/.pi/agent/guardme.yaml.",
  },
  {
    mode: "local-defaults",
    label: "Create project policy with sensible defaults",
    description: "Writes .pi/agent/guardme.yaml for this project only.",
  },
  {
    mode: "global-custom",
    label: "Build custom global policy",
    description: "Build a global policy from defaults or from a blank policy.",
  },
  {
    mode: "local-custom",
    label: "Build custom project policy",
    description: "Build a project policy from defaults or from a blank policy.",
  },
  {
    mode: "global-add-rule",
    label: "Add custom rule globally",
    description: "Append custom rules to ~/.pi/agent/guardme.yaml without replacing existing rules.",
  },
  {
    mode: "local-add-rule",
    label: "Add custom rule locally",
    description: "Append custom rules to .pi/agent/guardme.yaml without replacing existing rules.",
  },
];

const SETUP_MODE_GROUP_ENDS = new Set<SetupMode>(["local-defaults", "local-custom"]);

export function setupModeRows(selectedIndex: number, options: { readonly includeDescriptions?: boolean } = {}): readonly FrameMainRow[] {
  return SETUP_MODE_CHOICES.flatMap<FrameMainRow>((choice, index) => {
    const row: FrameMainRow = {
      kind: "text",
      text: choice.label,
      selected: index === selectedIndex,
      ...(options.includeDescriptions ? { description: choice.description } : {}),
    };
    return SETUP_MODE_GROUP_ENDS.has(choice.mode) ? [row, { kind: "blank" }] : [row];
  });
}

const ALL_ACTIONS: readonly PolicyAction[] = ["read", "list", "write", "edit", "delete", "move", "rename"];
const ALL_ACTION_SET: ReadonlySet<string> = new Set(ALL_ACTIONS);
const PATH_RULE_SECTION_SET: ReadonlySet<string> = new Set(PATH_RULE_SECTIONS);
const DEFAULT_DELETE_ACTIONS: readonly PolicyAction[] = ["delete", "move", "rename"];
const DEFAULT_READONLY_ACTIONS: readonly PolicyAction[] = ["read", "list"];
const CONFIG_FRAME_BODY_ROWS = 11;
const CONFIG_PANE_LABELS = ["General", "Policies", "Rules", "Setup"] as const;

export async function requestSetupConfiguration(
  ctx: SetupWizardContext,
  sensibleDefaults: GuardMePolicyConfig,
): Promise<SetupWizardConfig | undefined> {
  if (!ctx.hasUI) {
    return undefined;
  }

  const mode = await requestSetupMode(ctx);
  if (!mode || mode === "cancel") {
    return undefined;
  }

  const defaultsConfig = setupConfigForMode(mode, sensibleDefaults);
  if (defaultsConfig) {
    return defaultsConfig;
  }

  const scope: SetupScope = mode.startsWith("global") ? "global" : "local";
  if (isAddRuleSetupMode(mode)) {
    const config = await collectCustomRuleAdditions(ctx, scope);
    if (!config || countRules(config) === 0) {
      return undefined;
    }
    return createAppendRulesSetupConfig(scope, config);
  }

  const config = await collectCustomPolicy(ctx, sensibleDefaults, scope);
  if (!config) {
    return undefined;
  }

  return {
    scope,
    config,
    summary: `custom ${setupScopeLabel(scope)} (${countRules(config)} rule${countRules(config) === 1 ? "" : "s"})`,
    writeMode: "replace",
  };
}

export async function requestSetupMode(ctx: SetupWizardContext): Promise<SetupMode | undefined> {
  if (ctx.mode === "tui" && typeof ctx.ui.custom === "function") {
    const selected = await ctx.ui.custom<SetupMode | undefined>(
      (tui: { requestRender?: () => void }, theme: SetupTheme, _keybindings: unknown, done: (value: SetupMode | undefined) => void) =>
        createSetupModeComponent(tui, theme, done),
    );
    return selected;
  }

  if (typeof ctx.ui.select === "function") {
    const labels = SETUP_MODE_CHOICES.map((choice) => `${choice.label} — ${choice.description}`);
    const selected = await ctx.ui.select("GuardMe setup", labels);
    const selectedIndex = labels.findIndex((label, index) => label === selected || Boolean(selected?.startsWith(SETUP_MODE_CHOICES[index]!.label)));
    return selectedIndex >= 0 ? SETUP_MODE_CHOICES[selectedIndex]?.mode : undefined;
  }

  return undefined;
}

export async function collectCustomPolicy(
  ctx: SetupWizardContext,
  sensibleDefaults: GuardMePolicyConfig,
  scope?: SetupScope,
  initialConfig?: GuardMePolicyConfig,
): Promise<GuardMePolicyConfig | undefined> {
  if (!hasCustomPolicyInputs(ctx)) {
    return undefined;
  }

  const effectiveScope = scope ?? "local";
  const config = await initialCustomPolicyConfig(ctx, sensibleDefaults, effectiveScope, initialConfig);
  return config ? collectCustomPolicyRules(ctx, effectiveScope, config) : undefined;
}

function hasCustomPolicyInputs(ctx: SetupWizardContext): boolean {
  const hasTuiCustom = ctx.mode === "tui" && typeof ctx.ui.custom === "function";
  return Boolean(hasTuiCustom || (ctx.ui.input && ctx.ui.confirm && ctx.ui.select));
}

async function initialCustomPolicyConfig(
  ctx: SetupWizardContext,
  sensibleDefaults: GuardMePolicyConfig,
  scope: SetupScope,
  initialConfig?: GuardMePolicyConfig,
): Promise<GuardMePolicyConfig> {
  if (initialConfig) {
    return clonePolicyConfig(initialConfig);
  }

  const defaultRuleCount = countRules(sensibleDefaults);
  const startFromDefaults = await requestSetupBoolean(ctx, {
    title: "Start from sensible defaults?",
    message: "Choose starting rules before adding custom entries.",
    heading: "CUSTOM POLICY START",
    context: `${setupScopeContext(scope)} • choose defaults or blank`,
    yesLabel: "Yes, keep defaults",
    yesValue: `${defaultRuleCount} rules`,
    yesDescription: "Keep GuardMe's recommended protections, then add custom rules.",
    noLabel: "No, start blank",
    noValue: "0 rules",
    noDescription: "Write only the custom rules you add in this setup flow.",
  });
  return startFromDefaults ? clonePolicyConfig(sensibleDefaults) : createEmptyPolicyConfig();
}

async function collectCustomPolicyRules(
  ctx: SetupWizardContext,
  scope: SetupScope,
  initialConfig: GuardMePolicyConfig,
): Promise<GuardMePolicyConfig | undefined> {
  let config = initialConfig;
  while (true) {
    const section = await chooseRuleSection(ctx, scope);
    if (!section) {
      return undefined;
    }
    if (section === "save") {
      return config;
    }

    const rule = await promptForRule(ctx, section, scope);
    if (rule) {
      config = appendSetupRule(config, section, rule);
    }

    if (!(await shouldAddAnotherRule(ctx, scope))) {
      return config;
    }
  }
}

async function shouldAddAnotherRule(ctx: SetupWizardContext, scope: SetupScope): Promise<boolean> {
  return requestSetupBoolean(ctx, {
    title: "Add another GuardMe rule?",
    message: "Continue adding custom rules or move on to write confirmation.",
    heading: "CUSTOM RULES",
    context: `${setupScopeContext(scope)} • add rules or confirm`,
    yesLabel: "Yes, add another rule",
    yesValue: "continue",
    yesDescription: "Choose another rule section before saving.",
    noLabel: "No, save policy",
    noValue: "confirm",
    noDescription: "Continue to the policy write confirmation.",
  });
}

export async function collectCustomRuleAdditions(
  ctx: SetupWizardContext,
  scope: SetupScope = "local",
  initialConfig?: GuardMePolicyConfig,
): Promise<GuardMePolicyConfig | undefined> {
  const hasTuiCustom = ctx.mode === "tui" && typeof ctx.ui.custom === "function";
  if ((!ctx.ui.input && !hasTuiCustom) || (!ctx.ui.select && !hasTuiCustom)) {
    return undefined;
  }

  let config = initialConfig ? clonePolicyConfig(initialConfig) : createEmptyPolicyConfig();
  while (true) {
    const section = await chooseRuleSection(ctx, scope);
    if (!section) {
      return undefined;
    }
    if (section === "save") {
      return config;
    }

    const rule = await promptForRule(ctx, section, scope);
    if (rule) {
      config = appendSetupRule(config, section, rule);
    }
  }
}

export function createAppendRulesSetupConfig(scope: SetupScope, config: GuardMePolicyConfig): SetupWizardConfig {
  const rules = countRules(config);
  return {
    scope,
    config,
    summary: `append custom rules to ${setupScopeLabel(scope)} (${rules} rule${rules === 1 ? "" : "s"})`,
    writeMode: "append",
  };
}

interface SetupBooleanPrompt {
  readonly title: string;
  readonly message: string;
  readonly heading: string;
  readonly context: string;
  readonly yesLabel: string;
  readonly yesValue: string;
  readonly yesDescription: string;
  readonly noLabel: string;
  readonly noValue: string;
  readonly noDescription: string;
}

async function requestSetupBoolean(ctx: SetupWizardContext, prompt: SetupBooleanPrompt): Promise<boolean> {
  if (ctx.mode === "tui" && typeof ctx.ui.custom === "function") {
    const selected = await ctx.ui.custom<boolean | undefined>(
      (tui: { requestRender?: () => void }, theme: SetupTheme, _keybindings: unknown, done: (value: boolean | undefined) => void) =>
        createSetupBooleanComponent(tui, theme, done, prompt),
    );
    return selected ?? false;
  }

  return (await ctx.ui.confirm?.(prompt.title, prompt.message)) ?? false;
}

function createSetupModeComponent(
  tui: { requestRender?: () => void },
  theme: SetupTheme,
  done: (value: SetupMode | undefined) => void,
): { render: (width: number) => string[]; invalidate: () => void; handleInput: (data: string) => void } {
  let selectedIndex = 0;
  let cachedWidth: number | undefined;
  let cachedLines: string[] | undefined;

  const invalidate = () => {
    cachedWidth = undefined;
    cachedLines = undefined;
  };

  return {
    render(width: number): string[] {
      if (cachedLines && cachedWidth === width) {
        return cachedLines;
      }
      cachedWidth = width;
      cachedLines = buildSetupModeLines(width, theme, selectedIndex);
      return cachedLines;
    },
    invalidate,
    handleInput(data: string): void {
      if (isUp(data)) {
        selectedIndex = wrapIndex(selectedIndex - 1, SETUP_MODE_CHOICES.length);
        invalidate();
        tui.requestRender?.();
        return;
      }
      if (isDown(data)) {
        selectedIndex = wrapIndex(selectedIndex + 1, SETUP_MODE_CHOICES.length);
        invalidate();
        tui.requestRender?.();
        return;
      }
      if (isEnter(data)) {
        done(SETUP_MODE_CHOICES[selectedIndex]?.mode);
        return;
      }
      if (isEscape(data) || isQuit(data)) {
        done(undefined);
      }
    },
  };
}

function createSetupBooleanComponent(
  tui: { requestRender?: () => void },
  theme: SetupTheme,
  done: (value: boolean | undefined) => void,
  prompt: SetupBooleanPrompt,
): { render: (width: number) => string[]; invalidate: () => void; handleInput: (data: string) => void } {
  let selectedIndex = 0;
  let cachedWidth: number | undefined;
  let cachedLines: string[] | undefined;

  const invalidate = () => {
    cachedWidth = undefined;
    cachedLines = undefined;
  };

  return {
    render(width: number): string[] {
      if (cachedLines && cachedWidth === width) {
        return cachedLines;
      }
      cachedWidth = width;
      cachedLines = buildSetupBooleanLines(width, theme, prompt, selectedIndex);
      return cachedLines;
    },
    invalidate,
    handleInput(data: string): void {
      if (isUp(data) || isDown(data)) {
        selectedIndex = selectedIndex === 0 ? 1 : 0;
        invalidate();
        tui.requestRender?.();
        return;
      }
      if (isEnter(data)) {
        done(selectedIndex === 0);
        return;
      }
      if (isEscape(data) || isQuit(data)) {
        done(undefined);
      }
    },
  };
}

function buildSetupBooleanLines(width: number, theme: SetupTheme, prompt: SetupBooleanPrompt, selectedIndex: number): string[] {
  const selectedDescription = selectedIndex === 0 ? prompt.yesDescription : prompt.noDescription;
  const rows: FrameMainRow[] = [
    { kind: "heading", label: prompt.heading, value: `${selectedIndex + 1}/2` },
    { kind: "text", text: prompt.title },
    { kind: "text", text: prompt.message },
    { kind: "blank" },
    { kind: "value", label: prompt.yesLabel, value: prompt.yesValue, valueKind: "text", selected: selectedIndex === 0 },
    { kind: "value", label: prompt.noLabel, value: prompt.noValue, valueKind: "text", selected: selectedIndex === 1 },
  ];

  return renderGuardMeFrame(
    {
      title: "GuardMe",
      activePane: "Setup",
      context: prompt.context,
      keys: "↑↓ choice  Enter select  Esc/q quit",
      sidebar: CONFIG_PANE_LABELS.map((label) => ({ label, active: label === "Setup" })),
      rows,
      footer: footerSegments(`${selectedIndex + 1}/2`, selectedDescription),
      minContentRows: CONFIG_FRAME_BODY_ROWS,
      focus: "main",
      theme,
    },
    width,
  );
}

function buildSetupModeLines(width: number, theme: SetupTheme, selectedIndex: number): string[] {
  const rows: FrameMainRow[] = [
    { kind: "heading", label: "SETUP", value: `${selectedIndex + 1}/${SETUP_MODE_CHOICES.length}` },
    ...setupModeRows(selectedIndex),
  ];

  return renderGuardMeFrame(
    {
      title: "GuardMe",
      activePane: "Setup",
      context: "GuardMe setup • writes ~/.pi/agent/guardme.yaml or .pi/agent/guardme.yaml • custom rules available",
      keys: "↑↓ option  Enter select  Esc/q quit",
      sidebar: CONFIG_PANE_LABELS.map((label) => ({ label, active: label === "Setup" })),
      rows,
      footer: setupModeFooter(selectedIndex),
      minContentRows: CONFIG_FRAME_BODY_ROWS,
      focus: "main",
      theme,
    },
    width,
  );
}

function setupModeFooter(selectedIndex: number): string {
  const index = wrapIndex(selectedIndex, SETUP_MODE_CHOICES.length);
  const choice = SETUP_MODE_CHOICES[index];
  return footerSegments(`${index + 1}/${SETUP_MODE_CHOICES.length}`, choice?.description ?? "Choose a GuardMe setup action.");
}

async function chooseRuleSection(ctx: SetupWizardContext, scope: SetupScope): Promise<RuleSectionSelection | undefined> {
  const choices = ruleSectionChoices();
  if (ctx.mode === "tui" && typeof ctx.ui.custom === "function") {
    return ctx.ui.custom<RuleSectionSelection | undefined>(
      (tui: { requestRender?: () => void }, theme: SetupTheme, _keybindings: unknown, done: (value: RuleSectionSelection | undefined) => void) =>
        createRuleSectionComponent(tui, theme, done, choices, scope),
    );
  }

  const labels = choices.map((choice) => `${choice.label} — ${choice.description}`);
  const selected = await ctx.ui.select?.("Choose rule section", labels);
  const index = selected === undefined ? -1 : labels.indexOf(selected);
  return index >= 0 ? choices[index]?.section : undefined;
}

function createRuleSectionComponent(
  tui: { requestRender?: () => void },
  theme: SetupTheme,
  done: (value: RuleSectionSelection | undefined) => void,
  choices: readonly RuleSectionChoice[],
  scope: SetupScope,
): { render: (width: number) => string[]; invalidate: () => void; handleInput: (data: string) => void } {
  let selectedIndex = 0;
  let cachedWidth: number | undefined;
  let cachedLines: string[] | undefined;

  const invalidate = () => {
    cachedWidth = undefined;
    cachedLines = undefined;
  };

  return {
    render(width: number): string[] {
      if (cachedLines && cachedWidth === width) {
        return cachedLines;
      }
      cachedWidth = width;
      cachedLines = buildRuleSectionLines(width, theme, choices, selectedIndex, scope);
      return cachedLines;
    },
    invalidate,
    handleInput(data: string): void {
      if (isUp(data)) {
        selectedIndex = wrapIndex(selectedIndex - 1, choices.length);
        invalidate();
        tui.requestRender?.();
        return;
      }
      if (isDown(data)) {
        selectedIndex = wrapIndex(selectedIndex + 1, choices.length);
        invalidate();
        tui.requestRender?.();
        return;
      }
      if (isEnter(data)) {
        done(choices[selectedIndex]?.section);
        return;
      }
      if (isEscape(data) || isQuit(data)) {
        done(undefined);
      }
    },
  };
}

function buildRuleSectionLines(
  width: number,
  theme: SetupTheme,
  choices: readonly RuleSectionChoice[],
  selectedIndex: number,
  scope: SetupScope,
): string[] {
  const counter = choices.length === 0 ? "0/0" : `${selectedIndex + 1}/${choices.length}`;
  const rows: FrameMainRow[] = [
    { kind: "heading", label: "RULE SECTION", value: counter },
    ...choices.map<FrameMainRow>((choice, index) => ({
      kind: "value",
      label: choice.label,
      value: choice.value,
      valueKind: "text",
      selected: index === selectedIndex,
      description: choice.description,
    })),
  ];

  return renderGuardMeFrame(
    {
      title: "GuardMe",
      activePane: "Setup",
      context: setupScopeContext(scope),
      keys: "↑↓ section  Enter select  Esc/q quit",
      sidebar: CONFIG_PANE_LABELS.map((label) => ({ label, active: label === "Setup" })),
      rows,
      footer: ruleSectionFooter(choices, selectedIndex, scope),
      minContentRows: CONFIG_FRAME_BODY_ROWS,
      focus: "main",
      theme,
    },
    width,
  );
}

function ruleSectionFooter(choices: readonly RuleSectionChoice[], selectedIndex: number, scope: SetupScope): string {
  const selected = choices[selectedIndex];
  if (!selected) {
    return footerSegments("0/0", "No rule sections available");
  }
  return footerSegments(`${selectedIndex + 1}/${choices.length}`, setupScopeLabel(scope), selected.description);
}

function setupScopeContext(scope: SetupScope): string {
  return `custom ${setupScopeLabel(scope)} • writes ${setupScopeTarget(scope)}`;
}

export function setupScopeLabel(scope: SetupScope): string {
  return scope === "global" ? "global policy" : "project policy";
}

function setupScopeTarget(scope: SetupScope): string {
  return scope === "global" ? "~/.pi/agent/guardme.yaml" : ".pi/agent/guardme.yaml";
}

function ruleSectionChoices(): readonly RuleSectionChoice[] {
  const sections = [...PATH_RULE_SECTIONS, ...COMMAND_RULE_SECTIONS, "save"] as const;
  return sections.map((section) => ({
    section,
    label: ruleSectionLabel(section),
    value: ruleSectionValue(section),
    description: ruleSectionDescription(section),
  }));
}

function ruleSectionLabel(section: RuleSectionSelection): string {
  return section === "save" ? "Save policy" : section;
}

function ruleSectionValue(section: RuleSectionSelection): string {
  if (section === "save") {
    return "done";
  }
  return isPathSection(section) ? "path" : "command";
}

function ruleSectionDescription(section: RuleSectionSelection): string {
  if (section === "save") {
    return "Finish custom policy and continue to confirmation.";
  }
  return sectionDescription(section);
}

async function promptForRule(
  ctx: SetupWizardContext,
  section: PolicyConfigSection,
  scope: SetupScope,
): Promise<GuardMeRule | undefined> {
  const pattern = (await requestSetupTextInput(ctx, scope, {
    title: `Pattern for ${section}`,
    heading: `Pattern for ${section}`,
    placeholder: section.includes("Commands") ? "npm run test*" : "src/**",
    footer: sectionDescription(section),
  }))?.trim();
  if (!pattern) {
    return undefined;
  }

  const actions = isPathSection(section) ? await promptForActions(ctx, section, scope) : [];
  if (!actions) {
    return undefined;
  }
  const reason = (await requestSetupTextInput(ctx, scope, {
    title: "Reason for this rule",
    heading: "Rule reason",
    placeholder: "Why this rule exists",
    footer: "optional reason saved with the rule",
  }))?.trim();
  return {
    pattern,
    ...(actions.length > 0 ? { actions } : {}),
    ...(reason ? { reason } : {}),
  };
}

async function promptForActions(
  ctx: SetupWizardContext,
  section: PolicyConfigSection,
  scope: SetupScope,
): Promise<readonly PolicyAction[] | undefined> {
  const defaultActions = defaultActionsForSection(section);
  const raw = (await requestSetupTextInput(ctx, scope, {
    title: `Actions for ${section}`,
    heading: `Actions for ${section}`,
    placeholder: `${defaultActions.join(",")} (blank keeps this default)`,
    footer: "comma or space separated path actions",
  }))?.trim();
  if (!raw) {
    return defaultActions;
  }

  const actions = raw
    .split(/[\s,]+/)
    .map((action) => action.trim())
    .filter((action): action is PolicyAction => ALL_ACTION_SET.has(action));
  return actions.length > 0 ? [...new Set(actions)] : undefined;
}

interface SetupTextInputPrompt {
  readonly title: string;
  readonly heading: string;
  readonly placeholder?: string;
  readonly footer: string;
}

async function requestSetupTextInput(
  ctx: SetupWizardContext,
  scope: SetupScope,
  prompt: SetupTextInputPrompt,
): Promise<string | undefined> {
  if (ctx.mode === "tui" && typeof ctx.ui.custom === "function") {
    return ctx.ui.custom<string | undefined>(
      (tui: { requestRender?: () => void }, theme: SetupTheme, _keybindings: unknown, done: (value: string | undefined) => void) =>
        createSetupTextInputComponent(tui, theme, done, prompt, scope),
    );
  }

  return ctx.ui.input?.(prompt.title, prompt.placeholder);
}

function createSetupTextInputComponent(
  tui: { requestRender?: () => void },
  theme: SetupTheme,
  done: (value: string | undefined) => void,
  prompt: SetupTextInputPrompt,
  scope: SetupScope,
): { render: (width: number) => string[]; invalidate: () => void; handleInput: (data: string) => void } {
  let value = "";
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

  return {
    render(width: number): string[] {
      const key = JSON.stringify({ width, value });
      if (cachedLines && cachedKey === key) {
        return cachedLines;
      }
      cachedKey = key;
      cachedLines = buildSetupTextInputLines(width, theme, prompt, scope, value);
      return cachedLines;
    },
    invalidate,
    handleInput(data: string): void {
      if (isEnter(data)) {
        done(value);
        return;
      }
      if (isEscape(data) || isCtrlC(data)) {
        done(undefined);
        return;
      }
      if (isBackspace(data)) {
        value = Array.from(value).slice(0, -1).join("");
        rerender();
        return;
      }
      if (isPrintable(data)) {
        value = `${value}${data}`;
        rerender();
      }
    },
  };
}

function buildSetupTextInputLines(
  width: number,
  theme: SetupTheme,
  prompt: SetupTextInputPrompt,
  scope: SetupScope,
  value: string,
): string[] {
  const rows: FrameMainRow[] = [
    { kind: "heading", label: prompt.heading, value: "input" },
    { kind: "text", text: prompt.title },
    { kind: "blank" },
    { kind: "text", text: `> ${value}`, selected: true },
    ...(value.length === 0 && prompt.placeholder ? [{ kind: "text", text: `placeholder: ${prompt.placeholder}`, tone: "dim" } satisfies FrameMainRow] : []),
    { kind: "blank" },
    { kind: "text", text: "Enter submits this value without leaving GuardMe Config.", tone: "dim" },
  ];

  return renderGuardMeFrame(
    {
      title: "GuardMe",
      activePane: "Setup",
      context: setupScopeContext(scope),
      keys: "type value  Enter submit  Esc/Ctrl-C cancel",
      sidebar: CONFIG_PANE_LABELS.map((label) => ({ label, active: label === "Setup" })),
      rows,
      footer: footerSegments(prompt.title, prompt.footer),
      minContentRows: CONFIG_FRAME_BODY_ROWS,
      focus: "main",
      theme,
    },
    width,
  );
}

function appendSetupRule(
  config: GuardMePolicyConfig,
  section: PolicyConfigSection,
  rule: GuardMeRule,
): GuardMePolicyConfig {
  return {
    ...config,
    [section]: [...config[section], rule],
  };
}

function clonePolicyConfig(config: GuardMePolicyConfig): GuardMePolicyConfig {
  return {
    version: config.version,
    allowPaths: config.allowPaths.map((rule) => ({ ...rule })),
    denyPaths: config.denyPaths.map((rule) => ({ ...rule })),
    zeroAccessPaths: config.zeroAccessPaths.map((rule) => ({ ...rule })),
    readOnlyPaths: config.readOnlyPaths.map((rule) => ({ ...rule })),
    noDeletePaths: config.noDeletePaths.map((rule) => ({ ...rule })),
    allowCommands: config.allowCommands.map((rule) => ({ ...rule })),
    denyCommands: config.denyCommands.map((rule) => ({ ...rule })),
    dangerousCommands: config.dangerousCommands.map((rule) => ({ ...rule })),
    protectedCredentialPaths: config.protectedCredentialPaths.map((rule) => ({ ...rule })),
  };
}

export function setupConfigForMode(mode: SetupMode, sensibleDefaults: GuardMePolicyConfig): SetupWizardConfig | undefined {
  if (mode === "global-defaults" || mode === "local-defaults") {
    const scope: SetupScope = mode.startsWith("global") ? "global" : "local";
    return {
      scope,
      config: sensibleDefaults,
      summary: `${setupScopeLabel(scope)} with sensible GuardMe defaults`,
      writeMode: "replace",
    };
  }
  return undefined;
}

function isAddRuleSetupMode(mode: SetupMode): boolean {
  return mode === "global-add-rule" || mode === "local-add-rule";
}

export function countSetupRules(config: GuardMePolicyConfig): number {
  return countRules(config);
}

function countRules(config: GuardMePolicyConfig): number {
  return [...PATH_RULE_SECTIONS, ...COMMAND_RULE_SECTIONS].reduce((count, section) => count + config[section].length, 0);
}

function defaultActionsForSection(section: PolicyConfigSection): readonly PolicyAction[] {
  if (section === "allowPaths" || section === "readOnlyPaths") {
    return DEFAULT_READONLY_ACTIONS;
  }
  if (section === "noDeletePaths") {
    return DEFAULT_DELETE_ACTIONS;
  }
  return ALL_ACTIONS;
}

function isPathSection(section: PolicyConfigSection): boolean {
  return PATH_RULE_SECTION_SET.has(section);
}

function sectionDescription(section: PolicyConfigSection): string {
  switch (section) {
    case "allowPaths":
      return "allow matching path actions";
    case "denyPaths":
      return "deny matching path actions";
    case "zeroAccessPaths":
      return "block all access to matching paths";
    case "readOnlyPaths":
      return "allow reads/lists but block mutations";
    case "noDeletePaths":
      return "block delete/move/rename";
    case "allowCommands":
      return "allow matching shell commands";
    case "denyCommands":
      return "deny matching shell commands";
    case "dangerousCommands":
      return "coach first, then request approval";
    case "protectedCredentialPaths":
      return "protect credential-like paths";
  }
}

interface SetupTheme {
  readonly fg?: (color: string, text: string) => string;
}

function wrapIndex(index: number, length: number): number {
  if (length <= 0) {
    return 0;
  }
  return ((index % length) + length) % length;
}

