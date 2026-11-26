import type { ApprovalMode } from "../config/approval-mode.ts";
import type { ApprovalRule, ApprovalScope } from "../config/write-policy.ts";
import type { PolicyDecision, PolicyRequest, UserDecision } from "../policy/action.ts";
import { isUserDecision } from "../policy/action.ts";
import { fitCell, type ConfigFrameTheme } from "./config-frame.ts";
import { isDown, isEnter, isEscape, isUp, type KeybindingManager } from "./key-input.ts";
import { redactSensitiveText, renderMatchedRules, renderPolicySummary, type PolicySummaryLine } from "./render-policy-summary.ts";
import { truncateToVisibleWidth, visibleWidth } from "./text.ts";

export type ApprovalResult =
  | { readonly kind: "decision"; readonly decision: UserDecision }
  | { readonly kind: "blocked"; readonly reason: string };

export interface ApprovalUiContext {
  readonly cwd: string;
  readonly hasUI: boolean;
  readonly mode?: string;
  readonly approvalMode: ApprovalMode;
  readonly ui: {
    readonly custom?: <T>(factory: (...args: any[]) => unknown, options?: Record<string, unknown>) => Promise<T>;
    readonly select?: (title: string, options: readonly string[]) => Promise<string | undefined>;
  };
  /** The rule a saved choice writes; limits and orders the choices. */
  readonly rule: ApprovalRule;
}

export interface ApprovalChoice {
  readonly decision: UserDecision;
  readonly scope: ApprovalScope;
  readonly label: string;
  readonly description: string;
}

// Orchestrators answer by these labels; keep them fixed.
export const APPROVAL_CHOICES: readonly ApprovalChoice[] = [
  { decision: "allow-once", scope: "once", label: "Allow once", description: "Run this call only; do not save a rule." },
  { decision: "allow-session", scope: "session", label: "Allow for session", description: "Run now and allow the rule until this session ends." },
  { decision: "allow-local", scope: "project", label: "Allow for project", description: "Run now and save an allow rule in .pi/guardme.yaml." },
  { decision: "allow-global", scope: "global", label: "Allow globally", description: "Run now and save an allow rule in ~/.pi/agent/guardme.yaml." },
  { decision: "deny-once", scope: "once", label: "Deny once", description: "Block this call only; do not save a rule." },
  { decision: "deny-session", scope: "session", label: "Deny for session", description: "Block now and deny the rule until this session ends." },
  { decision: "deny-local", scope: "project", label: "Deny for project", description: "Block now and save a deny rule in .pi/guardme.yaml." },
  { decision: "deny-global", scope: "global", label: "Deny globally", description: "Block now and save a deny rule in ~/.pi/agent/guardme.yaml." },
];

/**
 * The choices of one prompt in drawn order. The first row is where the cursor
 * starts, so the deny group leads unless the risk is low: a stray Enter must
 * not approve.
 */
export function approvalChoices(risk: PolicyDecision["risk"], scopes: readonly ApprovalScope[]): readonly ApprovalChoice[] {
  const offered = APPROVAL_CHOICES.filter((choice) => scopes.includes(choice.scope));
  const allows = offered.filter((choice) => isAllowDecision(choice.decision));
  const denies = offered.filter((choice) => isDenyDecision(choice.decision));
  return risk === "low" ? [...allows, ...denies] : [...denies, ...allows];
}

/** "Saves: ..." line of the prompt. */
export function savedRuleSummary(rule: ApprovalRule): string {
  return rule.scopes.length > 1 ? `Saves: ${rule.pattern} (${rule.covers})` : "Saves: nothing, this request can only be answered once";
}

const MAX_APPROVAL_TARGET_WIDTH = 512;
const MAX_APPROVAL_REASON_WIDTH = 768;
const MAX_APPROVAL_RULE_WIDTH = 384;
const MAX_APPROVAL_UNAVAILABLE_WIDTH = 384;
const MAX_APPROVAL_MATCHED_RULES = 8;
const MAX_APPROVAL_BLOCK_LENGTH = 6144;

export const APPROVAL_UNAVAILABLE_NEXT_STEP =
  "Interactive approval is unavailable. Use a safe built-in tool, narrow the request, update GuardMe policy with a reviewed exact rule, or report this limitation. Do not retry the identical request unchanged.";

type ApprovalUiResolution =
  | { readonly kind: "custom" }
  | { readonly kind: "select" }
  | { readonly kind: "blocked"; readonly reason: string };

export function resolveApprovalUi(ctx: ApprovalUiContext): ApprovalUiResolution {
  if (ctx.approvalMode === "block") {
    return {
      kind: "blocked",
      reason: "GuardMe requires user approval for this action, but interactive approval is unavailable because approvalMode is 'block'. Blocking by default.",
    };
  }
  if (ctx.approvalMode === "auto" && ctx.mode !== "tui") {
    return {
      kind: "blocked",
      reason: `GuardMe requires user approval for this action, but interactive approval is unavailable because approvalMode is 'auto' and Pi mode is '${ctx.mode ?? "unknown"}', not 'tui'. Blocking by default.`,
    };
  }
  if (ctx.approvalMode === "agent") {
    return {
      kind: "blocked",
      reason: "GuardMe approvalMode 'agent' never invokes interactive approval UI in any run mode. The in-process retry gate must authorize an identical request from a later agent turn. Blocking by default.",
    };
  }
  if (!ctx.hasUI) {
    return {
      kind: "blocked",
      reason: "GuardMe requires user approval for this action, but this Pi session has no UI. Blocking by default.",
    };
  }
  // "list": a plain list an orchestrator can answer with arrow keys, without reading a drawn box.
  if (ctx.approvalMode !== "list" && ctx.mode === "tui" && typeof ctx.ui.custom === "function") {
    return { kind: "custom" };
  }
  if (typeof ctx.ui.select === "function") {
    return { kind: "select" };
  }
  return {
    kind: "blocked",
    reason: "GuardMe requires user approval, but no approval UI is available. Blocking by default.",
  };
}

export async function requestApprovalDecision(
  ctx: ApprovalUiContext,
  request: PolicyRequest,
  decision: PolicyDecision,
): Promise<ApprovalResult> {
  const resolution = resolveApprovalUi(ctx);
  if (resolution.kind === "blocked") {
    return resolution;
  }
  if (resolution.kind === "custom") {
    try {
      const selected = await requestTuiApproval(ctx, request, decision);
      return selected ? { kind: "decision", decision: selected } : { kind: "decision", decision: "deny-once" };
    } catch {
      if (typeof ctx.ui.select !== "function") {
        return { kind: "decision", decision: "deny-once" };
      }
    }
  }

  try {
    const selected = await requestSelectApproval(ctx, request, decision);
    return selected ? { kind: "decision", decision: selected } : { kind: "decision", decision: "deny-once" };
  } catch {
    return { kind: "decision", decision: "deny-once" };
  }
}

/**
 * Compact agent-facing block notification for approvalMode 'agent': what was
 * blocked, why, and what to do instead — no interactive approval involved.
 */
export function formatAgentModeBlockReason(
  request: PolicyRequest,
  decision: PolicyDecision,
  note: string,
  nextStep: string,
): string {
  const summary = renderPolicySummary(request, decision);
  const toolAction = `${request.toolName}:${request.action}`;
  const lines = [
    `GuardMe blocked ${boundedApprovalValue(summaryValue(summary, "Action", toolAction), 128)} (${decision.risk}): ${boundedApprovalValue(summaryValue(summary, "Target", "<unknown>"), MAX_APPROVAL_TARGET_WIDTH)}`,
    `Reason: ${boundedApprovalValue(summaryValue(summary, "Reason", decision.reason), MAX_APPROVAL_REASON_WIDTH)}`,
    boundedApprovalValue(note, MAX_APPROVAL_REASON_WIDTH),
    `Next step: ${boundedApprovalValue(nextStep, MAX_APPROVAL_REASON_WIDTH)}`,
  ];
  return boundApprovalBlock(lines.join("\n"));
}

export function formatApprovalUnavailableBlockReason(
  request: PolicyRequest,
  decision: PolicyDecision,
  unavailableReason: string,
  nextStep: string = APPROVAL_UNAVAILABLE_NEXT_STEP,
): string {
  const summary = renderPolicySummary(request, decision);
  const displayedRules = renderMatchedRules(decision.matchedRules.slice(0, MAX_APPROVAL_MATCHED_RULES));
  const omittedRuleCount = Math.max(0, decision.matchedRules.length - MAX_APPROVAL_MATCHED_RULES);
  const toolAction = `${request.toolName}:${request.action}`;
  const lines = [
    "WARNINGS & DECISIONS",
    `Risk classification: ${boundedApprovalValue(summaryValue(summary, "Risk", decision.risk), 64)}`,
    `Guarded tool and action: ${boundedApprovalValue(summaryValue(summary, "Action", toolAction), 128)}`,
    `Target or command: ${boundedApprovalValue(summaryValue(summary, "Target", "<unknown>"), MAX_APPROVAL_TARGET_WIDTH)}`,
    `Reason: ${boundedApprovalValue(summaryValue(summary, "Reason", decision.reason), MAX_APPROVAL_REASON_WIDTH)}`,
    `Interactive approval: ${boundedApprovalValue(unavailableReason, MAX_APPROVAL_UNAVAILABLE_WIDTH)}`,
    `Next step: ${boundedApprovalValue(nextStep, MAX_APPROVAL_REASON_WIDTH)}`,
    "Matched rules:",
    ...displayedRules.map((rule) => `- ${boundedApprovalValue(rule, MAX_APPROVAL_RULE_WIDTH)}`),
    ...(omittedRuleCount > 0 ? [`- ${omittedRuleCount} additional matched rule${omittedRuleCount === 1 ? "" : "s"} omitted.`] : []),
  ];
  return boundApprovalBlock(lines.join("\n"));
}

function boundedApprovalValue(value: string, width: number): string {
  return truncateToVisibleWidth(redactSensitiveText(value), width);
}

function boundApprovalBlock(value: string): string {
  if (value.length <= MAX_APPROVAL_BLOCK_LENGTH) {
    return value;
  }
  return `${value.slice(0, MAX_APPROVAL_BLOCK_LENGTH - 32)}\n[GuardMe guidance truncated]`;
}

export function isAllowDecision(decision: UserDecision): boolean {
  return decision.startsWith("allow-");
}

export function isDenyDecision(decision: UserDecision): boolean {
  return decision.startsWith("deny-");
}

async function requestSelectApproval(
  ctx: ApprovalUiContext,
  request: PolicyRequest,
  decision: PolicyDecision,
): Promise<UserDecision | undefined> {
  const choices = approvalChoices(decision.risk, ctx.rule.scopes);
  const selected = await ctx.ui.select?.(approvalSelectTitle(request, decision, ctx.rule), choices.map((choice) => choice.label));
  return choices.find((choice) => choice.label === selected)?.decision;
}

export function approvalSelectTitle(request: PolicyRequest, decision: PolicyDecision, rule: ApprovalRule): string {
  const summary = renderPolicySummary(request, decision);
  const segment = blockedSegment(request, decision);
  return [
    `GuardMe approval required: ${request.toolName}:${request.action} (${decision.risk})`,
    `Target: ${boundedApprovalValue(summaryValue(summary, "Target", "<unknown>"), MAX_APPROVAL_TARGET_WIDTH)}`,
    ...(segment ? [`Blocked part: ${boundedApprovalValue(segment, MAX_APPROVAL_TARGET_WIDTH)}`] : []),
    `Reason: ${boundedApprovalValue(summaryValue(summary, "Reason", decision.reason), MAX_APPROVAL_REASON_WIDTH)}`,
    boundedApprovalValue(savedRuleSummary(rule), MAX_APPROVAL_RULE_WIDTH),
  ].join("\n");
}

/** The failing shell segment, when it is only a part of the command. */
function blockedSegment(request: PolicyRequest, decision: PolicyDecision): string | undefined {
  const whole = request.command?.trim().replaceAll(/\s+/g, " ");
  return decision.commandSegment && decision.commandSegment !== whole ? decision.commandSegment : undefined;
}

interface ApprovalTui {
  readonly requestRender?: () => void;
  readonly terminal?: { readonly rows?: number };
}

async function requestTuiApproval(
  ctx: ApprovalUiContext,
  request: PolicyRequest,
  decision: PolicyDecision,
): Promise<UserDecision | undefined> {
  return ctx.ui.custom?.<UserDecision | undefined>(
    (tui: ApprovalTui, theme: ApprovalTheme, keybindings: KeybindingManager, done: (value: UserDecision | undefined) => void) =>
      createApprovalComponent(tui, theme, keybindings, done, request, decision, ctx.rule),
  );
}

type ApprovalTheme = ConfigFrameTheme;

export function approvalRowBudget(terminalRows: number | undefined): number {
  if (terminalRows === undefined || !Number.isFinite(terminalRows)) {
    return 24;
  }
  return Math.max(1, Math.min(24, Math.floor(terminalRows) - 6));
}

function createApprovalComponent(
  tui: ApprovalTui,
  theme: ApprovalTheme,
  keybindings: KeybindingManager,
  done: (value: UserDecision | undefined) => void,
  request: PolicyRequest,
  decision: PolicyDecision,
  rule: ApprovalRule,
): { render: (width: number) => string[]; invalidate: () => void; handleInput: (data: string) => void } {
  // Low-risk prompts start on "Allow once"; everything else starts on "Deny once".
  const choices = approvalChoices(decision.risk, rule.scopes);
  let selectedIndex = 0;
  let cachedWidth: number | undefined;
  let cachedRows: number | undefined;
  let cachedLines: string[] | undefined;

  const invalidate = () => {
    cachedWidth = undefined;
    cachedRows = undefined;
    cachedLines = undefined;
  };

  return {
    render(width: number): string[] {
      const terminalRows = tui.terminal?.rows;
      if (cachedLines && cachedWidth === width && cachedRows === terminalRows) {
        return cachedLines;
      }
      const lines = buildApprovalLines({ width, theme, request, decision, rule, choices, selectedIndex, rowBudget: approvalRowBudget(terminalRows) });
      cachedWidth = width;
      cachedRows = terminalRows;
      cachedLines = lines;
      return lines;
    },
    invalidate,
    handleInput(data: string): void {
      if (isUp(data, keybindings)) {
        selectedIndex = wrapIndex(selectedIndex - 1, choices.length);
        invalidate();
        tui.requestRender?.();
        return;
      }
      if (isDown(data, keybindings)) {
        selectedIndex = wrapIndex(selectedIndex + 1, choices.length);
        invalidate();
        tui.requestRender?.();
        return;
      }
      if (isEnter(data, keybindings)) {
        done(choices[selectedIndex]?.decision ?? "deny-once");
        return;
      }
      if (isEscape(data, keybindings)) {
        done("deny-once");
      }
    },
  };
}

const SELECTED_MARKER = "▶ ";
const APPROVAL_FIXED_FULL_ROWS = 19;

interface ApprovalLineOptions {
  readonly width: number;
  readonly theme: ApprovalTheme;
  readonly request: PolicyRequest;
  readonly decision: PolicyDecision;
  readonly rule: ApprovalRule;
  readonly choices: readonly ApprovalChoice[];
  readonly selectedIndex: number;
  readonly rowBudget: number;
}

function buildApprovalLines(options: ApprovalLineOptions): string[] {
  const { theme, request, decision, choices, selectedIndex } = options;
  const frameWidth = Math.max(1, Math.floor(options.width));
  const budget = Math.max(1, Math.floor(options.rowBudget));
  const summary = renderPolicySummary(request, decision);
  const selectedChoice = choices[selectedIndex] ?? choices[0]!;

  if (budget < 7) {
    return buildUltraShortApprovalLines(summary, decision, choices, selectedIndex, frameWidth, budget);
  }
  if (frameWidth < 20) {
    return buildTinyApprovalLines(summary, decision, choices, selectedIndex, frameWidth, budget);
  }
  if (budget < APPROVAL_FIXED_FULL_ROWS + 1) {
    return buildShortApprovalLines(summary, decision, choices, selectedIndex, frameWidth, budget, theme);
  }
  return buildFullApprovalLines({ ...options, summary, selectedChoice, width: frameWidth, budget });
}

interface FullApprovalLineOptions extends ApprovalLineOptions {
  readonly summary: readonly PolicySummaryLine[];
  readonly selectedChoice: ApprovalChoice;
  readonly budget: number;
}

function buildFullApprovalLines(options: FullApprovalLineOptions): string[] {
  const { summary, decision, rule, choices, selectedChoice, selectedIndex, width, budget, theme, request } = options;
  const innerWidth = width - 2;
  const counter = `${selectedIndex + 1}/${choices.length}`;
  const segment = blockedSegment(request, decision);
  const ruleRows = compactMatchedRuleRows(decision, Math.min(MAX_APPROVAL_MATCHED_RULES, budget - APPROVAL_FIXED_FULL_ROWS + (segment ? 0 : 1) + APPROVAL_CHOICES.length - choices.length));
  const toolAction = `${request.toolName}:${request.action}`;
  const summaryText = `Risk: ${summaryValue(summary, "Risk", decision.risk)} • Action: ${summaryValue(summary, "Action", toolAction)}`;
  const rows = [
    framedLine(summaryText, innerWidth, theme),
    framedLine(`Target: ${summaryValue(summary, "Target", "<unknown>")}`, innerWidth, theme),
    ...(segment ? [framedLine(`Blocked part: ${redactSensitiveText(segment)}`, innerWidth, theme)] : []),
    framedLine(`Reason: ${summaryValue(summary, "Reason", decision.reason)}`, innerWidth, theme, "warning"),
    framedLine(redactSensitiveText(savedRuleSummary(rule)), innerWidth, theme),
    ...ruleRows.map((row) => framedLine(row, innerWidth, theme, "dim")),
    buildApprovalFullBorder(width, theme),
    framedLine(`DECISION ${counter}`, innerWidth, theme, "accent"),
    ...choices.map((choice, index) => compactChoiceLine(choice, index === selectedIndex, innerWidth, theme)),
    framedLine(`Selected: ${selectedChoice.label} — ${selectedChoice.description}`, innerWidth, theme, "accent"),
    framedLine("Esc = Deny once • ↑↓/j/k choose • Enter select", innerWidth, theme, "dim"),
    buildApprovalBottomBorder(width, theme),
  ];
  // The cursor position stays out of the title: orchestrators read the title as the question.
  const topTitle = width >= 60 ? "GuardMe approval required" : "GuardMe";
  return [buildApprovalTopBorder(width, topTitle, "Decision", theme), ...rows].slice(0, budget);
}

function buildShortApprovalLines(
  summary: readonly PolicySummaryLine[],
  decision: PolicyDecision,
  choices: readonly ApprovalChoice[],
  selectedIndex: number,
  width: number,
  budget: number,
  theme: ApprovalTheme,
): string[] {
  const selectedChoice = choices[selectedIndex] ?? choices[0]!;
  const innerWidth = width - 2;
  const choiceCount = Math.max(1, budget - 7);
  const visibleIndexes = approvalChoiceWindow(selectedIndex, choiceCount, choices.length);
  const omittedRules = decision.matchedRules.length;
  const omittedRuleSummary = formatOmittedRuleCount(omittedRules, " • ");
  const decisionHeading = `DECISION ${selectedIndex + 1}/${choices.length}${omittedRuleSummary}`;
  const lines = [
    buildApprovalTopBorder(width, "GuardMe", "Decision", theme),
    framedLine(`Risk: ${summaryValue(summary, "Risk", decision.risk)} • Action: ${summaryValue(summary, "Action", decision.action)} • Target: ${summaryValue(summary, "Target", "<unknown>")}`, innerWidth, theme),
    framedLine(decisionHeading, innerWidth, theme, "accent"),
    ...visibleIndexes.map((index) => compactChoiceLine(choices[index]!, index === selectedIndex, innerWidth, theme)),
    framedLine(`Selected: ${selectedChoice.label} — ${selectedChoice.description}`, innerWidth, theme, "accent"),
    framedLine("Esc = Deny once • ↑↓/j/k choose • Enter select", innerWidth, theme, "dim"),
    buildApprovalBottomBorder(width, theme),
  ];
  return lines.slice(0, budget);
}

function buildUltraShortApprovalLines(
  summary: readonly PolicySummaryLine[],
  decision: PolicyDecision,
  choices: readonly ApprovalChoice[],
  selectedIndex: number,
  width: number,
  budget: number,
): string[] {
  const selectedChoice = choices[selectedIndex] ?? choices[0]!;
  const omittedRuleSummary = decision.matchedRules.length > 0 ? `Rules omitted: ${decision.matchedRules.length} • ` : "";
  const target = summaryValue(summary, "Target", "<unknown>");
  const lines = [
    `GuardMe • ${selectedChoice.label} • Esc=Deny once`,
    `${selectedIndex + 1}/${choices.length} • Risk: ${summaryValue(summary, "Risk", decision.risk)} • Action: ${summaryValue(summary, "Action", decision.action)}`,
    `${omittedRuleSummary}Target: ${target}`,
    selectedChoice.description,
    "↑↓/j/k choose • Enter select • Esc=Deny once",
  ];
  return lines.slice(0, budget).map((line) => boundedApprovalValue(line, width));
}

function buildTinyApprovalLines(
  summary: readonly PolicySummaryLine[],
  decision: PolicyDecision,
  choices: readonly ApprovalChoice[],
  selectedIndex: number,
  width: number,
  budget: number,
): string[] {
  const selectedChoice = choices[selectedIndex] ?? choices[0]!;
  const ruleRows = decision.matchedRules.length > 0 ? [`Rules omitted: ${decision.matchedRules.length}`] : [];
  const choiceCount = Math.max(1, budget - 5 - ruleRows.length);
  const visibleIndexes = approvalChoiceWindow(selectedIndex, choiceCount, choices.length);
  const lines = [
    "GuardMe",
    `Risk: ${summaryValue(summary, "Risk", decision.risk)} Action: ${summaryValue(summary, "Action", decision.action)}`,
    `Target: ${summaryValue(summary, "Target", "<unknown>")}`,
    ...ruleRows,
    ...visibleIndexes.map((index) => `${index === selectedIndex ? ">" : " "} ${choices[index]!.label}`),
    `${selectedIndex + 1}/${choices.length} ${selectedChoice.label}: ${selectedChoice.description}`,
    "Esc = Deny once",
  ];
  return lines.slice(0, budget).map((line) => boundedApprovalValue(line, width));
}

function compactMatchedRuleRows(decision: PolicyDecision, availableRows: number): readonly string[] {
  if (decision.matchedRules.length === 0 || availableRows <= 0) {
    return [];
  }
  const rendered = renderMatchedRules(decision.matchedRules);
  if (rendered.length <= availableRows) {
    return rendered.map((rule, index) => formatMatchedRuleRow(rule, index));
  }
  const displayedCount = Math.max(0, availableRows - 1);
  const omittedCount = rendered.length - displayedCount;
  return [
    ...rendered.slice(0, displayedCount).map((rule, index) => formatMatchedRuleRow(rule, index)),
    formatOmittedRuleCount(omittedCount),
  ];
}

function formatMatchedRuleRow(rule: string, index: number): string {
  const ruleNumber = index === 0 ? "" : ` ${index + 1}`;
  return `Rule${ruleNumber}: ${rule}`;
}

function formatOmittedRuleCount(count: number, prefix: string = ""): string {
  if (count <= 0) {
    return "";
  }
  const noun = count === 1 ? "rule" : "rules";
  return `${prefix}${count} matched ${noun} omitted`;
}

function compactChoiceLine(choice: ApprovalChoice, selected: boolean, width: number, theme: ApprovalTheme): string {
  const text = `${selected ? SELECTED_MARKER : "  "}${choice.label}`;
  return framedLine(selected ? maybeBold(theme, text) : text, width, theme, selected ? "accent" : "normal");
}

function approvalChoiceWindow(selectedIndex: number, count: number, total: number): readonly number[] {
  const visibleCount = Math.min(total, Math.max(1, count));
  const start = Math.min(Math.max(0, selectedIndex - Math.floor(visibleCount / 2)), total - visibleCount);
  return Array.from({ length: visibleCount }, (_value, index) => start + index);
}

function summaryValue(summary: readonly PolicySummaryLine[], label: string, fallback: string): string {
  return summary.find((line) => line.label === label)?.value ?? fallback;
}

function framedLine(text: string, width: number, theme: ApprovalTheme, role: string = "normal"): string {
  const content = role === "normal" ? fitCell(text, width) : style(theme, role, fitCell(text, width));
  return `${style(theme, "accent", "│")}${content}${style(theme, "accent", "│")}`;
}

function buildApprovalTopBorder(width: number, title: string, activePane: string, theme: ApprovalTheme): string {
  if (width <= 1) {
    return style(theme, "accent", "─".repeat(width));
  }

  const left = `╭─ ${title} `;
  const right = ` ${activePane} ─╮`;
  const leftWidth = visibleWidth(left);
  const rightWidth = visibleWidth(right);
  if (leftWidth + rightWidth < width) {
    return style(theme, "accent", `${left}${"─".repeat(width - leftWidth - rightWidth)}${right}`);
  }

  return style(theme, "accent", `╭${"─".repeat(width - 2)}╮`);
}

function buildApprovalFullBorder(width: number, theme: ApprovalTheme): string {
  if (width <= 1) {
    return style(theme, "accent", "─".repeat(width));
  }
  return style(theme, "accent", `├${"─".repeat(width - 2)}┤`);
}

function buildApprovalBottomBorder(width: number, theme: ApprovalTheme): string {
  if (width <= 1) {
    return style(theme, "accent", "─".repeat(width));
  }
  return style(theme, "accent", `╰${"─".repeat(width - 2)}╯`);
}

function maybeBold(theme: ApprovalTheme, text: string): string {
  return theme.bold ? theme.bold(text) : text;
}

function style(theme: ApprovalTheme, role: string, text: string): string {
  return theme.fg ? theme.fg(role, text) : text;
}

function wrapIndex(index: number, length: number): number {
  if (length <= 0) {
    return 0;
  }
  return ((index % length) + length) % length;
}

for (const choice of APPROVAL_CHOICES) {
  if (!isUserDecision(choice.decision)) {
    throw new Error(`Unknown GuardMe approval decision: ${choice.decision}`);
  }
}
