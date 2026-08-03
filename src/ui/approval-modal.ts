import type { ApprovalMode } from "../config/approval-mode.ts";
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
}

export interface ApprovalChoice {
  readonly decision: UserDecision;
  readonly label: string;
  readonly description: string;
}

export const APPROVAL_CHOICES: readonly ApprovalChoice[] = [
  { decision: "allow-once", label: "Allow once", description: "Run this call only; do not save a rule." },
  { decision: "deny-once", label: "Deny once", description: "Block this call only; do not save a rule." },
  { decision: "allow-local", label: "Allow + save project rule", description: "Run now and save an allow rule in .pi/agent/guardme.yaml." },
  { decision: "deny-local", label: "Deny + save project rule", description: "Block now and save a deny rule in .pi/agent/guardme.yaml." },
  { decision: "allow-global", label: "Allow + save global rule", description: "Run now and save an allow rule in ~/.pi/agent/guardme.yaml." },
  { decision: "deny-global", label: "Deny + save global rule", description: "Block now and save a deny rule in ~/.pi/agent/guardme.yaml." },
];

const DEFAULT_SELECTED_INDEX = 1;
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
  if (!ctx.hasUI) {
    return {
      kind: "blocked",
      reason: "GuardMe requires user approval for this action, but this Pi session has no UI. Blocking by default.",
    };
  }
  if (ctx.mode === "tui" && typeof ctx.ui.custom === "function") {
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

export function formatApprovalUnavailableBlockReason(
  request: PolicyRequest,
  decision: PolicyDecision,
  unavailableReason: string,
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
    `Next step: ${APPROVAL_UNAVAILABLE_NEXT_STEP}`,
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
  return decision === "allow-once" || decision === "allow-local" || decision === "allow-global";
}

export function isDenyDecision(decision: UserDecision): boolean {
  return decision === "deny-once" || decision === "deny-local" || decision === "deny-global";
}

async function requestSelectApproval(
  ctx: ApprovalUiContext,
  request: PolicyRequest,
  decision: PolicyDecision,
): Promise<UserDecision | undefined> {
  const labels = APPROVAL_CHOICES.map((choice) => `${choice.label} — ${choice.description}`);
  const selected = await ctx.ui.select?.(
    `GuardMe approval required: ${request.toolName}:${request.action} (${decision.risk})`,
    labels,
  );
  const selectedIndex = selected === undefined ? -1 : labels.indexOf(selected);
  return selectedIndex >= 0 ? APPROVAL_CHOICES[selectedIndex]?.decision : undefined;
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
      createApprovalComponent(tui, theme, keybindings, done, request, decision),
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
): { render: (width: number) => string[]; invalidate: () => void; handleInput: (data: string) => void } {
  let selectedIndex = DEFAULT_SELECTED_INDEX;
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
      const lines = buildApprovalLines(width, theme, request, decision, selectedIndex, approvalRowBudget(terminalRows));
      cachedWidth = width;
      cachedRows = terminalRows;
      cachedLines = lines;
      return lines;
    },
    invalidate,
    handleInput(data: string): void {
      if (isUp(data, keybindings)) {
        selectedIndex = wrapIndex(selectedIndex - 1, APPROVAL_CHOICES.length);
        invalidate();
        tui.requestRender?.();
        return;
      }
      if (isDown(data, keybindings)) {
        selectedIndex = wrapIndex(selectedIndex + 1, APPROVAL_CHOICES.length);
        invalidate();
        tui.requestRender?.();
        return;
      }
      if (isEnter(data, keybindings)) {
        done(APPROVAL_CHOICES[selectedIndex]?.decision ?? "deny-once");
        return;
      }
      if (isEscape(data, keybindings)) {
        done("deny-once");
      }
    },
  };
}

const SELECTED_MARKER = "▶ ";
const APPROVAL_FIXED_FULL_ROWS = 15;

function buildApprovalLines(
  width: number,
  theme: ApprovalTheme,
  request: PolicyRequest,
  decision: PolicyDecision,
  selectedIndex: number,
  rowBudget: number,
): string[] {
  const frameWidth = Math.max(1, Math.floor(width));
  const budget = Math.max(1, Math.floor(rowBudget));
  const summary = renderPolicySummary(request, decision);
  const selectedChoice = APPROVAL_CHOICES[selectedIndex] ?? APPROVAL_CHOICES[DEFAULT_SELECTED_INDEX]!;

  if (budget < 7) {
    return buildUltraShortApprovalLines(summary, decision, selectedChoice, selectedIndex, frameWidth, budget);
  }
  if (frameWidth < 20) {
    return buildTinyApprovalLines(summary, decision, selectedChoice, selectedIndex, frameWidth, budget);
  }
  if (budget < 16) {
    return buildShortApprovalLines(summary, decision, selectedChoice, selectedIndex, frameWidth, budget, theme);
  }
  return buildFullApprovalLines({ summary, decision, selectedChoice, selectedIndex, width: frameWidth, budget, theme, request });
}

interface FullApprovalLineOptions {
  readonly summary: readonly PolicySummaryLine[];
  readonly decision: PolicyDecision;
  readonly selectedChoice: ApprovalChoice;
  readonly selectedIndex: number;
  readonly width: number;
  readonly budget: number;
  readonly theme: ApprovalTheme;
  readonly request: PolicyRequest;
}

function buildFullApprovalLines(options: FullApprovalLineOptions): string[] {
  const { summary, decision, selectedChoice, selectedIndex, width, budget, theme, request } = options;
  const innerWidth = width - 2;
  const counter = `${selectedIndex + 1}/${APPROVAL_CHOICES.length}`;
  const ruleRows = compactMatchedRuleRows(decision, Math.min(MAX_APPROVAL_MATCHED_RULES, budget - APPROVAL_FIXED_FULL_ROWS));
  const toolAction = `${request.toolName}:${request.action}`;
  const summaryText = `Risk: ${summaryValue(summary, "Risk", decision.risk)} • Action: ${summaryValue(summary, "Action", toolAction)}`;
  const rows = [
    framedLine(summaryText, innerWidth, theme),
    framedLine(`Target: ${summaryValue(summary, "Target", "<unknown>")}`, innerWidth, theme),
    framedLine(`Reason: ${summaryValue(summary, "Reason", decision.reason)}`, innerWidth, theme, "warning"),
    ...ruleRows.map((row) => framedLine(row, innerWidth, theme, "dim")),
    buildApprovalFullBorder(width, theme),
    framedLine("DECISION", innerWidth, theme, "accent"),
    ...APPROVAL_CHOICES.map((choice, index) => compactChoiceLine(choice, index === selectedIndex, innerWidth, theme)),
    framedLine(`Selected: ${selectedChoice.label} — ${selectedChoice.description}`, innerWidth, theme, "accent"),
    framedLine("Esc = Deny once • ↑↓/j/k choose • Enter select", innerWidth, theme, "dim"),
    buildApprovalBottomBorder(width, theme),
  ];
  const topTitle = width >= 60 ? `GuardMe approval required ${counter}` : `GuardMe ${counter}`;
  return [buildApprovalTopBorder(width, topTitle, "Decision", theme), ...rows].slice(0, budget);
}

function buildShortApprovalLines(
  summary: readonly PolicySummaryLine[],
  decision: PolicyDecision,
  selectedChoice: ApprovalChoice,
  selectedIndex: number,
  width: number,
  budget: number,
  theme: ApprovalTheme,
): string[] {
  const innerWidth = width - 2;
  const choiceCount = Math.max(1, budget - 7);
  const visibleIndexes = approvalChoiceWindow(selectedIndex, choiceCount);
  const omittedRules = decision.matchedRules.length;
  const omittedRuleSummary = formatOmittedRuleCount(omittedRules, " • ");
  const decisionHeading = `DECISION ${selectedIndex + 1}/${APPROVAL_CHOICES.length}${omittedRuleSummary}`;
  const lines = [
    buildApprovalTopBorder(width, `GuardMe ${selectedIndex + 1}/${APPROVAL_CHOICES.length}`, "Decision", theme),
    framedLine(`Risk: ${summaryValue(summary, "Risk", decision.risk)} • Action: ${summaryValue(summary, "Action", decision.action)} • Target: ${summaryValue(summary, "Target", "<unknown>")}`, innerWidth, theme),
    framedLine(decisionHeading, innerWidth, theme, "accent"),
    ...visibleIndexes.map((index) => compactChoiceLine(APPROVAL_CHOICES[index]!, index === selectedIndex, innerWidth, theme)),
    framedLine(`Selected: ${selectedChoice.label} — ${selectedChoice.description}`, innerWidth, theme, "accent"),
    framedLine("Esc = Deny once • ↑↓/j/k choose • Enter select", innerWidth, theme, "dim"),
    buildApprovalBottomBorder(width, theme),
  ];
  return lines.slice(0, budget);
}

function buildUltraShortApprovalLines(
  summary: readonly PolicySummaryLine[],
  decision: PolicyDecision,
  selectedChoice: ApprovalChoice,
  selectedIndex: number,
  width: number,
  budget: number,
): string[] {
  const omittedRuleSummary = decision.matchedRules.length > 0 ? `Rules omitted: ${decision.matchedRules.length} • ` : "";
  const target = summaryValue(summary, "Target", "<unknown>");
  const lines = [
    `GuardMe ${selectedIndex + 1}/${APPROVAL_CHOICES.length} • ${selectedChoice.label} • Esc=Deny once`,
    `Risk: ${summaryValue(summary, "Risk", decision.risk)} • Action: ${summaryValue(summary, "Action", decision.action)}`,
    `${omittedRuleSummary}Target: ${target}`,
    selectedChoice.description,
    "↑↓/j/k choose • Enter select • Esc=Deny once",
  ];
  return lines.slice(0, budget).map((line) => boundedApprovalValue(line, width));
}

function buildTinyApprovalLines(
  summary: readonly PolicySummaryLine[],
  decision: PolicyDecision,
  selectedChoice: ApprovalChoice,
  selectedIndex: number,
  width: number,
  budget: number,
): string[] {
  const ruleRows = decision.matchedRules.length > 0 ? [`Rules omitted: ${decision.matchedRules.length}`] : [];
  const choiceCount = Math.max(1, budget - 5 - ruleRows.length);
  const visibleIndexes = approvalChoiceWindow(selectedIndex, choiceCount);
  const lines = [
    `GuardMe ${selectedIndex + 1}/${APPROVAL_CHOICES.length}`,
    `Risk: ${summaryValue(summary, "Risk", decision.risk)} Action: ${summaryValue(summary, "Action", decision.action)}`,
    `Target: ${summaryValue(summary, "Target", "<unknown>")}`,
    ...ruleRows,
    ...visibleIndexes.map((index) => `${index === selectedIndex ? ">" : " "} ${APPROVAL_CHOICES[index]!.label}`),
    `${selectedChoice.label}: ${selectedChoice.description}`,
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
    return rendered.map(formatMatchedRuleRow);
  }
  const displayedCount = Math.max(0, availableRows - 1);
  const omittedCount = rendered.length - displayedCount;
  return [...rendered.slice(0, displayedCount).map(formatMatchedRuleRow), formatOmittedRuleCount(omittedCount)];
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

function approvalChoiceWindow(selectedIndex: number, count: number): readonly number[] {
  const visibleCount = Math.min(APPROVAL_CHOICES.length, Math.max(1, count));
  const start = Math.min(Math.max(0, selectedIndex - Math.floor(visibleCount / 2)), APPROVAL_CHOICES.length - visibleCount);
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
