import type { PolicyDecision, PolicyRequest, UserDecision } from "../policy/action.ts";
import { USER_DECISIONS } from "../policy/action.ts";
import { fitCell, footerSegments, type ConfigFrameTheme } from "./config-frame.ts";
import { renderMatchedRules, renderPolicySummary, type PolicySummaryLine } from "./render-policy-summary.ts";
import { visibleWidth } from "./text.ts";

export type ApprovalResult =
  | { readonly kind: "decision"; readonly decision: UserDecision }
  | { readonly kind: "blocked"; readonly reason: string };

export interface ApprovalUiContext {
  readonly cwd: string;
  readonly hasUI: boolean;
  readonly mode?: string;
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

export async function requestApprovalDecision(
  ctx: ApprovalUiContext,
  request: PolicyRequest,
  decision: PolicyDecision,
): Promise<ApprovalResult> {
  if (!ctx.hasUI) {
    return {
      kind: "blocked",
      reason: "GuardMe requires user approval for this action, but this Pi session has no UI. Blocking by default.",
    };
  }

  if (ctx.mode === "tui" && typeof ctx.ui.custom === "function") {
    const selected = await requestTuiApproval(ctx, request, decision);
    return selected ? { kind: "decision", decision: selected } : { kind: "decision", decision: "deny-once" };
  }

  if (typeof ctx.ui.select === "function") {
    const selected = await requestSelectApproval(ctx, request, decision);
    return selected ? { kind: "decision", decision: selected } : { kind: "decision", decision: "deny-once" };
  }

  return {
    kind: "blocked",
    reason: "GuardMe requires user approval, but no approval UI is available. Blocking by default.",
  };
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

async function requestTuiApproval(
  ctx: ApprovalUiContext,
  request: PolicyRequest,
  decision: PolicyDecision,
): Promise<UserDecision | undefined> {
  return ctx.ui.custom?.<UserDecision | undefined>(
    (tui: { requestRender?: () => void }, theme: ApprovalTheme, _keybindings: unknown, done: (value: UserDecision | undefined) => void) =>
      createApprovalComponent(tui, theme, done, request, decision),
  );
}

type ApprovalTheme = ConfigFrameTheme;

function createApprovalComponent(
  tui: { requestRender?: () => void },
  theme: ApprovalTheme,
  done: (value: UserDecision | undefined) => void,
  request: PolicyRequest,
  decision: PolicyDecision,
): { render: (width: number) => string[]; invalidate: () => void; handleInput: (data: string) => void } {
  let selectedIndex = DEFAULT_SELECTED_INDEX;
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
      const lines = buildApprovalLines(width, theme, request, decision, selectedIndex);
      cachedWidth = width;
      cachedLines = lines;
      return lines;
    },
    invalidate,
    handleInput(data: string): void {
      if (isUp(data)) {
        selectedIndex = wrapIndex(selectedIndex - 1, APPROVAL_CHOICES.length);
        invalidate();
        tui.requestRender?.();
        return;
      }
      if (isDown(data)) {
        selectedIndex = wrapIndex(selectedIndex + 1, APPROVAL_CHOICES.length);
        invalidate();
        tui.requestRender?.();
        return;
      }
      if (isEnter(data)) {
        done(APPROVAL_CHOICES[selectedIndex]?.decision ?? "deny-once");
        return;
      }
      if (isEscape(data)) {
        done("deny-once");
      }
    },
  };
}

interface ApprovalDisplayRow {
  readonly text: string;
  readonly tone?: "accent" | "dim" | "normal" | "warning";
  readonly selected?: boolean;
}

const MIN_APPROVAL_BODY_ROWS = 11;
const SELECTED_MARKER = "▶ ";

function buildApprovalLines(
  width: number,
  theme: ApprovalTheme,
  request: PolicyRequest,
  decision: PolicyDecision,
  selectedIndex: number,
): string[] {
  const frameWidth = Math.max(1, Math.floor(width));
  const summary = renderPolicySummary(request, decision);
  const counter = `${selectedIndex + 1}/${APPROVAL_CHOICES.length}`;
  const selectedChoice = APPROVAL_CHOICES[selectedIndex];
  const actionFallback = `${request.toolName}:${request.action}`;
  const context = `Risk: ${summaryValue(summary, "Risk", decision.risk)} • Action: ${summaryValue(summary, "Action", actionFallback)} • Project: ${summaryValue(summary, "Project", request.cwd)}`;
  const footer = footerSegments(
    counter,
    selectedChoice?.description,
    `Recommendation: ${summaryValue(summary, "Recommendation", "Deny is safest unless the requested scope is necessary.")}`,
  );

  if (frameWidth < 20) {
    return renderTinyApproval(summary, decision, selectedChoice, frameWidth);
  }

  const innerWidth = frameWidth - 2;
  const rows: ApprovalDisplayRow[] = [
    ...headingRows("APPROVAL REQUIRED", counter, innerWidth),
    ...labeledRows("Target", summaryValue(summary, "Target", "<unknown>"), innerWidth),
    ...labeledRows("Reason", summaryValue(summary, "Reason", decision.reason), innerWidth, "warning"),
  ];

  for (const [index, rule] of renderMatchedRules(decision.matchedRules).entries()) {
    rows.push(...labeledRows(index === 0 ? "Rule" : `Rule ${index + 1}`, rule, innerWidth));
  }

  rows.push(
    { text: "" },
    { text: "DECISION", tone: "accent" },
    ...APPROVAL_CHOICES.flatMap((choice, index) => choiceRows(choice, index === selectedIndex, innerWidth)),
  );

  return renderApprovalFrame(
    {
      title: "GuardMe approval required",
      activePane: "Decision",
      context,
      keys: "↑↓ decision • Enter select • Esc deny once",
      rows,
      footer,
    },
    frameWidth,
    theme,
  );
}

function renderApprovalFrame(
  options: {
    readonly title: string;
    readonly activePane: string;
    readonly context: string;
    readonly keys: string;
    readonly rows: readonly ApprovalDisplayRow[];
    readonly footer: string;
  },
  width: number,
  theme: ApprovalTheme,
): string[] {
  const innerWidth = width - 2;
  const bodyRows: readonly ApprovalDisplayRow[] = options.rows.length >= MIN_APPROVAL_BODY_ROWS
    ? options.rows
    : [...options.rows, ...Array.from({ length: MIN_APPROVAL_BODY_ROWS - options.rows.length }, (): ApprovalDisplayRow => ({ text: "" }))];

  return [
    buildApprovalTopBorder(width, options.title, options.activePane, theme),
    ...wrapFramedParagraph(options.context, innerWidth, theme),
    ...wrapFramedParagraph(options.keys, innerWidth, theme, "dim"),
    buildApprovalFullBorder(width, theme),
    ...bodyRows.map((row) => renderApprovalRow(row, innerWidth, theme)),
    buildApprovalFullBorder(width, theme),
    ...wrapFramedParagraph(options.footer, innerWidth, theme, "dim"),
    buildApprovalBottomBorder(width, theme),
  ];
}

function summaryValue(summary: readonly PolicySummaryLine[], label: string, fallback: string): string {
  return summary.find((line) => line.label === label)?.value ?? fallback;
}

function headingRows(label: string, value: string, width: number): readonly ApprovalDisplayRow[] {
  const gap = width - visibleWidth(label) - visibleWidth(value);
  if (gap >= 1) {
    return [{ text: `${label}${" ".repeat(gap)}${value}`, tone: "accent" }];
  }
  return wrapTextToWidth(`${label} ${value}`, width).map((text) => ({ text, tone: "accent" }));
}

function labeledRows(label: string, value: string, width: number, tone: ApprovalDisplayRow["tone"] = "normal"): readonly ApprovalDisplayRow[] {
  const labelText = `${label}: `;
  const prefix = `  ${labelText}`;
  const continuationPrefix = `  ${" ".repeat(visibleWidth(labelText))}`;
  return wrapPrefixedText(prefix, value, width, continuationPrefix).map((text) => ({ text, tone }));
}

function choiceRows(choice: ApprovalChoice, selected: boolean, width: number): readonly ApprovalDisplayRow[] {
  const marker = selected ? SELECTED_MARKER : "  ";
  const markerWidth = visibleWidth(marker);
  const labelWidth = choiceLabelWidth(width);
  const gap = "  ";
  const descriptionWidth = width - markerWidth - labelWidth - visibleWidth(gap);

  if (descriptionWidth < 20) {
    return wrapPrefixedText(marker, `${choice.label} — ${choice.description}`, width, "  ").map((text) => ({ text, selected }));
  }

  const descriptionLines = wrapTextToWidth(choice.description, descriptionWidth);
  const continuationPrefix = `${" ".repeat(markerWidth)}${" ".repeat(labelWidth)}${gap}`;
  return descriptionLines.map((line, index) => ({
    text: index === 0
      ? `${marker}${padVisible(choice.label, labelWidth)}${gap}${line}`
      : `${continuationPrefix}${line}`,
    selected,
  }));
}

function choiceLabelWidth(width: number): number {
  const longestLabelWidth = Math.max(...APPROVAL_CHOICES.map((choice) => visibleWidth(choice.label)));
  return Math.min(longestLabelWidth, Math.max(14, Math.floor(width * 0.36)));
}

function padVisible(text: string, width: number): string {
  return `${text}${" ".repeat(Math.max(0, width - visibleWidth(text)))}`;
}

function wrapFramedParagraph(text: string, width: number, theme: ApprovalTheme, role: string = "normal"): string[] {
  return wrapTextToWidth(text, width).map((line) => framedLine(line, width, theme, role));
}

function renderApprovalRow(row: ApprovalDisplayRow, width: number, theme: ApprovalTheme): string {
  const role = roleForApprovalRow(row);
  const text = row.selected ? maybeBold(theme, row.text) : row.text;
  return framedLine(text, width, theme, role);
}

function roleForApprovalRow(row: ApprovalDisplayRow): string {
  if (row.selected) {
    return "accent";
  }
  if (row.tone && row.tone !== "normal") {
    return row.tone;
  }
  return "normal";
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

function wrapPrefixedText(prefix: string, text: string, firstWidth: number, continuationPrefix: string): readonly string[] {
  const firstContentWidth = Math.max(1, firstWidth - visibleWidth(prefix));
  const continuationContentWidth = Math.max(1, firstWidth - visibleWidth(continuationPrefix));
  return wrapTextToVariableWidths(text, firstContentWidth, continuationContentWidth).map((line, index) =>
    `${index === 0 ? prefix : continuationPrefix}${line}`,
  );
}

function wrapTextToWidth(text: string, width: number): readonly string[] {
  return wrapTextToVariableWidths(text, width, width);
}

function wrapTextToVariableWidths(text: string, firstWidth: number, continuationWidth: number): readonly string[] {
  const safeFirstWidth = Math.max(1, firstWidth);
  const safeContinuationWidth = Math.max(1, continuationWidth);
  let remaining = text.replace(/\s+/g, " ").trim();
  if (remaining.length === 0) {
    return [""];
  }

  const lines: string[] = [];
  let currentWidth = safeFirstWidth;
  while (remaining.length > 0) {
    const next = takeFittingPrefix(remaining, currentWidth);
    lines.push(next.line);
    remaining = next.remaining.trimStart();
    currentWidth = safeContinuationWidth;
  }
  return lines;
}

function takeFittingPrefix(text: string, width: number): { readonly line: string; readonly remaining: string } {
  if (visibleWidth(text) <= width) {
    return { line: text, remaining: "" };
  }

  const characters = Array.from(text);
  let usedWidth = 0;
  let endIndex = 0;
  let lastSpaceIndex = -1;

  for (const [index, character] of characters.entries()) {
    const nextWidth = usedWidth + visibleWidth(character);
    if (nextWidth > width) {
      break;
    }
    usedWidth = nextWidth;
    endIndex = index + 1;
    if (/\s/u.test(character)) {
      lastSpaceIndex = index + 1;
    }
  }

  if (lastSpaceIndex > 0) {
    return {
      line: characters.slice(0, lastSpaceIndex).join("").trimEnd(),
      remaining: characters.slice(lastSpaceIndex).join(""),
    };
  }

  const safeEndIndex = Math.max(1, endIndex);
  return {
    line: characters.slice(0, safeEndIndex).join(""),
    remaining: characters.slice(safeEndIndex).join(""),
  };
}

function renderTinyApproval(
  summary: readonly PolicySummaryLine[],
  decision: PolicyDecision,
  selectedChoice: ApprovalChoice | undefined,
  width: number,
): string[] {
  const lines = [
    "GuardMe approval required",
    `Risk: ${summaryValue(summary, "Risk", decision.risk)}`,
    `Action: ${summaryValue(summary, "Action", decision.action)}`,
    `Target: ${summaryValue(summary, "Target", "<unknown>")}`,
    selectedChoice ? `Choice: ${selectedChoice.label}` : "Choice: Deny once",
  ];
  return lines.flatMap((line) => wrapTextToWidth(line, width));
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

for (const choice of APPROVAL_CHOICES) {
  if (!(USER_DECISIONS as readonly string[]).includes(choice.decision)) {
    throw new Error(`Unknown GuardMe approval decision: ${choice.decision}`);
  }
}
