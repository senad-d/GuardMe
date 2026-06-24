import {
  sanitizeTerminalText,
  stripAnsiEscapes,
  truncateTailToVisibleWidth,
  truncateToVisibleWidth as truncate,
  visibleWidth,
} from "./text.ts";

export interface ConfigFrameTheme {
  readonly fg?: (color: string, text: string) => string;
  readonly bold?: (text: string) => string;
}

export interface FrameSidebarItem {
  readonly label: string;
  readonly active?: boolean;
  readonly description?: string;
}

export type FrameValueKind = "auto" | "boolean" | "empty" | "number" | "path" | "slider" | "status" | "text";

export type FrameMainRow =
  | { readonly kind: "blank"; readonly selected?: boolean }
  | { readonly kind: "heading"; readonly label: string; readonly value?: string | number }
  | {
      readonly kind: "text";
      readonly text: string;
      readonly selected?: boolean;
      readonly value?: string | number | boolean;
      readonly description?: string;
      readonly tone?: "dim" | "normal" | "warning";
      readonly preserveIndent?: boolean;
    }
  | {
      readonly kind: "value";
      readonly label: string;
      readonly value: string | number | boolean;
      readonly selected?: boolean;
      readonly valueKind?: FrameValueKind;
      readonly description?: string;
    };

export interface GuardMeFrameOptions {
  readonly title: string;
  readonly activePane: string;
  readonly context: string;
  readonly keys: string;
  readonly sidebar: readonly FrameSidebarItem[];
  readonly rows: readonly FrameMainRow[];
  readonly footer: string;
  readonly minContentRows?: number;
  readonly leftPaneWidth?: number;
  readonly focus?: "main" | "sidebar";
  readonly searchActive?: boolean;
  readonly theme?: ConfigFrameTheme;
}

const TINY_WIDTH = 24;
const WIDE_WIDTH = 72;
const MAX_VISIBLE_SETTING_ROWS = 10;
const MIN_BODY_ROWS = 8;
const DEFAULT_LEFT_PANE_WIDTH = 22;
const SELECTED_MARKER = "▶ ";
const FOOTER_SEPARATOR = " • ";
const DEFAULT_WIDE_HELP = "↑↓ move  Enter select  / search  Esc/q quit";

export function renderGuardMeFrame(options: GuardMeFrameOptions, requestedWidth: number): string[] {
  const width = Math.max(1, Math.floor(requestedWidth));
  if (width < TINY_WIDTH) {
    return renderTinyFrame(options, width);
  }
  if (width >= WIDE_WIDTH) {
    return renderWideFrame(options, width);
  }
  return renderNarrowFrame(options, width);
}

export function renderMainRow(row: FrameMainRow, width: number, focused = true, theme: ConfigFrameTheme = {}): string {
  switch (row.kind) {
    case "blank":
      return "";
    case "heading":
      return renderSectionHeader(row.label, row.value, width, focused, theme);
    case "text":
      return renderSettingRow(row.text, row.value, width, Boolean(row.selected), focused, theme, "text", row.tone, Boolean(row.preserveIndent));
    case "value":
      return renderSettingRow(row.label, row.value, width, Boolean(row.selected), focused, theme, row.valueKind);
  }
}

export function alignValue(label: string, value: string | number | boolean, width: number): string {
  const safeLabel = sanitizeTerminalText(label);
  const formattedValue = formatValue(value, undefined);
  const rawValueText = sanitizeTerminalText(formattedValue.text);
  const totalWidth = visibleWidth(safeLabel) + 1 + visibleWidth(rawValueText);
  if (totalWidth <= width) {
    return `${safeLabel}${" ".repeat(Math.max(1, width - visibleWidth(safeLabel) - visibleWidth(rawValueText)))}${rawValueText}`;
  }

  const valueWidth = valueColumnWidth(width, formattedValue.kind);
  const labelWidth = Math.max(1, width - 1 - valueWidth);
  const labelText = truncate(safeLabel, labelWidth);
  const valueText = clipValue(rawValueText, formattedValue.kind, valueWidth);
  const gap = Math.max(1, width - visibleWidth(labelText) - visibleWidth(valueText));
  return `${labelText}${" ".repeat(gap)}${valueText}`;
}

export function fitCell(value: string, width: number): string {
  const truncated = truncate(value, width);
  return `${truncated}${" ".repeat(Math.max(0, width - visibleWidth(truncated)))}`;
}

function renderWideFrame(options: GuardMeFrameOptions, width: number): string[] {
  const leftWidth = wideLeftPaneWidth(width, options.leftPaneWidth);
  const rightWidth = Math.max(10, width - leftWidth - 3);
  const focus: "main" | "sidebar" = options.focus ?? "main";
  const categoryRows = options.sidebar.map((item) => renderCategoryRow(item, leftWidth, focus === "sidebar", options.theme));
  const mainRows = visibleMainRows(options.rows).map((row) => renderMainRow(row, rightWidth, focus === "main", options.theme));
  const bodyHeight = Math.max(options.minContentRows ?? MIN_BODY_ROWS, MIN_BODY_ROWS, categoryRows.length, mainRows.length);

  const lines = [
    buildTopBorder(width, options.title, options.activePane, options.theme),
    framedLine(options.context, width - 2, options.theme),
    framedLine(options.keys || DEFAULT_WIDE_HELP, width - 2, options.theme, "dim"),
    buildSplitBorder("top", leftWidth, rightWidth, options.theme),
  ];

  for (let index = 0; index < bodyHeight; index += 1) {
    lines.push(splitLine(categoryRows[index] ?? "", mainRows[index] ?? "", leftWidth, rightWidth, options.theme));
  }

  lines.push(buildSplitBorder("bottom", leftWidth, rightWidth, options.theme));
  lines.push(framedLine(options.footer, width - 2, options.theme, "dim"));
  lines.push(style(options.theme, "accent", `╰${"─".repeat(width - 2)}╯`));
  return lines.map((line) => truncate(line, width));
}

function renderNarrowFrame(options: GuardMeFrameOptions, width: number): string[] {
  const innerWidth = width - 2;
  const categoryView = (options.focus ?? "main") === "sidebar" && !options.searchActive;
  const focus: "main" | "sidebar" = categoryView ? "sidebar" : "main";
  const bodyRows = categoryView
    ? options.sidebar.map((item) => renderCategoryRow(item, innerWidth, true, options.theme))
    : visibleMainRows(options.rows).map((row) => renderMainRow(row, innerWidth, focus === "main", options.theme));
  const bodyHeight = Math.max(options.minContentRows ?? MIN_BODY_ROWS, MIN_BODY_ROWS, bodyRows.length);
  const help = options.keys && options.keys !== DEFAULT_WIDE_HELP
    ? options.keys
    : categoryView
      ? "↑↓ category  Enter open  / search  Esc/q quit"
      : "↑↓ move  Enter select  / search  Esc/q quit";

  const lines = [
    buildTopBorder(width, options.title, options.activePane, options.theme),
    framedLine(options.context, innerWidth, options.theme),
    framedLine(help, innerWidth, options.theme, "dim"),
    buildFullBorder(width, options.theme),
  ];

  for (let index = 0; index < bodyHeight; index += 1) {
    lines.push(framedLine(bodyRows[index] ?? "", innerWidth, options.theme, undefined, false));
  }

  lines.push(buildFullBorder(width, options.theme));
  lines.push(framedLine(options.footer, innerWidth, options.theme, "dim"));
  lines.push(style(options.theme, "accent", `╰${"─".repeat(innerWidth)}╯`));
  return lines.map((line) => truncate(line, width));
}

function renderTinyFrame(options: GuardMeFrameOptions, width: number): string[] {
  const selectedRow = findSelectedRow(options.rows);
  const selectedCategory = options.sidebar.find((item) => item.active);
  const label = selectedRow ? labelForRow(selectedRow) : selectedCategory?.label ?? options.activePane;
  const value = selectedRow ? valueForRow(selectedRow) : undefined;
  const summary = value && visibleWidth(value) > 0 ? `${label}: ${value}` : label;
  const lines = [options.title, options.activePane, summary, "q quit"];
  return lines.map((line) => truncate(sanitizeTerminalText(line), width));
}

function wideLeftPaneWidth(totalWidth: number, requested?: number): number {
  const computed = Math.min(DEFAULT_LEFT_PANE_WIDTH, Math.max(16, Math.floor(totalWidth * 0.27)));
  const preferred = requested === undefined ? computed : Math.min(requested, DEFAULT_LEFT_PANE_WIDTH);
  return Math.min(Math.max(16, preferred), Math.max(16, totalWidth - 13));
}

function visibleMainRows(rows: readonly FrameMainRow[]): readonly FrameMainRow[] {
  if (rows.length <= MAX_VISIBLE_SETTING_ROWS + 1) {
    return rows;
  }

  const firstRow = rows[0];
  if (firstRow?.kind !== "heading") {
    return windowRows(rows, MAX_VISIBLE_SETTING_ROWS);
  }

  const settingRows = rows.slice(1);
  if (settingRows.length <= MAX_VISIBLE_SETTING_ROWS) {
    return rows;
  }
  return [firstRow, ...windowRows(settingRows, MAX_VISIBLE_SETTING_ROWS)];
}

function windowRows(rows: readonly FrameMainRow[], maxRows: number): readonly FrameMainRow[] {
  if (rows.length <= maxRows) {
    return rows;
  }
  const selectedRowIndex = rows.findIndex((row) => "selected" in row && row.selected);
  const selectedIndex = Math.max(0, selectedRowIndex);
  const half = Math.floor(maxRows / 2);
  const start = Math.max(0, Math.min(selectedIndex - half, rows.length - maxRows));
  return rows.slice(start, start + maxRows);
}

function renderCategoryRow(item: FrameSidebarItem, width: number, focused: boolean, theme: ConfigFrameTheme = {}): string {
  const selected = Boolean(item.active);
  const showMarker = selected && focused;
  const prefix = showMarker ? SELECTED_MARKER : "  ";
  const labelWidth = Math.max(0, width - visibleWidth(prefix));
  const rawLabel = truncate(sanitizeTerminalText(item.label), labelWidth);
  const styledPrefix = showMarker ? style(theme, "accent", prefix) : prefix;
  const styledLabel = selected
    ? style(theme, focused ? "accent" : "muted", focused ? maybeBold(theme, rawLabel) : rawLabel)
    : style(theme, "dim", rawLabel);
  return fitCell(`${styledPrefix}${styledLabel}`, width);
}

function renderSectionHeader(
  label: string,
  value: string | number | undefined,
  width: number,
  focused: boolean,
  theme: ConfigFrameTheme = {},
): string {
  const safeLabel = sanitizeTerminalText(label).toUpperCase();
  const safeValue = value === undefined ? undefined : sanitizeTerminalText(String(value));
  const labelRole = focused ? "accent" : "dim";
  if (safeValue === undefined) {
    return fitCell(style(theme, labelRole, maybeBold(theme, truncate(safeLabel, width))), width);
  }

  const counter = truncate(safeValue, Math.max(0, Math.min(width, visibleWidth(safeValue))));
  const titleWidth = Math.max(0, width - visibleWidth(counter) - 1);
  const title = truncate(safeLabel, titleWidth);
  const styledTitle = style(theme, labelRole, maybeBold(theme, title));
  const styledCounter = style(theme, "dim", counter);
  const gap = Math.max(1, width - visibleWidth(title) - visibleWidth(counter));
  return fitCell(`${styledTitle}${" ".repeat(gap)}${styledCounter}`, width);
}

function valueColumnWidth(width: number, kind: FrameValueKind): number {
  const maxWidth = kind === "path" ? 34 : 28;
  const ratio = kind === "path" ? 0.45 : 0.4;
  return Math.max(0, Math.min(maxWidth, Math.floor(width * ratio)));
}

function renderSettingRow(
  label: string,
  value: string | number | boolean | undefined,
  width: number,
  selected: boolean,
  focused: boolean,
  theme: ConfigFrameTheme = {},
  valueKind?: FrameValueKind,
  tone: "dim" | "normal" | "warning" = "normal",
  preserveIndent = false,
): string {
  if (width <= 0) {
    return "";
  }

  const showMarker = selected && focused;
  const prefix = showMarker ? SELECTED_MARKER : "  ";
  const styledPrefix = showMarker ? style(theme, "accent", prefix) : prefix;
  const prefixWidth = visibleWidth(prefix);
  const hasValue = value !== undefined && sanitizeTerminalText(String(value)).length > 0;

  if (!hasValue || width <= prefixWidth + 1) {
    const labelWidth = Math.max(0, width - prefixWidth);
    const rawLabel = truncate(sanitizeCellText(label, preserveIndent), labelWidth);
    const styledLabel = styleSettingLabel(rawLabel, selected, focused, theme, tone);
    return fitCell(`${styledPrefix}${styledLabel}`, width);
  }

  const formatted = formatValue(value, valueKind);
  const valueWidth = valueColumnWidth(width, formatted.kind);
  const labelWidth = Math.max(1, width - prefixWidth - 1 - valueWidth);
  const rawLabel = truncate(sanitizeCellText(label, preserveIndent), labelWidth);
  const rawValue = clipValue(formatted.text, formatted.kind, valueWidth);
  const styledLabel = styleSettingLabel(rawLabel, selected, focused, theme, tone);
  const styledValue = style(theme, roleForValue(formatted), rawValue);
  const gap = Math.max(1, width - prefixWidth - visibleWidth(rawLabel) - visibleWidth(rawValue));
  const line = `${styledPrefix}${styledLabel}${" ".repeat(gap)}${styledValue}`;
  return fitCell(line, width);
}

function styleSettingLabel(label: string, selected: boolean, focused: boolean, theme: ConfigFrameTheme, tone: "dim" | "normal" | "warning" = "normal"): string {
  if (!selected) {
    return tone === "normal" ? label : style(theme, tone, label);
  }
  if (focused) {
    return style(theme, "accent", maybeBold(theme, label));
  }
  return style(theme, "muted", label);
}

function sanitizeCellText(value: string, preserveIndent: boolean): string {
  if (!preserveIndent) {
    return sanitizeTerminalText(value);
  }
  return stripAnsiEscapes(String(value)).replace(/[\u0000-\u001F\u007F-\u009F]/g, " ");
}

function formatValue(value: string | number | boolean, explicitKind: FrameValueKind | undefined): { readonly text: string; readonly kind: FrameValueKind } {
  if (typeof value === "boolean") {
    return { text: value ? "ON" : "OFF", kind: "boolean" };
  }
  if (typeof value === "number") {
    return { text: String(value), kind: explicitKind ?? "number" };
  }

  const safe = sanitizeTerminalText(value);
  const lower = safe.toLowerCase();
  if (explicitKind) {
    return { text: safe, kind: explicitKind };
  }
  if (lower === "on" || lower === "off") {
    return { text: lower.toUpperCase(), kind: "boolean" };
  }
  if (lower === "not set" || lower === "<empty>" || lower === "auto" || lower === "none" || safe.length === 0) {
    return { text: safe.length > 0 ? safe : "not set", kind: "empty" };
  }
  if (lower === "active" || lower === "inactive" || lower === "degraded" || lower === "off") {
    return { text: safe, kind: "status" };
  }
  if (isPathLike(safe)) {
    return { text: safe, kind: "path" };
  }
  return { text: safe, kind: "text" };
}

function roleForValue(value: { readonly text: string; readonly kind: FrameValueKind }): string {
  const lower = value.text.toLowerCase();
  if (value.kind === "boolean") {
    return lower === "on" ? "success" : "dim";
  }
  if (value.kind === "empty") {
    return "dim";
  }
  if (value.kind === "status") {
    if (lower === "active") {
      return "success";
    }
    if (lower === "degraded") {
      return "warning";
    }
    return "dim";
  }
  if (lower === "off" || lower === "disabled" || lower === "no") {
    return "dim";
  }
  if (lower === "on" || lower === "enabled" || lower === "yes") {
    return "success";
  }
  return "text";
}

function clipValue(value: string, kind: FrameValueKind, width: number): string {
  if (kind === "path") {
    return truncateTailToVisibleWidth(value, width);
  }
  return truncate(value, width);
}

function isPathLike(value: string): boolean {
  return value.startsWith("~/") || value.startsWith("./") || value.startsWith("../") || value.startsWith("/") || value.includes("/.pi/") || value.includes(".yaml");
}

function buildTopBorder(width: number, title: string, activePane: string, theme: ConfigFrameTheme = {}): string {
  const safeTitle = sanitizeTerminalText(title);
  const safeScope = sanitizeTerminalText(activePane);
  const left = `╭─ ${safeTitle} `;
  const right = ` ${safeScope} ─╮`;
  const leftWidth = visibleWidth(left);
  const rightWidth = visibleWidth(right);
  if (leftWidth + rightWidth >= width) {
    const compactTitle = truncate(`${safeTitle} ${safeScope}`, Math.max(0, width - 4));
    return style(theme, "accent", `╭─${fitCell(compactTitle, width - 4)}─╮`);
  }
  return style(theme, "accent", `${left}${"─".repeat(width - leftWidth - rightWidth)}${right}`);
}

function framedLine(value: string, width: number, theme: ConfigFrameTheme = {}, contentRole?: string, sanitize = true): string {
  const safeValue = sanitize ? sanitizeTerminalText(value) : value;
  const cell = sanitize && contentRole === undefined ? fitSourceCell(safeValue, width) : fitCell(safeValue, width);
  const content = contentRole ? style(theme, contentRole, cell) : cell;
  return `${style(theme, "accent", "│")}${content}${style(theme, "accent", "│")}`;
}

function fitSourceCell(value: string, width: number): string {
  const prefix = "writes ";
  const separator = " • ";
  const separatorIndex = value.indexOf(separator, prefix.length);
  if (!value.startsWith(prefix) || separatorIndex < 0 || visibleWidth(value) <= width) {
    return fitCell(value, width);
  }

  const target = value.slice(prefix.length, separatorIndex);
  const suffix = value.slice(separatorIndex);
  const targetWidth = width - visibleWidth(prefix) - visibleWidth(suffix);
  if (targetWidth <= visibleWidth("…")) {
    return fitCell(value, width);
  }

  return fitCell(`${prefix}${truncateTailToVisibleWidth(target, targetWidth)}${suffix}`, width);
}

function splitLine(left: string, right: string, leftWidth: number, rightWidth: number, theme: ConfigFrameTheme = {}): string {
  const border = style(theme, "accent", "│");
  return `${border}${fitCell(left, leftWidth)}${border}${fitCell(right, rightWidth)}${border}`;
}

function buildSplitBorder(position: "top" | "bottom", leftWidth: number, rightWidth: number, theme: ConfigFrameTheme = {}): string {
  const joint = position === "top" ? "┬" : "┴";
  return style(theme, "accent", `├${"─".repeat(leftWidth)}${joint}${"─".repeat(rightWidth)}┤`);
}

function buildFullBorder(width: number, theme: ConfigFrameTheme = {}): string {
  return style(theme, "accent", `├${"─".repeat(width - 2)}┤`);
}

function findSelectedRow(rows: readonly FrameMainRow[]): FrameMainRow | undefined {
  return rows.find((row) => row.kind !== "blank" && "selected" in row && row.selected) ?? rows.find((row) => row.kind !== "blank" && row.kind !== "heading");
}

function labelForRow(row: FrameMainRow): string {
  if (row.kind === "text") {
    return sanitizeTerminalText(row.text);
  }
  if (row.kind === "value" || row.kind === "heading") {
    return sanitizeTerminalText(row.label);
  }
  return "";
}

function valueForRow(row: FrameMainRow): string | undefined {
  if (row.kind === "text" && row.value !== undefined) {
    return formatValue(row.value, "text").text;
  }
  if (row.kind === "value") {
    return formatValue(row.value, row.valueKind).text;
  }
  if (row.kind === "heading" && row.value !== undefined) {
    return sanitizeTerminalText(String(row.value));
  }
  return undefined;
}

function maybeBold(theme: ConfigFrameTheme, text: string): string {
  return theme.bold ? theme.bold(text) : text;
}

function style(theme: ConfigFrameTheme = {}, role: string, text: string): string {
  return theme.fg ? theme.fg(role, text) : text;
}

export function footerSegments(...segments: readonly (string | undefined | false)[]): string {
  return segments
    .map((segment) => (segment ? sanitizeTerminalText(segment) : ""))
    .filter((segment) => segment.length > 0)
    .join(FOOTER_SEPARATOR);
}
