import { constants } from "node:fs";
import { lstat, mkdir, open, readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";

import {
  GLOBAL_STATE_PATH,
  LOCAL_STATE_PATH,
  POLICY_VERSION,
} from "../constants.ts";
import {
  POLICY_RULE_CATEGORIES,
  RISK_LEVELS,
  RULE_SOURCE_KINDS,
  type MatchedRule,
  type PolicyRuleCategory,
  type PolicyAction,
  type PolicyDiagnostic,
  type PolicyReasonCode,
  type RiskLevel,
  type RuleSourceKind,
  type UserDecision,
  isPolicyAction,
  isUserDecision,
} from "../policy/action.ts";
import { redactSensitiveText } from "../policy/redact.ts";

export type GuardMeStateScope = "global" | "project";
export type PersistedDecisionTarget = "none" | "local-yaml" | "global-yaml";

const PERSISTED_DECISION_TARGETS = ["none", "local-yaml", "global-yaml"] as const;
const MAX_STATE_FILE_BYTES = 1024 * 1024;

export interface GuardMeStatePaths {
  readonly globalStatePath: string;
  readonly localStatePath: string;
  readonly displayGlobalStatePath: typeof GLOBAL_STATE_PATH;
  readonly displayLocalStatePath: typeof LOCAL_STATE_PATH;
}

export interface WarningStateRecord {
  readonly type: "warning";
  readonly version: number;
  readonly timestamp: string;
  readonly fingerprint: string;
  readonly scope: GuardMeStateScope;
  readonly cwd: string;
  readonly toolName: string;
  readonly action: PolicyAction;
  readonly risk: RiskLevel;
  readonly target: string;
  readonly count: number;
  readonly reason?: string;
  readonly matchedRules?: readonly MatchedRule[];
  readonly reasonCode?: PolicyReasonCode;
}

export interface UserDecisionStateRecord {
  readonly type: "decision";
  readonly version: number;
  readonly timestamp: string;
  readonly fingerprint: string;
  readonly scope: GuardMeStateScope;
  readonly cwd: string;
  readonly decision: UserDecision;
  readonly persistedTo: PersistedDecisionTarget;
  readonly reason?: string;
}

export type GuardMeStateRecord = WarningStateRecord | UserDecisionStateRecord;

export interface ReadStateFileResult {
  readonly path: string;
  readonly scope: GuardMeStateScope;
  readonly records: readonly GuardMeStateRecord[];
  readonly diagnostics: readonly PolicyDiagnostic[];
}

export interface LoadedWarningState {
  readonly paths: GuardMeStatePaths;
  readonly records: readonly GuardMeStateRecord[];
  readonly warnedFingerprints: ReadonlySet<string>;
  readonly warningCounts: ReadonlyMap<string, number>;
  readonly diagnostics: readonly PolicyDiagnostic[];
}

export interface CreateWarningRecordInput {
  readonly fingerprint: string;
  readonly scope: GuardMeStateScope;
  readonly cwd: string;
  readonly toolName: string;
  readonly action: PolicyAction;
  readonly risk: RiskLevel;
  readonly target: string;
  readonly count?: number;
  readonly timestamp?: string;
  readonly reason?: string;
  readonly matchedRules?: readonly MatchedRule[];
  readonly reasonCode?: PolicyReasonCode;
}

export interface CreateDecisionRecordInput {
  readonly fingerprint: string;
  readonly scope: GuardMeStateScope;
  readonly cwd: string;
  readonly decision: UserDecision;
  readonly persistedTo?: PersistedDecisionTarget;
  readonly reason?: string;
  readonly timestamp?: string;
}

export interface LoadWarningStateOptions {
  readonly cwd: string;
  readonly homeDir?: string;
  readonly loadLocalState?: boolean;
}

export function resolveStatePaths(cwd: string, homeDir = homedir()): GuardMeStatePaths {
  return {
    globalStatePath: join(resolve(homeDir), ".pi", "agent", "guardme-state.jsonl"),
    localStatePath: join(resolve(cwd), ".pi", "agent", "guardme-state.jsonl"),
    displayGlobalStatePath: GLOBAL_STATE_PATH,
    displayLocalStatePath: LOCAL_STATE_PATH,
  };
}

export function createWarningRecord(input: CreateWarningRecordInput): WarningStateRecord {
  return {
    type: "warning",
    version: POLICY_VERSION,
    timestamp: input.timestamp ?? new Date().toISOString(),
    fingerprint: input.fingerprint,
    scope: input.scope,
    cwd: input.cwd,
    toolName: input.toolName,
    action: input.action,
    risk: input.risk,
    target: redactSensitiveText(input.target),
    count: input.count ?? 1,
    ...(input.reason ? { reason: redactSensitiveText(input.reason) } : {}),
    ...(input.matchedRules && input.matchedRules.length > 0 ? { matchedRules: input.matchedRules.map(redactMatchedRule) } : {}),
    ...(input.reasonCode ? { reasonCode: input.reasonCode } : {}),
  };
}

export function createDecisionRecord(input: CreateDecisionRecordInput): UserDecisionStateRecord {
  return {
    type: "decision",
    version: POLICY_VERSION,
    timestamp: input.timestamp ?? new Date().toISOString(),
    fingerprint: input.fingerprint,
    scope: input.scope,
    cwd: input.cwd,
    decision: input.decision,
    persistedTo: input.persistedTo ?? "none",
    ...(input.reason ? { reason: redactSensitiveText(input.reason) } : {}),
  };
}

function redactMatchedRule(rule: MatchedRule): MatchedRule {
  return {
    ...rule,
    source: {
      ...rule.source,
      ...(rule.source.path ? { path: redactSensitiveText(rule.source.path) } : {}),
      ...(rule.source.label ? { label: redactSensitiveText(rule.source.label) } : {}),
    },
    ...(rule.pattern ? { pattern: redactSensitiveText(rule.pattern) } : {}),
    ...(rule.reason ? { reason: redactSensitiveText(rule.reason) } : {}),
  };
}

export async function appendStateRecord(path: string, record: GuardMeStateRecord): Promise<void> {
  const directory = dirname(path);
  await assertNoSymlinkInExistingPath(directory);
  await mkdir(directory, { recursive: true });
  await assertNoSymlinkInExistingPath(directory);
  await appendFileNoFollow(path, `${JSON.stringify(record)}\n`);
}

export async function appendWarningRecord(path: string, input: CreateWarningRecordInput): Promise<WarningStateRecord> {
  const record = createWarningRecord(input);
  await appendStateRecord(path, record);
  return record;
}

export async function appendDecisionRecord(path: string, input: CreateDecisionRecordInput): Promise<UserDecisionStateRecord> {
  const record = createDecisionRecord(input);
  await appendStateRecord(path, record);
  return record;
}

async function appendFileNoFollow(path: string, text: string): Promise<void> {
  const flags = constants.O_APPEND | constants.O_CREAT | constants.O_WRONLY | constants.O_NOFOLLOW;
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    handle = await open(path, flags, 0o600);
    await handle.writeFile(text, "utf8");
  } catch (error) {
    if (isNodeError(error) && error.code === "ELOOP") {
      throw new Error("Refusing to write GuardMe state through a symbolic link.");
    }
    throw error;
  } finally {
    await handle?.close();
  }
}

async function assertNoSymlinkInExistingPath(path: string): Promise<void> {
  const symlinkPath = await existingSymlinkInPath(path);
  if (symlinkPath) {
    throw new Error(`Refusing to write GuardMe state through symbolic link: ${symlinkPath}`);
  }
}

async function existingSymlinkInPath(path: string): Promise<string | undefined> {
  const absolutePath = resolve(path);
  const candidates: string[] = [];
  let current = absolutePath;
  while (dirname(current) !== current) {
    candidates.unshift(current);
    current = dirname(current);
  }
  candidates.unshift(current);

  const stateCandidates = candidates.findIndex((candidate) => basename(candidate) === ".pi");
  const checkedCandidates = stateCandidates >= 0 ? candidates.slice(stateCandidates) : candidates.slice(-1);

  for (const candidate of checkedCandidates) {
    try {
      const stats = await lstat(candidate);
      if (stats.isSymbolicLink()) {
        return candidate;
      }
    } catch (error) {
      if (isNodeError(error) && error.code === "ENOENT") {
        return undefined;
      }
      throw error;
    }
  }

  return undefined;
}

export async function readStateFile(path: string, scope: GuardMeStateScope): Promise<ReadStateFileResult> {
  try {
    const symlinkPath = await existingSymlinkInPath(path);
    if (symlinkPath) {
      return stateFileReadError(path, scope, "state.symlinkRejected", "Refusing to read GuardMe state through a symbolic link.", symlinkPath);
    }

    const fileStats = await lstat(path);
    if (!fileStats.isFile()) {
      return stateFileReadError(path, scope, "state.notFile", "GuardMe state path is not a regular file.");
    }
    if (fileStats.size > MAX_STATE_FILE_BYTES) {
      return stateFileReadError(path, scope, "state.fileTooLarge", `GuardMe state file is too large to read safely (${fileStats.size} bytes).`);
    }
  } catch (error) {
    if (isNodeError(error) && error.code === "ENOENT") {
      return { path, scope, records: [], diagnostics: [] };
    }
    return stateFileReadError(path, scope, "state.inspectFailed", `Unable to inspect GuardMe state file: ${formatStateReadError(error)}`);
  }

  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch (error) {
    return stateFileReadError(path, scope, "state.readFailed", `Unable to read GuardMe state file: ${formatStateReadError(error)}`);
  }

  const records: GuardMeStateRecord[] = [];
  const diagnostics: PolicyDiagnostic[] = [];
  for (const [index, line] of text.split(/\r?\n/).entries()) {
    const lineNumber = index + 1;
    if (line.trim() === "") {
      continue;
    }
    try {
      const parsed = JSON.parse(line) as unknown;
      const record = validateStateRecord(parsed, scope, path, lineNumber, diagnostics);
      if (record) {
        records.push(record);
      }
    } catch (error) {
      diagnostics.push({
        severity: "warning",
        code: "state.malformedJsonl",
        message: `Ignoring malformed GuardMe state JSONL line ${lineNumber}: ${error instanceof Error ? error.message : String(error)}`,
        source: { kind: scopeToSourceKind(scope), path },
        path,
        ruleIndex: lineNumber,
      });
    }
  }

  return { path, scope, records, diagnostics };
}

export async function loadWarningState(options: LoadWarningStateOptions): Promise<LoadedWarningState> {
  const paths = resolveStatePaths(options.cwd, options.homeDir);
  const [globalState, localState] = await Promise.all([
    readStateFile(paths.globalStatePath, "global"),
    options.loadLocalState === false
      ? skippedLocalStateFile(paths.localStatePath)
      : readStateFile(paths.localStatePath, "project"),
  ]);
  const records = [...globalState.records, ...localState.records].filter((record) => isRelevantRecord(record, options.cwd));
  const warningCounts = new Map<string, number>();
  for (const record of records) {
    if (record.type !== "warning") {
      continue;
    }
    warningCounts.set(record.fingerprint, (warningCounts.get(record.fingerprint) ?? 0) + Math.max(record.count, 1));
  }

  return {
    paths,
    records,
    warnedFingerprints: new Set(warningCounts.keys()),
    warningCounts,
    diagnostics: [...globalState.diagnostics, ...localState.diagnostics],
  };
}

export function hasWarnedFingerprint(state: LoadedWarningState, fingerprint: string): boolean {
  return state.warnedFingerprints.has(fingerprint);
}

function stateFileReadError(
  path: string,
  scope: GuardMeStateScope,
  code: string,
  message: string,
  diagnosticPath = path,
): ReadStateFileResult {
  return {
    path,
    scope,
    records: [],
    diagnostics: [
      {
        severity: "error",
        code,
        message,
        source: { kind: scopeToSourceKind(scope), path },
        path: diagnosticPath,
      },
    ],
  };
}

function skippedLocalStateFile(path: string): ReadStateFileResult {
  return {
    path,
    scope: "project",
    records: [],
    diagnostics: [
      {
        severity: "info",
        code: "state.localStateSkippedUntrustedProject",
        message: "Project is not trusted; local GuardMe state was not loaded.",
        source: { kind: "local", path },
        path,
      },
    ],
  };
}

function validateStateRecord(
  parsed: unknown,
  scope: GuardMeStateScope,
  path: string,
  lineNumber: number,
  diagnostics: PolicyDiagnostic[],
): GuardMeStateRecord | undefined {
  if (!isRecord(parsed)) {
    diagnostics.push(stateDiagnostic("state.invalidRecord", "Ignoring non-object GuardMe state record.", scope, path, lineNumber));
    return undefined;
  }

  if (parsed.type === "warning" && isString(parsed.fingerprint) && isString(parsed.cwd) && isString(parsed.toolName)) {
    const action = optionalPolicyAction(parsed.action, "shell");
    const risk = optionalRiskLevel(parsed.risk, "dangerous");
    if (!action || !risk) {
      diagnostics.push(stateDiagnostic("state.invalidRecord", "Ignoring GuardMe warning record with invalid action or risk.", scope, path, lineNumber));
      return undefined;
    }
    return {
      type: "warning",
      version: numberOrDefault(parsed.version, POLICY_VERSION),
      timestamp: stringOrDefault(parsed.timestamp, new Date(0).toISOString()),
      fingerprint: parsed.fingerprint,
      scope: parsed.scope === "global" ? "global" : "project",
      cwd: parsed.cwd,
      toolName: parsed.toolName,
      action,
      risk,
      target: isString(parsed.target) ? redactSensitiveText(parsed.target) : "<unknown>",
      count: numberOrDefault(parsed.count, 1),
      ...(isString(parsed.reason) ? { reason: redactSensitiveText(parsed.reason) } : {}),
      ...(Array.isArray(parsed.matchedRules) ? { matchedRules: parsed.matchedRules.map(parseMatchedRule).filter((rule): rule is MatchedRule => Boolean(rule)) } : {}),
      ...(isString(parsed.reasonCode) ? { reasonCode: parsed.reasonCode } : {}),
    };
  }

  if (parsed.type === "decision" && isString(parsed.fingerprint) && isString(parsed.cwd) && isString(parsed.decision)) {
    const persistedTo = optionalPersistedDecisionTarget(parsed.persistedTo, "none");
    if (!isUserDecision(parsed.decision) || !persistedTo) {
      diagnostics.push(stateDiagnostic("state.invalidRecord", "Ignoring GuardMe decision record with invalid decision fields.", scope, path, lineNumber));
      return undefined;
    }
    return {
      type: "decision",
      version: numberOrDefault(parsed.version, POLICY_VERSION),
      timestamp: stringOrDefault(parsed.timestamp, new Date(0).toISOString()),
      fingerprint: parsed.fingerprint,
      scope: parsed.scope === "global" ? "global" : "project",
      cwd: parsed.cwd,
      decision: parsed.decision,
      persistedTo,
      ...(isString(parsed.reason) ? { reason: redactSensitiveText(parsed.reason) } : {}),
    };
  }

  diagnostics.push(stateDiagnostic("state.invalidRecord", "Ignoring GuardMe state record with missing or invalid fields.", scope, path, lineNumber));
  return undefined;
}

function parseMatchedRule(value: unknown): MatchedRule | undefined {
  if (!isRecord(value) || !isString(value.category) || !(POLICY_RULE_CATEGORIES as readonly string[]).includes(value.category)) {
    return undefined;
  }

  const source = isRecord(value.source) ? value.source : {};
  const sourceKind: RuleSourceKind = isString(source.kind) && (RULE_SOURCE_KINDS as readonly string[]).includes(source.kind)
    ? (source.kind as RuleSourceKind)
    : "default";
  return {
    category: value.category as PolicyRuleCategory,
    source: {
      kind: sourceKind,
      ...(isString(source.path) ? { path: redactSensitiveText(source.path) } : {}),
      ...(typeof source.index === "number" && Number.isInteger(source.index) ? { index: source.index } : {}),
      ...(isString(source.label) ? { label: redactSensitiveText(source.label) } : {}),
    },
    ...(isString(value.pattern) ? { pattern: redactSensitiveText(value.pattern) } : {}),
    ...(Array.isArray(value.actions) ? { actions: value.actions.filter((action): action is PolicyAction => isString(action) && isPolicyAction(action)) } : {}),
    ...(isString(value.reason) ? { reason: redactSensitiveText(value.reason) } : {}),
  };
}

function optionalPolicyAction(value: unknown, fallback: PolicyAction): PolicyAction | undefined {
  if (value === undefined) {
    return fallback;
  }
  return isString(value) && isPolicyAction(value) ? value : undefined;
}

function optionalRiskLevel(value: unknown, fallback: RiskLevel): RiskLevel | undefined {
  if (value === undefined) {
    return fallback;
  }
  return isString(value) && (RISK_LEVELS as readonly string[]).includes(value) ? (value as RiskLevel) : undefined;
}

function optionalPersistedDecisionTarget(
  value: unknown,
  fallback: PersistedDecisionTarget,
): PersistedDecisionTarget | undefined {
  if (value === undefined) {
    return fallback;
  }
  return isString(value) && (PERSISTED_DECISION_TARGETS as readonly string[]).includes(value)
    ? (value as PersistedDecisionTarget)
    : undefined;
}

function isRelevantRecord(record: GuardMeStateRecord, cwd: string): boolean {
  return record.scope === "project" ? resolve(record.cwd) === resolve(cwd) : record.cwd === "" || resolve(record.cwd) === resolve(cwd);
}

function scopeToSourceKind(scope: GuardMeStateScope): Extract<RuleSourceKind, "global" | "local"> {
  return scope === "global" ? "global" : "local";
}

function stateDiagnostic(code: string, message: string, scope: GuardMeStateScope, path: string, lineNumber: number): PolicyDiagnostic {
  return {
    severity: "warning",
    code,
    message,
    source: { kind: scopeToSourceKind(scope), path },
    path,
    ruleIndex: lineNumber,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isString(value: unknown): value is string {
  return typeof value === "string";
}

function formatStateReadError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function numberOrDefault(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function stringOrDefault(value: unknown, fallback: string): string {
  return typeof value === "string" ? value : fallback;
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return typeof error === "object" && error !== null && "code" in error;
}
