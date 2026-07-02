import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import type { Dirent } from "node:fs";
import { readFile, readdir, stat } from "node:fs/promises";
import { basename, join } from "node:path";

import { EXTENSION_STATUS_KEY, GUARDED_TOOL_NAMES } from "../constants.ts";
import type { PathTarget, PolicyAction, PolicyDecision, PolicyDiagnostic, PolicyRequest, PolicyTarget, UserDecision } from "../policy/action.ts";
import {
  classifyShellCommand,
  detectLocalScriptExecutions,
  detectPackageScriptExecutions,
  extractExecutableCommandSegments,
  tokenizeShellCommand,
  type ExecutableCommandSegment,
  type LocalScriptExecution,
  type PackageScriptExecution,
} from "../policy/commands.ts";
import { createPolicyFingerprint, evaluatePolicyRequest } from "../policy/evaluate.ts";
import { normalizePolicyPath, pathTargetFromNormalizedPath } from "../policy/paths.ts";
import { redactSensitiveText } from "../policy/redact.ts";
import {
  extractScriptCommandsFromContent,
  type ExtractedScriptCommand,
  type ScriptContentExtractionResult,
} from "../policy/script-content.ts";
import { loadGuardMeConfig } from "../config/load-config.ts";
import { persistUserDecisionRule } from "../config/write-policy.ts";
import { appendDecisionRecord, appendWarningRecord } from "../state/warnings.ts";
import { isAllowDecision, requestApprovalDecision, type ApprovalUiContext } from "../ui/approval-modal.ts";
import { formatGuardMeStatus, getGuardMeSessionState, recordGuardMeGuidance, setGuardMeSessionState, type GuardMeSessionState } from "./session-store.ts";

export interface GuardedToolCallEvent {
  readonly toolName: string;
  readonly input: unknown;
}

export interface GuardedToolCallContext {
  readonly cwd: string;
  readonly hasUI: boolean;
  readonly mode?: string;
  readonly ui?: {
    readonly setStatus?: (key: string, text: string | undefined) => void;
  };
}

export interface ToolCallBlockResult {
  readonly block: true;
  readonly reason: string;
}

type ScriptInspectionSourceKind = "script-content" | "local-script";
type PersistedPolicyTarget = "none" | "local-yaml" | "global-yaml";
type StateFileSourceKind = "global" | "local";

const GUARDED_TOOL_NAME_SET: ReadonlySet<string> = new Set(GUARDED_TOOL_NAMES);

interface ScriptInspectionSource {
  readonly sourceKind: ScriptInspectionSourceKind;
  readonly sourcePath: string | undefined;
  readonly snippetLabel: string;
}

interface ScriptContentInspectionOptions extends ScriptInspectionSource {
  readonly shellHint?: boolean;
  readonly allowCommandDefaultDeny?: boolean;
}

/** Register GuardMe tool-call enforcement handlers. */
export function registerGuard(pi: ExtensionAPI): void {
  pi.on("tool_call", async (event, ctx) => evaluateGuardedToolCall(event, ctx));
}

export async function evaluateGuardedToolCall(
  event: GuardedToolCallEvent,
  ctx: GuardedToolCallContext,
): Promise<ToolCallBlockResult | undefined> {
  if (!isGuardedToolName(event.toolName)) {
    return undefined;
  }

  const state = getGuardMeSessionState();
  if (!state) {
    return block("GuardMe blocked the tool call because policy state is not initialized.");
  }

  if (!state.enabled) {
    return undefined;
  }

  const mapped = await mapToolCallToPolicyRequest(event, ctx.cwd, state.homeDir);
  if ("error" in mapped) {
    return block(mapped.error);
  }

  const decision = evaluatePolicyRequest({
    policy: state.config.config,
    request: mapped.request,
    commandClassification: mapped.commandClassification,
    warnedFingerprints: state.warnings.warnedFingerprints,
  });

  if (event.toolName === "bash" && decision.outcome !== "deny") {
    const scriptBlock = await inspectLocalScriptsBeforeExecution(state, ctx, mapped.request);
    if (scriptBlock) {
      return scriptBlock;
    }
  }

  const directBlock = await handlePolicyDecision(state, ctx, mapped.request, decision);
  if (directBlock) {
    return directBlock;
  }

  if (isEditMutationToolName(event.toolName) && !state.insecureEdits) {
    return inspectWriteEditContentBeforeMutation(state, ctx, event, mapped.request);
  }

  return undefined;
}

export async function mapToolCallToPolicyRequest(
  event: GuardedToolCallEvent,
  cwd: string,
  homeDir?: string,
): Promise<
  | { readonly request: PolicyRequest; readonly commandClassification?: ReturnType<typeof classifyShellCommand> }
  | { readonly error: string }
> {
  if (event.toolName === "bash") {
    const command = readStringProperty(event.input, "command");
    if (!command) {
      return { error: "GuardMe could not evaluate bash because input.command is missing." };
    }
    const commandClassification = classifyShellCommand(command);
    const normalized = await normalizeTargets(commandClassification.targetPaths, cwd, homeDir);
    if ("error" in normalized) {
      return { error: normalized.error };
    }
    const discoveryTargets = await protectedShellDiscoveryTargets(commandClassification, normalized.targets);
    const mutationTargets = await protectedMutationDescendantTargets(commandClassification.primaryAction, normalized.targets);
    return {
      request: {
        toolName: event.toolName,
        action: commandClassification.primaryAction,
        cwd,
        command,
        targets: [...normalized.targets, ...discoveryTargets, ...mutationTargets],
        riskHint: commandClassification.risk,
      },
      commandClassification,
    };
  }

  const action = toolNameToAction(event.toolName);
  const pathValues = extractToolPathValues(event.toolName, event.input);
  if (pathValues.length === 0) {
    return { error: `GuardMe could not evaluate ${event.toolName} because no path input was found.` };
  }

  const normalized = await normalizeTargets(pathValues, cwd, homeDir);
  if ("error" in normalized) {
    return { error: normalized.error };
  }
  const discoveryTargets = await protectedDiscoveryTargets(event.toolName, event.input, normalized.targets);
  return {
    request: {
      toolName: event.toolName,
      action,
      cwd,
      targets: [...normalized.targets, ...discoveryTargets],
    },
  };
}

async function handlePolicyDecision(
  state: GuardMeSessionState,
  ctx: GuardedToolCallContext,
  request: PolicyRequest,
  decision: PolicyDecision,
): Promise<ToolCallBlockResult | undefined> {
  await persistCoachingWarningIfNeeded(state, request, decision);
  if (decision.outcome === "coach" || decision.outcome === "deny") {
    refreshGuardMeStatus(ctx);
  }
  if (decision.outcome === "needs-user-decision") {
    const approval = await requestApprovalDecision(toApprovalContext(ctx), request, decision);
    if (approval.kind === "blocked") {
      recordDecisionGuidance(request, decision, approval.reason);
      return block(approval.reason);
    }
    const persisted = await persistApprovalRuleIfRequested(state, request, approval.decision, decision);
    if (!persisted.saved) {
      recordDecisionGuidance(request, decision, persisted.reason);
      return block(persisted.reason);
    }
    await reloadPolicyAfterPersistentDecision(state, persisted.persistedTo);
    await appendApprovalDecisionRecord(state, approval.decision, persisted.persistedTo, decision.fingerprint);
    refreshGuardMeStatus(ctx);
    if (isAllowDecision(approval.decision)) {
      return undefined;
    }
    const reason = `GuardMe denied this action by user decision: ${approval.decision}.`;
    recordDecisionGuidance(request, decision, reason);
    return block(reason);
  }
  return policyDecisionToToolBlock(request, decision);
}

async function inspectWriteEditContentBeforeMutation(
  state: GuardMeSessionState,
  ctx: GuardedToolCallContext,
  event: GuardedToolCallEvent,
  request: PolicyRequest,
): Promise<ToolCallBlockResult | undefined> {
  const snippets = await proposedContentSnippets(event, request);
  for (const snippet of snippets) {
    const inspection = extractScriptCommandsFromContent({ path: snippet.path, content: snippet.content });
    const blockResult = await evaluateScriptContentInspection(state, ctx, request, inspection, {
      sourceKind: "script-content",
      sourcePath: snippet.path,
      snippetLabel: snippet.label,
    });
    if (blockResult) {
      return blockResult;
    }
  }
  return undefined;
}

async function inspectLocalScriptsBeforeExecution(
  state: GuardMeSessionState,
  ctx: GuardedToolCallContext,
  request: PolicyRequest,
): Promise<ToolCallBlockResult | undefined> {
  if (!request.command) {
    return undefined;
  }

  for (const script of detectLocalScriptExecutions(request.command)) {
    const normalized = await normalizeTargets([script.rawPath], request.cwd, state.homeDir);
    if ("error" in normalized) {
      const synthetic = localScriptUninspectableRequest(request, script, script.rawPath, normalized.error);
      const decision = evaluatePolicyRequest({
        policy: state.config.config,
        request: synthetic,
        warnedFingerprints: currentWarnedFingerprints(state),
      });
      return (await handlePolicyDecision(state, ctx, synthetic, decision)) ?? block(normalized.error);
    }

    const scriptTarget = normalized.targets[0];
    if (!scriptTarget) {
      continue;
    }

    const readRequest: PolicyRequest = {
      toolName: "bash",
      action: "read",
      cwd: request.cwd,
      targets: [scriptTarget],
      fingerprintSeed: `local-script-read:${script.rawPath}`,
    };
    const readDecision = evaluatePolicyRequest({
      policy: state.config.config,
      request: readRequest,
      warnedFingerprints: currentWarnedFingerprints(state),
    });
    const readBlock = await handlePolicyDecision(state, ctx, readRequest, readDecision);
    if (readBlock) {
      return block(`GuardMe blocked local script inspection for ${script.rawPath}: ${readBlock.reason}`);
    }

    const content = await readInspectableScriptContent(scriptTarget, script);
    if ("error" in content) {
      const synthetic = localScriptUninspectableRequest(request, script, scriptTarget.raw, content.error);
      const decision = evaluatePolicyRequest({
        policy: state.config.config,
        request: synthetic,
        warnedFingerprints: currentWarnedFingerprints(state),
      });
      const handled = await handlePolicyDecision(state, ctx, synthetic, decision);
      return handled ?? block(content.error);
    }

    const inspection = extractScriptCommandsFromContent({
      path: scriptTarget.canonicalPath ?? scriptTarget.absolutePath ?? script.rawPath,
      content: content.content,
      forceCommandBearing: true,
      shellHint: script.shellHint,
    });
    const blockResult = await evaluateScriptContentInspection(state, ctx, request, inspection, {
      sourceKind: "local-script",
      sourcePath: script.rawPath,
      snippetLabel: script.invocation,
      shellHint: script.shellHint,
    });
    if (blockResult) {
      return blockResult;
    }
  }

  for (const script of detectPackageScriptExecutions(request.command)) {
    const blockResult = await inspectPackageScriptBeforeExecution(state, ctx, request, script);
    if (blockResult) {
      return blockResult;
    }
  }

  return undefined;
}

async function evaluateScriptContentInspection(
  state: GuardMeSessionState,
  ctx: GuardedToolCallContext,
  parentRequest: PolicyRequest,
  inspection: ScriptContentExtractionResult,
  source: ScriptContentInspectionOptions,
): Promise<ToolCallBlockResult | undefined> {
  if (!inspection.commandBearing) {
    return undefined;
  }

  if (inspection.uninspectable) {
    const synthetic = uninspectableContentRequest(parentRequest, source, inspection.uninspectable.reason);
    const decision = evaluatePolicyRequest({
      policy: state.config.config,
      request: synthetic,
      warnedFingerprints: currentWarnedFingerprints(state),
    });
    return handlePolicyDecision(state, ctx, synthetic, decision);
  }

  for (const command of inspection.commands) {
    const derived = await scriptCommandPolicyRequest(parentRequest, command, source, state.homeDir);
    if ("error" in derived) {
      const synthetic = uninspectableContentRequest(parentRequest, source, derived.error);
      const decision = evaluatePolicyRequest({
        policy: state.config.config,
        request: synthetic,
        warnedFingerprints: currentWarnedFingerprints(state),
      });
      return handlePolicyDecision(state, ctx, synthetic, decision);
    }

    const decision = evaluatePolicyRequest({
      policy: state.config.config,
      request: derived.request,
      commandClassification: derived.commandClassification,
      warnedFingerprints: currentWarnedFingerprints(state),
    });
    if (source.allowCommandDefaultDeny && isCommandDefaultDenyDecision(decision)) {
      continue;
    }
    const handled = await handlePolicyDecision(state, ctx, derived.request, decision);
    if (handled) {
      return block(formatScriptContentBlockReason(source.sourceKind, source.sourcePath, command, handled.reason));
    }
  }

  return undefined;
}

interface ProposedContentSnippet {
  readonly path?: string;
  readonly content: string;
  readonly label: string;
}

async function proposedContentSnippets(event: GuardedToolCallEvent, request: PolicyRequest): Promise<readonly ProposedContentSnippet[]> {
  const record = isRecord(event.input) ? event.input : {};
  const targetPath = request.targets.find((target): target is PathTarget => target.kind === "path")?.raw;

  if (event.toolName === "write") {
    const content = readStringProperty(record, "content");
    return content ? [{ path: targetPath, content, label: "write content" }] : [];
  }

  if (event.toolName !== "edit") {
    return [];
  }

  const snippets: ProposedContentSnippet[] = [];
  const newText = readStringProperty(record, "newText");
  if (newText) {
    snippets.push({ path: targetPath, content: newText, label: "edit newText" });
  }

  const edits = Array.isArray(record.edits) ? record.edits : [];
  for (const [index, edit] of edits.entries()) {
    if (!isRecord(edit)) {
      continue;
    }
    const editNewText = readStringProperty(edit, "newText");
    if (editNewText) {
      snippets.push({ path: targetPath, content: editNewText, label: `edit[${index}].newText` });
    }
  }

  const reconstructed = await reconstructedEditContent(record, request);
  if (reconstructed) {
    snippets.push({ path: targetPath, content: reconstructed, label: "reconstructed edit content" });
  }

  return snippets;
}

async function reconstructedEditContent(input: Record<string, unknown>, request: PolicyRequest): Promise<string | undefined> {
  const pathTarget = request.targets.find((target): target is PathTarget => target.kind === "path");
  const path = pathTarget?.canonicalPath ?? pathTarget?.absolutePath;
  const edits = Array.isArray(input.edits) ? input.edits.filter(isRecord) : [];
  if (!path || edits.length === 0) {
    return undefined;
  }

  let stats: Awaited<ReturnType<typeof stat>>;
  try {
    stats = await stat(path);
  } catch {
    return undefined;
  }
  if (!stats.isFile() || stats.size > MAX_INSPECTABLE_SCRIPT_BYTES) {
    return undefined;
  }

  let content: string;
  try {
    content = await readFile(path, "utf8");
  } catch {
    return undefined;
  }
  if (content.includes("\0")) {
    return undefined;
  }

  for (const edit of edits) {
    const oldText = readStringProperty(edit, "oldText");
    const newText = readStringProperty(edit, "newText") ?? "";
    if (oldText === undefined) {
      continue;
    }
    const editedContent = applyUniqueTextEdit(content, oldText, newText);
    if (editedContent === undefined) {
      return undefined;
    }
    content = editedContent;
  }

  return content;
}

function applyUniqueTextEdit(content: string, oldText: string, newText: string): string | undefined {
  if (oldText === "") {
    return undefined;
  }
  const firstIndex = content.indexOf(oldText);
  if (firstIndex < 0) {
    return undefined;
  }
  const searchStart = firstIndex + oldText.length;
  if (content.slice(searchStart).includes(oldText)) {
    return undefined;
  }
  return `${content.slice(0, firstIndex)}${newText}${content.slice(searchStart)}`;
}

const MAX_INSPECTABLE_SCRIPT_BYTES = 256 * 1024;

async function readInspectableScriptContent(
  target: PathTarget,
  script: LocalScriptExecution,
): Promise<{ readonly content: string } | { readonly error: string }> {
  const path = target.canonicalPath ?? target.absolutePath;
  if (!path) {
    return { error: `Local script '${script.rawPath}' could not be resolved safely.` };
  }

  let stats: Awaited<ReturnType<typeof stat>>;
  try {
    stats = await stat(path);
  } catch (error) {
    return { error: `Local script '${script.rawPath}' could not be inspected: ${formatPathResolutionError(error)}.` };
  }

  if (!stats.isFile()) {
    return { error: `Local script '${script.rawPath}' is not a regular file.` };
  }
  if (stats.size > MAX_INSPECTABLE_SCRIPT_BYTES) {
    return { error: `Local script '${script.rawPath}' is too large to inspect safely.` };
  }

  try {
    const content = await readFile(path, "utf8");
    if (content.includes("\0")) {
      return { error: `Local script '${script.rawPath}' appears to be binary and cannot be inspected safely.` };
    }
    return { content };
  } catch (error) {
    return { error: `Local script '${script.rawPath}' could not be read for inspection: ${formatPathResolutionError(error)}.` };
  }
}

async function inspectPackageScriptBeforeExecution(
  state: GuardMeSessionState,
  ctx: GuardedToolCallContext,
  request: PolicyRequest,
  script: PackageScriptExecution,
): Promise<ToolCallBlockResult | undefined> {
  const normalized = await normalizeTargets([script.rawPath], request.cwd, state.homeDir);
  if ("error" in normalized) {
    const synthetic = packageScriptUninspectableRequest(request, script, script.rawPath, normalized.error);
    const decision = evaluatePolicyRequest({
      policy: state.config.config,
      request: synthetic,
      warnedFingerprints: currentWarnedFingerprints(state),
    });
    return (await handlePolicyDecision(state, ctx, synthetic, decision)) ?? block(normalized.error);
  }

  const packageJsonTarget = normalized.targets[0];
  if (!packageJsonTarget) {
    return undefined;
  }

  const readRequest: PolicyRequest = {
    toolName: "bash",
    action: "read",
    cwd: request.cwd,
    targets: [packageJsonTarget],
    fingerprintSeed: `package-script-read:${script.invocation}:${script.scriptName}`,
  };
  const readDecision = evaluatePolicyRequest({
    policy: state.config.config,
    request: readRequest,
    warnedFingerprints: currentWarnedFingerprints(state),
  });
  const readBlock = await handlePolicyDecision(state, ctx, readRequest, readDecision);
  if (readBlock) {
    return block(`GuardMe blocked package script inspection for ${script.invocation}: ${readBlock.reason}`);
  }

  const content = await readInspectablePackageJsonContent(packageJsonTarget, script);
  if ("missing" in content) {
    return undefined;
  }

  if ("error" in content) {
    const synthetic = packageScriptUninspectableRequest(request, script, packageJsonTarget.raw, content.error);
    const decision = evaluatePolicyRequest({
      policy: state.config.config,
      request: synthetic,
      warnedFingerprints: currentWarnedFingerprints(state),
    });
    const handled = await handlePolicyDecision(state, ctx, synthetic, decision);
    return handled ?? block(content.error);
  }

  const inspection = extractScriptCommandsFromContent({
    path: packageJsonTarget.canonicalPath ?? packageJsonTarget.absolutePath ?? script.rawPath,
    content: content.content,
  });
  const scopedInspection = packageScriptInspection(inspection, script.scriptName);
  if (!scopedInspection.commandBearing) {
    return undefined;
  }

  const blockResult = await evaluateScriptContentInspection(state, ctx, request, scopedInspection, {
    sourceKind: "local-script",
    sourcePath: script.rawPath,
    snippetLabel: script.invocation,
    shellHint: true,
    allowCommandDefaultDeny: true,
  });
  if (blockResult) {
    return blockResult;
  }

  return undefined;
}

async function readInspectablePackageJsonContent(
  target: PathTarget,
  script: PackageScriptExecution,
): Promise<{ readonly content: string } | { readonly error: string } | { readonly missing: true }> {
  const path = target.canonicalPath ?? target.absolutePath;
  if (!path) {
    return { error: `package.json for '${script.invocation}' could not be resolved safely.` };
  }

  let stats: Awaited<ReturnType<typeof stat>>;
  try {
    stats = await stat(path);
  } catch (error) {
    if (isNodeError(error) && error.code === "ENOENT") {
      return { missing: true };
    }
    return { error: `package.json for '${script.invocation}' could not be inspected: ${formatPathResolutionError(error)}.` };
  }

  if (!stats.isFile()) {
    return { error: `package.json for '${script.invocation}' is not a regular file.` };
  }
  if (stats.size > MAX_INSPECTABLE_SCRIPT_BYTES) {
    return { error: `package.json for '${script.invocation}' is too large to inspect safely.` };
  }

  try {
    const content = await readFile(path, "utf8");
    if (content.includes("\0")) {
      return { error: `package.json for '${script.invocation}' appears to be binary and cannot be inspected safely.` };
    }
    return { content };
  } catch (error) {
    if (isNodeError(error) && error.code === "ENOENT") {
      return { missing: true };
    }
    return { error: `package.json for '${script.invocation}' could not be read for inspection: ${formatPathResolutionError(error)}.` };
  }
}

function packageScriptInspection(
  inspection: ScriptContentExtractionResult,
  scriptName: string,
): ScriptContentExtractionResult {
  if (inspection.uninspectable) {
    return inspection;
  }

  const scriptNames = packageScriptNames(scriptName);
  const commands = inspection.commands.filter((command) => {
    const extractedName = packageJsonScriptName(command);
    return extractedName ? scriptNames.has(extractedName) : false;
  });

  return { commandBearing: commands.length > 0, commands };
}

function packageScriptNames(scriptName: string): ReadonlySet<string> {
  return new Set([`pre${scriptName}`, scriptName, `post${scriptName}`]);
}

function packageJsonScriptName(command: ExtractedScriptCommand): string | undefined {
  const match = /^package\.json script '(.+)'$/u.exec(command.label);
  return match?.[1];
}

async function scriptCommandPolicyRequest(
  parentRequest: PolicyRequest,
  command: ExtractedScriptCommand,
  source: ScriptInspectionSource,
  homeDir: string | undefined,
): Promise<
  | { readonly request: PolicyRequest; readonly commandClassification: ReturnType<typeof classifyShellCommand> }
  | { readonly error: string }
> {
  const commandClassification = classifyShellCommand(command.command);
  const normalized = await normalizeTargets(commandClassification.targetPaths, parentRequest.cwd, homeDir);
  if ("error" in normalized) {
    return { error: normalized.error };
  }
  const discoveryTargets = await protectedShellDiscoveryTargets(commandClassification, normalized.targets);
  const mutationTargets = await protectedMutationDescendantTargets(commandClassification.primaryAction, normalized.targets);
  return {
    request: {
      toolName: parentRequest.toolName,
      action: commandClassification.primaryAction,
      cwd: parentRequest.cwd,
      command: command.command,
      targets: [
        ...normalized.targets,
        ...discoveryTargets,
        ...mutationTargets,
        { kind: "tool", raw: `${source.sourceKind}:${source.sourcePath ?? source.snippetLabel}:${command.lineStart}:${command.preview}` },
      ],
      riskHint: commandClassification.risk,
      fingerprintSeed: `${source.sourceKind}:${source.sourcePath ?? source.snippetLabel}:${command.context}:${command.lineStart}:${command.normalizedCommand}`,
      reasonCode: "script-content-denied",
      policyMissingReason: `${source.sourceKind === "local-script" ? "Local script" : "Proposed file content"} contains an unapproved command at line ${command.lineStart}: ${command.preview}.`,
      policyMissingGuidance: "Do not write or run generated scripts with unapproved commands. Use safe built-in tools, ask the user for approval, or propose a narrow allowCommands rule.",
      policyMissingRecommendation: "Request user approval for the exact extracted command before retrying.",
      requiresExactCommandAllow: true,
    },
    commandClassification,
  };
}

function uninspectableContentRequest(
  parentRequest: PolicyRequest,
  source: ScriptInspectionSource,
  reason: string,
): PolicyRequest {
  return {
    toolName: parentRequest.toolName,
    action: parentRequest.action,
    cwd: parentRequest.cwd,
    command: `${source.sourceKind}:${source.sourcePath ?? source.snippetLabel}`,
    targets: [{ kind: "tool", raw: `${source.sourceKind}:${source.sourcePath ?? source.snippetLabel}` }],
    riskHint: "medium",
    fingerprintSeed: `${source.sourceKind}:uninspectable:${source.sourcePath ?? source.snippetLabel}:${reason}`,
    reasonCode: source.sourceKind === "local-script" ? "local-script-uninspectable" : "script-content-denied",
    policyMissingReason: reason,
    policyMissingGuidance: "GuardMe could not inspect command-bearing content safely, so it failed closed. Ask the user before retrying or provide a smaller plain-text script.",
    policyMissingRecommendation: "Inspect the content with the user or rewrite it as safe, policy-approved steps.",
  };
}

function localScriptUninspectableRequest(
  parentRequest: PolicyRequest,
  script: LocalScriptExecution,
  path: string,
  reason: string,
): PolicyRequest {
  return {
    toolName: "bash",
    action: "shell",
    cwd: parentRequest.cwd,
    command: script.invocation,
    targets: [{ kind: "tool", raw: `local-script:${path}` }],
    riskHint: "medium",
    fingerprintSeed: `local-script-uninspectable:${path}:${reason}`,
    reasonCode: "local-script-uninspectable",
    policyMissingReason: reason,
    policyMissingGuidance: "GuardMe could not inspect the local script safely, so it failed closed. Ask the user to review the script or add a narrow policy rule after inspection.",
    policyMissingRecommendation: "Do not execute uninspectable local scripts without user approval.",
  };
}

function packageScriptUninspectableRequest(
  parentRequest: PolicyRequest,
  script: PackageScriptExecution,
  path: string,
  reason: string,
): PolicyRequest {
  return {
    toolName: "bash",
    action: "shell",
    cwd: parentRequest.cwd,
    command: script.invocation,
    targets: [{ kind: "tool", raw: `package-script:${path}:${script.scriptName}` }],
    riskHint: "medium",
    fingerprintSeed: `package-script-uninspectable:${path}:${script.scriptName}:${reason}`,
    reasonCode: "local-script-uninspectable",
    policyMissingReason: reason,
    policyMissingGuidance: "GuardMe could not inspect the package script safely, so it failed closed. Ask the user to review package.json or add a narrow policy rule after inspection.",
    policyMissingRecommendation: "Do not execute uninspectable package scripts without user approval.",
  };
}

function currentWarnedFingerprints(state: GuardMeSessionState): ReadonlySet<string> {
  return getGuardMeSessionState()?.warnings.warnedFingerprints ?? state.warnings.warnedFingerprints;
}

function isCommandDefaultDenyDecision(decision: PolicyDecision): boolean {
  return decision.matchedRules.some((rule) => rule.category === "commandDefaultDeny");
}

function formatScriptContentBlockReason(
  sourceKind: ScriptInspectionSourceKind,
  sourcePath: string | undefined,
  command: ExtractedScriptCommand,
  reason: string,
): string {
  const sourceLabel = sourceKind === "local-script" ? "local script" : "proposed file content";
  const location = sourcePath ? ` in ${sourcePath}` : "";
  return `GuardMe blocked ${sourceLabel}${location} at line ${command.lineStart} before execution/mutation. Extracted command: ${command.preview}.\n\n${reason}`;
}

export async function persistApprovalRuleIfRequested(
  state: GuardMeSessionState,
  request: PolicyRequest,
  userDecision: UserDecision,
  policyDecision: PolicyDecision,
): Promise<{ readonly saved: boolean; readonly reason: string; readonly persistedTo: PersistedPolicyTarget }> {
  if (!isPersistentUserDecision(userDecision)) {
    return { saved: true, reason: "No persistent rule requested.", persistedTo: "none" };
  }

  const scope = userDecision.endsWith("global") ? "global" : "local";
  const policyPath = scope === "global" ? state.config.paths.globalPolicyPath : state.config.paths.localPolicyPath;
  const persistenceRequest = policyDecision.suggestedCommandRule && request.command
    ? { ...request, command: policyDecision.suggestedCommandRule, targets: [{ kind: "command" as const, raw: policyDecision.suggestedCommandRule, normalized: policyDecision.suggestedCommandRule }] }
    : request;
  const result = await persistUserDecisionRule({
    cwd: state.cwd,
    homeDir: state.homeDir,
    policyPath,
    scope,
    decision: userDecision,
    request: persistenceRequest,
    hardDenied: policyDecision.risk === "hard-denied",
    reason: `Saved from GuardMe approval decision '${userDecision}'.`,
  });

  return {
    saved: result.saved,
    reason: result.reason ?? (result.saved ? "Saved GuardMe policy rule." : "Unable to save GuardMe policy rule."),
    persistedTo: scope === "global" ? "global-yaml" : "local-yaml",
  };
}

export async function reloadPolicyAfterPersistentDecision(
  state: GuardMeSessionState,
  persistedTo: PersistedPolicyTarget,
): Promise<void> {
  if (persistedTo === "none") {
    return;
  }

  const config = await loadGuardMeConfig({ cwd: state.cwd, homeDir: state.homeDir, loadLocalPolicy: state.projectTrusted });
  const diagnostics = [...state.settings.diagnostics, ...config.diagnostics, ...state.warnings.diagnostics];
  setGuardMeSessionState({
    ...state,
    config,
    diagnostics,
    degraded: diagnostics.some((diagnostic) => diagnostic.severity === "error"),
  });
}

export async function appendApprovalDecisionRecord(
  state: GuardMeSessionState,
  userDecision: UserDecision,
  persistedTo: PersistedPolicyTarget,
  fingerprint: string,
): Promise<void> {
  const globalDecision = persistedTo === "global-yaml" || userDecision.endsWith("global") || (!state.projectTrusted && persistedTo === "none");
  const path = globalDecision ? state.warnings.paths.globalStatePath : state.warnings.paths.localStatePath;
  try {
    const record = await appendDecisionRecord(path, {
      fingerprint,
      scope: globalDecision ? "global" : "project",
      cwd: state.cwd,
      decision: userDecision,
      persistedTo,
      reason: `User selected ${userDecision}.`,
    });
    const currentState = currentSessionStateFor(state);
    if (!currentState) {
      return;
    }
    setGuardMeSessionState({
      ...currentState,
      warnings: {
        ...currentState.warnings,
        records: [...currentState.warnings.records, record],
      },
    });
  } catch (error) {
    recordStateWriteFailure(state, path, globalDecision ? "global" : "local", error);
  }
}

export async function persistCoachingWarningIfNeeded(
  state: GuardMeSessionState,
  request: PolicyRequest,
  decision: PolicyDecision,
): Promise<void> {
  if (decision.outcome !== "coach" && decision.outcome !== "deny") {
    return;
  }

  const fingerprint = decision.outcome === "coach" ? decision.fingerprint : createPolicyFingerprint(request);
  const stateScope = state.projectTrusted ? "project" : "global";
  const statePath = state.projectTrusted ? state.warnings.paths.localStatePath : state.warnings.paths.globalStatePath;
  let record: Awaited<ReturnType<typeof appendWarningRecord>>;
  try {
    record = await appendWarningRecord(statePath, {
      fingerprint,
      scope: stateScope,
      cwd: state.cwd,
      toolName: request.toolName,
      action: request.action,
      risk: decision.risk,
      target: describePolicyRequestTarget(request),
      reason: decision.reason,
      matchedRules: decision.matchedRules,
      ...(decision.reasonCode ? { reasonCode: decision.reasonCode } : {}),
    });
  } catch (error) {
    recordStateWriteFailure(state, statePath, stateScope === "global" ? "global" : "local", error);
    return;
  }

  const currentState = currentSessionStateFor(state);
  if (!currentState) {
    return;
  }

  const warningCounts = new Map(currentState.warnings.warningCounts);
  warningCounts.set(record.fingerprint, (warningCounts.get(record.fingerprint) ?? 0) + Math.max(record.count, 1));
  setGuardMeSessionState({
    ...currentState,
    warnings: {
      ...currentState.warnings,
      records: [...currentState.warnings.records, record],
      warnedFingerprints: new Set(warningCounts.keys()),
      warningCounts,
    },
  });
}

function recordStateWriteFailure(
  state: GuardMeSessionState,
  path: string,
  sourceKind: StateFileSourceKind,
  error: unknown,
): void {
  const diagnostic: PolicyDiagnostic = {
    severity: "error",
    code: "state.writeFailed",
    message: `Unable to write GuardMe state file: ${formatStateWriteError(error)}`,
    source: { kind: sourceKind, path },
    path,
  };
  const currentState = currentSessionStateFor(state);
  if (!currentState) {
    return;
  }
  const diagnostics = [...currentState.diagnostics, diagnostic];
  setGuardMeSessionState({
    ...currentState,
    diagnostics,
    degraded: true,
  });
}

function currentSessionStateFor(state: GuardMeSessionState): GuardMeSessionState | undefined {
  const currentState = getGuardMeSessionState();
  return currentState?.cwd === state.cwd ? currentState : undefined;
}

function refreshGuardMeStatus(ctx: GuardedToolCallContext): void {
  const currentState = getGuardMeSessionState();
  if (!currentState) {
    return;
  }
  ctx.ui?.setStatus?.(EXTENSION_STATUS_KEY, formatGuardMeStatus(currentState));
}

function policyDecisionToToolBlock(request: PolicyRequest, decision: PolicyDecision): ToolCallBlockResult | undefined {
  if (decision.outcome === "allow") {
    return undefined;
  }

  if (decision.outcome === "coach") {
    const reason = `${decision.reason}\n\nGuardMe coaching: ${decision.guidance}`;
    recordDecisionGuidance(request, decision, decision.guidance);
    return block(reason);
  }

  if (decision.outcome === "needs-user-decision") {
    const guidance = "GuardMe requires user approval for this action before it can run.";
    recordDecisionGuidance(request, decision, guidance);
    return block(`${decision.reason}\n\n${guidance}`);
  }

  recordDecisionGuidance(request, decision, "Use safe built-in tools, narrow the request, or ask the user to update GuardMe policy.");
  return block(decision.reason);
}

function recordDecisionGuidance(request: PolicyRequest, decision: PolicyDecision, guidance: string): void {
  recordGuardMeGuidance({
    toolName: request.toolName,
    action: request.action,
    risk: decision.risk,
    reason: redactSensitiveText(decision.reason),
    guidance: redactSensitiveText(guidance),
    matchedRules: decision.matchedRules,
    target: redactSensitiveText(describePolicyRequestTarget(request)),
    ...(decision.reasonCode ? { reasonCode: decision.reasonCode } : {}),
  });
}

function isPersistentUserDecision(decision: UserDecision): boolean {
  return decision === "allow-local" || decision === "deny-local" || decision === "allow-global" || decision === "deny-global";
}

function isGuardedToolName(toolName: string): boolean {
  return GUARDED_TOOL_NAME_SET.has(toolName);
}

function isEditMutationToolName(toolName: string): boolean {
  return toolName === "write" || toolName === "edit";
}

function toolNameToAction(toolName: string): PolicyAction {
  if (toolName === "write") {
    return "write";
  }
  if (toolName === "edit") {
    return "edit";
  }
  if (toolName === "find" || toolName === "ls") {
    return "list";
  }
  return "read";
}

function extractToolPathValues(toolName: string, input: unknown): readonly string[] {
  const record = isRecord(input) ? input : {};
  const candidates: string[] = [];

  for (const key of ["path", "file", "target", "directory", "dir", "cwd"] as const) {
    const value = record[key];
    if (typeof value === "string" && value.trim() !== "") {
      candidates.push(value);
    }
  }

  for (const key of ["paths", "files", "targets", "directories"] as const) {
    const value = record[key];
    if (Array.isArray(value)) {
      candidates.push(...value.filter((item): item is string => typeof item === "string" && item.trim() !== ""));
    }
  }

  if (candidates.length === 0 && (toolName === "find" || toolName === "ls" || toolName === "grep")) {
    candidates.push(".");
  }

  return [...new Set(candidates)];
}

async function protectedMutationDescendantTargets(
  action: PolicyAction,
  targets: readonly PathTarget[],
): Promise<readonly PathTarget[]> {
  if (action !== "delete" && action !== "move" && action !== "rename") {
    return [];
  }

  const protectedTargets: PathTarget[] = [];
  for (const target of targets) {
    if (!target.exists || !target.canonicalPath) {
      continue;
    }
    for (const childPath of await protectedMutationDescendantPaths(target.canonicalPath)) {
      protectedTargets.push({
        kind: "path",
        raw: childPath,
        absolutePath: childPath,
        canonicalPath: childPath,
        exists: true,
        projectRoot: target.projectRoot,
        isInsideProject: target.isInsideProject,
      });
    }
  }
  return protectedTargets;
}

async function protectedShellDiscoveryTargets(
  commandClassification: ReturnType<typeof classifyShellCommand>,
  targets: readonly PathTarget[],
): Promise<readonly PathTarget[]> {
  const protectedTargets: PathTarget[] = [];
  for (const segment of extractExecutableCommandSegments(commandClassification.rawCommand)) {
    if (segment.commandName === "find") {
      protectedTargets.push(
        ...(await protectedDiscoveryTargets(
          "find",
          { pattern: shellFindPattern(segment.originalText) ?? shellFindPattern(segment.normalizedText) ?? "*" },
          pathTargetsForCommandSegment(segment, targets),
        )),
      );
      continue;
    }
    if (isGrepCommandName(segment.commandName) && shellGrepIsRecursive(segment.originalText)) {
      protectedTargets.push(...(await protectedDiscoveryTargets("grep", {}, pathTargetsForCommandSegment(segment, targets))));
    }
  }
  return dedupePathTargets(protectedTargets);
}

function isGrepCommandName(commandName: string | undefined): boolean {
  return commandName === "grep" || commandName === "ggrep";
}

function pathTargetsForCommandSegment(
  segment: ExecutableCommandSegment,
  targets: readonly PathTarget[],
): readonly PathTarget[] {
  const segmentRawTargets = new Set(segment.targetPaths);
  const segmentTargets = targets.filter((target) => segmentRawTargets.has(target.raw));
  return segmentTargets.length > 0 ? segmentTargets : targets;
}

function dedupePathTargets(targets: readonly PathTarget[]): readonly PathTarget[] {
  const seen = new Set<string>();
  return targets.filter((target) => {
    const key = target.canonicalPath ?? target.absolutePath ?? target.raw;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

function shellGrepIsRecursive(command: string): boolean {
  const tokens = tokenizeShellCommand(command);
  const grepIndex = tokens.findIndex((token) => isGrepCommandName(basename(token).toLowerCase()));
  if (grepIndex < 0) {
    return false;
  }
  for (const token of tokens.slice(grepIndex + 1)) {
    if (token === "--") {
      return false;
    }
    if (token === "--recursive" || isRecursiveShortGrepOption(token)) {
      return true;
    }
  }
  return false;
}

function isRecursiveShortGrepOption(token: string): boolean {
  return token.startsWith("-") && !token.startsWith("--") && token.slice(1).toLowerCase().includes("r");
}

function shellFindPattern(command: string): string | undefined {
  const tokens = tokenizeShellCommand(command);
  const findIndex = tokens.findIndex((token) => basename(token).toLowerCase() === "find");
  if (findIndex < 0) {
    return undefined;
  }
  for (let index = findIndex + 1; index < tokens.length - 1; index += 1) {
    const token = tokens[index];
    if (token === "-name" || token === "-iname" || token === "-path" || token === "-ipath" || token === "-wholename") {
      return tokens[index + 1];
    }
  }
  return undefined;
}

async function protectedDiscoveryTargets(
  toolName: string,
  input: unknown,
  targets: readonly PathTarget[],
): Promise<readonly PathTarget[]> {
  if (toolName !== "grep" && toolName !== "find") {
    return [];
  }

  const scopedPattern = toolName === "grep" ? readStringProperty(input, "glob") : readStringProperty(input, "pattern");
  if (scopedPattern && isCredentialLikeDiscoveryPattern(scopedPattern)) {
    return [{ kind: "path", raw: scopedPattern }];
  }
  if (!discoveryPatternMayReadProtectedDescendants(toolName, scopedPattern)) {
    return [];
  }

  const protectedTargets: PathTarget[] = [];
  for (const target of targets) {
    if (!target.exists || !target.canonicalPath) {
      continue;
    }
    for (const childPath of await directProtectedChildren(target.canonicalPath)) {
      protectedTargets.push({
        kind: "path",
        raw: childPath,
        absolutePath: childPath,
        canonicalPath: childPath,
        exists: true,
        projectRoot: target.projectRoot,
        isInsideProject: target.isInsideProject,
      });
    }
  }
  return protectedTargets;
}

function discoveryPatternMayReadProtectedDescendants(toolName: string, scopedPattern: string | undefined): boolean {
  if (toolName === "grep" && scopedPattern === undefined) {
    return true;
  }
  const normalized = scopedPattern?.trim();
  return (
    normalized === undefined ||
    normalized === "" ||
    normalized === "*" ||
    normalized === "**" ||
    normalized === "**/*" ||
    normalized === "./**" ||
    normalized === "./**/*"
  );
}

const MAX_PROTECTED_MUTATION_SCAN_DEPTH = 8;
const MAX_PROTECTED_MUTATION_SCAN_ENTRIES = 4096;

async function protectedMutationDescendantPaths(directoryPath: string): Promise<readonly string[]> {
  const scan: ProtectedMutationScan = {
    protectedPaths: [],
    queue: [{ path: directoryPath, depth: 0 }],
    scannedEntries: 0,
  };

  for (let index = 0; index < scan.queue.length && scan.scannedEntries < MAX_PROTECTED_MUTATION_SCAN_ENTRIES; index += 1) {
    await scanProtectedMutationDirectory(scan.queue[index]!, scan);
  }

  return [...new Set(scan.protectedPaths)];
}

interface ProtectedMutationScan {
  readonly protectedPaths: string[];
  readonly queue: { readonly path: string; readonly depth: number }[];
  scannedEntries: number;
}

async function scanProtectedMutationDirectory(
  current: { readonly path: string; readonly depth: number },
  scan: ProtectedMutationScan,
): Promise<void> {
  for (const entry of await readDirectoryDirents(current.path)) {
    if (scan.scannedEntries >= MAX_PROTECTED_MUTATION_SCAN_ENTRIES) {
      break;
    }
    scan.scannedEntries += 1;
    recordProtectedMutationEntry(current, entry, scan);
  }
}

function recordProtectedMutationEntry(
  current: { readonly path: string; readonly depth: number },
  entry: Dirent<string>,
  scan: ProtectedMutationScan,
): void {
  const childPath = join(current.path, entry.name);
  if (isProtectedMutationEntry(entry.name)) {
    scan.protectedPaths.push(childPath);
    return;
  }
  if (entry.isDirectory() && current.depth < MAX_PROTECTED_MUTATION_SCAN_DEPTH) {
    scan.queue.push({ path: childPath, depth: current.depth + 1 });
  }
}

async function readDirectoryDirents(directoryPath: string): Promise<Dirent<string>[]> {
  try {
    return await readdir(directoryPath, { withFileTypes: true });
  } catch {
    return [];
  }
}

async function directProtectedChildren(directoryPath: string): Promise<readonly string[]> {
  const entries = await readDirectoryEntries(directoryPath);
  const protectedChildren = entries.filter(isProtectedDiscoveryEntry).map((entry) => join(directoryPath, entry));
  if (entries.includes(".config") && (await directoryContains(join(directoryPath, ".config"), "gcloud"))) {
    protectedChildren.push(join(directoryPath, ".config", "gcloud"));
  }
  if (entries.includes(".docker") && (await directoryContains(join(directoryPath, ".docker"), "config.json"))) {
    protectedChildren.push(join(directoryPath, ".docker", "config.json"));
  }
  return protectedChildren;
}

async function readDirectoryEntries(directoryPath: string): Promise<readonly string[]> {
  try {
    return await readdir(directoryPath);
  } catch {
    return [];
  }
}

async function directoryContains(directoryPath: string, entryName: string): Promise<boolean> {
  try {
    return (await readdir(directoryPath)).includes(entryName);
  } catch {
    return false;
  }
}

function isProtectedMutationEntry(entry: string): boolean {
  const lower = entry.toLowerCase();
  return (
    lower === ".git" ||
    lower === "package-lock.json" ||
    lower === "pnpm-lock.yaml" ||
    lower === "yarn.lock" ||
    lower.startsWith(".env.") ||
    isProtectedDiscoveryEntry(entry)
  );
}

function isProtectedDiscoveryEntry(entry: string): boolean {
  const lower = entry.toLowerCase();
  return (
    lower === ".env" ||
    lower === ".npmrc" ||
    lower === ".pypirc" ||
    lower === ".netrc" ||
    lower === ".ssh" ||
    lower === ".gnupg" ||
    lower === ".1password" ||
    lower === ".aws" ||
    lower === ".azure" ||
    lower.includes("credential") ||
    lower.includes("secret") ||
    lower.includes("token")
  );
}

function isCredentialLikeDiscoveryPattern(pattern: string): boolean {
  const lower = pattern.toLowerCase();
  const basename = lower.replaceAll("\\", "/").split("/").pop() ?? lower;
  return (
    isProtectedDiscoveryEntry(basename) ||
    isProtectedEnvDiscoveryPattern(lower) ||
    lower.includes(".npmrc") ||
    lower.includes(".pypirc") ||
    lower.includes(".netrc") ||
    lower.includes(".ssh") ||
    lower.includes(".gnupg") ||
    lower.includes(".1password") ||
    lower.includes(".aws") ||
    lower.includes(".azure") ||
    lower.includes(".config/gcloud") ||
    lower.includes(".docker/config.json") ||
    lower.includes("credential") ||
    lower.includes("secret") ||
    lower.includes("token")
  );
}

function isProtectedEnvDiscoveryPattern(pattern: string): boolean {
  return pattern
    .replaceAll("\\", "/")
    .split("/")
    .filter(Boolean)
    .some((segment) => segment === ".env" || (segment.startsWith(".env") && hasGlobWildcard(segment)));
}

function hasGlobWildcard(segment: string): boolean {
  return segment.includes("*") || segment.includes("?") || segment.includes("[") || segment.includes("]");
}

async function normalizeTargets(
  pathValues: readonly string[],
  cwd: string,
  homeDir?: string,
): Promise<{ readonly targets: readonly PathTarget[] } | { readonly error: string }> {
  const targets: PolicyTarget[] = [];
  for (const pathValue of pathValues) {
    try {
      const normalized = await normalizePolicyPath(pathValue, { cwd, ...(homeDir ? { homeDir } : {}) });
      targets.push(pathTargetFromNormalizedPath(normalized));
    } catch (error) {
      return { error: `GuardMe could not safely resolve one or more tool paths (${formatPathResolutionError(error)}). Blocking by default.` };
    }
  }
  return { targets: targets.filter((target): target is PathTarget => target.kind === "path") };
}

function toApprovalContext(ctx: GuardedToolCallContext): ApprovalUiContext {
  return {
    cwd: ctx.cwd,
    hasUI: ctx.hasUI,
    mode: ctx.mode,
    ui: isRecord(ctx.ui) ? ctx.ui : {},
  } as ApprovalUiContext;
}

function describePolicyRequestTarget(request: PolicyRequest): string {
  if (request.command) {
    return request.command;
  }
  const targets = request.targets.map((target) => target.raw).filter(Boolean);
  return targets.length > 0 ? targets.join(", ") : `${request.toolName}:${request.action}`;
}

function formatPathResolutionError(error: unknown): string {
  if (isNodeError(error) && typeof error.code === "string") {
    return error.code;
  }
  return error instanceof Error ? error.name : "unknown error";
}

function formatStateWriteError(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}

function readStringProperty(input: unknown, key: string): string | undefined {
  if (!isRecord(input)) {
    return undefined;
  }
  const value = input[key];
  return typeof value === "string" && value.trim() !== "" ? value : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return typeof error === "object" && error !== null && "code" in error;
}

function block(reason: string): ToolCallBlockResult {
  return { block: true, reason };
}
