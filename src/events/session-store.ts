import type { GuardedToolContract } from "../constants.ts";
import type { LoadedGuardMeConfig } from "../config/load-config.ts";
import type { LoadedGuardMeRuntimeSettings } from "../config/runtime-settings.ts";
import type { MatchedRule, PolicyDiagnostic } from "../policy/action.ts";
import type { LoadedWarningState } from "../state/warnings.ts";

export interface GuardMeGuidanceEvent {
  readonly timestamp: string;
  readonly toolName: string;
  readonly action: string;
  readonly risk: string;
  readonly reason: string;
  readonly guidance: string;
  readonly matchedRules: readonly MatchedRule[];
  readonly target?: string;
  readonly reasonCode?: string;
}

export interface AgentApprovalState {
  readonly currentTurn: number;
  readonly blockedTurnByFingerprint: ReadonlyMap<string, number>;
  /**
   * Fingerprints of policy-missing commands that already received one
   * automatic later-turn approval this session. They stay allowed for the
   * rest of the session; dangerous actions never enter this set.
   */
  readonly sessionAllowedFingerprints: ReadonlySet<string>;
}

export type AgentApprovalEligibility = "unseen" | "same-turn" | "later-turn";

export interface GuardMeSessionState {
  readonly cwd: string;
  readonly homeDir?: string;
  readonly projectTrusted: boolean;
  readonly enabled: boolean;
  readonly insecureEdits: boolean;
  readonly loadedAt: string;
  readonly config: LoadedGuardMeConfig;
  readonly settings: LoadedGuardMeRuntimeSettings;
  readonly warnings: LoadedWarningState;
  readonly agentApprovals: AgentApprovalState;
  readonly diagnostics: readonly PolicyDiagnostic[];
  readonly degraded: boolean;
  readonly lastGuidance?: GuardMeGuidanceEvent;
}

let currentSessionState: GuardMeSessionState | undefined;
// Retained across session shutdown so guarded aliases fail closed (instead of
// silently unguarded) if a tool call arrives while no session state exists.
let lastKnownGuardedTools: Readonly<Record<string, GuardedToolContract>> | undefined;

export function setGuardMeSessionState(state: GuardMeSessionState): void {
  currentSessionState = state;
  lastKnownGuardedTools = state.config.config.guardedTools;
}

export function getLastKnownGuardedTools(): Readonly<Record<string, GuardedToolContract>> | undefined {
  return lastKnownGuardedTools;
}

export function getGuardMeSessionState(): GuardMeSessionState | undefined {
  return currentSessionState;
}

export function clearGuardMeSessionState(): void {
  currentSessionState = undefined;
}

export function beginGuardMeAgentTurn(): void {
  if (!currentSessionState) {
    return;
  }
  currentSessionState = {
    ...currentSessionState,
    agentApprovals: {
      ...currentSessionState.agentApprovals,
      currentTurn: currentSessionState.agentApprovals.currentTurn + 1,
    },
  };
}

export function agentApprovalEligibility(fingerprint: string): AgentApprovalEligibility {
  if (!currentSessionState) {
    return "unseen";
  }
  const blockedTurn = currentSessionState.agentApprovals.blockedTurnByFingerprint.get(fingerprint);
  if (blockedTurn === undefined) {
    return "unseen";
  }
  return blockedTurn < currentSessionState.agentApprovals.currentTurn ? "later-turn" : "same-turn";
}

export function recordAgentApprovalBlock(fingerprint: string): void {
  if (!currentSessionState || currentSessionState.agentApprovals.blockedTurnByFingerprint.has(fingerprint)) {
    return;
  }
  const blockedTurnByFingerprint = new Map(currentSessionState.agentApprovals.blockedTurnByFingerprint);
  blockedTurnByFingerprint.set(fingerprint, currentSessionState.agentApprovals.currentTurn);
  currentSessionState = {
    ...currentSessionState,
    agentApprovals: {
      ...currentSessionState.agentApprovals,
      blockedTurnByFingerprint,
    },
  };
}

export function deferAgentApproval(fingerprint: string): void {
  if (!currentSessionState) {
    return;
  }
  const blockedTurnByFingerprint = new Map(currentSessionState.agentApprovals.blockedTurnByFingerprint);
  blockedTurnByFingerprint.set(fingerprint, currentSessionState.agentApprovals.currentTurn);
  currentSessionState = {
    ...currentSessionState,
    agentApprovals: {
      ...currentSessionState.agentApprovals,
      blockedTurnByFingerprint,
    },
  };
}

export function recordSessionAgentAllow(fingerprint: string): void {
  if (!currentSessionState || currentSessionState.agentApprovals.sessionAllowedFingerprints.has(fingerprint)) {
    return;
  }
  const sessionAllowedFingerprints = new Set(currentSessionState.agentApprovals.sessionAllowedFingerprints);
  sessionAllowedFingerprints.add(fingerprint);
  currentSessionState = {
    ...currentSessionState,
    agentApprovals: {
      ...currentSessionState.agentApprovals,
      sessionAllowedFingerprints,
    },
  };
}

export function hasSessionAgentAllow(fingerprint: string): boolean {
  return currentSessionState?.agentApprovals.sessionAllowedFingerprints.has(fingerprint) ?? false;
}

export function consumeAgentApproval(fingerprint: string): void {
  if (!currentSessionState?.agentApprovals.blockedTurnByFingerprint.has(fingerprint)) {
    return;
  }
  const blockedTurnByFingerprint = new Map(currentSessionState.agentApprovals.blockedTurnByFingerprint);
  blockedTurnByFingerprint.delete(fingerprint);
  currentSessionState = {
    ...currentSessionState,
    agentApprovals: {
      ...currentSessionState.agentApprovals,
      blockedTurnByFingerprint,
    },
  };
}

export function recordGuardMeGuidance(guidance: Omit<GuardMeGuidanceEvent, "timestamp">): void {
  if (!currentSessionState) {
    return;
  }
  currentSessionState = {
    ...currentSessionState,
    lastGuidance: {
      ...guidance,
      timestamp: new Date().toISOString(),
    },
  };
}

export function clearGuardMeGuidance(): void {
  if (!currentSessionState?.lastGuidance) {
    return;
  }
  const { lastGuidance: _lastGuidance, ...state } = currentSessionState;
  currentSessionState = state;
}

export function formatGuardMeStatus(state: GuardMeSessionState): string | undefined {
  if (!state.enabled) {
    return undefined;
  }
  return "🛡️\u00a0";
}
