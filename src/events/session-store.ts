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

export interface GuardMeSessionState {
  readonly cwd: string;
  readonly homeDir?: string;
  readonly projectTrusted: boolean;
  readonly enabled: boolean;
  readonly loadedAt: string;
  readonly config: LoadedGuardMeConfig;
  readonly settings: LoadedGuardMeRuntimeSettings;
  readonly warnings: LoadedWarningState;
  readonly diagnostics: readonly PolicyDiagnostic[];
  readonly degraded: boolean;
  readonly lastGuidance?: GuardMeGuidanceEvent;
}

let currentSessionState: GuardMeSessionState | undefined;

export function setGuardMeSessionState(state: GuardMeSessionState): void {
  currentSessionState = state;
}

export function getGuardMeSessionState(): GuardMeSessionState | undefined {
  return currentSessionState;
}

export function clearGuardMeSessionState(): void {
  currentSessionState = undefined;
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
  const diagnosticCount = state.diagnostics.length;
  const warningCount = state.warnings.warnedFingerprints.size;
  if (!state.enabled) {
    return undefined;
  }
  if (state.degraded) {
    return `🛡️ degraded (${diagnosticCount} diagnostic${diagnosticCount === 1 ? "" : "s"})`;
  }
  return warningCount > 0 ? `🛡️ (${warningCount} warning${warningCount === 1 ? "" : "s"})` : "🛡️";
}
