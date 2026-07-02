import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

import { EXTENSION_DISPLAY_NAME, EXTENSION_STATUS_KEY } from "../constants.ts";
import { loadGuardMeConfig } from "../config/load-config.ts";
import { loadGuardMeRuntimeSettings } from "../config/runtime-settings.ts";
import { loadWarningState } from "../state/warnings.ts";
import {
  clearGuardMeSessionState,
  formatGuardMeStatus,
  setGuardMeSessionState,
  type GuardMeSessionState,
} from "./session-store.ts";

export interface GuardMeLifecycleContext {
  readonly cwd: string;
  readonly hasUI: boolean;
  readonly isProjectTrusted: () => boolean;
  readonly ui: {
    readonly setStatus: (key: string, text: string | undefined) => void;
    readonly notify?: (message: string, type?: "info" | "warning" | "error") => void;
  };
}

export interface StartGuardMeSessionOptions {
  readonly homeDir?: string;
  readonly projectTrusted?: boolean;
}

/** Register GuardMe session lifecycle handlers. */
export function registerLifecycle(pi: ExtensionAPI): void {
  pi.on("session_start", async (_event, ctx) => {
    await startGuardMeSession(ctx, {});
  });

  pi.on("session_shutdown", (_event, ctx) => {
    stopGuardMeSession(ctx);
  });
}

export async function startGuardMeSession(
  ctx: GuardMeLifecycleContext,
  options: StartGuardMeSessionOptions = {},
): Promise<GuardMeSessionState> {
  const projectTrusted = options.projectTrusted ?? ctx.isProjectTrusted();
  const settings = await loadGuardMeRuntimeSettings({ cwd: ctx.cwd, loadLocalSettings: projectTrusted });
  const config = await loadGuardMeConfig({ cwd: ctx.cwd, homeDir: options.homeDir, loadLocalPolicy: projectTrusted });
  const warnings = await loadWarningState({ cwd: ctx.cwd, homeDir: options.homeDir, loadLocalState: projectTrusted });
  const diagnostics = [...settings.diagnostics, ...config.diagnostics, ...warnings.diagnostics];
  const degraded = diagnostics.some((diagnostic) => diagnostic.severity === "error");
  const state: GuardMeSessionState = {
    cwd: ctx.cwd,
    ...(options.homeDir ? { homeDir: options.homeDir } : {}),
    projectTrusted,
    enabled: settings.settings.enabled,
    insecureEdits: settings.settings.insecureEdits,
    loadedAt: new Date().toISOString(),
    config,
    settings,
    warnings,
    diagnostics,
    degraded,
  };

  setGuardMeSessionState(state);
  ctx.ui.setStatus(EXTENSION_STATUS_KEY, formatGuardMeStatus(state));

  if (ctx.hasUI && degraded) {
    ctx.ui.notify?.(`${EXTENSION_DISPLAY_NAME} loaded with ${diagnostics.length} diagnostic${diagnostics.length === 1 ? "" : "s"}. Run /guardme for details.`, "warning");
  }

  return state;
}

export function stopGuardMeSession(ctx: Pick<GuardMeLifecycleContext, "ui">): void {
  clearGuardMeSessionState();
  ctx.ui.setStatus(EXTENSION_STATUS_KEY, undefined);
}

export { getGuardMeSessionState } from "./session-store.ts";
