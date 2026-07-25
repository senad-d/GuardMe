import type { PolicyDiagnostic } from "../policy/action.ts";

export const APPROVAL_MODES = ["auto", "interactive", "block"] as const;
export type ApprovalMode = (typeof APPROVAL_MODES)[number];

export const APPROVAL_MODE_ENV = "GUARDME_APPROVAL_MODE";
export const DEFAULT_APPROVAL_MODE: ApprovalMode = "auto";

const APPROVAL_MODE_SET: ReadonlySet<string> = new Set(APPROVAL_MODES);

export interface ApprovalModeEnvironmentResolution {
  readonly mode: ApprovalMode;
  readonly diagnostics: readonly PolicyDiagnostic[];
}

export function isApprovalMode(value: unknown): value is ApprovalMode {
  return typeof value === "string" && APPROVAL_MODE_SET.has(value);
}

export function resolveApprovalModeEnvironment(
  configuredMode: ApprovalMode,
  environment: Readonly<Record<string, string | undefined>> = process.env,
): ApprovalModeEnvironmentResolution {
  const value = environment[APPROVAL_MODE_ENV];
  if (value === undefined) {
    return { mode: configuredMode, diagnostics: [] };
  }
  if (isApprovalMode(value)) {
    return { mode: value, diagnostics: [] };
  }
  return {
    mode: "block",
    diagnostics: [
      {
        severity: "error",
        code: "config.invalidApprovalModeEnvironment",
        message: `${APPROVAL_MODE_ENV} must be one of: ${APPROVAL_MODES.join(", ")}. GuardMe is using block mode.`,
      },
    ],
  };
}
