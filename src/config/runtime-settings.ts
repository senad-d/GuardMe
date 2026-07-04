import { lstat, mkdir, readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";

import { LOCAL_SETTINGS_PATH, POLICY_VERSION } from "../constants.ts";
import type { PolicyDiagnostic } from "../policy/action.ts";
import { existingSymlinkInPath, isNodeError, writeTextAtomically } from "./safe-fs.ts";

export interface GuardMeRuntimeSettingsPaths {
  readonly settingsPath: string;
  readonly displaySettingsPath: typeof LOCAL_SETTINGS_PATH;
}

export interface GuardMeRuntimeSettings {
  readonly version: typeof POLICY_VERSION;
  readonly enabled: boolean;
  readonly insecureEdits: boolean;
}

export interface LoadedGuardMeRuntimeSettings {
  readonly paths: GuardMeRuntimeSettingsPaths;
  readonly settings: GuardMeRuntimeSettings;
  readonly found: boolean;
  readonly diagnostics: readonly PolicyDiagnostic[];
}

export interface LoadGuardMeRuntimeSettingsOptions {
  readonly cwd: string;
  readonly loadLocalSettings?: boolean;
}

export interface WriteGuardMeRuntimeSettingsOptions {
  readonly cwd: string;
  readonly enabled?: boolean;
  readonly insecureEdits?: boolean;
}

const MAX_SETTINGS_FILE_BYTES = 64 * 1024;
const DEFAULT_RUNTIME_SETTINGS: GuardMeRuntimeSettings = {
  version: POLICY_VERSION,
  enabled: true,
  insecureEdits: false,
};

export function resolveRuntimeSettingsPath(cwd: string): GuardMeRuntimeSettingsPaths {
  return {
    settingsPath: join(resolve(cwd), ".pi", "agent", "guardme-settings.json"),
    displaySettingsPath: LOCAL_SETTINGS_PATH,
  };
}

export async function loadGuardMeRuntimeSettings(
  options: LoadGuardMeRuntimeSettingsOptions,
): Promise<LoadedGuardMeRuntimeSettings> {
  const paths = resolveRuntimeSettingsPath(options.cwd);
  const safeDefault = defaultLoadedSettings(paths, false, []);
  if (options.loadLocalSettings === false) {
    return skippedLocalRuntimeSettings(paths);
  }

  let unsafePath: string | undefined;
  try {
    unsafePath = await existingSymlinkInPath(paths.settingsPath, options.cwd, true);
  } catch (error) {
    return defaultLoadedSettings(paths, false, [
      settingsDiagnostic(
        "settings.inspectFailed",
        `Unable to inspect GuardMe settings path: ${formatSettingsError(error)}`,
        paths.settingsPath,
      ),
    ]);
  }
  if (unsafePath) {
    return defaultLoadedSettings(paths, false, [
      settingsDiagnostic(
        "settings.symlinkRejected",
        "Refusing to read GuardMe runtime settings through a symbolic link.",
        unsafePath,
      ),
    ]);
  }

  try {
    const fileStats = await lstat(paths.settingsPath);
    if (!fileStats.isFile()) {
      return defaultLoadedSettings(paths, false, [
        settingsDiagnostic("settings.notFile", "GuardMe runtime settings path is not a regular file.", paths.settingsPath),
      ]);
    }
    if (fileStats.size > MAX_SETTINGS_FILE_BYTES) {
      return defaultLoadedSettings(paths, false, [
        settingsDiagnostic(
          "settings.fileTooLarge",
          `GuardMe runtime settings file is too large to read safely (${fileStats.size} bytes).`,
          paths.settingsPath,
        ),
      ]);
    }
  } catch (error) {
    if (isNodeError(error) && error.code === "ENOENT") {
      return safeDefault;
    }
    return defaultLoadedSettings(paths, false, [
      settingsDiagnostic(
        "settings.inspectFailed",
        `Unable to inspect GuardMe runtime settings: ${formatSettingsError(error)}`,
        paths.settingsPath,
      ),
    ]);
  }

  let text: string;
  try {
    text = await readFile(paths.settingsPath, "utf8");
  } catch (error) {
    if (isNodeError(error) && error.code === "ENOENT") {
      return safeDefault;
    }
    return defaultLoadedSettings(paths, false, [
      settingsDiagnostic(
        "settings.readFailed",
        `Unable to read GuardMe runtime settings: ${formatSettingsError(error)}`,
        paths.settingsPath,
      ),
    ]);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch (error) {
    return defaultLoadedSettings(paths, true, [
      settingsDiagnostic(
        "settings.invalidJson",
        `Ignoring malformed GuardMe runtime settings JSON: ${formatSettingsError(error)}`,
        paths.settingsPath,
      ),
    ]);
  }

  const validated = validateRuntimeSettings(parsed, paths.settingsPath);
  if (validated.diagnostics.length > 0) {
    return defaultLoadedSettings(paths, true, validated.diagnostics);
  }

  return {
    paths,
    settings: validated.settings,
    found: true,
    diagnostics: [],
  };
}

export async function writeGuardMeRuntimeSettings(options: WriteGuardMeRuntimeSettingsOptions): Promise<void> {
  const paths = resolveRuntimeSettingsPath(options.cwd);
  const targetPath = resolve(paths.settingsPath);
  const unsafeBefore = await existingSymlinkInPath(targetPath, options.cwd, true);
  if (unsafeBefore) {
    throw new Error(`GuardMe settings writes do not follow symbolic links: ${unsafeBefore}`);
  }

  const directory = dirname(targetPath);
  await mkdir(directory, { recursive: true });

  const unsafeAfter = await existingSymlinkInPath(targetPath, options.cwd, true);
  if (unsafeAfter) {
    throw new Error(`GuardMe settings writes do not follow symbolic links: ${unsafeAfter}`);
  }

  const current = await readExistingRuntimeSettingsForWrite(targetPath);
  const settings: GuardMeRuntimeSettings = {
    version: POLICY_VERSION,
    enabled: options.enabled ?? current.enabled,
    insecureEdits: options.insecureEdits ?? current.insecureEdits,
  };
  await writeTextAtomically(targetPath, `${JSON.stringify(settings, null, 2)}\n`, ".guardme-settings");
}

async function readExistingRuntimeSettingsForWrite(path: string): Promise<GuardMeRuntimeSettings> {
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch {
    return DEFAULT_RUNTIME_SETTINGS;
  }

  try {
    const parsed = JSON.parse(text) as unknown;
    const validated = validateRuntimeSettings(parsed, path);
    return validated.diagnostics.length === 0 ? validated.settings : DEFAULT_RUNTIME_SETTINGS;
  } catch {
    return DEFAULT_RUNTIME_SETTINGS;
  }
}

function defaultLoadedSettings(
  paths: GuardMeRuntimeSettingsPaths,
  found: boolean,
  diagnostics: readonly PolicyDiagnostic[],
): LoadedGuardMeRuntimeSettings {
  return {
    paths,
    settings: DEFAULT_RUNTIME_SETTINGS,
    found,
    diagnostics,
  };
}

function skippedLocalRuntimeSettings(paths: GuardMeRuntimeSettingsPaths): LoadedGuardMeRuntimeSettings {
  return defaultLoadedSettings(paths, false, [
    {
      severity: "info",
      code: "settings.localSettingsSkippedUntrustedProject",
      message: "Project is not trusted; local GuardMe runtime settings were not loaded.",
      source: { kind: "local", path: paths.settingsPath },
      path: paths.settingsPath,
    },
  ]);
}

function validateRuntimeSettings(parsed: unknown, path: string): { readonly settings: GuardMeRuntimeSettings; readonly diagnostics: readonly PolicyDiagnostic[] } {
  if (!isRecord(parsed)) {
    return {
      settings: DEFAULT_RUNTIME_SETTINGS,
      diagnostics: [settingsDiagnostic("settings.invalidShape", "GuardMe runtime settings must be a JSON object.", path)],
    };
  }

  if (parsed.version !== POLICY_VERSION) {
    return {
      settings: DEFAULT_RUNTIME_SETTINGS,
      diagnostics: [settingsDiagnostic("settings.invalidVersion", `GuardMe runtime settings version must be ${POLICY_VERSION}.`, path)],
    };
  }

  if (typeof parsed.enabled !== "boolean") {
    return {
      settings: DEFAULT_RUNTIME_SETTINGS,
      diagnostics: [settingsDiagnostic("settings.invalidEnabled", "GuardMe runtime settings enabled must be a boolean.", path)],
    };
  }

  if (parsed.insecureEdits !== undefined && typeof parsed.insecureEdits !== "boolean") {
    return {
      settings: DEFAULT_RUNTIME_SETTINGS,
      diagnostics: [settingsDiagnostic("settings.invalidInsecureEdits", "GuardMe runtime settings insecureEdits must be a boolean.", path)],
    };
  }

  return {
    settings: { version: POLICY_VERSION, enabled: parsed.enabled, insecureEdits: parsed.insecureEdits ?? false },
    diagnostics: [],
  };
}

function settingsDiagnostic(code: string, message: string, path: string): PolicyDiagnostic {
  return {
    severity: "error",
    code,
    message,
    source: { kind: "local", path },
    path,
  };
}

function formatSettingsError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

