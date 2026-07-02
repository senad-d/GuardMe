import { lstat, readFile, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";

import { GLOBAL_POLICY_PATH, LOCAL_POLICY_PATH } from "../constants.ts";
import type { PolicyDiagnostic, RuleSourceKind } from "../policy/action.ts";
import { type MergedGuardMePolicyConfig, mergePolicyConfigs, sourcePolicyConfig } from "./merge-policy.ts";
import {
  type ConfigValidationResult,
  type GuardMePolicyConfig,
  createBuiltInDefaultPolicy,
  createEmptyPolicyConfig,
  createRuleSource,
  parsePolicyYaml,
  validateGuardMeConfig,
} from "./schema.ts";

export interface GuardMeConfigPaths {
  readonly globalPolicyPath: string;
  readonly localPolicyPath: string;
  readonly displayGlobalPolicyPath: typeof GLOBAL_POLICY_PATH;
  readonly displayLocalPolicyPath: typeof LOCAL_POLICY_PATH;
}

type PolicyConfigFileSourceKind = Exclude<RuleSourceKind, "builtin" | "default" | "user">;

export interface PolicyConfigFileResult extends ConfigValidationResult {
  readonly path: string;
  readonly found: boolean;
  readonly skipped?: boolean;
  readonly sourceKind: PolicyConfigFileSourceKind;
}

export interface LoadedGuardMeConfig {
  readonly config: MergedGuardMePolicyConfig;
  readonly builtInConfig: GuardMePolicyConfig;
  readonly paths: GuardMeConfigPaths;
  readonly files: readonly PolicyConfigFileResult[];
  readonly diagnostics: readonly PolicyDiagnostic[];
}

export interface LoadGuardMeConfigOptions {
  readonly cwd: string;
  readonly homeDir?: string;
  readonly loadLocalPolicy?: boolean;
}

const MAX_POLICY_FILE_BYTES = 1024 * 1024;

export function resolvePolicyConfigPaths(cwd: string, homeDir = homedir()): GuardMeConfigPaths {
  return {
    globalPolicyPath: join(resolve(homeDir), ".pi", "agent", "guardme.yaml"),
    localPolicyPath: join(resolve(cwd), ".pi", "agent", "guardme.yaml"),
    displayGlobalPolicyPath: GLOBAL_POLICY_PATH,
    displayLocalPolicyPath: LOCAL_POLICY_PATH,
  };
}

export async function loadPolicyConfigFile(
  path: string,
  sourceKind: PolicyConfigFileSourceKind,
): Promise<PolicyConfigFileResult> {
  const source = createRuleSource(sourceKind, path);
  const inspected = await inspectPolicyFileBeforeRead(path, sourceKind, source);
  if (inspected) {
    return inspected;
  }

  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch (error) {
    return policyFileError(path, sourceKind, source, "config.readFailed", `Unable to read GuardMe policy file: ${formatConfigReadError(error)}`);
  }

  const parsed = parsePolicyYaml(text, source);
  const validated = validateGuardMeConfig(parsed.data, source);
  return {
    path,
    found: true,
    sourceKind,
    config: validated.config,
    diagnostics: [...parsed.diagnostics, ...validated.diagnostics],
  };
}

export async function loadGuardMeConfig(options: LoadGuardMeConfigOptions): Promise<LoadedGuardMeConfig> {
  const paths = resolvePolicyConfigPaths(options.cwd, options.homeDir);
  const builtInConfig = createBuiltInDefaultPolicy();
  const globalFile = await loadPolicyConfigFile(paths.globalPolicyPath, "global");
  const localFile = options.loadLocalPolicy === false
    ? skippedLocalPolicyConfigFile(paths.localPolicyPath)
    : await loadPolicyConfigFile(paths.localPolicyPath, "local");
  const files = [globalFile, localFile];
  const merged = mergePolicyConfigs([
    sourcePolicyConfig("builtin", builtInConfig),
    ...files.filter((file) => file.found).map((file) => sourcePolicyConfig(file.sourceKind, file.config, file.path)),
  ]);
  const diagnostics = [...files.flatMap((file) => file.diagnostics), ...merged.diagnostics];

  return {
    config: merged.config,
    builtInConfig,
    paths,
    files,
    diagnostics,
  };
}

function skippedLocalPolicyConfigFile(path: string): PolicyConfigFileResult {
  return {
    path,
    found: false,
    skipped: true,
    sourceKind: "local",
    config: createEmptyPolicyConfig(),
    diagnostics: [
      {
        severity: "info",
        code: "config.localPolicySkippedUntrustedProject",
        message: "Project is not trusted; local GuardMe policy was not loaded.",
        source: { kind: "local", path },
        path,
      },
    ],
  };
}

async function inspectPolicyFileBeforeRead(
  path: string,
  sourceKind: PolicyConfigFileSourceKind,
  source: ReturnType<typeof createRuleSource>,
): Promise<PolicyConfigFileResult | undefined> {
  try {
    const symlinkPath = await existingSymlinkInConfigPath(path);
    if (symlinkPath) {
      return policyFileError(path, sourceKind, source, "config.symlinkRejected", "Refusing to read GuardMe policy through a symbolic link.", symlinkPath);
    }

    const fileStats = await stat(path);
    if (!fileStats.isFile()) {
      return policyFileError(path, sourceKind, source, "config.notFile", "GuardMe policy path is not a regular file.");
    }
    if (fileStats.size > MAX_POLICY_FILE_BYTES) {
      return policyFileError(path, sourceKind, source, "config.fileTooLarge", `GuardMe policy file is too large to read safely (${fileStats.size} bytes).`);
    }
  } catch (error) {
    if (isNodeError(error) && error.code === "ENOENT") {
      return {
        path,
        found: false,
        sourceKind,
        config: createEmptyPolicyConfig(),
        diagnostics: [],
      };
    }
    return policyFileError(path, sourceKind, source, "config.inspectFailed", `Unable to inspect GuardMe policy file: ${formatConfigReadError(error)}`);
  }

  return undefined;
}

function policyFileError(
  path: string,
  sourceKind: PolicyConfigFileSourceKind,
  source: ReturnType<typeof createRuleSource>,
  code: string,
  message: string,
  diagnosticPath = path,
): PolicyConfigFileResult {
  return {
    path,
    found: false,
    skipped: true,
    sourceKind,
    config: createEmptyPolicyConfig(),
    diagnostics: [
      {
        severity: "error",
        code,
        message,
        source,
        path: diagnosticPath,
      },
    ],
  };
}

async function existingSymlinkInConfigPath(path: string): Promise<string | undefined> {
  const absolutePath = resolve(path);
  const candidates: string[] = [];
  let current = absolutePath;
  while (dirname(current) !== current) {
    candidates.unshift(current);
    current = dirname(current);
  }
  candidates.unshift(current);

  const configRootIndex = candidates.findIndex((candidate) => basename(candidate) === ".pi");
  const checkedCandidates = configRootIndex >= 0 ? candidates.slice(configRootIndex) : candidates.slice(-1);

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

function formatConfigReadError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return typeof error === "object" && error !== null && "code" in error;
}
