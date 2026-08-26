export const EXTENSION_DISPLAY_NAME = "GuardMe";
export const EXTENSION_STATUS_KEY = "guardme";
export const GUARDME_COMMAND_NAME = "guardme";
export const POLICY_VERSION = 1;

export const GUARDED_TOOL_NAMES = ["bash", "read", "write", "edit", "grep", "find", "ls"] as const;
export type GuardedToolContract = (typeof GUARDED_TOOL_NAMES)[number];
export const BUILT_IN_GUARDED_TOOLS: Readonly<Record<GuardedToolContract, GuardedToolContract>> =
  Object.fromEntries(GUARDED_TOOL_NAMES.map((name) => [name, name])) as Record<GuardedToolContract, GuardedToolContract>;

export const GLOBAL_POLICY_PATH = "~/.pi/agent/guardme.yaml";
export const LOCAL_POLICY_PATH = ".pi/agent/guardme.yaml";
export const GLOBAL_STATE_PATH = "~/.pi/agent/guardme-state.jsonl";
export const LOCAL_STATE_PATH = ".pi/agent/guardme-state.jsonl";
export const LOCAL_SETTINGS_PATH = ".pi/agent/guardme-settings.json";
