import assert from "node:assert/strict";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { EXTENSION_STATUS_KEY } from "../src/constants.ts";
import { writeGuardMeRuntimeSettings } from "../src/config/runtime-settings.ts";
import { registerLifecycle, startGuardMeSession, stopGuardMeSession } from "../src/events/register-lifecycle.ts";
import { getGuardMeSessionState } from "../src/events/session-store.ts";
import { appendWarningRecord, resolveStatePaths } from "../src/state/warnings.ts";

function createContext(cwd, trusted = true) {
  const statuses = [];
  const notifications = [];
  return {
    ctx: {
      cwd,
      hasUI: true,
      isProjectTrusted: () => trusted,
      ui: {
        setStatus: (key, text) => statuses.push([key, text]),
        notify: (message, type) => notifications.push([message, type]),
      },
    },
    statuses,
    notifications,
  };
}

test("session_start loads policy and warning state, exposes status, and stores session data", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-lifecycle-start-"));
  const home = join(root, "home");
  const cwd = join(root, "project");
  await mkdir(join(home, ".pi", "agent"), { recursive: true });
  await mkdir(join(cwd, ".pi", "agent"), { recursive: true });
  await writeFile(join(home, ".pi", "agent", "guardme.yaml"), "version: 1\nallowPaths:\n  - pattern: \"global/**\"\n", "utf8");
  await writeFile(join(cwd, ".pi", "agent", "guardme.yaml"), "version: 1\nallowPaths:\n  - pattern: \"local/**\"\n", "utf8");
  const statePaths = resolveStatePaths(cwd, home);
  await appendWarningRecord(statePaths.localStatePath, {
    fingerprint: "sha256:lifecycle",
    scope: "project",
    cwd,
    toolName: "bash",
    action: "delete",
    risk: "dangerous",
    target: "rm -rf build",
  });
  const { ctx, statuses } = createContext(cwd, true);

  const state = await startGuardMeSession(ctx, { homeDir: home });

  assert.equal(state.projectTrusted, true);
  assert.equal(getGuardMeSessionState(), state);
  const trustedAllowPaths = state.config.config.allowPaths.map((rule) => [rule.pattern, rule.source.kind]);
  assert.ok(trustedAllowPaths.some(([pattern, source]) => pattern === "**/.pi/skills/**" && source === "builtin"));
  assert.deepEqual(trustedAllowPaths.slice(-2), [
    ["global/**", "global"],
    ["local/**", "local"],
  ]);
  assert.equal(state.warnings.warnedFingerprints.has("sha256:lifecycle"), true);
  assert.equal(statuses.at(-1)?.[0], EXTENSION_STATUS_KEY);
  assert.equal(statuses.at(-1)?.[1], "🛡️ (1 warning)");
});

test("session_start loads persisted disabled runtime settings and clears status", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-lifecycle-disabled-"));
  const home = join(root, "home");
  const cwd = join(root, "project");
  await mkdir(cwd, { recursive: true });
  await writeGuardMeRuntimeSettings({ cwd, enabled: false });
  const { ctx, statuses } = createContext(cwd, true);

  const state = await startGuardMeSession(ctx, { homeDir: home });

  assert.equal(state.enabled, false);
  assert.equal(state.settings.settings.enabled, false);
  assert.equal(statuses.at(-1)?.[0], EXTENSION_STATUS_KEY);
  assert.equal(statuses.at(-1)?.[1], undefined);
});

test("untrusted projects skip local policy, settings, and state while still loading global policy", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-lifecycle-untrusted-"));
  const home = join(root, "home");
  const cwd = join(root, "project");
  await mkdir(join(home, ".pi", "agent"), { recursive: true });
  await mkdir(join(cwd, ".pi", "agent"), { recursive: true });
  await writeFile(join(home, ".pi", "agent", "guardme.yaml"), "version: 1\nallowPaths:\n  - pattern: \"global/**\"\n", "utf8");
  await writeFile(join(cwd, ".pi", "agent", "guardme.yaml"), "version: 1\nallowPaths:\n  - pattern: \"local/**\"\n", "utf8");
  await writeGuardMeRuntimeSettings({ cwd, enabled: false });
  const statePaths = resolveStatePaths(cwd, home);
  await appendWarningRecord(statePaths.localStatePath, {
    fingerprint: "sha256:untrusted-local",
    scope: "project",
    cwd,
    toolName: "bash",
    action: "delete",
    risk: "dangerous",
    target: "rm -rf build",
  });
  const { ctx } = createContext(cwd, false);

  const state = await startGuardMeSession(ctx, { homeDir: home });

  assert.equal(state.projectTrusted, false);
  assert.equal(state.enabled, true);
  assert.equal(state.degraded, false);
  const untrustedAllowPaths = state.config.config.allowPaths.map((rule) => [rule.pattern, rule.source.kind]);
  assert.ok(untrustedAllowPaths.some(([pattern, source]) => pattern === "**/.pi/skills/**" && source === "builtin"));
  assert.deepEqual(untrustedAllowPaths.slice(-1), [["global/**", "global"]]);
  assert.equal(state.warnings.warnedFingerprints.has("sha256:untrusted-local"), false);
  assert.ok(state.diagnostics.some((diagnostic) => diagnostic.code === "settings.localSettingsSkippedUntrustedProject"));
  assert.ok(state.diagnostics.some((diagnostic) => diagnostic.code === "config.localPolicySkippedUntrustedProject"));
  assert.ok(state.diagnostics.some((diagnostic) => diagnostic.code === "state.localStateSkippedUntrustedProject"));
});

test("malformed policy degrades lifecycle status and exposes diagnostics", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-lifecycle-degraded-"));
  const home = join(root, "home");
  const cwd = join(root, "project");
  await mkdir(join(home, ".pi", "agent"), { recursive: true });
  await mkdir(cwd, { recursive: true });
  await writeFile(join(home, ".pi", "agent", "guardme.yaml"), "version: nope\nallowPaths: bad\n", "utf8");
  const { ctx, statuses, notifications } = createContext(cwd, true);

  const state = await startGuardMeSession(ctx, { homeDir: home });

  assert.equal(state.degraded, true);
  assert.match(statuses.at(-1)?.[1] ?? "", /degraded/);
  assert.equal(notifications.at(-1)?.[1], "warning");
  assert.ok(state.diagnostics.some((diagnostic) => diagnostic.severity === "error"));
});

test("session_shutdown clears status and releases session-local state", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "guardme-lifecycle-stop-"));
  const { ctx, statuses } = createContext(cwd, true);
  await startGuardMeSession(ctx, { homeDir: join(cwd, "home") });

  stopGuardMeSession(ctx);

  assert.equal(getGuardMeSessionState(), undefined);
  assert.deepEqual(statuses.at(-1), [EXTENSION_STATUS_KEY, undefined]);
});

test("registerLifecycle wires session_start and session_shutdown handlers", async () => {
  const handlers = new Map();
  const pi = {
    on: (name, handler) => handlers.set(name, handler),
  };

  registerLifecycle(pi);

  assert.equal(typeof handlers.get("session_start"), "function");
  assert.equal(typeof handlers.get("session_shutdown"), "function");
});
