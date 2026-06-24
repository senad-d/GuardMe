import assert from "node:assert/strict";
import { access, mkdir, mkdtemp, readFile, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { loadPolicyConfigFile, resolvePolicyConfigPaths } from "../src/config/load-config.ts";
import { createEmptyPolicyConfig } from "../src/config/schema.ts";
import { persistUserDecisionRule, writePolicyConfigFile } from "../src/config/write-policy.ts";
import { APPROVAL_CHOICES } from "../src/ui/approval-modal.ts";
import { evaluateGuardedToolCall } from "../src/events/register-guard.ts";
import { startGuardMeSession, stopGuardMeSession } from "../src/events/register-lifecycle.ts";

function pathRequest(cwd, action = "write") {
  return {
    toolName: action === "read" ? "read" : "write",
    action,
    cwd,
    targets: [{ kind: "path", raw: "src/file.ts" }],
  };
}

test("saving an allow rule to local writes project GuardMe YAML only on explicit save", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-write-local-"));
  const home = join(root, "home");
  const cwd = join(root, "project");
  await mkdir(cwd, { recursive: true });
  const paths = resolvePolicyConfigPaths(cwd, home);

  await assert.rejects(access(paths.localPolicyPath));
  const result = await persistUserDecisionRule({
    cwd,
    homeDir: home,
    scope: "local",
    decision: "allow-local",
    request: pathRequest(cwd, "write"),
  });
  const loaded = await loadPolicyConfigFile(paths.localPolicyPath, "local");

  assert.equal(result.saved, true);
  assert.equal(result.path, paths.localPolicyPath);
  assert.equal(loaded.config.allowPaths[0]?.pattern, "src/file.ts");
  assert.deepEqual(loaded.config.allowPaths[0]?.actions, ["write"]);
});

test("saving a deny command rule to global writes global GuardMe YAML", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-write-global-"));
  const home = join(root, "home");
  const cwd = join(root, "project");
  await mkdir(cwd, { recursive: true });
  const paths = resolvePolicyConfigPaths(cwd, home);
  const request = {
    toolName: "bash",
    action: "delete",
    cwd,
    command: "rm -rf build",
    targets: [],
  };

  const result = await persistUserDecisionRule({ cwd, homeDir: home, scope: "global", decision: "deny-global", request });
  const loaded = await loadPolicyConfigFile(paths.globalPolicyPath, "global");

  assert.equal(result.saved, true);
  assert.equal(loaded.config.denyCommands[0]?.pattern, "rm -rf build");
});

test("policy writes use owner-only file permissions", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-write-mode-"));
  const home = join(root, "home");
  const cwd = join(root, "project");
  await mkdir(cwd, { recursive: true });
  const paths = resolvePolicyConfigPaths(cwd, home);

  await writePolicyConfigFile(
    paths.localPolicyPath,
    { ...createEmptyPolicyConfig(), allowPaths: [{ pattern: "src/**", actions: ["read"], reason: "Source reads." }] },
    { cwd, homeDir: home, scope: "local" },
  );

  assert.equal((await stat(paths.localPolicyPath)).mode & 0o777, 0o600);
});

test("direct policy writes refuse secret-like command rules", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-write-direct-secret-command-"));
  const home = join(root, "home");
  const cwd = join(root, "project");
  await mkdir(cwd, { recursive: true });
  const paths = resolvePolicyConfigPaths(cwd, home);

  await assert.rejects(
    writePolicyConfigFile(
      paths.localPolicyPath,
      { ...createEmptyPolicyConfig(), allowCommands: [{ pattern: "node deploy.mjs --token secret-value" }] },
      { cwd, homeDir: home, scope: "local" },
    ),
    /secret-like values/i,
  );
  await assert.rejects(access(paths.localPolicyPath));
});

test("persistent command rules refuse secret-like command values", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-write-secret-command-"));
  const home = join(root, "home");
  const cwd = join(root, "project");
  await mkdir(cwd, { recursive: true });
  const paths = resolvePolicyConfigPaths(cwd, home);
  const request = {
    toolName: "bash",
    action: "shell",
    cwd,
    command: "node script.mjs --token secret-value",
    targets: [],
  };

  const result = await persistUserDecisionRule({ cwd, homeDir: home, scope: "global", decision: "allow-global", request });

  assert.equal(result.saved, false);
  assert.equal(result.diagnostics[0]?.code, "policyWrite.secretCommandRejected");
  assert.match(result.reason ?? "", /secret-like values/i);
  await assert.rejects(access(paths.globalPolicyPath));
});

test("local policy writes refuse symlinked project config directories", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-write-symlink-"));
  const home = join(root, "home");
  const cwd = join(root, "project");
  const outside = join(root, "outside");
  await mkdir(cwd, { recursive: true });
  await mkdir(outside, { recursive: true });
  try {
    await symlink(outside, join(cwd, ".pi"), "dir");
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && ["EACCES", "EPERM"].includes(String(error.code))) {
      return;
    }
    throw error;
  }

  const result = await persistUserDecisionRule({
    cwd,
    homeDir: home,
    scope: "local",
    decision: "allow-local",
    request: pathRequest(cwd, "write"),
  });

  assert.equal(result.saved, false);
  assert.match(result.reason ?? "", /symbolic links?/i);
  await assert.rejects(access(join(outside, "agent", "guardme.yaml")));
});

test("global policy writes refuse symlinked global config directories", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-write-global-symlink-"));
  const home = join(root, "home");
  const cwd = join(root, "project");
  const outside = join(root, "outside");
  await mkdir(home, { recursive: true });
  await mkdir(cwd, { recursive: true });
  await mkdir(outside, { recursive: true });
  try {
    await symlink(outside, join(home, ".pi"), "dir");
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && ["EACCES", "EPERM"].includes(String(error.code))) {
      return;
    }
    throw error;
  }

  const result = await persistUserDecisionRule({
    cwd,
    homeDir: home,
    scope: "global",
    decision: "deny-global",
    request: {
      toolName: "bash",
      action: "delete",
      cwd,
      command: "rm -rf build",
      targets: [],
    },
  });

  assert.equal(result.saved, false);
  assert.match(result.reason ?? "", /symbolic links?/i);
  await assert.rejects(access(join(outside, "agent", "guardme.yaml")));
});

test("guard persists selected global allow rule from approval flow", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-write-guard-global-"));
  const home = join(root, "home");
  const cwd = join(root, "project");
  await mkdir(cwd, { recursive: true });
  const paths = resolvePolicyConfigPaths(cwd, home);
  const allowGlobal = APPROVAL_CHOICES.find((choice) => choice.decision === "allow-global");
  const label = `${allowGlobal.label} — ${allowGlobal.description}`;
  let selectCalls = 0;
  const ctx = {
    cwd,
    hasUI: true,
    mode: "rpc",
    isProjectTrusted: () => true,
    ui: {
      setStatus: () => {},
      notify: () => {},
      select: async () => {
        selectCalls += 1;
        return label;
      },
    },
  };
  await startGuardMeSession(ctx, { homeDir: home });

  await evaluateGuardedToolCall({ toolName: "bash", input: { command: "rm -rf build" } }, ctx);
  const second = await evaluateGuardedToolCall({ toolName: "bash", input: { command: "rm -rf build" } }, ctx);
  const third = await evaluateGuardedToolCall({ toolName: "bash", input: { command: "rm -rf build" } }, ctx);
  const yaml = await readFile(paths.globalPolicyPath, "utf8");

  assert.equal(second, undefined);
  assert.equal(third, undefined);
  assert.equal(selectCalls, 1);
  assert.match(yaml, /allowCommands:/);
  assert.match(yaml, /rm -rf build/);
  stopGuardMeSession(ctx);
});

test("approval flow refuses to persist secret-like command rules", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-write-guard-secret-command-"));
  const home = join(root, "home");
  const cwd = join(root, "project");
  await mkdir(cwd, { recursive: true });
  const paths = resolvePolicyConfigPaths(cwd, home);
  const allowGlobal = APPROVAL_CHOICES.find((choice) => choice.decision === "allow-global");
  const label = `${allowGlobal.label} — ${allowGlobal.description}`;
  const ctx = {
    cwd,
    hasUI: true,
    mode: "rpc",
    isProjectTrusted: () => true,
    ui: {
      setStatus: () => {},
      notify: () => {},
      select: async () => label,
    },
  };
  await startGuardMeSession(ctx, { homeDir: home });

  await evaluateGuardedToolCall({ toolName: "bash", input: { command: "custom-tool --token secret-value" } }, ctx);
  const second = await evaluateGuardedToolCall({ toolName: "bash", input: { command: "custom-tool --token secret-value" } }, ctx);

  assert.equal(second?.block, true);
  assert.match(second?.reason ?? "", /secret-like values/i);
  await assert.rejects(readFile(paths.globalPolicyPath, "utf8"));
  stopGuardMeSession(ctx);
});

test("hard-denied actions cannot be converted into allow rules", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-write-hard-deny-"));
  const home = join(root, "home");
  const cwd = join(root, "project");
  await mkdir(cwd, { recursive: true });
  const paths = resolvePolicyConfigPaths(cwd, home);
  const request = {
    toolName: "bash",
    action: "shell",
    cwd,
    command: "aws sts get-caller-identity",
    targets: [],
  };

  const result = await persistUserDecisionRule({
    cwd,
    homeDir: home,
    scope: "global",
    decision: "allow-global",
    request,
    hardDenied: true,
  });

  assert.equal(result.saved, false);
  assert.match(result.reason ?? "", /Hard-denied/);
  await assert.rejects(access(paths.globalPolicyPath));
});

test("malformed existing YAML is not rewritten automatically", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-write-malformed-"));
  const home = join(root, "home");
  const cwd = join(root, "project");
  const paths = resolvePolicyConfigPaths(cwd, home);
  await mkdir(join(cwd, ".pi", "agent"), { recursive: true });
  await writeFile(paths.localPolicyPath, "version: nope\nallowPaths: bad\n", "utf8");

  const result = await persistUserDecisionRule({
    cwd,
    homeDir: home,
    scope: "local",
    decision: "allow-local",
    request: pathRequest(cwd, "read"),
  });
  const text = await readFile(paths.localPolicyPath, "utf8");

  assert.equal(result.saved, false);
  assert.match(result.reason ?? "", /validation errors/);
  assert.equal(text, "version: nope\nallowPaths: bad\n");
});

test("oversized existing YAML is not rewritten automatically", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-write-oversized-"));
  const home = join(root, "home");
  const cwd = join(root, "project");
  const paths = resolvePolicyConfigPaths(cwd, home);
  const oversized = `#${"x".repeat(1024 * 1024 + 1)}`;
  await mkdir(join(cwd, ".pi", "agent"), { recursive: true });
  await writeFile(paths.localPolicyPath, oversized, "utf8");

  const result = await persistUserDecisionRule({
    cwd,
    homeDir: home,
    scope: "local",
    decision: "allow-local",
    request: pathRequest(cwd, "read"),
  });
  const text = await readFile(paths.localPolicyPath, "utf8");

  assert.equal(result.saved, false);
  assert.ok(result.diagnostics.some((diagnostic) => diagnostic.code === "config.fileTooLarge"));
  assert.equal(text, oversized);
});

test("guard persists selected local allow rule for a missing compound segment", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-write-segment-"));
  const home = join(root, "home");
  const cwd = join(root, "project");
  await mkdir(cwd, { recursive: true });
  const paths = resolvePolicyConfigPaths(cwd, home);
  const allowLocal = APPROVAL_CHOICES.find((choice) => choice.decision === "allow-local");
  const label = `${allowLocal.label} — ${allowLocal.description}`;
  const ctx = {
    cwd,
    hasUI: true,
    mode: "rpc",
    isProjectTrusted: () => true,
    ui: {
      setStatus: () => {},
      notify: () => {},
      select: async () => label,
    },
  };
  await startGuardMeSession(ctx, { homeDir: home });

  await evaluateGuardedToolCall({ toolName: "bash", input: { command: "pwd && unknown-tool" } }, ctx);
  const second = await evaluateGuardedToolCall({ toolName: "bash", input: { command: "pwd && unknown-tool" } }, ctx);
  const third = await evaluateGuardedToolCall({ toolName: "bash", input: { command: "pwd && unknown-tool" } }, ctx);
  const yaml = await readFile(paths.localPolicyPath, "utf8");

  assert.equal(second, undefined);
  assert.equal(third, undefined);
  assert.match(yaml, /allowCommands:/);
  assert.match(yaml, /pattern: "unknown-tool"/);
  assert.doesNotMatch(yaml, /pwd && unknown-tool/);
  stopGuardMeSession(ctx);
});

test("guard persists selected local allow rule from approval flow", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-write-guard-"));
  const home = join(root, "home");
  const cwd = join(root, "project");
  await mkdir(cwd, { recursive: true });
  const paths = resolvePolicyConfigPaths(cwd, home);
  const allowLocal = APPROVAL_CHOICES.find((choice) => choice.decision === "allow-local");
  const label = `${allowLocal.label} — ${allowLocal.description}`;
  let selectCalls = 0;
  const ctx = {
    cwd,
    hasUI: true,
    mode: "rpc",
    isProjectTrusted: () => true,
    ui: {
      setStatus: () => {},
      notify: () => {},
      select: async () => {
        selectCalls += 1;
        return label;
      },
    },
  };
  await startGuardMeSession(ctx, { homeDir: home });

  await evaluateGuardedToolCall({ toolName: "bash", input: { command: "rm -rf build" } }, ctx);
  const second = await evaluateGuardedToolCall({ toolName: "bash", input: { command: "rm -rf build" } }, ctx);
  const third = await evaluateGuardedToolCall({ toolName: "bash", input: { command: "rm -rf build" } }, ctx);
  const yaml = await readFile(paths.localPolicyPath, "utf8");

  assert.equal(second, undefined);
  assert.equal(third, undefined);
  assert.equal(selectCalls, 1);
  assert.match(yaml, /allowCommands:/);
  assert.match(yaml, /rm -rf build/);
  stopGuardMeSession(ctx);
});
