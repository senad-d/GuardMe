import assert from "node:assert/strict";
import { access, mkdir, mkdtemp, readFile, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  appendDecisionRecord,
  appendWarningRecord,
  createWarningRecord,
  hasWarnedFingerprint,
  loadWarningState,
  readStateFile,
  resolveStatePaths,
} from "../src/state/warnings.ts";

test("state path resolution uses approved global and project JSONL paths", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-state-paths-"));
  const home = join(root, "home");
  const cwd = join(root, "project");

  const paths = resolveStatePaths(cwd, home);

  assert.equal(paths.globalStatePath, join(home, ".pi", "agent", "guardme-state.jsonl"));
  assert.equal(paths.localStatePath, join(cwd, ".pi", "agent", "guardme-state.jsonl"));
  assert.equal(paths.displayGlobalStatePath, "~/.pi/agent/guardme-state.jsonl");
  assert.equal(paths.displayLocalStatePath, ".pi/agent/guardme-state.jsonl");
});

test("warning records append as JSONL and repeated fingerprints load across sessions", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-state-warning-"));
  const home = join(root, "home");
  const cwd = join(root, "project");
  await mkdir(cwd, { recursive: true });
  const paths = resolveStatePaths(cwd, home);

  const record = await appendWarningRecord(paths.localStatePath, {
    fingerprint: "sha256:first",
    scope: "project",
    cwd,
    toolName: "bash",
    action: "delete",
    risk: "dangerous",
    target: "rm -rf build --password hunter2",
    timestamp: "2026-06-21T00:00:00.000Z",
    reasonCode: "dangerous-command",
  });
  const text = await readFile(paths.localStatePath, "utf8");
  const loaded = await loadWarningState({ cwd, homeDir: home });

  assert.equal(record.type, "warning");
  assert.equal(record.target, "rm -rf build --password <redacted>");
  assert.equal(record.reasonCode, "dangerous-command");
  assert.equal(text.includes("hunter2"), false);
  assert.equal(text.trim().split("\n").length, 1);
  assert.equal(hasWarnedFingerprint(loaded, "sha256:first"), true);
  assert.equal(loaded.warningCounts.get("sha256:first"), 1);
  assert.equal(loaded.records[0]?.type === "warning" ? loaded.records[0].reasonCode : undefined, "dangerous-command");
});

test("state appends refuse symlinked project state paths", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-state-symlink-"));
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
  const paths = resolveStatePaths(cwd, home);

  await assert.rejects(
    appendWarningRecord(paths.localStatePath, {
      fingerprint: "sha256:symlink",
      scope: "project",
      cwd,
      toolName: "bash",
      action: "delete",
      risk: "dangerous",
      target: "rm -rf build",
    }),
    /symbolic link/i,
  );
  await assert.rejects(access(join(outside, "agent", "guardme-state.jsonl")));
});

test("state reads refuse symlinked state paths", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-state-read-symlink-"));
  const cwd = join(root, "project");
  const outside = join(root, "outside");
  await mkdir(join(cwd, ".pi", "agent"), { recursive: true });
  await mkdir(outside, { recursive: true });
  const outsideState = join(outside, "guardme-state.jsonl");
  const localState = join(cwd, ".pi", "agent", "guardme-state.jsonl");
  await writeFile(outsideState, JSON.stringify(createWarningRecord({ fingerprint: "sha256:outside", scope: "project", cwd, toolName: "bash", action: "delete", risk: "dangerous", target: "rm -rf build" })) + "\n", "utf8");
  try {
    await symlink(outsideState, localState);
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && ["EACCES", "EPERM"].includes(String(error.code))) {
      return;
    }
    throw error;
  }

  const result = await readStateFile(localState, "project");

  assert.equal(result.records.length, 0);
  assert.ok(result.diagnostics.some((diagnostic) => diagnostic.code === "state.symlinkRejected"));
});

test("oversized state files are rejected before parsing", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-state-too-large-"));
  const statePath = join(root, "guardme-state.jsonl");
  await writeFile(statePath, "#".repeat(1024 * 1024 + 1), "utf8");

  const result = await readStateFile(statePath, "global");

  assert.equal(result.records.length, 0);
  assert.ok(result.diagnostics.some((diagnostic) => diagnostic.code === "state.fileTooLarge"));
});

test("malformed JSONL lines are tolerated with diagnostics", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-state-malformed-"));
  const statePath = join(root, "guardme-state.jsonl");
  const valid = createWarningRecord({
    fingerprint: "sha256:valid",
    scope: "project",
    cwd: root,
    toolName: "bash",
    action: "delete",
    risk: "dangerous",
    target: "rm -rf build",
    timestamp: "2026-06-21T00:00:00.000Z",
  });
  await writeFile(statePath, `{bad json}\n${JSON.stringify(valid)}\n{"type":"warning"}\n`, "utf8");

  const result = await readStateFile(statePath, "project");

  assert.equal(result.records.length, 1);
  assert.equal(result.records[0]?.fingerprint, "sha256:valid");
  assert.ok(result.diagnostics.some((diagnostic) => diagnostic.code === "state.malformedJsonl"));
  assert.ok(result.diagnostics.some((diagnostic) => diagnostic.code === "state.invalidRecord"));
});

test("state records with invalid enum values are ignored", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-state-invalid-enums-"));
  const statePath = join(root, "guardme-state.jsonl");
  await writeFile(
    statePath,
    [
      JSON.stringify({ type: "warning", fingerprint: "sha256:bad-action", cwd: root, toolName: "bash", action: "not-real", risk: "dangerous" }),
      JSON.stringify({ type: "warning", fingerprint: "sha256:bad-risk", cwd: root, toolName: "bash", action: "delete", risk: "critical" }),
      JSON.stringify({ type: "decision", fingerprint: "sha256:bad-decision", cwd: root, decision: "approve-forever" }),
    ].join("\n") + "\n",
    "utf8",
  );

  const result = await readStateFile(statePath, "project");

  assert.equal(result.records.length, 0);
  assert.equal(result.diagnostics.filter((diagnostic) => diagnostic.code === "state.invalidRecord").length, 3);
});

test("decision records append without mixing generated state into YAML", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-state-decision-"));
  const statePath = join(root, ".pi", "agent", "guardme-state.jsonl");
  const record = await appendDecisionRecord(statePath, {
    fingerprint: "sha256:decision",
    scope: "global",
    cwd: root,
    decision: "deny-global",
    persistedTo: "global-yaml",
    reason: "Authorization: Bearer token-value",
    timestamp: "2026-06-21T00:01:00.000Z",
  });
  const result = await readStateFile(statePath, "global");

  assert.equal(record.type, "decision");
  assert.equal(result.records.length, 1);
  assert.equal(result.records[0]?.type, "decision");
  assert.equal(result.records[0]?.reason, "Authorization: Bearer <redacted>");
});

test("global warning state is filtered to the active project cwd", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-state-filter-"));
  const home = join(root, "home");
  const cwd = join(root, "project-a");
  const otherCwd = join(root, "project-b");
  await mkdir(cwd, { recursive: true });
  await mkdir(otherCwd, { recursive: true });
  const paths = resolveStatePaths(cwd, home);

  await appendWarningRecord(paths.globalStatePath, {
    fingerprint: "sha256:current",
    scope: "global",
    cwd,
    toolName: "bash",
    action: "delete",
    risk: "dangerous",
    target: "rm -rf build",
  });
  await appendWarningRecord(paths.globalStatePath, {
    fingerprint: "sha256:other",
    scope: "global",
    cwd: otherCwd,
    toolName: "bash",
    action: "delete",
    risk: "dangerous",
    target: "rm -rf build",
  });

  const loaded = await loadWarningState({ cwd, homeDir: home });

  assert.equal(hasWarnedFingerprint(loaded, "sha256:current"), true);
  assert.equal(hasWarnedFingerprint(loaded, "sha256:other"), false);
});
