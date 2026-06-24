import assert from "node:assert/strict";
import { access, mkdir, mkdtemp, readFile, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  loadGuardMeRuntimeSettings,
  resolveRuntimeSettingsPath,
  writeGuardMeRuntimeSettings,
} from "../src/config/runtime-settings.ts";

test("missing runtime settings default GuardMe to active", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "guardme-settings-missing-"));

  const loaded = await loadGuardMeRuntimeSettings({ cwd });

  assert.equal(loaded.found, false);
  assert.equal(loaded.settings.enabled, true);
  assert.equal(loaded.diagnostics.length, 0);
});

test("runtime settings persist enabled false and true", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "guardme-settings-roundtrip-"));
  const paths = resolveRuntimeSettingsPath(cwd);

  await writeGuardMeRuntimeSettings({ cwd, enabled: false });
  let loaded = await loadGuardMeRuntimeSettings({ cwd });
  assert.equal(loaded.found, true);
  assert.equal(loaded.settings.enabled, false);
  assert.match(await readFile(paths.settingsPath, "utf8"), /"enabled": false/);

  await writeGuardMeRuntimeSettings({ cwd, enabled: true });
  loaded = await loadGuardMeRuntimeSettings({ cwd });
  assert.equal(loaded.settings.enabled, true);
});

test("untrusted projects skip local runtime settings", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "guardme-settings-untrusted-"));
  await writeGuardMeRuntimeSettings({ cwd, enabled: false });

  const loaded = await loadGuardMeRuntimeSettings({ cwd, loadLocalSettings: false });

  assert.equal(loaded.found, false);
  assert.equal(loaded.settings.enabled, true);
  assert.ok(loaded.diagnostics.some((diagnostic) => diagnostic.code === "settings.localSettingsSkippedUntrustedProject"));
});

test("invalid runtime settings fail safe to active with diagnostics", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "guardme-settings-invalid-"));
  const paths = resolveRuntimeSettingsPath(cwd);
  await mkdir(join(cwd, ".pi", "agent"), { recursive: true });
  await writeFile(paths.settingsPath, "{not json", "utf8");

  const loaded = await loadGuardMeRuntimeSettings({ cwd });

  assert.equal(loaded.found, true);
  assert.equal(loaded.settings.enabled, true);
  assert.ok(loaded.diagnostics.some((diagnostic) => diagnostic.code === "settings.invalidJson"));
});

test("runtime settings reject invalid shapes", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "guardme-settings-shape-"));
  const paths = resolveRuntimeSettingsPath(cwd);
  await mkdir(join(cwd, ".pi", "agent"), { recursive: true });
  await writeFile(paths.settingsPath, JSON.stringify({ version: 1, enabled: "nope" }), "utf8");

  const loaded = await loadGuardMeRuntimeSettings({ cwd });

  assert.equal(loaded.settings.enabled, true);
  assert.ok(loaded.diagnostics.some((diagnostic) => diagnostic.code === "settings.invalidEnabled"));
});

test("oversized runtime settings fail safe to active", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "guardme-settings-oversized-"));
  const paths = resolveRuntimeSettingsPath(cwd);
  await mkdir(join(cwd, ".pi", "agent"), { recursive: true });
  await writeFile(paths.settingsPath, "#".repeat(64 * 1024 + 1), "utf8");

  const loaded = await loadGuardMeRuntimeSettings({ cwd });

  assert.equal(loaded.settings.enabled, true);
  assert.ok(loaded.diagnostics.some((diagnostic) => diagnostic.code === "settings.fileTooLarge"));
});

test("runtime settings writes refuse symlinked project settings paths", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-settings-symlink-"));
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

  await assert.rejects(
    writeGuardMeRuntimeSettings({ cwd, enabled: false }),
    /symbolic links|symlink/i,
  );
  await assert.rejects(access(join(outside, "agent", "guardme-settings.json")));

  const loaded = await loadGuardMeRuntimeSettings({ cwd });
  assert.equal(loaded.settings.enabled, true);
  assert.ok(loaded.diagnostics.some((diagnostic) => diagnostic.code === "settings.symlinkRejected"));
});
