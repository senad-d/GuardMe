import assert from "node:assert/strict";
import { access, mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { loadPolicyConfigFile, resolvePolicyConfigPaths } from "../src/config/load-config.ts";
import { appendPolicyConfigRules } from "../src/config/write-policy.ts";

async function tempProject(prefix) {
  const root = await mkdtemp(join(tmpdir(), prefix));
  const home = join(root, "home");
  const cwd = join(root, "project");
  await mkdir(cwd, { recursive: true });
  return { root, home, cwd, paths: resolvePolicyConfigPaths(cwd, home) };
}

test("appendPolicyConfigRules appends to existing sections without replacing existing rules", async () => {
  const { cwd, home, paths } = await tempProject("guardme-append-existing-");
  await mkdir(join(cwd, ".pi", "agent"), { recursive: true });
  await writeFile(
    paths.localPolicyPath,
    [
      "version: 1",
      "",
      "allowPaths:",
      "  - pattern: \"src/old.ts\"",
      "    actions: [read]",
      "    reason: \"Existing rule\"",
      "",
      "denyCommands:",
      "  - pattern: \"aws *\"",
      "    reason: \"Existing command\"",
      "",
    ].join("\n"),
    "utf8",
  );

  const result = await appendPolicyConfigRules({
    cwd,
    homeDir: home,
    scope: "local",
    rules: [
      {
        section: "allowPaths",
        rule: { pattern: "src/new.ts", actions: ["read", "write"], reason: "New source rule" },
      },
      { section: "dangerousCommands", rule: { pattern: "rm -rf build", reason: "Dangerous cleanup" } },
    ],
  });
  const text = await readFile(paths.localPolicyPath, "utf8");
  const loaded = await loadPolicyConfigFile(paths.localPolicyPath, "local");

  assert.equal(result.saved, true);
  assert.equal(result.added, 2);
  assert.match(text, /src\/old\.ts/);
  assert.match(text, /src\/new\.ts/);
  assert.match(text, /denyCommands:/);
  assert.match(text, /dangerousCommands:/);
  assert.equal(loaded.config.allowPaths.length, 2);
  assert.equal(loaded.config.dangerousCommands[0]?.pattern, "rm -rf build");
});

test("appendPolicyConfigRules creates a missing policy file", async () => {
  const { cwd, home, paths } = await tempProject("guardme-append-create-");

  await assert.rejects(access(paths.globalPolicyPath));
  const result = await appendPolicyConfigRules({
    cwd,
    homeDir: home,
    scope: "global",
    rules: [{ section: "allowCommands", rule: { pattern: "npm run test*", reason: "Project tests" } }],
  });
  const loaded = await loadPolicyConfigFile(paths.globalPolicyPath, "global");

  assert.equal(result.saved, true);
  assert.equal(result.created, true);
  assert.equal(loaded.config.allowCommands[0]?.pattern, "npm run test*");
});

test("appendPolicyConfigRules skips duplicate rules", async () => {
  const { cwd, home, paths } = await tempProject("guardme-append-duplicate-");

  const first = await appendPolicyConfigRules({
    cwd,
    homeDir: home,
    scope: "local",
    rules: [{ section: "denyCommands", rule: { pattern: "aws *", reason: "Cloud CLI" } }],
  });
  const second = await appendPolicyConfigRules({
    cwd,
    homeDir: home,
    scope: "local",
    rules: [{ section: "denyCommands", rule: { pattern: "aws *", reason: "Cloud CLI" } }],
  });
  const loaded = await loadPolicyConfigFile(paths.localPolicyPath, "local");

  assert.equal(first.saved, true);
  assert.equal(second.saved, false);
  assert.match(second.reason ?? "", /already exist/);
  assert.equal(loaded.config.denyCommands.length, 1);
});

test("appendPolicyConfigRules refuses secret-like command rules", async () => {
  const { cwd, home, paths } = await tempProject("guardme-append-secret-command-");

  const result = await appendPolicyConfigRules({
    cwd,
    homeDir: home,
    scope: "global",
    rules: [{ section: "allowCommands", rule: { pattern: "node deploy.mjs --token secret-value" } }],
  });

  assert.equal(result.saved, false);
  assert.match(result.reason ?? "", /secret-like values|sanitized/i);
  await assert.rejects(access(paths.globalPolicyPath));
});

test("appendPolicyConfigRules refuses malformed existing YAML", async () => {
  const { cwd, home, paths } = await tempProject("guardme-append-malformed-");
  await mkdir(join(cwd, ".pi", "agent"), { recursive: true });
  await writeFile(paths.localPolicyPath, "version: nope\nallowPaths: bad\n", "utf8");

  const result = await appendPolicyConfigRules({
    cwd,
    homeDir: home,
    scope: "local",
    rules: [{ section: "allowPaths", rule: { pattern: "src/**", actions: ["read"] } }],
  });
  const text = await readFile(paths.localPolicyPath, "utf8");

  assert.equal(result.saved, false);
  assert.match(result.reason ?? "", /validation errors/);
  assert.equal(text, "version: nope\nallowPaths: bad\n");
});
