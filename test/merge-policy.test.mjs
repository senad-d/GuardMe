import assert from "node:assert/strict";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { loadGuardMeConfig } from "../src/config/load-config.ts";
import { mergePolicyConfigs, sourcePolicyConfig } from "../src/config/merge-policy.ts";
import { createEmptyPolicyConfig } from "../src/config/schema.ts";

test("merge loads global rules before local overlay rules with source metadata", () => {
  const globalConfig = {
    ...createEmptyPolicyConfig(),
    allowPaths: [{ pattern: "src/**", actions: ["read", "list"], reason: "global source reads" }],
  };
  const localConfig = {
    ...createEmptyPolicyConfig(),
    allowPaths: [{ pattern: "test/**", actions: ["read", "list", "write"], reason: "local tests" }],
  };

  const merged = mergePolicyConfigs([
    sourcePolicyConfig("global", globalConfig, "/home/user/.pi/agent/guardme.yaml"),
    sourcePolicyConfig("local", localConfig, "/repo/.pi/agent/guardme.yaml"),
  ]);

  assert.deepEqual(
    merged.config.allowPaths.map((rule) => rule.pattern),
    ["src/**", "test/**"],
  );
  assert.equal(merged.config.allowPaths[0]?.source.kind, "global");
  assert.equal(merged.config.allowPaths[1]?.source.kind, "local");
  assert.equal(merged.config.allowPaths[0]?.section, "allowPaths");
});

test("local allow rules cannot weaken global deny and protection rules", () => {
  const globalConfig = {
    ...createEmptyPolicyConfig(),
    denyPaths: [{ pattern: "secrets/**", actions: ["read", "list"], reason: "global secret deny" }],
    readOnlyPaths: [{ pattern: "docs/**", reason: "global docs readonly" }],
    noDeletePaths: [{ pattern: "releases/**", reason: "global release retention" }],
  };
  const localConfig = {
    ...createEmptyPolicyConfig(),
    allowPaths: [
      { pattern: "secrets/**", actions: ["read"], reason: "attempted local override" },
      { pattern: "docs/**", actions: ["write"], reason: "attempted docs write" },
      { pattern: "releases/**", actions: ["delete"], reason: "attempted delete override" },
    ],
  };

  const merged = mergePolicyConfigs([
    sourcePolicyConfig("global", globalConfig, "/global.yaml"),
    sourcePolicyConfig("local", localConfig, "/local.yaml"),
  ]);

  assert.equal(merged.config.denyPaths[0]?.pattern, "secrets/**");
  assert.equal(merged.config.readOnlyPaths[0]?.pattern, "docs/**");
  assert.equal(merged.config.noDeletePaths[0]?.pattern, "releases/**");
  assert.deepEqual(
    merged.config.allowPaths.map((rule) => rule.pattern),
    ["secrets/**", "docs/**", "releases/**"],
  );
  assert.equal(
    merged.diagnostics.filter((diagnostic) => diagnostic.code === "merge.localAllowCannotOverrideProtection").length,
    3,
  );
});

test("merge deduplicates duplicate rules predictably by keeping first source", () => {
  const globalConfig = {
    ...createEmptyPolicyConfig(),
    denyCommands: [{ pattern: "sudo *", reason: "global deny" }],
  };
  const localConfig = {
    ...createEmptyPolicyConfig(),
    denyCommands: [{ pattern: "sudo *", reason: "global deny" }],
  };

  const merged = mergePolicyConfigs([
    sourcePolicyConfig("global", globalConfig, "/global.yaml"),
    sourcePolicyConfig("local", localConfig, "/local.yaml"),
  ]);

  assert.equal(merged.config.denyCommands.length, 1);
  assert.equal(merged.config.denyCommands[0]?.source.kind, "global");
});

test("merge deduplicates path rules with actions in different input orders", () => {
  const globalConfig = {
    ...createEmptyPolicyConfig(),
    allowPaths: [{ pattern: "src/**", actions: ["read", "write", "delete"], reason: "source access" }],
  };
  const localConfig = {
    ...createEmptyPolicyConfig(),
    allowPaths: [{ pattern: "src/**", actions: ["delete", "read", "write"], reason: "source access" }],
  };

  const merged = mergePolicyConfigs([
    sourcePolicyConfig("global", globalConfig, "/global.yaml"),
    sourcePolicyConfig("local", localConfig, "/local.yaml"),
  ]);

  assert.equal(merged.config.allowPaths.length, 1);
  assert.equal(merged.config.allowPaths[0]?.source.kind, "global");
});

test("loadGuardMeConfig returns merged built-in, global, and local policy sources", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-merge-load-"));
  const home = join(root, "home");
  const cwd = join(root, "project");
  await mkdir(join(home, ".pi", "agent"), { recursive: true });
  await mkdir(join(cwd, ".pi", "agent"), { recursive: true });
  await writeFile(join(home, ".pi", "agent", "guardme.yaml"), "version: 1\nallowPaths:\n  - pattern: \"global/**\"\n", "utf8");
  await writeFile(join(cwd, ".pi", "agent", "guardme.yaml"), "version: 1\nallowPaths:\n  - pattern: \"local/**\"\n", "utf8");

  const loaded = await loadGuardMeConfig({ cwd, homeDir: home });

  assert.ok(loaded.config.zeroAccessPaths.some((rule) => rule.source.kind === "builtin"));
  const allowPathSources = loaded.config.allowPaths.map((rule) => [rule.pattern, rule.source.kind]);
  assert.ok(allowPathSources.some(([pattern, source]) => pattern === "**/.pi/skills/**" && source === "builtin"));
  assert.deepEqual(allowPathSources.slice(-2), [
    ["global/**", "global"],
    ["local/**", "local"],
  ]);
});
