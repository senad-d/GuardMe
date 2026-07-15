import assert from "node:assert/strict";
import { mkdir, mkdtemp, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { loadGuardMeConfig, loadPolicyConfigFile, resolvePolicyConfigPaths } from "../src/config/load-config.ts";
import { createBuiltInDefaultPolicy } from "../src/config/schema.ts";

test("built-in default policy includes approved hard-protection sections", () => {
  const defaults = createBuiltInDefaultPolicy();

  assert.equal(defaults.version, 1);
  assert.ok(defaults.zeroAccessPaths.some((rule) => rule.pattern === "~/.ssh/**"));
  assert.ok(defaults.noDeletePaths.some((rule) => rule.pattern.includes(".git")));
  const envSuffixRule = defaults.denyPaths.find((rule) => rule.pattern === "**/.env.*");
  assert.deepEqual(envSuffixRule?.actions, ["delete", "move", "rename"]);
  const skillAllowRules = defaults.allowPaths.filter((rule) =>
    ["**/.pi/skills", "**/.pi/skills/**", "**/.pi/skill", "**/.pi/skill/**"].includes(rule.pattern),
  );
  assert.equal(skillAllowRules.length, 4);
  assert.ok(skillAllowRules.every((rule) => rule.actions?.includes("read") && rule.actions?.includes("list")));
  const piDocsAllowRules = defaults.allowPaths.filter((rule) =>
    [
      "/opt/homebrew/lib/node_modules/@earendil-works",
      "/opt/homebrew/lib/node_modules/@earendil-works/**",
    ].includes(rule.pattern),
  );
  assert.equal(piDocsAllowRules.length, 2);
  assert.ok(piDocsAllowRules.every((rule) => rule.actions?.includes("read") && rule.actions?.includes("list")));
  const nullSinkRule = defaults.allowPaths.find((rule) => rule.pattern === "/dev/null");
  assert.deepEqual(nullSinkRule?.actions, ["write"]);
  assert.ok(defaults.allowCommands.some((rule) => rule.pattern === "pwd *"));
  assert.ok(defaults.allowCommands.some((rule) => rule.pattern === "ls *"));
  assert.ok(defaults.allowCommands.some((rule) => rule.pattern === "find *"));
  assert.ok(defaults.allowCommands.some((rule) => rule.pattern === "npm *"));
  assert.ok(defaults.allowCommands.some((rule) => rule.pattern === "node *"));
  assert.ok(defaults.allowCommands.some((rule) => rule.pattern === "git *"));
  assert.ok(defaults.denyCommands.some((rule) => rule.pattern === "aws *"));
  assert.ok(defaults.denyCommands.some((rule) => rule.pattern === "az *"));
  assert.ok(defaults.denyCommands.some((rule) => rule.pattern === "gcloud *"));
  assert.ok(defaults.denyCommands.some((rule) => rule.pattern === "sudoedit *"));
  assert.ok(defaults.protectedCredentialPaths.some((rule) => rule.pattern === "~/.aws/**"));
  assert.ok(defaults.readOnlyPaths.some((rule) => rule.pattern === ".pi/agent/guardme-settings.json"));
});

test("config path resolution uses approved global and local policy paths", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-config-paths-"));
  const home = join(root, "home");
  const cwd = join(root, "project");

  const paths = resolvePolicyConfigPaths(cwd, home);

  assert.equal(paths.globalPolicyPath, join(home, ".pi", "agent", "guardme.yaml"));
  assert.equal(paths.localPolicyPath, join(cwd, ".pi", "agent", "guardme.yaml"));
  assert.equal(paths.displayGlobalPolicyPath, "~/.pi/agent/guardme.yaml");
  assert.equal(paths.displayLocalPolicyPath, ".pi/agent/guardme.yaml");
});

test("missing config files are accepted and load built-in defaults", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-missing-config-"));
  const home = join(root, "home");
  const cwd = join(root, "project");

  const loaded = await loadGuardMeConfig({ cwd, homeDir: home });

  assert.equal(loaded.files.length, 2);
  assert.ok(loaded.files.every((file) => file.found === false));
  assert.deepEqual(loaded.diagnostics, []);
  assert.ok(loaded.config.zeroAccessPaths.some((rule) => rule.pattern === "~/.ssh/**"));
});

test("policy reads refuse symlinked config paths", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-config-read-symlink-"));
  const cwd = join(root, "project");
  const outside = join(root, "outside");
  await mkdir(join(cwd, ".pi", "agent"), { recursive: true });
  await mkdir(outside, { recursive: true });
  const outsidePolicy = join(outside, "guardme.yaml");
  const localPolicy = join(cwd, ".pi", "agent", "guardme.yaml");
  await writeFile(outsidePolicy, "version: 1\nallowCommands:\n  - pattern: \"npm *\"\n", "utf8");
  try {
    await symlink(outsidePolicy, localPolicy);
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && ["EACCES", "EPERM"].includes(String(error.code))) {
      return;
    }
    throw error;
  }

  const loaded = await loadPolicyConfigFile(localPolicy, "local");

  assert.equal(loaded.found, false);
  assert.equal(loaded.config.allowCommands.length, 0);
  assert.ok(loaded.diagnostics.some((diagnostic) => diagnostic.code === "config.symlinkRejected"));
});

test("oversized policy files are rejected before parsing", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-config-too-large-"));
  const policyPath = join(root, "guardme.yaml");
  await writeFile(policyPath, "#".repeat(1024 * 1024 + 1), "utf8");

  const loaded = await loadPolicyConfigFile(policyPath, "global");

  assert.equal(loaded.found, false);
  assert.ok(loaded.diagnostics.some((diagnostic) => diagnostic.code === "config.fileTooLarge"));
});

test("valid YAML policy parses all supported sections", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-valid-config-"));
  const policyPath = join(root, "guardme.yaml");
  await writeFile(
    policyPath,
    `version: 1
allowPaths:
  - pattern: "src/**"
    actions: [read, list, write, edit]
    reason: "Project source"
denyPaths:
  - pattern: "**/.env*"
zeroAccessPaths:
  - pattern: "~/.ssh/**"
readOnlyPaths:
  - pattern: "docs/**"
noDeletePaths:
  - pattern: ".git/**"
allowCommands:
  - pattern: "npm run test*"
denyCommands:
  - pattern: "sudo *"
dangerousCommands:
  - pattern: "rm -rf *"
protectedCredentialPaths:
  - pattern: "~/.aws/**"
`,
    "utf8",
  );

  const loaded = await loadPolicyConfigFile(policyPath, "local");

  assert.equal(loaded.found, true);
  assert.deepEqual(loaded.diagnostics.filter((diagnostic) => diagnostic.severity === "error"), []);
  assert.equal(loaded.config.allowPaths[0]?.pattern, "src/**");
  assert.deepEqual(loaded.config.allowPaths[0]?.actions, ["read", "list", "write", "edit"]);
  assert.equal(loaded.config.denyCommands[0]?.pattern, "sudo *");
  assert.equal(loaded.config.protectedCredentialPaths[0]?.pattern, "~/.aws/**");
});

test("quoted YAML scalars round-trip generated escapes", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-quoted-config-"));
  const policyPath = join(root, "guardme.yaml");
  await writeFile(
    policyPath,
    `version: 1
allowCommands:
  - pattern: "echo \\"quoted\\" path\\\\name"
    reason: "Reason with \\"quotes\\" and backslash \\\\"
denyCommands:
  - pattern: 'sudo ''literal'' *'
`,
    "utf8",
  );

  const loaded = await loadPolicyConfigFile(policyPath, "local");

  assert.deepEqual(loaded.diagnostics.filter((diagnostic) => diagnostic.severity === "error"), []);
  assert.equal(loaded.config.allowCommands[0]?.pattern, 'echo "quoted" path\\name');
  assert.equal(loaded.config.allowCommands[0]?.reason, 'Reason with "quotes" and backslash \\');
  assert.equal(loaded.config.denyCommands[0]?.pattern, "sudo 'literal' *");
});

test("YAML comments are ignored only outside quoted scalars", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-comment-config-"));
  const policyPath = join(root, "guardme.yaml");
  await writeFile(
    policyPath,
    `version: 1
allowCommands:
  - pattern: 'echo ''#not-comment'' # still inside value'
    reason: "double # hash with \\\"escaped quote\\\"" # trailing comment
`,
    "utf8",
  );

  const loaded = await loadPolicyConfigFile(policyPath, "local");

  assert.deepEqual(loaded.diagnostics.filter((diagnostic) => diagnostic.severity === "error"), []);
  assert.equal(loaded.config.allowCommands[0]?.pattern, "echo '#not-comment' # still inside value");
  assert.equal(loaded.config.allowCommands[0]?.reason, 'double # hash with "escaped quote"');
});

test("YAML comments require separation before hash in unquoted scalars", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-comment-separation-config-"));
  const policyPath = join(root, "guardme.yaml");
  await writeFile(
    policyPath,
    `version: 1
allowCommands:
  - pattern: echo foo#literal
    reason: keep#literal # trailing comment
`,
    "utf8",
  );

  const loaded = await loadPolicyConfigFile(policyPath, "local");

  assert.deepEqual(loaded.diagnostics.filter((diagnostic) => diagnostic.severity === "error"), []);
  assert.equal(loaded.config.allowCommands[0]?.pattern, "echo foo#literal");
  assert.equal(loaded.config.allowCommands[0]?.reason, "keep#literal");
});

test("unsupported policy versions report diagnostics and ignore rules", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-unsupported-config-"));
  const policyPath = join(root, "guardme.yaml");
  await writeFile(
    policyPath,
    `version: 999
allowPaths:
  - pattern: "unsafe/**"
`,
    "utf8",
  );

  const loaded = await loadPolicyConfigFile(policyPath, "local");

  assert.equal(loaded.config.allowPaths.length, 0);
  assert.ok(loaded.diagnostics.some((diagnostic) => diagnostic.code === "config.unsupportedVersion"));
});

test("invalid path rule actions do not become broad allow rules", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-invalid-actions-"));
  const policyPath = join(root, "guardme.yaml");
  await writeFile(
    policyPath,
    `version: 1
allowPaths:
  - pattern: "/tmp/**"
    actions: read
  - pattern: "../outside/**"
    actions: [shell]
  - pattern: "src/**"
    actions: []
`,
    "utf8",
  );

  const loaded = await loadPolicyConfigFile(policyPath, "local");

  assert.equal(loaded.config.allowPaths.length, 0);
  assert.ok(loaded.diagnostics.some((diagnostic) => diagnostic.code === "config.actionsNotArray"));
  assert.ok(loaded.diagnostics.some((diagnostic) => diagnostic.code === "config.invalidPathAction"));
  assert.ok(loaded.diagnostics.some((diagnostic) => diagnostic.code === "config.actionsEmpty"));
});

test("command rule actions are rejected instead of silently ignored", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-command-actions-"));
  const policyPath = join(root, "guardme.yaml");
  await writeFile(
    policyPath,
    `version: 1
allowCommands:
  - pattern: "npm *"
    actions: [read]
`,
    "utf8",
  );

  const loaded = await loadPolicyConfigFile(policyPath, "local");

  assert.equal(loaded.config.allowCommands.length, 0);
  assert.ok(loaded.diagnostics.some((diagnostic) => diagnostic.code === "config.commandActionsUnsupported"));
});

test("malformed config returns diagnostics with file source information", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-bad-config-"));
  await mkdir(join(root, ".pi", "agent"), { recursive: true });
  const policyPath = join(root, ".pi", "agent", "guardme.yaml");
  await writeFile(
    policyPath,
    `version: one
allowPaths: "src/**"
denyPaths:
  - reason: "missing pattern"
`,
    "utf8",
  );

  const loaded = await loadPolicyConfigFile(policyPath, "global");
  const errors = loaded.diagnostics.filter((diagnostic) => diagnostic.severity === "error");

  assert.equal(loaded.found, true);
  assert.ok(errors.length >= 3);
  assert.ok(errors.every((diagnostic) => diagnostic.source?.kind === "global"));
  assert.ok(errors.every((diagnostic) => diagnostic.source?.path === policyPath));
  assert.ok(errors.some((diagnostic) => diagnostic.code === "config.invalidVersion"));
  assert.ok(errors.some((diagnostic) => diagnostic.code === "config.sectionNotArray"));
  assert.ok(errors.some((diagnostic) => diagnostic.code === "config.missingPattern"));
});
