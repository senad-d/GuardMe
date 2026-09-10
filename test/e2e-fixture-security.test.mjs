import assert from "node:assert/strict";
import { realpathSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join, relative, sep } from "node:path";
import { execPath } from "node:process";
import test from "node:test";

import { mergePolicyConfigs, sourcePolicyConfig } from "../src/config/merge-policy.ts";
import { createBuiltInDefaultPolicy } from "../src/config/schema.ts";
import { evaluatePolicyRequest } from "../src/policy/evaluate.ts";
import { normalizePolicyPath, pathTargetFromNormalizedPath } from "../src/policy/paths.ts";
import { createProjectFixture, pathExists } from "./e2e/helpers/project-fixture.mjs";
import { SAFE_RPC_PATH, createRpcChildEnv, createRpcSpawnCommand } from "./e2e/helpers/rpc-client.mjs";

test("e2e fixture isolates outside paths without inheriting OS-temp policy allowances", async () => {
  const fixture = await createProjectFixture("security");
  try {
    assert.ok(fixture.rootDir.startsWith(join(realpathSync(homedir()), ".cache", "guardme-tests", "guardme-e2e-security-")));
    assert.equal(isInside(fixture.rootDir, fixture.outsideReadPath), true);
    assert.equal(isInside(fixture.rootDir, fixture.outsideWritePath), true);
    assert.equal(isInside(fixture.rootDir, fixture.outsideDeletePath), true);
    assert.equal(isInside(fixture.projectDir, fixture.outsideReadPath), false, "outside read path must stay outside the project");
    assert.equal(isInside(fixture.projectDir, fixture.outsideWritePath), false, "outside write path must stay outside the project");
    assert.equal(isInside(fixture.projectDir, fixture.outsideDeletePath), false, "outside delete path must stay outside the project");
    assert.equal(await pathExists(fixture.outsideReadPath), true);
    assert.equal(await pathExists(fixture.outsideWritePath), true);
    assert.equal(await pathExists(fixture.outsideDeletePath), true);
    await assertOutsidePathRequiresAllow(fixture, "read", fixture.outsideReadPath);
    await assertOutsidePathRequiresAllow(fixture, "write", fixture.outsideWritePath);
    await assertOutsidePathRequiresAllow(fixture, "delete", fixture.outsideDeletePath);
  } finally {
    await fixture.cleanup();
  }

  assert.equal(await pathExists(fixture.rootDir), false, "fixture cleanup removes the isolated temp root");
});

test("e2e fixture rejects unsafe temp path labels", async () => {
  await assert.rejects(() => createProjectFixture("../escape"), /Unsafe e2e fixture label/);
  await assert.rejects(() => createProjectFixture("bad label"), /Unsafe e2e fixture label/);
});

test("rpc e2e helper uses node plus a checked CLI path and a fixed safe PATH", () => {
  const env = createRpcChildEnv(
    { homeDir: "/home/e2e" },
    { PATH: "/tmp/evil-bin", HOME: "/tmp/evil-home", GUARDME_APPROVAL_MODE: "interactive" },
  );
  const interactiveEnv = createRpcChildEnv(
    { homeDir: "/home/e2e", approvalMode: "interactive" },
    { PATH: "/tmp/evil-bin", HOME: "/tmp/evil-home" },
  );
  const spawnCommand = createRpcSpawnCommand(["--help"]);

  assert.equal(env.PATH, SAFE_RPC_PATH);
  assert.doesNotMatch(env.PATH, /\/tmp\/evil-bin/);
  assert.equal(env.HOME, "/home/e2e");
  assert.equal(env.GUARDME_APPROVAL_MODE, undefined);
  assert.equal(interactiveEnv.GUARDME_APPROVAL_MODE, "interactive");
  assert.equal(spawnCommand.command, execPath);
  assert.match(spawnCommand.args[0], new RegExp(`${escapeRegExp(`${sep}pi-coding-agent${sep}`)}.*cli\\.js$`));
  assert.equal(spawnCommand.args.at(-1), "--help");
});

async function assertOutsidePathRequiresAllow(fixture, action, rawPath) {
  const policy = mergePolicyConfigs([sourcePolicyConfig("builtin", createBuiltInDefaultPolicy())]).config;
  const normalized = await normalizePolicyPath(rawPath, { cwd: fixture.projectDir, homeDir: fixture.homeDir });
  const decision = evaluatePolicyRequest({
    policy,
    request: {
      toolName: action === "read" ? "read" : "write",
      action,
      cwd: fixture.projectDir,
      targets: [pathTargetFromNormalizedPath(normalized)],
    },
  });
  assert.equal(decision.outcome, "deny", `${action} fixture must not be allowed by the built-in policy`);
  assert.match(decision.reason, /Outside-project .* requires an explicit/);
}

function isInside(parent, child) {
  const childRelativePath = relative(parent, child);
  return childRelativePath !== "" && !childRelativePath.startsWith(`..${sep}`) && childRelativePath !== ".." && !isAbsolute(childRelativePath);
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
