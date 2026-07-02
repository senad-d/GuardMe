import assert from "node:assert/strict";
import { realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join, relative, sep } from "node:path";
import { execPath } from "node:process";
import test from "node:test";

import { createProjectFixture, pathExists } from "./e2e/helpers/project-fixture.mjs";
import { SAFE_RPC_PATH, createRpcChildEnv, createRpcSpawnCommand } from "./e2e/helpers/rpc-client.mjs";

test("e2e fixture creates outside paths inside an isolated per-test temp root", async () => {
  const fixture = await createProjectFixture("security");
  try {
    assert.ok(fixture.rootDir.startsWith(join(realpathSync(tmpdir()), "guardme-e2e-security-")));
    assert.equal(isInside(fixture.rootDir, fixture.outsideReadPath), true);
    assert.equal(isInside(fixture.rootDir, fixture.outsideWritePath), true);
    assert.equal(isInside(fixture.rootDir, fixture.outsideDeletePath), true);
    assert.equal(isInside(fixture.projectDir, fixture.outsideReadPath), false, "outside read path must stay outside the project");
    assert.equal(isInside(fixture.projectDir, fixture.outsideWritePath), false, "outside write path must stay outside the project");
    assert.equal(isInside(fixture.projectDir, fixture.outsideDeletePath), false, "outside delete path must stay outside the project");
    assert.equal(await pathExists(fixture.outsideReadPath), true);
    assert.equal(await pathExists(fixture.outsideWritePath), true);
    assert.equal(await pathExists(fixture.outsideDeletePath), true);
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
  const env = createRpcChildEnv({ homeDir: "/home/e2e" }, { PATH: "/tmp/evil-bin", HOME: "/tmp/evil-home" });
  const spawnCommand = createRpcSpawnCommand(["--help"]);

  assert.equal(env.PATH, SAFE_RPC_PATH);
  assert.doesNotMatch(env.PATH, /\/tmp\/evil-bin/);
  assert.equal(env.HOME, "/home/e2e");
  assert.equal(spawnCommand.command, execPath);
  assert.match(spawnCommand.args[0], new RegExp(`${escapeRegExp(`${sep}pi-coding-agent${sep}`)}.*cli\\.js$`));
  assert.equal(spawnCommand.args.at(-1), "--help");
});

function isInside(parent, child) {
  const childRelativePath = relative(parent, child);
  return childRelativePath !== "" && !childRelativePath.startsWith(`..${sep}`) && childRelativePath !== ".." && !isAbsolute(childRelativePath);
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
