import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";

import { loadPolicyConfigFile } from "../src/config/load-config.ts";
import { createBuiltInDefaultPolicy } from "../src/config/schema.ts";

const execFileAsync = promisify(execFile);
const installScript = new URL("../scripts/install-global-policy.mjs", import.meta.url);

test("global policy helper creates guardme.yaml with sensible defaults", async () => {
  const home = await mkdtemp(join(tmpdir(), "guardme-install-home-"));

  const { stdout } = await execFileAsync(process.execPath, [installScript.pathname], {
    env: { ...process.env, GUARDME_HOME_DIR: home },
  });
  const policyPath = join(home, ".pi", "agent", "guardme.yaml");
  const yaml = await readFile(policyPath, "utf8");

  assert.match(stdout, /Created GuardMe global policy/);
  assert.match(yaml, /zeroAccessPaths:/);
  assert.match(yaml, /noDeletePaths:/);
  assert.match(yaml, /denyPaths:/);
  assert.match(yaml, /allowCommands:/);
  assert.match(yaml, /denyCommands:/);
  assert.match(yaml, /dangerousCommands:/);
  assert.match(yaml, /protectedCredentialPaths:/);
  assert.match(yaml, /~\/\.ssh\/\*\*/);
  assert.match(yaml, /\.git\/\*\*/);
  const loaded = await loadPolicyConfigFile(policyPath, "global");
  assert.deepEqual(loaded.diagnostics.filter((diagnostic) => diagnostic.severity === "error"), []);
  assert.deepEqual(loaded.config, createBuiltInDefaultPolicy());
  assert.ok(loaded.config.zeroAccessPaths.length > 0);
  assert.ok(loaded.config.noDeletePaths.length > 0);
});

test("global policy helper does not overwrite existing guardme.yaml", async () => {
  const home = await mkdtemp(join(tmpdir(), "guardme-install-existing-"));
  const policyPath = join(home, ".pi", "agent", "guardme.yaml");
  await mkdir(join(home, ".pi", "agent"), { recursive: true });
  await writeFile(policyPath, "version: 1\n# keep custom policy\n", "utf8");

  const { stdout } = await execFileAsync(process.execPath, [installScript.pathname], {
    env: { ...process.env, GUARDME_HOME_DIR: home },
  });
  const yaml = await readFile(policyPath, "utf8");

  assert.match(stdout, /already exists/);
  assert.equal(yaml, "version: 1\n# keep custom policy\n");
});

test("global policy helper refuses symlinked policy directories", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-install-symlink-"));
  const home = join(root, "home");
  const outside = join(root, "outside");
  await mkdir(home, { recursive: true });
  await mkdir(outside, { recursive: true });
  try {
    await symlink(outside, join(home, ".pi"), "dir");
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && ["EACCES", "EPERM"].includes(String(error.code))) {
      return;
    }
    throw error;
  }

  await assert.rejects(
    execFileAsync(process.execPath, [installScript.pathname], {
      env: { ...process.env, GUARDME_HOME_DIR: home },
    }),
    /symbolic link/i,
  );
  await assert.rejects(readFile(join(outside, "agent", "guardme.yaml"), "utf8"));
});

test("global policy helper can be skipped by environment", async () => {
  const home = await mkdtemp(join(tmpdir(), "guardme-install-skip-"));

  await execFileAsync(process.execPath, [installScript.pathname], {
    env: { ...process.env, GUARDME_HOME_DIR: home, GUARDME_SKIP_GLOBAL_POLICY_INSTALL: "1" },
  });

  await assert.rejects(readFile(join(home, ".pi", "agent", "guardme.yaml"), "utf8"));
});
