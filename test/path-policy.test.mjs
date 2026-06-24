import assert from "node:assert/strict";
import { mkdir, mkdtemp, realpath, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { matchPolicyPathPattern, normalizePolicyPath } from "../src/policy/paths.ts";

test("path normalization strips Pi @ prefix and resolves relative paths against cwd", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "guardme-path-relative-"));
  await mkdir(join(cwd, "src"), { recursive: true });
  await writeFile(join(cwd, "src", "index.ts"), "export {};\n", "utf8");

  const normalized = await normalizePolicyPath("@src/index.ts", { cwd });

  assert.equal(normalized.inputPath, "src/index.ts");
  assert.equal(normalized.exists, true);
  assert.equal(normalized.isInsideProject, true);
  assert.equal(normalized.projectRelativePath, "src/index.ts");
});

test("path normalization expands home paths and marks them outside the project", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-path-home-"));
  const homeDir = join(root, "home");
  const cwd = join(root, "project");
  await mkdir(join(homeDir, ".ssh"), { recursive: true });
  await mkdir(cwd, { recursive: true });
  await writeFile(join(homeDir, ".ssh", "id_rsa"), "redacted", "utf8");

  const normalized = await normalizePolicyPath("~/.ssh/id_rsa", { cwd, homeDir });

  assert.equal(normalized.exists, true);
  assert.equal(normalized.isInsideProject, false);
  assert.equal(normalized.projectRelativePath, undefined);
  assert.equal(matchPolicyPathPattern("~/.ssh/**", normalized, { homeDir }).matched, true);
});

test("missing paths are resolved lexically through the nearest existing parent", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "guardme-path-missing-"));
  await mkdir(join(cwd, "src"), { recursive: true });

  const normalized = await normalizePolicyPath("src/new/file.ts", { cwd });

  assert.equal(normalized.exists, false);
  assert.equal(normalized.isInsideProject, true);
  assert.equal(normalized.projectRelativePath, "src/new/file.ts");
  assert.equal(normalized.nearestExistingParent, await realpath(join(cwd, "src")));
});

test("traversal attempts are detected and resolved conservatively", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-path-traversal-"));
  const cwd = join(root, "project");
  await mkdir(cwd, { recursive: true });
  await writeFile(join(root, "outside.txt"), "outside", "utf8");

  const normalized = await normalizePolicyPath("../outside.txt", { cwd });

  assert.equal(normalized.hadTraversal, true);
  assert.equal(normalized.exists, true);
  assert.equal(normalized.isInsideProject, false);
});

test("existing symlink targets are canonicalized before project-boundary checks", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-path-symlink-"));
  const cwd = join(root, "project");
  const outside = join(root, "outside");
  await mkdir(cwd, { recursive: true });
  await mkdir(outside, { recursive: true });
  await writeFile(join(outside, "secret.txt"), "secret", "utf8");
  await symlink(outside, join(cwd, "linked-outside"));

  const normalized = await normalizePolicyPath("linked-outside/secret.txt", { cwd });

  assert.equal(normalized.exists, true);
  assert.equal(normalized.isInsideProject, false);
  assert.equal(normalized.projectRelativePath, undefined);
});

test("glob matching supports project-relative, absolute, and protected patterns", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "guardme-path-glob-"));
  await mkdir(join(cwd, "src"), { recursive: true });
  await writeFile(join(cwd, "src", ".env.local"), "SECRET=redacted\n", "utf8");

  const normalized = await normalizePolicyPath("src/.env.local", { cwd });

  assert.equal(matchPolicyPathPattern("src/**", normalized).matched, true);
  assert.equal(matchPolicyPathPattern(`${normalized.projectRoot}/src/**`, normalized).matched, true);
  assert.equal(matchPolicyPathPattern("**/.env*", normalized).matched, true);
  assert.equal(matchPolicyPathPattern("docs/**", normalized).matched, false);
});
