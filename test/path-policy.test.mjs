import assert from "node:assert/strict";
import { mkdir, mkdtemp, realpath, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { expandStableShellVariables, matchPolicyPathPattern, normalizePolicyPath } from "../src/policy/paths.ts";

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

test("stable shell variables expand to literal paths only where the shell would use the agent's value", () => {
  const variables = { HOME: "/home/a", TMPDIR: "/tmp/mission/p/1/", PWD: "/work/p" };
  for (const [command, expected] of [
    ['mkdir -p "$TMPDIR/x" && cp a "${TMPDIR}/x/"', 'mkdir -p "/tmp/mission/p/1//x" && cp a "/tmp/mission/p/1//x/"'],
    ['cat "$PWD/a" $HOME/b', 'cat "/work/p/a" /home/a/b'],
    ["rm -f '$TMPDIR/a' \\$HOME/b", "rm -f '$TMPDIR/a' \\$HOME/b"],
    ['TMPDIR=/etc; rm -f "$TMPDIR/passwd"', 'TMPDIR=/etc; rm -f "$TMPDIR/passwd"'],
    ['cd /tmp && rm -rf "$PWD/x"', 'cd /tmp && rm -rf "$PWD/x"'],
    ['cat "$TMPDIRX/a" "${TMPDIR:-/x}/b"', 'cat "$TMPDIRX/a" "${TMPDIR:-/x}/b"'],
    ["python3 - <<'PY'\nopen('$TMPDIR/a')\nPY", "python3 - <<'PY'\nopen('$TMPDIR/a')\nPY"],
  ]) {
    assert.equal(expandStableShellVariables(command, variables), expected, command);
  }
  assert.equal(expandStableShellVariables('rm -f "$TMPDIR/a"', { TMPDIR: "relative dir" }), 'rm -f "$TMPDIR/a"');
});

test("stable shell expansion preserves trailing separators and ignores other environment values", () => {
  const variables = { TMPDIR: "/tmp/run/", PWD: "/stale", OTHER: "/etc" };
  assert.equal(expandStableShellVariables('cat "${TMPDIR}file"', variables), 'cat "/tmp/run/file"');
  assert.equal(expandStableShellVariables('cat "$PWD/file"', variables, "/work/project"), 'cat "/work/project/file"');
  assert.equal(expandStableShellVariables('cat "$OTHER/file"', variables), 'cat "$OTHER/file"');
  assert.equal(expandStableShellVariables('cat "$HOME/file"', variables), 'cat "$HOME/file"');
  assert.equal(expandStableShellVariables('cat "${TMPDIR}file"', { TMPDIR: "/" }), 'cat "/file"');
  assert.equal(expandStableShellVariables('cat "$TMPDIR/file"', { TMPDIR: "/tmp/unsafe path" }), 'cat "$TMPDIR/file"');
  const longValue = `/tmp/${"/".repeat(20_000)}suffix/`;
  assert.equal(expandStableShellVariables('cat "${TMPDIR}file"', { TMPDIR: longValue }), `cat "${longValue}file"`);
});
