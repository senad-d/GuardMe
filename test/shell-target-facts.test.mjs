import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { chmod, mkdir, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { classifyShellCommand } from "../src/policy/commands.ts";
import { nativeExecutableTokens, trackedRemovalTargets } from "../src/policy/shell-target-facts.ts";
import { outsideRoot } from "./support/outside-root.mjs";

async function nativeFile(path, hex = "7f454c46") {
  await writeFile(path, Buffer.from(hex, "hex"));
  await chmod(path, 0o755);
}

test("tracked-removal probes use trusted git even when PATH is hijacked", { skip: process.platform === "win32" }, async () => {
  const cwd = outsideRoot("guardme-git-probe-");
  await mkdir(join(cwd, "src"));
  await mkdir(join(cwd, "bin"));
  await writeFile(join(cwd, "src", "main.c"), "int main(void) {}\n");
  await writeFile(join(cwd, "tracked.txt"), "tracked\n");
  await writeFile(join(cwd, "bin", "git"), "#!/bin/sh\nexit 0\n");
  await chmod(join(cwd, "bin", "git"), 0o755);
  execFileSync("/usr/bin/git", ["init", "-q"], { cwd });
  execFileSync("/usr/bin/git", ["add", "src", "tracked.txt"], { cwd });

  const previous = process.env.PATH;
  process.env.PATH = join(cwd, "bin");
  try {
    const classification = classifyShellCommand("rm -rf src tracked.txt output src");
    assert.deepEqual(await trackedRemovalTargets(classification, cwd), [
      { raw: "src", tree: true },
      { raw: "tracked.txt", tree: false },
    ]);
    for (const command of ["rm -rf .", "rm -rf ../elsewhere", "rm -rf ~/outside", "rm -rf $UNKNOWN", "rm -rf src/*", "cat tracked.txt"]) {
      assert.deepEqual(await trackedRemovalTargets(classifyShellCommand(command), cwd), [], command);
    }
  } finally {
    if (previous === undefined) delete process.env.PATH;
    else process.env.PATH = previous;
  }
});

test("native facts deduplicate tokens and reject scripts, unresolved paths and escaping symlinks", async () => {
  const cwd = outsideRoot("guardme-native-facts-");
  const scratch = outsideRoot("guardme-native-scratch-");
  const outside = outsideRoot("guardme-native-outside-");
  await nativeFile(join(cwd, "elf"));
  await nativeFile(join(cwd, "macho"), "feedfacf");
  await nativeFile(join(scratch, "pe"), "4d5a0000");
  await nativeFile(join(outside, "other"));
  await nativeFile(join(cwd, "nonexec"));
  await chmod(join(cwd, "nonexec"), 0o644);
  await writeFile(join(cwd, "script"), "#!/bin/sh\necho hi\n");
  await chmod(join(cwd, "script"), 0o755);
  await symlink(join(outside, "other"), join(cwd, "escaped"));

  assert.deepEqual(await nativeExecutableTokens(`A=1 ./elf; ./macho; ./elf; ${scratch}/pe`, cwd, scratch), ["./elf", "./macho", `${scratch}/pe`]);
  for (const command of ["elf", "./missing", "./script", "./nonexec", "./escaped", "./$UNKNOWN", "~/elf", outside + "/other"]) {
    assert.deepEqual(await nativeExecutableTokens(command, cwd, scratch), [], command);
  }
  for (const root of [undefined, "relative", "/", join(cwd, "missing")]) {
    assert.deepEqual(await nativeExecutableTokens(`${scratch}/pe`, cwd, root), [], String(root));
  }
});
