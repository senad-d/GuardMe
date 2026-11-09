import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { chmod, mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { outsideRoot } from "./support/outside-root.mjs";

import { createBuiltInDefaultPolicy } from "../src/config/schema.ts";
import { mergePolicyConfigs, sourcePolicyConfig } from "../src/config/merge-policy.ts";
import { evaluateGuardedToolCall, mapToolCallToPolicyRequest } from "../src/events/register-guard.ts";
import { startGuardMeSession, stopGuardMeSession } from "../src/events/register-lifecycle.ts";
import { evaluatePolicyRequest } from "../src/policy/evaluate.ts";

// Regressions from Mission QA_DOCKER_RUST_2026-11-09 (G1-G6): a Rust port
// whose agents installed rustup under their run's TMPDIR.

const policy = mergePolicyConfigs([sourcePolicyConfig("builtin", createBuiltInDefaultPolicy())]).config;

async function evaluate(toolName, input, cwd) {
  const mapped = await mapToolCallToPolicyRequest({ toolName, input }, cwd);
  assert.ok("request" in mapped, JSON.stringify(mapped));
  return evaluatePolicyRequest({ policy, ...mapped });
}

const shell = (command, cwd) => evaluate("bash", { command }, cwd);

async function withTmpDir(run) {
  const previous = process.env.TMPDIR;
  process.env.TMPDIR = await mkdtemp(join(tmpdir(), "guardme-qa-run-"));
  try {
    await run(process.env.TMPDIR);
  } finally {
    if (previous === undefined) delete process.env.TMPDIR;
    else process.env.TMPDIR = previous;
  }
}

async function writeNativeBinary(path) {
  await mkdir(join(path, ".."), { recursive: true });
  await writeFile(path, Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]));
  await chmod(path, 0o755);
}

test("G1: recursive removal of git-tracked source needs approval, untracked output does not", async () => {
  const cwd = outsideRoot("guardme-qa-g1-");
  await mkdir(join(cwd, "legacy"), { recursive: true });
  await writeFile(join(cwd, "legacy", "wump.c"), "int main(void) { return 0; }\n");
  await mkdir(join(cwd, "target", "debug"), { recursive: true });
  await writeFile(join(cwd, "target", "debug", "out.o"), "x");
  const git = (...args) => execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@example.com", ...args], { cwd, stdio: "ignore" });
  git("init", "-q");
  git("add", "legacy");
  git("commit", "-q", "-m", "legacy");

  for (const command of ["rm -rf legacy", "rm -r legacy/wump.c", "mv legacy old-legacy", "rm -rf target legacy"]) {
    const decision = await shell(command, cwd);
    assert.equal(decision.outcome, "coach", command);
    assert.match(decision.reason, /git tracks/, command);
  }
  for (const command of ["rm -rf target", "rm legacy/wump.c", "mv legacy/wump.c legacy/main.c"]) {
    assert.equal((await shell(command, cwd)).outcome, "allow", command);
  }
  assert.equal((await shell("rm -rf .git", cwd)).outcome, "deny");
});

test("G2: leading assignments and harmless exports reach allowCommands; loader exports do not", async () => {
  await withTmpDir(async () => {
    const cwd = outsideRoot("guardme-qa-g2-");
    for (const command of [
      "CARGO_HOME=$TMPDIR/rust/cargo RUSTUP_HOME=$TMPDIR/rust/rustup $TMPDIR/rust/rustup-init -y --no-modify-path --profile minimal --default-toolchain 1.85.0 --component clippy,rustfmt",
      "CARGO_HOME=$TMPDIR/rust/cargo RUSTUP_HOME=$TMPDIR/rust/rustup rustfmt --edition 2024 src/game.rs",
      "export CARGO_HOME=$TMPDIR/rust/cargo RUSTUP_HOME=$TMPDIR/rust/rustup CARGO_TARGET_DIR=$TMPDIR/target; $TMPDIR/rust/cargo/bin/cargo build",
    ]) {
      assert.equal((await shell(command, cwd)).outcome, "allow", command);
    }
    for (const command of ["export CARGO_HOME=/x PATH=/evil:/usr/bin", "export GIT_SSH_COMMAND=/evil", "export DYLD_FALLBACK_LIBRARY_PATH=/evil"]) {
      assert.notEqual((await shell(command, cwd)).outcome, "allow", command);
    }
  });
});

test("G3: rust toolchain binaries run by basename or toolchain path", async () => {
  await withTmpDir(async () => {
    const cwd = outsideRoot("guardme-qa-g3-");
    const bin = "$TMPDIR/rust/rustup/toolchains/1.85.0-x86_64-unknown-linux-gnu/bin";
    for (const command of [
      `${bin}/rustfmt --edition 2024 --check tests/terminal.rs`,
      `${bin}/rustc --edition 2024 --test tests/terminal.rs -o $TMPDIR/x`,
      `${bin}/cargo clippy --all-targets`,
      `${bin}/cargo-clippy --version`,
      "clippy-driver --version",
      "rustfmt --check src/main.rs",
      "~/.rustup/toolchains/stable/bin/rustfmt --check src/main.rs",
    ]) {
      assert.equal((await shell(command, cwd)).outcome, "allow", command);
    }
  });
});

test("G4: native binaries built in the project or TMPDIR run; other binaries and scripts do not skip checks", async () => {
  await withTmpDir(async (tmp) => {
    const cwd = outsideRoot("guardme-qa-g4-");
    const elsewhere = outsideRoot("guardme-qa-g4-other-");
    await writeNativeBinary(join(cwd, "target", "debug", "wump"));
    await writeNativeBinary(join(tmp, "tester-kim-target", "debug", "wump"));
    await writeNativeBinary(join(elsewhere, "wump"));
    await writeFile(join(cwd, "run.sh"), "#!/bin/sh\necho hi\n");
    await chmod(join(cwd, "run.sh"), 0o755);

    for (const command of [
      "./target/debug/wump --seed 42",
      "target/debug/wump --seed 42",
      "printf 'n\\ns 3 6\\nn\\n' | $TMPDIR/tester-kim-target/debug/wump --seed 42 -r 10",
    ]) {
      assert.equal((await shell(command, cwd)).outcome, "allow", command);
    }
    assert.notEqual((await shell(`${elsewhere}/wump --seed 42`, cwd)).outcome, "allow");
    const script = await mapToolCallToPolicyRequest({ toolName: "bash", input: { command: "./run.sh" } }, cwd);
    assert.equal(script.request.nativeExecutables, undefined, "scripts keep script inspection");

    // The whole guard: local-script inspection must not refuse the binary as uninspectable.
    const ctx = { cwd, hasUI: false, mode: "print", isProjectTrusted: () => true, ui: { setStatus: () => {}, notify: () => {} } };
    await startGuardMeSession(ctx, { homeDir: join(elsewhere, "home"), environment: {} });
    try {
      assert.equal(await evaluateGuardedToolCall({ toolName: "bash", input: { command: "./target/debug/wump --seed 42" } }, ctx), undefined);
    } finally {
      stopGuardMeSession(ctx);
    }
  });
});

test("G5: $TMPDIR paths resolve in commands that carry a heredoc", async () => {
  await withTmpDir(async () => {
    const cwd = outsideRoot("guardme-qa-g5-");
    for (const command of [
      "cat > $TMPDIR/notes.md <<'EOF'\n$TMPDIR stays literal here\nEOF",
      "cat > \"${TMPDIR}/src/main.rs\" <<'EOF'\nfn main() {}\nEOF",
    ]) {
      assert.equal((await shell(command, cwd)).outcome, "allow", command);
    }
  });
});

test("G6: outside-project refusals name the blocked path", async () => {
  const cwd = outsideRoot("guardme-qa-g6-");
  const other = outsideRoot("guardme-qa-g6-other-");
  const list = await shell("ls $UNSET_DIR/rust", cwd);
  assert.equal(list.outcome, "deny");
  assert.match(list.reason, /Outside-project list .*Blocked path: '\$UNSET_DIR\/rust'/);
  const write = await evaluate("write", { path: join(other, "x.txt"), content: "x" }, cwd);
  assert.equal(write.outcome, "deny");
  assert.match(write.reason, /Outside-project write .*Blocked path: /);
});
