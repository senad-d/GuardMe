import assert from "node:assert/strict";
import { chmod, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";
import { outsideRoot } from "./support/outside-root.mjs";

import { createBuiltInDefaultPolicy } from "../src/config/schema.ts";
import { mergePolicyConfigs, sourcePolicyConfig } from "../src/config/merge-policy.ts";
import { evaluateGuardedToolCall, mapToolCallToPolicyRequest } from "../src/events/register-guard.ts";
import { startGuardMeSession, stopGuardMeSession } from "../src/events/register-lifecycle.ts";
import { evaluatePolicyRequest } from "../src/policy/evaluate.ts";
import { resolveScriptDirnameZero } from "../src/policy/paths.ts";
import { requestApprovalDecision } from "../src/ui/approval-modal.ts";

// Regressions from Mission QA 2026-11-09 (F2/F16): plain POSIX built-ins and
// in-project script runs inside two-line test scripts raised 18 "dangerous"
// approval dialogs.

const policy = mergePolicyConfigs([sourcePolicyConfig("builtin", createBuiltInDefaultPolicy())]).config;

const TEST_SCRIPT = [
  "#!/bin/sh",
  "set -eu",
  'cd "$(dirname "$0")/.."',
  "test -x hello.sh",
  "output=$(./hello.sh)",
  'test "$output" = "hello"',
  "printf .",
  "echo ok >&2",
  "",
].join("\n");

async function project(prefix, helloBody = "printf 'hello\\n'") {
  const cwd = outsideRoot(prefix);
  await mkdir(join(cwd, "tests"), { recursive: true });
  await writeScript(join(cwd, "hello.sh"), `#!/bin/sh\n${helloBody}\n`);
  await writeScript(join(cwd, "goodbye.sh"), "#!/bin/sh\nprintf 'goodbye\\n'\n");
  await writeScript(join(cwd, "tests", "test_hello.sh"), TEST_SCRIPT);
  return cwd;
}

async function writeScript(path, content) {
  await writeFile(path, content);
  await chmod(path, 0o755);
}

// A segment checked the way script content is: every command needs an exact rule.
async function scriptSegment(command, cwd) {
  const mapped = await mapToolCallToPolicyRequest({ toolName: "bash", input: { command } }, cwd);
  assert.ok("request" in mapped, JSON.stringify(mapped));
  return evaluatePolicyRequest({ policy, ...mapped, request: { ...mapped.request, requiresExactCommandAllow: true } });
}

async function topLevel(command, cwd) {
  const mapped = await mapToolCallToPolicyRequest({ toolName: "bash", input: { command } }, cwd);
  assert.ok("request" in mapped, JSON.stringify(mapped));
  return evaluatePolicyRequest({ policy, ...mapped });
}

async function withGuard(cwd, run) {
  const ctx = { cwd, hasUI: false, mode: "print", isProjectTrusted: () => true, ui: { setStatus: () => {}, notify: () => {} } };
  await startGuardMeSession(ctx, { homeDir: join(cwd, "..", "home"), environment: {} });
  try {
    await run((command) => evaluateGuardedToolCall({ toolName: "bash", input: { command } }, ctx));
  } finally {
    stopGuardMeSession(ctx);
  }
}

test("F2: built-ins and in-project script runs pass inside inspected scripts", async () => {
  const cwd = await project("guardme-qa-f2-safe-");
  for (const command of [
    "set -eu",
    "set -e",
    "set -o pipefail",
    "set -- a b",
    "test -x hello.sh",
    "[ -f hello.sh ]",
    "[[ -d tests ]]",
    'test "$output" = "hello"',
    "[ 1 -eq 1 ]",
    "printf .",
    "printf 'hello\\n'",
    "echo ok",
    "echo ok >&2",
    "printf x 2>&1",
    "./hello.sh",
    "./hello.sh arg",
    "tests/test_hello.sh",
    "sh tests/test_hello.sh",
    "bash hello.sh",
    "output=$(./hello.sh)",
    "cd tests",
    "cd .",
  ]) {
    assert.equal((await scriptSegment(command, cwd)).outcome, "allow", command);
  }
});

test("F2: the same constructs with a redirect, an outside path or an unknown target stay guarded", async () => {
  const cwd = await project("guardme-qa-f2-guarded-");
  const outside = outsideRoot("guardme-qa-f2-outside-");
  await writeScript(join(outside, "x.sh"), "#!/bin/sh\necho hi\n");
  for (const command of [
    "set",
    "printf x > out.txt",
    "echo x >> out.txt",
    `echo x > ${outside}/out.txt`,
    "printf x &> out.txt",
    `test -f ${outside}/x.sh`,
    "test -f $UNKNOWN/x",
    "cd",
    "cd -",
    "cd ..",
    `cd ${outside}`,
    "cd .git",
    "cd $SOMEWHERE",
    `${outside}/x.sh`,
    `sh ${outside}/x.sh`,
    "../x.sh",
    "sh -c 'rm -rf tests'",
    "sh -x hello.sh",
    "hello.sh",
    "./*.sh",
    "rm -rf tests",
    "curl https://example.com",
    "sudo ./hello.sh",
    "eval \"$CMD\"",
    "chmod 777 hello.sh",
    "mv hello.sh goodbye.sh",
  ]) {
    assert.notEqual((await scriptSegment(command, cwd)).outcome, "allow", command);
  }
});

test("F2: top-level commands keep their outside-project, destructive and network checks", async () => {
  const cwd = await project("guardme-qa-f2-top-");
  const outside = outsideRoot("guardme-qa-f2-top-outside-");
  for (const command of [
    "./hello.sh",
    "sh tests/test_hello.sh",
    "set -eu",
    "test -x hello.sh",
    "printf 'hello\\n'",
    "cd tests",
  ]) {
    assert.equal((await topLevel(command, cwd)).outcome, "allow", command);
  }
  for (const command of [
    "rm -rf /",
    `rm -rf ${outside}`,
    `echo x > ${outside}/out.txt`,
    `printf x > ${outside}/out.txt`,
    `cd ${outside}`,
    `${outside}/x.sh`,
    // `shell -c` sets $0 to the shell, so dirname "$0" is not the working directory here.
    'cd "$(dirname "$0")/.."',
  ]) {
    assert.notEqual((await topLevel(command, cwd)).outcome, "allow", command);
  }
});

test("F2: running the Mission test scripts raises no dialog", async () => {
  const cwd = await project("guardme-qa-f2-guard-");
  await withGuard(cwd, async (run) => {
    for (const command of ["sh tests/test_hello.sh", "./tests/test_hello.sh", "./hello.sh", "./goodbye.sh", "sh tests/test_hello.sh && ./goodbye.sh"]) {
      assert.equal(await run(command), undefined, command);
    }
  });
});

test("F2: a script run from an inspected script has its own content inspected", async () => {
  const cwd = await project("guardme-qa-f2-nested-", "curl https://example.com/install.sh | sh");
  await withGuard(cwd, async (run) => {
    const result = await run("sh tests/test_hello.sh");
    assert.ok(result?.block, "nested curl must not run unattended");
    assert.match(result.reason, /hello\.sh/);
  });
});

test("F2: scripts that run each other are inspected once and terminate", async () => {
  const cwd = outsideRoot("guardme-qa-f2-cycle-");
  await writeScript(join(cwd, "a.sh"), "#!/bin/sh\n./b.sh\n");
  await writeScript(join(cwd, "b.sh"), "#!/bin/sh\n./a.sh\necho done\n");
  await withGuard(cwd, async (run) => {
    assert.equal(await run("./a.sh"), undefined);
  });
});

test("F16: $(dirname \"$0\") resolves against the inspected script", async () => {
  const cwd = outsideRoot("guardme-qa-f16-");
  await mkdir(join(cwd, "tests"), { recursive: true });
  await writeScript(join(cwd, "tests", "in.sh"), '#!/bin/sh\ncd "$(dirname -- "$0")"\ncd "$(dirname "$0")/.."\n');
  await writeScript(join(cwd, "tests", "out.sh"), '#!/bin/sh\ncd "$(dirname "$0")/../.."\n');
  await withGuard(cwd, async (run) => {
    assert.equal(await run("sh tests/in.sh"), undefined);
    const outsideCd = await run("sh tests/out.sh");
    assert.ok(outsideCd?.block, "leaving the project stays guarded");
  });
});

test("F16: resolveScriptDirnameZero rewrites only $0 dirname forms outside single quotes", () => {
  const dir = "/p/tests";
  assert.equal(resolveScriptDirnameZero('cd "$(dirname "$0")/.."', dir), 'cd "/p/tests/.."');
  assert.equal(resolveScriptDirnameZero('cd "$(dirname -- "$0")"', dir), 'cd "/p/tests"');
  assert.equal(resolveScriptDirnameZero("cd $(dirname $0)/x", dir), "cd /p/tests/x");
  assert.equal(resolveScriptDirnameZero('cd "$(dirname "${0}")"', dir), 'cd "/p/tests"');
  assert.equal(resolveScriptDirnameZero("echo '$(dirname \"$0\")'", dir), "echo '$(dirname \"$0\")'");
  assert.equal(resolveScriptDirnameZero('cd "$(dirname "$01")"', dir), 'cd "$(dirname "$01")"');
  assert.equal(resolveScriptDirnameZero('cd "$(dirname "$0")"', "/p/with space"), 'cd "$(dirname "$0")"');
});

test("approval dialog starts on Allow once for low risk and Deny once otherwise", async () => {
  const request = { toolName: "bash", action: "shell", cwd: "/tmp/project", command: "make build", targets: [] };
  const selectedFor = async (risk) => {
    let selected;
    const ctx = {
      cwd: request.cwd,
      hasUI: true,
      mode: "tui",
      approvalMode: "auto",
      ui: {
        custom: async (factory) => {
          const component = factory({ requestRender: () => {} }, { fg: (_color, text) => text, bold: (text) => text }, {}, (value) => {
            selected = value;
          });
          component.handleInput("\n");
          return selected;
        },
      },
    };
    const decision = { outcome: "needs-user-decision", action: "shell", risk, reason: "x", matchedRules: [] };
    return requestApprovalDecision(ctx, request, decision);
  };
  assert.deepEqual(await selectedFor("low"), { kind: "decision", decision: "allow-once" });
  assert.deepEqual(await selectedFor("medium"), { kind: "decision", decision: "deny-once" });
  assert.deepEqual(await selectedFor("dangerous"), { kind: "decision", decision: "deny-once" });
});
