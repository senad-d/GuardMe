import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { access, chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { outsideRoot } from "./support/outside-root.mjs";

import { loadGuardMeConfig } from "../src/config/load-config.ts";
import { createBuiltInDefaultPolicy, createEmptyPolicyConfig } from "../src/config/schema.ts";
import { mergePolicyConfigs, sourcePolicyConfig } from "../src/config/merge-policy.ts";
import { persistUserDecisionRule } from "../src/config/write-policy.ts";
import { mapToolCallToPolicyRequest } from "../src/events/register-guard.ts";
import { startGuardMeSession, stopGuardMeSession } from "../src/events/register-lifecycle.ts";
import { detectLocalScriptExecutions } from "../src/policy/commands.ts";
import { evaluatePolicyRequest } from "../src/policy/evaluate.ts";

// Regressions from a Mission end-to-end run that raised 18 needless approval
// dialogs (I15a-f), and the project policy move to .pi/guardme.yaml (D21, D2).

const builtin = mergePolicyConfigs([sourcePolicyConfig("builtin", createBuiltInDefaultPolicy())]).config;

async function decide(command, cwd, policy = builtin, requiresExactCommandAllow = false) {
  const mapped = await mapToolCallToPolicyRequest({ toolName: "bash", input: { command } }, cwd);
  assert.ok("request" in mapped, JSON.stringify(mapped));
  return evaluatePolicyRequest({ policy, ...mapped, request: { ...mapped.request, requiresExactCommandAllow } });
}

// Points TMPDIR at a per-run directory such as /tmp/mission/<project>/<objective>.
async function withSessionTmpdir(run) {
  const previous = process.env.TMPDIR;
  const base = await mkdtemp(join(tmpdir(), "guardme-approvals-"));
  const sessionTmp = join(base, "mission", "p", "8");
  await mkdir(sessionTmp, { recursive: true });
  process.env.TMPDIR = sessionTmp;
  try {
    await run(base);
  } finally {
    await rm(base, { recursive: true, force: true });
    if (previous === undefined) {
      delete process.env.TMPDIR;
    } else {
      process.env.TMPDIR = previous;
    }
  }
}

function git(cwd, ...args) {
  return execFileSync("git", args, { cwd, encoding: "utf8" });
}

test("I15a: a call to a function defined in the command is judged by its body with the call's arguments", async () => {
  const policy = mergePolicyConfigs([sourcePolicyConfig("builtin", { ...createEmptyPolicyConfig(), allowCommands: [{ pattern: "docker compose -p x port *" }] })]).config;
  const cwd = outsideRoot("guardme-i15a-");
  const define = 'compose() { docker compose -p x "$@"; }; ';
  assert.equal((await decide(`${define}compose port linkbox 3000`, cwd, policy)).outcome, "allow");
  assert.notEqual((await decide(`${define}compose push`, cwd, policy)).outcome, "allow");
  // shift changes what $1 means, so the call is not mapped onto the body.
  assert.notEqual((await decide('f() { shift; docker compose -p x port "$1"; }; f a b', cwd, policy)).outcome, "allow");
});

test("I15b: the shell no-op guard passes while its substitutions and redirects are still judged", async () => {
  const cwd = outsideRoot("guardme-i15b-");
  assert.equal((await decide(': "${COMPOSE_PROJECT_NAME:?unset}"', cwd)).outcome, "allow");
  assert.equal((await decide(': "${X:?unset}" && docker compose ps', cwd)).outcome, "allow");
  for (const command of [': "$(aws s3 ls)"', ': "$(unknown-tool --run)"', ": > /etc/x"]) {
    assert.notEqual((await decide(command, cwd)).outcome, "allow", command);
  }
});

test("I15c: a redirect into the session TMPDIR or the project leaves a harmless command harmless", async () => {
  const cwd = outsideRoot("guardme-i15c-");
  await writeFile(join(cwd, "run.sh"), "#!/bin/sh\necho hi\n");
  await chmod(join(cwd, "run.sh"), 0o755);
  await withSessionTmpdir(async (base) => {
    assert.equal((await decide("./run.sh > $TMPDIR/x.log 2>&1", cwd)).outcome, "allow");
    assert.equal((await decide('echo x > "$TMPDIR/x.log"', cwd, builtin, true)).outcome, "allow");
    assert.equal((await decide("printf x >> out.txt", cwd, builtin, true)).outcome, "allow");
    for (const command of ["./run.sh > /etc/x", "echo x > /etc/x", `./run.sh > ${base}/outside-scratch.log`, "./run.sh > $UNSET/x.log"]) {
      assert.notEqual((await decide(command, cwd)).outcome, "allow", command);
    }
  });
});

test("I15d: sh -n only checks syntax, so the script is not inspected", () => {
  assert.deepEqual(detectLocalScriptExecutions("sh -n x.sh"), []);
  assert.deepEqual(detectLocalScriptExecutions("bash -nv x.sh"), []);
  assert.deepEqual(detectLocalScriptExecutions("bash -n -- x.sh"), []);
  assert.deepEqual(detectLocalScriptExecutions("sh -x x.sh").map((script) => script.rawPath), ["x.sh"]);
});

test("I15f: fnm list is allowed, fnm install still asks", async () => {
  const cwd = outsideRoot("guardme-i15f-");
  assert.equal((await decide("fnm list", cwd)).outcome, "allow");
  assert.notEqual((await decide("fnm install 22", cwd)).outcome, "allow");
});

test("D21: the project policy loads from .pi/guardme.yaml, the old path only warns", async () => {
  const policy = "version: 1\nallowCommands:\n  - pattern: \"only-in-project *\"\n";
  const moved = outsideRoot("guardme-d21-new-");
  await mkdir(join(moved, ".pi"), { recursive: true });
  await writeFile(join(moved, ".pi", "guardme.yaml"), policy);
  const loaded = await loadGuardMeConfig({ cwd: moved, homeDir: join(moved, "home") });
  assert.ok(loaded.config.allowCommands.some((rule) => rule.pattern === "only-in-project *" && rule.source.kind === "local"));
  assert.ok(!loaded.diagnostics.some((diagnostic) => diagnostic.code === "config.localPolicyMoved"));

  const old = outsideRoot("guardme-d21-old-");
  await mkdir(join(old, ".pi", "agent"), { recursive: true });
  await writeFile(join(old, ".pi", "agent", "guardme.yaml"), policy);
  const notices = [];
  const ctx = { cwd: old, hasUI: true, isProjectTrusted: () => true, ui: { setStatus: () => {}, notify: (message, type) => notices.push([message, type]) } };
  const state = await startGuardMeSession(ctx, { homeDir: join(old, "home") });
  stopGuardMeSession(ctx);
  assert.ok(!state.config.config.allowCommands.some((rule) => rule.pattern === "only-in-project *"));
  assert.deepEqual(notices.filter(([message]) => /moved to \.pi\/guardme\.yaml, rename it/u.test(message)).map(([, type]) => type), ["warning"]);

  const mapped = await mapToolCallToPolicyRequest({ toolName: "write", input: { path: ".pi/guardme.yaml", content: "version: 1\n" } }, moved);
  assert.ok("request" in mapped, JSON.stringify(mapped));
  assert.equal(evaluatePolicyRequest({ policy: builtin, ...mapped }).outcome, "deny");
});

test("D2: a saved project rule is ignored in .pi/.gitignore unless git tracks the policy", async () => {
  const save = (cwd) =>
    persistUserDecisionRule({ cwd, homeDir: join(cwd, "..", "home"), scope: "local", decision: "allow-local", request: { toolName: "bash", action: "shell", cwd, command: "make build", targets: [] } });

  const fresh = join(await mkdtemp(join(tmpdir(), "guardme-d2-fresh-")), "project");
  await mkdir(fresh);
  git(fresh, "init", "-q");
  assert.equal((await save(fresh)).saved, true);
  assert.equal(git(fresh, "status", "--porcelain"), "");
  await assert.rejects(access(join(fresh, ".gitignore")));

  const tracked = join(await mkdtemp(join(tmpdir(), "guardme-d2-tracked-")), "project");
  await mkdir(join(tracked, ".pi"), { recursive: true });
  git(tracked, "init", "-q");
  await writeFile(join(tracked, ".pi", "guardme.yaml"), "version: 1\n");
  git(tracked, "add", ".pi/guardme.yaml");
  assert.equal((await save(tracked)).saved, true);
  assert.doesNotMatch(await readFile(join(tracked, ".pi", ".gitignore"), "utf8").catch(() => ""), /guardme\.yaml/u);
});
