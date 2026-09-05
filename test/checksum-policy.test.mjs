import assert from "node:assert/strict";
import test from "node:test";

import { createBuiltInDefaultPolicy } from "../src/config/schema.ts";
import { mergePolicyConfigs, sourcePolicyConfig } from "../src/config/merge-policy.ts";
import { classifyShellCommand } from "../src/policy/commands.ts";
import { evaluatePolicyRequest } from "../src/policy/evaluate.ts";

const policy = mergePolicyConfigs([sourcePolicyConfig("builtin", createBuiltInDefaultPolicy())]).config;

function evaluate(command) {
  const classified = classifyShellCommand(command);
  return evaluatePolicyRequest({
    policy,
    commandClassification: classified,
    request: {
      toolName: "bash", action: classified.primaryAction, cwd: process.cwd(), command,
      targets: classified.targetPaths.map((raw) => ({ kind: "path", raw })),
    },
  });
}

test("default checksum permission allows direct Git verification compounds", () => {
  assert.equal(evaluate("git rev-parse HEAD; git diff --check; shasum -a 256 package.json pnpm-lock.yaml").outcome, "allow");
  assert.equal(evaluate("git rev-parse HEAD; git branch --show-current; git diff --name-only; git ls-files --others --exclude-standard; git diff --check; git diff -- apps/api/package.json apps/api/src/app.module.ts pnpm-workspace.yaml; shasum -a 256 apps/api/drizzle.config.ts apps/api/package.json apps/api/src/database/client.ts apps/api/src/database/migrate.ts apps/api/src/database/migrations/0001_platform.sql apps/api/src/app.module.ts apps/api/test/platform-migration.integration.spec.ts docs/testing.md pnpm-lock.yaml pnpm-workspace.yaml").outcome, "allow");
  for (const options of ["-a 256", "-a256", "--algorithm 256", "--algorithm=256", "-ba 256"]) {
    assert.deepEqual(classifyShellCommand(`shasum ${options} package.json`).targetPaths, ["package.json"]);
  }
  assert.deepEqual(classifyShellCommand("shasum -- -input").targetPaths, ["-input"]);
});

test("checksum permission retains credential and outside-project protections", () => {
  assert.equal(evaluate("shasum -a 256 .env").outcome, "deny");
  assert.equal(evaluate("shasum -a 256 /etc/passwd").outcome, "deny");
  assert.equal(evaluate("git diff --check; shasum -a 256 .env").outcome, "deny");
});

test("checksum manifests require review instead of implicit file access", () => {
  for (const options of ["-c", "--check", "-bc"]) {
    const decision = evaluate(`shasum ${options} checksums.txt`);
    assert.equal(decision.outcome, "coach");
    assert.match(decision.reason, /manifests/);
  }
});
