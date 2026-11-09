import assert from "node:assert/strict";
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { outsideRoot } from "./support/outside-root.mjs";

import { createBuiltInDefaultPolicy } from "../src/config/schema.ts";
import { mergePolicyConfigs, sourcePolicyConfig } from "../src/config/merge-policy.ts";
import { mapToolCallToPolicyRequest } from "../src/events/register-guard.ts";
import { evaluatePolicyRequest } from "../src/policy/evaluate.ts";

const policy = mergePolicyConfigs([sourcePolicyConfig("builtin", createBuiltInDefaultPolicy())]).config;

async function evaluate(command, cwd) {
  const mapped = await mapToolCallToPolicyRequest({ toolName: "bash", input: { command } }, cwd);
  assert.ok("request" in mapped, JSON.stringify(mapped));
  return evaluatePolicyRequest({ policy, ...mapped });
}

test("outside paths are testable and readable while writes and cd keep the project boundary", async () => {
  const cwd = outsideRoot("guardme-existence-project-");
  const sibling = outsideRoot("guardme-existence-sibling-");
  mkdirSync(join(sibling, "sub"));
  for (const command of [
    `test -d ${sibling}`,
    `[ -e ${sibling}/sub ]`,
    `if test -d ${sibling}; then printf 'READY\\n'; else printf 'MISSING\\n'; fi`,
    `test -d ${sibling} && ls ${sibling}`,
  ]) {
    assert.equal((await evaluate(command, cwd)).outcome, "allow", command);
  }
  for (const command of [
    `[ -d ${sibling} ] && cp a ${sibling}/`,
    `test -d ${sibling}; cd ${sibling}`,
    "test -f ~/.ssh/id_rsa",
    "[ -e ~/.aws/credentials ]",
  ]) {
    assert.equal((await evaluate(command, cwd)).outcome, "deny", command);
  }
});

test("force pushes and hard resets need approval while ordinary git pushes and resets do not", async () => {
  const cwd = outsideRoot("guardme-git-danger-");
  for (const command of ["git push --force origin main", "git push origin main --force", "git push -f", "git reset --hard HEAD~3"]) {
    assert.notEqual((await evaluate(command, cwd)).outcome, "allow", command);
  }
  for (const command of ["git push origin main --follow-tags", "git push -u origin feature", "git reset --soft HEAD~1"]) {
    assert.equal((await evaluate(command, cwd)).outcome, "allow", command);
  }
});
