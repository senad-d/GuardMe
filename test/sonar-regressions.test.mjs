import assert from "node:assert/strict";
import test from "node:test";
import { createBuiltInDefaultPolicy } from "../src/config/schema.ts";
import { mergePolicyConfigs, sourcePolicyConfig } from "../src/config/merge-policy.ts";
import { mapToolCallToPolicyRequest } from "../src/events/register-guard.ts";
import { evaluatePolicyRequest } from "../src/policy/evaluate.ts";
import { analyzeScriptShellFacts } from "../src/policy/script-variables.ts";

const policy = mergePolicyConfigs([sourcePolicyConfig("builtin", createBuiltInDefaultPolicy())]).config;

async function metadataDecision(operand) {
  const mapped = await mapToolCallToPolicyRequest({ toolName: "bash", input: { command: 'test -x "$x"' } }, process.cwd());
  assert.ok("request" in mapped);
  return evaluatePolicyRequest({ policy, request: { ...mapped.request, command: `test -x '${operand}'`, requiresExactCommandAllow: true } });
}

test("metadata operands accept only plain variable expansions", async () => {
  for (const operand of ["$x", "${x}/$y", "prefix${name_1}suffix", "$" + "a".repeat(20000)]) {
    assert.equal((await metadataDecision(operand)).risk, "low", operand);
  }
  for (const operand of ["$", "${}", "${x:-fallback}", "$(pick)", "$$x", "$x`pick`", "$x" + "a".repeat(20000) + "$"]) {
    assert.notEqual((await metadataDecision(operand)).risk, "low", operand);
  }
});

test("dot sourcing fails closed across whitespace and command separators", () => {
  for (const source of [". ./other.sh", "  . ./other.sh", "true;\t. ./other.sh", "true;\n\n  . ./other.sh", "\n".repeat(20000) + "\t. ./other.sh"]) {
    const facts = analyzeScriptShellFacts(`x=/project/script.sh\n${source}\n`, "/project");
    assert.equal(facts.variables.size, 0);
    assert.equal(facts.topLevelLines.size, 0);
  }
});

test("long whitespace without sourcing still resolves literal assignments", () => {
  const facts = analyzeScriptShellFacts("\n".repeat(20000) + " ".repeat(20000) + "\nx=/project/script.sh\n", "/project");
  assert.equal(facts.variables.get("x")?.value, "/project/script.sh");
});
