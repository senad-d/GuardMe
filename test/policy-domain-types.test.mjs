import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  POLICY_ACTIONS,
  POLICY_DECISION_OUTCOMES,
  RULE_SOURCE_KINDS,
  USER_DECISIONS,
  isPolicyAction,
  isUserDecision,
} from "../src/policy/action.ts";

test("policy domain actions cover all approved GuardMe action kinds", () => {
  assert.deepEqual(POLICY_ACTIONS, ["read", "list", "write", "edit", "delete", "move", "rename", "shell"]);
  assert.equal(isPolicyAction("read"), true);
  assert.equal(isPolicyAction("shell"), true);
  assert.equal(isPolicyAction("network"), false);
});

test("policy decisions and user decisions model the approved outcomes", () => {
  assert.deepEqual(POLICY_DECISION_OUTCOMES, ["allow", "deny", "coach", "needs-user-decision"]);
  assert.deepEqual(USER_DECISIONS, [
    "allow-once",
    "deny-once",
    "allow-local",
    "deny-local",
    "allow-global",
    "deny-global",
  ]);
  assert.equal(isUserDecision("allow-local"), true);
  assert.equal(isUserDecision("allow-forever"), false);
});

test("policy domain module remains independent from Pi runtime APIs", async () => {
  const source = await readFile(new URL("../src/policy/action.ts", import.meta.url), "utf8");
  assert.deepEqual(RULE_SOURCE_KINDS, ["builtin", "global", "local", "default", "user"]);
  assert.doesNotMatch(source, /@earendil-works\/pi-coding-agent/);
  assert.doesNotMatch(source, /ExtensionAPI/);
});
