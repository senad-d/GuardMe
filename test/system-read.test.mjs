import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { outsideRoot } from "./support/outside-root.mjs";

import { createBuiltInDefaultPolicy } from "../src/config/schema.ts";
import { mergePolicyConfigs, sourcePolicyConfig } from "../src/config/merge-policy.ts";
import { mapToolCallToPolicyRequest } from "../src/events/register-guard.ts";
import { evaluatePolicyRequest } from "../src/policy/evaluate.ts";

const defaults = createBuiltInDefaultPolicy();

function policyWith(extra = {}) {
  return mergePolicyConfigs([sourcePolicyConfig("builtin", { ...defaults, ...extra })]).config;
}

async function evaluate(toolName, input, cwd, policy = policyWith()) {
  const mapped = await mapToolCallToPolicyRequest({ toolName, input }, cwd);
  assert.ok("request" in mapped, JSON.stringify(mapped));
  return evaluatePolicyRequest({ policy, ...mapped });
}

const shell = (command, cwd, policy) => evaluate("bash", { command }, cwd, policy);

test("reads and listings work across the system while writes stay in the project and temp", async () => {
  const root = outsideRoot("guardme-system-read-");
  const cwd = join(root, "project");
  const other = join(root, "other");
  await mkdir(cwd, { recursive: true });
  await mkdir(other, { recursive: true });
  await writeFile(join(other, "notes.txt"), "notes\n", "utf8");

  for (const command of [`cat ${other}/notes.txt`, `ls ${other}`, `find ${other} -name '*.txt'`, `cp ${other}/notes.txt ./notes.txt`, `cat ${other}/notes.txt > /tmp/guardme-notes.txt`]) {
    assert.equal((await shell(command, cwd)).outcome, "allow", command);
  }
  assert.equal((await evaluate("read", { path: join(other, "notes.txt") }, cwd)).outcome, "allow");
  for (const command of [`echo x > ${other}/notes.txt`, `cp notes.txt ${other}/`, `rm ${other}/notes.txt`, `cd ${other} && echo x > notes.txt`, "cat $UNKNOWN/notes.txt"]) {
    assert.equal((await shell(command, cwd)).outcome, "deny", command);
  }
  assert.equal((await evaluate("write", { path: join(other, "x.txt"), content: "x" }, cwd)).outcome, "deny");
});

test("token stores, keychains, browser profiles and shell histories stay unreadable", async () => {
  const cwd = outsideRoot("guardme-system-secrets-");
  for (const path of ["~/.config/gh/hosts.yml", "~/.git-credentials", "~/.zsh_history", "~/Library/Keychains/login.keychain-db", "~/.pi/agent/litellm.json", "~/.ssh/id_rsa"]) {
    assert.equal((await shell(`cat ${path}`, cwd)).outcome, "deny", path);
  }
});

test("recursive content searches outside the project are gated when they would pass protected files", async () => {
  const root = outsideRoot("guardme-system-search-");
  const cwd = join(root, "project");
  const clean = join(root, "clean");
  const leaky = join(root, "leaky");
  const vault = join(root, "vault");
  await mkdir(cwd, { recursive: true });
  await mkdir(join(clean, "sub"), { recursive: true });
  await mkdir(join(leaky, "sub"), { recursive: true });
  await mkdir(join(vault, "tokens"), { recursive: true });
  await writeFile(join(clean, "sub", "a.txt"), "a\n", "utf8");
  await writeFile(join(leaky, ".env"), "SECRET=x\n", "utf8");
  await writeFile(join(leaky, "sub", "secrets.yaml"), "k: v\n", "utf8");
  const policy = policyWith({ protectedCredentialPaths: [...defaults.protectedCredentialPaths, { pattern: `${vault}/tokens/**` }] });

  for (const command of [`rg -n foo ${clean}`, `grep -rn foo ${clean}`, `grep -n foo ${leaky}/sub/a.txt`]) {
    assert.equal((await shell(command, cwd, policy)).outcome, "allow", command);
  }
  for (const command of [`grep -rn foo ${leaky}`, `rg -n foo ${leaky}`, `rg -n foo ${vault}`]) {
    assert.notEqual((await shell(command, cwd, policy)).outcome, "allow", command);
  }
  assert.equal((await evaluate("grep", { path: clean, pattern: "foo" }, cwd, policy)).outcome, "allow");
  assert.notEqual((await evaluate("grep", { path: leaky, pattern: "foo" }, cwd, policy)).outcome, "allow");
  assert.notEqual((await shell(`rg -n foo ${homedir()}`, cwd, policy)).outcome, "allow");
});
