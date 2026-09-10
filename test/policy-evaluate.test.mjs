import assert from "node:assert/strict";
import { mkdir, mkdtemp, symlink, writeFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { outsideRoot } from "./support/outside-root.mjs";

import { mergePolicyConfigs, sourcePolicyConfig } from "../src/config/merge-policy.ts";
import { createBuiltInDefaultPolicy, createEmptyPolicyConfig } from "../src/config/schema.ts";
import { classifyShellCommand } from "../src/policy/commands.ts";
import { USER_DECISIONS } from "../src/policy/action.ts";
import { commandGlobToRegExp, createPolicyFingerprint, evaluatePolicyRequest, isAgentAutomaticApprovalEligible } from "../src/policy/evaluate.ts";
import { normalizePolicyPath, pathTargetFromNormalizedPath } from "../src/policy/paths.ts";

function policyFrom(localConfig) {
  return mergePolicyConfigs([sourcePolicyConfig("builtin", createEmptyPolicyConfig()), sourcePolicyConfig("local", localConfig)]).config;
}

async function pathRequest(cwd, action, rawPath) {
  const normalized = await normalizePolicyPath(rawPath, { cwd });
  return {
    toolName: action === "read" ? "read" : "write",
    action,
    cwd,
    targets: [pathTargetFromNormalizedPath(normalized)],
  };
}

function shellRequest(cwd, command) {
  const classified = classifyShellCommand(command);
  return {
    request: {
      toolName: "bash",
      action: classified.primaryAction,
      cwd,
      command,
      targets: classified.targetPaths.map((target) => ({ kind: "path", raw: target })),
      riskHint: classified.risk,
    },
    classified,
  };
}

test("agent automatic approval eligibility rejects synthetic deny and protection decisions", () => {
  const eligibleDecision = {
    outcome: "needs-user-decision",
    action: "delete",
    risk: "dangerous",
    reason: "Synthetic coachable decision.",
    matchedRules: [
      {
        category: "dangerousCommands",
        source: { kind: "builtin", label: "synthetic dangerous command" },
        pattern: "rm -rf build",
        actions: ["delete"],
      },
    ],
    fingerprint: "sha256:synthetic",
    prompt: true,
    choices: USER_DECISIONS,
  };

  assert.equal(isAgentAutomaticApprovalEligible(eligibleDecision), true);
  assert.equal(
    isAgentAutomaticApprovalEligible({ ...eligibleDecision, outcome: "deny", block: true, hard: false }),
    false,
  );
  assert.equal(isAgentAutomaticApprovalEligible({ ...eligibleDecision, risk: "hard-denied" }), false);

  for (const category of [
    "denyPaths",
    "zeroAccessPaths",
    "readOnlyPaths",
    "noDeletePaths",
    "denyCommands",
    "protectedCredentialPaths",
    "hardDeny",
  ]) {
    const protectedDecision = {
      ...eligibleDecision,
      matchedRules: [{ category, source: { kind: "builtin", label: "synthetic protection" } }],
    };
    assert.equal(isAgentAutomaticApprovalEligible(protectedDecision), false, category);
  }

  for (const reasonCode of ["hard-denied-command", "path-protected", "outside-project-path"]) {
    assert.equal(isAgentAutomaticApprovalEligible({ ...eligibleDecision, reasonCode }), false, reasonCode);
  }
});

test("command glob matching supports optional trailing arguments", () => {
  const lsFamily = commandGlobToRegExp("ls *");
  assert.equal(lsFamily.test("ls"), true);
  assert.equal(lsFamily.test("ls -lh"), true);
  assert.equal(lsFamily.test("/bin/ls -lh"), false);
  assert.equal(commandGlobToRegExp("sudo *").test("sudo"), true);
  assert.equal(commandGlobToRegExp("ls *").test("eslint ."), false);
  assert.equal(commandGlobToRegExp("rm -rf build").test("rm -rf build"), true);
  assert.equal(commandGlobToRegExp("rm -rf build").test("rm -rf dist"), false);
});

test("hard-denied commands block even when an allow command rule matches", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "guardme-eval-command-"));
  const policy = policyFrom({
    ...createEmptyPolicyConfig(),
    allowCommands: [{ pattern: "aws *", reason: "attempted allow" }],
  });
  const { request, classified } = shellRequest(cwd, "aws sts get-caller-identity");

  const decision = evaluatePolicyRequest({ policy, request, commandClassification: classified });

  assert.equal(decision.outcome, "deny");
  assert.equal(decision.hard, true);
  assert.equal(decision.risk, "hard-denied");
});

test("zeroAccessPaths readOnlyPaths and noDeletePaths always block protected actions", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "guardme-eval-protections-"));
  await mkdir(join(cwd, "docs"), { recursive: true });
  await mkdir(join(cwd, ".git"), { recursive: true });
  await writeFile(join(cwd, "secret.txt"), "redacted", "utf8");
  await writeFile(join(cwd, "docs", "guide.md"), "guide", "utf8");

  const policy = policyFrom({
    ...createEmptyPolicyConfig(),
    allowPaths: [
      { pattern: "secret.txt", actions: ["read"] },
      { pattern: "docs/**", actions: ["write"] },
      { pattern: ".git/**", actions: ["delete"] },
    ],
    zeroAccessPaths: [{ pattern: "secret.txt" }],
    readOnlyPaths: [{ pattern: "docs/**" }],
    noDeletePaths: [{ pattern: ".git/**" }],
  });

  const zero = evaluatePolicyRequest({ policy, request: await pathRequest(cwd, "read", "secret.txt") });
  const readOnly = evaluatePolicyRequest({ policy, request: await pathRequest(cwd, "write", "docs/guide.md") });
  const noDelete = evaluatePolicyRequest({ policy, request: await pathRequest(cwd, "delete", ".git/config") });

  assert.equal(zero.outcome, "deny");
  assert.equal(zero.hard, true);
  assert.equal(readOnly.outcome, "deny");
  assert.equal(readOnly.hard, true);
  assert.equal(noDelete.outcome, "deny");
  assert.equal(noDelete.hard, true);
});

test("built-in noDeletePaths block repository metadata root actions", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "guardme-eval-git-root-"));
  await mkdir(join(cwd, ".git"), { recursive: true });
  const policy = mergePolicyConfigs([sourcePolicyConfig("builtin", createBuiltInDefaultPolicy())]).config;

  for (const action of ["delete", "move", "rename"]) {
    const decision = evaluatePolicyRequest({ policy, request: await pathRequest(cwd, action, ".git") });
    assert.equal(decision.outcome, "deny", action);
    assert.equal(decision.hard, true, action);
    assert.equal(decision.matchedRules[0]?.category, "noDeletePaths", action);
  }
});

test("credential-like path classifier blocks case variants before default project allow", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "guardme-eval-credential-case-"));
  await writeFile(join(cwd, "Secret.TXT"), "redacted", "utf8");
  await mkdir(join(cwd, ".SSH"), { recursive: true });
  const policy = mergePolicyConfigs([sourcePolicyConfig("builtin", createBuiltInDefaultPolicy())]).config;

  const secretFile = evaluatePolicyRequest({ policy, request: await pathRequest(cwd, "read", "Secret.TXT") });
  const sshDirectory = evaluatePolicyRequest({ policy, request: await pathRequest(cwd, "list", ".SSH") });
  const sshGlob = evaluatePolicyRequest({ policy, request: await pathRequest(cwd, "list", ".SSH*") });

  assert.equal(secretFile.outcome, "deny");
  assert.equal(secretFile.hard, true);
  assert.equal(secretFile.matchedRules[0]?.source.label, "credential path classifier");
  assert.equal(sshDirectory.outcome, "deny");
  assert.equal(sshDirectory.hard, true);
  assert.equal(sshGlob.outcome, "deny");
  assert.equal(sshGlob.hard, true);
});

test("env example files are editable but destructive actions remain protected by defaults", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "guardme-eval-env-example-"));
  await writeFile(join(cwd, ".env.example"), "TEST=example\n", "utf8");
  const policy = mergePolicyConfigs([sourcePolicyConfig("builtin", createBuiltInDefaultPolicy())]).config;

  const writeExample = evaluatePolicyRequest({ policy, request: await pathRequest(cwd, "write", ".env.example") });
  const readExample = evaluatePolicyRequest({ policy, request: await pathRequest(cwd, "read", ".env.example") });
  const deleteExample = evaluatePolicyRequest({ policy, request: await pathRequest(cwd, "delete", ".env.example") });
  const readEnv = evaluatePolicyRequest({ policy, request: await pathRequest(cwd, "read", ".env") });

  assert.equal(writeExample.outcome, "allow");
  assert.equal(readExample.outcome, "allow");
  assert.equal(deleteExample.outcome, "deny");
  assert.equal(readEnv.outcome, "deny");
});

test("non-template env variants are credential protected by defaults", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "guardme-eval-env-variant-"));
  await writeFile(join(cwd, ".env.local"), "SECRET=redacted\n", "utf8");
  const policy = mergePolicyConfigs([sourcePolicyConfig("builtin", createBuiltInDefaultPolicy())]).config;

  const readLocal = evaluatePolicyRequest({ policy, request: await pathRequest(cwd, "read", ".env.local") });
  const editProduction = evaluatePolicyRequest({ policy, request: await pathRequest(cwd, "edit", ".env.production") });

  assert.equal(readLocal.outcome, "deny");
  assert.equal(readLocal.hard, true);
  assert.equal(editProduction.outcome, "deny");
  assert.equal(editProduction.hard, true);
});

test("credential keyword protection uses word boundaries instead of substrings", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "guardme-eval-keyword-"));
  await mkdir(join(cwd, "src"), { recursive: true });
  await writeFile(join(cwd, "src", "tokenizer.ts"), "export const x = 1;\n", "utf8");
  await writeFile(join(cwd, "secrets.yaml"), "redacted\n", "utf8");
  const policy = mergePolicyConfigs([sourcePolicyConfig("builtin", createBuiltInDefaultPolicy())]).config;

  const codeRead = evaluatePolicyRequest({ policy, request: await pathRequest(cwd, "read", "src/tokenizer.ts") });
  const codeWrite = evaluatePolicyRequest({ policy, request: await pathRequest(cwd, "write", "src/tokenizer.ts") });
  const secretRead = evaluatePolicyRequest({ policy, request: await pathRequest(cwd, "read", "secrets.yaml") });

  assert.equal(codeRead.outcome, "allow");
  assert.equal(codeWrite.outcome, "allow");
  assert.equal(secretRead.outcome, "deny");
  assert.equal(secretRead.hard, true);
});

test("default allow list covers common dev commands and denies environment dumps", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "guardme-eval-dev-allow-"));
  const policy = mergePolicyConfigs([sourcePolicyConfig("builtin", createBuiltInDefaultPolicy())]).config;

  for (const command of [
    "pnpm install",
    "yarn test",
    "ls | sort -u",
    "awk '{print $1}' notes.txt",
    "[ -f package.json ] && echo yes",
    "diff a.txt b.txt",
    "tar -czf out.tgz src",
  ]) {
    const { request, classified } = shellRequest(cwd, command);
    const decision = evaluatePolicyRequest({ policy, request, commandClassification: classified });
    assert.equal(decision.outcome, "allow", command);
  }

  for (const command of ["env", "printenv", "env | grep -i aws", "node -p process.env"]) {
    const { request, classified } = shellRequest(cwd, command);
    const decision = evaluatePolicyRequest({ policy, request, commandClassification: classified });
    assert.equal(decision.outcome, "deny", command);
    assert.equal(decision.risk, "hard-denied", command);
  }
});

test("read-only path grants outside the project require anchored patterns", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "guardme-eval-anchored-"));
  const policy = mergePolicyConfigs([sourcePolicyConfig("builtin", createBuiltInDefaultPolicy())]).config;

  const piAuth = evaluatePolicyRequest({ policy, request: await pathRequest(cwd, "read", join(homedir(), ".pi", "agent", "auth.json")) });
  const otherProjectPi = evaluatePolicyRequest({
    policy,
    request: await pathRequest(cwd, "read", join(homedir(), "guardme-unrelated", ".pi", "agent", "guardme-state.jsonl")),
  });
  const otherProjectGit = evaluatePolicyRequest({
    policy,
    request: await pathRequest(cwd, "read", join(homedir(), "guardme-unrelated", ".git", "config")),
  });
  const globalPolicyRead = evaluatePolicyRequest({ policy, request: await pathRequest(cwd, "read", join(homedir(), ".pi", "agent", "guardme.yaml")) });

  assert.equal(piAuth.outcome, "deny");
  assert.equal(piAuth.hard, true);
  assert.equal(otherProjectPi.outcome, "deny");
  assert.equal(otherProjectGit.outcome, "deny");
  assert.equal(globalPolicyRead.outcome, "allow");
});

test("credential-printing and file-writing CLI subcommands are gated by defaults", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "guardme-eval-cli-gates-"));
  const policy = mergePolicyConfigs([sourcePolicyConfig("builtin", createBuiltInDefaultPolicy())]).config;

  for (const command of ["gh auth token", "git credential fill", "npm config get //registry.npmjs.org/:_authToken"]) {
    const { request, classified } = shellRequest(cwd, command);
    const decision = evaluatePolicyRequest({ policy, request, commandClassification: classified });
    assert.equal(decision.outcome, "deny", command);
  }

  for (const command of ["git apply fix.patch", "git config core.hooksPath /tmp/hooks", "npm pkg set scripts.test=vitest"]) {
    const { request, classified } = shellRequest(cwd, command);
    const decision = evaluatePolicyRequest({ policy, request, commandClassification: classified });
    assert.equal(decision.outcome, "coach", command);
  }

  for (const command of ["gh pr list", "git config user.name", "npm pkg get name"]) {
    const { request, classified } = shellRequest(cwd, command);
    const decision = evaluatePolicyRequest({ policy, request, commandClassification: classified });
    assert.equal(decision.outcome, "allow", command);
  }
});

test("fingerprints distinguish commands that differ only in secret values", () => {
  const base = { toolName: "bash", action: "shell", cwd: "/tmp/project", targets: [] };
  const first = createPolicyFingerprint({ ...base, command: "deploy --token=AAA" });
  const second = createPolicyFingerprint({ ...base, command: "deploy --token=BBB" });
  const repeat = createPolicyFingerprint({ ...base, command: "deploy --token=AAA" });

  assert.notEqual(first, second);
  assert.equal(first, repeat);
});

test("discovery-synthesized protections are approval-gated while zero-access stays hard", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "guardme-eval-discovery-"));
  const denyPolicy = policyFrom({
    ...createEmptyPolicyConfig(),
    denyPaths: [{ pattern: "vault/**", actions: ["read"] }],
  });
  const zeroPolicy = policyFrom({
    ...createEmptyPolicyConfig(),
    zeroAccessPaths: [{ pattern: "vault/**" }],
  });
  const request = {
    toolName: "grep",
    action: "read",
    cwd,
    targets: [
      { kind: "path", raw: "." },
      { kind: "path", raw: "vault/notes.txt", discovery: true },
    ],
  };

  const coached = evaluatePolicyRequest({ policy: denyPolicy, request });
  const prompted = evaluatePolicyRequest({ policy: denyPolicy, request, warnedFingerprints: new Set([coached.fingerprint]) });
  const zero = evaluatePolicyRequest({ policy: zeroPolicy, request });
  const direct = evaluatePolicyRequest({
    policy: denyPolicy,
    request: { ...request, targets: [{ kind: "path", raw: "vault/notes.txt" }] },
  });

  assert.equal(coached.outcome, "coach");
  assert.match(coached.reason, /traverse protected path/);
  assert.equal(prompted.outcome, "needs-user-decision");
  assert.equal(isAgentAutomaticApprovalEligible(prompted), false);
  assert.equal(zero.outcome, "deny");
  assert.equal(zero.hard, true);
  assert.equal(direct.outcome, "deny");
});

test("denyPaths beat allowPaths", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "guardme-eval-deny-allow-"));
  await writeFile(join(cwd, "blocked.txt"), "blocked", "utf8");
  const policy = policyFrom({
    ...createEmptyPolicyConfig(),
    allowPaths: [{ pattern: "blocked.txt", actions: ["read"] }],
    denyPaths: [{ pattern: "blocked.txt", actions: ["read"] }],
  });

  const decision = evaluatePolicyRequest({ policy, request: await pathRequest(cwd, "read", "blocked.txt") });

  assert.equal(decision.outcome, "deny");
  assert.equal(decision.matchedRules[0]?.category, "denyPaths");
});

test("inside-project reads and writes are allowed by default when no deny or protection matches", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "guardme-eval-inside-"));
  await writeFile(join(cwd, "README.md"), "readme", "utf8");

  const policy = policyFrom(createEmptyPolicyConfig());
  const readDecision = evaluatePolicyRequest({ policy, request: await pathRequest(cwd, "read", "README.md") });
  const writeDecision = evaluatePolicyRequest({ policy, request: await pathRequest(cwd, "write", "src/new.ts") });

  assert.equal(readDecision.outcome, "allow");
  assert.equal(writeDecision.outcome, "allow");
  assert.equal(readDecision.matchedRules[0]?.category, "defaultProjectPolicy");
});

test("outside-project reads require explicit allowPaths or readOnlyPaths", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-eval-outside-read-"));
  const cwd = join(root, "project");
  const outside = join(root, "outside.txt");
  await mkdir(cwd, { recursive: true });
  await writeFile(outside, "outside", "utf8");

  const noAllow = evaluatePolicyRequest({ policy: policyFrom(createEmptyPolicyConfig()), request: await pathRequest(cwd, "read", outside) });
  const allowPolicy = policyFrom({ ...createEmptyPolicyConfig(), readOnlyPaths: [{ pattern: outside, actions: ["read", "list"] }] });
  const allowed = evaluatePolicyRequest({ policy: allowPolicy, request: await pathRequest(cwd, "read", outside) });

  assert.equal(noAllow.outcome, "deny");
  assert.equal(allowed.outcome, "allow");
  assert.equal(allowed.matchedRules[0]?.category, "readOnlyPaths");
});

test("built-in defaults allow the OS temp directory, keep protections inside it, and still deny other outside paths", async () => {
  const cwd = join(outsideRoot("guardme-eval-temp-boundary-"), "project");
  const scratch = await mkdtemp(join(tmpdir(), "guardme-eval-scratch-"));
  await mkdir(cwd, { recursive: true });
  await writeFile(join(cwd, "old.txt"), "old", "utf8");
  await writeFile(join(scratch, "log.txt"), "log", "utf8");
  const policy = mergePolicyConfigs([sourcePolicyConfig("builtin", createBuiltInDefaultPolicy())]).config;
  const decide = (command) => {
    const { request, classified } = shellRequest(cwd, command);
    return evaluatePolicyRequest({ policy, request, commandClassification: classified });
  };

  for (const command of [
    `echo hi > ${scratch}/probe.log`, `cat ${scratch}/log.txt`, `ls ${scratch}`, `rm ${scratch}/log.txt`, `rm -rf ${scratch}`,
    `mv old.txt ${scratch}/old.txt`, `cp old.txt ${scratch}/`, `mkdir -p ${scratch}/dir`, `tar -czf ${scratch}/a.tgz old.txt`,
    "echo hi > /tmp/guardme-probe.log", "rm /tmp/guardme-probe.log", "mktemp -d",
  ]) {
    assert.equal(decide(command).outcome, "allow", command);
  }
  for (const command of [`cat ${scratch}/.env`, `rm ${scratch}/.env`, `cat ${scratch}/secrets.yaml`]) {
    assert.equal(decide(command).outcome, "deny", command);
  }
  const outsideRead = evaluatePolicyRequest({ policy, request: await pathRequest(cwd, "read", "/etc/hosts") });
  const outsideWrite = evaluatePolicyRequest({ policy, request: await pathRequest(cwd, "write", "/etc/guardme-probe") });
  assert.equal(outsideRead.outcome, "deny");
  assert.match(outsideRead.reason, /Outside-project read requires/);
  assert.equal(outsideWrite.outcome, "deny");
  assert.match(outsideWrite.reason, /Outside-project write requires/);
  assert.equal(decide("mv old.txt /etc/old.txt").outcome, "deny");
});

test("all built-in temp roots allow ordinary paths without widening credentials or neighboring directories", async () => {
  const cwd = outsideRoot("guardme-eval-temp-patterns-");
  const policy = mergePolicyConfigs([sourcePolicyConfig("builtin", createBuiltInDefaultPolicy())]).config;
  const roots = ["/tmp", "/private/tmp", "/var/tmp", "/private/var/tmp", "/var/folders/ab/example/T", "/private/var/folders/ab/example/T"];

  for (const root of roots) {
    for (const action of ["read", "list", "write", "edit", "delete", "move", "rename"]) {
      for (const target of [root, `${root}/guardme-scratch/nested/probe.log`]) {
        const allowed = evaluatePolicyRequest({ policy, request: await pathRequest(cwd, action, target) });
        assert.equal(allowed.outcome, "allow", `${action}: ${target}`);
      }
      for (const target of [`${root}/.env`, `${root}/guardme-scratch/credentials.json`, `${root}-neighbor/probe.log`]) {
        const denied = evaluatePolicyRequest({ policy, request: await pathRequest(cwd, action, target) });
        assert.equal(denied.outcome, "deny", `${action}: ${target}`);
      }
    }
  }
  for (const target of ["/var/folders/ab/example/C/probe.log", "/var/folders/ab/T/probe.log", "/var/folders/ab/example/extra/T/probe.log"]) {
    const denied = evaluatePolicyRequest({ policy, request: await pathRequest(cwd, "read", target) });
    assert.equal(denied.outcome, "deny", target);
  }
});

test("built-in defaults allow reading Pi skill files and local Pi docs outside the project", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-eval-skill-read-"));
  const cwd = join(root, "project");
  const pluralSkillsRoot = join(root, "other-project", ".pi", "skills");
  const pluralSkillDir = join(pluralSkillsRoot, "example-skill");
  const singularSkillDir = join(root, "legacy-project", ".pi", "skill", "example-skill");
  const pluralSkillPath = join(pluralSkillDir, "SKILL.md");
  const singularSkillPath = join(singularSkillDir, "SKILL.md");
  const piDocsRoot = "/opt/homebrew/lib/node_modules/@earendil-works/pi-coding-agent/docs";
  const piDocsPath = "/opt/homebrew/lib/node_modules/@earendil-works/pi-coding-agent/README.md";
  await mkdir(cwd, { recursive: true });
  await mkdir(pluralSkillDir, { recursive: true });
  await mkdir(singularSkillDir, { recursive: true });
  await writeFile(pluralSkillPath, "# Example skill\n", "utf8");
  await writeFile(singularSkillPath, "# Example skill\n", "utf8");
  const policy = mergePolicyConfigs([sourcePolicyConfig("builtin", createBuiltInDefaultPolicy())]).config;

  const pluralReadDecision = evaluatePolicyRequest({ policy, request: await pathRequest(cwd, "read", pluralSkillPath) });
  const singularReadDecision = evaluatePolicyRequest({ policy, request: await pathRequest(cwd, "read", singularSkillPath) });
  const skillListDecision = evaluatePolicyRequest({ policy, request: await pathRequest(cwd, "list", pluralSkillsRoot) });
  const piDocsReadDecision = evaluatePolicyRequest({ policy, request: await pathRequest(cwd, "read", piDocsPath) });
  const piDocsListDecision = evaluatePolicyRequest({ policy, request: await pathRequest(cwd, "list", piDocsRoot) });

  assert.equal(pluralReadDecision.outcome, "allow");
  assert.equal(pluralReadDecision.matchedRules[0]?.category, "allowPaths");
  assert.equal(singularReadDecision.outcome, "allow");
  assert.equal(skillListDecision.outcome, "allow");
  assert.equal(piDocsReadDecision.outcome, "allow");
  assert.equal(piDocsReadDecision.matchedRules[0]?.category, "allowPaths");
  assert.equal(piDocsListDecision.outcome, "allow");
});

test("@earendil-works defaults allow all scoped packages across installations without granting unrelated access", async () => {
  const root = outsideRoot("guardme-eval-pi-docs-");
  const cwd = join(root, "project");
  await mkdir(cwd, { recursive: true });
  const defaults = createBuiltInDefaultPolicy();
  const policy = policyFrom(defaults);

  for (const installation of ["sibling/node_modules", ".pi/agent/npm/node_modules", "usr/local/lib/node_modules"]) {
    const packageRoot = join(root, installation, "@earendil-works/pi-coding-agent");
    for (const relativePath of ["README.md", "docs/extensions.md", "examples/extensions/example.ts", "dist/index.js", "../pi-ai/README.md", "../pi-tui/src/index.ts"]) {
      const target = join(packageRoot, relativePath);
      await mkdir(join(target, ".."), { recursive: true });
      await writeFile(target, "example", "utf8");
      const read = evaluatePolicyRequest({ policy, request: await pathRequest(cwd, "read", target) });
      assert.equal(read.outcome, "allow", target);
      for (const action of ["write", "edit", "delete", "move", "rename"]) {
        const mutation = evaluatePolicyRequest({ policy, request: await pathRequest(cwd, action, target) });
        assert.equal(mutation.outcome, "deny", `${action}: ${target}`);
      }
    }
    for (const directory of ["docs", "examples", "..", "../pi-ai", "../pi-tui/src"]) {
      const listed = evaluatePolicyRequest({ policy, request: await pathRequest(cwd, "list", join(packageRoot, directory)) });
      assert.equal(listed.outcome, "allow");
    }
    for (const relativePath of ["../../other-package/README.md", "../../@earendil-works-other/package/README.md", "docs/.env", "examples/credentials.json"]) {
      const denied = evaluatePolicyRequest({ policy, request: await pathRequest(cwd, "read", join(packageRoot, relativePath)) });
      assert.equal(denied.outcome, "deny", relativePath);
    }
    const target = join(packageRoot, "README.md");
    const deniedPolicy = policyFrom({ ...defaults, denyPaths: [...defaults.denyPaths, { pattern: target }] });
    assert.equal(evaluatePolicyRequest({ policy: deniedPolicy, request: await pathRequest(cwd, "read", target) }).outcome, "deny");
  }
});

test("outside-project mutations require explicit allow and no protection", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-eval-outside-write-"));
  const cwd = join(root, "project");
  const outside = join(root, "outside.txt");
  await mkdir(cwd, { recursive: true });
  await writeFile(outside, "outside", "utf8");

  const noAllow = evaluatePolicyRequest({ policy: policyFrom(createEmptyPolicyConfig()), request: await pathRequest(cwd, "write", outside) });
  const allowPolicy = policyFrom({ ...createEmptyPolicyConfig(), allowPaths: [{ pattern: outside, actions: ["write"] }] });
  const allowed = evaluatePolicyRequest({ policy: allowPolicy, request: await pathRequest(cwd, "write", outside) });
  const protectedPolicy = policyFrom({
    ...createEmptyPolicyConfig(),
    allowPaths: [{ pattern: outside, actions: ["write"] }],
    zeroAccessPaths: [{ pattern: outside }],
  });
  const protectedDecision = evaluatePolicyRequest({ policy: protectedPolicy, request: await pathRequest(cwd, "write", outside) });

  assert.equal(noAllow.outcome, "deny");
  assert.equal(allowed.outcome, "allow");
  assert.equal(protectedDecision.outcome, "deny");
  assert.equal(protectedDecision.hard, true);
});

test("inside-project delete defaults coach first and ask on repeated fingerprints", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "guardme-eval-delete-repeat-"));
  await writeFile(join(cwd, "old.txt"), "old", "utf8");
  const policy = policyFrom(createEmptyPolicyConfig());
  const { request, classified } = shellRequest(cwd, "rm old.txt");
  const first = evaluatePolicyRequest({ policy, request, commandClassification: classified });
  const fingerprint = createPolicyFingerprint(request);
  const repeated = evaluatePolicyRequest({
    policy,
    request,
    commandClassification: classified,
    warnedFingerprints: new Set([fingerprint]),
  });

  assert.equal(first.outcome, "coach");
  assert.equal(repeated.outcome, "needs-user-decision");
});

test("explicit command allows can approve dangerous commands after hard protections", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "guardme-eval-dangerous-allow-"));
  const policy = policyFrom({
    ...createEmptyPolicyConfig(),
    allowCommands: [{ pattern: "rm -rf build", reason: "approved cleanup" }],
    dangerousCommands: [{ pattern: "rm -rf *" }],
  });
  const { request, classified } = shellRequest(cwd, "rm -rf build");

  const decision = evaluatePolicyRequest({ policy, request, commandClassification: classified });

  assert.equal(decision.outcome, "allow");
  assert.equal(decision.matchedRules[0]?.category, "allowCommands");
});

test("wildcard command allows approve safe individual segments after path checks", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "guardme-eval-segment-allow-"));
  const policy = policyFrom({
    ...createEmptyPolicyConfig(),
    allowCommands: [
      { pattern: "pwd *", reason: "allow pwd" },
      { pattern: "ls *", reason: "allow ls" },
      { pattern: "cat *", reason: "allow cat" },
      { pattern: "find *", reason: "allow find" },
    ],
    dangerousCommands: [{ pattern: "rm -rf *", reason: "dangerous cleanup" }],
  });

  const ls = shellRequest(cwd, "ls -la");
  const pwd = shellRequest(cwd, "pwd");
  const pwdFlag = shellRequest(cwd, "pwd -L");
  const compound = shellRequest(cwd, "pwd && ls -lh");
  const safeRead = shellRequest(cwd, "cat README.md");
  const safeFind = shellRequest(cwd, "find . -name '*.ts'");

  for (const { request, classified } of [ls, pwd, pwdFlag, compound, safeRead, safeFind]) {
    const decision = evaluatePolicyRequest({ policy, request, commandClassification: classified });
    assert.equal(decision.outcome, "allow", request.command);
  }
});

test("find -L requires an exact reviewed allow because symlinks can escape the search root", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "guardme-eval-find-symlink-"));
  const command = "find -L node_modules/pkg -maxdepth 2 -type f";
  const broadPolicy = policyFrom({ ...createEmptyPolicyConfig(), allowCommands: [{ pattern: "find *" }] });
  const exactPolicy = policyFrom({ ...createEmptyPolicyConfig(), allowCommands: [{ pattern: command }] });
  const { request, classified } = shellRequest(cwd, command);

  const broadDecision = evaluatePolicyRequest({ policy: broadPolicy, request, commandClassification: classified });
  const exactDecision = evaluatePolicyRequest({ policy: exactPolicy, request, commandClassification: classified });

  assert.equal(broadDecision.outcome, "coach");
  assert.match(broadDecision.reason, /symbolic links|symlink/i);
  assert.doesNotMatch(broadDecision.reason, /\.env/);
  assert.equal(exactDecision.outcome, "allow");
});

test("allowed command families can discard output through /dev/null", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "guardme-eval-null-redirection-"));
  const policy = mergePolicyConfigs([sourcePolicyConfig("builtin", createBuiltInDefaultPolicy())]).config;
  const commands = [
    "find specs -maxdepth 1 -type f -name 'spec-review-pi-extension-tasks*.md' -print 2>/dev/null",
    "find .github -maxdepth 3 -type f -print 2>/dev/null",
    "wc -l 2>/dev/null",
  ];

  for (const command of commands) {
    const { request, classified } = shellRequest(cwd, command);
    const decision = evaluatePolicyRequest({ policy, request, commandClassification: classified });

    assert.equal(decision.outcome, "allow", command);
  }
});

test("compound command allowlists block the first missing or dangerous segment", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "guardme-eval-segment-missing-"));
  const policy = policyFrom({
    ...createEmptyPolicyConfig(),
    allowCommands: [
      { pattern: "pwd *", reason: "allow pwd" },
      { pattern: "ls *", reason: "allow ls" },
    ],
    dangerousCommands: [{ pattern: "rm -rf *", reason: "dangerous cleanup" }],
  });

  const missing = shellRequest(cwd, "pwd && unknown-tool");
  const missingDecision = evaluatePolicyRequest({ policy, request: missing.request, commandClassification: missing.classified });
  assert.equal(missingDecision.outcome, "coach");
  assert.equal(missingDecision.reasonCode, "policy-missing-command");
  assert.match(missingDecision.reason, /unknown-tool/);

  const dangerous = shellRequest(cwd, "pwd && ls -lh && rm -rf build");
  const dangerousDecision = evaluatePolicyRequest({ policy, request: dangerous.request, commandClassification: dangerous.classified });
  assert.equal(dangerousDecision.outcome, "coach");
  assert.equal(dangerousDecision.reasonCode, "dangerous-command");
  assert.match(dangerousDecision.reason, /rm -rf build/);
});

test("wildcard command allows do not bypass protected paths or dangerous command forms", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "guardme-eval-segment-protect-"));
  const policy = policyFrom({
    ...createEmptyPolicyConfig(),
    allowCommands: [
      { pattern: "cat *", reason: "allow cat" },
      { pattern: "find *", reason: "allow find" },
      { pattern: "echo *", reason: "allow echo" },
    ],
    dangerousCommands: [{ pattern: "rm -rf *", reason: "dangerous cleanup" }],
  });

  const envRead = shellRequest(cwd, "cat .env");
  const passwdRead = shellRequest(cwd, "cat /etc/passwd");
  const findDelete = shellRequest(cwd, "find . -delete");
  const redirectedFindDelete = shellRequest(cwd, "find . -delete 2>/dev/null");
  const cloud = shellRequest(cwd, "aws sts get-caller-identity");
  const substitution = shellRequest(cwd, "echo $(rm -rf build)");

  const envDecision = evaluatePolicyRequest({ policy, request: envRead.request, commandClassification: envRead.classified });
  const passwdDecision = evaluatePolicyRequest({ policy, request: passwdRead.request, commandClassification: passwdRead.classified });
  const findDecision = evaluatePolicyRequest({ policy, request: findDelete.request, commandClassification: findDelete.classified });
  const redirectedFindDecision = evaluatePolicyRequest({
    policy,
    request: redirectedFindDelete.request,
    commandClassification: redirectedFindDelete.classified,
  });
  const cloudDecision = evaluatePolicyRequest({ policy, request: cloud.request, commandClassification: cloud.classified });
  const substitutionDecision = evaluatePolicyRequest({ policy, request: substitution.request, commandClassification: substitution.classified });

  assert.equal(envDecision.outcome, "deny");
  assert.equal(envDecision.hard, true);
  assert.equal(passwdDecision.outcome, "deny");
  assert.match(passwdDecision.reason, /Outside-project read requires/);
  assert.equal(findDecision.outcome, "coach");
  assert.match(findDecision.reason, /find -delete|exact allowCommands/);
  assert.equal(redirectedFindDecision.outcome, "coach");
  assert.match(redirectedFindDecision.reason, /find -delete|exact allowCommands/);
  assert.equal(cloudDecision.outcome, "deny");
  assert.equal(cloudDecision.hard, true);
  assert.equal(substitutionDecision.outcome, "coach");
  assert.match(substitutionDecision.reason, /rm -rf build/);
});

test("missing command fingerprints are based on the failed segment", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "guardme-eval-segment-fingerprint-"));
  const policy = policyFrom({ ...createEmptyPolicyConfig(), allowCommands: [{ pattern: "pwd *" }, { pattern: "ls *" }] });
  const first = shellRequest(cwd, "pwd && unknown-tool");
  const firstDecision = evaluatePolicyRequest({ policy, request: first.request, commandClassification: first.classified });
  assert.equal(firstDecision.outcome, "coach");

  const second = shellRequest(cwd, "ls && unknown-tool");
  const repeated = evaluatePolicyRequest({
    policy,
    request: second.request,
    commandClassification: second.classified,
    warnedFingerprints: new Set([firstDecision.fingerprint]),
  });

  assert.equal(repeated.outcome, "needs-user-decision");
  assert.equal(repeated.fingerprint, firstDecision.fingerprint);
});

test("command allows do not approve outside-project shell path access", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "guardme-eval-command-allow-outside-"));
  const policy = policyFrom({
    ...createEmptyPolicyConfig(),
    allowCommands: [{ pattern: "rm -rf build && cat /etc/passwd", reason: "too broad" }],
    dangerousCommands: [{ pattern: "rm -rf *" }],
  });
  const { request, classified } = shellRequest(cwd, "rm -rf build && cat /etc/passwd");

  const decision = evaluatePolicyRequest({ policy, request, commandClassification: classified });

  assert.equal(decision.outcome, "deny");
  assert.match(decision.reason, /Outside-project .* requires/);
});

test("wildcard command allows still guard compound command segments", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "guardme-eval-compound-allow-"));
  const policy = mergePolicyConfigs([sourcePolicyConfig("builtin", createBuiltInDefaultPolicy())]).config;
  const dangerous = shellRequest(cwd, "npm test && find build -delete");
  const outsideRead = shellRequest(cwd, "npm test && cat /etc/passwd");
  const dangerousWithOutsideRead = shellRequest(cwd, "find build -delete && cat /etc/passwd");
  const genericCompound = shellRequest(cwd, "npm test && echo ok");

  const dangerousDecision = evaluatePolicyRequest({
    policy,
    request: dangerous.request,
    commandClassification: dangerous.classified,
  });
  const outsideReadDecision = evaluatePolicyRequest({
    policy,
    request: outsideRead.request,
    commandClassification: outsideRead.classified,
  });
  const dangerousWithOutsideReadDecision = evaluatePolicyRequest({
    policy,
    request: dangerousWithOutsideRead.request,
    commandClassification: dangerousWithOutsideRead.classified,
  });
  const genericCompoundDecision = evaluatePolicyRequest({
    policy,
    request: genericCompound.request,
    commandClassification: genericCompound.classified,
  });

  assert.equal(dangerousDecision.outcome, "coach");
  assert.equal(dangerousDecision.matchedRules[0]?.category, "dangerousCommands");
  assert.equal(outsideReadDecision.outcome, "deny");
  assert.match(outsideReadDecision.reason, /Outside-project read requires/);
  assert.equal(dangerousWithOutsideReadDecision.outcome, "deny");
  assert.match(dangerousWithOutsideReadDecision.reason, /Outside-project .* requires/);
  assert.equal(genericCompoundDecision.outcome, "allow");
  assert.deepEqual(genericCompoundDecision.matchedRules.map((rule) => rule.pattern), ["npm *", "echo *"]);
});

test("deny command rules match later shell command segments and wrappers", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "guardme-eval-compound-deny-"));
  const policy = mergePolicyConfigs([sourcePolicyConfig("builtin", createBuiltInDefaultPolicy())]).config;
  const commands = [
    shellRequest(cwd, "npm test && sudo ls"),
    shellRequest(cwd, "sudo /bin/ls"),
    shellRequest(cwd, "/usr/bin/sudo ls"),
    shellRequest(cwd, "/usr/bin/sudoedit /etc/hosts"),
    shellRequest(cwd, "env -- /usr/bin/sudo ls"),
    shellRequest(cwd, "command /usr/bin/sudo ls"),
    shellRequest(cwd, "xargs sudo ls"),
    shellRequest(cwd, "env -- sudo ls"),
    shellRequest(cwd, "command sudo ls"),
  ];

  for (const { request, classified } of commands) {
    const decision = evaluatePolicyRequest({ policy, request, commandClassification: classified });

    assert.equal(decision.outcome, "deny", request.command);
    assert.equal(decision.matchedRules[0]?.category, "denyCommands", request.command);
    assert.match(decision.reason, /Privilege escalation/, request.command);
  }

  const worldWritable = shellRequest(cwd, "chmod 777 /tmp/file");
  const worldWritableDecision = evaluatePolicyRequest({
    policy,
    request: worldWritable.request,
    commandClassification: worldWritable.classified,
  });
  assert.equal(worldWritableDecision.outcome, "deny");
  assert.equal(worldWritableDecision.matchedRules[0]?.category, "denyCommands");
  assert.match(worldWritableDecision.reason, /World-writable/);

  const harmlessText = shellRequest(cwd, "echo sudo ls");
  const harmlessDecision = evaluatePolicyRequest({
    policy,
    request: harmlessText.request,
    commandClassification: harmlessText.classified,
  });
  assert.equal(harmlessDecision.outcome, "allow");
  assert.equal(harmlessDecision.matchedRules[0]?.category, "allowCommands");
  assert.equal(harmlessDecision.matchedRules[0]?.pattern, "echo *");
});

test("generic shell commands default-deny as policy-missing and prompt on repeat", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "guardme-eval-policy-missing-"));
  const policy = mergePolicyConfigs([sourcePolicyConfig("builtin", createBuiltInDefaultPolicy())]).config;
  const { request, classified } = shellRequest(cwd, "brave https://example.com");

  const first = evaluatePolicyRequest({ policy, request, commandClassification: classified });
  const repeated = evaluatePolicyRequest({
    policy,
    request,
    commandClassification: classified,
    warnedFingerprints: new Set([createPolicyFingerprint(request)]),
  });

  assert.equal(first.outcome, "coach");
  assert.equal(first.risk, "medium");
  assert.equal(first.reasonCode, "policy-missing-command");
  assert.match(first.reason, /blocks unclassified shell command segments by default/);
  assert.equal(repeated.outcome, "needs-user-decision");
  assert.equal(repeated.reasonCode, "policy-missing-command");
});

test("script-content command requests require exact command allows", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "guardme-eval-script-content-exact-"));
  const policy = policyFrom({ ...createEmptyPolicyConfig(), allowCommands: [{ pattern: "*", reason: "too broad" }] });
  const { request, classified } = shellRequest(cwd, "echo ok");

  const decision = evaluatePolicyRequest({
    policy,
    request: { ...request, requiresExactCommandAllow: true, reasonCode: "script-content-denied" },
    commandClassification: classified,
  });

  assert.equal(decision.outcome, "coach");
  assert.equal(decision.reasonCode, "script-content-denied");
});

test("dangerous command evaluation returns coach first and user decision after warning state", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "guardme-eval-dangerous-"));
  const policy = policyFrom({ ...createEmptyPolicyConfig(), dangerousCommands: [{ pattern: "rm -rf *" }] });
  const { request, classified } = shellRequest(cwd, "rm -rf build");
  const first = evaluatePolicyRequest({ policy, request, commandClassification: classified });
  const fingerprint = createPolicyFingerprint(request);
  const repeated = evaluatePolicyRequest({
    policy,
    request,
    commandClassification: classified,
    warnedFingerprints: new Set([fingerprint]),
  });

  assert.equal(first.outcome, "coach");
  assert.equal(first.block, true);
  assert.equal(repeated.outcome, "needs-user-decision");
  assert.equal(repeated.prompt, true);
});

test("exact whole-command allows do not cover background or |& compounds", () => {
  const cwd = process.cwd();
  const policy = policyFrom({ ...createEmptyPolicyConfig(), allowCommands: [{ pattern: "git status" }] });

  const single = shellRequest(cwd, "command git status");
  const singleDecision = evaluatePolicyRequest({ policy, request: single.request, commandClassification: single.classified });
  assert.equal(singleDecision.outcome, "allow");

  for (const command of ["command git status & rm -rf build", "command git status |& sh"]) {
    const compound = shellRequest(cwd, command);
    const decision = evaluatePolicyRequest({ policy, request: compound.request, commandClassification: compound.classified });
    assert.notEqual(decision.outcome, "allow", command);
  }
});

test("path allow rules do not match traversal or symlink escapes", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-eval-allow-escape-"));
  const cwd = join(root, "project");
  await mkdir(join(cwd, "docs"), { recursive: true });
  await writeFile(join(root, "secret.txt"), "outside", "utf8");
  await symlink(root, join(cwd, "docs", "link"));
  const policy = policyFrom({ ...createEmptyPolicyConfig(), allowPaths: [{ pattern: "docs/**", actions: ["read"] }] });

  const traversal = evaluatePolicyRequest({ policy, request: await pathRequest(cwd, "read", "docs/../../secret.txt") });
  assert.equal(traversal.outcome, "deny");

  const symlinked = evaluatePolicyRequest({ policy, request: await pathRequest(cwd, "read", "docs/link/secret.txt") });
  assert.equal(symlinked.outcome, "deny");

  const legit = evaluatePolicyRequest({ policy, request: await pathRequest(cwd, "read", "docs/readme.md") });
  assert.equal(legit.outcome, "allow");
});

test("shell-expanded variable paths are not treated as inside-project", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "guardme-eval-shellvar-"));

  const shellNormalized = await normalizePolicyPath("$HOME/.bash_history", { cwd, shellExpansion: true });
  assert.equal(shellNormalized.isInsideProject, false);

  const tildeUser = await normalizePolicyPath("~root/.bash_history", { cwd, shellExpansion: true });
  assert.equal(tildeUser.isInsideProject, false);

  const literal = await normalizePolicyPath("$HOME/.bash_history", { cwd });
  assert.equal(literal.isInsideProject, true);

  const policy = policyFrom(createEmptyPolicyConfig());
  const request = {
    toolName: "bash",
    action: "read",
    cwd,
    command: "cat $HOME/.bash_history",
    targets: [pathTargetFromNormalizedPath(shellNormalized)],
  };
  const decision = evaluatePolicyRequest({ policy, request });
  assert.equal(decision.outcome, "deny");
});

test("built-in defaults block direct writes into .git", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "guardme-eval-git-write-"));
  await mkdir(join(cwd, ".git"), { recursive: true });
  await writeFile(join(cwd, ".git", "config"), "[core]\n", "utf8");
  const policy = mergePolicyConfigs([sourcePolicyConfig("builtin", createBuiltInDefaultPolicy())]).config;

  const writeDecision = evaluatePolicyRequest({ policy, request: await pathRequest(cwd, "write", ".git/config") });
  assert.equal(writeDecision.outcome, "deny");
  assert.equal(writeDecision.hard, true);

  const readDecision = evaluatePolicyRequest({ policy, request: await pathRequest(cwd, "read", ".git/config") });
  assert.equal(readDecision.outcome, "allow");

  const { request, classified } = shellRequest(cwd, "echo x >> .git/config");
  const shellDecision = evaluatePolicyRequest({ policy, request, commandClassification: classified });
  assert.equal(shellDecision.outcome, "deny");
});

test("project-scoped rm and rmdir are allowed by the default policy, everything else still asks or denies", async () => {
  const cwd = join(outsideRoot("guardme-eval-project-delete-"), "project");
  await mkdir(cwd, { recursive: true });
  await mkdir(join(cwd, "build"), { recursive: true });
  await mkdir(join(cwd, "infra"), { recursive: true });
  await writeFile(join(cwd, "old.txt"), "old", "utf8");
  await writeFile(join(cwd, "infra", "main.tf"), "", "utf8");
  await writeFile(join(cwd, ".env"), "TOKEN=x", "utf8");
  const policy = mergePolicyConfigs([sourcePolicyConfig("builtin", createBuiltInDefaultPolicy())]).config;
  const decide = (command) => {
    const { request, classified } = shellRequest(cwd, command);
    return evaluatePolicyRequest({ policy, request, commandClassification: classified });
  };

  for (const command of ["rm old.txt", "rm -rf build", "rm -r -f build old.txt", "rmdir build", "rm infra/main.tf && rmdir infra", "/bin/rm old.txt", "mv old.txt new.txt", "mv -f old.txt build/", "rm -rf /tmp/x"]) {
    assert.equal(decide(command).outcome, "allow", command);
  }
  for (const command of ["rm -rf .", "rm -rf ./", "rm -rf *", "rm -rf build/*", "rm -rf /etc/x", "rm $F", "rm -rf ~/.aws", "find build -delete", "mv old.txt /etc/old.txt", "mv build/* old.txt"]) {
    assert.notEqual(decide(command).outcome, "allow", command);
  }
  assert.equal(decide("rm .env").outcome, "deny");
  assert.equal(decide("rm -rf .git").outcome, "deny");
});

test("nohup is a prefix wrapper: the wrapped command decides the outcome", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "guardme-eval-nohup-"));
  await mkdir(join(cwd, "site"), { recursive: true });
  const policy = mergePolicyConfigs([sourcePolicyConfig("builtin", createBuiltInDefaultPolicy())]).config;
  const decide = (command) => {
    const { request, classified } = shellRequest(cwd, command);
    return evaluatePolicyRequest({ policy, request, commandClassification: classified });
  };

  assert.equal(decide("nohup python3 -m http.server 0 --bind 127.0.0.1 --directory site >/dev/null 2>&1 &").outcome, "allow");
  assert.equal(decide("nohup aws s3 ls").outcome, "deny");
  assert.notEqual(decide("nohup unknown-tool --flag").outcome, "allow");
});

test("shell control-word headers and builtins do not block compound commands, hijack exports and outside cd still do", async () => {
  const cwd = join(outsideRoot("guardme-eval-shell-syntax-"), "project");
  await mkdir(join(cwd, "site"), { recursive: true });
  await writeFile(join(cwd, "old.txt"), "old", "utf8");
  const policy = mergePolicyConfigs([sourcePolicyConfig("builtin", createBuiltInDefaultPolicy())]).config;
  const decide = (command) => {
    const { request, classified } = shellRequest(cwd, command);
    return evaluatePolicyRequest({ policy, request, commandClassification: classified });
  };

  for (const command of [
    "if [ -f old.txt ]; then echo y; fi", "ls -la; if [ -f docs/testing.md ]; then printf 'x\\n'; fi", "for f in a b; do echo $f; done",
    "while read -r l; do echo $l; done < old.txt", "until false; do echo; done", "case x in a) echo;; esac",
    "cd site && ls", "export X=1; echo $X", "unset X", "exec node x.js", "wait", "wait 123", "exit 0", "false || true", ":", "type node", "jobs", "disown",
  ]) {
    assert.equal(decide(command).outcome, "allow", command);
  }
  for (const command of ["cd /etc && ls", "cd ../.. && ls", "export PATH=/evil:$PATH", 'export "PATH=/evil"', "export LD_PRELOAD=/evil.so", "exec aws s3 ls", "for f in $(aws s3 ls); do echo; done"]) {
    assert.equal(decide(command).outcome, "deny", command);
  }
});

test("npx-launched tools and common toolchains are allowed by default", async () => {
  const cwd = join(outsideRoot("guardme-eval-toolchains-"), "project");
  await mkdir(join(cwd, "bin"), { recursive: true });
  await writeFile(join(cwd, "old.txt"), "old", "utf8");
  await writeFile(join(cwd, "bin", "deploy"), "#!/bin/sh\necho hi\n", "utf8");
  const policy = mergePolicyConfigs([sourcePolicyConfig("builtin", createBuiltInDefaultPolicy())]).config;
  const decide = (command) => {
    const { request, classified } = shellRequest(cwd, command);
    return evaluatePolicyRequest({ policy, request, commandClassification: classified });
  };

  for (const command of [
    "npx serve site -l 5000", "npx vite", "npx playwright test", "vite build", "shellcheck bin/deploy", "bash -n bin/deploy", "shfmt -d bin/deploy",
    "sha256sum old.txt", "md5 old.txt", "base64 old.txt", "java -version", "./gradlew test", "mvn -q test", "dotnet test", "composer install", "bundle exec rake",
    "sqlite3 db.sqlite .tables", "pkill -f http.server", "wget -q http://127.0.0.1:1/", "netstat -an", "ln -s old.txt link.txt", "column -t old.txt", "seq 3",
    "terraform validate", "helm lint chart", "kubectl get pods", "hadolint Dockerfile", "actionlint",
  ]) {
    assert.equal(decide(command).outcome, "allow", command);
  }
  for (const command of ["npx frobnicate", "ssh host ls", "kubectl apply -f x.yaml", "terraform apply", "helm install x ./chart"]) {
    assert.notEqual(decide(command).outcome, "allow", command);
  }
});

test("shell function definitions and trap bodies are classified by what they run", async () => {
  const cwd = join(outsideRoot("guardme-eval-functions-"), "project");
  await mkdir(join(cwd, "infra"), { recursive: true });
  const policy = mergePolicyConfigs([sourcePolicyConfig("builtin", createBuiltInDefaultPolicy())]).config;
  const decide = (command) => {
    const { request, classified } = shellRequest(cwd, command);
    return evaluatePolicyRequest({ policy, request, commandClassification: classified });
  };

  for (const command of [
    "cleanup() { rm -rf -- infra; }; trap cleanup EXIT; terraform -chdir=infra fmt",
    "cleanup() {\n  rm -rf -- infra\n}\ntrap cleanup EXIT",
    "function cleanup { rm -rf infra; }",
    'trap "kill 0" EXIT',
    "trap - EXIT",
    "trap 'echo done' INT TERM",
  ]) {
    assert.equal(decide(command).outcome, "allow", command);
  }
  for (const command of ["f() { aws s3 ls; }", "trap 'aws s3 ls' EXIT", "function f { sudo ls; }"]) {
    assert.equal(decide(command).outcome, "deny", command);
  }
  assert.notEqual(decide("trap frobnicate EXIT").outcome, "allow");
  assert.notEqual(decide("trap 'frobnicate --now' EXIT").outcome, "allow");
});
