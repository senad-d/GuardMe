import assert from "node:assert/strict";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { mergePolicyConfigs, sourcePolicyConfig } from "../src/config/merge-policy.ts";
import { createBuiltInDefaultPolicy, createEmptyPolicyConfig } from "../src/config/schema.ts";
import { classifyShellCommand } from "../src/policy/commands.ts";
import { commandGlobToRegExp, createPolicyFingerprint, evaluatePolicyRequest } from "../src/policy/evaluate.ts";
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

test("built-in defaults allow reading Pi skill files and local Pi docs outside the project", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-eval-skill-read-"));
  const cwd = join(root, "project");
  const pluralSkillsRoot = join(root, "other-project", ".pi", "skills");
  const pluralSkillDir = join(pluralSkillsRoot, "example-skill");
  const singularSkillDir = join(root, "legacy-project", ".pi", "skill", "example-skill");
  const pluralSkillPath = join(pluralSkillDir, "SKILL.md");
  const singularSkillPath = join(singularSkillDir, "SKILL.md");
  const piDocsRoot = "/opt/homebrew/lib/node_modules/@earendil-works";
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
  const cloud = shellRequest(cwd, "aws sts get-caller-identity");
  const substitution = shellRequest(cwd, "echo $(rm -rf build)");

  const envDecision = evaluatePolicyRequest({ policy, request: envRead.request, commandClassification: envRead.classified });
  const passwdDecision = evaluatePolicyRequest({ policy, request: passwdRead.request, commandClassification: passwdRead.classified });
  const findDecision = evaluatePolicyRequest({ policy, request: findDelete.request, commandClassification: findDelete.classified });
  const cloudDecision = evaluatePolicyRequest({ policy, request: cloud.request, commandClassification: cloud.classified });
  const substitutionDecision = evaluatePolicyRequest({ policy, request: substitution.request, commandClassification: substitution.classified });

  assert.equal(envDecision.outcome, "deny");
  assert.equal(envDecision.hard, true);
  assert.equal(passwdDecision.outcome, "deny");
  assert.match(passwdDecision.reason, /Outside-project read requires/);
  assert.equal(findDecision.outcome, "coach");
  assert.match(findDecision.reason, /find -delete|exact allowCommands/);
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

test("wildcard command allows do not bypass guarded compound command segments", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "guardme-eval-compound-allow-"));
  const policy = mergePolicyConfigs([sourcePolicyConfig("builtin", createBuiltInDefaultPolicy())]).config;
  const dangerous = shellRequest(cwd, "npm test && rm -rf build");
  const outsideRead = shellRequest(cwd, "npm test && cat /etc/passwd");
  const dangerousWithOutsideRead = shellRequest(cwd, "rm -rf build && cat /etc/passwd");
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
  assert.equal(genericCompoundDecision.outcome, "coach");
  assert.equal(genericCompoundDecision.reasonCode, "policy-missing-command");
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
  assert.equal(harmlessDecision.outcome, "coach");
  assert.equal(harmlessDecision.reasonCode, "policy-missing-command");
  assert.match(harmlessDecision.reason, /No allowCommands rule/);
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
