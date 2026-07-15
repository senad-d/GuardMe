import assert from "node:assert/strict";
import { access, mkdir, mkdtemp, readFile, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { EXTENSION_STATUS_KEY } from "../src/constants.ts";
import { writeGuardMeRuntimeSettings } from "../src/config/runtime-settings.ts";
import { registerGuard, evaluateGuardedToolCall, mapToolCallToPolicyRequest } from "../src/events/register-guard.ts";
import { registerGuidance } from "../src/events/register-guidance.ts";
import { getGuardMeSessionState, startGuardMeSession, stopGuardMeSession } from "../src/events/register-lifecycle.ts";
import { resolveStatePaths } from "../src/state/warnings.ts";

async function createGuardContext(options = {}) {
  const root = await mkdtemp(join(tmpdir(), "guardme-tool-guard-"));
  const home = join(root, "home");
  const cwd = join(root, "project");
  await mkdir(cwd, { recursive: true });
  if (options.globalPolicy) {
    await mkdir(join(home, ".pi", "agent"), { recursive: true });
    await writeFile(join(home, ".pi", "agent", "guardme.yaml"), options.globalPolicy, "utf8");
  }
  if (options.localPolicy) {
    await mkdir(join(cwd, ".pi", "agent"), { recursive: true });
    await writeFile(join(cwd, ".pi", "agent", "guardme.yaml"), options.localPolicy, "utf8");
  }
  const statuses = [];
  const ctx = {
    cwd,
    hasUI: false,
    mode: "print",
    isProjectTrusted: () => options.trusted ?? true,
    ui: {
      setStatus: (key, text) => statuses.push([key, text]),
      notify: () => {},
    },
  };
  await startGuardMeSession(ctx, { homeDir: home });
  return { root, home, cwd, ctx, statuses };
}

test("read tool calls inside the project are allowed unless protected", async () => {
  const { cwd, ctx } = await createGuardContext();
  await writeFile(join(cwd, "README.md"), "readme", "utf8");
  await writeFile(join(cwd, ".env"), "SECRET=redacted\n", "utf8");
  await writeFile(join(cwd, ".env.example"), "TEST=example\n", "utf8");

  const allowed = await evaluateGuardedToolCall({ toolName: "read", input: { path: "README.md" } }, ctx);
  const envExample = await evaluateGuardedToolCall({ toolName: "read", input: { path: ".env.example" } }, ctx);
  const blocked = await evaluateGuardedToolCall({ toolName: "read", input: { path: ".env" } }, ctx);

  assert.equal(allowed, undefined);
  assert.equal(envExample, undefined);
  assert.equal(blocked?.block, true);
  assert.match(blocked?.reason ?? "", /Protected by GuardMe: denyPaths \*\*\/\.env -> Environment files may contain credentials\./);
  assert.match(blocked?.reason ?? "", /Note: Try using the tool when one is available that matches the command intent\./);
  stopGuardMeSession(ctx);
});

test("hard-denied protected paths are recorded in warning details", async () => {
  const { ctx } = await createGuardContext();

  const blocked = await evaluateGuardedToolCall({ toolName: "write", input: { path: ".env", content: "test=seki\n" } }, ctx);
  const state = getGuardMeSessionState();
  const record = state?.warnings.records.at(-1);

  assert.equal(blocked?.block, true);
  assert.match(blocked?.reason ?? "", /Protected by GuardMe: denyPaths \*\*\/\.env -> Environment files may contain credentials\./);
  assert.equal(record?.type, "warning");
  if (record?.type === "warning") {
    assert.match(record.reason ?? "", /Protected by GuardMe: denyPaths \*\*\/\.env/);
    assert.equal(record.matchedRules?.[0]?.category, "denyPaths");
    assert.equal(record.matchedRules?.[0]?.pattern, "**/.env");
  }
  stopGuardMeSession(ctx);
});

test("blocked tool calls refresh the footer warning status immediately", async () => {
  const { ctx, statuses } = await createGuardContext();

  const blocked = await evaluateGuardedToolCall({ toolName: "write", input: { path: ".env", content: "seki=test\n" } }, ctx);

  assert.equal(blocked?.block, true);
  assert.deepEqual(statuses.at(-1), [EXTENSION_STATUS_KEY, "🛡️ (1 warning)"]);
  stopGuardMeSession(ctx);
});

test("disabled GuardMe bypasses enforcement and re-enabled GuardMe blocks again", async () => {
  const { home, cwd, ctx } = await createGuardContext();
  await writeFile(join(cwd, ".env"), "SECRET=redacted\n", "utf8");

  let blocked = await evaluateGuardedToolCall({ toolName: "read", input: { path: ".env" } }, ctx);
  assert.equal(blocked?.block, true);

  await writeGuardMeRuntimeSettings({ cwd, enabled: false });
  await stopGuardMeSession(ctx);
  await startGuardMeSession(ctx, { homeDir: home });
  const allowed = await evaluateGuardedToolCall({ toolName: "read", input: { path: ".env" } }, ctx);
  assert.equal(allowed, undefined);

  await writeGuardMeRuntimeSettings({ cwd, enabled: true });
  await stopGuardMeSession(ctx);
  await startGuardMeSession(ctx, { homeDir: home });
  blocked = await evaluateGuardedToolCall({ toolName: "read", input: { path: ".env" } }, ctx);
  assert.equal(blocked?.block, true);
  stopGuardMeSession(ctx);
});

test("write and edit tool calls are treated as inside-project mutations", async () => {
  const { cwd, ctx } = await createGuardContext();
  await mkdir(join(cwd, "src"), { recursive: true });
  await writeFile(join(cwd, "src", "index.ts"), "const value = 1;\n", "utf8");

  const write = await evaluateGuardedToolCall({ toolName: "write", input: { path: "src/new.ts", content: "export {};" } }, ctx);
  const envExample = await evaluateGuardedToolCall({ toolName: "write", input: { path: ".env.example", content: "TEST=example\n" } }, ctx);
  const edit = await evaluateGuardedToolCall({ toolName: "edit", input: { path: "src/index.ts", edits: [] } }, ctx);

  assert.equal(write, undefined);
  assert.equal(envExample, undefined);
  assert.equal(edit, undefined);
  stopGuardMeSession(ctx);
});

test("write and edit script content are inspected before mutation", async () => {
  const { cwd, ctx } = await createGuardContext();
  await writeFile(join(cwd, "safe.sh"), "#!/bin/sh\necho safe\n", "utf8");

  const write = await evaluateGuardedToolCall({
    toolName: "write",
    input: { path: "audit.sh", content: "#!/bin/sh\ncat ~/.azure/azureProfile.json\n" },
  }, ctx);
  const edit = await evaluateGuardedToolCall({
    toolName: "edit",
    input: {
      path: "safe.sh",
      edits: [{ oldText: "echo safe", newText: "aws sts get-caller-identity" }],
    },
  }, ctx);
  const workflow = await evaluateGuardedToolCall({
    toolName: "write",
    input: {
      path: ".github/workflows/release.yml",
      content: "jobs:\n  release:\n    steps:\n      - run: |+ # keep newline\n          gcloud projects list\n",
    },
  }, ctx);

  assert.equal(write?.block, true);
  assert.match(write?.reason ?? "", /proposed file content|Credential|Cloud CLI/i);
  await assert.rejects(access(join(cwd, "audit.sh")));
  assert.equal(edit?.block, true);
  assert.match(edit?.reason ?? "", /proposed file content|Cloud CLI/i);
  assert.equal(workflow?.block, true);
  assert.match(workflow?.reason ?? "", /proposed file content|Cloud CLI/i);
  await assert.rejects(access(join(cwd, ".github", "workflows", "release.yml")));
  stopGuardMeSession(ctx);
});

test("insecure edits skips content scanning but preserves path protections and bash execution", async () => {
  const { home, cwd, ctx } = await createGuardContext({
    localPolicy: 'version: 1\nzeroAccessPaths:\n  - pattern: "vault/**"\nreadOnlyPaths:\n  - pattern: "docs/**"\nprotectedCredentialPaths:\n  - pattern: "private/**"\n',
  });
  await mkdir(join(cwd, "docs"), { recursive: true });
  await writeFile(join(cwd, "docs", "guide.md"), "guide\n", "utf8");
  await writeFile(join(cwd, "safe.sh"), "#!/bin/sh\necho safe\n", "utf8");
  await writeGuardMeRuntimeSettings({ cwd, insecureEdits: true });
  await stopGuardMeSession(ctx);
  await startGuardMeSession(ctx, { homeDir: home });

  const scriptWrite = await evaluateGuardedToolCall({
    toolName: "write",
    input: { path: "audit.sh", content: "#!/bin/sh\naws sts get-caller-identity\ncat ~/.aws/credentials\n" },
  }, ctx);
  const scriptEdit = await evaluateGuardedToolCall({
    toolName: "edit",
    input: { path: "safe.sh", edits: [{ oldText: "echo safe", newText: "az account show" }] },
  }, ctx);
  const envWrite = await evaluateGuardedToolCall({ toolName: "write", input: { path: ".env", content: "SECRET=redacted\n" } }, ctx);
  await writeFile(join(cwd, ".env"), "SECRET=redacted\n", "utf8");
  const envEdit = await evaluateGuardedToolCall({
    toolName: "edit",
    input: { path: ".env", edits: [{ oldText: "SECRET=redacted", newText: "SECRET=changed" }] },
  }, ctx);
  const credentialWrite = await evaluateGuardedToolCall({
    toolName: "write",
    input: { path: "Secret.TXT", content: "redacted\n" },
  }, ctx);
  const readOnlyWrite = await evaluateGuardedToolCall({
    toolName: "write",
    input: { path: "docs/guide.md", content: "updated\n" },
  }, ctx);
  const zeroAccessWrite = await evaluateGuardedToolCall({
    toolName: "write",
    input: { path: "vault/key.txt", content: "redacted\n" },
  }, ctx);
  const protectedCredentialWrite = await evaluateGuardedToolCall({
    toolName: "write",
    input: { path: "private/data.txt", content: "redacted\n" },
  }, ctx);

  assert.equal(scriptWrite, undefined);
  assert.equal(scriptEdit, undefined);
  assert.equal(envWrite?.block, true);
  assert.match(envWrite?.reason ?? "", /denyPaths|Environment files/i);
  assert.equal(envEdit?.block, true);
  assert.match(envEdit?.reason ?? "", /denyPaths|Environment files/i);
  assert.equal(credentialWrite?.block, true);
  assert.match(credentialWrite?.reason ?? "", /Credential-like|Credential/i);
  assert.equal(readOnlyWrite?.block, true);
  assert.match(readOnlyWrite?.reason ?? "", /read-only|readOnlyPaths/i);
  assert.equal(zeroAccessWrite?.block, true);
  assert.match(zeroAccessWrite?.reason ?? "", /zeroAccessPaths/i);
  assert.equal(protectedCredentialWrite?.block, true);
  assert.match(protectedCredentialWrite?.reason ?? "", /Credential-like|protectedCredentialPaths/i);

  await writeFile(join(cwd, "audit.sh"), "#!/bin/sh\naws sts get-caller-identity\n", "utf8");
  const execution = await evaluateGuardedToolCall({ toolName: "bash", input: { command: "bash audit.sh" } }, ctx);

  assert.equal(execution?.block, true);
  assert.match(execution?.reason ?? "", /local script|Cloud CLI|aws/i);
  stopGuardMeSession(ctx);
});

test("bash local script execution inspects script content before running", async () => {
  const { cwd, ctx } = await createGuardContext();
  await writeFile(join(cwd, "azure-cli-config-audit.sh"), "#!/bin/sh\naz account show\n", "utf8");

  const blocked = await evaluateGuardedToolCall({
    toolName: "bash",
    input: { command: "./azure-cli-config-audit.sh --output report.txt" },
  }, ctx);

  assert.equal(blocked?.block, true);
  assert.match(blocked?.reason ?? "", /local script|Cloud CLI|az/i);
  stopGuardMeSession(ctx);
});

test("bash package script execution inspects package.json scripts before running", async () => {
  const { cwd, ctx } = await createGuardContext();
  await writeFile(
    join(cwd, "package.json"),
    JSON.stringify({ scripts: { pretest: "echo preparing", test: "aws sts get-caller-identity", posttest: "echo done" } }, null, 2),
    "utf8",
  );

  const blocked = await evaluateGuardedToolCall({ toolName: "bash", input: { command: "npm test -- --watch" } }, ctx);

  assert.equal(blocked?.block, true);
  assert.match(blocked?.reason ?? "", /local script|package\.json|Cloud CLI|aws/i);

  await writeFile(
    join(cwd, "package.json"),
    JSON.stringify({ scripts: { test: "node --test test/*.test.mjs" } }, null, 2),
    "utf8",
  );
  const safe = await evaluateGuardedToolCall({ toolName: "bash", input: { command: "npm test" } }, ctx);
  assert.equal(safe, undefined);
  stopGuardMeSession(ctx);
});

test("bash package script inspection respects path policy before reading package.json", async () => {
  const { cwd, ctx } = await createGuardContext({
    localPolicy: 'version: 1\ndenyPaths:\n  - pattern: "package.json"\n    actions: [read]\n',
  });
  await writeFile(join(cwd, "package.json"), JSON.stringify({ scripts: { test: "echo ok" } }), "utf8");

  const blocked = await evaluateGuardedToolCall({ toolName: "bash", input: { command: "npm test" } }, ctx);

  assert.equal(blocked?.block, true);
  assert.match(blocked?.reason ?? "", /package script inspection|Path denied|denied by local policy/i);
  stopGuardMeSession(ctx);
});

test("bash package script inspection follows package manager cwd options", async () => {
  const { root, cwd, ctx } = await createGuardContext();
  await mkdir(join(cwd, "packages", "app"), { recursive: true });
  await writeFile(
    join(cwd, "packages", "app", "package.json"),
    JSON.stringify({ scripts: { test: "aws sts get-caller-identity" } }),
    "utf8",
  );

  const blocked = await evaluateGuardedToolCall({ toolName: "bash", input: { command: "npm --prefix packages/app test" } }, ctx);

  assert.equal(blocked?.block, true);
  assert.match(blocked?.reason ?? "", /local script|package\.json|Cloud CLI|aws/i);

  const outside = join(root, "outside-package");
  await mkdir(outside, { recursive: true });
  await writeFile(join(outside, "package.json"), JSON.stringify({ scripts: { test: "echo ok" } }), "utf8");

  const outsideBlocked = await evaluateGuardedToolCall({ toolName: "bash", input: { command: `npm --prefix ${outside} test` } }, ctx);

  assert.equal(outsideBlocked?.block, true);
  assert.match(outsideBlocked?.reason ?? "", /package script inspection|Outside-project read requires/i);

  const outsideTrailingOptionBlocked = await evaluateGuardedToolCall({ toolName: "bash", input: { command: `npm test --prefix ${outside}` } }, ctx);

  assert.equal(outsideTrailingOptionBlocked?.block, true);
  assert.match(outsideTrailingOptionBlocked?.reason ?? "", /package script inspection|Outside-project read requires/i);
  stopGuardMeSession(ctx);
});

test("concurrent coaching warnings merge into session state", async () => {
  const { ctx } = await createGuardContext();

  const [first, second] = await Promise.all([
    evaluateGuardedToolCall({ toolName: "bash", input: { command: "brave https://example.com" } }, ctx),
    evaluateGuardedToolCall({ toolName: "bash", input: { command: "open -a Brave https://example.com" } }, ctx),
  ]);

  assert.equal(first?.block, true);
  assert.equal(second?.block, true);
  assert.equal(getGuardMeSessionState()?.warnings.warnedFingerprints.size, 2);
  stopGuardMeSession(ctx);
});

test("generic browser launch commands default-deny and repeat fails closed without UI", async () => {
  const { home, cwd, ctx } = await createGuardContext();
  const statePaths = resolveStatePaths(cwd, home);

  const first = await evaluateGuardedToolCall({ toolName: "bash", input: { command: "brave https://example.com" } }, ctx);
  const second = await evaluateGuardedToolCall({ toolName: "bash", input: { command: "brave https://example.com" } }, ctx);
  const open = await evaluateGuardedToolCall({ toolName: "bash", input: { command: "open -a Brave https://example.com" } }, ctx);
  const jsonl = await readFile(statePaths.localStatePath, "utf8");

  assert.equal(first?.block, true);
  assert.match(first?.reason ?? "", /No allowCommands rule matches|unclassified shell commands/);
  assert.equal(second?.block, true);
  assert.match(second?.reason ?? "", /requires user approval|no UI/i);
  assert.equal(open?.block, true);
  assert.match(open?.reason ?? "", /No allowCommands rule matches|unclassified shell commands/);
  assert.equal(JSON.parse(jsonl.trim().split("\n")[0]).reasonCode, "policy-missing-command");
  stopGuardMeSession(ctx);
});

test("blocked policy-missing attempts inject concise follow-up guidance", async () => {
  const { ctx } = await createGuardContext();
  const handlers = new Map();
  registerGuidance({
    on: (name, handler) => handlers.set(name, handler),
  });

  await evaluateGuardedToolCall({ toolName: "bash", input: { command: "brave https://example.com" } }, ctx);
  const result = await handlers.get("before_agent_start")?.({}, ctx);

  assert.equal(result.message.customType, "guardme-guidance");
  assert.match(result.message.content, /GuardMe blocked the previous bash:shell request/);
  assert.match(result.message.content, /allowCommands/);
  assert.equal(result.message.display, true);
  stopGuardMeSession(ctx);
});

test("blocked follow-up guidance redacts secrets and strips terminal controls", async () => {
  const { ctx } = await createGuardContext();
  const handlers = new Map();
  registerGuidance({
    on: (name, handler) => handlers.set(name, handler),
  });

  await evaluateGuardedToolCall({ toolName: "bash", input: { command: "brave --token supersecret \u001B[31mhttps://example.com" } }, ctx);
  const result = await handlers.get("before_agent_start")?.({}, ctx);

  assert.doesNotMatch(result.message.content, /supersecret/);
  assert.doesNotMatch(result.message.content, /\u001B/);
  assert.match(result.message.content, /--token <redacted>/);
  stopGuardMeSession(ctx);
});

test("blocked follow-up guidance includes the relevant matched rule without dumping policy files", async () => {
  const { ctx } = await createGuardContext({
    globalPolicy: 'version: 1\ndenyCommands:\n  - pattern: "blocked-tool --token supersecret"\n    reason: "Global test denial."\n',
    localPolicy: 'version: 1\nallowCommands:\n  - pattern: "npm test*"\n    reason: "Local test allow."\n',
  });
  const handlers = new Map();
  registerGuidance({
    on: (name, handler) => handlers.set(name, handler),
  });

  await evaluateGuardedToolCall({ toolName: "bash", input: { command: "blocked-tool --token supersecret" } }, ctx);
  const result = await handlers.get("before_agent_start")?.({}, ctx);
  const content = result.message.content;

  assert.match(content, /WARNINGS & DECISIONS/);
  assert.match(content, /Matched rules:/);
  assert.match(content, /denyCommands blocked-tool --token <redacted>/);
  assert.match(content, /Global test denial/);
  assert.doesNotMatch(content, /GuardMe policy files/);
  assert.doesNotMatch(content, /Local test allow/);
  assert.doesNotMatch(content, /supersecret/);
  stopGuardMeSession(ctx);
});

test("bash tool calls are classified and blocked or allowed by policy", async () => {
  const { root, cwd, ctx } = await createGuardContext();
  const outside = join(root, "outside.txt");
  await writeFile(outside, "outside\n", "utf8");
  await writeFile(join(cwd, "README.md"), "readme\n", "utf8");
  await writeFile(join(cwd, ".env"), "SECRET=redacted\n", "utf8");

  const allowed = await evaluateGuardedToolCall({ toolName: "bash", input: { command: "npm test -- --help" } }, ctx);
  const cloud = await evaluateGuardedToolCall({ toolName: "bash", input: { command: "aws sts get-caller-identity" } }, ctx);
  const copyCredential = await evaluateGuardedToolCall({ toolName: "bash", input: { command: "cp .env copied.env" } }, ctx);
  const globCredential = await evaluateGuardedToolCall({ toolName: "bash", input: { command: "cat .env*" } }, ctx);
  const outsideRead = await evaluateGuardedToolCall({ toolName: "bash", input: { command: `grep outside < ${outside}` } }, ctx);
  const broadShellGrep = await evaluateGuardedToolCall({ toolName: "bash", input: { command: "grep -R SECRET ." } }, ctx);
  const absoluteBroadShellGrep = await evaluateGuardedToolCall({ toolName: "bash", input: { command: "/usr/bin/grep -R SECRET ." } }, ctx);
  const compoundBroadShellGrep = await evaluateGuardedToolCall({ toolName: "bash", input: { command: "chmod 600 README.md && grep -R SECRET ." } }, ctx);
  const broadShellFind = await evaluateGuardedToolCall({ toolName: "bash", input: { command: "find -name '*'" } }, ctx);
  const safeShellFind = await evaluateGuardedToolCall({ toolName: "bash", input: { command: "find -name '*.ts'" } }, ctx);
  const discardedFindErrors = await evaluateGuardedToolCall({
    toolName: "bash",
    input: { command: "find .github -maxdepth 3 -type f -print 2>/dev/null" },
  }, ctx);
  const wildcardAllowCompound = await evaluateGuardedToolCall({ toolName: "bash", input: { command: "npm test && rm -rf build" } }, ctx);
  const dangerousWithOutsideRead = await evaluateGuardedToolCall({ toolName: "bash", input: { command: `rm -rf build && cat ${outside}` } }, ctx);
  const dangerous = await evaluateGuardedToolCall({ toolName: "bash", input: { command: "rm -rf build" } }, ctx);

  assert.equal(allowed, undefined);
  assert.equal(cloud?.block, true);
  assert.match(cloud?.reason ?? "", /Cloud CLI/);
  assert.equal(copyCredential?.block, true);
  assert.match(copyCredential?.reason ?? "", /Environment files|Credential/i);
  assert.equal(globCredential?.block, true);
  assert.match(globCredential?.reason ?? "", /Credential|Environment files/i);
  assert.equal(outsideRead?.block, true);
  assert.match(outsideRead?.reason ?? "", /Outside-project read requires/);
  assert.equal(broadShellGrep?.block, true);
  assert.match(broadShellGrep?.reason ?? "", /Credential-like path|Environment files|Credential/i);
  assert.equal(absoluteBroadShellGrep?.block, true);
  assert.match(absoluteBroadShellGrep?.reason ?? "", /Credential-like path|Environment files|Credential/i);
  assert.equal(compoundBroadShellGrep?.block, true);
  assert.match(compoundBroadShellGrep?.reason ?? "", /Credential-like path|Environment files|Credential/i);
  assert.equal(broadShellFind?.block, true);
  assert.match(broadShellFind?.reason ?? "", /Credential-like path|Environment files|Credential/i);
  assert.equal(safeShellFind, undefined);
  assert.equal(discardedFindErrors, undefined);
  assert.equal(wildcardAllowCompound?.block, true);
  assert.match(wildcardAllowCompound?.reason ?? "", /GuardMe coaching|Recursive force deletion/);
  assert.equal(dangerousWithOutsideRead?.block, true);
  assert.match(dangerousWithOutsideRead?.reason ?? "", /Outside-project .* requires/);
  assert.equal(dangerous?.block, true);
  assert.match(dangerous?.reason ?? "", /GuardMe coaching|Recursive force deletion/);
  stopGuardMeSession(ctx);
});

test("destructive shell commands cannot target directories containing protected metadata", async () => {
  const { cwd, ctx } = await createGuardContext();
  await mkdir(join(cwd, ".git"), { recursive: true });
  await mkdir(join(cwd, "vendor", "module", ".git"), { recursive: true });
  await mkdir(join(cwd, "config"), { recursive: true });
  await writeFile(join(cwd, "config", ".env.local"), "TOKEN=redacted\n", "utf8");

  const blocked = await evaluateGuardedToolCall({ toolName: "bash", input: { command: "find . -delete" } }, ctx);
  const nestedBlocked = await evaluateGuardedToolCall({ toolName: "bash", input: { command: "rm -rf vendor" } }, ctx);
  const envTemplateBlocked = await evaluateGuardedToolCall({ toolName: "bash", input: { command: "rm -rf config" } }, ctx);

  assert.equal(blocked?.block, true);
  assert.match(blocked?.reason ?? "", /Repository metadata|deleted|renamed|moved/i);
  assert.equal(nestedBlocked?.block, true);
  assert.match(nestedBlocked?.reason ?? "", /Repository metadata|deleted|renamed|moved/i);
  assert.equal(envTemplateBlocked?.block, true);
  assert.match(envTemplateBlocked?.reason ?? "", /Environment template files|destructive changes/i);
  stopGuardMeSession(ctx);
});

test("bash evasions for cloud CLIs and credential literals are hard blocked", async () => {
  const { ctx } = await createGuardContext();

  const dynamicCloud = await evaluateGuardedToolCall({ toolName: "bash", input: { command: "aw${empty}s sts get-caller-identity" } }, ctx);
  const inlineCloud = await evaluateGuardedToolCall({ toolName: "bash", input: { command: "python -c \"import os; os.system('aws sts get-caller-identity')\"" } }, ctx);
  const inlineCredential = await evaluateGuardedToolCall({ toolName: "bash", input: { command: "node -e \"require('fs').readFileSync('.env','utf8')\"" } }, ctx);

  assert.equal(dynamicCloud?.block, true);
  assert.match(dynamicCloud?.reason ?? "", /Shell-expanded command names/);
  assert.equal(inlineCloud?.block, true);
  assert.match(inlineCloud?.reason ?? "", /cloud CLI/i);
  assert.equal(inlineCredential?.block, true);
  assert.match(inlineCredential?.reason ?? "", /Credential-like file reference/);
  stopGuardMeSession(ctx);
});

test("first dangerous attempt records coaching state and repeated attempt asks for user decision", async () => {
  const { home, cwd, ctx } = await createGuardContext();
  const statePaths = resolveStatePaths(cwd, home);

  const first = await evaluateGuardedToolCall({ toolName: "bash", input: { command: "rm -rf build" } }, ctx);
  const second = await evaluateGuardedToolCall({ toolName: "bash", input: { command: "rm -rf build" } }, ctx);
  const jsonl = await readFile(statePaths.localStatePath, "utf8");

  assert.equal(first?.block, true);
  assert.match(first?.reason ?? "", /GuardMe coaching/);
  assert.equal(second?.block, true);
  assert.match(second?.reason ?? "", /requires user approval/);
  assert.doesNotMatch(second?.reason ?? "", /GuardMe coaching/);
  assert.equal(jsonl.trim().split("\n").length, 1);
  assert.equal(JSON.parse(jsonl).type, "warning");
  stopGuardMeSession(ctx);
});

test("untrusted project coaching state is written globally instead of into the project", async () => {
  const { home, cwd, ctx } = await createGuardContext({ trusted: false });
  const statePaths = resolveStatePaths(cwd, home);

  const blocked = await evaluateGuardedToolCall({ toolName: "bash", input: { command: "rm -rf build" } }, ctx);
  const globalJsonl = await readFile(statePaths.globalStatePath, "utf8");

  assert.equal(blocked?.block, true);
  assert.match(blocked?.reason ?? "", /GuardMe coaching/);
  const globalRecord = JSON.parse(globalJsonl);
  assert.equal(globalRecord.scope, "global");
  await assert.rejects(access(statePaths.localStatePath));

  stopGuardMeSession(ctx);
  await startGuardMeSession(ctx, { homeDir: home });
  assert.equal(getGuardMeSessionState()?.warnings.warnedFingerprints.has(globalRecord.fingerprint), true);
  stopGuardMeSession(ctx);
});

test("state write failures degrade status while preserving fail-closed coaching", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-tool-state-failure-"));
  const home = join(root, "home");
  const cwd = join(root, "project");
  const outside = join(root, "outside");
  await mkdir(cwd, { recursive: true });
  await mkdir(outside, { recursive: true });
  try {
    await symlink(outside, join(cwd, ".pi"), "dir");
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && ["EACCES", "EPERM"].includes(String(error.code))) {
      return;
    }
    throw error;
  }
  const ctx = {
    cwd,
    hasUI: false,
    mode: "print",
    isProjectTrusted: () => true,
    ui: {
      setStatus: () => {},
      notify: () => {},
    },
  };
  await startGuardMeSession(ctx, { homeDir: home });

  const blocked = await evaluateGuardedToolCall({ toolName: "bash", input: { command: "rm -rf build" } }, ctx);
  const state = getGuardMeSessionState();

  assert.equal(blocked?.block, true);
  assert.match(blocked?.reason ?? "", /GuardMe coaching/);
  assert.equal(state?.degraded, true);
  assert.ok(state?.diagnostics.some((diagnostic) => diagnostic.code === "state.writeFailed"));
  stopGuardMeSession(ctx);
});

test("grep find and ls are mapped as read/list discovery actions", async () => {
  const { root, cwd, ctx } = await createGuardContext();
  const outside = join(root, "outside");
  await mkdir(outside, { recursive: true });
  await mkdir(join(cwd, "src"), { recursive: true });
  await writeFile(join(cwd, ".env"), "SECRET=redacted\n", "utf8");
  await writeFile(join(cwd, ".env.example"), "TEST=example\n", "utf8");
  await writeFile(join(cwd, "src", "index.ts"), "const value = 1;\n", "utf8");

  const grep = await evaluateGuardedToolCall({ toolName: "grep", input: { path: ".env", pattern: "SECRET" } }, ctx);
  const envExampleGrep = await evaluateGuardedToolCall({ toolName: "grep", input: { path: ".env.example", pattern: "TEST" } }, ctx);
  const broadGrep = await evaluateGuardedToolCall({ toolName: "grep", input: { pattern: "SECRET" } }, ctx);
  const broadShellGgrep = await evaluateGuardedToolCall({ toolName: "bash", input: { command: "ggrep -R SECRET ." } }, ctx);
  const scopedGrep = await evaluateGuardedToolCall({ toolName: "grep", input: { path: "src", glob: "*.ts", pattern: "value" } }, ctx);
  const credentialGlobGrep = await evaluateGuardedToolCall({ toolName: "grep", input: { path: "src", glob: "**/.aws/**", pattern: "key" } }, ctx);
  const broadFind = await evaluateGuardedToolCall({ toolName: "find", input: { path: ".", pattern: "*" } }, ctx);
  const scopedFind = await evaluateGuardedToolCall({ toolName: "find", input: { path: ".", pattern: "*.ts" } }, ctx);
  const find = await evaluateGuardedToolCall({ toolName: "find", input: { path: outside, pattern: "*" } }, ctx);
  const ls = await evaluateGuardedToolCall({ toolName: "ls", input: { path: outside } }, ctx);

  assert.equal(grep?.block, true);
  assert.equal(envExampleGrep, undefined);
  assert.equal(broadGrep?.block, true);
  assert.match(broadGrep?.reason ?? "", /Credential-like path|Environment files|Credential/i);
  assert.equal(broadShellGgrep?.block, true);
  assert.match(broadShellGgrep?.reason ?? "", /Credential-like path|Environment files|Credential/i);
  assert.equal(scopedGrep, undefined);
  assert.equal(credentialGlobGrep?.block, true);
  assert.match(credentialGlobGrep?.reason ?? "", /Credential-like path|Credential/i);
  assert.equal(broadFind?.block, true);
  assert.match(broadFind?.reason ?? "", /Credential-like path|Environment files|Credential/i);
  assert.equal(scopedFind, undefined);
  assert.equal(find?.block, true);
  assert.match(find?.reason ?? "", /Outside-project list requires/);
  assert.equal(ls?.block, true);
  stopGuardMeSession(ctx);
});

test("path resolution errors fail closed with an actionable block", async () => {
  const { ctx } = await createGuardContext();

  const blocked = await evaluateGuardedToolCall({ toolName: "read", input: { path: "bad\0path" } }, ctx);

  assert.equal(blocked?.block, true);
  assert.match(blocked?.reason ?? "", /could not safely resolve/);
  stopGuardMeSession(ctx);
});

test("mapper resolves home-relative paths with the session home override", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-tool-home-map-"));
  const home = join(root, "home");
  const cwd = join(root, "project");
  await mkdir(cwd, { recursive: true });

  const mapped = await mapToolCallToPolicyRequest({ toolName: "read", input: { path: "~/notes.txt" } }, cwd, home);

  assert.equal("request" in mapped, true);
  assert.equal("request" in mapped ? mapped.request.targets[0]?.absolutePath : undefined, join(home, "notes.txt"));
});

test("mapper covers every guarded built-in tool and ignores non-guarded shell escapes", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "guardme-tool-map-"));
  const mapped = await Promise.all([
    mapToolCallToPolicyRequest({ toolName: "bash", input: { command: "ls" } }, cwd),
    mapToolCallToPolicyRequest({ toolName: "read", input: { path: "README.md" } }, cwd),
    mapToolCallToPolicyRequest({ toolName: "write", input: { path: "README.md" } }, cwd),
    mapToolCallToPolicyRequest({ toolName: "edit", input: { path: "README.md" } }, cwd),
    mapToolCallToPolicyRequest({ toolName: "grep", input: { path: "README.md" } }, cwd),
    mapToolCallToPolicyRequest({ toolName: "find", input: { path: "." } }, cwd),
    mapToolCallToPolicyRequest({ toolName: "ls", input: { path: "." } }, cwd),
  ]);

  assert.deepEqual(
    mapped.map((result) => ("request" in result ? result.request.action : "error")),
    ["list", "read", "write", "edit", "read", "list", "list"],
  );

  const ignored = await evaluateGuardedToolCall({ toolName: "user_shell_escape", input: { command: "!ls" } }, { cwd, hasUI: false });
  assert.equal(ignored, undefined);
});

test("registerGuard wires a tool_call handler", () => {
  const handlers = new Map();
  registerGuard({ on: (name, handler) => handlers.set(name, handler) });
  assert.equal(typeof handlers.get("tool_call"), "function");
});
