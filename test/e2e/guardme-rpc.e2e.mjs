import assert from "node:assert/strict";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { loadPolicyConfigFile } from "../../src/config/load-config.ts";
import { writeGuardMeRuntimeSettings } from "../../src/config/runtime-settings.ts";
import { writePolicyConfigFile } from "../../src/config/write-policy.ts";

import {
  createApprovalUiHandler,
  createSetupUiHandler,
  eventsText,
  lastToolExecutionEnd,
  resultText,
  startRpcPi,
} from "./helpers/rpc-client.mjs";
import {
  EDITED_SAFE_NOTE_CONTENT,
  FAKE_ENV_SECRET,
  OUTSIDE_DELETE_PATH,
  OUTSIDE_READ_PATH,
  OUTSIDE_WRITE_PATH,
  SAFE_NOTE_CONTENT,
  SAFE_SCRIPT_CONTENT,
  createProjectFixture,
  pathExists,
  readIfExists,
} from "./helpers/project-fixture.mjs";

const RPC_TIMEOUT_MS = 180_000;

test("GuardMe RPC e2e setup, policy enforcement, approvals, and persistence", { timeout: 300_000 }, async () => {
  const fixture = await createProjectFixture("rpc");
  const artifactClients = [];
  const trackClient = (nextClient) => {
    artifactClients.push(nextClient);
    return nextClient;
  };
  fixture.trackRpcClient = trackClient;
  let client;
  let failed = false;
  try {
    client = trackClient(await startRpcPi({ projectDir: fixture.projectDir, homeDir: fixture.homeDir, timeoutMs: RPC_TIMEOUT_MS }));

    const commands = await client.send({ type: "get_commands" });
    assert.ok(commands.data.commands.some((command) => command.name === "guardme"), "/guardme command should be registered");

    await client.prompt("/guardme setup", { uiHandler: createSetupUiHandler(), timeoutMs: RPC_TIMEOUT_MS });
    await waitUntil(async () => pathExists(fixture.localPolicyPath), "local GuardMe policy to be written");
    const setupYaml = await fixture.readLocalPolicy();
    assert.match(setupYaml, /zeroAccessPaths:/);
    assert.match(setupYaml, /denyPaths:/);
    assert.match(setupYaml, /noDeletePaths:/);
    assert.match(setupYaml, /protectedCredentialPaths:/);
    assert.equal(await pathExists(fixture.globalPolicyPath), false, "setup should not write a global policy");

    await client.stop();
    client = trackClient(await startRpcPi({ projectDir: fixture.projectDir, homeDir: fixture.homeDir, timeoutMs: RPC_TIMEOUT_MS }));

    await assertAllowedRead(client);
    await assertAllowedValidationCommand(client);
    await assertAllowedWriteAndEdit(client, fixture);
    await assertAllowedScopedFind(client);
    await assertProtectedEnvRead(client, fixture);
    await assertCloudCliHardDeny(client, "hard-deny-cloud-cli");
    await assertCloudCliHardDeny(client, "hard-deny-cloud-cli-wrapper");
    await assertBroadDiscoveryProtection(client, fixture);
    await assertBroadFindDiscoveryProtection(client, fixture);
    await assertEnvDeleteHardDeny(client, fixture);
    await assertProtectedMetadataDelete(client, fixture);
    await assertOutsideRepositoryProtections(client, fixture);
    client = await assertOutsideReadExplicitAllow(client, fixture);
    await assertCommandAllowBoundary(client, fixture);
    await assertScriptContentProtections(client, fixture);
    await assertPolicyMissingApproval(client, fixture);
    client = await assertDangerousDenyLocalPersistence(client, fixture);
    client = await assertDangerousApprovalPersistence(client, fixture);
    client = await assertRuntimeSettingsDisableAndReenable(client, fixture);
  } catch (error) {
    failed = true;
    throw error;
  } finally {
    for (const startedClient of artifactClients) {
      await startedClient.stop();
    }
    if (artifactClients.length > 0) {
      await writeRpcArtifacts(fixture, artifactClients, failed ? "failed" : "passed");
    }
    await fixture.cleanup();
  }
});

async function assertAllowedRead(client) {
  const run = await runScenario(client, "allowed-read");
  const end = expectToolEnd(run.events, "read", { error: false });
  assert.match(resultText(end), /GuardMe e2e fixture/);
}

async function assertAllowedValidationCommand(client) {
  const run = await runScenario(client, "allowed-validation-command");
  const end = expectToolEnd(run.events, "bash", { error: false });
  assert.match(resultText(end), /guardme e2e validation ok/);
  assert.doesNotMatch(resultText(end), /GuardMe blocked/i);
}

async function assertAllowedWriteAndEdit(client, fixture) {
  let run = await runScenario(client, "allowed-write");
  let end = expectToolEnd(run.events, "write", { error: false });
  assert.doesNotMatch(resultText(end), /GuardMe blocked/i);
  assert.equal(await readFile(fixture.safeWritePath, "utf8"), "safe write from guardme e2e\n");

  await fixture.recreateSafeNote();
  assert.equal(await readFile(fixture.safeNotePath, "utf8"), SAFE_NOTE_CONTENT);
  run = await runScenario(client, "allowed-edit");
  end = expectToolEnd(run.events, "edit", { error: false });
  assert.doesNotMatch(resultText(end), /GuardMe blocked/i);
  assert.equal(await readFile(fixture.safeNotePath, "utf8"), EDITED_SAFE_NOTE_CONTENT);
}

async function assertAllowedScopedFind(client) {
  const run = await runScenario(client, "allowed-find-scoped");
  const end = expectToolEnd(run.events, "find", { error: false });
  assert.match(resultText(end), /README\.md/);
  assert.doesNotMatch(resultText(end), /GuardMe blocked/i);
}

async function assertProtectedEnvRead(client, fixture) {
  await fixture.recreateEnvTest();
  const run = await runScenario(client, "protected-env-read");
  const end = expectToolEnd(run.events, "read", { error: true });
  const text = resultText(end);
  assert.match(text, /GuardMe/i);
  assert.match(text, /Credential|Environment files|protected/i);
  assertNoSecretLeak(run.events);
}

async function assertCloudCliHardDeny(client, scenario) {
  const run = await runScenario(client, scenario);
  const end = expectToolEnd(run.events, "bash", { error: true });
  assert.match(resultText(end), /GuardMe/i);
  assert.match(resultText(end), /Cloud CLI|cloud CLI|Cloud CLIs/i);
}

async function assertBroadDiscoveryProtection(client, fixture) {
  await fixture.recreateEnvTest();
  const run = await runScenario(client, "broad-discovery-protected-descendant");
  const end = expectToolEnd(run.events, "grep", { error: true });
  assert.match(resultText(end), /Credential|Environment files|protected/i);
  assertNoSecretLeak(run.events);
}

async function assertBroadFindDiscoveryProtection(client, fixture) {
  await fixture.recreateEnvTest();
  const run = await runScenario(client, "broad-find-protected-descendant");
  const end = expectToolEnd(run.events, "find", { error: true });
  assert.match(resultText(end), /Credential|Environment files|protected/i);
  assertNoSecretLeak(run.events);
}

async function assertEnvDeleteHardDeny(client, fixture) {
  await fixture.recreateEnvTest();
  const run = await runScenario(client, "hard-deny-env-delete");
  const end = expectToolEnd(run.events, "bash", { error: true });
  assert.match(resultText(end), /Credential|Environment files|protected/i);
  assert.equal(await pathExists(join(fixture.projectDir, ".env")), true, ".env must remain after hard-denied delete");
  const yaml = await fixture.readLocalPolicy();
  assert.doesNotMatch(yaml, /rm -rf \.env/);
}

async function assertProtectedMetadataDelete(client, fixture) {
  await fixture.recreateGitMetadata();
  const run = await runScenario(client, "protected-metadata-delete");
  const end = expectToolEnd(run.events, "bash", { error: true });
  assert.match(resultText(end), /\.git|Repository metadata|protected|noDeletePaths/i);
  assert.equal(await pathExists(fixture.gitHeadPath), true, ".git metadata must remain after blocked delete");
}

async function assertOutsideRepositoryProtections(client, fixture) {
  await fixture.recreateOutsideFiles();

  let run = await runScenario(client, "outside-read-block");
  let end = expectToolEnd(run.events, "read", { error: true });
  assert.match(resultText(end), /Outside-project read requires/i);
  assert.doesNotMatch(eventsText(run.events), /outside fixture content should not leak/);

  run = await runScenario(client, "outside-write-block");
  end = expectToolEnd(run.events, "write", { error: true });
  assert.match(resultText(end), /Outside-project write requires|explicit allowPaths/i);
  assert.equal(await readFile(OUTSIDE_WRITE_PATH, "utf8"), "outside original\n");

  run = await runScenario(client, "outside-delete-block");
  end = expectToolEnd(run.events, "bash", { error: true });
  assert.match(resultText(end), /Outside-project .*requires|explicit allowPaths/i);
  assert.equal(await pathExists(OUTSIDE_DELETE_PATH), true, "outside delete target must remain");
}

async function assertOutsideReadExplicitAllow(client, fixture) {
  await addOutsideReadPolicyRule(fixture);
  client = await restartRpcClient(client, fixture);
  const run = await runScenario(client, "outside-read-allowed");
  const end = expectToolEnd(run.events, "read", { error: false });
  assert.match(resultText(end), /outside fixture content should not leak/);
  return client;
}

async function assertCommandAllowBoundary(client, fixture) {
  await fixture.recreateBuild();
  const run = await runScenario(client, "command-allow-boundary");
  const end = expectToolEnd(run.events, "bash", { error: true });
  assert.match(resultText(end), /Recursive force deletion|dangerous|GuardMe coaching/i);
  assert.equal(await pathExists(join(fixture.projectDir, "build", "keep.txt")), true, "build fixture must remain");
}

async function assertScriptContentProtections(client, fixture) {
  await fixture.recreateEnvTest();

  let run = await runScenario(client, "script-write-denied-content");
  let end = expectToolEnd(run.events, "write", { error: true });
  assert.match(resultText(end), /proposed file content|Credential|Environment files|blocked/i);
  assert.equal(await pathExists(join(fixture.projectDir, "scripts", "generated-unsafe.sh")), false);

  const safeScriptPath = join(fixture.projectDir, "scripts", "safe.sh");
  assert.equal(await readFile(safeScriptPath, "utf8"), SAFE_SCRIPT_CONTENT);
  run = await runScenario(client, "script-edit-denied-content");
  end = expectToolEnd(run.events, "edit", { error: true });
  assert.match(resultText(end), /proposed file content|Cloud CLI|blocked/i);
  assert.equal(await readFile(safeScriptPath, "utf8"), SAFE_SCRIPT_CONTENT, "safe script must remain byte-for-byte unchanged");

  await fixture.removeMarker();
  run = await runScenario(client, "local-script-exec-denied-content");
  end = expectToolEnd(run.events, "bash", { error: true });
  assert.match(resultText(end), /local script|Credential|Environment files|blocked/i);
  assert.equal(await pathExists(fixture.markerPath), false, "unsafe script marker must not be created");
  assertNoSecretLeak(run.events);
}

async function assertPolicyMissingApproval(client, fixture) {
  const first = await runScenario(client, "policy-missing-generic-command");
  let end = expectToolEnd(first.events, "bash", { error: true });
  assert.match(resultText(end), /No allowCommands rule matches|policy-missing|unclassified shell commands/i);

  await waitUntil(async () => (await readIfExists(fixture.localStatePath)).includes("policy-missing-command"), "policy-missing warning state");

  const beforeYaml = await fixture.readLocalPolicy();
  const second = await runScenario(client, "policy-missing-generic-command", { uiHandler: createApprovalUiHandler("Deny once") });
  assert.ok(second.uiRequests.some((request) => request.method === "select" && /GuardMe approval required/i.test(request.title ?? "")));
  end = expectToolEnd(second.events, "bash", { error: true });
  assert.match(resultText(end), /user decision|deny-once|denied/i);
  assert.equal(await fixture.readLocalPolicy(), beforeYaml, "deny once must not persist a YAML rule");

  const third = await runScenario(client, "policy-missing-generic-command", { uiHandler: createApprovalUiHandler("Allow once") });
  assert.ok(third.uiRequests.some((request) => request.method === "select" && /GuardMe approval required/i.test(request.title ?? "")));
  end = expectToolEnd(third.events, "bash", { error: false });
  assert.match(resultText(end), /guardme generic/);
  assert.equal(await fixture.readLocalPolicy(), beforeYaml, "allow once must not persist a YAML rule");
}

async function assertDangerousDenyLocalPersistence(client, fixture) {
  await fixture.recreateDenyTarget();
  const first = await runScenario(client, "approval-dangerous-deny");
  let end = expectToolEnd(first.events, "bash", { error: true });
  assert.match(resultText(end), /Recursive force deletion|GuardMe coaching|dangerous/i);
  assert.equal(await pathExists(fixture.denyTargetPath), true);

  const deny = await runScenario(client, "approval-dangerous-deny", { uiHandler: createApprovalUiHandler("Deny + save project rule") });
  assert.ok(deny.uiRequests.some((request) => request.method === "select" && /GuardMe approval required/i.test(request.title ?? "")));
  end = expectToolEnd(deny.events, "bash", { error: true });
  assert.match(resultText(end), /user decision|deny-local|denied/i);
  assert.equal(await pathExists(fixture.denyTargetPath), true);
  assert.match(await fixture.readLocalPolicy(), /denyCommands:/);
  assert.match(await fixture.readLocalPolicy(), /pattern: "rm -rf deny-target\/file\.txt"/);

  client = await restartRpcClient(client, fixture);
  await fixture.recreateDenyTarget();
  const persisted = await runScenario(client, "approval-dangerous-deny");
  end = expectToolEnd(persisted.events, "bash", { error: true });
  assert.match(resultText(end), /denyCommands|denied|GuardMe/i);
  assert.equal(await pathExists(fixture.denyTargetPath), true, "saved denyCommands rule should survive restart");
  assert.equal(persisted.uiRequests.some((request) => request.method === "select" && /GuardMe approval required/i.test(request.title ?? "")), false);
  return client;
}

async function assertDangerousApprovalPersistence(client, fixture) {
  await fixture.recreateApprovalTarget();
  const first = await runScenario(client, "approval-dangerous-delete");
  let end = expectToolEnd(first.events, "bash", { error: true });
  assert.match(resultText(end), /Recursive force deletion|GuardMe coaching|dangerous/i);
  assert.equal(await pathExists(fixture.approvalTargetPath), true);

  const beforeYaml = await fixture.readLocalPolicy();
  const deny = await runScenario(client, "approval-dangerous-delete", { uiHandler: createApprovalUiHandler("Deny once") });
  assert.ok(deny.uiRequests.some((request) => request.method === "select" && /GuardMe approval required/i.test(request.title ?? "")));
  end = expectToolEnd(deny.events, "bash", { error: true });
  assert.match(resultText(end), /user decision|deny-once|denied/i);
  assert.equal(await pathExists(fixture.approvalTargetPath), true);
  assert.equal(await fixture.readLocalPolicy(), beforeYaml, "deny once must not persist a YAML rule");

  await fixture.recreateApprovalTarget();
  const allow = await runScenario(client, "approval-dangerous-delete", { uiHandler: createApprovalUiHandler("Allow + save project rule") });
  end = expectToolEnd(allow.events, "bash", { error: false });
  assert.equal(resultText(end).includes("GuardMe blocked"), false);
  assert.equal(await pathExists(fixture.approvalTargetPath), false, "allow-local should let the delete run");
  const yaml = await fixture.readLocalPolicy();
  assert.match(yaml, /allowCommands:/);
  assert.match(yaml, /pattern: "rm -rf approval-target\/file\.txt"/);
  assert.equal(await pathExists(fixture.globalPolicyPath), false, "approval persistence must be local, not global");

  client = await restartRpcClient(client, fixture);
  await fixture.recreateApprovalTarget();
  const persisted = await runScenario(client, "approval-dangerous-delete");
  end = expectToolEnd(persisted.events, "bash", { error: false });
  assert.equal(await pathExists(fixture.approvalTargetPath), false, "saved allowCommands rule should survive restart");
  assert.equal(persisted.uiRequests.some((request) => request.method === "select" && /GuardMe approval required/i.test(request.title ?? "")), false);
  return client;
}

async function assertRuntimeSettingsDisableAndReenable(client, fixture) {
  await writeGuardMeRuntimeSettings({ cwd: fixture.projectDir, enabled: false });
  client = await restartRpcClient(client, fixture);
  await fixture.recreateEnvTest();
  let run = await runScenario(client, "protected-env-read");
  let end = expectToolEnd(run.events, "read", { error: false });
  assert.match(resultText(end), new RegExp(escapeRegExp(FAKE_ENV_SECRET)));

  await writeGuardMeRuntimeSettings({ cwd: fixture.projectDir, enabled: true });
  client = await restartRpcClient(client, fixture);
  await fixture.recreateEnvTest();
  run = await runScenario(client, "protected-env-read");
  end = expectToolEnd(run.events, "read", { error: true });
  assert.match(resultText(end), /Credential|Environment files|protected/i);
  assertNoSecretLeak(run.events);
  return client;
}

async function addOutsideReadPolicyRule(fixture) {
  const loaded = await loadPolicyConfigFile(fixture.localPolicyPath, "local");
  assert.equal(loaded.diagnostics.filter((diagnostic) => diagnostic.severity === "error").length, 0);
  await writePolicyConfigFile(
    fixture.localPolicyPath,
    {
      ...loaded.config,
      readOnlyPaths: [
        ...loaded.config.readOnlyPaths,
        {
          pattern: OUTSIDE_READ_PATH,
          actions: ["read"],
          reason: "Allow this deterministic outside read fixture for e2e coverage.",
        },
      ],
    },
    { cwd: fixture.projectDir, homeDir: fixture.homeDir, scope: "local" },
  );
}

async function restartRpcClient(client, fixture) {
  await client.stop();
  const restarted = await startRpcPi({ projectDir: fixture.projectDir, homeDir: fixture.homeDir, timeoutMs: RPC_TIMEOUT_MS });
  return typeof fixture.trackRpcClient === "function" ? fixture.trackRpcClient(restarted) : restarted;
}

async function runScenario(client, scenario, options = {}) {
  return client.promptAndWaitForAgentEnd(`SCENARIO: ${scenario}`, { timeoutMs: RPC_TIMEOUT_MS, ...options });
}

function expectToolEnd(events, toolName, options) {
  const end = lastToolExecutionEnd(events, toolName);
  assert.ok(end, `expected ${toolName} tool_execution_end in ${events.map((event) => event.type).join(", ")}`);
  assert.equal(end.isError, options.error, `${toolName} isError mismatch. Result:\n${resultText(end)}`);
  return end;
}

function assertNoSecretLeak(events) {
  assert.doesNotMatch(eventsText(events), new RegExp(escapeRegExp(FAKE_ENV_SECRET)), "blocked output must not leak fake .env secret value");
}

async function waitUntil(predicate, label, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await predicate()) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`Timed out waiting for ${label}`);
}

async function writeRpcArtifacts(fixture, clients, status) {
  const artifactDir = join(process.cwd(), "tmp", "e2e");
  await mkdir(artifactDir, { recursive: true });

  const aggregate = aggregateRpcClients(clients);
  const files = [
    ["guardme-rpc-summary.md", rpcSummaryArtifact(fixture, clients, aggregate, status)],
    ["guardme-rpc-events.jsonl", aggregate.events.map((event) => JSON.stringify(event)).join("\n")],
    ["guardme-rpc-ui-requests.jsonl", aggregate.uiRequests.map((request) => JSON.stringify(request)).join("\n")],
    ["guardme-rpc-stdout.jsonl", aggregate.stdoutLines.join("\n")],
    ["guardme-rpc-stderr.log", aggregate.stderr],
    ["guardme-rpc-policy.yaml", await readIfExists(fixture.localPolicyPath)],
    ["guardme-rpc-state.jsonl", await readIfExists(fixture.localStatePath)],
    ["guardme-rpc-settings.json", await readIfExists(join(fixture.projectDir, ".pi", "agent", "guardme-settings.json"))],
  ];

  for (const [file, text] of files) {
    await writeFile(join(artifactDir, file), withTrailingNewline(sanitizeArtifactText(text)), "utf8");
  }
}

function aggregateRpcClients(clients) {
  return {
    events: clients.flatMap((client) => client.events),
    uiRequests: clients.flatMap((client) => client.uiRequests),
    responses: clients.flatMap((client) => client.responses),
    stdoutLines: clients.flatMap((client) => client.stdoutLines),
    stderr: clients.map((client, index) => `# RPC process ${index + 1}\n${client.stderr}`).join("\n"),
  };
}

function rpcSummaryArtifact(fixture, clients, aggregate, status) {
  return [
    "# GuardMe RPC E2E Artifacts",
    "",
    `Status: ${status}`,
    `Generated: ${new Date().toISOString()}`,
    `Fixture root: ${fixture.rootDir}`,
    `Project: ${fixture.projectDir}`,
    `HOME: ${fixture.homeDir}`,
    "",
    "## Counts",
    "",
    `- RPC processes: ${clients.length}`,
    `- Events: ${aggregate.events.length}`,
    `- UI requests: ${aggregate.uiRequests.length}`,
    `- RPC responses: ${aggregate.responses.length}`,
    `- Stdout JSONL lines: ${aggregate.stdoutLines.length}`,
    `- Stderr bytes: ${aggregate.stderr.length}`,
    "",
    "## Files",
    "",
    "- guardme-rpc-events.jsonl",
    "- guardme-rpc-ui-requests.jsonl",
    "- guardme-rpc-stdout.jsonl",
    "- guardme-rpc-stderr.log",
    "- guardme-rpc-policy.yaml",
    "- guardme-rpc-state.jsonl",
    "- guardme-rpc-settings.json",
  ].join("\n");
}

function sanitizeArtifactText(text) {
  return String(text ?? "")
    .replaceAll(FAKE_ENV_SECRET, "<redacted-e2e-secret>")
    .replaceAll("GUARDME_E2E_FAKE_SECRET=not-real", "GUARDME_E2E_FAKE_SECRET=<redacted-e2e-secret>");
}

function withTrailingNewline(text) {
  return text.endsWith("\n") ? text : `${text}\n`;
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
