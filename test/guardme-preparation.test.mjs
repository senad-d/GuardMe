import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import test from "node:test";

const packageJson = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));

async function readProjectFile(path) {
  return readFile(new URL(`../${path}`, import.meta.url), "utf8");
}

test("package declares GuardMe Pi extension metadata", async () => {
  assert.equal(packageJson.name, "@senad-d/guardme");
  assert.equal(packageJson.pi?.extensions?.[0], "./src/extension.ts");
  assert.equal(
    packageJson.description,
    "Deny-first Pi guardrails that keep LLM shell and file access safe, transparent, and user-approved.",
  );
  assert.equal(packageJson.peerDependencies?.["@earendil-works/pi-coding-agent"], "*");
  assert.equal(packageJson.dependencies, undefined);
  assert.equal(packageJson.scripts?.preinstall, undefined);
  assert.equal(packageJson.scripts?.install, undefined);
  assert.equal(packageJson.scripts?.postinstall, undefined);
  assert.equal(packageJson.files.includes("scripts/install-global-policy.mjs"), false);
  assert.ok(packageJson.keywords.includes("pi-package"));
  assert.ok(packageJson.keywords.includes("tool-guardrails"));
  assert.equal(packageJson._template, undefined);
  await access(new URL("../src/extension.ts", import.meta.url));
});

test("prepared repository includes approved planning specs", async () => {
  await access(new URL("../docs/PROJECT_DEFINITION_BRIEF.md", import.meta.url));
  await access(new URL("../specs/spec-architecture.md", import.meta.url));
  await access(new URL("../specs/spec-guidelines.md", import.meta.url));
  await access(new URL("../specs/spec-tasks.md", import.meta.url));
});

test("implementation task spec tracks all completed tasks", async () => {
  const taskSpec = await readProjectFile("specs/spec-tasks.md");
  assert.match(taskSpec, /### 1\. Establish GuardMe constants and entry-point wiring[\s\S]*- \[x\] Replace remaining placeholder/);
  assert.match(taskSpec, /### 2\. Add policy domain types[\s\S]*- \[x\] Create domain types/);
  assert.match(taskSpec, /### 3\. Implement YAML config schema and default policy[\s\S]*- \[x\] Implement config schema/);
  assert.match(taskSpec, /### 4\. Implement global\/local policy merge semantics[\s\S]*- \[x\] Merge global YAML/);
  assert.match(taskSpec, /### 5\. Implement safe path normalization and glob matching[\s\S]*- \[x\] Implement path normalization/);
  assert.match(taskSpec, /### 6\. Implement shell command classification[\s\S]*- \[x\] Implement a conservative shell command classifier/);
  assert.match(taskSpec, /### 7\. Implement the policy evaluation engine[\s\S]*- \[x\] Implement the central deny-first decision engine/);
  assert.match(taskSpec, /### 8\. Implement JSONL warned-once state[\s\S]*- \[x\] Implement append\/read helpers/);
  assert.match(taskSpec, /### 9\. Implement Pi lifecycle integration[\s\S]*- \[x\] Register `session_start` and `session_shutdown` handlers/);
  assert.match(taskSpec, /### 10\. Implement tool-call enforcement adapters[\s\S]*- \[x\] Register `tool_call` enforcement/);
  assert.match(taskSpec, /### 11\. Implement coaching behavior[\s\S]*- \[x\] Implement first-dangerous-attempt coaching/);
  assert.match(taskSpec, /### 12\. Implement TUI approval modal and UI fallback[\s\S]*- \[x\] Implement a polished GuardMe approval UI/);
  assert.match(taskSpec, /### 13\. Implement YAML rule persistence[\s\S]*- \[x\] Implement persistence for user-selected allow\/deny rules/);
  assert.match(taskSpec, /### 14\. Implement `\/guardme` command[\s\S]*- \[x\] Implement `\/guardme` command/);
  assert.match(taskSpec, /### 15\. Add policy documentation[\s\S]*- \[x\] Add user-facing documentation for GuardMe policy YAML/);
  assert.match(taskSpec, /### 16\. Add comprehensive tests[\s\S]*- \[x\] Add unit and integration tests/);
  assert.match(taskSpec, /### 17\. Update package metadata and runtime dependencies[\s\S]*- \[x\] Add only the runtime dependencies/);
  assert.match(taskSpec, /### 18\. Run validation and isolated smoke tests[\s\S]*- \[x\] Run repository validation/);
  assert.doesNotMatch(taskSpec, /- \[ \] /);
});

test("policy documentation covers supported sections and limitations", async () => {
  const policyDoc = await readProjectFile("docs/POLICY.md");
  const readme = await readProjectFile("README.md");
  for (const section of [
    "allowPaths",
    "denyPaths",
    "zeroAccessPaths",
    "readOnlyPaths",
    "noDeletePaths",
    "allowCommands",
    "denyCommands",
    "dangerousCommands",
    "protectedCredentialPaths",
  ]) {
    assert.match(policyDoc, new RegExp(section));
  }
  assert.match(policyDoc, /cloud CLIs \(`aws`, `az`, `gcloud`\)/);
  assert.match(policyDoc, /not an OS sandbox/i);
  assert.match(readme, /docs\/POLICY\.md/);
});

test("extension entry point is a small GuardMe registration layer", async () => {
  const extension = await readProjectFile("src/extension.ts");
  assert.match(extension, /export default function guardMe/);
  assert.match(extension, /registerLifecycle\(pi\)/);
  assert.match(extension, /registerGuard\(pi\)/);
  assert.match(extension, /registerGuidance\(pi\)/);
  assert.match(extension, /registerGuardMeCommand\(pi\)/);
  assert.doesNotMatch(extension, /registerExampleCommand/);
  assert.doesNotMatch(extension, /registerExampleTool/);
});
