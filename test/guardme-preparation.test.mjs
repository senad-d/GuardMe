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
