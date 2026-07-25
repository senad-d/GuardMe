import assert from "node:assert/strict";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  APPROVAL_MODE_ENV,
  DEFAULT_APPROVAL_MODE,
  resolveApprovalModeEnvironment,
} from "../src/config/approval-mode.ts";
import { loadGuardMeConfig } from "../src/config/load-config.ts";

async function createApprovalModePolicies(globalMode, localMode) {
  const root = await mkdtemp(join(tmpdir(), "guardme-approval-mode-"));
  const homeDir = join(root, "home");
  const cwd = join(root, "project");
  await mkdir(join(homeDir, ".pi", "agent"), { recursive: true });
  await mkdir(join(cwd, ".pi", "agent"), { recursive: true });
  if (globalMode !== undefined) {
    await writeFile(join(homeDir, ".pi", "agent", "guardme.yaml"), `version: 1\napprovalMode: ${globalMode}\n`, "utf8");
  }
  if (localMode !== undefined) {
    await writeFile(join(cwd, ".pi", "agent", "guardme.yaml"), `version: 1\napprovalMode: ${localMode}\n`, "utf8");
  }
  return { cwd, homeDir };
}

test("approval mode environment resolution defaults to auto and accepts all validated values", () => {
  assert.equal(resolveApprovalModeEnvironment(DEFAULT_APPROVAL_MODE, {}).mode, "auto");
  assert.equal(resolveApprovalModeEnvironment("auto", { [APPROVAL_MODE_ENV]: "interactive" }).mode, "interactive");
  assert.equal(resolveApprovalModeEnvironment("interactive", { [APPROVAL_MODE_ENV]: "block" }).mode, "block");
});

test("invalid approval mode environment values fail closed without echoing the raw value", () => {
  const invalidValue = "secret-invalid-mode";
  const resolved = resolveApprovalModeEnvironment("interactive", { [APPROVAL_MODE_ENV]: invalidValue });

  assert.equal(resolved.mode, "block");
  assert.equal(resolved.diagnostics[0]?.code, "config.invalidApprovalModeEnvironment");
  assert.doesNotMatch(resolved.diagnostics[0]?.message ?? "", new RegExp(invalidValue));
});

test("trusted project approval mode overrides global mode and environment overrides both", async () => {
  const { cwd, homeDir } = await createApprovalModePolicies("interactive", "block");

  const trusted = await loadGuardMeConfig({ cwd, homeDir, environment: {} });
  const untrusted = await loadGuardMeConfig({ cwd, homeDir, loadLocalPolicy: false, environment: {} });
  const environmentOverride = await loadGuardMeConfig({
    cwd,
    homeDir,
    environment: { [APPROVAL_MODE_ENV]: "interactive" },
  });

  assert.equal(trusted.config.approvalMode, "block");
  assert.equal(untrusted.config.approvalMode, "interactive");
  assert.equal(environmentOverride.config.approvalMode, "interactive");
});

test("invalid project and environment approval modes resolve to block with diagnostics", async () => {
  const { cwd, homeDir } = await createApprovalModePolicies("interactive", "invalid-project-mode");

  const invalidProject = await loadGuardMeConfig({ cwd, homeDir, environment: {} });
  const invalidEnvironment = await loadGuardMeConfig({
    cwd,
    homeDir,
    loadLocalPolicy: false,
    environment: { [APPROVAL_MODE_ENV]: "invalid-environment-mode" },
  });

  assert.equal(invalidProject.config.approvalMode, "block");
  assert.ok(invalidProject.diagnostics.some((diagnostic) => diagnostic.code === "config.invalidApprovalMode"));
  assert.equal(invalidEnvironment.config.approvalMode, "block");
  assert.ok(invalidEnvironment.diagnostics.some((diagnostic) => diagnostic.code === "config.invalidApprovalModeEnvironment"));
});
