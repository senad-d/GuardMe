import assert from "node:assert/strict";
import test from "node:test";

import { detectLocalScriptExecutions } from "../src/policy/commands.ts";
import { extractScriptCommandsFromContent, isCommandBearingPath, redactedCommandPreview } from "../src/policy/script-content.ts";

test("script content extraction detects shell scripts and redacts previews", () => {
  const result = extractScriptCommandsFromContent({
    path: "scripts/audit.sh",
    content: "#!/usr/bin/env bash\n# comment\naws sts get-caller-identity --token secret-value\necho done\n",
  });

  assert.equal(result.commandBearing, true);
  assert.equal(result.commands.length, 2);
  assert.equal(result.commands[0].lineStart, 3);
  assert.match(result.commands[0].preview, /--token <redacted>/);
});

test("script content extraction covers package json Dockerfile Makefile and CI run blocks", () => {
  const packageJson = extractScriptCommandsFromContent({
    path: "package.json",
    content: JSON.stringify({ scripts: { audit: "az account show", test: "npm test" } }, null, 2),
  });
  const dockerfile = extractScriptCommandsFromContent({ path: "Dockerfile", content: "FROM node\nRUN gcloud projects list\n" });
  const makefile = extractScriptCommandsFromContent({ path: "Makefile", content: "audit:\n\tcat ~/.aws/credentials\n" });
  const workflow = extractScriptCommandsFromContent({
    path: ".github/workflows/ci.yml",
    content: "jobs:\n  test:\n    steps:\n      - run: |\n          echo ok\n          aws sts get-caller-identity\n",
  });
  const workflowWithChomping = extractScriptCommandsFromContent({
    path: ".github/workflows/release.yml",
    content: "jobs:\n  release:\n    steps:\n      - run: |+ # keep trailing newline\n          echo release\n          gcloud projects list\n",
  });

  assert.deepEqual(packageJson.commands.map((command) => command.command), ["az account show", "npm test"]);
  assert.equal(dockerfile.commands[0]?.command, "gcloud projects list");
  assert.equal(makefile.commands[0]?.command, "cat ~/.aws/credentials");
  assert.deepEqual(workflow.commands.map((command) => command.command), ["echo ok", "aws sts get-caller-identity"]);
  assert.deepEqual(workflowWithChomping.commands.map((command) => command.command), ["echo release", "gcloud projects list"]);
});

test("redacted command previews remove terminal control sequences", () => {
  const escape = String.fromCharCode(0x1b);
  const csi = String.fromCharCode(0x9b);

  assert.equal(redactedCommandPreview(`echo ${escape}[31mred${escape}[0m`), "echo red");
  assert.equal(redactedCommandPreview(`printf ${csi}31mred${csi}0m`), "printf red");
});

test("script content extraction reports uninspectable command-bearing content", () => {
  const binary = extractScriptCommandsFromContent({ path: "script.sh", content: "#!/bin/sh\n\0" });
  const unknownExecutable = extractScriptCommandsFromContent({ path: "bin/helper", content: "plain text", forceCommandBearing: true });

  assert.equal(binary.commandBearing, true);
  assert.match(binary.uninspectable?.reason ?? "", /binary/i);
  assert.equal(unknownExecutable.commandBearing, true);
  assert.match(unknownExecutable.uninspectable?.reason ?? "", /not a recognized text script/i);
});

test("local script execution detection covers direct and shell-wrapper forms", () => {
  assert.deepEqual(detectLocalScriptExecutions("./script --flag").map((execution) => execution.rawPath), ["./script"]);
  assert.deepEqual(detectLocalScriptExecutions("bash script.sh --flag").map((execution) => execution.rawPath), ["script.sh"]);
  assert.deepEqual(detectLocalScriptExecutions("bash -lc './nested.sh'").map((execution) => execution.rawPath), ["./nested.sh"]);
  assert.deepEqual(detectLocalScriptExecutions("open -a Brave https://example.com"), []);
});

test("command-bearing path detection is conservative", () => {
  assert.equal(isCommandBearingPath("deploy.sh"), true);
  assert.equal(isCommandBearingPath("Dockerfile"), true);
  assert.equal(isCommandBearingPath("README.md"), false);
});
