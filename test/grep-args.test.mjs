import assert from "node:assert/strict";
import test from "node:test";

import { classifyShellCommand } from "../src/policy/commands.ts";
import { credentialScanArgs, splitGrepArgs } from "../src/policy/grep-args.ts";

test("grep and rg split search text from file operands", () => {
  assert.deepEqual(splitGrepArgs(["-n", "\\.env", "src"], true).operands, ["src"]);
  assert.deepEqual(splitGrepArgs(["-t", "ts", "\\.env", "src"], true).operands, ["src"]);
  assert.deepEqual(splitGrepArgs(["-A", "3", "x", "file"], false).operands, ["file"]);
  assert.deepEqual(splitGrepArgs(["-e", "x", "a", "b"], false).operands, ["a", "b"]);
  assert.deepEqual(splitGrepArgs(["--files", "src"], true).operands, ["src"]);
  assert.deepEqual(splitGrepArgs(["-f", "pats.txt", "src"], true).optionFiles, ["pats.txt"]);
  assert.deepEqual(splitGrepArgs(["--color", "x", "file"], false).operands, ["file"]);
});

test("credential scan skips search text and exclusions but keeps include globs and path-like patterns", () => {
  assert.deepEqual(credentialScanArgs("rg", ["-n", "\\.env|token", "--glob", "!.env", "src"], true), ["-n", "--glob", "src"]);
  assert.deepEqual(credentialScanArgs("rg", ["--files", "-g", ".npmrc"], true), ["--files", "-g", ".npmrc"]);
  assert.deepEqual(credentialScanArgs("rg", ["~/.ssh", "src"], true), ["~/.ssh", "src"]);
  assert.deepEqual(credentialScanArgs("trivy", ["fs", "--skip-files", ".env", "--skip-dirs=.ssh", "."], false), ["fs", "--skip-files", "."]);
});

test("content searches for credential words are allowed while credential file reads stay hard-denied", () => {
  for (const command of ["rg -n '\\.env|GITHUB_TOKEN' src", "grep -n '.env' README.md", "rg -t ts 'process\\.env' src", "trivy fs --skip-files .env ."]) {
    assert.equal(classifyShellCommand(command).hardDenied, false, command);
  }
  for (const command of ["rg -n token .env", "grep -e x .env", "grep -A 3 x ~/.aws/credentials", "rg -f .env src", "rg --files -g '.npmrc'", "grep --color x ~/.ssh/id_rsa"]) {
    assert.equal(classifyShellCommand(command).hardDenied, true, command);
  }
  assert.match(classifyShellCommand("cat .env").reason, /'\.env'/);
});
