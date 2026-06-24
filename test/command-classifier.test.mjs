import assert from "node:assert/strict";
import test from "node:test";

import {
  classifyShellCommand,
  commandRuleMatchCandidates,
  commandSegmentRuleMatchCandidates,
  detectLocalScriptExecutions,
  detectPackageScriptExecutions,
  extractExecutableCommandSegments,
  tokenizeShellCommand,
} from "../src/policy/commands.ts";

test("shell tokenizer preserves quoted command strings and redirection targets", () => {
  assert.deepEqual(tokenizeShellCommand("bash -lc 'aws sts get-caller-identity'"), ["bash", "-lc", "aws sts get-caller-identity"]);
  assert.deepEqual(tokenizeShellCommand("echo hello > out.txt"), ["echo", "hello", ">", "out.txt"]);
  assert.deepEqual(tokenizeShellCommand("cat<~/.ssh/id_rsa"), ["cat", "<", "~/.ssh/id_rsa"]);
  assert.deepEqual(tokenizeShellCommand("echo ok\naws sts get-caller-identity"), ["echo", "ok", ";", "aws", "sts", "get-caller-identity"]);
});

test("cloud CLIs are hard denied through common wrappers", () => {
  for (const command of [
    "aws sts get-caller-identity",
    "command aws s3 ls",
    "command -p aws s3 ls",
    "env AWS_PROFILE=prod gcloud projects list",
    "env -C /tmp aws sts get-caller-identity",
    "env -S 'aws sts get-caller-identity'",
    "env --split-string='az account show'",
    "sudo -u root aws sts get-caller-identity",
    "sudo -p 'Password:' aws sts get-caller-identity",
    "doas -u root az account show",
    "bash -lc 'az account show'",
    "bash -cl 'aws sts get-caller-identity'",
    "bash -euc 'gcloud projects list'",
    "aw\\\ns sts get-caller-identity",
    "eval 'aws sts get-caller-identity'",
    "exec aws sts get-caller-identity",
    "$'aws' sts get-caller-identity",
    "$'\\x61ws' sts get-caller-identity",
    "$'\\141z' account show",
    "a$'w's sts get-caller-identity",
    "a$'\\167's sts get-caller-identity",
    "aw${empty}s sts get-caller-identity",
    "$(echo aws) sts get-caller-identity",
    "`echo aws` sts get-caller-identity",
    "python -c \"import os; os.system('aws sts get-caller-identity')\"",
    "node -e \"require('child_process').execSync('gcloud projects list')\"",
    "ruby -e \"system('az account show')\"",
    "npx aws sts get-caller-identity",
    "npx aws -c config",
    "npm exec -- aws sts get-caller-identity",
    "npm exec aws -- sts get-caller-identity",
    "pnpm dlx aws sts get-caller-identity",
    "yarn dlx gcloud projects list",
    "bunx az account show",
    "bun x gcloud projects list",
  ]) {
    const classified = classifyShellCommand(command);
    assert.equal(classified.hardDenied, true, command);
    assert.equal(classified.risk, "hard-denied", command);
    assert.equal(classified.primaryAction, "shell", command);
  }
});

test("cloud CLIs are hard denied inside shell substitutions", () => {
  for (const command of [
    "echo $(aws sts get-caller-identity)",
    "printf '%s' `az account show`",
    "diff <(gcloud projects list) allowed.txt",
  ]) {
    const classified = classifyShellCommand(command);
    assert.equal(classified.hardDenied, true, command);
    assert.equal(classified.risk, "hard-denied", command);
    assert.match(classified.reason, /Nested .*substitution/, command);
  }

  const quoted = classifyShellCommand("printf '%s' '$(aws sts get-caller-identity)'");
  assert.equal(quoted.hardDenied, false);
});

test("cloud CLIs are hard denied through command separators", () => {
  for (const command of [
    "echo ok\naws sts get-caller-identity",
    "echo ok & az account show",
    "printf done; gcloud projects list",
    "(aws sts get-caller-identity)",
    "{ aws sts get-caller-identity; }",
    "if true; then aws sts get-caller-identity; fi",
  ]) {
    const classified = classifyShellCommand(command);
    assert.equal(classified.hardDenied, true, command);
    assert.equal(classified.risk, "hard-denied", command);
  }
});

test("cloud CLIs are hard denied through command-executing wrappers", () => {
  for (const command of [
    "xargs -I{} aws s3 ls {}",
    "find . -name '*' -exec gcloud projects list ;",
    "find . -name '*' -exec gcloud projects list \\;",
    "find . -name '*' -exec echo {} \\; -exec aws sts get-caller-identity \\;",
    "find . -name '*' -exec bash -lc 'aws sts get-caller-identity' ;",
    "watch -n 1 az account show",
    "timeout --kill-after 1s 5s aws sts get-caller-identity",
    "nice -n 10 aws s3 ls",
    "xargs bash -lc 'az account show'",
  ]) {
    const classified = classifyShellCommand(command);
    assert.equal(classified.hardDenied, true, command);
    assert.equal(classified.risk, "hard-denied", command);
    assert.match(classified.reason, /wrapper/i, command);
  }
});

test("command rule candidates normalize absolute executable paths", () => {
  assert.ok(commandRuleMatchCandidates("/usr/bin/sudo ls").includes("sudo ls"));
  assert.ok(commandRuleMatchCandidates("env -- /usr/bin/sudo ls").includes("sudo ls"));
  assert.ok(commandRuleMatchCandidates("command /usr/bin/sudo ls").includes("sudo ls"));
  assert.ok(commandRuleMatchCandidates("/opt/homebrew/bin/terraform plan").includes("terraform plan"));
});

test("segment rule candidates include prefix-unwrapped executables without recursing into command runners", () => {
  assert.ok(commandSegmentRuleMatchCandidates("env -- /bin/ls -lh").includes("ls -lh"));
  assert.ok(commandSegmentRuleMatchCandidates("command /usr/bin/sudo ls").includes("sudo ls"));
  assert.deepEqual(commandSegmentRuleMatchCandidates("find . -exec rm -rf {} \\;").filter((candidate) => candidate.startsWith("rm")), []);
});

test("executable command segments include compounds, substitutions, and find exec commands", () => {
  assert.deepEqual(extractExecutableCommandSegments("pwd && ls -lh").map((segment) => segment.normalizedText), ["pwd", "ls -lh"]);

  const substitutionSegments = extractExecutableCommandSegments("echo $(rm -rf build)");
  assert.ok(substitutionSegments.some((segment) => segment.normalizedText === "rm -rf build" && segment.sourceKind === "substitution"));

  const findSegments = extractExecutableCommandSegments("find . -exec rm -rf {} \\;");
  assert.ok(findSegments.some((segment) => segment.normalizedText.startsWith("find . -exec")));
  assert.ok(findSegments.some((segment) => segment.normalizedText === "rm -rf" && segment.sourceKind === "find-exec"));
});

test("disk formatting and raw block-device operations are hard denied", () => {
  for (const command of ["diskutil eraseDisk JHFS+ Untitled /dev/disk2", "mkfs.ext4 /dev/sdb1", "sudo dd if=input.img of=/dev/disk2"]) {
    const classified = classifyShellCommand(command);
    assert.equal(classified.hardDenied, true, command);
    assert.equal(classified.risk, "hard-denied", command);
  }
});

test("compound command classifications keep guarded paths from lower-priority segments", () => {
  const classified = classifyShellCommand("rm -rf build && cat /etc/passwd");

  assert.equal(classified.kind, "dangerous");
  assert.equal(classified.primaryAction, "delete");
  assert.deepEqual(classified.targetPaths, ["build", "/etc/passwd"]);
});

test("recursive force deletion and .git deletion are detected", () => {
  for (const command of ["rm -rf build", "rm -r -f build", "rm --recursive --force build", "rm -R --force build"]) {
    const recursive = classifyShellCommand(command);
    assert.equal(recursive.kind, "dangerous", command);
    assert.equal(recursive.primaryAction, "delete", command);
    assert.equal(recursive.requiresUserDecision, true, command);
    assert.deepEqual(recursive.targetPaths, ["build"], command);
  }

  for (const command of ["rm -fr .git", "rm -rf .git/", "rm -r .git/config"]) {
    const gitDelete = classifyShellCommand(command);
    assert.equal(gitDelete.hardDenied, true, command);
    assert.equal(gitDelete.primaryAction, "delete", command);
  }
});

test("credential reads are detected without reading files", () => {
  for (const command of [
    "cat .env",
    "cat .env*",
    "grep token ~/.aws/credentials",
    "ggrep token ~/.aws/credentials",
    "less ~/.ssh/id_rsa",
    "cat<~/.ssh/id_rsa",
    "cat < .env > copied.txt",
    "base64 ~/.ssh/id_rsa",
    "sed -n p ~/.netrc",
    "python -c \"print(open('.env').read())\"",
    "node -e \"require('fs').readFileSync('.env','utf8')\"",
    "ruby -e \"File.read('~/.ssh/id_rsa')\"",
  ]) {
    const classified = classifyShellCommand(command);
    assert.equal(classified.credentialAccess, true, command);
    assert.ok(["dangerous", "hard-denied"].includes(classified.risk), command);
    assert.equal(classified.primaryAction, "read", command);
  }

  const copied = classifyShellCommand("dd if=.env of=copied.env");
  assert.equal(copied.credentialAccess, true);
  assert.equal(copied.risk, "dangerous");
  assert.equal(copied.primaryAction, "write");

  const envExample = classifyShellCommand("cat .env.example");
  assert.equal(envExample.credentialAccess, false);
  assert.equal(envExample.primaryAction, "read");

  const shellTest = classifyShellCommand("[ -e .env ]");
  assert.equal(shellTest.hardDenied, false);
  assert.equal(shellTest.credentialAccess, true);
  assert.equal(shellTest.primaryAction, "list");

  const redirectedGrep = classifyShellCommand("grep root < /etc/passwd");
  assert.equal(redirectedGrep.primaryAction, "read");
  assert.deepEqual(redirectedGrep.targetPaths, ["/etc/passwd"]);

  const listedCredentialGlob = classifyShellCommand("ls .SSH*");
  assert.equal(listedCredentialGlob.credentialAccess, true);
  assert.equal(listedCredentialGlob.primaryAction, "list");
});

test("common shell commands map to read list write edit move and rename actions", () => {
  assert.equal(classifyShellCommand("ls src").primaryAction, "list");
  assert.equal(classifyShellCommand("find -name '*.ts'").targetPaths[0], ".");
  assert.equal(classifyShellCommand("grep -R value").targetPaths[0], ".");
  assert.equal(classifyShellCommand("ggrep -R value").targetPaths[0], ".");
  assert.equal(classifyShellCommand("cat README.md").primaryAction, "read");
  assert.equal(classifyShellCommand("echo hello > out.txt").primaryAction, "write");
  assert.equal(classifyShellCommand("cp README.md README.copy").primaryAction, "write");
  assert.equal(classifyShellCommand("tar -cf archive.tar src").primaryAction, "write");
  assert.equal(classifyShellCommand("dd if=README.md of=README.copy").primaryAction, "write");
  assert.equal(classifyShellCommand("touch out.txt").primaryAction, "write");
  assert.equal(classifyShellCommand("sed -i s/a/b/ file.txt").primaryAction, "edit");
  assert.equal(classifyShellCommand("chmod 600 file.txt").primaryAction, "edit");
  assert.equal(classifyShellCommand("mv src/a.ts lib/a.ts").primaryAction, "move");
  assert.equal(classifyShellCommand("mv src/a.ts src/b.ts").primaryAction, "rename");
});

test("local script execution targets are detected without treating GUI launchers as scripts", () => {
  assert.deepEqual(detectLocalScriptExecutions("./audit.sh --output report.txt").map((execution) => execution.rawPath), ["./audit.sh"]);
  assert.deepEqual(detectLocalScriptExecutions("bash audit.sh --output report.txt").map((execution) => execution.rawPath), ["audit.sh"]);
  assert.deepEqual(detectLocalScriptExecutions("zsh ./audit --output report.txt").map((execution) => execution.rawPath), ["./audit"]);
  assert.deepEqual(detectLocalScriptExecutions("bash -lc './audit.sh --output report.txt'").map((execution) => execution.rawPath), ["./audit.sh"]);
  assert.deepEqual(detectLocalScriptExecutions("open -a Brave https://example.com"), []);
  assert.deepEqual(detectLocalScriptExecutions("/usr/bin/sudo ls"), []);
});

test("package script execution targets are detected through package manager aliases", () => {
  assert.deepEqual(detectPackageScriptExecutions("npm test -- --watch").map((execution) => execution.scriptName), ["test"]);
  assert.deepEqual(detectPackageScriptExecutions("npm run test -- --watch").map((execution) => execution.scriptName), ["test"]);
  assert.deepEqual(detectPackageScriptExecutions("bash -lc 'npm run test'").map((execution) => execution.scriptName), ["test"]);
  assert.deepEqual(detectPackageScriptExecutions("pnpm run build").map((execution) => execution.scriptName), ["build"]);
  assert.deepEqual(detectPackageScriptExecutions("yarn test").map((execution) => execution.scriptName), ["test"]);
  assert.deepEqual(detectPackageScriptExecutions("bun run test").map((execution) => execution.scriptName), ["test"]);
  assert.deepEqual(detectPackageScriptExecutions("npm exec aws sts get-caller-identity"), []);
});

test("package script execution targets honor package-manager cwd options", () => {
  assert.deepEqual(
    detectPackageScriptExecutions("npm --prefix packages/app test").map((execution) => [execution.scriptName, execution.rawPath]),
    [["test", "packages/app/package.json"]],
  );
  assert.deepEqual(
    detectPackageScriptExecutions("npm --prefix=packages/app run build").map((execution) => [execution.scriptName, execution.rawPath]),
    [["build", "packages/app/package.json"]],
  );
  assert.deepEqual(
    detectPackageScriptExecutions("pnpm -C packages/app run build").map((execution) => [execution.scriptName, execution.rawPath]),
    [["build", "packages/app/package.json"]],
  );
  assert.deepEqual(
    detectPackageScriptExecutions("yarn --cwd packages/app test").map((execution) => [execution.scriptName, execution.rawPath]),
    [["test", "packages/app/package.json"]],
  );
  assert.deepEqual(
    detectPackageScriptExecutions("bash -lc 'bun --cwd packages/app run test'").map((execution) => [execution.scriptName, execution.rawPath]),
    [["test", "packages/app/package.json"]],
  );
  assert.deepEqual(
    detectPackageScriptExecutions("npm test --prefix packages/app").map((execution) => [execution.scriptName, execution.rawPath]),
    [["test", "packages/app/package.json"]],
  );
  assert.deepEqual(
    detectPackageScriptExecutions("npm run test -- --prefix ignored").map((execution) => [execution.scriptName, execution.rawPath]),
    [["test", "package.json"]],
  );
});

test("ambiguous destructive commands require user decision", () => {
  for (const command of ["rsync -a --delete src/ dest/", "rsync -a --delete-after src/ dest/", "find . -delete", "git clean -fdx"]) {
    const classified = classifyShellCommand(command);
    assert.equal(classified.risk, "dangerous", command);
    assert.equal(classified.requiresUserDecision, true, command);
  }
});
