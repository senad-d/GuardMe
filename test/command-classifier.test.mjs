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

test("shell tokenizer preserves ANSI-C escapes and descriptor redirection tokens", () => {
  assert.deepEqual(tokenizeShellCommand("printf $'a\\n' 2>>err.log 1>&2 0<>input"), [
    "printf",
    "a\n",
    "2>>",
    "err.log",
    "1>&",
    "2",
    "0<>",
    "input",
  ]);
  assert.deepEqual(tokenizeShellCommand("echo a\\\r\nb"), ["echo", "ab"]);
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
    "npx --call='aws sts get-caller-identity'",
  ]) {
    const classified = classifyShellCommand(command);
    assert.equal(classified.hardDenied, true, command);
    assert.equal(classified.risk, "hard-denied", command);
    assert.match(classified.reason, /wrapper/i, command);
  }
});

test("classification precedence preserves guarded policy boundary decisions", () => {
  const credentialRead = classifyShellCommand("cat .env");
  assert.equal(credentialRead.hardDenied, true);
  assert.equal(credentialRead.primaryAction, "read");
  assert.equal(credentialRead.credentialAccess, true);

  const outsideRedirection = classifyShellCommand("echo ok > /tmp/guardme-output.txt");
  assert.equal(outsideRedirection.primaryAction, "write");
  assert.equal(outsideRedirection.risk, "dangerous");
  assert.equal(outsideRedirection.requiresUserDecision, true);

  const discardedStderr = classifyShellCommand("find src -type f 2>/dev/null");
  assert.equal(discardedStderr.primaryAction, "list");
  assert.equal(discardedStderr.risk, "low");
  assert.equal(discardedStderr.dangerous, false);
  assert.equal(discardedStderr.requiresUserDecision, false);
  assert.deepEqual(discardedStderr.targetPaths, ["src"]);

  const redirectedDelete = classifyShellCommand("find . -delete 2>/dev/null");
  assert.equal(redirectedDelete.primaryAction, "delete");
  assert.equal(redirectedDelete.risk, "dangerous");
  assert.equal(redirectedDelete.dangerous, true);

  const wrappedDelete = classifyShellCommand("bash -lc 'rm -rf build'");
  assert.equal(wrappedDelete.primaryAction, "delete");
  assert.equal(wrappedDelete.risk, "dangerous");

  const ambiguous = classifyShellCommand("git clean -fdx");
  assert.equal(ambiguous.kind, "ambiguous");
  assert.equal(ambiguous.requiresUserDecision, true);
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

test("credential detection handles long exact path boundaries", () => {
  const longPrefix = "a".repeat(50000);

  assert.equal(classifyShellCommand(`cat ${longPrefix}.env.example`).credentialAccess, false);
  assert.equal(classifyShellCommand(`cat ${longPrefix}/.env`).credentialAccess, true);
  assert.equal(classifyShellCommand(`python -c "print('${longPrefix}.env.example')"`).credentialAccess, false);
  assert.equal(classifyShellCommand(`python -c "print('${longPrefix} .env*')"`).credentialAccess, true);
});

test("environment dumps are hard denied while env wrapper forms stay classifiable", () => {
  for (const command of ["env", "env -0", "env | grep -i aws", "printenv", "printenv AWS_SECRET_ACCESS_KEY"]) {
    const classified = classifyShellCommand(command);
    assert.equal(classified.hardDenied, true, command);
    assert.equal(classified.risk, "hard-denied", command);
    assert.equal(classified.credentialAccess, true, command);
  }

  assert.equal(classifyShellCommand("env FOO=1 npm test").hardDenied, false);
  assert.equal(classifyShellCommand("env -S 'npm test'").hardDenied, false);
});

test("inline code that reads the process environment is hard denied", () => {
  for (const command of [
    "node -e 'console.log(process.env)'",
    "node -p process.env",
    "node --print process.env",
    "python3 -c \"import os; print(os.environ)\"",
  ]) {
    const classified = classifyShellCommand(command);
    assert.equal(classified.hardDenied, true, command);
    assert.equal(classified.credentialAccess, true, command);
  }

  assert.equal(classifyShellCommand("node -e 'console.log(1+1)'").hardDenied, false);
});

test("non-template .env variants are credential protected while templates stay usable", () => {
  for (const command of [
    "cat .env.local",
    "cat .env.production",
    "awk '{print}' .env.local",
    "node -e \"require('fs').readFileSync('.env.local','utf8')\"",
  ]) {
    const classified = classifyShellCommand(command);
    assert.equal(classified.hardDenied, true, command);
    assert.equal(classified.credentialAccess, true, command);
  }

  for (const command of ["cat .env.example", "cat .env.sample", "cat .env.template", "cat .env.dist"]) {
    assert.equal(classifyShellCommand(command).credentialAccess, false, command);
  }
});

test("awk and sed script operands are not treated as target paths", () => {
  assert.deepEqual(classifyShellCommand("awk '{print $1}' notes.txt").targetPaths, ["notes.txt"]);
  assert.deepEqual(classifyShellCommand("awk -F: '{print $1}' data.csv").targetPaths, ["data.csv"]);
  assert.deepEqual(classifyShellCommand("awk -f prog.awk data.csv").targetPaths, ["prog.awk", "data.csv"]);
  assert.deepEqual(classifyShellCommand("sed -n '$p' notes.txt").targetPaths, ["notes.txt"]);
  assert.deepEqual(classifyShellCommand("sed -e 's/a/b/' -e 's/c/d/' input.txt").targetPaths, ["input.txt"]);
});

test("find global symlink options preserve starting paths and classify -L conservatively", () => {
  const followed = classifyShellCommand("find -L node_modules/pkg -maxdepth 2 -type f");
  assert.deepEqual(followed.targetPaths, ["node_modules/pkg"]);
  assert.equal(followed.risk, "dangerous");
  assert.equal(followed.requiresUserDecision, true);
  assert.match(followed.reason, /symbolic links|symlink/i);

  assert.deepEqual(classifyShellCommand("find -H src -name '*.ts'").targetPaths, ["src"]);
  assert.deepEqual(classifyShellCommand("find -P src -name '*.ts'").targetPaths, ["src"]);
  assert.deepEqual(classifyShellCommand("find -L -maxdepth 2 -type f").targetPaths, ["."]);
  assert.deepEqual(classifyShellCommand("find -- -leading-dash -type f").targetPaths, ["-leading-dash"]);
});

test("common shell commands map to read list write edit move and rename actions", () => {
  assert.equal(classifyShellCommand("ls src").primaryAction, "list");
  assert.equal(classifyShellCommand("find -name '*.ts'").targetPaths[0], ".");
  assert.equal(classifyShellCommand("grep -R value").targetPaths[0], ".");
  assert.equal(classifyShellCommand("ggrep -R value").targetPaths[0], ".");
  assert.equal(classifyShellCommand("rg value").targetPaths[0], ".");
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

test("shell wrapper unwrapping preserves outer redirection targets", () => {
  const credentialRead = classifyShellCommand("bash -c 'cat' < ~/.ssh/id_rsa");
  assert.equal(credentialRead.hardDenied, true);
  assert.equal(credentialRead.credentialAccess, true);
  assert.ok(credentialRead.targetPaths.includes("~/.ssh/id_rsa"));

  const envRead = classifyShellCommand("env -S 'cat' < .env");
  assert.equal(envRead.hardDenied, true);
  assert.equal(envRead.credentialAccess, true);

  const redirectedWrite = classifyShellCommand("bash -c 'ls' > /etc/cron.d/evil");
  assert.equal(redirectedWrite.primaryAction, "write");
  assert.equal(redirectedWrite.risk, "dangerous");
  assert.equal(redirectedWrite.requiresUserDecision, true);
  assert.ok(redirectedWrite.targetPaths.includes("/etc/cron.d/evil"));

  const insideWrite = classifyShellCommand("bash -c 'ls' > out.txt");
  assert.ok(insideWrite.targetPaths.includes("out.txt"));
});

test("clobber redirection operators are tokenized and classified like plain redirections", () => {
  assert.deepEqual(tokenizeShellCommand("echo x >| out.txt"), ["echo", "x", ">|", "out.txt"]);
  assert.deepEqual(tokenizeShellCommand("echo x 1>| out.txt"), ["echo", "x", "1>|", "out.txt"]);

  for (const [clobbered, plain] of [
    ["echo x >| .env", "echo x > .env"],
    ["echo x 1>| .env", "echo x 1> .env"],
    ["echo x >| out.txt", "echo x > out.txt"],
  ]) {
    const clobberedClassified = classifyShellCommand(clobbered);
    const plainClassified = classifyShellCommand(plain);
    assert.equal(clobberedClassified.hardDenied, plainClassified.hardDenied, clobbered);
    assert.equal(clobberedClassified.primaryAction, plainClassified.primaryAction, clobbered);
    assert.equal(clobberedClassified.risk, plainClassified.risk, clobbered);
    assert.deepEqual(clobberedClassified.targetPaths, plainClassified.targetPaths, clobbered);
  }
});

test("unexpanded shell variable mutation targets classify as outside-ish", () => {
  const redirected = classifyShellCommand("echo hi > $HOME/.zshenv");
  assert.equal(redirected.risk, "dangerous");
  assert.equal(redirected.requiresUserDecision, true);
});

test("source and dot execution are detected as local script executions", () => {
  const sourced = detectLocalScriptExecutions("source ./deploy.sh");
  assert.deepEqual(sourced.map((execution) => [execution.rawPath, execution.shellHint]), [["./deploy.sh", true]]);

  const dotted = detectLocalScriptExecutions(". scripts/env.sh");
  assert.deepEqual(dotted.map((execution) => [execution.rawPath, execution.shellHint]), [["scripts/env.sh", true]]);
});

test("destructive inline code is detected across interpreters", () => {
  for (const command of [
    "python3 -c \"import shutil; shutil.rmtree('build')\"",
    "python2 -c \"import shutil; shutil.rmtree('build')\"",
    "ruby -e \"FileUtils.rm_rf('build')\"",
    "perl -e \"unlink('build/file')\"",
  ]) {
    const classified = classifyShellCommand(command);
    assert.equal(classified.risk, "dangerous", command);
    assert.equal(classified.requiresUserDecision, true, command);
  }
});

test("credential keyword matching uses word boundaries", () => {
  assert.equal(classifyShellCommand("cat src/tokenizer.ts").credentialAccess, false);
  assert.equal(classifyShellCommand("cat secretary-notes.md").credentialAccess, false);
  assert.equal(classifyShellCommand("cat api-tokens.txt").credentialAccess, true);
  assert.equal(classifyShellCommand("cat my-secret.yaml").credentialAccess, true);
});
