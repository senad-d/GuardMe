import assert from "node:assert/strict";
import test from "node:test";

import { createBuiltInDefaultPolicy } from "../src/config/schema.ts";
import { mergePolicyConfigs, sourcePolicyConfig } from "../src/config/merge-policy.ts";
import { classifyShellCommand, commandRuleMatchCandidates, detectLocalScriptExecutions, extractExecutableCommandSegments, tokenizeShellCommand } from "../src/policy/commands.ts";
import { evaluatePolicyRequest } from "../src/policy/evaluate.ts";
import { prepareShellHeredocs } from "../src/policy/heredocs.ts";

const policy = mergePolicyConfigs([sourcePolicyConfig("builtin", createBuiltInDefaultPolicy())]).config;

function evaluate(command) {
  const classified = classifyShellCommand(command);
  return evaluatePolicyRequest({
    policy, commandClassification: classified,
    request: { toolName: "bash", action: classified.primaryAction, cwd: process.cwd(), command,
      targets: classified.targetPaths.map((raw) => ({ kind: "path", raw })) },
  });
}

const diagnostic = [
  "node --input-type=module <<'NODE'",
  "import { classifyShellCommand } from './src/policy/commands.ts';",
  "const samples = [",
  "  `mkdir -p .task21-verification; curl --head https://nodejs.org`,",
  "  `git diff --check; shasum -a 256 apps/api/package.json`",
  "];",
  "for (const [index, sample] of samples.entries()) {",
  "  console.log(JSON.stringify({index, command: classifyShellCommand(sample)}));",
  "}",
  "NODE",
].join("\n");

test("quoted Node diagnostics are one interpreter segment, not JavaScript-shaped shell commands", () => {
  assert.equal(evaluate(diagnostic).outcome, "allow");
  const segments = extractExecutableCommandSegments(diagnostic);
  assert.equal(segments.length, 1);
  assert.equal(segments[0].commandName, "node");
  assert.deepEqual(detectLocalScriptExecutions(diagnostic), []);
  assert.ok(!commandRuleMatchCandidates(diagnostic).some((candidate) => /^(?:import|curl|mkdir|shasum|git)\b/u.test(candidate)));
});

test("quoted heredoc data is not expanded by the shell", () => {
  for (const delimiter of ["'DATA'", '"DATA"', "\\DATA", "D'AT'A"]) {
    const command = `cat <<${delimiter}\n$(aws s3 ls)\n\`gcloud projects list\`\n.env\nDATA`;
    assert.equal(evaluate(command).outcome, "allow", delimiter);
    assert.deepEqual(extractExecutableCommandSegments(command).map((segment) => segment.commandName), ["cat"]);
  }
  assert.equal(evaluate("node <<'JS'\nconsole.log(`literal $(aws s3 ls)`);\nJS").outcome, "deny"); // Existing interpreter cloud-literal guard remains conservative.
});

test("interpreter stdin retains credential environment and destructive-code checks", () => {
  for (const body of [
    "console.log(process.env);",
    "require('fs').readFileSync('.env');",
    "require('child_process').execSync('aws s3 ls');",
  ]) {
    assert.equal(evaluate(`node <<'JS'\n${body}\nJS`).outcome, "deny", body);
  }
  assert.equal(evaluate("node <<'JS'\nrequire('fs').rmSync('build', {recursive: true});\nJS").outcome, "coach");
  assert.equal(evaluate("python3 <<'PY'\nprint(1 + 1)\nPY").outcome, "allow");
  assert.equal(evaluate("python3 <<'PY'\nimport os\nprint(os.environ)\nPY").outcome, "deny");
});

test("shell heredocs and trailing commands remain executable policy segments", () => {
  assert.equal(evaluate("bash -s <<'SH'\npwd\ngit diff --check\nSH").outcome, "allow");
  assert.equal(evaluate("sh <<'SH'\naws s3 ls\nSH").outcome, "deny");
  assert.equal(evaluate("sh <<'SH'\nrm -rf build\nSH").outcome, "coach");
  assert.equal(evaluate("node <<'JS'\nconsole.log(1)\nJS\naws s3 ls").outcome, "deny");
  assert.equal(evaluate("node <<'JS'; aws s3 ls\nconsole.log(1)\nJS").outcome, "deny");
  assert.equal(evaluate("node <<'JS' > .env\nconsole.log(1)\nJS").outcome, "deny");
  assert.equal(evaluate("node <<'JS' < .env\nconsole.log(1)\nJS").outcome, "deny");
});

test("multiple quoted documents and tab stripping preserve boundaries", () => {
  assert.equal(evaluate("cat <<'A' <<'B'\nfirst\nA\nsecond\nB\ngit diff --check").outcome, "allow");
  assert.equal(evaluate("node <<-'JS'\n\tconsole.log(1);\n\tJS\ngit diff --check").outcome, "allow");
  assert.equal(evaluate("node 0<<'JS'\nconsole.log(1);\nJS").outcome, "allow");
  assert.equal(evaluate("cat <<'A'; node <<'B'\ntext\nA\nconsole.log(1);\nB").outcome, "allow");
  assert.equal(evaluate("cat <<'A'\ntext\nA\ncat <<'B'\ntext\nB\ncat .env").outcome, "deny");
});

test("unsupported and malformed heredocs fail closed with an explicit diagnostic", () => {
  for (const command of [
    "node <<'JS'\nconsole.log(1);", "node <<'JS'\nconsole.log(1);\n JS",
    "cat <<'EOF'", "cat <<EOF\n$(aws s3 ls)\nEOF", "cat <<EOF\n'$(aws s3 ls)'\nEOF",
    "cat <<'EOF' | sh\naws s3 ls\nEOF", "node 3<<'EOF'\nconsole.log(1);\nEOF",
    "node -- <<'EOF'\nconsole.log(1);\nEOF", "unknown-tool <<'EOF'\ntext\nEOF",
  ]) {
    const classified = classifyShellCommand(command);
    assert.equal(classified.hardDenied, true, command);
    assert.match(classified.reason, /heredoc/i, command);
    assert.equal(evaluate(command).outcome, "deny", command);
  }
});

test("delimiter escape handling and analysis-only body quoting preserve literal text", () => {
  const body = String.raw`console.log("it's quoted: \\ and '");`;
  const tokens = tokenizeShellCommand(["node <<'JS'", body, "JS"].join("\n"));
  assert.equal(tokens[tokens.indexOf("--eval") + 1], body);
  assert.equal(evaluate("cat <<''\nbody\n\npwd").outcome, "allow");
  assert.equal(evaluate(String.raw`cat <<"E\$F"` + "\nbody\nE$F").outcome, "allow");
  for (const command of [
    "cat <<'OPEN\nbody\nOPEN", 'cat <<"OPEN\rbody\nOPEN',
    String.raw`cat <<"BAD\q"` + "\nbody\nBADq",
    String.raw`cat <<\ `, "cat <<" + String.fromCodePoint(92),
  ]) {
    assert.match(prepareShellHeredocs(command).error, /heredoc/i, command);
  }
});

test("quoted shell strings and comments are not mistaken for heredoc openers", () => {
  for (const command of ["printf '%s' '<<EOF'", 'node -e "console.log(\'<<EOF\')"', "echo hello # <<'EOF'"]) {
    assert.equal(prepareShellHeredocs(command).command, command);
    assert.equal(prepareShellHeredocs(command).error, undefined);
  }
});
