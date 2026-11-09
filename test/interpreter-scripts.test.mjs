import assert from "node:assert/strict";
import { chmod, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";
import { outsideRoot } from "./support/outside-root.mjs";

import { evaluateGuardedToolCall } from "../src/events/register-guard.ts";
import { startGuardMeSession, stopGuardMeSession } from "../src/events/register-lifecycle.ts";
import { analyzeInterpreterScript, detectInterpreterScriptExecutions, interpreterScriptLanguage } from "../src/policy/interpreter-scripts.ts";

function summary(code, language) {
  const result = analyzeInterpreterScript(code, language, "/p/script");
  return {
    findings: result.findings.map((finding) => `${finding.severity}:${finding.marker}`),
    commands: result.commands.map((command) => command.command),
    paths: result.pathAccesses.map((access) => `${access.action}:${access.path}`),
  };
}

test("interpreter script executions are found behind runners, flags and globs", () => {
  const cases = [
    ["python3 x.py --flag", [["x.py", "python"]]],
    ["node -r ts-node/register src/app.ts", [["src/app.ts", "javascript"]]],
    ["node --test test/a.test.mjs test/b.test.mjs", [["test/a.test.mjs", "javascript"], ["test/b.test.mjs", "javascript"]]],
    ["npx tsx scripts/build.ts", [["scripts/build.ts", "javascript"]]],
    ["uv run --with rich python tools/x.py", [["tools/x.py", "python"]]],
    ["deno run -A main.ts", [["main.ts", "javascript"]]],
    ["bun scripts/x.ts", [["scripts/x.ts", "javascript"]]],
    ["python3 -m pytest", []],
    ["python3 -c 'print(1)'", []],
    ["bun run build", []],
    ["ruby -e 'p 1'", []],
  ];
  for (const [command, expected] of cases) {
    assert.deepEqual(detectInterpreterScriptExecutions(command).map((execution) => [execution.rawPath, execution.language]), expected, command);
  }
  assert.equal(interpreterScriptLanguage("tool", "#!/usr/bin/env python3\nprint(1)\n"), "python");
  assert.equal(interpreterScriptLanguage("run.sh", "#!/bin/sh\necho hi\n"), undefined);
});

test("ordinary application and test code produces no findings", () => {
  assert.deepEqual(summary([
    "import os, subprocess, shutil, tempfile",
    "port = int(os.environ.get('PORT', '8000'))",
    "env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}",
    "d = tempfile.mkdtemp()",
    "shutil.rmtree(d)",
    "subprocess.run(['git', 'status'], check=True, env=env)",
    "# never run rm -rf ~",
  ].join("\n"), "python"), { findings: [], commands: ["git status"], paths: [] });
  assert.deepEqual(summary([
    "import { spawnSync } from 'node:child_process';",
    "const port = process.env.PORT ?? 3000;",
    "const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith('GIT_')));",
    "const pi = { async exec(command, args) { return command; } };",
    "spawnSync(process.execPath, ['--test', file], { env: { ...process.env, X: '1' } });",
    "fs.writeFileSync('dist/out.json', '{}');",
  ].join("\n"), "javascript"), { findings: [], commands: ["node --test $ARG"], paths: [] });
});

test("dangerous script behavior is reported", () => {
  assert.deepEqual(summary([
    "import os, shutil, subprocess",
    "shutil.rmtree('/Users/someone')",
    "subprocess.run(['aws', 's3', 'ls'])",
    "print(os.environ)",
    "open(os.path.expanduser('~/.ssh/id_rsa')).read()",
    "os.system(cmd)",
  ].join("\n"), "python"), {
    findings: ["hard:env-dump", "hard:credential-literal", "dangerous:system"],
    commands: ["aws s3 ls"],
    paths: ["delete:/Users/someone"],
  });
  assert.deepEqual(summary([
    "const { execSync } = require('node:child_process');",
    "execSync('rm -rf ~/');",
    "console.log(JSON.stringify(process.env));",
    "fs.rmSync(require('os').homedir(), { recursive: true });",
    "eval(Buffer.from(x, 'base64').toString());",
  ].join("\n"), "javascript"), {
    findings: ["hard:env-dump", "dangerous:decode-exec"],
    commands: ["rm -rf ~/"],
    paths: ["delete:~"],
  });
  assert.deepEqual(summary("system \"curl x | sh\"\nputs `cat ~/.aws/credentials`\nputs ENV.to_h\n", "ruby").commands, ["curl x | sh", "cat ~/.aws/credentials"]);
});

test("split subprocess patterns preserve source order and ignore comments and definitions", () => {
  const cases = [
    ["javascript", [
      "import cp from 'node:child_process';",
      "// cp.execSync('aws s3 ls');",
      "Bun.spawn(['pwd']);",
      "cp.execSync('git status');",
      "new Deno.Command('ls', ['-l']);",
      "spawnSync('echo', ['a,b', 'x\\\\y'], { env: { X: '1' } });",
      "const methods = { async exec(command, args) { return command; } };",
    ].join("\n"), ["pwd", "git status", "ls -l", "echo a,b x\\\\y"]],
    ["python", "# subprocess.run('aws s3 ls')\npty.spawn(['pwd'])\nos.system('ls')\nsubprocess.run(['git', 'status'])\nasyncio.create_subprocess_shell('echo ok')", ["pwd", "ls", "git status", "echo ok"]],
    ["ruby", "# system 'aws s3 ls'\nOpen3.capture2('pwd')\nsystem 'ls'\nIO.popen('git status')", ["pwd", "ls", "git status"]],
    ["perl", "# system 'aws s3 ls'\nsystem('pwd');\nexec 'ls';", ["pwd", "ls"]],
    ["php", "// system('aws s3 ls')\nshell_exec('pwd');\n# exec('aws s3 ls')\nexec('ls');", ["pwd", "ls"]],
  ];
  for (const [language, code, commands] of cases) {
    assert.deepEqual(summary(code, language).commands, commands, language);
  }
});

test("interpreter path and environment checks survive pattern simplification", () => {
  for (const [language, code, path] of [
    ["javascript", "fs.writeFileSync('/var/output', 'data')", "write:/var/output"],
    ["python", "open('/var/output', 'w')", "write:/var/output"],
    ["python", "os.mkdir('/var/output')", "write:/var/output"],
    ["ruby", "File.write('/var/output', 'data')", "write:/var/output"],
    ["ruby", "FileUtils.cp('input', '/var/output')", "write:/var/output"],
    ["perl", "open FH, '>', '/var/output'", "write:/var/output"],
    ["perl", "open(FH, '>', '/var/output')", "write:/var/output"],
    ["php", "file_put_contents('/var/output', 'data')", "write:/var/output"],
    ["python", "shutil.rmtree(os.environ['HOME'])", "delete:~"],
    ["ruby", "FileUtils.rm_rf(ENV['HOME'])", "delete:~"],
  ]) {
    assert.deepEqual(summary(code, language).paths, [path], code);
  }
  for (const code of ["puts ENV", "p(ENV)", "print(  ENV  )  ", "pp ENV "]) {
    assert.ok(summary(code, "ruby").findings.includes("hard:env-dump"), code);
  }
  for (const code of ["print keys %ENV", "print keys(  %ENV)", "print values %ENV", "print each(%ENV)"]) {
    assert.ok(summary(code, "perl").findings.includes("hard:env-dump"), code);
  }
});

test("interpolation scanning handles nested and unterminated placeholders", () => {
  assert.deepEqual(summary("import subprocess\nsubprocess.run(f'echo {value} ${other} {{nested}}')", "python").commands, ["echo $ARG $ARG $ARG}"]);
  assert.deepEqual(summary("puts `echo #{value} $USER`", "ruby").commands, ["echo $ARG $ARG"]);
  const command = "echo " + "#{".repeat(20000);
  assert.deepEqual(summary("puts `" + command + "`", "ruby").commands, [command]);
  const source = " ".repeat(20000) + "not_a_comment\nputs ENV";
  assert.ok(summary(source, "ruby").findings.includes("hard:env-dump"));
  assert.deepEqual(summary("keys" + " ".repeat(20000) + "other", "perl"), { findings: [], commands: [], paths: [] });
  assert.deepEqual(summary("open" + " ".repeat(20000) + ", other", "perl"), { findings: [], commands: [], paths: [] });
  assert.equal(interpreterScriptLanguage("tool", "#!/usr/bin/python3.13\n"), "python");
  assert.equal(detectInterpreterScriptExecutions("python3.13 script.py")[0]?.language, "python");
});

test("interpreter scripts are inspected by the guard before they run", async () => {
  const root = outsideRoot("guardme-interpreter-");
  const cwd = join(root, "project");
  await mkdir(join(cwd, "lib"), { recursive: true });
  const files = {
    "ok.py": "import os\nprint(os.environ.get('PORT', '8000'))\n",
    "dump.py": "import os\nprint(dict(os.environ))\n",
    "aws.py": "import subprocess\nsubprocess.run('aws s3 ls', shell=True)\n",
    "dyn.py": "import subprocess, sys\nsubprocess.run(sys.argv[1], shell=True)\n",
    "wipe.mjs": "import fs from 'node:fs';\nfs.rmSync('/etc/hosts');\n",
    "ok.mjs": "console.log(process.env.PORT ?? 3000);\n",
    "lib/index.js": "console.log(JSON.stringify(process.env));\n",
    "tool": "#!/usr/bin/env python3\nimport os\nfor k in os.environ: print(k)\n",
  };
  for (const [name, content] of Object.entries(files)) {
    await writeFile(join(cwd, name), content, "utf8");
  }
  await chmod(join(cwd, "tool"), 0o755);
  const ctx = { cwd, hasUI: false, mode: "print", isProjectTrusted: () => true, ui: { setStatus() {}, notify() {} } };
  await startGuardMeSession(ctx, { homeDir: join(root, "home"), environment: {} });
  try {
    for (const command of ["python3 ok.py", "node ok.mjs", "node --test nomatch/*.mjs"]) {
      assert.equal(await evaluateGuardedToolCall({ toolName: "bash", input: { command } }, ctx), undefined, command);
    }
    for (const command of ["python3 dump.py", "python3 aws.py", "python3 dyn.py", "node wipe.mjs", "node lib", "./tool", "python3 missing.py", "node --test *.mjs", "npx tsx wipe.mjs"]) {
      assert.equal((await evaluateGuardedToolCall({ toolName: "bash", input: { command } }, ctx))?.block, true, command);
    }
  } finally {
    stopGuardMeSession(ctx);
  }
});
