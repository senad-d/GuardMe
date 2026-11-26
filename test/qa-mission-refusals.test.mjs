import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { outsideRoot } from "./support/outside-root.mjs";

import { createBuiltInDefaultPolicy } from "../src/config/schema.ts";
import { mergePolicyConfigs, sourcePolicyConfig } from "../src/config/merge-policy.ts";
import { mapToolCallToPolicyRequest } from "../src/events/register-guard.ts";
import { evaluatePolicyRequest } from "../src/policy/evaluate.ts";

// Regressions from the Mission refusal review 2026-11-26: 116 refusals on the
// home server and mislocaltest, about 100 of them harmless. Each harmless form
// sits next to the form that must stay refused.

const policy = mergePolicyConfigs([sourcePolicyConfig("builtin", createBuiltInDefaultPolicy())]).config;
const cwd = outsideRoot("guardme-refusals-");
// A per-run directory such as /tmp/mission/<project>/<objective>.
const base = await mkdtemp(join(tmpdir(), "guardme-refusals-"));
const T = join(base, "mission", "p", "8");
await mkdir(T, { recursive: true, mode: 0o700 });
process.env.TMPDIR = T;
test.after(() => rm(base, { recursive: true, force: true }));

async function outcome(command, call = { toolName: "bash", input: { command } }) {
  const mapped = await mapToolCallToPolicyRequest(call, cwd);
  assert.ok("request" in mapped, JSON.stringify(mapped));
  return evaluatePolicyRequest({ policy, ...mapped }).outcome;
}

async function assertOutcomes(expected, commands) {
  for (const command of commands) {
    assert.equal(await outcome(command), expected, command);
  }
}

test("a name assigned a scratch path once is checked as that path", async () => {
  await assertOutcomes("allow", [
    `scratch=${T}/a\nnode server.js > "$scratch/server.log" 2>&1 &`,
    `S="$TMPDIR/sources"; curl -fsSL https://nodejs.org/x -o "$S/a.json"`,
    `log="${T}/s.log"\nnpm start >"$log" 2>&1 &\ntrap 'rm -f "$log"' EXIT`,
    `S="$TMPDIR/s"; B="$S/build"; mkdir -p "$B"; make > "$B/make.log" 2>&1`,
    `rsync -a --exclude node_modules src/ "${T}/copy/src/"`,
  ]);
  assert.equal(await outcome('d=/etc; cp x "$d/passwd"'), "deny");
  assert.equal(await outcome("rsync -a src/ /etc/x/"), "deny");
  for (const command of [`d=${T}/a; d=/etc; cp x "$d/passwd"`, `false && d=${T}/a; cp x "$d/passwd"`, `rsync -a --delete src/ ${T}/copy/`]) {
    assert.notEqual(await outcome(command), "allow", command);
  }
});

test("source files named after tokens or env are readable, credential files are not", async () => {
  const read = (path) => outcome("", { toolName: "read", input: { path } });
  assert.equal(await read("node_modules/eslint/lib/token-store/backward-token-cursor.js"), "allow");
  assert.equal(await outcome("cat src/.env.local.ts"), "allow");
  assert.equal(await outcome("python3 - <<'PY'\nprint('shape=mxgraph.aws4.resourceIcon;')\nPY"), "allow");
  assert.equal(await read("config/tokens.json"), "deny");
  await assertOutcomes("deny", ["cat .env.local", "cat config/secrets.json", "cat secrets/index.ts", "cat ~/.aws/credentials"]);
});

test("terminal drivers are judged by the command they run, read-only probes are allowed", async () => {
  await assertOutcomes("allow", [
    "fc-list | head -2",
    "ldconfig -p | grep X11",
    "dpkg-query -W xterm",
    "zutty -help | head -5",
    `patch --dry-run ${T}/a.ts ${T}/a.patch`,
    'script -qefc "stty cols 100 rows 36; npm run dev" /dev/null',
    `zutty -geometry 112x33 -e script --quiet --command "npm run dev -- --no-session" ${T}/pi.log`,
  ]);
  await assertOutcomes("deny", ["script -q -e -c 'aws s3 ls' /dev/null", "zutty -e aws s3 ls", "script -q /dev/null rm -rf /etc/x"]);
  for (const command of ['script -qefc "cowsay hi" /dev/null', "printf 'cowsay hi\\n' | script -q /dev/null", "ldconfig"]) {
    assert.equal(await outcome(command), "coach", command);
  }
});

test("a cloud CLI name in inline code counts only where the code starts a process", async () => {
  assert.equal(await outcome(`node --input-type=module -e 'for (const q of ["ec2", "aws lambda"]) console.log(q)'`), "allow");
  await assertOutcomes("deny", [
    `node -e 'require("child_process").execSync("aws s3 ls")'`,
    `python3 -c "import os; os.system('aws sts get-caller-identity')"`,
  ]);
});

test("a code heredoc may be piped on, a data heredoc may not", async () => {
  await assertOutcomes("allow", [
    `python3 - <<'PY' | tee "$TMPDIR/x.txt"\nprint(1)\nPY`,
    "echo hi && python3 - <<'PY'\nprint(1)\nPY",
  ]);
  await assertOutcomes("deny", [
    `python3 - <<'PY' | tee "$TMPDIR/x.txt"\nimport os\nos.system("aws s3 ls")\nPY`,
    "cat <<'EOF' | sh\naws s3 ls\nEOF",
    "cat x | python3 - <<'PY'\nprint(1)\nPY",
    "cat <<'A' | python3 - <<'PY'\nx\nA\nprint(1)\nPY",
  ]);
});

test('"$(command -v name)" in command position is that command', async () => {
  assert.equal(await outcome(`DISPLAY= PATH="${T}/empty" "$(command -v node)" node_modules/vitest/vitest.mjs run`), "allow");
  assert.equal(await outcome('"$(command -v aws)" s3 ls'), "deny");
  assert.notEqual(await outcome('rm "$(command -v node)"'), "allow");
});
