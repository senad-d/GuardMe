import assert from "node:assert/strict";
import test from "node:test";

import { expandMktempVariables } from "../src/policy/temp-variables.ts";

const env = { TMPDIR: "/tmp/run/" };
const cwd = "/work/project";

test("mktemp-assigned names resolve to their template path after an unconditional assignment", () => {
  for (const [command, expected] of [
    ['d=$(mktemp -d /tmp/x.XXXXXX); cp a "$d/"', 'd=$(mktemp -d /tmp/x.XXXXXX); cp a "/tmp/x.XXXXXX/"'],
    ['d="$(mktemp -d)"; cp a "${d}/b"', 'd="$(mktemp -d)"; cp a "/tmp/run/tmp.XXXXXXXXXX/b"'],
    ['w=$(mktemp -d "${TMPDIR:-/tmp}/nw.XXXXXX") && cp a "$w/"', 'w=$(mktemp -d "${TMPDIR:-/tmp}/nw.XXXXXX") && cp a "/tmp/run/nw.XXXXXX/"'],
    ["d=$(mktemp -d /tmp/x.XXXXXX)\ntrap 'rm -rf \"$d\"' EXIT", "d=$(mktemp -d /tmp/x.XXXXXX)\ntrap 'rm -rf \"/tmp/x.XXXXXX\"' EXIT"],
    ['d=$(mktemp -d build/.t.XXXXXX) && cp a "$d/"', 'd=$(mktemp -d build/.t.XXXXXX) && cp a "/work/project/build/.t.XXXXXX/"'],
    ['d=$(mktemp -p /var/tmp t.XXXXXX); cat "$d"', 'd=$(mktemp -p /var/tmp t.XXXXXX); cat "/var/tmp/t.XXXXXX"'],
  ]) {
    assert.equal(expandMktempVariables(command, env, cwd), expected, command);
  }
});

test("mktemp-assigned names stay unresolved when the shell may not hold that value", () => {
  for (const command of [
    '( d=$(mktemp -d /tmp/x.XXXXXX) ); rm -rf "$d/"',
    'false && d=$(mktemp -d /tmp/x.XXXXXX); rm -rf "$d/"',
    'if true; then d=$(mktemp -d /tmp/x.XXXXXX); fi; rm -rf "$d/"',
    'd=$(mktemp -d /tmp/x.XXXXXX); d=/home; rm -rf "$d/"',
    'd=$(mktemp -d /tmp/x.XXXXXX); unset d; rm -rf "$d/"',
    "d=$(mktemp -d /tmp/x.XXXXXX); sh -c 'rm -rf $d/'",
    'rm -rf "$d/"; d=$(mktemp -d /tmp/x.XXXXXX)',
    'd=$(mktemp -d /tmp/fixed); rm -rf "$d"/*',
    'd=$(mktemp -d /tmp/x.XXXXXX) cmd; rm -rf "$d/"',
    'd=$(mktemp -t x); rm -rf "$d/"',
    'cd sub; d=$(mktemp -d t.XXXXXX); rm -rf "$d/"',
    "bash <<'SH'\nd=$(mktemp -d /tmp/x.XXXXXX)\nSH\nrm -rf \"$d/\"",
  ]) {
    assert.equal(expandMktempVariables(command, env, cwd), command, command);
  }
});

test("mktemp resolution leaves quoted heredoc bodies untouched", () => {
  const command = "d=$(mktemp -d /tmp/x.XXXXXX)\nnode - \"$d/a\" <<'JS'\nconsole.log('$d')\nJS";
  assert.equal(
    expandMktempVariables(command, env, cwd),
    "d=$(mktemp -d /tmp/x.XXXXXX)\nnode - \"/tmp/x.XXXXXX/a\" <<'JS'\nconsole.log('$d')\nJS",
  );
});

test("mktemp suffixes and combined flags are validated without unbounded suffix matching", () => {
  for (const suffix of ["XXX", "XXXXXX", "X".repeat(20000)]) {
    const command = `d=$(mktemp -dq /tmp/x.${suffix}); cat "$d"`;
    assert.equal(expandMktempVariables(command, env, cwd), `d=$(mktemp -dq /tmp/x.${suffix}); cat "/tmp/x.${suffix}"`);
  }
  for (const flags of ["-", "-dx", "--unknown"]) {
    const command = `d=$(mktemp ${flags} /tmp/x.XXXXXX); cat "$d"`;
    assert.equal(expandMktempVariables(command, env, cwd), command);
  }
  for (const suffix of ["XX", "XXXXXXz"]) {
    const command = `d=$(mktemp /tmp/x.${suffix}); cat "$d"`;
    assert.equal(expandMktempVariables(command, env, cwd), command);
  }
});

test("a $PWD mktemp template resolves to the project unless the command changes directory", () => {
  const command = "s=$(mktemp -d \"$PWD/node_modules/.m.XXXXXX\")\ncp a \"$s/\"\nnode - <<'JS'\nconsole.log(1)\nJS";
  assert.match(expandMktempVariables(command, env, cwd), /cp a "\/work\/project\/node_modules\/\.m\.XXXXXX\/"/);
  const moved = 'cd sub; s=$(mktemp -d "$PWD/.m.XXXXXX"); cp a "$s/"';
  assert.equal(expandMktempVariables(moved, env, cwd), moved);
});
