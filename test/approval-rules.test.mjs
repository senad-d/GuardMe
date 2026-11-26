import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { projectPolicyRoot, resolvePolicyConfigPaths, setSessionMemoryPolicy } from "../src/config/load-config.ts";
import { approvalRule } from "../src/config/write-policy.ts";
import { evaluateGuardedToolCall } from "../src/events/register-guard.ts";
import { startGuardMeSession, stopGuardMeSession } from "../src/events/register-lifecycle.ts";
import { getGuardMeSessionState } from "../src/events/session-store.ts";
import { suggestCommandRule } from "../src/policy/evaluate.ts";

const bash = (command) => ({ toolName: "bash", input: { command } });

async function startSession(answer, environment = {}) {
  const root = await mkdtemp(join(tmpdir(), "guardme-approval-rules-"));
  const cwd = join(root, "project");
  await mkdir(cwd, { recursive: true });
  const prompts = [];
  const ctx = {
    cwd,
    hasUI: true,
    mode: "rpc",
    isProjectTrusted: () => true,
    ui: {
      setStatus: () => {},
      notify: () => {},
      select: async (title, options) => {
        prompts.push({ title, options });
        return answer;
      },
    },
  };
  setSessionMemoryPolicy();
  await startGuardMeSession(ctx, { homeDir: join(root, "home"), environment: { GUARDME_APPROVAL_MODE: "list", ...environment } });
  return { ctx, root, cwd, prompts };
}

test("an approval saves the kind of command, not its literal text", () => {
  const cases = [
    ["pdftotext -v", "pdftotext *"],
    ["fc-list", "fc-list *"],
    ["pdftotext   -layout  a.pdf  out.txt", "pdftotext *"],
    ["/usr/bin/pdftotext -v", "/usr/bin/pdftotext *"],
    ["./scripts/build.sh --fast", "./scripts/build.sh *"],
    ["git push origin feature/x", "git push *"],
    ["git status", "git status *"],
    ["gh pr create --title x", "gh pr *"],
    ["npm run build", "npm run *"],
    ["npx tsc --noEmit", "npx tsc *"],
    ["docker compose up -d", "docker compose *"],
    ["kubectl get pods -A", "kubectl get *"],
    ["cargo test --all", "cargo test *"],
    ["apt-get install -y jq", "apt-get install *"],
    ["make build", "make build *"],
    // No subcommand to keep: the literal command.
    ["git -C /tmp status", "git -C /tmp status"],
    ["kubectl --token abc get pods", "kubectl --token abc get pods"],
    // Wrappers and interpreters run their arguments.
    ["sudo apt-get update", "sudo apt-get update"],
    ["python3 -c 'print(1)'", "python3 -c 'print(1)'"],
    ["/bin/bash -c ls", "/bin/bash -c ls"],
    // Not a plain word: a variable or a quoted name.
    ["$TOOL --version", "$TOOL --version"],
    ['"my tool" -v', '"my tool" -v'],
  ];
  for (const [command, rule] of cases) {
    assert.equal(suggestCommandRule(command), rule, command);
  }
});

test("a path approval saves the directory inside the project and the exact path outside it", () => {
  const decision = { risk: "medium" };
  const inside = { kind: "path", raw: "src/api/users.ts", isInsideProject: true, projectRelativePath: "src/api/users.ts" };
  const outside = { kind: "path", raw: "/etc/hosts", isInsideProject: false };
  const request = (target) => ({ toolName: "write", action: "write", cwd: "/repo", targets: [target] });

  assert.deepEqual(approvalRule(request(inside), decision, true), {
    pattern: "src/api/**",
    covers: "every path under src/api",
    exact: false,
    scopes: ["once", "session", "project", "global"],
  });
  assert.equal(approvalRule(request(outside), decision, false).pattern, "/etc/hosts");
  assert.deepEqual(approvalRule(request(outside), decision, false).scopes, ["once", "session", "global"]);
  assert.equal(approvalRule(request(inside), { risk: "dangerous" }, true).pattern, "src/api/users.ts");
});

test("allow for session covers later commands of the same kind and writes no file", async () => {
  const { ctx, cwd, root, prompts } = await startSession("Allow for session");

  assert.equal((await evaluateGuardedToolCall(bash("pdftotext -v"), ctx))?.block, true);
  assert.equal(await evaluateGuardedToolCall(bash("pdftotext -v"), ctx), undefined);
  assert.equal(await evaluateGuardedToolCall(bash("pdftotext -layout a.pdf"), ctx), undefined);

  assert.equal(prompts.length, 1);
  assert.match(prompts[0].title, /Saves: pdftotext \* \(every pdftotext command\)/);
  assert.equal(prompts[0].options[0], "Deny once");
  const paths = resolvePolicyConfigPaths(cwd, join(root, "home"));
  await assert.rejects(readFile(paths.localPolicyPath, "utf8"));
  await assert.rejects(readFile(paths.globalPolicyPath, "utf8"));
  const record = getGuardMeSessionState().warnings.records.findLast((entry) => entry.type === "decision");
  assert.deepEqual(
    { decision: record.decision, persistedTo: record.persistedTo, toolName: record.toolName, target: record.target, rule: record.rule },
    { decision: "allow-session", persistedTo: "session", toolName: "bash", target: "pdftotext -v", rule: "pdftotext *" },
  );
  stopGuardMeSession(ctx);
});

test("a compound command shows the blocked part apart from the whole command", async () => {
  const { ctx, prompts } = await startSession("Deny once");

  await evaluateGuardedToolCall(bash("pwd && pdftotext -v"), ctx);
  await evaluateGuardedToolCall(bash("pwd && pdftotext -v"), ctx);

  assert.match(prompts[0].title, /Target: pwd && pdftotext -v\nBlocked part: pdftotext -v\n/);
  stopGuardMeSession(ctx);
});

test("a rule another agent saves in the shared session file applies without a restart, and a deny there is final", async () => {
  const sessionPolicy = join(await mkdtemp(join(tmpdir(), "guardme-session-file-")), "guard-session.yaml");
  const { ctx, prompts } = await startSession("Deny for session", { GUARDME_SESSION_POLICY: sessionPolicy });

  await writeFile(sessionPolicy, 'version: 1\n\nallowCommands:\n  - pattern: "pdftotext *"\n', "utf8");
  assert.equal(await evaluateGuardedToolCall(bash("pdftotext -v"), ctx), undefined);

  await evaluateGuardedToolCall(bash("acme-fonts"), ctx);
  await evaluateGuardedToolCall(bash("acme-fonts"), ctx);
  const denied = await evaluateGuardedToolCall(bash("acme-fonts --lang en"), ctx);

  assert.equal(prompts.length, 1);
  assert.match(await readFile(sessionPolicy, "utf8"), /denyCommands:\n\s+- pattern: "acme-fonts \*"/);
  assert.equal(denied?.block, true);
  // Orchestrators retry a refusal that says "GuardMe coaching"; a deny rule must not.
  assert.doesNotMatch(denied.reason, /GuardMe coaching/);
  const warning = getGuardMeSessionState().warnings.records.findLast((entry) => entry.type === "warning");
  assert.equal(warning.matchedRules[0].source.kind, "session");
  stopGuardMeSession(ctx);
});

test("a linked git worktree uses the project policy of its main checkout", async () => {
  const root = await mkdtemp(join(tmpdir(), "guardme-worktree-"));
  const main = join(root, "main");
  const worktree = join(root, "trees", "task-1");
  const gitDir = join(main, ".git", "worktrees", "task-1");
  await mkdir(gitDir, { recursive: true });
  await mkdir(worktree, { recursive: true });
  await writeFile(join(worktree, ".git"), `gitdir: ${gitDir}\n`, "utf8");
  await writeFile(join(gitDir, "commondir"), "../..\n", "utf8");

  assert.equal(projectPolicyRoot(worktree), main);
  assert.equal(projectPolicyRoot(main), main);
  assert.equal(resolvePolicyConfigPaths(worktree, root).localPolicyPath, join(main, ".pi", "guardme.yaml"));
});
