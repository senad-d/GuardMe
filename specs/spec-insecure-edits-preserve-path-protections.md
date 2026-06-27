# Plan: Preserve Path Protections During Insecure Edits

## Task Description
Fix GuardMe's **Insecure edits** mode so it no longer bypasses path protections for `write` and `edit` tool calls. Insecure edits should remain an explicit authoring escape hatch for mutation-time script/content inspection, but it must not allow writes or edits to paths protected by `denyPaths`, `zeroAccessPaths`, `protectedCredentialPaths`, `readOnlyPaths`, outside-project mutation rules, or other path-policy guards.

Task type: fix  
Complexity: medium

## Objective
When `.pi/agent/guardme-settings.json` contains `"insecureEdits": true`, GuardMe must still run normal path-policy evaluation for `write` and `edit`; only the post-policy script-content scan should be skipped.

## Problem Statement
The current implementation short-circuits `write` and `edit` calls before path extraction and policy evaluation:

```ts
if (state.insecureEdits && isEditMutationToolName(event.toolName)) {
  return undefined;
}
```

This makes protected paths writable/editable while insecure edits is enabled. In practice, it allowed `.env` to be created and edited even though the built-in policy has `denyPaths: **/.env` for all path actions. That violates the expected invariant that deny/protected credential paths remain protected even during insecure authoring workflows.

## Solution Approach
Change the semantics of **Insecure edits** from "bypass all GuardMe policy for write/edit" to "skip only proposed content/script inspection after path policy allows the write/edit".

High-level behavior after the fix:

1. GuardMe disabled still bypasses all enforcement for the trusted project, as today.
2. GuardMe enabled + insecure edits off:
   - `write`/`edit` path policy runs.
   - proposed content/script scanning runs.
3. GuardMe enabled + insecure edits on:
   - `write`/`edit` path policy still runs.
   - proposed content/script scanning is skipped.
4. `bash`, `read`, `grep`, `find`, and `ls` remain guarded exactly as today.

## Relevant Files

Use these files to complete the task:

- `src/events/register-guard.ts` - Main enforcement adapter. Remove the early `insecureEdits` bypass and gate only `inspectWriteEditContentBeforeMutation(...)`.
- `src/policy/evaluate.ts` - Existing path-policy precedence should not need semantic changes; use it as the source of truth for deny/protected path behavior.
- `src/config/schema.ts` - Built-in default protections for `.env`, credential paths, read-only GuardMe config files, etc.; likely no code change, but tests rely on these rules.
- `src/events/session-store.ts` - Status still reports insecure edits; likely no logic change unless wording is revised elsewhere.
- `src/commands/guardme-command.ts` - Update notification/status copy so it no longer says write/edit bypass GuardMe policy entirely.
- `src/ui/config-tui.ts` - Update General-pane search/description/confirmation text to explain that path protections remain enforced.
- `README.md` - Update policy/state and configuration wording.
- `docs/POLICY.md` - Update Insecure edits semantics and precedence notes.
- `SECURITY.md` - Update security scope so it does not claim write/edit are unguarded wholesale.
- `CHANGELOG.md` - Record the behavior correction.
- `specs/spec-insecure-edits.md` - Existing spec currently documents the too-broad bypass; update it or mark it superseded by this fix plan.
- `test/tool-guard.test.mjs` - Main adapter tests for the corrected behavior.
- `test/config-tui.test.mjs` and `test/guardme-command.test.mjs` - Copy/UX tests that currently expect broad bypass wording.
- `test/policy-evaluate.test.mjs` - Existing path precedence tests; add pure evaluator tests only if a path-policy gap is discovered.

### New Files

No new source files are required.

## Implementation Phases

### Phase 1: Reframe semantics and tests
- Update/replace the current insecure-edits adapter test that expects `.env` writes to be allowed.
- Add regression coverage proving protected paths remain blocked when insecure edits is on.
- Keep coverage proving script-bearing content can still be authored to an otherwise allowed path while insecure edits is on.

### Phase 2: Core enforcement change
- Remove the early `write`/`edit` bypass in `evaluateGuardedToolCall`.
- Let `mapToolCallToPolicyRequest(...)`, `evaluatePolicyRequest(...)`, and `handlePolicyDecision(...)` always run for `write`/`edit` while GuardMe is enabled.
- Skip only `inspectWriteEditContentBeforeMutation(...)` when `state.insecureEdits` is true.

### Phase 3: Documentation and UX alignment
- Update UI/command/documentation copy to state that insecure edits skips content inspection only.
- Remove or revise wording that says write/edit bypass GuardMe policy or path protections.
- Validate focused tests, then run the broader suite.

## Step by Step Tasks

IMPORTANT: Execute every step in order, top to bottom.

### 1. Add regression tests for protected paths under insecure edits
- In `test/tool-guard.test.mjs`, rename or split the existing test `insecure edits bypass write and edit policy while bash execution remains guarded`.
- Keep the positive case: with insecure edits on, writing a script containing denied commands to an ordinary allowed path such as `audit.sh` should be allowed.
- Change the `.env` expectation: writing `.env` with insecure edits on must return a block result.
- Add an `edit` attempt against `.env` after creating it directly in the fixture; it must also block.
- Add at least one protected credential-like filename case, such as `Secret.TXT` or `token.txt`, to confirm classifier/protected credential path checks still apply.
- Add a read-only/path-policy case if practical, such as a local `readOnlyPaths` rule for `docs/**` and a blocked write/edit to `docs/guide.md`.

### 2. Implement the adapter change
- In `src/events/register-guard.ts`, remove this early bypass:

```ts
if (state.insecureEdits && isEditMutationToolName(event.toolName)) {
  return undefined;
}
```

- Keep the GuardMe disabled bypass unchanged:

```ts
if (!state.enabled) {
  return undefined;
}
```

- Change the final write/edit content-inspection branch to run only when insecure edits is off:

```ts
if ((event.toolName === "write" || event.toolName === "edit") && !state.insecureEdits) {
  return inspectWriteEditContentBeforeMutation(state, ctx, event, mapped.request);
}
```

- Leave `bash` local-script/package-script execution inspection unchanged.

### 3. Verify path-policy precedence still covers the desired protections
- Confirm `evaluatePolicyRequest(...)` still evaluates, in order:
  - command hard denies,
  - credential-like path denial,
  - `zeroAccessPaths`, `protectedCredentialPaths`, `readOnlyPaths`, `noDeletePaths`,
  - `denyPaths`,
  - outside-project path denial,
  - explicit/default allows.
- Do not add a special insecure-edits flag to the policy evaluator unless a test exposes a real need; the adapter-level change should be enough.

### 4. Update command and TUI copy
- In `src/commands/guardme-command.ts`, replace copy like:
  - `write/edit tool calls bypass GuardMe policy in this project`
- Suggested replacement:
  - `Insecure edits are ON: write/edit content scanning is skipped, but path protections still apply.`
- In `src/ui/config-tui.ts`, update General row/search/confirmation descriptions from broad policy bypass to content-scan bypass.
- Ensure warning language remains strong: generated scripts can be written, but execution remains guarded.

### 5. Update documentation
- In `docs/POLICY.md`, revise the runtime settings description and precedence item for `write`/`edit` payload scanning:
  - insecure edits skips script-content inspection only,
  - path protections and deny rules still run.
- In `README.md`, revise policy/state and configuration sections similarly.
- In `SECURITY.md`, replace wording that `write`/`edit` are not guarded with wording that path policy remains guarded but content inspection is skipped.
- In `CHANGELOG.md`, update the unreleased entry for **Insecure edits** to describe the corrected behavior.
- Update or mark `specs/spec-insecure-edits.md` as superseded where it claims no path policy is applied.

### 6. Run focused validation
- Run the focused test files listed below.
- Fix any expected-copy assertions in UI/command tests.
- If a protected path is still allowed, inspect whether the relevant tool input is being mapped to a path target correctly before changing evaluator semantics.

### 7. Run full validation
- Run typecheck and the full test suite.
- Review docs for any remaining phrase like `bypass GuardMe policy` applied to insecure edits.
- Confirm no implementation change weakens `bash`, `read`, `grep`, `find`, or `ls` enforcement.

## Testing Strategy

Test both negative and positive behavior with `insecureEdits: true`:

- Negative/protected cases:
  - `write` to `.env` is blocked by built-in `denyPaths`.
  - `edit` of `.env` is blocked by built-in `denyPaths`.
  - `write` to a credential-like filename is blocked by the credential classifier or `protectedCredentialPaths`.
  - `write`/`edit` to a read-only path is blocked if covered by policy.
  - outside-project write/edit remains denied without explicit `allowPaths`.
- Positive/authoring case:
  - `write` to an ordinary project file containing denied shell content is allowed with insecure edits on.
  - Running that file via `bash` remains blocked if the script contains denied commands.
- Regression baseline:
  - With insecure edits off, unsafe proposed content still blocks before mutation.

## Acceptance Criteria

- With GuardMe enabled and insecure edits on, `.env` write/edit attempts are blocked.
- `denyPaths`, `zeroAccessPaths`, `protectedCredentialPaths`, `readOnlyPaths`, and outside-project write/edit requirements still apply to `write` and `edit`.
- Insecure edits still allows authoring command-bearing content to otherwise allowed paths.
- `bash` execution of unsafe generated scripts remains guarded.
- UI, command notifications, README, policy docs, security docs, changelog, and older specs no longer claim that insecure edits bypasses all write/edit policy.
- Focused and full validation commands pass.

## Validation Commands

Execute these commands to validate the task is complete:

- `node --test test/tool-guard.test.mjs test/config-tui.test.mjs test/guardme-command.test.mjs` - Focused adapter and UX regression tests.
- `node --test test/runtime-settings.test.mjs test/policy-evaluate.test.mjs` - Runtime setting and policy precedence safety checks.
- `npm run typecheck` - TypeScript compile/type validation.
- `npm test` - Full project test suite.
- `rg -n 'bypass GuardMe policy|bypasses GuardMe policy|path protections and script-content scanning|does not guard write or edit' README.md docs SECURITY.md CHANGELOG.md specs src test` - Manual wording audit; remaining matches should be intentional and corrected for the new semantics.

## Notes

- This is a security-sensitive behavior correction. Prefer the narrower interpretation: insecure edits skips content scanning only.
- Do not weaken GuardMe's disabled/off behavior in this fix; that is a separate explicit project setting.
- Keep implementation minimal. The existing evaluator already has the correct deny-first path precedence once the adapter stops bypassing it.
