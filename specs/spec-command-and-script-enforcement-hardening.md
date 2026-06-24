# Plan: Command and Script Enforcement Hardening

## Task Description

Fix GuardMe policy gaps that let an LLM bypass command rules by writing a helper script and then executing it, or by running generic shell commands that are absent from both `allowCommands` and `denyCommands`. The hardening must block unsafe writes before files are created/modified, default-deny unclassified shell commands, inject actionable model-facing guidance, and prompt the user on repeated attempts to save an allow or deny rule where policy allows it.

## Objective

GuardMe should stop LLM tool actions before execution when:

- a proposed `write` or `edit` payload contains denied, hard-denied, dangerous, or policy-missing commands;
- a `bash` command executes a local script whose content fails policy;
- a generic shell command such as `brave ...` or `open -a Brave ...` is not explicitly allowed or denied.

After the first dangerous/policy-missing attempt, GuardMe should block with guidance and record JSONL state. On a repeated same-type attempt, GuardMe should ask the user to allow or block and optionally persist the decision. Hard-denied and explicit-denied actions remain non-overridable.

## Problem Statement

Investigation found these current gaps:

- `src/events/register-guard.ts` maps `write` and `edit` tool calls only by path; it ignores `content`, `newText`, and other proposed file text, so command-bearing scripts can be written inside the project.
- `src/policy/commands.ts` classifies commands such as `./azure-cli-config-audit.sh --output azure-cli-audit-report.txt`, `open -a Brave https://...`, and `brave https://...` as low-risk generic shell commands with no target paths.
- `src/policy/evaluate.ts` currently allows generic shell commands when no deny rule, dangerous rule, hard denial, or path requirement matches.
- Running a local script does not inspect the script content before execution.
- `src/events/register-guidance.ts` is intentionally a no-op, so there is no dedicated guidance injection beyond the tool-call block reason.
- Existing tests cover many direct command/path forms but not generated-script bypasses or unknown-command default-deny behavior.

## Solution Approach

Add a command-default-deny layer and script-content policy layer:

1. Classify generic shell commands that do not match allow/deny/dangerous/hard policy as `policy-missing` and block them on first attempt.
2. Add a script-content extractor that scans proposed `write`/`edit` content and readable local scripts before mutation/execution.
3. Evaluate extracted commands through the same deny-first/default-deny policy as direct `bash` commands.
4. Record dangerous and policy-missing first attempts in JSONL with redacted fingerprints and reason codes.
5. Reuse the approval UI on repeated dangerous/policy-missing attempts, saving narrow allow/deny rules only when doing so does not weaken hard protections.
6. Add model-facing guidance that explains why the action was blocked and tells the model to use existing safe tools, request user approval, or propose a policy rule.

## Relevant Files

- `src/events/register-guard.ts` - Add write/edit content scanning, local-script execution inspection, policy-missing state handling, and model-facing block guidance.
- `src/events/register-guidance.ts` - Implement concise guidance injection for prior blocked/coached/policy-missing events.
- `src/events/session-store.ts` - Store last guidance/blocked event metadata if needed.
- `src/policy/commands.ts` - Identify local script execution targets and support default-deny policy-missing classification.
- `src/policy/evaluate.ts` - Add policy-missing decisions before default path allows for `bash` commands.
- `src/policy/action.ts` - Add reason-code or metadata fields if needed for policy-missing and script-content decisions.
- `src/state/warnings.ts` - Persist and load reason codes for dangerous/policy-missing warning records without storing full content.
- `src/config/write-policy.ts` - Save command allow/deny rules for policy-missing command approvals, including content-derived command approvals.
- `src/ui/approval-modal.ts` - Display policy-missing/script-content facts and deny-only behavior for hard-denied repeats.
- `docs/POLICY.md`, `README.md`, `SECURITY.md`, `CHANGELOG.md` - Document default-deny commands, script-content scanning, and limitations.
- `test/command-classifier.test.mjs`, `test/policy-evaluate.test.mjs`, `test/tool-guard.test.mjs`, `test/warning-state.test.mjs`, `test/write-policy.test.mjs` - Extend coverage.

### New Files

- `src/policy/script-content.ts` - Pure helpers to identify command-bearing files/snippets, extract commands with source metadata, redact snippets, and build content-derived policy requests.
- `test/script-content.test.mjs` - Unit tests for script/content extraction and redaction.

## Implementation Phases

### Phase 1: Policy model and extraction foundation

- Add reason-code metadata for dangerous, policy-missing, and script-content decisions.
- Implement script-content extraction for high-confidence command-bearing files.
- Add local script execution target detection.
- Add unit tests before changing enforcement.

### Phase 2: Enforcement integration

- Make generic `bash` commands default-deny unless explicitly allowed or hard/deny/dangerous classified.
- Block write/edit payloads before mutation when extracted content fails policy.
- Inspect local scripts before `bash` execution and fail closed when inspection is impossible or policy fails.
- Persist warned-once state for policy-missing attempts.

### Phase 3: UX, persistence, docs, and validation

- Extend approval UI/rule persistence for policy-missing command decisions.
- Add model-facing guidance injection.
- Update docs and changelog.
- Run full tests and isolated smoke scenarios.

## Step by Step Tasks

### 1. Add regression tests that reproduce the gaps

- Add a `write` test where `content` contains a script that reads `~/.azure`, `~/.aws`, `.env`, or SSH keys; assert the tool call blocks before write.
- Add an `edit` test where `newText` inserts a forbidden command; assert the edit blocks.
- Add a `bash` test for `./script.sh` where the script file contains a forbidden command; assert execution blocks.
- Add `bash` tests for `open -a Brave ...` and `brave ...`; assert first attempt blocks as policy-missing and repeat prompts/blocks without UI.

### 2. Extend policy decision metadata

- Add a lightweight reason-code field or equivalent metadata for decisions and warning records.
- Use reason codes such as `dangerous-command`, `policy-missing-command`, `script-content-denied`, and `local-script-uninspectable`.
- Ensure fingerprints redact secret-like text and never include full file contents.

### 3. Implement script-content extraction

- Create `src/policy/script-content.ts` with pure helpers.
- Detect command-bearing contexts: shell shebangs, `.sh`, `.bash`, `.zsh`, `.command`, Makefile recipes, `package.json` scripts, Dockerfile `RUN`, CI `run:` blocks, and obvious heredoc/stdin shell bodies where practical.
- Return extracted commands with path, line number/range, context label, and redacted preview.
- Keep extraction conservative: if content is command-bearing but cannot be safely evaluated, return an uninspectable/policy-missing finding.

### 4. Detect local script execution

- Extend command classification or add helper logic to identify `./script`, `script.sh`, `bash script.sh`, `sh script`, and `zsh script.zsh` forms after common wrappers.
- Resolve script paths through existing safe path normalization.
- Read only policy-permitted local scripts; fail closed when the target is outside policy, binary, too large, symlink-ambiguous, or unreadable.

### 5. Add command default-deny evaluation

- In `evaluatePolicyRequest`, do not allow `bash` commands solely because no deny matched.
- Apply order: hard denial → deny rules/protections → outside path requirements → exact allow rules → dangerous handling → policy-missing handling.
- Ensure built-in tool path defaults still allow direct `read`, `write`, `edit`, `grep`, `find`, and `ls` behavior as documented.
- Ensure built-in/common `allowCommands` such as `npm test*` still work, but broad wildcard allows cannot approve appended guarded segments or script content that fails policy.

### 6. Integrate write/edit content scanning

- For `write`, inspect `input.content` before allowing the tool call.
- For `edit`, inspect each `newText`; when safe and practical, reconstruct final content in memory and scan that too.
- Evaluate extracted commands with the same policy as direct `bash` commands.
- Block before any file mutation when extracted content fails policy.

### 7. Integrate local-script pre-execution inspection

- For `bash` local-script execution, inspect the script before allowing execution.
- If script content contains hard-denied or explicit-denied commands, block without allow persistence.
- If script content contains dangerous or policy-missing commands, use first-coach/repeat-prompt behavior.

### 8. Extend approval and persistence

- Reuse approval UI for repeated policy-missing command/content decisions.
- Save narrow `allowCommands` rules for user-approved policy-missing commands.
- Save `denyCommands` rules for user-denied policy-missing commands.
- Reject saved allow rules that would weaken hard denials, deny rules, or protected path policy.

### 9. Implement model-facing guidance injection

- Standardize block reasons so the model receives: what was blocked, which policy class matched, and how to proceed safely.
- Implement `registerGuidance` to inject concise follow-up guidance when useful, without secrets, output, or full file content.
- Ensure non-UI repeat blocks explain that user approval is required but unavailable.

### 10. Update documentation

- Update `docs/POLICY.md` with command default-deny semantics and script-content scanning.
- Update `README.md` behavior and hard-protection sections.
- Update `SECURITY.md` to explain this is still Pi-session enforcement, not an OS sandbox.
- Update `CHANGELOG.md` with the user-visible hardening.

### 11. Validate

- Run targeted tests after each module.
- Run the full validation commands.
- Perform isolated smoke tests with only GuardMe loaded.

## Testing Strategy

- Unit tests for script-content extraction, local script target detection, command default-deny, and redaction.
- Policy tests proving unknown commands block first and prompt on repeat.
- Adapter tests proving `write`/`edit` content is blocked before mutation.
- Adapter tests proving local scripts are inspected before `bash` execution.
- UI/persistence tests proving repeated policy-missing commands can be saved as allow/deny rules and hard-denied commands cannot be allowed.
- Non-UI tests proving repeated dangerous/policy-missing prompts fail closed.

## Acceptance Criteria

- `write` and `edit` calls that introduce forbidden or policy-missing commands block before mutating files.
- `bash` local-script execution inspects script content and blocks scripts that fail policy.
- Generic commands absent from allow/deny/dangerous/hard policy block by default.
- First dangerous or policy-missing attempts provide model-facing guidance and append JSONL warning state.
- Repeated dangerous or policy-missing attempts prompt the user when UI exists and block when UI is unavailable.
- User-approved policy-missing commands can be saved to allow/deny YAML without weakening hard policy.
- Hard-denied and explicit-denied commands remain non-overridable.
- Tests and docs cover the script-writing bypass and unknown-command behavior.

## Validation Commands

- `npm run typecheck` - Verify TypeScript compiles.
- `npm run test` - Run unit/integration tests.
- `npm run check:pack` - Verify package contents remain clean.
- `npm run validate` - Run full repository validation.
- `pi --no-extensions -e .` - Isolated manual smoke test.

## Notes

- This hardening still does not make GuardMe an OS sandbox. A user-approved command can run arbitrary child processes with the local user's permissions.
- Prefer exact, narrow command rules over wildcard command allows.
- Avoid reading or storing full generated files in state, diagnostics, UI, or logs.
