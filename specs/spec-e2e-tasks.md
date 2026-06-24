# Plan: GuardMe E2E Implementation Tasks

## Task Description

Task-focused plan for adding a separate GuardMe e2e test suite. The suite starts Pi, runs local setup first, uses a scripted provider for deterministic assistant tool calls, verifies policy/approval behavior, covers high-risk GuardMe bypass classes, and creates a single text artifact with all `/guardme` TUI panels.

## Objective

Implement e2e coverage without changing the default unit test workflow or adding CI requirements yet.

## Relevant Files

- `specs/spec-e2e-architecture.md` - architecture source of truth.
- `specs/spec-e2e-guidelines.md` - implementation and safety guidelines.
- `package.json` - add e2e scripts.
- `docs/VALIDATION.md` - document local e2e commands and artifact path.
- `test/e2e/` - new e2e tests, helpers, and fixtures.
- `.gitignore` - ensure artifacts under `tmp/` stay ignored.

## Step by Step Tasks

### 1. Add e2e directory structure

- [ ] Create `test/e2e/`.
- [ ] Create `test/e2e/helpers/`.
- [ ] Create `test/e2e/fixtures/`.
- [ ] Keep generated output under `tmp/e2e/`.

#### Acceptance criteria

- E2E files are clearly separated from existing `test/*.test.mjs` files.
- No generated artifact is tracked by git.

### 2. Add isolated project fixture helper

- [ ] Create `test/e2e/helpers/project-fixture.mjs`.
- [ ] Create a disposable project directory under a concrete `/tmp/guardme-e2e-*` path.
- [ ] Create a disposable HOME directory.
- [ ] Populate minimal project files:
  - `README.md`
  - `package.json` with a harmless `test` script for allowed validation command scenarios
  - `.env.test` with fake values only
  - `build/keep.txt` for command-allow-boundary destructive segment checks
  - `scripts/safe.sh` for edit-content checks
  - `scripts/unsafe.sh` that would create a marker only if local-script execution actually runs
  - a safe file for outside-repository scenarios where needed
- [ ] Expose helper APIs to recreate `.env.test`, `build/`, outside files, approval targets, and marker files between scenario phases.
- [ ] Expose cleanup that only removes the known fixture root.

#### Acceptance criteria

- Fixture never uses the developer's real HOME.
- Fixture never deletes broad paths.
- `.env.test` exists before protected read, discovery, and hard-deny deletion scenarios.
- Script fixtures and marker paths are deterministic and contain fake data only.

### 3. Add RPC client helper

- [ ] Create `test/e2e/helpers/rpc-client.mjs`.
- [ ] Spawn Pi with isolated environment and flags.
- [ ] Parse JSONL stdout by `\n` only.
- [ ] Send JSONL commands to stdin.
- [ ] Collect events, responses, stderr, and extension UI requests.
- [ ] Provide helper APIs:
  - `startRpcPi(options)`
  - `send(command)`
  - `prompt(message)`
  - `promptAndWaitForAgentEnd(message)`
  - `respondToExtensionUi(id, response)`
  - `stop()`
- [ ] Fail tests on `extension_error`.

#### Acceptance criteria

- Helper can start Pi with GuardMe and the scripted provider.
- Helper can invoke extension commands such as `/guardme setup`.
- Helper can answer select/confirm approval requests.

### 4. Add scripted provider fixture

- [ ] Create `test/e2e/fixtures/scripted-provider.ts`.
- [ ] Register provider `guardme-e2e` and model `scripted`.
- [ ] Implement deterministic scenario routing from prompt text.
- [ ] Emit assistant text or one tool call per scenario.
- [ ] Add scenarios:
  - `allowed-read`
  - `allowed-validation-command`
  - `protected-env-read`
  - `hard-deny-cloud-cli`
  - `hard-deny-cloud-cli-wrapper`
  - `broad-discovery-protected-descendant`
  - `hard-deny-env-delete`
  - `outside-read-block`
  - `outside-write-block`
  - `outside-delete-block`
  - `command-allow-boundary`
  - `script-write-denied-content`
  - `script-edit-denied-content`
  - `local-script-exec-denied-content`
  - `policy-missing-generic-command`
  - `approval-dangerous-delete`
- [ ] Keep provider network-free.

#### Acceptance criteria

- Pi can select model `guardme-e2e/scripted`.
- Scenarios emit predictable tool calls.
- No real LLM/API key is required.

### 5. Add package scripts

- [ ] Add `test:e2e:rpc` to run RPC e2e tests.
- [ ] Add `test:e2e:tui` to run TUI capture only.
- [ ] Add `test:e2e` as the local aggregate command.
- [ ] Do not change `npm test`.
- [ ] Do not change CI.

#### Acceptance criteria

- `npm test` still runs only existing fast tests.
- E2E commands are opt-in.
- CI workflow remains unchanged.

### 6. Implement setup-first RPC e2e

- [ ] Create `test/e2e/guardme-rpc.e2e.mjs`.
- [ ] Start Pi in RPC mode with GuardMe and scripted provider loaded.
- [ ] Invoke `/guardme setup` before all policy scenarios.
- [ ] Handle setup UI:
  - select project/local sensible defaults
  - confirm policy write
- [ ] Assert `.pi/agent/guardme.yaml` exists.
- [ ] Assert local policy YAML contains expected sections.
- [ ] Restart or reload Pi if needed before policy scenarios.

#### Acceptance criteria

- Local project configuration is created first.
- No global policy is written for this setup scenario.
- Later scenarios run with local policy loaded.

### 7. Implement allowed action e2e scenarios

- [ ] Prompt scripted provider for `allowed-read`.
- [ ] Assert assistant tool call reads `README.md` successfully.
- [ ] Prompt scripted provider for `allowed-validation-command`.
- [ ] Use the fixture `package.json` harmless `test` script so the validation command is deterministic.
- [ ] Assert the allowed command succeeds and no GuardMe block is emitted.

#### Acceptance criteria

- At least one allowed assistant tool call is verified through real Pi events.
- At least one allowed `bash` validation command is verified through real Pi events.
- The test proves GuardMe does not block all normal project work.

### 8. Implement protected read and cloud CLI hard-deny scenarios

- [ ] Ensure `.env.test` exists and contains fake secret-like values only.
- [ ] Prompt scripted provider for `protected-env-read`.
- [ ] Assert `read .env.test` is blocked and fake secret content does not appear in captured output.
- [ ] Prompt scripted provider for `hard-deny-cloud-cli`.
- [ ] Assert `aws sts get-caller-identity` is hard-blocked before execution.
- [ ] Prompt scripted provider for `hard-deny-cloud-cli-wrapper` using one wrapper such as `env -S "aws sts get-caller-identity"` or `bash -c 'aws sts get-caller-identity'`.
- [ ] Assert the wrapped cloud CLI is also hard-blocked.

#### Acceptance criteria

- Protected credential reads are blocked through real Pi tool events.
- Direct and representative wrapped cloud CLI commands are blocked without requiring real cloud credentials.
- Blocked outputs do not leak fake fixture secrets.

### 9. Implement broad discovery protection scenario

- [ ] Ensure `.env.test` exists as a direct descendant of the disposable project.
- [ ] Prompt scripted provider for `broad-discovery-protected-descendant` using direct `grep` or `find` where possible.
- [ ] Assert the broad discovery call is blocked.
- [ ] Assert fake `.env.test` contents are absent from RPC logs and tool output.
- [ ] Optionally add a narrowly scoped safe discovery positive case if stable.

#### Acceptance criteria

- GuardMe blocks broad discovery over directories containing protected descendants.
- The test proves discovery tools are covered, not only `read` and `bash`.

### 10. Implement `.env.test` hard-deny deletion scenario

- [ ] Ensure `.env.test` exists in the disposable project.
- [ ] Prompt scripted provider for `hard-deny-env-delete`.
- [ ] Provider emits:

```bash
rm -rf .env.test
```

- [ ] Assert tool call is blocked.
- [ ] Assert `.env.test` still exists.
- [ ] Assert local YAML does not gain an allow rule for this command.
- [ ] Assert block reason references environment/credential/protected behavior.

#### Acceptance criteria

- `.env.test` deletion is hard-blocked.
- The test does not treat `.env.test` as approval-allowable.

### 11. Implement outside-repository protection scenarios

- [ ] Create explicit outside files under `/tmp/guardme-e2e-outside-*`.
- [ ] Prompt scripted provider for outside read.
- [ ] Prompt scripted provider for outside write/edit.
- [ ] Prompt scripted provider for outside delete.
- [ ] Assert each is blocked by default.
- [ ] Assert outside files are not modified/deleted.

#### Acceptance criteria

- GuardMe blocks assistant access outside the repository by default.
- Tests cover at least read, write/edit, and delete classes.

### 12. Implement command allow boundary scenario

- [ ] Ensure `build/keep.txt` exists.
- [ ] Prompt scripted provider for `command-allow-boundary`.
- [ ] Provider emits a compound command such as:

```bash
npm test -- --help && rm -rf build
```

- [ ] Assert the compound command is blocked before execution.
- [ ] Assert `build/keep.txt` still exists.
- [ ] Assert the block reason references the destructive segment, dangerous command, or broad allow boundary.

#### Acceptance criteria

- A broad default validation allow does not approve appended guarded shell segments.
- The positive allowed validation scenario still proves normal validation can run.

### 13. Implement script-content and local-script bypass scenarios

- [ ] Prompt scripted provider for `script-write-denied-content`.
- [ ] Provider emits a `write` tool call for an inside-project script containing a denied command such as `cat .env.test` or `aws sts get-caller-identity`.
- [ ] Assert GuardMe blocks before the file is created or modified.
- [ ] Prompt scripted provider for `script-edit-denied-content`.
- [ ] Provider emits an `edit` tool call that would insert a denied command into `scripts/safe.sh` or `package.json`.
- [ ] Assert the target file remains byte-for-byte unchanged.
- [ ] Prompt scripted provider for `local-script-exec-denied-content`.
- [ ] Provider emits `bash scripts/unsafe.sh`.
- [ ] Assert GuardMe blocks before the script runs.
- [ ] Assert the script marker side-effect file is absent.

#### Acceptance criteria

- Generated command-bearing writes and edits cannot bypass policy.
- Local script execution is inspected before execution.
- Blocked script scenarios do not leak fake secrets or create marker side effects.

### 14. Implement policy-missing generic command approval scenario

- [ ] Prompt scripted provider for `policy-missing-generic-command` with a safe no-network command not covered by `allowCommands`.
- [ ] Assert first attempt blocks with coaching and writes warning state with `policy-missing-command` semantics.
- [ ] Prompt the same scenario again.
- [ ] Assert an approval `extension_ui_request` is emitted.
- [ ] Respond with a non-persistent decision such as `Deny once` or `Allow once`.
- [ ] Assert no YAML allow/deny rule is written for the non-persistent decision.

#### Acceptance criteria

- Default-deny generic shell command behavior is tested through a real assistant bash tool call.
- Repeated policy-missing commands reach the approval flow.
- One-time approval decisions do not persist rules.

### 15. Implement dangerous approval persistence scenario with allow-local

- [ ] Use a safe, non-hard-denied dangerous command target, not `.env.test`.
- [ ] First prompt emits the dangerous command.
- [ ] Assert first attempt blocks with coaching and writes warning state.
- [ ] Second prompt emits same command.
- [ ] Respond to approval UI with `Deny once`.
- [ ] Assert command is blocked and no allow rule exists.
- [ ] Third prompt emits same command.
- [ ] Respond to approval UI with `Allow + save project rule`.
- [ ] Assert command is allowed.
- [ ] Assert `.pi/agent/guardme.yaml` contains exact `allowCommands` rule.
- [ ] Stop Pi.
- [ ] Recreate target if needed.
- [ ] Start Pi again with the same fixture project/HOME.
- [ ] Emit same command.
- [ ] Assert command is allowed without another approval UI request.

#### Acceptance criteria

- Deny-once and allow-local are both tested.
- Persistence works beyond the current Pi process.
- The saved rule is local, not global.

### 16. Implement TUI panel capture helper

- [ ] Create `test/e2e/helpers/tui-capture.mjs`.
- [ ] Start interactive Pi in a pseudo-terminal.
- [ ] Set `PI_TUI_WRITE_LOG` to a concrete artifact path.
- [ ] Send keyboard input to open `/guardme`.
- [ ] Strip ANSI/OSC/control sequences from captured output.
- [ ] Write sections to `tmp/e2e/guardme-tui-panels.txt`.

#### Acceptance criteria

- Helper produces readable text output.
- Artifact path is ignored by git.
- Helper does not rely on exact terminal dimensions unless explicitly configured.

### 17. Implement TUI local setup and all-panel capture

- [ ] Create `test/e2e/guardme-tui-capture.e2e.mjs`.
- [ ] Start from a disposable project without local policy.
- [ ] Open `/guardme`.
- [ ] Navigate to Setup.
- [ ] Select local/project sensible defaults.
- [ ] Capture setup selection screen.
- [ ] Capture confirmation screen.
- [ ] Confirm write.
- [ ] Capture success screen.
- [ ] Reopen or continue `/guardme` after setup.
- [ ] Capture all main panes:
  - General
  - Policies
  - Rules
  - Diagnostics
  - Setup
- [ ] Seed deterministic warning and decision records if previous steps do not naturally create them in this fixture.
- [ ] Capture warning/decision detail screens.
- [ ] Capture General pane rows for GuardMe active/off state and project trust as text.
- [ ] Write all captures into one file.

#### Acceptance criteria

- `npm run test:e2e:tui` creates one file with all GuardMe panels.
- The file includes local setup process screens first.
- The file includes all main panes after setup.
- The file includes warning/decision detail text and General pane settings/trust rows.

### 18. Add artifact assertions

- [ ] Assert TUI artifact contains `GuardMe Config`.
- [ ] Assert it contains `GENERAL`, `POLICIES`, `RULES`, `DIAGNOSTICS`, and `SETUP`.
- [ ] Assert it contains local setup text such as project/local policy write confirmation.
- [ ] Assert it contains warning/decision detail labels when seeded records are present.
- [ ] Assert it contains General pane GuardMe status and project trust labels.
- [ ] Assert it does not contain raw ANSI escape characters.

#### Acceptance criteria

- TUI capture is useful for visual review.
- Assertions are content-based, not pixel-perfect.

### 19. Update validation documentation

- [ ] Update `docs/VALIDATION.md` with e2e commands.
- [ ] Document that e2e is local-only and not in CI.
- [ ] Document the TUI artifact path.
- [ ] Document that scripted provider is deterministic and no real LLM key is needed.

#### Acceptance criteria

- A developer can run e2e tests from the docs.
- Docs explain why e2e is separate from normal tests.

### 20. Validate full implementation

- [ ] Run `npm test`.
- [ ] Run `npm run test:e2e:rpc`.
- [ ] Run `npm run test:e2e:tui` locally.
- [ ] Run `npm run validate`.
- [ ] Inspect generated TUI artifact manually.

#### Acceptance criteria

- All selected commands pass locally.
- TUI artifact is readable and contains all required panels.
- No generated artifacts or fixture state are tracked by git.

## Testing Strategy

Implement e2e tests after helper code is in place. Keep assertions focused on user-visible integration outcomes:

- process starts
- setup creates local config
- assistant tool calls are guarded
- protected files remain intact and fake secret content is not leaked
- cloud CLI hard-denies fire before execution
- broad discovery over protected descendants blocks
- outside-repo access blocks
- broad validation command allows do not approve appended guarded segments
- generated script writes/edits and local script execution are inspected before mutation/execution
- policy-missing generic commands are coached first and reach approval on repeat
- approval decisions behave correctly
- local persistence survives restart
- TUI text can be inspected in one file

## Acceptance Criteria

- Separate e2e suite exists and is not part of default `npm test`.
- E2E starts real Pi with GuardMe loaded.
- Local configuration setup is tested first.
- Scripted provider drives real assistant tool calls.
- `.env.test` read and deletion with `rm -rf .env.test` are blocked.
- Direct and representative wrapped cloud CLI commands are blocked before execution.
- Broad discovery over protected descendants is blocked without leaking fake secret content.
- Outside `/tmp/...` read/write/delete scenarios are tested.
- Broad validation command allows do not approve appended guarded segments.
- Generated script writes/edits and local script execution cannot bypass policy.
- Policy-missing generic commands are coached first and reach approval on repeat.
- Approval flow uses deny-once then allow-local and persists beyond current process.
- TUI e2e creates one text file with setup screens, detail screens, and all main GuardMe panels.
- No CI changes are made.

## Validation Commands

- `npm test` - Existing tests remain green.
- `npm run test:e2e:rpc` - Run deterministic RPC e2e scenarios.
- `npm run test:e2e:tui` - Generate and validate TUI panel capture.
- `npm run test:e2e` - Run local e2e suite.
- `npm run validate` - Full existing validation.

## Notes

Do not use `rm -rf .env.test` as the allow-local persistence command. It must remain a hard-deny/protected-file scenario. Use a separate safe target for approval persistence.
