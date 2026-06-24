# Plan: GuardMe E2E Test Architecture

## Task Description

Design a separate end-to-end test suite for GuardMe that starts Pi with this extension loaded, drives realistic user/application flows, captures the TUI as text, and validates command/path approval behavior with deterministic model output. The suite must be separate from normal unit tests and is not required in CI yet.

## Objective

Create a blueprint for an e2e harness that verifies GuardMe from the outside like a user would use it:

- start Pi with GuardMe loaded
- run local GuardMe setup before policy scenarios
- exercise real assistant tool-call enforcement through a scripted provider
- capture `/guardme` TUI panels into one text artifact
- verify allowed, denied, approval, local persistence, and outside-repository protections
- verify the highest-risk bypass classes that only show up through real Pi tool execution: protected reads, cloud CLI hard-denies, broad discovery, command-allow boundaries, generated script/content scanning, and local script execution inspection

## Problem Statement

Existing tests cover GuardMe modules and adapters well, but they mostly call exported functions directly. They do not fully prove that Pi startup, extension registration, model-produced tool calls, extension UI requests, TUI rendering, setup flows, and persistence work together in a realistic process.

GuardMe only guards Pi LLM `tool_call` events. User shell escapes and direct RPC `bash` commands are not equivalent to assistant tool calls. Therefore, deterministic e2e tests need a scripted model provider that emits known tool calls without using a real API.

## Solution Approach

Add a separate e2e suite launched by `npm run test:e2e`. The suite has two layers:

1. **RPC e2e layer**: starts `pi --mode rpc --no-extensions -e . -e <scripted-provider>` in a disposable project and HOME. The scripted provider emits deterministic assistant tool calls based on prompt scenario names. The e2e client handles RPC events and extension UI requests, including setup selection and approval choices.
2. **TUI capture layer**: starts interactive Pi in a pseudo-terminal with `PI_TUI_WRITE_LOG` set. It drives `/guardme`, performs or verifies local setup first, visits all GuardMe panes, sanitizes the ANSI stream, and writes a single text artifact containing all captured panels.

The TUI capture is local/optional for now and must not be added to CI until it is stable enough.

## Relevant Files

Existing files to use or verify:

- `src/extension.ts` - GuardMe entry point loaded by Pi with `-e .`.
- `src/events/register-guard.ts` - real policy enforcement path that e2e must exercise through assistant tool calls.
- `src/commands/guardme-command.ts` - `/guardme` command and setup flow.
- `src/ui/config-tui.ts` - frame/pane rendering used by TUI capture.
- `src/ui/approval-modal.ts` - approval UI/fallback behavior for repeated dangerous or policy-missing actions.
- `src/config/load-config.ts` - local/global policy path resolution for assertions.
- `src/config/runtime-settings.ts` - project-local GuardMe on/off settings path used by optional runtime-setting checks.
- `src/policy/commands.ts` - shell classifier behavior that e2e should exercise through real assistant bash tool calls.
- `src/policy/script-content.ts` - generated-file and local-script inspection behavior that e2e should cover as bypass regressions.
- `src/state/warnings.ts` - warning/decision state path resolution for assertions.
- `docs/VALIDATION.md` - should be updated with e2e commands after implementation.
- `package.json` - add separate e2e scripts only; do not put e2e into default `npm test`.
- `.gitignore` - ensure generated e2e artifacts stay out of commits unless explicitly intended.

### New Files

Recommended new files:

- `test/e2e/guardme-rpc.e2e.mjs` - deterministic RPC e2e scenarios.
- `test/e2e/guardme-tui-capture.e2e.mjs` - local TUI capture runner; skipped unless explicitly requested.
- `test/e2e/helpers/rpc-client.mjs` - JSONL RPC process helper.
- `test/e2e/helpers/project-fixture.mjs` - disposable project/HOME setup helper.
- `test/e2e/helpers/tui-capture.mjs` - pseudo-terminal/ANSI-log capture helper.
- `test/e2e/fixtures/scripted-provider.ts` - Pi extension registering a deterministic provider.
- `tmp/e2e/guardme-tui-panels.txt` - generated artifact path for all captured GuardMe panels; ignored.

## Architecture Details

### Process isolation

Every e2e test should create a disposable root under an explicit path such as `/tmp/guardme-e2e-rpc` or `/tmp/guardme-e2e-tui`. Avoid variable-based shell temp paths inside guarded bash calls. The Node e2e harness may use `fs.mkdtemp`, but shell commands invoked from assistant scenarios should use concrete paths.

Each spawned Pi process should receive isolated environment variables:

- `HOME=<fixture home>`
- `PI_OFFLINE=1`
- `PI_SKIP_VERSION_CHECK=1`
- `GUARDME_SKIP_GLOBAL_POLICY_INSTALL=1` when running npm install-like code is not needed
- `PI_TUI_WRITE_LOG=<artifact log>` for TUI capture only

Pi startup flags for RPC e2e:

```bash
pi --mode rpc \
  --no-extensions \
  -e . \
  -e test/e2e/fixtures/scripted-provider.ts \
  --provider guardme-e2e \
  --model scripted \
  --offline \
  --no-session \
  --approve
```

### Scripted provider

The scripted provider should be a test-only Pi extension. It registers provider `guardme-e2e` and model `scripted`. The provider emits deterministic assistant messages containing tool calls.

Scenario selection can be based on the latest user prompt, for example:

- `SCENARIO: setup-check`
- `SCENARIO: allowed-read`
- `SCENARIO: allowed-validation-command`
- `SCENARIO: hard-deny-env-delete`
- `SCENARIO: protected-env-read`
- `SCENARIO: hard-deny-cloud-cli`
- `SCENARIO: hard-deny-cloud-cli-wrapper`
- `SCENARIO: broad-discovery-protected-descendant`
- `SCENARIO: outside-read-block`
- `SCENARIO: outside-write-block`
- `SCENARIO: outside-delete-block`
- `SCENARIO: command-allow-boundary`
- `SCENARIO: script-write-denied-content`
- `SCENARIO: script-edit-denied-content`
- `SCENARIO: local-script-exec-denied-content`
- `SCENARIO: policy-missing-generic-command`
- `SCENARIO: approval-rm-tmp`

The provider must not call any network service. It should emit one assistant message per prompt with either text or one tool call. For approval repeat tests, the e2e client sends the same scenario multiple times.

If the fixture needs `@earendil-works/pi-ai` helpers such as `createAssistantMessageEventStream`, keep that dependency test-only. Prefer dev dependency or runtime resolution through Pi's documented extension imports; do not add non-Pi runtime dependencies to the published GuardMe package for e2e only.

### RPC e2e client

The RPC client helper should:

- spawn Pi
- write JSONL commands to stdin
- parse stdout by LF only
- collect events and responses
- respond to `extension_ui_request` dialogs
- fail fast on `extension_error`
- expose helpers such as `promptAndWaitForAgentEnd`, `waitForUiRequest`, and `shutdown`

Dialog handling must support:

- setup `select` request: choose project/local sensible defaults first
- setup confirmation: confirm write
- approval `select` request: choose deny once or allow + save project rule depending on scenario phase
- notification/status events: collect for assertions but do not fail by default

### Local setup first

The first e2e flow must create local GuardMe configuration before any command enforcement scenario.

Recommended robust path:

1. Start Pi in RPC mode.
2. Send prompt command `/guardme setup` or `/guardme` depending on the chosen setup UI route.
3. On setup selection, choose `Create project policy with sensible defaults`.
4. Confirm write.
5. Assert `.pi/agent/guardme.yaml` exists in the disposable project.
6. Restart or reload if needed so local policy is definitely loaded before other tests.

The TUI capture layer should also demonstrate local setup visually by capturing setup/confirm/success screens when feasible.

### TUI capture architecture

The TUI capture runner should:

1. create a disposable project and HOME
2. start interactive Pi in a pseudo-terminal
3. set `PI_TUI_WRITE_LOG` to a concrete artifact log path
4. open `/guardme`
5. perform local setup first if no local policy exists
6. capture all GuardMe panes into a single sanitized text file:
   - General
   - Policies
   - Rules
   - Diagnostics
   - Setup
   - setup confirmation/success screens when setup is exercised
   - warning/decision details; seed deterministic warning and decision records if the TUI fixture would not naturally create them
   - General pane runtime settings and project-trust rows, at least as captured text
7. strip ANSI/OSC/control sequences from the log
8. write section headers around each captured pane

Default generated artifact:

```text
tmp/e2e/guardme-tui-panels.txt
```

The artifact should be human-readable and intentionally not committed by default.

### Required policy scenarios

#### Setup scenario

- project starts with no `.pi/agent/guardme.yaml`
- setup creates local policy first
- local policy contains sensible default sections such as `zeroAccessPaths`, `denyPaths`, `noDeletePaths`, and `protectedCredentialPaths`

#### Allowed scenarios

- assistant calls `read README.md` and it succeeds
- assistant calls allowed validation command such as `npm test -- --help` only if the command is safe in the disposable project

#### Protected read and cloud CLI hard-deny scenarios

The e2e suite should cover at least one protected direct read and one hard-denied cloud CLI command through real assistant tool calls:

- `protected-env-read`: assistant calls `read .env.test`; expected result is a GuardMe block, no secret-like fixture content appears in tool output, and the block reason references credential/protected path behavior.
- `hard-deny-cloud-cli`: assistant calls `bash` with `aws sts get-caller-identity`; expected result is a hard block before execution and a reason that mentions cloud CLI denial.
- `hard-deny-cloud-cli-wrapper`: assistant calls one representative wrapper form such as `env -S "aws sts get-caller-identity"` or `bash -c 'aws sts get-caller-identity'`; expected result is the same hard block. Keep exhaustive wrapper coverage in unit tests.

#### Broad discovery protection

Create `.env.test` in the disposable project, then use at least one real discovery tool path that would otherwise enumerate or read across the project:

- preferred direct built-in tool checks: `grep` or `find` over `.` with a broad pattern/glob
- optional shell equivalent: `grep -R token .` or `find . -name '*'`

Expected result:

- broad discovery is blocked when a direct protected descendant is present
- `.env.test` contents are not returned in any event or artifact
- a scoped safe discovery can remain an allowed scenario if it does not touch protected descendants

#### Hard-denied `.env.test` deletion

The e2e fixture must create a file named `.env.test` in the disposable repo, then the scripted provider emits:

```bash
rm -rf .env.test
```

Expected result:

- tool call is blocked
- no approval allow option should persist an allow for this hard-denied action
- `.env.test` still exists after the scenario
- block reason mentions environment/credential/protected path behavior

This scenario is not the allow-local approval scenario because `.env*` protection is intentionally hard-denied.

#### Outside-repository protections

Use explicit concrete paths under `/tmp/guardme-e2e-outside-*`, for example:

- `/tmp/guardme-e2e-outside-read/secret.txt`
- `/tmp/guardme-e2e-outside-write/file.txt`
- `/tmp/guardme-e2e-outside-delete/file.txt`

Scenarios:

- outside read without policy blocks
- outside write/edit without policy blocks
- outside delete without policy blocks
- optional: outside read with explicit local `readOnlyPaths` rule succeeds, if added later as a positive policy test

#### Command allow boundary

The default policy allows common validation commands such as `npm test*`, but that allow must not approve appended guarded segments. Add a scenario where the scripted provider emits a compound command such as:

```bash
npm test -- --help && rm -rf build
```

Expected result:

- the compound command is blocked before any destructive segment runs
- the `build` fixture still exists
- the block reason references the guarded destructive segment or broad command-allow boundary
- a simple allowed validation command remains covered separately so the e2e suite proves normal project work still succeeds

#### Script-content and local-script bypass protection

Cover the bypass class where the assistant writes or edits a helper script and then executes it:

- `script-write-denied-content`: assistant calls `write` for an inside-project script containing a hard-denied command such as `cat .env.test` or `aws sts get-caller-identity`; expected result is blocked before the file is created or modified.
- `script-edit-denied-content`: assistant calls `edit` to insert a denied command into an existing safe script or `package.json` script; expected result is blocked and the file remains byte-for-byte unchanged.
- `local-script-exec-denied-content`: fixture contains a script with denied or policy-missing content plus a marker side effect; assistant calls `bash scripts/unsafe.sh`; expected result is blocked before execution and the marker file is not created.

Use only fake fixture secrets and marker files. Keep the commands concrete and deterministic.

#### Policy-missing generic command flow

Dangerous delete approval does not prove default-deny shell-command approval. Add a safe generic command scenario such as `node -e "console.log('guardme generic')"` or another deterministic no-network command that is not covered by `allowCommands`.

Expected result:

1. First attempt blocks with `policy-missing-command` coaching and writes warning state.
2. Repeated attempt opens approval UI in RPC.
3. At least one phase selects `Deny once` or `Allow once` without writing YAML.
4. If the scenario saves a rule, it must save a narrow exact `allowCommands` entry and survive restart.

#### Optional hard-protection precedence check

If implementation time permits, pre-seed a local policy that appears to allow a protected target such as `.env.test`, then verify the protected read/delete still blocks. This proves real config loading plus deny-over-allow precedence from the outside.

#### Approval persistence with allow-local

Use a non-hard-denied dangerous command so approval can legitimately allow it. Because `.env.test` must remain hard-denied, use a separate safe disposable target such as:

```bash
rm -rf /tmp/guardme-e2e-approval-target/file.txt
```

or an inside-project non-secret target if the policy permits approval. The target must be safe to delete and recreated between phases.

Flow:

1. First attempt blocks with coaching and writes warning state.
2. Second same attempt shows approval; e2e selects `Deny once`.
3. Assert target still exists and no allow rule is written.
4. Third same attempt shows approval; e2e selects `Allow + save project rule`.
5. Assert command runs and local YAML contains exact `allowCommands` rule.
6. Restart Pi with same fixture HOME/project.
7. Recreate target.
8. Same command is allowed without a new approval prompt.

### Non-goals

- Do not add these e2e tests to CI yet.
- Do not use real LLM providers or real cloud credentials.
- Do not treat TUI text snapshots as pixel-perfect UI tests.
- Do not test user-entered `!` / `!!` shell escapes as GuardMe-protected actions.

## Implementation Phases

### Phase 1: Foundation

- Add e2e directory structure and helpers.
- Add separate npm scripts.
- Add scripted provider fixture.
- Add disposable project/HOME setup helper.

### Phase 2: RPC E2E

- Implement local setup-first flow.
- Implement allowed/denied/outside path scenarios.
- Implement protected read, cloud CLI hard-deny, broad discovery, command-allow boundary, script-content, and local-script execution scenarios.
- Implement `.env.test` deletion hard-deny scenario.
- Implement policy-missing command approval if it is not already covered by the dangerous-command approval flow.
- Implement allow-local approval persistence across restart.

### Phase 3: TUI Capture

- Implement pseudo-terminal runner.
- Capture setup and all GuardMe panes into one text artifact.
- Document local run command and artifact location.

## Acceptance Criteria

- `npm test` remains unit/integration only.
- `npm run test:e2e` runs the separate e2e suite.
- The e2e suite starts Pi as a subprocess with GuardMe loaded via `-e .`.
- The first e2e flow creates local GuardMe configuration before other policy scenarios.
- A scripted provider emits deterministic assistant tool calls without network access.
- `.env.test` read and deletion via `rm -rf .env.test` are blocked and the file remains.
- `aws sts get-caller-identity` and one representative wrapped cloud CLI form are hard-blocked before execution.
- Broad discovery over a project containing protected descendants is blocked without leaking fixture secret content.
- Outside-repository read/write/delete attempts under `/tmp/...` are blocked by default.
- Broad allowed validation command patterns do not approve appended guarded segments.
- Generated script writes/edits and local script execution cannot bypass command/path policy.
- A repeated policy-missing generic command is coached first and can be approved only through the UI flow.
- A repeated dangerous non-hard-denied command supports deny-once, then allow-local, then persists across Pi restart.
- TUI capture creates a single text file containing all GuardMe panels.
- E2E artifacts are ignored by git unless explicitly promoted to docs.

## Validation Commands

- `npm test` - Existing fast tests still pass.
- `npm run test:e2e` - Run all non-CI e2e tests locally.
- `npm run test:e2e:rpc` - Run deterministic RPC e2e tests only.
- `npm run test:e2e:tui` - Run TUI capture locally and generate the panel artifact.
- `npm run validate` - Existing package validation remains green.

## Notes

- Prefer Node `child_process.spawn` for RPC e2e and a pseudo-terminal tool for TUI capture.
- If a new dependency is needed for robust PTY control, keep it in `devDependencies` only and document why.
- TUI automation should be resilient: assert key labels and sections, not exact frame spacing.
