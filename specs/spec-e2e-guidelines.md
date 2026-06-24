# Plan: GuardMe E2E Test Guidelines

## Task Description

Define engineering guidelines for implementing GuardMe e2e tests that start Pi, exercise real extension behavior, capture TUI text, and verify setup, allow, deny, approval, persistence, and outside-repository protections.

## Objective

Keep the e2e suite realistic, deterministic, safe, and separate from fast tests while avoiding accidental filesystem or credential exposure.

## Problem Statement

GuardMe is security-sensitive. E2E tests that spawn Pi and execute assistant-requested commands can accidentally touch local files, global Pi state, or real credentials if they are not isolated. TUI automation can also become brittle if it asserts exact terminal rendering instead of meaningful UI content.

## Solution Approach

Use disposable project/HOME directories, a deterministic scripted provider, explicit file paths, and narrowly scoped assertions. Run e2e tests only through separate scripts. Generate TUI panel captures as local artifacts, not CI requirements.

## Relevant Files

- `specs/spec-e2e-architecture.md` - architecture and flow decisions for this e2e suite.
- `test/e2e/` - new e2e tests and helpers.
- `test/e2e/fixtures/scripted-provider.ts` - deterministic provider fixture.
- `package.json` - separate scripts such as `test:e2e`, `test:e2e:rpc`, and `test:e2e:tui`.
- `docs/VALIDATION.md` - user-facing e2e run instructions after implementation.
- `.gitignore` - generated TUI artifacts and temp outputs must remain ignored.

## Guidelines

### Separation

- Do not add e2e tests to the default `npm test` command.
- Do not add e2e tests to CI yet.
- Add dedicated commands:
  - `npm run test:e2e`
  - `npm run test:e2e:rpc`
  - `npm run test:e2e:tui`
- Keep e2e helpers under `test/e2e/` so they are clearly distinct from unit tests.

### Process isolation

- Every e2e test must use a disposable project directory and disposable HOME.
- Never use the developer's real `~/.pi/agent` state.
- Spawn Pi with environment overrides:
  - `HOME=<fixture-home>`
  - `PI_OFFLINE=1`
  - `PI_SKIP_VERSION_CHECK=1`
- Use `--no-extensions -e .` so only GuardMe and explicit test fixtures load.
- Use `--approve` to avoid interactive trust prompts in subprocess tests.
- Use `--no-session` unless a scenario explicitly needs session persistence.

### Shell safety

- Commands emitted by the scripted provider must be explicit and safe.
- Use fake secret values only; assertions must verify those fake values do not appear in tool output or artifacts for blocked scenarios.
- Destructive or script-execution scenarios must use marker files under the fixture root or `/tmp/guardme-e2e-*` so the test can prove whether execution happened.
- Avoid variable/substitution temp paths in shell commands.
- Prefer concrete paths under:
  - the disposable project
  - `/tmp/guardme-e2e-*`
- Never point destructive commands at broad paths like `/tmp`, the repository root, `$HOME`, or parent directories.
- Never call real cloud CLIs in a way that could reach credentials; hard-deny tests should rely on GuardMe blocking before execution.
- For destructive approval tests, recreate the target before each phase and assert exactly what was removed.

### Local setup first

- The first e2e flow must exercise local setup before all other policy scenarios.
- Prefer selecting project/local sensible defaults through the real `/guardme setup` flow in RPC mode.
- Assert `.pi/agent/guardme.yaml` exists after setup.
- Assert local YAML includes key sections such as:
  - `zeroAccessPaths`
  - `denyPaths`
  - `noDeletePaths`
  - `protectedCredentialPaths`
- After setup, restart or reload Pi before command scenarios if needed to ensure local policy is loaded.

### Scripted provider behavior

- The scripted provider must be deterministic and network-free.
- Scenario prompts should be explicit, e.g. `SCENARIO: hard-deny-env-delete`.
- Each scenario should emit one clear tool call unless the scenario intentionally tests multiple calls.
- Scenarios must include command-bearing `write`/`edit` tool calls and local-script execution, not only `bash` commands.
- The provider should use stable tool call IDs or predictable prefixes for easier assertions.
- Provider output should include minimal text; policy assertions should rely on tool events and filesystem state.
- If provider helper imports require `@earendil-works/pi-ai`, keep the dependency test-only/dev-only.

### RPC e2e assertions

- Assert process startup succeeds and `/guardme` command is available.
- Fail on `extension_error` events.
- For blocked tool calls, assert:
  - `tool_execution_end.isError` or tool result error semantics as emitted by Pi
  - result text contains GuardMe block reason
  - protected file still exists when applicable
  - fake secret fixture values and blocked script output do not appear in tool output, RPC logs, or TUI artifacts
- For allowed tool calls, assert:
  - tool execution completes successfully
  - expected file/output side effect occurs or remains absent as designed
- For approval flows, assert:
  - first attempt creates warning state
  - repeated attempt emits an approval `extension_ui_request`
  - deny-once blocks and writes no allow rule
  - allow-local writes project YAML
  - restart honors the saved project allow rule without another approval request

### Protected reads and cloud CLI hard-denies

- Create `.env.test` with fake values only.
- Add a `protected-env-read` scenario where the provider calls the built-in `read` tool on `.env.test`.
- Add a `hard-deny-cloud-cli` scenario where the provider calls `bash` with `aws sts get-caller-identity`.
- Add one representative wrapper variant, for example `env -S "aws sts get-caller-identity"` or `bash -c 'aws sts get-caller-identity'`.
- Assert each blocks before execution.
- Assert block reasons reference protected credential paths or cloud CLI hard-deny behavior.
- Keep exhaustive wrapper/obfuscation coverage in unit tests; e2e only needs representative proof that the real Pi hook sees assistant tool calls.

### Broad discovery protection

- Use a fixture project that contains `.env.test` as a direct descendant.
- Add at least one broad discovery scenario using direct built-in `grep` or `find`; optionally add shell `grep -R`/`find` equivalents.
- Assert the broad discovery tool call is blocked by GuardMe.
- Assert fake `.env.test` content is not present in any captured tool output.
- Keep a narrowly scoped safe discovery as an allowed scenario if it is stable and useful.

### `.env.test` deletion scenario

- Create `.env.test` in the disposable project.
- Scripted provider emits:

```bash
rm -rf .env.test
```

- This must be treated as a hard/protected denial, not as an approval-allow scenario.
- Assert `.env.test` still exists.
- Assert no allow-local rule is written for `.env.test` deletion.
- Assert the block reason references environment/credential/protected path policy.

### Outside-repository scenarios

- Use concrete paths under `/tmp/guardme-e2e-*`.
- Cover at least:
  - outside read block
  - outside write/edit block
  - outside delete block
- Assert outside files are not modified or deleted unless the scenario explicitly allows a safe action.
- Keep outside test files non-sensitive and created by the test itself.

### Command allow boundary scenario

- Provide a stable fixture `package.json` with a harmless `test` script so a simple validation command can be allowed.
- Add a positive allowed validation command scenario such as `npm test -- --help` or an equivalent harmless fixture command.
- Add a compound scenario such as `npm test -- --help && rm -rf build`.
- Assert the compound command is blocked before the destructive segment executes.
- Assert the `build` fixture remains present.
- Assert the block reason references a guarded destructive segment, dangerous command, or broad command allow boundary.

### Script-content and local-script bypass scenarios

- Add a `script-write-denied-content` scenario where the assistant uses `write` to create an inside-project script containing `cat .env.test`, `aws sts get-caller-identity`, or another blocked command.
- Assert GuardMe blocks before the target file is created or modified.
- Add a `script-edit-denied-content` scenario where the assistant uses `edit` to insert a denied command into an existing safe script or `package.json` script.
- Assert the file remains byte-for-byte unchanged.
- Add a `local-script-exec-denied-content` scenario where the fixture script would create a marker file only if it actually runs.
- Assert the assistant `bash scripts/unsafe.sh` tool call is blocked and the marker file is absent.
- Use fake values only and avoid scripts that could touch real credentials or broad filesystem paths.

### Policy-missing generic command scenario

- Add a safe no-network command that is not covered by default `allowCommands`, such as `node -e "console.log('guardme generic')"`, if stable in the fixture.
- Assert the first attempt blocks with `policy-missing-command` coaching and writes warning state.
- Assert a repeated attempt opens an approval request in RPC.
- Exercise at least one non-persistent decision (`Deny once` or `Allow once`) so the test proves one-time choices do not write YAML.
- If adding persistence for this scenario, assert an exact local `allowCommands` rule and restart behavior, or document that dangerous-command persistence covers restart separately.

### Optional hard-protection precedence scenario

- Pre-seed a local YAML rule that appears to allow a protected target such as `.env.test`.
- Restart Pi so policy reloads from disk.
- Assert protected read or delete still blocks.
- This scenario proves e2e config loading and deny-over-allow behavior without replacing unit-test matrix coverage.

### Approval persistence scenario

- Use `allow-local`, not `allow-global`.
- Do not use `.env.test` for allow-local because `.env*` must remain protected.
- Use a non-hard-denied dangerous command against a safe disposable target.
- Required flow:
  1. first attempt: coaching block
  2. second attempt: approval request; choose deny once
  3. third attempt: approval request; choose allow + save project rule
  4. restart Pi
  5. same command allowed without approval
- Assert local YAML contains a narrow exact `allowCommands` entry.

### TUI capture guidelines

- TUI capture is a local artifact generator, not a CI check for now.
- Use `PI_TUI_WRITE_LOG` to capture the raw TUI stream.
- Strip ANSI, OSC, bell, and cursor control sequences before writing the artifact.
- Write one file containing all captured panels with section headers, for example:

```text
# GuardMe TUI Capture

## Setup - Select Local Defaults
...

## Setup - Confirm Write
...

## Setup - Complete
...

## General
...

## Policies
...

## Rules
...

## Diagnostics
...

## Setup
...
```

- Assert key text exists, not exact line positions.
- Capture all main panes after local setup:
  - General
  - Policies
  - Rules
  - Diagnostics
  - Setup
- Seed deterministic warning and decision records when the TUI fixture would not naturally create them, so warning/decision detail screens are captured consistently.
- Capture the General pane rows for GuardMe active/off state and project trust as text; toggling them is optional until TUI automation is stable.
- Default artifact path should be ignored, e.g. `tmp/e2e/guardme-tui-panels.txt`.

### Test data hygiene

- Do not commit generated `.pi/`, state JSONL, policy YAML from disposable tests, logs, or TUI captures.
- Test-created secret-like files such as `.env.test` must contain fake values only.
- Do not print real environment variables.
- Redact any command text that includes token-like strings in assertions or artifacts.

### Dependency rules

- Prefer no new runtime dependencies.
- Any PTY or scripted-provider helper dependency must be `devDependencies` only.
- Do not add e2e-only libraries to package `dependencies`.
- Keep published package contents unchanged unless docs/scripts intentionally change.

### Failure diagnostics

- On e2e failure, preserve useful artifacts under `tmp/e2e/...`:
  - RPC event log
  - Pi stderr
  - sanitized TUI capture
  - local policy YAML
  - state JSONL
- Do not dump large raw ANSI logs by default.
- Do not dump real home/global config paths.

## Step by Step Tasks

### 1. Prepare e2e helpers safely

- Create helper functions for disposable project/HOME creation.
- Create helper functions for spawning Pi with isolated env.
- Create JSONL reader/writer helpers for RPC.
- Create artifact writer helper under `tmp/e2e/`.

### 2. Build deterministic scripted provider

- Register `guardme-e2e/scripted` provider.
- Add a scenario router based on prompt text.
- Emit tool calls for each approved e2e scenario.
- Keep provider network-free.

### 3. Implement setup-first e2e flow

- Start Pi in RPC mode.
- Invoke `/guardme setup`.
- Respond to UI requests to create local sensible defaults.
- Assert local policy exists and contains expected sections.

### 4. Implement policy e2e scenarios

- Add allowed read/command scenario.
- Add protected `.env.test` read and cloud CLI hard-deny scenarios.
- Add broad discovery over protected descendants.
- Add `.env.test` hard-deny deletion scenario.
- Add outside read/write/delete block scenarios.
- Add command-allow boundary, script-content, and local-script execution bypass scenarios.
- Add policy-missing generic command approval behavior.
- Add approval persistence with deny-once, allow-local, and restart.

### 5. Implement TUI capture

- Start interactive Pi with `PI_TUI_WRITE_LOG`.
- Perform or verify local setup first.
- Visit all panes.
- Write one sanitized text file with all panels.

### 6. Document and validate

- Add scripts to `package.json`.
- Update `docs/VALIDATION.md`.
- Run unit tests and e2e tests locally.

## Testing Strategy

Use e2e tests for integration behavior only. Keep detailed policy matrix coverage in existing unit tests.

E2E should answer:

- Does Pi load GuardMe correctly as an extension?
- Does `/guardme` setup create local policy first?
- Do assistant tool calls go through GuardMe?
- Are hard protections, cloud CLI blocks, outside-project boundaries, and broad discovery enforced in a real Pi process?
- Do generated script writes/edits and local script execution fail closed before mutation/execution?
- Does command default-deny and repeated approval work for both dangerous and policy-missing commands?
- Does approval state survive process restart when saved locally?
- Does TUI rendering produce readable panels in one artifact?

## Acceptance Criteria

- E2E suite is separate from `npm test`.
- No CI integration is added yet.
- Local setup is tested first.
- Scripted provider is deterministic and network-free.
- `.env.test` read and deletion with `rm -rf .env.test` are blocked.
- Cloud CLI hard-deny is covered for a direct command and one representative wrapper.
- Broad discovery over protected descendants is blocked without leaking fake secret content.
- Outside `/tmp/guardme-e2e-*` read/write/delete attempts are covered.
- Broad validation command allows do not approve appended guarded segments.
- Generated script writes/edits and local script execution cannot bypass policy.
- A policy-missing generic command is coached first and reaches approval on repeat.
- Approval persistence uses `allow-local` and survives restart.
- TUI capture writes one file containing all main GuardMe panels.
- Generated e2e artifacts are ignored.

## Validation Commands

- `npm test` - Fast unit/integration tests.
- `npm run test:e2e:rpc` - RPC e2e scenarios.
- `npm run test:e2e:tui` - TUI capture artifact generation.
- `npm run test:e2e` - All local e2e checks.
- `npm run validate` - Existing validation remains green.

## Notes

If TUI automation proves flaky, keep `test:e2e:tui` as an explicit manual/local command and do not include it in aggregate `test:e2e` until stable. The artifact creation requirement still remains for local use.
