# Plan: GuardMe Implementation Tasks

## Task Description

Task-focused implementation plan for GuardMe development. These tasks were completed one checkbox at a time after repository preparation, with tests/docs updated alongside feature changes.

## Objective

Implement GuardMe's Pi-session policy enforcement for LLM tool calls, including YAML policy loading, deny-first path/command evaluation, JSONL warned-once state, TUI approval, rule persistence, command/status UX, tests, and documentation.

## Relevant Files

- `docs/PROJECT_DEFINITION_BRIEF.md` - Approved product and architecture brief.
- `specs/spec-architecture.md` - Architecture source of truth.
- `specs/spec-guidelines.md` - Implementation guidelines and security rules.
- `src/extension.ts` - Entry point that should stay small.
- `src/constants.ts` - Shared constants.
- `src/config/` - New config modules.
- `src/state/` - New JSONL state modules.
- `src/policy/` - New policy engine modules.
- `src/events/` - Pi event registration.
- `src/ui/` - Approval UI modules.
- `src/commands/` - `/guardme` command.
- `test/` - Unit and integration tests.
- `README.md`, `SECURITY.md`, `docs/` - User-facing docs.

## Step by Step Tasks

### 1. Establish GuardMe constants and entry-point wiring

- [x] Replace remaining placeholder/template source code with GuardMe constants and a small extension entry point that imports and calls planned `register*` functions only after those modules exist.

Keep `src/extension.ts` minimal and avoid putting policy logic directly in the factory. Do not start background jobs in the extension factory.

#### Acceptance criteria

- `src/extension.ts` exports `guardMe` as the default extension function.
- `src/extension.ts` only wires registration functions and contains no policy implementation logic.
- No template example command/tool remains registered at runtime.
- `npm run typecheck` passes after this task.

### 2. Add policy domain types

- [x] Create domain types for policy actions, action targets, rule sources, risk levels, policy requests, policy decisions, diagnostics, and user decisions.

Keep these types independent from Pi APIs so they can be imported by pure tests.

#### Acceptance criteria

- Policy action types cover `read`, `list`, `write`, `edit`, `delete`, `move`, `rename`, and `shell`.
- Policy decisions can represent allow, deny, coach/block, and needs-user-decision outcomes.
- Decision details include matched rule metadata and user-facing reasons.
- Unit tests can import the domain types without importing Pi runtime APIs.

### 3. Implement YAML config schema and default policy

- [x] Implement config schema, built-in default policy, validation diagnostics, and global/local config path resolution for `~/.pi/agent/guardme.yaml` and `.pi/agent/guardme.yaml`.

Do not create YAML files on startup. Built-in defaults and the installer-created global policy should cover hard protections and initial project behavior.

#### Acceptance criteria

- Missing config files are accepted and result in built-in defaults.
- Malformed config returns diagnostics with file/source information.
- The schema supports `allowPaths`, `denyPaths`, `zeroAccessPaths`, `readOnlyPaths`, `noDeletePaths`, `allowCommands`, `denyCommands`, `dangerousCommands`, and `protectedCredentialPaths`.
- Tests cover missing config, valid config, malformed config, and default hard protections.

### 4. Implement global/local policy merge semantics

- [x] Merge global YAML as the base and local YAML as project overlay, with arrays unioned and local policy unable to weaken global denials or hard protections.

Retain rule source metadata (`builtin`, `global`, `local`) for diagnostics and UI.

#### Acceptance criteria

- Global rules load before local rules.
- Local allow rules do not override global deny, `zeroAccessPaths`, `readOnlyPaths`, or `noDeletePaths`.
- Duplicate rules are deduplicated or handled predictably.
- Tests prove deny-over-allow and global-protection precedence.

### 5. Implement safe path normalization and glob matching

- [x] Implement path normalization, project-boundary detection, glob matching, and symlink-aware canonicalization for policy evaluation.

Normalize leading `@`, relative paths, absolute paths, `~`, missing paths, and traversal attempts.

#### Acceptance criteria

- Relative paths resolve against `ctx.cwd`.
- Existing paths are canonicalized with realpath where possible.
- Missing paths are resolved lexically and checked conservatively.
- Both absolute and project-relative glob matching work.
- Tests cover `@path`, `~`, `..`, absolute paths, relative paths, missing paths, and protected patterns.

### 6. Implement shell command classification

- [x] Implement a conservative shell command classifier for hard-denied, dangerous, read/list, write/edit, delete, move, rename, and ambiguous command patterns.

Focus on high-confidence detection and fail closed for dangerous ambiguity. Do not execute commands during classification.

#### Acceptance criteria

- Cloud CLIs `aws`, `az`, and `gcloud` are always classified as hard denied.
- Disk formatting/raw disk patterns are hard denied.
- `rm -rf` variants and `.git` deletion are detected.
- Credential reads such as `.env`, SSH keys, and cloud credential paths are detected.
- Ambiguous destructive/outside-project commands require user decision or block in non-UI mode.
- Tests cover hard-denied and dangerous command examples from the approved brief.

### 7. Implement the policy evaluation engine

- [x] Implement the central deny-first decision engine that evaluates normalized policy requests against hard protections, merged YAML rules, default project behavior, and dangerous-command state.

The engine should not call Pi UI directly; it should return structured decisions for adapters to handle.

#### Acceptance criteria

- Hard denials always block.
- `zeroAccessPaths`, `readOnlyPaths`, and `noDeletePaths` are always respected.
- `denyPaths`/`denyCommands` beat `allowPaths`/`allowCommands`.
- Inside-project reads/writes are allowed by default unless denied/protected.
- Outside-project reads require explicit allow/read-only rule.
- Outside-project writes/deletes/moves/renames require explicit allow and no protection match.
- Tests cover each precedence layer and default behavior.

### 8. Implement JSONL warned-once state

- [x] Implement append/read helpers for global and project JSONL state files, including warning fingerprints and user-decision records.

Keep generated state separate from YAML and avoid recording secrets or raw file contents.

#### Acceptance criteria

- State files are resolved as `~/.pi/agent/guardme-state.jsonl` and `.pi/agent/guardme-state.jsonl`.
- First warning records append as JSONL.
- Repeated warning fingerprints are detected across sessions.
- Malformed JSONL lines are tolerated with diagnostics.
- Tests cover append, read, malformed lines, and fingerprint matching.

### 9. Implement Pi lifecycle integration

- [x] Register `session_start` and `session_shutdown` handlers to load policy/state, expose diagnostics, set status, and clean up session-local data.

Keep lifecycle work bounded and do not start long-lived resources.

#### Acceptance criteria

- `session_start` loads built-in/global/local policy and state for the active `ctx.cwd`.
- Local policy is treated according to Pi project trust expectations.
- Status shows GuardMe loaded or degraded with diagnostics.
- `session_shutdown` clears status/widgets and releases in-memory state.
- No file watchers, timers, sockets, or background jobs are started.

### 10. Implement tool-call enforcement adapters

- [x] Register `tool_call` enforcement for `bash`, `read`, `write`, `edit`, `grep`, `find`, and `ls` LLM tool calls.

Map each tool's input into policy requests and use the policy engine result to allow, block, coach, or request user decision.

#### Acceptance criteria

- `bash` commands are classified and blocked/allowed according to policy.
- `read`, `grep`, `find`, and `ls` are treated as read/list/discovery actions.
- `write` and `edit` are treated as mutation actions.
- Blocked calls return clear reasons to the LLM.
- GuardMe does not guard user-entered `!`/`!!` shell escapes in this implementation.
- Adapter tests cover representative tool inputs for every guarded built-in tool.

### 11. Implement coaching behavior

- [x] Implement first-dangerous-attempt coaching that blocks the current call, records JSONL warning state, and returns safer-behavior guidance to the LLM.

Use coaching only for dangerous-but-not-hard-forbidden decisions; hard denials should simply deny with reason.

#### Acceptance criteria

- First dangerous fingerprint is blocked with a coaching reason.
- The coaching reason suggests a safer alternative or asks the model to narrow scope.
- A JSONL warning record is appended.
- Repeated dangerous fingerprint no longer uses first-time coaching and instead proceeds to user decision logic.
- Tests cover first vs repeated dangerous attempts.

### 12. Implement TUI approval modal and UI fallback

- [x] Implement a polished GuardMe approval UI that lets users allow/deny once or save allow/deny rules to local/global YAML.

Use `ctx.ui.custom()` in TUI mode and a simpler select fallback when UI exists but custom TUI is unavailable. Block when UI is unavailable.

#### Acceptance criteria

- TUI modal shows risk level, action, command/path, project root, matched rules, sources, and recommendation.
- Choices include allow once, deny once, allow local, deny local, allow global, deny global.
- Escape/cancel behaves as deny once.
- Non-UI prompt-needed decisions block with a clear reason.
- UI code does not display file contents, command output, or secrets.

### 13. Implement YAML rule persistence

- [x] Implement persistence for user-selected allow/deny rules to local or global GuardMe YAML files.

Persist only the requested rule, create YAML files only when saving/setup requires it, and reject attempts to persist rules that weaken hard protections.

#### Acceptance criteria

- Saving to local writes `.pi/agent/guardme.yaml`.
- Saving to global writes `~/.pi/agent/guardme.yaml`.
- Parent directories are created only for explicit save/setup flows.
- Saved rules include pattern/action/reason metadata.
- Hard-denied actions cannot be converted into allow rules.
- Tests cover local/global save and hard-deny rejection.

### 14. Implement `/guardme` command

- [x] Implement `/guardme` command with help, status, config path display, diagnostics, and optional setup flow.

Keep the command read-only by default; setup may create global/local default or custom YAML only after user-driven setup choices.

#### Acceptance criteria

- `/guardme` shows current status and policy source paths.
- `/guardme help` explains usage and policy paths.
- `/guardme status` lists diagnostics without leaking secrets.
- Optional setup flow uses a TUI/select setup UI before writing files.
- Command works in TUI and degrades safely in non-UI modes.

### 15. Add policy documentation

- [x] Add user-facing documentation for GuardMe policy YAML, JSONL state, default protections, precedence, approval choices, and limitations.

Keep examples concrete and label implementation limitations clearly.

#### Acceptance criteria

- `docs/POLICY.md` documents every supported YAML section.
- README links to the policy documentation.
- SECURITY states GuardMe is Pi-session enforcement, not OS sandboxing.
- Docs include examples for global/local config and saved decisions.
- Docs mention cloud CLIs are always denied by GuardMe.

### 16. Add comprehensive tests

- [x] Add unit and integration tests for config, state, path matching, command classification, policy evaluation, Pi tool-call adapters, and non-UI fail-closed behavior.

Use table-driven tests for policy examples.

#### Acceptance criteria

- Tests cover deny-over-allow precedence.
- Tests cover all hard-denied examples in the approved brief.
- Tests cover global/local config merge behavior.
- Tests cover first-warning vs repeated-warning state behavior.
- Tests cover every guarded built-in tool adapter.
- `npm run test` passes.

### 17. Update package metadata and runtime dependencies

- [x] Add only the runtime dependencies actually imported by the implementation and keep Pi core packages in peer dependencies with `"*"`.

Do not add unused dependencies. If implementation uses YAML/glob libraries, place them in `dependencies` and update lockfiles as needed. The package postinstall script must create the global GuardMe YAML with sensible defaults only when missing.

#### Acceptance criteria

- `package.json` contains no unused runtime dependencies.
- Pi core packages remain peer dependencies with `"*"`.
- Non-Pi runtime libraries are in `dependencies`.
- Development tools are in `devDependencies`.
- `npm install` succeeds and lockfile state is consistent if a lockfile is used.
- Package install creates `~/.pi/agent/guardme.yaml` with sensible defaults when missing and does not overwrite existing policy.

### 18. Run validation and isolated smoke tests

- [x] Run repository validation and perform an isolated Pi smoke test for the completed GuardMe implementation.

Use isolated loading to avoid interference from other extensions.

#### Acceptance criteria

- `npm run typecheck` passes.
- `npm run test` passes.
- `npm run check:pack` passes.
- `npm run validate` passes.
- `pi --no-extensions -e .` loads GuardMe successfully.
- Manual smoke cases demonstrate allowed project read, blocked `.env` read, blocked cloud CLI, first dangerous coaching, repeated dangerous approval, and saved YAML decision.

## Testing Strategy

Implement tests alongside each task. Prefer pure tests first, then adapter tests, then manual Pi smoke tests. Do not defer security-critical test coverage until the end.

## Acceptance Criteria

- All task checkboxes remain unchecked until implemented in a separate session.
- Each completed future task must satisfy its own acceptance criteria before checking it off.
- The final implementation must match `specs/spec-architecture.md` and `specs/spec-guidelines.md` or document approved deviations.

## Validation Commands

- `npm run typecheck` - TypeScript validation.
- `npm run test` - Unit/integration test suite.
- `npm run check:pack` - Package contents validation.
- `npm run validate` - Full repository validation.
- `pi --no-extensions -e .` - Isolated Pi smoke test.

## Notes

Do not run `subagent_tasks` against this task spec. Future feature changes should continue the one-task-at-a-time workflow and update tests/docs with each change.
