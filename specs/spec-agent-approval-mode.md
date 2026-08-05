# Agent Approval Mode Handoff

## Goal

Add explicit opt-in `approvalMode: agent` behavior without allowing persisted warnings or same-response duplicate tool calls to bypass the first in-process block.

## Current state

Implementation, tests, and documentation are complete and remain uncommitted. Final verification passed: focused tests (`90/90`), the full unit suite (`259/259`), RPC e2e (`3/3`), typecheck, formatting, package-content validation, and `npm run validate`.

### 1. Add the `agent` configuration mode

- [x] Accept `agent` in YAML and `GUARDME_APPROVAL_MODE` validation.
- [x] Preserve `auto` as the default and fail invalid values closed to `block`.
- [x] Show the resolved mode in the `/guardme` Policies pane.

#### Why

Automatic behavior must be explicit because persisted warning fingerprints can outlive an agent process.

#### How

Extend the approval-mode union, schema diagnostic, config tests, and read-only configuration display.

#### Where

- `src/config/approval-mode.ts`
- `src/config/schema.ts`
- `src/commands/guardme-command.ts`
- `src/ui/config-tui.ts`
- `test/approval-mode.test.mjs`
- `test/config-tui.test.mjs`

#### Acceptance criteria

- `approvalMode: agent` loads from global/project YAML.
- `GUARDME_APPROVAL_MODE=agent` overrides YAML.
- Invalid modes still resolve to `block` with diagnostics.
- `/guardme` shows the effective mode and override order.

### 2. Implement process-local, turn-aware approval

- [x] Register `turn_start` and track a monotonically increasing in-memory turn counter.
- [x] Arm a fingerprint when its first coachable attempt blocks in RPC/JSON/print agent mode.
- [x] Block same-turn duplicates.
- [x] Allow-once only an identical fingerprint armed in an earlier turn.
- [x] Consume the approval so the next execution starts another block/retry cycle.
- [x] Keep TUI behavior on the existing user approval prompt.
- [x] Add defense-in-depth eligibility checks for deny/protection categories and reason codes.

#### Why

Persisted `guardme-state.jsonl` warnings and sibling tool calls from one assistant response must not count as the first and second in-process attempts.

#### How

Keep automatic retry state in `GuardMeSessionState`, use Pi `turn_start` rather than warning counts, and resolve agent approval before invoking any non-TUI UI method.

#### Where

- `src/events/session-store.ts`
- `src/events/register-lifecycle.ts`
- `src/events/register-guard.ts`
- `src/policy/evaluate.ts`
- `src/ui/approval-modal.ts`

#### Acceptance criteria

- A fresh process blocks its first attempt even when the fingerprint exists on disk.
- Duplicate calls in one assistant response remain blocked.
- An identical later-turn retry is allowed once.
- A call after consumption is blocked until another later-turn retry.
- `agent` never invokes approval UI outside TUI.
- TUI still presents the normal six user choices.

### 3. Audit automatic decisions separately

- [x] Add validated `automatic-decision` JSONL records.
- [x] Record `allow-once`, `approvalMode: agent`, and `persistedTo: none`.
- [x] Render automatic decisions distinctly in `/guardme` warning/decision details.
- [x] Fail closed when the required automatic-decision append does not succeed.

#### Why

An automatic allow must not be represented as a user decision and must never save a policy rule.

#### How

Use a separate state-record variant and append it before consuming the in-memory approval.

#### Where

- `src/state/warnings.ts`
- `src/events/register-guard.ts`
- `src/ui/detail-formatters.ts`
- `src/ui/config-tui.ts`
- `test/warning-state.test.mjs`
- `test/detail-formatters.test.mjs`

#### Acceptance criteria

- Automatic approvals append an `automatic-decision` record.
- Loaded automatic records do not arm approval state or alter warned fingerprints.
- No local/global YAML rule is written automatically.
- Audit-write failure blocks execution and defers eligibility to a later turn.

### 4. Preserve all hard safety boundaries

- [x] Keep hard denials blocked across turns.
- [x] Keep explicit command/path deny rules blocked across turns.
- [x] Keep protected credentials and paths blocked across turns.
- [x] Keep outside-project denials blocked across turns.

#### Why

Agent mode is only an alternative approval mechanism for existing coachable decisions, not a policy-precedence override.

#### How

Require a `needs-user-decision` outcome and reject deny/protection categories and reason codes before consulting the turn gate.

#### Where

- `src/policy/evaluate.ts`
- `src/events/register-guard.ts`
- `test/tool-guard.test.mjs`
- `test/policy-evaluate.test.mjs` (add focused helper coverage if needed)

#### Acceptance criteria

- No forbidden class creates an in-memory approval candidate.
- Repeating forbidden requests in later turns never produces `automatic-decision` records.

### 5. Complete regression and integration coverage

- [x] Cover same-turn duplicate blocking, later-turn allow-once, consumption, and fresh-process persisted-warning behavior in tool-guard tests.
- [x] Cover agent-mode TUI/non-TUI UI resolution.
- [x] Cover configuration, state parsing, detail formatting, and configuration display.
- [x] Add a focused unit test for `isAgentAutomaticApprovalEligible` with synthetic deny/protection decisions.
- [x] Add an audit-write-failure test proving same-turn retries remain blocked after append failure.
- [x] Add or extend a Pi RPC/JSON e2e scenario that uses real `turn_start` events instead of directly advancing the test turn.
- [x] Run all final verification commands after the latest source edits.

#### Why

The security properties depend on actual turn boundaries, process resets, state-write behavior, and policy precedence.

#### How

Use pure eligibility tests, tool-guard integration tests, and the deterministic Pi e2e provider.

#### Where

- `test/policy-evaluate.test.mjs`
- `test/tool-guard.test.mjs`
- `test/e2e/guardme-rpc.e2e.mjs`
- `test/e2e/helpers/rpc-client.mjs` if helper changes are required
- `docs/VALIDATION.md`

#### Acceptance criteria

- Focused tests pass.
- Full `npm test` passes.
- Typecheck, formatting, package checks, and full validation pass.
- The e2e child emits no approval dialog request in `agent` mode.
- The e2e state contains an automatic audit record and no automatic YAML rule.

### 6. Finish documentation and review

- [x] Document opt-in YAML/environment configuration and exact semantics.
- [x] Document safety exclusions, consumption, audit records, and persisted-warning behavior.
- [x] Update security, structure, validation, architecture, guidelines, and changelog text.
- [x] Review all wording against final behavior after tests.
- [x] Review the complete diff and commit only when requested.

#### Why

Users must understand that `agent` is opt-in and is not subagent auto-detection or a general policy bypass.

#### How

Keep examples explicit and distinguish automatic decisions from user decisions.

#### Where

- `README.md`
- `SECURITY.md`
- `CHANGELOG.md`
- `docs/POLICY.md`
- `docs/STRUCTURE.md`
- `docs/VALIDATION.md`
- `specs/spec-architecture.md`
- `specs/spec-guidelines.md`

#### Acceptance criteria

- Documentation lists `auto | interactive | agent | block` consistently.
- Documentation states that Pi exposes run mode but no reliable subagent marker.
- Documentation recommends `GUARDME_APPROVAL_MODE=agent` only for explicitly managed children.
- Documentation clearly states every non-overridable class.

## Final verification commands

```bash
npm run typecheck
node --test test/approval-mode.test.mjs test/approval-ui.test.mjs test/policy-evaluate.test.mjs test/tool-guard.test.mjs test/warning-state.test.mjs
npm run test
npm run format:check
npm run check:pack
npm run validate
```

## Modified files currently in the worktree

### Runtime and configuration

- `src/config/approval-mode.ts`
- `src/config/schema.ts`
- `src/policy/evaluate.ts`
- `src/events/register-guard.ts`
- `src/events/register-lifecycle.ts`
- `src/events/session-store.ts`
- `src/state/warnings.ts`
- `src/ui/approval-modal.ts`
- `src/ui/config-tui.ts`
- `src/ui/detail-formatters.ts`
- `src/commands/guardme-command.ts`

### Tests

- `test/approval-mode.test.mjs`
- `test/approval-ui.test.mjs`
- `test/config-tui.test.mjs`
- `test/detail-formatters.test.mjs`
- `test/lifecycle.test.mjs`
- `test/policy-evaluate.test.mjs`
- `test/tool-guard.test.mjs`
- `test/warning-state.test.mjs`
- `test/e2e/fixtures/scripted-provider.ts`
- `test/e2e/guardme-rpc.e2e.mjs`

### Documentation and specs

- `README.md`
- `SECURITY.md`
- `CHANGELOG.md`
- `docs/POLICY.md`
- `docs/STRUCTURE.md`
- `docs/VALIDATION.md`
- `specs/spec-architecture.md`
- `specs/spec-guidelines.md`
- `specs/spec-agent-approval-mode.md`
