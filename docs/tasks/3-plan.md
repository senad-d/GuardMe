# Plan for objective 3

Deliver issue #28 (ci-fix): the failing check it describes blocks other pull requests.

Each task ran as its own chain on its agent; tasks without a dependency ran in parallel.

## Task preserve-pending-guidance: Preserve pending guidance across custom-triggered runs

Agent: backend. Depends on: none.

- `src/events/register-guidance.ts`
- `test/tool-guard.test.mjs`

- [ ] Fix issue #28 by preserving pending safety guidance across custom-triggered runs and delivering it exactly once to the next user-prompt run.

### Why
Pi 1.2.0 introduced before_agent_start events for idle extension-triggered custom runs. In src/events/register-guidance.ts, the current callback ignores the event, renders lastGuidance, and clears it unconditionally. A custom run can therefore consume guidance intended for the next user prompt. Existing tests use empty event objects and miss this sequence. This is a reproducible compatibility defect, not a CI workflow failure; no executed failing regression was supplied.

### Required reading and references
Read AGENTS.md and the full issue at .pi/issues/28-unblock-27-preserve-pending-guidance-across-custom-triggered-runs.json. Read the two owned files and the relevant instructions in docs/VALIDATION.md; docs/testing.md does not exist. Issue references are https://github.com/senad-d/GuardMe/pull/27 (held dependency update, context only) and https://github.com/earendil-works/pi/releases/tag/v1.2.0 (custom-run behavior change). The cached issue supplies the PR assessment; the installed Pi CHANGELOG.md under /opt/mission/node_modules/@earendil-works/pi-coding-agent/ corroborates the release change. Consult the installed SDK declarations in dist/core/extensions/types.d.ts for supported event shapes, and the repository-pinned SDK for legacy compatibility.

### How
First add an automated regression in test/tool-guard.test.mjs and demonstrate that it fails against the unchanged handler. Follow the existing guidance-test setup: block a tool request to record pending guidance, then invoke the registered before_agent_start handler with a realistic Pi 1.4.0 custom event, a realistic user event, and another user event. Assert that the custom event returns no guidance and leaves pending state intact, the first user event returns the expected guardme-guidance message and clears pending state, and the following user event returns nothing. Pi 1.4.0 discriminates events with messageType: 'custom' or 'user'; custom events carry message rather than prompt, while user events carry prompt and optional images. Populate required common fields from the SDK declarations rather than using empty mocks for this regression.

Then update src/events/register-guidance.ts to recognize custom events before consuming guidance. Skip injection and consumption for explicit custom runs. Preserve handling of legacy events without messageType; do not gate delivery solely on messageType === 'user'. Keep the change compatible with the repository's pinned SDK typings as well as Pi 1.4.0. Preserve the existing rendering, redaction, sanitization, message shape, and once-only consumption behavior.

Retain existing guidance security tests and add or strengthen coverage for no pending guidance on supported event shapes and a realistic legacy 1.1.0 user event without messageType. Preserve compatibility with existing empty-event mocks. Use the established node:test/assert, Map-backed pi.on mocks, createGuardContext, evaluateGuardedToolCall, and stopGuardMeSession conventions. Reuse test/support/outside-root.mjs for denial fixtures: OS-temp policy allowances can otherwise mask the denial. Relevant read-only context is src/events/session-store.ts for pending-state updates, src/events/register-guard.ts for redacted guidance creation, and src/ui/text.ts for sanitization. No entry-point or export change is needed. Follow strict NodeNext TypeScript, .ts imports, type-only SDK imports where applicable, two-space indentation, LF/final newline, and standalone helpers rather than nested functions.

### Where
Edit only src/events/register-guidance.ts and test/tool-guard.test.mjs. Tests belong with this fix; no separate documentation task is needed.

### Verification
Fresh worktrees lack node_modules. Install repository dependencies using the documented npm ci --ignore-scripts command. Use the documented focused check node --test test/tool-guard.test.mjs to demonstrate regression failure before the fix and success afterward. Run npm run validate against the pinned dependencies to catch legacy typing and behavior regressions. For the issue-required compatibility verification, run npm install --no-save --package-lock=false --ignore-scripts @earendil-works/pi-coding-agent@1.4.0, followed by npm run validate and npm run test:e2e. The latter covers RPC and TUI. Run the separately documented npm run format:check as well. Record actual results; never describe unexecuted checks as passing. If an environmental limitation prevents a required check, report it as unverified with what was checked instead.

### Acceptance criteria
- The regression fails on the original handler for the issue's pending-guidance → custom → user sequence, then passes with the fix.
- Custom runs neither inject nor clear pending guidance; the next user-prompt run receives it exactly once.
- No-pending behavior, actual supported user/custom shapes, legacy 1.1.0 handling, redaction, terminal-control sanitization, and existing matched-rule coverage remain passing.
- With Pi 1.4.0 temporarily installed, npm run validate and npm run test:e2e both exit 0, including the new regression.
- No verification dependency changes are committed. package.json and package-lock.json remain unchanged.

### Out of scope
Deliver the compatibility fix for main through the assigned worktree, not by changing PR #27 or its branch. Do not change dependency versions, bot configuration, CI/E2E workflows, or pre-existing undici advisories. Do not add retries or increase timeouts as a substitute for fixing guidance consumption. Mark the task complete only when its acceptance criteria are met; otherwise explicitly report remaining verification gaps.
