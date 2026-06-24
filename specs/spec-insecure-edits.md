# Plan: Insecure Edits Runtime Setting

## Task Description
Add a project-local GuardMe runtime setting that lets users deliberately bypass GuardMe enforcement for `write` and `edit` tool calls. The setting should appear in `/guardme` under GENERAL directly below the existing GuardMe toggle and allow generated scripts or other file content to be written even when that content contains commands that GuardMe would normally block.

## Objective
Users can turn on an explicit, clearly-labeled escape hatch for file mutations when they need to create scripts that contain policy-denied commands, while GuardMe continues to enforce policy for shell execution, reads, discovery tools, and local-script execution.

## Problem Statement
GuardMe currently inspects proposed `write`/`edit` content before mutation. This closes generated-script bypasses, but it is too aggressive for legitimate authoring workflows where the user wants to write a script containing commands that are not allowed to run through Pi. The block happens at authoring time even though the script is not being executed.

## Solution Approach
Add a new boolean runtime setting, stored in `.pi/agent/guardme-settings.json`, named `insecureEdits` in code and labeled **Insecure edits** in the GuardMe Config UI. It defaults to `false` and is loaded only when the project is trusted, matching the existing GuardMe runtime setting behavior.

When `insecureEdits` is `true`, `write` and `edit` tool calls bypass GuardMe policy evaluation entirely: no path policy, deny rule, read-only protection, or script-content scanning is applied to those two tools. This is intentionally insecure and should require a confirmation when enabling. Other guarded tools (`bash`, `read`, `grep`, `find`, `ls`) continue to use the existing deny-first policy. Local script execution through `bash` remains inspected and blocked if the script content violates policy.

## Relevant Files

- `src/config/runtime-settings.ts` - Extend runtime settings schema, validation, defaults, and writer so `insecureEdits` persists without losing the existing `enabled` value.
- `src/events/session-store.ts` - Store the effective insecure-edits setting in session state and expose it in status formatting.
- `src/events/register-lifecycle.ts` - Populate session state from loaded runtime settings.
- `src/events/register-guard.ts` - Short-circuit `write`/`edit` enforcement when insecure edits are enabled.
- `src/ui/config-tui.ts` - Add the GENERAL row, confirmation screen, search candidate, footers, and action routing.
- `src/commands/guardme-command.ts` - Persist the new setting from `/guardme`, reload state, and show it in status output.
- `test/runtime-settings.test.mjs` - Cover default, backward-compatible loading, and persistence.
- `test/tool-guard.test.mjs` - Cover write/edit bypass while bash execution remains guarded.
- `test/config-tui.test.mjs` and `test/guardme-command.test.mjs` - Cover UI rendering/routing and command persistence.
- `README.md`, `docs/POLICY.md`, `SECURITY.md`, `CHANGELOG.md` - Document the escape hatch and its risk.

### New Files

No new source module is required.

## Implementation Phases

### Phase 1: Runtime settings foundation
- Add `insecureEdits: boolean` to runtime settings with default `false`.
- Keep old settings files valid when they only contain `enabled`.
- Update the settings writer to preserve unspecified existing setting values.

### Phase 2: Enforcement bypass
- Add `insecureEdits` to `GuardMeSessionState` during session startup.
- In `evaluateGuardedToolCall`, allow `write`/`edit` immediately when GuardMe is enabled and insecure edits are on.
- Leave all non-edit tools and bash local-script execution behavior unchanged.

### Phase 3: UI, command, docs, and tests
- Add the GENERAL row directly below GuardMe.
- Require confirmation when enabling insecure edits; allow disabling directly.
- Persist changes through `/guardme`, reload state, and update status/summary output.
- Update tests and docs.

## Step by Step Tasks

### 1. Extend runtime settings
- Add the `insecureEdits` field to the TypeScript interface.
- Default missing or invalid settings to `enabled: true` and `insecureEdits: false`.
- Accept legacy JSON that has `version` and `enabled` but no `insecureEdits`.
- Update writes so changing one runtime setting preserves the other.

### 2. Add session state and guard bypass
- Add `insecureEdits` to `GuardMeSessionState`.
- Set it from `settings.settings.insecureEdits` in `startGuardMeSession`.
- In `evaluateGuardedToolCall`, after checking GuardMe is enabled, return `undefined` for `write` and `edit` when `insecureEdits` is true.
- Ensure `bash` remains guarded, including execution of scripts that were written while insecure edits was on.

### 3. Update GuardMe Config UI
- Add `insecureEdits` to `ConfigSnapshot`.
- Render an **Insecure edits** row immediately below **GuardMe** in GENERAL.
- Add search metadata, row selection bounds, footer text, and confirmation rows.
- Confirm enabling with risk copy that states write/edit bypasses path policy and script-content scanning.
- Disable without confirmation.

### 4. Wire command persistence
- Add a `set-insecure-edits` config action.
- Add `setInsecureEdits` command handling that writes `.pi/agent/guardme-settings.json`, reloads session state, and notifies the user.
- Preserve `enabled` when toggling insecure edits and preserve `insecureEdits` when toggling GuardMe.
- Include the setting in `/guardme status` legacy summary.

### 5. Update documentation
- Document the setting in README and policy docs.
- Explain in SECURITY that this is a deliberate authoring escape hatch, not a sandbox.
- Update CHANGELOG with user-visible behavior.

### 6. Validate
- Run focused runtime, UI, command, and guard tests.
- Run `npm run typecheck` and `npm test`.

## Testing Strategy
- Unit-test settings defaults, legacy settings compatibility, and round-trip persistence.
- Adapter-test that `write` and `edit` calls with blocked script content are allowed when insecure edits is on.
- Adapter-test that `bash ./script.sh` still blocks when the script contains denied commands.
- TUI tests for row placement, confirmation, direct disable, and search.
- Command tests for persisted JSON and notification copy.

## Acceptance Criteria
- GENERAL shows **Insecure edits** directly below **GuardMe**.
- The setting defaults to off and legacy settings files remain valid.
- Enabling requires confirmation and writes `.pi/agent/guardme-settings.json`.
- When enabled, `write` and `edit` tool calls bypass GuardMe policy and script-content scanning.
- Other guarded tools remain protected, including `bash` execution of local scripts.
- Toggling GuardMe does not reset the insecure-edits value, and toggling insecure edits does not reset GuardMe enabled/off.
- Tests and documentation cover the insecure behavior clearly.

## Validation Commands
- `node --test test/runtime-settings.test.mjs test/tool-guard.test.mjs test/config-tui.test.mjs test/guardme-command.test.mjs`
- `npm run typecheck`
- `npm test`

## Notes
This feature intentionally weakens write/edit protection. The UI and docs should use warning language and avoid implying that GuardMe still protects file mutations while insecure edits is on.
