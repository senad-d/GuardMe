# Plan: Append Custom Rules from Setup TUI

## Task Description
Add Setup-pane functionality for appending custom GuardMe rules to the global or project-local `guardme.yaml` without replacing the existing policy file. The TUI should add two Setup options, `Add custom rule globally` and `Add custom rule locally`. Selecting either opens the existing rule-section picker, lets users enter rule values inside the GuardMe Config frame instead of the external input prompt, allows multiple rules to be added, and writes the additions to the selected policy file.

## Objective
Users can append one or more custom path/command rules to `~/.pi/agent/guardme.yaml` or `.pi/agent/guardme.yaml` from `/guardme` Setup while keeping existing policy content and applying the updated rules after save.

## Problem Statement
The existing custom policy setup flow builds a complete policy and writes it through the normal policy writer, which is appropriate for first-time/default setup but overwrites an existing policy file. Rule value collection also uses `ctx.ui.input`, which opens a separate prompt screen instead of keeping the interaction inside the GuardMe Config frame.

## Solution Approach
Introduce an append-rules flow separate from the existing create/build policy flow:

- Extend Setup choices with append modes for global/local custom rules.
- Reuse the rule-section picker but collect rule pattern/actions/reason through an in-frame TUI text-input component when running in TUI mode.
- Collect a batch of custom rules in memory until the user selects `Save policy`.
- Add a policy append writer that validates the target, validates existing YAML, deduplicates rules, and updates only GuardMe rule sections instead of replacing the policy with defaults or a blank config.
- Reload GuardMe session state after a successful append so new rules apply immediately.

## Relevant Files

- `src/ui/setup-wizard.ts`
  - Add setup modes and labels.
  - Add append-rule collection flow.
  - Replace TUI rule inputs with framed text-input components.
- `src/ui/config-tui.ts`
  - Render six Setup rows instead of four.
  - Route new Setup rows to append-rule actions.
  - Update counters, wrapping, search candidates, and footers.
- `src/commands/guardme-command.ts`
  - Handle append-rule actions from `/guardme`.
  - Use append writer for append-mode setup configs.
  - Reload session state and report accurate append/update messages.
- `src/config/write-policy.ts`
  - Add reusable append-to-policy functionality with validation, deduplication, secret-command checks, and atomic writes.
- `test/setup-wizard.test.mjs`
  - Cover new setup choices and framed TUI input.
- `test/config-tui.test.mjs`
  - Cover new Setup rows and action routing.
- New test file: `test/append-policy-rules.test.mjs`
  - Cover appending to existing YAML, creating a missing file, deduplication, and refusal on malformed YAML.

## Implementation Phases

### Phase 1: Foundation
- Define append setup modes and setup config write mode metadata.
- Add writer-level append APIs for section updates.

### Phase 2: Core Implementation
- Implement framed text-input prompts for pattern/actions/reason in TUI mode.
- Implement custom-rule append collection loop using the existing rule-section picker and `Save policy` row.
- Wire `/guardme` Setup actions to append flow and session reload.

### Phase 3: Integration & Polish
- Update confirmation/success copy so append operations do not claim they overwrite existing policies.
- Update tests for six Setup options and new append behavior.
- Run focused and full validation commands.

## Step by Step Tasks

### 1. Extend setup modes
- Add `global-add-rule` and `local-add-rule` to `SetupMode`.
- Add corresponding entries to `SETUP_MODE_CHOICES` with clear append-oriented descriptions.
- Replace hard-coded `1/4` setup counters/footers with dynamic `SETUP_MODE_CHOICES.length` values where practical.

### 2. Add framed TUI text input
- Add a setup text-input component in `src/ui/setup-wizard.ts` using `renderGuardMeFrame`.
- Support printable input, backspace, Enter submit, Escape/Ctrl-C cancel.
- Use it from `promptForRule`, `promptForActions`, and reason collection when `ctx.mode === "tui"` and `ctx.ui.custom` exists.
- Keep the existing `ctx.ui.input` fallback for non-TUI/rpc modes.

### 3. Add custom-rule append collector
- Implement `collectCustomRuleAdditions(ctx, scope)` returning a blank `GuardMePolicyConfig` containing only newly added rules.
- Use `chooseRuleSection`; after every submitted rule, return to the section picker.
- Finish when the user selects `Save policy`; cancel on Escape/q from the picker.

### 4. Add append writer
- Add exported append API in `src/config/write-policy.ts`.
- Validate target path with `validatePolicyWriteTarget`.
- Load existing YAML with `loadPolicyConfigFile` and refuse to update if there are errors.
- Deduplicate rules using the existing rule-key logic.
- For existing valid YAML, update the requested section(s) while preserving existing rules; for missing files, create a minimal policy YAML.
- Keep secret-like command rule protections.
- Write atomically and maintain owner-only file permissions for newly created temp replacements.

### 5. Wire command and TUI actions
- Add a `ConfigAction` for append-rule setup.
- Route new setup rows in `requestGuardMeConfigAction` to that action.
- In `runConfig`, collect additions, confirm/update the selected policy, and reload session state.
- In `/guardme setup`, allow selecting append modes and write them through append semantics.

### 6. Update confirmation and success copy
- Ensure append-mode confirmation says update/append, not overwrite.
- Ensure success notifications and framed success footers say updated/created and include the target path.
- Preserve project-trust guidance for local policy appends.

### 7. Test and validate
- Update existing Setup tests for six choices.
- Add tests for framed input and append writer behavior.
- Run focused tests first, then typecheck/full tests.

## Testing Strategy

- Unit-test setup mode rendering and selection wrapping.
- Unit-test framed input by simulating custom TUI component keystrokes.
- Unit-test config TUI routing for default, custom-build, and append-rule rows.
- Unit-test append writer against temp global/local policy files.
- Validate malformed/oversized/unsafe existing YAML is not rewritten.
- Run TypeScript typecheck to catch union/type updates.

## Acceptance Criteria

- Setup pane shows six options including `Add custom rule globally` and `Add custom rule locally`.
- Selecting either append option opens the rule-section picker with the same GuardMe Config frame.
- Selecting a section opens an in-frame text input instead of the external input screen.
- Users can add multiple rules before selecting `Save policy`.
- Existing policy files are updated with new rule entries without replacing them with defaults/blank policy.
- Missing target policy files are created safely.
- Malformed existing YAML is not rewritten automatically.
- Successful appends reload GuardMe session state so new rules apply.

## Validation Commands

- `npm run typecheck` - Validate TypeScript unions and imports.
- `node --test test/setup-wizard.test.mjs test/config-tui.test.mjs test/append-policy-rules.test.mjs` - Run focused tests for this feature.
- `npm test` - Run the full unit test suite.

## Notes

- Existing repository status contains unrelated modified files. Avoid touching them unless required for this feature.
- The append writer may normalize only the inserted rule snippets; it should not use the default-policy writer for append-mode saves.
