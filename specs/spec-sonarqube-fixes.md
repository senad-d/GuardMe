# Plan: SonarQube Fixes

## Task Description
Create and execute a fix backlog for every active SonarQube/SonarCloud issue currently reported for `senad-d_GuardMe`.

## Objective
Resolve all 32 active Sonar issues listed below, preserve existing GuardMe behavior, and return the Sonar quality gate from `ERROR` to passing.

## Problem Statement
The current Sonar project summary reports quality gate `ERROR`, 26 code smells, and 6 vulnerabilities. The issues are concentrated in publish scripts, CI workflows, policy parsing/evaluation helpers, configuration UI rendering, and e2e helpers.

## Solution Approach
Fix one Sonar issue per task. Prefer minimal behavior-preserving changes, keep issue IDs in commit notes or PR descriptions, and validate locally after each coherent group of changes. For Sonar guidance, follow the exact rule messages and remediation guidance returned by Sonar.

## Sonar Snapshot
- Project: `senad-d_GuardMe`
- Quality gate: `ERROR`
- Active issues read: 32
- Code smells: 26
- Vulnerabilities: 6
- Security hotspots: 0
- Coverage: 0.0

## Relevant Files
Use these files to complete the tasks:

- `scripts/publish-npm.mjs` — publish-time validation, git/npm command spawning, and child process environment hardening.
- `scripts/coverage.mjs` — coverage runner with top-level promise handling.
- `.github/workflows/ci.yml` — CI dependency installation command.
- `.github/workflows/e2e-tui.yml` — TUI e2e dependency installation command.
- `src/commands/guardme-command.ts` — GuardMe command rendering, setup flow action typing, and project trust options.
- `src/policy/commands.ts` — command option parsing helpers.
- `src/policy/evaluate.ts` — credential path pattern helpers.
- `src/policy/redact.ts` — sensitive text redaction regexes.
- `src/policy/script-content.ts` — script/YAML parsing helpers and ANSI stripping.
- `src/ui/config-frame.ts` — configuration frame value typing and formatting.
- `src/ui/config-tui.ts` — configuration TUI components and row activation handlers.
- `test/e2e/fixtures/scripted-provider.ts` — scripted provider fixture shell quoting.
- `test/e2e/helpers/rpc-client.mjs` — RPC client stdout event handling.
- `test/e2e/helpers/tui-capture.mjs` — TUI capture fixture custom handlers.

## Implementation Phases

### Phase 1: Security and Reliability
Address vulnerabilities and reliability-impacting issues first: CI install hardening, PATH-dependent command execution, and loop counter assignment.

### Phase 2: High-Severity Maintainability
Address blocker/critical/major maintainability issues: invariant returns, cognitive complexity, duplicate implementations, nested ternaries, nested template literals, regex character classes, and string-prefix checks.

### Phase 3: Low-Severity Maintainability
Address minor readability issues: generic `Error` type checks, repeated union types, unnecessary array cloning, `.find()` existence checks, and negated conditions.

### Phase 4: Validation and Sonar Recheck
Run local validation, then rerun Sonar analysis and confirm all listed issue IDs are gone.

## Step by Step Tasks
IMPORTANT: Execute every step in order, top to bottom. Mark each checkbox with `x` only after its acceptance criteria are met.

### 1. Fix version type-check error specificity

- [x] In `scripts/publish-npm.mjs:30`, update the `validateVersionInput` non-string type-check throw to use `TypeError` instead of generic `Error`.

#### Sonar issue
- ID: `AZ8iPgSbQNFxXeYuOqhm`
- Rule: `javascript:S7786`
- Message: ``new Error()` is too unspecific for a type check. Use `new TypeError()` instead.`

#### Acceptance criteria
- The listed Sonar issue no longer appears.
- `validateVersionInput` still rejects non-string values with the same message.
- Existing version validation behavior is unchanged.

### 2. Fix package-name type-check error specificity

- [x] In `scripts/publish-npm.mjs:41`, update the `validatePackageName` non-string type-check throw to use `TypeError` instead of generic `Error`.

#### Sonar issue
- ID: `AZ8iPgSbQNFxXeYuOqhn`
- Rule: `javascript:S7786`
- Message: ``new Error()` is too unspecific for a type check. Use `new TypeError()` instead.`

#### Acceptance criteria
- The listed Sonar issue no longer appears.
- `validatePackageName` still rejects non-string names with the same message.
- Existing package-name validation behavior is unchanged.

### 3. Remove duplicate character-class overlap in package-name validation

- [x] In `scripts/publish-npm.mjs:46`, remove the duplicate/overlapping character-class logic from the package-name whitespace/control-character regex while preserving the same validation intent.

#### Sonar issue
- ID: `AZ8iPgSbQNFxXeYuOqho`
- Rule: `javascript:S5869`
- Message: `Remove duplicates in this character class.`

#### Acceptance criteria
- The listed Sonar issue no longer appears.
- Package names with whitespace or control characters are still rejected.
- Valid lowercase package names are still accepted.

### 4. Fix git-branch type-check error specificity

- [x] In `scripts/publish-npm.mjs:79`, update the `validateGitBranchName` non-string type-check throw to use `TypeError` instead of generic `Error`.

#### Sonar issue
- ID: `AZ8iPgSbQNFxXeYuOqhp`
- Rule: `javascript:S7786`
- Message: ``new Error()` is too unspecific for a type check. Use `new TypeError()` instead.`

#### Acceptance criteria
- The listed Sonar issue no longer appears.
- `validateGitBranchName` still rejects non-string branch names with the same message.
- Existing branch-name validation behavior is unchanged.

### 5. Remove PATH reliance from git capture execution

- [x] In `scripts/publish-npm.mjs:100`, revise the `execFileSync` git invocation so OS command execution does not rely on PATH resolution.

#### Sonar issue
- ID: `AZ8iPgSbQNFxXeYuOqhq`
- Rule: `javascript:S4036`
- Message: `Make sure the "PATH" variable only contains fixed, unwriteable directories.`

#### Acceptance criteria
- The listed Sonar vulnerability no longer appears.
- Git status capture still works from the repository root.
- Existing `SAFE_CHILD_PATH` environment hardening remains intact or is replaced by an equally fixed, non-user-writable approach.

### 6. Remove PATH reliance from git spawn execution

- [x] In `scripts/publish-npm.mjs:111`, revise the `spawnSync` git invocation so OS command execution does not rely on PATH resolution.

#### Sonar issue
- ID: `AZ8iPgSbQNFxXeYuOqhr`
- Rule: `javascript:S4036`
- Message: `Make sure the "PATH" variable only contains fixed, unwriteable directories.`

#### Acceptance criteria
- The listed Sonar vulnerability no longer appears.
- Git spawn operations still run with the same arguments, cwd, stdio, and environment behavior.
- Publishing flow behavior is unchanged except for safer command resolution.

### 7. Remove PATH reliance from npm spawn execution

- [x] In `scripts/publish-npm.mjs:120`, revise the `spawnSync` npm invocation so OS command execution does not rely on PATH resolution.

#### Sonar issue
- ID: `AZ8iPgSbQNFxXeYuOqhs`
- Rule: `javascript:S4036`
- Message: `Make sure the "PATH" variable only contains fixed, unwriteable directories.`

#### Acceptance criteria
- The listed Sonar vulnerability no longer appears.
- npm `whoami`, version, and publish-related spawn operations still run as before.
- Publishing flow behavior is unchanged except for safer command resolution.

### 8. Fix command-argument type-check error specificity

- [x] In `scripts/publish-npm.mjs:146`, update the non-array command-argument type-check throw to use `TypeError` instead of generic `Error`.

#### Sonar issue
- ID: `AZ8iPgSbQNFxXeYuOqht`
- Rule: `javascript:S7786`
- Message: ``new Error()` is too unspecific for a type check. Use `new TypeError()` instead.`

#### Acceptance criteria
- The listed Sonar issue no longer appears.
- `assertSafeCommandArgs` still rejects non-array arguments with the same message.
- Existing argument validation behavior is unchanged.

### 9. Add a type alias for setup action flow results

- [x] In `src/commands/guardme-command.ts:238`, introduce a meaningful type alias for `ConfigAction | "continue" | undefined` and use it at the reported location and related flow locations.

#### Sonar issue
- ID: `AZ8iPgPQQNFxXeYuOqhk`
- Rule: `typescript:S4323`
- Message: `Replace this union type with a type alias.`

#### Acceptance criteria
- The listed Sonar issue no longer appears.
- The alias is used consistently for the repeated setup action result type.
- TypeScript compilation succeeds without changing setup flow behavior.

### 10. Remove unnecessary array cloning in negative integer option parsing

- [x] In `src/policy/commands.ts:2061`, remove the unnecessary array clone from `isNegativeIntegerOption` while preserving ASCII digit validation.

#### Sonar issue
- ID: `AZ8iPgMyQNFxXeYuOqhc`
- Rule: `typescript:S7747`
- Message: `Unnecessarily cloning an array.`

#### Acceptance criteria
- The listed Sonar issue no longer appears.
- Negative integer option detection still accepts strings like `-1` and rejects non-digit suffixes.
- Command parsing tests still pass.

### 11. Use `.some()` for basename credential prefix existence checks

- [x] In `src/policy/evaluate.ts:817`, replace the `.find()` existence check with `.some()` or equivalent existence-specific logic.

#### Sonar issue
- ID: `AZ8iPgNQQNFxXeYuOqhd`
- Rule: `typescript:S7754`
- Message: `Prefer .some(…) over .find(…).`

#### Acceptance criteria
- The listed Sonar issue no longer appears.
- `basenameCredentialPattern` still returns the basename only when a credential prefix matches.
- Policy evaluation tests still pass.

### 12. Remove duplicate character-class overlap in secret flag redaction

- [x] In `src/policy/redact.ts:3`, remove the duplicate/overlapping character-class logic from `SECRET_FLAG_PATTERN` while preserving redaction behavior.

#### Sonar issue
- ID: `AZ8iPgODQNFxXeYuOqhj`
- Rule: `typescript:S5869`
- Message: `Remove duplicates in this character class.`

#### Acceptance criteria
- The listed Sonar issue no longer appears.
- Secret flags with quoted and unquoted values are still redacted.
- Non-secret flags are not newly redacted.

### 13. Use `startsWith()` for YAML block scalar pipe check

- [x] In `src/policy/script-content.ts:702`, replace the indexed start-of-string check for `|` with `String#startsWith`.

#### Sonar issue
- ID: `AZ8iPgNqQNFxXeYuOqhe`
- Rule: `typescript:S6557`
- Message: `Use 'String#startsWith' method instead.`

#### Acceptance criteria
- The listed Sonar issue no longer appears.
- YAML block scalar header detection for `|` remains unchanged.
- Script-content parsing tests still pass.

### 14. Use `startsWith()` for YAML block scalar greater-than check

- [x] In `src/policy/script-content.ts:702`, replace the indexed start-of-string check for `>` with `String#startsWith`.

#### Sonar issue
- ID: `AZ8iPgNqQNFxXeYuOqhf`
- Rule: `typescript:S6557`
- Message: `Use 'String#startsWith' method instead.`

#### Acceptance criteria
- The listed Sonar issue no longer appears.
- YAML block scalar header detection for `>` remains unchanged.
- Script-content parsing tests still pass.

### 15. Use `startsWith()` for YAML scalar plus sign check

- [x] In `src/policy/script-content.ts:720`, replace the indexed start-of-string check for `+` with `String#startsWith`.

#### Sonar issue
- ID: `AZ8iPgNqQNFxXeYuOqhg`
- Rule: `typescript:S6557`
- Message: `Use 'String#startsWith' method instead.`

#### Acceptance criteria
- The listed Sonar issue no longer appears.
- YAML block scalar modifier parsing for leading `+` remains unchanged.
- Script-content parsing tests still pass.

### 16. Use `startsWith()` for YAML scalar minus sign check

- [x] In `src/policy/script-content.ts:720`, replace the indexed start-of-string check for `-` with `String#startsWith`.

#### Sonar issue
- ID: `AZ8iPgNqQNFxXeYuOqhh`
- Rule: `typescript:S6557`
- Message: `Use 'String#startsWith' method instead.`

#### Acceptance criteria
- The listed Sonar issue no longer appears.
- YAML block scalar modifier parsing for leading `-` remains unchanged.
- Script-content parsing tests still pass.

### 17. Extract the nested ternary in YAML block scalar modifier parsing

- [x] In `src/policy/script-content.ts:723`, extract the nested ternary into independent statements while keeping modifier parsing behavior unchanged.

#### Sonar issue
- ID: `AZ8iPgNqQNFxXeYuOqhi`
- Rule: `typescript:S3358`
- Message: `Extract this nested ternary operation into an independent statement.`

#### Acceptance criteria
- The listed Sonar issue no longer appears.
- The logic for `digits` and trailing signs remains equivalent.
- TypeScript compilation and script-content tests pass.

### 18. Add a type alias for frame value types

- [x] In `src/ui/config-frame.ts:60`, introduce a meaningful type alias for the repeated `string | number | boolean` value type and use it at the reported and related locations.

#### Sonar issue
- ID: `AZ8iPgJmQNFxXeYuOqha`
- Rule: `typescript:S4323`
- Message: `Replace this union type with a type alias.`

#### Acceptance criteria
- The listed Sonar issue no longer appears.
- Frame row value typing remains equivalent.
- TUI rendering tests and TypeScript compilation pass.

### 19. Refactor duplicate General-row activation implementations

- [x] In `src/ui/config-tui.ts:734`, update the function whose implementation duplicates line 502 so the shared intent is explicit and duplication is removed.

#### Sonar issue
- ID: `AZ8iPgMDQNFxXeYuOqhb`
- Rule: `typescript:S4144`
- Message: `Update this function so that its implementation is not identical to the one on line 502.`

#### Acceptance criteria
- The listed Sonar issue no longer appears.
- Both config and success components still activate General rows identically from a user perspective.
- Prefer a shared top-level helper over adding nested functions.

### 20. Remove nested template literal in scripted provider shell quoting

- [x] In `test/e2e/fixtures/scripted-provider.ts:112`, refactor the nested template literal in `shellQuote` into a separate statement or constant.

#### Sonar issue
- ID: `AZ8iPgQQQNFxXeYuOqhl`
- Rule: `typescript:S4624`
- Message: `Refactor this code to not use nested template literals.`

#### Acceptance criteria
- The listed Sonar issue no longer appears.
- Shell quoting still escapes single quotes as before.
- E2E scripted provider scenarios still pass.

### 21. Use top-level await in the coverage script

- [x] In `scripts/coverage.mjs:60`, replace the top-level promise chain with top-level `await` and equivalent error handling.

#### Sonar issue
- ID: `AZ8iPgStQNFxXeYuOqhu`
- Rule: `javascript:S7785`
- Message: `Prefer top-level await over using a promise chain.`

#### Acceptance criteria
- The listed Sonar issue no longer appears.
- `npm run coverage` still writes `coverage/lcov.info` on success.
- Failure handling still writes an error message and sets a non-zero exit code.

### 22. Disable lifecycle scripts during CI dependency installation

- [x] In `.github/workflows/ci.yml:33`, update the dependency installation command so package-manager lifecycle scripts do not run during install.

#### Sonar issue
- ID: `AZ8iPgTMQNFxXeYuOqhv`
- Rule: `githubactions:S6505`
- Message: `Omitting "--ignore-scripts" allows lifecycle scripts to run during package installation.`

#### Acceptance criteria
- The listed Sonar vulnerability no longer appears.
- CI dependency installation still succeeds.
- The subsequent `npm run validate` step still has all dependencies available.

### 23. Require locked dependency resolution in CI

- [x] In `.github/workflows/ci.yml:33`, update the dependency installation command so it uses the committed lock file and does not resolve floating dependency versions.

#### Sonar issue
- ID: `AZ8iPgTMQNFxXeYuOqhw`
- Rule: `githubactions:S8543`
- Message: `Using dependencies without locking resolved versions is security-sensitive.`

#### Acceptance criteria
- The listed Sonar vulnerability no longer appears.
- CI install uses `package-lock.json` deterministically.
- This task remains compatible with task 22, preferably as one hardened install command.

### 24. Disable lifecycle scripts during E2E TUI dependency installation

- [x] In `.github/workflows/e2e-tui.yml:35`, update the dependency installation command so package-manager lifecycle scripts do not run during install.

#### Sonar issue
- ID: `AZ8iPgTjQNFxXeYuOqhx`
- Rule: `githubactions:S6505`
- Message: `Omitting "--ignore-scripts" allows lifecycle scripts to run during package installation.`

#### Acceptance criteria
- The listed Sonar vulnerability no longer appears.
- E2E TUI workflow dependency installation still succeeds.
- `npm run test:e2e:tui` still runs after install.

### 25. Add a type alias for GuardMe status context picks

- [x] In `src/commands/guardme-command.ts:131`, introduce a meaningful type alias for `Pick<GuardMeCommandContext, "cwd" | "homeDir" | "isProjectTrusted">` and use it at repeated locations.

#### Sonar issue
- ID: `AZ8dpv95IBtyveMqfJ0I`
- Rule: `typescript:S4323`
- Message: `Replace this union type with a type alias.`

#### Acceptance criteria
- The listed Sonar issue no longer appears.
- `renderStatus`, `renderDiagnostics`, `renderPaths`, and `createConfigSnapshot` retain equivalent parameter typing.
- TypeScript compilation passes.

### 26. Invert the project trust option condition

- [x] In `src/commands/guardme-command.ts:602`, invert the negated condition and swap branches so the conditional reads positively.

#### Sonar issue
- ID: `AZ8dpv95IBtyveMqfJ0Q`
- Rule: `typescript:S7735`
- Message: `Unexpected negated condition.`

#### Acceptance criteria
- The listed Sonar issue no longer appears.
- The object spread still includes `projectTrusted` only when an override exists.
- Setup/session behavior is unchanged.

### 27. Remove duplicate character-class overlap in secret assignment redaction

- [x] In `src/policy/redact.ts:1`, remove the duplicate/overlapping character-class logic from `SECRET_ASSIGNMENT_PATTERN` while preserving redaction behavior.

#### Sonar issue
- ID: `AZ8dpv8FIBtyveMqfJy3`
- Rule: `typescript:S5869`
- Message: `Remove duplicates in this character class.`

#### Acceptance criteria
- The listed Sonar issue no longer appears.
- Secret assignments with quoted and unquoted values are still redacted.
- Non-secret assignments are not newly redacted.

### 28. Remove loop-counter assignment from ANSI control sequence stripping

- [x] In `src/policy/script-content.ts:200`, refactor the loop so the loop counter is not assigned inside the loop body.

#### Sonar issue
- ID: `AZ8dpv8PIBtyveMqfJzF`
- Rule: `typescript:S2310`
- Message: `Remove this assignment of "index".`

#### Acceptance criteria
- The listed Sonar issue no longer appears.
- ANSI control sequences are still skipped exactly as before.
- Unterminated escape sequences are still preserved exactly as before.

### 29. Reduce RPC stdout handler cognitive complexity

- [x] In `test/e2e/helpers/rpc-client.mjs:264`, refactor `handleStdoutLine` to reduce cognitive complexity from 18 to 15 or lower.

#### Sonar issue
- ID: `AZ8dpv_fIBtyveMqfJ0v`
- Rule: `javascript:S3776`
- Message: `Refactor this function to reduce its Cognitive Complexity from 18 to the 15 allowed.`

#### Acceptance criteria
- The listed Sonar issue no longer appears.
- JSON parse errors, responses, UI requests, extension errors, and event waiter resolution still behave as before.
- Prefer extracted top-level or class helper methods over nested functions.

### 30. Remove unnecessary event waiter array spread

- [x] In `test/e2e/helpers/rpc-client.mjs:316`, remove the unnecessary spread conversion from the `for...of` event waiter loop without changing waiter resolution behavior.

#### Sonar issue
- ID: `AZ8dpv_fIBtyveMqfJ0w`
- Rule: `javascript:S7747`
- Message: ``for…of` can iterate over iterable, it's unnecessary to convert to an array.`

#### Acceptance criteria
- The listed Sonar issue no longer appears.
- Multiple matching or non-matching waiters are not skipped accidentally.
- RPC e2e tests still pass.

### 31. Refactor first TUI capture custom handler invariant returns

- [x] In `test/e2e/helpers/tui-capture.mjs:157`, refactor the custom handler so it no longer has multiple return statements returning the same value.

#### Sonar issue
- ID: `AZ8dpv-_IBtyveMqfJ0o`
- Rule: `javascript:S3516`
- Message: `Refactor this function to not always return the same value.`

#### Acceptance criteria
- The listed Sonar issue no longer appears.
- The first capture scenario still drives the same component inputs.
- The handler still returns the selected value once per invocation.

### 32. Refactor second TUI capture custom handler invariant returns

- [x] In `test/e2e/helpers/tui-capture.mjs:264`, refactor the custom handler so it no longer has multiple return statements returning the same value.

#### Sonar issue
- ID: `AZ8dpv-_IBtyveMqfJ0p`
- Rule: `javascript:S3516`
- Message: `Refactor this function to not always return the same value.`

#### Acceptance criteria
- The listed Sonar issue no longer appears.
- The second capture scenario still drives the same component inputs.
- The handler still returns the selected value once per invocation.

## Testing Strategy
- Run focused tests after changing each affected area where practical.
- Run full repository validation before marking the spec complete.
- Rerun Sonar analysis after local validation to confirm all listed issue IDs are resolved.

## Acceptance Criteria
- All 32 task checkboxes are marked `[x]` only after their task-specific acceptance criteria pass.
- No listed Sonar issue ID remains active after a fresh Sonar analysis.
- No new Sonar vulnerabilities or blocker/critical code smells are introduced.
- Existing GuardMe command, policy, TUI, publish-script, and e2e behavior remains intact.

## Validation Commands
Execute these commands to validate the task is complete:

- `npm run typecheck` — TypeScript compilation.
- `npm test` — Unit tests.
- `npm run check` — Package/content checks.
- `npm run coverage` — Coverage generation for Sonar input.
- `npm run test:e2e:rpc` — RPC e2e coverage for RPC helper changes.
- `npm run test:e2e:tui` — TUI e2e coverage for TUI helper/workflow changes.
- `npm run validate` — Project validation bundle.
- `sonar-scanner` — Optional when Sonar credentials are available; confirm the 32 listed issue IDs are gone.

## Notes
- Sonar source snippets were unavailable for many issues, so use the listed local file paths and line numbers as the implementation source of truth.
- Some tasks can be implemented in the same edit when they touch the same line or command, but keep each task checkbox separate and mark each one only after its own Sonar issue is resolved.
