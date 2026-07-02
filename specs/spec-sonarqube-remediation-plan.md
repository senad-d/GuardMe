# Plan: SonarQube Remediation and Coverage

## Task Description

Create a task-focused remediation plan for all active SonarQube/SonarCloud findings currently reported for `senad-d_GuardMe`, then add a dedicated coverage task so future scans can report test coverage.

Polled Sonar snapshot:

- Project: `senad-d_GuardMe`
- Organization: `senad-d`
- Quality gate: `NONE`
- Active issues fetched: 174 of 174 across two pages
- Issue mix: 7 bugs, 13 vulnerabilities, 154 code smells
- Security hotspots: 0
- Other metrics: reliability rating `4.0`, security rating `4.0`, duplicated lines density `2.8`, maintainability rating `1.0`, NCLOC `13021`

## Baseline Record

- Remediation baseline: 174 active issues total: 7 bugs, 13 vulnerabilities, and 154 code smells.
- Security hotspot baseline: 0 open security hotspots.
- Quality gate baseline: `NONE`.
- Issue traceability: Appendix A issue IDs are the baseline IDs to keep in commit and PR notes when refactors move lines.
- Disposition control: confirmed this baseline treats all 174 Appendix A issues as active and does not document any issue as false-positive or accepted; any future false-positive or accepted disposition requires maintainer approval.
- Initial validation before remediation code changes: `npm run validate` passed on 2026-07-02, including `npm run typecheck`, `npm run test` with 213/213 tests passing, `npm run check`, and `npm run check:pack`.

## Objective

Drive the repository to a clean Sonar scan by fixing every active bug, vulnerability, and code smell listed in Appendix A, while adding a repeatable coverage report path for Sonar ingestion.

## Problem Statement

Sonar currently reports security-sensitive script/test-helper vulnerabilities, correctness bugs, high cognitive complexity, regex performance/maintainability issues, duplicate or suspicious branches, and many TypeScript/JavaScript readability issues. The repository also has no coverage script/report path in `package.json`, so Sonar cannot consistently track test coverage.

## Solution Approach

Address high-risk issues first, then refactor maintainability hotspots by domain, then apply mechanical readability fixes. Keep each remediation behavior-preserving unless the Sonar finding exposes a correctness bug. Add focused tests around every refactor before or alongside code changes. Finish by adding a single coverage task that produces `coverage/lcov.info` and by re-polling Sonar until no active issues remain.

## Relevant Files

Use these files to complete the task:

- `package.json` - Existing test/validation scripts and new coverage script.
- `scripts/publish-npm.mjs` - Security vulnerabilities around command execution and PATH handling.
- `scripts/check-format.mjs` - Regex performance finding.
- `dev-shims/pi-coding-agent/index.js` - Empty method finding.
- `src/commands/guardme-command.ts` - Complexity, ternary, and readability findings.
- `src/config/load-config.ts` - Union type alias finding.
- `src/config/merge-policy.ts` - Complexity, duplicate function, Set, and sort comparator findings.
- `src/config/runtime-settings.ts` - Complexity finding.
- `src/config/schema.ts` - Complexity, replaceAll, and RegExp.exec findings.
- `src/config/write-policy.ts` - Complexity, sort comparator, `.at`, and `String.raw` findings.
- `src/events/register-guard.ts` - includes, type alias, regex, complexity, and replaceAll findings.
- `src/events/register-lifecycle.ts` - re-export finding.
- `src/events/session-store.ts` - nested ternary finding.
- `src/policy/commands.ts` - Largest cluster: complexity, regex, duplicate branches, nested ternaries, parameter count, and readability findings.
- `src/policy/evaluate.ts` - Complexity, nested template literal, nested ternary, and `String.raw` findings.
- `src/policy/redact.ts` - Regex complexity, duplicate character classes, and concise character class findings.
- `src/policy/script-content.ts` - Regex, complexity, replaceAll, startsWith, RegExp.exec, control character, and assignment findings.
- `src/state/warnings.ts` - Complexity findings.
- `src/ui/approval-modal.ts` - findIndex/indexOf, nested template literal, repeated push, and nested ternary findings.
- `src/ui/config-frame.ts` - repeated push, nested ternary, parameter count, and default-parameter-order findings.
- `src/ui/config-tui.ts` - UI complexity, duplicate cases, nested ternaries, parameter count, and negated-condition findings.
- `src/ui/detail-formatters.ts` - conditional returning same value bug.
- `src/ui/setup-wizard.ts` - complexity, type alias, findIndex/indexOf, and ternary findings.
- `src/ui/text.ts` - complexity and Unicode code point findings.
- `test/e2e/fixtures/scripted-provider.ts` - temporary directory security and regex/readability findings.
- `test/e2e/helpers/project-fixture.mjs` - temporary directory security findings.
- `test/e2e/helpers/rpc-client.mjs` - PATH security, complexity, and iterable findings.
- `test/e2e/helpers/tui-capture.mjs` - control-character and constant-return findings.
- `test/*.test.mjs`, `test/e2e/*.mjs` - Regression tests for behavior-preserving fixes.

### New Files

- `sonar-project.properties` - Create only if the project does not already configure Sonar coverage elsewhere; include the LCOV report path.
- Optional `scripts/coverage.mjs` - Create only if package scripts need a small wrapper to generate LCOV from the Node test runner or a coverage tool.

## Implementation Phases

### Phase 1: Risk-First Remediation

Fix vulnerabilities and correctness bugs before broad refactors. Add or update tests around script spawning, temp fixture directories, sort ordering, regex behavior, and UI capture logic.

### Phase 2: Complexity and Maintainability Refactors

Split large functions into typed helper functions, replace nested ternaries with named decisions, reduce parameter counts with option objects, remove duplicate branches, and preserve public behavior through existing and new tests.

### Phase 3: Mechanical Cleanup, Coverage, and Sonar Verification

Apply low-risk readability/performance fixes, add the coverage script/report path, run the full validation suite, rerun Sonar analysis, and re-poll active issues.

## Task Detail Matrix

Use this matrix to understand where each task applies, why it matters, and the task-specific acceptance criteria before making changes.

- [x] Task 1: Establish the remediation baseline

**Where to fix/record**

- `specs/spec-sonarqube-remediation-plan.md` and PR notes.
- Sonar project `senad-d_GuardMe`, default branch/scope.

**Why**

- The baseline prevents hidden scope creep and distinguishes existing Sonar debt from issues introduced during refactors.

**Acceptance criteria**

- Baseline records 174 active issues: 7 bugs, 13 vulnerabilities, 154 code smells.
- Baseline records zero security hotspots and quality gate `NONE`.
- Initial `npm run validate` result is captured before code changes.

- [x] Task 2: Fix all security vulnerability findings

**Where to fix**

- `scripts/publish-npm.mjs`: lines 25, 41, and 95 for untrusted data passed to OS commands; lines 56 and 95 for unsafe `PATH` handling.
- `test/e2e/fixtures/scripted-provider.ts`: lines 6-8 for publicly writable directory usage.
- `test/e2e/helpers/project-fixture.mjs`: lines 5-7 and 16 for publicly writable directory usage.
- `test/e2e/helpers/rpc-client.mjs`: line 59 for unsafe `PATH` handling.

**Why**

- These findings can enable shell sandbox escape, PATH hijacking, or unsafe temporary-file behavior. They are the highest-priority fixes because they affect security boundaries even when some files are test helpers.

**Acceptance criteria**

- Publish script validates all untrusted CLI/package inputs before process execution.
- Command execution avoids shell interpolation for user-controlled data.
- Child process environments use a fixed/minimal safe `PATH` or explicit executable paths.
- Temporary test fixtures use per-test `mkdtemp`-style directories and clean them up.
- Regression tests prove malicious args, PATH injection, and unsafe temp paths are rejected or isolated.
- Sonar no longer reports IDs `AZ8dpv_-IBtyveMqfJ06`, `AZ8dpv_-IBtyveMqfJ08`, `AZ8dpv_-IBtyveMqfJ03`, `AZ8dpv_-IBtyveMqfJ04`, `AZ8dpv_-IBtyveMqfJ07`, `AZ8dpv_qIBtyveMqfJ0x`, `AZ8dpv_qIBtyveMqfJ0y`, `AZ8dpv_qIBtyveMqfJ0z`, `AZ8dpv_HIBtyveMqfJ0q`, `AZ8dpv_HIBtyveMqfJ0r`, `AZ8dpv_HIBtyveMqfJ0s`, `AZ8dpv_HIBtyveMqfJ0t`, and `AZ8dpv_fIBtyveMqfJ0u`.

- [x] Task 3: Fix all Sonar bug findings

**Where to fix**

- `src/config/merge-policy.ts`: line 199 sort comparator.
- `src/config/write-policy.ts`: line 529 sort comparator.
- `src/ui/detail-formatters.ts`: line 50 conditional expression returning the same value for both branches.
- `src/policy/script-content.ts`: line 154 unintended control character in regex.
- `test/e2e/helpers/tui-capture.mjs`: line 104 unintended control characters in regex.

**Why**

- These are correctness/reliability findings: alphabetical sort can corrupt numeric/domain ordering, identical conditional branches hide broken intent, and unintended control characters make regex behavior fragile or wrong.

**Acceptance criteria**

- Sorts use explicit numeric or domain-specific comparator functions.
- The duplicate-value conditional is removed or corrected to preserve intended true/false behavior.
- Regexes no longer contain unintended control characters and still match intended ANSI/script content cases.
- Targeted tests fail against the old behavior and pass with the corrected behavior.
- Sonar no longer reports the seven bug IDs: `AZ8dpv-gIBtyveMqfJ0d`, `AZ8dpv-qIBtyveMqfJ0h`, `AZ8dpv8PIBtyveMqfJy_`, `AZ8dpv8YIBtyveMqfJzS`, `AZ8dpv-_IBtyveMqfJ0l`, `AZ8dpv-_IBtyveMqfJ0m`, and `AZ8dpv-_IBtyveMqfJ0n`.

- [x] Task 4: Refactor command and policy parsing complexity

**Where to fix**

- `src/policy/commands.ts`: complexity hotspots at lines 348, 535, 761, 951, 1018, 1091, 1276, 1428, and 1559.
- `src/policy/commands.ts`: nested ternaries around line 890, duplicate branch around line 447, excessive parameters at line 730, and redundant `index` assignments around lines 374, 975, 999, and 1010.
- `src/policy/commands.ts`: regex/readability issues around lines 135, 401, 934, 1191, 1418, 1517, 1528, 1756, 1880, 1887, 1892, 1893, and 1931.
- Tests: `test/command-classifier.test.mjs`, `test/policy-evaluate.test.mjs`, and related policy tests.

**Why**

- Command classification is a security-critical policy boundary. High cognitive complexity, duplicate branches, and risky regexes make command decisions hard to audit and increase the chance of unsafe allow/deny behavior.

**Acceptance criteria**

- Each refactored function is at or below Sonar's cognitive complexity threshold of 15.
- The `classification` helper uses an options/context object instead of an 11-parameter signature.
- Duplicate branch and redundant assignment findings are removed without changing classification results.
- Command classifier tests cover the same deny/allow/dangerous/ambiguous cases before and after refactor.
- Sonar no longer reports any `src/policy/commands.ts` issue IDs listed in Appendix A.

- [ ] Task 5: Refactor core config, evaluation, state, and command modules

**Where to fix**

- `src/commands/guardme-command.ts`: lines 97, 127, 185, 385, 395, 398-403, 445, 580, and 598.
- `src/config/merge-policy.ts`: lines 60, 71, and 157.
- `src/config/runtime-settings.ts`: line 277.
- `src/config/schema.ts`: lines 365, 593, 601, and 641.
- `src/config/write-policy.ts`: lines 168, 362, 401, and 566.
- `src/events/register-guard.ts`: lines 431, 746, 1082, 1160, and 1279.
- `src/events/register-lifecycle.ts`: line 80.
- `src/events/session-store.ts`: line 78.
- `src/policy/evaluate.ts`: lines 111, 319, 479, 574, and 702.
- `src/policy/script-content.ts`: lines 71, 85, 188, 231, 306, 441, and 454, plus regex-specific lines handled in Task 7.
- `src/state/warnings.ts`: lines 246 and 372.

**Why**

- These modules load, merge, persist, and evaluate GuardMe policy. They must remain easy to reason about because subtle changes affect user protection and saved policy behavior.

**Acceptance criteria**

- All listed cognitive complexity functions are at or below 15.
- Nested ternaries are replaced with named decisions or simple helper functions.
- Duplicate implementations are replaced by shared helpers or intentionally differentiated logic.
- Existing tests for config, runtime settings, policy evaluation, script content, command output, lifecycle, and warning state pass.
- New regression tests cover any extracted helper with non-trivial branching.

- [ ] Task 6: Refactor UI/TUI modules and e2e UI helpers

**Where to fix**

- `src/ui/approval-modal.ts`: lines 84, 172, 195-196, and 295.
- `src/ui/config-frame.ts`: lines 133-165, 148, 221, 255, and 461.
- `src/ui/config-tui.ts`: lines 449-544, 457, 505-510, 786, 824-910, 958, 1160, 1237, 1262, 1419, 1720, 1791, and 1841-1919.
- `src/ui/setup-wizard.ts`: lines 161, 434, 445, and 561.
- `src/ui/text.ts`: lines 116 and 124.
- `test/e2e/helpers/tui-capture.mjs`: lines 144 and 247 for blocker constant-return code smell fixes.

**Why**

- UI/TUI code has many render-state branches. Reducing complexity and parameter count makes behavior easier to test while keeping approval/config screens stable.

**Acceptance criteria**

- High-complexity UI functions are split into render-state builders, action handlers, or small pure helpers.
- `renderPaneScreen` and `renderSettingRow` use typed props objects or smaller cohesive parameters.
- Duplicate cases, repeated `push()` sequences, nested template literals, nested ternaries, and negated-condition findings are removed.
- TUI capture helper return values are meaningful or the constant-return functions are removed.
- Existing UI tests pass and include focused assertions for any changed output or helper behavior.

- [ ] Task 7: Fix regex performance and maintainability issues

**Where to fix**

- `scripts/check-format.mjs`: line 51.
- `src/events/register-guard.ts`: line 1082.
- `src/policy/commands.ts`: lines 1191, 1418, 1756, and 1893.
- `src/policy/redact.ts`: lines 1 and 3.
- `src/policy/script-content.ts`: lines 154, 199, 212, 289, 344, 368, 371, 416, 420, and 458.
- `test/e2e/fixtures/scripted-provider.ts`: lines 80 and 156.

**Why**

- Super-linear regex backtracking is a reliability and potential denial-of-service risk. Duplicate/over-complex character classes also make security parsing harder to audit.

**Acceptance criteria**

- No changed regex has known super-linear backtracking on representative long inputs.
- Complex regexes are split into smaller named expressions or procedural parsing where clearer.
- Character classes remove duplicates and use concise syntax only when semantics stay unchanged.
- `.match()` checks flagged by Sonar use `RegExp.exec()`.
- Tests cover representative accepted and rejected inputs, including long adversarial strings.

- [ ] Task 8: Apply low-risk TypeScript and JavaScript readability fixes

**Where to fix**

- `dev-shims/pi-coding-agent/index.js`: line 10 empty method.
- `scripts/publish-npm.mjs`: line 146 top-level await.
- `src/config/load-config.ts`: line 29 type alias.
- Remaining minor/major readability findings across `src/commands`, `src/config`, `src/events`, `src/policy`, `src/ui`, and `test/e2e` listed in Appendix A.

**Why**

- These are mostly mechanical improvements that reduce noise in Sonar and make future reviews focus on real risk instead of style/readability debt.

**Acceptance criteria**

- Empty methods either document intentional no-op behavior clearly or are removed/replaced.
- Flagged idioms are updated to Sonar-preferred equivalents: `.find()`, type aliases, `Set.has()`, `.includes()`, `.at()`, `replaceAll()`, `startsWith()`, `codePointAt()`, `for...of`, and `export ... from`.
- Default parameters are last, or the function uses an options object.
- `npm run typecheck` and relevant tests pass after mechanical changes.

- [ ] Task 9: Add coverage reporting for Sonar

**Where to fix**

- `package.json`: add the coverage script.
- `sonar-project.properties`: create or update with `sonar.javascript.lcov.reportPaths=coverage/lcov.info` if coverage is not configured elsewhere.
- `.gitignore`: confirm `coverage/` remains ignored.
- Optional `scripts/coverage.mjs`: only if a wrapper is needed to produce LCOV.

**Why**

- Sonar currently has no repeatable LCOV input path in this repository, so quality trends miss test coverage even when tests exist.

**Acceptance criteria**

- A single documented command, preferably `npm run coverage`, generates `coverage/lcov.info`.
- Coverage command fails when tests fail.
- Sonar configuration points to `coverage/lcov.info`.
- Coverage includes the riskiest refactored areas: command classification, policy evaluation, config merge/write, script-content parsing, and UI render helpers.
- Generated coverage files are not committed.

- [ ] Task 10: Validate and re-poll Sonar

**Where to fix/verify**

- Local repository validation commands.
- Sonar project `senad-d_GuardMe` after analysis rerun.
- This spec or PR notes for final counts.

**Why**

- The plan is complete only when local checks pass and Sonar confirms the active issue inventory has been cleared or explicitly approved exceptions remain.

**Acceptance criteria**

- `npm run typecheck`, `npm run test`, `npm run test:e2e`, `npm run validate`, and the new coverage command pass.
- `coverage/lcov.info` exists after coverage runs.
- Re-polled Sonar shows zero active baseline bugs, vulnerabilities, and code smells, or each remaining item has a documented maintainer-approved rationale.

## Step by Step Tasks

IMPORTANT: Execute every step in order, top to bottom. Mark each task complete only after the linked Sonar issue IDs in Appendix A are fixed or intentionally documented with a maintainer-approved rationale.

- [x] Task 1: Establish the remediation baseline

- [x] Save this Sonar snapshot as the baseline for the remediation branch: 174 active issues, 7 bugs, 13 vulnerabilities, 154 code smells.
- [x] Confirm no issue is closed as false-positive or accepted without maintainer approval.
- [x] Keep issue IDs from Appendix A in commit/PR notes so moved-line findings can be traced after refactors.
- [x] Run the current validation suite before changes to separate existing failures from remediation regressions.

- [x] Task 2: Fix all security vulnerability findings

- [x] Harden `scripts/publish-npm.mjs` command execution: validate CLI/package arguments before invoking OS commands and avoid untrusted shell interpolation.
- [x] Replace inherited or user-controlled `PATH` usage in `scripts/publish-npm.mjs` and `test/e2e/helpers/rpc-client.mjs` with fixed, minimal, expected executable lookup behavior.
- [x] Replace publicly writable temp-directory patterns in `test/e2e/fixtures/scripted-provider.ts` and `test/e2e/helpers/project-fixture.mjs` with safe per-test temporary directories and cleanup.
- [x] Add tests proving malicious publish arguments, unsafe PATH values, and unsafe temp paths are rejected or isolated.
- Covers vulnerability IDs: `AZ8dpv_-IBtyveMqfJ06`, `AZ8dpv_-IBtyveMqfJ08`, `AZ8dpv_-IBtyveMqfJ03`, `AZ8dpv_-IBtyveMqfJ04`, `AZ8dpv_-IBtyveMqfJ07`, `AZ8dpv_qIBtyveMqfJ0x`, `AZ8dpv_qIBtyveMqfJ0y`, `AZ8dpv_qIBtyveMqfJ0z`, `AZ8dpv_HIBtyveMqfJ0q`, `AZ8dpv_HIBtyveMqfJ0r`, `AZ8dpv_HIBtyveMqfJ0s`, `AZ8dpv_HIBtyveMqfJ0t`, `AZ8dpv_fIBtyveMqfJ0u`.
- Local validation: `npm run typecheck`, `npm run test`, `npm run test:e2e:rpc`, `npm run test:e2e:tui`, and `npm run validate` pass. Sonar re-poll remains part of Task 10 after analysis reruns.

- [x] Task 3: Fix all Sonar bug findings

- [x] Add numeric or domain-specific compare functions for `.sort()` calls in `src/config/merge-policy.ts` and `src/config/write-policy.ts`.
- [x] Correct the conditional in `src/ui/detail-formatters.ts` so true/false branches do not return the same value unless the condition is removed.
- [x] Remove unintended regex control characters in `src/policy/script-content.ts` and `test/e2e/helpers/tui-capture.mjs` while preserving intended matching behavior.
- [x] Add regression tests for each corrected behavior.
- Covers bug IDs: `AZ8dpv-gIBtyveMqfJ0d`, `AZ8dpv-qIBtyveMqfJ0h`, `AZ8dpv8PIBtyveMqfJy_`, `AZ8dpv8YIBtyveMqfJzS`, `AZ8dpv-_IBtyveMqfJ0l`, `AZ8dpv-_IBtyveMqfJ0m`, `AZ8dpv-_IBtyveMqfJ0n`.
- Local validation: `npm run typecheck`, `npm run test`, `npm run test:e2e:rpc`, `npm run test:e2e:tui`, and `npm run validate` pass. Sonar re-poll remains part of Task 10 after analysis reruns.

- [x] Task 4: Refactor command and policy parsing complexity

- [x] Split `src/policy/commands.ts` high-complexity functions into parser stages, predicate helpers, and small result builders.
- [x] Replace deep branch chains with data-driven rule tables where rule order matters and tests can assert precedence.
- [x] Replace nested ternaries with explicit named local variables or helper functions.
- [x] Reduce `classification` parameter count by introducing a typed options/context object.
- [x] Remove duplicate branches and redundant `index` assignments without changing classifier decisions.
- [x] Update `test/command-classifier.test.mjs` and related policy tests to lock down command classification before and after refactors.
- Covers primary IDs in `src/policy/commands.ts`: `AZ8dpv6kIBtyveMqfJyQ`, `AZ8dpv6kIBtyveMqfJyR`, `AZ8dpv6kIBtyveMqfJyS`, `AZ8dpv6kIBtyveMqfJyT`, `AZ8dpv6kIBtyveMqfJyU`, `AZ8dpv6kIBtyveMqfJyV`, `AZ8dpv6kIBtyveMqfJyW`, `AZ8dpv6kIBtyveMqfJyX`, `AZ8dpv6kIBtyveMqfJyY`, `AZ8dpv6kIBtyveMqfJyZ`, `AZ8dpv6kIBtyveMqfJya`, `AZ8dpv6kIBtyveMqfJyb`, `AZ8dpv6kIBtyveMqfJyc`, `AZ8dpv6kIBtyveMqfJyd`, `AZ8dpv6kIBtyveMqfJye`, `AZ8dpv6kIBtyveMqfJyf`, `AZ8dpv6kIBtyveMqfJyg`, `AZ8dpv6kIBtyveMqfJyh`, `AZ8dpv6kIBtyveMqfJyi`, `AZ8dpv6kIBtyveMqfJyj`, `AZ8dpv6kIBtyveMqfJyk`, `AZ8dpv6kIBtyveMqfJyl`, `AZ8dpv6kIBtyveMqfJym`, `AZ8dpv6kIBtyveMqfJyn`, `AZ8dpv6kIBtyveMqfJyo`, `AZ8dpv6kIBtyveMqfJyp`, `AZ8dpv6kIBtyveMqfJyq`, `AZ8dpv6kIBtyveMqfJyr`, `AZ8dpv6kIBtyveMqfJys`, `AZ8dpv6kIBtyveMqfJyt`, `AZ8dpv6kIBtyveMqfJyu`, `AZ8dpv6kIBtyveMqfJyv`.
- Local validation: `npm run typecheck`, `npm run test`, `npm run test:e2e:rpc`, `npm run test:e2e:tui`, and `npm run validate` pass. Sonar re-poll remains part of Task 10 after analysis reruns.

- [ ] Task 5: Refactor core config, evaluation, state, and command modules

- [ ] Reduce cognitive complexity in `src/commands/guardme-command.ts`, `src/config/merge-policy.ts`, `src/config/runtime-settings.ts`, `src/config/schema.ts`, `src/config/write-policy.ts`, `src/events/register-guard.ts`, `src/policy/evaluate.ts`, `src/policy/script-content.ts`, and `src/state/warnings.ts`.
- [ ] Extract named helper functions for repeated validation, formatting, branching, and option-building logic.
- [ ] Replace nested ternaries in command/config/session modules with explicit `if`/`else` or small pure helper functions.
- [ ] Replace duplicate function implementations in `src/config/merge-policy.ts` with a shared helper or intentional, differentiated behavior.
- [ ] Update the existing unit tests for config merge/write, schema, runtime settings, policy evaluation, script content, command UI, and warning state.
- Covers IDs listed for `src/commands/guardme-command.ts`, `src/config/*`, `src/events/*`, `src/events/session-store.ts`, `src/policy/evaluate.ts`, `src/policy/script-content.ts`, and `src/state/warnings.ts` in Appendix A.

- [ ] Task 6: Refactor UI/TUI modules

- [ ] Reduce cognitive complexity in `src/ui/config-tui.ts`, `src/ui/setup-wizard.ts`, and `src/ui/text.ts` by extracting pure render-state builders and keyboard/action handlers.
- [ ] Replace `renderPaneScreen` and `renderSettingRow` long parameter lists with typed props objects.
- [ ] Replace nested ternaries, duplicate switch/case blocks, repeated `push()` sequences, negated conditions, and nested template literals with clearer named constructs.
- [ ] Refactor constant-return functions in `test/e2e/helpers/tui-capture.mjs` so their return values represent meaningful state, or inline/remove them if they are unnecessary.
- [ ] Preserve rendered output through snapshot-like assertions or focused existing tests in `test/config-tui.test.mjs`, `test/config-frame.test.mjs`, `test/setup-wizard.test.mjs`, `test/approval-ui.test.mjs`, and `test/ui-text.test.mjs`.
- Covers IDs listed for `src/ui/approval-modal.ts`, `src/ui/config-frame.ts`, `src/ui/config-tui.ts`, `src/ui/detail-formatters.ts`, `src/ui/setup-wizard.ts`, and `src/ui/text.ts` in Appendix A.

- [ ] Task 7: Fix regex performance and maintainability issues

- [ ] Simplify or split regexes with super-linear backtracking risk in `scripts/check-format.mjs`, `src/events/register-guard.ts`, `src/policy/commands.ts`, and `src/policy/script-content.ts`.
- [ ] Rewrite `src/policy/redact.ts` regexes to reduce complexity, remove duplicate character-class entries, and use concise character classes where safe.
- [ ] Replace `.match()` checks with `RegExp.exec()` where Sonar requires it.
- [ ] Use `String.raw` for regex/string literals that currently rely on hard-to-read escaping.
- [ ] Add targeted tests for representative safe and malicious inputs for every regex that changes.
- Covers regex-focused IDs in `scripts/check-format.mjs`, `src/config/schema.ts`, `src/config/write-policy.ts`, `src/events/register-guard.ts`, `src/policy/commands.ts`, `src/policy/evaluate.ts`, `src/policy/redact.ts`, `src/policy/script-content.ts`, `test/e2e/fixtures/scripted-provider.ts`, and `test/e2e/helpers/tui-capture.mjs`.

- [ ] Task 8: Apply low-risk TypeScript and JavaScript readability fixes

- [ ] Replace `.filter(...)[0]` or destructured `.filter()` patterns with `.find()` where only one element is needed.
- [ ] Introduce type aliases for repeated inline union types.
- [ ] Replace array membership lists with `Set` where Sonar flagged repeated inclusion checks.
- [ ] Replace `.indexOf() >= 0` with `.includes()`, and replace `.findIndex()` with `.indexOf()` when searching for the exact item index.
- [ ] Use `.at()`, `replaceAll()`, `startsWith()`, `codePointAt()`, direct `for...of` iteration, and direct `export ... from` syntax where flagged.
- [ ] Reorder default parameters so defaults are last, or replace the parameter list with an options object if call sites become unclear.
- Covers all remaining minor/major maintainability IDs in Appendix A not resolved by tasks 4-7.

- [ ] Task 9: Add coverage reporting for Sonar

- [ ] Add exactly one coverage implementation path that works with the current Node test runner.
- [ ] Prefer a script that generates `coverage/lcov.info` for Sonar, for example `npm run coverage` using native Node test coverage if it can emit LCOV, or a small dev dependency such as `c8` if native output cannot satisfy Sonar.
- [ ] Add or update Sonar configuration so JavaScript/TypeScript coverage points to `coverage/lcov.info`.
- [ ] Ensure `coverage/` remains ignored and generated reports are not committed.
- [ ] Document the local command in `package.json` scripts and, if needed, project docs.
- [ ] Add coverage for the riskiest refactored modules first: command classification, policy evaluation, config merge/write, script-content regex parsing, and UI render helpers.

- [ ] Task 10: Validate and re-poll Sonar

- [ ] Run all local validation commands.
- [ ] Run the new coverage command and confirm an LCOV report exists.
- [ ] Rerun the repository Sonar analysis with coverage enabled.
- [ ] Poll Sonar again and confirm active issues drop to zero, or create follow-up issue-specific tasks for any newly introduced/moved findings.
- [ ] Update this spec or PR notes with the final Sonar counts.

## Testing Strategy

- Use existing unit tests as guardrails before refactors, then add focused tests for every behavior-changing fix.
- For security fixes, test rejected malicious arguments/paths and allowed safe values.
- For parser and regex refactors, keep table-driven tests with before/after representative inputs.
- For UI refactors, test pure render-state helpers and stable output strings rather than relying only on interactive flows.
- For coverage, verify the command exits non-zero on test failure and writes `coverage/lcov.info` on success.

## Acceptance Criteria

- All 174 active Sonar issues in Appendix A are fixed or explicitly documented with maintainer-approved rationale.
- Sonar reports 0 active bugs, 0 active vulnerabilities, and 0 active code smells for this baseline after analysis reruns.
- A dedicated `npm run coverage` or equivalent package script generates `coverage/lcov.info`.
- Sonar coverage configuration points at the generated LCOV file.
- Existing behavior remains covered by tests, and new tests cover security and correctness changes.
- `npm run validate` passes.

## Validation Commands

Execute these commands to validate the task is complete:

- `npm run typecheck` - Type-check all TypeScript.
- `npm run test` - Run unit tests.
- `npm run test:e2e` - Run end-to-end tests.
- `npm run validate` - Run the repository validation chain.
- `npm run coverage` - Generate coverage after task 9 adds the script.
- `test -f coverage/lcov.info` - Confirm LCOV output exists.
- `sonar-scanner -Dsonar.projectKey=senad-d_GuardMe -Dsonar.organization=senad-d -Dsonar.javascript.lcov.reportPaths=coverage/lcov.info` - Optional local Sonar scan when scanner credentials are available; otherwise rerun the CI Sonar analysis.

## Notes

- Issue IDs may become stale after line-moving refactors; when that happens, match by file, rule, and message.
- Prefer code fixes over suppressions. Use suppressions only when a maintainer agrees the finding is not actionable.
- Keep security-sensitive code paths explicit and easy to audit, even if that means extracting more small helpers.
- The current Sonar quality gate is `NONE`; consider adding a gate after this cleanup so regressions fail CI.

## Appendix A: Polled Active Issue Inventory

This inventory covers all 174 active Sonar issues fetched from pages 1 and 2.

| File | Count | Issue IDs |
| --- | ---: | --- |
| `dev-shims/pi-coding-agent/index.js` | 1 | `AZ8dpwAIIBtyveMqfJ09` |
| `scripts/check-format.mjs` | 1 | `AZ8dpv_2IBtyveMqfJ02` |
| `scripts/publish-npm.mjs` | 6 | `AZ8dpv_-IBtyveMqfJ06`, `AZ8dpv_-IBtyveMqfJ08`, `AZ8dpv_-IBtyveMqfJ03`, `AZ8dpv_-IBtyveMqfJ04`, `AZ8dpv_-IBtyveMqfJ07`, `AZ8dpv_-IBtyveMqfJ05` |
| `src/commands/guardme-command.ts` | 13 | `AZ8dpv95IBtyveMqfJ0J`, `AZ8dpv95IBtyveMqfJ0H`, `AZ8dpv95IBtyveMqfJ0I`, `AZ8dpv95IBtyveMqfJ0K`, `AZ8dpv95IBtyveMqfJ0L`, `AZ8dpv95IBtyveMqfJ0M`, `AZ8dpv95IBtyveMqfJ0N`, `AZ8dpv95IBtyveMqfJ0O`, `AZ8dpv95IBtyveMqfJ0P`, `AZ8dpv95IBtyveMqfJ0Q`, `AZ8dpv95IBtyveMqfJ0R`, `AZ8dpv95IBtyveMqfJ0S`, `AZ8dpv95IBtyveMqfJ0T` |
| `src/config/load-config.ts` | 1 | `AZ8dpv-YIBtyveMqfJ0Z` |
| `src/config/merge-policy.ts` | 4 | `AZ8dpv-gIBtyveMqfJ0a`, `AZ8dpv-gIBtyveMqfJ0b`, `AZ8dpv-gIBtyveMqfJ0c`, `AZ8dpv-gIBtyveMqfJ0d` |
| `src/config/runtime-settings.ts` | 1 | `AZ8dpv-DIBtyveMqfJ0U` |
| `src/config/schema.ts` | 4 | `AZ8dpv-OIBtyveMqfJ0V`, `AZ8dpv-OIBtyveMqfJ0W`, `AZ8dpv-OIBtyveMqfJ0X`, `AZ8dpv-OIBtyveMqfJ0Y` |
| `src/config/write-policy.ts` | 5 | `AZ8dpv-qIBtyveMqfJ0e`, `AZ8dpv-qIBtyveMqfJ0f`, `AZ8dpv-qIBtyveMqfJ0g`, `AZ8dpv-qIBtyveMqfJ0h`, `AZ8dpv-qIBtyveMqfJ0i` |
| `src/events/register-guard.ts` | 5 | `AZ8dpv9eIBtyveMqfJ0A`, `AZ8dpv9eIBtyveMqfJ0B`, `AZ8dpv9eIBtyveMqfJ0C`, `AZ8dpv9eIBtyveMqfJ0D`, `AZ8dpv9eIBtyveMqfJ0E` |
| `src/events/register-lifecycle.ts` | 1 | `AZ8dpv9vIBtyveMqfJ0G` |
| `src/events/session-store.ts` | 1 | `AZ8dpv9nIBtyveMqfJ0F` |
| `src/policy/commands.ts` | 32 | `AZ8dpv6kIBtyveMqfJyQ`, `AZ8dpv6kIBtyveMqfJyR`, `AZ8dpv6kIBtyveMqfJyS`, `AZ8dpv6kIBtyveMqfJyT`, `AZ8dpv6kIBtyveMqfJyU`, `AZ8dpv6kIBtyveMqfJyV`, `AZ8dpv6kIBtyveMqfJyW`, `AZ8dpv6kIBtyveMqfJyX`, `AZ8dpv6kIBtyveMqfJyY`, `AZ8dpv6kIBtyveMqfJyZ`, `AZ8dpv6kIBtyveMqfJya`, `AZ8dpv6kIBtyveMqfJyb`, `AZ8dpv6kIBtyveMqfJyc`, `AZ8dpv6kIBtyveMqfJyd`, `AZ8dpv6kIBtyveMqfJye`, `AZ8dpv6kIBtyveMqfJyf`, `AZ8dpv6kIBtyveMqfJyg`, `AZ8dpv6kIBtyveMqfJyh`, `AZ8dpv6kIBtyveMqfJyi`, `AZ8dpv6kIBtyveMqfJyj`, `AZ8dpv6kIBtyveMqfJyk`, `AZ8dpv6kIBtyveMqfJyl`, `AZ8dpv6kIBtyveMqfJym`, `AZ8dpv6kIBtyveMqfJyn`, `AZ8dpv6kIBtyveMqfJyo`, `AZ8dpv6kIBtyveMqfJyp`, `AZ8dpv6kIBtyveMqfJyq`, `AZ8dpv6kIBtyveMqfJyr`, `AZ8dpv6kIBtyveMqfJys`, `AZ8dpv6kIBtyveMqfJyt`, `AZ8dpv6kIBtyveMqfJyu`, `AZ8dpv6kIBtyveMqfJyv` |
| `src/policy/evaluate.ts` | 5 | `AZ8dpv7-IBtyveMqfJyw`, `AZ8dpv7-IBtyveMqfJyx`, `AZ8dpv7-IBtyveMqfJyy`, `AZ8dpv7-IBtyveMqfJyz`, `AZ8dpv7-IBtyveMqfJy0` |
| `src/policy/redact.ts` | 8 | `AZ8dpv8FIBtyveMqfJy1`, `AZ8dpv8FIBtyveMqfJy2`, `AZ8dpv8FIBtyveMqfJy3`, `AZ8dpv8FIBtyveMqfJy4`, `AZ8dpv8FIBtyveMqfJy5`, `AZ8dpv8FIBtyveMqfJy6`, `AZ8dpv8FIBtyveMqfJy7`, `AZ8dpv8FIBtyveMqfJy8` |
| `src/policy/script-content.ts` | 21 | `AZ8dpv8PIBtyveMqfJy9`, `AZ8dpv8PIBtyveMqfJy-`, `AZ8dpv8PIBtyveMqfJy_`, `AZ8dpv8PIBtyveMqfJzA`, `AZ8dpv8PIBtyveMqfJzB`, `AZ8dpv8PIBtyveMqfJzC`, `AZ8dpv8PIBtyveMqfJzD`, `AZ8dpv8PIBtyveMqfJzE`, `AZ8dpv8PIBtyveMqfJzF`, `AZ8dpv8PIBtyveMqfJzG`, `AZ8dpv8PIBtyveMqfJzH`, `AZ8dpv8PIBtyveMqfJzI`, `AZ8dpv8PIBtyveMqfJzJ`, `AZ8dpv8PIBtyveMqfJzK`, `AZ8dpv8PIBtyveMqfJzL`, `AZ8dpv8PIBtyveMqfJzM`, `AZ8dpv8PIBtyveMqfJzN`, `AZ8dpv8PIBtyveMqfJzO`, `AZ8dpv8PIBtyveMqfJzP`, `AZ8dpv8PIBtyveMqfJzQ`, `AZ8dpv8PIBtyveMqfJzR` |
| `src/state/warnings.ts` | 2 | `AZ8dpv-1IBtyveMqfJ0j`, `AZ8dpv-1IBtyveMqfJ0k` |
| `src/ui/approval-modal.ts` | 5 | `AZ8dpv8rIBtyveMqfJzV`, `AZ8dpv8rIBtyveMqfJzW`, `AZ8dpv8rIBtyveMqfJzX`, `AZ8dpv8rIBtyveMqfJzY`, `AZ8dpv8rIBtyveMqfJzZ` |
| `src/ui/config-frame.ts` | 9 | `AZ8dpv9AIBtyveMqfJze`, `AZ8dpv9AIBtyveMqfJzf`, `AZ8dpv9AIBtyveMqfJzg`, `AZ8dpv9AIBtyveMqfJzh`, `AZ8dpv9AIBtyveMqfJzi`, `AZ8dpv9AIBtyveMqfJzj`, `AZ8dpv9AIBtyveMqfJzk`, `AZ8dpv9AIBtyveMqfJzl`, `AZ8dpv9AIBtyveMqfJzm` |
| `src/ui/config-tui.ts` | 25 | `AZ8dpv9QIBtyveMqfJz6`, `AZ8dpv9QIBtyveMqfJzq`, `AZ8dpv9QIBtyveMqfJzx`, `AZ8dpv9QIBtyveMqfJz0`, `AZ8dpv9QIBtyveMqfJzn`, `AZ8dpv9QIBtyveMqfJzo`, `AZ8dpv9QIBtyveMqfJzp`, `AZ8dpv9QIBtyveMqfJzr`, `AZ8dpv9QIBtyveMqfJzs`, `AZ8dpv9QIBtyveMqfJzt`, `AZ8dpv9QIBtyveMqfJzu`, `AZ8dpv9QIBtyveMqfJzv`, `AZ8dpv9QIBtyveMqfJzw`, `AZ8dpv9QIBtyveMqfJzy`, `AZ8dpv9QIBtyveMqfJzz`, `AZ8dpv9QIBtyveMqfJz1`, `AZ8dpv9QIBtyveMqfJz2`, `AZ8dpv9QIBtyveMqfJz3`, `AZ8dpv9QIBtyveMqfJz4`, `AZ8dpv9QIBtyveMqfJz5`, `AZ8dpv9QIBtyveMqfJz7`, `AZ8dpv9QIBtyveMqfJz8`, `AZ8dpv9QIBtyveMqfJz9`, `AZ8dpv9QIBtyveMqfJz-`, `AZ8dpv9QIBtyveMqfJz_` |
| `src/ui/detail-formatters.ts` | 1 | `AZ8dpv8YIBtyveMqfJzS` |
| `src/ui/setup-wizard.ts` | 4 | `AZ8dpv82IBtyveMqfJza`, `AZ8dpv82IBtyveMqfJzb`, `AZ8dpv82IBtyveMqfJzc`, `AZ8dpv82IBtyveMqfJzd` |
| `src/ui/text.ts` | 2 | `AZ8dpv8gIBtyveMqfJzT`, `AZ8dpv8gIBtyveMqfJzU` |
| `test/e2e/fixtures/scripted-provider.ts` | 5 | `AZ8dpv_qIBtyveMqfJ0x`, `AZ8dpv_qIBtyveMqfJ0y`, `AZ8dpv_qIBtyveMqfJ0z`, `AZ8dpv_qIBtyveMqfJ00`, `AZ8dpv_qIBtyveMqfJ01` |
| `test/e2e/helpers/project-fixture.mjs` | 4 | `AZ8dpv_HIBtyveMqfJ0q`, `AZ8dpv_HIBtyveMqfJ0r`, `AZ8dpv_HIBtyveMqfJ0s`, `AZ8dpv_HIBtyveMqfJ0t` |
| `test/e2e/helpers/rpc-client.mjs` | 3 | `AZ8dpv_fIBtyveMqfJ0u`, `AZ8dpv_fIBtyveMqfJ0v`, `AZ8dpv_fIBtyveMqfJ0w` |
| `test/e2e/helpers/tui-capture.mjs` | 5 | `AZ8dpv-_IBtyveMqfJ0l`, `AZ8dpv-_IBtyveMqfJ0m`, `AZ8dpv-_IBtyveMqfJ0n`, `AZ8dpv-_IBtyveMqfJ0o`, `AZ8dpv-_IBtyveMqfJ0p` |
