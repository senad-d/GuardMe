# Plan: Segment-Aware Command Allowlists

## Task Description

Refine GuardMe command policy so `allowCommands` patterns are useful for normal agent workflows without weakening deny-first protections. Instead of treating a wildcard allow rule as too broad for most classified commands, GuardMe should split shell commands into executable segments, evaluate every segment against hard-deny/path/script protections, and allow the full command only when each segment is permitted by an acceptable command rule.

The motivating example is that a user should be able to configure rules such as `ls *` and `pwd *`, then allow `pwd && ls -lh`, while still blocking `pwd && ls -lh && rm -rf build`, `cat .env`, `cat /etc/passwd`, `aws sts get-caller-identity`, or any compound command containing an unallowed segment.

## Objective

Implement a balanced command allowlist model that:

- lets wildcard `allowCommands` rules authorize safe command families and flag combinations;
- evaluates compound shell commands segment by segment;
- blocks the whole command if any segment is denied, dangerous without exact allow, protected, outside-project without path permission, uninspectable, or policy-missing;
- uses warned-once coaching and repeated-attempt approval for missing or dangerous segments;
- preserves hard-deny, path protection, script-content, local-script, and outside-project safety guarantees.

## Problem Statement

The current command allow behavior is safe but too strict. A rule such as `ls *` matches `ls -la` textually, but the allow is rejected because `ls` is classified as a `list` command and wildcard command allows are not allowed to override classified risk. As a result, many harmless discovery commands require exact allow rules for every flag combination, which is not practical because the LLM's exact commands are hard to know in advance.

At the same time, simply letting wildcard rules override every classification would be unsafe. A broad rule like `cat *` must not read `.env` or `/etc/passwd`, `find *` must not approve `find . -delete`, and `npm test*` must not approve appended guarded segments. The solution needs a middle ground: pattern-based allows for safe segments, deny-first blocking for unsafe segments, and user approval for repeated missing patterns.

## Solution Approach

Introduce a command-segment evaluation layer:

1. Parse each `bash` command into executable segments, including top-level compounds, pipelines, wrappers, command substitutions, process substitutions, package runners, and `find -exec` where practical.
2. Classify each segment independently and retain aggregate command metadata for UI/debugging.
3. Apply hard-deny, explicit deny, protected path, outside-project, dangerous, script-content, and local-script checks before allow evaluation.
4. Evaluate `allowCommands` against each segment. Wildcard rules may approve non-dangerous generic/read/list/write/edit segments after path gates. Exact rules are required for dangerous/destructive/delete/move/rename behavior.
5. Allow the full command only if every executable segment is allowed or covered by a compatible exact full-command allow.
6. If one or more segments are policy-missing, block the whole command with guidance naming the first missing segment. Persist a redacted segment fingerprint; on repeated similar attempts, prompt the user when UI exists.

## Relevant Files

- `src/policy/commands.ts` - Extend command parsing/classification to expose executable segment metadata and segment match candidates.
- `src/policy/evaluate.ts` - Replace whole-command-only allow behavior with segment-aware allow evaluation while preserving deny-first precedence.
- `src/events/register-guard.ts` - Map `bash` tool calls into segment-aware policy requests and make block reasons identify failed segments.
- `src/policy/action.ts` - Add segment/fingerprint metadata if needed for policy decisions and warnings.
- `src/state/warnings.ts` - Persist missing/dangerous segment fingerprints without storing secrets or full script content.
- `src/config/schema.ts` - Update built-in default policy if the agreed starter allowlist changes.
- `scripts/install-global-policy.mjs` - Keep installer-created global policy aligned with built-in defaults for new installs only.
- `docs/POLICY.md`, `README.md`, `SECURITY.md`, `CHANGELOG.md` - Document segment-aware allow semantics, examples, and limitations.
- `specs/spec-architecture.md` and `specs/spec-guidelines.md` - Keep architecture/guideline specs aligned with this plan.
- `test/command-classifier.test.mjs` - Add parser and segment extraction coverage.
- `test/policy-evaluate.test.mjs` - Add pure policy tests for wildcard segment allows and missing segments.
- `test/tool-guard.test.mjs` - Add end-to-end adapter tests for `bash` compounds, protected paths, and approvals.
- `test/config-schema.test.mjs`, `test/install-global-policy.test.mjs` - Update only if default policy contents change.

### New Files

No new source file is strictly required. If `src/policy/commands.ts` becomes too large, create:

- `src/policy/command-segments.ts` - Pure segment extraction, normalization, and segment-level match helpers.
- `test/command-segments.test.mjs` - Focused tests for segment splitting and command glob behavior.

## Implementation Phases

### Phase 1: Segment model and regression tests

- Define the executable segment terminology and redacted fingerprint shape.
- Add failing tests for the desired behavior before changing policy evaluation.
- Decide whether to keep segment helpers in `commands.ts` or split them into `command-segments.ts`.

### Phase 2: Balanced allow evaluation

- Expose segment metadata from command classification.
- Implement command glob semantics that support user-friendly trailing argument wildcards.
- Evaluate allow/deny rules per segment with deny-first precedence.
- Preserve exact full-command allow behavior where it is still safe.

### Phase 3: UX, defaults, docs, and validation

- Improve coaching and approval prompts so they name the failing segment.
- Save persistent approvals as narrow segment-level rules.
- Update default starter policy only if explicitly accepted, and never mutate existing global policy automatically.
- Update docs, changelog, and validation coverage.

## Step by Step Tasks

### 1. Add regression tests for the target behavior

- [ ] Add pure policy tests showing `allowCommands: [{ pattern: "ls *" }]` allows `ls -la` after deny/path checks pass.
- [ ] Add pure policy tests showing `allowCommands: [{ pattern: "pwd *" }]` allows both `pwd` and `pwd -L`.
- [ ] Add compound tests showing `pwd && ls -lh` is allowed when `pwd *` and `ls *` are allowed.
- [ ] Add compound tests showing `pwd && unknown-tool` blocks as policy-missing and identifies `unknown-tool` as the failed segment.
- [ ] Add safety tests showing `pwd && ls -lh && rm -rf build` blocks because of the dangerous segment unless an exact safe approval exists for that destructive segment.
- [ ] Add protection tests showing wildcard allows do not approve `cat .env`, `cat /etc/passwd`, `find . -delete`, `aws sts get-caller-identity`, command substitutions such as `echo $(rm -rf build)`, or wrapped denied commands.

#### Acceptance criteria

- Tests express the desired semantics before implementation and fail against the current strict exact-allow behavior.
- Regression cases include both whole-command success and single-segment failure in compounds.
- Every safety regression asserts the block reason or matched rule class, not only that a block occurred.

### 2. Define and expose executable command segments

- [ ] Add an exported segment model, either inside `src/policy/commands.ts` or a new `src/policy/command-segments.ts` module.
- [ ] Represent each segment with normalized text, original text, command name, action, risk, target paths, source kind (`top-level`, `pipeline`, `wrapper`, `substitution`, `find-exec`, `package-runner`, etc.), and matched classifier details.
- [ ] Reuse existing tokenizer/splitter logic where possible; do not introduce shell execution or a heavyweight parser without explicit approval.
- [ ] Include nested executable forms already considered by hard-deny logic: command substitution, process substitution, backticks, `bash -c`, `env -S`, `xargs`, `parallel`, `find -exec`, `npx`/`npm exec`/`pnpm dlx`/`yarn dlx`/`bunx`, `eval`, and `exec`.
- [ ] Keep aggregate `CommandClassification` behavior available for existing path/action logic until it can be safely replaced.

#### Acceptance criteria

- Segment extraction returns `pwd` and `ls -lh` for `pwd && ls -lh`.
- Segment extraction returns nested dangerous segments for `echo $(rm -rf build)` and `find . -exec rm -rf {} \;`.
- Segment metadata includes enough information for policy evaluation to report which segment failed.
- Existing command-classifier tests still pass or are updated to equivalent segment-aware assertions.

### 3. Implement balanced command glob semantics

- [ ] Keep command matching anchored to normalized command text; `*` and `?` remain simple glob operators.
- [ ] Add a documented trailing-argument wildcard behavior: a pattern ending in ` *` matches the command with zero or more arguments, so `ls *` matches both `ls` and `ls -lh`, and `pwd *` matches both `pwd` and `pwd -L`.
- [ ] Preserve exact-rule detection separately from wildcard-rule detection, because exact rules can approve some dangerous-but-not-hard-forbidden commands while wildcard rules cannot.
- [ ] Apply the same normalized matching rules to deny/dangerous candidates where doing so only broadens safety, for example `sudo *` should also catch bare `sudo` if the matcher supports optional trailing arguments.
- [ ] Add tests for whitespace normalization, absolute executable basename candidates, quoted arguments, and optional trailing wildcard behavior.

#### Acceptance criteria

- `commandGlobToRegExp` or its replacement is covered by direct tests.
- `ls *` matches `ls`, `ls -lh`, and `/bin/ls -lh` when basename candidates are intended to match.
- `ls *` does not match unrelated commands such as `eslint .`.
- Exact-rule checks still distinguish `rm -rf build` from `rm -rf *`.

### 4. Add segment-aware allow evaluation

- [ ] Evaluate hard-denied command classification before all allow logic.
- [ ] Evaluate `denyCommands` against every segment and existing whole-command candidates before allow logic.
- [ ] Detect `dangerousCommands` and built-in dangerous classifications per segment before allow logic, but allow an exact compatible command rule to approve dangerous-but-not-hard-forbidden inside-project behavior after all hard/path protections pass.
- [ ] Evaluate protected credential paths, hard path protections, explicit `denyPaths`, and outside-project path requirements before allow decisions.
- [ ] Allow a simple or compound command only when every executable segment is either allowed by a compatible `allowCommands` rule or covered by a compatible exact whole-command allow.
- [ ] Permit wildcard allows for non-dangerous generic/read/list/write/edit segments after path gates pass.
- [ ] Require exact allows or approval flow for dangerous, destructive, delete, move, and rename segments.
- [ ] If multiple segments fail, report the highest-risk failure first and include a concise summary that additional segments were not allowed.

#### Acceptance criteria

- `pwd && ls -lh` allows with `pwd *` and `ls *`.
- `pwd && ls -lh && unknown-tool` blocks because `unknown-tool` is policy-missing.
- `ls *` allows `ls -la` without requiring `ls -la` as an exact rule.
- `cat *` allows `cat README.md` but not `cat .env` or `cat /etc/passwd`.
- `find *` allows safe project discovery but not `find . -delete` or broad protected discovery when direct protected descendants exist.
- Existing exact allow behavior for safe approved dangerous commands such as `rm -rf build` remains intact after hard protections pass.

### 5. Preserve script-content, local-script, and package-script protections

- [ ] Ensure a wildcard allow for a local script invocation, for example `./scripts/*`, does not bypass local script content inspection.
- [ ] Ensure package-manager allow rules such as `npm test*` still inspect `package.json` scripts and lifecycle hooks before execution.
- [ ] Keep package-script inherited allow behavior only for ordinary internal script commands that do not hit hard-deny, dangerous, protected-path, or outside-project findings.
- [ ] Ensure generated command-bearing content written by `write`/`edit` still requires exact or segment-level approval for extracted commands and cannot rely on a broad parent shell allow.
- [ ] Add tests for wildcard-allowed invocations whose script content contains a hard-denied command, dangerous command, and policy-missing command.

#### Acceptance criteria

- A wildcard command allow cannot make an uninspectable local script executable.
- A wildcard command allow cannot write a script containing `aws`, `.env`, `~/.aws`, or `rm -rf` without the existing script-content workflow blocking first.
- Package script inspection behavior is unchanged except for clearer segment-aware diagnostics.
- Non-UI repeated script-content or local-script prompts still fail closed.

### 6. Improve coaching, fingerprints, and approval persistence

- [ ] Change policy-missing coaching for compounds to identify the first missing segment and list allowed/matched segments when helpful.
- [ ] Generate warned-once fingerprints from the redacted missing/dangerous segment plus action/risk/source context, not from the entire compound command only.
- [ ] On repeated missing-segment attempts, prompt the user when UI exists and block when UI is unavailable.
- [ ] Persist saved allow decisions as narrow exact segment rules by default, not broad wildcard compound rules.
- [ ] Persist saved deny decisions as exact or family rules according to the approval choice, with clear UI wording.
- [ ] Keep refusing to save allow rules for hard-denied actions or rules containing secret-like values.

#### Acceptance criteria

- First `pwd && unknown-tool` blocks with coaching that names `unknown-tool`.
- Repeating `ls && unknown-tool` after `pwd && unknown-tool` can reuse the missing-segment warning fingerprint if the normalized missing segment is the same.
- Persistent allow for a missing segment writes an `allowCommands` rule for that segment, not the entire compound unless explicitly selected.
- Hard-denied and explicit-denied repeats still do not offer an allow option.

### 7. Review and update starter allowlist defaults

- [ ] Decide the exact starter command allowlist for new installs. Recommended minimal balanced preset: `pwd *`, `ls *`, `cat *`, `head *`, `tail *`, `wc *`, `grep *`, `find *`, plus existing package validation commands.
- [ ] Add any new command classifier support needed before including a command in defaults; do not add default patterns for commands whose path behavior is unknown.
- [ ] Update `createBuiltInDefaultPolicy()` and `scripts/install-global-policy.mjs` only for newly agreed defaults.
- [ ] Do not mutate or migrate an existing `~/.pi/agent/guardme.yaml` automatically; document manual migration or provide a future explicit `/guardme` action if needed.
- [ ] Update config/install tests for new default rules if defaults change.

#### Acceptance criteria

- New installs receive the agreed balanced starter allowlist if and only if defaults are changed.
- Existing global policy files are never overwritten or silently broadened.
- Each default allow rule has tests proving protected paths and dangerous variants still block.
- Documentation clearly labels starter defaults as command patterns constrained by deny/path/script protections.

### 8. Update documentation and specs

- [ ] Update `docs/POLICY.md` with segment-aware allow examples, including `pwd && ls -lh`, `pwd && unknown-tool`, `cat .env`, and `find . -delete`.
- [ ] Update README usage examples and SECURITY boundary language if user-visible command behavior changes.
- [ ] Update CHANGELOG with the behavior change and migration notes for existing global policies.
- [ ] Keep `specs/spec-architecture.md` and `specs/spec-guidelines.md` aligned with the final design decisions.

#### Acceptance criteria

- Policy docs explain that `allowCommands` patterns match executable segments, not only entire command strings.
- Docs explain that wildcard allows do not bypass hard denials, protected paths, outside-project requirements, dangerous/destructive checks, script-content scanning, or local-script inspection.
- Docs explain trailing argument wildcard behavior.
- Examples match tested behavior.

### 9. Validate the full behavior

- [ ] Run targeted unit tests after each policy/classifier change.
- [ ] Run full repository validation before handoff.
- [ ] Perform manual smoke tests in an isolated Pi session with a temporary global/local policy.
- [ ] Verify non-UI behavior blocks prompt-needed decisions without hanging or silently allowing.

#### Acceptance criteria

- `npm run typecheck` passes.
- `npm run test` passes.
- `npm run check:pack` passes.
- `npm run validate` passes.
- Manual smoke test confirms `pwd && ls -lh` is allowed with `pwd *` and `ls *`.
- Manual smoke test confirms a compound containing one unallowed segment blocks and then prompts on repeat when UI exists.
- Manual smoke test confirms protected/dangerous examples still block even when broad safe command patterns exist.

## Testing Strategy

Use layered tests:

1. Pure command segment tests for splitting, normalization, nested command extraction, wrappers, and trailing wildcard matching.
2. Pure policy tests for allow/deny precedence and segment-aware all-segments-must-pass behavior.
3. Adapter tests for `bash` tool calls, local script inspection, package script inspection, and script-content write/edit scanning.
4. State/UI tests for missing-segment coaching, repeated prompts, and saved rule persistence.
5. Documentation/example regression tests where practical, or direct policy tests mirroring every documented example.

## Acceptance Criteria

- Wildcard `allowCommands` rules can approve safe command segments such as `ls -lh` and `pwd` without exact per-flag rules.
- Compound shell commands run only when every executable segment is allowed and all deny/protection/path/script checks pass.
- A single denied, dangerous, protected, outside-project, uninspectable, or policy-missing segment blocks the entire command.
- First missing/dangerous segment attempts coach and record JSONL state; repeated attempts prompt with UI or block without UI.
- Persistent approvals save narrow segment-level rules by default.
- Hard denials, explicit denials, protected credential paths, outside-project path requirements, dangerous/destructive checks, script-content scanning, and local-script inspection remain non-bypassable.
- Docs and tests cover the intended behavior and migration/default-policy implications.

## Validation Commands

- `npm run typecheck` - Verify TypeScript compiles.
- `npm run test` - Run unit/integration tests.
- `npm run check:pack` - Verify package contents remain clean.
- `npm run validate` - Run full repository validation.
- `pi --no-extensions -e .` - Manual isolated Pi extension smoke test.

## Notes

- This change should make GuardMe less frustrating without making it an OS sandbox. Allowed shell segments still run with the local user's permissions.
- Prefer exact saved approvals for unknown or risky commands. Wildcard rules are for user-authored safe command families, not automatic approvals.
- Keep implementation deterministic and conservative. When segment extraction is ambiguous, block with guidance rather than guessing.
