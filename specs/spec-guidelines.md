# Plan: GuardMe Engineering Guidelines

## Task Description

Define implementation guidelines for GuardMe, a Pi extension that guards LLM tool calls with IAM-like policy. These guidelines capture coding conventions, Pi extension best practices, generated script/content safety rules, deny-first segment-aware command allowlist policy, package metadata rules, documentation rules, testing rules, security/privacy requirements, and isolated smoke-test expectations for the later implementation session.

## Objective

Give implementation and future maintenance work a concise source of truth for how GuardMe should be built, reviewed, tested, and documented without drifting from the approved project definition.

## Problem Statement

GuardMe is security-sensitive because it evaluates shell commands, generated file content, local script execution, and filesystem paths before Pi tools execute. Mistakes in defaults, matching, precedence, prompting, content inspection, or persistence could either block legitimate work unexpectedly or allow sensitive access that the user expected to deny. The implementation must be conservative, explicit, well tested, and practical enough that safe discovery/introspection commands do not require a separate exact rule for every possible flag combination.

Two bypass classes must be treated as first-class requirements: writing a script/helper file that contains forbidden commands and then executing it, and running generic commands that are absent from both the allow and deny command policy.

## Solution Approach

Use small, testable modules with clear domain types and a deny-first, segment-aware command allowlist policy engine. Keep Pi integration thin: event handlers should adapt Pi inputs to domain requests, split shell commands into executable segments, inspect generated command-bearing content before mutation/execution, call pure policy logic, and map decisions to Pi block/prompt behavior. Never treat GuardMe as an OS sandbox; document the limitations everywhere users make trust decisions.

## Relevant Files

- `src/extension.ts` - Must remain small and only call registration functions.
- `src/constants.ts` - Centralize public names and paths.
- `src/config/` - YAML schema, load/merge/write logic.
- `src/state/` - JSONL warning and decision state.
- `src/policy/` - Pure policy model, matching, path resolution, command classification, script-content extraction, decisions.
- `src/events/` - Pi lifecycle, `tool_call` registration, and guidance injection.
- `src/ui/` - User approval UI and rendering helpers.
- `src/commands/` - `/guardme` command only.
- `test/` - Unit and integration tests for package, policy, state, UI, and adapters.
- `docs/` - Policy reference, structure guide, project definition brief, validation guide.
- `README.md` and `SECURITY.md` - User-facing installation, usage, and security boundary.

## Implementation Guidelines

### General coding conventions

- Keep modules focused and small.
- Prefer pure functions in `src/policy/`, `src/config/`, and `src/state/`.
- Avoid hidden process-global mutable state except for session-local caches owned by registration modules.
- Prefer explicit result objects over throwing for expected policy/config validation errors.
- Throw only for programmer errors or truly unrecoverable IO failures.
- Return structured diagnostics with source path, rule index, severity, and message where possible.
- Do not log raw secrets, full file contents, command output, environment values, or credential paths beyond minimally necessary redacted path labels.
- Content inspection may read proposed write/edit text or local scripts for policy evaluation, but diagnostics/state/UI must store only redacted snippets, normalized command labels, and fingerprints.
- Avoid broad catch-and-ignore around security decisions; if evaluation is ambiguous for a dangerous action, script content, or unknown shell command, fail closed.

### Pi extension best practices

- Keep `src/extension.ts` small. It should import feature modules and call their `register*` functions.
- Do not start long-lived processes, file watchers, timers, sockets, or background jobs directly in the extension factory.
- Start session-scoped work from `session_start`, a command, or a tool; clean up in `session_shutdown`.
- Use `pi.on("tool_call", ...)` for enforcement before built-in tools execute.
- Use `ctx.hasUI` before any dialog and `ctx.mode === "tui"` before TUI-specific custom UI.
- In non-UI modes, block any action that would require user approval.
- Use `ctx.cwd` as the active project root.
- `registerGuidance` should inject concise model-facing guidance after blocked/coached/policy-missing events; it must not leak full file content, command output, or secrets.
- Use Pi's `CONFIG_DIR_NAME` instead of hardcoding `.pi` if implementation needs rebrand-aware config paths; preserve the approved user-facing default `.pi/agent/guardme.yaml` unless Pi API requires a different composition.
- Clear status/widgets on `session_shutdown`.
- Use concise `ctx.ui.notify()` messages; do not spam notifications for every allowed tool call.
- If GuardMe later registers custom tools, each tool must define TypeBox schemas, descriptions, `promptSnippet`, and `promptGuidelines`; every guideline must name the tool explicitly.
- Use `StringEnum` from `@earendil-works/pi-ai` for string enum schemas if enum fields are needed.
- If any future custom tool mutates files, use Pi file mutation queue helpers and resolve paths safely.
- Truncate large tool outputs and tell the agent when output is truncated.
- Store branch-sensitive state in tool result `details` when possible. GuardMe's warned-once state is intentionally separate JSONL because it is policy/session behavior, not branch-local LLM context.

### Policy semantics

- Deny always wins over allow.
- Built-in hard denials cannot be overridden by YAML or user prompts.
- `zeroAccessPaths` blocks read, list, write, edit, delete, move, rename, and shell-derived access.
- `readOnlyPaths` allows read/list but blocks mutations.
- `noDeletePaths` blocks deletion, destructive moves, and destructive renames.
- `denyPaths` and `denyCommands` beat `allowPaths` and `allowCommands`.
- `allowCommands` is evaluated per executable shell segment. A compound command such as `pwd && ls -lh` may run only when every executable segment is allowed by an acceptable command rule and no stronger deny/protection applies.
- Wildcard `allowCommands` rules may authorize non-dangerous generic/read/list/write/edit segments after path checks. They cannot authorize hard-denied commands, protected credential access, outside-project path access, uninspectable local scripts, script-content failures, dangerous commands, or destructive delete/move/rename behavior.
- A trailing argument wildcard such as `pwd *` or `ls *` should be treated as zero-or-more arguments in the balanced matcher so users do not need separate `pwd` and `pwd *` rules for no-argument commands.
- Exact `allowCommands` rules may approve dangerous-but-not-hard-forbidden inside-project commands only after hard protections, deny rules, and path requirements pass.
- Generated file/script content is evaluated before write/edit mutations are allowed; content-derived deny/hard-deny/policy-missing decisions block the mutation.
- Local script execution is evaluated before `bash` runs the script; script content cannot be used to bypass command/path policy.
- Generic `bash` command segments are default-deny: if any executable segment is absent from allow, deny, dangerous, and hard-deny classification, it is policy-missing and must block the whole command first.
- Local policy can add stricter rules and additional project-specific allow rules, but cannot weaken global hard denials or global deny/protection rules.
- Cloud CLIs (`aws`, `az`, `gcloud`) are always denied in GuardMe and may be managed by a future separate extension.
- Git/network policy is otherwise out of scope except when a command also matches file, credential, cloud CLI, or destructive policy.
- Direct reads/writes inside the project are allowed by default unless denied/protected and unless proposed write/edit content fails script/content policy.
- Deletes inside the project require destructive-command analysis and may trigger coaching/user approval.
- Outside-project reads require explicit allow/read-only policy.
- Outside-project writes/deletes/moves/renames require explicit allow and must not hit any protected/deny rule.
- Browser launchers, GUI app launchers, network clients, local executables, and other generic shell command segments require explicit command policy before execution.

### Path matching rules

- Normalize leading `@` from model path arguments.
- Resolve relative paths against `ctx.cwd`.
- Expand `~` to the user's home directory.
- Canonicalize existing paths through realpath to reduce symlink bypasses.
- For missing paths, resolve lexically and check parent directories when possible.
- Match both absolute paths and project-relative paths.
- Treat path traversal (`..`) and symlink uncertainty conservatively.
- Keep glob behavior documented with examples.
- Prefer explicit rule source metadata so UI can explain which rule matched.

### Shell command classification rules

- Start with explicit high-confidence patterns instead of pretending to parse every shell feature perfectly.
- Split compound commands, pipelines, shell wrappers, command substitutions, process substitutions, and `find -exec`/package-runner forms into executable segments where practical.
- Require every executable segment to pass deny-first checks and command allow matching; one denied, dangerous, protected, uninspectable, or policy-missing segment blocks the entire command.
- Hard deny cloud CLI binaries even when wrapped by common launch forms such as `command aws`, `env aws`, or simple shell prefixes.
- Hard deny obvious disk formatting/raw disk patterns.
- Detect recursive force deletion such as `rm -rf`, `rm -fr`, `rm --recursive --force`, and dangerous root/home/project patterns.
- Detect deleting `.git` by command and by path match.
- Detect common credential reads: exact `.env`, ambiguous `.env*` shell globs, SSH private keys, cloud credential directories, and credential-like filenames; do not hard-block exact template files such as `.env.example` unless policy denies them.
- Detect local script execution forms such as `./script.sh`, `bash script.sh`, `sh script`, and `zsh script.zsh`, and request content inspection before allowing execution.
- Treat unrecognized or unmatched generic command segments as policy-missing even if they look low-risk.
- If a destructive command, script, or unknown command is ambiguous, require approval or block in non-UI mode.
- Do not execute shell commands during classification.

### Script and generated content rules

- `write` must inspect the proposed `content` before writing when the target path or content looks command-bearing.
- `edit` must inspect each `newText` replacement and, when feasible, the reconstructed file content before applying the edit.
- Command-bearing content includes shell shebangs, shell file extensions, Makefile recipes, package manager scripts, CI `run:` blocks, Dockerfile `RUN` lines, and heredoc/stdin script bodies where practical.
- Extracted commands must be evaluated with the same deny-first/default-deny command policy as direct `bash` calls.
- If extracted content contains a hard-denied or explicit-denied command, block without offering an allow decision.
- If extracted content contains dangerous or policy-missing commands, block the first attempt with guidance and use the repeated-attempt approval flow.
- Do not write partial files when content policy blocks. The block must happen before the target file is created or modified.
- Script-content diagnostics should identify the file path and normalized command label, not the full file content.
- Local script execution must fail closed if the script path cannot be resolved safely, is outside policy, is binary/too large to inspect, or contains command-bearing content that cannot be confidently evaluated.

### Warned-once behavior

- First dangerous-but-not-hard-forbidden or policy-missing segment fingerprint: block the tool call and return a coaching reason that tells the model which segment failed and what safer next step to try.
- Persist the first warning in JSONL state with a reason code such as `dangerous-command`, `policy-missing-command`, or `script-content-denied`.
- Repeated fingerprint/type: ask the user when UI exists.
- If the user chooses a one-time decision, do not write YAML policy.
- If the user chooses persistent decision, write the selected allow/deny rule to local/global YAML after rechecking that the rule does not weaken hard policy or existing deny/protection policy.
- If no UI exists for a repeated dangerous or policy-missing action, block.
- Fingerprints should be stable enough to recognize repeated behavior for the missing/dangerous segment across similar compounds, but should not include secret contents or full file contents.

### TUI and user experience rules

- Use a clear modal/overlay for TUI approval.
- Show risk level, requested action, path/command, project root, matched rules, source of each rule, and the recommended safer behavior.
- Provide exactly these decision classes in the approval flow:
  - allow once
  - deny once
  - allow and save to local config
  - deny and save to local config
  - allow and save to global config
  - deny and save to global config
- Make the safest option easy to understand, not hidden.
- Support escape/cancel as deny once.
- Use theme colors (`success`, `warning`, `error`, `accent`, `muted`, `dim`) instead of hardcoded ANSI where possible.
- Keep rendered lines within the provided width and use Pi TUI helpers for wrapping/truncation.
- Avoid rendering full secrets, full command output, or full file contents in the UI.
- For hard-denied or explicit-denied repeats, present deny-only explanatory UI if needed; never offer an allow action that would weaken hard policy.

### Config and persistence rules

- Do not create config files at startup.
- Create global YAML during package postinstall only when missing; never overwrite existing user policy.
- Create project-local YAML only when the user saves a rule or runs setup.
- Keep policy YAML human-editable.
- Keep generated state in separate JSONL files:
  - global: `~/.pi/agent/guardme-state.jsonl`
  - local: `.pi/agent/guardme-state.jsonl`
- Tolerate missing YAML/state files.
- Report malformed YAML clearly.
- For malformed security-critical rules, fail closed for matching/ambiguous actions.
- Preserve unrelated YAML comments/formatting when practical; if not feasible, document that saved rules may rewrite the GuardMe YAML file.
- Never store credentials, environment values, command output, or full generated file content in state.

### Package metadata rules

- Package name: `@senad-d/guardme`.
- Display name: `GuardMe`.
- Repository: `https://github.com/senad-d/GuardMe`.
- Keep the Pi manifest pointing at `./src/extension.ts` unless the entry point moves.
- Include `pi-package`, `pi-extension`, `security`, `policy`, and `guardrails` style keywords.
- Keep Pi core packages in `peerDependencies` with `"*"`.
- Put non-Pi runtime libraries (`yaml`, glob matcher, etc.) in `dependencies` only when imported by runtime code.
- Put local development/test tools in `devDependencies`.
- Keep package contents minimal; do not publish `.pi/`, `specs/`, state files, caches, reports, tarballs, credentials, or local paths.

### Documentation rules

- README must clearly label planned vs implemented behavior until feature work is complete.
- SECURITY must state that GuardMe is not an OS sandbox and only covers Pi LLM tool calls routed through the extension.
- Document default hard denials, segment-aware command allowlist behavior, policy-missing shell segments, script-content scanning, and policy precedence.
- Document global/local YAML paths, installer-created global defaults, and JSONL state paths.
- Document non-UI fail-closed behavior and model-facing block guidance.
- Include isolated smoke testing with `pi --no-extensions -e .`.
- Update CHANGELOG for every user-visible behavior change.
- Document any new dependency and why it is needed.

### Testing rules

- Prioritize table-driven pure unit tests.
- Include tests for deny-over-allow precedence.
- Include tests for global/local merge behavior.
- Include tests for local rules not weakening global denials/protections.
- Include tests for path normalization with relative paths, absolute paths, `~`, leading `@`, `..`, missing files, and symlinks where feasible.
- Include tests for hard-denied command families.
- Include tests for generated script/file content that attempts hard-denied credential access.
- Include tests proving local script execution is inspected before `bash` runs it.
- Include tests proving generic commands absent from both allow and deny policy are blocked first and prompt on repeat.
- Include tests proving wildcard allow rules can approve safe command segments such as `ls -lh`, `pwd`, and `pwd && ls -lh` while still blocking a compound when any segment is unallowed.
- Include tests proving wildcard allow rules do not bypass protected paths, outside-project path requirements, dangerous/destructive commands, command substitutions, wrappers, or script-content failures.
- Include tests for first-warning vs repeated-warning state behavior.
- Include tests for non-UI prompt-needed blocking.
- Keep package/metadata tests separate from feature behavior tests.
- Do not mark future task-spec checkboxes complete until the corresponding implementation and tests are actually done.

### Validation and smoke-test rules

Run these during implementation milestones:

- `npm run typecheck`
- `npm run test`
- `npm run check:pack`
- `npm run validate`
- `pi --no-extensions -e .`

Manual smoke scenarios after implementation:

- Allowed project read succeeds.
- Protected `.env` read blocks.
- `aws sts get-caller-identity` blocks.
- Writing a script that reads `~/.azure`, `~/.aws`, `.env`, or SSH keys blocks before the file is written.
- Running a local script is inspected and blocks if script content contains denied or policy-missing commands.
- A generic browser/GUI launcher such as `open -a Brave ...` or `brave ...` blocks when no allow/deny command rule exists.
- With explicit `pwd *` and `ls *` allow rules, `pwd && ls -lh` runs, while `pwd && unknown-tool` blocks on the missing segment.
- First `rm -rf build`-style dangerous or policy-missing attempt receives coaching and records state.
- Repeated dangerous or policy-missing attempt opens approval UI in TUI mode.
- Saved local/global rule appears in the expected YAML file.
- Outside-project read without allow rule blocks.
- Outside-project read with explicit read-only allow succeeds.
- Outside-project write remains denied unless explicitly allowed and not protected.

## Implementation Phases

### Phase 1: Safety foundation

- Establish policy types, defaults, config paths, path matching, segment-aware command allowlist semantics, and script-content extraction.
- Add tests for hard denials, default-deny commands, generated script content, and precedence before event integration.

### Phase 2: Pi integration

- Add lifecycle and `tool_call` event adapters.
- Add write/edit content scanning and local-script execution inspection.
- Add warned-once JSONL behavior for dangerous and policy-missing attempts.
- Add non-UI fail-closed handling.

### Phase 3: User experience and packaging

- Add TUI approval modal and YAML rule persistence.
- Add model-facing guidance injection for blocked/coached/policy-missing actions.
- Add `/guardme` command.
- Complete docs, tests, validation, and smoke testing.

## Step by Step Tasks

### 1. Check the approved sources

- Read `docs/PROJECT_DEFINITION_BRIEF.md` and the relevant spec files before implementing, including `specs/spec-architecture.md`, `specs/spec-guidelines.md`, `specs/spec-tasks.md`, and any focused change spec such as `specs/spec-segment-aware-command-allowlists.md`.
- Resolve conflicts by asking the user which decision wins.

### 2. Keep feature work scoped

- Implement one task-spec checkbox at a time.
- Update tests and docs with each feature change.
- Stop before changing policy semantics that are not covered by the specs.

### 3. Apply security-sensitive review

- Review every file, shell, path, state, and config change for accidental access leaks.
- Prefer fail-closed behavior for ambiguity.

### 4. Validate continuously

- Run targeted tests after each module.
- Run full validation before final handoff.

## Testing Strategy

Use a layered test strategy:

1. Pure unit tests for policy/config/path/command/script-content modules.
2. Adapter tests for Pi tool-call input mapping, write/edit content scanning, and local-script execution inspection.
3. UI decision mapping tests that avoid fragile full terminal rendering.
4. Manual isolated Pi smoke tests for real extension loading.

## Acceptance Criteria

- Future implementation follows deny-first policy, hard protection rules, and segment-aware command allowlist behavior.
- `src/extension.ts` stays small and delegates to modules.
- Config, state, policy, UI, and event code remain separated.
- Generated command-bearing files are inspected before write/edit mutations, and blocked content is not written.
- Local scripts are inspected before `bash` execution.
- Tests cover policy precedence, hard denials, generated script content, local script execution, merge semantics, and warned-once/policy-missing behavior.
- Docs clearly distinguish Pi-session enforcement from OS sandboxing.
- Package metadata follows Pi package dependency rules.

## Validation Commands

- `npm run typecheck` - Verify TypeScript correctness.
- `npm run test` - Run unit and integration tests.
- `npm run check:pack` - Ensure package contents stay clean.
- `npm run validate` - Full repository validation.
- `pi --no-extensions -e .` - Isolated manual Pi extension smoke test.

## Notes

These guidelines are intentionally conservative. GuardMe's value depends on predictable policy behavior and clear communication when it cannot enforce something outside Pi's extension/tool-call path.
